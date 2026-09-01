"""Symbol-leak gnarliness bar (todo.md D2).

A release-blocking measurement gate for metadata/symbol hygiene. The pass
renames internal (static) symbols to BLAKE3 digests at the IR level, so an
IR-level decompiler cannot recover the original helper names. This bar turns
that into a hard, falsifiable check.

Contract:
  * A program defines static helper functions and file-static variables with
    distinctive secret names.
  * The plain IR (-emit-llvm) carries those names verbatim, proving the scan
    would detect a leak.
  * The obfuscated IR (meta level >= 2) carries NONE of the secret names
    (they are BLAKE3-digested), yet the linked binary still runs and matches
    native output.

Exit: 0 ok | 1 contract failure | 2 missing clang.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
VSDEVCMD = tp.VSDEVCMD

SECRET_SYMS = (
    "taokari_symbol_leak_decryptor",
    "taokari_symbol_leak_validator",
    "taokari_symbol_leak_state",
)


def run(command: list[str], *, cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    if VSDEVCMD.exists():
        with tempfile.NamedTemporaryFile(
            "w", suffix=".cmd", delete=False, encoding="utf-8"
        ) as handle:
            batch = Path(handle.name)
            handle.write(
                "@echo off\n"
                f'call "{VSDEVCMD}" -arch=x64 -host_arch=x64 >nul\n'
                f"{subprocess.list2cmdline(command)}\n"
                "exit /b %ERRORLEVEL%\n"
            )
        try:
            return subprocess.run(
                ["cmd.exe", "/d", "/c", str(batch)], cwd=cwd,
                text=True, capture_output=True,
            )
        finally:
            batch.unlink(missing_ok=True)
    return subprocess.run(command, cwd=cwd, text=True, capture_output=True)


def must(result: subprocess.CompletedProcess[str], label: str) -> bool:
    if result.returncode:
        sys.stderr.write(f"{label} failed:\n")
        sys.stderr.write(result.stdout + result.stderr)
        return False
    return True


def mllvm(flags: list[str]) -> list[str]:
    out = []
    for f in flags:
        out += ["-mllvm", f]
    return out


SOURCE = r"""
#include <stdio.h>

static int @@STATE@@ = 0;

static __attribute__((noinline)) int @@DEC@@(int x) {
  @@STATE@@ ^= 0x5a5a;
  return (x * 31) ^ @@STATE@@;
}

static __attribute__((noinline)) int @@VAL@@(int x) {
  return @@DEC@@(x) + @@DEC@@(x + 1);
}

int main(void) {
  printf("symleak:%d\n", @@VAL@@(7));
  return 0;
}
""".replace("@@STATE@@", SECRET_SYMS[2]) \
   .replace("@@DEC@@", SECRET_SYMS[0]) \
   .replace("@@VAL@@", SECRET_SYMS[1])


def leak_scan(ir_text: str) -> list[str]:
    return [sym for sym in SECRET_SYMS if sym in ir_text]


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-symleak-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "symleak.c"
        src.write_text(SOURCE, encoding="utf-8")

        plain_ir = tmp / "plain.ll"
        if not must(run([str(CLANG), str(src), "-O2", "-fno-discard-value-names",
                         "-S", "-emit-llvm", "-o", str(plain_ir)]),
                    "plain emit-llvm"):
            return 1
        plain_text = plain_ir.read_text(encoding="utf-8", errors="ignore")
        if not leak_scan(plain_text):
            print("FAIL: plain IR carries no secret symbol; scan cannot "
                  "detect a regression", file=sys.stderr)
            return 1

        cfg = tmp / "meta2.json"
        cfg.write_text(json.dumps({
            "randomSeed": "taokari-symbol-leak-bar-seed",
            "meta": {"enable": True, "level": 2, "releaseStrip": True},
        }), encoding="utf-8")
        obf_ir = tmp / "obf.ll"
        if not must(run([str(CLANG), str(src), "-O2", "-fno-discard-value-names",
                         *mllvm(["-taokari", "-taokari-meta",
                                 f"-taokari-cfg={cfg}"]),
                         "-S", "-emit-llvm", "-o", str(obf_ir)]),
                    "obfuscated emit-llvm"):
            return 1
        obf_text = obf_ir.read_text(encoding="utf-8", errors="ignore")
        leaked = leak_scan(obf_text)
        if leaked:
            print(f"FAIL: secret symbols survived into obfuscated IR: {leaked}",
                  file=sys.stderr)
            return 1

        plain_exe = tmp / "plain.exe"
        if not must(run([str(CLANG), str(src), "-O2", "-o", str(plain_exe)]),
                    "plain build"):
            return 1
        plain_run = run([str(plain_exe)])
        if plain_run.returncode:
            sys.stderr.write("plain run failed\n")
            return 1

        obf_exe = tmp / "obf.exe"
        if not must(run([str(CLANG), str(src), "-O2",
                         *mllvm(["-taokari", "-taokari-meta",
                                 f"-taokari-cfg={cfg}"]),
                         "-o", str(obf_exe)]), "obfuscated build"):
            return 1
        obf_run = run([str(obf_exe)])
        if obf_run.returncode or obf_run.stdout != plain_run.stdout:
            print(f"FAIL: obfuscated runtime mismatch rc={obf_run.returncode} "
                  f"out={obf_run.stdout!r} expected={plain_run.stdout!r}",
                  file=sys.stderr)
            return 1

    print(f"symbol-leak-bar: ok (0/{len(SECRET_SYMS)} secret internal symbols "
          f"in obfuscated IR, runtime matches native)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
