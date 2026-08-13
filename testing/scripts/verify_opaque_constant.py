"""Verify the opaque-constant pass.

-taokari-ocnst rewrites plain integer constants as opaque
XOR-of-runtime-values expressions (C = (seed_a ^ K) ^ (seed_b ^ K ^ C)),
distinct from -taokari-cie (which encrypts via a global pool). The two
seeds are runtime frame addresses (numerically equal), so the XOR cancels
to the exact original value at runtime, but neither seed is statically
known, so InstCombine cannot fold it back.

Contract (same source, -emit-llvm + linked binary):
  * Build with -taokari-ocnst: the IR carries ocnst.* markers and the
    plaintext constant does NOT appear as a bare literal in the binary.
  * Build WITHOUT ocnst (just -taokari for the master switch but ocnst off):
    no ocnst.* markers (pass is opt-in).
  * Correctness: the obfuscated binary runs and matches native output.
  * Composability: ocnst + cie together still produce a correct binary.

Exit: 0 ok | 1 contract failure | 2 missing clang.
"""
from __future__ import annotations

import struct
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
CLANGXX = tp.tool("clang++")
VSDEVCMD = tp.VSDEVCMD

PLAIN_CONST = 0x12345678


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


SOURCE = f"""
#include <stdio.h>
#include <stdint.h>

__attribute__((noinline)) int32_t magic(int x) {{
  int32_t secret = {PLAIN_CONST};
  return (x ^ secret) + secret;
}}

int main(void) {{
  printf("ocnst:%d\\n", magic(7));
  return 0;
}}
"""

EH_SOURCE = r"""
#include <cstdio>
#include <string>

__attribute__((noinline)) int run(int seed) {
  std::string s = seed & 1 ? "ocnst-yes" : "ocnst-no";
  int acc = 0x12345678;
  try {
    if ((seed & 3) == 3)
      throw seed;
    acc ^= seed * 11 + 5;
  } catch (int v) {
    acc ^= v ^ (int)s.size();
  }
  acc += (int)s.size();
  return acc;
}

int main() {
  std::printf("ocnst-eh:%d:%d:%d\n", run(1), run(3), run(8));
  return 0;
}
"""


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-ocnst-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "ocnst.c"
        src.write_text(SOURCE, encoding="utf-8")

        ir = tmp / "ocnst.ll"
        if not must(run([str(CLANG), str(src), "-O2", "-fno-discard-value-names",
                         *mllvm(["-taokari", "-taokari-ocnst",
                                 "-taokari-ocnst-prob=100"]),
                         "-S", "-emit-llvm", "-o", str(ir)]), "emit-llvm"):
            return 1
        ir_text = ir.read_text(encoding="utf-8", errors="ignore")
        if "ocnst.val" not in ir_text or "ocnst.nonce" not in ir_text:
            print("FAIL: ocnst IR has no ocnst.val/ocnst.nonce markers",
                  file=sys.stderr)
            return 1

        off_ir = tmp / "off.ll"
        if not must(run([str(CLANG), str(src), "-O2", "-fno-discard-value-names",
                         "-mllvm", "-taokari",
                         "-S", "-emit-llvm", "-o", str(off_ir)]), "emit-llvm off"):
            return 1
        if "ocnst.val" in off_ir.read_text(encoding="utf-8", errors="ignore"):
            print("FAIL: ocnst leaked markers when not enabled", file=sys.stderr)
            return 1

        native = run([str(CLANG), str(src), "-O2", "-o", str(tmp / "native.exe")])
        if not must(native, "native build"):
            return 1
        native_run = run([str(tmp / "native.exe")])
        if native_run.returncode:
            sys.stderr.write("native run failed\n")
            return 1

        obf = tmp / "ocnst.exe"
        if not must(run([str(CLANG), str(src), "-O2",
                         *mllvm(["-taokari", "-taokari-ocnst",
                                 "-taokari-ocnst-prob=100"]),
                         "-o", str(obf)]), "ocnst exe build"):
            return 1
        obf_run = run([str(obf)])
        if obf_run.returncode or obf_run.stdout != native_run.stdout:
            print(f"FAIL: ocnst runtime mismatch rc={obf_run.returncode} "
                  f"out={obf_run.stdout!r} expected={native_run.stdout!r}",
                  file=sys.stderr)
            return 1

        plain_le = struct.pack("<I", PLAIN_CONST)
        plain_be = struct.pack(">I", PLAIN_CONST)
        obf_bytes = obf.read_bytes()
        if plain_le in obf_bytes or plain_be in obf_bytes:
            print("FAIL: plaintext constant survived into the ocnst binary",
                  file=sys.stderr)
            return 1

        both = tmp / "both.exe"
        if not must(run([str(CLANG), str(src), "-O2",
                         *mllvm(["-taokari", "-taokari-ocnst",
                                 "-taokari-ocnst-prob=100",
                                 "-taokari-cie", "-taokari-level-cie=3"]),
                         "-o", str(both)]), "ocnst+cie exe build"):
            return 1
        both_run = run([str(both)])
        if both_run.returncode or both_run.stdout != native_run.stdout:
            print(f"FAIL: ocnst+cie runtime mismatch rc={both_run.returncode} "
                  f"out={both_run.stdout!r}", file=sys.stderr)
            return 1

        if not CLANGXX.exists():
            print("opaque-constant: ok (C path; clang++ missing, EH skipped)")
            return 0

        eh = tmp / "ocnst_eh.cpp"
        eh.write_text(EH_SOURCE, encoding="utf-8")
        eh_native = tmp / "ocnst_eh_native.exe"
        eh_obf = tmp / "ocnst_eh_obf.exe"
        if not must(run([str(CLANGXX), str(eh), "-O2", "-std=c++17",
                         "-o", str(eh_native)]), "ocnst EH native"):
            return 1
        if not must(run([str(CLANGXX), str(eh), "-O2", "-std=c++17",
                         *mllvm(["-taokari", "-taokari-ocnst",
                                 "-taokari-ocnst-prob=100"]),
                         "-o", str(eh_obf)]), "ocnst EH protected"):
            return 1
        eh_nrun = run([str(eh_native)])
        eh_orun = run([str(eh_obf)])
        if eh_nrun.returncode or eh_orun.returncode or eh_nrun.stdout != eh_orun.stdout:
            print(f"FAIL: ocnst EH mismatch native={eh_nrun.stdout!r} "
                  f"obf={eh_orun.stdout!r} rc={eh_nrun.returncode}/{eh_orun.returncode}",
                  file=sys.stderr)
            return 1

    print(f"opaque-constant: ok (markers present, plaintext hidden in binary, "
          f"runtime matches native, ocnst+cie composable, EH matches)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
