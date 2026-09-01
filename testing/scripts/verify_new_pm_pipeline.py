"""New-PM pipeline verifier (todo.md 1.5).

Taokari ships under LLVM's new pass manager: the default clang -O2 pipeline
hooks ObfuscationPassManagerPass at the OptimizerLastEP
(PassBuilderPipelines.cpp), so every normal build exercises the new-PM path.
This verifier makes that contract falsifiable.

Contract:
  * A default clang -O2 build with string encryption enabled produces an
    obfuscated binary whose output matches native AND whose obfuscation
    artifact (the encrypted-string decryptor marker) is present, proving the
    new-PM bridge fired the obfuscator.
  * A -O0 build with the same flags also fires the bridge (obfuscation is a
    last-EP hook, not gated on opt level) and still runs correctly.

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

MARKER = "EncryptedString"


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

static const char *secret = "taokari-newpm-pipeline-secret";

int main(void) {
  int h = 0;
  for (const char *p = secret; *p; ++p)
    h = h * 131 + *p;
  printf("newpm-pipe:%d\n", h);
  return 0;
}
"""


def build_run_check(tmp: Path, opt: str, cfg: Path) -> bool:
    exe = tmp / f"{opt}.exe"
    if not must(run([str(CLANG), str(tmp / "pipe.c"), opt,
                     *mllvm(["-taokari", "-taokari-cse",
                             f"-taokari-cfg={cfg}"]),
                     "-o", str(exe)]), f"{opt} obfuscated build"):
        return False
    ir = tmp / f"{opt}.ll"
    if not must(run([str(CLANG), str(tmp / "pipe.c"), opt, "-fno-discard-value-names",
                     *mllvm(["-taokari", "-taokari-cse",
                             f"-taokari-cfg={cfg}"]),
                     "-S", "-emit-llvm", "-o", str(ir)]), f"{opt} emit-llvm"):
        return False
    ir_text = ir.read_text(encoding="utf-8", errors="ignore")
    if MARKER not in ir_text:
        print(f"FAIL: {opt} default-pipeline IR has no {MARKER} marker; the "
              f"new-PM bridge did not fire the obfuscator", file=sys.stderr)
        return False
    out = run([str(exe)])
    if out.returncode:
        print(f"FAIL: {opt} obfuscated binary exited {out.returncode}",
              file=sys.stderr)
        return False
    return True


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-newpm-pipe-") as tmp_name:
        tmp = Path(tmp_name)
        (tmp / "pipe.c").write_text(SOURCE, encoding="utf-8")
        cfg = tmp / "cse3.json"
        cfg.write_text(json.dumps({"cse": {"enable": True, "level": 3}}),
                       encoding="utf-8")

        plain = tmp / "plain.exe"
        if not must(run([str(CLANG), str(tmp / "pipe.c"), "-O2", "-o", str(plain)]),
                    "plain build"):
            return 1
        plain_run = run([str(plain)])
        if plain_run.returncode:
            sys.stderr.write("plain run failed\n")
            return 1

        for opt in ("-O2", "-O0"):
            if not build_run_check(tmp, opt, cfg):
                return 1
            obf_out = run([tmp / f"{opt}.exe"]).stdout
            if obf_out != plain_run.stdout:
                print(f"FAIL: {opt} obfuscated output {obf_out!r} != native "
                      f"{plain_run.stdout!r}", file=sys.stderr)
                return 1

    print("new-pm-pipeline: ok (default clang -O2 and -O0 pipelines fire the "
          "obfuscator under new-PM, EncryptedString marker present, output "
          "matches native)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
