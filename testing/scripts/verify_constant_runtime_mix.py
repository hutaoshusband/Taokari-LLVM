from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CLANG = ROOT / "build" / "taokari-local" / "bin" / "clang.exe"
VSDEVCMD = Path(r"C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat")

SOURCE = r"""
#include <stdio.h>

__attribute__((noinline)) unsigned int int_probe(unsigned int x) {
  return (x + 123456789u) + (x ^ 123456789u);
}

__attribute__((noinline)) double fp_probe(double x) {
  return x + 3.25 + 3.25;
}

int main(void) {
  printf("constmix:%u:%.2f\n", int_probe(7), fp_probe(1.0));
  return 0;
}
"""


def run(command: list[str], *, cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
  if VSDEVCMD.exists():
    with tempfile.NamedTemporaryFile("w", suffix=".cmd", delete=False, encoding="utf-8") as handle:
      batch = Path(handle.name)
      handle.write(
          "@echo off\n"
          f'call "{VSDEVCMD}" -arch=x64 -host_arch=x64 >nul\n'
          f"{subprocess.list2cmdline(command)}\n"
          "exit /b %ERRORLEVEL%\n"
      )
    try:
      return subprocess.run(["cmd.exe", "/d", "/c", str(batch)], cwd=cwd, text=True, capture_output=True)
    finally:
      batch.unlink(missing_ok=True)
  return subprocess.run(command, cwd=cwd, text=True, capture_output=True)


def main() -> int:
  if not CLANG.exists():
    print(f"missing clang: {CLANG}", file=sys.stderr)
    return 2

  with tempfile.TemporaryDirectory(prefix="taokari-constmix-") as tmp_name:
    tmp = Path(tmp_name)
    src = tmp / "constmix.c"
    src.write_text(SOURCE, encoding="utf-8")
    cfg = tmp / "constmix.json"
    cfg.write_text(
        '{"cie":{"enable":true,"level":2,"volatileSeed":true,'
        '"decryptorMba":true},'
        '"cfe":{"enable":true,"level":2,"volatileSeed":true,'
        '"decryptorMba":true}}',
        encoding="utf-8",
    )

    base = [
        str(CLANG), str(src), "-O2", "-fno-discard-value-names",
        "-mllvm", f"-taokari-cfg={cfg}",
    ]

    ir = tmp / "constmix.ll"
    compiled_ir = run([*base, "-S", "-emit-llvm", "-o", str(ir)])
    if compiled_ir.returncode:
      print(compiled_ir.stdout, end="")
      print(compiled_ir.stderr, end="", file=sys.stderr)
      return compiled_ir.returncode

    text = ir.read_text(encoding="utf-8", errors="ignore")
    required = [
        "__taokari_const_nonce",
        "taokari.const.seed.cache",
        "load volatile i64",
        "taokari.const.seed.mix",
        "taokari.const.seed.unmix",
        "taokari.const.decrypt.share",
        ".mba.add",
        "!noobf",
    ]
    missing = [needle for needle in required if needle not in text]
    if missing:
      print(f"missing constant runtime-mix IR markers: {', '.join(missing)}", file=sys.stderr)
      return 1

    exe = tmp / "constmix.exe"
    compiled_exe = run([*base, "-o", str(exe)])
    if compiled_exe.returncode:
      print(compiled_exe.stdout, end="")
      print(compiled_exe.stderr, end="", file=sys.stderr)
      return compiled_exe.returncode
    ran = run([str(exe)])
    if ran.returncode or ran.stdout != "constmix:246913582:7.50\n":
      print(f"bad run: rc={ran.returncode} stdout={ran.stdout!r}", file=sys.stderr)
      print(ran.stderr, end="", file=sys.stderr)
      return 1

  print("constant runtime mix: ok")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
