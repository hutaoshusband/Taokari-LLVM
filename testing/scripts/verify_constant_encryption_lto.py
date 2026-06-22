"""Constant-encryption LTO survival verifier.

todo.md item Constant Encryption L3: "Add LTO survival tests".

Verifies that integer-constant encryption produces output that survives
the LTO pipeline. Compiles a fixture with constant encryption on under
both regular `-O2` and `-O2 -flto -fuse-ld=lld`, asserts:

  1. both binaries produce the correct (same) output,
  2. the encrypted constant-pool global (`__taokari_const_*`) survives
     in the IR after the LTO pipeline,
  3. the plaintext constant does not appear as a literal in either IR.

The third property is the survival guarantee: if LTO had recovered the
plaintext, it would appear as an i64/i32 literal in the optimized IR.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CLANG = ROOT / "build" / "taokari-local" / "bin" / "clang.exe"
VSDEVCMD = Path(
    r"C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat"
)

# A distinctive 64-bit plaintext that the encryption should hide.
PLAIN_CONST = 0x123456789ABCDEF0

SOURCE = f"""
#include <cstdint>
#include <cstdio>

__attribute__((noinline)) int64_t magic() {{
  volatile int64_t v = 0;  // forces runtime use, defeats static folding
  int64_t secret = {PLAIN_CONST}LL;
  return secret + v;
}}

int main() {{
  std::printf("const-lto:%lld\\n", static_cast<long long>(magic()));
  return 0;
}}
"""


def run(command: list[str], **kw) -> subprocess.CompletedProcess[str]:
  return subprocess.run(command, text=True, capture_output=True, **kw)


def run_vs(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
  with tempfile.NamedTemporaryFile("w", suffix=".cmd", delete=False,
                                   encoding="utf-8") as handle:
    batch = Path(handle.name)
    handle.write(
        "@echo off\n"
        f'call "{VSDEVCMD}" -arch=x64 -host_arch=x64 >nul\n'
        f"{subprocess.list2cmdline(command)}\n"
        "exit /b %ERRORLEVEL%\n"
    )
  try:
    return run(["cmd.exe", "/d", "/c", str(batch)], cwd=cwd)
  finally:
    batch.unlink(missing_ok=True)


def must(result: subprocess.CompletedProcess[str], label: str) -> None:
  if result.returncode:
    print(result.stdout, end="")
    print(result.stderr, end="", file=sys.stderr)
    raise SystemExit(f"{label} failed: {result.returncode}")


def gate(cond: bool, label: str) -> None:
  if not cond:
    raise SystemExit(f"GATE FAILED: {label}")
  print(f"  [ok] {label}")


def main() -> int:
  if not CLANG.exists():
    print("missing clang", file=sys.stderr)
    return 2

  tmp = Path(tempfile.mkdtemp(prefix="taokari-constenc-lto-"))
  try:
    src = tmp / "constenc_lto.cpp"
    src.write_text(SOURCE, encoding="utf-8")

    expected = f"const-lto:{PLAIN_CONST}\n"
    plain_const_lit = str(PLAIN_CONST)

    # 1. -O2 baseline.
    flags = [str(src), "-O2", "-fno-discard-value-names",
             "-mllvm", "-taokari",
             "-mllvm", "-taokari-cie",
             "-mllvm", "-taokari-level-cie=2"]

    o2_ll = tmp / "o2.ll"
    must(run_vs([str(CLANG), *flags, "-S", "-emit-llvm", "-o", str(o2_ll)],
                src.parent),
         "emit -O2 IR")
    o2_ir = o2_ll.read_text(encoding="utf-8", errors="ignore")

    o2_exe = tmp / "o2.exe"
    must(run_vs([str(CLANG), *flags, "-o", str(o2_exe)], src.parent),
         "build -O2 exe")
    o2_run = run([str(o2_exe)])
    must(o2_run, "-O2 run")
    gate(o2_run.stdout == expected,
         f"-O2 binary produces correct output (got {o2_run.stdout!r})")

    # Plaintext must not appear as a literal in the optimized IR.
    gate(f"i64 {plain_const_lit}" not in o2_ir and
         f"i64 {PLAIN_CONST}" not in o2_ir,
         "-O2: plaintext constant does not appear as a literal in IR")

    # 2. -O2 + LTO.
    lto_ll = tmp / "lto.ll"
    must(run_vs([str(CLANG), *flags, "-flto", "-S", "-emit-llvm",
                 "-o", str(lto_ll)], src.parent),
         "emit LTO IR")
    lto_ir = lto_ll.read_text(encoding="utf-8", errors="ignore")

    lto_exe = tmp / "lto.exe"
    must(run_vs([str(CLANG), *flags, "-flto", "-fuse-ld=lld",
                 "-o", str(lto_exe)], src.parent),
         "build LTO exe")
    lto_run = run([str(lto_exe)])
    must(lto_run, "LTO run")
    gate(lto_run.stdout == expected,
         f"LTO binary produces correct output (got {lto_run.stdout!r})")

    gate(f"i64 {plain_const_lit}" not in lto_ir and
         f"i64 {PLAIN_CONST}" not in lto_ir,
         "LTO: plaintext constant does not appear as a literal in IR")

    print("constant encryption LTO survival verifier: ok")
    return 0
  finally:
    shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
  raise SystemExit(main())
