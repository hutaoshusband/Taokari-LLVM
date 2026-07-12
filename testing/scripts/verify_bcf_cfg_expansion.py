"""BCF CFG-explosion benchmark.

todo.md BCF L3: "Add benchmark for CFG explosion".

Builds the same fixture plain and with BCF on at level 3, emits LLVM
IR for both, and counts the basic blocks in each. Reports the
expansion ratio. This is the CFG-explosion cost metric the L3 BCF
needs: it must show that BCF materially grows the CFG without making
the binary wrong, and the ratio must stay in a sensible range (too
small and the protection is weak; too large and the binary is
unshippable).

The verifier passes when:
  * the obfuscated binary still produces the correct output,
  * the obfuscated IR has strictly more basic blocks than the plain IR,
  * the expansion ratio is between 1.5x and 30x (sanity bound).
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
VSDEVCMD = tp.VSDEVCMD

SOURCE = r"""
#include <cstdio>

__attribute__((noinline)) int compute(int a, int b) {
  int x = a + b;
  int y = a * b;
  int z = (x ^ y) + (x & y) - (x | y);
  if (z > 100)
    return z - 1;
  if (z < -100)
    return z + 1;
  return z;
}

int main() {
  volatile int sink = 0;
  int r1 = compute(7 + sink, 11);
  int r2 = compute(-7 - sink, -11);
  std::printf("bcf-cfg:%d:%d\n", r1, r2);
  return 0;
}
"""


def run(command: list[str], **kw) -> subprocess.CompletedProcess[str]:
  return subprocess.run(command, text=True, capture_output=True, **kw)


def run_vs(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
  if not tp.IS_WINDOWS:
    return subprocess.run(command, cwd=cwd, text=True, capture_output=True)
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


def count_basic_blocks(ir_text: str) -> int:
  # Count label definitions at column 0 (basic block headers). Exclude
  # the trailing attributes/ident lines.
  return len(re.findall(r"^\w[^\n]*:\s*(?:;.*)?$", ir_text, re.M))


def main() -> int:
  if not CLANG.exists():
    print("missing clang", file=sys.stderr)
    return 2

  tmp = Path(tempfile.mkdtemp(prefix="taokari-bcf-cfg-"))
  try:
    src = tmp / "bcf_cfg.cpp"
    src.write_text(SOURCE, encoding="utf-8")

    # Plain IR.
    plain_ll = tmp / "plain.ll"
    must(run_vs([str(CLANG), str(src), "-O0", "-fno-discard-value-names",
                 "-S", "-emit-llvm", "-o", str(plain_ll)], src.parent),
         "emit plain IR")
    plain_ir = plain_ll.read_text(encoding="utf-8", errors="ignore")
    plain_bb = count_basic_blocks(plain_ir)

    # Obfuscated IR with BCF at level 3.
    obf_ll = tmp / "obf.ll"
    must(run_vs([str(CLANG), str(src), "-O0", "-fno-discard-value-names",
                 "-mllvm", "-taokari",
                 "-mllvm", "-taokari-bcf",
                 "-mllvm", "-taokari-level-bcf=3",
                 "-mllvm", "-taokari-bcf-prob=100",
                 "-S", "-emit-llvm", "-o", str(obf_ll)], src.parent),
         "emit obf IR")
    obf_ir = obf_ll.read_text(encoding="utf-8", errors="ignore")
    obf_bb = count_basic_blocks(obf_ir)

    # Sanity: obfuscated binary still runs correctly.
    exe = tmp / "obf.exe"
    must(run_vs([str(CLANG), str(src), "-O0",
                 "-mllvm", "-taokari",
                 "-mllvm", "-taokari-bcf",
                 "-mllvm", "-taokari-level-bcf=3",
                 "-mllvm", "-taokari-bcf-prob=100",
                 "-o", str(exe)], src.parent),
         "build obf exe")
    ran = run([str(exe)])
    must(ran, "obf run")
    expected = "bcf-cfg:0:0\n"
    gate(ran.stdout == expected,
         f"obfuscated binary still produces correct output "
         f"(got {ran.stdout!r})")

    print(f"  [info] plain blocks: {plain_bb}, obf blocks: {obf_bb}")
    gate(obf_bb > plain_bb,
         "BCF materially expanded the CFG (more blocks than plain)")
    ratio = obf_bb / plain_bb if plain_bb else 0.0
    gate(1.5 <= ratio <= 30.0,
         f"CFG expansion ratio in sane range (got {ratio:.2f}x)")
    print(f"  [info] CFG explosion ratio: {ratio:.2f}x")

    print("BCF CFG-explosion benchmark: ok")
    return 0
  finally:
    shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
  raise SystemExit(main())
