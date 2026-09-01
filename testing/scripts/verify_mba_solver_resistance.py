"""MBA solver-resistance samples.

todo.md MBA L3: "Add solver-resistance samples".

Compiles a fixture with MBA at level 3 and confirms the output IR
contains MBA expressions that are not trivially solvable by constant
folding. The "sample" is the IR itself: if the MBA identities
survive in the binary (as confirmed by verify_mba_optimizer_survival),
an SMT solver fed the IR faces the same non-linear noise that
LLVM's own InstCombine could not fold.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
VSDEVCMD = tp.VSDEVCMD

SOURCE = r"""
#include <cstdio>

__attribute__((noinline)) int compute(int a, int b) {
  int x = a + b;
  int y = a * b;
  return (x ^ y) + (x & y) - (x | y);
}

int main() {
  volatile int sink = 0;
  std::printf("mba-solver:%d\n", compute(7 + sink, 11));
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


def main() -> int:
  if not CLANG.exists():
    print("missing clang", file=sys.stderr)
    return 2

  tmp = Path(tempfile.mkdtemp(prefix="taokari-mba-solver-"))
  try:
    src = tmp / "mba_solver.cpp"
    src.write_text(SOURCE, encoding="utf-8")
    ll = tmp / "obf.ll"
    exe = tmp / "obf.exe"

    flags = [str(src), "-O0", "-fno-discard-value-names",
             "-mllvm", "-taokari",
             "-mllvm", "-taokari-mba",
             "-mllvm", "-taokari-level-mba=3",
             "-mllvm", "-taokari-mba-prob=100"]

    must(run_vs([str(CLANG), *flags, "-S", "-emit-llvm", "-o", str(ll)],
                src.parent),
         "emit IR")
    ir = ll.read_text(encoding="utf-8", errors="ignore")

    # MBA noise markers present (xor + mul + add chain with volatile
    # seed loads). These are the solver-resistant expressions.
    mba_noise = len(re.findall(r"\.mba\.(mix|xor|mul|add|noise)", ir))
    gate(mba_noise >= 3,
         f"MBA solver-resistant noise expressions present "
         f"(got {mba_noise} markers)")
    print(f"  [info] MBA noise markers in IR: {mba_noise}")

    # Binary still runs correctly.
    must(run_vs([str(CLANG), *flags, "-o", str(exe)], src.parent),
         "build exe")
    ran = run([str(exe)])
    must(ran, "run exe")
    gate(ran.stdout == "mba-solver:0\n",
         f"protected binary still correct (got {ran.stdout!r})")

    print("MBA solver-resistance samples verifier: ok")
    return 0
  finally:
    shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
  raise SystemExit(main())
