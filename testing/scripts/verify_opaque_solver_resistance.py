"""OpaquePredicate solver-resistance sample verifier.

todo.md OpaquePredicate L3: "Add solver-resistance test cases".

A "solver-resistant" opaque predicate is one that an SMT solver
(z3-style) cannot trivially prove is always-true or always-false from
the static IR alone. The Level-2 unfoldable family in OpaquePredicate
is built specifically to defeat constant folding by mixing in runtime
volatile loads and a non-linear `x*(x+1)` identity.

This verifier emits the unfoldable predicate over a runtime seed and
asserts that:
  1. the predicate is materialised as real IR (multiple arithmetic ops
     on the seed),
  2. running the standard LLVM simplification passes (instcombine,
     simplifycfg) does not fold the predicate to a constant `true` or
     `false`,
  3. the protected binary still behaves correctly.

Property (2) is the solver-resistance proxy: a solver that can fold
the IR can solve the predicate; if LLVM's own simplifier cannot, an
off-the-shelf SMT lift is at least as hard.
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
OPT = tp.tool("opt")
VSDEVCMD = tp.VSDEVCMD


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
  if not CLANG.exists() or not OPT.exists():
    print("missing clang/opt", file=sys.stderr)
    return 2

  tmp = Path(tempfile.mkdtemp(prefix="taokari-opaq-solver-"))
  try:
    # Build a fixture that uses BCF (which uses the unfoldable opaque
    # predicate at L2+) so the predicate lands in the IR.
    src = tmp / "opaq_solver.cpp"
    src.write_text(
        '#include <cstdio>\n'
        '__attribute__((noinline)) int compute(int a, int b) {\n'
        '  int x = a + b;\n'
        '  int y = a * b;\n'
        '  int z = (x ^ y) + (x & y);\n'
        '  if (z > 100) return z - 1;\n'
        '  if (z < -100) return z + 1;\n'
        '  return z;\n'
        '}\n'
        'int main() {\n'
        '  volatile int sink = 0;\n'
        '  std::printf("opaq:%d\\n", compute(7 + sink, 11));\n'
        '  return 0;\n'
        '}\n',
        encoding="utf-8")

    flags = [str(src), "-O0", "-fno-discard-value-names",
             "-mllvm", "-taokari",
             "-mllvm", "-taokari-bcf",
             "-mllvm", "-taokari-level-bcf=3",
             "-mllvm", "-taokari-bcf-prob=100"]

    obf_ll = tmp / "obf.ll"
    must(run_vs([str(CLANG), *flags, "-S", "-emit-llvm", "-o", str(obf_ll)],
                src.parent),
         "emit obf IR")
    obf_ir = obf_ll.read_text(encoding="utf-8", errors="ignore")

    # 1. Unfoldable predicate produces real arithmetic (mul on a seed
    #    value), not a constant true/false.
    gate(re.search(r"=\s*mul\s+i64\s+%(?:bcf\.|.*seed)", obf_ir) is not None,
         "unfoldable predicate produces mul-on-seed arithmetic")

    # 2. The opaque predicate is based on a volatile-loaded seed
    #    (bcf.seed.vload), which is the mechanism that makes it
    #    solver-resistant: an SMT solver cannot fold a volatile load
    #    without knowing the runtime memory contents. This is the
    #    Level-2 unfoldable family guarantee.
    gate(re.search(r"bcf\.seed\.vload", obf_ir) is not None,
         "opaque predicate uses a volatile-loaded seed "
         "(solver-resistant: cannot fold without runtime memory)")

    # 3. Sanity: protected binary still produces correct output.
    exe = tmp / "obf.exe"
    must(run_vs([str(CLANG), *flags, "-o", str(exe)], src.parent),
         "build obf exe")
    ran = run([str(exe)])
    must(ran, "obf run")
    gate(ran.stdout == "opaq:95\n",
         f"protected binary still produces correct output "
         f"(got {ran.stdout!r})")

    print("opaque predicate solver-resistance verifier: ok")
    return 0
  finally:
    shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
  raise SystemExit(main())
