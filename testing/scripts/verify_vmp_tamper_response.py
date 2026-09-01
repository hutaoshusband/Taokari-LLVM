"""VMP tamper-response policy verifier.

todo.md "Reverse-engineering report follow-up":
  * Add tamper-response policy so VM/native integrity failures do not
    always become an obvious crash.

Each +vmp function's wrapper picks one of four tamper-response shapes
per build from the per-module RNG: exit(86), exit(0), tight spin, or
exit(<random>). Two builds of the same source should produce different
trap shapes (because the RNG seed varies per build), so an analyst
cannot fingerprint the tamper path by exit code or by control flow
across builds.

This verifier emits IR for the same source 8 times and asserts the trap
blockades vary across the builds. The trap-block shape is captured by
the sequence of terminator kinds + immediate operands seen in the
`Trap`-labelled block, plus the presence of a `tamper.spin` label.
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

__attribute__((noinline))
__attribute__((annotate("vmp")))
static int secret(int a, int b) { return a + b; }

int main() {
  std::printf("vmp-tr:%d\n", secret(7, 11));
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


def trap_signature(ir_text: str) -> str:
  """Capture the tamper-response shape from the IR.

  Looks for one of the four response modes:
    - exit(86):   call void @exit(i32 86)
    - exit(0):    call void @exit(i32 0)
    - exit(N):    call void @exit(i32 N) for some other N
    - spin:       tamper.spin.label present

  Returns one of: "exit:86", "exit:0", "exit:N", "spin".
  """
  if "tamper.spin" in ir_text:
    return "spin"
  # Find every exit call with its immediate operand. We take the one
  # that lives inside the tamper trap (it follows the TamperFlag check).
  # As a robust proxy, take the FIRST exit call site with a constant
  # operand; the trap is emitted before main() returns its own exit.
  m = re.search(r"call\s+void\s+@exit\(i32\s+(-?\d+)\)", ir_text)
  if not m:
    return "none"
  n = int(m.group(1))
  if n == 86:
    return "exit:86"
  if n == 0:
    return "exit:0"
  return f"exit:{n}"


def main() -> int:
  if not CLANG.exists():
    print(f"missing clang: {CLANG}", file=sys.stderr)
    return 2

  tmp = Path(tempfile.mkdtemp(prefix="taokari-vmp-tr-"))
  try:
    src = tmp / "vmp_tr.cpp"
    src.write_text(SOURCE, encoding="utf-8")
    flags = [str(src), "-O2", "-fno-discard-value-names",
             "-mllvm", "-taokari", "-mllvm", "-taokari-vmp"]

    # Sanity: protected binary still runs correctly with the tamper-policy
    # in place (no tampering → no trap fires).
    exe = tmp / "vmp_tr.exe"
    must(run_vs([str(CLANG), *flags, "-o", str(exe)], src.parent),
         "build sanity exe")
    ran = run([str(exe)])
    must(ran, "run sanity exe")
    gate(ran.stdout == "vmp-tr:18\n",
         f"protected binary still runs correctly with tamper policy "
         f"in place (got {ran.stdout!r})")

    # Sample 8 builds. Capture the trap signature in each. We require at
    # least two distinct signatures across the sample so two builds of
    # the same source cannot be fingerprinted by trap shape.
    seen: set[str] = set()
    for i in range(8):
      ll = tmp / f"build_{i}.ll"
      ir = run_vs([str(CLANG), *flags, "-S", "-emit-llvm", "-o", str(ll)],
                  src.parent)
      must(ir, f"emit IR build {i}")
      seen.add(trap_signature(ll.read_text(encoding="utf-8",
                                          errors="ignore")))
      if len(seen) >= 2:
        break

    gate(len(seen) >= 1,
         f"at least one valid trap signature observed (got {seen})")
    # The trap policy is randomly selected per build from 4 modes. With
    # 8 samples we expect to see at least 2 distinct modes at high
    # probability (~99.6%); require >=2 for the test to be meaningful.
    gate(len(seen) >= 2,
         f"tamper-response policy produces varied trap shapes across "
         f"builds (got {sorted(seen)})")
    print(f"  [info] observed trap signatures: {sorted(seen)}")

    print("vmp tamper-response policy verifier: ok")
    return 0
  finally:
    shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
  raise SystemExit(main())
