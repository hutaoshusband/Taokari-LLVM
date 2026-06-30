"""MBA optimizer-survival verifier.

todo.md MBA L2 items:
  * Add InstCombine survival tests
  * Add Reassociate survival tests
  * Add GVN survival tests

Compiles a fixture with MBA on at level 3, emits the IR, then runs
specific LLVM cleanup passes (instcombine, reassociate, gvnn, simplifycfg)
on the protected IR via the local `opt`. Asserts that the MBA noise
markers (`mba.mix.*`, `mba.noise*`) survive each pass.

Survival here means "the optimizer did not fold the noise back to the
plaintext expression": the noise uses volatile loads from private
globals, so instcombine cannot eliminate them; reassociate may reorder
but cannot remove the volatile dependency; gvn cannot deduplicate
across distinct volatile loads.
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
OPT = tp.tool("opt")
VSDEVCMD = tp.VSDEVCMD

SOURCE = r"""
#include <cstdint>
#include <cstdio>

__attribute__((noinline)) int compute(int a, int b) {
  volatile int sink = 0;
  int x = a + b;
  int y = a * b;
  int z = (x ^ y) + (x & y) - (x | y);
  return z + sink;
}

int main(int argc, char **) {
  volatile int force = argc;
  int a = force ? 7 : 0;
  int b = force ? 11 : 0;
  std::printf("mba-surv:%d\n", compute(a, b));
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
  if not CLANG.exists() or not OPT.exists():
    print("missing clang/opt", file=sys.stderr)
    return 2

  tmp = Path(tempfile.mkdtemp(prefix="taokari-mba-surv-"))
  try:
    src = tmp / "mba_surv.cpp"
    src.write_text(SOURCE, encoding="utf-8")

    # Emit IR at -O0 with MBA forced on at level 3 and prob=100 so the
    # noise markers land in the IR before any optimizer pass sees them.
    # The survival passes are then run explicitly via opt.
    flags = [str(src), "-O0", "-fno-discard-value-names",
             "-mllvm", "-taokari", "-mllvm", "-taokari-mba",
             "-mllvm", "-taokari-mba-prob=100",
             "-mllvm", "-taokari-level-mba=3"]

    # Sanity: protected binary still runs correctly.
    exe = tmp / "obf.exe"
    must(run_vs([str(CLANG), *flags, "-o", str(exe)], src.parent),
         "build obf exe")
    base_run = run([str(exe)])
    must(base_run, "obf run")

    # Emit IR.
    obf_ll = tmp / "obf.ll"
    must(run_vs([str(CLANG), *flags, "-S", "-emit-llvm", "-o", str(obf_ll)],
                src.parent),
         "emit obf IR")
    obf_ir = obf_ll.read_text(encoding="utf-8", errors="ignore")
    gate(re.search(r"mba\.(mix|noise)", obf_ir) is not None,
         "MBA noise markers present in pre-opt IR")

    # Run targeted LLVM cleanup passes and assert the markers survive.
    # The passes are applied in isolation so we can attribute any
    # collapse to the specific pass.
    pipelines = [
        ("instcombine", "instcombine"),
        ("reassociate", "reassociate"),
        ("gvn", "gvn"),
        ("simplifycfg", "simplifycfg"),
    ]
    for label, passes in pipelines:
      out_ll = tmp / f"{label}.ll"
      # Run opt with just this pass. The opt invocation does not pull
      # in Taokari's ObfuscationPassManager (it's a plain -passes=
      # pipeline), so the protected IR is only cleaned, not re-obfuscated.
      opt_run = run([str(OPT), f"-passes={passes}", "-S",
                     str(obf_ll), "-o", str(out_ll)])
      must(opt_run, f"opt {passes}")
      out_ir = out_ll.read_text(encoding="utf-8", errors="ignore")
      gate(re.search(r"mba\.(mix|noise)", out_ir) is not None,
           f"{label}: MBA noise markers survived")

    print("MBA optimizer-survival verifier: ok")
    return 0
  finally:
    shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
  raise SystemExit(main())
