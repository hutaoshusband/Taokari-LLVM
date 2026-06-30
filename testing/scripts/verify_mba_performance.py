"""MBA performance profile verifier.

todo.md MBA L3: "Add performance profile tests".

Measures the runtime overhead of MBA substitution by running a
compute-heavy loop plain and MBA-protected, then asserting the
obfuscated version completes within a reasonable factor of the plain
one. The bound is generous (10x) because MBA adds arithmetic; the
test catches catastrophic regressions, not micro-overhead.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
VSDEVCMD = tp.VSDEVCMD

SOURCE = r"""
#include <cstdio>
#include <cstdlib>

__attribute__((noinline)) int heavy(int n) {
  int acc = 0;
  for (int i = 0; i < n; ++i) {
    acc = acc + (i * 3);
    acc = acc ^ (i + 7);
    acc = acc & (i | 1);
  }
  return acc;
}

int main(int argc, char **argv) {
  int n = argc > 1 ? atoi(argv[1]) : 1000000;
  volatile int sink = 0;
  int r = heavy(n);
  sink = r;
  std::printf("mba-perf:%d\n", r + sink);
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


def measure(exe: Path, iterations: int = 2000000) -> float:
  times: list[float] = []
  for _ in range(3):
    start = time.perf_counter()
    r = run([str(exe), str(iterations)], timeout=30)
    elapsed = time.perf_counter() - start
    if r.returncode != 0:
      raise SystemExit(f"run failed: rc={r.returncode}")
    times.append(elapsed)
  return min(times)


def main() -> int:
  if not CLANG.exists():
    print("missing clang", file=sys.stderr)
    return 2

  tmp = Path(tempfile.mkdtemp(prefix="taokari-mba-perf-"))
  try:
    src = tmp / "mba_perf.cpp"
    src.write_text(SOURCE, encoding="utf-8")

    plain_exe = tmp / "plain.exe"
    must(run_vs([str(CLANG), str(src), "-O2", "-o", str(plain_exe)],
                src.parent),
         "build plain")

    obf_exe = tmp / "obf.exe"
    must(run_vs([str(CLANG), str(src), "-O2",
                 "-mllvm", "-taokari",
                 "-mllvm", "-taokari-mba",
                 "-mllvm", "-taokari-level-mba=3",
                 "-mllvm", "-taokari-mba-prob=100",
                 "-o", str(obf_exe)], src.parent),
         "build obf")

    plain_time = measure(plain_exe)
    obf_time = measure(obf_exe)
    ratio = obf_time / plain_time if plain_time else 0.0

    print(f"  [info] plain: {plain_time:.4f}s, obf: {obf_time:.4f}s, "
          f"ratio: {ratio:.2f}x")
    gate(ratio <= 10.0,
         f"MBA overhead within 10x bound (got {ratio:.2f}x)")

    print("MBA performance profile verifier: ok")
    return 0
  finally:
    shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
  raise SystemExit(main())
