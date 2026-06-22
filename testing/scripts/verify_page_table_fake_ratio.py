"""Verify page-table fake-entry counts are not a fixed half-ratio."""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CLANG = ROOT / "build" / "taokari-local" / "bin" / "clang.exe"

BRANCH_SOURCE = r"""
volatile int seed;
__attribute__((noinline)) int route(int x) {
  int r = seed;
  if (x & 1) r += 3; else r -= 5;
  if (x & 2) r += 7; else r -= 11;
  if (x & 4) r += 13; else r -= 17;
  if (x & 8) r += 19; else r -= 23;
  if (x & 16) r += 29; else r -= 31;
  if (x & 32) r += 37; else r -= 41;
  if (x & 64) r += 43; else r -= 47;
  if (x & 128) r += 53; else r -= 59;
  return r;
}
int main(void) { return route(85); }
"""

CALL_SOURCE = r"""
__attribute__((noinline)) static int f0(int x) { return x + 1; }
__attribute__((noinline)) static int f1(int x) { return x + 3; }
__attribute__((noinline)) static int f2(int x) { return x + 5; }
__attribute__((noinline)) static int f3(int x) { return x + 7; }
__attribute__((noinline)) static int f4(int x) { return x + 11; }
__attribute__((noinline)) static int f5(int x) { return x + 13; }
__attribute__((noinline)) int run(int x) {
  return f0(x) + f1(x) + f2(x) + f3(x) + f4(x) + f5(x);
}
int main(void) { return run(9); }
"""

GLOBAL_SOURCE = r"""
static int g0 = 1, g1 = 3, g2 = 5, g3 = 7, g4 = 11, g5 = 13;
__attribute__((noinline)) int read_globals(int x) {
  int r = g0 + g1;
  if (x & 1) r += g2;
  if (x & 2) r += g3;
  if (x & 4) r += g4;
  if (x & 8) r += g5;
  return r;
}
int main(void) { return read_globals(15); }
"""

ARRAY_RE = re.compile(
    r"^@(?P<name>[^\s=]+)\s*=[^\r\n]*\[(?P<count>\d+)\s+x\s+i\d+\]\s+"
    r"\[(?P<body>[^\r\n]*)\]",
    re.M,
)


def run(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
  return subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)


def must(result: subprocess.CompletedProcess[str], label: str) -> None:
  if result.returncode:
    print(result.stdout, end="")
    print(result.stderr, end="", file=sys.stderr)
    raise SystemExit(f"{label} failed: {result.returncode}")


def object_table_fake_count(ir: str, marker: str) -> tuple[int, int]:
  for match in ARRAY_RE.finditer(ir):
    name = match.group("name")
    if marker not in name or "_objects" not in name or "_objects_share" in name:
      continue
    total = int(match.group("count"))
    real = match.group("body").count("ptrtoint")
    if real:
      return real, total - real
  raise SystemExit(f"missing {marker} object table")


def compile_fake_counts(tmp: Path, name: str, source: str,
                        flags: list[str], marker: str) -> list[tuple[int, int]]:
  src = tmp / f"{name}.c"
  src.write_text(source, encoding="utf-8")
  counts: list[tuple[int, int]] = []
  for i in range(8):
    ll = tmp / f"{name}_{i}.ll"
    cmd = [
        str(CLANG), "-x", "c", str(src), "-O0", "-Xclang",
        "-disable-O0-optnone", "-S", "-emit-llvm", "-o", str(ll),
        *flags,
    ]
    must(run(cmd, tmp), f"{name} IR build {i}")
    counts.append(object_table_fake_count(
        ll.read_text(encoding="utf-8", errors="ignore"), marker))
  return counts


def verify_varies(name: str, counts: list[tuple[int, int]]) -> None:
  real_counts = {real for real, _ in counts}
  fake_counts = [fake for _, fake in counts]
  if len(real_counts) != 1:
    raise SystemExit(f"{name}: real entry count changed: {counts}")
  if any(fake <= 0 for fake in fake_counts):
    raise SystemExit(f"{name}: missing fake entries: {counts}")
  if len(set(fake_counts)) < 2:
    raise SystemExit(f"{name}: fake-entry count stayed fixed: {counts}")
  fixed_half = max(1, next(iter(real_counts)) // 2)
  if all(fake == fixed_half for fake in fake_counts):
    raise SystemExit(f"{name}: fake-entry count stayed at half-ratio: {counts}")


def main() -> int:
  if not CLANG.exists():
    print(f"missing clang: {CLANG}", file=sys.stderr)
    return 2

  tmp = Path(tempfile.mkdtemp(prefix="taokari-fake-ratio-"))
  try:
    cases = [
        ("indbr", BRANCH_SOURCE, [
            "-mllvm", "-taokari", "-mllvm", "-taokari-indbr",
            "-mllvm", "-taokari-level-indbr=2",
        ], "_IndirectBr_objects"),
        ("icall", CALL_SOURCE, [
            "-mllvm", "-taokari", "-mllvm", "-taokari-icall",
            "-mllvm", "-taokari-level-icall=2",
        ], "_IndirectCallee_objects"),
        ("indgv", GLOBAL_SOURCE, [
            "-mllvm", "-taokari", "-mllvm", "-taokari-indgv",
            "-mllvm", "-taokari-level-indgv=2",
        ], "_IndirectGVs_objects"),
    ]
    for name, source, flags, marker in cases:
      verify_varies(name, compile_fake_counts(tmp, name, source, flags, marker))
  finally:
    shutil.rmtree(tmp, ignore_errors=True)

  print("verify_page_table_fake_ratio: ok")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
