"""Verifier for randomized VMP interpreter frame-region layout."""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CLANG = ROOT / "build" / "taokari-local" / "bin" / "clang.exe"
SOURCE_PATH = (
    ROOT / "upstream" / "taokari" / "llvm" / "lib" / "Transforms"
    / "Obfuscation" / "Virtualization" / "CodeVirtualization.cpp"
)

SOURCE = r"""
__attribute__((noinline))
__attribute__((annotate("vmp")))
static int secret(int a, int b) {
  int x = a + b;
  int y = x * 3;
  return y - a;
}

int main(void) {
  return secret(7, 11) == 47 ? 0 : 1;
}
"""

SAMPLE_COUNT = 4


def run(command: list[str], **kw) -> subprocess.CompletedProcess[str]:
  return subprocess.run(command, text=True, capture_output=True, **kw)


def must(result: subprocess.CompletedProcess[str], label: str) -> None:
  if result.returncode:
    print(result.stdout, end="")
    print(result.stderr, end="", file=sys.stderr)
    raise SystemExit(f"{label} failed: {result.returncode}")


def gate(cond: bool, label: str) -> None:
  if not cond:
    raise SystemExit(f"GATE FAILED: {label}")
  print(f"  [ok] {label}")


def interpreter_body(ir_text: str) -> str:
  m = re.search(
      r'define[^{]*?@"?(__taokari_vmp_interp_[^"\s(]+)"?\s*\([^)]*\)[^{]*\{'
      r'([\s\S]*?)\n\}',
      ir_text)
  return m.group(2) if m else ""


def frame_layout(ir_text: str) -> tuple[tuple[int, int, int, int], tuple[str, ...]]:
  body = interpreter_body(ir_text)
  gate(bool(body), "VMP interpreter body present in IR")
  matches = re.findall(
      r"%(stack|locals|frame|callargs)\d*\s*=\s*alloca \[(\d+) x i64\]",
      body)
  found = {
      name: int(size)
      for name, size in matches
  }
  missing = {"stack", "locals", "frame", "callargs"} - set(found)
  if missing:
    for line in body.splitlines():
      if "alloca" in line:
        print(f"    {line.strip()}")
  gate(not missing, f"all frame regions have explicit sizes (missing {missing})")
  sizes = (found["stack"], found["locals"], found["frame"], found["callargs"])
  order = tuple(name for name, _ in matches)
  return sizes, order


def compile_ir(tmp: Path, index: int) -> str:
  src = tmp / f"vmp_frame_sizes_{index}.c"
  ll = tmp / f"vmp_frame_sizes_{index}.ll"
  src.write_text(SOURCE, encoding="utf-8")
  flags = [
      str(src), "-O2", "-fno-discard-value-names",
      "-mllvm", "-taokari", "-mllvm", "-taokari-vmp",
      "-S", "-emit-llvm", "-o", str(ll),
  ]
  must(run([str(CLANG), *flags], cwd=tmp), f"emit IR sample {index}")
  return ll.read_text(encoding="utf-8", errors="ignore")


def main() -> int:
  gate(CLANG.exists(), f"local clang exists at {CLANG}")

  source_text = SOURCE_PATH.read_text(encoding="utf-8", errors="ignore")
  for region, size in (
      ("stack", 64), ("locals", 64), ("frame", 64), ("callargs", 8)
  ):
    fixed = (
        f'CreateAlloca(I64, ConstantInt::get(I64, {size}), "{region}")'
    )
    gate(fixed not in source_text, f"{region} alloca no longer has fixed size")

  tmp = Path(tempfile.mkdtemp(prefix="taokari-vmp-frame-sizes-"))
  try:
    samples = [frame_layout(compile_ir(tmp, i)) for i in range(SAMPLE_COUNT)]
  finally:
    shutil.rmtree(tmp, ignore_errors=True)

  size_samples = [sample[0] for sample in samples]
  order_samples = [sample[1] for sample in samples]
  gate(len(set(size_samples)) >= 2,
       f"frame-region size tuple varies across compiler runs: {size_samples}")
  gate(len(set(order_samples)) >= 2,
       f"frame-region order varies across compiler runs: {order_samples}")
  for stack, locals_, frame, callargs in size_samples:
    gate(64 <= stack <= 128, f"stack size {stack} is within 64..128")
    gate(64 <= locals_ <= 128, f"locals size {locals_} is within 64..128")
    gate(64 <= frame <= 128, f"frame size {frame} is within 64..128")
    gate(8 <= callargs <= 16, f"callargs size {callargs} is within 8..16")

  print("vmp frame layout variation verifier: ok")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
