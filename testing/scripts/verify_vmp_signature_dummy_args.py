"""Verifier for randomized VMP interpreter dummy arguments."""
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
  int y = a * b;
  return (x ^ y) + (x & y);
}

int main(void) {
  return secret(7, 11) == 95 ? 0 : 1;
}
"""


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


def interpreter_params(ir_text: str) -> tuple[str, ...]:
  match = re.search(
      r'define[^{]*?@"?__taokari_vmp_interp_[^"\s(]+"?\s*\(([^)]*)\)',
      ir_text)
  gate(match is not None, "VMP interpreter definition present")
  params = [p.strip() for p in match.group(1).split(",") if p.strip()]
  return tuple(params)


def compile_ir(tmp: Path, index: int) -> str:
  src = tmp / f"vmp_sig_dummy_{index}.c"
  ll = tmp / f"vmp_sig_dummy_{index}.ll"
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
  gate("InterpParam::Dummy" in source_text, "dummy parameter role exists")
  gate("ParamLayout.insert" in source_text,
       "dummy parameters are inserted into the interpreter layout")

  tmp = Path(tempfile.mkdtemp(prefix="taokari-vmp-sig-dummy-"))
  try:
    samples = [interpreter_params(compile_ir(tmp, i)) for i in range(8)]
  finally:
    shutil.rmtree(tmp, ignore_errors=True)

  counts = [len(params) for params in samples]
  gate(all(12 <= count <= 15 for count in counts),
       f"interpreter arity includes 1..4 dummy args: {counts}")
  dummy_positions: list[tuple[int, ...]] = []
  for params in samples:
    positions = tuple(
        i for i, param in enumerate(params) if "vmp.dummy" in param)
    dummy_positions.append(positions)
    gate(positions, f"dummy arg present at position(s) {positions}")
    gate(len(positions) == len(params) - 11,
         f"dummy count matches arity delta for {len(params)} args")

  gate(len(set(dummy_positions)) >= 2,
       f"dummy positions vary across compiler runs: {dummy_positions}")
  gate(any(pos and pos[-1] != len(samples[i]) - 1
           for i, pos in enumerate(dummy_positions)),
       "at least one sample inserts a dummy before the final argument")

  print("vmp interpreter dummy-argument verifier: ok")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
