"""Verifier for randomized VMP interpreter signature layout."""
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


def interpreter_params(ir_text: str) -> tuple[str, ...]:
  match = re.search(
      r'define[^{]*?@"?__taokari_vmp_interp_[^"\s(]+"?\s*\(([^)]*)\)',
      ir_text)
  gate(match is not None, "VMP interpreter definition present")
  params = [p.strip() for p in match.group(1).split(",") if p.strip()]
  return tuple(params)


def param_name(param: str) -> str:
  match = re.search(r"%([A-Za-z0-9_.]+)$", param)
  return match.group(1) if match else ""


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
  gate("InterpParam::BCTail" in source_text and "InterpParam::BCSplit" in source_text,
       "bytecode pointer is split in the interpreter ABI")
  gate("std::swap(ParamLayout" in source_text,
       "real interpreter parameters are shuffled")
  gate("ParamLayout.insert" in source_text,
       "dummy parameters are inserted into the interpreter layout")

  tmp = Path(tempfile.mkdtemp(prefix="taokari-vmp-sig-dummy-"))
  try:
    samples = [interpreter_params(compile_ir(tmp, i))
               for i in range(SAMPLE_COUNT)]
  finally:
    shutil.rmtree(tmp, ignore_errors=True)

  counts = [len(params) for params in samples]
  gate(all(14 <= count <= 17 for count in counts),
       f"interpreter arity includes 1..4 dummy args: {counts}")
  dummy_positions: list[tuple[int, ...]] = []
  real_orders: list[tuple[str, ...]] = []
  old_order = (
      "bc.a", "bc.b", "bc.split", "bclen", "pc.map", "ptr.table",
      "ptr.count", "args", "arg.len", "tamper", "bytecode.tag",
      "opcode.map", "bytecode.key")
  for params in samples:
    names = tuple(param_name(param) for param in params)
    positions = tuple(
        i for i, name in enumerate(names) if name.startswith("vmp.dummy"))
    dummy_positions.append(positions)
    real_order = tuple(name for name in names if not name.startswith("vmp.dummy"))
    real_orders.append(real_order)
    gate("bc" not in names, "old single bytecode pointer name is absent")
    for split_name in ("bc.a", "bc.b", "bc.split"):
      gate(split_name in names, f"{split_name} is present in interpreter ABI")
    gate(positions, f"dummy arg present at position(s) {positions}")
    gate(len(positions) == len(params) - 13,
         f"dummy count matches arity delta for {len(params)} args")
    gate(real_order != old_order,
         f"real interpreter parameter order differs from old ABI: {real_order}")

  gate(len(set(dummy_positions)) >= 2,
       f"dummy positions vary across compiler runs: {dummy_positions}")
  gate(len(set(real_orders)) >= 2,
       f"real parameter order varies across compiler runs: {real_orders}")
  gate(any(pos and pos[-1] != len(samples[i]) - 1
           for i, pos in enumerate(dummy_positions)),
       "at least one sample inserts a dummy before the final argument")

  print("vmp interpreter signature-layout verifier: ok")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
