"""Verify VMP opcode maps get randomized decoy entries."""
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
SAMPLE_COUNT = 3
COMPILE_TIMEOUT_SECONDS = 45
OLD_FIXED_POPULATED_COUNT = 44

SOURCE = r"""
__attribute__((noinline))
__attribute__((annotate("vmp")))
static int secret(int a, int b) {
  return ((a + b) ^ a) + (b & 7);
}

int main(void) {
  return secret(7, 11) == 24 ? 0 : 1;
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


def populated_opmap_entries(ir_text: str) -> int:
  m = re.search(
      r'@"?__taokari_vmp_opmap_[^"\s=]+?"?\s*=\s*private unnamed_addr '
      r'constant\s*\[\d+\s*x\s*i64\]\s*\[([^\]]+)\]',
      ir_text)
  gate(m is not None, "VMP opcode map global present")
  entries = [int(v) for v in re.findall(r"i64\s+(-?\d+)", m.group(1))]
  gate(len(entries) == 64, "opcode map still uses the 64-slot dispatch table")
  return sum(1 for value in entries if value != -1)


def compile_ir(tmp: Path, index: int) -> str:
  src = tmp / f"vmp_opmap_decoys_{index}.c"
  ll = tmp / f"vmp_opmap_decoys_{index}.ll"
  src.write_text(SOURCE, encoding="utf-8")
  flags = [
      str(src), "-O2", "-fno-discard-value-names",
      "-mllvm", "-taokari", "-mllvm", "-taokari-vmp",
      "-S", "-emit-llvm", "-o", str(ll),
  ]
  must(run([str(CLANG), *flags], cwd=tmp, timeout=COMPILE_TIMEOUT_SECONDS),
       f"emit IR sample {index}")
  return ll.read_text(encoding="utf-8", errors="ignore")


def main() -> int:
  gate(CLANG.exists(), f"local clang exists at {CLANG}")

  source_text = SOURCE_PATH.read_text(encoding="utf-8", errors="ignore")
  gate("addOpcodeMapDecoys" in source_text,
       "opcode-map decoy helper is present")
  gate("1 + (RNG() % 8)" in source_text,
       "decoy count is randomized per interpreter")
  gate("Decode[Empty[I]] = Pads[RNG() % 3]" in source_text,
       "decoys route through randomized pad handlers")

  tmp = Path(tempfile.mkdtemp(prefix="taokari-vmp-opmap-decoys-"))
  try:
    counts = [
        populated_opmap_entries(compile_ir(tmp, index))
        for index in range(SAMPLE_COUNT)
    ]
  finally:
    shutil.rmtree(tmp, ignore_errors=True)

  gate(all(count > OLD_FIXED_POPULATED_COUNT for count in counts),
       f"opcode maps carry decoy entries beyond the old fixed count: {counts}")
  gate(len(set(counts)) >= 2,
       f"populated opcode-map count varies across builds: {counts}")
  print("vmp opcode-map decoy verifier: ok")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
