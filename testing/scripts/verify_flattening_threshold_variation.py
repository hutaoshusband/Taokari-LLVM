"""Verify flattening default thresholds are varied per build."""
from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "upstream" / "taokari" / "llvm" / "lib" / "Transforms" / "Obfuscation" / "Flattening.cpp"


def main() -> int:
  text = SOURCE.read_text(encoding="utf-8", errors="ignore")
  checks = {
      "variation helper": r"varyDefaultLimit\(std::mt19937_64 &RNG, uint32_t Base\)",
      "minus 25 percent": r"Base\s*-\s*Base\s*/\s*4",
      "plus 25 percent": r"Base\s*\+\s*Base\s*/\s*4",
      "insts member": r"BuildMaxInsts\s*=\s*varyDefaultLimit\(RNG, DefaultMaxInsts\)",
      "blocks member": r"BuildMaxBlocks\s*=\s*varyDefaultLimit\(RNG, DefaultMaxBlocks\)",
      "allocas member": r"BuildMaxAllocas\s*=\s*varyDefaultLimit\(RNG, DefaultMaxAllocas\)",
  }
  missing = [name for name, pattern in checks.items()
             if not re.search(pattern, text)]
  if missing:
    print(f"flattening threshold verifier: FAIL {missing}", file=sys.stderr)
    return 1
  fixed_fallbacks = (
      r"flaOpt->maxInsts\(\)\s*\?\s*flaOpt->maxInsts\(\)\s*:\s*DefaultMaxInsts",
      r"flaOpt->maxBlocks\(\)\s*\?\s*flaOpt->maxBlocks\(\)\s*:\s*DefaultMaxBlocks",
      r"flaOpt->maxAllocas\(\)\s*\?\s*flaOpt->maxAllocas\(\)\s*:\s*DefaultMaxAllocas",
  )
  if any(re.search(pattern, text) for pattern in fixed_fallbacks):
    print("flattening threshold verifier: FAIL fixed default fallback",
          file=sys.stderr)
    return 1
  print("flattening threshold verifier: ok")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
