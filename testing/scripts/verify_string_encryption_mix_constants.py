"""Verify StringEncryption key-mix constants are build-derived."""
from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "upstream" / "taokari" / "llvm" / "lib" / "Transforms" / "Obfuscation" / "StringEncryption.cpp"


def main() -> int:
  text = SOURCE.read_text(encoding="utf-8", errors="ignore")
  fixed = ("0x5du", "0x3bu", "0x11u", "0x45d9u", "0x9e37u",
           "0x0101u", "0x9e3779b9u")
  hits = [value for value in fixed if value in text]
  if hits:
    print(f"string mix verifier: FAIL fixed constants remain {hits}",
          file=sys.stderr)
    return 1
  checks = {
      "derive helper": r"deriveStringMix\(uint32_t BuildNonce, unsigned Shift",
      "encrypt i8": r"deriveStringMix\(BuildNonce, 8, 0xffu\)",
      "encrypt i16": r"deriveStringMix\(BuildNonce, 16, 0xffffu\)",
      "decrypt mix lambda": r"auto BuildMix = \[&\]\(unsigned ShiftBits\)",
      "decrypt string mix": r"IRB\.CreateMul\(IRB\.CreateAdd\(StringIDArg",
      "decrypt position mix": r"BuildMix\(PositionMixShift\)",
      "decrypt key-index mix": r"BuildMix\(KeyIndexMixShift\)",
  }
  missing = [name for name, pattern in checks.items()
             if not re.search(pattern, text, re.S)]
  if missing:
    print(f"string mix verifier: FAIL {missing}", file=sys.stderr)
    return 1
  print("string mix verifier: ok")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
