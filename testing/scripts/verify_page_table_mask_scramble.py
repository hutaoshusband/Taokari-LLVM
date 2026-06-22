"""Verify page-table masks are scrambled before choosing cipher ops."""
from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = (
    ROOT / "upstream" / "taokari" / "llvm" / "lib" / "Transforms" /
    "Obfuscation" / "Utils.cpp"
)


def main() -> int:
  text = SOURCE.read_text(encoding="utf-8", errors="ignore")
  checks = {
      "scramble helper": r"scramblePageMask\(uint8_t Mask, uint64_t ObjKey",
      "odd affine multiplier": r"\|\s*1u;",
      "encode": r"maskCipher\(scramblePageMask\(mask, ObjFullKey, k\)",
      "function decode": r"scramblePageMask\(mask, args\.FuncKey, j\)",
      "module decode": r"scramblePageMask\(mask, args\.ModuleKey, j\)",
  }
  missing = [name for name, pattern in checks.items()
             if not re.search(pattern, text)]
  if missing:
    print(f"page-table mask scramble verifier: FAIL {missing}",
          file=sys.stderr)
    return 1
  if re.search(r"maskIndex\.push_back\(mask\)", text):
    print("page-table mask scramble verifier: FAIL raw decode mask",
          file=sys.stderr)
    return 1
  if re.search(r"maskCipher\(mask,\s*preIndex", text):
    print("page-table mask scramble verifier: FAIL raw encode mask",
          file=sys.stderr)
    return 1
  print("page-table mask scramble verifier: ok")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
