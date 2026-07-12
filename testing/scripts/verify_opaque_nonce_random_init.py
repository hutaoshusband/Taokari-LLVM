"""Verify OpaquePredicate runtime nonce init is RNG-derived."""
from __future__ import annotations

import re
import sys
from pathlib import Path
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "upstream" / "taokari" / "llvm" / "lib" / "Transforms" / "Obfuscation" / "OpaquePredicate.cpp"


def main() -> int:
  text = SOURCE.read_text(encoding="utf-8", errors="ignore")
  if "0x9E3779B97F4A7C15ull" in text:
    print("opaque nonce verifier: FAIL fixed nonce initializer remains",
          file=sys.stderr)
    return 1
  checks = {
      "runtime nonce takes rng": r"getOrCreateRuntimeNonce\([^)]*std::mt19937_64 &RNG",
      "rng init": r"auto \*Init = randomInt\(IntTy, RNG\);",
      "caller passes rng": r"getOrCreateRuntimeNonce\(M, IRB, IntTy, RNG, Name\)",
  }
  missing = [name for name, pattern in checks.items()
             if not re.search(pattern, text, re.S)]
  if missing:
    print(f"opaque nonce verifier: FAIL {missing}", file=sys.stderr)
    return 1
  print("opaque nonce verifier: ok")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
