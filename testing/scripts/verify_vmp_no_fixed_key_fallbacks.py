"""Verify VMP key generation does not reintroduce fixed zero fallbacks."""
from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = (
    ROOT
    / "upstream"
    / "taokari"
    / "llvm"
    / "lib"
    / "Transforms"
    / "Obfuscation"
    / "Virtualization"
    / "CodeVirtualization.cpp"
)

FALLBACKS = {
    "PcKeyConst": "0x9E3779B97F4A7C15",
    "StackKeyConst": "0xD1B54A32D192ED03",
    "DispatchKey": "0xA0761D6478BD642F",
    "BytecodeKey": "0xD1B54A32D192ED03",
}


def main() -> int:
    text = SOURCE.read_text(encoding="utf-8", errors="ignore")
    missing = [
        name for name in FALLBACKS
        if not re.search(rf"\buint64_t\s+{name}\s*=\s*nextNonZeroKey\(\);", text)
    ]
    if missing:
        print(
            "vmp fixed-key fallback verifier: FAIL "
            f"(not drawn with nextNonZeroKey: {', '.join(missing)})",
            file=sys.stderr,
        )
        return 1

    for name, literal in FALLBACKS.items():
        if re.search(rf"if\s*\(\s*!{name}\s*\)\s*{name}\s*=\s*{literal}", text):
            print(
                "vmp fixed-key fallback verifier: FAIL "
                f"({name} still falls back to {literal})",
                file=sys.stderr,
            )
            return 1

    if not re.search(r"while\s*\(\s*!Key\s*\)\s*Key\s*=\s*RNG\(\);", text):
        print(
            "vmp fixed-key fallback verifier: FAIL "
            "(nextNonZeroKey no longer redraws zero keys)",
            file=sys.stderr,
        )
        return 1

    print("vmp fixed-key fallback verifier: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
