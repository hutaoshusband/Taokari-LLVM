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

SCHEDULE_LITERALS = {
    "bytecode step": "0x9E3779B97F4A7C15",
    "splitmix mul1": "0xBF58476D1CE4E5B9",
    "splitmix mul2": "0x94D049BB133111EB",
    "fnv offset": "0xCBF29CE484222325",
    "fnv prime": "0x100000001B3",
    "rotation domain": "0xD1342543DE82EF95",
    "opcode domain": "0xA5A5A5A5D3C3B2A1",
    "operand domain": "0x3C6EF372FE94F82A",
    "callee domain": "0x6A09E667F3BCC909",
    "key mul": "0xD6E8FEB86659FD93",
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

    if not re.search(r"\bCalleeTableKey\s*=\s*nextNonZeroKey\(\);", text):
        print(
            "vmp fixed-key fallback verifier: FAIL "
            "(CalleeTableKey is not drawn with nextNonZeroKey)",
            file=sys.stderr,
        )
        return 1

    for label, literal in SCHEDULE_LITERALS.items():
        if literal in text:
            print(
                "vmp fixed-key fallback verifier: FAIL "
                f"({label} still uses fixed literal {literal})",
                file=sys.stderr,
            )
            return 1

    for field in (
        "Step", "Mix1", "Mix2", "OpcodeDomain", "OperandDomain",
        "RotationDomain", "CalleeDomain", "RouteDomain", "HashOffset",
        "HashPrime", "KeyMul",
    ):
        if not re.search(rf"Schedule\.{field}\s*=\s*next", text):
            print(
                "vmp fixed-key fallback verifier: FAIL "
                f"(Schedule.{field} is not initialized from the RNG)",
                file=sys.stderr,
            )
            return 1

    print("vmp fixed-key fallback verifier: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
