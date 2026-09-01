"""Verify the Level-3 AArch64 MIR parity plan stays concrete."""
from __future__ import annotations

from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
PLAN = ROOT / "docs" / "MACHINE_IR_AARCH64_PARITY.md"

REQUIRED = [
    "-mllvm -taokari-mir=<passes>",
    "+mir:<subpass>",
    "marker",
    "dirtybytes",
    "junk",
    "sub",
    "unmodelled",
    "AArch64 `addPreEmitPass()`",
    "-target aarch64-pc-windows-msvc",
    "-mllvm -verify-machineinstrs",
    "No x86 registers",
    "preserve NZCV",
    "No AArch64 object contains x86 MIR byte signatures",
    "Do not claim IDA/D810 parity until an AArch64 IDA snapshot exists",
]


def main() -> int:
    text = PLAN.read_text(encoding="utf-8")
    missing = [needle for needle in REQUIRED if needle not in text]
    if missing:
        raise SystemExit("missing AArch64 plan requirements: " + ", ".join(missing))
    print("verify_machine_obf_l3_aarch64_plan: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
