"""Platform feature matrix verifier (todo.md A3).

Confirms docs/PLATFORM_MATRIX.md lists per-platform pass support for
Windows x64, Linux x64 and AArch64, and marks unsupported combinations
explicitly.

Exit: 0 ok | 1 contract failure.
"""
from __future__ import annotations

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
DOC = ROOT / "docs" / "PLATFORM_MATRIX.md"

REQUIRED_PLATFORMS = ("Windows x64", "Linux x64", "AArch64")
REQUIRED_SECTIONS = ("IR passes", "Backend / native passes",
                     "Unsupported combinations")
SAMPLE_PASSES = ("-taokari-fla", "-taokari-bcf", "-taokari-mba",
                 "-taokari-mir=", "-taokari-rtti")


def main() -> int:
    if not DOC.exists():
        print(f"FAIL: {DOC} missing", file=sys.stderr)
        return 1
    text = DOC.read_text(encoding="utf-8")

    missing_platforms = [p for p in REQUIRED_PLATFORMS if p not in text]
    if missing_platforms:
        print(f"FAIL: matrix missing platforms {missing_platforms}",
              file=sys.stderr)
        return 1
    missing_sections = [s for s in REQUIRED_SECTIONS if s not in text]
    if missing_sections:
        print(f"FAIL: matrix missing sections {missing_sections}",
              file=sys.stderr)
        return 1
    missing_passes = [p for p in SAMPLE_PASSES if p not in text]
    if missing_passes:
        print(f"FAIL: matrix missing pass flags {missing_passes}",
              file=sys.stderr)
        return 1
    if "❌" not in text:
        print("FAIL: matrix does not mark any combination unsupported",
              file=sys.stderr)
        return 1

    print("platform-matrix: ok (Windows x64 / Linux x64 / AArch64 listed; "
          "IR + backend sections present; sample pass flags covered; "
          "unsupported combos marked)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
