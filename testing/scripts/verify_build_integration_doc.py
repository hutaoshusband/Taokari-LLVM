"""Build integration doc verifier (todo.md E4).

Confirms docs/BUILD_INTEGRATION.md covers CMake, Ninja, Visual Studio, the
blanket .bat recipes, and +vmp/-vmp annotation examples.

Exit: 0 ok | 1 contract failure.
"""
from __future__ import annotations

import sys
from pathlib import Path
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
DOC = ROOT / "docs" / "BUILD_INTEGRATION.md"

REQUIRED_SECTIONS = ("## CMake", "## Ninja", "## Visual Studio",
                     "blanket recipes", "annotation examples")
REQUIRED_TOKENS = ("build_strong.bat", "build_max_protection.bat",
                   "annotate(\"+vmp\")", "annotate(\"-vmp\")",
                   "-mllvm -taokari-cfg")


def main() -> int:
    if not DOC.exists():
        print(f"FAIL: {DOC} missing", file=sys.stderr)
        return 1
    text = DOC.read_text(encoding="utf-8")
    missing_sections = [s for s in REQUIRED_SECTIONS if s.lower() not in text.lower()]
    if missing_sections:
        print(f"FAIL: doc missing sections {missing_sections}", file=sys.stderr)
        return 1
    missing_tokens = [t for t in REQUIRED_TOKENS if t not in text]
    if missing_tokens:
        print(f"FAIL: doc missing tokens {missing_tokens}", file=sys.stderr)
        return 1

    print("build-integration-doc: ok (CMake/Ninja/VS sections present; "
          "build_*.bat recipes documented; +vmp/-vmp annotation examples "
          "and -taokari-cfg covered)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
