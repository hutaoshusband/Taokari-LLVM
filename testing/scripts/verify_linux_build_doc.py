"""Linux build documentation verifier (todo.md A1).

Confirms docs/BUILD_LINUX.md exists and documents every section a developer
needs to build Taokari on Linux, and that the referenced build script
exists and is syntactically valid bash.

Exit: 0 ok | 1 contract failure.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DOC = ROOT / "docs" / "BUILD_LINUX.md"
SCRIPT = ROOT / "scripts" / "build-linux.sh"

REQUIRED_SECTIONS = (
    "## Prerequisites",
    "## Configure",
    "## Build",
    "## Verify",
    "## Scope",
)
REQUIRED_FLAGS = (
    "-DLLVM_ENABLE_PROJECTS",
    "-DLLVM_TARGETS_TO_BUILD",
    "-DCMAKE_BUILD_TYPE=Release",
)


def main() -> int:
    if not DOC.exists():
        print(f"FAIL: {DOC} missing", file=sys.stderr)
        return 1
    text = DOC.read_text(encoding="utf-8")
    missing = [s for s in REQUIRED_SECTIONS if s not in text]
    if missing:
        print(f"FAIL: {DOC} missing sections {missing}", file=sys.stderr)
        return 1
    missing_flags = [f for f in REQUIRED_FLAGS if f not in text]
    if missing_flags:
        print(f"FAIL: {DOC} missing cmake flags {missing_flags}", file=sys.stderr)
        return 1
    if "libxml2" not in text.lower():
        print("FAIL: doc does not mention libxml2", file=sys.stderr)
        return 1
    if "build-linux.sh" not in text:
        print("FAIL: doc does not reference scripts/build-linux.sh", file=sys.stderr)
        return 1

    if not SCRIPT.exists():
        print(f"FAIL: {SCRIPT} missing", file=sys.stderr)
        return 1
    check = subprocess.run(["bash", "-n", "scripts/build-linux.sh"], cwd=ROOT)
    if check.returncode:
        print(f"FAIL: {SCRIPT} is not valid bash", file=sys.stderr)
        return 1
    if "cmake --build" not in SCRIPT.read_text(encoding="utf-8"):
        print(f"FAIL: {SCRIPT} does not build", file=sys.stderr)
        return 1

    print("linux-build-doc: ok (BUILD_LINUX.md covers prerequisites/configure/"
          "build/verify/scope with cmake flags; build-linux.sh is valid bash)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
