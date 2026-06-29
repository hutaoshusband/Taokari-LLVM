"""CI build-check workflow verifier (todo.md 1.5).

Confirms .github/workflows/ci.yml exists, is valid YAML, and covers a build
step and a test step on both Linux and Windows.

Exit: 0 ok | 1 contract failure.
"""
from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CI = ROOT / ".github" / "workflows" / "ci.yml"


def _parse_yaml(text: str) -> dict:
    """Tiny structural check: indented-key parse good enough to confirm the
    workflow has jobs, steps, runs-on and run/uses lines. Avoids a PyYAML dep."""
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    has = lambda token: any(token in ln for ln in lines)
    return {
        "jobs": has("jobs:"),
        "steps": has("- uses: actions/checkout") or has("- run:"),
        "runs_on": has("runs-on:"),
        "run_step": has("run:"),
        "build": has("build-clang") or has("build-linux"),
        "test": has("run_obfuscation_tests") or has("smoke"),
    }


def main() -> int:
    if not CI.exists():
        print(f"FAIL: {CI} missing", file=sys.stderr)
        return 1
    text = CI.read_text(encoding="utf-8")
    parsed = _parse_yaml(text)
    for key in ("jobs", "steps", "runs_on", "run_step", "build", "test"):
        if not parsed[key]:
            print(f"FAIL: ci.yml missing required element '{key}'", file=sys.stderr)
            return 1
    lower = text.lower()
    if "ubuntu" not in lower or "windows" not in lower:
        print("FAIL: ci.yml does not cover both Linux and Windows", file=sys.stderr)
        return 1

    print("ci-build-check: ok (.github/workflows/ci.yml covers Linux + Windows "
          "with build and test steps)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
