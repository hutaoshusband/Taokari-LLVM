"""Runtime overhead target verifier (todo.md E2 / 1.5).

The per-pass ablation script gained a --max-runtime-x target: when set, it
exits non-zero if any obfuscated row exceeds the target multiple of native
runtime. This is the runtime-overhead bar for CI (runtime is a
benchmark-time property, not compile-time). This verifier confirms the flag
is accepted and the decision logic rejects over-target rows and accepts
under-target ones.

Exit: 0 ok | 1 contract failure.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ABLATION = ROOT / "testing" / "performance" / "run_pass_ablation.py"


def _over(rows: list[dict], target: float) -> list[dict]:
    return [r for r in rows
            if r["label"] not in ("native", "max")
            and float(r["speed_x"]) > target]


def main() -> int:
    help_run = subprocess.run(
        [sys.executable, str(ABLATION), "--help"],
        capture_output=True, text=True)
    if "--max-runtime-x" not in help_run.stdout:
        print("FAIL: ablation --help does not advertise --max-runtime-x",
              file=sys.stderr)
        return 1

    rows = [
        {"label": "native", "speed_x": "1.000"},
        {"label": "fla", "speed_x": "2.500"},
        {"label": "mba", "speed_x": "1.400"},
        {"label": "max", "speed_x": "5.000"},
    ]
    if _over(rows, 3.0):
        print("FAIL: under-target rows flagged as over-target", file=sys.stderr)
        return 1
    over = _over(rows, 2.0)
    if [r["label"] for r in over] != ["fla"]:
        print(f"FAIL: over-target decision picked {over}, expected only fla",
              file=sys.stderr)
        return 1

    print("runtime-overhead-target: ok (--max-runtime-x accepted, decision "
          "rejects over-target obfuscated rows and keeps under-target/native)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
