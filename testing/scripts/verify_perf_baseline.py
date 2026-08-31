"""Release-gate wrapper: quick correctness-gated perf regression check.

Runs testing/performance/run_perf_gate.py --quick.

Exit: 0 ok | 1 regression | 2 skip (tooling or baseline unavailable).
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "performance" / "run_perf_gate.py"


def main() -> int:
    r = subprocess.run([sys.executable, str(SCRIPT), "--quick"])
    if r.returncode == 2:
        print("perf_baseline: skip (perf tooling or baseline unavailable)")
    elif r.returncode == 0:
        print("perf_baseline: ok")
    return r.returncode


if __name__ == "__main__":
    raise SystemExit(main())
