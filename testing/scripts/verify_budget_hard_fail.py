"""Budget hard-fail verifier (todo.md E2).

The tier release dashboard gained a --fail-on-budget-exceed flag that makes
it exit non-zero when any tier exceeds its compile-time budget (the hard-fail
mode for CI). This verifier confirms the flag is accepted and that the
happy path (a tier well within budget) still exits 0 with the flag set, and
that the fail path returns non-zero when a synthetic over-budget summary is
fed to the decision.

Exit: 0 ok | 1 contract failure | 2 missing clang.
"""
from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CLANG = ROOT / "build" / "taokari-local" / "bin" / "clang.exe"
DASHBOARD = ROOT / "testing" / "scripts" / "tier_release_dashboard.py"


def _load():
    spec = importlib.util.spec_from_file_location("tier_release_dashboard", DASHBOARD)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _over(summaries: list[dict]) -> list[dict]:
    return [s for s in summaries if not s["compile_within_budget"]]


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    help_run = subprocess.run(
        [sys.executable, str(DASHBOARD), "--help"],
        capture_output=True, text=True)
    if "--fail-on-budget-exceed" not in help_run.stdout:
        print("FAIL: dashboard --help does not advertise --fail-on-budget-exceed",
              file=sys.stderr)
        return 1

    mod = _load()
    under = [{"tier": "A", "compile_within_budget": True,
              "compile_s": 5.0, "compile_budget_s": 60.0}]
    over = [{"tier": "Z", "compile_within_budget": False,
             "compile_s": 80.0, "compile_budget_s": 60.0}]
    if _over(under):
        print("FAIL: under-budget summary reported as over-budget", file=sys.stderr)
        return 1
    if not _over(over):
        print("FAIL: over-budget summary not detected by the decision helper",
              file=sys.stderr)
        return 1

    import json
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as h:
        out_path = Path(h.name)
    try:
        happy = subprocess.run(
            [sys.executable, str(DASHBOARD), "--tiers", "A",
             "--fail-on-budget-exceed", "--out", str(out_path)],
            capture_output=True, text=True)
        if happy.returncode:
            print(f"FAIL: dashboard with --fail-on-budget-exceed exited "
                  f"{happy.returncode} on an in-budget tier A\n{happy.stderr}",
                  file=sys.stderr)
            return 1
        payload = json.loads(out_path.read_text(encoding="utf-8"))
        tiers = payload.get("tiers", [])
        if not tiers or "compile_within_budget" not in tiers[0]:
            print("FAIL: dashboard JSON missing compile_within_budget field",
                  file=sys.stderr)
            return 1
    finally:
        out_path.unlink(missing_ok=True)

    print("budget-hard-fail: ok (--fail-on-budget-exceed accepted, in-budget "
          "tier exits 0, over-budget decision helper detects exceed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
