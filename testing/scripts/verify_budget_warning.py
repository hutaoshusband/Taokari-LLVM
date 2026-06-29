"""Budget-warning verifier (todo.md E2).

The tier release dashboard computes a per-tier compile-time budget and now
emits a warning when a tier exceeds it (markdown section + stderr line).
This verifier exercises the warning logic directly on synthetic summaries
so the contract is fast and deterministic: an over-budget tier produces the
warning, an under-budget tier does not.

Exit: 0 ok | 1 contract failure.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DASHBOARD = ROOT / "testing" / "scripts" / "tier_release_dashboard.py"


def _load():
    spec = importlib.util.spec_from_file_location("tier_release_dashboard", DASHBOARD)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _summary(tier: str, compile_s: float, budget: float) -> dict:
    return {
        "tier": tier,
        "correct": True,
        "build_ok": True,
        "compile_s": compile_s,
        "compile_budget_s": budget,
        "compile_within_budget": compile_s <= budget,
        "binary_size": 1000,
        "node_ratio": 2.0,
        "edge_ratio": 2.0,
        "node_bar": 1.5,
        "edge_bar": 1.5,
        "meets_gnarliness_bar": True,
        "transformed_functions": 3,
        "passes": {"fla": {"enable": True}, "mba": {"enable": True}},
        "vmp": {"enabled": False, "virtualized": 0, "partially_virtualized": 0,
                "skipped": 0, "skipped_reasons": {}, "total_words": 0},
    }


def main() -> int:
    mod = _load()

    over = mod.render_markdown([_summary("X", 80.0, 60.0)])
    if "Budget warnings" not in over:
        print("FAIL: over-budget tier produced no 'Budget warnings' section",
              file=sys.stderr)
        return 1
    if "tier X: 80.0s > 60.0s budget" not in over:
        print("FAIL: budget warning did not name the over-budget tier/value",
              file=sys.stderr)
        return 1

    under = mod.render_markdown([_summary("Y", 10.0, 60.0)])
    if "Budget warnings" in under:
        print("FAIL: under-budget tier produced a spurious budget warning",
              file=sys.stderr)
        return 1

    mixed = mod.render_markdown([_summary("A", 5.0, 60.0), _summary("B", 80.0, 60.0)])
    if mixed.count("tier B: 80.0s > 60.0s budget") != 1:
        print("FAIL: mixed dashboard did not warn on exactly the over-budget tier",
              file=sys.stderr)
        return 1
    if "tier A:" in mixed.split("Budget warnings")[1] if "Budget warnings" in mixed else True:
        if "Budget warnings" in mixed and "tier A: 5" in mixed.split("Budget warnings")[1]:
            print("FAIL: under-budget tier A listed in the budget-warning section",
                  file=sys.stderr)
            return 1

    print("budget-warning: ok (over-budget tier -> markdown warning section + "
          "named tier/value; under-budget tier -> no warning; mixed -> only "
          "over-budget tier warned)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
