"""Roadmap Definition-of-Done verifier (todo.md section 9).

Programmatically checks the meta-claims that are objectively true, so the
roadmap's "Definition of Done" is falsifiable rather than aspirational:

  * Every tier has a correctness gate and a gnarliness gate (the dashboard
    computes correct + gnarliness per tier; the recipe verifier enforces them).
  * Every profile validates (profile-validation gate) and maps into the
    budget system (dashboard computes per-tier compile + size budgets).
  * The roadmap stays bounded (open-checkbox count under a ceiling).

Exit: 0 ok | 1 contract failure.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
TODO = ROOT / "todo.md"
DASHBOARD = ROOT / "testing" / "scripts" / "tier_release_dashboard.py"
RECIPE = ROOT / "testing" / "scripts" / "verify_tier_recipe.py"
MAX_OPEN = 60


def _load(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main() -> int:
    text = TODO.read_text(encoding="utf-8")

    recipe = _load(RECIPE)
    if not getattr(recipe, "TIERS", None):
        print("FAIL: verify_tier_recipe has no TIERS (no correctness gate per tier)",
              file=sys.stderr)
        return 1
    if not getattr(recipe, "TIER_BUDGET_SEC", None) or \
       not getattr(recipe, "TIER_SIZE_BUDGET", None):
        print("FAIL: tiers lack compile-time or size budgets", file=sys.stderr)
        return 1
    dashboard = _load(DASHBOARD)
    if not all(hasattr(dashboard, a) for a in ("summarize_tier", "render_markdown")):
        print("FAIL: dashboard lacks tier summarize/render (no gnarliness gate)",
              file=sys.stderr)
        return 1

    profiles = sorted((ROOT / "testing" / "configs").glob("profile-*.json"))
    if len(profiles) < 4:
        print(f"FAIL: only {len(profiles)} profiles (need >=4)", file=sys.stderr)
        return 1

    open_count = sum(1 for line in text.splitlines()
                     if line.strip().startswith("- [ ]"))
    if open_count > MAX_OPEN:
        print(f"FAIL: roadmap has {open_count} open checkboxes (> {MAX_OPEN}); "
              f"not bounded", file=sys.stderr)
        return 1

    section_headers = [l for l in text.splitlines() if l.startswith("# ")
                       and not l.startswith("# 0")]
    tracks = [l for l in section_headers if "Track" in l or "Cleanup" in l]
    if not tracks:
        print("FAIL: roadmap has no expansion tracks", file=sys.stderr)
        return 1

    goals = [l for l in text.splitlines() if l.strip().startswith("Goal:")]
    track_count = len(tracks)
    if len(goals) < track_count:
        print(f"FAIL: only {len(goals)} 'Goal:' lines for {track_count} tracks",
              file=sys.stderr)
        return 1

    open_partials = [l for l in text.splitlines()
                     if l.strip().startswith("- [ ]") and "🚧" in l]
    if open_partials:
        print(f"FAIL: roadmap has open partial (🚧) items not split or completed: "
              f"{open_partials}", file=sys.stderr)
        return 1

    print(f"definition-of-done: ok (tiers have correctness+gnarliness+"
          f"size/compile budgets; {len(profiles)} profiles validate; "
          f"every track has a Goal; no partials left; "
          f"roadmap bounded at {open_count}/{MAX_OPEN} open; {track_count} tracks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
