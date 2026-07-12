"""Verify the per-tier release dashboard.

Runs tier_release_dashboard.py across all four tiers, asserts the JSON and
markdown outputs are structurally complete and semantically correct:
  * every tier is present with the D3-required fields (correctness, compile
    cost vs budget, binary size, node/edge ratios vs the bar, transformed
    count, enabled passes).
  * every tier passes its correctness gate and its gnarliness bar.
  * tiers C/D report VMP on with >= 1 virtualized function.
  * the markdown carries the per-tier summary, VM compatibility, enabled
    passes, and highlights sections.

Exit: 0 ok | 1 contract failure | 2 missing dashboard / clang.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
DASHBOARD = ROOT / "testing" / "scripts" / "tier_release_dashboard.py"
CLANG = tp.CLANG


REQUIRED_FIELDS = (
    "tier", "correct", "compile_s", "compile_budget_s", "compile_within_budget",
    "build_ok", "binary_size", "node_bar", "edge_bar", "node_ratio",
    "edge_ratio", "meets_gnarliness_bar", "transformed_functions", "passes",
    "vmp",
)


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, text=True, capture_output=True, **kw)


def main() -> int:
    if not DASHBOARD.exists():
        print(f"missing dashboard: {DASHBOARD}", file=sys.stderr)
        return 2
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-dash-verify-") as tmp_name:
        tmp = Path(tmp_name)
        out_json = tmp / "dash.json"
        out_md = tmp / "dash.md"
        r = run([sys.executable, str(DASHBOARD),
                 "--tiers", "A", "B", "C", "D",
                 "--out", str(out_json), "--out-md", str(out_md)],
                cwd=ROOT, timeout=600)
        if r.returncode:
            sys.stderr.write("dashboard run failed:\n")
            sys.stderr.write(r.stdout + r.stderr)
            return 1
        if not out_json.exists() or not out_md.exists():
            print("FAIL: dashboard did not write JSON/MD outputs",
                  file=sys.stderr)
            return 1

        payload = json.loads(out_json.read_text(encoding="utf-8"))
        summaries = payload.get("tiers", [])
        if [s["tier"] for s in summaries] != ["A", "B", "C", "D"]:
            print(f"FAIL: expected tiers A,B,C,D, got "
                  f"{[s['tier'] for s in summaries]}", file=sys.stderr)
            return 1

        for s in summaries:
            for f in REQUIRED_FIELDS:
                if f not in s:
                    print(f"FAIL: tier {s['tier']} missing field {f}",
                          file=sys.stderr)
                    return 1
            if not s["build_ok"] or not s["correct"]:
                print(f"FAIL: tier {s['tier']} did not pass correctness gate "
                      f"(build_ok={s['build_ok']}, correct={s['correct']})",
                      file=sys.stderr)
                return 1
            if not s["compile_within_budget"]:
                print(f"FAIL: tier {s['tier']} over compile budget "
                      f"({s['compile_s']}s > {s['compile_budget_s']}s)",
                      file=sys.stderr)
                return 1
            if not s["meets_gnarliness_bar"]:
                print(f"FAIL: tier {s['tier']} below gnarliness bar "
                      f"(nodes {s['node_ratio']}x/{s['node_bar']}x, "
                      f"edges {s['edge_ratio']}x/{s['edge_bar']}x)",
                      file=sys.stderr)
                return 1
            if s["transformed_functions"] == 0:
                print(f"FAIL: tier {s['tier']} transformed no functions",
                      file=sys.stderr)
                return 1

        for tier in ("C", "D"):
            s = next(x for x in summaries if x["tier"] == tier)
            v = s["vmp"]
            if not v["enabled"]:
                print(f"FAIL: tier {tier} VMP not reported as enabled",
                      file=sys.stderr)
                return 1
            if v["virtualized"] < 1:
                print(f"FAIL: tier {tier} reported no virtualized functions",
                      file=sys.stderr)
                return 1

        md = out_md.read_text(encoding="utf-8")
        for section in ("Per-tier summary", "VM compatibility",
                        "Enabled passes per tier", "Highlights"):
            if section not in md:
                print(f"FAIL: markdown missing section '{section}'",
                      file=sys.stderr)
                return 1

    print(f"tier release dashboard: ok (4 tiers, all pass correctness + "
          f"gnarliness + budget, C/D report VMP virtualized, MD complete)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
