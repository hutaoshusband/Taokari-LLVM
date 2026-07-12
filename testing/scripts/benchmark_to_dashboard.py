"""Render a benchmark JSON file as a markdown dashboard.

todo.md Testing L3: "Add regression dashboard".

Takes the JSON written by `run_obfuscation_tests.py --benchmark-json`
and renders a per-case plain-vs-obfuscated size/runtime/compile-time
summary as markdown, with the worst overheads flagged. Useful as a
regression dashboard: pipe it into a file or PR comment to see at a
glance which fixtures got slower or bigger.

Usage:
    python testing/scripts/benchmark_to_dashboard.py bench.json > dash.md
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def fmt_overhead(x: float) -> str:
    if x <= 0:
        return "n/a"
    if x < 1.05:
        return f"{x:.2f}x"
    if x < 2.0:
        return f"**{x:.2f}x**"
    return f"⚠ **{x:.2f}x**"


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: benchmark_to_dashboard.py <bench.json>", file=sys.stderr)
        return 2
    rows = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    if not rows:
        print("(no rows)", file=sys.stderr)
        return 1

    by_mode: dict[str, list[dict]] = {}
    for r in rows:
        by_mode.setdefault(r["mode"], []).append(r)

    out: list[str] = []
    out.append("# Taokari obfuscation benchmark dashboard\n")
    out.append("Plain-vs-obfuscated cost per fixture, grouped by build mode.\n")
    out.append("Bold = notable overhead; warning emoji = significant overhead.\n")

    worst_size = ("", 0.0)
    worst_runtime = ("", 0.0)
    worst_compile = ("", 0.0)

    for mode, rs in sorted(by_mode.items()):
        out.append(f"\n## Mode: `{mode}`\n")
        out.append("| Case | plain size | obf size | size | "
                   "plain run | obf run | runtime | "
                   "plain compile | obf compile | compile |")
        out.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: "
                   "| ---: | ---: | ---: |")
        for r in sorted(rs, key=lambda x: x["case"]):
            try:
                size_oh = float(r["size_overhead"])
                run_oh = float(r["runtime_overhead"])
                cmp_oh = float(r["compile_overhead"])
            except (KeyError, ValueError, TypeError):
                continue
            if size_oh > worst_size[1]:
                worst_size = (f"{mode}/{r['case']}", size_oh)
            if run_oh > worst_runtime[1]:
                worst_runtime = (f"{mode}/{r['case']}", run_oh)
            if cmp_oh > worst_compile[1]:
                worst_compile = (f"{mode}/{r['case']}", cmp_oh)
            out.append(
                f"| {r['case']} "
                f"| {r['plain_size']} "
                f"| {r['obf_size']} "
                f"| {fmt_overhead(size_oh)} "
                f"| {r['plain_runtime_s']}s "
                f"| {r['obf_runtime_s']}s "
                f"| {fmt_overhead(run_oh)} "
                f"| {r['plain_compile_s']}s "
                f"| {r['obf_compile_s']}s "
                f"| {fmt_overhead(cmp_oh)} |"
            )

    out.append("\n## Worst overheads\n")
    out.append(f"- size:    {worst_size[0]} @ {worst_size[1]:.2f}x")
    out.append(f"- runtime: {worst_runtime[0]} @ {worst_runtime[1]:.2f}x")
    out.append(f"- compile: {worst_compile[0]} @ {worst_compile[1]:.2f}x")

    sys.stdout.write("\n".join(out) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
