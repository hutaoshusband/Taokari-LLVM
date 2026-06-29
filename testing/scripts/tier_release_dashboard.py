"""Per-tier release dashboard for Tier A/B/C/D.

Builds one demo program under each tier's flag recipe and renders a release
dashboard summary covering the D3 items:
  - per-tier correctness / compile time / binary size
  - gnarliness (CFG node/edge ratio vs the tier's bar)
  - VMP compatibility (virtualized / partially_virtualized / skipped counts
    + skipped reasons) for tiers that enable VMP
  - enabled passes per tier (from -taokari-report)
  - transformed function count
  - worst (slowest) tier

Outputs JSON (machine-readable) and markdown (human-readable) to --out and
--out.md. Reuses the recipes and demo source from verify_tier_recipe.py and
the gnarliness bars from measure_ida_cfg_complexity.py.

Run:
    python tier_release_dashboard.py [--tiers A B C D] [--out dash.json]
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from verify_vmp_coverage import CLANG, run, ROOT, VSDEVCMD
from measure_ida_cfg_complexity import TIER_BARS, emit_ir, parse_functions
from verify_tier_recipe import (
    DEMO_SOURCE, TIERS, TIER_BUDGET_SEC, TIER_SIZE_BUDGET, VMP_FUNCTIONS,
    parse_compat_report,
)


def tier_cfg(tier: str, tmpdir: Path) -> Path:
    cfg = tmpdir / f"tier_{tier}.json"
    cfg.write_text(
        '{"randomSeed": "taokari-tier-%s-seed", "meta": {"enable": true, '
        '"level": 3, "releaseStrip": true, "randomizeSections": true}}'
        % tier,
        encoding="utf-8",
    )
    return cfg


def tier_build(tier: str, src: Path, exe: Path, report_path: Path | None,
               tmpdir: Path, cfg: Path) -> dict:
    flags = list(TIERS[tier])
    flags += ["-mllvm", f"-taokari-cfg={cfg}"]
    if report_path is not None:
        flags += ["-mllvm", f"-taokari-vmp-compat-report={report_path}"]
    flags += ["-mllvm", "-taokari-report"]

    build_cmd = [str(CLANG), "-O2", str(src), "-o", str(exe),
                 "-Wl,/DEBUG:NONE"] + flags
    t0 = time.monotonic()
    r = run(build_cmd, use_vs_env=True)
    elapsed = time.monotonic() - t0
    report_text = r.stderr + r.stdout
    return {
        "compile_s": round(elapsed, 2),
        "returncode": r.returncode,
        "report_text": report_text,
    }


def parse_pass_report(text: str) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for m in re.finditer(r"taokari-report:\s*(\w+)\s+enable=(\w+)\s+level=(\d+)",
                         text):
        out[m.group(1)] = {"enable": m.group(2) == "true",
                           "level": int(m.group(3))}
    return out


def summarize_tier(tier: str, tmpdir: Path) -> dict:
    bar = TIER_BARS[tier]
    budget = TIER_BUDGET_SEC[tier]
    size_budget = TIER_SIZE_BUDGET[tier]
    src = tmpdir / f"tier_{tier}.c"
    src.write_text(DEMO_SOURCE, encoding="utf-8")

    plain_ll = tmpdir / f"plain_{tier}.ll"
    emit_ir(src, plain_ll, [])
    plain_metrics = parse_functions(
        plain_ll.read_text(encoding="utf-8", errors="ignore"))

    report_path = tmpdir / f"report_{tier}.TSV" if tier in ("C", "D") else None
    cfg = tier_cfg(tier, tmpdir)
    exe = tmpdir / f"out_{tier}.exe"
    build = tier_build(tier, src, exe, report_path, tmpdir, cfg)

    binary_size = exe.stat().st_size if exe.exists() else 0
    summary: dict = {
        "tier": tier,
        "correct": False,
        "compile_s": build["compile_s"],
        "compile_budget_s": budget,
        "compile_within_budget": build["compile_s"] <= budget,
        "build_ok": build["returncode"] == 0,
        "binary_size": binary_size,
        "size_budget_b": size_budget,
        "size_within_budget": binary_size <= size_budget,
        "node_bar": bar["node_factor"],
        "edge_bar": bar["edge_factor"],
        "passes": parse_pass_report(build["report_text"]),
    }

    if build["returncode"] == 0 and exe.exists():
        rr = run([str(exe)])
        summary["correct"] = (rr.returncode == 0
                              and rr.stdout.startswith("tier:"))

    obf_ll = tmpdir / f"obf_{tier}.ll"
    obf_flags = (list(TIERS[tier])
                 + ["-mllvm", f"-taokari-cfg={cfg}", "-mllvm", "-taokari-report"])
    try:
        emit_ir(src, obf_ll, obf_flags)
    except SystemExit:
        obf_ll = tmpdir / f"obf_{tier}.missing"
    obf_metrics = (parse_functions(obf_ll.read_text(encoding="utf-8",
                                                   errors="ignore"))
                   if obf_ll.exists() else {})
    if plain_metrics and obf_metrics:
        plain_target = max(plain_metrics.items(),
                           key=lambda kv: kv[1]["nodes"])[0]
        obf_target = max(obf_metrics.items(),
                         key=lambda kv: kv[1]["nodes"])[0]
        pn = plain_metrics[plain_target]["nodes"] or 1
        pe = plain_metrics[plain_target]["edges"] or 1
        summary["node_ratio"] = round(obf_metrics[obf_target]["nodes"] / pn, 2)
        summary["edge_ratio"] = round(obf_metrics[obf_target]["edges"] / pe, 2)
        summary["meets_gnarliness_bar"] = (
            summary["node_ratio"] >= bar["node_factor"]
            and summary["edge_ratio"] >= bar["edge_factor"])
    else:
        summary["node_ratio"] = 0.0
        summary["edge_ratio"] = 0.0
        summary["meets_gnarliness_bar"] = (tier == "A")

    summary["transformed_functions"] = sum(
        1 for p in summary["passes"].values() if p["enable"])

    vmp: dict = {"enabled": False, "virtualized": 0, "partially_virtualized": 0,
                 "skipped": 0, "skipped_reasons": {}, "total_words": 0}
    if report_path is not None and report_path.exists():
        rows = parse_compat_report(
            report_path.read_text(encoding="utf-8", errors="ignore"))
        vmp["enabled"] = True
        for fn, row in rows.items():
            status = row["status"]
            if status == "virtualized":
                vmp["virtualized"] += 1
                vmp["total_words"] += int(row.get("words", "0") or 0)
            elif status == "partially_virtualized":
                vmp["partially_virtualized"] += 1
            elif status == "skipped":
                vmp["skipped"] += 1
                reason = row.get("reason", "unknown")
                vmp["skipped_reasons"][reason] = (
                    vmp["skipped_reasons"].get(reason, 0) + 1)
    summary["vmp"] = vmp
    return summary


def render_markdown(summaries: list[dict]) -> str:
    out: list[str] = ["# Taokari per-tier release dashboard\n"]
    out.append("Correctness, gnarliness, compile cost and VM compatibility "
               "per tier.\n")
    out.append("\n## Per-tier summary\n")
    out.append("| Tier | Correct | Compile (s) | Budget (s) | Binary (B) | "
               "Nodes | Node bar | Edges | Edge bar | Transformed |")
    out.append("| --- | :---: | ---: | ---: | ---: | ---: | ---: | ---: | "
               "---: | ---: |")
    for s in summaries:
        out.append(
            f"| {s['tier']} | {'✓' if s['correct'] else '✗'} | "
            f"{s['compile_s']} | {s['compile_budget_s']} | "
            f"{s['binary_size']} | "
            f"{s['node_ratio']}x | {s['node_bar']}x | "
            f"{s['edge_ratio']}x | {s['edge_bar']}x | "
            f"{s['transformed_functions']} |"
        )

    out.append("\n## VM compatibility\n")
    out.append("| Tier | VMP | Virtualized | Partial | Skipped | Total words |")
    out.append("| --- | :---: | ---: | ---: | ---: | ---: |")
    for s in summaries:
        v = s["vmp"]
        out.append(
            f"| {s['tier']} | {'on' if v['enabled'] else 'off'} | "
            f"{v['virtualized']} | {v['partially_virtualized']} | "
            f"{v['skipped']} | {v['total_words']} |"
        )

    any_skipped = [s for s in summaries
                   if s["vmp"]["enabled"] and s["vmp"]["skipped"] > 0]
    if any_skipped:
        out.append("\n## Skipped-function reasons\n")
        for s in any_skipped:
            for reason, count in s["vmp"]["skipped_reasons"].items():
                out.append(f"- tier {s['tier']}: {count}x `{reason}`")

    out.append("\n## Enabled passes per tier\n")
    for s in summaries:
        enabled = [name for name, p in s["passes"].items() if p["enable"]]
        out.append(f"- tier {s['tier']}: {', '.join(enabled) or '(none)'}")

    over = [s for s in summaries if not s["compile_within_budget"]]
    if over:
        out.append("\n## Budget warnings\n")
        out.append("Tier compile time exceeded its budget (lower the level or "
                   "drop a pass on this tier).\n")
        for s in over:
            out.append(f"- tier {s['tier']}: {s['compile_s']}s > "
                       f"{s['compile_budget_s']}s budget")
    size_over = [s for s in summaries if not s["size_within_budget"]]
    if size_over:
        if not over:
            out.append("\n## Budget warnings\n")
        out.append("Tier binary size exceeded its budget (the obfuscation is "
                   "bloating past the size ceiling).\n")
        for s in size_over:
            out.append(f"- tier {s['tier']}: {s['binary_size']} B > "
                       f"{s['size_budget_b']} B budget")

    valid = [s for s in summaries if s["build_ok"] and s["correct"]]
    slowest = max(summaries, key=lambda s: s["compile_s"]) if summaries else None
    out.append("\n## Highlights\n")
    if slowest:
        out.append(f"- slowest tier: {slowest['tier']} "
                   f"({slowest['compile_s']}s)")
    out.append(f"- tiers passing correctness gate: "
               f"{', '.join(s['tier'] for s in valid) or '(none)'}")
    return "\n".join(out) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tiers", nargs="+", default=["A", "B", "C", "D"],
                        choices=list(TIERS))
    parser.add_argument("--out", type=Path, default=None,
                        help="write JSON summary here")
    parser.add_argument("--out-md", type=Path, default=None,
                        help="write markdown dashboard here")
    parser.add_argument("--fail-on-budget-exceed", action="store_true",
                        help="exit non-zero if any tier exceeds its budget")
    args = parser.parse_args()

    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    tmp = Path(tempfile.mkdtemp(prefix="taokari-dash-"))
    try:
        summaries = [summarize_tier(t, tmp) for t in args.tiers]
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)

    payload = {"tiers": summaries}
    text = json.dumps(payload, indent=2)
    md = render_markdown(summaries)
    over = [s for s in summaries if not s["compile_within_budget"]]
    for s in over:
        print(f"warning: tier {s['tier']} exceeded its compile-time budget "
              f"({s['compile_s']}s > {s['compile_budget_s']}s)", file=sys.stderr)
    size_over = [s for s in summaries if not s["size_within_budget"]]
    for s in size_over:
        print(f"warning: tier {s['tier']} exceeded its binary-size budget "
              f"({s['binary_size']} B > {s['size_budget_b']} B)", file=sys.stderr)
    if args.out:
        args.out.write_text(text, encoding="utf-8")
    if args.out_md:
        args.out_md.write_text(md, encoding="utf-8")
    if not args.out and not args.out_md:
        print(text)
    print(md, file=sys.stderr)
    if args.fail_on_budget_exceed and (over or size_over):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
