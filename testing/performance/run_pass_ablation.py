"""Per-pass obfuscation ablation: which protection at which level costs the most size and speed.

For each level-aware pass it builds the benchmark with ONLY that pass on
(no -taokari-max, no master preset) at levels 1..4, plus a native baseline
and a -taokari-max reference. Records compile time, binary size and per-case
runtime, then ranks passes by size delta and runtime delta vs native.

Reuses run_performance_matrix.py's VS-env runner, benchmark source and timing
parser so the numbers are directly comparable to the preset matrix.
"""
from __future__ import annotations

import argparse
import csv
import statistics
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_performance_matrix import (
    CLANG,
    OUT,
    SRC,
    compile_preset as _compile_preset,
    run_best,
    source_with_iters,
)
import _taokari_portable as tp


@dataclass(frozen=True)
class Pass:
    name: str
    level_flag: str


LEVEL_PASSES = (
    Pass("fla", "-taokari-level-fla"),
    Pass("bcf", "-taokari-level-bcf"),
    Pass("mba", "-taokari-level-mba"),
    Pass("cie", "-taokari-level-cie"),
    Pass("cfe", "-taokari-level-cfe"),
    Pass("indbr", "-taokari-level-indbr"),
    Pass("icall", "-taokari-level-icall"),
    Pass("indgv", "-taokari-level-indgv"),
)

LEVELLESS_PASSES = (
    Pass("cse", None),
    Pass("ocnst", None),
    Pass("outline", None),
    Pass("meta", None),
    Pass("rtti", None),
)

LEVELS = (1, 2, 3, 4)


def master_flags() -> tuple[str, ...]:
    return ("-mllvm", "-taokari")


def pass_flags(p: Pass, level: int | None) -> tuple[str, ...]:
    flags = list(master_flags())
    flags += ("-mllvm", f"-taokari-{p.name}")
    if p.level_flag and level is not None:
        flags += ("-mllvm", f"{p.level_flag}={level}")
    return tuple(flags)


def max_flags() -> tuple[str, ...]:
    return ("-mllvm", "-taokari-max")


def native_flags() -> tuple[str, ...]:
    return ()


def compile_flags(flags: tuple[str, ...], src: Path, out: Path) -> float:
    preset_compat = type("P", (), {"flags": flags, "vmp_attrs": False})()
    return _compile_preset(preset_compat, src, out)


def build_and_run(label: str, flags: tuple[str, ...], src: Path, tmpdir: Path, rounds: int) -> tuple[float, int, dict[str, tuple[int, int]]]:
    exe = tmpdir / tp.exe_name(label)
    compile_s = compile_flags(flags, src, exe)
    timings = run_best(exe, rounds)
    size = exe.stat().st_size
    return compile_s, size, timings


def fmt_bytes(n: int) -> str:
    return f"{n / 1024:.1f}KB"


def case_summary(timings: dict[str, tuple[int, int]]) -> tuple[float, float]:
    if not timings:
        return 0.0, 0.0
    total = sum(ns for ns, _ in timings.values())
    median = statistics.median(ns for ns, _ in timings.values())
    return total / 1e6, median / 1e6


def write_csv(rows: list[dict[str, str]], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def collapse(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    seen: dict[str, dict[str, str]] = {}
    for r in rows:
        seen.setdefault(r["label"], r)
    return list(seen.values())


def write_report(rows: list[dict[str, str]], native_size: int, native_total_ms: float, path: Path) -> None:
    obf = collapse([r for r in rows if r["label"] not in ("native", "max")])
    by_size = sorted(obf, key=lambda r: -float(r["size_x"]))
    by_speed = sorted(obf, key=lambda r: -float(r["speed_x"]))
    by_compile = sorted(obf, key=lambda r: -float(r["compile_s"]))

    def line(r: dict[str, str]) -> str:
        return (f"| {r['label']:<14} | size {float(r['size_kb']):>8.1f}KB "
                f"({float(r['size_x']):>5.2f}x) | run {float(r['total_ms']):>8.2f}ms "
                f"({float(r['speed_x']):>5.2f}x) | build {float(r['compile_s']):>6.2f}s |")

    md = ["# Taokari per-pass ablation", "",
          f"Native baseline: size {fmt_bytes(native_size)}, runtime {native_total_ms:.2f}ms total.", "",
          "## Biggest binary-size cost", "",
          "| pass           |                         metrics                          |",
          "|----------------|----------------------------------------------------------|"]
    md += [line(r) for r in by_size[:8]]
    md += ["", "## Biggest runtime cost", "",
           "| pass           |                         metrics                          |",
           "|----------------|----------------------------------------------------------|"]
    md += [line(r) for r in by_speed[:8]]
    md += ["", "## Biggest compile-time cost", "",
           "| pass           |                         metrics                          |",
           "|----------------|----------------------------------------------------------|"]
    md += [line(r) for r in by_compile[:8]]
    max_row = next((r for r in rows if r["label"] == "max"), None)
    if max_row:
        md += ["", "## -taokari-max reference", "",
               f"size {float(max_row['size_kb']):.1f}KB ({float(max_row['size_x']):.2f}x native), "
               f"runtime {float(max_row['total_ms']):.2f}ms ({float(max_row['speed_x']):.2f}x native), "
               f"build {float(max_row['compile_s']):.2f}s"]
    path.write_text("\n".join(md) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Per-pass Taokari size/speed ablation.")
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--iters", type=int, default=50_000_000)
    parser.add_argument("--out-dir", type=Path, default=OUT / "results_ablation")
    parser.add_argument("--only", action="append", help="limit to pass name(s); repeatable")
    parser.add_argument("--levels", help="comma-separated subset of 1..4")
    parser.add_argument("--no-levelless", action="store_true", help="skip cse/ocnst/outline/meta/rtti")
    parser.add_argument("--max", action="store_true", help="also build the -taokari-max reference")
    parser.add_argument("--max-runtime-x", type=float, default=None,
                        help="runtime-overhead target: exit 1 if any obfuscated "
                             "row exceeds this multiple of native runtime")
    args = parser.parse_args()

    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2
    if not SRC.exists():
        print(f"missing source: {SRC}", file=sys.stderr)
        return 2

    chosen_levels = [int(x) for x in args.levels.split(",")] if args.levels else list(LEVELS)
    wanted = set(args.only or ())
    level_passes = [p for p in LEVEL_PASSES if not wanted or p.name in wanted]
    levelless = [p for p in LEVELLESS_PASSES if not wanted or p.name in wanted]
    if args.no_levelless:
        levelless = []

    args.out_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, str]] = []
    native_size = 0
    native_total_ms = 0.0

    with tempfile.TemporaryDirectory(prefix="taokari-abl-") as tmp:
        tmpdir = Path(tmp)
        src = source_with_iters(tmpdir, args.iters)

        print("[BUILD/RUN] native", flush=True)
        compile_s, size, timings = build_and_run("native", native_flags(), src, tmpdir, args.rounds)
        native_size = size
        _, native_median_ms = case_summary(timings)
        native_total_ms = sum(ns for ns, _ in timings.values()) / 1e6
        for case, (ns, iters) in sorted(timings.items()):
            rows.append({"label": "native", "case": case, "compile_s": f"{compile_s:.3f}",
                         "size_kb": f"{size / 1024:.1f}", "size_x": "1.000",
                         "total_ms": f"{native_total_ms:.3f}", "speed_x": "1.000",
                         "case_ns": str(ns), "iters": str(iters)})

        def add_row(label: str, c_s: float, sz: int, tm: dict[str, tuple[int, int]]) -> None:
            total_ms = sum(ns for ns, _ in tm.values()) / 1e6
            sz_x = sz / native_size if native_size else 0
            sp_x = total_ms / native_total_ms if native_total_ms else 0
            for case, (ns, iters) in sorted(tm.items()):
                rows.append({"label": label, "case": case, "compile_s": f"{c_s:.3f}",
                             "size_kb": f"{sz / 1024:.1f}", "size_x": f"{sz_x:.3f}",
                             "total_ms": f"{total_ms:.3f}", "speed_x": f"{sp_x:.3f}",
                             "case_ns": str(ns), "iters": str(iters)})

        for p in level_passes:
            for lvl in chosen_levels:
                label = f"{p.name}_l{lvl}"
                print(f"[BUILD/RUN] {label}", flush=True)
                try:
                    c_s, sz, tm = build_and_run(label, pass_flags(p, lvl), src, tmpdir, args.rounds)
                except RuntimeError as exc:
                    print(f"[FAIL] {label}: {exc}", file=sys.stderr)
                    continue
                add_row(label, c_s, sz, tm)

        for p in levelless:
            label = f"{p.name}_on"
            print(f"[BUILD/RUN] {label}", flush=True)
            try:
                c_s, sz, tm = build_and_run(label, pass_flags(p, None), src, tmpdir, args.rounds)
            except RuntimeError as exc:
                print(f"[FAIL] {label}: {exc}", file=sys.stderr)
                continue
            add_row(label, c_s, sz, tm)

        if args.max:
            print("[BUILD/RUN] max", flush=True)
            try:
                c_s, sz, tm = build_and_run("max", max_flags(), src, tmpdir, args.rounds)
                add_row("max", c_s, sz, tm)
            except RuntimeError as exc:
                print(f"[FAIL] max: {exc}", file=sys.stderr)

    csv_path = args.out_dir / "ablation.csv"
    md_path = args.out_dir / "ablation.md"
    write_csv(rows, csv_path)
    write_report(rows, native_size, native_total_ms, md_path)
    print(f"[REPORT] {csv_path}")
    print(f"[REPORT] {md_path}")

    obf = [r for r in rows if r["label"] not in ("native", "max")]
    if obf:
        worst_size = max(obf, key=lambda r: float(r["size_x"]))
        worst_speed = max(obf, key=lambda r: float(r["speed_x"]))
        print(f"\nBIGGEST SIZE:   {worst_size['label']}  {float(worst_size['size_x']):.2f}x native "
              f"({float(worst_size['size_kb']):.1f}KB)")
        print(f"BIGGEST SPEED:  {worst_speed['label']}  {float(worst_speed['speed_x']):.2f}x native "
              f"({float(worst_speed['total_ms']):.2f}ms)")
    if args.max_runtime_x is not None and obf:
        over = [r for r in obf if float(r["speed_x"]) > args.max_runtime_x]
        if over:
            print(f"\nFAIL: runtime-overhead target {args.max_runtime_x}x exceeded by "
                  + ", ".join(f"{r['label']}({float(r['speed_x']):.2f}x)" for r in over),
                  file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
