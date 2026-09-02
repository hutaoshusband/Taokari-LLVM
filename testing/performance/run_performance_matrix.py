"""Taokari preset performance matrix.

Builds the existing VMP benchmark source under current protection presets,
runs each executable, then writes CSV and Markdown reports.
"""
from __future__ import annotations

import argparse
import csv
import statistics
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "testing" / "scripts"))
import _taokari_portable as tp

SRC = ROOT / "testing" / "cases" / "vmp_benchmark" / "src" / "main.c"
OUT = ROOT / "testing" / "performance" / "results"
CLANG = tp.CLANG


@dataclass(frozen=True)
class Preset:
    name: str
    flags: tuple[str, ...]
    vmp_attrs: bool = False


LEVEL_PASSES = ("indbr", "icall", "indgv", "fla", "bcf", "mba", "cie", "cfe")


def level_flags(level: int) -> tuple[str, ...]:
    return tuple(item for name in LEVEL_PASSES for item in ("-mllvm", f"-taokari-level-{name}={level}"))


PRESETS: tuple[Preset, ...] = (
    Preset("native", ()),
    Preset("taokari_l1", ("-mllvm", "-taokari", *level_flags(1))),
    Preset("taokari_l4", ("-mllvm", "-taokari", *level_flags(4))),
    Preset("taokari_max", ("-mllvm", "-taokari-max")),
    Preset("taokari_max_no_bcf_after", ("-mllvm", "-taokari-max", "-mllvm", "-taokari-max-no-bcf-after")),
    Preset("taokari_max_no_bcf_before", ("-mllvm", "-taokari-max", "-mllvm", "-taokari-max-no-bcf-before")),
    Preset("taokari_max_no_fla", ("-mllvm", "-taokari-max", "-mllvm", "-taokari-max-no-fla")),
    Preset("taokari_max_no_mba", ("-mllvm", "-taokari-max", "-mllvm", "-taokari-max-no-mba")),
    Preset("taokari_max_no_const", ("-mllvm", "-taokari-max", "-mllvm", "-taokari-max-no-const")),
    Preset("taokari_max_no_indirects", ("-mllvm", "-taokari-max", "-mllvm", "-taokari-max-no-indirects")),
    Preset("vmp_l1", ("-mllvm", "-taokari", "-mllvm", "-taokari-vmp", "-mllvm", "-taokari-level-vmp=1"), True),
    Preset("vmp_l3", ("-mllvm", "-taokari", "-mllvm", "-taokari-vmp", "-mllvm", "-taokari-level-vmp=3"), True),
    Preset("taokari_max_vmp_l3", ("-mllvm", "-taokari-max", "-mllvm", "-taokari-vmp", "-mllvm", "-taokari-level-vmp=3"), True),
)


def source_with_iters(tmpdir: Path, iters: int) -> Path:
    if iters == 50_000_000:
        return SRC
    text = SRC.read_text(encoding="utf-8")
    # ponytail: temp source keeps the checked-in benchmark stable; add a real CLI to the C file if more knobs appear.
    text = text.replace("#define ITERS 50000000", f"#define ITERS {iters}")
    out = tmpdir / f"main_{iters}.c"
    out.write_text(text, encoding="utf-8")
    return out


def compile_preset(preset: Preset, src: Path, out: Path) -> float:
    attr = r'-DVMP_CASE_ATTRS=__attribute__((noinline,annotate("+vmp")))' if preset.vmp_attrs else r"-DVMP_CASE_ATTRS=__attribute__((noinline))"
    cmd = [str(CLANG), str(src), attr, "-O2", *preset.flags, "-o", str(out)]
    start = time.perf_counter()
    res = tp.run(cmd, vs=True)
    seconds = time.perf_counter() - start
    if res.returncode:
        raise RuntimeError(res.stdout + res.stderr)
    return seconds


def parse_timings(stdout: str) -> dict[str, tuple[int, int]]:
    out: dict[str, tuple[int, int]] = {}
    for line in stdout.splitlines():
        parts = line.strip().split(":")
        if len(parts) != 3:
            continue
        try:
            out[parts[0]] = (int(parts[1]), int(parts[2]))
        except ValueError:
            continue
    return out


def run_best(exe: Path, rounds: int) -> dict[str, tuple[int, int]]:
    samples: dict[str, list[tuple[int, int]]] = {}
    for _ in range(rounds):
        res = tp.run([str(exe)])
        if res.returncode:
            raise RuntimeError(res.stdout + res.stderr)
        for case, timing in parse_timings(res.stdout).items():
            samples.setdefault(case, []).append(timing)
    return {case: min(values, key=lambda item: item[0]) for case, values in samples.items()}


def write_markdown(rows: list[dict[str, str]], path: Path) -> None:
    headers = ("preset", "case", "runtime_ms", "vs_native", "compile_s", "size_kb")
    lines = ["# Taokari Performance Matrix", "", "| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(row[h] for h in headers) + " |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def self_test() -> int:
    parsed = parse_timings("add_case:1200:50\nbad\nsub_case:2400:50\n")
    assert parsed == {"add_case": (1200, 50), "sub_case": (2400, 50)}
    assert statistics.median([3.0, 1.0, 2.0]) == 2.0
    return 0


def check_budget(rows: list[dict[str, str]], preset: str, max_median_ratio: float | None, max_size_kb: float | None) -> int:
    selected = [row for row in rows if row["preset"] == preset]
    if not selected:
        print(f"budget fail: missing preset {preset}", file=sys.stderr)
        return 1
    if max_median_ratio is not None:
        median = statistics.median(float(row["vs_native"]) for row in selected)
        if median > max_median_ratio:
            print(f"budget fail: {preset} median {median:.3f}x > {max_median_ratio:.3f}x", file=sys.stderr)
            return 1
    if max_size_kb is not None:
        size = max(float(row["size_kb"]) for row in selected)
        if size > max_size_kb:
            print(f"budget fail: {preset} size {size:.1f} KB > {max_size_kb:.1f} KB", file=sys.stderr)
            return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Measure Taokari preset performance.")
    parser.add_argument("--preset", action="append", choices=[p.name for p in PRESETS], help="preset(s) to run; repeatable")
    parser.add_argument("--rounds", type=int, default=3, help="run each executable this many times; best timing wins")
    parser.add_argument("--iters", type=int, default=50_000_000, help="benchmark loop iterations per case")
    parser.add_argument("--out-dir", type=Path, default=OUT)
    parser.add_argument("--fail-preset", default="taokari_max", choices=[p.name for p in PRESETS], help="preset checked by fail budgets")
    parser.add_argument("--fail-median-ratio", type=float, help="fail if preset median vs_native exceeds this")
    parser.add_argument("--fail-size-kb", type=float, help="fail if preset size exceeds this")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return self_test()
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2
    if not SRC.exists():
        print(f"missing source: {SRC}", file=sys.stderr)
        return 2
    if args.rounds < 1:
        print("--rounds must be >= 1", file=sys.stderr)
        return 1
    if args.iters < 1:
        print("--iters must be >= 1", file=sys.stderr)
        return 1

    requested = set(args.preset or ())
    if requested and "native" not in requested:
        requested.add("native")
    chosen = [p for p in PRESETS if not requested or p.name in requested]
    args.out_dir.mkdir(parents=True, exist_ok=True)
    native: dict[str, tuple[int, int]] | None = None
    rows: list[dict[str, str]] = []

    with tempfile.TemporaryDirectory(prefix="taokari-perf-") as tmp:
        tmpdir = Path(tmp)
        src = source_with_iters(tmpdir, args.iters)
        for preset in chosen:
            exe = tmpdir / tp.exe_name(preset.name)
            print(f"[BUILD] {preset.name}", flush=True)
            compile_s = compile_preset(preset, src, exe)
            print(f"[RUN] {preset.name}", flush=True)
            timings = run_best(exe, args.rounds)
            if preset.name == "native":
                native = timings
            if native is None:
                raise RuntimeError("native preset must run before ratio presets")
            for case, (ns, iters) in sorted(timings.items()):
                base_ns = native[case][0]
                rows.append({
                    "preset": preset.name,
                    "case": case,
                    "runtime_ms": f"{ns / 1e6:.3f}",
                    "vs_native": f"{(ns / base_ns if base_ns else 0):.3f}",
                    "compile_s": f"{compile_s:.3f}",
                    "size_kb": f"{exe.stat().st_size / 1024:.1f}",
                    "ns": str(ns),
                    "iters": str(iters),
                })

    csv_path = args.out_dir / "report.csv"
    md_path = args.out_dir / "report.md"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    write_markdown(rows, md_path)
    print(f"[REPORT] {csv_path}")
    print(f"[REPORT] {md_path}")
    return check_budget(rows, args.fail_preset, args.fail_median_ratio, args.fail_size_kb)


if __name__ == "__main__":
    raise SystemExit(main())
