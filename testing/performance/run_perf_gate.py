"""Correctness-gated performance regression gate.

Compiles the baseline corpus cases plain and obfuscated (default IR stack,
level 4) and verifies every obfuscated run matches the plain run's
stdout/stderr/exit before any measurement counts. Compile-time and size use
the median of --samples obfuscated builds (per-compile RNG jitters binary
size ~6%); runtime is best-of --rounds. Ratios are checked against
testing/performance/baseline.json with per-metric relative tolerances
(Windows: compile +40%, runtime +20%, size +10% plus an absolute runtime
floor +0.25; Linux: compile +40%, runtime +75%, size +40%, no floor —
calibrated to measured session-to-session size-median swings of up to
+28% on /mnt/c).

Exit: 0 pass | 1 regression or correctness mismatch | 2 tooling/baseline missing.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "testing" / "scripts"))
import _taokari_portable as tp

BASELINE = Path(__file__).resolve().parent / "baseline.json"
ALL_CASES = ("multithreading", "tiny_aes", "atomics", "flattening_stress",
             "pointer_heavy", "hashing", "arith_logic", "dynamic_memory",
             "math_heavy", "mba_basic")
QUICK = ("mba_basic", "hashing", "arith_logic")
TOLERANCES = {"compile": 0.40, "runtime": 0.20, "size": 0.10}
FLOORS = {"compile": 0.0, "runtime": 0.25, "size": 0.0}
LINUX_TOLERANCES = {"compile": 0.40, "runtime": 0.75, "size": 0.40}
LINUX_FLOORS = {"compile": 0.0, "runtime": 0.0, "size": 0.0}
ADDR = re.compile(r"0x[0-9a-fA-F]{6,}")


def load_harness():
    spec = importlib.util.spec_from_file_location(
        "taokari_harness", ROOT / "testing" / "run_obfuscation_tests.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def norm(text: str) -> str:
    return ADDR.sub("0xADDR", text)


def platform_of(explicit: str | None) -> str:
    return explicit or ("windows" if tp.IS_WINDOWS else "linux")


def within(measured: float, base: float, tol: float, floor: float = 0.0) -> bool:
    return measured <= max(base * (1 + tol), base + floor)


def compile_case(harness, clang, case, obf: bool, level: int):
    harness.MODE_DRIVER["default"] = clang
    start = time.perf_counter()
    exe = harness.compile_case(clang, case, "default", obfuscate=obf,
                               level=level if obf else None)
    return exe, time.perf_counter() - start


def run_best(harness, exe, rounds, ref=None):
    best = float("inf")
    last = None
    for _ in range(rounds):
        start = time.perf_counter()
        r = harness.run([str(exe)])
        best = min(best, time.perf_counter() - start)
        last = r
        if ref is not None and (r.returncode != ref[0]
                                or norm(r.stdout) != norm(ref[1])
                                or norm(r.stderr) != norm(ref[2])):
            raise RuntimeError(
                "obfuscated output mismatch\n"
                f"obf rc={r.returncode} out={r.stdout!r} err={r.stderr!r}\n"
                f"plain rc={ref[0]} out={ref[1]!r} err={ref[2]!r}")
    if last is None or last.returncode:
        rc = last.returncode if last else -1
        raise RuntimeError(f"{exe.name} failed rc={rc}\n{last.stderr if last else ''}")
    return best, last


def measure(harness, clang, case, level: int, rounds: int, samples: int) -> dict:
    plain_exe, p_compile = compile_case(harness, clang, case, False, level)
    p_size = plain_exe.stat().st_size
    p_best, p_run = run_best(harness, plain_exe, rounds)
    ref = (p_run.returncode, p_run.stdout, p_run.stderr)
    o_compiles, o_sizes = [], []
    o_best = None
    for i in range(samples):
        obf_exe, o_compile = compile_case(harness, clang, case, True, level)
        o_compiles.append(o_compile)
        o_sizes.append(obf_exe.stat().st_size)
        if i == 0:
            o_best, _ = run_best(harness, obf_exe, rounds, ref)
    o_compile = statistics.median(o_compiles)
    o_size = statistics.median(o_sizes)
    return {
        "compile": o_compile / p_compile if p_compile else 0.0,
        "runtime": o_best / p_best if p_best else 0.0,
        "size": o_size / p_size if p_size else 0.0,
        "obf_size_kb": round(o_size / 1024, 1),
    }


def self_test() -> int:
    assert norm("ptr 0x7ff61234ab90 end") == "ptr 0xADDR end"
    assert norm("no addresses here")
    assert within(1.30, 1.0, 0.30) and not within(1.31, 1.0, 0.30)
    assert within(1.22, 1.00, 0.20, 0.25) and not within(1.26, 1.00, 0.20, 0.25)
    assert within(2.08, 1.97, 0.10) and not within(2.20, 1.97, 0.10)
    assert set(QUICK) <= set(ALL_CASES)
    assert set(LINUX_TOLERANCES) == set(LINUX_FLOORS) == set(TOLERANCES)
    data = json.loads(BASELINE.read_text(encoding="utf-8"))
    assert "linux" in data and "windows" in data
    win = data["windows"]
    need = ("compile", "runtime", "size", "obf_size_kb")
    bad = [c for c in ALL_CASES
           if c not in win or any(k not in win[c] or win[c][k] <= 0 for k in need)]
    assert not bad, f"bad windows baseline entries: {bad}"
    print(f"perf-gate self-test: ok ({len(win)} windows baseline cases, "
          f"tolerances {TOLERANCES})")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Correctness-gated perf regression gate.")
    ap.add_argument("--update-baseline", action="store_true",
                    help="write measured ratios into this platform's baseline section")
    ap.add_argument("--quick", action="store_true", help="run the 3-case subset")
    ap.add_argument("--self-test", action="store_true",
                    help="logic checks only, no compiler needed")
    ap.add_argument("--platform", choices=["windows", "linux"])
    ap.add_argument("--rounds", type=int, default=5, help="best-of-N executions")
    ap.add_argument("--samples", type=int, default=3,
                    help="obfuscated compile samples; median compile/size")
    ap.add_argument("--compile-tol", type=float, default=None,
                    help="default: per-platform (windows 0.40 / linux 0.40)")
    ap.add_argument("--runtime-tol", type=float, default=None,
                    help="default: per-platform (windows 0.20 / linux 0.75)")
    ap.add_argument("--size-tol", type=float, default=None,
                    help="default: per-platform (windows 0.10 / linux 0.40)")
    args = ap.parse_args()

    if args.self_test:
        return self_test()
    if args.rounds < 1 or args.samples < 1:
        print("--rounds/--samples must be >= 1", file=sys.stderr)
        return 2
    clang = tp.CLANG
    if not clang.exists():
        print(f"perf-gate: skip, missing clang {clang}", file=sys.stderr)
        return 2
    if not BASELINE.exists():
        print(f"perf-gate: skip, missing {BASELINE}", file=sys.stderr)
        return 2
    harness = load_harness()
    cases = {c.name: c for c in harness.CASES}
    names = QUICK if args.quick else ALL_CASES
    unknown = [n for n in names if n not in cases]
    if unknown:
        print(f"perf-gate: unknown cases {unknown}", file=sys.stderr)
        return 2

    plat = platform_of(args.platform)
    dtol = TOLERANCES if plat == "windows" else LINUX_TOLERANCES
    floors = FLOORS if plat == "windows" else LINUX_FLOORS
    tol = {k: dtol[k] if v is None else v for k, v in
           {"compile": args.compile_tol, "runtime": args.runtime_tol,
            "size": args.size_tol}.items()}
    base = json.loads(BASELINE.read_text(encoding="utf-8")).get(plat, {})
    if not args.update_baseline and not base:
        print(f"perf-gate: skip, no {plat} baseline (run --update-baseline)",
              file=sys.stderr)
        return 2
    results: dict[str, dict] = {}
    failures: list[str] = []
    for name in names:
        print(f"[PERF] {name}", flush=True)
        try:
            m = measure(harness, clang, cases[name], harness.DEFAULT_LEVEL,
                        args.rounds, args.samples)
        except Exception as exc:
            failures.append(f"{name}: {exc}")
            print(f"[FAIL] {name}: {exc}", file=sys.stderr)
            continue
        results[name] = m
        print(f"[PERF] {name}: compile {m['compile']:.2f}x runtime {m['runtime']:.2f}x "
              f"size {m['size']:.2f}x ({m['obf_size_kb']}KB)")

    if args.update_baseline:
        data = json.loads(BASELINE.read_text(encoding="utf-8"))
        data.setdefault(plat, {}).update(results)
        BASELINE.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n",
                            encoding="utf-8")
        print(f"[BASELINE] {plat} section updated with {len(results)} cases")
        return 1 if failures else 0

    for name, m in results.items():
        b = base.get(name)
        if not b:
            continue
        for key in ("compile", "runtime", "size"):
            if not within(m[key], b[key], tol[key], floors[key]):
                failures.append(f"{name} {key} {m[key]:.2f}x > baseline "
                                f"{b[key]:.2f}x + {tol[key]:.0%}")
    for f in failures:
        print(f"[REGRESSION] {f}", file=sys.stderr)
    compared = sum(1 for n in results if n in base)
    print(f"perf-gate: {'FAIL' if failures else 'ok'} "
          f"({compared} cases compared, tol compile +{tol['compile']:.0%} "
          f"runtime +{tol['runtime']:.0%} size +{tol['size']:.0%}, "
          f"runtime floor +{floors['runtime']:.0%}, {args.samples} samples)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
