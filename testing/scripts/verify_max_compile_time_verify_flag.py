"""Compile-time A/B benchmark for the Taokari Max Protection recipe.

Proves the compile-time win from dropping `-mllvm -verify-machineinstrs`
from the production Max Protection build. That flag is a `cl::Hidden`
LLVM *debug-only* safety check (`VerifyMachineCode` in
TargetPassConfig.cpp) that re-runs the MachineVerifier after every
codegen pass. It has zero effect on obfuscation strength, binary output,
or runtime behavior — it only asserts MIR stays verifier-clean during
*development* of new passes.

What this script does:
  1. Compiles the same source under the EXACT Max Protection flag recipe
     from build_max_protection.bat twice — once WITH and once WITHOUT
     `-mllvm -verify-machineinstrs`.
  2. Repeats each compile N times and takes the min wall-clock seconds
     (min is the most stable metric for short compiles).
  3. Asserts the without-verify variant is materially faster (>= 1.3x).
  4. Asserts both binaries produce the same stdout on the same input
     (semantic equivalence — the verifier flag does not change codegen).

Usage:
    python testing/scripts/verify_max_compile_time_verify_flag.py
        [--clang PATH] [--source PATH] [--runs N] [--out PATH]

Exits 0 on success, non-zero on failure.
"""
from __future__ import annotations

import argparse
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CLANG = ROOT / "build" / "taokari-local" / "bin" / "clang.exe"
DEFAULT_SOURCE = ROOT / "build" / "max-protection" / "bench_big.c"
VSDEVCMD = Path(
    r"C:\Program Files\Microsoft Visual Studio\18\Community"
    r"\Common7\Tools\VsDevCmd.bat"
)

# The Max Protection recipe from build_max_protection.bat, minus the
# path-rewrite flags that depend on caller context (added at runtime).
MAX_PROTECTION_FLAGS = [
    "-O2",
    "-fno-ident",
    "-mllvm", "-taokari",
    "-mllvm", "-taokari-fla", "-mllvm", "-taokari-level-fla=4",
    "-mllvm", "-taokari-bcf", "-mllvm", "-taokari-level-bcf=2",
    "-mllvm", "-taokari-mba", "-mllvm", "-taokari-mba-prob=40",
    "-mllvm", "-taokari-cie", "-mllvm", "-taokari-level-cie=2",
    "-mllvm", "-taokari-cfe", "-mllvm", "-taokari-level-cfe=2",
    "-mllvm", "-taokari-cse",
    "-mllvm", "-taokari-icall",
    "-mllvm", "-taokari-indbr",
    "-mllvm", "-taokari-indgv",
    "-mllvm", "-taokari-meta", "-mllvm", "-taokari-level-meta=3",
    "-mllvm", "-taokari-vmp-padding=5",
    "-Wl,/DEBUG:NONE",
]

SPEEDUP_THRESHOLD_X = 1.3


def eprint(*args, **kwargs) -> None:
    print(*args, file=sys.stderr, **kwargs)


def find_vsdevcmd() -> Path | None:
    if VSDEVCMD.exists():
        return VSDEVCMD
    return None


def build_vs_env() -> dict[str, str]:
    """Return env with MSVC INCLUDE/LIB/PATH set, by sourcing VsDevCmd."""
    env = os.environ.copy()
    vs = find_vsdevcmd()
    if vs is None:
        eprint(f"warning: VsDevCmd not found at {VSDEVCMD}; "
               "assuming caller already set MSVC env")
        return env
    # Use cmd to dump env after sourcing VsDevCmd, then parse it back.
    cmd = (
        f'cmd /c """{vs}" -arch=x64 -host_arch=x64 >nul && set"'
    )
    out = subprocess.run(cmd, shell=False, capture_output=True, text=True)
    if out.returncode != 0:
        eprint(f"warning: VsDevCmd failed: {out.stderr.strip()}")
        return env
    for line in out.stdout.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            env[k] = v
    return env


def time_compile_once(
    clang: Path, args: list[str], env: dict[str, str]
) -> tuple[float, int]:
    start = time.perf_counter()
    proc = subprocess.run(
        [str(clang)] + args,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    elapsed = time.perf_counter() - start
    if proc.returncode != 0:
        eprint("clang failed:")
        eprint(proc.stderr)
        raise SystemExit(proc.returncode)
    return elapsed, proc.returncode


def time_compile_min(
    clang: Path,
    args: list[str],
    env: dict[str, str],
    runs: int,
) -> float:
    times: list[float] = []
    for i in range(runs):
        t, _ = time_compile_once(clang, args, env)
        times.append(t)
        eprint(f"  run {i+1}: {t:.3f}s")
    return min(times)


def run_exe(exe: Path, args: list[str], env: dict[str, str]) -> str:
    proc = subprocess.run(
        [str(exe)] + args,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return proc.stdout


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clang", type=Path, default=DEFAULT_CLANG)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--runs", type=int, default=5,
                        help="compiles per variant (default 5, min is taken)")
    parser.add_argument("--out", type=Path,
                        default=ROOT / "build" / "max-protection"
                                       / "verify_flag_ab_result.txt",
                        help="path to write a key=value summary")
    args = parser.parse_args()

    if not args.clang.exists():
        eprint(f"missing clang: {args.clang}")
        return 2
    if not args.source.exists():
        eprint(f"missing source: {args.source}")
        return 2

    env = build_vs_env()
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        old_exe = td_path / "old_with_verify.exe"
        new_exe = td_path / "new_no_verify.exe"
        report = td_path / "report.txt"

        # Common Max Protection flags, with VS env-equivalent path rewrites.
        common = list(MAX_PROTECTION_FLAGS) + [
            "-ffile-prefix-map=" + str(ROOT) + "=.",
            "-fdebug-prefix-map=" + str(ROOT) + "=.",
            "-fmacro-prefix-map=" + str(ROOT) + "=.",
            "-mllvm", "-taokari-cfg=" + str(td_path / "cfg.json"),
        ]
        # Write a minimal cfg (build_max_protection.bat shape).
        (td_path / "cfg.json").write_text(
            '{"randomSeed":"taokari-verify-flag-ab","meta":{"enable":true,'
            '"level":3,"releaseStrip":true,"randomizeSections":true}}',
            encoding="ascii",
        )

        # OLD recipe: WITH -mllvm -verify-machineinstrs
        eprint("[1/2] OLD recipe WITH -mllvm -verify-machineinstrs ...")
        old_args = common + [
            "-mllvm", "-taokari-vmp-compat-report=" + str(report),
            "-mllvm", "-verify-machineinstrs",
            str(args.source), "-o", str(old_exe),
        ]
        old_min = time_compile_min(args.clang, old_args, env, args.runs)
        old_size = old_exe.stat().st_size
        eprint(f"  OLD min: {old_min:.3f}s   exe: {old_size} bytes")

        # NEW recipe: WITHOUT -mllvm -verify-machineinstrs
        eprint("[2/2] NEW recipe WITHOUT -mllvm -verify-machineinstrs ...")
        new_args = common + [
            "-mllvm", "-taokari-vmp-compat-report=" + str(report),
            str(args.source), "-o", str(new_exe),
        ]
        new_min = time_compile_min(args.clang, new_args, env, args.runs)
        new_size = new_exe.stat().st_size
        eprint(f"  NEW min: {new_min:.3f}s   exe: {new_size} bytes")

        speedup = old_min / new_min if new_min > 0 else float("inf")
        saved_pct = 100.0 * (old_min - new_min) / old_min if old_min > 0 else 0.0
        eprint("")
        eprint("============================================================")
        eprint(" Taokari Max Protection compile-time A/B (verify flag)")
        eprint("============================================================")
        eprint(f"  OLD (with    -verify-machineinstrs): "
               f"{old_min:.3f}s   exe={old_size}B")
        eprint(f"  NEW (without -verify-machineinstrs): "
               f"{new_min:.3f}s   exe={new_size}B")
        eprint(f"  Speedup: {speedup:.2f}x   time saved: {saved_pct:.1f}%")
        eprint("============================================================")

        # Semantic equivalence check: both binaries must produce identical
        # stdout on the same input args.
        run_args = ["1", "2", "3", "4", "5"]
        old_out = run_exe(old_exe, run_args, env)
        new_out = run_exe(new_exe, run_args, env)
        if old_out != new_out:
            eprint("FAIL: stdout mismatch between OLD and NEW binaries.")
            eprint(f"  OLD: {old_out!r}")
            eprint(f"  NEW: {new_out!r}")
            return 1
        eprint(f"[ok] OLD and NEW binaries produce identical stdout "
               f"({old_out.strip()!r})")

        if speedup < SPEEDUP_THRESHOLD_X:
            eprint(f"FAIL: speedup {speedup:.2f}x < required "
                   f"{SPEEDUP_THRESHOLD_X}x. The optimization is not "
                   f"effective on this host.")
            return 1
        eprint(f"[ok] speedup {speedup:.2f}x >= {SPEEDUP_THRESHOLD_X}x threshold")

        # Persist results for the build log.
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(
            f"source={args.source}\n"
            f"old_with_verify_min_seconds={old_min:.3f}\n"
            f"old_with_verify_exe_bytes={old_size}\n"
            f"new_no_verify_min_seconds={new_min:.3f}\n"
            f"new_no_verify_exe_bytes={new_size}\n"
            f"speedup_x={speedup:.2f}\n"
            f"time_saved_pct={saved_pct:.1f}\n"
            f"semantic_match=true\n",
            encoding="ascii",
        )
        eprint(f"[ok] result written to {args.out}")
        eprint("verify_max_compile_time_verify_flag: ok")
        return 0


if __name__ == "__main__":
    sys.exit(main())
