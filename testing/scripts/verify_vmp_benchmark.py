"""Verify VMP per-function runtime overhead stays inside budget."""
from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
SRC = ROOT / "testing" / "cases" / "vmp_benchmark" / "src" / "main.c"
VSDEVCMD = tp.VSDEVCMD
DEFAULT_ITERS = 1_000_000
MIN_NATIVE_NS = 1_000_000
CASE_BUDGETS = {
    "add_case": 2500.0,
    "branch_case": 8000.0,
    "div_case": 5000.0,
    "loop_sum_case": 10000.0,
    "mul_case": 2500.0,
    "sub_case": 2500.0,
    "xor_case": 2500.0,
}


def run(cmd: list[str], use_vs_env: bool = False,
        timeout: int = 180) -> subprocess.CompletedProcess[str]:
    def invoke(actual: list[str]) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                actual, cwd=ROOT, text=True, capture_output=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout if isinstance(exc.stdout, str) else ""
            stderr = exc.stderr if isinstance(exc.stderr, str) else ""
            return subprocess.CompletedProcess(
                actual, 124, stdout,
                stderr + f"\ntimeout after {timeout}s\n",
            )

    if use_vs_env and VSDEVCMD.exists():
        with tempfile.NamedTemporaryFile(
            "w", suffix=".cmd", delete=False, encoding="utf-8"
        ) as handle:
            batch = Path(handle.name)
            handle.write(
                "@echo off\n"
                f'call "{VSDEVCMD}" -arch=x64 -host_arch=x64 >nul\n'
                f"{subprocess.list2cmdline(cmd)}\n"
                "exit /b %ERRORLEVEL%\n"
            )
        try:
            return invoke(["cmd.exe", "/d", "/c", str(batch)])
        finally:
            batch.unlink(missing_ok=True)
    return invoke(cmd)


def compile_exe(src: Path, out: Path, *, vmp: bool, iters: int) -> None:
    if vmp:
        case_attrs = r'-DVMP_CASE_ATTRS=__attribute__((noinline,annotate("+vmp")))'
        flags = [
            str(CLANG), str(src), case_attrs, f"-DITERS={iters}",
            "-O2", "-mllvm", "-taokari", "-mllvm", "-taokari-vmp",
            "-o", str(out),
        ]
    else:
        case_attrs = r"-DVMP_CASE_ATTRS=__attribute__((noinline))"
        flags = [
            str(CLANG), str(src), case_attrs, f"-DITERS={iters}",
            "-O2", "-o", str(out),
        ]
    res = run(flags, use_vs_env=True)
    if res.returncode:
        sys.stderr.write(res.stdout + res.stderr)
        raise SystemExit(1)


def parse_timings(stdout: str) -> dict[str, tuple[int, int]]:
    """Parse '<case>:<ns>:<iters>' lines into {case: (ns, iters)}."""
    out: dict[str, tuple[int, int]] = {}
    for line in stdout.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        parts = line.split(":")
        if len(parts) != 3:
            continue
        try:
            out[parts[0]] = (int(parts[1]), int(parts[2]))
        except ValueError:
            continue
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iters", type=int, default=DEFAULT_ITERS)
    parser.add_argument("--max-overhead", type=float, default=None)
    args = parser.parse_args(argv)

    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2
    if not SRC.exists():
        print(f"missing source: {SRC}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-vmp-bench-") as tmp:
        tmpdir = Path(tmp)
        native_exe = tmpdir / "native.exe"
        vmp_exe = tmpdir / "vmp.exe"
        compile_exe(SRC, native_exe, vmp=False, iters=args.iters)
        compile_exe(SRC, vmp_exe, vmp=True, iters=args.iters)

        native_run = run([str(native_exe)])
        vmp_run = run([str(vmp_exe)])
        if native_run.returncode:
            sys.stderr.write(native_run.stdout + native_run.stderr)
            return 1
        if vmp_run.returncode:
            sys.stderr.write(vmp_run.stdout + vmp_run.stderr)
            return 1

        native = parse_timings(native_run.stdout)
        vmp = parse_timings(vmp_run.stdout)

    print(f"{'case':<18} {'native_ms':>10} {'vmp_ms':>10} {'overhead':>10}")
    print("-" * 52)
    failures: list[str] = []
    for case in sorted(CASE_BUDGETS):
        if case not in native or case not in vmp:
            failures.append(f"{case}: missing timing row")
            continue
        n_ns, _ = native[case]
        v_ns, _ = vmp[case]
        n_ms = n_ns / 1e6
        v_ms = v_ns / 1e6
        ratio = v_ns / max(n_ns, MIN_NATIVE_NS)
        budget = args.max_overhead if args.max_overhead else CASE_BUDGETS[case]
        print(f"{case:<18} {n_ms:>10.2f} {v_ms:>10.2f} "
              f"{ratio:>9.1f}x / {budget:.0f}x")
        if ratio > budget:
            failures.append(f"{case}: {ratio:.1f}x > {budget:.0f}x")

    if failures:
        for failure in failures:
            print(f"vmp overhead budget: FAIL ({failure})", file=sys.stderr)
        return 1

    print("\nvmp overhead budget: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
