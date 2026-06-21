"""VMP baseline benchmark (L1.5.4).

Measures interpreter overhead vs native for each L1.5 IR feature. Builds the
benchmark source twice (plain NATIVE and +vmp), runs each, parses per-case
nanosecond timings from stdout, and reports the vmp/native overhead ratio.

This is the baseline reference for the L2 benchmark -- it establishes the
cost floor of virtualization before bytecode encryption / handler obfuscation
layers land.

Exit contract:
  0  -- benchmark ran and ratios printed (always informational; no pass/fail)
  1  -- build or run failure
  2  -- missing clang / source
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CLANG = ROOT / "build" / "taokari-local" / "bin" / "clang.exe"
SRC = ROOT / "testing" / "cases" / "vmp_benchmark" / "src" / "main.c"
VSDEVCMD = Path(
    r"C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat"
)


def run(cmd: list[str], use_vs_env: bool = False) -> subprocess.CompletedProcess[str]:
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
            return subprocess.run(
                ["cmd.exe", "/d", "/c", str(batch)],
                cwd=ROOT,
                text=True,
                capture_output=True,
            )
        finally:
            batch.unlink(missing_ok=True)
    return subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True)


def compile_exe(src: Path, out: Path, *, vmp: bool) -> None:
    if vmp:
        case_attrs = r'-DVMP_CASE_ATTRS=__attribute__((noinline,annotate("+vmp")))'
        flags = [
            str(CLANG), str(src), case_attrs,
            "-O2", "-mllvm", "-taokari", "-mllvm", "-taokari-vmp",
            "-o", str(out),
        ]
    else:
        case_attrs = r"-DVMP_CASE_ATTRS=__attribute__((noinline))"
        flags = [str(CLANG), str(src), case_attrs, "-O2", "-o", str(out)]
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


def main() -> int:
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
        compile_exe(SRC, native_exe, vmp=False)
        compile_exe(SRC, vmp_exe, vmp=True)

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
    for case in sorted(set(native) & set(vmp)):
        n_ns, _ = native[case]
        v_ns, _ = vmp[case]
        n_ms = n_ns / 1e6
        v_ms = v_ns / 1e6
        ratio = (v_ns / n_ns) if n_ns > 0 else float("inf")
        print(f"{case:<18} {n_ms:>10.2f} {v_ms:>10.2f} {ratio:>9.1f}x")
    print("\nvmp benchmark: baseline recorded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
