"""VMP differential correctness harness (L1.5.3).

Compiles the same case-source twice -- once as a plain NATIVE oracle and
once with `-mllvm -taokari -taokari-vmp` (case fns annotated `+vmp`) --
then runs both over an input grid of (a, b) pairs and asserts the two
stdout streams match line-for-line on every input.

This is the regression net for the L1.5 IR-widening (L1.5.1) and the
dispatch refactor (L1.5.2). It is a NEW pattern in this repo -- the
existing verifiers run a binary once against a hardcoded expected string;
none sweep a single binary across an input grid. The two-binary +
Python-side stdout diff idiom is borrowed from verify_machine_obf_level1.

Exit contract (matches the other verify_* scripts):
  0  + "vmp differential: ok"            -- all inputs agree
  1                                       -- mismatch / build failure
  2                                       -- missing clang / source
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CLANG = ROOT / "build" / "taokari-local" / "bin" / "clang.exe"
SRC = ROOT / "testing" / "cases" / "vmp_differential" / "src" / "main.c"
VSDEVCMD = Path(
    r"C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat"
)

# Input grid: (a, b) pairs exercising edge values for the current integer ISA.
#
# (INT_MAX, 1) was the regression target for L1.5.1 width tracking: it
# overflows an i32 *intermediate* in branch_case's `int x = (a+b) ^ 5`.
# Before width tracking the VM promoted operands to i64 (no wraparound) and
# only truncated at return, diverging from native i32 semantics. With width
# tracking (per-operand VmTy, narrowing after every binary op) both builds
# must agree on every input including this one.
INPUTS: list[tuple[int, int]] = [
    (0, 0),
    (1, 1),
    (-1, 1),
    (1, -1),
    (-1, -1),
    (5, 40),
    (40, 5),
    (41, 1),
    (17, 17),
    (100, -100),
    (2147483647, 1),    # INT_MAX + 1: intermediate i32 overflow, must wrap
    (-2147483648, 1),   # INT_MIN + 1
    (22, 19),
    (2, 4),
    # Shift / div / rem exercise cases: b as shift amount (masked to 0..7)
    # and as divisor. (100, 7) hits non-power-of-two div/rem; (-100, 7)
    # hits signed div/rem sign behavior.
    (256, 3),
    (-256, 4),
    (100, 7),
    (-100, 7),
    (1073741824, 2),    # 2^30 << 2 overflows i32 intermediate -> wrap
]


def run(cmd: list[str], use_vs_env: bool = False) -> subprocess.CompletedProcess[str]:
    """Wrap a command in VsDevCmd when requested (matches run_obfuscation_tests)."""
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
    # Inject the full attribute list via -D. The annotation spelling is the
    # short form `annotate("+vmp")` (without the leading __), valid inside an
    # __attribute__((...)) list. subprocess.list2cmdline handles the quoting
    # of the embedded quotes and parentheses for the Windows command line.
    if vmp:
        case_attrs = r'-DVMP_CASE_ATTRS=__attribute__((noinline,annotate("+vmp")))'
        flags = [
            str(CLANG),
            str(src),
            case_attrs,
            "-O2",
            "-mllvm", "-taokari",
            "-mllvm", "-taokari-vmp",
            "-o",
            str(out),
        ]
    else:
        case_attrs = r"-DVMP_CASE_ATTRS=__attribute__((noinline))"
        flags = [
            str(CLANG),
            str(src),
            case_attrs,
            "-O2",
            "-o",
            str(out),
        ]
    res = run(flags, use_vs_env=True)
    if res.returncode:
        sys.stderr.write(res.stdout + res.stderr)
        raise SystemExit(1)


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2
    if not SRC.exists():
        print(f"missing source: {SRC}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-vmp-diff-") as tmp:
        tmpdir = Path(tmp)
        native_exe = tmpdir / "native.exe"
        vmp_exe = tmpdir / "vmp.exe"

        compile_exe(SRC, native_exe, vmp=False)
        compile_exe(SRC, vmp_exe, vmp=True)

        failures: list[str] = []
        for a, b in INPUTS:
            native_run = run([str(native_exe), str(a), str(b)])
            vmp_run = run([str(vmp_exe), str(a), str(b)])
            if native_run.returncode:
                print(
                    f"[a={a},b={b}] native exited {native_run.returncode}\n"
                    f"{native_run.stdout}{native_run.stderr}",
                    file=sys.stderr,
                )
                failures.append(f"native-exit a={a},b={b}")
                continue
            if vmp_run.returncode:
                print(
                    f"[a={a},b={b}] vmp exited {vmp_run.returncode}\n"
                    f"{vmp_run.stdout}{vmp_run.stderr}",
                    file=sys.stderr,
                )
                failures.append(f"vmp-exit a={a},b={b}")
                continue
            if native_run.stdout != vmp_run.stdout:
                print(
                    f"[a={a},b={b}] stdout mismatch\n"
                    f"native={native_run.stdout!r}\n"
                    f"vmp    ={vmp_run.stdout!r}",
                    file=sys.stderr,
                )
                failures.append(f"stdout a={a},b={b}")

    if failures:
        print(f"vmp differential: FAIL ({len(failures)} input(s))", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1

    print(f"vmp differential: ok ({len(INPUTS)} inputs)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
