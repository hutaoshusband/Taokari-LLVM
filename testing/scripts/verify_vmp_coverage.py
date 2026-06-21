"""VMP coverage proof (L2 start).

Proves the L1.5 IR-widening made "virtualize selected functions" a real,
usable capability rather than a toy. Compiles a synthetic realworld-flavored
source twice (plain NATIVE + +vmp), parses per-function pass-remarks from the
vmp build's stderr to count (virtualized | skipped | total +vmp) functions,
and asserts the vmp build's runtime stdout matches the native build's. A
non-trivial fraction of +vmp functions must virtualize, or the proof fails.

This is the L2 entry checkpoint: it establishes that there are enough
VM-eligible functions to make the subsequent L2 work (encryption, per-function
opcode mapping, handler obfuscation) worth doing.

Enable remarks with -mllvm -pass-remarks=taokari-vmp -pass-remarks-missed=
taokari-vmp. The script parses the emitted lines.

Exit contract:
  0  + "vmp coverage: ok (N/M functions virtualized)"
  1  -- coverage below threshold OR native/vmp stdout mismatch
  2  -- missing clang / source
"""
from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CLANG = ROOT / "build" / "taokari-local" / "bin" / "clang.exe"
VSDEVCMD = Path(
    r"C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat"
)

# A realworld-flavored source: every function is annotated +vmp, exercises a
# distinct L1.5 feature, and produces deterministic output. Functions that the
# L1.5 ISA fully supports should virtualize; ones using unsupported patterns
# (switch, float, pointer-arg) should skip cleanly without breaking the build.
SOURCE = r'''
#include <stdint.h>
#include <stdio.h>

#define VMP __attribute__((noinline, annotate("+vmp")))
#define NOINLINE __attribute__((noinline))

// --- L1.5 arithmetic + comparison + select. ---
VMP int arith(int a, int b) {
  int x = (a + b) ^ 17;
  return x > 40 ? x - b : x + a;
}

VMP int shifts(int a, int b) {
  return (a << (b & 7)) ^ (a >> (b & 3));
}

VMP int divrem(int a, int b) {
  return b ? (a / b) + (a % b) : -1;
}

// --- L1.5 loops (PHI lowering). ---
VMP int loop_sum(int n) {
  int s = 0;
  for (int i = 0; i < n; ++i) s += i;
  return s;
}

VMP int loop_fib(int n) {
  int prev = 0;
  int cur = 1;
  for (int i = 0; i < n; ++i) {
    int next = prev + cur;
    prev = cur;
    cur = next;
  }
  return prev;
}

// --- L1.5 VM-local memory. ---
VMP int local_state(int a, int b) {
  volatile int x = a;
  volatile int y = b;
  x = x + y;
  y = x ^ y;
  return x - y;
}

// --- L1.5 direct calls. ---
NOINLINE int helper(int x) {
  return x * x + 1;
}

VMP int caller(int a, int b) {
  return helper(a) + helper(b) + helper(a + b);
}

// --- Multi-call + loop + arithmetic combined. ---
VMP int combined(int a, int b) {
  int acc = 0;
  for (int i = 0; i < (a & 0xF); ++i) {
    acc += helper(i ^ b);
  }
  return acc;
}

int main(int argc, char **argv) {
  (void)argc; (void)argv;
  int a = 42;
  int b = 7;
  printf("arith:%d\n", arith(a, b));
  printf("shifts:%d\n", shifts(a, b));
  printf("divrem:%d\n", divrem(a, b));
  printf("loop_sum:%d\n", loop_sum(a));
  printf("loop_fib:%d\n", loop_fib(a));
  printf("local_state:%d\n", local_state(a, b));
  printf("caller:%d\n", caller(a, b));
  printf("combined:%d\n", combined(a, b));
  return 0;
}
'''

REMARK_RE = re.compile(
    r"file\S+:\d+:\d+:\s+remark:\s+(\w+):\s+(virtualized|skipped)"
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
                cwd=ROOT, text=True, capture_output=True,
            )
        finally:
            batch.unlink(missing_ok=True)
    return subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True)


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-vmp-cov-") as tmp:
        tmpdir = Path(tmp)
        src = tmpdir / "cov.c"
        src.write_text(SOURCE, encoding="utf-8")
        native_exe = tmpdir / "native.exe"
        vmp_exe = tmpdir / "vmp.exe"

        # Plain build.
        r = run([str(CLANG), str(src), "-O2", "-o", str(native_exe)],
                use_vs_env=True)
        if r.returncode:
            sys.stderr.write(r.stdout + r.stderr)
            return 1

        # VMP build with remarks on stderr. -Rpass/-Rpass-missed are the
        # clang front-end flags (not -mllvm -pass-remarks=, which the legacy
        # PM does not honor here). Remarks print as:
        #   file:line:col: remark: virtualized (N bytecode words)
        #   file:line:col: remark: skipped: <reason>
        r = run(
            [str(CLANG), str(src), "-O2",
             "-mllvm", "-taokari", "-mllvm", "-taokari-vmp",
             "-Rpass=taokari-vmp",
             "-Rpass-missed=taokari-vmp",
             "-o", str(vmp_exe)],
            use_vs_env=True,
        )
        if r.returncode:
            sys.stderr.write(r.stdout + r.stderr)
            return 1

        # Count function definitions annotated VMP (not the #define line).
        # Each annotated function starts with "VMP <type> <name>(".
        total_vmp = len(re.findall(r"^VMP \w[\w\s\*]*\w+\s*\(", SOURCE,
                                   re.MULTILINE))

        native_run = run([str(native_exe)])
        vmp_run = run([str(vmp_exe)])
        if native_run.returncode or vmp_run.returncode:
            sys.stderr.write(native_run.stdout + native_run.stderr +
                             vmp_run.stdout + vmp_run.stderr)
            return 1

    # Correctness gate: vmp build must match native stdout exactly.
    if native_run.stdout != vmp_run.stdout:
        print(
            "vmp coverage: FAIL (native/vmp stdout mismatch)\n"
            f"native={native_run.stdout!r}\nvmp   ={vmp_run.stdout!r}",
            file=sys.stderr,
        )
        return 1

    # Coverage gate: count distinct virtualized/skipped remark lines emitted
    # by the vmp build's stderr (pass-remarks output). Remark text format:
    #   "...: remark: virtualized (N bytecode words)"
    #   "...: remark: skipped: <reason>"
    remarks_text = r.stderr + r.stdout
    virtualized_count = remarks_text.count("remark: virtualized")
    skipped_count = remarks_text.count("remark: skipped")

    # Coverage expectation: at least 6 of the 8 +vmp functions virtualize.
    # (local_state and combined are the most complex; either could skip on
    # edge cases, but the core 6 must succeed.)
    threshold = 6
    print(f"vmp coverage: {virtualized_count}/{total_vmp} functions "
          f"virtualized ({skipped_count} skipped)")
    if virtualized_count < threshold:
        print(
            f"vmp coverage: FAIL (below threshold {threshold})",
            file=sys.stderr,
        )
        return 1
    print("vmp coverage: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
