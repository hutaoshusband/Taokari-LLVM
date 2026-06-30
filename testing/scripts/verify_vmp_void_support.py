"""Verify VMP support for protected void functions."""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
VSDEVCMD = tp.VSDEVCMD

SOURCE = r'''
#include <stdio.h>

#ifndef VMP_ATTR
#define VMP_ATTR __attribute__((noinline))
#endif

VMP_ATTR void vm_inc(int *p, int a) {
  int v = *p;
  *p = (v + a) ^ 0x5a;
}

VMP_ATTR void vm_mix(int *p, int a) {
  int v = (*p * 3) - a;
  *p = v > 100 ? v - 17 : v + 23;
}

int main(void) {
  int value = 7;
  vm_inc(&value, 11);
  vm_mix(&value, 5);
  printf("vmp-void:%d\n", value);
  return 0;
}
'''


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


def build(src: Path, out: Path, *, vmp: bool) -> int:
    flags = [str(CLANG), str(src), "-O2", "-o", str(out)]
    if vmp:
        flags[2:2] = [
            r'-DVMP_ATTR=__attribute__((noinline,annotate("+vmp")))',
            "-mllvm", "-taokari",
            "-mllvm", "-taokari-vmp",
        ]
    result = run(flags, use_vs_env=True)
    if result.returncode:
        sys.stderr.write(result.stdout + result.stderr)
    return result.returncode


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-vmp-void-") as tmp:
        tmpdir = Path(tmp)
        src = tmpdir / "void_vmp.c"
        native = tmpdir / "native.exe"
        vmp = tmpdir / "vmp.exe"
        ll = tmpdir / "vmp.ll"
        src.write_text(SOURCE, encoding="utf-8")

        if build(src, native, vmp=False) or build(src, vmp, vmp=True):
            return 1
        ir = run([
            str(CLANG), str(src),
            r'-DVMP_ATTR=__attribute__((noinline,annotate("+vmp")))',
            "-O2", "-mllvm", "-taokari", "-mllvm", "-taokari-vmp",
            "-S", "-emit-llvm", "-o", str(ll),
        ], use_vs_env=True)
        if ir.returncode:
            sys.stderr.write(ir.stdout + ir.stderr)
            return 1

        text = ll.read_text(encoding="utf-8", errors="ignore")
        for name in ("vm_inc", "vm_mix"):
            if f"@__taokari_vmp_bc_{name}" not in text:
                print(f"vmp void support: FAIL ({name} not virtualized)",
                      file=sys.stderr)
                return 1

        native_run = run([str(native)])
        vmp_run = run([str(vmp)])
        if native_run.returncode or vmp_run.returncode:
            sys.stderr.write(native_run.stdout + native_run.stderr)
            sys.stderr.write(vmp_run.stdout + vmp_run.stderr)
            return 1
        if native_run.stdout != vmp_run.stdout:
            print("vmp void support: FAIL (stdout mismatch)", file=sys.stderr)
            print(f"native={native_run.stdout!r}", file=sys.stderr)
            print(f"vmp   ={vmp_run.stdout!r}", file=sys.stderr)
            return 1

    print("vmp void support: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
