"""Verify VMP partial function splitting around unsupported native islands."""
from __future__ import annotations

import re
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

__attribute__((noinline)) double native_noise(double x) {
  return (x * 1.75) + 3.0;
}

VMP_ATTR int split_case(int x, int y) {
  double d = native_noise((double)(x + y));
  int seed = (int)d;
  if ((seed ^ x) & 1) {
    int mixed = (seed + y) ^ (x * 3);
    seed = mixed - 7;
  }
  return seed + y;
}

int main(void) {
  int a = split_case(13, 5);
  int b = split_case(4, 9);
  printf("vmp-split:%d:%d\n", a, b);
  return 0;
}
'''

BASE_FLAGS = ["-O0", "-Xclang", "-disable-O0-optnone"]
VMP_ATTR = r'-DVMP_ATTR=__attribute__((noinline,annotate("+vmp")))'


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


def must(result: subprocess.CompletedProcess[str]) -> bool:
    if result.returncode:
        sys.stderr.write(result.stdout + result.stderr)
        return False
    return True


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-vmp-split-") as tmp:
        tmpdir = Path(tmp)
        src = tmpdir / "split_vmp.c"
        vmp_ll = tmpdir / "vmp.ll"
        native = tmpdir / "native.exe"
        vmp = tmpdir / "vmp.exe"
        src.write_text(SOURCE, encoding="utf-8")

        vmp_flags = [
            str(CLANG), str(src), VMP_ATTR, *BASE_FLAGS,
            "-mllvm", "-taokari", "-mllvm", "-taokari-vmp",
            "-Rpass=taokari-vmp", "-Rpass-missed=taokari-vmp",
        ]
        ir = run([*vmp_flags, "-S", "-emit-llvm", "-o", str(vmp_ll)],
                 use_vs_env=True)
        if not must(ir):
            return 1
        remarks = ir.stdout + ir.stderr
        if "partially virtualized" not in remarks:
            print("vmp function split support: FAIL (partial remark missing)",
                  file=sys.stderr)
            return 1
        vmp_text = vmp_ll.read_text(encoding="utf-8", errors="ignore")
        if not re.search(r"@__taokari_vmp_bc_.*vmp\.split", vmp_text):
            print("vmp function split support: FAIL (split bytecode missing)",
                  file=sys.stderr)
            return 1
        if re.search(r"@__taokari_vmp_bc_split_case\s*=", vmp_text):
            print("vmp function split support: FAIL (whole function virtualized)",
                  file=sys.stderr)
            return 1

        if not must(run([str(CLANG), str(src), *BASE_FLAGS, "-o", str(native)],
                        use_vs_env=True)):
            return 1
        build = run([*vmp_flags, "-o", str(vmp)], use_vs_env=True)
        if not must(build):
            return 1
        native_run = run([str(native)])
        vmp_run = run([str(vmp)])
        if native_run.returncode or vmp_run.returncode:
            sys.stderr.write(native_run.stdout + native_run.stderr)
            sys.stderr.write(vmp_run.stdout + vmp_run.stderr)
            return 1
        if native_run.stdout != vmp_run.stdout:
            print("vmp function split support: FAIL (stdout mismatch)",
                  file=sys.stderr)
            print(f"native={native_run.stdout!r}", file=sys.stderr)
            print(f"vmp   ={vmp_run.stdout!r}", file=sys.stderr)
            return 1

    print("vmp function split support: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
