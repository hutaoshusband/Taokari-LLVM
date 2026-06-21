"""Build and validate a fully virtualized max-protection VMP sample."""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CLANG = ROOT / "build" / "taokari-local" / "bin" / "clang.exe"
OUT = ROOT / "build" / "vmp-validation"
VSDEVCMD = Path(
    r"C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat"
)

SOURCE = r'''
#include <stdint.h>
#include <stdio.h>

#define VMP __attribute__((noinline, annotate("+vmp")))
#define NO_VMP __attribute__((annotate("-vmp")))

VMP int vm_mix(int a, int b) {
  int x = ((a + b) ^ 0x1357) - (a & b);
  return x > 900 ? x - b : x + a;
}

VMP int vm_shift(int a, int b) {
  return (a << (b & 7)) ^ ((uint32_t)a >> (b & 3));
}

VMP int vm_divrem(int a, int b) {
  return b ? (a / b) ^ (a % b) : -99;
}

VMP int vm_cmp(int a, int b) {
  int x = (a ^ b) + 41;
  return x >= 128 ? x - a : x + b;
}

VMP int vm_bits(int a, int b) {
  int x = (a & 0x55AA) | (b ^ 0x33CC);
  return (x ^ (a - b)) + (a | b);
}

VMP int vm_helper(int x) {
  return (x * x) + 17;
}

VMP int vm_call(int a, int b) {
  return vm_helper(a) + vm_helper(b) - vm_helper(a - b);
}

NO_VMP int main(void) {
  int a = 37;
  int b = 11;
  printf("full-vmp:%d:%d:%d:%d:%d:%d:%d\n",
         vm_mix(a, b), vm_shift(a, b), vm_divrem(a, b), vm_cmp(a, b),
         vm_bits(a, b), vm_helper(a), vm_call(a, b));
  return 0;
}
'''

MAX_FLAGS = [
    "-O2",
    "-mllvm", "-taokari",
    "-mllvm", "-taokari-vmp",
    "-mllvm", "-taokari-level-vmp=4",
    "-mllvm", "-taokari-indbr",
    "-mllvm", "-taokari-icall",
    "-mllvm", "-taokari-indgv",
    "-mllvm", "-taokari-fla",
    "-mllvm", "-taokari-bcf",
    "-mllvm", "-taokari-mba",
    "-mllvm", "-taokari-cse",
    "-mllvm", "-taokari-cie",
    "-mllvm", "-taokari-cfe",
    "-mllvm", "-taokari-meta",
    "-mllvm", f"-taokari-cfg={ROOT / 'testing' / 'configs' / 'rtti.json'}",
]

LEVEL_FLAGS = [
    "indbr", "icall", "indgv", "fla", "bcf", "mba", "cie", "cfe", "meta"
]


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


def compile_exe(src: Path, out: Path, max_protection: bool) -> subprocess.CompletedProcess[str]:
    flags = [str(CLANG), str(src), "-o", str(out)]
    if max_protection:
        flags[2:2] = MAX_FLAGS
        for name in LEVEL_FLAGS:
            flags[2:2] = ["-mllvm", f"-taokari-level-{name}=4"]
        flags[2:2] = ["-Rpass=taokari-vmp", "-Rpass-missed=taokari-vmp"]
    else:
        flags[2:2] = ["-O2"]
    return run(flags, use_vs_env=True)


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    OUT.mkdir(parents=True, exist_ok=True)
    src = OUT / "full_vmp_sample.c"
    native = OUT / "full_vmp_native.exe"
    protected = OUT / "full_vmp_max_vmp.exe"
    src.write_text(SOURCE, encoding="utf-8")

    for exe in (native, protected):
        exe.unlink(missing_ok=True)

    native_build = compile_exe(src, native, max_protection=False)
    if native_build.returncode:
        sys.stderr.write(native_build.stdout + native_build.stderr)
        return 1

    max_build = compile_exe(src, protected, max_protection=True)
    if max_build.returncode:
        sys.stderr.write(max_build.stdout + max_build.stderr)
        return 1

    native_run = run([str(native)])
    max_run = run([str(protected)])
    if native_run.returncode or max_run.returncode:
        sys.stderr.write(native_run.stdout + native_run.stderr)
        sys.stderr.write(max_run.stdout + max_run.stderr)
        return 1
    if native_run.stdout != max_run.stdout:
        print("vmp full virtualization: FAIL (stdout mismatch)", file=sys.stderr)
        print(f"native={native_run.stdout!r}", file=sys.stderr)
        print(f"max   ={max_run.stdout!r}", file=sys.stderr)
        return 1

    target_count = len(re.findall(r"^VMP\s+int\s+vm_", SOURCE, re.MULTILINE))
    remarks = max_build.stdout + max_build.stderr
    virtualized = remarks.count("remark: virtualized")
    skipped = remarks.count("remark: skipped")
    if virtualized != target_count or skipped:
        print(
            f"vmp full virtualization: FAIL ({virtualized}/{target_count} "
            f"virtualized, {skipped} skipped)",
            file=sys.stderr,
        )
        sys.stderr.write(remarks)
        return 1

    print(f"vmp full virtualization: ok ({virtualized}/{target_count})")
    print(f"binary: {protected}")
    print(max_run.stdout, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
