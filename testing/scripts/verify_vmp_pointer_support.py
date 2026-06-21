"""VMP pointer-argument load/store differential verifier."""
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

SOURCE = r"""
#include <stdio.h>

#ifndef VMP
#define VMP __attribute__((noinline))
#endif

VMP int ptr_load_case(int *p) {
  return *p + 3;
}

VMP int ptr_store_case(int *p, int v) {
  *p = v + 5;
  return *p;
}

VMP int ptr_alias_case(int *p, int *q) {
  *p = 10;
  *q = *q + 7;
  return *p;
}

VMP int ptr_gep_load_case(int *p, unsigned i) {
  return p[i & 3] + 9;
}

VMP int ptr_gep_store_case(int *p, unsigned i, int v) {
  p[i & 3] = v - 4;
  return p[i & 3];
}

int main(void) {
  int a = 39;
  int b = 0;
  int c = 1;
  int arr[4] = {3, 5, 7, 11};
  int load = ptr_load_case(&a);
  int store = ptr_store_case(&b, 20);
  int alias = ptr_alias_case(&c, &c);
  int gep_load = ptr_gep_load_case(arr, 6);
  int gep_store = ptr_gep_store_case(arr, 1, 44);
  printf("ptr:%d:%d:%d:%d:%d:%d:%d:%d\n", load, store, b, alias, c,
         gep_load, gep_store, arr[1]);
  return 0;
}
"""


def run(cmd: list[str], *, cwd: Path = ROOT,
        use_vs_env: bool = False) -> subprocess.CompletedProcess[str]:
    if use_vs_env and VSDEVCMD.exists():
        with tempfile.NamedTemporaryFile("w", suffix=".cmd", delete=False,
                                         encoding="utf-8") as handle:
            batch = Path(handle.name)
            handle.write("@echo off\n")
            handle.write(f'call "{VSDEVCMD}" -arch=x64 -host_arch=x64 >nul\n')
            handle.write(subprocess.list2cmdline(cmd) + "\n")
        try:
            return subprocess.run(["cmd.exe", "/c", str(batch)], cwd=cwd,
                                  text=True, capture_output=True)
        finally:
            batch.unlink(missing_ok=True)
    return subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)


def compile_exe(src: Path, out: Path, *, vmp: bool) -> subprocess.CompletedProcess[str]:
    flags = [str(CLANG), str(src), "-O2", "-o", str(out)]
    if vmp:
        flags.extend([
            r'-DVMP=__attribute__((noinline,annotate("+vmp")))',
            "-mllvm", "-taokari", "-mllvm", "-taokari-vmp",
        ])
    return run(flags, use_vs_env=True)


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-vmp-ptr-") as tmp:
        tmpdir = Path(tmp)
        src = tmpdir / "ptr.c"
        native = tmpdir / "native.exe"
        vmp = tmpdir / "vmp.exe"
        ll = tmpdir / "vmp.ll"
        src.write_text(SOURCE, encoding="utf-8")

        native_build = compile_exe(src, native, vmp=False)
        if native_build.returncode:
            sys.stderr.write(native_build.stdout + native_build.stderr)
            return 1
        vmp_build = compile_exe(src, vmp, vmp=True)
        if vmp_build.returncode:
            sys.stderr.write(vmp_build.stdout + vmp_build.stderr)
            return 1

        native_run = run([str(native)])
        vmp_run = run([str(vmp)])
        if native_run.returncode or vmp_run.returncode:
            sys.stderr.write(native_run.stdout + native_run.stderr)
            sys.stderr.write(vmp_run.stdout + vmp_run.stderr)
            return 1
        if native_run.stdout != vmp_run.stdout:
            print("vmp pointer support: FAIL (stdout mismatch)", file=sys.stderr)
            print(f"native={native_run.stdout!r}", file=sys.stderr)
            print(f"vmp={vmp_run.stdout!r}", file=sys.stderr)
            return 1

        ir = run([
            str(CLANG), str(src), "-O2", "-S", "-emit-llvm", "-o", str(ll),
            r'-DVMP=__attribute__((noinline,annotate("+vmp")))',
            "-mllvm", "-taokari", "-mllvm", "-taokari-vmp",
        ], use_vs_env=True)
        if ir.returncode:
            sys.stderr.write(ir.stdout + ir.stderr)
            return 1
        text = ll.read_text(encoding="utf-8", errors="ignore")
        names = set(re.findall(r"@__taokari_vmp_bc_(ptr_\w+_case)", text))
        expected = {
            "ptr_load_case",
            "ptr_store_case",
            "ptr_alias_case",
            "ptr_gep_load_case",
            "ptr_gep_store_case",
        }
        if not expected.issubset(names):
            print(f"vmp pointer support: FAIL (missing bytecode {expected - names})",
                  file=sys.stderr)
            return 1
        if "i64 35, label" not in text or "i64 36, label" not in text:
            print("vmp pointer support: FAIL (external memory handlers missing)",
                  file=sys.stderr)
            return 1
        if "i64 37, label" not in text:
            print("vmp pointer support: FAIL (external GEP handler missing)",
                  file=sys.stderr)
            return 1

    print(f"vmp pointer support: ok ({native_run.stdout.strip()})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
