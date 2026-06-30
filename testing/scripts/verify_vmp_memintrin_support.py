"""Verify VMP lowering for memcpy/memset/memmove intrinsics."""
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

VMP_ATTR int mem_ops(unsigned char *buf, unsigned char *tmp, int seed) {
  __builtin_memset(buf, seed & 0xff, 40);
  __builtin_memcpy(buf + 8, tmp, 32);
  __builtin_memmove(buf + 1, buf, 31);
  return buf[0] + buf[1] + buf[7] + buf[8] +
         buf[15] + buf[31] + buf[39];
}

int main(void) {
  unsigned char buf[40] = {0};
  unsigned char tmp[32] = {0};
  for (int i = 0; i < 32; ++i)
    tmp[i] = (unsigned char)(i * 3 + 1);
  int got = mem_ops(buf, tmp, 0x22);
  printf("vmp-memintrin:%d:%u:%u:%u:%u:%u:%u:%u:%u\n",
         got, buf[0], buf[1], buf[7], buf[8], buf[15], buf[31], buf[32], buf[39]);
  return 0;
}
'''

BASE_FLAGS = ["-O1"]
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

    with tempfile.TemporaryDirectory(prefix="taokari-vmp-memintrin-") as tmp:
        tmpdir = Path(tmp)
        src = tmpdir / "memintrin_vmp.c"
        plain_ll = tmpdir / "plain.ll"
        vmp_ll = tmpdir / "vmp.ll"
        native = tmpdir / "native.exe"
        vmp = tmpdir / "vmp.exe"
        src.write_text(SOURCE, encoding="utf-8")

        if not must(run([str(CLANG), str(src), *BASE_FLAGS, "-S",
                         "-emit-llvm", "-o", str(plain_ll)],
                        use_vs_env=True)):
            return 1
        plain_text = plain_ll.read_text(encoding="utf-8", errors="ignore")
        for intrinsic in ("llvm.memset", "llvm.memcpy", "llvm.memmove"):
            if intrinsic not in plain_text:
                print(f"vmp memintrin support: FAIL ({intrinsic} missing in control IR)",
                      file=sys.stderr)
                return 1

        vmp_flags = [
            str(CLANG), str(src), VMP_ATTR, *BASE_FLAGS,
            "-mllvm", "-taokari", "-mllvm", "-taokari-vmp",
        ]
        if not must(run([*vmp_flags, "-S", "-emit-llvm", "-o", str(vmp_ll)],
                        use_vs_env=True)):
            return 1
        vmp_text = vmp_ll.read_text(encoding="utf-8", errors="ignore")
        if "@__taokari_vmp_bc_mem_ops" not in vmp_text:
            print("vmp memintrin support: FAIL (mem_ops not virtualized)",
                  file=sys.stderr)
            return 1

        if not must(run([str(CLANG), str(src), *BASE_FLAGS, "-o", str(native)],
                        use_vs_env=True)):
            return 1
        if not must(run([*vmp_flags, "-o", str(vmp)], use_vs_env=True)):
            return 1
        native_run = run([str(native)])
        vmp_run = run([str(vmp)])
        if native_run.returncode or vmp_run.returncode:
            sys.stderr.write(native_run.stdout + native_run.stderr)
            sys.stderr.write(vmp_run.stdout + vmp_run.stderr)
            return 1
        if native_run.stdout != vmp_run.stdout:
            print("vmp memintrin support: FAIL (stdout mismatch)", file=sys.stderr)
            print(f"native={native_run.stdout!r}", file=sys.stderr)
            print(f"vmp   ={vmp_run.stdout!r}", file=sys.stderr)
            return 1

    print("vmp memintrin support: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
