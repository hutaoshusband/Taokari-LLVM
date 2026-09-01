"""Verify VMP raw SwitchInst lowering."""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
VSDEVCMD = tp.VSDEVCMD

SOURCE = r'''
#include <stdio.h>

#ifndef VMP_ATTR
#define VMP_ATTR __attribute__((noinline))
#endif

VMP_ATTR int switch_case(int x) {
  switch (x & 15) {
  case 0: return x + 101;
  case 1: return x - 17;
  case 5: return (x * 3) ^ 0x55;
  case 9: return x + 777;
  case 14: return x ^ 0x1234;
  default: return (x ^ 0x33) - 7;
  }
}

int main(void) {
  int acc = 0;
  for (int i = 0; i < 32; ++i)
    acc += switch_case((i * 7) - 13);
  printf("vmp-switch:%d\n", acc);
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

    with tempfile.TemporaryDirectory(prefix="taokari-vmp-switch-") as tmp:
        tmpdir = Path(tmp)
        src = tmpdir / "switch_vmp.c"
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
        if "switch i" not in plain_text:
            print("vmp switch support: FAIL (control IR has no raw switch)",
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
        if "@__taokari_vmp_bc_switch_case" not in vmp_text:
            print("vmp switch support: FAIL (switch_case not virtualized)",
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
            print("vmp switch support: FAIL (stdout mismatch)", file=sys.stderr)
            print(f"native={native_run.stdout!r}", file=sys.stderr)
            print(f"vmp   ={vmp_run.stdout!r}", file=sys.stderr)
            return 1

    print("vmp switch support: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
