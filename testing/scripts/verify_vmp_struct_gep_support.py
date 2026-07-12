"""Verify VMP lowering for multi-index and struct-field GEPs."""
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

typedef struct Node {
  int a;
  unsigned char tag;
  int b;
  int c[3];
} Node;

VMP_ATTR int struct_gep(Node *nodes, int idx) {
  int mix = nodes[idx].c[2] + nodes[idx].tag;
  nodes[idx].b += mix;
  nodes[idx + 1].c[1] = (nodes[idx + 1].c[1] ^ nodes[idx].a) + nodes[idx].tag;
  return nodes[idx].b + nodes[idx + 1].c[1] + nodes[idx].c[0];
}

int main(void) {
  Node nodes[4] = {
      {3, 1, 11, {7, 13, 17}},
      {5, 9, 19, {23, 29, 31}},
      {37, 4, 41, {43, 47, 53}},
      {59, 6, 61, {67, 71, 73}},
  };
  int got = struct_gep(nodes, 1);
  printf("vmp-struct-gep:%d:%d:%d:%u\n",
         got, nodes[1].b, nodes[2].c[1], nodes[1].tag);
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

    with tempfile.TemporaryDirectory(prefix="taokari-vmp-struct-gep-") as tmp:
        tmpdir = Path(tmp)
        src = tmpdir / "struct_gep_vmp.c"
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
        if "getelementptr" not in plain_text or "struct_gep" not in plain_text:
            print("vmp struct GEP support: FAIL (control IR has no struct GEP)",
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
        if "@__taokari_vmp_bc_struct_gep" not in vmp_text:
            print("vmp struct GEP support: FAIL (struct_gep not virtualized)",
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
            print("vmp struct GEP support: FAIL (stdout mismatch)", file=sys.stderr)
            print(f"native={native_run.stdout!r}", file=sys.stderr)
            print(f"vmp   ={vmp_run.stdout!r}", file=sys.stderr)
            return 1

    print("vmp struct GEP support: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
