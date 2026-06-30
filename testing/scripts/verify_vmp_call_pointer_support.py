"""Verify VMP direct calls with pointer args and pointer returns."""
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

typedef struct Node {
  int base;
  int delta;
  int out;
} Node;

__attribute__((noinline)) int native_add(Node *nodes, int idx, int seed) {
  nodes[idx].out = nodes[idx].base + nodes[idx].delta + seed;
  return nodes[idx].out;
}

__attribute__((noinline)) Node *native_pick(Node *nodes, unsigned idx) {
  return &nodes[(idx ^ 3u) & 3u];
}

VMP_ATTR int call_pointer_case(Node *nodes, int seed) {
  int a = native_add(nodes, 1, seed);
  Node *picked = native_pick(nodes, 2);
  picked->out += a + picked->base;
  return picked->out + nodes[1].out;
}

int main(void) {
  Node nodes[4] = {
      {3, 5, 0},
      {7, 11, 0},
      {13, 17, 0},
      {19, 23, 0},
  };
  int got = call_pointer_case(nodes, 29);
  printf("vmp-call-ptr:%d:%d:%d\n", got, nodes[1].out, nodes[2].out);
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

    with tempfile.TemporaryDirectory(prefix="taokari-vmp-call-ptr-") as tmp:
        tmpdir = Path(tmp)
        src = tmpdir / "call_ptr_vmp.c"
        vmp_ll = tmpdir / "vmp.ll"
        native = tmpdir / "native.exe"
        vmp = tmpdir / "vmp.exe"
        src.write_text(SOURCE, encoding="utf-8")

        vmp_flags = [
            str(CLANG), str(src), VMP_ATTR, *BASE_FLAGS,
            "-mllvm", "-taokari", "-mllvm", "-taokari-vmp",
        ]
        if not must(run([*vmp_flags, "-S", "-emit-llvm", "-o", str(vmp_ll)],
                        use_vs_env=True)):
            return 1
        vmp_text = vmp_ll.read_text(encoding="utf-8", errors="ignore")
        if "@__taokari_vmp_bc_call_pointer_case" not in vmp_text:
            print("vmp call pointer support: FAIL (caller not virtualized)",
                  file=sys.stderr)
            return 1
        thunks = set(re.findall(r"@__taokari_vmp_callthunk_(\w+)", vmp_text))
        if not {"native_add", "native_pick"}.issubset(thunks):
            print("vmp call pointer support: FAIL (pointer call thunks missing)",
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
            print("vmp call pointer support: FAIL (stdout mismatch)", file=sys.stderr)
            print(f"native={native_run.stdout!r}", file=sys.stderr)
            print(f"vmp   ={vmp_run.stdout!r}", file=sys.stderr)
            return 1

    print("vmp call pointer support: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
