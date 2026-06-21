"""Verify VMP function-pointer call support through typed call stubs."""
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

typedef int (*NodeOp)(Node *, int);
typedef Node *(*PickOp)(Node *, unsigned);

__attribute__((noinline)) int add_node(Node *nodes, int seed) {
  nodes[1].out = nodes[1].base + nodes[1].delta + seed;
  return nodes[1].out;
}

__attribute__((noinline)) Node *pick_node(Node *nodes, unsigned idx) {
  return &nodes[(idx ^ 3u) & 3u];
}

VMP_ATTR int indirect_case(NodeOp op, PickOp pick, Node *nodes, int seed) {
  int first = op(nodes, seed);
  Node *picked = pick(nodes, 2);
  picked->out += first + picked->base;
  return first + picked->out + nodes[1].out;
}

int main(void) {
  Node nodes[4] = {
      {2, 3, 0},
      {5, 7, 0},
      {11, 13, 0},
      {17, 19, 0},
  };
  int got = indirect_case(add_node, pick_node, nodes, 23);
  printf("vmp-indcall:%d:%d:%d\n", got, nodes[1].out, nodes[2].out);
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

    with tempfile.TemporaryDirectory(prefix="taokari-vmp-indcall-") as tmp:
        tmpdir = Path(tmp)
        src = tmpdir / "indcall_vmp.c"
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
        if "@__taokari_vmp_bc_indirect_case" not in vmp_text:
            print("vmp indirect call support: FAIL (caller not virtualized)",
                  file=sys.stderr)
            return 1
        if len(re.findall(r"@__taokari_vmp_indcall_stub_\d+", vmp_text)) < 2:
            print("vmp indirect call support: FAIL (indirect stubs missing)",
                  file=sys.stderr)
            return 1
        if "call ptr %" not in vmp_text:
            print("vmp indirect call support: FAIL (typed indirect call missing)",
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
            print("vmp indirect call support: FAIL (stdout mismatch)", file=sys.stderr)
            print(f"native={native_run.stdout!r}", file=sys.stderr)
            print(f"vmp   ={vmp_run.stdout!r}", file=sys.stderr)
            return 1

    print("vmp indirect call support: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
