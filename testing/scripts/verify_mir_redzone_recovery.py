from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

from _mir_signatures import DIRTY_VARIANTS, JUNK, SUB_VARIANTS

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
OBJDUMP = tp.tool("llvm-objdump")

SOURCE = r"""
#include <stdio.h>

__attribute__((noinline, annotate("+vmp")))
int guarded(int a, int b) {
  int x = ((a + b) ^ 0x51) * 7;
  return (x & 3) ? x - a : x + b;
}

int main(void) {
  printf("vmp-mir:%d:%d\n", guarded(9, 4), guarded(31, 8));
  return 0;
}
"""


def run(command: list[str], **kw) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, **kw)


def must(result: subprocess.CompletedProcess[str], label: str) -> None:
    if result.returncode:
        print(result.stdout, end="")
        print(result.stderr, end="", file=sys.stderr)
        raise SystemExit(f"{label} failed: {result.returncode}")


def function_bytes(obj: Path, name_prefix: str) -> bytes:
    result = run([str(OBJDUMP), "-d", str(obj)])
    must(result, "objdump")
    match = re.search(
        r"<(" + re.escape(name_prefix) + r"[^>]*)>:\n(?P<body>.*?)(?:\n\n|\Z)",
        result.stdout,
        re.S,
    )
    if not match:
        raise SystemExit(f"missing symbol prefix {name_prefix}")
    values: list[int] = []
    for line in match.group("body").splitlines():
        if ":" not in line:
            continue
        tail = line.split(":", 1)[1]
        for token in tail.strip().split():
            if re.fullmatch(r"[0-9a-fA-F]{2}", token):
                values.append(int(token, 16))
            else:
                break
    return bytes(values)


def main() -> int:
    for tool in (CLANG, OBJDUMP):
        if not tool.exists():
            print(f"missing tool: {tool}", file=sys.stderr)
            return 2

    tmp = Path(tempfile.mkdtemp(prefix="taokari-mir-recovery-"))
    try:
        src = tmp / "vmp_mir.c"
        obj = tmp / "vmp_mir.obj"
        exe = tmp / "vmp_mir.exe"
        src.write_text(SOURCE, encoding="utf-8")
        flags = [
            str(CLANG), str(src), "-O2", "-fno-discard-value-names",
            "-mllvm", "-taokari", "-mllvm", "-taokari-vmp",
            "-mllvm", "-verify-machineinstrs",
            "-mllvm", "-taokari-mir=dirtybytes,junk,sub",
            "-mllvm", "-taokari-mir-verbose",
        ]
        # Contract: the +vmp interpreter carries no-red-zone and PEI gives it
        # a real frame, so the SysV red-zone safety gate must NOT refuse it.
        # Every build must receive all three MIR subpass signatures in the
        # interpreter body (subpass probabilities default to 100), and no
        # build may be skipped for "live values below RSP".
        for _ in range(3):
            built = run([*flags, "-c", "-o", str(obj)], cwd=src.parent)
            must(built, "build obj")
            if "live values below RSP" in built.stderr:
                print(built.stderr, end="", file=sys.stderr)
                raise SystemExit(
                    "red-zone safety gate refused a framed function "
                    "(keepsLiveBelowRsp false positive is back)")
            body = function_bytes(obj, "__taokari_vmp_interp_i64_guarded_")
            missing = [n for n, pats in (
                ("dirtybytes", DIRTY_VARIANTS), ("junk", (JUNK,)),
                ("sub", SUB_VARIANTS)) if not any(p in body for p in pats)]
            if missing:
                raise SystemExit(
                    f"VMP interpreter lacks MIR {', '.join(missing)}")
        must(run([*flags, "-o", str(exe)], cwd=src.parent), "build exe")
        ran = run([str(exe)])
        must(ran, "run exe")
        if not ran.stdout.startswith("vmp-mir:"):
            raise SystemExit(f"bad output: {ran.stdout!r}")
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)

    print("mir redzone recovery: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
