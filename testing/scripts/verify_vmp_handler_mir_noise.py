from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
import _taokari_portable as tp

from verify_machine_obf_level2 import DIRTY_GUARDS, JUNK, SUB


ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
OBJDUMP = tp.tool("llvm-objdump")
VSDEVCMD = tp.VSDEVCMD

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


def run_vs(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    if not tp.IS_WINDOWS:
      return subprocess.run(command, cwd=cwd, text=True, capture_output=True)
    with tempfile.NamedTemporaryFile("w", suffix=".cmd", delete=False,
                                     encoding="utf-8") as handle:
        batch = Path(handle.name)
        handle.write(
            "@echo off\n"
            f'call "{VSDEVCMD}" -arch=x64 -host_arch=x64 >nul\n'
            f"{subprocess.list2cmdline(command)}\n"
            "exit /b %ERRORLEVEL%\n"
        )
    try:
        return run(["cmd.exe", "/d", "/c", str(batch)], cwd=cwd)
    finally:
        batch.unlink(missing_ok=True)


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

    tmp = Path(tempfile.mkdtemp(prefix="taokari-vmp-mir-"))
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
        ]
        must(run_vs([*flags, "-c", "-o", str(obj)], src.parent), "build obj")
        body = function_bytes(obj, "__taokari_vmp_interp_i64_guarded_")
        if not any(pattern in body for pattern in DIRTY_GUARDS):
            raise SystemExit("VMP interpreter body lacks MIR dirtybytes")
        if JUNK not in body:
            raise SystemExit("VMP interpreter body lacks MIR junk")
        if SUB not in body:
            raise SystemExit("VMP interpreter body lacks MIR substitution")
        must(run_vs([*flags, "-o", str(exe)], src.parent), "build exe")
        ran = run([str(exe)])
        must(ran, "run exe")
        if not ran.stdout.startswith("vmp-mir:"):
            raise SystemExit(f"bad output: {ran.stdout!r}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("vmp handler MIR noise: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
