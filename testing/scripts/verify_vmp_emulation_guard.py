"""Verify level-4 dynamic anti-emulation checks reach VMP interpreters."""
from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

from verify_vmp_basic_block_bytecode import CLANG, ROOT, run


SOURCE = r"""
#include <stdio.h>

#ifdef USE_VMP
#define VMP "+vmp,"
#else
#define VMP ""
#endif

__attribute__((noinline, annotate(VMP "+dyn^dyn=4")))
int guarded(int a, int b) {
  int x = ((a ^ 0x41) + b) * 3;
  return (x & 1) ? x - a : x + b;
}

int main(void) {
  printf("emu:%d:%d\n", guarded(9, 4), guarded(31, 8));
  return 0;
}
"""

INTERP_RE = re.compile(
    r"define[^{@]*@__taokari_vmp_interp_i64_guarded_[^(]*"
    r"\([^)]*\)[^{]*\{(?P<body>.*?)\n\}",
    re.S,
)


def compat_rows(path: Path) -> dict[str, str]:
    rows: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and not line.startswith("function\t"):
            rows[parts[0]] = parts[1]
    return rows


def build(tmp: Path, label: str, use_vmp: bool) -> str:
    src = tmp / f"{label}.c"
    ll = tmp / f"{label}.ll"
    exe = tmp / f"{label}.exe"
    report = tmp / f"{label}.tsv"
    src.write_text(SOURCE, encoding="utf-8")
    flags = [
        str(CLANG), str(src), "-O2", "-fno-discard-value-names",
        "-mllvm", "-taokari", "-mllvm", "-taokari-dyn",
    ]
    if use_vmp:
        flags.insert(1, "-DUSE_VMP=1")
        flags.extend([
            "-mllvm", "-taokari-vmp",
            "-mllvm", f"-taokari-vmp-compat-report={report}",
        ])
    ir = run([*flags, "-S", "-emit-llvm", "-o", str(ll)], use_vs_env=True)
    if ir.returncode:
        sys.stderr.write(ir.stdout + ir.stderr)
        raise SystemExit(ir.returncode)
    built = run([*flags, "-o", str(exe)], use_vs_env=True)
    if built.returncode:
        sys.stderr.write(built.stdout + built.stderr)
        raise SystemExit(built.returncode)
    ran = run([str(exe)])
    if ran.returncode or not ran.stdout.startswith("emu:"):
        sys.stderr.write(ran.stdout + ran.stderr)
        raise SystemExit(1)
    if use_vmp and compat_rows(report).get("guarded") != "virtualized":
        raise SystemExit("guarded did not virtualize")
    return ll.read_text(encoding="utf-8", errors="ignore")


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-vmp-emulation-") as tmp_name:
        tmp = Path(tmp_name)
        dyn_text = build(tmp, "dyn", False)
        vmp_text = build(tmp, "vmp", True)

    if "GetTickCount64" not in dyn_text or "dyn.emu" not in dyn_text:
        raise SystemExit("normal DynamicProtection level 4 lacks emulation guard")
    match = INTERP_RE.search(vmp_text)
    if not match:
        raise SystemExit("missing VMP interpreter")
    body = match.group("body")
    if "GetTickCount64" not in body or "dyn.emu" not in body:
        raise SystemExit("VMP interpreter loop lacks emulation guard")
    if "__taokari_dyn_tamper" not in vmp_text:
        raise SystemExit("VMP emulation guard did not use dynamic tamper flag")

    print("vmp emulation guard: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
