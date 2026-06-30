"""Verify VMP handler bodies carry MBA-shaped arithmetic noise."""
from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path
import _taokari_portable as tp

from verify_vmp_basic_block_bytecode import CLANG, ROOT, run


SOURCE = r"""
#include <stdio.h>

#define VMP __attribute__((noinline, annotate("+vmp")))

VMP int mba_mix(int a, int b) {
  int x = (a + b) ^ 0x55;
  int y = (a * 7) - (b | 3);
  if ((x & 1) != 0)
    y += x / 3;
  else
    y ^= x << 2;
  return (y % 17) + (x & y);
}

int main(void) {
  printf("vmp-handler-mba:%d:%d\n", mba_mix(31, 7), mba_mix(12, 5));
  return 0;
}
"""


def compat_rows(path: Path) -> dict[str, str]:
    rows: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and not line.startswith("function\t"):
            rows[parts[0]] = parts[1]
    return rows


def check_ir(text: str, report: Path) -> None:
    if compat_rows(report).get("mba_mix") != "virtualized":
        raise SystemExit("mba_mix did not virtualize")
    if "__taokari_vmp_handler_noise_mba_mix_" not in text:
        raise SystemExit("handler MBA sink global missing")

    counts = {
        "and": len(re.findall(r"%h\.and\d* = and i64", text)),
        "shl": len(re.findall(r"%h\.shl\d* = shl i64", text)),
        "xor": len(re.findall(r"%h\.xor\d* = xor i64", text)),
        "sum": len(re.findall(r"%h\.sum\d* = add i64", text)),
        "store": len(re.findall(
            r"store i64 %h\.sum\d*, ptr @__taokari_vmp_handler_noise_mba_mix_",
            text,
        )),
    }
    missing = [name for name, count in counts.items() if count < 8]
    if missing:
        raise SystemExit(f"handler MBA shape too sparse: {counts}")


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-vmp-handler-mba-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "handler_mba.c"
        ll = tmp / "handler_mba.ll"
        exe = tmp / "handler_mba.exe"
        report = tmp / "handler_mba.tsv"
        src.write_text(SOURCE, encoding="utf-8")
        flags = [
            str(CLANG), str(src), "-O2", "-fno-discard-value-names",
            "-mllvm", "-taokari", "-mllvm", "-taokari-vmp",
            "-mllvm", f"-taokari-vmp-compat-report={report}",
        ]
        ir = run([*flags, "-S", "-emit-llvm", "-o", str(ll)],
                 use_vs_env=True)
        if ir.returncode:
            sys.stderr.write(ir.stdout + ir.stderr)
            return 1
        build = run([*flags, "-o", str(exe)], use_vs_env=True)
        if build.returncode:
            sys.stderr.write(build.stdout + build.stderr)
            return 1
        result = run([str(exe)])
        if result.returncode or not result.stdout.startswith("vmp-handler-mba:"):
            sys.stderr.write(result.stdout + result.stderr)
            return 1
        check_ir(ll.read_text(encoding="utf-8", errors="ignore"), report)

    print("vmp handler MBA: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
