"""Verify VMP handler bodies include bogus-control-flow diamonds."""
from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

from verify_vmp_basic_block_bytecode import CLANG, ROOT, run


SOURCE = r"""
#include <stdio.h>

#define VMP __attribute__((noinline, annotate("+vmp")))

VMP int bcf_mix(int a, int b) {
  int x = (a ^ b) + 13;
  int y = (a * 5) - (b * 3);
  if ((x & 2) != 0)
    y += x / 5;
  else
    y ^= x << 1;
  return (y % 19) ^ (x | y);
}

int main(void) {
  printf("vmp-handler-bcf:%d:%d\n", bcf_mix(31, 7), bcf_mix(12, 5));
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
    if compat_rows(report).get("bcf_mix") != "virtualized":
        raise SystemExit("bcf_mix did not virtualize")
    if "__taokari_vmp_handler_noise_bcf_mix_" not in text:
        raise SystemExit("handler BCF sink global missing")

    counts = {
        "real": len(re.findall(r"(?m)^.*\.bcf\.real:", text)),
        "fake": len(re.findall(r"(?m)^.*\.bcf\.fake:", text)),
        "prod": len(re.findall(r"%h\.bcf\.prod\d* = mul i64", text)),
        "bit": len(re.findall(r"%h\.bcf\.bit\d* = and i64", text)),
        "cond": len(re.findall(r"%h\.bcf\.cond\d* = icmp eq i64", text)),
        "fake_store": len(re.findall(
            r"store i64 %h\.bcf\.fake\.mix\d*, ptr "
            r"@__taokari_vmp_handler_noise_bcf_mix_",
            text,
        )),
    }
    missing = [name for name, count in counts.items() if count < 8]
    if missing:
        raise SystemExit(f"handler BCF shape too sparse: {counts}")


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-vmp-handler-bcf-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "handler_bcf.c"
        ll = tmp / "handler_bcf.ll"
        exe = tmp / "handler_bcf.exe"
        report = tmp / "handler_bcf.tsv"
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
        if result.returncode or not result.stdout.startswith("vmp-handler-bcf:"):
            sys.stderr.write(result.stdout + result.stderr)
            return 1
        check_ir(ll.read_text(encoding="utf-8", errors="ignore"), report)

    print("vmp handler BCF: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
