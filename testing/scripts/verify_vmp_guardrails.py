"""Verify VMP bytecode budget guardrails."""
from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

from verify_vmp_coverage import CLANG, run


def source() -> str:
    return """
#include <stdio.h>

#define VMP __attribute__((noinline, optnone, annotate("+vmp")))
#define VMP_TINY __attribute__((noinline, annotate("+vmp")))

VMP_TINY int small_case(int x) {
  return x + 1;
}

VMP int oversized_case(int x) {
  return ((x + 3) ^ 7) - 2;
}

int main(void) {
  printf("guard:%d:%d\\n", small_case(9), oversized_case(3));
  return 0;
}
"""


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-vmp-guard-") as tmp:
        tmpdir = Path(tmp)
        src = tmpdir / "guard.c"
        ll = tmpdir / "guard.ll"
        exe = tmpdir / "guard.exe"
        src.write_text(source(), encoding="utf-8")
        flags = [
            str(CLANG), str(src), "-O2",
            "-mllvm", "-taokari", "-mllvm", "-taokari-vmp",
            "-mllvm", "-taokari-vmp-max-bytecode-words=32",
            "-Rpass=taokari-vmp", "-Rpass-missed=taokari-vmp",
        ]

        ir = run([*flags, "-S", "-emit-llvm", "-o", str(ll)],
                 use_vs_env=True)
        if ir.returncode:
            sys.stderr.write(ir.stdout + ir.stderr)
            return 1
        remarks = ir.stdout + ir.stderr
        if "remark: virtualized" not in remarks:
            print("vmp guardrails: FAIL (normal function not virtualized)",
                  file=sys.stderr)
            return 1
        if "bytecode size budget exceeded" not in remarks:
            print("vmp guardrails: FAIL (oversized function not refused)",
                  file=sys.stderr)
            return 1

        text = ll.read_text(encoding="utf-8", errors="ignore")
        if "@__taokari_vmp_bc_small_case" not in text:
            print("vmp guardrails: FAIL (small bytecode missing)",
                  file=sys.stderr)
            return 1
        if re.search(r"@__taokari_vmp_bc_oversized_case\\b", text):
            print("vmp guardrails: FAIL (oversized bytecode emitted)",
                  file=sys.stderr)
            return 1

        build = run([*flags, "-o", str(exe)], use_vs_env=True)
        if build.returncode:
            sys.stderr.write(build.stdout + build.stderr)
            return 1
        result = run([str(exe)])
        if result.returncode:
            sys.stderr.write(result.stdout + result.stderr)
            return 1
        if not result.stdout.startswith("guard:"):
            print(f"vmp guardrails: FAIL (bad stdout {result.stdout!r})",
                  file=sys.stderr)
            return 1

    print("vmp guardrails: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
