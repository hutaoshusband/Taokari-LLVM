"""Verify -taokari-max -taokari-max-no-vmp defuses the VMP hang.

Section 22 Phase 1.1: under bare -taokari-max, every non-trivial function
becomes a VMP candidate with no budget cap, so -taokari-max + -taokari-vmp
hangs the compile. -taokari-max-no-vmp forces vmp off while keeping every
other max-strength pass at L4/prob 100.

Contract:
  * Source has many non-trivial functions (so VMP global-enable would hang).
  * Build with -taokari-max -taokari-max-no-vmp finishes under the budget.
  * The VMP compatibility report contains zero virtualized rows.
  * The protected binary still runs correctly.

Exit:
  0 + "max build no-vmp hang: ok"
  1 -- build hung / over budget / leaked VMP / bad output
  2 -- missing clang
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
import time
from pathlib import Path

from verify_vmp_coverage import CLANG, run, VSDEVCMD, ROOT

# Budget from Section 22 Phase 4 (demo target ceiling). The 20-function
# source below is the non-trivial source the plan calls for.
COMPILE_BUDGET_SECONDS = 60

# 20 non-trivial functions: every one would become a VMP candidate under
# bare -taokari-max (no +vmp/-vmp annotation, so toObfuscate falls through
# to the global enable). That is the bomb this verifier defuses.
SOURCE = r'''
#include <stdio.h>

#define NOINLINE __attribute__((noinline))

NOINLINE int f0(int x){return ((x*7)^0x33)+1;}
NOINLINE int f1(int x){return ((x+9)^0x57)-3;}
NOINLINE int f2(int x){return ((x-5)^0x1f)*2;}
NOINLINE int f3(int x){return ((x^0x6a)+13)-4;}
NOINLINE int f4(int x){return ((x*3)^0x2c)+7;}
NOINLINE int f5(int x){return ((x+11)^0x4b)-5;}
NOINLINE int f6(int x){return ((x-7)^0x71)*3;}
NOINLINE int f7(int x){return ((x^0x55)+17)-9;}
NOINLINE int f8(int x){return ((x*5)^0x3e)+2;}
NOINLINE int f9(int x){return ((x+3)^0x88)-1;}
NOINLINE int f10(int x){return ((x-9)^0x29)*5;}
NOINLINE int f11(int x){return ((x^0x7c)+5)-2;}
NOINLINE int f12(int x){return ((x*2)^0x91)+4;}
NOINLINE int f13(int x){return ((x+15)^0x23)-6;}
NOINLINE int f14(int x){return ((x-11)^0x44)*4;}
NOINLINE int f15(int x){return ((x^0x9d)+21)-8;}
NOINLINE int f16(int x){return ((x*6)^0x12)+3;}
NOINLINE int f17(int x){return ((x+1)^0xa3)-7;}
NOINLINE int f18(int x){return ((x-3)^0x5c)*6;}
NOINLINE int f19(int x){return ((x^0xb1)+19)-10;}

int main(void){
  int s=0;
  int(*fs[20])(int)={f0,f1,f2,f3,f4,f5,f6,f7,f8,f9,
                     f10,f11,f12,f13,f14,f15,f16,f17,f18,f19};
  for(int i=0;i<20;++i) s+=fs[i](i+1);
  printf("maxnovmp:%d\n", s);
  return 0;
}
'''


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-maxnovmp-") as tmp:
        tmpdir = Path(tmp)
        src = tmpdir / "src.c"
        exe = tmpdir / "out.exe"
        report = tmpdir / "report.txt"
        src.write_text(SOURCE, encoding="utf-8")

        flags = [
            str(CLANG), "-O2", str(src), "-o", str(exe),
            "-mllvm", "-taokari-max",
            "-mllvm", "-taokari-max-no-vmp",
            "-mllvm", f"-taokari-vmp-compat-report={report}",
        ]

        start = time.monotonic()
        build = run(flags, use_vs_env=True)
        elapsed = time.monotonic() - start
        if build.returncode:
            sys.stderr.write(build.stdout + build.stderr)
            print("max build no-vmp hang: FAIL (build failed)",
                  file=sys.stderr)
            return 1

        if elapsed > COMPILE_BUDGET_SECONDS:
            print(
                f"max build no-vmp hang: FAIL "
                f"(compile {elapsed:.1f}s > {COMPILE_BUDGET_SECONDS}s budget)",
                file=sys.stderr,
            )
            return 1

        # VMP must be fully off: zero virtualized rows in the compat report.
        # No +vmp annotation means no rows should ever be written, but the
        # explicit gate proves the global-enable fallthrough is dead.
        report_text = report.read_text(encoding="utf-8", errors="ignore")
        virtualized_rows = sum(
            1 for line in report_text.splitlines()
            if line and "virtualized" in line.lower()
        )
        if virtualized_rows:
            print(
                f"max build no-vmp hang: FAIL "
                f"({virtualized_rows} virtualized rows leaked into report)",
                file=sys.stderr,
            )
            return 1

        result = run([str(exe)])
        if result.returncode:
            sys.stderr.write(result.stdout + result.stderr)
            print("max build no-vmp hang: FAIL (bad run rc)", file=sys.stderr)
            return 1
        if not result.stdout.startswith("maxnovmp:"):
            print(
                f"max build no-vmp hang: FAIL (bad stdout {result.stdout!r})",
                file=sys.stderr,
            )
            return 1

    print(
        f"max build no-vmp hang: ok (compile {elapsed:.1f}s, "
        f"0 virtualized rows)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
