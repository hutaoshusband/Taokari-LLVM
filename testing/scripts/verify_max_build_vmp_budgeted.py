"""Verify -taokari-max -taokari-vmp finishes under budget with caps on.

Section 22 Phase 1.2/1.3/1.4: the three VMP budget caps now default on
(64 back edges, 32x bytecode expansion, 2048 words). This verifier
proves that even with bare `-taokari-max -taokari-vmp` (no escape
hatch) the build finishes fast and the caps refuse runaway functions
instead of hanging.

Contract:
  * Source has many non-trivial functions under bare -taokari-vmp.
  * Build with -taokari-max -taokari-vmp finishes under the budget.
  * The binary runs and exits without STATUS_ACCESS_VIOLATION.

Exit:
  0 + "max build vmp budgeted: ok"
  1 -- build hung / over budget / access violation / bad output
  2 -- missing clang
"""
from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

from verify_vmp_coverage import CLANG, run

COMPILE_BUDGET_SECONDS = 120

# Same 20-function source as verify_max_build_no_vmp_hang.py: every
# function is non-trivial so under bare -taokari-max -taokari-vmp every
# one becomes a VM candidate. The Phase 1 caps must refuse the runaway
# ones and let the build finish fast.
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
  printf("maxvmp:%d\n", s);
  return 0;
}
'''


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-maxvmp-") as tmp:
        tmpdir = Path(tmp)
        src = tmpdir / "src.c"
        exe = tmpdir / "out.exe"
        report = tmpdir / "report.txt"
        src.write_text(SOURCE, encoding="utf-8")

        # Bare -taokari-max -taokari-vmp: no escape hatch. The three
        # Phase 1 caps (back edges=64, expansion=32, words=2048) must
        # refuse the functions that would hang the build and let it
        # finish under budget.
        flags = [
            str(CLANG), "-O2", str(src), "-o", str(exe),
            "-mllvm", "-taokari-max",
            "-mllvm", "-taokari-vmp",
            "-mllvm", f"-taokari-vmp-compat-report={report}",
        ]

        start = time.monotonic()
        build = run(flags, use_vs_env=True)
        elapsed = time.monotonic() - start
        if build.returncode:
            sys.stderr.write(build.stdout + build.stderr)
            print("max build vmp budgeted: FAIL (build failed)",
                  file=sys.stderr)
            return 1

        if elapsed > COMPILE_BUDGET_SECONDS:
            print(
                f"max build vmp budgeted: FAIL "
                f"(compile {elapsed:.1f}s > {COMPILE_BUDGET_SECONDS}s budget)",
                file=sys.stderr,
            )
            return 1

        result = run([str(exe)])
        # STATUS_ACCESS_VIOLATION on Windows is 0xC0000005 -> return code -1073741819.
        if result.returncode == -1073741819 or result.returncode == 0xC0000005:
            print("max build vmp budgeted: FAIL (STATUS_ACCESS_VIOLATION)",
                  file=sys.stderr)
            return 1
        if result.returncode:
            sys.stderr.write(result.stdout + result.stderr)
            print("max build vmp budgeted: FAIL (bad run rc)",
                  file=sys.stderr)
            return 1
        if not result.stdout.startswith("maxvmp:"):
            print(
                f"max build vmp budgeted: FAIL (bad stdout {result.stdout!r})",
                file=sys.stderr,
            )
            return 1

    print(f"max build vmp budgeted: ok (compile {elapsed:.1f}s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
