"""Verify VMP bytecode budget guardrails."""
from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

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


def hot_loop_source() -> str:
    return """
#include <stdio.h>

#define VMP __attribute__((noinline, annotate("+vmp")))

volatile int loop_seed = 1;

VMP int straight_case(int x) {
  return (x * 3) + 1;
}

VMP int hot_loop_case(int x) {
  int s = 0;
  for (int i = 0; i < x; ++i) s += i ^ loop_seed;
  return s;
}

int main(void) {
  printf("hot:%d:%d\\n", straight_case(4), hot_loop_case(6));
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

        hot_src = tmpdir / "hot.c"
        hot_ll = tmpdir / "hot.ll"
        hot_exe = tmpdir / "hot.exe"
        hot_src.write_text(hot_loop_source(), encoding="utf-8")
        hot_flags = [
            str(CLANG), str(hot_src), "-O2",
            "-mllvm", "-taokari", "-mllvm", "-taokari-vmp",
            "-mllvm", "-taokari-vmp-max-bytecode-words=0",
            "-mllvm", "-taokari-vmp-max-back-edges=0",
            "-Rpass=taokari-vmp", "-Rpass-missed=taokari-vmp",
        ]
        hot_ir = run([*hot_flags, "-S", "-emit-llvm", "-o", str(hot_ll)],
                     use_vs_env=True)
        if hot_ir.returncode:
            sys.stderr.write(hot_ir.stdout + hot_ir.stderr)
            return 1
        hot_remarks = hot_ir.stdout + hot_ir.stderr
        if "hot-loop budget exceeded" not in hot_remarks:
            print("vmp guardrails: FAIL (hot loop not refused)",
                  file=sys.stderr)
            return 1
        hot_text = hot_ll.read_text(encoding="utf-8", errors="ignore")
        if "@__taokari_vmp_bc_straight_case" not in hot_text:
            print("vmp guardrails: FAIL (straight bytecode missing)",
                  file=sys.stderr)
            return 1
        if re.search(r"@__taokari_vmp_bc_hot_loop_case\\b", hot_text):
            print("vmp guardrails: FAIL (hot loop bytecode emitted)",
                  file=sys.stderr)
            return 1
        hot_build = run([*hot_flags, "-o", str(hot_exe)], use_vs_env=True)
        if hot_build.returncode:
            sys.stderr.write(hot_build.stdout + hot_build.stderr)
            return 1
        hot_result = run([str(hot_exe)])
        if hot_result.returncode:
            sys.stderr.write(hot_result.stdout + hot_result.stderr)
            return 1
        if not hot_result.stdout.startswith("hot:"):
            print(f"vmp guardrails: FAIL (bad hot stdout {hot_result.stdout!r})",
                  file=sys.stderr)
            return 1

        expansion_ll = tmpdir / "expansion.ll"
        expansion_exe = tmpdir / "expansion.exe"
        expansion_flags = [
            str(CLANG), str(src), "-O2",
            "-mllvm", "-taokari", "-mllvm", "-taokari-vmp",
            "-mllvm", "-taokari-vmp-max-bytecode-words=0",
            "-mllvm", "-taokari-vmp-max-bytecode-expansion=1",
            "-Rpass=taokari-vmp", "-Rpass-missed=taokari-vmp",
        ]
        expansion_ir = run(
            [*expansion_flags, "-S", "-emit-llvm", "-o", str(expansion_ll)],
            use_vs_env=True)
        if expansion_ir.returncode:
            sys.stderr.write(expansion_ir.stdout + expansion_ir.stderr)
            return 1
        expansion_remarks = expansion_ir.stdout + expansion_ir.stderr
        if "bytecode expansion budget exceeded" not in expansion_remarks:
            print("vmp guardrails: FAIL (expansion budget not enforced)",
                  file=sys.stderr)
            return 1
        expansion_build = run([*expansion_flags, "-o", str(expansion_exe)],
                              use_vs_env=True)
        if expansion_build.returncode:
            sys.stderr.write(expansion_build.stdout + expansion_build.stderr)
            return 1
        expansion_result = run([str(expansion_exe)])
        if expansion_result.returncode:
            sys.stderr.write(expansion_result.stdout + expansion_result.stderr)
            return 1
        if not expansion_result.stdout.startswith("guard:"):
            print("vmp guardrails: FAIL (bad expansion fallback stdout)",
                  file=sys.stderr)
            return 1

    print("vmp guardrails: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
