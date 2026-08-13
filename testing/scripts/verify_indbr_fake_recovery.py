"""IndBr L3+ lists a fake recovery block on each indirectbr.

The extra destination is not selected by real true/false indices. It
exists so a decompiler sees an error-recovery edge. The recovery block
itself is an always-true opaque predicate into llvm.trap.

Contract:
  * L3 IR contains indbr.recover and an indirectbr with >=3 labels.
  * L2 IR has no indbr.recover.
  * L3 binary matches native.

Exit: 0 ok | 1 contract failure | 2 missing clang.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

CLANG = tp.CLANG
SOURCE = """
#include <stdio.h>
__attribute__((noinline)) int pick(int x) {
  if (x > 0) return x + 3;
  return x - 5;
}
int main(void) {
  printf("indbr:%d\\n", pick(2) + pick(-4));
  return 0;
}
"""


def mllvm(flags: list[str]) -> list[str]:
    out = []
    for f in flags:
        out += ["-mllvm", f]
    return out


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2
    extra = [] if tp.IS_WINDOWS else ["-fdeclspec", "-D_GNU_SOURCE"]
    with tempfile.TemporaryDirectory(prefix="taokari-indbr-rec-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "ib.c"
        src.write_text(SOURCE, encoding="utf-8")
        l3 = tmp / "l3.ll"
        r = tp.run([str(CLANG), str(src), "-O0", "-fno-discard-value-names",
                    *extra,
                    *mllvm(["-taokari", "-taokari-indbr",
                            "-taokari-level-indbr=3"]),
                    "-S", "-emit-llvm", "-o", str(l3)])
        if r.returncode:
            print("FAIL L3 emit\n", r.stderr[:400], file=sys.stderr)
            return 1
        l3t = l3.read_text(encoding="utf-8", errors="ignore")
        l2 = tmp / "l2.ll"
        r = tp.run([str(CLANG), str(src), "-O0", "-fno-discard-value-names",
                    *extra,
                    *mllvm(["-taokari", "-taokari-indbr",
                            "-taokari-level-indbr=2"]),
                    "-S", "-emit-llvm", "-o", str(l2)])
        if r.returncode:
            print("FAIL L2 emit\n", r.stderr[:400], file=sys.stderr)
            return 1
        l2t = l2.read_text(encoding="utf-8", errors="ignore")
        if "indbr.recover" not in l3t:
            print("FAIL: L3 IR has no indbr.recover block", file=sys.stderr)
            return 1
        if "indirectbr" not in l3t:
            print("FAIL: L3 IR has no indirectbr", file=sys.stderr)
            return 1
        has_three = False
        for line in l3t.splitlines():
            if "indirectbr" in line and line.count("label") >= 3:
                has_three = True
                break
        if not has_three:
            print("FAIL: L3 indirectbr has fewer than 3 destinations",
                  file=sys.stderr)
            return 1
        if "indbr.recover" in l2t:
            print("FAIL: L2 IR leaked indbr.recover", file=sys.stderr)
            return 1
        native = tmp / "native"
        r = tp.run([str(CLANG), str(src), "-O0", *extra, "-o", str(native)])
        if r.returncode:
            print("FAIL native", file=sys.stderr)
            return 1
        nrun = tp.run([str(native)])
        obf = tmp / "l3"
        r = tp.run([str(CLANG), str(src), "-O0", *extra,
                    *mllvm(["-taokari", "-taokari-indbr",
                            "-taokari-level-indbr=3"]),
                    "-o", str(obf)])
        if r.returncode:
            print("FAIL L3 build\n", r.stderr[:400], file=sys.stderr)
            return 1
        orun = tp.run([str(obf)])
        if orun.returncode or orun.stdout != nrun.stdout:
            print(f"FAIL L3 rc={orun.returncode} out={orun.stdout!r} "
                  f"want={nrun.stdout!r}", file=sys.stderr)
            return 1
    print("indbr fake recovery: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
