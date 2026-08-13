"""IndGV L2+ splits each encrypted pointer into two additive shares.

The objects array stores Enc+Share; a parallel _objects_share table holds
Share. Reconstructing a pointer requires both arrays.

Contract:
  * L2 IR contains _IndirectGVs_objects_share.
  * L1 IR does not.
  * L2 binary matches native.

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
static int G = 7;
__attribute__((noinline)) int add(int x) { return G + x; }
int main(void) {
  printf("indgv:%d\\n", add(3) + add(4));
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
    with tempfile.TemporaryDirectory(prefix="taokari-indgv-share-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "gv.c"
        src.write_text(SOURCE, encoding="utf-8")
        l2 = tmp / "l2.ll"
        r = tp.run([str(CLANG), str(src), "-O0", "-fno-discard-value-names",
                    *extra,
                    *mllvm(["-taokari", "-taokari-indgv",
                            "-taokari-level-indgv=2"]),
                    "-S", "-emit-llvm", "-o", str(l2)])
        if r.returncode:
            print("FAIL L2 emit\n", r.stderr[:400], file=sys.stderr)
            return 1
        l2t = l2.read_text(encoding="utf-8", errors="ignore")
        l1 = tmp / "l1.ll"
        r = tp.run([str(CLANG), str(src), "-O0", "-fno-discard-value-names",
                    *extra,
                    *mllvm(["-taokari", "-taokari-indgv",
                            "-taokari-level-indgv=1"]),
                    "-S", "-emit-llvm", "-o", str(l1)])
        if r.returncode:
            print("FAIL L1 emit\n", r.stderr[:400], file=sys.stderr)
            return 1
        l1t = l1.read_text(encoding="utf-8", errors="ignore")
        if "_objects_share" not in l2t:
            print("FAIL: L2 IR has no objects_share table", file=sys.stderr)
            return 1
        if "_objects_share" in l1t:
            print("FAIL: L1 IR leaked objects_share", file=sys.stderr)
            return 1
        native = tmp / "native"
        r = tp.run([str(CLANG), str(src), "-O0", *extra, "-o", str(native)])
        if r.returncode:
            print("FAIL native", file=sys.stderr)
            return 1
        nrun = tp.run([str(native)])
        obf = tmp / "l2"
        r = tp.run([str(CLANG), str(src), "-O0", *extra,
                    *mllvm(["-taokari", "-taokari-indgv",
                            "-taokari-level-indgv=2"]),
                    "-o", str(obf)])
        if r.returncode:
            print("FAIL L2 build\n", r.stderr[:400], file=sys.stderr)
            return 1
        orun = tp.run([str(obf)])
        if orun.returncode or orun.stdout != nrun.stdout:
            print(f"FAIL L2 rc={orun.returncode} out={orun.stdout!r} "
                  f"want={nrun.stdout!r}", file=sys.stderr)
            return 1
    print("indgv two-share: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
