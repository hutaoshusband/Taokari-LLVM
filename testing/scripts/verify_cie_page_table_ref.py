"""CIE L4 resolves the constant pool through a page table.

At cie L4 the pool base is looked up via createPageTable instead of a
.cie.pool.ref load. L3 keeps the indirect pointer slot. returnsTwice
callers keep a direct pool GEP.

Contract:
  * L4 IR contains a .cie.pt page table and no .cie.pool.ref.
  * L3 IR contains .cie.pool.ref and no .cie.pt table.
  * L4 binary matches native.

Exit: 0 ok | 1 contract failure | 2 missing clang.
"""
from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
SOURCE = """
#include <cstdint>
#include <cstdio>
__attribute__((noinline)) int64_t magic() {
  volatile int64_t v = 1;
  return 0xCAFEBABEDEADC0DELL + v;
}
int main() {
  std::printf("ciept:%lld\\n", static_cast<long long>(magic()));
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
    with tempfile.TemporaryDirectory(prefix="taokari-cie-pt-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "cie_pt.cpp"
        src.write_text(SOURCE, encoding="utf-8")
        l4 = tmp / "l4.ll"
        r = tp.run([str(CLANG), str(src), "-O2", "-fno-discard-value-names",
                    *mllvm(["-taokari", "-taokari-cie", "-taokari-level-cie=4"]),
                    "-S", "-emit-llvm", "-o", str(l4)])
        if r.returncode:
            print("FAIL L4 emit\n", r.stderr[:400], file=sys.stderr)
            return 1
        l4t = l4.read_text(encoding="utf-8", errors="ignore")
        l3 = tmp / "l3.ll"
        r = tp.run([str(CLANG), str(src), "-O2", "-fno-discard-value-names",
                    *mllvm(["-taokari", "-taokari-cie", "-taokari-level-cie=3"]),
                    "-S", "-emit-llvm", "-o", str(l3)])
        if r.returncode:
            print("FAIL L3 emit\n", r.stderr[:400], file=sys.stderr)
            return 1
        l3t = l3.read_text(encoding="utf-8", errors="ignore")
        if ".cie.pt_objects" not in l4t and ".cie.pt_page_table_" not in l4t:
            print("FAIL: L4 IR has no cie page table", file=sys.stderr)
            return 1
        if ".cie.pool.ref" in l4t:
            print("FAIL: L4 IR still has .cie.pool.ref", file=sys.stderr)
            return 1
        if ".cie.pool.ref" not in l3t:
            print("FAIL: L3 IR lost .cie.pool.ref", file=sys.stderr)
            return 1
        if ".cie.pt_page_table_" in l3t:
            print("FAIL: L3 IR leaked cie page table", file=sys.stderr)
            return 1
        native = tmp / "native"
        r = tp.run([str(CLANG), str(src), "-O2", "-o", str(native)])
        if r.returncode:
            print("FAIL native build", file=sys.stderr)
            return 1
        nrun = tp.run([str(native)])
        obf = tmp / "l4"
        r = tp.run([str(CLANG), str(src), "-O2",
                    *mllvm(["-taokari", "-taokari-cie", "-taokari-level-cie=4"]),
                    "-o", str(obf)])
        if r.returncode:
            print("FAIL L4 build\n", r.stderr[:400], file=sys.stderr)
            return 1
        orun = tp.run([str(obf)])
        if orun.returncode or orun.stdout != nrun.stdout:
            print(f"FAIL L4 rc={orun.returncode} out={orun.stdout!r} "
                  f"want={nrun.stdout!r}", file=sys.stderr)
            return 1
        nd = tmp / "l4_nodedup.ll"
        r = tp.run([str(CLANG), str(src), "-O2", "-fno-discard-value-names",
                    *mllvm(["-taokari", "-taokari-cie", "-taokari-level-cie=4",
                            "-taokari-cie-no-dedup"]),
                    "-S", "-emit-llvm", "-o", str(nd)])
        if r.returncode:
            print("FAIL no-dedup emit\n", r.stderr[:400], file=sys.stderr)
            return 1
        ndt = nd.read_text(encoding="utf-8", errors="ignore")
        shard_defs = re.findall(
            r'define internal i64 @"?[^"]*cie\.shard\.\d+"?\(([^)]*)\)', ndt)
        if not shard_defs:
            print("FAIL no-dedup IR has no cie shards", file=sys.stderr)
            return 1
        if any(params.strip() for params in shard_defs):
            print("FAIL no-dedup shards still take a pool-base argument",
                  file=sys.stderr)
            return 1
        calls = re.findall(
            r'cie\.shard\.call\w* = call i64 @"?[^"]+"?\(([^)]*)\)', ndt)
        if not calls:
            print("FAIL no-dedup IR has no cie shard calls", file=sys.stderr)
            return 1
        if any(args.strip() for args in calls):
            print("FAIL no-dedup shard calls still receive a shared "
                  "pool-base slot value", file=sys.stderr)
            return 1
        shard_bodies = re.findall(
            r'define internal i64 @"?[^"]*cie\.shard\.\d+"?\(\)[\s\S]*?\n}',
            ndt)
        chains = sum(1 for body in shard_bodies
                     if "cie.pt_page_table_" in body)
        if chains != len(shard_bodies) or not chains:
            print(f"FAIL no-dedup shards lack per-use page-table decode "
                  f"chains ({chains}/{len(shard_bodies)})", file=sys.stderr)
            return 1
        ndbin = tmp / "l4_nodedup"
        r = tp.run([str(CLANG), str(src), "-O2",
                    *mllvm(["-taokari", "-taokari-cie", "-taokari-level-cie=4",
                            "-taokari-cie-no-dedup"]),
                    "-o", str(ndbin)])
        if r.returncode:
            print("FAIL no-dedup build\n", r.stderr[:400], file=sys.stderr)
            return 1
        ndrun = tp.run([str(ndbin)])
        if ndrun.returncode or ndrun.stdout != nrun.stdout:
            print(f"FAIL no-dedup rc={ndrun.returncode} out={ndrun.stdout!r} "
                  f"want={nrun.stdout!r}", file=sys.stderr)
            return 1
    print("cie page-table pool ref: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
