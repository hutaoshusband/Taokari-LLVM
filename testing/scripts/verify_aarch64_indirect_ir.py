"""Verify AArch64-targeted obfuscated IR is well-formed and codegens.

Regression test for a malformed-IR bug on AArch64: the indirect-call/branch/
global page-table decrypt path calls llvm.ptrauth.sign to sign the recovered
pointer. That intrinsic's declaration in the module returns an integer type,
so the call result was an i64. When IndirectBranch fed that i64 straight into
an `indirectbr` address operand, the IR became `indirectbr i64 %x, [...]`,
which is illegal (the address must be pointer-typed). The X86 path skipped
ptrauth entirely (PtrAuthKey = -1), so the bug was invisible on X86 and only
surfaced when targeting AArch64.

The fix casts the ptrauth.sign result back to the pointer type the caller
expects, regardless of how the intrinsic was declared.

This verifier is compile/codegen-only: the WSL host has no AArch64 runtime,
so we emit + assemble obfuscated IR for aarch64-linux-gnu and assert:
  * the obfuscated IR contains no `indirectbr <integer-type>` operand,
  * the IR assembles to a valid AArch64 object for indbr/icall/indgv at L1-L4.

Contract: every indirect pass at every level produces AArch64-codegenable IR.

Exit: 0 ok | 1 contract failure | 2 missing clang.
"""
from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
TARGET = "aarch64-linux-gnu"

SOURCE = r"""
__attribute__((noinline)) int probe(int x) {
  int s = x;
  for (int i = 0; i < x; ++i) { if (i & 1) s += i; else s ^= i; }
  return s;
}
__attribute__((noinline)) int (*select(int k))(int) {
  static int (*tbl[2])(int) = {probe, probe};
  return tbl[k & 1];
}
int (*gp)(int) = probe;
"""


def run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return tp.run(cmd)


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    failures = 0
    with tempfile.TemporaryDirectory(prefix="taokari-aarch64-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "aarch64.c"
        src.write_text(SOURCE, encoding="utf-8")

        for pass_name in ("indbr", "icall", "indgv"):
            for lvl in (1, 2, 3, 4):
                ir = tmp / f"{pass_name}_{lvl}.ll"
                flags = ["-mllvm", "-taokari", f"-mllvm", f"-taokari-{pass_name}"]
                if pass_name != "cse":
                    flags += ["-mllvm", f"-taokari-level-{pass_name}={lvl}"]
                r = run([str(CLANG), f"--target={TARGET}", "-O2", "-ffreestanding",
                         *flags, str(src), "-S", "-emit-llvm", "-o", str(ir)])
                if r.returncode:
                    print(f"FAIL  {pass_name}-L{lvl}: IR emit failed\n{r.stderr[:200]}",
                          file=sys.stderr)
                    failures += 1
                    continue
                text = ir.read_text(encoding="utf-8", errors="ignore")
                # The bug: indirectbr with a non-pointer (integer) address.
                bad = re.findall(r"indirectbr\s+(i\d+)\s+", text)
                if bad:
                    print(f"FAIL  {pass_name}-L{lvl}: malformed indirectbr with "
                          f"{bad} address operand", file=sys.stderr)
                    failures += 1
                    continue
                # Codegen the IR for AArch64.
                obj = tmp / f"{pass_name}_{lvl}.o"
                r = run([str(CLANG), f"--target={TARGET}", "-O2", "-c",
                         str(ir), "-o", str(obj)])
                if r.returncode:
                    print(f"FAIL  {pass_name}-L{lvl}: AArch64 codegen failed\n"
                          f"{r.stderr[:200]}", file=sys.stderr)
                    failures += 1
                    continue
                print(f"ok    {pass_name}-L{lvl}: IR well-formed + AArch64 codegen")

    if failures:
        print(f"aarch64-indirect-ir: {failures} config(s) failed", file=sys.stderr)
        return 1
    print("aarch64-indirect-ir: ok (indbr/icall/indgv L1-L4 all produce "
          "well-formed, AArch64-codegenable IR)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
