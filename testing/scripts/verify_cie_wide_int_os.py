"""Verify ConstantIntEncryption (cie) handles wide-integer constants at -Os.

Regression test for a hard backend crash in cie level>=3 under size
optimization. At -Os, clang promotes 64x64->128 high-multiply patterns
(mulhi) to i128 arithmetic, producing instructions like `lshr i128 x, 64`.
cie encrypts the i128 shift-amount constant via a helper shard, but the shard
returns i64. The call site only handled narrower-than-64 (trunc) and
exactly-64 cases, so for a wider-than-64 constant it substituted the raw i64
shard result into an i128 operand, emitting malformed IR (`lshr i128, i64`)
that the X86 SelectionDAG could not legalize at -Os -> "Do not know how to
expand this operator's operand".

The fix widens the shard result with zext when the original constant type is
wider than i64 (and narrows with trunc inside the shard body, symmetrically).

Contract:
  * A mulhi-style source compiles cleanly under cie level 3 AND level 4 at
    -O2, -O3, -Os and -Oz (previously -Os crashed at cie>=3).
  * The obfuscated binary's output matches the plain baseline at each level.

Exit: 0 ok | 1 contract failure | 2 missing clang.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))

import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG

SOURCE = r"""
#include <stdint.h>
#include <stdio.h>

__attribute__((noinline)) static uint64_t mulhi(uint64_t a, uint64_t b) {
  uint64_t a_lo = a & 0xFFFFFFFFull;
  uint64_t a_hi = a >> 32;
  uint64_t b_lo = b & 0xFFFFFFFFull;
  uint64_t b_hi = b >> 32;
  uint64_t lo = a_lo * b_lo;
  uint64_t mid1 = a_hi * b_lo;
  uint64_t mid2 = a_lo * b_hi;
  uint64_t carry = ((mid1 & 0xFFFFFFFFull) + (mid2 & 0xFFFFFFFFull) +
                    (lo >> 32)) >> 32;
  return a_hi * b_hi + (mid1 >> 32) + (mid2 >> 32) + carry;
}

__attribute__((noinline)) static uint64_t pow_mod(uint64_t base, uint64_t exp,
                                                  uint64_t mod) {
  uint64_t result = 1 % mod;
  base %= mod;
  while (exp) {
    if (exp & 1)
      result = mulhi(result, base) % mod + (result * base) % mod;
    base = mulhi(base, base) % mod + (base * base) % mod;
    exp >>= 1;
  }
  return result % mod;
}

int main(void) {
  uint64_t hi = mulhi(0x123456789ABCDEF0ull, 0xFEDCBA9876543210ull);
  uint64_t pm = pow_mod(7, 13, 1000);
  printf("wide:%llu:%llu\n", (unsigned long long)hi, (unsigned long long)pm);
  return 0;
}
"""


def run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return tp.run(cmd)


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-cie-wide-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "wide.c"
        src.write_text(SOURCE, encoding="utf-8")
        extra = [] if os.name == "nt" else ["-fdeclspec", "-D_GNU_SOURCE"]

        baseline = tmp / "base"
        r = run([str(CLANG), str(src), "-O2", *extra, "-o", str(baseline)])
        if r.returncode:
            print(f"baseline build failed\n{r.stdout}{r.stderr}", file=sys.stderr)
            return 1
        base_run = run([str(baseline)])
        if base_run.returncode:
            print(f"baseline run failed\n{base_run.stdout}{base_run.stderr}",
                  file=sys.stderr)
            return 1
        expected = base_run.stdout

        failures = 0
        for opt in ("O2", "O3", "Os", "Oz"):
            for lvl in (3, 4):
                obf = tmp / f"obf_{opt}_{lvl}"
                r = run([str(CLANG), str(src), f"-{opt}",
                         "-mllvm", "-taokari",
                         "-mllvm", "-taokari-cie",
                         "-mllvm", f"-taokari-level-cie={lvl}",
                         *extra, "-o", str(obf)])
                if r.returncode:
                    print(f"FAIL  -{opt} cie={lvl}: compile crashed\n"
                          f"{r.stdout}{r.stderr}", file=sys.stderr)
                    failures += 1
                    continue
                ran = run([str(obf)])
                if ran.returncode or ran.stdout != expected:
                    print(f"FAIL  -{opt} cie={lvl}: runtime mismatch "
                          f"rc={ran.returncode} out={ran.stdout!r} "
                          f"expected={expected!r}", file=sys.stderr)
                    failures += 1
                    continue
                print(f"ok    -{opt} cie={lvl}: matches baseline")

    if failures:
        print(f"cie-wide-int: {failures} config(s) failed", file=sys.stderr)
        return 1
    print("cie-wide-int: ok (cie>=3 survives -Os/-Oz on i128-promoted math, "
          "output matches baseline)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
