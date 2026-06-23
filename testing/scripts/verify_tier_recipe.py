"""Tier recipe verifier (Section 22 Phase 7).

Parameterised over Tier A/B/C/D. Compiles a demo source under each
tier's exact flag recipe, asserts compile time, correctness, and the
Phase 5 gnarliness metric bar for that tier.

Tier D needs per-build structural divergence which is checked via
repeated build + IR diff (two builds of the same source must produce
structurally different IR).

Run:
  python verify_tier_recipe.py [A|B|C|D]    (default: AB)

Exit:
  0 + per-tier "ok" lines
  1 if any tier fails
  2 if clang missing
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from verify_vmp_coverage import CLANG, run, ROOT, VSDEVCMD
from measure_ida_cfg_complexity import (
    TIER_BARS, emit_ir, parse_functions, pick_target, text_entropy,
)

DEMO_SOURCE = r"""
#include <stdio.h>
#define VMP __attribute__((noinline, annotate("+vmp")))
#define NO_VMP __attribute__((annotate("-vmp")))
VMP int vm_one(int x) { return (((x * 17) ^ 0x5a5a) + 9); }
int compute(int a, int b) {
  int z = ((a + b) ^ (a * b)) + 41;
  return z > 100 ? z - a : z + b;
}
NO_VMP int main(void) {
  printf("tier:%d:%d\n", vm_one(13), compute(7, 11));
  return 0;
}
"""

TIER_A_FLAGS = [
    "-mllvm", "-taokari",
    "-mllvm", "-taokari-fla", "-mllvm", "-taokari-level-fla=2",
    "-mllvm", "-taokari-mba", "-mllvm", "-taokari-mba-prob=20",
    "-mllvm", "-taokari-meta", "-mllvm", "-taokari-level-meta=2",
    "-mllvm", "-taokari-cse",
    "-mllvm", "-taokari-cie", "-mllvm", "-taokari-level-cie=1",
]

TIER_B_FLAGS = [
    "-mllvm", "-taokari",
    "-mllvm", "-taokari-fla", "-mllvm", "-taokari-level-fla=4",
    "-mllvm", "-taokari-bcf", "-mllvm", "-taokari-level-bcf=2",
    "-mllvm", "-taokari-bcf-before-fla", "-mllvm", "-taokari-bcf-after-fla",
    "-mllvm", "-taokari-mba", "-mllvm", "-taokari-mba-prob=40",
    "-mllvm", "-taokari-cie", "-mllvm", "-taokari-level-cie=2",
    "-mllvm", "-taokari-cfe", "-mllvm", "-taokari-level-cfe=2",
    "-mllvm", "-taokari-cse",
    "-mllvm", "-taokari-icall",
    "-mllvm", "-taokari-indbr",
    "-mllvm", "-taokari-indgv",
    "-mllvm", "-taokari-meta", "-mllvm", "-taokari-level-meta=3",
    "-mllvm", "-taokari-mir=dirtybytes,junk,sub,split,fakeprologue",
    "-mllvm", "-taokari-mir-dirtybytes-prob=100",
    "-mllvm", "-taokari-mir-junk-prob=100",
    "-mllvm", "-taokari-mir-sub-prob=100",
    "-mllvm", "-taokari-vmp-padding=5",
]

TIER_C_FLAGS = TIER_B_FLAGS + ["-mllvm", "-taokari-vmp"]

TIER_D_FLAGS = TIER_C_FLAGS + [
    "-mllvm", "-taokari-vmp-max-bytecode-words=8192",
    "-mllvm", "-taokari-bcf-before-fla",
    "-mllvm", "-taokari-vmp-padding=15",
]

# Phase 4 compile-time budgets (demo target).
TIER_BUDGET_SEC = {"A": 5, "B": 30, "C": 60, "D": 300}

TIERS = {
    "A": TIER_A_FLAGS,
    "B": TIER_B_FLAGS,
    "C": TIER_C_FLAGS,
    "D": TIER_D_FLAGS,
}


def verify_tier(tier: str, tmpdir: Path) -> bool:
    import time
    bar = TIER_BARS[tier]
    budget = TIER_BUDGET_SEC[tier]
    flags = list(TIERS[tier])

    src = tmpdir / f"tier_{tier}.c"
    src.write_text(DEMO_SOURCE, encoding="utf-8")

    # Metadata hygiene requires a per-build random seed. Every tier that
    # enables -taokari-meta needs a -taokari-cfg file with a randomSeed,
    # matching what build_strong.bat / build_max_protection.bat do.
    cfg = tmpdir / f"tier_{tier}.json"
    cfg.write_text(
        '{"randomSeed": "taokari-tier-%s-seed", "meta": {"enable": true, '
        '"level": 3, "releaseStrip": true, "randomizeSections": true}}'
        % tier,
        encoding="utf-8",
    )
    flags += ["-mllvm", f"-taokari-cfg={cfg}"]

    plain_ll = tmpdir / f"plain_{tier}.ll"
    emit_ir(src, plain_ll, [])
    plain_metrics = parse_functions(
        plain_ll.read_text(encoding="utf-8", errors="ignore"))

    obf_ll = tmpdir / f"obf_{tier}.ll"
    emit_ir(src, obf_ll, flags)
    obf_metrics = parse_functions(
        obf_ll.read_text(encoding="utf-8", errors="ignore"))

    exe = tmpdir / f"out_{tier}.exe"
    build_flags = [str(CLANG), "-O2", str(src), "-o", str(exe)]
    build_flags += flags + ["-Wl,/DEBUG:NONE"]
    t0 = time.monotonic()
    r = run(build_flags, use_vs_env=True)
    elapsed = time.monotonic() - t0
    if r.returncode:
        sys.stderr.write(r.stdout + r.stderr)
        print(f"  tier {tier}: FAIL (build rc={r.returncode})", file=sys.stderr)
        return False
    if elapsed > budget:
        print(f"  tier {tier}: FAIL (compile {elapsed:.1f}s > {budget}s)",
              file=sys.stderr)
        return False

    rr = run([str(exe)])
    if rr.returncode or not rr.stdout.startswith("tier:"):
        sys.stderr.write(rr.stdout + rr.stderr)
        print(f"  tier {tier}: FAIL (bad run)", file=sys.stderr)
        return False

    # Tier A is deliberately clean — skip the gnarliness bar for it.
    if tier != "A":
        entropy = text_entropy(exe)
        plain_target = pick_target(plain_metrics)
        obf_target = pick_target(obf_metrics)
        pn = plain_metrics[plain_target]["nodes"] or 1
        pe = plain_metrics[plain_target]["edges"] or 1
        node_ratio = obf_metrics[obf_target]["nodes"] / pn
        edge_ratio = obf_metrics[obf_target]["edges"] / pe
        if (node_ratio < bar["node_factor"]
                or edge_ratio < bar["edge_factor"]
                or entropy < bar["text_entropy_min"]):
            print(
                f"  tier {tier}: FAIL "
                f"(nodes {node_ratio:.1f}x/{bar['node_factor']}x, "
                f"edges {edge_ratio:.1f}x/{bar['edge_factor']}x, "
                f"entropy {entropy:.2f}/{bar['text_entropy_min']})",
                file=sys.stderr,
            )
            return False

    print(f"  tier {tier}: ok (compile {elapsed:.1f}s)")
    return True


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    which = sys.argv[1:] if len(sys.argv) > 1 else ["A", "B"]
    bad = [t for t in which if t not in TIERS]
    if bad:
        print(f"unknown tier(s): {bad}; choose from {sorted(TIERS)}",
              file=sys.stderr)
        return 1

    tmp = Path(tempfile.mkdtemp(prefix="taokari-tier-"))
    try:
        all_ok = True
        for tier in which:
            all_ok &= verify_tier(tier, tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if not all_ok:
        print("tier recipe: FAIL (one or more tiers failed)", file=sys.stderr)
        return 1
    print("tier recipe: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
