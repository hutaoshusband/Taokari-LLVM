"""Tier recipe verifier (Section 22 Phase 7).

Parameterised over Tier A/B/C/D. Compiles a demo source under each
tier's exact flag recipe, asserts compile time, correctness, and the
Phase 5 gnarliness metric bar for that tier.

Tiers C/D use the annotated demo source (vm_one +vmp, main -vmp) and
also check the VMP compat report: every +vmp function must show
'virtualized', not 'partially virtualized' or 'skipped'.

Tier D additionally requires per-build structural divergence: two
builds of the same source must produce structurally different IR.

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
import time
from pathlib import Path

from verify_vmp_coverage import CLANG, run, ROOT, VSDEVCMD
from measure_ida_cfg_complexity import (
    TIER_BARS, emit_ir, parse_functions, pick_target, text_entropy,
)

# Demo source for tiers C/D: vm_one is +vmp (the canonical sensitive
# function), main is -vmp (CRT/wrapper). compute() is left unannotated
# so the Tier B blanket + Phase 1 cap-fallthrough behaviour is visible.
# vm_one carries real control flow (an if + a loop) so the plain-baseline
# CFG has non-zero edges and the 10x/15x node/edge bar is well-defined.
DEMO_SOURCE = r"""
#include <stdio.h>
#define VMP __attribute__((noinline, annotate("+vmp")))
#define NO_VMP __attribute__((annotate("-vmp")))
VMP int vm_one(int x) {
  int acc = (x * 17) ^ 0x5a5a;
  for (int i = 0; i < (x & 7); ++i) {
    acc = (acc + i) ^ (acc >> 3);
    if (acc & 1) acc += 9;
  }
  return acc + 9;
}
int compute(int a, int b) {
  int z = ((a + b) ^ (a * b)) + 41;
  return z > 100 ? z - a : z + b;
}
NO_VMP int main(void) {
  printf("tier:%d:%d\n", vm_one(13), compute(7, 11));
  return 0;
}
"""

# Function names carrying the +vmp annotation in DEMO_SOURCE.
VMP_FUNCTIONS = ("vm_one",)

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

# Tier C = Tier B blanket + VMP enabled on the +vmp annotations.
# Uses the per-function -taokari-vmp global switch; the +vmp annotations
# select which functions virtualize, and Phase 1 caps refuse runaways.
TIER_C_FLAGS = TIER_B_FLAGS + ["-mllvm", "-taokari-vmp"]

# Tier D = Tier C + heavier noise + per-function budget headroom.
TIER_D_FLAGS = TIER_C_FLAGS + [
    "-mllvm", "-taokari-vmp-max-bytecode-words=8192",
    "-mllvm", "-taokari-bcf-before-fla",
    "-mllvm", "-taokari-vmp-padding=15",
]

# Phase 4 compile-time budgets (demo target, seconds).
TIER_BUDGET_SEC = {"A": 5, "B": 30, "C": 60, "D": 300}

TIERS = {
    "A": TIER_A_FLAGS,
    "B": TIER_B_FLAGS,
    "C": TIER_C_FLAGS,
    "D": TIER_D_FLAGS,
}


def _extract_fn_body(ir_text: str, fn_name: str) -> str:
    """Body text (between { and matching column-0 }) of one IR function."""
    import re
    fn_re = re.compile(
        r'^define\s+.*?@"?' + re.escape(fn_name) + r'"?\s*\([^)]*\)[^{]*\{',
        re.M,
    )
    m = fn_re.search(ir_text)
    if not m:
        return ""
    start = m.end()
    end = ir_text.find("\n}\n", start)
    if end < 0:
        end = len(ir_text)
    return ir_text[start:end]


def parse_compat_report(text: str) -> dict[str, dict]:
    """Parse the TSV VMP compat report into {fn: {status, words, ...}}.

    Header: function<TAB>status<TAB>reason<TAB>words<TAB>split_regions
    """
    rows: dict[str, dict] = {}
    for line in text.splitlines():
        if not line.strip() or line.startswith("function\t"):
            continue
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        rows[parts[0]] = {
            "status": parts[1], "reason": parts[2], "words": parts[3],
        }
    return rows


def ir_cfg_signature(ir_text: str, fn_name: str) -> tuple[int, int]:
    """(nodes, edges) of one named function from IR text."""
    metrics = parse_functions(ir_text)
    m = metrics.get(fn_name)
    if not m:
        return (0, 0)
    return (m["nodes"], m["edges"])


def cfg_signature_str(ir_text: str, fn_name: str) -> str:
    """A coarse textual signature of a function's CFG shape for diff.

    Captures block label sequence + edge count + switch-arm count so a
    per-build seed shuffle shows up as a different signature.
    """
    import re
    fn_re = re.compile(
        r'^define\s+.*?@"?' + re.escape(fn_name) + r'"?\s*\([^)]*\)[^{]*\{',
        re.M,
    )
    m = fn_re.search(ir_text)
    if not m:
        return ""
    start = m.end()
    end = ir_text.find("\n}\n", start)
    if end < 0:
        end = len(ir_text)
    body = ir_text[start:end]
    labels = re.findall(r'^[\w.$-]+:\s*(?:;.*)?$', body, re.M)
    edges = (len(re.findall(r'\bbr\s+', body))
             + len(re.findall(r'\bswitch\s+', body)))
    arms = body.count(", label %")
    # Sort labels so trivial naming differences don't mask structural
    # identity, but keep edge/arm counts raw.
    return f"{tuple(sorted(labels))}|edges={edges}|arms={arms}"


def verify_tier(tier: str, tmpdir: Path) -> bool:
    bar = TIER_BARS[tier]
    budget = TIER_BUDGET_SEC[tier]
    flags = list(TIERS[tier])

    src = tmpdir / f"tier_{tier}.c"
    src.write_text(DEMO_SOURCE, encoding="utf-8")

    cfg = tmpdir / f"tier_{tier}.json"
    cfg.write_text(
        '{"randomSeed": "taokari-tier-%s-seed", "meta": {"enable": true, '
        '"level": 3, "releaseStrip": true, "randomizeSections": true}}'
        % tier,
        encoding="utf-8",
    )
    flags += ["-mllvm", f"-taokari-cfg={cfg}"]

    # For tiers C/D, attach a compat-report path so we can assert every
    # +vmp function virtualized.
    report = None
    if tier in ("C", "D"):
        report = tmpdir / f"tier_{tier}_report.txt"
        flags += ["-mllvm", f"-taokari-vmp-compat-report={report}"]

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

    # Tier A is deliberately clean — skip the gnarliness bar.
    if tier != "A":
        entropy = text_entropy(exe)
        # For tiers C/D the gnarliness bar applies to the +vmp functions
        # specifically (10x/15x or 20x/30x), not the blanket target.
        if tier in ("C", "D"):
            target = VMP_FUNCTIONS[0]
            pn, pe = ir_cfg_signature(
                plain_ll.read_text(encoding="utf-8", errors="ignore"),
                target)
            on, oe = ir_cfg_signature(
                obf_ll.read_text(encoding="utf-8", errors="ignore"),
                target)
        else:
            plain_target = pick_target(plain_metrics)
            obf_target = pick_target(obf_metrics)
            pn = plain_metrics[plain_target]["nodes"] or 1
            pe = plain_metrics[plain_target]["edges"] or 1
            on = obf_metrics[obf_target]["nodes"]
            oe = obf_metrics[obf_target]["edges"]
            target = obf_target
        node_ratio = on / pn if pn else 0.0
        edge_ratio = oe / pe if pe else 0.0
        if (node_ratio < bar["node_factor"]
                or edge_ratio < bar["edge_factor"]
                or entropy < bar["text_entropy_min"]):
            print(
                f"  tier {tier}: FAIL "
                f"({target}: nodes {node_ratio:.1f}x/{bar['node_factor']}x, "
                f"edges {edge_ratio:.1f}x/{bar['edge_factor']}x, "
                f"entropy {entropy:.2f}/{bar['text_entropy_min']})",
                file=sys.stderr,
            )
            return False

    # Tiers C/D: every +vmp function must virtualize.
    if report is not None:
        report_text = report.read_text(
            encoding="utf-8", errors="ignore") if report.exists() else ""
        rows = parse_compat_report(report_text)
        plain_text = plain_ll.read_text(encoding="utf-8", errors="ignore")
        for fn in VMP_FUNCTIONS:
            row = rows.get(fn)
            if not row:
                print(f"  tier {tier}: FAIL ({fn} missing from compat "
                      f"report)", file=sys.stderr)
                return False
            if row["status"] != "virtualized":
                print(f"  tier {tier}: FAIL ({fn} status={row['status']!r}, "
                      f"expected 'virtualized')", file=sys.stderr)
                return False
            # Phase 3 record-keeping for the demo: native IR inst count,
            # emitted bytecode words, and back-edge count of the +vmp
            # function. Back-edge count is approximated by counting
            # branch-back targets in the plain IR (a function with no
            # loops has 0). This is the per-function budget record the
            # plan asks for, captured for the canonical demo target.
            import re as _re
            fn_body = _extract_fn_body(plain_text, fn)
            native_insts = len(_re.findall(
                r'^\s*(?:%[\w.]+|tail\s+)?\s*=\s*', fn_body, _re.M))
            # Count back edges: branches whose target label appears
            # lexically earlier in the function body.
            labels_before = {}
            back_edges = 0
            pos = 0
            for lm in _re.finditer(r'^([\w.$-]+):\s*$', fn_body, _re.M):
                labels_before[lm.group(1)] = lm.start()
            for bm in _re.finditer(r'\bbr\s+(?:i1\s+[^,]+,\s*)?label\s+%([\w.$-]+)',
                                   fn_body, _re.M):
                tgt = bm.group(1)
                if tgt in labels_before and labels_before[tgt] < bm.start():
                    back_edges += 1
            print(f"    {fn}: status=virtualized words={row['words']} "
                  f"native_insts~={native_insts} back_edges={back_edges}")

    print(f"  tier {tier}: ok (compile {elapsed:.1f}s)")
    return True


def verify_tier_d_divergence(tmpdir: Path) -> bool:
    """Two builds of the same source under Tier D must produce
    structurally different IR for the +vmp function (per-build seed
    visible in CFG diff).
    """
    src = tmpdir / "div_src.c"
    src.write_text(DEMO_SOURCE, encoding="utf-8")
    sigs: set[str] = set()
    for i in range(2):
        cfg = tmpdir / f"div_{i}.json"
        # Distinct seeds per build.
        cfg.write_text(
            '{"randomSeed": "taokari-tier-D-div%d-seed", "meta": '
            '{"enable": true, "level": 3, "releaseStrip": true, '
            '"randomizeSections": true}}' % i,
            encoding="utf-8",
        )
        ll = tmpdir / f"div_{i}.ll"
        flags = list(TIER_D_FLAGS) + ["-mllvm", f"-taokari-cfg={cfg}"]
        emit_ir(src, ll, flags)
        sigs.add(cfg_signature_str(
            ll.read_text(encoding="utf-8", errors="ignore"), VMP_FUNCTIONS[0]))
    if len(sigs) < 2:
        print("  tier D: FAIL (two builds produced identical IR for "
              f"{VMP_FUNCTIONS[0]})", file=sys.stderr)
        return False
    print(f"  tier D divergence: ok ({len(sigs)} distinct signatures)")
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
            if tier == "D":
                all_ok &= verify_tier_d_divergence(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if not all_ok:
        print("tier recipe: FAIL (one or more tiers failed)", file=sys.stderr)
        return 1
    print("tier recipe: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
