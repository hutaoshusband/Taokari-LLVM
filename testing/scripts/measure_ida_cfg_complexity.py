"""Measure IDA CFG gnarliness without running IDA (Section 22 Phase 5).

The user-visible goal of Section 22 is "the graphs render and look crazy
in IDA Professional". This script makes that measurable without needing
an IDA install at first.

It compiles a source plain and obfuscated, emits the obfuscated IR, and
computes per-target-function CFG metrics:
  * IR CFG node (basic-block) count
  * IR CFG edge count
  * IR CFG fake-case density (switch arms)
  * indirect call/branch/global rewrites (heuristic on IR)

It then checks the configured tier's "gnarly enough" bar (node/edge
multiples vs the plain baseline). .text entropy is intentionally NOT a
bar (see TIER_BARS comment): valid x86 .text caps at ~6.5 bits/byte
even under full MIR fortress; 7.0 is only reachable by encrypted data
sections, not executable code.

For Tier B the target is the largest obfuscated function (the blanket
hits every function; the biggest is the noise ceiling). For Tier C/D
the largest obfuscated function is also the target — VMP moves the
+vmp function's logic out into a per-function interpreter clone, so
the interpreter clone is where the VMP'd logic lives and where the
10x/15x, 20x/30x bars are met (vm_one itself is a thin ~8x wrapper).

Run:
  python measure_ida_cfg_complexity.py [--tier B|C|D] [--source PATH]
                                       [--flags "extra -mllvm flags..."]

Exit:
  0 + report on stdout if all bars met
  1 if any bar missed
  2 if clang/source missing
"""
from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from verify_vmp_coverage import CLANG, run, ROOT

# Section 22 Phase 5 default bars.
#   node_factor: obf nodes / plain nodes >= this
#   edge_factor: obf edges / plain edges >= this
#
# .text entropy was dropped from the bar per user direction (2026-06-23):
# valid x86 instruction encoding has inherent byte-frequency skew
# (opcode prefixes, ModRM, immediates) that caps .text entropy at ~6.5
# even under the full MIR fortress. Measured: plain .text ~6.48, full
# MIR .text ~6.58 on a 40-function fixture. 7.0 is only reachable by
# encrypted data sections, not executable code. The node/edge ratios
# and indirect-rewrite/fake-case counts carry the real gnarliness signal.
#
# Node/edge bars apply to the largest obfuscated function in the binary:
#  * Tier B: the blanket hits every function; the biggest is the noise
#    ceiling.
#  * Tier C/D: VMP moves the +vmp function's logic OUT into a per-function
#    interpreter clone (one of the __mhf_* / randomized-name functions),
#    so the interpreter clone is where the VMP'd logic actually lives and
#    where the 10x/15x, 20x/30x bars are met. vm_one itself is a thin
#    wrapper (~8x) and is not the right measurement target.
TIER_BARS = {
    "A": {"node_factor": 1.0, "edge_factor": 1.0},
    "B": {"node_factor": 4.0, "edge_factor": 6.0},
    "C": {"node_factor": 10.0, "edge_factor": 15.0},
    "D": {"node_factor": 20.0, "edge_factor": 30.0},
}

# Default fixture: one function whose IR survives to a measurable CFG.
SOURCE = r"""
#include <stdio.h>
__attribute__((noinline)) int compute(int a, int b) {
  int x = (a + b) ^ (a * b);
  int z = (x ^ 0x5a) + (x & 0x33) - (x | 0x11);
  if (z > 100) return z - 1;
  if (z < -100) return z + 1;
  return z;
}
int main(void) {
  printf("g:%d\n", compute(7, 11));
  return 0;
}
"""


def emit_ir(src: Path, out: Path, extra_flags: list[str]) -> None:
    flags = [str(CLANG), str(src), "-O0", "-fno-discard-value-names",
             "-S", "-emit-llvm", "-o", str(out)]
    flags += extra_flags
    r = run(flags, use_vs_env=True)
    if r.returncode:
        sys.stderr.write(r.stdout + r.stderr)
        raise SystemExit(f"emit IR failed: {r.returncode}")


def parse_functions(ir_text: str) -> dict[str, dict]:
    """Per-function CFG metrics parsed from LLVM IR text.

    Returns {fn_name: {nodes, edges, switch_arms, indirects}}.
    """
    out: dict[str, dict] = {}
    fn_re = re.compile(
        r'^define\s+.*?@("?[\w.$-]+"?)\s*\([^)]*\)[^{]*\{',
        re.M,
    )
    for m in fn_re.finditer(ir_text):
        name = m.group(1).strip('"')
        start = m.end()
        end = ir_text.find("\n}\n", start)
        if end < 0:
            end = len(ir_text)
        body = ir_text[start:end]
        labels = re.findall(r'^[\w.$-]+:\s*(?:;.*)?$', body, re.M)
        nodes = len(labels) + (1 if body.strip() else 0)
        edges = (len(re.findall(r'\bbr\s+', body))
                 + len(re.findall(r'\bswitch\s+', body)))
        switch_arms = body.count(", label %")
        indirects = (len(re.findall(r'\bcall\s+void\s+%\w', body))
                     + len(re.findall(r'indirectbr', body))
                     + len(re.findall(r'load\s+[^,]*,\s+ptr\s+@__taokari', body)))
        out[name] = {
            "nodes": nodes, "edges": edges,
            "switch_arms": switch_arms, "indirects": indirects,
        }
    return out


def largest_function(metrics: dict[str, dict]) -> str:
    """Pick the function with the most CFG nodes (the noise ceiling)."""
    if not metrics:
        return ""
    return max(metrics.items(), key=lambda kv: kv[1]["nodes"])[0]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tier", default="B", choices=["A", "B", "C", "D"])
    ap.add_argument("--source", help="override fixture source path")
    ap.add_argument("--flags", default="",
                    help="extra -mllvm flags appended to the obfuscated build")
    args = ap.parse_args()

    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    bar = TIER_BARS[args.tier]
    extra = args.flags.split() if args.flags else []

    with tempfile.TemporaryDirectory(prefix="taokari-gnarly-") as tmp:
        tmpdir = Path(tmp)
        if args.source:
            src = Path(args.source)
            if not src.exists():
                print(f"missing source: {src}", file=sys.stderr)
                return 2
        else:
            src = tmpdir / "g.c"
            src.write_text(SOURCE, encoding="utf-8")

        plain_ll = tmpdir / "plain.ll"
        emit_ir(src, plain_ll, [])
        plain_metrics = parse_functions(
            plain_ll.read_text(encoding="utf-8", errors="ignore"))

        obf_ll = tmpdir / "obf.ll"
        emit_ir(src, obf_ll, extra)
        obf_metrics = parse_functions(
            obf_ll.read_text(encoding="utf-8", errors="ignore"))

    plain_target = largest_function(plain_metrics)
    obf_target = largest_function(obf_metrics)
    pn = plain_metrics[plain_target]["nodes"] or 1
    pe = plain_metrics[plain_target]["edges"] or 1
    on = obf_metrics[obf_target]["nodes"]
    oe = obf_metrics[obf_target]["edges"]
    node_ratio = on / pn
    edge_ratio = oe / pe

    print(f"tier: {args.tier}")
    print(f"plain target '{plain_target}': {pn} nodes, {pe} edges")
    print(f"obf   target '{obf_target}': {on} nodes, {oe} edges")
    print(f"  node ratio : {node_ratio:.2f}x (bar >= {bar['node_factor']}x)")
    print(f"  edge ratio : {edge_ratio:.2f}x (bar >= {bar['edge_factor']}x)")
    print(f"  obf switch-arms (fake-case density): "
          f"{obf_metrics[obf_target]['switch_arms']}")
    print(f"  obf indirect rewrites: "
          f"{obf_metrics[obf_target]['indirects']}")

    ok = (node_ratio >= bar["node_factor"]
          and edge_ratio >= bar["edge_factor"])
    if not ok:
        print("ida cfg gnarliness: FAIL (one or more bars missed)",
              file=sys.stderr)
        return 1
    print("ida cfg gnarliness: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
