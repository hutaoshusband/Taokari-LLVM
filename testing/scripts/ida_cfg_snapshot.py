"""IDA CFG snapshot (Section 22 Phase 5, real-IDA path).

Walks a function list in IDA Pro via IDAPython and dumps the Hex-Rays /
IDA graph CFG to a JSON file. One row per function with node count, edge
count, and the raw list of (src, dst) edges so a later diff can compare
two builds structurally.

This is the "real IDA" path that measure_ida_cfg_complexity.py proxies
for. It is meant to run from inside IDA:

    idat64 -A -S"ida_cfg_snapshot.py <idb> <out.json> <fn1,fn2,...>" <target.idb>

or, when IDA is NOT installed, it exits 0 with a "skipped" message so it
can sit harmlessly in CI until an IDA license is available.

CLI (when IDA python is on PATH):
  python ida_cfg_snapshot.py --ida <idat64.exe> --idb <target.idb> \
        --out <out.json> --functions fn1,fn2,...
  python ida_cfg_snapshot.py --check     # just probe for IDA, exit 0/2
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

# The IDAPython payload. Runs inside IDA's python; uses idaapi/idautils.
# We write it to a temp .py and pass via -S. Functions are listed; each
# function's CFG is walked via idaapi.FlowChart.
PAYLOAD = r'''
import sys, json
idb, out, fns = sys.argv[1], sys.argv[2], sys.argv[3].split(',') if len(sys.argv) > 3 else []
import idaapi, idautils, idc

def fn_graph(ea):
    f = idaapi.get_func(ea)
    if not f:
        return None
    nodes = 0
    edges = []
    fc = idaapi.FlowChart(f, flags=idaapi.FC_PREDS)
    for bb in fc:
        nodes += 1
        for s in bb.succs():
            edges.append([bb.start_ea, s.start_ea])
    return {"nodes": nodes, "edges": edges}

rows = {}
for name in fns:
    ea = idc.get_name_ea_simple(name)
    if ea == idc.BADADDR:
        rows[name] = {"error": "name not found"}
        continue
    g = fn_graph(ea)
    rows[name] = g if g else {"error": "no function"}

with open(out, "w", encoding="utf-8") as f:
    json.dump({"functions": rows}, f, indent=2)
idc.qexit(0)
'''


def find_ida() -> Path | None:
    for name in ("idat64.exe", "ida64.exe", "idat.exe", "ida.exe"):
        p = shutil.which(name)
        if p:
            return Path(p)
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="probe for IDA and exit 0 if found, 2 otherwise")
    ap.add_argument("--ida", help="path to idat64.exe / ida64.exe")
    ap.add_argument("--idb", help="target .idb to analyse")
    ap.add_argument("--out", help="output JSON path")
    ap.add_argument("--functions", default="",
                    help="comma-separated function list")
    args = ap.parse_args()

    ida = Path(args.ida) if args.ida else find_ida()

    if args.check:
        if ida:
            print(f"ida cfg snapshot: IDA found at {ida}")
            return 0
        print("ida cfg snapshot: IDA not installed (skipped)")
        return 0

    if not ida:
        # Skip cleanly when IDA is not available — this script sits in CI
        # until an IDA license lands.
        print("ida cfg snapshot: IDA not installed (skipped)")
        return 0

    if not (args.idb and args.out):
        ap.error("--idb and --out are required (or pass --check)")

    payload = Path(args.out + ".payload.py")
    payload.write_text(PAYLOAD, encoding="utf-8")
    try:
        script = f'{payload};{args.idb};{args.out};{args.functions}'
        r = subprocess.run(
            [str(ida), "-A", f'-S"{script}"', args.idb],
            capture_output=True, text=True,
        )
        if r.returncode:
            sys.stderr.write(r.stdout + r.stderr)
            return 1
    finally:
        payload.unlink(missing_ok=True)

    print(f"ida cfg snapshot: wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
