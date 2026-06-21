"""IDA-side VMP L2 inspection.

Run with IDA/idat using TAOKARI_IDA_REPORT=<path>. The target binary should be
built with CodeView/PDB info so internal VMP helper names are visible.
"""
from __future__ import annotations

import json
import os

import ida_auto
import ida_bytes
import ida_funcs
import ida_name
import ida_pro
import ida_ua
import idautils


def main() -> int:
    report_path = os.environ.get("TAOKARI_IDA_REPORT")
    if not report_path:
        return 2

    ida_auto.auto_wait()

    names = {name: ea for ea, name in idautils.Names()}
    extra_symbols = os.environ.get("TAOKARI_IDA_SYMBOLS_JSON")
    if extra_symbols:
        for name, ea in json.loads(extra_symbols).items():
            names[name] = int(ea)
    interp_ea = next(
        (ea for name, ea in names.items()
         if name.startswith("__taokari_vmp_interp_i64")),
        None,
    )
    bytecode = {
        name: ea for name, ea in names.items()
        if name.startswith("__taokari_vmp_bc_")
    }

    mnems: dict[str, int] = {}
    if interp_ea is not None:
        for head in idautils.FuncItems(interp_ea):
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, head):
                mnem = ida_ua.print_insn_mnem(head).lower()
                mnems[mnem] = mnems.get(mnem, 0) + 1

    first_qwords: dict[str, int] = {}
    for name, ea in bytecode.items():
        data = ida_bytes.get_bytes(ea, 8)
        if data:
            first_qwords[name] = int.from_bytes(data, "little", signed=True)

    report = {
        "interpreter_found": interp_ea is not None,
        "interpreter_ea": interp_ea,
        "bytecode_globals": len(bytecode),
        "first_qwords": first_qwords,
        "xor_count": mnems.get("xor", 0),
        "imul_count": mnems.get("imul", 0),
        "jmp_count": mnems.get("jmp", 0),
    }

    ok = (
        report["interpreter_found"]
        and report["xor_count"] >= 2
        and report["imul_count"] >= 1
    )
    report["ok"] = ok
    with open(report_path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
    return 0 if ok else 1


ida_pro.qexit(main())
