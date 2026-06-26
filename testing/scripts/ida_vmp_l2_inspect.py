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
import ida_segment
import ida_ua
import idautils

try:
    import ida_hexrays
except ImportError:
    ida_hexrays = None


DIRTY_STACK = bytes.fromhex(
    "9c 50 51 48 89 e0 48 8d 48 01 48 0f af c1 a8 01 74 08 0f 0b eb fe cc f1 0f 0b 59 58 9d"
)
DIRTY_STACK_DEC = bytes.fromhex(
    "9c 50 51 48 89 e0 48 8d 48 ff 48 0f af c1 a8 01 74 08 0f 0b eb fe cc f1 0f 0b 59 58 9d"
)
OLD_DOUBLE_XOR_DIRTY = bytes.fromhex(
    "9c 50 8a 04 24 34 a7 34 a7 3a 04 24 74 08 0f 0b eb fe cc f1 0f 0b 58 9d"
)
OLD_FIXED_DIRTY = bytes.fromhex("48 39 e4 74 08 0f 0b eb fe cc f1 0f 0b")


def function_snapshot(ea: int | None) -> dict[str, object]:
    out: dict[str, object] = {
        "found": ea is not None,
        "ea": ea,
        "size": 0,
        "mnems": {},
        "pseudocode_lines": 0,
    }
    if ea is None:
        return out
    fn = ida_funcs.get_func(ea)
    if not fn:
        return out
    out["size"] = int(fn.end_ea - fn.start_ea)
    mnems: dict[str, int] = {}
    for head in idautils.FuncItems(fn.start_ea):
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, head):
            mnem = ida_ua.print_insn_mnem(head).lower()
            mnems[mnem] = mnems.get(mnem, 0) + 1
    out["mnems"] = mnems
    if ida_hexrays and ida_hexrays.init_hexrays_plugin():
        try:
            cfunc = ida_hexrays.decompile(fn.start_ea)
            if cfunc:
                out["pseudocode_lines"] = len(str(cfunc).splitlines())
        except Exception:
            pass
    return out


def first_text_match(pattern: bytes) -> int | None:
    for start in idautils.Segments():
        seg = ida_segment.getseg(start)
        if not seg:
            continue
        name = ida_segment.get_segm_name(seg).lower()
        if ".text" not in name:
            continue
        data = ida_bytes.get_bytes(seg.start_ea, seg.end_ea - seg.start_ea)
        if not data:
            continue
        pos = data.find(pattern)
        if pos >= 0:
            return int(seg.start_ea + pos)
    return None


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
    victim_ea = names.get("victim") or names.get("_victim")
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

    hexrays_available = bool(
        ida_hexrays and ida_hexrays.init_hexrays_plugin()
    )
    pseudocode_lines = 0
    if hexrays_available and interp_ea is not None:
        try:
            cfunc = ida_hexrays.decompile(interp_ea)
            pseudocode_lines = len(str(cfunc).splitlines()) if cfunc else 0
        except Exception:
            pseudocode_lines = 0

    report = {
        "interpreter_found": interp_ea is not None,
        "interpreter_ea": interp_ea,
        "bytecode_globals": len(bytecode),
        "first_qwords": first_qwords,
        "hexrays_available": hexrays_available,
        "interpreter_pseudocode_lines": pseudocode_lines,
        "xor_count": mnems.get("xor", 0),
        "imul_count": mnems.get("imul", 0),
        "jmp_count": mnems.get("jmp", 0),
        "victim": function_snapshot(victim_ea),
        "dirty_guard_ea": first_text_match(DIRTY_STACK) or first_text_match(DIRTY_STACK_DEC),
        "old_double_xor_dirty_ea": first_text_match(OLD_DOUBLE_XOR_DIRTY),
        "old_fixed_dirty_ea": first_text_match(OLD_FIXED_DIRTY),
    }
    victim = report["victim"]
    victim_mnems = victim.get("mnems", {}) if isinstance(victim, dict) else {}
    runtime_rekey_ok = (
        isinstance(victim, dict)
        and victim.get("found")
        and int(victim.get("size", 0)) >= 128
        and int(victim_mnems.get("xor", 0)) >= 2
        and int(victim_mnems.get("imul", 0)) >= 1
        and int(victim_mnems.get("call", 0)) >= 1
    )
    dirty_guard_ok = (
        report["dirty_guard_ea"] is not None
        and report["old_double_xor_dirty_ea"] is None
        and report["old_fixed_dirty_ea"] is None
    )
    report["runtime_rekey_ok"] = runtime_rekey_ok
    report["dirty_guard_ok"] = dirty_guard_ok

    ok = (
        report["interpreter_found"]
        and report["xor_count"] >= 2
        and report["imul_count"] >= 1
        and (not hexrays_available or pseudocode_lines >= 20)
        and runtime_rekey_ok
        and dirty_guard_ok
    )
    report["ok"] = ok
    with open(report_path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
    return 0 if ok else 1


ida_pro.qexit(main())
