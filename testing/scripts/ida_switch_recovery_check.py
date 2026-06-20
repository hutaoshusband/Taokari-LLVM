from __future__ import annotations

import json
from pathlib import Path

import ida_auto
import ida_funcs
import ida_nalt
import idautils


TARGET_NAMES = ("taokari_ida_switch_probe",)


def has_switch_info(ea: int) -> bool:
    try:
        return ida_nalt.get_switch_info(ea) is not None
    except Exception:
        return False


def main() -> int:
    ida_auto.auto_wait()
    input_path = Path(ida_nalt.get_input_file_path())
    report_path = input_path.with_suffix(input_path.suffix + ".ida-switch.json")

    targets: list[dict[str, object]] = []
    for func_ea in idautils.Functions():
        name = ida_funcs.get_func_name(func_ea)
        if not any(target in name for target in TARGET_NAMES):
            continue
        func = ida_funcs.get_func(func_ea)
        switch_sites: list[str] = []
        for ea in idautils.FuncItems(func_ea):
            if has_switch_info(ea):
                switch_sites.append(hex(ea))
        targets.append({
            "name": name,
            "start": hex(func.start_ea) if func else hex(func_ea),
            "switch_sites": switch_sites,
        })

    report = {
        "input": str(input_path),
        "targets": targets,
        "ok": bool(targets) and all(not item["switch_sites"] for item in targets),
    }
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    if not report["ok"]:
        raise SystemExit(f"IDA switch recovery check failed; report: {report_path}")
    print(f"IDA switch recovery check passed; report: {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
