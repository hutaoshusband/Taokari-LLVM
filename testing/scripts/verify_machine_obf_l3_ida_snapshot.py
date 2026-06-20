"""Level-3 MIR Hex-Rays before/after snapshot gate."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CLANG = ROOT / "build" / "taokari-local" / "bin" / "clang.exe"
DEFAULT_IDA = Path(r"C:\Program Files\IDA Professional 9.1\ida.exe")
VSDEVCMD = Path(
    r"C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat"
)

SOURCE = r'''
#include <stdio.h>

__declspec(dllexport) __declspec(noinline) int guarded(int x) {
  return (x * 19) ^ 0x51;
}

int main(void) {
  printf("ida-snapshot:%d\n", guarded(23));
  return 0;
}
'''

IDA_SCRIPT = r'''
import json
import ida_auto
import ida_entry
import ida_funcs
import ida_hexrays
import ida_lines
import ida_nalt
import ida_pro

ida_auto.auto_wait()
item = {
    "input": ida_nalt.get_input_file_path(),
    "hexrays": bool(ida_hexrays.init_hexrays_plugin()),
    "exports": [],
    "guarded": None,
}
for i in range(ida_entry.get_entry_qty()):
    ordv = ida_entry.get_entry_ordinal(i)
    ea = ida_entry.get_entry(ordv)
    name = ida_entry.get_entry_name(ordv)
    item["exports"].append({"name": name, "ea": hex(ea)})
    if name == "guarded":
        f = ida_funcs.get_func(ea)
        guarded = {"name": name, "ea": hex(ea), "func": bool(f)}
        if f:
            guarded["start_ea"] = hex(f.start_ea)
            guarded["end_ea"] = hex(f.end_ea)
            guarded["size"] = int(f.end_ea - f.start_ea)
        try:
            cfunc = ida_hexrays.decompile(ea)
            if cfunc:
                lines = [ida_lines.tag_remove(sl.line) for sl in cfunc.get_pseudocode()]
                guarded["pseudocode"] = "\n".join(lines)
                guarded["line_count"] = len(lines)
        except Exception as exc:
            guarded["error"] = str(exc)
        item["guarded"] = guarded

with open(SNAPSHOT_OUT, "a", encoding="utf-8") as f:
    f.write(json.dumps(item) + "\n")
ida_pro.qexit(0)
'''


def run(command: list[str], **kw) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, **kw)


def run_vs(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    with tempfile.NamedTemporaryFile("w", suffix=".cmd", delete=False, encoding="utf-8") as h:
        batch = Path(h.name)
        h.write(
            "@echo off\n"
            f'call "{VSDEVCMD}" -arch=x64 -host_arch=x64 >nul\n'
            f"{subprocess.list2cmdline(command)}\n"
            "exit /b %ERRORLEVEL%\n"
        )
    try:
        return run(["cmd.exe", "/d", "/c", str(batch)], cwd=cwd)
    finally:
        batch.unlink(missing_ok=True)


def must(result: subprocess.CompletedProcess[str], label: str) -> None:
    if result.returncode:
        print(result.stdout, end="")
        print(result.stderr, end="", file=sys.stderr)
        raise SystemExit(f"{label} failed: {result.returncode}")


def ida_path() -> Path:
    configured = os.environ.get("TAOKARI_IDA")
    return Path(configured) if configured else DEFAULT_IDA


def compile_pair(tmp: Path) -> tuple[Path, Path]:
    src = tmp / "ida_snapshot.c"
    src.write_text(SOURCE, encoding="utf-8")
    plain, obf = tmp / "plain.exe", tmp / "obf.exe"
    must(run_vs([str(CLANG), str(src), "-O1", "-o", str(plain)], tmp), "plain compile")
    must(
        run_vs(
            [
                str(CLANG),
                str(src),
                "-O1",
                "-mllvm", "-taokari-mir=dirtybytes,junk,sub,unmodelled,fakebounds,split",
                "-mllvm", "-verify-machineinstrs",
                "-o", str(obf),
            ],
            tmp,
        ),
        "obfuscated compile",
    )
    return plain, obf


def run_ida(ida: Path, target: Path, script: Path, log: Path, out: Path) -> None:
    before = len(load_snapshots(out)) if out.exists() else 0
    result = run([str(ida), "-A", f"-L{log}", f"-S{script}", str(target)], timeout=120)
    after = len(load_snapshots(out)) if out.exists() else 0
    if after <= before:
        must(result, target.name)


def load_snapshots(path: Path) -> list[dict]:
    if not path.exists():
        raise SystemExit("IDA did not write snapshot output")
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def run_checks(tmp: Path) -> int:
    ida = ida_path()
    if not ida.exists():
        print(f"missing IDA: {ida} (set TAOKARI_IDA)", file=sys.stderr)
        return 2
    plain, obf = compile_pair(tmp)

    out = tmp / "ida_snapshot.jsonl"
    script = tmp / "snapshot.py"
    script.write_text(
        'SNAPSHOT_OUT = r"' + str(out).replace("\\", "\\\\") + '"\n' + IDA_SCRIPT,
        encoding="ascii",
    )
    run_ida(ida, plain, script, tmp / "plain.log", out)
    run_ida(ida, obf, script, tmp / "obf.log", out)

    snapshots = load_snapshots(out)
    if len(snapshots) != 2:
        raise SystemExit(f"expected 2 IDA snapshots, got {len(snapshots)}")
    plain_snap, obf_snap = snapshots
    plain_func = plain_snap.get("guarded") or {}
    obf_func = obf_snap.get("guarded") or {}
    if not plain_snap.get("hexrays") or not obf_snap.get("hexrays"):
        raise SystemExit("Hex-Rays unavailable in IDA snapshot")
    if not plain_func.get("func") or not obf_func.get("func"):
        raise SystemExit("guarded export was not recognized as a function")

    plain_pseudo = plain_func.get("pseudocode", "")
    obf_pseudo = obf_func.get("pseudocode", "")
    if "return (19 * a1) ^ 0x51u;" not in plain_pseudo:
        raise SystemExit("plain Hex-Rays snapshot does not show clean source-like return")
    if "__readeflags" not in obf_pseudo and "__writeeflags" not in obf_pseudo:
        raise SystemExit("obfuscated Hex-Rays snapshot lacks MIR flag-noise pseudocode")
    if int(obf_func.get("line_count", 0)) < int(plain_func.get("line_count", 0)) + 8:
        raise SystemExit(
            "obfuscated Hex-Rays snapshot too close to plain: "
            f"{plain_func.get('line_count')}->{obf_func.get('line_count')}"
        )

    print(
        "verify_machine_obf_l3_ida_snapshot: ok "
        f"lines={plain_func.get('line_count')}->{obf_func.get('line_count')} "
        f"size={plain_func.get('size')}->{obf_func.get('size')}"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    if not CLANG.exists():
        print(f"missing tool: {CLANG}", file=sys.stderr)
        return 2
    tmp = Path(tempfile.mkdtemp(prefix="taokari-mir-l3-ida-"))
    try:
        return run_checks(tmp)
    finally:
        if args.keep:
            print(f"kept temp dir: {tmp}")
        else:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
