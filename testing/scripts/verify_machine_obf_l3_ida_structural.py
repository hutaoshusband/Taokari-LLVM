"""IDA structural snapshot comparison (C3.5).

Runs IDA headlessly on a plain and a MIR-obfuscated build of the same module,
captures module-wide structural metrics (function count, total function bytes,
decompiler success count, mean function size) as JSON artifacts, and asserts
the MIR build shifts them in the expected direction:

- function_count: split fragments entry blocks, so the count rises or the mean
  size changes; at minimum the metrics are captured for regression tracking.
- decompile_success: every exported function must still decompile (correctness
  preserved); fragmentation is structural, not a decompiler break.

Skips gracefully (exit 2) when IDA is unavailable. Set TAOKARI_IDA to point at
a non-default install.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
DEFAULT_IDA = Path(r"C:\Program Files\IDA Professional 9.1\ida.exe")
VSDEVCMD = tp.VSDEVCMD

MIR = "dirtybytes,junk,sub,split,fakeprologue"

SOURCE = r'''
#include <cstdint>
#include <cstdio>
#define NOINLINE __attribute__((noinline))
#define OPTNONE __attribute__((optnone))
#define DLLEXPORT __declspec(dllexport)
extern "C" {
DLLEXPORT NOINLINE OPTNONE uint32_t fa(uint32_t x) { return x * 7u + 1; }
DLLEXPORT NOINLINE OPTNONE uint32_t fb(uint32_t x) { return x ^ 0x55u; }
DLLEXPORT NOINLINE OPTNONE uint32_t fc(uint32_t x) { return x + (x << 3); }
}
int main() {
  std::printf("ida-struct:%u:%u:%u\n", fa(1), fb(2), fc(3));
  return 0;
}
'''

IDA_SCRIPT = r'''
import json
import ida_auto
import ida_funcs
import ida_hexrays
import idautils
import idaapi

ida_auto.auto_wait()
hexrays_ok = ida_hexrays.init_hexrays_plugin()

fcount = 0
total_bytes = 0
decomp_ok = 0
decomp_fail = 0
for fea in idautils.Functions():
    f = ida_funcs.get_func(fea)
    if not f:
        continue
    fcount += 1
    total_bytes += int(f.end_ea - f.start_ea)
    if hexrays_ok:
        try:
            if ida_hexrays.decompile(fea):
                decomp_ok += 1
            else:
                decomp_fail += 1
        except Exception:
            decomp_fail += 1

item = {
    "input": idaapi.get_input_file_path(),
    "ida_kernel_version": idaapi.get_kernel_version(),
    "hexrays": hexrays_ok,
    "function_count": fcount,
    "total_function_bytes": total_bytes,
    "mean_function_bytes": (total_bytes / fcount) if fcount else 0,
    "decompile_ok": decomp_ok,
    "decompile_fail": decomp_fail,
}
with open(SNAPSHOT_OUT, "w", encoding="utf-8") as fh:
    fh.write(json.dumps(item) + "\n")
idaapi.qexit(0)
'''


def run(command: list[str], **kw) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, **kw)


def run_vs(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    if not tp.IS_WINDOWS:
      return subprocess.run(command, cwd=cwd, text=True, capture_output=True)
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


def snapshot(ida: Path, exe: Path, out: Path, script_file: Path, log: Path) -> dict:
    if out.exists():
        out.unlink()
    full = (
        'SNAPSHOT_OUT = r"' + str(out).replace("\\", "\\\\") + '"\n'
        + IDA_SCRIPT
    )
    script_file.write_text(full, encoding="ascii")
    result = run([str(ida), "-A", f"-L{log}", f"-S{script_file}", str(exe)],
                 timeout=180)
    if not out.exists():
        must(result, exe.name)
        raise SystemExit(f"IDA did not write snapshot for {exe.name}")
    return json.loads(out.read_text(encoding="utf-8").strip())


def run_checks(tmp: Path) -> int:
    src = tmp / "ida_struct.cpp"
    src.write_text(SOURCE, encoding="utf-8")

    plain = tmp / "plain.exe"
    obf = tmp / "obf.exe"
    must(run_vs([str(CLANG), str(src), "-std=c++17", "-O1", "-o", str(plain)],
                src.parent), "plain build")
    must(run_vs([str(CLANG), str(src), "-std=c++17", "-O1", "-mllvm",
                 "-verify-machineinstrs", "-mllvm", f"-taokari-mir={MIR}",
                 "-o", str(obf)], src.parent), "obf build")

    plain_out = run([str(plain)])
    obf_out = run([str(obf)])
    must(plain_out, "plain run")
    must(obf_out, "obf run")
    if plain_out.stdout != obf_out.stdout:
        raise SystemExit(f"stdout mismatch: {plain_out.stdout!r} != {obf_out.stdout!r}")

    ida = ida_path()
    plain_snap = snapshot(ida, plain, tmp / "plain.snapshot.json",
                          tmp / "snap.py", tmp / "plain.ida.log")
    obf_snap = snapshot(ida, obf, tmp / "obf.snapshot.json",
                        tmp / "snap.py", tmp / "obf.ida.log")

    if obf_snap["decompile_fail"] > plain_snap["decompile_fail"]:
        raise SystemExit(
            f"MIR build broke decompilation: fail {plain_snap['decompile_fail']}"
            f"->{obf_snap['decompile_fail']}")
    if obf_snap["total_function_bytes"] <= plain_snap["total_function_bytes"]:
        raise SystemExit(
            "MIR build did not grow total function bytes (no structural impact)")

    print(
        "verify_machine_obf_l3_ida_structural: ok "
        f"functions={plain_snap['function_count']}->{obf_snap['function_count']} "
        f"bytes={plain_snap['total_function_bytes']}->{obf_snap['total_function_bytes']} "
        f"decompile_ok={obf_snap['decompile_ok']}"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    for tool in (CLANG, ida_path()):
        if not tool.exists():
            print(f"missing tool: {tool}", file=sys.stderr)
            return 2
    tmp = Path(tempfile.mkdtemp(prefix="taokari-mir-ida-struct-"))
    try:
        return run_checks(tmp)
    finally:
        if args.keep:
            print(f"kept temp dir: {tmp}")
        else:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
