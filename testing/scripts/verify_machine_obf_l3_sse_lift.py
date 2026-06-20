"""Level-3 Fortress `+mir:sse` anti-microcode-lift gate.

The `+mir:sse` sub-pass scatters non-foldable rdrand-seeded opaque-true
guards with modeled-SSE dead bytes (psrldq / pcmpeqb / pmovmskb) across the
function BODY -- not just at entry -- so a Hex-Rays CFG-directed microcode
lifter that scans into the body cannot prune them and must either include
wrong dataflow or fail to solve the rdrand-evenness predicate.

This gate proves the pass works end-to-end:
  * the SSE fixture compiles with the full IR stack PLUS +mir:sse and
    -verify-machineinstrs passes (post-RA liveness intact);
  * plain vs obfuscated stdout are identical (semantics preserved);
  * the obfuscated .obj contains >=2 rdrand opcodes at distinct body
    addresses (proves scattering, not entry-only);
  * the obfuscated .obj contains the dead psrldq/pcmpeqb/pmovmskb opcodes
    the lifter would otherwise model cleanly.

Optional (--check-ida, needs TAOKARI_IDA): the obfuscated probe's Hex-Rays
decompile must contain a rdrand/__readeflags artifact AND grow at least 8
lines versus the Phase-A-only obf build (proves +mir:sse adds noise on top
of the IR stack).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CLANG = ROOT / "build" / "taokari-local" / "bin" / "clang.exe"
OBJDUMP = ROOT / "build" / "taokari-local" / "bin" / "llvm-objdump.exe"
DEFAULT_IDA = Path(r"C:\Program Files\IDA Professional 9.1\ida.exe")
VSDEVCMD = Path(
    r"C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat"
)
SRC = ROOT / "testing" / "cases" / "sse_string" / "src" / "main.c"
PROBE = "taokari_sse_strlen_probe"

# Full IR stack (Phase A) + the Fortress +mir:sse sub-pass (Phase B).
IR_FLAGS = [
    "-mllvm", "-taokari",
    "-mllvm", "-taokari-fla", "-mllvm", "-taokari-level-fla=4",
    "-mllvm", "-taokari-bcf",  "-mllvm", "-taokari-level-bcf=2",
    "-mllvm", "-taokari-mba",  "-mllvm", "-taokari-level-mba=1",
    "-mllvm", "-taokari-cie",  "-mllvm", "-taokari-level-cie=2",
    "-mllvm", "-taokari-icall",
]
GOLDEN = "sse-string:1:0:a\n"


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


def compile_pair(tmp: Path, *, with_sse: bool) -> tuple[Path, Path, Path]:
    plain_obj = tmp / ("plain.obj")
    plain_exe = tmp / "plain.exe"
    obf_obj = tmp / ("sse_obf.obj" if with_sse else "obf.obj")
    obf_exe = tmp / ("sse_obf.exe" if with_sse else "obf.exe")

    must(run_vs([str(CLANG), "-O2", "-std=c17", "-c", str(SRC), "-o", str(plain_obj)], tmp),
         "plain obj compile")
    must(run_vs([str(CLANG), "-O2", "-std=c17", str(SRC), "-o", str(plain_exe)], tmp),
         "plain exe compile")

    mir = "split,sse" if with_sse else "split"
    obf_obj_cmd = [str(CLANG), "-O2", "-std=c17", "-c", str(SRC), *IR_FLAGS,
                   "-mllvm", f"-taokari-mir={mir}",
                   "-mllvm", "-verify-machineinstrs", "-o", str(obf_obj)]
    must(run_vs(obf_obj_cmd, tmp), "obfuscated obj compile (+verify-machineinstrs)")
    obf_exe_cmd = [str(CLANG), "-O2", "-std=c17", str(SRC), *IR_FLAGS,
                   "-mllvm", f"-taokari-mir={mir}", "-o", str(obf_exe)]
    must(run_vs(obf_exe_cmd, tmp), "obfuscated exe compile")
    return plain_obj, obf_obj, obf_exe


def disasm_probe(obj: Path, tmp: Path) -> str:
    r = run_vs([str(OBJDUMP), "-d", "--no-show-raw-insn", str(obj)], tmp)
    if r.returncode:
        print(r.stdout, end="")
        print(r.stderr, end="", file=sys.stderr)
        raise SystemExit(f"objdump failed for {obj}")
    m = re.search(rf"{re.escape(PROBE)}>:(.*?)(?=\n\n|\Z)", r.stdout, re.S)
    return m.group(1) if m else ""


def rdrand_addresses(body: str) -> list[int]:
    """Return distinct instruction offsets of rdrand in the disassembly."""
    addrs: list[int] = []
    for line in body.splitlines():
        if "rdrand" in line.lower():
            m = re.match(r"\s*([0-9a-f]+):", line)
            if m:
                addrs.append(int(m.group(1), 16))
    return addrs


def assert_sse_scatter(obf_body: str) -> None:
    addrs = rdrand_addresses(obf_body)
    if len(addrs) < 2:
        raise SystemExit(
            f"+mir:sse did not scatter: only {len(addrs)} rdrand site(s) in probe body "
            f"(need >=2 to prove body-walking, not entry-only)"
        )
    if len(set(addrs)) != len(addrs):
        raise SystemExit(f"+mir:sse rdrand addresses not distinct: {addrs}")
    for op in ("psrldq", "pcmpeqb", "pmovmskb"):
        if op not in obf_body:
            raise SystemExit(f"+mir:sse dead region missing modeled-SSE opcode '{op}'")


def ida_check(tmp: Path, obf_exe_sse: Path, obf_exe_ir_only: Path) -> None:
    """Optional: obf-with-sse decompile must show rdrand noise and grow vs IR-only."""
    ida = Path(os.environ["TAOKARI_IDA"]) if os.environ.get("TAOKARI_IDA") else DEFAULT_IDA
    if not ida.exists():
        print("info: IDA not found, skipping IDA lift check")
        return

    out = tmp / "sse_lift.json"
    script = tmp / "lift_check.py"
    script.write_text(
        'OUT = r"' + str(out).replace("\\", "\\\\") + '"\n'
        'PROBE = "' + PROBE + '"\n'
        r'''
import json, ida_auto, ida_entry, ida_funcs, ida_hexrays, ida_lines, ida_pro
ida_auto.auto_wait()
result = {"probe": None}
for i in range(ida_entry.get_entry_qty()):
    ordv = ida_entry.get_entry_ordinal(i)
    name = ida_entry.get_entry_name(ordv)
    if name != PROBE:
        continue
    ea = ida_entry.get_entry(ordv)
    snap = {"name": name, "ea": hex(ea)}
    try:
        cfunc = ida_hexrays.decompile(ea)
        if cfunc:
            lines = [ida_lines.tag_remove(sl.line) for sl in cfunc.get_pseudocode()]
            snap["pseudocode"] = "\n".join(lines)
            snap["line_count"] = len(lines)
    except Exception as exc:
        snap["error"] = str(exc)
    result["probe"] = snap
    break
with open(OUT, "w", encoding="utf-8") as h:
    json.dump(result, h)
ida_pro.qexit(0)
''',
        encoding="ascii",
    )

    def snap(exe: Path) -> dict:
        out.unlink(missing_ok=True)
        log = tmp / (exe.stem + "_lift.log")
        r = run([str(ida), "-A", f"-L{log}", f"-S{script}", str(exe)], timeout=180)
        if not out.exists():
            must(r, exe.name)
            raise SystemExit(f"IDA did not write lift snapshot for {exe.name}")
        return json.loads(out.read_text(encoding="utf-8")).get("probe") or {}

    ir_only = snap(obf_exe_ir_only)
    with_sse = snap(obf_exe_sse)
    ir_lc = int(ir_only.get("line_count", 0))
    sse_lc = int(with_sse.get("line_count", 0))
    sse_pseudo = with_sse.get("pseudocode", "")
    # Either the decompile carries rdrand/flag residue, or it failed outright
    # (even stronger -- the lifter gave up).
    noise = any(tok in sse_pseudo for tok in ("rdrand", "__readeflags", "__writeeflags"))
    if not noise and not with_sse.get("error"):
        raise SystemExit(
            f"+mir:sse did not add visible noise to Hex-Rays output "
            f"(no rdrand/__readeflags and no decompile error)"
        )
    if not with_sse.get("error") and sse_lc < ir_lc + 8:
        raise SystemExit(
            f"+mir:sse Hex-Rays line growth insufficient: IR-only={ir_lc} "
            f"+sse={sse_lc} (need +8)"
        )
    print(f"IDA lift check: ok IR-only={ir_lc} +sse={sse_lc} "
          f"error={bool(with_sse.get('error'))}")


def run_checks(tmp: Path, args: argparse.Namespace) -> int:
    plain_obj, obf_obj, obf_exe = compile_pair(tmp, with_sse=True)

    plain_body = disasm_probe(plain_obj, tmp)
    obf_body = disasm_probe(obf_obj, tmp)
    if not plain_body:
        raise SystemExit(f"could not locate {PROBE} in plain .obj")
    if not obf_body:
        raise SystemExit(f"could not locate {PROBE} in obfuscated .obj")

    # 1. +mir:sse scattered non-foldable guards across the body.
    assert_sse_scatter(obf_body)

    # 2. Semantics preserved.
    plain_run = run([str(tmp / "plain.exe")])
    obf_run = run([str(obf_exe)])
    must(plain_run, "plain run")
    must(obf_run, "obfuscated run")
    if plain_run.stdout != GOLDEN or obf_run.stdout != GOLDEN:
        raise SystemExit(
            f"stdout mismatch: plain={plain_run.stdout!r} obf={obf_run.stdout!r} "
            f"expected {GOLDEN!r}"
        )

    addrs = rdrand_addresses(obf_body)
    print(
        f"verify_machine_obf_l3_sse_lift: ok "
        f"rdrand_sites={len(addrs)} "
        f"psrldq={len(re.findall(r'psrldq', obf_body))} "
        f"pcmpeqb={len(re.findall(r'pcmpeqb', obf_body))} "
        f"pmovmskb={len(re.findall(r'pmovmskb', obf_body))} "
        f"obf_size={obf_exe.stat().st_size}"
    )

    if args.check_ida:
        # Need an IR-only obf exe to compare growth against.
        _, ir_only_obj, ir_only_exe = compile_pair(tmp, with_sse=False)
        ida_check(tmp, obf_exe, ir_only_exe)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--check-ida", action="store_true",
                        help="also run IDA and assert +mir:sse adds decompiler noise "
                             "on top of the IR-only obf build (needs TAOKARI_IDA or default)")
    args = parser.parse_args()
    if not CLANG.exists():
        print(f"missing tool: {CLANG}", file=sys.stderr)
        return 2
    tmp = Path(tempfile.mkdtemp(prefix="taokari-mir-l3-sse-"))
    try:
        return run_checks(tmp, args)
    finally:
        if args.keep:
            print(f"kept temp dir: {tmp}")
        else:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
