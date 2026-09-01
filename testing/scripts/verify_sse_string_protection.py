"""Full-stack protection gate for the SSE string-op fixture.

Reproduces and attacks the exact weakness pattern reported against the
obfuscator: a CRT-style SSE byte search whose plain binary lowers to
pcmpeqb + pmovmskb + a jump-table dispatch with `psrldq $N` arms (the
"case N: shift by N" pattern Hex-Rays models cleanly). See
testing/cases/sse_string/src/main.c.

This gate proves the IR obfuscation stack addresses the complaints at the
layer they actually live in (the binary, not the IR -- clang vectorises the
intrinsics out of LLVM IR but the SSE ops survive in the .obj disassembly,
which is what Hex-Rays lifts from):
  1. plain .obj contains a clean switch-driven psrldq dispatch (control:
     the gap is real and reproducible).
  2. obfuscated .obj no longer exposes that clean dispatch.
  3. both binaries produce identical stdout (semantics preserved).

Optional (when --check-ida and TAOKARI_IDA is set): the obfuscated export
must not be recoverable as a clean IDA switch via ida_nalt.get_switch_info.
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
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
LLVM_DIS = tp.tool("opt")  # round-trips .bc via -S
OBJDUMP = tp.tool("llvm-objdump")
DEFAULT_IDA = Path(r"C:\Program Files\IDA Professional 9.1\ida.exe")
VSDEVCMD = tp.VSDEVCMD
SRC = ROOT / "testing" / "cases" / "sse_string" / "src" / "main.c"
PROBE = "taokari_sse_strlen_probe"

# Full IR obfuscation stack: every pass that attacks one of the complaints.
OBF_FLAGS = [
    "-mllvm", "-taokari",
    "-mllvm", "-taokari-fla", "-mllvm", "-taokari-level-fla=4",  # destroy the switch
    "-mllvm", "-taokari-bcf",  "-mllvm", "-taokari-level-bcf=2",  # opaque-guarded fake paths
    "-mllvm", "-taokari-mba",  "-mllvm", "-taokari-level-mba=1",  # hide arithmetic
    "-mllvm", "-taokari-cie",  "-mllvm", "-taokari-level-cie=2",  # hide constants 1..15
    "-mllvm", "-taokari-icall",                                     # route the static tail call
    "-mllvm", "-taokari-mir=split",                                # attack function recognition
    "-mllvm", "-verify-machineinstrs",
]

GOLDEN = "sse-string:1:0:a\n"


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


def compile_plain(src: Path, obj: Path, exe: Path, tmp: Path) -> None:
    must(run_vs([str(CLANG), "-O2", "-std=c17", "-c", str(src), "-o", str(obj)], tmp), "plain obj compile")
    must(run_vs([str(CLANG), "-O2", "-std=c17", str(src), "-o", str(exe)], tmp), "plain exe compile")


def compile_obf(src: Path, obj: Path, exe: Path, tmp: Path) -> None:
    cmd = [str(CLANG), "-O2", "-std=c17", "-c", str(src), *OBF_FLAGS, "-o", str(obj)]
    must(run_vs(cmd, tmp), "obfuscated obj compile")
    cmd = [str(CLANG), "-O2", "-std=c17", str(src), *OBF_FLAGS, "-o", str(exe)]
    must(run_vs(cmd, tmp), "obfuscated exe compile")


def disasm_probe(obj: Path) -> str:
    """Return the disassembly of the probe function from a .obj, or '' on miss."""
    r = run_vs([str(OBJDUMP), "-d", "--no-show-raw-insn", str(obj)], obj.parent)
    if r.returncode:
        print(r.stdout, end="")
        print(r.stderr, end="", file=sys.stderr)
        raise SystemExit(f"objdump failed: {r.returncode}")
    m = re.search(
        rf"^[\s\w<>]*{re.escape(PROBE)}[^:]*>:\n(.*?)(?=\n\n|\n\d+ .*?:|\Z)",
        r.stdout,
        re.S | re.M,
    )
    return m.group(1) if m else ""


def ir_of_probe(obfuscate: bool, tmp: Path) -> str:
    """Emit LLVM IR (plain or obfuscated) and return the probe function body.

    Note: -O2 vectorises the SSE intrinsics out of IR, so this check is about
    the *switch dispatch*, not the SSE ops. Width varies (i16/i32).
    """
    bc = tmp / ("obf.bc" if obfuscate else "plain.bc")
    flags = OBF_FLAGS if obfuscate else []
    r = run_vs([str(CLANG), "-O2", "-std=c17", "-c", "-emit-llvm", str(SRC), *flags, "-o", str(bc)], tmp)
    if r.returncode:
        print(r.stdout, end="")
        print(r.stderr, end="", file=sys.stderr)
        raise SystemExit(f"emit {'obfuscated' if obfuscate else 'plain'} bitcode failed")
    ll = tmp / (bc.stem + ".ll")
    r = run_vs([str(LLVM_DIS), "-S", str(bc), "-o", str(ll)], tmp)
    if r.returncode:
        print(r.stdout, end="")
        print(r.stderr, end="", file=sys.stderr)
        raise SystemExit("opt -S bitcode failed")
    text = ll.read_text(encoding="utf-8") if ll.exists() else ""
    m = re.search(rf"define[^@]*@{re.escape(PROBE)}[^\n]*\n(?:.*\n)*?\}}", text)
    return m.group(0) if m else text


def assert_plain_pattern(obj_body: str) -> None:
    """Plain .obj must show the textbook SSE + jump-table + psrldq dispatch."""
    missing = [op for op in ("pcmpeqb", "pmovmskb") if op not in obj_body]
    if missing:
        raise SystemExit(f"plain .obj missing SSE ops {missing} -- fixture regressed: {obj_body[:400]!r}")
    if "psrldq" not in obj_body:
        raise SystemExit(f"plain .obj missing 'psrldq' shift arms -- fixture regressed: {obj_body[:400]!r}")
    # A jump-table dispatch: indirect jump via a base+index table lookup.
    if "*%r" not in obj_body.replace(" ", "").lower() and "jmpq" not in obj_body.lower() and "jmp *" not in obj_body.lower():
        raise SystemExit(f"plain .obj missing jump-table indirect jmp -- fixture regressed: {obj_body[:400]!r}")


def assert_obfuscated_pattern(obj_body: str, plain_body: str) -> None:
    """The obfuscated .obj must not expose the clean switch-driven psrldq dispatch.

    The clean pattern is: many distinct `psrldq $<imm>` arms reached from one
    indirect jump table. After fla L4 the dispatcher is gone; after const-enc
    the immediates are hidden behind decryptors. We accept SSE ops still
    appearing (they are the function's real logic) but the jump-table-driven
    multi-arm psrldq dispatch must be gone.
    """
    obf_psrldq = len(re.findall(r"\bpsrldq\b", obj_body))
    plain_psrldq = len(re.findall(r"\bpsrldq\b", plain_body))
    # Obfuscation must collapse the dispatch: dramatically fewer psrldq arms
    # than the plain jump-table form, OR the indirect jump-table gone.
    has_jumptable = ("*%r" in obj_body.replace(" ", "").lower()
                     or "jmpq" in obj_body.lower() or "jmp *" in obj_body.lower())
    if has_jumptable and obf_psrldq >= plain_psrldq - 1:
        raise SystemExit(
            f"obfuscated .obj still exposes the clean psrldq jump-table dispatch: "
            f"plain psrldq={plain_psrldq} obf psrldq={obf_psrldq}"
        )


def assert_obfuscated_ir(ir_body: str, plain_ir_body: str) -> None:
    """The obfuscated IR must not contain a switch -- fla L4 must have destroyed it."""
    plain_switch = re.search(r"\bswitch\b", plain_ir_body)
    if not plain_switch:
        # The IR width varies (i16/i32) and the switch may be lowered late; this
        # is informational, not gating, since the binary-level gate is the real
        # proof.
        print(f"info: plain IR has no 'switch' keyword (lowered to jump table early); "
              f"binary-level gate is authoritative")
        return
    if re.search(r"\bswitch\b", ir_body):
        raise SystemExit("obfuscated IR still contains a 'switch' -- fla L4 did not destroy the dispatch")


def ida_switch_check(tmp: Path, obf_exe: Path) -> None:
    """Optional: prove IDA reports no switch_sites for the obfuscated probe."""
    ida = Path(os.environ["TAOKARI_IDA"]) if os.environ.get("TAOKARI_IDA") else DEFAULT_IDA
    if not ida.exists():
        print("info: IDA not found, skipping IDA switch check")
        return
    out = tmp / "ida_switch.json"
    script = tmp / "switch_check.py"
    script.write_text(
        'OUT = r"' + str(out).replace("\\", "\\\\") + '"\n'
        'PROBE = "' + PROBE + '"\n'
        r'''
import json, ida_auto, ida_bytes, ida_entry, ida_funcs, ida_nalt, ida_pro, idaapi
ida_auto.auto_wait()
result = {"probe": None, "switch_sites": 0}
for i in range(ida_entry.get_entry_qty()):
    ordv = ida_entry.get_entry_ordinal(i)
    name = ida_entry.get_entry_name(ordv)
    if name != PROBE:
        continue
    ea = ida_entry.get_entry(ordv)
    f = ida_funcs.get_func(ea)
    if not f:
        result["probe"] = {"recognized": False}
        break
    sites = 0
    cur = f.start_ea
    while cur != idaapi.BADADDR and cur < f.end_ea:
        if ida_nalt.get_switch_info(cur):
            sites += 1
        cur = ida_bytes.next_head(cur, f.end_ea)
    result["probe"] = {"recognized": True, "start": hex(f.start_ea), "end": hex(f.end_ea)}
    result["switch_sites"] = sites
    break
with open(OUT, "w", encoding="utf-8") as h:
    json.dump(result, h)
ida_pro.qexit(0)
''',
        encoding="ascii",
    )
    log = tmp / "ida_switch.log"
    r = run([str(ida), "-A", f"-L{log}", f"-S{script}", str(obf_exe)], timeout=180)
    if not out.exists():
        must(r, "IDA switch check")
    data = json.loads(out.read_text(encoding="utf-8"))
    probe = data.get("probe") or {}
    if not probe.get("recognized"):
        raise SystemExit(f"IDA did not recognize {PROBE} as a function: {probe}")
    sites = int(data.get("switch_sites", 0))
    if sites > 0:
        raise SystemExit(f"obfuscated {PROBE} still has {sites} IDA switch_sites -- dispatch not destroyed")
    print(f"IDA switch check: ok (0 switch_sites for {PROBE})")


def run_checks(tmp: Path, args: argparse.Namespace) -> int:
    plain_obj, plain_exe = tmp / "plain.obj", tmp / "plain.exe"
    obf_obj, obf_exe = tmp / "obf.obj", tmp / "obf.exe"

    compile_plain(SRC, plain_obj, plain_exe, tmp)
    compile_obf(SRC, obf_obj, obf_exe, tmp)

    plain_body = disasm_probe(plain_obj)
    obf_body = disasm_probe(obf_obj)
    if not plain_body:
        raise SystemExit(f"could not locate {PROBE} in plain .obj disassembly")
    if not obf_body:
        raise SystemExit(f"could not locate {PROBE} in obfuscated .obj disassembly")

    # 1. Control: plain .obj must show the textbook weakness pattern.
    assert_plain_pattern(plain_body)

    # 2. Obfuscated .obj must not still expose the clean jump-table + psrldq dispatch.
    assert_obfuscated_pattern(obf_body, plain_body)

    # 3. IR-level switch destruction (informational if lowered early).
    assert_obfuscated_ir(ir_of_probe(True, tmp), ir_of_probe(False, tmp))

    # 4. Semantics preserved.
    plain_run = run([str(plain_exe)])
    obf_run = run([str(obf_exe)])
    must(plain_run, "plain run")
    must(obf_run, "obfuscated run")
    if plain_run.stdout != GOLDEN:
        raise SystemExit(f"plain stdout mismatch: {plain_run.stdout!r} expected {GOLDEN!r}")
    if obf_run.stdout != GOLDEN:
        raise SystemExit(f"obfuscated stdout mismatch: {obf_run.stdout!r} expected {GOLDEN!r}")

    print(f"verify_sse_string_protection: ok "
          f"plain_psrldq={len(re.findall(r'psrldq', plain_body))} "
          f"obf_psrldq={len(re.findall(r'psrldq', obf_body))} "
          f"plain_size={plain_exe.stat().st_size} obf_size={obf_exe.stat().st_size}")

    if args.check_ida:
        ida_switch_check(tmp, obf_exe)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--check-ida", action="store_true",
                        help="also run IDA and assert no switch_sites remain (needs TAOKARI_IDA or default install)")
    args = parser.parse_args()
    if not CLANG.exists():
        print(f"missing tool: {CLANG}", file=sys.stderr)
        return 2
    tmp = Path(tempfile.mkdtemp(prefix="taokari-sse-prot-"))
    try:
        return run_checks(tmp, args)
    finally:
        if args.keep:
            print(f"kept temp dir: {tmp}")
        else:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())