"""Level-3 MIR Hex-Rays before/after snapshot gate.

Default behaviour is unchanged: snapshots the `guarded` fixture and checks it
grew with flag noise. `--fixture sse` adds the SSE string-op fixture, whose
plain Hex-Rays decompile shows the textbook `case N: shift by N` SSE dispatch
that the obfuscator must destroy.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
DEFAULT_IDA = Path(r"C:\Program Files\IDA Professional 9.1\ida.exe")
VSDEVCMD = tp.VSDEVCMD

# Default Fortress MIR sub-pass set used for every fixture.
DEFAULT_MIR = "dirtybytes,junk,sub,unmodelled,fakebounds,split"

GUARDED_SOURCE = r'''
#include <stdio.h>

__declspec(dllexport) __declspec(noinline) int guarded(int x) {
  return (x * 19) ^ 0x51;
}

int main(void) {
  printf("ida-snapshot:%d\n", guarded(23));
  return 0;
}
'''


@dataclass
class Fixture:
    """One Hex-Rays snapshot target.

    plain_pseudo_must_contain: assert the plain decompile of `probe` contains
        each substring (proves the fixture is non-vacuous -- the weakness
        pattern is really there before obfuscation).
    obf_min_extra_lines: obfuscated pseudocode must have at least
        plain_line_count + N lines (protection added visible noise).
    obf_must_contain_any: obfuscated pseudocode must contain at least one of
        these substrings (flag noise, MBA residue, rdrand artifact).
    obf_no_ida_switch: if True, walk every instruction in the obfuscated
        function and assert ida_nalt.get_switch_info returns nothing
        (dispatch destroyed, mirroring ida_switch_recovery_check.py).
    extra_obf_flags: extra -mllvm flags beyond DEFAULT_MIR (e.g. the full IR
        stack needed to destroy the SSE switch dispatch).
    """
    name: str
    src: Path
    probe: str
    plain_pseudo_must_contain: tuple[str, ...] = ()
    obf_min_extra_lines: int = 8
    obf_must_contain_any: tuple[str, ...] = ("__readeflags", "__writeeflags")
    obf_no_ida_switch: bool = False
    extra_obf_flags: tuple[str, ...] = ()


def _write_guarded_source(tmp: Path) -> Path:
    p = tmp / "guarded.c"
    p.write_text(GUARDED_SOURCE, encoding="utf-8")
    return p


# Full IR stack needed to destroy the SSE fixture's switch dispatch at the IR
# layer (see verify_sse_string_protection.py). The MIR Fortress set still runs
# on top via DEFAULT_MIR.
SSE_IR_FLAGS = (
    "-taokari", "-taokari-fla", "-taokari-level-fla=4",
    "-taokari-bcf", "-taokari-level-bcf=2",
    "-taokari-mba", "-taokari-level-mba=1",
    "-taokari-cie", "-taokari-level-cie=2",
    "-taokari-icall",
)


def fixtures_for(names: list[str], tmp: Path) -> list[Fixture]:
    sse_src = ROOT / "testing" / "cases" / "sse_string" / "src" / "main.c"
    registry = {
        "guarded": Fixture(
            name="guarded",
            src=_write_guarded_source(tmp),
            probe="guarded",
            plain_pseudo_must_contain=("return (19 * a1) ^ 0x51u;",),
            obf_min_extra_lines=8,
            obf_must_contain_any=("__readeflags", "__writeeflags"),
        ),
        "sse": Fixture(
            name="sse",
            src=sse_src,
            probe="taokari_sse_strlen_probe",
            # Plain decompile of the SSE probe shows the clean SSE dispatch:
            # _mm_srli_si128 shifts driven by a switch over the match index.
            # Match flexibly: Hex-Rays spellings vary across versions
            # (_mm_srli_si128 vs srli_si128 vs a switch statement).
            plain_pseudo_must_contain=("srli_si128",),
            obf_min_extra_lines=12,
            # After obfuscation: flag noise from MIR, OR the function fails to
            # decompile at all (even stronger), OR rdrand residue if +mir:sse.
            obf_must_contain_any=("__readeflags", "__writeeflags", "rdrand"),
            obf_no_ida_switch=True,
            extra_obf_flags=SSE_IR_FLAGS,
        ),
    }
    out: list[Fixture] = []
    for n in names:
        if n not in registry:
            raise SystemExit(f"unknown fixture: {n} (known: {sorted(registry)})")
        out.append(registry[n])
    return out


# IDA script: snapshots every probe in PROBES for the current binary, plus
# module-level facts (kernel version, hexrays, d810). For obf_no_ida_switch
# fixtures it also walks each probe function counting switch_info sites.
IDA_SCRIPT = r'''
import importlib.util
import json
import ida_auto
import ida_bytes
import ida_entry
import ida_funcs
import ida_hexrays
import idaapi
import ida_lines
import ida_nalt
import ida_pro
import os
import sys

ida_auto.auto_wait()
def has_d810():
    if importlib.util.find_spec("d810") or importlib.util.find_spec("D810"):
        return True
    for base in sys.path:
        try:
            if any("d810" in name.lower() for name in os.listdir(base)):
                return True
        except Exception:
            pass
    return False

PROBES = [p for p in PROBE_NAMES.split(",") if p]
CHECK_SWITCH = bool(int(SWITCH_CHECK))

item = {
    "input": ida_nalt.get_input_file_path(),
    "ida_kernel_version": idaapi.get_kernel_version(),
    "hexrays": bool(ida_hexrays.init_hexrays_plugin()),
    "d810": has_d810(),
    "exports": [],
    "probes": {},
}
wanted = set(PROBES)
for i in range(ida_entry.get_entry_qty()):
    ordv = ida_entry.get_entry_ordinal(i)
    ea = ida_entry.get_entry(ordv)
    name = ida_entry.get_entry_name(ordv)
    item["exports"].append({"name": name, "ea": hex(ea)})
    if name not in wanted:
        continue
    f = ida_funcs.get_func(ea)
    snap = {"name": name, "ea": hex(ea), "func": bool(f)}
    if f:
        snap["start_ea"] = hex(f.start_ea)
        snap["end_ea"] = hex(f.end_ea)
        snap["size"] = int(f.end_ea - f.start_ea)
        if CHECK_SWITCH:
            sites = 0
            cur = f.start_ea
            while cur != idaapi.BADADDR and cur < f.end_ea:
                if ida_nalt.get_switch_info(cur):
                    sites += 1
                cur = ida_bytes.next_head(cur, f.end_ea)
            snap["switch_sites"] = sites
    try:
        cfunc = ida_hexrays.decompile(ea)
        if cfunc:
            lines = [ida_lines.tag_remove(sl.line) for sl in cfunc.get_pseudocode()]
            snap["pseudocode"] = "\n".join(lines)
            snap["line_count"] = len(lines)
    except Exception as exc:
        snap["error"] = str(exc)
    item["probes"][name] = snap

with open(SNAPSHOT_OUT, "a", encoding="utf-8") as fh:
    fh.write(json.dumps(item) + "\n")
ida_pro.qexit(0)
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


def compile_pair(fix: Fixture, tmp: Path) -> tuple[Path, Path]:
    plain, obf = tmp / f"{fix.name}_plain.exe", tmp / f"{fix.name}_obf.exe"
    must(run_vs([str(CLANG), str(fix.src), "-O1", "-o", str(plain)], tmp), f"{fix.name} plain compile")
    obf_cmd = [str(CLANG), str(fix.src), "-O1"]
    # Pair each -taokari-* token with -mllvm.
    for tok in fix.extra_obf_flags:
        obf_cmd += ["-mllvm", tok]
    obf_cmd += ["-mllvm", "-taokari-mir=" + DEFAULT_MIR,
                "-mllvm", "-verify-machineinstrs",
                "-o", str(obf)]
    must(run_vs(obf_cmd, tmp), f"{fix.name} obfuscated compile")
    return plain, obf


def run_ida(ida: Path, target: Path, script: Path, log: Path, out: Path,
            probes: list[str], check_switch: bool) -> dict:
    before = len(load_snapshots(out)) if out.exists() else 0
    full = (
        'PROBE_NAMES = r"' + ",".join(probes) + '"\n'
        'SWITCH_CHECK = r"' + ("1" if check_switch else "0") + '"\n'
        'SNAPSHOT_OUT = r"' + str(out).replace("\\", "\\\\") + '"\n'
        + IDA_SCRIPT
    )
    script.write_text(full, encoding="ascii")
    result = run([str(ida), "-A", f"-L{log}", f"-S{script}", str(target)], timeout=180)
    snaps = load_snapshots(out)
    if len(snaps) <= before:
        must(result, target.name)
        raise SystemExit(f"IDA did not append a snapshot for {target.name}")
    return snaps[-1]


def load_snapshots(path: Path) -> list[dict]:
    if not path.exists():
        raise SystemExit("IDA did not write snapshot output")
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def require_ida92_d810(snapshots: list[dict]) -> None:
    versions = {str(s.get("ida_kernel_version", "")) for s in snapshots}
    if not versions or any(not v.startswith("9.2") for v in versions):
        raise SystemExit("strict IDA gate requires IDA 9.2, got: " + ", ".join(sorted(versions)))
    if not all(bool(s.get("d810")) for s in snapshots):
        raise SystemExit("strict IDA gate requires D810 plugin visible to IDAPython")


def require_function_confusion(probe_snap: dict) -> None:
    if probe_snap.get("func") and not probe_snap.get("error"):
        raise SystemExit("strict function-confusion gate requires IDA function recognition or decompilation to fail")


def check_fixture(fix: Fixture, plain_snap: dict, obf_snap: dict,
                  require_confusion: bool) -> None:
    if not plain_snap.get("hexrays") or not obf_snap.get("hexrays"):
        raise SystemExit(f"[{fix.name}] Hex-Rays unavailable in IDA snapshot")
    plain_probe = plain_snap.get("probes", {}).get(fix.probe) or {}
    obf_probe = obf_snap.get("probes", {}).get(fix.probe) or {}
    if not plain_probe.get("func"):
        raise SystemExit(f"[{fix.name}] plain {fix.probe} not recognized as a function")
    if require_confusion:
        require_function_confusion(obf_probe)
        print(f"verify_machine_obf_l3_ida_snapshot[{fix.name}]: ok function-confusion")
        return
    if not obf_probe.get("func"):
        raise SystemExit(f"[{fix.name}] obfuscated {fix.probe} not recognized as a function")

    plain_pseudo = plain_probe.get("pseudocode", "")
    obf_pseudo = obf_probe.get("pseudocode", "")
    for needle in fix.plain_pseudo_must_contain:
        if needle not in plain_pseudo:
            raise SystemExit(
                f"[{fix.name}] plain Hex-Rays snapshot missing {needle!r} -- "
                f"fixture may have regressed"
            )
    if not any(tok in obf_pseudo for tok in fix.obf_must_contain_any):
        raise SystemExit(
            f"[{fix.name}] obfuscated Hex-Rays snapshot lacks any of "
            f"{fix.obf_must_contain_any}"
        )
    plain_lc = int(plain_probe.get("line_count", 0))
    obf_lc = int(obf_probe.get("line_count", 0))
    if obf_lc < plain_lc + fix.obf_min_extra_lines:
        raise SystemExit(
            f"[{fix.name}] obfuscated Hex-Rays snapshot too close to plain: "
            f"{plain_lc}->{obf_lc} (need +{fix.obf_min_extra_lines})"
        )
    if fix.obf_no_ida_switch:
        sites = int(obf_probe.get("switch_sites", -1))
        if sites < 0:
            raise SystemExit(f"[{fix.name}] switch-site count not collected")
        if sites > 0:
            raise SystemExit(
                f"[{fix.name}] obfuscated {fix.probe} still has {sites} IDA "
                f"switch_sites -- dispatch not destroyed"
            )
    print(
        f"verify_machine_obf_l3_ida_snapshot[{fix.name}]: ok "
        f"lines={plain_lc}->{obf_lc} size={plain_probe.get('size')}->{obf_probe.get('size')}"
    )


def run_checks(tmp: Path, fixture_names: list[str], require_exact_lab: bool,
               require_confusion: bool) -> int:
    ida = ida_path()
    if not ida.exists():
        print(f"missing IDA: {ida} (set TAOKARI_IDA)", file=sys.stderr)
        return 2
    fixes = fixtures_for(fixture_names, tmp)

    out = tmp / "ida_snapshot.jsonl"
    script = tmp / "snapshot.py"

    snapshots: list[dict] = []
    for fix in fixes:
        plain, obf = compile_pair(fix, tmp)
        check_switch = fix.obf_no_ida_switch
        snapshots.append(run_ida(ida, plain, script, tmp / f"{fix.name}_plain.log", out,
                                 [fix.probe], check_switch))
        snapshots.append(run_ida(ida, obf, script, tmp / f"{fix.name}_obf.log", out,
                                 [fix.probe], check_switch))

    if require_exact_lab:
        require_ida92_d810(snapshots)

    # snapshots is [plain_grounded, obf_guarded, plain_sse, obf_sse, ...] in
    # fixture order, two per fixture.
    for i, fix in enumerate(fixes):
        check_fixture(fix, snapshots[2 * i], snapshots[2 * i + 1], require_confusion)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep", action="store_true")
    parser.add_argument(
        "--fixture", action="append", default=None,
        choices=["guarded", "sse"],
        help="fixture to snapshot (repeatable); default: guarded only",
    )
    parser.add_argument(
        "--require-ida92-d810",
        action="store_true",
        help="fail unless the snapshot ran under IDA 9.2 with D810 visible to IDAPython",
    )
    parser.add_argument(
        "--require-function-confusion",
        action="store_true",
        help="fail unless IDA cannot recognize or decompile the protected function",
    )
    args = parser.parse_args()
    if not CLANG.exists():
        print(f"missing tool: {CLANG}", file=sys.stderr)
        return 2
    tmp = Path(tempfile.mkdtemp(prefix="taokari-mir-l3-ida-"))
    try:
        names = args.fixture or ["guarded"]
        return run_checks(tmp, names, args.require_ida92_d810, args.require_function_confusion)
    finally:
        if args.keep:
            print(f"kept temp dir: {tmp}")
        else:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
