"""VMP decompiler snapshot verifier with multi-tool runner detection.

Mirrors verify_vmp_decompiler_lift.py but is tool-agnostic: it detects any
installed decompiler (IDA Hex-Rays and/or Ghidra headless), runs each present
tool on a plain and a +vmp build of the same victim, dumps per-function
pseudocode as a JSON snapshot artifact, and asserts the VMP build hides the
source constant `0x1357` and grows decompiler lift effort beyond the plain
baseline.

Skips gracefully (exit 2) when no decompiler is installed. Set:
  * TAOKARI_IDA    -> path to ida.exe (default: IDA Professional 9.1 install)
  * TAOKARI_GHIDRA -> Ghidra install root (contains support/analyzeHeadless.bat)
or put analyzeHeadless.bat on PATH.

Contract (per present tool):
  * plain decompile exposes the source constant `1357`.
  * VMP decompile hides `1357`.
  * VMP pseudocode is materially longer than plain.
Snapshots written to ./artifacts/vmp_decompiler_snapshot/<tool>.json when
--artifacts is given.

Exit: 0 ok | 1 contract failure | 2 no decompiler / missing clang.
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

from typing import Callable


ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
DEFAULT_IDA = Path(r"C:\Program Files\IDA Professional 9.1\ida.exe")
VSDEVCMD = tp.VSDEVCMD
MAP_RE = re.compile(r"\s+[0-9A-Fa-f]+:[0-9A-Fa-f]+\s+(\S+)\s+([0-9A-Fa-f]{16})\s")

SOURCE = r"""
#include <stdio.h>

#ifdef USE_VMP
#define VMP_ATTR __attribute__((noinline, annotate("+vmp")))
#else
#define VMP_ATTR __attribute__((noinline))
#endif

VMP_ATTR int victim(int a, int b) {
  int x = (a + b + 3) ^ 0x1357;
  x = (x * 5) - (a & 15);
  return x ^ (b << 2);
}

int main(void) {
  printf("lift:%d\n", victim(9, 4));
  return 0;
}
"""

IDA_SCRIPT = r'''
from __future__ import annotations

import json
import os

import ida_auto
import ida_lines
import ida_pro
import idautils

try:
    import ida_hexrays
except ImportError:
    ida_hexrays = None


def main() -> int:
    report_path = os.environ.get("TAOKARI_SNAPSHOT_REPORT")
    if not report_path:
        return 2
    ida_auto.auto_wait()
    names = {name: ea for ea, name in idautils.Names()}
    extra = os.environ.get("TAOKARI_IDA_SYMBOLS_JSON")
    if extra:
        for name, ea in json.loads(extra).items():
            names[name] = int(ea)
    ea = names.get("victim")
    if ea is None:
        ea = names.get("_victim")
    hexrays = bool(ida_hexrays and ida_hexrays.init_hexrays_plugin())
    pseudo = ""
    error = ""
    if hexrays and ea is not None:
        try:
            cfunc = ida_hexrays.decompile(ea)
            if cfunc:
                pseudo = "\n".join(
                    ida_lines.tag_remove(line.line)
                    for line in cfunc.get_pseudocode()
                )
        except Exception as exc:
            error = str(exc)
    with open(report_path, "w", encoding="utf-8") as handle:
        json.dump({
            "tool": "ida",
            "victim_ea": ea,
            "hexrays": hexrays,
            "pseudocode": pseudo,
            "switch_recovered": ("switch" in pseudo),
            "switch_cases": pseudo.count("case ") + pseudo.count("default:"),
            "error": error,
        }, handle, indent=2, sort_keys=True)
    return 0


ida_pro.qexit(main())
'''

GHIDRA_SCRIPT = r'''
import json
import os

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor


def find_victim():
    for sym in currentProgram.getSymbolTable().getAllSymbols(True):
        name = sym.getName()
        if name in ("victim", "_victim"):
            return sym.getAddress()
    return None


def main():
    report_path = os.environ.get("TAOKARI_SNAPSHOT_REPORT")
    if not report_path:
        return
    fm = currentProgram.getFunctionManager()
    ea = find_victim()
    func = fm.getFunctionAt(ea) if ea is not None else None
    pseudo = ""
    error = ""
    decomp_ok = False
    if func is not None:
        di = DecompInterface()
        di.openProgram(currentProgram)
        try:
            res = di.decompile(func, 60, ConsoleTaskMonitor())
            if res and res.decompileCompleted():
                decomp_ok = True
                pseudo = res.getDecompiledFunction().getC()
            elif res:
                error = res.getErrorMessage() or "decompile failed"
        except Exception as exc:
            error = str(exc)
        finally:
            di.dispose()
    with open(report_path, "w", encoding="utf-8") as handle:
        json.dump({
            "tool": "ghidra",
            "victim_ea": str(ea) if ea is not None else None,
            "hexrays": decomp_ok,
            "pseudocode": pseudo,
            "switch_recovered": ("switch" in pseudo),
            "switch_cases": pseudo.count("case ") + pseudo.count("default:"),
            "error": error,
        }, handle, indent=2, sort_keys=True)


main()
'''


def run(cmd: list[str], *, cwd: Path = ROOT, timeout: int = 300,
        env: dict[str, str] | None = None,
        use_vs_env: bool = False) -> subprocess.CompletedProcess[str]:
    if use_vs_env and VSDEVCMD.exists():
        with tempfile.NamedTemporaryFile("w", suffix=".cmd", delete=False,
                                         encoding="utf-8") as handle:
            batch = Path(handle.name)
            handle.write("@echo off\n")
            handle.write(f'call "{VSDEVCMD}" -arch=x64 -host_arch=x64 >nul\n')
            handle.write(subprocess.list2cmdline(cmd) + "\n")
            handle.write("exit /b %ERRORLEVEL%\n")
        try:
            return subprocess.run(["cmd.exe", "/d", "/c", str(batch)],
                                  cwd=cwd, text=True, capture_output=True,
                                  timeout=timeout, env=env)
        finally:
            batch.unlink(missing_ok=True)
    return subprocess.run(cmd, cwd=cwd, text=True, capture_output=True,
                          timeout=timeout, env=env)


def must(result: subprocess.CompletedProcess[str], label: str) -> None:
    if result.returncode:
        sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise SystemExit(f"{label} failed: {result.returncode}")


def ida_path() -> Path | None:
    configured = os.environ.get("TAOKARI_IDA")
    candidate = Path(configured) if configured else DEFAULT_IDA
    return candidate if candidate.exists() else None


def ghidra_headless() -> Path | None:
    configured = os.environ.get("TAOKARI_GHIDRA")
    candidates: list[Path] = []
    if configured:
        candidates.append(Path(configured) / "support" / "analyzeHeadless.bat")
    for path in os.environ.get("PATH", "").split(os.pathsep):
        candidates.append(Path(path) / "analyzeHeadless.bat")
    for c in candidates:
        if c.exists():
            return c
    return None


def map_symbols(path: Path) -> dict[str, int]:
    symbols: dict[str, int] = {}
    for name, va in MAP_RE.findall(path.read_text(encoding="utf-8", errors="ignore")):
        if name in {"victim", "_victim"} or name.startswith("__taokari_vmp_interp_i64"):
            symbols[name] = int(va, 16)
    return symbols


def build(src: Path, exe: Path, map_file: Path, *, vmp: bool) -> None:
    cmd = [
        str(CLANG), str(src), "-O1", "-gcodeview", "-fno-discard-value-names",
        "-Wl,/DEBUG:FULL", f"-Wl,/MAP:{map_file}", "-o", str(exe),
    ]
    if vmp:
        cmd[1:1] = ["-DUSE_VMP=1"]
        cmd.extend(["-mllvm", "-taokari", "-mllvm", "-taokari-vmp"])
    must(run(cmd, use_vs_env=True), "build " + exe.name)


def run_ida(ida: Path, exe: Path, script: Path, report: Path,
            symbols: dict[str, int]) -> dict:
    env = os.environ.copy()
    env["TAOKARI_SNAPSHOT_REPORT"] = str(report)
    env["TAOKARI_IDA_SYMBOLS_JSON"] = json.dumps(symbols)
    log = report.with_suffix(".log")
    result = run([str(ida), "-A", f"-L{log}", f"-S{script}", str(exe)], env=env)
    if not report.exists():
        sys.stderr.write(result.stdout + result.stderr)
        if log.exists():
            sys.stderr.write(log.read_text(encoding="utf-8", errors="ignore"))
        raise SystemExit(f"IDA did not write snapshot for {exe.name}")
    return json.loads(report.read_text(encoding="utf-8"))


def run_ghidra(headless: Path, exe: Path, script: Path, report: Path,
               project_dir: Path, project: str) -> dict:
    if report.exists():
        report.unlink()
    env = os.environ.copy()
    env["TAOKARI_SNAPSHOT_REPORT"] = str(report)
    project_dir.mkdir(parents=True, exist_ok=True)
    result = run([str(headless), str(project_dir), project,
                  "-import", str(exe), "-overwrite",
                  "-postScript", script.name,
                  "-scriptPath", str(script.parent),
                  "-deleteProject"], env=env)
    if not report.exists():
        sys.stderr.write(result.stdout + result.stderr)
        raise SystemExit(f"Ghidra did not write snapshot for {exe.name}")
    return json.loads(report.read_text(encoding="utf-8"))


SnapshotFn = Callable[[Path], dict]


def make_runner(tool: str, tmp: Path, ida: Path | None,
                headless: Path | None) -> tuple[str, SnapshotFn]:
    if tool == "ida":
        if ida is None:
            raise RuntimeError("ida not detected")
        script = tmp / "ida_snapshot.py"
        script.write_text(IDA_SCRIPT, encoding="utf-8")
        def runner(exe: Path) -> dict:
            map_file = exe.with_suffix(".map")
            return run_ida(ida, exe, script, exe.with_suffix(".json"),
                           map_symbols(map_file))
        return "ida", runner
    if tool == "ghidra":
        if headless is None:
            raise RuntimeError("ghidra not detected")
        script = tmp / "ghidra_snapshot.py"
        script.write_text(GHIDRA_SCRIPT, encoding="utf-8")
        proj = tmp / "ghidra_proj"
        def runner(exe: Path) -> dict:
            return run_ghidra(headless, exe, script, exe.with_suffix(".json"),
                              proj, exe.stem)
        return "ghidra", runner
    raise ValueError(f"unknown tool {tool}")


def assert_snapshot(name: str, plain: dict, vmp: dict) -> None:
    if not plain.get("hexrays") or not vmp.get("hexrays"):
        raise SystemExit(f"{name}: decompiler unavailable or failed to lift victim")
    plain_pseudo = str(plain.get("pseudocode", "")).lower()
    vmp_pseudo = str(vmp.get("pseudocode", "")).lower()
    if "1357" not in plain_pseudo:
        raise SystemExit(f"{name}: plain decompile did not expose source constant")
    if "1357" in vmp_pseudo:
        raise SystemExit(f"{name}: VMP decompile still exposes source constant")
    if len(vmp_pseudo.splitlines()) < len(plain_pseudo.splitlines()) + 20:
        raise SystemExit(f"{name}: VMP decompile did not grow beyond plain lift")


def run_checks(tmp: Path, tools: list[str], artifacts: Path | None) -> int:
    src = tmp / "snapshot.c"
    src.write_text(SOURCE, encoding="utf-8")
    plain = tmp / "plain.exe"
    vmp = tmp / "vmp.exe"
    build(src, plain, plain.with_suffix(".map"), vmp=False)
    build(src, vmp, vmp.with_suffix(".map"), vmp=True)

    plain_run = run([str(plain)])
    vmp_run = run([str(vmp)])
    if plain_run.returncode or vmp_run.returncode or plain_run.stdout != vmp_run.stdout:
        print("runtime mismatch between plain and VMP snapshot fixtures",
              file=sys.stderr)
        return 1

    ida = ida_path()
    headless = ghidra_headless()
    ran = 0
    for tool in tools:
        name, runner = make_runner(tool, tmp, ida, headless)
        plain_snap = runner(plain)
        vmp_snap = runner(vmp)
        assert_snapshot(name, plain_snap, vmp_snap)
        if artifacts:
            artifacts.mkdir(parents=True, exist_ok=True)
            out = artifacts / f"{name}.json"
            out.write_text(json.dumps({"plain": plain_snap, "vmp": vmp_snap},
                                      indent=2, sort_keys=True), encoding="utf-8")
        ran += 1
        plain_sw = plain_snap.get("switch_cases", 0)
        vmp_sw = vmp_snap.get("switch_cases", 0)
        print(f"  {name}: ok (plain {len(str(plain_snap.get('pseudocode','')).splitlines())} lines"
              f" -> vmp {len(str(vmp_snap.get('pseudocode','')).splitlines())} lines;"
              f" switch cases plain {plain_sw} -> vmp {vmp_sw})")
    print(f"verify_vmp_decompiler_snapshot: ok ({ran} tool(s))")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts", type=Path, default=None,
                        help="directory to write JSON snapshots into")
    args = parser.parse_args()
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    tools: list[str] = []
    if ida_path():
        tools.append("ida")
    if ghidra_headless():
        tools.append("ghidra")
    if not tools:
        print("verify_vmp_decompiler_snapshot: SKIP "
              "(no IDA/Ghidra detected; set TAOKARI_IDA or TAOKARI_GHIDRA)",
              file=sys.stderr)
        return 2

    tmp = Path(tempfile.mkdtemp(prefix="taokari-vmp-snap-"))
    try:
        return run_checks(tmp, tools, args.artifacts)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
