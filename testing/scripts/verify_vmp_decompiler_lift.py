from __future__ import annotations

import json
import os
import re
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
    report_path = os.environ.get("TAOKARI_IDA_REPORT")
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
            "victim_ea": ea,
            "hexrays": hexrays,
            "pseudocode": pseudo,
            "error": error,
        }, handle, indent=2, sort_keys=True)
    return 0


ida_pro.qexit(main())
'''


def run(cmd: list[str], *, cwd: Path = ROOT, timeout: int = 240,
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


def ida_path() -> Path:
    return Path(os.environ["TAOKARI_IDA"]) if os.environ.get("TAOKARI_IDA") else DEFAULT_IDA


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
    result = run(cmd, use_vs_env=True)
    if result.returncode:
        sys.stderr.write(result.stdout + result.stderr)
        raise SystemExit(result.returncode)


def decompile(ida: Path, exe: Path, script: Path, report: Path,
              symbols: dict[str, int]) -> dict[str, object]:
    env = os.environ.copy()
    env["TAOKARI_IDA_REPORT"] = str(report)
    env["TAOKARI_IDA_SYMBOLS_JSON"] = json.dumps(symbols)
    log = report.with_suffix(".log")
    result = run([str(ida), "-A", f"-L{log}", f"-S{script}", str(exe)],
                 timeout=300, env=env)
    if not report.exists():
        sys.stderr.write(result.stdout + result.stderr)
        if log.exists():
            sys.stderr.write(log.read_text(encoding="utf-8", errors="ignore"))
        raise SystemExit(1)
    return json.loads(report.read_text(encoding="utf-8"))


def main() -> int:
    ida = ida_path()
    if not ida.exists():
        print(f"missing IDA: {ida} (set TAOKARI_IDA)", file=sys.stderr)
        return 2
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-vmp-lift-") as tmp:
        tmpdir = Path(tmp)
        src = tmpdir / "lift.c"
        script = tmpdir / "ida_lift.py"
        src.write_text(SOURCE, encoding="utf-8")
        script.write_text(IDA_SCRIPT, encoding="utf-8")
        plain = tmpdir / "plain.exe"
        vmp = tmpdir / "vmp.exe"
        plain_map = tmpdir / "plain.map"
        vmp_map = tmpdir / "vmp.map"
        build(src, plain, plain_map, vmp=False)
        build(src, vmp, vmp_map, vmp=True)

        plain_run = run([str(plain)])
        vmp_run = run([str(vmp)])
        if plain_run.returncode or vmp_run.returncode or plain_run.stdout != vmp_run.stdout:
            print("runtime mismatch between plain and VMP lift fixtures", file=sys.stderr)
            return 1

        plain_report = decompile(ida, plain, script, tmpdir / "plain.json",
                                 map_symbols(plain_map))
        vmp_report = decompile(ida, vmp, script, tmpdir / "vmp.json",
                               map_symbols(vmp_map))
        if not plain_report.get("hexrays") or not vmp_report.get("hexrays"):
            print("Hex-Rays unavailable for VMP lift test", file=sys.stderr)
            return 1
        plain_pseudo = str(plain_report.get("pseudocode", "")).lower()
        vmp_pseudo = str(vmp_report.get("pseudocode", "")).lower()
        if "1357" not in plain_pseudo:
            print("plain decompile did not expose source arithmetic", file=sys.stderr)
            return 1
        if "1357" in vmp_pseudo:
            print("VMP wrapper decompile still exposes source constant", file=sys.stderr)
            return 1
        if len(vmp_pseudo.splitlines()) < len(plain_pseudo.splitlines()) + 20:
            print("VMP wrapper decompile did not grow beyond source lift", file=sys.stderr)
            return 1

    print("vmp decompiler lift: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
