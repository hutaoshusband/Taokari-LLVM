"""Run the VMP L2 IDA inspection gate when IDA is installed."""
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
IDA_SCRIPT = ROOT / "testing" / "scripts" / "ida_vmp_l2_inspect.py"
MAP_RE = re.compile(r"\s+[0-9A-Fa-f]+:[0-9A-Fa-f]+\s+(\S+)\s+([0-9A-Fa-f]{16})\s")

SOURCE = r"""
#include <stdint.h>

#define VMP __attribute__((noinline, annotate("+vmp")))

VMP int victim(int a, int b) {
  int x = (a + b + 3) ^ 0x1357;
  x = (x * 5) - (a & 15);
  return x ^ (b << 2);
}

int main(void) {
  int expected = (((((9 + 4 + 3) ^ 0x1357) * 5) - (9 & 15)) ^ (4 << 2));
  return victim(9, 4) == expected
      ? 0 : 1;
}
"""


def run(cmd: list[str], *, cwd: Path = ROOT, timeout: int = 180,
        env: dict[str, str] | None = None,
        use_vs_env: bool = False) -> subprocess.CompletedProcess[str]:
    if use_vs_env and VSDEVCMD.exists():
        with tempfile.NamedTemporaryFile("w", suffix=".cmd", delete=False,
                                         encoding="utf-8") as handle:
            batch = Path(handle.name)
            handle.write("@echo off\n")
            handle.write(f'call "{VSDEVCMD}" -arch=x64 -host_arch=x64 >nul\n')
            handle.write(subprocess.list2cmdline(cmd) + "\n")
        try:
            return subprocess.run(["cmd.exe", "/c", str(batch)], cwd=cwd,
                                  text=True, capture_output=True,
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
        if name.startswith("__taokari_vmp_interp_i64"):
            symbols[name] = int(va, 16)
    return symbols


def main() -> int:
    ida = ida_path()
    if not ida.exists():
        print(f"missing IDA: {ida} (set TAOKARI_IDA)", file=sys.stderr)
        return 2
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-vmp-ida-") as tmp:
        tmpdir = Path(tmp)
        src = tmpdir / "vmp_ida.c"
        exe = tmpdir / "vmp_ida.exe"
        map_file = tmpdir / "vmp_ida.map"
        report = tmpdir / "vmp_ida_report.json"
        log = tmpdir / "ida.log"
        src.write_text(SOURCE, encoding="utf-8")

        build = run([
            str(CLANG), str(src), "-O1", "-gcodeview", "-o", str(exe),
            "-Wl,/DEBUG:FULL", f"-Wl,/MAP:{map_file}",
            "-mllvm", "-taokari", "-mllvm", "-taokari-vmp",
        ], use_vs_env=True)
        if build.returncode:
            sys.stderr.write(build.stdout + build.stderr)
            return 1

        env = os.environ.copy()
        env["TAOKARI_IDA_REPORT"] = str(report)
        symbols = map_symbols(map_file)
        if not symbols:
            print("missing VMP interpreter symbols in linker map", file=sys.stderr)
            return 1
        env["TAOKARI_IDA_SYMBOLS_JSON"] = json.dumps(symbols)
        ida_run = run([str(ida), "-A", f"-L{log}", f"-S{IDA_SCRIPT}", str(exe)],
                      timeout=240, env=env)
        if not report.exists():
            sys.stderr.write(ida_run.stdout + ida_run.stderr)
            if log.exists():
                sys.stderr.write(log.read_text(encoding="utf-8", errors="ignore"))
            return 1

        data = json.loads(report.read_text(encoding="utf-8"))
        if not data.get("ok"):
            print(json.dumps(data, indent=2, sort_keys=True), file=sys.stderr)
            return 1

    print("vmp ida l2: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
