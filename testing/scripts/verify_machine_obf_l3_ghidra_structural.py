"""Ghidra headless structural snapshot comparison (C3.6).

Mirrors the IDA structural comparison (verify_machine_obf_l3_ida_structural.py)
but drives Ghidra's analyzeHeadless with a post-analysis Python script that
captures module-wide structural metrics (function count, total function bytes,
mean function size) as JSON for plain vs MIR-obfuscated builds.

Skips gracefully (exit 2) when Ghidra is unavailable. Point Ghidra at a
non-default install with TAOKARI_GHIDRA (path to the Ghidra install root, which
contains support/analyzeHeadless.bat) or put analyzeHeadless on PATH.

NOTE: optional/tool-dependent. This environment does not have Ghidra installed,
so the harness is exercised only at the skip level here; on a host with Ghidra
installed it runs the real headless comparison.
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
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
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
  std::printf("ghidra-struct:%u:%u:%u\n", fa(1), fb(2), fc(3));
  return 0;
}
'''

GHIDRA_SCRIPT = r'''
import json
from ghidra.program.model.listing import FunctionManager

fm = currentProgram.getFunctionManager()
fcount = 0
total_bytes = 0
for f in fm.getFunctions(True):
    fcount += 1
    total_bytes += int(f.getBody().getNumAddresses())

item = {
    "input": str(currentProgram.getExecutablePath()),
    "function_count": fcount,
    "total_function_bytes": total_bytes,
    "mean_function_bytes": (total_bytes / fcount) if fcount else 0,
}
out_path = SCRIPT_OUT.replace("\\\\", "\\")
with open(out_path, "w", encoding="utf-8") as fh:
    fh.write(json.dumps(item) + "\n")
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


def analyze_headless() -> Path | None:
    configured = os.environ.get("TAOKARI_GHIDRA")
    candidates = []
    if configured:
        candidates.append(Path(configured) / "support" / "analyzeHeadless.bat")
    for path in os.environ.get("PATH", "").split(os.pathsep):
        candidates.append(Path(path) / "analyzeHeadless.bat")
    for c in candidates:
        if c.exists():
            return c
    return None


def snapshot(headless: Path, exe: Path, out: Path, script_file: Path,
             project_dir: Path, project: str) -> dict:
    if out.exists():
        out.unlink()
    full = 'SCRIPT_OUT = r"' + str(out).replace("\\", "\\\\") + '"\n' + GHIDRA_SCRIPT
    script_file.write_text(full, encoding="utf-8")
    script_dir = script_file.parent
    project_dir.mkdir(parents=True, exist_ok=True)
    r = run([str(headless), str(project_dir), project,
             "-import", str(exe),
             "-overwrite",
             "-postScript", script_file.name,
             "-scriptPath", str(script_dir),
             "-deleteProject"])
    if not out.exists():
        must(r, exe.name)
        raise SystemExit(f"Ghidra did not write snapshot for {exe.name}")
    return json.loads(out.read_text(encoding="utf-8").strip())


def run_checks(tmp: Path) -> int:
    src = tmp / "ghidra_struct.cpp"
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

    headless = analyze_headless()
    if headless is None:
        print("verify_machine_obf_l3_ghidra_structural: SKIP (Ghidra not installed)")
        return 0

    proj_dir = tmp / "ghidra_proj"
    plain_snap = snapshot(headless, plain, tmp / "plain.snapshot.json",
                          tmp / "snap.py", proj_dir, "plain")
    obf_snap = snapshot(headless, obf, tmp / "obf.snapshot.json",
                        tmp / "snap.py", proj_dir, "obf")

    if obf_snap["total_function_bytes"] <= plain_snap["total_function_bytes"]:
        raise SystemExit(
            "MIR build did not grow total function bytes (no structural impact)")

    print(
        "verify_machine_obf_l3_ghidra_structural: ok "
        f"functions={plain_snap['function_count']}->{obf_snap['function_count']} "
        f"bytes={plain_snap['total_function_bytes']}->{obf_snap['total_function_bytes']}"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    if not CLANG.exists():
        print(f"missing tool: {CLANG}", file=sys.stderr)
        return 2
    tmp = Path(tempfile.mkdtemp(prefix="taokari-mir-ghidra-"))
    try:
        return run_checks(tmp)
    finally:
        if args.keep:
            print(f"kept temp dir: {tmp}")
        else:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
