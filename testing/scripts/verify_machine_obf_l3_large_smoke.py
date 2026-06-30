"""Large C++ binary MIR smoke test (C2.5).

Compiles the full ImGui codebase (4 translation units, ~30k lines total)
through every MIR Fortress sub-pass, asserting the build succeeds, the
MachineVerifier accepts the post-RA output, the binary is produced, and its
runtime output matches the plain build. Exercises multiple MIR sub-passes on
realistic large C++ code. Heavy: belongs in the extended suite.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
VSDEVCMD = tp.VSDEVCMD
IMGUI = ROOT / "testing" / "vendor" / "imgui"
HEADLESS = ROOT / "testing" / "cases" / "imgui_headless" / "src" / "main.cpp"

MIR_SET = "dirtybytes,junk,sub,split,fakeprologue"
TIMEOUT_S = 600


def run(command: list[str], **kw) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True,
                          timeout=TIMEOUT_S, **kw)


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


def build(srcs, out: Path, includes, *mir_args: str) -> None:
    cmd = [str(CLANG), "-std=c++17", "-O1", "-I", str(includes),
           *mir_args, *srcs, "-o", str(out)]
    must(run_vs(cmd, ROOT), out.name)


def run_checks(tmp: Path) -> int:
    srcs = [str(HEADLESS), str(IMGUI / "imgui.cpp"), str(IMGUI / "imgui_draw.cpp"),
            str(IMGUI / "imgui_tables.cpp"), str(IMGUI / "imgui_widgets.cpp")]

    plain = tmp / "plain.exe"
    t0 = time.time()
    build(srcs, plain, IMGUI)
    plain_elapsed = time.time() - t0
    plain_run = run([str(plain)])
    must(plain_run, "plain run")

    obf = tmp / "obf.exe"
    t0 = time.time()
    build(srcs, obf, IMGUI,
          "-mllvm", "-verify-machineinstrs",
          "-mllvm", f"-taokari-mir={MIR_SET}")
    obf_elapsed = time.time() - t0
    obf_run = run([str(obf)])
    must(obf_run, "obfuscated run")

    if plain_run.stdout != obf_run.stdout:
        raise SystemExit(f"stdout mismatch: {plain_run.stdout!r} != {obf_run.stdout!r}")

    plain_kb = plain.stat().st_size // 1024
    obf_kb = obf.stat().st_size // 1024
    print(f"imgui plain: {plain_kb} KiB / {plain_elapsed:.1f}s")
    print(f"imgui MIR:   {obf_kb} KiB / {obf_elapsed:.1f}s")
    print("verify_machine_obf_l3_large_smoke: ok")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    for tool, path in (("clang", CLANG), ("imgui", IMGUI / "imgui.cpp"),
                       ("headless", HEADLESS)):
        if not path.exists():
            print(f"missing {tool}: {path}", file=sys.stderr)
            return 2
    tmp = Path(tempfile.mkdtemp(prefix="taokari-mir-smoke-"))
    try:
        return run_checks(tmp)
    finally:
        if args.keep:
            print(f"kept temp dir: {tmp}")
        else:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
