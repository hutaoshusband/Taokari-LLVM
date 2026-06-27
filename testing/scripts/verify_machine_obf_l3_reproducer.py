"""MIR crash reproducer minimizer (C2.4) smoke verification."""
from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CLANG = ROOT / "build" / "taokari-local" / "bin" / "clang.exe"
VSDEVCMD = Path(
    r"C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat"
)

SOURCE = r'''
#include <cstdint>
#include <cstdio>
extern "C" __attribute__((noinline,optnone))
uint32_t sink(uint32_t x) { return x * 31u + 7; }
int main() { std::printf("repro:%u\n", sink(13)); return 0; }
'''


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
        return subprocess.run(["cmd.exe", "/d", "/c", str(batch)],
                              text=True, capture_output=True)
    finally:
        batch.unlink(missing_ok=True)


def compile_obj(src: Path, out: Path, *mir_args: str) -> subprocess.CompletedProcess[str]:
    cmd = [str(CLANG), str(src), "-std=c++17", "-O1", "-c",
           "-mllvm", "-verify-machineinstrs", *mir_args, "-o", str(out)]
    return run_vs(cmd, src.parent)


def run_checks() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="taokari-mir-repro-"))
    src = tmp / "r.cpp"
    src.write_text(SOURCE, encoding="utf-8")

    repro_dir = tmp / "repro"
    r = compile_obj(src, tmp / "ok.obj",
                    "-mllvm", "-taokari-mir=dirtybytes,junk,sub,split,fakeprologue",
                    "-mllvm", f"-taokari-mir-reproducer-dir={repro_dir}")
    if r.returncode != 0:
        raise SystemExit(f"transform failed:\n{r.stderr}")
    if list(repro_dir.glob("*")) if repro_dir.exists() else []:
        raise SystemExit("reproducer written on a successful transform (false positive)")

    r = compile_obj(src, tmp / "strict.obj",
                    "-mllvm", "-taokari-mir=dirtybytes,junk,sub",
                    "-mllvm", "-taokari-mir-strict")
    if r.returncode != 0:
        raise SystemExit(f"strict-mode safe transform failed:\n{r.stderr}")

    flag_probe = compile_obj(src, tmp / "flag.obj",
                             "-mllvm", "-taokari-mir=dirtybytes",
                             "-mllvm", "-taokari-mir-reproducer-dir=")
    if flag_probe.returncode != 0:
        raise SystemExit(f"empty reproducer dir flag rejected:\n{flag_probe.stderr}")

    print("verify_machine_obf_l3_reproducer: ok")
    return 0


def main() -> int:
    if not CLANG.exists():
        print(f"missing tool: {CLANG}", file=sys.stderr)
        return 2
    return run_checks()


if __name__ == "__main__":
    raise SystemExit(main())
