"""MIR post-RA release verifier gate (C2.2) verification."""
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
int main() { std::printf("verify:%u\n", sink(13)); return 0; }
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
    tmp = Path(tempfile.mkdtemp(prefix="taokari-mir-verify-"))
    src = tmp / "v.cpp"
    src.write_text(SOURCE, encoding="utf-8")

    for mir in ("dirtybytes,junk,sub", "split", "fakeprologue", "sse,unmodelled"):
        r = compile_obj(src, tmp / f"{mir.replace(',','_')}.obj",
                        "-mllvm", f"-taokari-mir={mir}")
        if r.returncode != 0:
            raise SystemExit(
                f"transform {mir!r} failed the release verifier gate:\n{r.stderr}")
        if "post-transform verify" in r.stderr and " verifier " in r.stderr:
            raise SystemExit(
                f"transform {mir!r} triggered a verifier report:\n{r.stderr}")

    off = compile_obj(src, tmp / "off.obj",
                      "-mllvm", "-taokari-mir=dirtybytes,junk,sub",
                      "-mllvm", "-taokari-mir-release-verify=false")
    if off.returncode != 0:
        raise SystemExit(f"gate-disable compile failed:\n{off.stderr}")

    print("verify_machine_obf_l3_release_verifier: ok")
    return 0


def main() -> int:
    if not CLANG.exists():
        print(f"missing tool: {CLANG}", file=sys.stderr)
        return 2
    return run_checks()


if __name__ == "__main__":
    raise SystemExit(main())
