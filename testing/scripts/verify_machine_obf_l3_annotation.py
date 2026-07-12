"""MIR per-function annotation parsing (C1.7) verification."""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
VSDEVCMD = tp.VSDEVCMD

JUNK = bytes.fromhex("9c 50 80 34 24 5a 80 34 24 5a 58 9d")
SUB_ADD_LEA = bytes.fromhex(
    "9c 50 48 89 e0 48 8d 40 13 48 83 e8 13 58 9d")
SUB_DOUBLE_NEG = bytes.fromhex("9c 50 48 f7 d8 48 f7 d8 58 9d")
SUB_DOUBLE_NOT = bytes.fromhex("9c 50 48 f7 d0 48 f7 d0 58 9d")
SUB_VARIANTS = (SUB_ADD_LEA, SUB_DOUBLE_NEG, SUB_DOUBLE_NOT)
DIRTY_STACK = bytes.fromhex(
    "9c 50 51 48 89 e0 48 8d 48 01 48 0f af c1 a8 01 74 08 0f 0b eb fe cc f1 0f 0b 59 58 9d"
)
DIRTY_STACK_DEC = bytes.fromhex(
    "9c 50 51 48 89 e0 48 8d 48 ff 48 0f af c1 a8 01 74 08 0f 0b eb fe cc f1 0f 0b 59 58 9d"
)
DIRTY_SHIFT = bytes.fromhex(
    "9c 50 51 48 89 e0 48 d1 e0 a8 01 74 08 0f 0b eb fe cc f1 0f 0b 59 58 9d"
)
DIRTY_VARIANTS = (DIRTY_STACK, DIRTY_STACK_DEC, DIRTY_SHIFT)


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


def compile_obj(src: Path, out: Path, *mir_args: str) -> subprocess.CompletedProcess[str]:
    cmd = [str(CLANG), str(src), "-std=c++17", "-O1", "-c",
           "-mllvm", "-verify-machineinstrs", *mir_args, "-o", str(out)]
    r = run_vs(cmd, src.parent)
    must(r, out.name)
    return r


def obj_bytes(obj: Path) -> bytes:
    return obj.read_bytes()


def run_checks(tmp: Path) -> int:
    multi = r'''
#include <cstdint>
#include <cstdio>
#define NOINLINE __attribute__((noinline))
#define OPTNONE __attribute__((optnone))
extern "C" {
NOINLINE OPTNONE __attribute__((annotate("+mir:junk"))) __attribute__((annotate("+mir:sub")))
uint32_t both_on(uint32_t a) { return a * 7u + 1; }
}
int main() { std::printf("ann:%u\n", both_on(3)); return 0; }
'''
    src = tmp / "multi.cpp"
    src.write_text(multi, encoding="utf-8")
    compile_obj(src, tmp / "multi.obj")
    multi_bytes = obj_bytes(tmp / "multi.obj")
    if JUNK not in multi_bytes:
        raise SystemExit("multi-subpass: +mir:junk missing")
    if not any(v in multi_bytes for v in SUB_VARIANTS):
        raise SystemExit("multi-subpass: +mir:sub missing")

    disable = r'''
#include <cstdint>
#include <cstdio>
#define NOINLINE __attribute__((noinline))
#define OPTNONE __attribute__((optnone))
extern "C" NOINLINE OPTNONE __attribute__((annotate("-mir:junk")))
uint32_t only_one(uint32_t a) { return a + 9; }
int main() { std::printf("dis:%u\n", only_one(5)); return 0; }
'''
    dsrc = tmp / "disable.cpp"
    dsrc.write_text(disable, encoding="utf-8")
    compile_obj(dsrc, tmp / "disable.obj",
                "-mllvm", "-taokari-mir=junk",
                "-mllvm", "-taokari-mir-junk-prob=100")
    if JUNK not in obj_bytes(tmp / "disable.obj"):
        raise SystemExit("global -taokari-mir=junk should still mark main()")
    disable_solo = r'''
#include <cstdint>
#include <cstdio>
#define NOINLINE __attribute__((noinline))
#define OPTNONE __attribute__((optnone))
extern "C" NOINLINE OPTNONE __attribute__((annotate("-mir:junk")))
uint32_t solo(uint32_t a) { return a + 9; }
int main() { std::printf("dis:%u\n", solo(5)); return 0; }
'''
    ssrc = tmp / "solo.cpp"
    ssrc.write_text(disable_solo, encoding="utf-8")
    compile_obj(ssrc, tmp / "solo.obj")
    if JUNK in obj_bytes(tmp / "solo.obj"):
        raise SystemExit("-mir:junk leaked junk bytes with no global flag")

    unknown = r'''
#include <cstdint>
#include <cstdio>
#define NOINLINE __attribute__((noinline))
#define OPTNONE __attribute__((optnone))
extern "C" NOINLINE OPTNONE __attribute__((annotate("+mir:boguspass")))
uint32_t unk(uint32_t a) { return a + 3; }
int main() { std::printf("unk:%u\n", unk(2)); return 0; }
'''
    usrc = tmp / "unknown.cpp"
    usrc.write_text(unknown, encoding="utf-8")
    ur = compile_obj(usrc, tmp / "unknown.obj")
    if "unknown +mir:boguspass" not in ur.stderr:
        raise SystemExit("unknown MIR sub-pass name did not produce a warning")

    print("verify_machine_obf_l3_annotation: ok")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    if not CLANG.exists():
        print(f"missing tool: {CLANG}", file=sys.stderr)
        return 2
    tmp = Path(tempfile.mkdtemp(prefix="taokari-mir-ann-"))
    try:
        return run_checks(tmp)
    finally:
        if args.keep:
            print(f"kept temp dir: {tmp}")
        else:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
