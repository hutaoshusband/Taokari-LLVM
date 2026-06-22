"""Level-3 MIR runtime-dependent dirty-byte guard verification."""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CLANG = ROOT / "build" / "taokari-local" / "bin" / "clang.exe"
VSDEVCMD = Path(
    r"C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat"
)

DIRTY_STACK = bytes.fromhex(
    "9c 50 51 48 89 e0 48 8d 48 01 48 0f af c1 a8 01 74 08 0f 0b eb fe cc f1 0f 0b 59 58 9d"
)
DIRTY_STACK_DEC = bytes.fromhex(
    "9c 50 51 48 89 e0 48 8d 48 ff 48 0f af c1 a8 01 74 08 0f 0b eb fe cc f1 0f 0b 59 58 9d"
)
DIRTY_GUARDS = (DIRTY_STACK, DIRTY_STACK_DEC)
OLD_DOUBLE_XOR_DIRTY = bytes.fromhex(
    "9c 50 8a 04 24 34 a7 34 a7 3a 04 24 74 08 0f 0b eb fe cc f1 0f 0b 58 9d"
)
OLD_FIXED_DIRTY = bytes.fromhex("48 39 e4 74 08 0f 0b eb fe cc f1 0f 0b")

SOURCE = r'''
#include <cstdint>
#include <cstdio>

#define NOINLINE __attribute__((noinline))
#define OPTNONE __attribute__((optnone))

extern "C" NOINLINE OPTNONE uint32_t guarded(uint32_t x) {
  return (x * 7u) ^ 0x51u;
}

int main() {
  std::printf("mir-dirty-guard:%u\n", guarded(19));
  return 0;
}
'''


def run(command: list[str], **kw) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, **kw)


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
        return run(["cmd.exe", "/d", "/c", str(batch)], cwd=cwd)
    finally:
        batch.unlink(missing_ok=True)


def must(result: subprocess.CompletedProcess[str], label: str) -> None:
    if result.returncode:
        print(result.stdout, end="")
        print(result.stderr, end="", file=sys.stderr)
        raise SystemExit(f"{label} failed: {result.returncode}")


def compile_one(src: Path, out: Path, *args: str) -> None:
    cmd = [str(CLANG), str(src), "-std=c++17", "-O1", *args, "-o", str(out)]
    must(run_vs(cmd, src.parent), out.name)


def run_checks(tmp: Path) -> int:
    src = tmp / "mirobf_l3_dirty_guard.cpp"
    src.write_text(SOURCE, encoding="utf-8")

    plain = tmp / "plain.exe"
    obf = tmp / "obf.exe"
    obj = tmp / "dirty.obj"
    compile_one(src, plain)
    compile_one(src, obf, "-mllvm", "-verify-machineinstrs", "-mllvm", "-taokari-mir=dirtybytes")
    compile_one(src, obj, "-c", "-mllvm", "-verify-machineinstrs", "-mllvm", "-taokari-mir=dirtybytes")

    plain_run = run([str(plain)])
    obf_run = run([str(obf)])
    must(plain_run, "plain run")
    must(obf_run, "obfuscated run")
    if plain_run.stdout != obf_run.stdout:
        raise SystemExit(f"stdout mismatch: {plain_run.stdout!r} != {obf_run.stdout!r}")

    data = obj.read_bytes()
    if not any(pattern in data for pattern in DIRTY_GUARDS):
        raise SystemExit("missing runtime-dependent dirty-byte guard")
    if OLD_DOUBLE_XOR_DIRTY in data:
        raise SystemExit("old double-xor dirty-byte guard survived")
    if OLD_FIXED_DIRTY in data:
        raise SystemExit("old fixed cmp-rsp dirty-byte guard survived")

    print("verify_machine_obf_l3_dirty_guard: ok")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    if not CLANG.exists():
        print(f"missing tool: {CLANG}", file=sys.stderr)
        return 2
    tmp = Path(tempfile.mkdtemp(prefix="taokari-mir-l3-dirty-"))
    try:
        return run_checks(tmp)
    finally:
        if args.keep:
            print(f"kept temp dir: {tmp}")
        else:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
