"""Level-3 MIR cross-pass integration verification."""
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
JUNK = bytes.fromhex("9c 50 80 34 24 5a 80 34 24 5a 58 9d")
SUB = bytes.fromhex("9c 50 48 89 e0 48 8d 40 13 48 83 e8 13 58 9d")

SOURCE = ROOT / "testing" / "cases" / "c_console" / "src" / "main.c"

IR_AND_MIR_FLAGS = [
    "-O2",
    "-mllvm", "-taokari",
    "-mllvm", "-taokari-fla",
    "-mllvm", "-taokari-bcf",
    "-mllvm", "-taokari-indbr",
    "-mllvm", "-taokari-mir=dirtybytes,junk,sub",
]


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


def clang(src: Path, out: Path, *args: str) -> None:
    cmd = [str(CLANG), str(src), "-std=c17", *args, "-o", str(out)]
    must(run_vs(cmd, src.parent), out.name)


def require(data: bytes, pattern: bytes, name: str) -> None:
    if pattern not in data:
        raise SystemExit(f"missing {name} MIR bytes after IR passes")


def require_any(data: bytes, patterns: tuple[bytes, ...], name: str) -> None:
    if not any(pattern in data for pattern in patterns):
        raise SystemExit(f"missing {name} MIR bytes after IR passes")


def run_checks(tmp: Path) -> int:
    plain = tmp / "plain.exe"
    obf = tmp / "obf.exe"
    obj = tmp / "cross.obj"
    clang(SOURCE, plain, "-O2")
    clang(SOURCE, obf, *IR_AND_MIR_FLAGS, "-mllvm", "-verify-machineinstrs")
    clang(SOURCE, obj, "-c", *IR_AND_MIR_FLAGS, "-mllvm", "-verify-machineinstrs")

    plain_run = run([str(plain)])
    obf_run = run([str(obf)])
    must(plain_run, "plain run")
    must(obf_run, "obfuscated run")
    if plain_run.stdout != obf_run.stdout:
        raise SystemExit(f"stdout mismatch: {plain_run.stdout!r} != {obf_run.stdout!r}")

    data = obj.read_bytes()
    require_any(data, DIRTY_GUARDS, "dirtybytes")
    if OLD_DOUBLE_XOR_DIRTY in data:
        raise SystemExit("old double-xor dirtybytes survived after IR passes")
    require(data, JUNK, "junk")
    require(data, SUB, "substitution")

    print("verify_machine_obf_l3_cross_pass: ok")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    if not CLANG.exists():
        print(f"missing tool: {CLANG}", file=sys.stderr)
        return 2
    tmp = Path(tempfile.mkdtemp(prefix="taokari-mir-l3-cross-"))
    try:
        return run_checks(tmp)
    finally:
        if args.keep:
            print(f"kept temp dir: {tmp}")
        else:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
