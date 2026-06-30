"""MIR anti-microcode substitution family (C3.1) verification."""
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

SUB_ADD_LEA = bytes.fromhex(
    "9c 50 48 89 e0 48 8d 40 13 48 83 e8 13 58 9d")
SUB_DOUBLE_NEG = bytes.fromhex("9c 50 48 f7 d8 48 f7 d8 58 9d")
SUB_DOUBLE_NOT = bytes.fromhex("9c 50 48 f7 d0 48 f7 d0 58 9d")
VARIANTS = (SUB_ADD_LEA, SUB_DOUBLE_NEG, SUB_DOUBLE_NOT)


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


def compile_obj(src: Path, out: Path, *mir_args: str) -> bytes:
    cmd = [str(CLANG), str(src), "-std=c++17", "-O1", "-c",
           "-mllvm", "-verify-machineinstrs", *mir_args, "-o", str(out)]
    must(run_vs(cmd, src.parent), out.name)
    return out.read_bytes()


def run_checks(tmp: Path) -> int:
    bodies = []
    names = ("alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta",
             "theta", "iota", "kappa")
    for n in names:
        bodies.append(
            f'extern "C" __attribute__((noinline,optnone)) '
            f'uint32_t sub_{n}(uint32_t x) {{ return x * 13u + 1; }}\n'
        )
    src = tmp / "subfam.cpp"
    src.write_text(
        "#include <cstdint>\n#include <cstdio>\n" + "".join(bodies) +
        "int main() { std::printf(\"subfam:%u\\n\", sub_alpha(7)); return 0; }\n",
        encoding="utf-8")

    data = compile_obj(src, tmp / "subfam.obj", "-mllvm", "-taokari-mir=sub")
    present = [v for v in VARIANTS if v in data]
    if len(present) < 2:
        raise SystemExit(
            f"expected >=2 distinct substitution variants, saw {len(present)}")

    plain = tmp / "plain.exe"
    must(run_vs([str(CLANG), str(src), "-std=c++17", "-O1", "-o", str(plain)],
                src.parent), "plain")
    obf = tmp / "obf.exe"
    must(run_vs([str(CLANG), str(src), "-std=c++17", "-O1", "-mllvm",
                 "-verify-machineinstrs", "-mllvm", "-taokari-mir=sub",
                 "-o", str(obf)], src.parent), "obf")
    plain_run = run([str(plain)])
    obf_run = run([str(obf)])
    must(plain_run, "plain run")
    must(obf_run, "obf run")
    if plain_run.stdout != obf_run.stdout:
        raise SystemExit(f"stdout mismatch: {plain_run.stdout!r} != {obf_run.stdout!r}")

    print("verify_machine_obf_l3_substitution_family: ok")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    if not CLANG.exists():
        print(f"missing tool: {CLANG}", file=sys.stderr)
        return 2
    tmp = Path(tempfile.mkdtemp(prefix="taokari-mir-subfam-"))
    try:
        return run_checks(tmp)
    finally:
        if args.keep:
            print(f"kept temp dir: {tmp}")
        else:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
