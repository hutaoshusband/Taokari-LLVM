"""MIR config validation (C1.8) verification."""
from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
VSDEVCMD = tp.VSDEVCMD

PROBS = ["dirtybytes", "junk", "sub", "sse", "split", "fakeprologue"]


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
        return subprocess.run(["cmd.exe", "/d", "/c", str(batch)],
                              text=True, capture_output=True)
    finally:
        batch.unlink(missing_ok=True)


def compile_with(prob_arg: str | None) -> subprocess.CompletedProcess[str]:
    tmp = Path(tempfile.mkdtemp(prefix="taokari-mir-cfg-"))
    src = tmp / "c.cpp"
    src.write_text("int main(){return 0;}", encoding="utf-8")
    args = [str(CLANG), str(src), "-std=c++17", "-O1", "-c",
            "-mllvm", "-verify-machineinstrs", "-o", str(tmp / "o.obj")]
    if prob_arg is not None:
        args += ["-mllvm", prob_arg]
    return run_vs(args, src.parent)


def expect_fail(result: subprocess.CompletedProcess[str], label: str,
               marker: str) -> None:
    if result.returncode == 0:
        raise SystemExit(f"{label}: expected failure, got success")
    if marker not in result.stderr:
        raise SystemExit(f"{label}: stderr missing marker {marker!r}\n{result.stderr}")


def expect_ok(result: subprocess.CompletedProcess[str], label: str) -> None:
    if result.returncode != 0:
        raise SystemExit(f"{label}: expected success, got failure\n{result.stderr}")


def run_checks() -> int:
    for p in PROBS:
        expect_fail(compile_with(f"-taokari-mir-{p}-prob=150"),
                    f"{p} prob=150 (over max)", f"{p}-prob")
        expect_fail(compile_with(f"-taokari-mir-{p}-prob=-1"),
                    f"{p} prob=-1 (negative)", "value invalid for uint")
        expect_fail(compile_with(f"-taokari-mir-{p}-prob=abc"),
                    f"{p} prob=abc (wrong type)", "value invalid for uint")
        expect_ok(compile_with(f"-taokari-mir-{p}-prob=0"), f"{p} prob=0 (boundary)")
        expect_ok(compile_with(f"-taokari-mir-{p}-prob=100"), f"{p} prob=100 (boundary)")

    expect_ok(compile_with(None), "missing keys use defaults")

    over = compile_with("-taokari-mir-split-prob=200")
    if over.returncode == 0:
        raise SystemExit("over-max prob should fail")
    if "out of range" not in over.stderr:
        raise SystemExit(f"over-max prob stderr lacks 'out of range':\n{over.stderr}")

    print("verify_machine_obf_l3_config_validation: ok")
    return 0


def main() -> int:
    if not CLANG.exists():
        print(f"missing tool: {CLANG}", file=sys.stderr)
        return 2
    return run_checks()


if __name__ == "__main__":
    raise SystemExit(main())
