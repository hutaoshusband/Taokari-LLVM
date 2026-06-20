from __future__ import annotations

import argparse
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CLANG = ROOT / "build" / "taokari-local" / "bin" / "clang.exe"
SOURCE = ROOT / "testing" / "cases" / "ida_switch_recovery" / "src" / "main.c"
VSDEVCMD = Path(r"C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat")
FLAGS = [
    "-O2",
    "-std=c17",
    "-fno-discard-value-names",
    "-mllvm", "-taokari",
    "-mllvm", "-taokari-fla",
    "-mllvm", "-taokari-level-fla=4",
]


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    if VSDEVCMD.exists():
        with tempfile.NamedTemporaryFile("w", suffix=".cmd", delete=False, encoding="utf-8") as handle:
            batch = Path(handle.name)
            handle.write(
                "@echo off\n"
                f'call "{VSDEVCMD}" -arch=x64 -host_arch=x64 >nul\n'
                f"{subprocess.list2cmdline(command)}\n"
                "exit /b %ERRORLEVEL%\n"
            )
        try:
            return subprocess.run(["cmd.exe", "/d", "/c", str(batch)], cwd=ROOT, text=True, capture_output=True)
        finally:
            batch.unlink(missing_ok=True)
    return subprocess.run(command, cwd=ROOT, text=True, capture_output=True)


def check(result: subprocess.CompletedProcess[str], label: str) -> None:
    if result.returncode:
        raise SystemExit(f"{label} failed\n{result.stdout}{result.stderr}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Build IDA switch-recovery fixture.")
    parser.add_argument("--artifacts-dir", type=Path, default=ROOT / "testing" / "ida_l4")
    args = parser.parse_args()
    args.artifacts_dir.mkdir(parents=True, exist_ok=True)

    ll = args.artifacts_dir / "ida_switch_recovery.ll"
    exe = args.artifacts_dir / "ida_switch_recovery.exe"
    check(run([str(CLANG), "-S", "-emit-llvm", str(SOURCE), *FLAGS, "-o", str(ll)]), "emit llvm")
    ir = ll.read_text(encoding="utf-8", errors="ignore")
    assert "switch i" not in ir, "IDA fixture still contains LLVM switch"
    assert "switchBucket" in ir, "IDA fixture missing L4 bucket dispatcher"

    check(run([str(CLANG), str(SOURCE), *FLAGS, "-o", str(exe)]), "compile exe")
    result = run([str(exe)])
    check(result, "run exe")
    assert result.stdout.startswith("ida-switch:"), result.stdout
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
