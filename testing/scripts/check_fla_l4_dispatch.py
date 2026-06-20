from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CLANG = ROOT / "build" / "taokari-local" / "bin" / "clang.exe"
SOURCE = ROOT / "testing" / "cases" / "flattening_stress" / "src" / "main.cpp"
VSDEVCMD = Path(r"C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat")
EXPECTED = "flattening-stress:2287845297:2439064602\n"
FLAGS = [
    "-O2",
    "-std=c++17",
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
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(prefix="taokari-fla-l4-") as td:
        out = Path(td)
        ll = out / "flattening_l4.ll"
        exe = out / "flattening_l4.exe"

        check(run([str(CLANG), "-S", "-emit-llvm", str(SOURCE), *FLAGS, "-o", str(ll)]), "emit llvm")
        ir = ll.read_text(encoding="utf-8", errors="ignore")
        assert "switch i" not in ir, "level-4 dispatcher still emits LLVM switch"
        assert "br i1" in ir, "level-4 compare/branch dispatcher missing"

        check(run([str(CLANG), str(SOURCE), *FLAGS, "-o", str(exe)]), "compile exe")
        result = run([str(exe)])
        check(result, "run exe")
        assert result.stdout == EXPECTED, f"stdout {result.stdout!r} expected {EXPECTED!r}"
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
