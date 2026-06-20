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


def compile_and_check(out: Path, name: str, extra_flags: list[str], want_indirectbr: bool) -> None:
    ll = out / f"{name}.ll"
    exe = out / f"{name}.exe"
    flags = [*FLAGS, *extra_flags]

    check(run([str(CLANG), "-S", "-emit-llvm", str(SOURCE), *flags, "-o", str(ll)]), f"emit llvm {name}")
    ir = ll.read_text(encoding="utf-8", errors="ignore")
    assert "switch i" not in ir, f"{name}: level-4 dispatcher still emits LLVM switch"
    assert "br i1" in ir, f"{name}: level-4 compare/branch dispatcher missing"
    assert ir.count("switchHit") >= 20, f"{name}: level-4 sparse/fake case density too low"
    if want_indirectbr:
        assert "indirectbr" in ir, f"{name}: indirectbr dispatcher missing"
    else:
        assert "switchBucket" in ir, f"{name}: level-4 bucket dispatcher missing"
        assert "indirectbr" not in ir, f"{name}: indirectbr should be opt-in"

    check(run([str(CLANG), str(SOURCE), *flags, "-o", str(exe)]), f"compile exe {name}")
    result = run([str(exe)])
    check(result, f"run exe {name}")
    assert result.stdout == EXPECTED, f"{name}: stdout {result.stdout!r} expected {EXPECTED!r}"


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(prefix="taokari-fla-l4-") as td:
        out = Path(td)
        compile_and_check(out, "flattening_l4", [], False)
        compile_and_check(
            out,
            "flattening_l4_indirectbr",
            ["-mllvm", "-taokari-fla-indirectbr-dispatch"],
            True,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
