from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
IS_WINDOWS = os.name == "nt"
EXE = ".exe" if IS_WINDOWS else ""
OBJ = ".obj" if IS_WINDOWS else ".o"
SHARED_LIB = ".dll" if IS_WINDOWS else ".so"

_WINDOWS_BUILD = ROOT / "build" / "taokari-local" / "bin"
_LINUX_BUILD = ROOT / "build" / "taokari-linux" / "bin"


def _resolve_bin_dir() -> Path:
    override = os.environ.get("TAOKARI_BIN")
    if override:
        return Path(override)
    if _LINUX_BUILD.exists() and not IS_WINDOWS:
        return _LINUX_BUILD
    return _WINDOWS_BUILD


BIN = _resolve_bin_dir()
CLANG = BIN / f"clang{EXE}"
CLANG_CL = _WINDOWS_BUILD / f"clang-cl{EXE}"
READOBJ = BIN / f"llvm-readobj{EXE}"
OBJDUMP = BIN / f"llvm-objdump{EXE}"
READELF = BIN / f"llvm-readelf{EXE}"
NM = BIN / f"llvm-nm{EXE}"
AR = BIN / f"llvm-ar{EXE}"

VSDEVCMD = Path(
    r"C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat"
)


def tool(name: str) -> Path:
    return BIN / f"{name}{EXE}"


def run(command: list[str], *, cwd: Path = ROOT, vs: bool = False) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    if vs and VSDEVCMD.exists():
        with tempfile.NamedTemporaryFile("w", suffix=".cmd", delete=False, encoding="utf-8") as handle:
            batch = Path(handle.name)
            handle.write(
                "@echo off\n"
                f'call "{VSDEVCMD}" -arch=x64 -host_arch=x64 >nul\n'
                f"{subprocess.list2cmdline(command)}\n"
                "exit /b %ERRORLEVEL%\n"
            )
        try:
            return subprocess.run(
                ["cmd.exe", "/d", "/c", str(batch)],
                cwd=cwd, text=True, capture_output=True, env=env,
                encoding="utf-8", errors="replace",
            )
        finally:
            batch.unlink(missing_ok=True)
    return subprocess.run(
        command, cwd=cwd, text=True, capture_output=True, env=env,
        encoding="utf-8", errors="replace",
    )


def checked(command: list[str], *, cwd: Path = ROOT, vs: bool = False) -> subprocess.CompletedProcess[str]:
    result = run(command, cwd=cwd, vs=vs)
    if result.returncode:
        print(result.stdout, end="")
        print(result.stderr, end="", file=sys.stderr)
        raise SystemExit(result.returncode)
    return result


def exe_name(name: str) -> str:
    return f"{name}{EXE}"


def obj_name(name: str) -> str:
    return f"{name}{OBJ}"
