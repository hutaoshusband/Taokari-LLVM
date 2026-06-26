from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from taokari_postlink_hash import MAGIC, patch, pe_sections, pick_section, verify


ROOT = Path(__file__).resolve().parents[2]
CLANG = ROOT / "build" / "taokari-local" / "bin" / "clang.exe"
VSDEVCMD = Path(
    r"C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat"
)

SOURCE = r"""
#include <cstdio>

__attribute__((noinline))
__attribute__((annotate("+nativeint")))
static int guarded(int x) { return (x * 3) ^ 0x55; }

int main() {
  std::printf("postlink:%d\n", guarded(9));
  return 0;
}
"""


def run(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    if VSDEVCMD.exists():
        with tempfile.NamedTemporaryFile("w", suffix=".cmd", delete=False,
                                         encoding="utf-8") as handle:
            batch = Path(handle.name)
            handle.write(
                "@echo off\n"
                f'call "{VSDEVCMD}" -arch=x64 -host_arch=x64 >nul\n'
                f"{subprocess.list2cmdline(command)}\n"
                "exit /b %ERRORLEVEL%\n"
            )
        try:
            return subprocess.run(["cmd.exe", "/d", "/c", str(batch)], cwd=cwd,
                                  text=True, capture_output=True)
        finally:
            batch.unlink(missing_ok=True)
    return subprocess.run(command, cwd=cwd, text=True, capture_output=True)


def must(result: subprocess.CompletedProcess[str], label: str) -> None:
    if result.returncode:
        print(result.stdout, end="")
        print(result.stderr, end="", file=sys.stderr)
        raise SystemExit(f"{label} failed: {result.returncode}")


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2
    tmp = Path(tempfile.mkdtemp(prefix="taokari-postlink-"))
    try:
        src = tmp / "postlink.cpp"
        exe = tmp / "postlink.exe"
        src.write_text(SOURCE, encoding="utf-8")
        must(run([str(CLANG), str(src), "-O2", "-mllvm", "-taokari",
                  "-o", str(exe)], tmp), "build")
        data = exe.read_bytes()
        if data.count(MAGIC) != 1:
            raise SystemExit("post-link text hash slot missing or duplicated")
        try:
            verify(exe, ".text")
        except ValueError:
            pass
        else:
            raise SystemExit("unpatched binary verified unexpectedly")
        patch(exe, ".text")
        verify(exe, ".text")
        clean = run([str(exe)], tmp)
        must(clean, "patched run")
        if clean.stdout != "postlink:78\n":
            raise SystemExit(f"output drift: {clean.stdout!r}")
        tampered = tmp / "postlink_tampered.exe"
        shutil.copy2(exe, tampered)
        patched = bytearray(tampered.read_bytes())
        text = pick_section(pe_sections(patched), ".text")
        if text.raw_size < 16:
            raise SystemExit(".text too small")
        patched[text.raw_ptr + 8] ^= 1
        tampered.write_bytes(patched)
        try:
            verify(tampered, ".text")
        except ValueError:
            pass
        else:
            raise SystemExit("tampered .text verified unexpectedly")
        print("post-link text hash verifier: ok")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
