"""Build and load a DLL containing a VMP-protected export."""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CLANG = ROOT / "build" / "taokari-local" / "bin" / "clang.exe"
VSDEVCMD = Path(
    r"C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat"
)

DLL_SOURCE = r"""
#define VMP __attribute__((noinline, annotate("+vmp")))

__declspec(dllexport) VMP int vm_dll_add(int a, int b) {
  int x = (a + b) ^ 0x55;
  x = (x * 3) - (a & 7);
  return x + 11;
}
"""

LOADER_SOURCE = r"""
#include <windows.h>

typedef int (__cdecl *vm_dll_add_t)(int, int);

int main(void) {
  HMODULE dll = LoadLibraryA("vmp_probe.dll");
  if (!dll)
    return 10;
  vm_dll_add_t fn = (vm_dll_add_t)GetProcAddress(dll, "vm_dll_add");
  if (!fn)
    return 11;
  int got = fn(17, 25);
  FreeLibrary(dll);
  return got == ((((17 + 25) ^ 0x55) * 3) - (17 & 7) + 11) ? 0 : 12;
}
"""


def run(cmd: list[str], *, cwd: Path = ROOT,
        use_vs_env: bool = False) -> subprocess.CompletedProcess[str]:
    if use_vs_env and VSDEVCMD.exists():
        with tempfile.NamedTemporaryFile("w", suffix=".cmd", delete=False,
                                         encoding="utf-8") as handle:
            batch = Path(handle.name)
            handle.write("@echo off\n")
            handle.write(f'call "{VSDEVCMD}" -arch=x64 -host_arch=x64 >nul\n')
            handle.write(subprocess.list2cmdline(cmd) + "\n")
        try:
            return subprocess.run(["cmd.exe", "/c", str(batch)], cwd=cwd,
                                  text=True, capture_output=True)
        finally:
            batch.unlink(missing_ok=True)
    return subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-vmp-dll-") as tmp:
        tmpdir = Path(tmp)
        dll_c = tmpdir / "vmp_probe.c"
        loader_c = tmpdir / "loader.c"
        dll = tmpdir / "vmp_probe.dll"
        loader = tmpdir / "loader.exe"
        dll_c.write_text(DLL_SOURCE, encoding="utf-8")
        loader_c.write_text(LOADER_SOURCE, encoding="utf-8")

        build_dll = run([
            str(CLANG), str(dll_c), "-shared", "-o", str(dll),
            "-mllvm", "-taokari", "-mllvm", "-taokari-vmp",
        ], use_vs_env=True)
        if build_dll.returncode:
            sys.stderr.write(build_dll.stdout + build_dll.stderr)
            return 1

        build_loader = run([str(CLANG), str(loader_c), "-o", str(loader)],
                           use_vs_env=True)
        if build_loader.returncode:
            sys.stderr.write(build_loader.stdout + build_loader.stderr)
            return 1

        result = run([str(loader)], cwd=tmpdir)
        if result.returncode:
            sys.stderr.write(result.stdout + result.stderr)
            print(f"vmp dll load: FAIL (loader exited {result.returncode})",
                  file=sys.stderr)
            return 1

    print("vmp dll load: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
