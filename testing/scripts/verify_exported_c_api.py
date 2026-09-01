"""Exported C API fixture (todo.md F2).

A real-world compatibility case for an exported C API: a DLL with several
__declspec(dllexport) functions built under obfuscation, loaded at runtime
via LoadLibrary + GetProcAddress. Exported-symbol resolution and the ABI of
the protected exports must survive the obfuscator.

Contract:
  * Build a DLL exporting three C functions (arithmetic, lookup, accumulate)
    under full obfuscation.
  * Build a loader EXE that LoadLibrary's the DLL, resolves each export, and
    calls it.
  * The loader's computed result must equal the expected native result.

Exit: 0 ok | 1 contract failure | 2 missing clang.
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
VSDEVCMD = tp.VSDEVCMD


def run(command: list[str], *, cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    if VSDEVCMD.exists():
        with tempfile.NamedTemporaryFile(
            "w", suffix=".cmd", delete=False, encoding="utf-8"
        ) as handle:
            batch = Path(handle.name)
            handle.write(
                "@echo off\n"
                f'call "{VSDEVCMD}" -arch=x64 -host_arch=x64 >nul\n'
                f"{subprocess.list2cmdline(command)}\n"
                "exit /b %ERRORLEVEL%\n"
            )
        try:
            return subprocess.run(
                ["cmd.exe", "/d", "/c", str(batch)], cwd=cwd,
                text=True, capture_output=True,
            )
        finally:
            batch.unlink(missing_ok=True)
    return subprocess.run(command, cwd=cwd, text=True, capture_output=True)


def must(result: subprocess.CompletedProcess[str], label: str) -> bool:
    if result.returncode:
        sys.stderr.write(f"{label} failed:\n")
        sys.stderr.write((result.stdout or "") + (result.stderr or ""))
        return False
    return True


def mllvm(flags: list[str]) -> list[str]:
    out = []
    for f in flags:
        out += ["-mllvm", f]
    return out


OBF_FLAGS = mllvm(["-taokari", "-taokari-indbr", "-taokari-icall", "-taokari-indgv",
                   "-taokari-fla", "-taokari-bcf", "-taokari-mba", "-taokari-cse",
                   "-taokari-cie", "-taokari-cfe"])


DLL_SOURCE = r"""
#include <stdint.h>

__declspec(dllexport) int32_t c_api_add(int32_t a, int32_t b) {
  int32_t r = (a ^ 0x33) + (b * 7) - (a & 0x0F);
  return r + 5;
}

__declspec(dllexport) int32_t c_api_lookup(int32_t index) {
  static const int32_t table[8] = {10, 21, 32, 43, 54, 65, 76, 87};
  if (index < 0 || index > 7)
    return -1;
  int32_t v = table[index];
  return (v * 3) ^ (index + 1);
}

__declspec(dllexport) int32_t c_api_accumulate(const int32_t *data, int32_t n) {
  int32_t s = 0;
  for (int32_t i = 0; i < n; ++i)
    s = (s + data[i] * (i + 1)) ^ 0x11;
  return s;
}
"""


LOADER_SOURCE = r"""
#include <windows.h>
#include <stdint.h>
#include <stdio.h>

typedef int32_t (__cdecl *add_t)(int32_t, int32_t);
typedef int32_t (__cdecl *lookup_t)(int32_t);
typedef int32_t (__cdecl *accum_t)(const int32_t *, int32_t);

int main(void) {
  HMODULE dll = LoadLibraryA("capi_probe.dll");
  if (!dll) {
    printf("capi:loadfail\n");
    return 1;
  }
  add_t add = (add_t)GetProcAddress(dll, "c_api_add");
  lookup_t lookup = (lookup_t)GetProcAddress(dll, "c_api_lookup");
  accum_t accum = (accum_t)GetProcAddress(dll, "c_api_accumulate");
  if (!add || !lookup || !accum) {
    printf("capi:resolvefail\n");
    FreeLibrary(dll);
    return 1;
  }
  int32_t a = add(17, 25);
  int32_t l = lookup(3);
  static const int32_t data[5] = {1, 2, 3, 4, 5};
  int32_t acc = accum(data, 5);
  FreeLibrary(dll);
  printf("capi:%d:%d:%d\n", a, l, acc);
  return 0;
}
"""


def expected() -> tuple[int, int, int]:
    a = ((17 ^ 0x33) + (25 * 7) - (17 & 0x0F)) + 5
    v = 43
    l = (v * 3) ^ (3 + 1)
    data = [1, 2, 3, 4, 5]
    s = 0
    for i in range(5):
        s = (s + data[i] * (i + 1)) ^ 0x11
    return a, l, s


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-capi-") as tmp_name:
        tmp = Path(tmp_name)
        dll_src = tmp / "capi.c"
        dll_src.write_text(DLL_SOURCE, encoding="utf-8")
        loader_src = tmp / "loader.c"
        loader_src.write_text(LOADER_SOURCE, encoding="utf-8")

        dll = tmp / "capi_probe.dll"
        if not must(run([str(CLANG), str(dll_src), "-O2", "-shared",
                         *OBF_FLAGS, "-o", str(dll)]),
                    "DLL build (obfuscated)"):
            return 1

        loader = tmp / "loader.exe"
        if not must(run([str(CLANG), str(loader_src), "-O2",
                         "-o", str(loader)]),
                    "loader build"):
            return 1

        result = run([str(loader)], cwd=tmp)
        if result.returncode:
            sys.stderr.write(f"loader run failed rc={result.returncode}\n")
            sys.stderr.write(result.stdout + result.stderr)
            return 1

        a, l, s = expected()
        want = f"capi:{a}:{l}:{s}\n"
        if result.stdout != want:
            print(f"FAIL: exported C API result {result.stdout!r} != expected "
                  f"{want!r}", file=sys.stderr)
            return 1

    print(f"exported-c-api: ok (3 exports resolved via LoadLibrary/GetProcAddress, "
          f"results match native under full obfuscation)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
