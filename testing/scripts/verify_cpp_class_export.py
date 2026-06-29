"""C++ class export fixture (todo.md F2).

A real-world compatibility case for a C++ class export: a DLL exports a C
factory that returns a pointer to an abstract interface (pure-virtual class),
and the loader invokes methods through the vtable across the DLL boundary.
This is the COM / plugin-ABI shape. The vtable export and cross-boundary
virtual dispatch must survive the obfuscator.

Contract:
  * Build a DLL exporting a factory (extern "C") that constructs a concrete
    implementation of an abstract interface, under full obfuscation.
  * Build a loader EXE that gets the interface pointer and calls the virtual
    methods.
  * The loader's computed result must equal the expected native result.

Exit: 0 ok | 1 contract failure | 2 missing clang.
"""
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
#include <cstdint>

struct ICalculator {
  virtual ~ICalculator() {}
  virtual int32_t combine(int32_t a, int32_t b) = 0;
  virtual int32_t sequence(int32_t n) = 0;
};

struct CalculatorImpl : ICalculator {
  int32_t combine(int32_t a, int32_t b) override {
    int32_t r = (a ^ 0x2A) + (b * 5) - (a & 0x0F);
    return r + 7;
  }
  int32_t sequence(int32_t n) override {
    int32_t s = 0;
    for (int32_t i = 0; i < n; ++i)
      s = (s + i * (i + 1)) ^ 0x11;
    return s;
  }
};

extern "C" __declspec(dllexport) ICalculator *make_calculator() {
  return new CalculatorImpl();
}

extern "C" __declspec(dllexport) void destroy_calculator(ICalculator *c) {
  delete c;
}
"""


LOADER_SOURCE = r"""
#include <windows.h>
#include <cstdint>
#include <stdio.h>

struct ICalculator {
  virtual ~ICalculator() {}
  virtual int32_t combine(int32_t a, int32_t b) = 0;
  virtual int32_t sequence(int32_t n) = 0;
};

typedef ICalculator *(*make_t)();
typedef void (*destroy_t)(ICalculator *);

int main(void) {
  HMODULE dll = LoadLibraryA("cppcls_probe.dll");
  if (!dll) {
    printf("cppcls:loadfail\n");
    return 1;
  }
  make_t make = (make_t)GetProcAddress(dll, "make_calculator");
  destroy_t destroy = (destroy_t)GetProcAddress(dll, "destroy_calculator");
  if (!make || !destroy) {
    printf("cppcls:resolvefail\n");
    FreeLibrary(dll);
    return 1;
  }
  ICalculator *c = make();
  if (!c) {
    printf("cppcls:nullfactory\n");
    FreeLibrary(dll);
    return 1;
  }
  int32_t comb = c->combine(17, 25);
  int32_t seq = c->sequence(6);
  destroy(c);
  FreeLibrary(dll);
  printf("cppcls:%d:%d\n", comb, seq);
  return 0;
}
"""


def expected() -> tuple[int, int]:
    a, b = 17, 25
    comb = ((a ^ 0x2A) + (b * 5) - (a & 0x0F)) + 7
    s = 0
    for i in range(6):
        s = (s + i * (i + 1)) ^ 0x11
    return comb, s


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-cppcls-") as tmp_name:
        tmp = Path(tmp_name)
        dll_src = tmp / "cppcls.cpp"
        dll_src.write_text(DLL_SOURCE, encoding="utf-8")
        loader_src = tmp / "loader.cpp"
        loader_src.write_text(LOADER_SOURCE, encoding="utf-8")

        dll = tmp / "cppcls_probe.dll"
        if not must(run([str(CLANG), str(dll_src), "-std=c++17", "-O2", "-shared",
                         *OBF_FLAGS, "-o", str(dll)]),
                    "DLL build (obfuscated)"):
            return 1

        loader = tmp / "loader.exe"
        if not must(run([str(CLANG), str(loader_src), "-std=c++17", "-O2",
                         "-o", str(loader)]),
                    "loader build"):
            return 1

        result = run([str(loader)], cwd=tmp)
        if result.returncode:
            sys.stderr.write(f"loader run failed rc={result.returncode}\n")
            sys.stderr.write(result.stdout + result.stderr)
            return 1

        comb, seq = expected()
        want = f"cppcls:{comb}:{seq}\n"
        if result.stdout != want:
            print(f"FAIL: C++ class export result {result.stdout!r} != expected "
                  f"{want!r}", file=sys.stderr)
            return 1

    print(f"cpp-class-export: ok (factory + vtable dispatch across DLL boundary "
          f"survive full obfuscation)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
