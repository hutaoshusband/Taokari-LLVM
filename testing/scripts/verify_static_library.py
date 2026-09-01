"""Static library fixture (todo.md F2).

A real-world compatibility case for a static-library link: object code is
obfuscated, archived into a static library (.lib), and linked into an EXE
that consumes it. The archive must preserve the obfuscated code and the link
must resolve the library symbols correctly.

Contract:
  * Compile a core source to an object under full obfuscation and archive it
    into a static library.
  * Link a main EXE against the static library and run it.
  * The result must equal the expected native result.

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
BIN = tp.BIN
CLANG = tp.CLANG
LLVM_AR = tp.tool("llvm-ar")
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


LIB_SOURCE = r"""
#include <stdint.h>

int32_t statlib_hash(const char *s) {
  int32_t h = 5381;
  for (const unsigned char *p = (const unsigned char *)s; *p; ++p)
    h = h * 33 + *p;
  return h;
}

int32_t statlib_fold(int32_t x, int32_t n) {
  int32_t acc = x;
  for (int32_t i = 0; i < n; ++i)
    acc = (acc ^ (i + 1)) * 7;
  return acc;
}
"""


MAIN_SOURCE = r"""
#include <stdint.h>
#include <stdio.h>

int32_t statlib_hash(const char *s);
int32_t statlib_fold(int32_t x, int32_t n);

int main(void) {
  int32_t h = statlib_hash("taokari-static-lib");
  int32_t f = statlib_fold(11, 4);
  printf("statlib:%d:%d\n", h, f);
  return 0;
}
"""


def expected() -> tuple[int, int]:
    s = "taokari-static-lib"
    h = 5381
    for ch in s.encode():
        h = (h * 33 + ch) & 0xFFFFFFFF
    h = h - 0x100000000 if h >= 0x80000000 else h
    acc = 11
    for i in range(4):
        v = (acc ^ (i + 1)) * 7
        acc = ((v + 0x100000000) if v < 0 else v) & 0xFFFFFFFF
        acc = acc - 0x100000000 if acc >= 0x80000000 else acc
    return h, acc


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-statlib-") as tmp_name:
        tmp = Path(tmp_name)
        lib_src = tmp / "statlib.c"
        lib_src.write_text(LIB_SOURCE, encoding="utf-8")
        main_src = tmp / "main.c"
        main_src.write_text(MAIN_SOURCE, encoding="utf-8")

        obj = tmp / "statlib.obj"
        if not must(run([str(CLANG), str(lib_src), "-O2", "-c",
                         *OBF_FLAGS, "-o", str(obj)]),
                    "obfuscated object build"):
            return 1

        static_lib = tmp / "libtaokari_statlib.a"
        if not must(run([str(LLVM_AR), "rcs", str(static_lib), str(obj)]),
                    "static archive"):
            return 1

        exe = tmp / "main.exe"
        if not must(run([str(CLANG), str(main_src), "-O2", str(static_lib),
                         "-o", str(exe)]),
                    "EXE link against static lib"):
            return 1

        result = run([str(exe)])
        if result.returncode:
            sys.stderr.write(f"EXE run failed rc={result.returncode}\n")
            sys.stderr.write(result.stdout + result.stderr)
            return 1

        h, f = expected()
        want = f"statlib:{h}:{f}\n"
        if result.stdout != want:
            print(f"FAIL: static-lib result {result.stdout!r} != expected "
                  f"{want!r}", file=sys.stderr)
            return 1

    print(f"static-library: ok (obfuscated object archived into .a and linked "
          f"into EXE; result matches native)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
