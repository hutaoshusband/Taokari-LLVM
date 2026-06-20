"""Level-2 MIR obfuscation verification."""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CLANG = ROOT / "build" / "taokari-local" / "bin" / "clang.exe"
VSDEVCMD = Path(
    r"C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat"
)

MARKER = bytes.fromhex("48 8d 40 00")
DIRTY = bytes.fromhex("48 39 e4 74 08 0f 0b eb fe cc f1 0f 0b")
JUNK = bytes.fromhex("9c 50 80 34 24 5a 80 34 24 5a 58 9d")
SUB = bytes.fromhex("9c 50 48 89 e0 48 8d 40 13 48 83 e8 13 58 9d")

NO_ANNOTATIONS = r'''
#define TAO_DIRTY
#define TAO_JUNK
#define TAO_SUB
#define TAO_OFF
'''

ANNOTATIONS = r'''
#if defined(__clang__)
#define TAO_DIRTY __attribute__((annotate("+mir:dirtybytes")))
#define TAO_JUNK  __attribute__((annotate("+mir:junk")))
#define TAO_SUB   __attribute__((annotate("+mir:sub")))
#define TAO_OFF   __attribute__((annotate("-mir")))
#else
#define TAO_DIRTY
#define TAO_JUNK
#define TAO_SUB
#define TAO_OFF
#endif
'''

SOURCE_BODY = r'''
#include <cstdint>
#include <cstdio>

#define NOINLINE __attribute__((noinline))
#define OPTNONE __attribute__((optnone))

extern "C" {
NOINLINE OPTNONE TAO_DIRTY uint32_t dirty_sum(uint32_t a, uint32_t b) { return a + b + 7; }
NOINLINE OPTNONE TAO_JUNK  uint32_t junk_sum(uint32_t a, uint32_t b) { return a * 33u + b; }
NOINLINE OPTNONE TAO_SUB   uint32_t sub_sum(uint32_t a, uint32_t b) { return (a ^ b) + 9; }
NOINLINE OPTNONE TAO_OFF   uint32_t off_sum(uint32_t a, uint32_t b) { return a - b; }
NOINLINE OPTNONE           uint32_t flag_sum(uint32_t a, uint32_t b) { return a + (b * 3u); }
}

int main() {
  std::printf("mir2:%u:%u:%u:%u:%u\n", dirty_sum(1, 2), junk_sum(3, 4),
              sub_sum(5, 6), off_sum(9, 4), flag_sum(7, 8));
  return 0;
}
'''


def run(command: list[str], **kw) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, **kw)


def run_vs(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    with tempfile.NamedTemporaryFile("w", suffix=".cmd", delete=False, encoding="utf-8") as h:
        batch = Path(h.name)
        h.write(
            "@echo off\n"
            f'call "{VSDEVCMD}" -arch=x64 -host_arch=x64 >nul\n'
            f"{subprocess.list2cmdline(command)}\n"
            "exit /b %ERRORLEVEL%\n"
        )
    try:
        return run(["cmd.exe", "/d", "/c", str(batch)], cwd=cwd)
    finally:
        batch.unlink(missing_ok=True)


def must(result: subprocess.CompletedProcess[str], label: str) -> None:
    if result.returncode:
        print(result.stdout, end="")
        print(result.stderr, end="", file=sys.stderr)
        raise SystemExit(f"{label} failed: {result.returncode}")


def clang(src: Path, out: Path, *args: str) -> None:
    cmd = [str(CLANG), str(src), "-std=c++17", "-O1", *args, "-o", str(out)]
    must(run_vs(cmd, src.parent), out.name)


def compile_obj(src: Path, out: Path, mir: str | None) -> bytes:
    args = ["-c", "-mllvm", "-verify-machineinstrs"]
    if mir is not None:
        args += ["-mllvm", f"-taokari-mir={mir}"]
    clang(src, out, *args)
    return out.read_bytes()


def assert_has(data: bytes, pattern: bytes, name: str) -> None:
    if pattern not in data:
        raise SystemExit(f"missing {name} pattern")


def assert_not_has(data: bytes, pattern: bytes, name: str) -> None:
    if pattern in data:
        raise SystemExit(f"unexpected {name} pattern")


def run_checks(tmp: Path) -> int:
    src = tmp / "mirobf_level2.cpp"
    annotated_src = tmp / "mirobf_level2_annotated.cpp"
    src.write_text(NO_ANNOTATIONS + SOURCE_BODY, encoding="utf-8")
    annotated_src.write_text(ANNOTATIONS + SOURCE_BODY, encoding="utf-8")

    plain = tmp / "plain.exe"
    obf = tmp / "obf.exe"
    clang(src, plain)
    clang(src, obf, "-mllvm", "-verify-machineinstrs", "-mllvm", "-taokari-mir=dirtybytes,junk,sub")
    plain_run = run([str(plain)])
    obf_run = run([str(obf)])
    must(plain_run, "plain run")
    must(obf_run, "obfuscated run")
    if plain_run.stdout != obf_run.stdout:
        raise SystemExit(f"stdout mismatch: {plain_run.stdout!r} != {obf_run.stdout!r}")

    dirty_obj = compile_obj(src, tmp / "dirty.obj", "dirtybytes")
    assert_has(dirty_obj, DIRTY, "dirtybytes")
    assert_not_has(dirty_obj, JUNK, "junk")
    assert_not_has(dirty_obj, SUB, "substitution")

    junk_obj = compile_obj(src, tmp / "junk.obj", "junk")
    assert_has(junk_obj, JUNK, "junk")
    assert_not_has(junk_obj, DIRTY, "dirtybytes")
    assert_not_has(junk_obj, SUB, "substitution")

    sub_obj = compile_obj(src, tmp / "sub.obj", "sub")
    assert_has(sub_obj, SUB, "substitution")
    assert_not_has(sub_obj, DIRTY, "dirtybytes")
    assert_not_has(sub_obj, JUNK, "junk")

    all_obj = compile_obj(src, tmp / "all.obj", "dirtybytes,junk,sub")
    assert_has(all_obj, DIRTY, "dirtybytes")
    assert_has(all_obj, JUNK, "junk")
    assert_has(all_obj, SUB, "substitution")
    assert_not_has(all_obj, MARKER, "legacy marker")

    legacy_obj = compile_obj(src, tmp / "legacy.obj", "1")
    assert_has(legacy_obj, MARKER, "legacy marker")
    assert_has(legacy_obj, DIRTY, "dirtybytes")
    assert_has(legacy_obj, JUNK, "junk")
    assert_has(legacy_obj, SUB, "substitution")

    annotated_obj = compile_obj(annotated_src, tmp / "annotated.obj", None)
    assert_has(annotated_obj, DIRTY, "annotated dirtybytes")
    assert_has(annotated_obj, JUNK, "annotated junk")
    assert_has(annotated_obj, SUB, "annotated substitution")
    assert_not_has(annotated_obj, MARKER, "legacy marker")

    llvm_ir = tmp / "input.O2.ll"
    clang(src, llvm_ir, "-O2", "-S", "-emit-llvm")
    ir_bytes = llvm_ir.read_bytes()
    for name, pattern in {"dirtybytes": DIRTY, "junk": JUNK, "substitution": SUB}.items():
        assert_not_has(ir_bytes, pattern, f"IR-level {name}")

    print("verify_machine_obf_level2: ok")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    if not CLANG.exists():
        print(f"missing tool: {CLANG}", file=sys.stderr)
        return 2
    tmp = Path(tempfile.mkdtemp(prefix="taokari-mir-l2-"))
    try:
        return run_checks(tmp)
    finally:
        if args.keep:
            print(f"kept temp dir: {tmp}")
        else:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
