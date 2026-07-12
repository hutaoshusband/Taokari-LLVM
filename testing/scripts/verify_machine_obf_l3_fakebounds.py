"""Level-3 MIR fake prologue/epilogue boundary-byte verification."""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
VSDEVCMD = tp.VSDEVCMD

FAKE_BOUNDS = bytes.fromhex(
    "9c 50 8a 04 24 34 6b 34 6b 3a 04 24 74 0f "
    "55 48 89 e5 48 83 ec 20 c9 c3 55 48 89 e5 5d 58 9d"
)
FRAME_PATTERN = bytes.fromhex("55 48 89 e5 48 83 ec 20 c9 c3 55 48 89 e5 5d")

ANNOTATIONS = r'''
#if defined(__clang__)
#define TAO_FAKEBOUNDS __attribute__((annotate("+mir:fakebounds")))
#else
#define TAO_FAKEBOUNDS
#endif
'''

SOURCE_BODY = r'''
#include <cstdint>
#include <cstdio>

#define NOINLINE __attribute__((noinline))
#define OPTNONE __attribute__((optnone))

extern "C" NOINLINE OPTNONE TAO_FAKEBOUNDS uint32_t guarded(uint32_t x) {
  return (x * 19u) ^ 0x51u;
}

int main() {
  std::printf("mir-fakebounds:%u\n", guarded(23));
  return 0;
}
'''


def run(command: list[str], **kw) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, **kw)


def run_vs(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    if not tp.IS_WINDOWS:
      return subprocess.run(command, cwd=cwd, text=True, capture_output=True)
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


def run_checks(tmp: Path) -> int:
    annotated = tmp / "mirobf_l3_fakebounds.cpp"
    plain_src = tmp / "mirobf_l3_fakebounds_plain.cpp"
    annotated.write_text(ANNOTATIONS + SOURCE_BODY, encoding="utf-8")
    plain_src.write_text(ANNOTATIONS.replace("+mir:fakebounds", "-mir") + SOURCE_BODY, encoding="utf-8")

    plain = tmp / "plain.exe"
    obf = tmp / "obf.exe"
    annotated_obj = tmp / "annotated.obj"
    flagged_obj = tmp / "flagged.obj"
    default_obj = tmp / "default.obj"

    clang(plain_src, plain)
    clang(annotated, obf)
    clang(annotated, annotated_obj, "-c", "-mllvm", "-verify-machineinstrs")
    clang(plain_src, flagged_obj, "-c", "-mllvm", "-verify-machineinstrs", "-mllvm", "-taokari-mir=fakebounds")
    clang(plain_src, default_obj, "-c", "-mllvm", "-verify-machineinstrs", "-mllvm", "-taokari-mir=dirtybytes,junk,sub")

    plain_run = run([str(plain)])
    obf_run = run([str(obf)])
    must(plain_run, "plain run")
    must(obf_run, "obfuscated run")
    if plain_run.stdout != obf_run.stdout:
        raise SystemExit(f"stdout mismatch: {plain_run.stdout!r} != {obf_run.stdout!r}")

    for path in (annotated_obj, flagged_obj):
        data = path.read_bytes()
        if FAKE_BOUNDS not in data:
            raise SystemExit(f"missing fake boundary bytes in {path.name}")
        if FRAME_PATTERN not in data:
            raise SystemExit(f"missing fake prologue/epilogue pattern in {path.name}")
    if FAKE_BOUNDS in default_obj.read_bytes():
        raise SystemExit("fake boundary bytes emitted by default MIR set")

    print("verify_machine_obf_l3_fakebounds: ok")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    if not CLANG.exists():
        print(f"missing tool: {CLANG}", file=sys.stderr)
        return 2
    tmp = Path(tempfile.mkdtemp(prefix="taokari-mir-l3-fakebounds-"))
    try:
        return run_checks(tmp)
    finally:
        if args.keep:
            print(f"kept temp dir: {tmp}")
        else:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
