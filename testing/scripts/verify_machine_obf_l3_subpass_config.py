"""MIR sub-pass probability config (C1.5/C1.6) verification."""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
VSDEVCMD = tp.VSDEVCMD

SPLIT_MARKER = bytes.fromhex("9c 9d")
FAKE_PROLOGUE = bytes.fromhex(
    "9c 50 8a 04 24 34 6b 34 6b 3a 04 24 74 0f 55 48 89 e5 48 83 ec 20 c9 c3 55 48 89 e5 5d 58 9d"
)

SOURCE = r'''
#include <cstdint>
#include <cstdio>

#define NOINLINE __attribute__((noinline))
#define OPTNONE __attribute__((optnone))

extern "C" __declspec(dllexport) NOINLINE OPTNONE
uint32_t cfg_guarded(uint32_t x) {
  uint32_t y = (x * 17u) ^ 0x77u;
  return y + ((x & 3u) * 5u);
}

int main() {
  std::printf("mir-cfg:%u\n", cfg_guarded(31));
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


def compile_obj(src: Path, out: Path, *mir_args: str) -> bytes:
    clang(src, out, "-c", "-mllvm", "-verify-machineinstrs", *mir_args)
    return out.read_bytes()


def run_exe(exe: Path) -> str:
    r = run([str(exe)])
    must(r, exe.name)
    return r.stdout


def run_checks(tmp: Path) -> int:
    src = tmp / "mirobf_cfg.cpp"
    src.write_text(SOURCE, encoding="utf-8")

    plain = tmp / "plain.exe"
    clang(src, plain)
    obf = tmp / "obf.exe"
    clang(src, obf, "-mllvm", "-taokari-mir=split,fakeprologue",
          "-mllvm", "-taokari-mir-split-prob=100",
          "-mllvm", "-taokari-mir-fakeprologue-prob=100")
    if run_exe(plain) != run_exe(obf):
        raise SystemExit("plain/obf stdout mismatch")

    split_off = compile_obj(src, tmp / "split_off.obj",
                            "-mllvm", "-taokari-mir=split",
                            "-mllvm", "-taokari-mir-split-prob=0")
    if SPLIT_MARKER in split_off:
        raise SystemExit("split emitted at prob=0")

    split_on = compile_obj(src, tmp / "split_on.obj",
                           "-mllvm", "-taokari-mir=split",
                           "-mllvm", "-taokari-mir-split-prob=100")
    if SPLIT_MARKER not in split_on:
        raise SystemExit("split absent at prob=100")

    fake_off = compile_obj(src, tmp / "fake_off.obj",
                           "-mllvm", "-taokari-mir=fakeprologue",
                           "-mllvm", "-taokari-mir-fakeprologue-prob=0")
    if FAKE_PROLOGUE in fake_off:
        raise SystemExit("fakeprologue emitted at prob=0")

    fake_on = compile_obj(src, tmp / "fake_on.obj",
                          "-mllvm", "-taokari-mir=fakeprologue",
                          "-mllvm", "-taokari-mir-fakeprologue-prob=100")
    if FAKE_PROLOGUE not in fake_on:
        raise SystemExit("fakeprologue absent at prob=100")

    det_a = compile_obj(src, tmp / "det_a.obj",
                        "-mllvm", "-taokari-mir=split,fakeprologue",
                        "-mllvm", "-taokari-mir-split-prob=50")
    det_b = compile_obj(src, tmp / "det_b.obj",
                        "-mllvm", "-taokari-mir=split,fakeprologue",
                        "-mllvm", "-taokari-mir-split-prob=50")
    if (SPLIT_MARKER in det_a) != (SPLIT_MARKER in det_b):
        raise SystemExit("non-deterministic split decision at fixed seed")
    if (FAKE_PROLOGUE in det_a) != (FAKE_PROLOGUE in det_b):
        raise SystemExit("non-deterministic fakeprologue decision at fixed seed")

    print("verify_machine_obf_l3_subpass_config: ok")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    if not CLANG.exists():
        print(f"missing tool: {CLANG}", file=sys.stderr)
        return 2
    tmp = Path(tempfile.mkdtemp(prefix="taokari-mir-cfg-"))
    try:
        return run_checks(tmp)
    finally:
        if args.keep:
            print(f"kept temp dir: {tmp}")
        else:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
