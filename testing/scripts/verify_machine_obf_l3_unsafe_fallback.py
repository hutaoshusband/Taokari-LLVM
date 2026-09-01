"""MIR unsafe-function fallback (C2.3) verification."""
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

FAKE_PROLOGUE = bytes.fromhex(
    "9c 50 8a 04 24 34 6b 34 6b 3a 04 24 74 0f 55 48 89 e5 48 83 ec 20 c9 c3 55 48 89 e5 5d 58 9d"
)

EH_SOURCE = r'''
#include <cstdint>
#include <cstdio>
struct Bomb { ~Bomb() {} };
extern "C" __declspec(dllexport) __attribute__((noinline,optnone))
uint32_t may_throw(uint32_t x) {
  Bomb b;
  try {
    if (x & 1) throw 7;
    return x * 3u;
  } catch (int) {
    return x + 100u;
  }
}
int main() {
  try {
    std::printf("eh:%u:%u\n", may_throw(4), may_throw(5));
  } catch (...) {
    std::printf("eh:caught\n");
  }
  return 0;
}
'''

SAFE_SOURCE = r'''
#include <cstdint>
#include <cstdio>
extern "C" __declspec(dllexport) __attribute__((noinline,optnone))
uint32_t plain_fn(uint32_t x) { return x * 3u + 1; }
int main() { std::printf("safe:%u\n", plain_fn(7)); return 0; }
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


def clang(src: Path, out: Path, *args: str) -> subprocess.CompletedProcess[str]:
    cmd = [str(CLANG), str(src), "-std=c++17", "-O1", *args, "-o", str(out)]
    r = run_vs(cmd, src.parent)
    must(r, out.name)
    return r


def run_checks(tmp: Path) -> int:
    eh_src = tmp / "eh.cpp"
    eh_src.write_text(EH_SOURCE, encoding="utf-8")

    plain = tmp / "plain.exe"
    clang(eh_src, plain)
    plain_out = run([str(plain)])
    must(plain_out, "plain run")

    obf = tmp / "eh_obf.exe"
    clang(eh_src, obf, "-mllvm", "-verify-machineinstrs",
          "-mllvm", "-taokari-mir=fakeprologue,sse,split")
    obf_out = run([str(obf)])
    must(obf_out, "obfuscated EH run")
    if obf_out.stdout != plain_out.stdout:
        raise SystemExit(f"EH stdout mismatch: {plain_out.stdout!r} != {obf_out.stdout!r}")

    eh_obj = tmp / "eh.obj"
    cr = clang(eh_src, eh_obj, "-c", "-mllvm", "-verify-machineinstrs",
               "-mllvm", "-taokari-mir=fakeprologue,sse,split",
               "-mllvm", "-taokari-mir-verbose")
    if "skip may_throw" not in cr.stderr or "EH/funclet" not in cr.stderr:
        raise SystemExit(f"verbose skip for may_throw missing:\n{cr.stderr}")

    safe_src = tmp / "safe.cpp"
    safe_src.write_text(SAFE_SOURCE, encoding="utf-8")
    safe_obj = tmp / "safe.obj"
    clang(safe_src, safe_obj, "-c", "-mllvm", "-verify-machineinstrs",
          "-mllvm", "-taokari-mir=fakeprologue")
    if FAKE_PROLOGUE not in safe_obj.read_bytes():
        raise SystemExit("safe function was not transformed (gate over-fired)")

    print("verify_machine_obf_l3_unsafe_fallback: ok")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    if not CLANG.exists():
        print(f"missing tool: {CLANG}", file=sys.stderr)
        return 2
    tmp = Path(tempfile.mkdtemp(prefix="taokari-mir-unsafe-"))
    try:
        return run_checks(tmp)
    finally:
        if args.keep:
            print(f"kept temp dir: {tmp}")
        else:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
