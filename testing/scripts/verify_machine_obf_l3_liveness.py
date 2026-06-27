"""MIR liveness regression tests (C2.1) for every sub-pass.

Each sub-pass is exercised on call-heavy, branch-heavy and terminator-heavy
fixtures. Every obfuscated build runs -verify-machineinstrs (the post-RA
liveness gate) AND must produce stdout identical to the plain build, which
proves live-in/live-out and physical-register preservation around calls,
branches and terminators.
"""
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

SUBPASSES = ["dirtybytes", "junk", "sub", "split", "fakeprologue", "sse", "unmodelled"]

CALL_FIXTURE = r'''
#include <cstdint>
#include <cstdio>
__attribute__((noinline,optnone)) uint32_t leaf(uint32_t a, uint32_t b) { return a * b + 1; }
__attribute__((noinline,optnone)) uint32_t caller(uint32_t x) {
  uint32_t s = 0;
  for (int i = 0; i < 4; ++i) s += leaf(x, i);
  return s;
}
int main() { std::printf("liveness-call:%u\n", caller(7)); return 0; }
'''

BRANCH_FIXTURE = r'''
#include <cstdint>
#include <cstdio>
__attribute__((noinline,optnone)) uint32_t dispatch(uint32_t x) {
  switch (x & 7) {
    case 0: return x + 1;
    case 1: return x * 2;
    case 2: return x ^ 0x55;
    case 3: return x - 7;
    case 4: return x | 0x80;
    case 5: return x & 0x0f;
    default: return x + (x << 3);
  }
}
int main() {
  uint32_t acc = 0;
  for (uint32_t i = 0; i < 16; ++i) acc ^= dispatch(i);
  std::printf("liveness-branch:%u\n", acc);
  return 0;
}
'''

TERMINATOR_FIXTURE = r'''
#include <cstdint>
#include <cstdio>
__attribute__((noinline,optnone)) int64_t loop_sum(const int32_t *p, uint32_t n) {
  int64_t s = 0;
  for (uint32_t i = 0; i < n; ++i) {
    if (p[i] < 0) continue;
    if (p[i] == 0) break;
    s += p[i];
  }
  return s;
}
int main() {
  int32_t buf[] = {3, -1, 0, 9, 4, -2, 7};
  std::printf("liveness-term:%lld\n", (long long)loop_sum(buf, 7));
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


def run_exe(exe: Path) -> str:
    r = run([str(exe)])
    must(r, exe.name)
    return r.stdout


def run_checks(tmp: Path) -> int:
    fixtures = {
        "call": CALL_FIXTURE,
        "branch": BRANCH_FIXTURE,
        "term": TERMINATOR_FIXTURE,
    }
    for name, body in fixtures.items():
        src = tmp / f"{name}.cpp"
        src.write_text(body, encoding="utf-8")
        plain_out = run_exe_after_clang(src, tmp, name)
        for sp in SUBPASSES:
            obf = tmp / f"{name}_{sp}.exe"
            clang(src, obf, "-mllvm", "-verify-machineinstrs",
                  "-mllvm", f"-taokari-mir={sp}")
            out = run_exe(obf)
            if out != plain_out:
                raise SystemExit(
                    f"{name}/{sp}: stdout mismatch {plain_out!r} != {out!r}")

    print("verify_machine_obf_l3_liveness: ok")
    return 0


def run_exe_after_clang(src: Path, tmp: Path, name: str) -> str:
    plain = tmp / f"{name}_plain.exe"
    clang(src, plain, "-mllvm", "-verify-machineinstrs")
    return run_exe(plain)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    if not CLANG.exists():
        print(f"missing tool: {CLANG}", file=sys.stderr)
        return 2
    tmp = Path(tempfile.mkdtemp(prefix="taokari-mir-live-"))
    try:
        return run_checks(tmp)
    finally:
        if args.keep:
            print(f"kept temp dir: {tmp}")
        else:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
