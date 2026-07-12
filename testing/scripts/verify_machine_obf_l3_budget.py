"""Level-3 MIR size/compile-time budget gate."""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
VSDEVCMD = tp.VSDEVCMD

SOURCE = r'''
#include <cstdint>
#include <cstdio>

#define NOINLINE __attribute__((noinline))
#define OPTNONE __attribute__((optnone))

extern "C" {
NOINLINE OPTNONE uint32_t alpha(uint32_t x) { return (x * 33u) ^ 0x45a1u; }
NOINLINE OPTNONE uint32_t beta(uint32_t x) { return (x + 17u) * 9u; }
NOINLINE OPTNONE uint32_t gamma(uint32_t a, uint32_t b) { return alpha(a) + beta(b); }
}

int main() {
  std::printf("mir-budget:%u\n", gamma(11, 29));
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


def compile_exe(src: Path, out: Path, *, obfuscate: bool) -> float:
    cmd = [str(CLANG), str(src), "-std=c++17", "-O1"]
    if obfuscate:
        cmd += [
            "-mllvm", "-verify-machineinstrs",
            "-mllvm", "-taokari-mir=dirtybytes,junk,sub",
        ]
    cmd += ["-o", str(out)]
    start = time.perf_counter()
    must(run_vs(cmd, src.parent), out.name)
    return time.perf_counter() - start


def over_budget(value: float, base: float, ratio: float, slack: float) -> bool:
    return value > base * ratio + slack


def run_checks(tmp: Path, args: argparse.Namespace) -> int:
    src = tmp / "mirobf_l3_budget.cpp"
    src.write_text(SOURCE, encoding="utf-8")

    plain = tmp / "plain.exe"
    obf = tmp / "obf.exe"
    plain_compile = compile_exe(src, plain, obfuscate=False)
    obf_compile = compile_exe(src, obf, obfuscate=True)

    plain_run = run([str(plain)])
    obf_run = run([str(obf)])
    must(plain_run, "plain run")
    must(obf_run, "obfuscated run")
    if plain_run.stdout != obf_run.stdout:
        raise SystemExit(f"stdout mismatch: {plain_run.stdout!r} != {obf_run.stdout!r}")

    plain_size = plain.stat().st_size
    obf_size = obf.stat().st_size
    if over_budget(obf_compile, plain_compile, args.max_compile_ratio, args.compile_slack):
        raise SystemExit(
            "compile-time budget exceeded: "
            f"plain={plain_compile:.3f}s obf={obf_compile:.3f}s "
            f"limit={args.max_compile_ratio}x+{args.compile_slack:.3f}s"
        )
    if over_budget(obf_size, plain_size, args.max_size_ratio, args.size_slack):
        raise SystemExit(
            "binary-size budget exceeded: "
            f"plain={plain_size} obf={obf_size} "
            f"limit={args.max_size_ratio}x+{args.size_slack:.0f} bytes"
        )

    print(
        "verify_machine_obf_l3_budget: ok "
        f"compile={plain_compile:.3f}s->{obf_compile:.3f}s "
        f"size={plain_size}->{obf_size}"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--max-compile-ratio", type=float, default=6.0)
    parser.add_argument("--compile-slack", type=float, default=15.0)
    parser.add_argument("--max-size-ratio", type=float, default=1.25)
    parser.add_argument("--size-slack", type=float, default=32768.0)
    args = parser.parse_args()
    if not CLANG.exists():
        print(f"missing tool: {CLANG}", file=sys.stderr)
        return 2
    tmp = Path(tempfile.mkdtemp(prefix="taokari-mir-l3-budget-"))
    try:
        return run_checks(tmp, args)
    finally:
        if args.keep:
            print(f"kept temp dir: {tmp}")
        else:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
