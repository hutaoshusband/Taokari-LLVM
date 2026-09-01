"""Binary-level function boundary fragmentation metric (C3.7).

Estimates function-boundary fragmentation from object artifacts using
llvm-objdump, focusing on stable structural properties:

- entry_trampoline_count: how many function entries are immediately followed
  by an unconditional jump to a relocated body (the +mir:split signature).
- fake_prologue_count: how many guarded frame-looking byte sequences survive
  (the +mir:fakeprologue signature).

The metric is generated from symbol-bearing .obj files (not stripped PEs) so
function boundaries are known exactly. It distinguishes intended MIR boundary
fragmentation (split trampolines, fake prologues present) from baseline noise
(plain build has zero of each) and from correctness failures (plain and
fragmented builds must produce identical stdout).
"""
from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
OBJDUMP = tp.tool("llvm-objdump")
VSDEVCMD = tp.VSDEVCMD

FAKE_PROLOGUE = bytes.fromhex(
    "9c 50 8a 04 24 34 6b 34 6b 3a 04 24 74 0f 55 48 89 e5 48 83 ec 20 c9 c3 55 48 89 e5 5d 58 9d"
)

SOURCE = r'''
#include <cstdint>
#include <cstdio>
#define NOINLINE __attribute__((noinline))
#define OPTNONE __attribute__((optnone))
extern "C" {
NOINLINE OPTNONE uint32_t fa(uint32_t x) { return x * 7u + 1; }
NOINLINE OPTNONE uint32_t fb(uint32_t x) { return x ^ 0x55u; }
NOINLINE OPTNONE uint32_t fc(uint32_t x) { return x + (x << 3); }
NOINLINE OPTNONE uint32_t fd(uint32_t x) { return x | 0x80u; }
}
int main() {
  std::printf("frag:%u:%u:%u:%u\n", fa(1), fb(2), fc(3), fd(4));
  return 0;
}
'''

SPLIT_TRAMPOLINE_RE = re.compile(
    r"<(fa|fb|fc|fd|main)>:\n"
    r"\s+[0-9a-f]+:\s+(?:[0-9a-f]{2}\s+)+\s*(pushfq|9c)\s*\n"
    r"\s+[0-9a-f]+:\s+(?:[0-9a-f]{2}\s+)+\s*(popfq|9d)\s*\n"
    r"\s+[0-9a-f]+:\s+(?:[0-9a-f]{2}\s+)+\s*(?:jmp|jmpq)\s",
    re.IGNORECASE,
)


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


def compile_obj(src: Path, out: Path, *mir_args: str) -> Path:
    cmd = [str(CLANG), str(src), "-std=c++17", "-O1", "-c",
           "-mllvm", "-verify-machineinstrs", *mir_args, "-o", str(out)]
    must(run_vs(cmd, src.parent), out.name)
    return out


def count_split_trampolines(disasm: str) -> int:
    return len(SPLIT_TRAMPOLINE_RE.findall(disasm))


def count_fake_prologues(obj: Path) -> int:
    data = obj.read_bytes()
    count = 0
    idx = 0
    while True:
        idx = data.find(FAKE_PROLOGUE, idx)
        if idx < 0:
            break
        count += 1
        idx += 1
    return count


def run_checks(tmp: Path) -> int:
    src = tmp / "frag.cpp"
    src.write_text(SOURCE, encoding="utf-8")

    plain_obj = compile_obj(src, tmp / "plain.obj")
    split_obj = compile_obj(src, tmp / "split.obj",
                            "-mllvm", "-taokari-mir=split")
    fake_obj = compile_obj(src, tmp / "fake.obj",
                           "-mllvm", "-taokari-mir=fakeprologue")

    plain_disasm = run([str(OBJDUMP), "-d", str(plain_obj)])
    split_disasm = run([str(OBJDUMP), "-d", str(split_obj)])
    must(plain_disasm, "objdump plain")
    must(split_disasm, "objdump split")

    plain_tramp = count_split_trampolines(plain_disasm.stdout)
    split_tramp = count_split_trampolines(split_disasm.stdout)
    plain_fake = count_fake_prologues(plain_obj)
    split_fake = count_fake_prologues(split_obj)
    fake_fake = count_fake_prologues(fake_obj)

    if split_tramp <= plain_tramp:
        raise SystemExit(
            f"boundary metric too weak: trampolines plain={plain_tramp} "
            f"split={split_tramp}")
    if plain_fake != 0:
        raise SystemExit(f"plain build leaked fake prologues: {plain_fake}")
    if fake_fake <= split_fake:
        raise SystemExit(
            f"fakeprologue metric too weak: fake={fake_fake} split={split_fake}")

    plain_exe = tmp / "plain.exe"
    split_exe = tmp / "split.exe"
    must(run_vs([str(CLANG), str(src), "-std=c++17", "-O1", "-o", str(plain_exe)],
                src.parent), "plain exe")
    must(run_vs([str(CLANG), str(src), "-std=c++17", "-O1", "-mllvm",
                 "-verify-machineinstrs", "-mllvm", "-taokari-mir=split,fakeprologue",
                 "-o", str(split_exe)], src.parent), "split exe")
    plain_out = run([str(plain_exe)])
    split_out = run([str(split_exe)])
    must(plain_out, "plain run")
    must(split_out, "split run")
    if plain_out.stdout != split_out.stdout:
        raise SystemExit(f"stdout mismatch: {plain_out.stdout!r} != {split_out.stdout!r}")

    print(
        "verify_machine_obf_l3_boundary_metric: ok "
        f"trampolines={plain_tramp}->{split_tramp} "
        f"fake_prologues={plain_fake}->{fake_fake}"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    for tool in (CLANG, OBJDUMP):
        if not tool.exists():
            print(f"missing tool: {tool}", file=sys.stderr)
            return 2
    tmp = Path(tempfile.mkdtemp(prefix="taokari-mir-boundary-"))
    try:
        return run_checks(tmp)
    finally:
        if args.keep:
            print(f"kept temp dir: {tmp}")
        else:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
