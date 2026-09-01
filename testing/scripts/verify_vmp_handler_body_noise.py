"""VMP handler body obfuscation verifier.

todo.md "Reverse-engineering report follow-up":
  * Add handler body obfuscation for VMP interpreters: apply safe BCF/MBA
    or MIR noise to handler bodies without breaking VM correctness.

Each handler body in a `__taokari_vmp_interp_*` interpreter now carries a
per-handler MBA noise block at its head: it derives two keyed copies of the
VM stack pointer, computes `(sp^k1) + 2*((sp^k1) & (sp^k2))` (the MBA
identity for `a + b`) and stores the result in a private
`__taokari_vmp_handler_noise_*` global. The store is semantically dead from
the program's perspective (the global is private and never read), but it
has a real memory side effect so the optimizer cannot DCE it, and the
arithmetic shape reads as real work to a decompiler.

This verifier asserts:
  - each interpreter has a `__taokari_vmp_handler_noise_*` global
  - the interpreter body contains MBA-shaped arithmetic on the stack
    pointer (xor + and + shl + add chain) feeding such a store
  - the protected binary still produces correct output (semantics
    preserved under the noise)
"""
from __future__ import annotations

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
VSDEVCMD = tp.VSDEVCMD

SOURCE = r"""
#include <cstdio>

__attribute__((noinline))
__attribute__((annotate("vmp")))
static int alpha(int a, int b) {
  int x = a + b;
  return (x ^ a) + (x & b);
}

int main() {
  std::printf("vmp-noise:%d\n", alpha(7, 11));
  return 0;
}
"""


def run(command: list[str], **kw) -> subprocess.CompletedProcess[str]:
  return subprocess.run(command, text=True, capture_output=True, **kw)


def run_vs(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
  if not tp.IS_WINDOWS:
    return subprocess.run(command, cwd=cwd, text=True, capture_output=True)
  with tempfile.NamedTemporaryFile("w", suffix=".cmd", delete=False,
                                   encoding="utf-8") as handle:
    batch = Path(handle.name)
    handle.write(
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


def gate(cond: bool, label: str) -> None:
  if not cond:
    raise SystemExit(f"GATE FAILED: {label}")
  print(f"  [ok] {label}")


def main() -> int:
  if not CLANG.exists():
    print(f"missing clang: {CLANG}", file=sys.stderr)
    return 2

  tmp = Path(tempfile.mkdtemp(prefix="taokari-vmp-noise-"))
  try:
    src = tmp / "vmp_noise.cpp"
    src.write_text(SOURCE, encoding="utf-8")
    ll = tmp / "vmp_noise.ll"
    exe = tmp / "vmp_noise.exe"
    flags = [str(src), "-O2", "-fno-discard-value-names",
             "-mllvm", "-taokari", "-mllvm", "-taokari-vmp"]

    ir = run_vs([str(CLANG), *flags, "-S", "-emit-llvm", "-o", str(ll)],
                src.parent)
    must(ir, "emit IR")
    ir_text = ll.read_text(encoding="utf-8", errors="ignore")

    gate("__taokari_vmp_interp_" in ir_text,
         "at least one VMP interpreter present")
    noise_globals = re.findall(
        r"@\"?(__taokari_vmp_handler_noise_[^\"\s]+)", ir_text)
    gate(len(noise_globals) >= 1,
         f"per-interpreter noise global emitted (got {len(noise_globals)})")

    sp_load = re.findall(r"%h\.sp\w*\s*=\s*load i64", ir_text)
    gate(len(sp_load) >= 1,
         f"handler body loads SP for MBA noise (got {len(sp_load)} loads)")

    xor_a = re.findall(r"%h\.a\w*\s*=\s*xor i64 %h\.sp", ir_text)
    b_seed = re.findall(r"%h\.b\.seed\w*\s*=\s*add i64 %h\.sp", ir_text)
    xor_b = re.findall(r"%h\.b\w*\s*=\s*xor i64 %h\.b\.seed", ir_text)
    gate(len(xor_a) >= 1 and len(b_seed) >= 1 and len(xor_b) >= 1,
         "handler body builds two keyed SP-derived values")

    and_chain = re.findall(r"%h\.and\w*\s*=\s*and i64", ir_text)
    shl_chain = re.findall(r"%h\.shl\w*\s*=\s*shl i64", ir_text)
    sum_chain = re.findall(r"%h\.sum\w*\s*=\s*add i64", ir_text)
    gate(len(and_chain) >= 1 and len(shl_chain) >= 1 and len(sum_chain) >= 1,
         "handler body builds MBA add identity chain (and/shl/add)")

    store_to_noise = re.findall(
        r"store i64 %h\.sum\w*, ptr @\"?__taokari_vmp_handler_noise_", ir_text)
    gate(len(store_to_noise) >= 1,
         "MBA noise value is stored to the private noise global "
         "(cannot be DCE'd)")

    build = run_vs([str(CLANG), *flags, "-o", str(exe)], src.parent)
    must(build, "build exe")
    ran = run([str(exe)])
    must(ran, "run exe")
    expected = "vmp-noise:23\n"
    gate(ran.stdout == expected,
         f"protected binary still produces correct output "
         f"(got {ran.stdout!r}, want {expected!r})")

    print("vmp handler body noise verifier: ok")
    return 0
  finally:
    shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
  raise SystemExit(main())
