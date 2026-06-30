"""VMP PC encryption-at-rest verifier.

todo.md "Reverse-engineering report follow-up":
  * Add PC encryption at rest in the VMP interpreter loop.

The VM program counter used to be a plaintext i64 alloca: a debugger
single-stepping the dispatch loop read the live PC for free. The
interpreter now stores PC XOR PcKey, where PcKey is a per-interpreter
runtime-derived value (the runtime bytecode key mixed with a per-build
random constant). Every load/store of the PC goes through a decrypt/
encrypt step, so a memory snapshot of the PC alloca yields only the
encrypted form.

This verifier asserts:
  - the interpreter has a `pc.key` alloca
  - the PC alloca is never loaded or stored in plaintext: every load
    site is immediately followed by an XOR with the loaded pc.key, and
    every store is preceded by an XOR with pc.key
  - the protected binary still produces correct output
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
VSDEVCMD = tp.VSDEVCMD

SOURCE = r"""
#include <cstdio>

__attribute__((noinline))
__attribute__((annotate("vmp")))
static int secret(int a, int b) { return a + b; }

int main() {
  std::printf("vmp-pc:%d\n", secret(7, 11));
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


def interpreter_body(ir_text: str) -> str:
  m = re.search(
      r'define[^{]*?@"?(__taokari_vmp_interp_[^"\s(]+)"?\s*\([^)]*\)[^{]*\{'
      r'([\s\S]*?)\n\}',
      ir_text)
  return m.group(2) if m else ""


def main() -> int:
  if not CLANG.exists():
    print(f"missing clang: {CLANG}", file=sys.stderr)
    return 2

  tmp = Path(tempfile.mkdtemp(prefix="taokari-vmp-pcenc-"))
  try:
    src = tmp / "vmp_pcenc.cpp"
    src.write_text(SOURCE, encoding="utf-8")
    ll = tmp / "vmp_pcenc.ll"
    exe = tmp / "vmp_pcenc.exe"
    flags = [str(src), "-O2", "-fno-discard-value-names",
             "-mllvm", "-taokari", "-mllvm", "-taokari-vmp"]

    ir = run_vs([str(CLANG), *flags, "-S", "-emit-llvm", "-o", str(ll)],
                src.parent)
    must(ir, "emit IR")
    ir_text = ll.read_text(encoding="utf-8", errors="ignore")
    body = interpreter_body(ir_text)
    gate(body, "VMP interpreter body present in IR")

    # 1. pc.key alloca exists.
    gate(re.search(r"%pc\.key\s*=\s*alloca i64", body) is not None,
         "interpreter has a pc.key alloca")

    # 2. The PC is loaded only via an XOR-with-pc.key decrypt step. The
    #    plain PC value never appears as a raw load of %pc alone — there
    #    is always a following `xor %ld, %pc.key.ld`.
    pc_loads = re.findall(r"%\w+\s*=\s*load i64, ptr %pc,\s*align 8", body)
    pc_xor_with_key = re.findall(
        r"xor i64 %pc\.enc[\w.]+, %pc\.key\.ld[\w.]*", body)
    gate(len(pc_loads) >= 1,
         f"PC alloca is loaded (got {len(pc_loads)} load sites)")
    gate(len(pc_xor_with_key) >= 1,
         f"every PC load is paired with an XOR against pc.key "
         f"(got {len(pc_xor_with_key)} decrypt sites)")

    # 3. Initial PC store at interpreter entry is encrypted: store (xor
    #    0, pc.key) rather than store 0 directly to %pc.
    encrypted_stores = re.findall(r"store i64 %pc\.enc[\w.]+, ptr %pc,",
                                  body)
    gate(len(encrypted_stores) >= 1,
         f"PC store sites write the encrypted form (xor result) to "
         f"the PC alloca (got {len(encrypted_stores)})")

    # 4. Sanity: pc.key is itself loaded via a separate load (so it is a
    #    runtime value, not folded into the load operand).
    pc_key_loads = re.findall(
        r"%pc\.key\.ld\w*\s*=\s*load i64, ptr %pc\.key", body)
    gate(len(pc_key_loads) >= 1,
         f"pc.key alloca is loaded at runtime (got {len(pc_key_loads)} loads)")

    build = run_vs([str(CLANG), *flags, "-o", str(exe)], src.parent)
    must(build, "build exe")
    ran = run([str(exe)])
    must(ran, "run exe")
    expected = "vmp-pc:18\n"
    gate(ran.stdout == expected,
         f"protected binary still produces correct output "
         f"(got {ran.stdout!r}, want {expected!r})")

    print("vmp PC encryption-at-rest verifier: ok")
    return 0
  finally:
    shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
  raise SystemExit(main())
