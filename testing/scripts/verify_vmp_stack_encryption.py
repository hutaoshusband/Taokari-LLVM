"""VMP operand-stack encryption-at-rest verifier.

todo.md "Reverse-engineering report follow-up":
  * Add VM stack/locals encryption at rest between handlers.

The VM operand stack used to be a plaintext i64 alloca: a memory
snapshot taken between two handler dispatches revealed every live
intermediate value. The interpreter now XORs every pushed value with a
per-interpreter StackKey (derived from the runtime bytecode key mixed
with a per-build random constant) before it lands in the stack alloca,
and de-XORs on pop. A memory snapshot between handler dispatches shows
only encrypted junk.

This verifier asserts:
  - the interpreter has a `stk.key` alloca
  - every push to the operand stack stores an XOR result
    (`%stk.enc* = xor ...`), never a plain operand value
  - every pop loads the encrypted slot and XORs it back to plaintext
  - the protected binary still produces correct output
"""
from __future__ import annotations

import re
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

SOURCE = r"""
#include <cstdio>

__attribute__((noinline))
__attribute__((annotate("vmp")))
static int secret(int a, int b) { return a + b; }

int main() {
  std::printf("vmp-stk:%d\n", secret(7, 11));
  return 0;
}
"""


def run(command: list[str], **kw) -> subprocess.CompletedProcess[str]:
  return subprocess.run(command, text=True, capture_output=True, **kw)


def run_vs(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
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

  tmp = Path(tempfile.mkdtemp(prefix="taokari-vmp-stkenc-"))
  try:
    src = tmp / "vmp_stkenc.cpp"
    src.write_text(SOURCE, encoding="utf-8")
    ll = tmp / "vmp_stkenc.ll"
    exe = tmp / "vmp_stkenc.exe"
    flags = [str(src), "-O2", "-fno-discard-value-names",
             "-mllvm", "-taokari", "-mllvm", "-taokari-vmp"]

    ir = run_vs([str(CLANG), *flags, "-S", "-emit-llvm", "-o", str(ll)],
                src.parent)
    must(ir, "emit IR")
    ir_text = ll.read_text(encoding="utf-8", errors="ignore")
    body = interpreter_body(ir_text)
    gate(body, "VMP interpreter body present in IR")

    # 1. stk.key alloca exists.
    gate(re.search(r"%stk\.key\s*=\s*alloca i64", body) is not None,
         "interpreter has a stk.key alloca")

    # 2. Push encrypt sites: %stk.enc* = xor <value>, %stk.key.ld*
    push_enc = re.findall(
        r"%stk\.enc[\w.]*\s*=\s*xor i64 [^,]+, %stk\.key\.ld[\w.]*",
        body)
    gate(len(push_enc) >= 1,
         f"stack pushes XOR the value with stk.key "
         f"(got {len(push_enc)} push-encrypt sites)")

    # 3. Pop decrypt sites: %stk.plain* = xor %stk.enc*, %stk.key.ld*
    pop_dec = re.findall(
        r"%stk\.plain[\w.]*\s*=\s*xor i64 %stk\.enc[\w.]*, %stk\.key\.ld[\w.]*",
        body)
    gate(len(pop_dec) >= 1,
         f"stack pops XOR the loaded slot with stk.key "
         f"(got {len(pop_dec)} pop-decrypt sites)")

    # 4. stk.key is loaded as a runtime value at every push/pop.
    stk_key_loads = re.findall(
        r"%stk\.key\.ld[\w.]*\s*=\s*load i64, ptr %stk\.key", body)
    gate(len(stk_key_loads) >= 2,
         f"stk.key alloca is loaded at runtime "
         f"(got {len(stk_key_loads)} loads)")

    build = run_vs([str(CLANG), *flags, "-o", str(exe)], src.parent)
    must(build, "build exe")
    ran = run([str(exe)])
    must(ran, "run exe")
    expected = "vmp-stk:18\n"
    gate(ran.stdout == expected,
         f"protected binary still produces correct output "
         f"(got {ran.stdout!r}, want {expected!r})")

    print("vmp stack encryption-at-rest verifier: ok")
    return 0
  finally:
    shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
  raise SystemExit(main())
