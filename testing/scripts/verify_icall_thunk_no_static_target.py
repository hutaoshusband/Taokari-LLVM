"""IndirectCall thunk static-target verifier.

todo.md "Reverse-engineering report follow-up":
  * Harden IndirectCall thunks that still collapse to trivial `jmp target`
    patterns in native output.
  * Add verifier that protected indirect-call thunks do not expose direct
    static jump targets.

The Level-3 shard shape (IndirectCall.cpp `getOrCreateCallShard`) used to
contain a direct `call @real_callee` inside the shard's "real" branch. After
codegen this is a `call rel32` to a known target, so an analyst recovers the
real call graph by reading the shard body. The shard was a thin wrapper with
a visible static edge.

This verifier asserts the shard body has NO direct call to the real callee.
Every shard-internal call edge must be indirect (called operand is a load or
an arithmetic expression on a loaded value), so the static disassembler
cannot resolve the target without executing the decryption.
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
__attribute__((noinline)) static int callee_a(int x) { return x * 3 + 1; }
__attribute__((noinline)) static int callee_b(int x) { return x - 7; }

__attribute__((noinline)) int entry(int x) {
  int a = callee_a(x);
  int b = callee_a(x + 1);
  return callee_b(a + b);
}

int main(void) { return entry(9) == 52 ? 0 : 1; }
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


def shard_bodies(ir: str) -> list[str]:
  return re.findall(
      r'define[^{]*?@__taokari_icall_shard_[^\s(]+[^{]*\{[\s\S]*?\n\}', ir)


def real_callee_names(ir: str) -> list[str]:
  """Internal noinline callees that should be hidden behind shards.

  Matches mangled (``?callee_a@@YAHH@Z`` MSVC-style) and plain (``callee_a``)
  names. Returns names without the leading ``@``.
  """
  found: set[str] = set()
  for m in re.finditer(r'@("?(\?callee_[a-z]|callee_[a-z])[A-Za-z0-9_@?]*)', ir):
    found.add(m.group(1))
  return list(found)


def shard_exposes_real_callee(shard_body: str, real_names: list[str]) -> bool:
  """A shard body "exposes" a real callee if it contains a direct call to it.

  Direct = the called operand is the bare @name (a Function), not a load or
  arithmetic expression. Indirect calls have shapes like `call ... %ptr` or
  `call ... %5` where the operand is a value, not a global function name.
  """
  for name in real_names:
    # match "call ... @name(...)" with name being a direct function reference
    if re.search(rf'\bcall\b[^@]*@{re.escape(name)}\b', shard_body):
      return True
  return False


def main() -> int:
  if not CLANG.exists():
    print(f"missing clang: {CLANG}", file=sys.stderr)
    return 2

  tmp = Path(tempfile.mkdtemp(prefix="taokari-icall-thunk-"))
  try:
    src = tmp / "icall_thunk.c"
    src.write_text(SOURCE, encoding="utf-8")
    ll = tmp / "icall_thunk.ll"
    exe = tmp / "icall_thunk.exe"
    flags = [str(src), "-O2", "-fno-discard-value-names",
             "-mllvm", "-taokari", "-mllvm", "-taokari-icall",
             "-mllvm", "-taokari-level-icall=3",
             "-mllvm", "-taokari-icall-prob=100",
             "-mllvm", "-taokari-icall-func-prob=100"]

    ir = run_vs([str(CLANG), *flags, "-S", "-emit-llvm", "-o", str(ll)],
                src.parent)
    must(ir, "emit IR")
    ir_text = ll.read_text(encoding="utf-8", errors="ignore")

    bodies = shard_bodies(ir_text)
    gate(len(bodies) >= 2, "Level-3 emits >=2 call shards (callee_a, callee_b)")

    real_names = real_callee_names(ir_text)
    gate(bool(real_names), "real callee names located in IR")

    leaking = [b for b in bodies if shard_exposes_real_callee(b, real_names)]
    gate(not leaking,
         "shards contain no direct call to the real callee (static edge hidden)")

    build = run_vs([str(CLANG), *flags, "-o", str(exe)], src.parent)
    must(build, "build exe")
    ran = run([str(exe)])
    must(ran, "run exe")
    gate(ran.returncode == 0,
         f"protected binary still passes semantics (rc={ran.returncode})")

    print("indirect call thunk static-target verifier: ok")
    return 0
  finally:
    shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
  raise SystemExit(main())
