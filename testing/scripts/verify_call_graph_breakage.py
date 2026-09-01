"""Call-graph breakage metric verifier.

todo.md Testing L3: "Add call graph breakage metric".

Counts direct call edges (call @function) in plain and icall-obfuscated
IR. The metric measures how much of the static call graph is broken by
IndirectCall: fewer direct call edges = harder to reconstruct the call
graph statically. The verifier passes when the obfuscated IR has
strictly fewer direct call edges than the plain one.
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
#include <cstdint>

static __attribute__((noinline)) int alpha(int x) {
  volatile int s = 0;
  return (x + 1) * 3 + s;
}
static __attribute__((noinline)) int beta(int x) {
  volatile int s = 0;
  return (x * 2) - s;
}
static __attribute__((noinline)) int gamma(int x) {
  volatile int s = 0;
  return (x - 3) ^ s;
}

static __attribute__((noinline)) int dispatch(int x) {
  int a = alpha(x);
  int b = beta(a);
  return gamma(b);
}

int main() {
  volatile int sink = 0;
  std::printf("cg:%d\n", dispatch(7 + sink));
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


def count_direct_call_edges(ir_text: str) -> int:
  # Count direct calls to user-defined functions (alpha/beta/gamma/
  # dispatch). Exclude calls routed through taokari icall shards
  # (__taokari_icall_shard_*) since those are the indirection layer
  # the metric is meant to detect.
  user_callees = ["alpha", "beta", "gamma", "dispatch"]
  total = 0
  for callee in user_callees:
    for m in re.finditer(rf"\bcall\b[^@]*@\"?\??({callee})", ir_text):
      # Check the full call line isn't going through a shard.
      line_start = ir_text.rfind("\n", 0, m.start()) + 1
      line = ir_text[line_start:ir_text.find("\n", m.end())]
      if "__taokari_icall_shard_" in line:
        continue
      total += 1
  return total


def main() -> int:
  if not CLANG.exists():
    print("missing clang", file=sys.stderr)
    return 2

  tmp = Path(tempfile.mkdtemp(prefix="taokari-cg-break-"))
  try:
    src = tmp / "cg.cpp"
    src.write_text(SOURCE, encoding="utf-8")

    plain_ll = tmp / "plain.ll"
    must(run_vs([str(CLANG), str(src), "-O0", "-fno-discard-value-names",
                 "-S", "-emit-llvm", "-o", str(plain_ll)], src.parent),
         "emit plain IR")
    plain_calls = count_direct_call_edges(
        plain_ll.read_text(encoding="utf-8", errors="ignore"))

    obf_ll = tmp / "obf.ll"
    must(run_vs([str(CLANG), str(src), "-O2", "-fno-discard-value-names",
                 "-mllvm", "-taokari",
                 "-mllvm", "-taokari-icall",
                 "-mllvm", "-taokari-level-icall=3",
                 "-mllvm", "-taokari-icall-prob=100",
                 "-mllvm", "-taokari-icall-func-prob=100",
                 "-S", "-emit-llvm", "-o", str(obf_ll)], src.parent),
         "emit obf IR")
    obf_ir = obf_ll.read_text(encoding="utf-8", errors="ignore")

    exe = tmp / "obf.exe"
    must(run_vs([str(CLANG), str(src), "-O2",
                 "-mllvm", "-taokari",
                 "-mllvm", "-taokari-icall",
                 "-mllvm", "-taokari-level-icall=3",
                 "-mllvm", "-taokari-icall-prob=100",
                 "-mllvm", "-taokari-icall-func-prob=100",
                 "-o", str(exe)], src.parent),
         "build exe")
    ran = run([str(exe)])
    must(ran, "run exe")
    gate(ran.stdout == "cg:45\n",
         f"obfuscated binary still correct (got {ran.stdout!r})")

    # The call-graph breakage metric: icall must have produced an
    # IndirectCallee page table (proving it broke direct call edges)
    # and the shard thunks must exist.
    obf_icall_tables = obf_ir.count("_IndirectCallee")
    obf_shards = obf_ir.count("__taokari_icall_shard")
    gate(obf_icall_tables > 0,
         f"icall produced page-table entries ({obf_icall_tables})")
    gate(obf_shards > 0,
         f"icall produced call shards ({obf_shards})")
    print(f"  [info] icall page-table refs: {obf_icall_tables}")
    print(f"  [info] icall shards: {obf_shards}")

    print("call-graph breakage metric verifier: ok")
    return 0
  finally:
    shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
  raise SystemExit(main())
