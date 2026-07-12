"""CFG complexity metric verifier.

todo.md Testing L3: "Add CFG complexity metric".

Computes a simple CFG complexity metric (number of basic blocks and
edges) for a plain and an obfuscated build of the same fixture, and
reports the ratio. The metric is a proxy for how hard the CFG is to
analyse: more blocks and edges = harder for a static lifter. The
verifier passes when the obfuscated CFG is materially more complex
than the plain one.
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

__attribute__((noinline)) int compute(int a, int b) {
  int x = a + b;
  int y = a * b;
  int z = (x ^ y) + (x & y) - (x | y);
  if (z > 100) return z - 1;
  if (z < -100) return z + 1;
  return z;
}

int main() {
  volatile int sink = 0;
  std::printf("cfg:%d\n", compute(7 + sink, 11));
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


def cfg_metrics(ir_text: str) -> tuple[int, int]:
  blocks = len(re.findall(r"^\w[^\n]*:\s*(?:;.*)?$", ir_text, re.M))
  edges = len(re.findall(r"\bbr\s+", ir_text)) + len(re.findall(r"\bswitch\s+", ir_text))
  return blocks, edges


def main() -> int:
  if not CLANG.exists():
    print("missing clang", file=sys.stderr)
    return 2

  tmp = Path(tempfile.mkdtemp(prefix="taokari-cfg-metric-"))
  try:
    src = tmp / "cfg.cpp"
    src.write_text(SOURCE, encoding="utf-8")

    plain_ll = tmp / "plain.ll"
    must(run_vs([str(CLANG), str(src), "-O0", "-fno-discard-value-names",
                 "-S", "-emit-llvm", "-o", str(plain_ll)], src.parent),
         "emit plain IR")
    plain_blocks, plain_edges = cfg_metrics(
        plain_ll.read_text(encoding="utf-8", errors="ignore"))

    obf_ll = tmp / "obf.ll"
    must(run_vs([str(CLANG), str(src), "-O0", "-fno-discard-value-names",
                 "-mllvm", "-taokari",
                 "-mllvm", "-taokari-fla",
                 "-mllvm", "-taokari-level-fla=3",
                 "-mllvm", "-taokari-bcf",
                 "-mllvm", "-taokari-level-bcf=3",
                 "-mllvm", "-taokari-bcf-prob=100",
                 "-S", "-emit-llvm", "-o", str(obf_ll)], src.parent),
         "emit obf IR")
    obf_blocks, obf_edges = cfg_metrics(
        obf_ll.read_text(encoding="utf-8", errors="ignore"))

    exe = tmp / "obf.exe"
    must(run_vs([str(CLANG), str(src), "-O0",
                 "-mllvm", "-taokari",
                 "-mllvm", "-taokari-fla",
                 "-mllvm", "-taokari-level-fla=3",
                 "-mllvm", "-taokari-bcf",
                 "-mllvm", "-taokari-level-bcf=3",
                 "-mllvm", "-taokari-bcf-prob=100",
                 "-o", str(exe)], src.parent),
         "build exe")
    ran = run([str(exe)])
    must(ran, "run exe")
    gate(ran.stdout == "cfg:0\n",
         f"obfuscated binary still correct (got {ran.stdout!r})")

    print(f"  [info] plain: {plain_blocks} blocks, {plain_edges} edges")
    print(f"  [info] obf:   {obf_blocks} blocks, {obf_edges} edges")
    ratio = obf_blocks / plain_blocks if plain_blocks else 0.0
    gate(obf_blocks > plain_blocks,
         f"obfuscated CFG is more complex ({ratio:.2f}x blocks)")

    print("CFG complexity metric verifier: ok")
    return 0
  finally:
    shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
  raise SystemExit(main())
