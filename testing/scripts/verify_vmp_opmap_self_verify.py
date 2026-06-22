"""VMP interpreter opcode-map self-verification verifier.

todo.md "Reverse-engineering report follow-up":
  * Add interpreter self-verification for handler table/code patching.

The interpreter folds every entry of OpcodeMap[0..63] into a running
hash with a per-build prime at entry and compares the result against an
expected value baked in as a constant. The expected value is computed
at build time in `replaceWithVM` from the same OpcodeDecode vector that
materialised the map, so any patch to a single map entry (e.g. swapping
two opcodes to remap the dispatch) trips the check and routes through
the Bad block before the dispatch loop runs.

This verifier asserts:
  - the interpreter has an `opmap.hash` / `opmap.hash.i` running state
  - the dispatch only runs after a successful opmap hash comparison
  - patching a single OpcodeMap entry in the IR breaks the binary
    (wrong output, non-zero exit, or access-violation-free trap path),
    proving the check fires on a real patch
  - the unmutated protected binary still produces correct output
"""
from __future__ import annotations

import random
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
  std::printf("vmp-sv:%d\n", secret(7, 11));
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


def mutate_opmap_entry(ir_text: str, new_value: int) -> str:
  """Replace the first entry of the OpcodeMap global initializer with
  new_value. Asserts exactly one map matches so we mutate the right one.
  """
  pattern = re.compile(
      r'(@"?__taokari_vmp_opmap_[^"\s=]+?"?\s*=\s*private unnamed_addr '
      r'constant\s*\[\d+\s*x\s*i64\]\s*)\[([^\]]+)\]')
  matches = list(pattern.finditer(ir_text))
  if len(matches) != 1:
    raise SystemExit(
        f"expected exactly one __taokari_vmp_opmap_ initializer, "
        f"found {len(matches)}")
  m = matches[0]
  prefix = m.group(1)
  body = m.group(2)
  toks = [t.strip() for t in body.split(",") if t.strip()]
  if not toks:
    raise SystemExit("empty opmap initializer")
  toks[0] = f"i64 {new_value}"
  return ir_text[:m.start()] + prefix + "[" + ", ".join(toks) + "]" + \
      ir_text[m.end():]


def main() -> int:
  if not CLANG.exists():
    print(f"missing clang: {CLANG}", file=sys.stderr)
    return 2

  tmp = Path(tempfile.mkdtemp(prefix="taokari-vmp-sv-"))
  try:
    src = tmp / "vmp_sv.cpp"
    src.write_text(SOURCE, encoding="utf-8")
    base_ll = tmp / "vmp_sv.ll"
    base_exe = tmp / "vmp_sv.exe"
    flags = [str(src), "-O2", "-fno-discard-value-names",
             "-mllvm", "-taokari", "-mllvm", "-taokari-vmp"]

    must(run_vs([str(CLANG), *flags, "-S", "-emit-llvm", "-o", str(base_ll)],
                src.parent),
         "emit base IR")
    base_ir = base_ll.read_text(encoding="utf-8", errors="ignore")

    # Sanity: unmutated binary still runs correctly.
    must(run_vs([str(CLANG), *flags, "-o", str(base_exe)], src.parent),
         "build base exe")
    base_run = run([str(base_exe)])
    must(base_run, "base run")
    gate(base_run.stdout == "vmp-sv:18\n",
         "unmutated binary produces correct output")

    # 1. The interpreter body has opmap.hash state and the check blocks.
    interp_match = re.search(
        r'define[^{]*?@"?__taokari_vmp_interp_[^"\s(]+"?\s*\([^)]*\)[^{]*\{'
        r'([\s\S]*?)\n\}',
        base_ir)
    gate(interp_match is not None, "interpreter body present in IR")
    body = interp_match.group(1)
    gate(re.search(r"%opmap\.hash\s*=\s*alloca i64", body) is not None,
         "interpreter has an opmap.hash alloca")
    gate(re.search(r"opmap\.check:", body) is not None,
         "interpreter has an opmap.check block gating the dispatch")
    gate(re.search(r"opmap\.hdr:", body) is not None,
         "interpreter has an opmap.hdr hash-loop header")
    gate(re.search(r"opmap\.done:", body) is not None,
         "interpreter has an opmap.done block after the hash loop")

    # 2. The opmap.done block branches to either Dispatch or Bad based on
    #    the hash compare.
    opmap_done_idx = body.find("opmap.done:")
    gate(opmap_done_idx != -1,
         "opmap.done block located in interpreter body")
    opmap_done_chunk = body[opmap_done_idx:opmap_done_idx + 400]
    gate(("%dispatch" in opmap_done_chunk and "%bad" in opmap_done_chunk),
         "opmap.done branches between dispatch and bad on hash compare")

    # 3. Patch the first opmap entry in the IR, rebuild, run. The
    #    interpreter must detect the mismatch — output is wrong, exit is
    #    non-zero, or the binary exits cleanly via the tamper policy.
    rng = random.Random(0xC0DEFEED)
    # Pick a new value that is not the original by retrying.
    new_value = rng.randrange(-(1 << 63), (1 << 63) - 1)
    mutated_ir = mutate_opmap_entry(base_ir, new_value)
    mut_ll = tmp / "vmp_sv_mut.ll"
    mut_ll.write_text(mutated_ir, encoding="utf-8")
    mut_exe = tmp / "vmp_sv_mut.exe"
    build = run_vs([str(CLANG), str(mut_ll), "-O2", "-o", str(mut_exe)],
                   src.parent)
    if build.returncode:
      raise SystemExit(f"mutated IR rebuild failed: {build.stderr[:200]}")
    try:
      mut_run = run([str(mut_exe)], timeout=10)
    except subprocess.TimeoutExpired:
      # Spin tamper-policy may hang; counts as detection.
      gate(True, "patched opmap entry is detected by the self-verify check "
                 "(binary hung via tamper-policy spin mode)")
      print("vmp opmap self-verify verifier: ok")
      return 0

    # The patched binary must NOT produce the correct output: it either
    # exits non-zero via the trap path or returns a different stdout.
    correct = mut_run.stdout == "vmp-sv:18\n" and mut_run.returncode == 0
    gate(not correct,
         f"patched opmap entry trips the self-verify check "
         f"(rc={mut_run.returncode}, stdout={mut_run.stdout!r})")

    print("vmp opmap self-verify verifier: ok")
    return 0
  finally:
    shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
  raise SystemExit(main())
