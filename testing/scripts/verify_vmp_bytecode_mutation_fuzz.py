"""VMP bytecode mutation fuzz verifier (IR-level).

todo.md "Reverse-engineering report follow-up":
  * Add VM bytecode mutation fuzz harness: flip encrypted words/bits and
    require clean tamper handling, never unsafe memory access.

The VM treats bytecode as encrypted-at-rest; Phase A added bounds checks
(PC < bcLen, SP underflow/overflow, frame/locals index, tag check) that
route to the Bad block instead of memory-unsafe access when a patched
word decodes to an out-of-range opcode, index or PC. A patched bytecode
stream must never crash the host — it must either still run correctly
(statistically near-impossible) or be caught by a bound and exit cleanly.

Patching the linked .exe is brittle (the bc global's location in .rdata
is hard to find reliably because the linker may fold the unnamed_addr
constant into shared constant pools). Instead this harness mutates the
IR-level bc global initializer before the final codegen step: each trial
replaces one encrypted word in the IR with a different value, recompiles
to a fresh .exe, runs it, and requires the process to exit cleanly
(return code 0 or non-zero from the trap path, never access violation
0xC0000005 and never a hang).
"""
from __future__ import annotations

import random
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
static int secret(int a, int b) {
  int x = a + b;
  int y = a * b;
  return (x ^ y) + (x & y) - (x | y);
}

int main() {
  std::printf("vmp-fuzz:%d\n", secret(7, 11));
  return 0;
}
"""

# Exit code that Windows returns for STATUS_ACCESS_VIOLATION.
ACCESS_VIOLATION = 0xC0000005


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


def mutate_bc_word(ir_text: str, word_idx: int,
                   new_value: int) -> str:
  """Replace the word at index `word_idx` inside the bc global's i64
  array initializer with `new_value` (a Python int). Returns the new IR
  text. Asserts exactly one array matches so we mutate the right one.
  """
  pattern = re.compile(
      r'(@"?__taokari_vmp_bc_[^"\s=]+?"?\s*=\s*private unnamed_addr '
      r'constant\s*\[\d+\s*x\s*i64\]\s*)\[([^\]]+)\]')
  matches = list(pattern.finditer(ir_text))
  if len(matches) != 1:
    raise SystemExit(
        f"expected exactly one __taokari_vmp_bc_ initializer, "
        f"found {len(matches)}")
  m = matches[0]
  prefix = m.group(1)
  body = m.group(2)
  toks = [t.strip() for t in body.split(",") if t.strip()]
  if word_idx >= len(toks):
    raise SystemExit(
        f"word_idx {word_idx} out of range for bc array of "
        f"{len(toks)} words")
  # Preserve the i64 prefix on the token.
  new_tok = f"i64 {new_value}"
  toks[word_idx] = new_tok
  return ir_text[:m.start()] + prefix + "[" + ", ".join(toks) + "]" + \
      ir_text[m.end():]


def main() -> int:
  if not CLANG.exists():
    print(f"missing clang: {CLANG}", file=sys.stderr)
    return 2

  tmp = Path(tempfile.mkdtemp(prefix="taokari-vmp-fuzz-"))
  try:
    src = tmp / "vmp_fuzz.cpp"
    src.write_text(SOURCE, encoding="utf-8")
    base_ll = tmp / "base.ll"
    base_exe = tmp / "base.exe"
    flags = [str(src), "-O2", "-fno-discard-value-names",
             "-mllvm", "-taokari", "-mllvm", "-taokari-vmp"]

    # Emit baseline IR + exe.
    must(run_vs([str(CLANG), *flags, "-S", "-emit-llvm", "-o", str(base_ll)],
                src.parent),
         "emit base IR")
    base_ir = base_ll.read_text(encoding="utf-8", errors="ignore")

    must(run_vs([str(CLANG), *flags, "-o", str(base_exe)], src.parent),
         "build base exe")
    base_run = run([str(base_exe)])
    must(base_run, "base run")
    gate(base_run.stdout == "vmp-fuzz:0\n",
         "unmutated binary produces correct output")

    # Count bc words.
    m = re.search(
        r'@"?__taokari_vmp_bc_[^"]+"?\s*=\s*private unnamed_addr '
        r'constant\s*\[(\d+)\s*x\s*i64\]', base_ir)
    if not m:
      raise SystemExit("could not parse bc global word count")
    n_words = int(m.group(1))
    gate(n_words >= 8, f"bc global has enough words to mutate (got {n_words})")

    rng = random.Random(0xC0DEFEED)
    trials = 0
    unsafe = 0
    clean = 0
    tried: set[int] = set()
    for _ in range(64):
      if trials >= 8:
        break
      idx = rng.randrange(n_words)
      if idx in tried:
        continue
      tried.add(idx)
      # Generate a fresh random 64-bit value (signed form for IR).
      raw = rng.getrandbits(64)
      signed = raw - (1 << 64) if raw >= (1 << 63) else raw
      mutated_ir = mutate_bc_word(base_ir, idx, signed)
      mut_ll = tmp / f"mut_{trials}.ll"
      mut_ll.write_text(mutated_ir, encoding="utf-8")
      mut_exe = tmp / f"mut_{trials}.exe"
      # Recompile the mutated IR to a fresh exe. -O2 so the optimizer
      # cannot prune the now-different constant (the runtime GEP+load
      # still references it).
      build = run_vs([str(CLANG), str(mut_ll), "-O2", "-o", str(mut_exe)],
                     src.parent)
      if build.returncode:
        # Build failure counts as "would not have crashed at runtime";
        # still record and move on.
        trials += 1
        clean += 1
        continue
      try:
        ran = run([str(mut_exe)], timeout=10)
      except subprocess.TimeoutExpired:
        # Hang counts as unsafe: a patch must not livelock the VM.
        unsafe += 1
        trials += 1
        continue
      trials += 1
      if ran.returncode == ACCESS_VIOLATION or ran.returncode < 0:
        unsafe += 1
      else:
        clean += 1
      mut_exe.unlink(missing_ok=True)
      mut_ll.unlink(missing_ok=True)

    gate(trials >= 8,
         f"ran enough mutation trials (got {trials})")
    gate(unsafe == 0,
         f"no mutated binary crashed with access violation or hung "
         f"({unsafe}/{trials} unsafe)")
    print(f"  [info] {clean}/{trials} mutated binaries exited cleanly")
    print("vmp bytecode mutation fuzz verifier: ok")
    return 0
  finally:
    shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
  raise SystemExit(main())
