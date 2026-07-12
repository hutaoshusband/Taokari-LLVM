"""Native function-level integrity verifier.

todo.md "Reverse-engineering report follow-up":
  * Add a function-level integrity check prototype first; verify patching
    a protected native block trips the tamper path.
  * Add a verifier that patches one protected native byte and proves
    runtime detects it without memory unsafety.

The NativeIntegrity pass emits a per-function private constant pool
global `__taokari_nativeint_pool_<fn>` of 8 i64 words and an entry-block
hash check that folds every word into a FNV-like hash and compares
against an expected value baked in at build time. Patching any pool
byte trips the check and routes through the tamper path (libc exit).

This verifier:
  1. Compiles a `+nativeint` function and confirms the unmutated binary
     still produces correct output.
  2. Locates the pool global in IR, extracts its byte initializer.
  3. Finds the pool bytes in the linked .exe.
  4. Flips one byte in the linked exe.
  5. Runs the patched exe and requires a non-zero exit (the trap path),
     never an access violation (no memory unsafety).
"""
from __future__ import annotations

import random
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
NATIVE_INTEGRITY_SOURCE = (
    ROOT / "upstream" / "taokari" / "llvm" / "lib" / "Transforms" /
    "Obfuscation" / "NativeIntegrity.cpp"
)
VSDEVCMD = tp.VSDEVCMD

SOURCE = r"""
#include <cstdio>

__attribute__((noinline))
__attribute__((annotate("+nativeint")))
static int secret(int a, int b) { return a + b; }

int main() {
  std::printf("nativeint:%d\n", secret(7, 11));
  return 0;
}
"""

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


def extract_pool_bytes(ir_text: str) -> bytes | None:
  m = re.search(
      r'@"?__taokari_nativeint_pool_[^"]+"?\s*=\s*private unnamed_addr '
      r'constant\s*\[\d+\s*x\s*i64\]\s*\[([^\]]+)\]',
      ir_text)
  if not m:
    return None
  words: list[int] = []
  for tok in m.group(1).split(","):
    tok = tok.strip()
    if not tok.startswith("i64"):
      continue
    lit = tok[3:].strip()
    try:
      words.append(int(lit, 0) & 0xFFFFFFFFFFFFFFFF)
    except ValueError:
      return None
  if not words:
    return None
  return struct.pack("<" + "Q" * len(words), *words)


def main() -> int:
  if not CLANG.exists():
    print(f"missing clang: {CLANG}", file=sys.stderr)
    return 2
  source_text = NATIVE_INTEGRITY_SOURCE.read_text(encoding="utf-8",
                                                  errors="ignore")
  fixed_literals = ["0xCBF29CE484222325", "0x9E3779B97F4A7C15",
                    "0x100000001B3"]
  present = [literal for literal in fixed_literals if literal in source_text]
  if present:
    print(f"nativeint verifier: FAIL fixed hash literals remain {present}",
          file=sys.stderr)
    return 1
  for needle in ("HashOffset = nextNonZeroKey()",
                 "HashStep = nextOddKey()",
                 "HashPrime = nextOddKey()"):
    if needle not in source_text:
      print(f"nativeint verifier: FAIL missing {needle}", file=sys.stderr)
      return 1

  tmp = Path(tempfile.mkdtemp(prefix="taokari-ni-"))
  try:
    src = tmp / "ni.cpp"
    src.write_text(SOURCE, encoding="utf-8")
    ll = tmp / "ni.ll"
    exe = tmp / "ni.exe"
    flags = [str(src), "-O2", "-fno-discard-value-names",
             "-mllvm", "-taokari"]

    # Emit IR once. The same IR is then compiled to the .exe, so both
    # share the same per-build pool initializer (the pass consumes RNG
    # draws at IR emission time, not at codegen).
    must(run_vs([str(CLANG), *flags, "-S", "-emit-llvm", "-o", str(ll)],
                src.parent),
         "emit IR")
    ir_text = ll.read_text(encoding="utf-8", errors="ignore")
    pool = extract_pool_bytes(ir_text)
    gate(pool is not None and len(pool) >= 16,
         "nativeint pool initializer extracted from IR")

    # Build the .exe from the emitted IR (not from the source) so the
    # pool bytes match exactly. The nativeint pass has already run when
    # the IR was emitted, so this is just lowering + linking.
    must(run_vs([str(CLANG), str(ll), "-o", str(exe)], src.parent),
         "build exe from IR")
    base_run = run([str(exe)])
    must(base_run, "base run")
    gate(base_run.stdout == "nativeint:18\n",
         "unmutated binary produces correct output")

    exe_bytes = bytearray(exe.read_bytes())
    pool_off = exe_bytes.find(pool)
    gate(pool_off != -1,
         "nativeint pool bytes located in the linked .exe")

    # Patch one byte of the pool and rerun.
    rng = random.Random(0xC0DEFEED)
    patched = bytearray(exe_bytes)
    byte_idx = rng.randrange(len(pool))
    patched[pool_off + byte_idx] ^= (1 << rng.randrange(8))
    patched_exe = tmp / "ni_patched.exe"
    patched_exe.write_bytes(bytes(patched))
    if not tp.IS_WINDOWS:
      patched_exe.chmod(0o755)
    try:
      pat_run = run([str(patched_exe)], timeout=10)
    except subprocess.TimeoutExpired:
      raise SystemExit(
          "FAIL: patched binary hung — tamper path livelocked")
    gate(pat_run.returncode != 0,
         f"patched pool byte trips the integrity check "
         f"(rc={pat_run.returncode})")
    gate(pat_run.returncode != ACCESS_VIOLATION,
         "tamper path exits without memory unsafety "
         "(no access violation)")
    # Output must NOT match the unmutated output (wrong result OR no
    # output at all because of the trap path).
    correct = pat_run.stdout == "nativeint:18\n"
    gate(not correct,
         f"patched binary does not produce correct output "
         f"(got {pat_run.stdout!r})")

    print("native function-level integrity verifier: ok")
    return 0
  finally:
    shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
  raise SystemExit(main())
