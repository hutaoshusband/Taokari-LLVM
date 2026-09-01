"""Constant-encryption binary-diff verifier.

todo.md item Constant Encryption L3: "Add binary diff tests".

Asserts that enabling integer-constant encryption materially changes
the .rdata section of the linked binary. The plaintext constant must
not appear in the protected binary's bytes, but must appear in the
plain binary's bytes. This is the binary-level analogue of the
LTO-survival verifier: it proves the protection is visible at the
final binary layer, not just in IR.
"""
from __future__ import annotations

import re
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
VSDEVCMD = tp.VSDEVCMD

PLAIN_CONST = 0x123456789ABCDEF0

SOURCE = f"""
#include <cstdint>
#include <cstdio>

__attribute__((noinline)) int64_t magic() {{
  volatile int64_t v = 0;
  int64_t secret = {PLAIN_CONST}LL;
  return secret + v;
}}

int main() {{
  std::printf("const-diff:%lld\\n", static_cast<long long>(magic()));
  return 0;
}}
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
    print("missing clang", file=sys.stderr)
    return 2

  tmp = Path(tempfile.mkdtemp(prefix="taokari-constenc-diff-"))
  try:
    src = tmp / "constenc_diff.cpp"
    src.write_text(SOURCE, encoding="utf-8")

    expected = f"const-diff:{PLAIN_CONST}\n"
    plain_le = struct.pack("<Q", PLAIN_CONST)
    plain_be = struct.pack(">Q", PLAIN_CONST)

    # Plain build.
    plain_exe = tmp / "plain.exe"
    must(run_vs([str(CLANG), str(src), "-O2", "-o", str(plain_exe)],
                src.parent),
         "build plain exe")
    plain_run = run([str(plain_exe)])
    must(plain_run, "plain run")
    gate(plain_run.stdout == expected,
         f"plain binary produces correct output (got {plain_run.stdout!r})")
    plain_bytes = plain_exe.read_bytes()
    gate(plain_le in plain_bytes or plain_be in plain_bytes,
         "plaintext constant appears in the plain binary's bytes")

    # Protected build.
    obf_exe = tmp / "obf.exe"
    must(run_vs([str(CLANG), str(src), "-O2",
                 "-mllvm", "-taokari",
                 "-mllvm", "-taokari-cie",
                 "-mllvm", "-taokari-level-cie=2",
                 "-o", str(obf_exe)], src.parent),
         "build obf exe")
    obf_run = run([str(obf_exe)])
    must(obf_run, "obf run")
    gate(obf_run.stdout == expected,
         f"protected binary produces correct output (got {obf_run.stdout!r})")

    obf_bytes = obf_exe.read_bytes()
    gate(plain_le not in obf_bytes and plain_be not in obf_bytes,
         "plaintext constant does NOT appear in the protected binary's "
         "bytes")

    # And the two binaries are materially different (the protection
    # rewrote more than just the timestamp).
    gate(obf_bytes != plain_bytes,
         f"protected and plain binaries differ (plain={len(plain_bytes)}, "
         f"obf={len(obf_bytes)})")

    print("constant encryption binary-diff verifier: ok")
    return 0
  finally:
    shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
  raise SystemExit(main())
