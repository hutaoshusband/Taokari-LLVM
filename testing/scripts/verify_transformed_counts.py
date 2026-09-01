"""Per-pass transformed-count verifier.

todo.md Testing L2 items:
  * Record number of transformed functions
  * Record number of transformed instructions
  * Record number of obfuscated strings
  * Record number of obfuscated constants

Compiles a fixture with all passes on, emits LLVM IR, and counts
per-pass structural markers as the "number of transformed X" metric:
  * obfuscated strings: EncryptedStringTable globals
  * icall transforms: _IndirectCallee page-table globals
  * indbr transforms: _IndirectBr page-table globals
  * indgv transforms: _IndirectGVs page-table globals
  * mba transforms: mba.* instruction-name markers
  * fla transforms: switchDispatch block labels
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

static const char *kSecret = "taokari-count-secret-string";
static const int64_t kMagic = 0x1234567890ABCDEFLL;

__attribute__((noinline)) int compute(int a, int b) {
  int x = a + b;
  int y = a * b;
  int z = (x ^ y) + (x & y) - (x | y);
  if (z > 100) return z - 1;
  return z;
}

int g_state = 7;
int main() {
  volatile int sink = 0;
  int r = compute(7 + sink, 11);
  g_state += r;
  std::printf("counts:%d:%d:%s:%lld\n", r, g_state, kSecret,
              static_cast<long long>(kMagic));
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
    print("missing clang", file=sys.stderr)
    return 2

  tmp = Path(tempfile.mkdtemp(prefix="taokari-counts-"))
  try:
    src = tmp / "counts.cpp"
    src.write_text(SOURCE, encoding="utf-8")
    ll = tmp / "counts.ll"
    exe = tmp / "counts.exe"
    flags = [str(src), "-O2", "-fno-discard-value-names",
             "-mllvm", "-taokari",
             "-mllvm", "-taokari-indbr",
             "-mllvm", "-taokari-icall",
             "-mllvm", "-taokari-indgv",
             "-mllvm", "-taokari-fla",
             "-mllvm", "-taokari-bcf",
             "-mllvm", "-taokari-mba",
             "-mllvm", "-taokari-cse",
             "-mllvm", "-taokari-cie",
             "-mllvm", "-taokari-cfe"]

    # Emit IR.
    must(run_vs([str(CLANG), *flags, "-S", "-emit-llvm", "-o", str(ll)],
                src.parent),
         "emit IR")
    ir = ll.read_text(encoding="utf-8", errors="ignore")

    # Sanity: binary still runs.
    must(run_vs([str(CLANG), *flags, "-o", str(exe)], src.parent),
         "build exe")
    ran = run([str(exe)])
    must(ran, "run exe")

    # Count per-pass structural markers.
    counts: dict[str, int] = {
        "obfuscated_strings":
            len(re.findall(r"@.*EncryptedStringTable", ir)),
        "icall_transforms":
            ir.count("_IndirectCallee"),
        "indbr_transforms":
            ir.count("_IndirectBr"),
        "indgv_transforms":
            ir.count("_IndirectGVs"),
        "mba_transforms":
            len(re.findall(r"\.mba\.", ir)),
        "fla_transforms":
            ir.count("switchDispatch"),
        "bcf_transforms":
            ir.count("bcf.guard"),
    }
    active = {k: v for k, v in counts.items() if v > 0}
    gate(len(active) >= 3,
         f"at least 3 passes produced structural transforms "
         f"(got {len(active)}: {active})")
    print(f"  [info] per-pass transform counts: {active}")

    print("transformed-count verifier: ok")
    return 0
  finally:
    shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
  raise SystemExit(main())
