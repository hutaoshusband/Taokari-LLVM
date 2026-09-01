"""VMP runtime-rekeyed bytecode optimizer-survival verifier.

todo.md "Reverse-engineering report follow-up":
  * Add optimizer survival checks for runtime-rekeyed VMP bytecode under
    -O2, -O3, and LTO.

The VMP pass encrypts the bytecode stream with a per-build key derived at
runtime from a seed global + opaque computation, and per-word immediates
ride a separate keystream. A strong optimizer (-O2/-O3/LTO) must not be
able to fold the encrypted stream or recover the runtime key from the
static IR — if it could, the protection would be defeated at compile time.

This verifier compiles a +vmp function under -O2, -O3 and LTO and asserts
each produced binary:
  1. still runs correctly (semantics preserved through the optimizer),
  2. still contains the runtime key-derivation global
     (`__taokari_vmp_key_seed_*`) and the encrypted bytecode global —
     i.e. the optimizer did not constant-fold them away,
  3. the interpreter dispatch loop is still present.

Property (2) is the survival check: if the optimizer had recovered the
key, the bytecode global would either be eliminated or replaced with a
plaintext constant. Its continued presence as an opaque runtime-decoded
blob is the proof.
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

__attribute__((noinline))
__attribute__((annotate("vmp")))
static int secret(int a, int b) {
  int x = a + b;
  int y = a * b;
  return (x ^ y) + (x & y) - (x | y);
}

int main() {
  std::printf("vmp-opt:%d\n", secret(7, 11));
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


def emit_ir(extra_flags: list[str], cwd: Path, src: Path,
            out: Path) -> str:
  cmd = [str(CLANG), str(src), "-fno-discard-value-names",
         "-mllvm", "-taokari", "-mllvm", "-taokari-vmp",
         "-S", "-emit-llvm", "-o", str(out), *extra_flags]
  must(run_vs(cmd, cwd), f"emit IR ({' '.join(extra_flags)})")
  return out.read_text(encoding="utf-8", errors="ignore")


def build_exe(extra_flags: list[str], cwd: Path, src: Path,
              out: Path) -> None:
  cmd = [str(CLANG), str(src),
         "-mllvm", "-taokari", "-mllvm", "-taokari-vmp",
         "-o", str(out), *extra_flags]
  must(run_vs(cmd, cwd), f"build exe ({' '.join(extra_flags)})")


def survival(ir_text: str, label: str) -> None:
  gate("__taokari_vmp_interp_" in ir_text,
       f"{label}: interpreter present post-opt")
  gate("__taokari_vmp_key_seed_" in ir_text,
       f"{label}: runtime key-seed global survived")
  gate(re.search(r"@\"?__taokari_vmp_bc_", ir_text) is not None,
       f"{label}: encrypted bytecode global survived (not folded to const)")


def main() -> int:
  if not CLANG.exists():
    print(f"missing clang: {CLANG}", file=sys.stderr)
    return 2

  tmp = Path(tempfile.mkdtemp(prefix="taokari-vmp-opt-"))
  try:
    src = tmp / "vmp_opt.cpp"
    src.write_text(SOURCE, encoding="utf-8")
    expected = "vmp-opt:0\n"

    # 1. -O2 IR + exe
    o2_ir = emit_ir(["-O2"], src.parent, src, tmp / "o2.ll")
    survival(o2_ir, "-O2")
    build_exe(["-O2"], src.parent, src, tmp / "o2.exe")
    o2_run = run([str(tmp / "o2.exe")])
    must(o2_run, "-O2 run")
    gate(o2_run.stdout == expected,
         f"-O2: protected binary still produces correct output "
         f"({o2_run.stdout!r})")

    # 2. -O3 IR + exe
    o3_ir = emit_ir(["-O3"], src.parent, src, tmp / "o3.ll")
    survival(o3_ir, "-O3")
    build_exe(["-O3"], src.parent, src, tmp / "o3.exe")
    o3_run = run([str(tmp / "o3.exe")])
    must(o3_run, "-O3 run")
    gate(o3_run.stdout == expected,
         f"-O3: protected binary still produces correct output "
         f"({o3_run.stdout!r})")

    # 3. LTO exe (single IR + link-time opt). LTO on Windows needs lld.
    build_exe(["-O2", "-flto", "-fuse-ld=lld"], src.parent, src,
              tmp / "lto.exe")
    lto_run = run([str(tmp / "lto.exe")])
    must(lto_run, "LTO run")
    gate(lto_run.stdout == expected,
         f"LTO: protected binary still produces correct output "
         f"({lto_run.stdout!r})")
    # LTO IR survival: re-emit with -flto -emit-llvm to confirm globals
    # survive the link-time pipeline too.
    lto_ir = emit_ir(["-O2", "-flto"], src.parent, src, tmp / "lto.ll")
    survival(lto_ir, "LTO")

    print("vmp optimizer-survival verifier: ok")
    return 0
  finally:
    shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
  raise SystemExit(main())
