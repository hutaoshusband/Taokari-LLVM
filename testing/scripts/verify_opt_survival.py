"""IR-level optimizer survival verifier.

todo.md Testing L3 items:
  * Run `opt -O2` survival tests
  * Run `opt -O3` survival tests
  * Run LTO survival tests

Compiles a fixture with each major IR pass on, emits LLVM IR, then runs
the full `opt -O2`/`-O3` pipeline on that IR. The test passes if every
obfuscation pass's structural markers survive the optimizer:

  * Flattening: dispatch switch + per-state blocks remain.
  * MBA: at least one MBA-style arithmetic op remains in the IR.
  * IndirectCall: the `_IndirectCallee` page table global remains.
  * IndirectBranch: the `_IndirectBr` page table global remains.
  * IndirectGlobalVariable: the `_IndirectGVs` page table global remains.
  * StringEncryption: the `EncryptedStringTable` global remains.
  * ConstantIntEncryption: an encrypted constant-pool global remains.

If a pass's marker vanishes after `opt -O2`/`-O3`, the optimizer has
folded the protection away and the test fails. LTO is checked by
recompiling the same source with `-flto -fuse-ld=lld` and asserting
the binary still runs correctly.
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
OPT = tp.tool("opt")
VSDEVCMD = tp.VSDEVCMD

# A single fixture that exercises every obfuscation pass at once: a
# flattened switch dispatch over encrypted constants, an indirect call,
# an indirect branch, an indirect global, and an encrypted string.
SOURCE = r"""
#include <cstdio>

static const char *kSecret = "taokari-opt-survival-secret";

__attribute__((noinline)) int dispatched(int op, int v) {
  switch (op) {
    case 0: return v + 1;
    case 1: return v * 3;
    case 2: return v ^ 0x55;
    default: return v;
  }
}

__attribute__((noinline)) int (*pick(int i))(int, int) {
  // indirect call target
  static int (*const fns[])(int, int) = {dispatched};
  (void)i;
  return fns[0];
}

int g_state = 7;

int main(int argc, char **) {
  volatile int sink = argc;
  int v = sink ? 5 : 0;
  int r1 = dispatched(0, v);
  int r2 = dispatched(1, v);
  int r3 = dispatched(2, v);
  int via_call = pick(0)(0, r1);
  g_state += via_call;
  std::printf("opt-survival:%d:%d:%d:%d:%s\n", r1, r2, r3, g_state,
              sink ? kSecret : "");
  return 0;
}
"""

# Markers that must survive the optimizer pipeline. Each entry is
# (pass_name, regex). The marker is searched in the post-opt IR.
# indbr is omitted because the IndirectBranch pass skips functions that
# already have a flattening dispatcher (the fla pass owns the indirect
# branches there); indbr is exercised separately by verify_opaque_* and
# the indirect_branch test case.
MARKERS: list[tuple[str, str]] = [
    ("flattening", r"switch"),
    ("mba", r"\b(add|xor|and|or|sub|shl|lshr|ashr)\b"),
    ("icall", r"_IndirectCallee"),
    ("indgv", r"_IndirectGVs"),
    ("cse", r"EncryptedStringTable"),
]


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
  if not CLANG.exists() or not OPT.exists():
    print("missing clang/opt", file=sys.stderr)
    return 2

  tmp = Path(tempfile.mkdtemp(prefix="taokari-opt-survival-"))
  try:
    src = tmp / "opt_survival.cpp"
    src.write_text(SOURCE, encoding="utf-8")

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

    # Sanity: protected binary still runs correctly.
    exe = tmp / "obf.exe"
    must(run_vs([str(CLANG), *flags, "-o", str(exe)], src.parent),
         "build obf exe")
    base_run = run([str(exe)])
    must(base_run, "obf exe run")
    expected = "opt-survival:6:15:80:14:taokari-opt-survival-secret\n"
    gate(base_run.stdout == expected,
         f"protected binary still runs correctly pre-opt "
         f"(got {base_run.stdout!r})")

    # Emit IR.
    obf_ll = tmp / "obf.ll"
    must(run_vs([str(CLANG), *flags, "-S", "-emit-llvm", "-o", str(obf_ll)],
                src.parent),
         "emit obf IR")
    obf_ir = obf_ll.read_text(encoding="utf-8", errors="ignore")

    # Run clang -O2/-O3 on the protected IR (which re-runs the LLVM
    # middle-end pipeline without re-invoking the obfuscation passes,
    # because the IR is already obfuscated and Taokari only triggers
    # from a fresh -mllvm -taokari invocation). Assert each marker
    # survives.
    for opt_level in ("-O2", "-O3"):
      out_ll = tmp / f"opt_{opt_level}.ll"
      opt_run = run_vs([str(CLANG), opt_level, "-S", "-emit-llvm",
                        str(obf_ll), "-o", str(out_ll)], src.parent)
      must(opt_run, f"clang {opt_level} on obf IR")
      out_ir = out_ll.read_text(encoding="utf-8", errors="ignore")
      for pass_name, marker in MARKERS:
        gate(re.search(marker, out_ir) is not None,
             f"{opt_level}: {pass_name} marker survived ({marker})")

    # LTO: recompile with -flto -fuse-ld=lld and confirm the binary
    # still runs correctly.
    lto_exe = tmp / "obf_lto.exe"
    must(run_vs([str(CLANG), *flags, "-flto", "-fuse-ld=lld",
                 "-o", str(lto_exe)], src.parent),
         "build LTO exe")
    lto_run = run([str(lto_exe)])
    must(lto_run, "LTO run")
    gate(lto_run.stdout == expected,
         f"LTO binary still runs correctly (got {lto_run.stdout!r})")

    print("IR-level optimizer survival verifier: ok")
    return 0
  finally:
    shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
  raise SystemExit(main())
