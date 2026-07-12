"""Verify enhanced indirect branch/call page tables use the pointer key."""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG_CL
CLANG_CC = ROOT / "build" / "taokari-local" / "bin" / "clang.exe"
VSDEVCMD = tp.VSDEVCMD

BRANCH_SOURCE = r"""
#include <stdio.h>
__declspec(noinline) int branchy(int x) {
  int r = 0;
  for (int i = 0; i < 2000; ++i) {
    if (((x + i) & 3) == 0) r += i ^ x;
    else if ((i & 7) == 3) r -= i;
    else r += x - i;
  }
  return r;
}
int main(void) {
  printf("%d\n", branchy(17));
  return 0;
}
"""

CALL_SOURCE = r"""
#include <stdio.h>
static __declspec(noinline) int a(int x) { return x + 3; }
static __declspec(noinline) int b(int x) { return x * 5; }
__declspec(noinline) int run(int x) {
  int r = 0;
  for (int i = 0; i < 128; ++i)
    r += (i & 1) ? a(x + i) : b(x - i);
  return r;
}
int main(void) {
  printf("%d\n", run(9));
  return 0;
}
"""

TRAP_BRANCH_SOURCE = r"""
volatile int guard = 0;

__declspec(noinline) int guarded_trap_branch(int x) {
  if (guard)
    __builtin_debugtrap();
  if (x & 1)
    return x + 7;
  return x - 3;
}

int main(void) {
  return guarded_trap_branch(42) == 39 ? 0 : 1;
}
"""

ASSERT_BRANCH_SOURCE = r"""
#include <assert.h>

__declspec(noinline) int guarded_assert_branch(int offset) {
  assert(offset >= -1);
  if (offset < 0)
    return 11;
  return offset + 3;
}

int main(void) {
  return guarded_assert_branch(0) == 3 ? 0 : 1;
}
"""

STRING_NOOBF_SOURCE = r"""
#include <stdio.h>

__declspec(noinline) int string_user(int x) {
  const char* s = x ? "alpha-secret" : "beta-secret";
  if (s[0] == 'a')
    return 7;
  return 3;
}

int main(void) {
  printf("%d\n", string_user(1));
  return 0;
}
"""


def run(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    with tempfile.NamedTemporaryFile("w", suffix=".cmd", delete=False, encoding="utf-8") as h:
        batch = Path(h.name)
        h.write("@echo off\n")
        h.write(f'call "{VSDEVCMD}" -arch=x64 -host_arch=x64 >nul\n')
        h.write(subprocess.list2cmdline(cmd) + "\n")
        h.write("exit /b %ERRORLEVEL%\n")
    try:
        return subprocess.run(["cmd.exe", "/d", "/c", str(batch)], cwd=cwd,
                              text=True, capture_output=True)
    finally:
        batch.unlink(missing_ok=True)


def must(result: subprocess.CompletedProcess[str], label: str) -> None:
    if result.returncode:
        print(result.stdout, end="")
        print(result.stderr, end="", file=sys.stderr)
        raise SystemExit(f"{label} failed: {result.returncode}")


def build_and_compare(tmp: Path, name: str, source: str, flags: list[str]) -> None:
    src = tmp / f"{name}.cpp"
    plain = tmp / f"{name}_plain.exe"
    obf = tmp / f"{name}_obf.exe"
    src.write_text(source, encoding="utf-8")
    base = [str(CLANG), "/nologo", "/EHsc", "/std:c++20", "/O2", "/MT", str(src)]
    must(run([*base, f"/Fe:{plain}"], tmp), f"{name} plain build")
    must(run([*base, f"/Fe:{obf}", *flags], tmp), f"{name} obf build")
    plain_run = subprocess.run([str(plain)], text=True, capture_output=True)
    obf_run = subprocess.run([str(obf)], text=True, capture_output=True)
    must(plain_run, f"{name} plain run")
    must(obf_run, f"{name} obf run")
    if plain_run.stdout != obf_run.stdout:
        raise SystemExit(f"{name} stdout mismatch: {plain_run.stdout!r} != {obf_run.stdout!r}")


def verify_trap_branch_not_indirected(tmp: Path) -> None:
    src = tmp / "trap_branch.cpp"
    ir = tmp / "trap_branch.ll"
    src.write_text(TRAP_BRANCH_SOURCE, encoding="utf-8")
    cmd = [
        str(CLANG_CC), "-S", "-emit-llvm", "-O2", str(src), "-o", str(ir),
        "-mllvm", "-taokari", "-mllvm", "-taokari-indbr",
        "-mllvm", "-taokari-level-indbr=2",
    ]
    must(run(cmd, tmp), "trap branch IR build")
    text = ir.read_text(encoding="utf-8")
    if "indirectbr" in text:
        raise SystemExit("trap branch fixture was rewritten with indirectbr")

    exe = tmp / "trap_branch_obf.exe"
    base = [str(CLANG), "/nologo", "/EHsc", "/std:c++20", "/O2", "/MT", str(src)]
    must(run([*base, f"/Fe:{exe}",
              "-mllvm", "-taokari", "-mllvm", "-taokari-indbr",
              "-mllvm", "-taokari-level-indbr=2"], tmp),
         "trap branch obf build")
    must(subprocess.run([str(exe)], text=True, capture_output=True),
         "trap branch obf run")


def verify_assert_branch_not_indirected(tmp: Path) -> None:
    src = tmp / "assert_branch.cpp"
    ir = tmp / "assert_branch.ll"
    src.write_text(ASSERT_BRANCH_SOURCE, encoding="utf-8")
    cmd = [
        str(CLANG_CC), "-S", "-emit-llvm", "-O2", str(src), "-o", str(ir),
        "-mllvm", "-taokari", "-mllvm", "-taokari-indbr",
        "-mllvm", "-taokari-level-indbr=2",
    ]
    must(run(cmd, tmp), "assert branch IR build")
    text = ir.read_text(encoding="utf-8")
    if "indirectbr" in text:
        raise SystemExit("assert branch fixture was rewritten with indirectbr")

    exe = tmp / "assert_branch_obf.exe"
    base = [str(CLANG), "/nologo", "/EHsc", "/std:c++20", "/O2", "/MT", str(src)]
    must(run([*base, f"/Fe:{exe}",
              "-mllvm", "-taokari", "-mllvm", "-taokari-indbr",
              "-mllvm", "-taokari-level-indbr=2"], tmp),
         "assert branch obf build")
    must(subprocess.run([str(exe)], text=True, capture_output=True),
         "assert branch obf run")


def verify_string_noobf_blocks_indbr(tmp: Path) -> None:
    src = tmp / "string_noobf.cpp"
    ir = tmp / "string_noobf.ll"
    src.write_text(STRING_NOOBF_SOURCE, encoding="utf-8")
    cmd = [
        str(CLANG_CC), "-S", "-emit-llvm", "-O2", str(src), "-o", str(ir),
        "-mllvm", "-taokari", "-mllvm", "-taokari-cse",
        "-mllvm", "-taokari-indbr", "-mllvm", "-taokari-level-indbr=2",
    ]
    must(run(cmd, tmp), "string noobf IR build")
    text = ir.read_text(encoding="utf-8")
    if '"?string_user@@YAHH@Z_IndirectBr' in text or "string_user" in text and "indirectbr" in text:
        raise SystemExit("string noobf fixture was rewritten with indirectbr")

    plain = tmp / "string_plain.exe"
    obf = tmp / "string_obf.exe"
    base = [str(CLANG), "/nologo", "/EHsc", "/std:c++20", "/O2", "/MT", str(src)]
    must(run([*base, f"/Fe:{plain}"], tmp), "string plain build")
    must(run([*base, f"/Fe:{obf}",
              "-mllvm", "-taokari", "-mllvm", "-taokari-cse",
              "-mllvm", "-taokari-indbr", "-mllvm", "-taokari-level-indbr=2"], tmp),
         "string obf build")
    plain_run = subprocess.run([str(plain)], text=True, capture_output=True)
    obf_run = subprocess.run([str(obf)], text=True, capture_output=True)
    must(plain_run, "string plain run")
    must(obf_run, "string obf run")
    if plain_run.stdout != obf_run.stdout:
      raise SystemExit(f"string stdout mismatch: {plain_run.stdout!r} != {obf_run.stdout!r}")


def main() -> int:
    if not CLANG.exists():
        print(f"missing tool: {CLANG}", file=sys.stderr)
        return 2
    if not CLANG_CC.exists():
        print(f"missing tool: {CLANG_CC}", file=sys.stderr)
        return 2
    tmp = Path(tempfile.mkdtemp(prefix="taokari-page-key-"))
    try:
        build_and_compare(tmp, "indbr", BRANCH_SOURCE, [
            "-mllvm", "-taokari", "-mllvm", "-taokari-indbr",
            "-mllvm", "-taokari-level-indbr=2",
        ])
        build_and_compare(tmp, "icall", CALL_SOURCE, [
            "-mllvm", "-taokari", "-mllvm", "-taokari-icall",
            "-mllvm", "-taokari-level-icall=2",
        ])
        verify_trap_branch_not_indirected(tmp)
        verify_assert_branch_not_indirected(tmp)
        verify_string_noobf_blocks_indbr(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("verify_page_table_ptr_key: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
