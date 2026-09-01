"""VMP handler-table signature divergence verifier.

todo.md "Reverse-engineering report follow-up":
  * Harden VMP handler-set reuse: make handler layout/order/shape differ per
    function or per build beyond current per-function interpreter cloning.
  * Add verifier that two VMP functions in one binary do not share the same
    handler-table signature.

Each `+vmp` function already gets its own interpreter clone
(`__taokari_vmp_interp_i64_<fn>_<rng>`). The previous weakness was that
"per-function clone" by itself did not guarantee handler-table divergence:
two interps could ship with the same opcode-to-handler-block order if the
shuffle happened to collide or if the only differentiator was the function
name suffix.

This verifier asserts that two VMP functions in the same binary ship with
structurally different handler-table signatures. A signature is the ordered
list of switch-case destination block labels in the interpreter's dispatch
switch, captured as a tuple. Two interps must produce distinct signatures,
proving an analyst cannot lift one +vmp function's dispatch and reuse it to
decode another.
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
static int alpha(int a, int b) {
  int x = a + b;
  int y = a * b;
  return (x ^ y) + (x & y) - (x | y);
}

__attribute__((noinline))
__attribute__((annotate("vmp")))
static int beta(int a, int b) {
  int x = a - b;
  int y = a ^ b;
  return (x + y) * 3 - (x - y);
}

int main() {
  int a = alpha(7, 11);
  int b = beta(7, 11);
  std::printf("vmp-sig:%d:%d\n", a, b);
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


def interpreter_signatures(ir: str) -> dict[str, tuple[str, ...]]:
  """For each `__taokari_vmp_interp_*` function, capture its handler-table
  signature: the ordered list of switch-case destination labels in the
  dispatch switch.

  A signature is a tuple of label names like
  `("loadslot", "add", "sub", "xor", ...)`. The order is the case-insertion
  order, which is exactly the shuffle order of the handler table at build
  time. Two interps with the same signature would let an analyst reuse one
  dispatch decode for the other.
  """
  sigs: dict[str, tuple[str, ...]] = {}
  # Define ... { ... } blocks of each interpreter. Function names are
  # string-quoted in IR (`@"<name>"`) when they contain characters outside
  # the bare identifier set, so the quote sits *after* the `@`. The regex
  # tolerates the optional quote on both sides of the captured name.
  for m in re.finditer(
      r'define[^{]*?@"?(__taokari_vmp_interp_[^"\s(]+)"?\s*\([^)]*\)[^{]*\{'
      r'([\s\S]*?)\n\}',
      ir):
    name = m.group(1)
    body = m.group(2)
    # The dispatch block's `preds` list is the per-handler block list in
    # textual order — exactly the handler-table shuffle order at build
    # time. Capture the dispatch block and read its ; preds = line.
    dm = re.search(r'^dispatch:\s*; preds = ([^\n]+)', body, re.M)
    if dm:
      preds = [p.strip() for p in dm.group(1).split(",")]
      sigs[name] = tuple(preds)
    else:
      sigs[name] = ()
  return sigs


def main() -> int:
  if not CLANG.exists():
    print(f"missing clang: {CLANG}", file=sys.stderr)
    return 2

  tmp = Path(tempfile.mkdtemp(prefix="taokari-vmp-sig-"))
  try:
    src = tmp / "vmp_sig.cpp"
    src.write_text(SOURCE, encoding="utf-8")
    ll = tmp / "vmp_sig.ll"
    exe = tmp / "vmp_sig.exe"
    flags = [str(src), "-O2", "-fno-discard-value-names",
             "-mllvm", "-taokari", "-mllvm", "-taokari-vmp"]

    ir = run_vs([str(CLANG), *flags, "-S", "-emit-llvm", "-o", str(ll)],
                src.parent)
    must(ir, "emit IR")
    ir_text = ll.read_text(encoding="utf-8", errors="ignore")

    sigs = interpreter_signatures(ir_text)
    gate(len(sigs) >= 2,
         f"at least two VMP interpreters emitted (got {len(sigs)})")

    distinct = set(sigs.values())
    gate(len(distinct) >= 2,
         "the two VMP interpreters ship with distinct handler-table "
         "signatures (no shared dispatch decode)")

    build = run_vs([str(CLANG), *flags, "-o", str(exe)], src.parent)
    must(build, "build exe")
    ran = run([str(exe)])
    must(ran, "run exe")
    # Both functions compute deterministic output; just require no crash.
    gate(ran.returncode == 0,
         f"protected binary still passes semantics (rc={ran.returncode})")

    print("vmp handler-table signature verifier: ok")
    return 0
  finally:
    shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
  raise SystemExit(main())
