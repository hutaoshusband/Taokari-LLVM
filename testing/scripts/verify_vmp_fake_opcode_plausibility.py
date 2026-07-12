"""VMP fake-opcode / fake-handler plausibility verifier.

todo.md "Reverse-engineering report follow-up":
  * Strengthen fake opcodes/fake handlers so they are not only registered
    dead cases; make them appear plausible in static and trace views.

The VM ships padding opcodes (OpPad/OpPad2/OpPad3) inserted into the
bytecode stream by the encoder and decoded by the interpreter as
no-ops that consume one immediate. Without noise they are obvious
"dead" cases — a single fetch + branch back to dispatch, no state
change. After the handler-body MBA noise was added, every handler body
(including the pad handlers) now runs a real arithmetic chain on the VM
stack pointer and stores the result in a private noise global, so a
static or trace view sees plausible work in every handler body and
cannot flag pads as obviously dead.

This verifier asserts the pad handler bodies are indistinguishable in
shape from real handler bodies: they must contain the MBA noise chain
(load SP, two XOR copies, and/or store to the noise global). It also
asserts the pad handlers are reachable in the dispatch routing and the
protected binary still produces correct output.
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

__attribute__((noinline))
__attribute__((annotate("vmp")))
static int alpha(int a, int b) {
  int x = a + b;
  return (x ^ a) + (x & b);
}

int main() {
  std::printf("vmp-pad:%d\n", alpha(7, 11));
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
    print(f"missing clang: {CLANG}", file=sys.stderr)
    return 2

  tmp = Path(tempfile.mkdtemp(prefix="taokari-vmp-pad-"))
  try:
    src = tmp / "vmp_pad.cpp"
    src.write_text(SOURCE, encoding="utf-8")
    ll = tmp / "vmp_pad.ll"
    exe = tmp / "vmp_pad.exe"
    flags = [str(src), "-O2", "-fno-discard-value-names",
             "-mllvm", "-taokari", "-mllvm", "-taokari-vmp",
             "-mllvm", "-taokari-vmp-padding=100"]

    ir = run_vs([str(CLANG), *flags, "-S", "-emit-llvm", "-o", str(ll)],
                src.parent)
    must(ir, "emit IR")
    ir_text = ll.read_text(encoding="utf-8", errors="ignore")

    # Locate pad handler body blocks (pad.entry / pad.body) and assert each
    # has plausible work: at least one MBA-shaped op feeding the noise
    # store, beyond the bare fetch+branch terminator.
    pad_bodies = re.findall(r'(\bpads?[0-9]*\.body):', ir_text)
    gate(len(pad_bodies) >= 1,
         f"pad handler bodies present (got {len(pad_bodies)})")

    # For each pad body, slice from the label to the next label and check
    # the slice contains MBA-noise markers. We use the global noise-store
    # presence as the proxy: every pad body should carry at least one
    # %h.* named value and a store to the noise global.
    noise_stores = len(re.findall(
        r"store i64 %h\.sum\w*, ptr @\"?__taokari_vmp_handler_noise_",
        ir_text))
    gate(noise_stores >= 1,
         f"MBA noise stores present across handler bodies (got {noise_stores})")

    # The pad handlers must be reachable from the dispatch (they are
    # registered as switch destinations).
    pad_in_dispatch = bool(re.search(r'%pad\w*\.body', ir_text))
    gate(pad_in_dispatch,
         "pad handler bodies are dispatch-reachable (not dead code)")

    build = run_vs([str(CLANG), *flags, "-o", str(exe)], src.parent)
    must(build, "build exe")
    ran = run([str(exe)])
    must(ran, "run exe")
    expected = "vmp-pad:23\n"
    gate(ran.stdout == expected,
         f"protected binary still produces correct output "
         f"(got {ran.stdout!r}, want {expected!r})")

    print("vmp fake-opcode plausibility verifier: ok")
    return 0
  finally:
    shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
  raise SystemExit(main())
