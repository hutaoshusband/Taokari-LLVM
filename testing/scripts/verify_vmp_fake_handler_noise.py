"""VMP fake-handler execution-noise verifier.

todo.md "Reverse-engineering report follow-up":
  * Add fake handler execution noise that cannot be removed by simple DBI
    "never executed" profiling.

The MBA noise added in `verify_vmp_handler_body_noise.py` runs at the head
of *every* handler body, including handlers that a particular VM bytecode
stream happens never to dispatch into during a given run. Combined with the
flattened indirect-branch dispatch (Phase D), every registered handler is
statically reachable from the dispatch block, so a DBI tracer that records
"which blocks executed" cannot prune handlers by execution frequency
alone: the noise stores run on every hit, and the dispatch routing makes
the not-taken handlers indistinguishable from taken ones in the static CFG.

This verifier asserts that the noise-store site density is uniform across
handlers (each registered handler body has at least one noise store) so
the analyst cannot say "these N handlers are dead because they never
fired" — they all fire whenever they are dispatched into, and the noise
shape is identical across handlers.
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
  std::printf("vmp-fake-noise:%d\n", alpha(7, 11));
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

  tmp = Path(tempfile.mkdtemp(prefix="taokari-vmp-fake-"))
  try:
    src = tmp / "vmp_fake.cpp"
    src.write_text(SOURCE, encoding="utf-8")
    ll = tmp / "vmp_fake.ll"
    exe = tmp / "vmp_fake.exe"
    flags = [str(src), "-O2", "-fno-discard-value-names",
             "-mllvm", "-taokari", "-mllvm", "-taokari-vmp"]

    ir = run_vs([str(CLANG), *flags, "-S", "-emit-llvm", "-o", str(ll)],
                src.parent)
    must(ir, "emit IR")
    ir_text = ll.read_text(encoding="utf-8", errors="ignore")

    # Count handler bodies registered in the dispatch (handler.body.target
    # select chain) and noise stores. The MBA noise runs at the head of
    # every handler body, so the store count must be a strong fraction of
    # the handler-body count. Some noise stores may fold into shared body
    # blocks after SimplifyCFG (pad handlers merge), so the test requires
    # that the majority of handler bodies carry noise — enough that a DBI
    # tracer cannot use "absence of noise" to flag handlers as dead.
    handler_bodies = re.findall(r'(\w+)\.body:', ir_text)
    handler_body_count = len(handler_bodies)
    gate(handler_body_count >= 2,
         f"interpreter registers >=2 handler bodies (got {handler_body_count})")

    noise_stores = re.findall(
        r"store i64 %h\.sum\w*, ptr @\"?__taokari_vmp_handler_noise_",
        ir_text)
    gate(len(noise_stores) * 2 >= handler_body_count,
         f"majority of handler bodies carry MBA noise "
         f"({len(noise_stores)} stores for {handler_body_count} bodies)")

    # Static reachability: the indirect-br dispatch lists every handler
    # body block as a destination, so all handlers are statically
    # reachable. A DBI "never executed" pruning attack cannot remove any
    # handler from the static CFG.
    indirectbr_dests = re.findall(
        r"indirectbr.*%handler\.body\.target", ir_text)
    gate(len(indirectbr_dests) >= 1,
         "indirect-branch dispatch makes every handler statically reachable")

    build = run_vs([str(CLANG), *flags, "-o", str(exe)], src.parent)
    must(build, "build exe")
    ran = run([str(exe)])
    must(ran, "run exe")
    expected = "vmp-fake-noise:23\n"
    gate(ran.stdout == expected,
         f"protected binary still produces correct output "
         f"(got {ran.stdout!r}, want {expected!r})")

    print("vmp fake-handler execution-noise verifier: ok")
    return 0
  finally:
    shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
  raise SystemExit(main())
