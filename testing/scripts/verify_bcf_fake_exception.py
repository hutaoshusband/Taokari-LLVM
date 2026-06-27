"""Verify BCF fake exception-looking regions (where safe).

At BCF L3+ the BogusControlFlow pass now emits fake exception-looking bogus
regions in non-EH functions: an .bcf.exh block that loads an "exception
record", mixes it with a frame nonce, and calls the cleanup handler stub,
guarded by an .bcf.exh.gate that branches to it only on an unfoldable-false
opaque predicate. So a static analyser reads exception-handler-shaped code
that is in fact unreachable at runtime.

Contract (same source, -emit-llvm):
  * L3 build: .bcf.exh / .bcf.exh.gate / .bcf.exh.opaque markers appear (the
    fake-EH region fired), and the region is gated by a false opaque
    predicate (gate branches to .bcf.exh on the false edge).
  * The function has NO personality fn (safety: real EH functions are
    skipped).
  * L2 build: no .bcf.exh markers (region is L3-gated).
  * Correctness: the L3 obfuscated binary runs and matches native output.
  * An EH-heavy source (a function with a personality) does NOT get the
    fake-EH region (safety gate).

Exit: 0 ok | 1 contract failure | 2 missing clang.
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CLANG = ROOT / "build" / "taokari-local" / "bin" / "clang.exe"
VSDEVCMD = Path(
    r"C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat"
)

SOURCE = r"""
#include <stdio.h>

volatile int g_sink = 3;

__attribute__((noinline)) int probe(int x) {
  int y = x + g_sink;
  if (x & 1) {
    y = y * 7 + 11;
    g_sink += y;
  } else {
    y = y * 5 - 9;
    g_sink ^= y;
  }
  return y ^ g_sink;
}

int main(void) {
  int a = probe(7);
  int b = probe(10);
  printf("bcfexh:%d\n", a + b);
  return 0;
}
"""

EH_SOURCE = r"""
#include <stdio.h>
#include <stdexcept>

__attribute__((noinline)) int may_throw(int x) {
  if (x < 0) throw std::runtime_error("neg");
  return x * 3;
}

int main(void) {
  try {
    printf("bcfexh:%d\n", may_throw(5));
  } catch (const std::exception &e) {
    printf("bcfexh:caught\n");
  }
  return 0;
}
"""


def run(command: list[str], *, cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    if VSDEVCMD.exists():
        with tempfile.NamedTemporaryFile(
            "w", suffix=".cmd", delete=False, encoding="utf-8"
        ) as handle:
            batch = Path(handle.name)
            handle.write(
                "@echo off\n"
                f'call "{VSDEVCMD}" -arch=x64 -host_arch=x64 >nul\n'
                f"{subprocess.list2cmdline(command)}\n"
                "exit /b %ERRORLEVEL%\n"
            )
        try:
            return subprocess.run(
                ["cmd.exe", "/d", "/c", str(batch)], cwd=cwd,
                text=True, capture_output=True,
            )
        finally:
            batch.unlink(missing_ok=True)
    return subprocess.run(command, cwd=cwd, text=True, capture_output=True)


def must(result: subprocess.CompletedProcess[str], label: str) -> bool:
    if result.returncode:
        sys.stderr.write(f"{label} failed:\n")
        sys.stderr.write(result.stdout + result.stderr)
        return False
    return True


def mllvm(flags: list[str]) -> list[str]:
    out = []
    for f in flags:
        out += ["-mllvm", f]
    return out


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-bcf-exh-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "bcf_exh.c"
        src.write_text(SOURCE, encoding="utf-8")

        l3 = tmp / "l3.ll"
        if not must(run([str(CLANG), str(src), "-O2", "-fno-discard-value-names",
                         *mllvm(["-taokari", "-taokari-bcf", "-taokari-level-bcf=3",
                                 "-taokari-bcf-prob=100", "-taokari-bcf-loops=1"]),
                         "-S", "-emit-llvm", "-o", str(l3)]), "L3 emit-llvm"):
            return 1
        l3_text = l3.read_text(encoding="utf-8", errors="ignore")

        l2 = tmp / "l2.ll"
        if not must(run([str(CLANG), str(src), "-O2", "-fno-discard-value-names",
                         *mllvm(["-taokari", "-taokari-bcf", "-taokari-level-bcf=2",
                                 "-taokari-bcf-prob=100", "-taokari-bcf-loops=1"]),
                         "-S", "-emit-llvm", "-o", str(l2)]), "L2 emit-llvm"):
            return 1
        l2_text = l2.read_text(encoding="utf-8", errors="ignore")

        if l3_text.count(".bcf.exh") == 0:
            print("FAIL: L3 IR has no .bcf.exh region", file=sys.stderr)
            return 1
        if l3_text.count("bcf.exh.gate") == 0 or l3_text.count("bcf.exh.opaque") == 0:
            print("FAIL: L3 IR has no .bcf.exh.gate / opaque predicate",
                  file=sys.stderr)
            return 1
        if "personality" in l3_text:
            print("FAIL: fake-EH region leaked a personality into a non-EH fn",
                  file=sys.stderr)
            return 1
        if ".bcf.exh" in l2_text:
            print("FAIL: L2 IR leaked .bcf.exh markers (must be L3-gated)",
                  file=sys.stderr)
            return 1

        native = run([str(CLANG), str(src), "-O2", "-fno-discard-value-names",
                      "-o", str(tmp / "native.exe")])
        if not must(native, "native build"):
            return 1
        native_run = run([str(tmp / "native.exe")])
        if native_run.returncode:
            sys.stderr.write("native run failed\n")
            return 1

        obf = tmp / "l3.exe"
        if not must(run([str(CLANG), str(src), "-O2", "-fno-discard-value-names",
                         *mllvm(["-taokari", "-taokari-bcf", "-taokari-level-bcf=3",
                                 "-taokari-bcf-prob=100", "-taokari-bcf-loops=1"]),
                         "-o", str(obf)]), "L3 exe build"):
            return 1
        obf_run = run([str(obf)])
        if obf_run.returncode or obf_run.stdout != native_run.stdout:
            print(f"FAIL: L3 runtime mismatch rc={obf_run.returncode} "
                  f"out={obf_run.stdout!r} expected={native_run.stdout!r}",
                  file=sys.stderr)
            return 1

        eh_src = tmp / "eh.cpp"
        eh_src.write_text(EH_SOURCE, encoding="utf-8")
        eh_ir = tmp / "eh.ll"
        if not must(run([str(CLANG), str(eh_src), "-O2", "-fno-discard-value-names",
                         "-std=c++17", "-fcxx-exceptions",
                         *mllvm(["-taokari", "-taokari-bcf", "-taokari-level-bcf=3",
                                 "-taokari-bcf-prob=100", "-taokari-bcf-loops=1"]),
                         "-S", "-emit-llvm", "-o", str(eh_ir)]), "EH emit-llvm"):
            return 1
        eh_text = eh_ir.read_text(encoding="utf-8", errors="ignore")
        if "personality" not in eh_text:
            print("FAIL: EH source did not actually carry a personality "
                  "(test fixture broken)", file=sys.stderr)
            return 1
        if ".bcf.exh" in eh_text:
            print("FAIL: fake-EH region fired inside an EH function (safety "
                  "gate broken)", file=sys.stderr)
            return 1

    print(f"bcf fake-exception regions: ok (L3 markers present, gated by "
          f"opaque-false, no personality leak, L2 clean, EH fn skipped, "
          f"runtime matches native)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
