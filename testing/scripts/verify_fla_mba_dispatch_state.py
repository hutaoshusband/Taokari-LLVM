"""Verify MBA on flattening dispatch-state updates.

In fortress mode (fla L3+), the Flattening pass now rewrites the dispatcher
state-update path with MBA identities instead of plain XOR:
  * the loop decode (switchVar.enc1, switchXor.xor1, switchCond)
  * the per-block next-state encode (nextEnc)
all go through buildMbaXor, which emits .mba.* sub-instructions. At L2 the
plain XOR path is kept (buildMbaXor is fortress-gated).

Contract (same source, -emit-llvm):
  * L3 build: .mba.* markers appear anchored to the dispatch-state names
    (switchVar / switchXor / switchCond / nextEnc).
  * L2 build: no .mba.* markers in the dispatch-state path (gated off).
  * Correctness: the L4 obfuscated binary runs and matches native output.

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
  printf("flamba:%d\n", a + b);
  return 0;
}
"""

DISPATCH_ANCHORS = ("switchVar", "switchXor", "switchCond", "nextEnc")


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


def emit_ir(src: Path, out: Path, level: int) -> subprocess.CompletedProcess[str]:
    return run([
        str(CLANG), str(src), "-O2", "-fno-discard-value-names",
        "-mllvm", "-taokari",
        "-mllvm", "-taokari-fla",
        "-mllvm", f"-taokari-level-fla={level}",
        "-S", "-emit-llvm", "-o", str(out),
    ])


def count_dispatch_mba(text: str) -> int:
    count = 0
    for line in text.splitlines():
        if ".mba." not in line:
            continue
        if any(anchor in line for anchor in DISPATCH_ANCHORS):
            count += 1
    return count


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-fla-mba-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "fla_mba.c"
        src.write_text(SOURCE, encoding="utf-8")

        l3 = tmp / "l3.ll"
        if not must(emit_ir(src, l3, 3), "L3 emit-llvm"):
            return 1
        l3_text = l3.read_text(encoding="utf-8", errors="ignore")

        l2 = tmp / "l2.ll"
        if not must(emit_ir(src, l2, 2), "L2 emit-llvm"):
            return 1
        l2_text = l2.read_text(encoding="utf-8", errors="ignore")

        l3_mba = count_dispatch_mba(l3_text)
        l2_mba = count_dispatch_mba(l2_text)
        if "loopEntry" not in l3_text or "switchVar" not in l3_text:
            print("FAIL: L3 build did not flatten (no dispatcher)", file=sys.stderr)
            return 1
        if l3_mba == 0:
            print("FAIL: L3 dispatch-state path has no .mba.* markers",
                  file=sys.stderr)
            return 1
        if l2_mba > 0:
            print(f"FAIL: L2 dispatch-state path leaked {l2_mba} .mba.* markers "
                  f"(MBA must be fortress-gated)", file=sys.stderr)
            return 1

        native = run([str(CLANG), str(src), "-O2", "-fno-discard-value-names",
                      "-o", str(tmp / "native.exe")])
        if not must(native, "native build"):
            return 1
        native_run = run([str(tmp / "native.exe")])
        if native_run.returncode:
            sys.stderr.write("native run failed\n")
            return 1

        exe = tmp / "l4.exe"
        if not must(run([
            str(CLANG), str(src), "-O2", "-fno-discard-value-names",
            "-mllvm", "-taokari", "-mllvm", "-taokari-fla",
            "-mllvm", "-taokari-level-fla=4",
            "-o", str(exe),
        ]), "L4 exe build"):
            return 1
        obf_run = run([str(exe)])
        if obf_run.returncode or obf_run.stdout != native_run.stdout:
            print(f"FAIL: L4 runtime mismatch rc={obf_run.returncode} "
                  f"out={obf_run.stdout!r} expected={native_run.stdout!r}",
                  file=sys.stderr)
            return 1

    print(f"fla MBA dispatch-state: ok (L3 mba markers={l3_mba}, "
          f"L2 mba markers={l2_mba}, L4 runtime matches native)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
