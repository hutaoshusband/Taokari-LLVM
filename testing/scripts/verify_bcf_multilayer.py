"""Verify BCF L3/L4 multi-layer bogus graphs.

The BogusControlFlow pass now nests opaque-guarded bogus blocks: L3 builds a
2-layer graph (a decompiler must peel 2 opaque predicates to reach the real
block), L4 builds 3. Each layer has its own RNG-shaped opaque seed and a
junk-filled fake region that branches into the next layer.

Contract (same source built per level, -emit-llvm):
  * L2: exactly one guard layer (.bcf.guard1), no layer-2/3 markers.
  * L3: at least one .bcf.guard2 and one .bcf.fake.layer2 marker (2 layers).
  * L4: at least one .bcf.guard3 and one .bcf.fake.layer3 marker (3 layers).
  * Each higher level's guard count strictly increases (layers stack).
  * Correctness: the L4 obfuscated binary runs and matches the native output.

Exit: 0 ok | 1 contract failure | 2 missing clang.
"""
from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
VSDEVCMD = tp.VSDEVCMD

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
  printf("bcfml:%d\n", a + b);
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


def emit_ir(level: int, src: Path, out: Path) -> subprocess.CompletedProcess[str]:
    return run([
        str(CLANG), str(src), "-O2", "-fno-discard-value-names",
        "-mllvm", "-taokari",
        "-mllvm", "-taokari-bcf",
        "-mllvm", f"-taokari-level-bcf={level}",
        "-mllvm", "-taokari-bcf-prob=100",
        "-mllvm", "-taokari-bcf-loops=1",
        "-S", "-emit-llvm", "-o", str(out),
    ])


def count_marker(text: str, marker: str) -> int:
    return len(re.findall(re.escape(marker), text))


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-bcf-ml-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "bcf_ml.c"
        src.write_text(SOURCE, encoding="utf-8")

        ir_by_level: dict[int, str] = {}
        for level in (2, 3, 4):
            ir = tmp / f"bcf_l{level}.ll"
            if not must(emit_ir(level, src, ir), f"emit-llvm L{level}"):
                return 1
            ir_by_level[level] = ir.read_text(encoding="utf-8", errors="ignore")

        for level, text in ir_by_level.items():
            if ".bcf.guard" not in text:
                print(f"FAIL: L{level} produced no .bcf.guard markers",
                      file=sys.stderr)
                return 1

        l2, l3, l4 = ir_by_level[2], ir_by_level[3], ir_by_level[4]

        if "bcf.guard2" in l2 or "bcf.fake.layer" in l2:
            print("FAIL: L2 must not emit multi-layer markers", file=sys.stderr)
            return 1
        if "bcf.guard2" not in l3 or "bcf.fake.layer2" not in l3:
            print("FAIL: L3 missing layer-2 markers (.bcf.guard2/.bcf.fake.layer2)",
                  file=sys.stderr)
            return 1
        if "bcf.guard3" not in l4 or "bcf.fake.layer3" not in l4:
            print("FAIL: L4 missing layer-3 markers (.bcf.guard3/.bcf.fake.layer3)",
                  file=sys.stderr)
            return 1

        g2 = count_marker(l2, ".bcf.guard1")
        g3 = count_marker(l3, ".bcf.guard")
        g4 = count_marker(l4, ".bcf.guard")
        if not (g2 < g3 < g4):
            print(f"FAIL: guard counts must strictly increase L2<L3<L4, "
                  f"got {g2}<{g3}<{g4}", file=sys.stderr)
            return 1

        native = run([
            str(CLANG), str(src), "-O2", "-fno-discard-value-names", "-o",
            str(tmp / "native.exe"),
        ])
        if not must(native, "native build"):
            return 1
        native_run = run([str(tmp / "native.exe")])
        if native_run.returncode:
            sys.stderr.write("native run failed\n")
            return 1

        exe = tmp / "bcf_l4.exe"
        if not must(run([
            str(CLANG), str(src), "-O2", "-fno-discard-value-names",
            "-mllvm", "-taokari", "-mllvm", "-taokari-bcf",
            "-mllvm", "-taokari-level-bcf=4",
            "-mllvm", "-taokari-bcf-prob=100",
            "-mllvm", "-taokari-bcf-loops=1",
            "-o", str(exe),
        ]), "L4 exe build"):
            return 1
        obf_run = run([str(exe)])
        if obf_run.returncode or obf_run.stdout != native_run.stdout:
            print(f"FAIL: L4 runtime mismatch rc={obf_run.returncode} "
                  f"out={obf_run.stdout!r} expected={native_run.stdout!r}",
                  file=sys.stderr)
            return 1

    print(f"bcf multi-layer: ok (guards L2={g2} < L3={g3} < L4={g4}, "
          f"runtime matches native)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
