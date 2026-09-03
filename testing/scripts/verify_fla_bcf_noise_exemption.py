"""Verify flattening's workload gates exempt BCF noise under pinned budgets.

BCF-before-flattening inflates functions with bcf.dead.slot allocas and
fake-block clones (~1000 allocas on a 20-line fixture). The workload gates
measure user-function complexity, so those Taokari-noise allocas are
exempted from the counts (taokari.bcf.slot metadata + bcf. name prefix).
Functions still over budget after the exemption are refused on purpose:
full BCF -> FLA composition on those shapes measured 60x compile overhead.

Contract (config pins the budgets high, so only the exemption decides):
  * 3 fresh compiles of a BCF-attractive fixture with a config pinning
    fla maxInsts=40000 / maxBlocks=4000 / maxAllocas=800 and bcf level 3:
    taokari.bcf.slot markers PRESENT (BCF ran), taokari-flattened PRESENT
    (the exemption let flattening apply), runtime output equals plain.
  * The unmarked-alloca count of the fixture (~5) is far below the pinned
    maxAllocas=800, so a regression back to unexempted counting fails on
    the flattened check, deterministically.

Exit:
  0 + "fla bcf noise exemption: ok"
  1 -- contract violation
  2 -- missing clang
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

ROOT = tp.ROOT
CLANG = tp.CLANG
VSDEVCMD = tp.VSDEVCMD

SRC = """#include <stdio.h>
static __attribute__((noinline)) int mix(int a, int b) {
  int acc = a;
  for (int i = 0; i < 6; ++i) {
    if ((acc ^ b) & 1) acc = acc * 3 - i;
    else acc = (acc + b) / 2 + i;
    if ((acc & 7) == 5) acc ^= i << 2;
  }
  return acc;
}
int main(void) {
  printf("flamax:%d:%d\\n", mix(9, 4), mix(31, 8));
  return 0;
}
"""
CFG = {
    "fla": {"enable": True, "level": 4,
            "maxInsts": 40000, "maxBlocks": 4000, "maxAllocas": 800},
    "bcf": {"enable": True, "level": 3},
}


def run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    if VSDEVCMD.exists():
        with tempfile.NamedTemporaryFile("w", suffix=".cmd", delete=False, encoding="utf-8") as handle:
            batch = Path(handle.name)
            handle.write(
                "@echo off\n"
                f'call "{VSDEVCMD}" -arch=x64 -host_arch=x64 >nul\n'
                f"{subprocess.list2cmdline(cmd)}\n"
                "exit /b %ERRORLEVEL%\n"
            )
        try:
            return subprocess.run(["cmd.exe", "/d", "/c", str(batch)], cwd=ROOT, text=True, capture_output=True)
        finally:
            batch.unlink(missing_ok=True)
    return subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True)


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-flamax-") as tmp:
        d = Path(tmp)
        src = d / "flamax.c"
        src.write_text(SRC, encoding="utf-8")
        cfg = d / "cfg.json"
        cfg.write_text(json.dumps(CFG), encoding="utf-8")
        cfg_flags = ["-mllvm", f"-taokari-cfg={cfg}"]

        plain = d / "plain.exe"
        r = run([str(CLANG), "-O2", "-std=c17", str(src), "-o", str(plain)])
        if r.returncode or not plain.exists():
            print(f"  [FAIL] plain build rc={r.returncode}", file=sys.stderr)
            return 1
        want = run([str(plain)])
        if want.returncode:
            print(f"  [FAIL] plain run rc={want.returncode}", file=sys.stderr)
            return 1

        for i in range(3):
            ir = d / f"max_{i}.ll"
            r = run([str(CLANG), "-O2", "-std=c17", *cfg_flags, "-S", "-emit-llvm",
                     str(src), "-o", str(ir)])
            if r.returncode or not ir.exists():
                print(f"  [FAIL] compile {i}: rc={r.returncode}: {r.stderr[:300]}",
                      file=sys.stderr)
                return 1
            text = ir.read_text(encoding="utf-8")
            has_bcf = "taokari.bcf.slot" in text
            has_fla = "taokari-flattened" in text
            if not has_bcf:
                print(f"  [FAIL] compile {i}: no taokari.bcf.slot markers "
                      "(BCF did not run; control broken)", file=sys.stderr)
                return 1
            if not has_fla:
                print(f"  [FAIL] compile {i}: BCF noise allocas still defeat "
                      "the workload gates", file=sys.stderr)
                return 1
            exe = d / f"max_{i}.exe"
            r = run([str(CLANG), "-O2", "-std=c17", *cfg_flags, str(src), "-o", str(exe)])
            if r.returncode or not exe.exists():
                print(f"  [FAIL] link {i}: rc={r.returncode}", file=sys.stderr)
                return 1
            r = run([str(exe)])
            if r.returncode or r.stdout.strip() != want.stdout.strip():
                print(f"  [FAIL] run {i}: rc={r.returncode} "
                      f"out={r.stdout.strip()!r} want={want.stdout.strip()!r}",
                      file=sys.stderr)
                return 1
        print("  [ok] 3/3 pinned-budget builds: BCF ran AND flattening applied, outputs match")

    print("fla bcf noise exemption: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
