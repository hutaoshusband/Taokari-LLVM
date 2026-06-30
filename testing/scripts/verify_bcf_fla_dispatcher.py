"""Verify BCF fake-region / flattening dispatcher integration.

When BCF runs before flattening (-taokari-bcf-before-fla) at fla L3+,
the Flattening pass now chains BCF-generated fake regions (.bcf.fake
blocks) into the dispatcher's fake-case target, so the flattening
dispatcher's bogus switch edges route through BCF-style junk regions
instead of only cloned real blocks.

Contract (same source, fla L3, BCF before fla, -emit-llvm):
  * The IR contains both .bcf.fake blocks and switchFakeCaseGate/clone
    dispatcher blocks (both passes fired).
  * At least one .bcf.fake block's terminator successor is a flattening-
    generated block (switchFakeCaseGate / switchFakeSucc / .tao.clone /
    switchDefault). That is the wiring this feature adds: without it,
    every .bcf.fake successor is a real (non-flattening) block.
  * A fla-L3 build WITHOUT bcf-before-fla has no .bcf.fake blocks at all
    (proves the .bcf.fake markers come from BCF, not fla).
  * Correctness: the combined obfuscated binary runs and matches native.

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
  printf("bcffla:%d\n", a + b);
  return 0;
}
"""

BR_LABEL = re.compile(r'br label %([^\s,;]+)')


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


def emit_ir(src: Path, out: Path, extra: list[str]) -> subprocess.CompletedProcess[str]:
    mllvm: list[str] = []
    for flag in extra:
        mllvm.append("-mllvm")
        mllvm.append(flag)
    return run([
        str(CLANG), str(src), "-O2", "-fno-discard-value-names",
        "-mllvm", "-taokari",
        *mllvm,
        "-S", "-emit-llvm", "-o", str(out),
    ])


def parse_block_successors(text: str) -> dict[str, list[str]]:
    succ: dict[str, list[str]] = {}
    cur = None
    for line in text.splitlines():
        m = re.match(r'^([^\s;][^:]*):\s', line)
        if m and not line.startswith("  "):
            cur = m.group(1).strip()
            succ.setdefault(cur, [])
            continue
        if cur is None:
            continue
        for br in BR_LABEL.findall(line):
            succ[cur].append(br)
    return succ


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-bcf-fla-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "bcf_fla.c"
        src.write_text(SOURCE, encoding="utf-8")

        combined = tmp / "combined.ll"
        if not must(emit_ir(src, combined, [
            "-taokari-bcf", "-taokari-level-bcf=3",
            "-taokari-bcf-prob=100", "-taokari-bcf-loops=1",
            "-taokari-bcf-before-fla",
            "-taokari-fla", "-taokari-level-fla=3",
        ]), "combined emit-llvm"):
            return 1
        combined_text = combined.read_text(encoding="utf-8", errors="ignore")

        fla_only = tmp / "fla_only.ll"
        if not must(emit_ir(src, fla_only, [
            "-taokari-fla", "-taokari-level-fla=3",
        ]), "fla-only emit-llvm"):
            return 1
        fla_only_text = fla_only.read_text(encoding="utf-8", errors="ignore")

        if ".bcf.fake" not in combined_text:
            print("FAIL: combined build has no .bcf.fake blocks (BCF did not run)",
                  file=sys.stderr)
            return 1
        if "switchFakeCaseGate" not in combined_text and ".tao.clone" not in combined_text:
            print("FAIL: combined build has no flattening dispatcher blocks",
                  file=sys.stderr)
            return 1
        if ".bcf.fake" in fla_only_text:
            print("FAIL: fla-only build leaked .bcf.fake markers", file=sys.stderr)
            return 1

        succ = parse_block_successors(combined_text)
        fla_block_markers = (
            "switchFakeCaseGate", "switchFakeSucc", "switchDefault",
            "switchTrap", "tao.clone", "switchDispatch", "switchBucket",
            "loopEnd", "loopEntry",
        )
        wired = 0
        bcf_count = 0
        for blk, succs in succ.items():
            if ".bcf.fake" not in blk:
                continue
            bcf_count += 1
            for s in succs:
                if any(m in s for m in fla_block_markers):
                    wired += 1
                    break
        if bcf_count == 0:
            print("FAIL: no .bcf.fake blocks found in successor map", file=sys.stderr)
            return 1
        if wired == 0:
            print(f"FAIL: none of {bcf_count} .bcf.fake blocks route into the "
                  f"flattening dispatcher (integration did not fire)",
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

        exe = tmp / "combined.exe"
        exe_flags = [
            "-taokari-bcf", "-taokari-level-bcf=3",
            "-taokari-bcf-prob=100", "-taokari-bcf-loops=1",
            "-taokari-bcf-before-fla",
            "-taokari-fla", "-taokari-level-fla=3",
        ]
        exe_cmd = [str(CLANG), str(src), "-O2", "-fno-discard-value-names",
                   "-mllvm", "-taokari"]
        for flag in exe_flags:
            exe_cmd += ["-mllvm", flag]
        exe_cmd += ["-o", str(exe)]
        if not must(run(exe_cmd), "combined exe build"):
            return 1
        obf_run = run([str(exe)])
        if obf_run.returncode or obf_run.stdout != native_run.stdout:
            print(f"FAIL: combined runtime mismatch rc={obf_run.returncode} "
                  f"out={obf_run.stdout!r} expected={native_run.stdout!r}",
                  file=sys.stderr)
            return 1

    print(f"bcf/fla dispatcher integration: ok ({wired}/{bcf_count} .bcf.fake "
          f"blocks wired into dispatcher, runtime matches native)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
