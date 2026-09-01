"""Verify BCF fake-region / flattening dispatcher integration.

When BCF runs before flattening (-taokari-bcf-before-fla) at fla L3+,
the Flattening pass must preserve BCF-generated fake-region exits.
Redirecting a .bcf.fake block into the flattening trap chain changes
BCF's fallback path from semantically equivalent junk into a crash.

Contract (same source, fla L3, BCF before fla, -emit-llvm):
  * The IR contains both .bcf.fake blocks and switchFakeCaseGate/clone
    dispatcher blocks (both passes fired).
  * No .bcf.fake block decodes its next dispatcher state back to the
    function-entry case. That restart corrupts live state on the fallback path.
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
sys.path.insert(0, str(Path(__file__).resolve().parent))
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

CASE = re.compile(r'i64 (-?\d+), label %([^\s\]]+)')
STATE_STORE = re.compile(
    r'store volatile i64 (-?\d+), ptr %(switchVar|switchXor)'
)


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


def parse_blocks(text: str) -> dict[str, list[str]]:
    blocks: dict[str, list[str]] = {}
    cur = None
    for line in text.splitlines():
        m = re.match(r'^([^\s;][^:]*):\s', line)
        if m and not line.startswith("  "):
            cur = m.group(1).strip()
            blocks.setdefault(cur, [])
            continue
        if cur is None:
            continue
        blocks[cur].append(line)
    return blocks


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

        probe_match = re.search(
            r'define\b[^{]*@probe\([^)]*\)[^{]*\{(.*?)^\}',
            combined_text, re.MULTILINE | re.DOTALL,
        )
        if not probe_match:
            print("FAIL: probe function missing from combined IR", file=sys.stderr)
            return 1

        probe_ir = probe_match.group(1)
        mask = (1 << 64) - 1
        cases = {
            int(value) & mask: label
            for value, label in CASE.findall(probe_ir)
        }
        entry_states = {
            value for value, label in cases.items() if label.startswith("first")
        }
        if not entry_states:
            print("FAIL: flattening entry state missing", file=sys.stderr)
            return 1

        bcf_count = 0
        entry_redirects = 0
        for name, lines in parse_blocks(probe_ir).items():
            if ".bcf.fake" not in name:
                continue
            stores = dict(
                (slot, int(value) & mask)
                for value, slot in STATE_STORE.findall("\n".join(lines))
            )
            if "switchVar" not in stores or "switchXor" not in stores:
                continue
            bcf_count += 1
            if (stores["switchVar"] ^ stores["switchXor"]) in entry_states:
                entry_redirects += 1

        if bcf_count == 0:
            print("FAIL: no flattened .bcf.fake exits found", file=sys.stderr)
            return 1
        if entry_redirects:
            print(f"FAIL: {entry_redirects}/{bcf_count} .bcf.fake exits restart "
                  f"at the flattening entry state", file=sys.stderr)
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

    print(f"bcf/fla dispatcher integration: ok ({bcf_count} .bcf.fake "
          f"exits preserved, runtime matches native)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
