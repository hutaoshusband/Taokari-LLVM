"""Verify randomizeSections never assigns custom sections to thread-local globals.

A thread_local global with an explicit section is emitted as a TLS section
with that name; ld requires all TLS sections adjacent to .tbss, so a local
TLS global renamed to .data.<digest> made max-protected binaries fail at
link time ("TLS sections are not adjacent"). randomizeSections now skips
thread-local globals; this verifier pins the contract with local-linkage
TLS globals under max protection.

Contract:
  * Config A: TLS fixture -> object with -mllvm -taokari-max
    -mllvm -taokari-max-no-vmp, 3 fresh compiles; rc 0.
  * Config B: same fixture linked + run (plain vs max), stdout equal.

Exit:
  0 + "tls section randomization: ok"
  1 -- link or output failure
  2 -- missing clang
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

ROOT = tp.ROOT
CLANG = tp.CLANG
VSDEVCMD = tp.VSDEVCMD
EXE = tp.EXE

TLS_SRC = """#include <stdio.h>
static __thread unsigned counter;
static __thread const char *label = "tls";
__attribute__((noinline)) static void bump(void) { counter += 2; }
int main(void) {
  bump();
  bump();
  printf("tls:%u:%s\\n", counter, label);
  return counter == 4 ? 0 : 1;
}
"""


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

    with tempfile.TemporaryDirectory(prefix="taokari-tls-sec-") as tmp:
        d = Path(tmp)
        src = d / "tls.c"
        src.write_text(TLS_SRC, encoding="utf-8")
        base = ["-O2", "-std=c17", "-fdeclspec", "-D_GNU_SOURCE"]
        max_flags = ["-mllvm", "-taokari-max", "-mllvm", "-taokari-max-no-vmp"]

        plain = d / f"plain{EXE}"
        r = run([str(CLANG), *base, str(src), "-o", str(plain)])
        if r.returncode or not plain.exists():
            print(f"  [FAIL] plain build rc={r.returncode}: {r.stderr[:300]}", file=sys.stderr)
            return 1
        want = run([str(plain)])
        if want.returncode:
            print(f"  [FAIL] plain run rc={want.returncode}", file=sys.stderr)
            return 1

        for i in range(3):
            exe = d / f"max_{i}{EXE}"
            r = run([str(CLANG), *base, *max_flags, str(src), "-o", str(exe)])
            if r.returncode or not exe.exists():
                print(f"  [FAIL] max link {i}: rc={r.returncode}: {r.stderr[:300]}", file=sys.stderr)
                return 1
            r = run([str(exe)])
            if r.returncode or r.stdout.strip() != want.stdout.strip():
                print(f"  [FAIL] max run {i}: rc={r.returncode} out={r.stdout.strip()!r} "
                      f"want={want.stdout.strip()!r}", file=sys.stderr)
                return 1
        print("  [ok] 3/3 max TLS links and runs match plain")

    print("tls section randomization: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
