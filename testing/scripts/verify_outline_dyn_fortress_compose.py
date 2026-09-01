"""Full IR-obfuscation compose verifier.

Proves that the heaviest IR-layer combination still produces a correct binary:
function outlining (L3 callout fortress) + dynamic protection (L3) + flattening
+ BCF + MBA + indirect calls/branches/globals + string/constant encryption all
stacked on the same sensitive function. This is the combination a real
"fortress" build uses, so a green run here means the headline features compose
end-to-end without semantic drift.

Runs without a debugger attached, so the dynamic-protection check takes its
normal path (no false positive).
"""
from __future__ import annotations

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
#include <stdint.h>

static int64_t g_state = 0;

__attribute__((noinline, annotate("+outline^outline=3 +dyn^dyn=3")))
int64_t sensitive(int64_t a, int64_t b, int64_t c) {
    int64_t x = a * 17 + b;
    int64_t y = (x ^ 0x5a5a) - c;
    int64_t z = y + (a << 2);
    g_state = z;            /* side effect must survive every layer */
    return z + 9;
}

int main(void) {
    int64_t s = sensitive(13, 100, 7);
    /* x=321, y=321^0x5a5a-7=23311, z=23311+52=23363, ret=23372, g_state=23363 */
    printf("fortress:%lld:%lld\n", (long long)s, (long long)g_state);
    return 0;
}
"""


def run(command: list[str], *, cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    if VSDEVCMD.exists():
        with tempfile.NamedTemporaryFile("w", suffix=".cmd", delete=False, encoding="utf-8") as handle:
            batch = Path(handle.name)
            handle.write(
                "@echo off\n"
                f'call "{VSDEVCMD}" -arch=x64 -host_arch=x64 >nul\n'
                f"{subprocess.list2cmdline(command)}\n"
                "exit /b %ERRORLEVEL%\n"
            )
        try:
            return subprocess.run(["cmd.exe", "/d", "/c", str(batch)], cwd=cwd,
                                  text=True, capture_output=True)
        finally:
            batch.unlink(missing_ok=True)
    return subprocess.run(command, cwd=cwd, text=True, capture_output=True)


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    flags = [
        "-mllvm", "-taokari",
        # Callout fortress + dynamic protection (this session's headline passes).
        "-mllvm", "-taokari-outline",
        "-mllvm", "-taokari-dyn",
        # The rest of the IR stack at fortress-strength.
        "-mllvm", "-taokari-fla", "-mllvm", "-taokari-level-fla=2",
        "-mllvm", "-taokari-bcf", "-mllvm", "-taokari-level-bcf=2",
        "-mllvm", "-taokari-mba", "-mllvm", "-taokari-level-mba=2",
        "-mllvm", "-taokari-icall", "-mllvm", "-taokari-level-icall=2",
        "-mllvm", "-taokari-indbr", "-mllvm", "-taokari-level-indbr=2",
        "-mllvm", "-taokari-indgv", "-mllvm", "-taokari-level-indgv=2",
        "-mllvm", "-taokari-cse",
        "-mllvm", "-taokari-cie", "-mllvm", "-taokari-level-cie=2",
        "-mllvm", "-taokari-cfe", "-mllvm", "-taokari-level-cfe=2",
    ]

    with tempfile.TemporaryDirectory(prefix="taokari-compose-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "fortress.c"
        src.write_text(SOURCE, encoding="utf-8")

        obf = tmp / "fortress_obf.exe"
        res = run([str(CLANG), str(src), "-O2", "-fno-discard-value-names",
                   *flags, "-o", str(obf)])
        if res.returncode:
            print(res.stdout, end="")
            print(res.stderr, end="", file=sys.stderr)
            print("full compose failed to compile", file=sys.stderr)
            return res.returncode

        obf_run = run([str(obf)])
        if obf_run.returncode:
            print(f"full compose runtime failed (rc={obf_run.returncode}): "
                  f"{obf_run.stdout}{obf_run.stderr}", file=sys.stderr)
            return obf_run.returncode

        ref = tmp / "fortress_ref.exe"
        rres = run([str(CLANG), str(src), "-O2", "-o", str(ref)])
        if rres.returncode:
            print(rres.stderr, end="", file=sys.stderr)
            return rres.returncode
        ref_run = run([str(ref)])
        if obf_run.stdout != ref_run.stdout:
            print(f"full compose output drift:\n  obf: {obf_run.stdout!r}\n  "
                  f"ref: {ref_run.stdout!r}", file=sys.stderr)
            return 1

    print(f"fortress compose: ok ({obf_run.stdout.strip()})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
