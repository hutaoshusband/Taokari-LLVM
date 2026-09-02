"""Verify opaque-constant skips integer constants wider than 64 bits.

The transform stores the constant into an i64 pool entry and truncs the
decrypted i64 back to the operand type, so >64-bit ConstantInt operands are
unsupported. Pre-fix, ANY i128 constant hit one of two asserts on the
assert-enabled build (APInt.h:1544 "Too many bits for uint64_t" when the
value needs >64 bits via getZExtValue, Instructions.cpp:3040 "Invalid cast!"
when CreateTrunc tries i64 -> i128) and NDEBUG builds miscompiled (the trunc
substitutes a wrong value).

Contract:
  * Sources containing i128 constants (wide-valued and narrow-valued) compile
    cleanly with -taokari-ocnst -taokari-ocnst-prob=100 at -O0 and -O2,
    5 compiles per cell (the pass is RNG-driven; one lucky compile proves
    nothing), and every binary's stdout matches the plain baseline.
  * The wide fixture also survives one full -taokari-max -taokari-max-no-vmp
    build (ocnst is part of the max stack).

Exit: 0 ok | 1 contract failure | 2 missing clang.
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

WIDE = r"""
#include <stdio.h>
int main(void) {
  unsigned __int128 x = ((unsigned __int128)0x12345678ULL << 64) | 0x9abcdef012345678ULL;
  unsigned __int128 y = x * 3;
  unsigned __int128 z = x ^ (((unsigned __int128)0xfedcba98ULL << 64) | 0x76543210fedcba98ULL);
  unsigned long long a = (unsigned long long)(y >> 64), b = (unsigned long long)y;
  unsigned long long c = (unsigned long long)(z >> 64), d = (unsigned long long)z;
  printf("%016llx%016llx %016llx%016llx\n", a, b, c, d);
  return 0;
}
"""

NARROW = r"""
#include <stdio.h>
int main(void) {
  unsigned __int128 x = 5;
  unsigned __int128 y = x * 3;
  printf("%llu\n", (unsigned long long)y);
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
                "@echo off" + chr(10)
                + "call " + chr(34) + str(VSDEVCMD) + chr(34)
                + " -arch=x64 -host_arch=x64 >nul" + chr(10)
                + subprocess.list2cmdline(command) + chr(10)
                + "exit /b %ERRORLEVEL%" + chr(10)
            )
        try:
            return subprocess.run(
                ["cmd.exe", "/d", "/c", str(batch)], cwd=cwd,
                text=True, capture_output=True,
            )
        finally:
            batch.unlink(missing_ok=True)
    return subprocess.run(command, cwd=cwd, text=True, capture_output=True)


def mllvm(flags: list[str]) -> list[str]:
    out = []
    for f in flags:
        out += ["-mllvm", f]
    return out


def fail(msg: str) -> int:
    print("ocnst-wide-constant: FAIL (" + msg + ")", file=sys.stderr)
    return 1


def main() -> int:
    if not CLANG.exists():
        print("missing clang: " + str(CLANG), file=sys.stderr)
        return 2

    fixtures = [("wide", WIDE), ("narrow", NARROW)]
    compiles = 5
    with tempfile.TemporaryDirectory(prefix="taokari-ocnstwc-") as tmp_name:
        tmp = Path(tmp_name)
        for name, src_text in fixtures:
            src = tmp / ("ocnst_" + name + ".c")
            src.write_text(src_text, encoding="utf-8")
            for opt in ("O0", "O2"):
                plain = tmp / (name + "_" + opt + "_plain" + tp.EXE)
                r = run([str(CLANG), str(src), "-" + opt, "-o", str(plain)])
                if r.returncode:
                    return fail(name + " plain -" + opt + " build rc="
                                + str(r.returncode) + "\n" + r.stdout + r.stderr)
                prun = run([str(plain)])
                if prun.returncode:
                    return fail(name + " plain -" + opt + " run rc="
                                + str(prun.returncode))
                for i in range(compiles):
                    obf = tmp / (name + "_" + opt + "_" + str(i) + tp.EXE)
                    r = run([str(CLANG), str(src), "-" + opt,
                             *mllvm(["-taokari-ocnst",
                                     "-taokari-ocnst-prob=100"]),
                             "-o", str(obf)])
                    if r.returncode:
                        return fail(name + " -" + opt + " obf compile " + str(i)
                                    + " rc=" + str(r.returncode) + "\n"
                                    + r.stdout + r.stderr)
                    orun = run([str(obf)])
                    if orun.returncode or orun.stdout != prun.stdout:
                        return fail(name + " -" + opt + " run " + str(i)
                                    + " rc=" + str(orun.returncode) + " out="
                                    + repr(orun.stdout) + " expected="
                                    + repr(prun.stdout))

        wsrc = tmp / "ocnst_wide.c"
        maxobf = tmp / ("ocnst_wide_max" + tp.EXE)
        r = run([str(CLANG), str(wsrc), "-O0",
                 *mllvm(["-taokari-max", "-taokari-max-no-vmp"]),
                 "-o", str(maxobf)])
        if r.returncode:
            return fail("wide -taokari-max -taokari-max-no-vmp compile rc="
                        + str(r.returncode) + "\n" + r.stdout + r.stderr)
        mrun = run([str(maxobf)])
        plain0 = run([str(tmp / ("wide_O0_plain" + tp.EXE))])
        if mrun.returncode or mrun.stdout != plain0.stdout:
            return fail("max run rc=" + str(mrun.returncode) + " out="
                        + repr(mrun.stdout) + " expected="
                        + repr(plain0.stdout))

    print("ocnst-wide-constant: ok (" + str(len(fixtures)) + " fixtures x 2 "
          "opt levels x " + str(compiles) + " compiles match plain, max build "
          "matches)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
