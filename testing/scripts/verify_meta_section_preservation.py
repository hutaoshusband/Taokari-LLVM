"""Verify randomizeSections preserves explicit user sections (constructor idioms).

randomizeSections (MetadataHygiene) re-sectioned every local non-comdat
non-TLS object, including ones the user placed by hand with
__attribute__((section(".init_array"))) (ELF) or section(".CRT$XCU")
(PE/COFF). Overwriting those sections silently deregisters load-time
constructors: a plain build prints ctor:1 while a -taokari-max build
printed ctor:0 with the ctor pointer moved to .data.<digest>. The pass
must skip every object that already has an explicit section;
randomization stays active for everything else (normal builds emit zero
section-attributed IR objects, so nothing is lost).

Contract:
  * Config A: .CRT$XCU/.init_array ctor fixture, plain vs
    -mllvm -taokari-max -mllvm -taokari-max-no-vmp, 3 fresh compiles;
    the constructor must run in both (stdout ctor:1, rc 0, equal).
  * Config B: each max OBJECT keeps the ctor section name verbatim in
    the section table (byte grep, COFF inline names / ELF .shstrtab).
  * Config C (over-skip guard): each max object still gains randomized
    .data$<digest8> / .data.<digest8> sections, i.e. the fix must not
    disable randomizeSections.

Exit:
  0 + "meta section preservation: ok"
  1 -- compile/link/run/section mismatch
  2 -- missing clang
"""
from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

CLANG = tp.CLANG
EXE = tp.EXE
OBJ = tp.OBJ
CTOR_SEC = b".CRT$XCU" if tp.IS_WINDOWS else b".init_array"
MAX_FLAGS = ["-mllvm", "-taokari-max", "-mllvm", "-taokari-max-no-vmp"]

SRC = """#include <stdio.h>
static unsigned ctor_ran;
#if defined(_WIN32)
#define CTOR_SEC ".CRT$XCU"
#else
#define CTOR_SEC ".init_array"
#endif
static int ctor(void) { ctor_ran = 1; return 0; }
__attribute__((section(CTOR_SEC), used)) static int (*ctor_p)(void) = ctor;
int main(void) { printf("ctor:%u", ctor_ran); putchar(10); return ctor_ran ? 0 : 1; }
"""


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-meta-sec-") as tmp:
        d = Path(tmp)
        src = d / "ctor.c"
        src.write_text(SRC, encoding="utf-8")
        base = ["-O2", "-std=c17"]

        plain = d / f"plain{EXE}"
        r = tp.run([str(CLANG), *base, str(src), "-o", str(plain)], vs=True)
        if r.returncode or not plain.exists():
            print(f"  [FAIL] plain build rc={r.returncode}: {r.stderr[:300]}", file=sys.stderr)
            return 1
        want = tp.run([str(plain)])
        if want.returncode or want.stdout.strip() != "ctor:1":
            print(f"  [FAIL] plain run rc={want.returncode} out={want.stdout.strip()!r}", file=sys.stderr)
            return 1

        for i in range(3):
            exe = d / f"max_{i}{EXE}"
            obj = d / f"max_{i}{OBJ}"
            r = tp.run([str(CLANG), *base, *MAX_FLAGS, "-c", str(src), "-o", str(obj)], vs=True)
            if r.returncode or not obj.exists():
                print(f"  [FAIL] max compile {i}: rc={r.returncode}: {r.stderr[:300]}", file=sys.stderr)
                return 1
            table = obj.read_bytes()
            if CTOR_SEC not in table:
                print(f"  [FAIL] max object {i}: {CTOR_SEC.decode()} section lost to randomizeSections",
                      file=sys.stderr)
                return 1
            if not re.search(rb"\.data[$.][0-9a-f]{8}", table):
                print(f"  [FAIL] max object {i}: no randomized .data sections; randomizeSections inert",
                      file=sys.stderr)
                return 1
            r = tp.run([str(CLANG), *base, *MAX_FLAGS, str(src), "-o", str(exe)], vs=True)
            if r.returncode or not exe.exists():
                print(f"  [FAIL] max link {i}: rc={r.returncode}: {r.stderr[:300]}", file=sys.stderr)
                return 1
            r = tp.run([str(exe)])
            if r.returncode or r.stdout.strip() != want.stdout.strip():
                print(f"  [FAIL] max run {i}: rc={r.returncode} out={r.stdout.strip()!r} "
                      f"want={want.stdout.strip()!r}", file=sys.stderr)
                return 1
        print("  [ok] 3/3 max builds ran the ctor; ctor section preserved; randomization active")

    print("meta section preservation: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
