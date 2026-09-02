"""Verify per-function nativeint annotations reach NativeIntegrity.

stripMetadata (MetadataHygiene) erased llvm.global.annotations under
-taokari-max / config releaseStrip BEFORE the annotation-consuming
passes ran, so readAnnotate() returned empty and the `-nativeint`
opt-out was silently ignored under bare -taokari-max (and nativeint
opt-in died under releaseStrip configs). MetadataHygiene must be
scheduled AFTER its annotation consumers (NativeIntegrity,
DynamicProtection).

Observable: NativeIntegrity stamps a fixed 16-byte magic into its
text-hash slot initializer (NativeIntegrity.cpp getTextHashSlot); the
bytes appear in any object in which at least one function got the
integrity check. Single-function objects make the check per-function
precise, and symbol renaming / section randomization cannot remove the
constant bytes.

Contract:
  * A: -nativeint + -taokari-max -taokari-max-no-vmp object: magic ABSENT.
  * B: -nativeint + plain -taokari object: magic ABSENT.
  * C: +nativeint + plain -taokari object: magic PRESENT.
  * D: no annotation + -taokari-max -taokari-max-no-vmp object: magic
       PRESENT (max coverage of unannotated functions must not regress).
  * E: +nativeint + -taokari-max -taokari-max-no-vmp object: magic PRESENT.
  * F: full program with -nativeint f under max-no-vmp builds and runs
       with rc 0 (no exit(86) false trip).
  * G: +mir + max-no-mir object: MIR marker PRESENT (the annotation opts
       the function back into the disabled layer; survives annotation
       stripping via the taokari-mir function attribute).
  * H: no annotation + max-no-mir: marker ABSENT.
  * I: -dyn + max + -taokari-dyn object: no dyn helpers (the opt-out
       annotation survives stripping; forced probability 0 = deterministic;
       the unannotated default draw is probabilistic and unasserted).
  Dyn per-function opt-in/out is probabilistic per compile and covered by
  the same reorder; it is asserted by the dynamic_protection gate instead.

Exit:
  0 + "nativeint annotation order: ok"
  1 -- contract violation
  2 -- missing clang
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

CLANG = tp.CLANG
EXE = tp.EXE
OBJ = tp.OBJ
MAGIC = bytes([0xB6, 0x4F, 0x41, 0x29, 0x17, 0xC3, 0x5A, 0xE8,
               0x91, 0x0D, 0xFA, 0x72, 0x4C, 0x2B, 0x80, 0x6E])
PLAINF = ["-mllvm", "-taokari"]
MAXF = ["-mllvm", "-taokari", "-mllvm", "-taokari-max",
        "-mllvm", "-taokari-max-no-vmp"]


def tu(ann: str) -> str:
    attr = f'__attribute__((annotate("{ann}"))) ' if ann else ""
    return (f"{attr}__attribute__((noinline)) int f(int x) "
            f"{{ return x * 3 + 1; }}\n")


PROG = """static __attribute__((annotate("-nativeint"))) int f(int x) { return x * 3 + 1; }
int main(void) { volatile int v = f(7); return v == 22 ? 0 : 1; }
"""

# (name, annotation, extra flags, magic expected)
CASES = [
    ("optout_max", "-nativeint", MAXF, False),
    ("optout_plain", "-nativeint", PLAINF, False),
    ("optin_plain", "+nativeint", PLAINF, True),
    ("plain_max", "", MAXF, True),
    ("optin_max", "+nativeint", MAXF, True),
]


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-nativeint-order-") as tmp:
        d = Path(tmp)
        bad = []
        for name, ann, flags, want in CASES:
            src = d / f"{name}.c"
            src.write_text(tu(ann), encoding="utf-8")
            obj = d / f"{name}{OBJ}"
            r = tp.run([str(CLANG), "-c", "-O2", "-std=c17", str(src),
                        "-o", str(obj), *flags], vs=True)
            if r.returncode or not obj.exists():
                print(f"  [FAIL] {name}: compile rc={r.returncode}: "
                      f"{r.stderr[:300]}", file=sys.stderr)
                return 1
            got = MAGIC in obj.read_bytes()
            if got != want:
                state = "applied" if got else "absent"
                contract = "required" if want else "ignored (annotation dead)"
                print(f"  [FAIL] {name}: nativeint {state} but {contract}",
                      file=sys.stderr)
                bad.append(name)

        MIR_MARKER = bytes([0x48, 0x8D, 0x40, 0x00])
        NOMIRF = MAXF + ["-mllvm", "-taokari-max-no-mir"]
        DYNF = MAXF + ["-mllvm", "-taokari-dyn"]

        for name, ann, flags, helper_want in [
            ("dynout_max", "-dyn", DYNF, False),
        ]:
            src = d / f"{name}.c"
            src.write_text(tu(ann), encoding="utf-8")
            obj = d / f"{name}{OBJ}"
            r = tp.run([str(CLANG), "-c", "-O2", "-std=c17", str(src),
                        "-o", str(obj), *flags], vs=True)
            if r.returncode or not obj.exists():
                print(f"  [FAIL] {name}: compile rc={r.returncode}: "
                      f"{r.stderr[:300]}", file=sys.stderr)
                return 1
            got = b"__taokari_dyn_" in obj.read_bytes()
            if got != helper_want:
                print(f"  [FAIL] {name}: dyn helpers {'present' if got else 'absent'} "
                      f"but {'required' if helper_want else 'must be absent'} "
                      f"(dyn opt-out annotation dead under max)", file=sys.stderr)
                bad.append(name)

        for name, ann, flags, marker_want in [
            ("mirin_maxnomir", "+mir", NOMIRF, True),
            ("mirin_ctrl_maxnomir", "", NOMIRF, False),
        ]:
            src = d / f"{name}.c"
            src.write_text(tu(ann), encoding="utf-8")
            obj = d / f"{name}{OBJ}"
            r = tp.run([str(CLANG), "-c", "-O2", "-std=c17", str(src),
                        "-o", str(obj), *flags], vs=True)
            if r.returncode or not obj.exists():
                print(f"  [FAIL] {name}: compile rc={r.returncode}: "
                      f"{r.stderr[:300]}", file=sys.stderr)
                return 1
            got = MIR_MARKER in obj.read_bytes()
            if got != marker_want:
                print(f"  [FAIL] {name}: mir marker {'present' if got else 'absent'} "
                      f"but {'required' if marker_want else 'must be absent'} "
                      f"(mir annotation dead under max)", file=sys.stderr)
                bad.append(name)

        prog = d / "prog.c"
        prog.write_text(PROG, encoding="utf-8")
        exe = d / f"prog{EXE}"
        r = tp.run([str(CLANG), "-O2", "-std=c17", str(prog), "-o", str(exe),
                    *MAXF], vs=True)
        if r.returncode or not exe.exists():
            print(f"  [FAIL] runtime build rc={r.returncode}: "
                  f"{r.stderr[:300]}", file=sys.stderr)
            return 1
        run = tp.run([str(exe)])
        if run.returncode != 0:
            print(f"  [FAIL] runtime rc={run.returncode} out="
                  f"{run.stdout.strip()!r}", file=sys.stderr)
            return 1

        if bad:
            print(f"nativeint annotation order: FAIL ({', '.join(bad)})",
                  file=sys.stderr)
            return 1
    print("nativeint annotation order: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
