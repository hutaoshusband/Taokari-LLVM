"""Verify CIE pool serialization reserves ceil(width/8) bytes for odd widths.

C23 _BitInt(N) produces odd-width ConstantInt operands (e.g. i13). The CIE
pool serialized BitWidth/8 bytes per entry (floor) while the pool load reads
ceil(width/8) bytes: an i13 entry got 1 byte and its 2-byte load consumed a
neighbor's byte (or ran past the pool). Miscompiled constants under NDEBUG,
no trap on assert builds - silence made it invisible.

Contract:
  * Config A: `void sink(_BitInt(13)); int main(){ sink(3000); }` at
    -std=c23 -O0 -mllvm -taokari-cie -mllvm -taokari-level-cie=3, 3 fresh
    compiles, rc 0, stdout matches plain.
  * Config B: same at -taokari-level-cie=4.
  * IR tripwire (RNG-immune): the emitted cie pool must be
    `[6 x i8]` (ceil(13/8) + 4 for the i32 entry); pre-fix it is `[5 x i8]`.

Exit:
  0 + "cie bitint odd width: ok"
  1 -- compile, pool-shape, or output mismatch
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

SRC_IR = ("void sink(_BitInt(13) v) {}\n"
          "int main(void) { sink(3000); return 0; }\n")
SRC_RUN = ("#include <stdio.h>\n"
           "static _BitInt(13) got;\n"
           "void sink(_BitInt(13) v) { got = v; }\n"
           "int main(void) { sink(3000); printf(\"bitint:%d\\n\", (int)got); "
           "return got == 3000 ? 0 : 1; }\n")


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

    with tempfile.TemporaryDirectory(prefix="taokari-cie-bitint-") as tmp:
        d = Path(tmp)
        src_ir = d / "bitint_ir.c"
        src_ir.write_text(SRC_IR, encoding="utf-8")
        src = d / "bitint_run.c"
        src.write_text(SRC_RUN, encoding="utf-8")

        base = ["-std=c23", "-mllvm", "-taokari-cie"]
        for level in ("3", "4"):
            for i in range(3):
                ir = d / f"obf_{level}_{i}.ll"
                r = run([str(CLANG), "-O0", *base, "-mllvm", f"-taokari-level-cie={level}",
                         "-S", "-emit-llvm", str(src_ir), "-o", str(ir)])
                if r.returncode or not ir.exists():
                    print(f"  [FAIL] L{level} compile {i}: rc={r.returncode}: {r.stderr[:300]}",
                          file=sys.stderr)
                    return 1
                text = ir.read_text(encoding="utf-8")
                pool = [ln for ln in text.splitlines() if "cie.pool = private unnamed_addr constant" in ln]
                if not pool:
                    print(f"  [FAIL] L{level} compile {i}: no cie.pool in IR", file=sys.stderr)
                    return 1
                if "[6 x i8]" not in pool[0]:
                    print(f"  [FAIL] L{level} compile {i}: pool is not [6 x i8]: {pool[0].strip()}",
                          file=sys.stderr)
                    return 1
            print(f"  [ok] L{level}: pool reserves ceil(13/8)+4 bytes x3 compiles")

        plain = d / "plain.exe"
        r = run([str(CLANG), "-O0", "-std=c23", str(src), "-o", str(plain)])
        if r.returncode or not plain.exists():
            print(f"  [FAIL] plain build rc={r.returncode}", file=sys.stderr)
            return 1
        want = run([str(plain)])
        if want.returncode:
            print(f"  [FAIL] plain run rc={want.returncode}", file=sys.stderr)
            return 1
        for i in range(3):
            exe = d / f"obf_{i}.exe"
            r = run([str(CLANG), "-O0", *base, "-mllvm", "-taokari-level-cie=3", str(src), "-o", str(exe)])
            if r.returncode or not exe.exists():
                print(f"  [FAIL] L3 link {i}: rc={r.returncode}", file=sys.stderr)
                return 1
            r = run([str(exe)])
            if r.returncode or r.stdout.strip() != want.stdout.strip():
                print(f"  [FAIL] L3 run {i}: rc={r.returncode} out={r.stdout.strip()!r}",
                      file=sys.stderr)
                return 1
        print("  [ok] L3 runs match plain x3")

    print("cie bitint odd width: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
