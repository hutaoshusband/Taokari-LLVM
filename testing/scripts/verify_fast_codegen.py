"""Fast iteration preserves IR/MIR protection and supports large spill frames."""
from __future__ import annotations

from pathlib import Path
import re
import struct
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp
from _mir_signatures import DIRTY_VARIANTS, JUNK, SUB_VARIANTS


FAST = ["-mllvm", "-optimize-regalloc=0", "-mllvm", "-disable-peephole",
        "-mllvm", "-disable-branch-fold", "-mllvm", "-disable-block-placement",
        "-Wl,/STACK:16777216"]
SOURCE = r'''
#include <stdio.h>
__attribute__((noinline)) static void touch(volatile unsigned char *p, unsigned n) {
  p[0] = 7;
  p[n - 1] = 11;
}
int main(int argc, char **argv) {
  volatile unsigned char pad[1200064];
  unsigned n = 1200000u + ((unsigned)argc & 63u);
  touch(pad, n);
  printf("fast-stack-probe:%u:%u:%u\n", pad[0], pad[n - 1], n);
  return 0;
}
'''


def checked(command: list[str], *, vs: bool = False):
    result = tp.run(command, vs=vs)
    if result.returncode:
        raise RuntimeError(f"exit {result.returncode}: {' '.join(command)}\n"
                           f"{result.stdout}{result.stderr}")
    return result


def main() -> int:
    if not tp.IS_WINDOWS or not tp.CLANG.exists():
        print("requires Windows clang", file=sys.stderr)
        return 2
    for recipe in ("build_strong.bat", "build_max_protection.bat"):
        text = (tp.ROOT / recipe).read_text(encoding="utf-8")
        match = re.search(r'if "%TAOKARI_FAST_CODEGEN%"=="1" set "CODEGEN_FLAGS=(.*)"', text)
        assert match and match.group(1).split() == FAST, f"fast recipe drift: {recipe}"
    with tempfile.TemporaryDirectory(prefix="taokari-fast-codegen-") as tmp:
        work = Path(tmp)
        src = work / "stack.c"
        src.write_text(SOURCE, encoding="utf-8")
        native = work / "native.exe"
        checked([str(tp.CLANG), str(src), "-O2", "-Wl,/STACK:16777216",
                 "-o", str(native)], vs=True)
        inputs = ([], ["one"], ["one", "two"])
        expected = [checked([str(native), *args]).stdout for args in inputs]
        frozen = work / "frozen.ll"
        checked([str(tp.CLANG), str(src), "-O2", "-S", "-emit-llvm",
                 "-mllvm", "-taokari-fla", "-mllvm", "-taokari-level-fla=4",
                 "-mllvm", "-taokari-cse", "-o", str(frozen)], vs=True)
        text = frozen.read_text(encoding="utf-8")
        assert "EncryptedStringTable" in text, "IR protection did not run"
        assert "[1200064 x i8]" in text, "large-stack trigger was optimized away"
        for name, flags in (("normal", ["-Wl,/STACK:16777216"]), ("fast", FAST)):
            exe = work / f"{name}.exe"
            start = time.monotonic()
            checked([str(tp.CLANG), str(frozen), "-O2", "-Xclang", "-disable-llvm-passes",
                     "-mllvm", "-taokari", "-mllvm", "-taokari-mir=dirtybytes,junk,sub",
                     "-mllvm", "-taokari-mir-dirtybytes-prob=100",
                     "-mllvm", "-taokari-mir-junk-prob=100",
                     "-mllvm", "-taokari-mir-sub-prob=100",
                     *flags, "-o", str(exe)], vs=True)
            for args, ref in zip(inputs, expected):
                assert checked([str(exe), *args]).stdout == ref, f"{name} output mismatch"
            blob = exe.read_bytes()
            assert b"fast-stack-probe:" not in blob, "plaintext leak"
            assert JUNK in blob and any(s in blob for s in DIRTY_VARIANTS)
            assert any(s in blob for s in SUB_VARIANTS), "MIR protection lost"
            pe = struct.unpack_from("<I", blob, 0x3c)[0]
            assert struct.unpack_from("<H", blob, pe + 24)[0] == 0x20b
            assert struct.unpack_from("<Q", blob, pe + 24 + 72)[0] == 16777216
            print(f"fast codegen: {name}: {time.monotonic() - start:.2f}s, "
                  "native output, IR/MIR protection and large stack ok", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
