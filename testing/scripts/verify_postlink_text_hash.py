from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp
from taokari_postlink_hash import (MAGIC, patch, pe_sections, pick_section,
                                   sections_of, verify)


ROOT = tp.ROOT
CLANG = tp.CLANG


SOURCE = r"""
#include <cstdio>

__attribute__((noinline))
__attribute__((annotate("+nativeint")))
static int guarded(int x) { return (x * 3) ^ 0x55; }

int main() {
  std::printf("postlink:%d\n", guarded(9));
  return 0;
}
"""


def must(result: subprocess.CompletedProcess[str], label: str) -> None:
    if result.returncode:
        print(result.stdout, end="")
        print(result.stderr, end="", file=sys.stderr)
        raise SystemExit(f"{label} failed: {result.returncode}")


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2
    tmp = Path(tempfile.mkdtemp(prefix="taokari-postlink-"))
    try:
        src = tmp / "postlink.cpp"
        exe = tmp / tp.exe_name("postlink")
        src.write_text(SOURCE, encoding="utf-8")
        must(tp.run([str(CLANG), str(src), "-O2", "-std=c++17",
                     *(["-fdeclspec"] if not tp.IS_WINDOWS else []),
                     "-mllvm", "-taokari", "-o", str(exe)], vs=True), "build")
        data = exe.read_bytes()
        if data.count(MAGIC) != 1:
            raise SystemExit("post-link text hash slot missing or duplicated")
        try:
            verify(exe, ".text")
        except ValueError:
            pass
        else:
            raise SystemExit("unpatched binary verified unexpectedly")
        patch(exe, ".text")
        verify(exe, ".text")
        clean = tp.run([str(exe)])
        must(clean, "patched run")
        if clean.stdout != "postlink:78\n":
            raise SystemExit(f"output drift: {clean.stdout!r}")
        tampered = tmp / tp.exe_name("postlink_tampered")
        shutil.copy2(exe, tampered)
        patched = bytearray(tampered.read_bytes())
        text = pick_section(sections_of(patched)[0], ".text")
        if text.raw_size < 16:
            raise SystemExit(".text too small")
        patched[text.raw_ptr + 8] ^= 1
        tampered.write_bytes(patched)
        try:
            verify(tampered, ".text")
        except ValueError:
            pass
        else:
            raise SystemExit("tampered .text verified unexpectedly")
        print("post-link text hash verifier: ok")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
