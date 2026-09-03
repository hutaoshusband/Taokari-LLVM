from __future__ import annotations

import hashlib
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG

SOURCE = r"""
#include <stdio.h>

static unsigned mix(unsigned a, unsigned b) {
  unsigned x = a, y = b;
  for (int i = 0; i < 8; i++) {
    x = (x ^ y) * 0x9E3779B9u + (y << 3);
    y = (y + x) ^ (x >> 5) + i;
    x ^= x >> 7; y ^= y << 11;
  }
  return x ^ y;
}

static unsigned chain(unsigned v) {
  unsigned acc = v;
  for (int i = 0; i < 12; i++)
    acc = mix(acc, acc + i) ^ mix(acc << 1, i);
  return acc;
}

int main(void) {
  unsigned h = 0;
  for (unsigned i = 0; i < 24; i++)
    h = chain(h + i * 0x5bd1e995u);
  printf("ra-basic:%08x\n", h);
  return 0;
}
"""

OBF = ["-mllvm", "-taokari", "-mllvm", "-taokari-fla", "-mllvm", "-taokari-bcf",
       "-mllvm", "-taokari-mba", "-mllvm", "-taokari-indbr",
       "-mllvm", "-taokari-level-fla=4", "-mllvm", "-taokari-level-bcf=4",
       "-mllvm", "-taokari-level-mba=4", "-mllvm", "-taokari-level-indbr=4"]


def run(command: list[str], **kw) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, **kw)


def must(result: subprocess.CompletedProcess[str], label: str) -> None:
    if result.returncode:
        print(result.stdout, end="")
        print(result.stderr, end="", file=sys.stderr)
        raise SystemExit(f"{label} failed: {result.returncode}")


def content_digest(obj: Path) -> str:
    blob = bytearray(obj.read_bytes())
    if tp.IS_WINDOWS:
        blob[4:8] = b"\0\0\0\0"  #COFF TimeDateStamp is wall-clock, not codegen
    return hashlib.sha256(bytes(blob)).hexdigest()


def main() -> int:
    if not CLANG.exists():
        print(f"missing tool: {CLANG}", file=sys.stderr)
        return 2

    tmp = Path(tempfile.mkdtemp(prefix="taokari-ra-basic-"))
    try:
        src = tmp / "ra_basic.c"
        frozen = tmp / "ra_basic_frozen.ll"
        src.write_text(SOURCE, encoding="utf-8")
        must(run([str(CLANG), str(src), "-O2", "-std=c17", *OBF,
                  "-S", "-emit-llvm", "-o", str(frozen)]), "frozen IR emit")

        # Contract: with -taokari-ra-basic absent the optimized-codegen register
        # allocator (greedy) must be untouched; present, it must switch to
        # RABasic; an explicit -regalloc= still wins over the new flag. Frozen
        # IR keeps every compile backend-identical up to the allocator.
        objs = {}
        for tag, extra in (("off1", []), ("off2", []),
                           ("on", ["-mllvm", "-taokari-ra-basic"])):
            obj = tmp / f"ra_basic_{tag}{tp.OBJ}"
            built = run([str(CLANG), str(frozen), "-O2", "-Xclang",
                         "-disable-llvm-passes", *extra, "-c", "-o", str(obj)])
            must(built, f"compile {tag}")
            objs[tag] = obj

        if content_digest(objs["off1"]) != content_digest(objs["off2"]):
            raise SystemExit("backend not self-consistent (flag-off objects differ)")
        if content_digest(objs["off1"]) == content_digest(objs["on"]):
            raise SystemExit("flag-on object identical to flag-off (allocator unchanged?)")
        must(run([str(CLANG), str(frozen), "-O2", "-Xclang",
                  "-disable-llvm-passes", "-mllvm", "-taokari-ra-basic",
                  "-mllvm", "-regalloc=greedy", "-c",
                  "-o", str(tmp / f"ra_basic_override{tp.OBJ}")]),
             "-regalloc= override over the flag")

        exe_plain = tmp / tp.exe_name("ra_basic_plain")
        must(run([str(CLANG), str(src), "-O2", "-std=c17",
                  "-o", str(exe_plain)]), "build plain")
        plain = ""
        for tag in ("off1", "on"):
            exe = tmp / tp.exe_name(f"ra_basic_{tag}")
            must(run([str(CLANG), str(objs[tag]), "-o", str(exe)]), f"link {tag}")
            ran = run([str(exe)])
            must(ran, f"run {tag}")
            if plain and ran.stdout != plain:
                raise SystemExit(f"output mismatch: {tag} {ran.stdout!r} != {plain!r}")
            plain = ran.stdout
        ran = run([str(exe_plain)])
        must(ran, "run plain")
        if ran.stdout != plain:
            raise SystemExit(f"obfuscated output mismatch vs plain: {plain!r}")
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)

    print("ra basic flag: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
