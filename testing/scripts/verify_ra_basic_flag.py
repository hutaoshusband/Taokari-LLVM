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

OFF = ["-mllvm", "-taokari-ra-basic=0"]
GREEDY = ["-mllvm", "-regalloc=greedy"]


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


def backend_obj(clang_args: list[str], frozen: Path, tag: str, tmp: Path) -> Path:
    obj = tmp / f"ra_basic_{tag}{tp.OBJ}"
    built = run([str(CLANG), str(frozen), "-O2", "-Xclang",
                 "-disable-llvm-passes", *clang_args, "-c", "-o", str(obj)])
    must(built, f"compile {tag}")
    return obj


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

        # Contract: with obfuscation active the optimized-codegen allocator
        # defaults to RABasic; -taokari-ra-basic=0 restores greedy; an explicit
        # -regalloc= still wins; plain non-obfuscated codegen is untouched by
        # the default. Frozen IR keeps every compile backend-identical up to
        # the allocator.
        objs = {}
        for tag, extra in (("obf_def1", OBF), ("obf_def2", OBF),
                           ("obf_off", [*OBF, *OFF]),
                           ("obf_greedy", [*OBF, *GREEDY]),
                           ("plain_def", []), ("plain_off", OFF),
                           ("plain_on", ["-mllvm", "-taokari-ra-basic"])):
            objs[tag] = backend_obj(extra, frozen, tag, tmp)

        for a, b, must_differ, why in (
            ("obf_def1", "obf_def2", False, "backend not self-consistent (default objects differ)"),
            ("obf_def1", "obf_off", True, "obfuscated default object identical to ra-basic=0 (allocator unchanged?)"),
            ("obf_off", "obf_greedy", False, "-regalloc=greedy object differs from ra-basic=0 (override lost?)"),
            ("plain_def", "plain_off", False, "plain default object differs from plain ra-basic=0"),
            ("plain_def", "plain_on", False, "plain default object differs from plain ra-basic=1"),
        ):
            da, db = content_digest(objs[a]), content_digest(objs[b])
            if (da == db) == must_differ:
                raise SystemExit(why)

        must(run([str(CLANG), str(src), "-O2", "-std=c17",
                  "-o", str(tmp / tp.exe_name("ra_basic_plain"))]), "build plain")
        plain = ""
        for tag in ("obf_def1", "obf_off"):
            exe = tmp / tp.exe_name(f"ra_basic_{tag}")
            must(run([str(CLANG), str(objs[tag]), "-o", str(exe)]), f"link {tag}")
            ran = run([str(exe)])
            must(ran, f"run {tag}")
            if plain and ran.stdout != plain:
                raise SystemExit(f"output mismatch: {tag} {ran.stdout!r} != {plain!r}")
            plain = ran.stdout
        ran = run([str(tmp / tp.exe_name("ra_basic_plain"))])
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
