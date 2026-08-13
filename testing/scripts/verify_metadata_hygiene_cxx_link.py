"""Link C++ EH + std::string under metadata hygiene L3.

Max and meta L3 used to emit a strong `std::exception` vftable by pulling
private associative COMDAT members into unique sections, so the object
conflicted with libvcruntime (LNK2005). This gate compiles the same
shape native vs protected and requires a clean link plus matching output.

Exit: 0 ok | 1 compile/link/mismatch | 2 missing clang++
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp


CLANGXX = tp.tool("clang++")

SOURCE = r"""
#include <cstdio>
#include <string>

__attribute__((noinline)) int run(int seed) {
  std::string s = seed & 2 ? "meta-yes" : "meta-no";
  int acc = (int)s.size();
  try {
    if ((seed & 7) == 3)
      throw seed;
    acc ^= seed * 11 + 5;
  } catch (int v) {
    acc ^= v ^ (int)s.size();
  }
  return acc;
}

int main() {
  std::printf("meta-cxx:%d:%d:%d\n", run(1), run(3), run(8));
  return 0;
}
"""


def main() -> int:
    if not CLANGXX.exists():
        print(f"missing clang++: {CLANGXX}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-meta-cxx-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "meta_cxx.cpp"
        src.write_text(SOURCE, encoding="utf-8")
        cfg = tmp / "meta.json"
        cfg.write_text(json.dumps({
            "randomSeed": "taokari-meta-cxx-link-seed!!",
            "meta": {
                "enable": True,
                "level": 3,
                "releaseStrip": True,
                "randomizeSections": True,
            },
        }), encoding="utf-8")

        native = tmp / f"native{tp.EXE}"
        protected = tmp / f"obf{tp.EXE}"
        nbuild = tp.run(
            [str(CLANGXX), str(src), "-O2", "-std=c++17", "-o", str(native)],
            vs=True,
        )
        if nbuild.returncode:
            sys.stderr.write(nbuild.stdout + nbuild.stderr)
            return 1
        pbuild = tp.run(
            [str(CLANGXX), str(src), "-O2", "-std=c++17", "-o", str(protected),
             "-mllvm", "-taokari", "-mllvm", "-taokari-meta",
             "-mllvm", "-taokari-level-meta=3",
             "-mllvm", f"-taokari-cfg={cfg}"],
            vs=True,
        )
        if pbuild.returncode:
            sys.stderr.write(pbuild.stdout + pbuild.stderr)
            return 1
        nrun = tp.run([str(native)])
        prun = tp.run([str(protected)])
        if nrun.returncode != prun.returncode or nrun.stdout != prun.stdout:
            print(
                f"FAIL: mismatch native={nrun.stdout!r} obf={prun.stdout!r} "
                f"rc={nrun.returncode}/{prun.returncode}",
                file=sys.stderr,
            )
            return 1

    print(f"metadata hygiene cxx link: ok {nrun.stdout.strip()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
