"""Verify page-table MBA add decryptors use more than one formula."""
from __future__ import annotations

import re
import shutil
import sys
import tempfile
from pathlib import Path
import _taokari_portable as tp

from verify_page_table_fake_ratio import BRANCH_SOURCE, CLANG, must, run


ROOT = Path(__file__).resolve().parents[2]
UTILS = (ROOT / "upstream" / "taokari" / "llvm" / "lib" / "Transforms" /
         "Obfuscation" / "Utils.cpp")
SHAPES = (".mba.carry", ".mba.sum", ".mba.not")


def verify_static() -> None:
  text = UTILS.read_text(encoding="utf-8", errors="ignore")
  if "Salt % 3" not in text:
    raise SystemExit("buildMBAAdd is not salt-selected")
  for shape in SHAPES:
    if shape not in text:
      raise SystemExit(f"missing MBA add shape {shape}")


def main() -> int:
  if not CLANG.exists():
    print(f"missing clang: {CLANG}", file=sys.stderr)
    return 2

  verify_static()
  tmp = Path(tempfile.mkdtemp(prefix="taokari-pt-mba-"))
  try:
    src = tmp / "indbr.c"
    src.write_text(BRANCH_SOURCE, encoding="utf-8")
    seen: set[str] = set()
    for i in range(8):
      ll = tmp / f"indbr_{i}.ll"
      cmd = [
          str(CLANG), "-x", "c", str(src), "-O0", "-Xclang",
          "-disable-O0-optnone", "-fno-discard-value-names",
          "-S", "-emit-llvm", "-o", str(ll),
          "-mllvm", "-taokari", "-mllvm", "-taokari-indbr",
          "-mllvm", "-taokari-level-indbr=2",
      ]
      must(run(cmd, tmp), f"indbr IR build {i}")
      ir = ll.read_text(encoding="utf-8", errors="ignore")
      seen.update(shape for shape in SHAPES
                  if f"taokari.ptr.decrypt{shape}" in ir)
  finally:
    shutil.rmtree(tmp, ignore_errors=True)

  if len(seen) < 2:
    raise SystemExit(f"page-table MBA add shape stayed fixed: {sorted(seen)}")

  print("verify_page_table_mba_add_variation: ok")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
