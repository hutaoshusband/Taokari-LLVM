"""Verify page-table integrity guards vary their trap intrinsic."""
from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

from verify_page_table_fake_ratio import BRANCH_SOURCE, CLANG, must, run


TRAPS = ("llvm.trap", "llvm.debugtrap", "llvm.ubsantrap")


def main() -> int:
  if not CLANG.exists():
    print(f"missing clang: {CLANG}", file=sys.stderr)
    return 2

  tmp = Path(tempfile.mkdtemp(prefix="taokari-trap-family-"))
  try:
    src = tmp / "indbr.c"
    src.write_text(BRANCH_SOURCE, encoding="utf-8")
    seen: set[str] = set()
    for i in range(8):
      ll = tmp / f"indbr_{i}.ll"
      cmd = [
          str(CLANG), "-x", "c", str(src), "-O0", "-Xclang",
          "-disable-O0-optnone", "-S", "-emit-llvm", "-o", str(ll),
          "-mllvm", "-taokari", "-mllvm", "-taokari-indbr",
          "-mllvm", "-taokari-level-indbr=2",
      ]
      must(run(cmd, tmp), f"indbr IR build {i}")
      ir = ll.read_text(encoding="utf-8", errors="ignore")
      seen.update(trap for trap in TRAPS if trap in ir)
  finally:
    shutil.rmtree(tmp, ignore_errors=True)

  if len(seen) < 2:
    raise SystemExit(f"trap family stayed fixed: {sorted(seen)}")

  print("verify_page_table_trap_family: ok")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
