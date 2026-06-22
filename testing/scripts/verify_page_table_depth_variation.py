"""Verify page-table depth no longer stays fixed at 1 or level."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from verify_page_table_fake_ratio import (
    BRANCH_SOURCE,
    CALL_SOURCE,
    CLANG,
    GLOBAL_SOURCE,
    must,
    run,
)


ROOT = Path(__file__).resolve().parents[2]
UTILS = ROOT / "upstream" / "taokari" / "llvm" / "lib" / "Transforms" / "Obfuscation" / "Utils.cpp"
SOURCES = [
    ROOT / "upstream" / "taokari" / "llvm" / "lib" / "Transforms" / "Obfuscation" / "IndirectBranch.cpp",
    ROOT / "upstream" / "taokari" / "llvm" / "lib" / "Transforms" / "Obfuscation" / "IndirectCall.cpp",
    ROOT / "upstream" / "taokari" / "llvm" / "lib" / "Transforms" / "Obfuscation" / "IndirectGlobalVariable.cpp",
    ROOT / "upstream" / "taokari" / "llvm" / "lib" / "Transforms" / "Obfuscation" / "StringEncryption.cpp",
]
GLOBAL_RE = re.compile(r"^@(?P<name>[^\s=]+)\s*=", re.M)


STRING_SOURCE = r'''
static const char *secret = "taokari-depth-secret";
int main(void) { return secret[0]; }
'''


def count_tables(ir: str, marker: str) -> int:
  return len({
      match.group("name")
      for match in GLOBAL_RE.finditer(ir)
      if marker in match.group("name")
  })


def compile_ir(tmp: Path, name: str, source: str, flags: list[str]) -> str:
  src = tmp / f"{name}.c"
  src.write_text(source, encoding="utf-8")
  out = tmp / f"{name}.ll"
  cmd = [
      str(CLANG), "-x", "c", str(src), "-O0", "-Xclang",
      "-disable-O0-optnone", "-S", "-emit-llvm", "-o", str(out),
      *flags,
  ]
  must(run(cmd, tmp), f"{name} IR build")
  return out.read_text(encoding="utf-8", errors="ignore")


def verify_static() -> None:
  utils = UTILS.read_text(encoding="utf-8", errors="ignore")
  if "choosePageTableDepth" not in utils or "chooseModulePageTableDepth" not in utils:
    raise SystemExit("missing page-table depth helpers")
  if "pageMaskNibble" not in utils:
    raise SystemExit("missing safe mask nibble helper")
  if re.search(r">>\s*\(\w+\s*\*\s*4\)", utils):
    raise SystemExit("raw page-mask shift still present")

  for source in SOURCES:
    text = source.read_text(encoding="utf-8", errors="ignore")
    if re.search(r"\.CountLoop\s*=\s*1\s*;", text):
      raise SystemExit(f"{source.name}: fixed module depth remains")
  for source in SOURCES[:3]:
    text = source.read_text(encoding="utf-8", errors="ignore")
    if re.search(r"\.CountLoop\s*=\s*opt\.level\(\)\s*;", text):
      raise SystemExit(f"{source.name}: fixed function depth remains")
    if "FuncPageDepth = choosePageTableDepth" not in text:
      raise SystemExit(f"{source.name}: missing randomized function depth")
    if "buildDecrypt.FuncLoopCount = FuncPageDepth;" not in text:
      raise SystemExit(f"{source.name}: decrypt depth not wired")


def verify_indirect_depths(tmp: Path) -> None:
  cases = [
      ("indbr", BRANCH_SOURCE, [
          "-mllvm", "-taokari", "-mllvm", "-taokari-indbr",
          "-mllvm", "-taokari-level-indbr=3",
      ], "_IndirectBr_page_table_", "_IndirectBr_enhanced_page_table_"),
      ("icall", CALL_SOURCE, [
          "-mllvm", "-taokari", "-mllvm", "-taokari-icall",
          "-mllvm", "-taokari-level-icall=3",
      ], "_IndirectCallee_page_table_", "_IndirectCallee_enhanced_page_table_"),
      ("indgv", GLOBAL_SOURCE, [
          "-mllvm", "-taokari", "-mllvm", "-taokari-indgv",
          "-mllvm", "-taokari-level-indgv=3",
      ], "_IndirectGVs_page_table_", "_IndirectGVs_enhanced_page_table_"),
  ]
  observed: list[int] = []
  for name, source, flags, module_marker, func_marker in cases:
    module_depths: list[int] = []
    func_depths: list[int] = []
    for i in range(4):
      ir = compile_ir(tmp, f"{name}_{i}", source, flags)
      module_depths.append(count_tables(ir, module_marker))
      func_depths.append(count_tables(ir, func_marker))
    if any(depth < 2 or depth > 6 for depth in module_depths):
      raise SystemExit(f"{name}: module depth outside 2..6: {module_depths}")
    if any(depth < 2 or depth > 5 for depth in func_depths):
      raise SystemExit(f"{name}: function depth outside level-3 range: {func_depths}")
    observed.extend(module_depths + func_depths)
  if len(set(observed)) < 2:
    raise SystemExit(f"page-table depths did not vary: {observed}")


def verify_string_depth(tmp: Path) -> None:
  cfg = tmp / "strenc.json"
  cfg.write_text(
      json.dumps({"cse": {
          "enable": True,
          "level": 3,
          "stringPageTableAccess": True,
      }}),
      encoding="utf-8",
  )
  ir = compile_ir(tmp, "strenc", STRING_SOURCE, [
      "-mllvm", "-taokari", "-mllvm", "-taokari-cse",
      "-mllvm", f"-taokari-cfg={cfg}",
  ])
  depth = count_tables(ir, "_StringPools_page_table_")
  if depth < 2 or depth > 6:
    raise SystemExit(f"strenc: module depth outside 2..6: {depth}")


def main() -> int:
  if not CLANG.exists():
    print(f"missing clang: {CLANG}", file=sys.stderr)
    return 2
  verify_static()
  tmp = Path(tempfile.mkdtemp(prefix="taokari-pt-depth-"))
  try:
    verify_indirect_depths(tmp)
    verify_string_depth(tmp)
  finally:
    shutil.rmtree(tmp, ignore_errors=True)
  print("verify_page_table_depth_variation: ok")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
