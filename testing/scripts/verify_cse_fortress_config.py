"""CSE fortress-tier config verifier (TK-044).

docs/CONFIGURATION.md documents a fortress tier whose knob keys were all
mis-spelled (decryptorFlattening, shardedPool, ...) and whose tier never
fired from the level alone: every knob was gated `Fortress && knob`, so
`{cse:{enable:true,level:3}}` produced byte-identical output to level 2.
Asserts that:
  1. a level-3 cse config with NO knob keys emits the full fortress tier
     in -O0 IR (sharded pools, decoy pools, pool page table, indirect
     decryptor slots) -- the auto-enable,
  2. the real-spelling knob keys still compose explicitly, including at
     level 2 (CIE `knob || level>=3` precedent),
  3. an explicit `false` under level 3 is overridden (knob bits cannot
     distinguish explicit false from unset; documented),
  4. plain vs fortress build stdout is byte-identical,
  5. the fortress markers survive -O2 under -fno-discard-value-names.

Run against build/taokari-local/tmp_goal/tk031/clang-landing.exe to see the
pre-fix teeth: gate 1 fails because the dead tier emits no markers.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
VSDEVCMD = tp.VSDEVCMD

SEED = "tk044-cse-fortress-config-seed"

SOURCE = r"""
#include <stdio.h>

static const char *secret = "taokari-fortress-secret";
static const char *tag    = "cse";
volatile unsigned g_sink = 0;

__attribute__((noinline)) static int score(const char *s) {
  int acc = 0;
  for (const char *p = s; *p; ++p) {
    acc = acc * 131 + (unsigned char)*p;
  }
  return acc;
}

int main(void) {
  if (g_sink) {
    printf("%s\n", secret);
  }
  printf("cse-fortress:%s:%d:%d\n", tag, score(secret), score("plaintext"));
  return 0;
}
"""


def run(command: list[str], **kw) -> subprocess.CompletedProcess[str]:
  return subprocess.run(command, text=True, capture_output=True, **kw)


def run_vs(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
  if not tp.IS_WINDOWS:
    return subprocess.run(command, cwd=cwd, text=True, capture_output=True)
  with tempfile.NamedTemporaryFile("w", suffix=".cmd", delete=False,
                                   encoding="utf-8") as handle:
    batch = Path(handle.name)
    handle.write(
        "@echo off\n"
        f'call "{VSDEVCMD}" -arch=x64 -host_arch=x64 >nul\n'
        f"{subprocess.list2cmdline(command)}\n"
        "exit /b %ERRORLEVEL%\n"
    )
  try:
    return run(["cmd.exe", "/d", "/c", str(batch)], cwd=cwd)
  finally:
    batch.unlink(missing_ok=True)


def must(result: subprocess.CompletedProcess[str], label: str) -> None:
  if result.returncode:
    print(result.stdout, end="")
    print(result.stderr, end="", file=sys.stderr)
    raise SystemExit(f"{label} failed: {result.returncode}")


def gate(cond: bool, label: str) -> None:
  if not cond:
    raise SystemExit(f"GATE FAILED: {label}")
  print(f"  [ok] {label}")


def write_cfg(path: Path, level: int, **knobs) -> None:
  cfg = {
      "randomSeed": SEED,
      "cse": {
          "enable": True,
          "level": level,
      },
  }
  cfg["cse"].update(knobs)
  path.write_text(json.dumps(cfg), encoding="utf-8")


def compile_cmd(clang: Path, src: Path, out: Path, cfg: Path | None,
                opt: str, emit_ir: bool = False) -> list[str]:
  cmd = [str(clang), str(src), opt, "-o", str(out)]
  if emit_ir:
    cmd += ["-S", "-emit-llvm", "-fno-discard-value-names"]
  if not tp.IS_WINDOWS:
    cmd += ["-fdeclspec", "-D_GNU_SOURCE"]
  if cfg:
    cmd += ["-mllvm", "-taokari", "-mllvm", "-taokari-cse",
            "-mllvm", f"-taokari-cfg={cfg}"]
  return cmd


def fortress_markers(ir: str) -> dict[str, bool]:
  return {
      "sharded pool globals (>=2 EncryptedStringTable_N)":
          len(re.findall(r"@EncryptedStringTable_\d+ = ", ir)) >= 2,
      "decoy pools (>=2 FakeStringPool_N)":
          len(re.findall(r"@FakeStringPool_\d+ = ", ir)) >= 2,
      "pool page table (_StringPools_page_table_/_objects + inttoptr)":
          ("_StringPools_page_table_" in ir and "_StringPools_objects" in ir
           and "inttoptr" in ir),
      "indirect decryptor slot (strenc.decslot.)":
          "strenc.decslot." in ir,
  }


def main() -> int:
  parser = argparse.ArgumentParser()
  parser.add_argument("--clang", default=str(tp.CLANG),
                      help="compiler binary under test (parent for teeth)")
  args = parser.parse_args()
  clang = Path(args.clang).resolve()
  if not clang.exists():
    print(f"missing clang: {clang}", file=sys.stderr)
    return 2

  tmp = Path(tempfile.mkdtemp(prefix="taokari-cse-fortress-"))
  try:
    src = tmp / "cse_fortress.c"
    src.write_text(SOURCE.strip() + "\n", encoding="utf-8")

    plain_exe = tmp / "plain.exe"
    must(run_vs(compile_cmd(clang, src, plain_exe, None, "-O2"), src.parent),
         "build plain exe")
    plain_run = run([str(plain_exe)])
    must(plain_run, "run plain exe")
    gate(plain_run.stdout.startswith("cse-fortress:cse:")
         and plain_run.stdout.endswith("\n"),
         f"plain binary produces deterministic output (got "
         f"{plain_run.stdout!r})")

    # Gate 1 (teeth against a pre-fix binary): the documented level-3
    # auto-enable. A cse config with no knob keys must fire the tier.
    print(f"gate 1: level-3 cfg with no knob keys fires the fortress tier "
          f"({clang.name})")
    auto_cfg = tmp / "auto.json"
    write_cfg(auto_cfg, level=3)
    auto_ir_path = tmp / "auto-O0.ll"
    must(run_vs(compile_cmd(clang, src, auto_ir_path, auto_cfg, "-O0",
                            emit_ir=True), src.parent),
         "emit level-3 -O0 IR")
    auto_ir = auto_ir_path.read_text(encoding="utf-8", errors="ignore")
    for name, ok in fortress_markers(auto_ir).items():
      gate(ok, f"auto-enable: {name}")
    gate("EncryptedStringTable" in auto_ir, "auto-enable: string pass ran")

    # Gate 2: real-spelling knobs compose explicitly, including below the
    # fortress level (CIE `knob || level>=3` precedent).
    print("gate 2: explicit real-spelling knobs at level 2")
    l2_cfg = tmp / "explicit_l2.json"
    write_cfg(l2_cfg, level=2, stringShardedPool=True, stringFakePools=True,
              stringPageTableAccess=True, stringDecryptorIndirectCall=True)
    l2_ir_path = tmp / "explicit_l2-O0.ll"
    must(run_vs(compile_cmd(clang, src, l2_ir_path, l2_cfg, "-O0",
                            emit_ir=True), src.parent),
         "emit level-2 explicit-knobs -O0 IR")
    l2_ir = l2_ir_path.read_text(encoding="utf-8", errors="ignore")
    for name, ok in fortress_markers(l2_ir).items():
      gate(ok, f"explicit level 2: {name}")
    l2_exe = tmp / "explicit_l2.exe"
    must(run_vs(compile_cmd(clang, src, l2_exe, l2_cfg, "-O2"), src.parent),
         "build level-2 explicit-knobs exe")
    l2_run = run([str(l2_exe)])
    must(l2_run, "run level-2 explicit-knobs exe")
    gate(l2_run.stdout == plain_run.stdout,
         f"level-2 explicit-knobs stdout matches plain: {l2_run.stdout!r}")

    # Gate 3: explicit false under level 3 is overridden -- knob bits are
    # plain bools and cannot distinguish explicit false from unset
    # (documented in docs/CONFIGURATION.md).
    print("gate 3: explicit false overridden at level 3 (documented)")
    off_cfg = tmp / "explicit_false.json"
    write_cfg(off_cfg, level=3, stringShardedPool=False, stringFakePools=False)
    off_ir_path = tmp / "explicit_false-O0.ll"
    must(run_vs(compile_cmd(clang, src, off_ir_path, off_cfg, "-O0",
                            emit_ir=True), src.parent),
         "emit level-3 explicit-false -O0 IR")
    off_ir = off_ir_path.read_text(encoding="utf-8", errors="ignore")
    gate(len(re.findall(r"@EncryptedStringTable_\d+ = ", off_ir)) >= 2,
         "explicit-false override: sharded pool globals still present")
    gate(len(re.findall(r"@FakeStringPool_\d+ = ", off_ir)) >= 2,
         "explicit-false override: decoy pools still present")

    # Gate 4: the full fortress build stays behaviorally identical.
    print("gate 4: runtime parity plain vs fortress")
    fort_exe = tmp / "fortress.exe"
    must(run_vs(compile_cmd(clang, src, fort_exe, auto_cfg, "-O2"),
                src.parent), "build fortress exe")
    fort_run = run([str(fort_exe)])
    must(fort_run, "run fortress exe")
    gate(fort_run.stdout == plain_run.stdout,
         f"fortress stdout matches plain: {fort_run.stdout!r}")

    # Gate 5: the markers survive -O2 under -fno-discard-value-names
    # (TK-031 lesson: value names must be kept for inspection).
    print("gate 5: fortress markers survive -O2")
    o2_ir_path = tmp / "auto-O2.ll"
    must(run_vs(compile_cmd(clang, src, o2_ir_path, auto_cfg, "-O2",
                            emit_ir=True), src.parent),
         "emit level-3 -O2 IR")
    o2_ir = o2_ir_path.read_text(encoding="utf-8", errors="ignore")
    gate(len(re.findall(r"@EncryptedStringTable_\d+ = ", o2_ir)) >= 2,
         "-O2 survival: sharded pool globals")
    gate(len(re.findall(r"@FakeStringPool_\d+ = ", o2_ir)) >= 2,
         "-O2 survival: decoy pools")
    gate("_StringPools_page_table_" in o2_ir and "_StringPools_objects" in o2_ir,
         "-O2 survival: pool page table")
    gate("strenc.decslot." in o2_ir, "-O2 survival: indirect decryptor slot")

    print("cse fortress config verifier: ok")
    return 0
  finally:
    shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
  raise SystemExit(main())
