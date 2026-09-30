"""indgv/cse string-GV single-ownership verifier (TK-038).

IndirectGlobalVariable re-implemented cse's string-shape test as
`isCString() || i16`, while cse (post-TK-018) also owns NUL-padded char
arrays. Two consequences, both proven empirically (tk045/INVESTIGATION.md):

  1. Whenever the obfuscation manager runs (even with indgv DISABLED),
     indgv's doInitialization bakes NUL-padded string GVs into the dormant
     `_IndirectGVs_objects` page table. cse then sees that constant user and
     demotes the string to the anchored-plaintext path (startup-decrypted
     anc image) instead of its primary lazy per-use decrypt.
  2. At fortress levels the cse lazy path itself crashed on any string
     loaded at a conditional (non-dominating) site: deferred scrubs were
     flushed into every return block, including blocks not dominated by the
     use that defined the scrub's operands. The drift masked this for
     padded shapes; plain isCString arrays crashed at HEAD.

This verifier locks the fixed behavior:
  - INVARIANT gates: single ownership (indgv page tables never reference
    string GVs), no anchor fallback, no plaintext in the binary, output
    byte-exact vs plain. These gates pass on post-fix binaries AND on
    HEAD (7ba450ea6) end-state IR -- the invariant held at HEAD too, via
    the anchor demotion. They have NO teeth against HEAD; the premise
    "leak or miscompile" was refuted.
  - FIX-LOCK gates: cse's primary lazy path (dec globals / fortress heap
    buffers) serves the strings and the fortress crash is gone. These DO
    fail against pre-fix binaries (tk031 clang-landing.exe, def09eb2, and
    a HEAD build) -- the anchor fallback and the crash are observable
    there. Teeth documented, not fabricated.

Run: python testing/scripts/verify_indgv_cse_string_ownership.py
     [--clang PATH]  (parent binary for teeth)
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
VSDEVCMD = tp.VSDEVCMD

SEED = "tk038-indgv-cse-string-ownership"

SOURCE = r"""
#include <stdio.h>

static const char g_pad[31]   = "taokari-secret";
static const char g_plain[15] = "taokari-ctrl";

volatile unsigned g_sink = 0;

int main(void) {
  unsigned sum = 0;
  unsigned idx = g_sink;
  if (idx < 31) {
    sum += (unsigned)(unsigned char)g_pad[idx];
  }
  if (idx < 15) {
    sum += (unsigned)(unsigned char)g_plain[idx];
  }
  printf("ownership:%s:%s:%u\n", g_pad, g_plain, sum);
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


def compile_cmd(clang: Path, src: Path, out: Path, opt: str,
                extra: list[str], emit_ir: bool = False) -> list[str]:
  cmd = [str(clang), str(src), opt, "-o", str(out)]
  if emit_ir:
    # Marker gates key on value names; non-asserts builds discard them at
    # -O2 unless retention is forced.
    cmd += ["-S", "-emit-llvm", "-fno-discard-value-names"]
  cmd += extra
  return cmd


def both_on_flags() -> list[str]:
  return ["-mllvm", "-taokari-indgv", "-mllvm", "-taokari-cse"]


def fortress_cfg(path: Path, level: int) -> None:
  path.write_text(
      json.dumps({"randomSeed": SEED, "cse": {"enable": True,
                                              "level": level}}),
      encoding="utf-8")


def split_blocks(ir: str, func_name: str) -> dict[str, list[str]]:
  """Return {label: [instruction lines]} for one function's body."""
  m = re.search(rf"define\s+[^{{]*@{re.escape(func_name)}\s*\(", ir)
  if not m:
    raise ValueError(f"function @{func_name} not found in IR")
  body_start = ir.index("{", m.start()) + 1
  body_end = ir.index("\n}", body_start)
  blocks: dict[str, list[str]] = {}
  label = "__entry__"
  for line in ir[body_start:body_end].splitlines():
    head = line.strip()
    m = re.match(r"^([-_a-zA-Z0-9.$]+):\s*(?:;.*)?$", head)
    if m:
      label = m.group(1)
      blocks.setdefault(label, [])
    elif head and not head.startswith(";"):
      blocks.setdefault(label, []).append(head)
  return blocks


def preds_of(blocks: dict[str, list[str]], label: str) -> set[str]:
  preds = set()
  for pred, lines in blocks.items():
    for ln in lines:
      for m in re.finditer(r"label\s+%([-_a-zA-Z0-9.$]+)", ln):
        if m.group(1) == label:
          preds.add(pred)
  return preds


def deferred_flush_reaches_ret(blocks: dict[str, list[str]]) -> bool:
  """True when a flag-guarded deferred scrub sits on a path into a ret.

  Full-coverage flush shape: some block S calls a shared scrub function and
  branches into a block that returns; S is entered from a conditional branch
  that loads an entry-placed strenc.scrublive flag. The pre-TK-046 narrowing
  emitted no scrub at all on non-dominated join returns.
  """
  scrub_blocks = {lbl for lbl, lines in blocks.items()
                  if any("call void @goron_scrub_string_i" in ln
                         for ln in lines)}
  ret_blocks = {lbl for lbl, lines in blocks.items()
                if any(re.search(r"\bret\b", ln) for ln in lines)}
  for scrub in scrub_blocks:
    targets = set()
    for ln in blocks[scrub]:
      targets.update(m.group(1) for m in
                     re.finditer(r"label\s+%([-_a-zA-Z0-9.$]+)", ln))
    if not (targets & ret_blocks):
      continue
    for pred in preds_of(blocks, scrub):
      plines = blocks[pred]
      if not any(re.search(r"br\s+i1", ln) for ln in plines):
        continue
      if not any(re.search(r"load\s+i8,\s+ptr\s+%strenc\.scrublive", ln)
                 for ln in plines):
        continue
      return True
  return False


# TK-046 gates additionally lock the full-coverage deferred flush: an
# entry-placed strenc.scrublive flag, the use-site live mark, and a
# flag-guarded scrub chain reaching the non-dominated join return.
def main() -> int:
  parser = argparse.ArgumentParser()
  parser.add_argument("--clang", default=str(tp.CLANG),
                      help="compiler binary under test (parent for teeth)")
  args = parser.parse_args()
  clang = Path(args.clang).resolve()
  if not clang.exists():
    print(f"missing clang: {clang}", file=sys.stderr)
    return 2

  tmp = Path(tempfile.mkdtemp(prefix="taokari-indgv-cse-own-"))
  try:
    src = tmp / "ownership.c"
    src.write_text(SOURCE.strip() + "\n", encoding="utf-8")

    plain_exe = tmp / "plain.exe"
    must(run_vs(compile_cmd(clang, src, plain_exe, "-O2", []),
                src.parent),
         "build plain exe")
    plain_run = run([str(plain_exe)])
    must(plain_run, "run plain exe")
    expected = plain_run.stdout
    gate(expected.startswith("ownership:taokari-secret:taokari-ctrl:")
         and expected.endswith("\n"),
         f"plain binary prints the plaintext strings (got {expected!r})")

    both_ir_path = tmp / "both-O2.ll"
    both_exe = tmp / "both.exe"
    must(run_vs(compile_cmd(clang, src, both_exe, "-O2", both_on_flags()),
                src.parent),
         "build indgv+cse exe")
    must(run_vs(compile_cmd(clang, src, both_ir_path, "-O2",
                            both_on_flags(), emit_ir=True),
                src.parent),
         "emit indgv+cse IR")
    both_ir = both_ir_path.read_text(encoding="utf-8", errors="ignore")
    both_run = run([str(both_exe)])
    must(both_run, "run indgv+cse exe")

    print("invariant gates (indgv+cse, default levels):")
    gate(both_run.returncode == 0, "indgv+cse exe exits 0")
    gate(both_run.stdout == expected,
         "indgv+cse stdout byte-identical to plain")

    leaked = []
    for needle in (b"taokari-secret", b"taokari-ctrl"):
      if needle in both_exe.read_bytes():
        leaked.append(needle.decode())
    gate(not leaked, f"no plaintext in indgv+cse binary (found {leaked})")

    objs = [ln for ln in both_ir.splitlines()
            if "_IndirectGVs_objects" in ln]
    gate(bool(objs), "indgv module page table present in IR")
    gate(not any(re.search(r"ptr @g_(pad|plain)\b", ln) for ln in objs),
         "single ownership: indgv page table claims neither string GV")

    for gv in ("g_pad", "g_plain"):
      gate(not re.search(rf"@anc[0-9a-f]*{gv}\b", both_ir),
           f"no anchor-image fallback for {gv} (cse lazy path owns it)")
    gate("@g_pad = " not in both_ir and "@g_plain = " not in both_ir,
         "both source string GVs erased after cse ownership")

    print("fix-lock gates (cse fortress L3, lazy path on a conditional "
          "load -- crasher at HEAD):")
    cfg = tmp / "l3.json"
    fortress_cfg(cfg, 3)
    fort_exe = tmp / "fort.exe"
    fort_build = run_vs(compile_cmd(
        clang, src, fort_exe, "-O2",
        ["-mllvm", "-taokari", "-mllvm", "-taokari-cse",
         f"-mllvm", f"-taokari-cfg={cfg}"]), src.parent)
    gate(fort_build.returncode == 0,
         "cse L3 build of conditional-load fixture succeeds "
         "(HEAD asserts in InstCombine here)")
    if fort_build.returncode == 0:
      fort_run = run([str(fort_exe)])
      gate(fort_run.returncode == 0 and fort_run.stdout == expected,
           "cse L3 stdout byte-identical to plain")

    print("fix-lock gates (cse L4 full-coverage deferred flush on the "
          "non-dominated join return -- TK-046):")
    l4cfg = tmp / "l4.json"
    fortress_cfg(l4cfg, 4)
    l4_ir_path = tmp / "l4.ll"
    l4_ir_build = run_vs(compile_cmd(
        clang, src, l4_ir_path, "-O2",
        ["-mllvm", "-taokari", "-mllvm", "-taokari-cse",
         f"-mllvm", f"-taokari-cfg={l4cfg}"], emit_ir=True), src.parent)
    gate(l4_ir_build.returncode == 0, "cse L4 build of the fixture succeeds")
    l4_ir = l4_ir_path.read_text(encoding="utf-8", errors="ignore")
    main_blocks = split_blocks(l4_ir, "main")
    gate(any("strenc.scrublive" in ln and "alloca i8" in ln
             for lines in main_blocks.values() for ln in lines),
         "entry-placed strenc.scrublive flag alloca present in main")
    gate(any(re.search(r"store\s+i8\s+1,\s+ptr\s+%strenc\.scrublive", ln)
             for lines in main_blocks.values() for ln in lines),
         "use site marks the temp live (store i8 1 to the flag)")
    gate(deferred_flush_reaches_ret(main_blocks),
         "flag-guarded scrub call sits on a path into the join return "
         "(parent narrowing emits no scrub there)")

    print(f"\nPASS ({clang.name})")
    return 0
  finally:
    pass


if __name__ == "__main__":
  raise SystemExit(main())
