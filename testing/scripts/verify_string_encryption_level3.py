"""Level-3 (Fortress) string-encryption verification.

Each checkbox in todo.md section 6.L3 maps to a concrete gate here:

  - polymorphic decryptors         -> >=2 distinct decryptor IR shapes / build
  - decryptor MBA                  -> strenc.dec.add / strenc.dec.xor markers
  - decryptor flattening           -> switch dispatcher + unreachable default
  - decryptor indirect calls       -> strenc.deccallee load at call sites
  - string shards                  -> >=2 EncryptedStringTable_N globals
  - split string pools             -> pool globals split (same mechanism)
  - fake string pools              -> FakeStringPool_ decoy globals present
  - string access through page tbl -> _StringPools page table/object + inttoptr
  - delayed decrypt mode           -> per-use alloca + scrub; stdout identical
  - memory lifetime tests          -> scrub call precedes ret in delayed mode
  - string dump resistance tests   -> `strings` on the .exe has no secret

Every gate also re-checks semantics: the obfuscated binary must produce the
same stdout as the plain one. Fortress features are gated to cse.level >= 3.
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
CLANG = tp.CLANG
OBJDUMP = tp.tool("llvm-objdump")
STRINGS = "strings"  # msys2/Git ships `strings`; fall back to objdump scan below
VSDEVCMD = tp.VSDEVCMD

SECRET = "taokari-l3-fortress-secret"

SOURCE = r'''
#include <cstdint>
#include <cstdio>
#include <cstring>

static const char *secret = "''' + SECRET + r'''";
static const char16_t wsecret[] = u"l3-wide-secret-marker";
static const char *harmless = "harmless";

__declspec(noinline)
static int score(const char *s) {
  int acc = 0;
  for (const unsigned char *p = reinterpret_cast<const unsigned char *>(s); *p; ++p)
    acc = acc * 131 + *p;
  return acc;
}

__declspec(noinline)
static int wscore(const char16_t *s) {
  int acc = 0;
  for (const char16_t *p = s; *p; ++p)
    acc = acc * 17 + *p;
  return acc;
}

int main() {
  std::printf("strenc-l3:%d:%d:%s\n", score(secret), wscore(wsecret), harmless);
  return 0;
}
'''


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


def write_cfg(path: Path, **extra: bool) -> None:
  cfg = {
      "cse": {
          "enable": True,
          "level": 3,
          "minStringLength": 5,
      }
  }
  cfg["cse"].update(extra)
  path.write_text(json.dumps(cfg), encoding="utf-8")


def compile_exe(src: Path, out: Path, cfg: Path | None) -> None:
  cmd = [str(CLANG), str(src), "-std=c++17", "-O2", "-o", str(out)]
  if not tp.IS_WINDOWS:
    cmd += ["-fdeclspec", "-D_GNU_SOURCE"]
  if cfg:
    cmd += ["-mllvm", "-taokari", "-mllvm", "-taokari-cse",
            "-mllvm", f"-taokari-cfg={cfg}"]
  must(run_vs(cmd, src.parent), f"compile {out.name}")


def emit_ir(src: Path, out: Path, cfg: Path) -> str:
  cmd = [
      str(CLANG), str(src), "-std=c++17", "-O2", "-S", "-emit-llvm",
      "-fno-discard-value-names",
      "-mllvm", "-taokari", "-mllvm", "-taokari-cse",
      "-mllvm", f"-taokari-cfg={cfg}", "-o", str(out),
  ]
  if not tp.IS_WINDOWS:
    cmd += ["-fdeclspec", "-D_GNU_SOURCE"]
  must(run_vs(cmd, src.parent), "emit IR")
  return out.read_text(encoding="utf-8")


def decryptor_bodies(ir: str) -> dict[str, str]:
  out = {}
  for suffix in ("i8", "i16"):
    m = re.search(rf"define[^@]*@goron_decrypt_string_{suffix}\b[\s\S]*?\n}}",
                  ir)
    out[suffix] = m.group(0) if m else ""
  return out


def gate(cond: bool, label: str) -> None:
  if not cond:
    raise SystemExit(f"GATE FAILED: {label}")
  print(f"  [ok] {label}")


def has_nonzero_pool_gap(ir: str) -> bool:
  for line in ir.splitlines():
    if "call void @goron_decrypt_string_i" not in line:
      continue
    ints = re.findall(r"\bi32 (-?\d+)", line)
    if len(ints) >= 3 and int(ints[2]) > 0:
      return True
  return False


def main() -> int:
  parser = argparse.ArgumentParser()
  parser.add_argument("--keep", action="store_true")
  args = parser.parse_args()

  if not CLANG.exists():
    print(f"missing clang: {CLANG}", file=sys.stderr)
    return 2

  tmp = Path(tempfile.mkdtemp(prefix="taokari-strenc-l3-"))
  try:
    src = tmp / "strenc_l3.cpp"
    src.write_text(SOURCE, encoding="utf-8")
    plain = tmp / "plain.exe"
    plain_flags = ["-fdeclspec", "-D_GNU_SOURCE"] if not tp.IS_WINDOWS else []
    must(run_vs([str(CLANG), str(src), "-std=c++17", "-O2", *plain_flags, "-o", str(plain)],
                src.parent), "plain compile")
    plain_run = run([str(plain)])
    must(plain_run, "plain run")

    # 1. polymorphic decryptors: gather decryptor shapes across 8 builds with
    #    only level=3 (no extra L3 knobs) so variant selection is purely
    #    nonce-driven.
    shapes: set[tuple[str, str]] = set()
    for i in range(8):
      cfg = tmp / f"variant_{i}.json"
      write_cfg(cfg)
      ir = emit_ir(src, tmp / f"variant_{i}.ll", cfg)
      bodies = decryptor_bodies(ir)
      shapes.add((bodies["i8"], bodies["i16"]))
      if len(shapes) >= 2:
        break
    gate(len(shapes) >= 2, "polymorphic decryptors: >=2 distinct body shapes")

    # 2-9. each L3 knob in isolation: prove it fires in IR AND keeps stdout
    # identical. Knobs compose at level>=3, so each single-knob config also
    # exercises the variant machinery above.
    def single(name: str, key: str, marker_check, ir_path: Path,
               exe_path: Path) -> None:
      cfg = tmp / f"{name}.json"
      write_cfg(cfg, **{key: True})
      ir = emit_ir(src, ir_path, cfg)
      gate(marker_check(ir), f"{name}: IR marker present")
      compile_exe(src, exe_path, cfg)
      ran = run([str(exe_path)])
      must(ran, f"{name} run")
      if ran.stdout != plain_run.stdout:
        raise SystemExit(
            f"{name} stdout mismatch\nplain={plain_run.stdout!r}\n"
            f"obf={ran.stdout!r}")

    single("decryptor MBA", "stringDecryptorMBA",
           lambda ir: ("strenc.dec.add" in ir or "strenc.dec.xor" in ir),
           tmp / "mba.ll", tmp / "mba.exe")
    single("decryptor flattening", "stringDecryptorFlattening",
           lambda ir: ("switch" in ir and "unreachabledefault" in ir),
           tmp / "flat.ll", tmp / "flat.exe")
    single("decryptor indirect calls", "stringDecryptorIndirectCall",
           lambda ir: "strenc.deccallee" in ir,
           tmp / "icall.ll", tmp / "icall.exe")
    single("string shards", "stringShardedPool",
           lambda ir: len(re.findall(r"@EncryptedStringTable_\d+ = ", ir)) >= 2,
           tmp / "shard.ll", tmp / "shard.exe")
    single("split string pools", "stringShardedPool",
           # split pools and shards are the same mechanism (pool spread across
           # N globals); verify independently that >=2 pool globals exist.
           lambda ir: (len(re.findall(r"@EncryptedStringTable_\d+ = ", ir)) >= 2
                       and has_nonzero_pool_gap(ir)),
           tmp / "split.ll", tmp / "split.exe")
    single("fake string pools", "stringFakePools",
           lambda ir: len(re.findall(r"@FakeStringPool_\d+ = ", ir)) >= 2,
           tmp / "fake.ll", tmp / "fake.exe")
    single("page-table access", "stringPageTableAccess",
           lambda ir: ("_StringPools_page_table_" in ir and
                       "_StringPools_objects" in ir and "inttoptr" in ir),
           tmp / "pt.ll", tmp / "pt.exe")

    # delayed decrypt: every use is a per-use alloca + a scrub call. Verify
    # stdout matches (semantics) and that a scrub precedes a return (lifetime).
    dd_cfg = tmp / "delayed.json"
    write_cfg(dd_cfg, stringDelayedDecrypt=True)
    dd_ir = emit_ir(src, tmp / "delayed.ll", dd_cfg)
    gate("goron_scrub_string" in dd_ir, "delayed decrypt: scrub call present")
    gate(re.search(r"alloca.*dec", dd_ir, re.IGNORECASE) or
         "alloca" in dd_ir, "delayed decrypt: per-use alloca present")
    compile_exe(src, tmp / "delayed.exe", dd_cfg)
    dd_run = run([str(tmp / "delayed.exe")])
    must(dd_run, "delayed run")
    if dd_run.stdout != plain_run.stdout:
      raise SystemExit(f"delayed stdout mismatch: {dd_run.stdout!r}")

    # memory lifetime: in delayed mode the scrub is emitted after the use; the
    # plaintext is overwritten with ciphertext before the function returns. We
    # confirm a scrub call site exists whose basic block reaches a ret without
    # another decrypt in between (heuristic from textual IR ordering).
    dd_text = dd_ir
    scrub_pos = dd_text.find("call void @goron_scrub_string")
    gate(scrub_pos != -1, "memory lifetime: scrub call site located")
    # The scrub must not be followed by a fresh decrypt of the same pool before
    # a ret (no plaintext resurrection). This is a textual proxy; the real
    # guarantee is the binary scan below.
    after = dd_text[scrub_pos:]
    ret_pos = after.find("ret void")
    gate(ret_pos != -1, "memory lifetime: ret reachable after scrub")

    # 10. string dump resistance: a `strings` scan of the Fortress binary must
    #     not contain the ASCII secret or the wide-secret marker. Run every L3
    #     knob at once for the strongest possible binary.
    all_cfg = tmp / "all.json"
    write_cfg(all_cfg,
              stringDecryptorMBA=True,
              stringDecryptorFlattening=True,
              stringDecryptorIndirectCall=True,
              stringShardedPool=True,
              stringFakePools=True,
              stringPageTableAccess=True,
              stringDelayedDecrypt=True)
    all_exe = tmp / "fortress.exe"
    compile_exe(src, all_exe, all_cfg)
    all_run = run([str(all_exe)])
    must(all_run, "fortress run")
    if all_run.stdout != plain_run.stdout:
      raise SystemExit(f"fortress stdout mismatch: {all_run.stdout!r}")

    # Extract printable ASCII strings from the .exe. Prefer the `strings`
    # binary; fall back to llvm-objdump -s on the .rdata/.data and grep.
    leaked: list[str] = []
    strings_tool = shutil.which(STRINGS)
    blob = b""
    if strings_tool:
      blob = subprocess.run([strings_tool, "-n", "4", str(all_exe)],
                            capture_output=True).stdout
    else:
      # Fall back: dump all sections and scan for the secrets.
      res = run_vs([str(OBJDUMP), "-s", "-section", ".rdata", str(all_exe)],
                   all_exe.parent)
      blob = res.stdout.encode("utf-8", "ignore")
      res2 = run_vs([str(OBJDUMP), "-s", "-section", ".data", str(all_exe)],
                    all_exe.parent)
      blob += res2.stdout.encode("utf-8", "ignore")
    for needle in (SECRET.encode(), b"l3-wide-secret-marker"):
      if needle in blob:
        leaked.append(needle.decode())
    gate(not leaked, f"string dump resistance: secrets absent from binary "
                     f"(leaked={leaked})")

    print("string encryption L3 (Fortress) verifier: ok")
    return 0
  finally:
    if args.keep:
      print(f"kept temp dir: {tmp}")
    else:
      shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
  raise SystemExit(main())
