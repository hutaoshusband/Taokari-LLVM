"""String-encryption padded-char-array verifier (TK-018).

ConstantDataSequential::isCString() rejects arrays with interior NULs, so
NUL-padded fixed-size char arrays (strncpy expansion, char a[N] = "str")
used to fall through string collection and stay plaintext in the protected
binary. Asserts that:
  1. the obfuscated object/exe no longer contains the plaintext bytes,
  2. the scan itself works (plain control) and the pass ran
     (EncryptedStringTable in IR),
  3. plain and obfuscated runs still agree byte-for-byte,
  4. no padded char-array literal survives in the protected IR,
  5. a skipStrings exemption for the base string also exempts the padded
     variants (config respect).
"""
from __future__ import annotations

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
VSDEVCMD = tp.VSDEVCMD

SECRET = b"taokari-secret"
# StringEncryption derives per-compile entropy from the OS (getRandomBytes),
# not from randomSeed; the key stays pinned for the cfg consumers that honor it.
SEED = "tk018-padded-cstring-seed"

SOURCE = r"""
#include <stdio.h>
#include <string.h>

static const char *secret = "taokari-secret";
static const char *tag    = "FX";
volatile unsigned g_pad = 0;

__attribute__((noinline)) static int score(const char *s) {
  int acc = 0;
  for (const char *p = s; *p; ++p) {
    acc = acc * 31 + (unsigned char)*p;
  }
  return acc;
}

int main(void) {
  char init[32] = "taokari-secret";
  unsigned n = (unsigned)sizeof(init) - g_pad;
  unsigned padsum = 0;
  for (unsigned i = 0; i < n; ++i) {
    padsum = padsum * 31 + (unsigned char)init[i];
  }

  char buf[32];
  strncpy(buf, secret, sizeof(buf) - 1);
  buf[sizeof(buf) - 1] = '\0';
  size_t len = strlen(buf);
  buf[len] = '|';
  buf[len + 1] = '\0';
  strncat(buf, tag, sizeof(buf) - strlen(buf) - 1);

  int combined = score(buf);
  int plain    = score("plaintext");
  printf("strings:%s:%d:%d:%u\n", tag, combined, plain, padsum);
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


def write_cfg(path: Path, **extra) -> None:
  cfg = {
      "randomSeed": SEED,
      "cse": {
          "enable": True,
          "level": 2,
          "minStringLength": 5,
      },
  }
  cfg["cse"].update(extra)
  path.write_text(json.dumps(cfg), encoding="utf-8")


def compile_cmd(src: Path, out: Path, cfg: Path | None,
                emit_ir: bool = False) -> list[str]:
  cmd = [str(CLANG), str(src), "-O2", "-o", str(out)]
  if emit_ir:
    cmd += ["-S", "-emit-llvm"]
  else:
    cmd += ["-c"] if out.suffix in (".obj", ".o") else []
  if not tp.IS_WINDOWS:
    cmd += ["-fdeclspec"]
  if cfg:
    cmd += ["-mllvm", "-taokari", "-mllvm", "-taokari-cse",
            "-mllvm", f"-taokari-cfg={cfg}"]
  return cmd


def main() -> int:
  if not CLANG.exists():
    print(f"missing clang: {CLANG}", file=sys.stderr)
    return 2

  tmp = Path(tempfile.mkdtemp(prefix="taokari-strenc-padded-"))
  try:
    src = tmp / "padded_cstring.c"
    src.write_text(SOURCE.strip() + "\n", encoding="utf-8")

    # Gate 2 positive control: plain build has the bytes and the plain IR
    # still holds the padded literals.
    plain_exe = tmp / "plain.exe"
    must(run_vs(compile_cmd(src, plain_exe, None), src.parent),
         "build plain exe")
    plain_run = run([str(plain_exe)])
    must(plain_run, "run plain exe")
    plain_out = plain_run.stdout
    gate(plain_out.startswith("strings:FX:") and plain_out.endswith("\n"),
         f"plain binary produces deterministic output (got {plain_out!r})")
    gate(SECRET in plain_exe.read_bytes(),
         "plaintext secret appears in the plain binary (scan control)")

    plain_ir = tmp / "plain.ll"
    must(run_vs(compile_cmd(src, plain_ir, None, emit_ir=True), src.parent),
         "emit plain IR")
    plain_ir_text = plain_ir.read_text(encoding="utf-8", errors="ignore")
    gate(re.search(r'\[\d+ x i8\] c"taokari-secret', plain_ir_text)
         is not None,
         "plain IR holds the padded char-array literal (IR control)")

    # Gate 4: protected IR has no padded literal and the pass ran.
    cfg = tmp / "cse.json"
    write_cfg(cfg)
    obf_ir = tmp / "obf.ll"
    must(run_vs(compile_cmd(src, obf_ir, cfg, emit_ir=True), src.parent),
         "emit obfuscated IR")
    obf_ir_text = obf_ir.read_text(encoding="utf-8", errors="ignore")
    gate("EncryptedStringTable" in obf_ir_text,
         "obfuscated IR contains EncryptedStringTable (pass ran)")
    gate(re.search(r'\[\d+ x i8\] c"taokari-secret', obf_ir_text) is None,
         "obfuscated IR has NO padded char-array literal (gate 4)")

    # Gate 1: obfuscated object and exe must not contain the secret bytes.
    cfg2 = tmp / "cse_obj.json"
    write_cfg(cfg2)
    obf_obj = tmp / ("obf.obj" if tp.IS_WINDOWS else "obf.o")
    must(run_vs(compile_cmd(src, obf_obj, cfg2), src.parent),
         "build obfuscated object")
    obf_exe = tmp / "obf.exe"
    must(run_vs(compile_cmd(src, obf_exe, cfg), src.parent),
         "build obfuscated exe")
    obf_bytes = obf_exe.read_bytes() + obf_obj.read_bytes()
    gate(SECRET not in obf_bytes,
         "obfuscated object/exe do NOT contain the plaintext secret (gate 1)")

    # Gate 3: differential behavior, byte-for-byte stdout.
    obf_run = run([str(obf_exe)])
    must(obf_run, "run obfuscated exe")
    gate(obf_run.stdout == plain_out,
         f"protected stdout matches plain (gate 3): {obf_run.stdout!r}")

    # Gate 5: skipStrings exemption covers the padded variants too.
    skip_cfg = tmp / "cse_skip.json"
    write_cfg(skip_cfg, skipStrings=["taokari-secret"])
    skip_exe = tmp / "skip.exe"
    must(run_vs(compile_cmd(src, skip_exe, skip_cfg), src.parent),
         "build skipStrings-exempt exe")
    gate(SECRET in skip_exe.read_bytes(),
         "skipStrings exemption keeps the padded variants plaintext "
         "(gate 5)")
    skip_run = run([str(skip_exe)])
    must(skip_run, "run skipStrings-exempt exe")
    gate(skip_run.stdout == plain_out,
         f"skipStrings-exempt stdout matches plain: {skip_run.stdout!r}")

    print("string encryption padded-cstring verifier: ok")
    return 0
  finally:
    shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
  raise SystemExit(main())
