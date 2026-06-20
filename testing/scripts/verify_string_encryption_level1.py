"""Level-1 string-encryption verification.

Checks the existing StringEnc surface without touching the main test runner:
UTF-8, UTF-16, and wide strings decrypt correctly; minStringLength/skipStrings
leave harmless strings alone; status slots no longer use plain 0/1 sentinels;
decryptors carry build nonce and position-dependent key mixing.
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


ROOT = Path(__file__).resolve().parents[2]
CLANG = ROOT / "build" / "taokari-local" / "bin" / "clang.exe"
VSDEVCMD = Path(
    r"C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat"
)


SOURCE = r'''
#include <cstdint>
#include <cstdio>
#include <cwchar>

static const char *ascii_secret = "ascii-taokari-secret";
static const char16_t utf16_secret[] = u"utf16-taokari-secret";
static const wchar_t wide_secret[] = L"wide-taokari-secret";
static const char *harmless = "harmless";
static const char *tiny = "tiny";
static volatile int guard = 0;

template <typename T>
__declspec(noinline)
static int score16(const T *s) {
  int acc = 0;
  for (const T *p = s; *p; ++p)
    acc = acc * 33 + static_cast<unsigned>(*p);
  return acc;
}

__declspec(noinline)
static int score8(const char *s) {
  int acc = 0;
  for (const unsigned char *p = reinterpret_cast<const unsigned char *>(s); *p; ++p)
    acc = acc * 31 + *p;
  return acc;
}

int main() {
  const char *a = guard ? "unused-a" : ascii_secret;
  const char16_t *u = guard ? u"unused-u" : utf16_secret;
  const wchar_t *w = guard ? L"unused-w" : wide_secret;
  std::printf("strenc:%d:%d:%d:%s:%s\n",
              score8(a),
              score16(u),
              score16(w),
              harmless,
              tiny);
  return 0;
}
'''


def run(command: list[str], **kw) -> subprocess.CompletedProcess[str]:
  return subprocess.run(command, text=True, capture_output=True, **kw)


def run_vs(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
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


def compile_exe(src: Path, out: Path, cfg: Path | None) -> None:
  cmd = [str(CLANG), str(src), "-std=c++17", "-O2", "-o", str(out)]
  if cfg:
    cmd += ["-mllvm", "-taokari", "-mllvm", "-taokari-cse",
            "-mllvm", f"-taokari-cfg={cfg}"]
  must(run_vs(cmd, src.parent), f"compile {out.name}")


def emit_ir(src: Path, out: Path, cfg: Path) -> str:
  cmd = [
      str(CLANG), str(src), "-std=c++17", "-O2", "-S", "-emit-llvm",
      "-mllvm", "-taokari", "-mllvm", "-taokari-cse",
      "-mllvm", f"-taokari-cfg={cfg}", "-o", str(out),
  ]
  must(run_vs(cmd, src.parent), "emit IR")
  return out.read_text(encoding="utf-8")


def check_ir(ir: str) -> None:
  required = ["goron_decrypt_string_i8", "goron_decrypt_string_i16",
              "harmless", "tiny"]
  for needle in required:
    if needle not in ir:
      raise SystemExit(f"missing expected IR marker: {needle}")

  leaked = ["ascii-taokari-secret", "utf16-taokari-secret",
            "wide-taokari-secret"]
  for needle in leaked:
    if needle in ir:
      raise SystemExit(f"secret string leaked in IR: {needle}")

  status_values = re.findall(r"@dec_status_[^=]*=.*global i32 (-?\d+)", ir)
  if not status_values:
    raise SystemExit("no dec_status globals found")
  bad = [value for value in status_values if value in {"0", "1"}]
  if bad:
    raise SystemExit(f"plain status initializer found: {bad[0]}")
  if re.search(r"store i32 1, ptr .*dec_status", ir):
    raise SystemExit("plain status store found")

  calls = re.findall(
      r"call void @goron_decrypt_string_i(?:8|16)\([^\n]*, i32 (-?\d+), i32 (\d+), i32 (-?\d+)\)",
      ir,
  )
  if not calls:
    raise SystemExit("decrypt calls do not carry done_status/string_id/build_nonce")
  for _done_status, _string_id, build_nonce in calls:
    if build_nonce in {"0", "1"}:
      raise SystemExit("weak build nonce found")

  i8_body = re.search(r"define private void @goron_decrypt_string_i8\b[\s\S]*?\n}", ir)
  i16_body = re.search(r"define private void @goron_decrypt_string_i16\b[\s\S]*?\n}", ir)
  if not i8_body or not i16_body:
    raise SystemExit("missing i8/i16 decryptor body")
  if not all(needle in i8_body.group(0) for needle in ["lshr", "59", "17"]):
    raise SystemExit("i8 decryptor lacks nonce/position key mixing")
  if not all(needle in i16_body.group(0) for needle in ["lshr", "40503", "257"]):
    raise SystemExit("i16 decryptor lacks nonce/position key mixing")


def run_checks(tmp: Path) -> int:
    src = tmp / "stringenc_level1.cpp"
    plain = tmp / "plain.exe"
    obf = tmp / "obf.exe"
    ll = tmp / "obf.ll"
    cfg = tmp / "stringenc.json"
    src.write_text(SOURCE, encoding="utf-8")
    cfg.write_text(json.dumps({
        "cse": {
            "enable": True,
            "minStringLength": 5,
            "skipStrings": ["harmless"],
        }
    }), encoding="utf-8")

    compile_exe(src, plain, None)
    compile_exe(src, obf, cfg)
    plain_run = run([str(plain)])
    obf_run = run([str(obf)])
    must(plain_run, "plain run")
    must(obf_run, "obfuscated run")
    if plain_run.stdout != obf_run.stdout:
      raise SystemExit(
          f"stdout mismatch\nplain={plain_run.stdout!r}\nobf={obf_run.stdout!r}"
      )

    check_ir(emit_ir(src, ll, cfg))
    print("string encryption verifier: ok")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()

    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    tmp = Path(tempfile.mkdtemp(prefix="taokari-strenc-l1-"))
    try:
        return run_checks(tmp)
    finally:
        if args.keep:
            print(f"kept temp dir: {tmp}")
        else:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
