"""Key-schedule recovery verifier for StringEncryption.

todo.md "Reverse-engineering report follow-up":
  * Fix StringEncryption's remaining XOR-key weakness: replace single-pass
    inline XOR-looking decode with rolling or stateful per-character mixing.
  * Add verifier that the string literal/key schedule is not recoverable as
    adjacent encrypted bytes plus inline XOR key.

What an analyst with the binary does today to recover strings:
  1. locate the encrypted pool global
  2. assume the first K bytes are the XOR key and the next N bytes are the
     ciphertext
  3. XOR them per-position (with key wraparound) and check for ASCII output

The current encoder stores [junk | key | ciphertext | junk] in the pool and
the decode loop is dominated by per-character XOR. This verifier proves two
gates:

  A. pool-byte brute force: for every window [offset .. offset+K] treated as
     a candidate key and every reasonable key length K, sliding XOR over the
     following L bytes must NOT yield the known plaintext secret. The encoder
     must mix the key with per-position state so a plain wraparound-XOR over
     adjacent pool bytes does not decrypt.
  B. IR shape: the decryptor body must not be dominated by a single inline
     `xor` per character that consumes the pool key verbatim. We assert that
     per-iteration work includes non-XOR state (add/sub/rotate/mix) so the
     decode is stateful/rolling, not a clean XOR lift.

Both gates are semantic too: the protected binary must still produce the same
stdout as the plain one, so the encoder is provably self-consistent.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
VSDEVCMD = tp.VSDEVCMD

# A secret that is long enough to be recoverable by naive wraparound-XOR if the
# encoder stored key||cipher adjacently. Distinct characters make a wrong key
# obvious (not all printable).
SECRET = "taokari-key-schedule-rolling-mix-secret-7Q"

SOURCE = r'''
#include <cstdio>

static const char *secret = "''' + SECRET + r'''";

__declspec(noinline)
static int score(const char *s) {
  int acc = 0;
  for (const unsigned char *p = reinterpret_cast<const unsigned char *>(s); *p; ++p)
    acc = acc * 131 + *p;
  return acc;
}

int main() {
  std::printf("strenc-key:%d\n", score(secret));
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


def gate(cond: bool, label: str) -> None:
  if not cond:
    raise SystemExit(f"GATE FAILED: {label}")
  print(f"  [ok] {label}")


def write_cfg(path: Path, **extra) -> None:
  cfg = {"cse": {"enable": True, "level": 3, "minStringLength": 5}}
  cfg["cse"].update(extra)
  path.write_text(json.dumps(cfg), encoding="utf-8")


def compile_exe(src: Path, out: Path, cfg: Path) -> None:
  cmd = [str(CLANG), str(src), "-std=c++17", "-O2", "-o", str(out),
         "-mllvm", "-taokari", "-mllvm", "-taokari-cse",
         "-mllvm", f"-taokari-cfg={cfg}"]
  if not tp.IS_WINDOWS:
    cmd += ["-fdeclspec", "-D_GNU_SOURCE"]
  must(run_vs(cmd, src.parent), f"compile {out.name}")


def emit_ir(src: Path, out: Path, cfg: Path) -> str:
  cmd = [str(CLANG), str(src), "-std=c++17", "-O2", "-S", "-emit-llvm",
         "-fno-discard-value-names",
         "-mllvm", "-taokari", "-mllvm", "-taokari-cse",
         "-mllvm", f"-taokari-cfg={cfg}", "-o", str(out)]
  if not tp.IS_WINDOWS:
    cmd += ["-fdeclspec", "-D_GNU_SOURCE"]
  must(run_vs(cmd, src.parent), "emit IR")
  return out.read_text(encoding="utf-8")


def extract_pool_bytes(ir: str) -> bytes:
  """Concatenate every EncryptedStringTable initializer blob.

  The pool global is emitted as a constant byte array in IR. Each line looks
  like `c"XX\\XX..."; the hex pairs are the raw bytes. Multiple pool shards
  may exist; we concatenate them so the brute-force scan covers the whole
  data layout an analyst sees.
  """
  blob = bytearray()
  for m in re.finditer(r'@(?:EncryptedStringTable|FakeStringPool)[^\n]*?'
                       r'c"([^"]*)"', ir):
    raw = m.group(1)
    i = 0
    while i < len(raw):
      ch = raw[i]
      if ch == "\\":
        hexpart = raw[i + 1:i + 3]
        if re.fullmatch(r"[0-9A-Fa-f]{2}", hexpart):
          blob.append(int(hexpart, 16))
          i += 3
          continue
        i += 1
      else:
        blob.append(ord(ch))
        i += 1
  return bytes(blob)


def brute_force_xor_recover(blob: bytes, secret: bytes,
                            max_key: int = 64) -> bool:
  """Return True if a wraparound-XOR over adjacent pool bytes yields secret.

  Mirrors the classic analyst attack: try every (offset, keylen) pair, treat
  the keylen bytes starting at offset as the key, XOR the next len(secret)
  bytes with that key (wraparound), check for an exact plaintext match.
  """
  n = len(blob)
  L = len(secret)
  if L == 0 or n < L:
    return False
  for keylen in range(1, max_key + 1):
    for off in range(0, n - keylen - L + 1):
      key = blob[off:off + keylen]
      cipher = blob[off + keylen:off + keylen + L]
      got = bytes(c ^ key[i % keylen] for i, c in enumerate(cipher))
      if got == secret:
        return True
  return False


def decryptor_is_pure_xor(ir: str) -> bool:
  """Heuristic: is the i8 decryptor a clean wraparound XOR over the pool key?

  A "clean XOR lift" has the shape: load key byte, load cipher byte, xor,
  store. No add/sub/rotate/state mixing. We require at least one non-XOR
  arithmetic op per iteration (add/sub/rotate/and/or/shl) so the decode is
  stateful/rolling, not a single-XOR lift.
  """
  m = re.search(r"define[^@]*@goron_decrypt_string_i8\b[\s\S]*?\n}",
                ir)
  if not m:
    return True  # missing decryptor is treated as a different kind of fail
  body = m.group(0)
  # Count per-iteration arithmetic ops other than xor.
  non_xor = sum(len(re.findall(rf"\b{op}\b", body))
                for op in ("add", "sub", "shl", "lshr", "ashr", "and", "or"))
  xors = len(re.findall(r"\bxor\b", body))
  # A pure XOR lift has zero non-XOR arithmetic ops on the data path. The
  # status compare uses icmp (not counted). Allow the trivial xor count to
  # remain, but require state-mixing ops alongside it.
  return non_xor == 0 and xors > 0


def main() -> int:
  if not CLANG.exists():
    print(f"missing clang: {CLANG}", file=sys.stderr)
    return 2

  tmp = Path(tempfile.mkdtemp(prefix="taokari-strenc-key-"))
  try:
    source_text = (
        ROOT / "upstream" / "taokari" / "llvm" / "lib" / "Transforms"
        / "Obfuscation" / "StringEncryption.cpp"
    ).read_text(encoding="utf-8", errors="ignore")
    gate("getRandomBytes(JunkBytes, 1, 16)" in source_text,
         "pool entries carry randomized tail junk after ciphertext")

    src = tmp / "strenc_key.cpp"
    src.write_text(SOURCE, encoding="utf-8")
    plain = tmp / "plain.exe"
    plain_flags = ["-fdeclspec", "-D_GNU_SOURCE"] if not tp.IS_WINDOWS else []
    must(run_vs([str(CLANG), str(src), "-std=c++17", "-O2", *plain_flags, "-o", str(plain)],
                src.parent), "plain compile")
    plain_run = run([str(plain)])
    must(plain_run, "plain run")

    cfg = tmp / "cse3.json"
    write_cfg(cfg)
    ir = emit_ir(src, tmp / "cse3.ll", cfg)

    blob = extract_pool_bytes(ir)
    gate(len(blob) > 0, "pool bytes extractable from IR")
    gate(not brute_force_xor_recover(blob, SECRET.encode()),
         "wraparound-XOR over adjacent pool bytes does not recover secret")

    gate(not decryptor_is_pure_xor(ir),
         "decryptor is not a pure inline XOR lift (stateful mixing present)")

    exe = tmp / "cse3.exe"
    compile_exe(src, exe, cfg)
    ran = run([str(exe)])
    must(ran, "protected run")
    if ran.stdout != plain_run.stdout:
      raise SystemExit(f"stdout mismatch: {ran.stdout!r} != {plain_run.stdout!r}")

    print("string encryption key-schedule verifier: ok")
    return 0
  finally:
    shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
  raise SystemExit(main())
