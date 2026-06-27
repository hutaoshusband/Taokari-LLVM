"""Verify CIE per-function constant pool.

At cie L3+ the ConstantIntEncryption pass now collects every encrypted
integer constant of a function into a single per-function byte-array
global (the "pool", named <fn>.cie.pool) instead of emitting one
GlobalVariable per constant. Each use site GEPs into the pool at its own
offset and decrypts, so a reverser cannot enumerate individual constant
globals.

Contract (same source, -emit-llvm + linked binary):
  * L3 build: the IR contains a .cie.pool global and cie.pool.ptr /
    cie.pool.ld loads indexing into it (pool path fired).
  * L2 build: no .cie.pool global (pool is L3-gated).
  * L3 binary: the plaintext constant does NOT appear in the .rdata/.data
    bytes (encryption survived to the final binary).
  * Correctness: the L3 obfuscated binary runs and matches native output.

Exit: 0 ok | 1 contract failure | 2 missing clang.
"""
from __future__ import annotations

import struct
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CLANG = ROOT / "build" / "taokari-local" / "bin" / "clang.exe"
VSDEVCMD = Path(
    r"C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat"
)

PLAIN_CONST = 0x123456789ABCDEF0

SOURCE = f"""
#include <cstdint>
#include <cstdio>

__attribute__((noinline)) int64_t magic() {{
  volatile int64_t v = 0;
  int64_t secret = {PLAIN_CONST}LL;
  int64_t secret2 = {PLAIN_CONST ^ 0x0F0F0F0F0F0F0F0F}LL;
  return (secret + v) ^ secret2;
}}

int main() {{
  std::printf("ciepool:%lld\\n", static_cast<long long>(magic()));
  return 0;
}}
"""


def run(command: list[str], *, cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    if VSDEVCMD.exists():
        with tempfile.NamedTemporaryFile(
            "w", suffix=".cmd", delete=False, encoding="utf-8"
        ) as handle:
            batch = Path(handle.name)
            handle.write(
                "@echo off\n"
                f'call "{VSDEVCMD}" -arch=x64 -host_arch=x64 >nul\n'
                f"{subprocess.list2cmdline(command)}\n"
                "exit /b %ERRORLEVEL%\n"
            )
        try:
            return subprocess.run(
                ["cmd.exe", "/d", "/c", str(batch)], cwd=cwd,
                text=True, capture_output=True,
            )
        finally:
            batch.unlink(missing_ok=True)
    return subprocess.run(command, cwd=cwd, text=True, capture_output=True)


def must(result: subprocess.CompletedProcess[str], label: str) -> bool:
    if result.returncode:
        sys.stderr.write(f"{label} failed:\n")
        sys.stderr.write(result.stdout + result.stderr)
        return False
    return True


def mllvm(flags: list[str]) -> list[str]:
    out = []
    for f in flags:
        out += ["-mllvm", f]
    return out


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-cie-pool-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "cie_pool.cpp"
        src.write_text(SOURCE, encoding="utf-8")

        l3_ir = tmp / "l3.ll"
        if not must(run([
            str(CLANG), str(src), "-O2", "-fno-discard-value-names",
            *mllvm(["-taokari", "-taokari-cie", "-taokari-level-cie=3"]),
            "-S", "-emit-llvm", "-o", str(l3_ir),
        ]), "L3 emit-llvm"):
            return 1
        l3_text = l3_ir.read_text(encoding="utf-8", errors="ignore")

        l2_ir = tmp / "l2.ll"
        if not must(run([
            str(CLANG), str(src), "-O2", "-fno-discard-value-names",
            *mllvm(["-taokari", "-taokari-cie", "-taokari-level-cie=2"]),
            "-S", "-emit-llvm", "-o", str(l2_ir),
        ]), "L2 emit-llvm"):
            return 1
        l2_text = l2_ir.read_text(encoding="utf-8", errors="ignore")

        if ".cie.pool" not in l3_text:
            print("FAIL: L3 IR has no .cie.pool global", file=sys.stderr)
            return 1
        if ("cie.pool.ld" not in l3_text and "cie.shard.ld" not in l3_text) or \
                "getelementptr" not in l3_text:
            print("FAIL: L3 IR has no pool/shard load+GEP markers",
                  file=sys.stderr)
            return 1
        if not any(("cie.pool" in line or "cie.shard" in line)
                   and "getelementptr" in line
                   for line in l3_text.splitlines()):
            print("FAIL: L3 IR does not GEP into the pool", file=sys.stderr)
            return 1
        if ".cie.pool.ref" not in l3_text and "cie.shard.ref" not in l3_text:
            print("FAIL: L3 IR has no indirect pool-ref slot "
                  "(indirect constant references not wired)", file=sys.stderr)
            return 1
        if ("cie.pool.ref.ld" not in l3_text
                and "cie.shard.ref.ld" not in l3_text):
            print("FAIL: L3 IR has no indirect pool/shard base load",
                  file=sys.stderr)
            return 1
        if ".cie.pool" in l2_text:
            print("FAIL: L2 IR leaked a .cie.pool global (pool must be L3-gated)",
                  file=sys.stderr)
            return 1

        native = run([str(CLANG), str(src), "-O2", "-o", str(tmp / "native.exe")])
        if not must(native, "native build"):
            return 1
        native_run = run([str(tmp / "native.exe")])
        if native_run.returncode:
            sys.stderr.write("native run failed\n")
            return 1

        obf = tmp / "l3.exe"
        if not must(run([
            str(CLANG), str(src), "-O2",
            *mllvm(["-taokari", "-taokari-cie", "-taokari-level-cie=3"]),
            "-o", str(obf),
        ]), "L3 exe build"):
            return 1
        obf_run = run([str(obf)])
        if obf_run.returncode or obf_run.stdout != native_run.stdout:
            print(f"FAIL: L3 runtime mismatch rc={obf_run.returncode} "
                  f"out={obf_run.stdout!r} expected={native_run.stdout!r}",
                  file=sys.stderr)
            return 1

        plain_le = struct.pack("<Q", PLAIN_CONST)
        plain_be = struct.pack(">Q", PLAIN_CONST)
        obf_bytes = obf.read_bytes()
        if plain_le in obf_bytes or plain_be in obf_bytes:
            print("FAIL: plaintext constant survived into the L3 binary",
                  file=sys.stderr)
            return 1

    print(f"cie per-function pool: ok (.cie.pool present at L3, absent at L2, "
          f"plaintext hidden in binary, runtime matches native)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
