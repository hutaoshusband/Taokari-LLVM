"""ocnst/cie composition verifier (TK-017).

OpaqueConstant was registered after ConstantIntEncryption, and CIE's
candidate predicate is a strict superset of ocnst's, so ocnst found zero
candidates and the help-text promise ("composable with cie") was dead.
With ocnst registered first it takes its subset (16..64-bit constants in
non-GEP non-PHI non-terminator instructions) and CIE handles the rest
(8-bit constants, GEP offset operands, PHI feeds). Asserts that:
  1. the composed pipeline carries real ocnst substitution markers
     (NOT the pre-eligibility <fn>.ocnst.nonce global, which is created
     even when the pass finds nothing to rewrite),
  2. CIE markers still appear in the composed pipeline,
  3. ocnst only shrinks CIE's share (composed CIE markers <= cie-only),
  4. native, cie-only and composed stdout agree byte-for-byte.
The ocnst rewrite is made seed-independent with -taokari-ocnst-prob=100:
the (FuncRNG() % 100) >= Probability rejection never fires, so every
eligible candidate is substituted deterministically. CIE seeds itself
from OS entropy and ocnst substitution is deterministic, so no gate
depends on randomSeed; it stays pinned for the cfg consumers that
honor it (RTTI erasers, MetadataHygiene).
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

CLANG = tp.CLANG
VSDEVCMD = tp.VSDEVCMD

SEED = "tk017-ocnst-cie-composition"

# Substitution-value names OpaqueConstant emits (OpaqueConstant.cpp):
# ".ocnst.enc.<n>" globals, "ocnst.enc.ld"/"ocnst.nonce.ld" loads,
# "ocnst.plain" xor and "ocnst.val" trunc. The <fn>.ocnst.nonce global
# (getOrCreateNonce) exists before any candidate is found and must not
# count as proof of a rewrite, so it is deliberately absent here.
OCNST_SUBST = re.compile(
    r"\.ocnst\.enc\.\d+|ocnst\.(?:enc\.ld|nonce\.ld|plain|val)")

# CIE pool-path names, all level >= 3 gated (ConstantIntEncryption.cpp):
# <fn>.cie.pool, <fn>.cie.pool.ref, <fn>.cie.shard.<n>, cie.pool.ld,
# cie.pool.ptr, cie.pool.ref.ld, cie.shard.ref.ld.
CIE_MARKER = re.compile(r"cie\.pool|cie\.shard")

SOURCE = r"""
#include <stdio.h>
#include <stdint.h>

static uint32_t table[64];
static volatile uint32_t g_seed = 0x12345678u;

/* 8-bit constants: CIE-only territory (ocnst skips types under 16 bits). */
__attribute__((noinline)) static unsigned char mix8(unsigned char a) {
  unsigned char r = (a == (unsigned char)0xA7u) ? (unsigned char)0x3Cu
                  : (a <  (unsigned char)0x80u) ? (unsigned char)0xB1u
                  : (unsigned char)0x5Eu;
  return r;
}

/* 32/64-bit magic constants in plain binops: ocnst/cie intersection. */
__attribute__((noinline)) static uint32_t mix32(uint32_t x) {
  x *= 0x85EBCA6Bu;
  x ^= x >> 13;
  x *= 0xC2B2AE35u;
  x ^= x >> 16;
  return x;
}

__attribute__((noinline)) static uint64_t mix64(uint64_t x) {
  x *= 0x9E3779B97F4A7C15ull;
  x ^= x >> 29;
  x *= 0xBF58476D1CE4E5B9ull;
  x ^= x >> 32;
  return x;
}

int main(void) {
  uint64_t h = mix64(((uint64_t)g_seed << 16) ^ 0x0123456789ABCDEFull);
  h ^= mix32(g_seed ^ 0xDEADBEEFu);

  /* GEP constant offsets: CIE-only territory (ocnst skips GEP insts). */
  table[g_seed % 8u] = (uint32_t)h;
  h += table[37] + table[19] - table[7];

  /* Loop with a PHI-visible constant: CIE-only territory. */
  uint32_t acc = 0x811C9DC5u;
  for (uint32_t i = 0; i < 16u; ++i) {
    acc = acc * 0x01000193u + (uint32_t)mix8((unsigned char)(acc >> 8));
  }

  unsigned char c = mix8((unsigned char)(h >> 24));
  printf("ocnst-cie:%02x:%u:%llu\n", c, acc % 100000u,
         (unsigned long long)(h ^ acc));
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


def write_cfg(path: Path) -> None:
  cfg = {
      "randomSeed": SEED,
      "cie": {
          "enable": True,
          "level": 3,
      },
  }
  path.write_text(json.dumps(cfg), encoding="utf-8")


def compile_cmd(src: Path, out: Path, taokari: list[str],
                emit_ir: bool = False) -> list[str]:
  # Marker gates inspect the raw -O0 IR (mba-verifier convention): at -O2
  # the optimizer folds/uniques value names the marker counts rely on.
  opt = ["-O0", "-fno-discard-value-names"] if emit_ir else ["-O2"]
  cmd = [str(CLANG), str(src), *opt, "-o", str(out)]
  if emit_ir:
    cmd += ["-S", "-emit-llvm"]
  if not tp.IS_WINDOWS:
    cmd += ["-fdeclspec"]
  cmd += taokari
  return cmd


def main() -> int:
  if not CLANG.exists():
    print(f"missing clang: {CLANG}", file=sys.stderr)
    return 2

  tmp = Path(tempfile.mkdtemp(prefix="taokari-ocnst-cie-"))
  try:
    src = tmp / "ocnst_cie.c"
    src.write_text(SOURCE.strip() + "\n", encoding="utf-8")
    cfg = tmp / "cie3.json"
    write_cfg(cfg)

    cie_only_flags = ["-mllvm", "-taokari", "-mllvm", "-taokari-cie",
                      "-mllvm", f"-taokari-cfg={cfg}"]
    composed_flags = cie_only_flags + ["-mllvm", "-taokari-ocnst",
                                       "-mllvm", "-taokari-ocnst-prob=100"]

    cie_ir = tmp / "cie_only.ll"
    must(run_vs(compile_cmd(src, cie_ir, cie_only_flags, emit_ir=True),
                src.parent), "emit cie-only IR")
    composed_ir = tmp / "composed.ll"
    must(run_vs(compile_cmd(src, composed_ir, composed_flags, emit_ir=True),
                src.parent), "emit composed IR")
    cie_text = cie_ir.read_text(encoding="utf-8", errors="ignore")
    composed_text = composed_ir.read_text(encoding="utf-8", errors="ignore")

    # Gate A (teeth): real ocnst substitution markers in the composed IR.
    # The bare <fn>.ocnst.nonce global proves nothing: it is created before
    # eligibility, so a tail-registered (dead) ocnst still leaks one into
    # the IR. Only the enc/ld/plain/val family proves a rewrite happened.
    ocnst_hits = len(OCNST_SUBST.findall(composed_text))
    gate(ocnst_hits > 0,
         f"composed IR contains ocnst substitution markers "
         f"(gate A, found {ocnst_hits})")

    # Gate B: CIE still fires in the composed pipeline (pool path, L3).
    composed_cie_hits = len(CIE_MARKER.findall(composed_text))
    gate(composed_cie_hits > 0,
         f"composed IR still contains CIE pool markers "
         f"(gate B, found {composed_cie_hits})")

    # Gate C: ocnst may only shrink CIE's share, never grow it.
    cie_only_hits = len(CIE_MARKER.findall(cie_text))
    gate(composed_cie_hits <= cie_only_hits,
         f"CIE markers composed ({composed_cie_hits}) <= cie-only "
         f"({cie_only_hits}) (gate C)")

    # Gate D: differential runtime parity, byte-for-byte stdout.
    stdout = {}
    for name, flags in (("native", []), ("cie", cie_only_flags),
                        ("composed", composed_flags)):
      exe = tmp / f"{name}.exe"
      must(run_vs(compile_cmd(src, exe, flags), src.parent),
           f"build {name} exe")
      ran = run([str(exe)])
      must(ran, f"run {name} exe")
      stdout[name] = ran.stdout
    gate(stdout["native"].startswith("ocnst-cie:")
         and stdout["native"].endswith("\n"),
         f"native binary produces deterministic output "
         f"(got {stdout['native']!r})")
    gate(stdout["native"] == stdout["cie"] == stdout["composed"],
         f"native/cie/composed stdout agree byte-for-byte "
         f"(gate D): {stdout['native']!r}")

    print("ocnst/cie composition verifier: ok")
    return 0
  finally:
    shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
  raise SystemExit(main())
