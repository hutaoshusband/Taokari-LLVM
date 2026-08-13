"""Verify CIE indirect constant references.

At cie L3+ the ConstantIntEncryption pass resolves the per-function pool
base through an opaque indirect pointer slot (<fn>.cie.pool.ref) instead
of a direct @pool reference. Each use site loads the pool base from the
slot, then GEPs into it, so no use site carries a direct reference to the
@pool global. This is the constant-layer analogue of indirect-call/branch
page-table indirection.

Contract (same source, -emit-llvm):
  * L3 build: a .cie.pool.ref global exists and every pool access loads the
    base via cie.pool.ref.ld before GEPing (no use-site GEPs @pool directly).
  * A direct @pool GEP at a use site would betray the pool; assert there is
    at least one cie.pool.ref.ld and that GEPs reference the loaded base
    rather than the pool global symbol.
  * L2 build: no .cie.pool and no .cie.pool.ref (both are L3-gated).
  * Correctness: the L3 obfuscated binary runs and matches native output.

Exit: 0 ok | 1 contract failure | 2 missing clang.
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
VSDEVCMD = tp.VSDEVCMD

PLAIN_CONST = 0xCAFEBABEDEADC0DE

SOURCE = f"""
#include <cstdint>
#include <cstdio>

__attribute__((noinline)) int64_t magic() {{
  volatile int64_t v = 1;
  int64_t secret = {PLAIN_CONST}LL;
  return secret + v;
}}

int main() {{
  std::printf("cieindir:%lld\\n", static_cast<long long>(magic()));
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

    with tempfile.TemporaryDirectory(prefix="taokari-cie-indir-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "cie_indir.cpp"
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
        if ".cie.pool.ref" not in l3_text:
            print("FAIL: L3 IR has no indirect .cie.pool.ref slot",
                  file=sys.stderr)
            return 1
        ref_ld_count = (l3_text.count("cie.pool.ref.ld")
                       + l3_text.count("cie.shard.ref.ld"))
        if ref_ld_count == 0:
            print("FAIL: L3 IR has no indirect pool/shard base load "
                  "(indirection never resolved)", file=sys.stderr)
            return 1

        direct_pool_gep = 0
        for line in l3_text.splitlines():
            if "getelementptr" not in line:
                continue
            if ".cie.pool\"" in line and ".cie.pool.ref" not in line:
                direct_pool_gep += 1
        if direct_pool_gep > 0:
            print(f"FAIL: {direct_pool_gep} use-site GEP(s) reference the pool "
                  f"global directly (indirection defeated)", file=sys.stderr)
            return 1

        if ".cie.pool" in l2_text:
            print("FAIL: L2 IR leaked .cie.pool (must be L3-gated)",
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

    print(f"cie indirect constant ref: ok ({ref_ld_count} indirect base load(s), "
          f"0 direct pool GEPs, runtime matches native)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
