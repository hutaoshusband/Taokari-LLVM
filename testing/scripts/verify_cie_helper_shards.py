"""Verify CIE constant access through helper shards.

At cie L3+ the ConstantIntEncryption pass now routes each constant access
through an outlined helper shard function (<fn>.cie.shard.<n>) that
encapsulates the pool load + decrypt. Each use site becomes a call
(cie.shard.call) rather than inlined pool-GEP/load/decrypt IR, so a
decompiler reads the constant access as a call edge, not an inline
arithmetic chain. One shard per distinct encrypted constant.

Contract (same source, -emit-llvm):
  * L3 build: .cie.shard. functions exist and use sites call them
    (cie.shard.call markers present).
  * L3 build: the shard bodies contain the pool GEP/load + decrypt
    (cie.shard.ptr / cie.shard.ld markers), proving the work moved into the
    shard rather than the use site.
  * L2 build: no .cie.shard functions (shards are L3-gated).
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

PLAIN_CONST = 0xABCDEF0123456789

SOURCE = f"""
#include <cstdint>
#include <cstdio>

__attribute__((noinline)) int64_t magic() {{
  volatile int64_t v = 0;
  int64_t secret = {PLAIN_CONST}LL;
  int64_t secret2 = {PLAIN_CONST ^ 0xAAAAAAAAAAAAAAAA}LL;
  return (secret + v) ^ secret2;
}}

int main() {{
  std::printf("cieshard:%lld\\n", static_cast<long long>(magic()));
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


def count_marker(text: str, marker: str) -> int:
    return text.count(marker)


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-cie-shard-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "cie_shard.cpp"
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

        shard_defs = count_marker(l3_text, ".cie.shard.")
        shard_calls = count_marker(l3_text, "cie.shard.call")
        shard_ptrs = count_marker(l3_text, "cie.shard.ptr")
        shard_lds = count_marker(l3_text, "cie.shard.ld")
        if shard_defs == 0:
            print("FAIL: L3 IR defines no .cie.shard functions", file=sys.stderr)
            return 1
        if shard_calls == 0:
            print("FAIL: L3 IR has no cie.shard.call use-site calls", file=sys.stderr)
            return 1
        if shard_ptrs == 0 or shard_lds == 0:
            print("FAIL: L3 shard bodies missing pool GEP/load (cie.shard.ptr/.ld)",
                  file=sys.stderr)
            return 1
        if ".cie.shard" in l2_text:
            print("FAIL: L2 IR leaked .cie.shard (shards must be L3-gated)",
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

    print(f"cie helper shards: ok ({shard_defs} shard fns, {shard_calls} use-site "
          f"calls, pool work in shard bodies, runtime matches native)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
