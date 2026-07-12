"""Verify VMP uses per-function runtime ISA tokens beyond opcode permutation."""
from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
VSDEVCMD = tp.VSDEVCMD

SOURCE = r"""
#include <stdio.h>

#define VMP __attribute__((noinline, annotate("+vmp")))

VMP int isa_alpha(int a, int b) {
  int x = ((a + b) ^ 0x71) * 5;
  int y = ((a << 2) | (b & 15)) - 3;
  return (x > y) ? (x / 3 + y) : (x - y);
}

VMP int isa_beta(int a, int b) {
  int x = ((a - b) ^ 0x35) * 7;
  int y = ((unsigned)b >> 1) + (a & 31);
  return (x != y) ? (x % 11 + y) : (x ^ y);
}

int main(void) {
  printf("vmp-isa:%d:%d\n", isa_alpha(41, 9), isa_beta(41, 9));
  return 0;
}
"""

OPMAP_RE = re.compile(
    r"@__taokari_vmp_opmap_(\w+) = .*?\[\d+ x i64\] \[(.*?)\]",
    re.S,
)
I64_RE = re.compile(r"i64 (-?\d+)")
STABLE_OPCODE_MAX = 44


def run(cmd: list[str], *, cwd: Path = ROOT, timeout: int = 180,
        use_vs_env: bool = False) -> subprocess.CompletedProcess[str]:
    if use_vs_env and VSDEVCMD.exists():
        with tempfile.NamedTemporaryFile("w", suffix=".cmd", delete=False,
                                         encoding="utf-8") as handle:
            batch = Path(handle.name)
            handle.write("@echo off\n")
            handle.write(f'call "{VSDEVCMD}" -arch=x64 -host_arch=x64 >nul\n')
            handle.write(subprocess.list2cmdline(cmd) + "\n")
            handle.write("exit /b %ERRORLEVEL%\n")
        try:
            return subprocess.run(["cmd.exe", "/d", "/c", str(batch)],
                                  cwd=cwd, text=True, capture_output=True,
                                  timeout=timeout)
        finally:
            batch.unlink(missing_ok=True)
    return subprocess.run(cmd, cwd=cwd, text=True, capture_output=True,
                          timeout=timeout)


def compat_rows(path: Path) -> dict[str, str]:
    rows: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and not line.startswith("function\t"):
            rows[parts[0]] = parts[1]
    return rows


def parse_opmaps(ir: str) -> dict[str, tuple[int, ...]]:
    return {
        name: tuple(int(v) for v in I64_RE.findall(body))
        for name, body in OPMAP_RE.findall(ir)
    }


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-vmp-isa-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "isa.c"
        ll = tmp / "isa.ll"
        exe = tmp / "isa.exe"
        report = tmp / "isa.tsv"
        src.write_text(SOURCE, encoding="utf-8")
        flags = [
            str(CLANG), str(src), "-O2", "-fno-discard-value-names",
            "-mllvm", "-taokari", "-mllvm", "-taokari-vmp",
            "-mllvm", f"-taokari-vmp-compat-report={report}",
        ]
        ir = run([*flags, "-S", "-emit-llvm", "-o", str(ll)],
                 use_vs_env=True)
        if ir.returncode:
            sys.stderr.write(ir.stdout + ir.stderr)
            return 1
        build = run([*flags, "-o", str(exe)], use_vs_env=True)
        if build.returncode:
            sys.stderr.write(build.stdout + build.stderr)
            return 1
        result = run([str(exe)])
        if result.returncode or not result.stdout.startswith("vmp-isa:"):
            sys.stderr.write(result.stdout + result.stderr)
            return 1

        rows = compat_rows(report)
        for name in ("isa_alpha", "isa_beta"):
            if rows.get(name) != "virtualized":
                raise SystemExit(f"{name} did not virtualize")

        opmaps = parse_opmaps(ll.read_text(encoding="utf-8", errors="ignore"))
        wanted = {name: opmaps.get(name) for name in ("isa_alpha", "isa_beta")}
        if any(values is None for values in wanted.values()):
            raise SystemExit("missing per-function opcode maps")
        if wanted["isa_alpha"] == wanted["isa_beta"]:
            raise SystemExit("two VMP functions reused the same ISA map")

        for name, values in wanted.items():
            assert values is not None
            live = [v for v in values if v >= 0]
            high = [v for v in live if v > STABLE_OPCODE_MAX]
            if len(live) < STABLE_OPCODE_MAX:
                raise SystemExit(f"{name} lost live runtime opcode tokens")
            if len(high) < 8:
                raise SystemExit(
                    f"{name} runtime ISA only permutes stable opcode values"
                )

    print("vmp isa randomization: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
