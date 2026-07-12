"""Verify VMP bytecode uses distinct encrypted basic-block domains."""
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

#define NOINLINE __attribute__((noinline))
#define VMP __attribute__((noinline, annotate("+vmp")))

NOINLINE int side_a(int x) { return (x * 3) + 11; }
NOINLINE int side_b(int x) { return (x ^ 0x35) - 7; }
NOINLINE int side_c(int x) { return (x << 1) ^ 0x123; }
NOINLINE int side_d(int x) { return (x >> 1) + 0x29; }

VMP int block_mix(int x, int y) {
  int r = x + 17;
  if ((x & 1) != 0)
    r += side_a(y);
  else
    r -= side_b(y);
  if ((r & 4) != 0)
    r ^= side_c(x);
  else
    r += side_d(y);
  return r ^ (x * 5);
}

int main(void) {
  printf("vmp-bb:%d:%d\n", block_mix(17, 9), block_mix(22, 5));
  return 0;
}
"""

BC_RE = re.compile(
    r"@__taokari_vmp_bc_(\w+) = .*?\[(\d+) x i64\] \[(.*?)\]",
    re.S,
)
PCMAP_RE = re.compile(
    r"@__taokari_vmp_pcmap_(\w+) = .*?constant \[(\d+) x i8\] c\"((?:\\.|[^\"])*)\"",
    re.S,
)
I64_RE = re.compile(r"i64 (-?\d+)")


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


def parse_ir_c_bytes(body: str) -> list[int]:
    out: list[int] = []
    i = 0
    while i < len(body):
        if body[i] == "\\" and i + 2 < len(body):
            h = body[i + 1:i + 3]
            if re.fullmatch(r"[0-9A-Fa-f]{2}", h):
                out.append(int(h, 16))
                i += 3
                continue
            out.append(ord(body[i + 1]) & 0xFF)
            i += 2
            continue
        out.append(ord(body[i]) & 0xFF)
        i += 1
    return out


def compat_rows(path: Path) -> dict[str, str]:
    rows: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and not line.startswith("function\t"):
            rows[parts[0]] = parts[1]
    return rows


def check_ir(text: str, report: Path) -> None:
    if compat_rows(report).get("block_mix") != "virtualized":
        raise SystemExit("block_mix did not virtualize")

    bc_match = next(
        ((name, body) for name, _count, body in BC_RE.findall(text)
         if name == "block_mix"),
        None,
    )
    pc_match = next(
        ((name, count, body) for name, count, body in PCMAP_RE.findall(text)
         if name == "block_mix"),
        None,
    )
    if bc_match is None or pc_match is None:
        raise SystemExit("missing block_mix bytecode or pc map")

    words = [int(v) for v in I64_RE.findall(bc_match[1])]
    flags = parse_ir_c_bytes(pc_match[2])
    if len(words) != int(pc_match[1]) or len(words) != len(flags):
        raise SystemExit("bytecode and pc map lengths differ")
    if any(0 <= word < 64 for word in words[:8]):
        raise SystemExit("bytecode still exposes plaintext opcode-like words")

    starts = [flag >> 1 for flag in flags if (flag & 1) != 0]
    if len(starts) < 8:
        raise SystemExit("too few opcode-start markers in pc map")
    if len(set(starts)) < 4:
        raise SystemExit("basic-block bytecode did not get separate domains")
    changes = sum(1 for a, b in zip(starts, starts[1:]) if a != b)
    if changes < 3:
        raise SystemExit("pc map rotation does not advance across blocks")


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-vmp-bb-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "bb.c"
        ll = tmp / "bb.ll"
        exe = tmp / "bb.exe"
        report = tmp / "bb.tsv"
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
        if result.returncode or not result.stdout.startswith("vmp-bb:"):
            sys.stderr.write(result.stdout + result.stderr)
            return 1
        check_ir(ll.read_text(encoding="utf-8", errors="ignore"), report)

    print("vmp basic-block bytecode: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
