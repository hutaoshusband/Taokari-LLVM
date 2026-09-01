"""Verify same-source VMP builds differ across build seeds."""
from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
VSDEVCMD = tp.VSDEVCMD

SOURCE = r"""
#include <stdio.h>

#define VMP __attribute__((noinline, annotate("+vmp")))

VMP int poly_one(int a, int b) {
  int x = ((a + b) ^ 0x45) * 3;
  int y = (a & 7) + (b << 2);
  if ((x ^ y) & 1)
    return x - y;
  return x + y + 9;
}

int main(void) {
  printf("vmp-poly:%d\n", poly_one(7, 11));
  return 0;
}
"""

KEY_RE = re.compile(r"@__taokari_vmp_key_seed_(\w+) = .*?global i64 (-?\d+)")
OPMAP_RE = re.compile(
    r"@__taokari_vmp_opmap_(\w+) = .*?\[\d+ x i64\] \[(.*?)\]",
    re.S,
)
BC_RE = re.compile(
    r"@__taokari_vmp_bc_(\w+) = .*?\[\d+ x i64\] \[(.*?)\]",
    re.S,
)
INTERP_RE = re.compile(r"define[^{]*?@\"?(__taokari_vmp_interp_i64_[^\"\s(]+)")
I64_RE = re.compile(r"i64 (-?\d+)")


@dataclass(frozen=True)
class Signature:
    key_seed: tuple[tuple[str, str], ...]
    opmap: tuple[tuple[str, tuple[int, ...]], ...]
    bytecode: tuple[tuple[str, tuple[int, ...]], ...]
    interpreters: tuple[str, ...]


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


def signature(ir: str) -> Signature:
    key_seed = tuple(sorted(KEY_RE.findall(ir)))
    opmap = tuple(
        sorted((name, tuple(int(v) for v in I64_RE.findall(body)))
               for name, body in OPMAP_RE.findall(ir))
    )
    bytecode = tuple(
        sorted((name, tuple(int(v) for v in I64_RE.findall(body)))
               for name, body in BC_RE.findall(ir))
    )
    interpreters = tuple(sorted(INTERP_RE.findall(ir)))
    return Signature(key_seed, opmap, bytecode, interpreters)


def compat_virtualized(path: Path) -> bool:
    text = path.read_text(encoding="utf-8", errors="ignore")
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and parts[0] == "poly_one":
            return parts[1] == "virtualized"
    return False


def build_one(tmp: Path, src: Path, seed: str) -> Signature:
    cfg = tmp / f"{seed}.json"
    ll = tmp / f"{seed}.ll"
    exe = tmp / f"{seed}.exe"
    report = tmp / f"{seed}.tsv"
    cfg.write_text(json.dumps({"randomSeed": seed}), encoding="utf-8")
    flags = [
        str(CLANG), str(src), "-O2", "-fno-discard-value-names",
        "-mllvm", "-taokari", "-mllvm", "-taokari-vmp",
        "-mllvm", f"-taokari-cfg={cfg}",
        "-mllvm", f"-taokari-vmp-compat-report={report}",
    ]
    ir = run([*flags, "-S", "-emit-llvm", "-o", str(ll)], use_vs_env=True)
    if ir.returncode:
        sys.stderr.write(ir.stdout + ir.stderr)
        raise SystemExit(1)
    build = run([*flags, "-o", str(exe)], use_vs_env=True)
    if build.returncode:
        sys.stderr.write(build.stdout + build.stderr)
        raise SystemExit(1)
    result = run([str(exe)])
    if result.returncode or not result.stdout.startswith("vmp-poly:"):
        sys.stderr.write(result.stdout + result.stderr)
        raise SystemExit("polymorphic VMP binary failed at runtime")
    if not compat_virtualized(report):
        raise SystemExit(f"poly_one did not virtualize under seed {seed}")
    sig = signature(ll.read_text(encoding="utf-8", errors="ignore"))
    if not sig.key_seed or not sig.opmap or not sig.bytecode or not sig.interpreters:
        raise SystemExit(f"missing VMP signature material under seed {seed}")
    return sig


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-vmp-poly-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "poly.c"
        src.write_text(SOURCE, encoding="utf-8")
        a = build_one(tmp, src, "taokari-vmp-poly-a")
        b = build_one(tmp, src, "taokari-vmp-poly-b")

    checks = {
        "key_seed": a.key_seed != b.key_seed,
        "opmap": a.opmap != b.opmap,
        "bytecode": a.bytecode != b.bytecode,
        "interpreters": a.interpreters != b.interpreters,
    }
    failures = [name for name, ok in checks.items() if not ok]
    if failures:
        raise SystemExit("polymorphic VMP builds did not differ in: "
                         + ", ".join(failures))

    print("vmp polymorphic builds: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
