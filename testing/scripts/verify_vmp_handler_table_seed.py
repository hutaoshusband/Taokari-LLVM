"""Verify VMP handler table obfuscation changes with the build seed."""
from __future__ import annotations

import json
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
import _taokari_portable as tp

from verify_vmp_basic_block_bytecode import CLANG, run


SOURCE = r"""
#include <stdio.h>

#define VMP __attribute__((noinline, annotate("+vmp")))

VMP int seeded_handlers(int a, int b) {
  int x = ((a + b) ^ 0x67) * 3;
  int y = ((a << 2) - (b / 3)) ^ 0x21;
  if ((x ^ y) & 1)
    return x - y + (a % 5);
  return x + y - (b % 7);
}

int main(void) {
  printf("vmp-handler-seed:%d:%d\n",
         seeded_handlers(21, 8), seeded_handlers(5, 14));
  return 0;
}
"""

INTERP_RE = re.compile(
    r"define[^{@]*@__taokari_vmp_interp_i64_seeded_handlers_[^(]*"
    r"\([^)]*\)[^{]*\{(?P<body>.*?)\n\}",
    re.S,
)
ENTRY_RE = re.compile(r"^([a-zA-Z0-9_.]+\.entry):", re.M)
ROUTE_RE = re.compile(r"store i64 (-?\d+), ptr %handler\.state")


@dataclass(frozen=True)
class HandlerSignature:
    order: tuple[str, ...]
    routes: tuple[int, ...]


def compat_virtualized(path: Path) -> bool:
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and parts[0] == "seeded_handlers":
            return parts[1] == "virtualized"
    return False


def handler_signature(ir: str) -> HandlerSignature:
    match = INTERP_RE.search(ir)
    if not match:
        raise SystemExit("missing seeded_handlers interpreter")
    body = match.group("body")
    order = tuple(name for name in ENTRY_RE.findall(body)
                  if name != "handler.route")
    routes = tuple(int(v) for v in ROUTE_RE.findall(body))
    if len(order) < 8 or len(routes) < 8:
        raise SystemExit("handler table evidence is too small")
    return HandlerSignature(order, routes)


def build_one(tmp: Path, seed: str) -> HandlerSignature:
    cfg = tmp / f"{seed}.json"
    src = tmp / f"{seed}.c"
    ll = tmp / f"{seed}.ll"
    exe = tmp / f"{seed}.exe"
    report = tmp / f"{seed}.tsv"
    cfg.write_text(json.dumps({"randomSeed": seed}), encoding="utf-8")
    src.write_text(SOURCE, encoding="utf-8")
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
    built = run([*flags, "-o", str(exe)], use_vs_env=True)
    if built.returncode:
        sys.stderr.write(built.stdout + built.stderr)
        raise SystemExit(1)
    result = run([str(exe)])
    if result.returncode or not result.stdout.startswith("vmp-handler-seed:"):
        sys.stderr.write(result.stdout + result.stderr)
        raise SystemExit(1)
    if not compat_virtualized(report):
        raise SystemExit(f"seeded_handlers did not virtualize under {seed}")
    return handler_signature(ll.read_text(encoding="utf-8", errors="ignore"))


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-vmp-handler-seed-") as tmp_name:
        tmp = Path(tmp_name)
        a = build_one(tmp, "vmp-handler-seed-a")
        b = build_one(tmp, "vmp-handler-seed-b")

    if a.order == b.order:
        raise SystemExit("handler table order ignored build seed")
    if a.routes == b.routes:
        raise SystemExit("handler route tokens ignored build seed")

    print("vmp handler-table seed: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
