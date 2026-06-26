"""Verify VMP bytecode integrity seeds are cross-function."""
from __future__ import annotations

import json
import re
import sys
import tempfile
from pathlib import Path

from verify_vmp_basic_block_bytecode import CLANG, ROOT, run


SOURCE = r"""
#include <stdio.h>

#define VMP __attribute__((noinline, annotate("+vmp")))

VMP int cross_a(int a) {
  int x = ((a + 3) ^ 0x51) * 5;
  return (x / 3) + (a & 7);
}

VMP int cross_b(int b) {
  int y = ((b * 7) ^ 0x24) + __B_CONST__;
  return (y % 11) ^ (b << 1);
}

int main(void) {
  printf("vmp-cross:%d:%d\n", cross_a(31), cross_b(12));
  return 0;
}
"""

FUNC_RE = re.compile(
    r"define[^{@]*@(?P<name>cross_[ab])\([^)]*\)[^{]*\{(?P<body>.*?)\n\}",
    re.S,
)
INTERP_RE = re.compile(
    r"define[^{@]*@__taokari_vmp_interp_i64_(?P<name>cross_[ab])_[^(]*"
    r"\([^)]*\)[^{]*\{(?P<body>.*?)\n\}",
    re.S,
)
TAG_STORE_RE = re.compile(r"store i64 (-?\d+), ptr %(?:vmp\.rekey\.tag|tag)")


def compat_rows(path: Path) -> dict[str, str]:
    rows: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and not line.startswith("function\t"):
            rows[parts[0]] = parts[1]
    return rows


def tag_seed(pattern: re.Pattern[str], text: str, name: str) -> int:
    for match in pattern.finditer(text):
        if match.group("name") != name:
            continue
        seed = TAG_STORE_RE.search(match.group("body"))
        if seed:
            return int(seed.group(1))
    raise SystemExit(f"missing tag seed for {name}")


def build_variant(tmp: Path, label: str, b_const: int) -> int:
    cfg = tmp / f"{label}.json"
    src = tmp / f"{label}.c"
    ll = tmp / f"{label}.ll"
    exe = tmp / f"{label}.exe"
    report = tmp / f"{label}.tsv"
    cfg.write_text(json.dumps({"randomSeed": "vmp-cross-integrity"}),
                   encoding="utf-8")
    src.write_text(SOURCE.replace("__B_CONST__", str(b_const)),
                   encoding="utf-8")
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
    if result.returncode or not result.stdout.startswith("vmp-cross:"):
        sys.stderr.write(result.stdout + result.stderr)
        raise SystemExit(1)

    rows = compat_rows(report)
    if rows.get("cross_a") != "virtualized" or rows.get("cross_b") != "virtualized":
        raise SystemExit(f"VMP functions did not virtualize in {label}: {rows}")

    text = ll.read_text(encoding="utf-8", errors="ignore")
    wrapper_seed = tag_seed(FUNC_RE, text, "cross_a")
    interp_seed = tag_seed(INTERP_RE, text, "cross_a")
    if wrapper_seed != interp_seed:
        raise SystemExit("wrapper/interpreter bytecode tag seeds differ")
    return wrapper_seed


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-vmp-cross-int-") as tmp_name:
        tmp = Path(tmp_name)
        seed_a = build_variant(tmp, "base", 11)
        seed_b = build_variant(tmp, "mutated", 19)
        if seed_a == seed_b:
            raise SystemExit("cross_a tag seed ignored cross_b bytecode change")

    print("vmp cross bytecode integrity: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
