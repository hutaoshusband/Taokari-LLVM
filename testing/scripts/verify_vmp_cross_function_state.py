"""Verify VMP interpreters share module-level VM state."""
from __future__ import annotations

import json
import re
import sys
import tempfile
from pathlib import Path
import _taokari_portable as tp

from verify_vmp_basic_block_bytecode import CLANG, run


SOURCE = r"""
#include <stdio.h>

#define VMP __attribute__((noinline, annotate("+vmp")))

VMP int state_a(int a) {
  int x = ((a + 7) ^ 0x35) * 5;
  return (x & 3) ? x - a : x + 11;
}

VMP int state_b(int b) {
  int y = ((b * 9) ^ 0x62) + 13;
  return (y % 17) + (b << 2);
}

int main(void) {
  printf("vmp-state:%d:%d:%d\n", state_a(11), state_b(19), state_a(5));
  return 0;
}
"""

FUNC_RE = re.compile(
    r"define[^{@]*@(?P<name>state_[ab])\([^)]*\)[^{]*\{(?P<body>.*?)\n\}",
    re.S,
)
INTERP_RE = re.compile(
    r"define[^{@]*@__taokari_vmp_interp_i64_(?P<name>state_[ab])_[^(]*"
    r"\([^)]*\)[^{]*\{(?P<body>.*?)\n\}",
    re.S,
)


def compat_rows(path: Path) -> dict[str, str]:
    rows: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and not line.startswith("function\t"):
            rows[parts[0]] = parts[1]
    return rows


def body_map(pattern: re.Pattern[str], text: str) -> dict[str, str]:
    return {match.group("name"): match.group("body")
            for match in pattern.finditer(text)}


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-vmp-xstate-") as tmp_name:
        tmp = Path(tmp_name)
        cfg = tmp / "seed.json"
        src = tmp / "state.c"
        ll = tmp / "state.ll"
        exe = tmp / "state.exe"
        report = tmp / "state.tsv"
        cfg.write_text(json.dumps({"randomSeed": "vmp-cross-state"}),
                       encoding="utf-8")
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
            return 1
        built = run([*flags, "-o", str(exe)], use_vs_env=True)
        if built.returncode:
            sys.stderr.write(built.stdout + built.stderr)
            return 1
        result = run([str(exe)])
        if result.returncode or not result.stdout.startswith("vmp-state:"):
            sys.stderr.write(result.stdout + result.stderr)
            return 1

        rows = compat_rows(report)
        for name in ("state_a", "state_b"):
            if rows.get(name) != "virtualized":
                raise SystemExit(f"{name} did not virtualize: {rows}")

        text = ll.read_text(encoding="utf-8", errors="ignore")

    if text.count("@__taokari_vmp_xstate =") != 1:
        raise SystemExit("missing single shared VM state global")
    wrappers = body_map(FUNC_RE, text)
    interps = body_map(INTERP_RE, text)
    for name in ("state_a", "state_b"):
        body = wrappers.get(name)
        if not body or "@__taokari_vmp_xstate" not in body:
            raise SystemExit(f"{name} wrapper does not pass shared VM state")
        if "call i64 @__taokari_vmp_interp_i64_" not in body:
            raise SystemExit(f"{name} wrapper did not call a VMP interpreter")
        ibody = interps.get(name)
        if not ibody:
            raise SystemExit(f"missing {name} interpreter")
        if "load volatile i64" not in ibody or "store volatile i64" not in ibody:
            raise SystemExit(f"{name} interpreter lacks volatile VM state update")
        if "vmp.xstate" not in ibody:
            raise SystemExit(f"{name} interpreter lacks VM state names")

    print("vmp cross-function state: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
