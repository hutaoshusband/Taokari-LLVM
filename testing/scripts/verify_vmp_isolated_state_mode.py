from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

from verify_vmp_basic_block_bytecode import CLANG, run


SOURCE = r"""
#include <stdio.h>

#define VMP __attribute__((noinline, annotate("+vmp")))

VMP int iso_a(int a) {
  int x = ((a + 5) ^ 0x29) * 3;
  return (x & 1) ? x - a : x + 7;
}

VMP int iso_b(int b) {
  int y = ((b * 11) ^ 0x63) + 17;
  return (y % 13) + (b << 1);
}

int main(void) {
  printf("vmp-iso:%d:%d:%d\n", iso_a(11), iso_b(19), iso_a(5));
  return 0;
}
"""


def compat_rows(path: Path) -> dict[str, str]:
    rows: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and not line.startswith("function\t"):
            rows[parts[0]] = parts[1]
    return rows


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-vmp-iso-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "iso.c"
        ll = tmp / "iso.ll"
        exe = tmp / "iso.exe"
        report = tmp / "iso.tsv"
        src.write_text(SOURCE, encoding="utf-8")
        flags = [
            str(CLANG), str(src), "-O2", "-fno-discard-value-names",
            "-mllvm", "-taokari", "-mllvm", "-taokari-vmp",
            "-mllvm", "-taokari-vmp-test-isolated-state",
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
        if result.returncode or not result.stdout.startswith("vmp-iso:"):
            sys.stderr.write(result.stdout + result.stderr)
            return 1

        rows = compat_rows(report)
        for name in ("iso_a", "iso_b"):
            if rows.get(name) != "virtualized":
                raise SystemExit(f"{name} did not virtualize: {rows}")

        text = ll.read_text(encoding="utf-8", errors="ignore")

    states = re.findall(r"@__taokari_vmp_xstate_[^=\s]+ =", text)
    if len(states) != 2:
        raise SystemExit(f"expected two isolated VM states, got {len(states)}")
    if "@__taokari_vmp_xstate =" in text:
        raise SystemExit("isolated mode still emitted shared VM state")
    for name in ("iso_a", "iso_b"):
        if f"@__taokari_vmp_xstate_{name}" not in text:
            raise SystemExit(f"missing isolated VM state for {name}")

    print("vmp isolated state mode: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
