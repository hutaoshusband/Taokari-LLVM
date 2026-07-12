"""Verify configurable VMP dummy opcode padding preserves behavior."""
from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path
import _taokari_portable as tp

from verify_vmp_coverage import CLANG, SOURCE, run

BC_RE = re.compile(r"@__taokari_vmp_bc_\w+ = .*?\[(\d+) x i64\]")
HIST_RE = re.compile(
    r"padding histogram \((\d+) opcodes, (\d+) top hits, "
    r"(\d+) bp, (\d+) pad hits\)"
)


def fail(msg: str) -> int:
    print(f"vmp padding: FAIL ({msg})", file=sys.stderr)
    return 1


def bytecode_words(text: str) -> int:
    return sum(int(n) for n in BC_RE.findall(text))


def histogram_top_share(remarks: str) -> tuple[int, int, int]:
    opcodes = top_hits = pad_hits = 0
    for ops, top, _bp, pads in HIST_RE.findall(remarks):
        opcodes += int(ops)
        top_hits += int(top)
        pad_hits += int(pads)
    if not opcodes:
        return 0, 0, 0
    return (top_hits * 10000) // opcodes, opcodes, pad_hits


def build(tmpdir: Path, name: str, padding: int) -> tuple[int, str, str]:
    src = tmpdir / f"{name}.c"
    ll = tmpdir / f"{name}.ll"
    exe = tmpdir / f"{name}.exe"
    src.write_text(SOURCE, encoding="utf-8")
    flags = [
        str(CLANG), str(src), "-O2",
        "-mllvm", "-taokari",
        "-mllvm", "-taokari-vmp",
        "-mllvm", f"-taokari-vmp-padding={padding}",
        "-Rpass=taokari-vmp",
        "-Rpass-missed=taokari-vmp",
    ]
    ir = run([*flags, "-S", "-emit-llvm", "-o", str(ll)], use_vs_env=True)
    if ir.returncode:
        sys.stderr.write(ir.stdout + ir.stderr)
        return -1, "", ""
    linked = run([*flags, "-o", str(exe)], use_vs_env=True)
    if linked.returncode:
        sys.stderr.write(linked.stdout + linked.stderr)
        return -1, "", ""
    result = run([str(exe)])
    if result.returncode:
        sys.stderr.write(result.stdout + result.stderr)
        return -1, "", ""
    return (
        bytecode_words(ll.read_text(encoding="utf-8", errors="ignore")),
        result.stdout,
        ir.stdout + ir.stderr,
    )


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-vmp-padding-") as tmp:
        tmpdir = Path(tmp)
        base_words, base_out, base_remarks = build(tmpdir, "base", 0)
        padded_words, padded_out, padded_remarks = build(tmpdir, "padded", 100)
        if base_words < 0 or padded_words < 0:
            return 1
        if padded_out != base_out:
            return fail("padded execution changed program output")
        if padded_words <= base_words:
            return fail("padding did not increase encoded bytecode size")
        base_share, base_ops, base_pads = histogram_top_share(base_remarks)
        padded_share, padded_ops, padded_pads = histogram_top_share(padded_remarks)
        if not base_ops or not padded_ops:
            return fail("padding histogram remarks missing")
        if base_pads:
            return fail("disabled padding still emitted pad handler hits")
        if not padded_pads:
            return fail("enabled padding emitted no pad handler hits")
        if padded_share >= base_share:
            return fail("padding did not flatten top handler hit concentration")

    print("vmp padding: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
