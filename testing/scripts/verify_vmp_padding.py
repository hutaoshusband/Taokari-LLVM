"""Verify configurable VMP dummy opcode padding preserves behavior."""
from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

from verify_vmp_coverage import CLANG, SOURCE, run

BC_RE = re.compile(r"@__taokari_vmp_bc_\w+ = .*?\[(\d+) x i64\]")


def fail(msg: str) -> int:
    print(f"vmp padding: FAIL ({msg})", file=sys.stderr)
    return 1


def bytecode_words(text: str) -> int:
    return sum(int(n) for n in BC_RE.findall(text))


def build(tmpdir: Path, name: str, padding: int) -> tuple[int, str]:
    src = tmpdir / f"{name}.c"
    ll = tmpdir / f"{name}.ll"
    exe = tmpdir / f"{name}.exe"
    src.write_text(SOURCE, encoding="utf-8")
    flags = [
        str(CLANG), str(src), "-O2",
        "-mllvm", "-taokari",
        "-mllvm", "-taokari-vmp",
        "-mllvm", f"-taokari-vmp-padding={padding}",
    ]
    ir = run([*flags, "-S", "-emit-llvm", "-o", str(ll)], use_vs_env=True)
    if ir.returncode:
        sys.stderr.write(ir.stdout + ir.stderr)
        return -1, ""
    linked = run([*flags, "-o", str(exe)], use_vs_env=True)
    if linked.returncode:
        sys.stderr.write(linked.stdout + linked.stderr)
        return -1, ""
    result = run([str(exe)])
    if result.returncode:
        sys.stderr.write(result.stdout + result.stderr)
        return -1, ""
    return bytecode_words(ll.read_text(encoding="utf-8", errors="ignore")), result.stdout


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-vmp-padding-") as tmp:
        tmpdir = Path(tmp)
        base_words, base_out = build(tmpdir, "base", 0)
        padded_words, padded_out = build(tmpdir, "padded", 100)
        if base_words < 0 or padded_words < 0:
            return 1
        if padded_out != base_out:
            return fail("padded execution changed program output")
        if padded_words <= base_words:
            return fail("padding did not increase encoded bytecode size")

    print("vmp padding: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
