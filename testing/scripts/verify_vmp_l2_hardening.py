"""VMP Level-2 hardening verifier.

Checks generated IR for the first practical-VM hardening layer:
encrypted bytecode globals, per-function bytecode keys, per-function opcode
masks, and non-canonical handler layout. Runtime output must still match.
"""
from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

from verify_vmp_coverage import CLANG, ROOT, SOURCE, run


GLOBAL_RE = re.compile(
    r"@__taokari_vmp_bc_(\w+) = .*?\[(\d+) x i64\] \[(.*?)\]",
)
CALL_RE = re.compile(
    r"call i64 @__taokari_vmp_interp_i64\("
    r"ptr nonnull @__taokari_vmp_bc_(\w+), i64 \d+, "
    r"ptr nonnull @__taokari_vmp_pcmap_\w+, ptr (?:nonnull %\d+|null), "
    r"i64 \d+, ptr nonnull %\d+, "
    r"i64 \d+, ptr nonnull %\d+, i64 -?\d+, "
    r"i64 (-?\d+), i64 (-?\d+)\)"
)
I64_RE = re.compile(r"i64 (-?\d+)")


def fail(msg: str) -> int:
    print(f"vmp l2 hardening: FAIL ({msg})", file=sys.stderr)
    return 1


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-vmp-l2-") as tmp:
        tmpdir = Path(tmp)
        src = tmpdir / "l2.c"
        ll = tmpdir / "l2.ll"
        exe = tmpdir / "l2.exe"
        src.write_text(SOURCE, encoding="utf-8")

        flags = [
            str(CLANG), str(src), "-O2",
            "-mllvm", "-taokari", "-mllvm", "-taokari-vmp",
        ]
        ir = run([*flags, "-S", "-emit-llvm", "-o", str(ll)], use_vs_env=True)
        if ir.returncode:
            sys.stderr.write(ir.stdout + ir.stderr)
            return 1
        text = ll.read_text(encoding="utf-8", errors="ignore")

        globals_by_name: dict[str, list[int]] = {}
        for name, _count, body in GLOBAL_RE.findall(text):
            words = [int(v) for v in I64_RE.findall(body)]
            if words:
                globals_by_name[name] = words
        calls = [(name, int(key), int(mask)) for name, key, mask in CALL_RE.findall(text)]
        if len(calls) < 6:
            return fail("missing hardened interpreter calls")

        keys = {key for _name, key, _mask in calls}
        masks = {mask for _name, _key, mask in calls}
        if len(keys) < 4 or len(masks) < 4:
            return fail("keys/opcode masks are not per-function")

        for name, key, mask in calls:
            words = globals_by_name.get(name)
            if not words:
                return fail(f"missing bytecode global for {name}")
            first_plain_mapped = words[0] ^ key
            if first_plain_mapped != (1 ^ mask):
                return fail(f"{name} first opcode does not decrypt through key+mask")
            if words[0] in (1, 1 ^ mask):
                return fail(f"{name} bytecode first word is plaintext")

        switch_match = re.search(r"switch i64 .*?\[(.*?)\]", text, re.S)
        if not switch_match:
            return fail("missing interpreter switch")
        case_values = [int(v) for v in re.findall(r"i64 (\d+), label", switch_match.group(1))]
        if case_values == sorted(case_values):
            return fail("handler cases are still canonical order")

        build = run([*flags, "-o", str(exe)], use_vs_env=True)
        if build.returncode:
            sys.stderr.write(build.stdout + build.stderr)
            return 1
        result = run([str(exe)])
        if result.returncode:
            sys.stderr.write(result.stdout + result.stderr)
            return 1

    print("vmp l2 hardening: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
