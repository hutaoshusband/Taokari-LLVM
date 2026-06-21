"""VMP Level-2 hardening verifier.

Checks generated IR for the first practical-VM hardening layer:
encrypted bytecode globals, per-function bytecode keys, per-function opcode
maps, and non-canonical handler layout. Runtime output must still match.
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
OPMAP_RE = re.compile(
    r"@__taokari_vmp_opmap_(\w+) = .*?\[(\d+) x i64\] \[(.*?)\]",
)
CALL_RE = re.compile(
    r"call i64 @(__taokari_vmp_interp_i64_[^(]+)\((.*?)\)"
)
BC_ARG_RE = re.compile(r"ptr nonnull @__taokari_vmp_bc_(\w+)")
CALL_TAIL_RE = re.compile(
    r"i64 (-?\d+), ptr (?:nonnull )?@__taokari_vmp_opmap_(\w+), i64 ([^,]+)$"
)
KEY_SEED_RE = re.compile(r"@__taokari_vmp_key_seed_(\w+) = .*?global i64 (-?\d+)")
I64_RE = re.compile(r"i64 (-?\d+)")


def fail(msg: str) -> int:
    print(f"vmp l2 hardening: FAIL ({msg})", file=sys.stderr)
    return 1


def check_ir(text: str) -> int:
    for constant in (
        "-6510615554653179231",
        "4354685564936845354",
        "-4658895280553007687",
        "-7723592293110705685",
    ):
        if constant not in text:
            return fail("bytecode stream schedule constants missing")

    globals_by_name: dict[str, list[int]] = {}
    for name, _count, body in GLOBAL_RE.findall(text):
        words = [int(v) for v in I64_RE.findall(body)]
        if words:
            globals_by_name[name] = words
    opmaps: dict[str, tuple[int, ...]] = {}
    for name, _count, body in OPMAP_RE.findall(text):
        values = tuple(int(v) for v in I64_RE.findall(body))
        if values:
            opmaps[name] = values

    calls: list[tuple[str, str]] = []
    interp_names: list[str] = []
    for interp_name, args in CALL_RE.findall(text):
        interp_names.append(interp_name)
        bc_match = BC_ARG_RE.search(args)
        tail_match = CALL_TAIL_RE.search(args)
        if not bc_match or not tail_match:
            continue
        _tag, opmap_name, key_arg = tail_match.groups()
        if bc_match.group(1) != opmap_name:
            return fail(f"{bc_match.group(1)} uses mismatched opcode map")
        calls.append((bc_match.group(1), key_arg.strip()))
    if len(calls) < 6:
        return fail("missing hardened interpreter calls")
    if len(set(interp_names)) != len(calls):
        return fail("interpreter symbols are still shared")

    seed_globals = dict(KEY_SEED_RE.findall(text))
    if len(seed_globals) < len(calls):
        return fail("missing per-function runtime key seeds")
    if len(set(seed_globals.values())) < 4:
        return fail("runtime key seeds are not per-function")
    if len(opmaps) < len(calls) or len(set(opmaps.values())) < 4:
        return fail("opcode maps are not per-function")

    expected_ops = set(range(1, 39))
    for name, key_arg in calls:
        words = globals_by_name.get(name)
        if not words:
            return fail(f"missing bytecode global for {name}")
        opmap = opmaps.get(name)
        if not opmap:
            return fail(f"{name} missing opcode map")
        decoded = [op for op in opmap if op >= 0]
        if set(decoded) != expected_ops or len(decoded) != len(expected_ops):
            return fail(f"{name} opcode map does not decode the VM opcode set")
        if re.fullmatch(r"-?\d+", key_arg):
            return fail(f"{name} bytecode key is still a plaintext call literal")
        if name not in seed_globals:
            return fail(f"{name} missing runtime key seed global")
        if 0 <= words[0] < 64:
            return fail(f"{name} bytecode first word is plaintext")

    switch_bodies = re.findall(r"switch i64 .*?\[(.*?)\]", text, re.S)
    if not switch_bodies:
        return fail("missing interpreter switch")
    case_orders = [
        tuple(int(v) for v in re.findall(r"i64 (\d+), label", body))
        for body in switch_bodies
    ]
    if any(order == tuple(sorted(order)) for order in case_orders):
        return fail("handler cases are still canonical order")
    if len(set(case_orders)) < 2:
        return fail("handler switch order is still shared")
    return 0


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-vmp-l2-") as tmp:
        tmpdir = Path(tmp)
        src = tmpdir / "l2.c"
        src.write_text(SOURCE, encoding="utf-8")

        for opt in ("-O2", "-O3"):
            ll = tmpdir / f"l2{opt}.ll"
            exe = tmpdir / f"l2{opt}.exe"
            flags = [
                str(CLANG), str(src), opt,
                "-mllvm", "-taokari", "-mllvm", "-taokari-vmp",
            ]
            ir = run([*flags, "-S", "-emit-llvm", "-o", str(ll)],
                     use_vs_env=True)
            if ir.returncode:
                sys.stderr.write(ir.stdout + ir.stderr)
                return 1
            checked = check_ir(ll.read_text(encoding="utf-8", errors="ignore"))
            if checked:
                return checked

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
