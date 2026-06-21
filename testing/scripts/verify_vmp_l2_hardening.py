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
PCMAP_RE = re.compile(
    r"@__taokari_vmp_pcmap_(\w+) = .*?constant \[(\d+) x i8\] c\"((?:\\.|[^\"])*)\"",
    re.S,
)
CALLEE_TABLE_RE = re.compile(
    r"@__taokari_vmp_callees = .*?\[(\d+) x i64\] \[(.*?)\]",
    re.S,
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


def check_ir(text: str) -> int:
    for constant in (
        "-6510615554653179231",
        "4354685564936845354",
        "-4658895280553007687",
        "-7723592293110705685",
        "-3372029247567499371",
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
    pcmaps: dict[str, list[int]] = {}
    for name, count, body in PCMAP_RE.findall(text):
        flags = parse_ir_c_bytes(body)
        if len(flags) != int(count):
            return fail(f"{name} pcmap length is wrong")
        pcmaps[name] = flags

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

    expected_ops = set(range(1, 45))
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
        flags = pcmaps.get(name)
        if not flags:
            return fail(f"{name} missing pc rotation map")
        if len(flags) != len(words):
            return fail(f"{name} pc rotation map length does not match bytecode")
        if not any((flag & 1) != 0 for flag in flags):
            return fail(f"{name} pc map lost opcode-start markers")

    rotated = [
        name for name, flags in pcmaps.items()
        if len({flag >> 1 for flag in flags}) > 1
    ]
    if len(rotated) < 2:
        return fail("per-basic-block bytecode rotation is not observable")

    if text.count("indirectbr") < len(calls) * 2:
        return fail("VM handler dispatch is not flattened through two indirectbr layers")
    if text.count("blockaddress(") < len(calls):
        return fail("VM handler dispatch does not use blockaddress targets")
    indirect_dests = [
        len(re.findall(r"label ", body))
        for body in re.findall(r"indirectbr ptr .*?\[(.*?)\]", text, re.S)
    ]
    if len(indirect_dests) < len(calls):
        return fail("missing VM indirectbr destination lists")
    if any(count < len(expected_ops) + 4 for count in indirect_dests):
        return fail("fake/dead handler targets are missing")

    callee_match = CALLEE_TABLE_RE.search(text)
    if not callee_match:
        return fail("missing direct-call callee table")
    callee_count = int(callee_match.group(1))
    callee_body = callee_match.group(2)
    if "__taokari_vmp_callthunk_" not in text:
        return fail("direct-call thunks were not emitted")
    if "__taokari_vmp_callthunk_" in callee_body or "ptrtoint" in callee_body:
        return fail("callee table still exposes thunk pointers")
    callee_tokens = [int(v) for v in I64_RE.findall(callee_body)]
    if len(callee_tokens) != callee_count:
        return fail("callee table token count is wrong")
    if any(0 <= token < callee_count for token in callee_tokens):
        return fail("callee table entries are still plaintext indices")
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
