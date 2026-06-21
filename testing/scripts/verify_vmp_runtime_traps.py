"""Runtime tamper checks for the Taokari VMP interpreter."""
from __future__ import annotations

import re
import random
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CLANG = ROOT / "build" / "taokari-local" / "bin" / "clang.exe"
VSDEVCMD = Path(
    r"C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat"
)

GOLDEN = 0x9E3779B97F4A7C15
MASK64 = (1 << 64) - 1
TRAP_EXIT = 86

OP_PUSH_CONST = 2
OP_LOAD_SLOT = 3
OP_STORE_SLOT = 4
OP_SDIV = 24
OP_SREM = 26
OP_LOAD_PTR = 32
OP_STORE_PTR = 33
OP_RET = 16
OP_JMP = 14

TY_I32 = 32 | (1 << 8)
TY_I64 = 64 | (1 << 8)

SOURCE = r"""
#include <stdint.h>

#define VMP __attribute__((noinline, annotate("+vmp")))

VMP int victim(int a, int b) {
  int x = a;
  int local[4] = {1, 2, 3, 4};
  x = (x + b + 1) ^ local[0];
  x = (x + b + 2) ^ local[1];
  x = (x + b + 3) ^ local[2];
  x = (x + b + 4) ^ local[3];
  x = (x + b + 5) ^ local[0];
  x = (x + b + 6) ^ local[1];
  x = (x + b + 7) ^ local[2];
  x = (x + b + 8) ^ local[3];
  x = (x + b + 9) ^ local[0];
  x = (x + b + 10) ^ local[1];
  x = (x + b + 11) ^ local[2];
  x = (x + b + 12) ^ local[3];
  x = (x + b + 13) ^ local[0];
  x = (x + b + 14) ^ local[1];
  x = (x + b + 15) ^ local[2];
  x = (x + b + 16) ^ local[3];
  x = (x + b + 17) ^ local[0];
  x = (x + b + 18) ^ local[1];
  x = (x + b + 19) ^ local[2];
  x = (x + b + 20) ^ local[3];
  x = (x + b + 21) ^ local[0];
  x = (x + b + 22) ^ local[1];
  x = (x + b + 23) ^ local[2];
  x = (x + b + 24) ^ local[3];
  x = (x + b + 25) ^ local[0];
  x = (x + b + 26) ^ local[1];
  x = (x + b + 27) ^ local[2];
  x = (x + b + 28) ^ local[3];
  x = (x * 3) + (a & 7);
  x = x - (b | 5);
  x = b ? (x / b) + (x % b) : x;
  return x + local[(a ^ b) & 3];
}

int main(void) {
  int r = victim(91, 7);
  return r == victim(91, 7) ? 0 : 1;
}
"""

BC_RE = re.compile(
    r"@__taokari_vmp_bc_(\w+) = private unnamed_addr constant "
    r"\[(\d+) x i64\] \[(.*?)\], align 8",
    re.S,
)
PCMAP_RE = re.compile(
    r"@__taokari_vmp_pcmap_(\w+) = private unnamed_addr constant "
    r"\[(\d+) x i8\] (.*?), align 1",
    re.S,
)
CALL_RE = re.compile(
    r"call i64 @__taokari_vmp_interp_i64\("
    r"ptr [^,]*@__taokari_vmp_bc_(\w+), i64 \d+, "
    r"ptr [^,]*@__taokari_vmp_pcmap_\w+, ptr [^,]+, i64 \d+, "
    r"ptr [^,]+, i64 \d+, "
    r"ptr [^,]+, i64 (-?\d+), i64 ([^,]+), i64 (-?\d+)\)"
)
KEY_SEED_RE = re.compile(r"@__taokari_vmp_key_seed_(\w+) = .*?global i64 (-?\d+)")
KEY_DERIV_RE = re.compile(
    r"(%\d+) = load volatile i64, ptr @__taokari_vmp_key_seed_(\w+), align 8\s+"
    r"(%\d+) = xor i64 \1, (-?\d+)\s+"
    r"(%\d+) = mul i64 \3, (-?\d+)\s+"
    r"(%\d+) = add i64 \5, (-?\d+)\s+"
    r"(%\d+) = shl i64 \7, (\d+)\s+"
    r"(%\d+) = lshr i64 \7, (\d+)\s+"
    r"(%\d+) = or i64 \9, \11\s+"
    r"(%\d+) = xor i64 \13, (-?\d+)",
    re.S,
)
I64_RE = re.compile(r"i64 (-?\d+)")


def run(cmd: list[str], *, cwd: Path = ROOT,
        use_vs_env: bool = False) -> subprocess.CompletedProcess[str]:
    if use_vs_env and VSDEVCMD.exists():
        with tempfile.NamedTemporaryFile("w", suffix=".cmd", delete=False,
                                         encoding="utf-8") as handle:
            batch = Path(handle.name)
            handle.write("@echo off\n")
            handle.write(f'call "{VSDEVCMD}" -arch=x64 -host_arch=x64 >nul\n')
            handle.write(subprocess.list2cmdline(cmd) + "\n")
        try:
            return subprocess.run(["cmd.exe", "/c", str(batch)], cwd=cwd,
                                  text=True, capture_output=True)
        finally:
            batch.unlink(missing_ok=True)
    return subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)


def to_u64(v: int) -> int:
    return v & MASK64


def to_i64(v: int) -> int:
    v &= MASK64
    return v - (1 << 64) if v & (1 << 63) else v


def rotl64(v: int, rot: int) -> int:
    rot &= 63
    v &= MASK64
    return to_u64((v << rot) | (v >> (64 - rot))) if rot else v


def bytecode_schedule(key: int, index: int) -> int:
    x = to_u64(key) ^ to_u64(index * GOLDEN) ^ 0xA5A5A5A5D3C3B2A1
    x ^= x >> 30
    x = to_u64(x * 0xBF58476D1CE4E5B9)
    x ^= x >> 27
    x = to_u64(x * 0x94D049BB133111EB)
    x ^= x >> 31
    return to_u64(x)


def derived_keys(text: str) -> dict[str, int]:
    seeds = {name: to_u64(int(value)) for name, value in KEY_SEED_RE.findall(text)}
    keys: dict[str, int] = {}
    for match in KEY_DERIV_RE.finditer(text):
        name = match.group(2)
        if name not in seeds:
            continue
        key_value = match.group(14)
        xor_in = to_u64(int(match.group(4)))
        mul = to_u64(int(match.group(6)))
        add_in = to_u64(int(match.group(8)))
        rot = int(match.group(10))
        xor_out = to_u64(int(match.group(15)))
        mixed = rotl64(to_u64(((seeds[name] ^ xor_in) * mul) + add_in), rot)
        keys[key_value] = to_i64(mixed ^ xor_out)
    return keys


def encode(words: list[int], starts: list[int], key: int,
           opmask: int, total: int) -> tuple[list[int], list[int]]:
    plain = words + [0] * (total - len(words))
    pcmap = starts + [0] * (total - len(starts))
    if len(plain) != total or len(pcmap) != total:
        raise ValueError("test bytecode longer than generated bytecode")
    out: list[int] = []
    for i, word in enumerate(plain):
        mapped = word ^ opmask if pcmap[i] else word
        enc = to_u64(mapped) ^ bytecode_schedule(key, i)
        out.append(to_i64(enc))
    return out, pcmap


def bytecode_tag(encoded: list[int]) -> int:
    tag = 0xCBF29CE484222325
    for i, word in enumerate(encoded):
        tag ^= to_u64(word) + to_u64(i * GOLDEN)
        tag = to_u64(tag * 0x100000001B3)
    return to_i64(tag)


def program(*items: tuple[int, list[int]]) -> tuple[list[int], list[int]]:
    words: list[int] = []
    starts: list[int] = []
    for op, immediates in items:
        starts.append(1)
        words.append(op)
        words.extend(immediates)
        starts.extend([0] * len(immediates))
    return words, starts


def i64_array(values: list[int]) -> str:
    return ", ".join(f"i64 {v}" for v in values)


def i8_array(values: list[int]) -> str:
    return ", ".join(f"i8 {v}" for v in values)


def replace_array(text: str, regex: re.Pattern[str], name: str,
                  elem_ty: str, values: list[int]) -> str:
    def repl(match: re.Match[str]) -> str:
        if match.group(1) != name:
            return match.group(0)
        body = i64_array(values) if elem_ty == "i64" else i8_array(values)
        align = 8 if elem_ty == "i64" else 1
        return (
            f"@__taokari_vmp_{'bc' if elem_ty == 'i64' else 'pcmap'}_{name} = "
            f"private unnamed_addr constant [{len(values)} x {elem_ty}] "
            f"[{body}], align {align}"
        )
    return regex.sub(repl, text)


def replace_encoded_ir(text: str, name: str, encoded: list[int],
                       pcmap: list[int] | None,
                       update_tag: bool) -> str:
    count = len(encoded)
    text = replace_array(text, BC_RE, name, "i64", encoded)
    if pcmap is not None:
        text = replace_array(text, PCMAP_RE, name, "i8", pcmap)
    text = re.sub(
        rf"\[\d+ x i64\], ptr @__taokari_vmp_bc_{re.escape(name)}",
        f"[{count} x i64], ptr @__taokari_vmp_bc_{name}",
        text,
    )
    text = re.sub(
        rf"\[\d+ x i8\], ptr @__taokari_vmp_pcmap_{re.escape(name)}",
        f"[{count} x i8], ptr @__taokari_vmp_pcmap_{name}",
        text,
    )
    text = re.sub(
        rf"(@__taokari_vmp_bc_{re.escape(name)}, i64 )\d+"
        rf"(, ptr @__taokari_vmp_pcmap_{re.escape(name)})",
        rf"\g<1>{count}\g<2>",
        text,
    )
    if update_tag:
        tag = bytecode_tag(encoded)
        text = re.sub(
        rf"(@__taokari_vmp_bc_{re.escape(name)}, i64 \d+, "
        rf"ptr @__taokari_vmp_pcmap_{re.escape(name)}, ptr [^,]+, "
            rf"i64 \d+, ptr [^,]+, i64 \d+, ptr [^,]+, i64 )-?\d+",
            rf"\g<1>{tag}",
            text,
        )
    return text


def mutate_ir(text: str, name: str, count: int, key: int, opmask: int,
              words: list[int], starts: list[int]) -> str:
    count = max(count, len(words))
    encoded, pcmap = encode(words, starts, key, opmask, count)
    return replace_encoded_ir(text, name, encoded, pcmap, update_tag=True)


def encoded_words(text: str, name: str) -> list[int]:
    for match in BC_RE.finditer(text):
        if match.group(1) == name:
            return [int(v) for v in I64_RE.findall(match.group(3))]
    raise ValueError(f"missing bytecode global for {name}")


def fail(msg: str) -> int:
    print(f"vmp runtime traps: FAIL ({msg})", file=sys.stderr)
    return 1


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-vmp-traps-") as tmp:
        tmpdir = Path(tmp)
        src = tmpdir / "trap.c"
        base_ll = tmpdir / "trap.ll"
        src.write_text(SOURCE, encoding="utf-8")

        flags = [
            str(CLANG), str(src), "-O0",
            "-mllvm", "-taokari", "-mllvm", "-taokari-vmp",
        ]
        built_ir = run([*flags, "-S", "-emit-llvm", "-o", str(base_ll)],
                       use_vs_env=True)
        if built_ir.returncode:
            sys.stderr.write(built_ir.stdout + built_ir.stderr)
            return 1

        text = base_ll.read_text(encoding="utf-8", errors="ignore")
        calls = CALL_RE.findall(text)
        if not calls:
            return fail("missing interpreter call")
        name, _tag_s, key_s, mask_s = calls[0]
        if re.fullmatch(r"-?\d+", key_s.strip()):
            key = int(key_s)
        else:
            keys = derived_keys(text)
            if key_s.strip() not in keys:
                return fail("missing runtime bytecode key derivation")
            key = keys[key_s.strip()]
        opmask = int(mask_s)
        globals_by_name = {m.group(1): int(m.group(2)) for m in BC_RE.finditer(text)}
        count = globals_by_name.get(name, 0)
        if "store i64 1, ptr" not in text:
            return fail("Bad block does not set tamper flag")

        overflow_words, overflow_starts = program(
            *[(OP_PUSH_CONST, [i, TY_I32]) for i in range(65)],
            (OP_RET, []),
        )
        cases = [
            ("stack-pop-underflow", *program((OP_RET, []))),
            ("stack-push-overflow", overflow_words, overflow_starts),
            ("loadslot-out-of-range", *program((OP_LOAD_SLOT, [99, TY_I32]), (OP_RET, []))),
            ("storeslot-out-of-range", *program((OP_PUSH_CONST, [7, TY_I32]),
                                                 (OP_STORE_SLOT, [99]),
                                                 (OP_PUSH_CONST, [1, TY_I32]),
                                                 (OP_RET, []))),
            ("loadptr-frame-out-of-range", *program((OP_PUSH_CONST, [99, TY_I64]),
                                                     (OP_LOAD_PTR, [TY_I32]),
                                                     (OP_RET, []))),
            ("storeptr-frame-out-of-range", *program((OP_PUSH_CONST, [7, TY_I32]),
                                                      (OP_PUSH_CONST, [99, TY_I64]),
                                                      (OP_STORE_PTR, [TY_I32]),
                                                      (OP_PUSH_CONST, [1, TY_I32]),
                                                      (OP_RET, []))),
            ("div-by-zero", *program((OP_PUSH_CONST, [123, TY_I32]),
                                      (OP_PUSH_CONST, [0, TY_I32]),
                                      (OP_SDIV, [TY_I32]),
                                      (OP_RET, []))),
            ("rem-by-zero", *program((OP_PUSH_CONST, [123, TY_I32]),
                                      (OP_PUSH_CONST, [0, TY_I32]),
                                      (OP_SREM, [TY_I32]),
                                      (OP_RET, []))),
            ("invalid-opcode", *program((999, []))),
            ("pc-mid-immediate", *program((OP_JMP, [1]),
                                           (OP_PUSH_CONST, [5, TY_I32]),
                                           (OP_RET, []))),
        ]

        for label, words, starts in cases:
            ll = tmpdir / f"{label}.ll"
            exe = tmpdir / f"{label}.exe"
            ll.write_text(mutate_ir(text, name, count, key, opmask, words, starts),
                          encoding="utf-8")
            build = run([str(CLANG), str(ll), "-o", str(exe)], use_vs_env=True)
            if build.returncode:
                sys.stderr.write(build.stdout + build.stderr)
                return fail(f"{label} did not compile")
            result = run([str(exe)])
            if result.returncode != TRAP_EXIT:
                sys.stderr.write(result.stdout + result.stderr)
                return fail(f"{label} returned {result.returncode}, expected {TRAP_EXIT}")
            print(f"  ok {label}")

        base_encoded = encoded_words(text, name)
        rng = random.Random(0x54414F)
        fuzz_cases: list[tuple[str, list[int], list[int] | None]] = []
        for i in range(8):
            mutated = base_encoded.copy()
            idx = rng.randrange(len(mutated))
            mutated[idx] = to_i64(to_u64(mutated[idx]) ^ (1 << rng.randrange(63)))
            fuzz_cases.append((f"encrypted-bitflip-{i}", mutated, None))
        for i in range(8):
            mutated = base_encoded.copy()
            mutated[rng.randrange(len(mutated))] = to_i64(rng.getrandbits(64))
            fuzz_cases.append((f"encrypted-word-replace-{i}", mutated, None))
        fuzz_cases.append(("encrypted-truncated", base_encoded[:-1], [0] * (len(base_encoded) - 1)))
        fuzz_cases.append(("encrypted-extended", base_encoded + [to_i64(rng.getrandbits(64))],
                           [0] * (len(base_encoded) + 1)))

        for label, encoded, pcmap in fuzz_cases:
            ll = tmpdir / f"{label}.ll"
            exe = tmpdir / f"{label}.exe"
            ll.write_text(replace_encoded_ir(text, name, encoded, pcmap,
                                             update_tag=False),
                          encoding="utf-8")
            build = run([str(CLANG), str(ll), "-o", str(exe)], use_vs_env=True)
            if build.returncode:
                sys.stderr.write(build.stdout + build.stderr)
                return fail(f"{label} did not compile")
            result = run([str(exe)])
            if result.returncode != TRAP_EXIT:
                sys.stderr.write(result.stdout + result.stderr)
                return fail(f"{label} returned {result.returncode}, expected {TRAP_EXIT}")
            print(f"  ok {label}")

    print("vmp runtime traps: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
