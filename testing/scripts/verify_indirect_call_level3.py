"""Verify Level-3/Fortress indirect-call hardening."""
from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

from verify_vmp_coverage import CLANG, run


SOURCE = r"""
__attribute__((noinline)) static int callee_a(int x) { return x * 3 + 1; }
__attribute__((noinline)) static int callee_b(int x) { return x - 7; }

__attribute__((noinline)) int entry(int x) {
  int a = callee_a(x);
  int b = callee_a(x + 1);
  return callee_b(a + b);
}

int main(void) { return entry(9) == 52 ? 0 : 1; }
"""

EXTERNAL_SOURCE = r"""
extern int external_callee(int);
int entry(int x) { return external_callee(x); }
"""


def fail(msg: str) -> int:
    print(f"indirect call level3: FAIL ({msg})", file=sys.stderr)
    return 1


def clang(args: list[str]) -> subprocess.CompletedProcess[str]:
    return run([str(CLANG), *args], use_vs_env=True)


def check_l3_ir(text: str) -> int:
    required = [
        "__taokari_icall_shard_",
        "__taokari_icall_fake_",
        "__taokari_icall_shard_seed_",
        "_IndirectCallee_objects_share",
        "_IndirectCallee_enhanced_page_table_",
        "__taokari_page_seed",
        "taokari.ptr.decrypt",
    ]
    missing = [needle for needle in required if needle not in text]
    if missing:
      return fail("missing L3 markers: " + ", ".join(missing))
    if not re.search(r"_IndirectCallee_objects.*__taokari_icall_shard_", text):
        return fail("module page table does not point at call shards")
    formulas = [
        "llvm.fshl.i64", "llvm.fshr.i64", "llvm.bswap.i64",
        " xor i64 ", " add i64 ", " sub i64 ", " mul i64 ",
    ]
    if sum(1 for formula in formulas if formula in text) < 4:
        return fail("not enough call reconstruction formula variants")
    if not re.search(r"__taokari_icall_shard_ptr_callee_a", text):
        return fail("encrypted real callee pointer missing inside shard")
    if not re.search(r"__taokari_icall_shard_fptr_callee_a", text):
        return fail("encrypted fake callee pointer missing inside shard")
    if not re.search(r"inttoptr\s+i64.*to\s+ptr", text):
        return fail("indirect-call target reconstruction missing inside shard")
    if re.search(r"call(?:\s+\w+)*\s+i32\s+@callee_a\(", text):
        return fail("shard still exposes a direct call to the real callee")
    if len(set(re.findall(r"@[^ ]+_IndirectCallee_enhanced_page_table_\d+", text))) < 3:
        return fail("not enough decryptor/page-table variants")
    return 0


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-icall-l3-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "icall_l3.c"
        src.write_text(SOURCE, encoding="utf-8")
        ll = tmp / "icall_l3.ll"
        exe = tmp / "icall_l3.exe"
        flags = [
            str(src), "-O2", "-fno-discard-value-names",
            "-mllvm", "-taokari",
            "-mllvm", "-taokari-icall",
            "-mllvm", "-taokari-level-icall=3",
            "-mllvm", "-taokari-icall-prob=100",
            "-mllvm", "-taokari-icall-func-prob=100",
        ]

        ir = clang([*flags, "-S", "-emit-llvm", "-o", str(ll)])
        if ir.returncode:
            sys.stderr.write(ir.stdout + ir.stderr)
            return 1
        checked = check_l3_ir(ll.read_text(encoding="utf-8", errors="ignore"))
        if checked:
            return checked

        build = clang([*flags, "-o", str(exe)])
        if build.returncode:
            sys.stderr.write(build.stdout + build.stderr)
            return 1
        result = run([str(exe)])
        if result.returncode:
            sys.stderr.write(result.stdout + result.stderr)
            return fail(f"Windows x64 executable returned {result.returncode}")

        a64_ll = tmp / "icall_l3_aarch64.ll"
        a64 = clang([
            *flags, "-target", "aarch64-pc-windows-msvc",
            "-S", "-emit-llvm", "-o", str(a64_ll),
        ])
        if a64.returncode:
            sys.stderr.write(a64.stdout + a64.stderr)
            return 1
        a64_text = a64_ll.read_text(encoding="utf-8", errors="ignore")
        if "llvm.ptrauth.sign" not in a64_text:
            return fail("AArch64 PAC signing path missing")
        discs = [int(v) for v in re.findall(r"llvm\.ptrauth\.sign[^(]*\([^)]*i64 (-?\d+)\)", a64_text)]
        if not discs or any(v == 0 for v in discs) or len(set(discs)) < 2:
            return fail("AArch64 PAC discriminators are not per-object/module seeded")

        ext_src = tmp / "external.c"
        ext_obj = tmp / "external.obj"
        ext_src.write_text(EXTERNAL_SOURCE, encoding="utf-8")
        ext = clang([
            str(ext_src), "-O2",
            "-mllvm", "-taokari",
            "-mllvm", "-taokari-icall",
            "-mllvm", "-taokari-level-icall=3",
            "-c", "-o", str(ext_obj),
        ])
        if ext.returncode:
            sys.stderr.write(ext.stdout + ext.stderr)
            return 1
        ext_ir = tmp / "external.ll"
        ext = clang([
            str(ext_src), "-O2",
            "-mllvm", "-taokari",
            "-mllvm", "-taokari-icall",
            "-mllvm", "-taokari-level-icall=3",
            "-S", "-emit-llvm", "-o", str(ext_ir),
        ])
        if ext.returncode:
            sys.stderr.write(ext.stdout + ext.stderr)
            return 1
        if "_IndirectCallee" in ext_ir.read_text(encoding="utf-8", errors="ignore"):
            return fail("external cross-module call was page-table obfuscated")

    print("indirect call level3: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
