"""Verify VMP call thunks route through IndirectCall page tables when enabled."""
from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

from verify_vmp_coverage import CLANG, SOURCE, run


def fail(msg: str) -> int:
    print(f"vmp icall route: FAIL ({msg})", file=sys.stderr)
    return 1


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-vmp-icall-") as tmp:
        tmpdir = Path(tmp)
        src = tmpdir / "icall.c"
        ll = tmpdir / "icall.ll"
        exe = tmpdir / "icall.exe"
        src.write_text(SOURCE, encoding="utf-8")
        flags = [
            str(CLANG), str(src), "-O2",
            "-mllvm", "-taokari",
            "-mllvm", "-taokari-vmp",
            "-mllvm", "-taokari-icall",
            "-mllvm", "-taokari-level-icall=2",
        ]

        ir = run([*flags, "-S", "-emit-llvm", "-o", str(ll)], use_vs_env=True)
        if ir.returncode:
            sys.stderr.write(ir.stdout + ir.stderr)
            return 1
        text = ll.read_text(encoding="utf-8", errors="ignore")
        if "_IndirectCallee_page_table" not in text:
            return fail("missing IndirectCall page table")
        if "_IndirectCallee_objects_share" not in text:
            return fail("missing level-2 shared object table")
        if not re.search(r"_IndirectCallee_objects.*__taokari_vmp_callthunk_", text):
            return fail("VMP call thunks are not present in the IndirectCall table")
        if re.search(r"call\s+i64\s+@__taokari_vmp_callthunk_", text):
            return fail("VM handler still directly calls a VMP call thunk")

        build = run([*flags, "-o", str(exe)], use_vs_env=True)
        if build.returncode:
            sys.stderr.write(build.stdout + build.stderr)
            return 1
        result = run([str(exe)])
        if result.returncode:
            sys.stderr.write(result.stdout + result.stderr)
            return 1

        obf_ll = tmpdir / "thunk_obf.ll"
        obf_exe = tmpdir / "thunk_obf.exe"
        obf_flags = [
            str(CLANG), str(src), "-O2", "-fno-discard-value-names",
            "-mllvm", "-taokari",
            "-mllvm", "-taokari-vmp",
            "-mllvm", "-taokari-mba",
            "-mllvm", "-taokari-mba-prob=100",
            "-mllvm", "-taokari-bcf",
            "-mllvm", "-taokari-level-bcf=2",
            "-mllvm", "-taokari-bcf-prob=100",
            "-mllvm", "-taokari-bcf-loops=2",
        ]
        obf_ir = run([*obf_flags, "-S", "-emit-llvm", "-o", str(obf_ll)],
                     use_vs_env=True)
        if obf_ir.returncode:
            sys.stderr.write(obf_ir.stdout + obf_ir.stderr)
            return 1
        obf_text = obf_ll.read_text(encoding="utf-8", errors="ignore")
        thunk_bodies = re.findall(
            r"define internal i64 @__taokari_vmp_callthunk_[^{]+{(.*?)^}",
            obf_text, re.S | re.M)
        if not thunk_bodies:
            return fail("missing VMP call thunk bodies")
        if not all(".bcf.fake" in body for body in thunk_bodies):
            return fail("VMP call thunks were not BCF-obfuscated")
        if not any(".mba." in body for body in thunk_bodies):
            return fail("VMP call thunk arithmetic was not MBA-obfuscated")
        obf_build = run([*obf_flags, "-o", str(obf_exe)], use_vs_env=True)
        if obf_build.returncode:
            sys.stderr.write(obf_build.stdout + obf_build.stderr)
            return 1
        obf_result = run([str(obf_exe)])
        if obf_result.returncode:
            sys.stderr.write(obf_result.stdout + obf_result.stderr)
            return 1

    print("vmp icall route: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
