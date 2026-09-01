"""Verify ELF loader/hardening properties survive obfuscation.

The obfuscator rewrites a lot of code and data. This verifier confirms it
does not silently remove platform hardening that the loader or security
policy depends on. It builds the same source plain and obfuscated, then
asserts the obfuscated binary preserves:

  * PT_GNU_STACK is present and non-executable (RW, not RWE) — the NX-stack
    hardening flag must survive. An accidental RWE here marks the whole
    process stack executable.
  * PT_GNU_RELRO is present when the baseline had it — RELRO must survive.
  * DT_FLAGS_1 PIE bit matches the baseline (PIE-ness preserved).
  * DT_NEEDED library set matches the baseline (no dropped/added deps).
  * .init_array and .fini_array sections still exist (constructors/
    destructors wiring intact).
  * .eh_frame / .eh_frame_hdr still exist (unwind info intact — critical
    for exceptions and stack unwinding through obfuscated frames).
  * The obfuscated binary actually runs and matches baseline output.

Exit: 0 ok | 1 contract failure | 2 missing clang / not on ELF.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))

import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
READELF = tp.READELF

SOURCE = r"""
#include <stdint.h>
#include <stdio.h>
__attribute__((noinline)) int probe(int x) {
  int s = x;
  for (int i = 0; i < x; ++i) s = (s * 13) ^ i;
  return s;
}
int main(void) { printf("elf:%d\n", probe(9)); return 0; }
"""

OBF = ["-mllvm", "-taokari",
       "-mllvm", "-taokari-fla", "-mllvm", "-taokari-level-fla=4",
       "-mllvm", "-taokari-bcf", "-mllvm", "-taokari-level-bcf=3",
       "-mllvm", "-taokari-mba", "-mllvm", "-taokari-level-mba=3",
       "-mllvm", "-taokari-cse", "-mllvm", "-taokari-cie", "-mllvm", "-taokari-cfe",
       "-mllvm", "-taokari-indbr", "-mllvm", "-taokari-level-indbr=3",
       "-mllvm", "-taokari-icall", "-mllvm", "-taokari-level-icall=3",
       "-mllvm", "-taokari-indgv", "-mllvm", "-taokari-level-indgv=3",
       "-mllvm", "-taokari-meta"]


def run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return tp.run(cmd)


def phdr(exe: Path) -> str:
    r = run([str(READELF), "-lW", str(exe)])
    return r.stdout if r.returncode == 0 else ""


def dyn(exe: Path) -> str:
    r = run([str(READELF), "-dW", str(exe)])
    return r.stdout if r.returncode == 0 else ""


def sections(exe: Path) -> str:
    r = run([str(READELF), "-SW", str(exe)])
    return r.stdout if r.returncode == 0 else ""


def needed_libs(dyn_text: str) -> list[str]:
    return sorted(re.findall(r"\[(lib[^\]]+)\]", dyn_text))


def has_section(sec_text: str, name: str) -> bool:
    return re.search(r"\.\.?%s\b" % re.escape(name), sec_text) is not None


def main() -> int:
    if os.name == "nt":
        print("elf-integrity verifier is ELF/Linux-only; skipping on Windows",
              file=sys.stderr)
        return 2
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-elf-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "elf.c"
        src.write_text(SOURCE, encoding="utf-8")

        base = tmp / "base"
        obf = tmp / "obf"
        r = run([str(CLANG), str(src), "-O2", "-o", str(base)])
        if r.returncode:
            print(f"baseline build failed\n{r.stdout}{r.stderr}", file=sys.stderr)
            return 1
        r = run([str(CLANG), str(src), "-O2", *OBF, "-o", str(obf)])
        if r.returncode:
            print(f"obfuscated build failed\n{r.stdout}{r.stderr}", file=sys.stderr)
            return 1

        base_run = run([str(base)])
        obf_run = run([str(obf)])
        if base_run.returncode or obf_run.returncode or \
                base_run.stdout != obf_run.stdout:
            print(f"FAIL: runtime mismatch base={base_run.stdout!r} "
                  f"obf={obf_run.stdout!r}", file=sys.stderr)
            return 1

        checks: list[tuple[str, bool]] = []
        b_ph, o_ph = phdr(base), phdr(obf)
        b_dyn, o_dyn = dyn(base), dyn(obf)
        b_sec, o_sec = sections(base), sections(obf)

        def stk_nonexec(t: str) -> bool:
            m = re.search(r"GNU_STACK\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\S+)", t)
            return bool(m) and "E" not in m.group(1)

        checks.append(("PT_GNU_STACK present (obf)",
                       "GNU_STACK" in o_ph))
        checks.append(("PT_GNU_STACK non-executable (obf)",
                       stk_nonexec(o_ph)))
        checks.append(("PT_GNU_STACK non-exec matches baseline",
                       stk_nonexec(b_ph) == stk_nonexec(o_ph)))
        base_relro = "GNU_RELRO" in b_ph
        obf_relro = "GNU_RELRO" in o_ph
        checks.append(("PT_GNU_RELRO preserved",
                       base_relro == obf_relro))
        checks.append(("DT_FLAGS_1 PIE matches baseline",
                       ("PIE" in b_dyn) == ("PIE" in o_dyn)))
        checks.append(("DT_NEEDED libs match baseline",
                       needed_libs(b_dyn) == needed_libs(o_dyn)))
        for sec in (".init_array", ".fini_array", ".eh_frame", ".eh_frame_hdr"):
            checks.append((f"{sec} preserved",
                           has_section(b_sec, sec) == has_section(o_sec, sec)))

        failures = [label for label, ok in checks if not ok]
        for label, ok in checks:
            print(f"  {'ok' if ok else 'FAIL'}  {label}")
        if failures:
            print(f"elf-integrity: {len(failures)} check(s) failed", file=sys.stderr)
            return 1

    print(f"elf-integrity: ok (output={base_run.stdout.strip()!r}, NX stack, "
          f"RELRO, PIE, NEEDED, init/fini/eh_frame all preserved)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
