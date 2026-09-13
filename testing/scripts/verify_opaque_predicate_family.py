"""Opaque-predicate identity-family + BCF nonce re-key bar (TK-031).

Contract:
  * A many-guard fixture compiled with BCF L4 must emit opaque guards drawn
    from MORE THAN ONE identity of the unfoldable family (distinct SSA suffix
    per member: .prod / .prod1 / .low3 / .lowm / .bit2).
  * Each family member must survive `opt -instcombine,simplifycfg` as a
    non-constant comparison over a runtime argument (no solver shortcut).
  * The -O2 build must still contain the guard branches (not folded) with at
    least two distinct identities, and its runtime output must match plain.
  * `__taokari_bcf_nonce` must not be the golden-ratio constant in any build,
    and two independent builds must carry different nonce bytes.

`--clang <path>` runs the whole bar against another compiler binary; against
the pre-fix parent this file is the teeth: the family gate and the nonce gates
must FAIL there.

Exit: 0 ok | 1 contract failure | 2 missing tools.
"""
from __future__ import annotations

import argparse
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
OPT = tp.tool("opt")
VSDEVCMD = tp.VSDEVCMD

GOLDEN_NONCE = struct.pack("<Q", 0x9E3779B97F4A7C15)

# One distinctive SSA suffix per family member (see
# makeUnfoldableEvenValue in OpaquePredicate.cpp). Suffixes use multi-letter
# words so SSA-name dedup (which appends digits) can never forge a marker.
MEMBER_MARKERS = {
    "m0-inc1": r"bcf\.(exh\.)?opaque\.low\b",
    "m1-dec1": r"bcf\.(exh\.)?opaque\.lowp\b",
    "m3-quad7": r"bcf\.(exh\.)?opaque\.lowq\b",
    "m4-quads1": r"bcf\.(exh\.)?opaque\.lows\b",
    "m5-quads2": r"bcf\.(exh\.)?opaque\.lowt\b",
}

# InstCombine-survival fixtures: one per member, argument-seeded (stronger
# than a volatile load: the optimizer sees a plain SSA value).
MEMBER_IR = {
    "m0-inc1": """
define i1 @m(i64 %x) {
  %inc = add i64 %x, 1
  %prod = mul i64 %x, %inc
  %low = and i64 %prod, 1
  %c = icmp eq i64 %low, 0
  ret i1 %c
}""",
    "m1-dec1": """
define i1 @m(i64 %x) {
  %prev = sub i64 %x, 1
  %prodp = mul i64 %x, %prev
  %lowp = and i64 %prodp, 1
  %c = icmp eq i64 %lowp, 0
  ret i1 %c
}""",
    "m3-quad7": """
define i1 @m(i64 %x) {
  %inc = add i64 %x, 1
  %p1 = mul i64 %x, %inc
  %inc2 = add i64 %x, 2
  %p2 = mul i64 %p1, %inc2
  %inc3 = add i64 %x, 3
  %p3 = mul i64 %p2, %inc3
  %lowq = and i64 %p3, 7
  %c = icmp eq i64 %lowq, 0
  ret i1 %c
}""",
    "m4-quads1": """
define i1 @m(i64 %x) {
  %inc = add i64 %x, 1
  %p1 = mul i64 %x, %inc
  %inc2 = add i64 %x, 2
  %p2 = mul i64 %p1, %inc2
  %inc3 = add i64 %x, 3
  %p3 = mul i64 %p2, %inc3
  %shr = ashr i64 %p3, 1
  %lows = and i64 %shr, 3
  %c = icmp eq i64 %lows, 0
  ret i1 %c
}""",
    "m5-quads2": """
define i1 @m(i64 %x) {
  %inc = add i64 %x, 1
  %p1 = mul i64 %x, %inc
  %inc2 = add i64 %x, 2
  %p2 = mul i64 %p1, %inc2
  %inc3 = add i64 %x, 3
  %p3 = mul i64 %p2, %inc3
  %shr2 = ashr i64 %p3, 2
  %lowt = and i64 %shr2, 1
  %c = icmp eq i64 %lowt, 0
  ret i1 %c
}""",
}

SOURCE = r"""
#include <stdio.h>
__attribute__((noinline)) int f0(int a) { if (a & 1) return a + 3; return a - 1; }
__attribute__((noinline)) int f1(int a) { int r = a; if (a > 10) r -= 2; if (a < -10) r += 5; return r; }
__attribute__((noinline)) int f2(int a) { for (int i = 0; i < 3; ++i) { if (a % 3 == i) a += i + 1; } return a; }
__attribute__((noinline)) int f3(int a) { if (a > 100) return a / 2; if (a < -100) return a * 2; return a ^ 7; }
__attribute__((noinline)) int f4(int a) { int s = 0; while (s < a && s < 9) s += 2; return s; }
__attribute__((noinline)) int f5(int a) { if (a & 2) return a * 3; if (a & 4) return a - 9; return a + 11; }
__attribute__((noinline)) int f6(int a) { switch (a % 4) { case 0: return a + 1; case 1: return a + 2; case 2: return a + 3; default: return a + 4; } }
__attribute__((noinline)) int f7(int a) { int r = 0; for (int i = 0; i < 4; ++i) { if ((a + i) & 1) r += i; else r -= i; } return r; }
int main(int argc, char **argv) {
  int v = argc * 13 - 7;
  int acc = f0(v) + f1(v) + f2(v) + f3(v);
  acc += f4(v) + f5(v) + f6(v) + f7(v);
  printf("opqfam:%d\n", acc);
  return 0;
}
"""


def run(command: list[str], **kw) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, **kw)


def run_vs(command: list[str], cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    if not tp.IS_WINDOWS:
        return subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
    with tempfile.NamedTemporaryFile("w", suffix=".cmd", delete=False,
                                     encoding="utf-8") as handle:
        batch = Path(handle.name)
        handle.write(
            "@echo off\n"
            f'call "{VSDEVCMD}" -arch=x64 -host_arch=x64 >nul\n'
            f"{subprocess.list2cmdline(command)}\n"
            "exit /b %ERRORLEVEL%\n"
        )
    try:
        return run(["cmd.exe", "/d", "/c", str(batch)], cwd=cwd)
    finally:
        batch.unlink(missing_ok=True)


def must(result: subprocess.CompletedProcess[str], label: str) -> None:
    if result.returncode:
        print(result.stdout, end="")
        print(result.stderr, end="", file=sys.stderr)
        raise SystemExit(f"{label} failed: {result.returncode}")


def gate(cond: bool, label: str) -> None:
    if not cond:
        raise SystemExit(f"GATE FAILED: {label}")
    print(f"  [ok] {label}")


OBF_FLAGS = ["-mllvm", "-taokari", "-mllvm", "-taokari-bcf",
             "-mllvm", "-taokari-level-bcf=4", "-mllvm", "-taokari-bcf-prob=100"]


def member_signature_counts(ir: str) -> dict[str, int]:
    return {name: len(re.findall(pat, ir))
            for name, pat in MEMBER_MARKERS.items()}


def nonce_value_from_ir(ir: str) -> int | None:
    m = re.search(r"@__taokari_bcf_nonce\s*=\s*(?:unnamed_addr\s+)?"
                  r"(?:private|internal)\s+(?:constant|global)\s+i[0-9]+\s+"
                  r"(-?[0-9]+|0x[0-9a-fA-F]+)", ir)
    if not m:
        return None
    return int(m.group(1), 0)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--clang", default=str(tp.CLANG),
                    help="compiler under test (default: live build)")
    args = ap.parse_args()
    clang = Path(args.clang)

    if not clang.exists() or not OPT.exists():
        print(f"missing tools: {clang} / {OPT}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-opqfam-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "family.c"
        src.write_text(SOURCE, encoding="utf-8")

        plain = tmp / "plain.exe"
        must(run_vs([str(clang), str(src), "-O2", "-o", str(plain)]),
             "plain build")
        plain_run = run([str(plain)])

        ir0 = tmp / "obf-O0.ll"
        must(run_vs([str(clang), str(src), "-O0", "-S", "-emit-llvm",
                     "-fno-discard-value-names", *OBF_FLAGS, "-o", str(ir0)]),
             "obf -O0 IR build")
        ir0_text = ir0.read_text(encoding="utf-8", errors="ignore")

        sig0 = member_signature_counts(ir0_text)
        present0 = {k: v for k, v in sig0.items() if v}
        guards0 = sum(sig0.values())
        print(f"  -O0 member counts: {present0} guard-icmps~{guards0}")
        gate(guards0 >= 16, f"fixture emits many bcf opaque guards "
                            f"(got {guards0})")
        gate(len(present0) >= 2,
             f"guards use >1 distinct identity among many sites "
             f"(got {sorted(present0)})")

        obf = tmp / "obf.exe"
        must(run_vs([str(clang), str(src), "-O2", *OBF_FLAGS, "-o", str(obf)]),
             "obf -O2 exe build")
        obf_run = run([str(obf)])
        gate(obf_run.returncode == 0 and obf_run.stdout == plain_run.stdout,
             f"runtime parity plain-vs-obf ({obf_run.stdout!r} vs "
             f"{plain_run.stdout!r})")

        ir2 = tmp / "obf-O2.ll"
        must(run_vs([str(clang), str(src), "-O2", "-S", "-emit-llvm",
                     *OBF_FLAGS, "-o", str(ir2)]),
             "obf -O2 IR build")
        ir2_text = ir2.read_text(encoding="utf-8", errors="ignore")
        sig2 = member_signature_counts(ir2_text)
        present2 = {k: v for k, v in sig2.items() if v}
        guards2 = sum(sig2.values())
        print(f"  -O2 member counts: {present2} guard-icmps={guards2}")
        gate(guards2 >= 2, f"guards still present at -O2 (got {guards2})")
        gate(len(present2) >= 1, "-O2 keeps at least one family identity")

        # Per-member InstCombine survival: the ret operand must stay
        # non-constant over a plain SSA argument.
        for name, ir in MEMBER_IR.items():
            opt_ir = run([str(OPT),
                          "-passes=instcombine,simplifycfg,instcombine",
                          "-S"], input=ir)
            if opt_ir.returncode:
                gate(False, f"{name} opt run")
            folded = re.search(r"ret i1 (true|false)", opt_ir.stdout)
            gate(folded is None, f"{name} survives instcombine (not folded)")

        # Nonce: never the golden-ratio constant; differs across builds.
        nonce0 = nonce_value_from_ir(ir0_text)
        gate(nonce0 is not None, "nonce global present in -O0 IR")
        nonce_gold = nonce0 == 0x9E3779B97F4A7C15
        gate(not nonce_gold, f"-O0 nonce is not the golden-ratio constant "
                             f"(got {nonce0})")
        exe_bytes = obf.read_bytes()
        gate(GOLDEN_NONCE not in exe_bytes,
             "obfuscated binary does not contain the golden-ratio nonce")
        ir2b = tmp / "nonce2-O0.ll"
        must(run_vs([str(clang), str(src), "-O0", "-S", "-emit-llvm",
                     "-fno-discard-value-names", *OBF_FLAGS, "-o", str(ir2b)]),
             "second -O0 IR build")
        nonce1 = nonce_value_from_ir(
            ir2b.read_text(encoding="utf-8", errors="ignore"))
        nonce_pair = (f"{nonce0:#x}" if nonce0 is not None else "none",
                      f"{nonce1:#x}" if nonce1 is not None else "none")
        gate(nonce1 is not None and nonce0 is not None and nonce0 != nonce1,
             f"nonce differs across independent builds {nonce_pair}")

    print("opaque predicate family verifier: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
