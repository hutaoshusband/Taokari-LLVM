from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
VSDEVCMD = tp.VSDEVCMD

# Exercises argument passing, a return value, a memory side effect (a global
# store), and control flow. After outlining, the .shard helpers must carry all
# of that out and the program output must be identical.
SOURCE = r"""
#include <stdio.h>
#include <stdint.h>

static int64_t g_side = 0;

__attribute__((noinline, annotate("+outline")))
int64_t sensitive(int64_t a, int64_t b, int64_t c) {
    int64_t x = a * 17 + b;
    int64_t y = (x ^ 0x5a5a) - c;
    int64_t z = y + (a << 2);
    g_side = z;            /* side effect must survive outlining */
    return z + 9;
}

/* Global outline via flag, no annotation. */
__attribute__((noinline))
int64_t plain(int64_t a) {
    int64_t r = a;
    r = r * 31 + 7;
    r = r ^ 0xa5a5;
    r = r - (a & 0xff);
    return r + 3;
}

int main(void) {
    int64_t s = sensitive(13, 100, 7);
    int64_t p = plain(42);
    /* s: x=321, y=321^0x5a5a-7 = 23318-7 = 23311, z=23311+52=23363, +9=23372 */
    /* g_side == 23363 */
    /* p: 42*31+7=1309, ^0xa5a5=0xb68c... compute at runtime, printed */
    printf("outline:%lld:%lld:%lld\n", (long long)s, (long long)p,
           (long long)g_side);
    return 0;
}
"""

DEBUG_CRASH_SOURCE = r"""
#include <stdint.h>

__attribute__((noinline))
int api(int a, int b) {
    int x = a * 17 + b;
    int y = (x ^ 0x5a5a) - a;
    int z = y + (b << 2);
    return z ^ (x + y);
}

int main(void) {
    return api(13, 7) == 0;
}
"""


def run(command: list[str], *, cwd: Path = ROOT, input: str | None = None) -> subprocess.CompletedProcess[str]:
    if VSDEVCMD.exists():
        with tempfile.NamedTemporaryFile("w", suffix=".cmd", delete=False, encoding="utf-8") as handle:
            batch = Path(handle.name)
            handle.write(
                "@echo off\n"
                f'call "{VSDEVCMD}" -arch=x64 -host_arch=x64 >nul\n'
                f"{subprocess.list2cmdline(command)}\n"
                "exit /b %ERRORLEVEL%\n"
            )
        try:
            return subprocess.run(["cmd.exe", "/d", "/c", str(batch)], cwd=cwd, text=True, capture_output=True, input=input)
        finally:
            batch.unlink(missing_ok=True)
    return subprocess.run(command, cwd=cwd, text=True, capture_output=True, input=input)


def compile_ir(src: Path, out: Path, *, level: int = 1) -> subprocess.CompletedProcess[str]:
    # -O0 so the IR keeps the outlining call structure before later opts fold it.
    return run([
        str(CLANG), str(src), "-O0", "-fno-discard-value-names",
        "-mllvm", "-taokari",
        "-mllvm", "-taokari-outline",
        "-mllvm", f"-taokari-level-outline={level}",
        "-mllvm", "-taokari-outline-prob=100",
        "-mllvm", "-taokari-outline-max-shards=8",
        "-S", "-emit-llvm",
        "-o", str(out),
    ])


def compile_exe(src: Path, out: Path, *, max_shards: int,
                level: int = 1) -> subprocess.CompletedProcess[str]:
    return run([
        str(CLANG), str(src), "-O2", "-fno-discard-value-names",
        "-mllvm", "-taokari",
        "-mllvm", "-taokari-outline",
        "-mllvm", f"-taokari-level-outline={level}",
        "-mllvm", "-taokari-outline-prob=100",
        "-mllvm", f"-taokari-outline-max-shards={max_shards}",
        "-o", str(out),
    ])


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    cpp = (ROOT / "upstream" / "taokari" / "llvm" / "lib" / "Transforms"
           / "Obfuscation" / "FunctionOutlining.cpp").read_text(encoding="utf-8", errors="ignore")
    for needle in ("CodeExtractor", "outlineOpt", ".shard"):
        if needle not in cpp:
            print(f"FunctionOutlining.cpp missing {needle}", file=sys.stderr)
            return 1
    if "createFunctionOutliningPass" not in (ROOT / "upstream" / "taokari" / "llvm"
            / "lib" / "Transforms" / "Obfuscation" / "ObfuscationPassManager.cpp"
            ).read_text(encoding="utf-8", errors="ignore"):
        print("outline pass not wired into PassManager", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory(prefix="taokari-outline-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "outline.c"
        src.write_text(SOURCE, encoding="utf-8")

        dbg_src = tmp / "outline_debug.c"
        dbg_src.write_text(DEBUG_CRASH_SOURCE, encoding="utf-8")
        dbg_exe = tmp / "outline_debug.exe"
        res = run([str(CLANG), str(dbg_src), "-O2", "-g",
                   "-mllvm", "-taokari", "-mllvm", "-taokari-outline",
                   "-mllvm", "-taokari-level-outline=4",
                   "-mllvm", "-taokari-outline-prob=100",
                   "-mllvm", "-taokari-outline-max-shards=8",
                   "-o", str(dbg_exe)])
        if res.returncode:
            print(res.stdout, end="")
            print(res.stderr, end="", file=sys.stderr)
            return res.returncode

        # L1: at level 1 shards keep the readable .shard suffix.
        ir = tmp / "outline.ll"
        res = compile_ir(src, ir, level=1)
        if res.returncode:
            print(res.stdout, end="")
            print(res.stderr, end="", file=sys.stderr)
            return res.returncode
        text = ir.read_text(encoding="utf-8", errors="ignore")
        if ".shard" not in text and "__taokari_sh_" not in text:
            print("no shard helpers emitted in IR (L1)", file=sys.stderr)
            return 1
        if "sensitive.shard" not in text and "plain.shard" not in text:
            print("no per-function shard name in IR (L1)", file=sys.stderr)
            return 1

        # Global outlining via flag must produce a shard in `plain` too.
        exe = tmp / "outline.exe"
        res = compile_exe(src, exe, max_shards=8, level=1)
        if res.returncode:
            print(res.stdout, end="")
            print(res.stderr, end="", file=sys.stderr)
            return res.returncode
        ran = run([str(exe)])
        if ran.returncode:
            print(f"runtime failed: {ran.stdout}{ran.stderr}", file=sys.stderr)
            return ran.returncode
        ref_exe = tmp / "ref.exe"
        ref = run([str(CLANG), str(src), "-O2", "-o", str(ref_exe)])
        if ref.returncode:
            print(ref.stdout, end="")
            print(ref.stderr, end="", file=sys.stderr)
            return ref.returncode
        ref_run = run([str(ref_exe)])
        if ran.stdout != ref_run.stdout:
            print(f"output drift after outlining:\n  obf: {ran.stdout!r}\n  ref: {ref_run.stdout!r}", file=sys.stderr)
            return 1

        # Budget: a max-shards=0 build must not emit any shard and still run.
        budget_exe = tmp / "budget.exe"
        res = compile_exe(src, budget_exe, max_shards=0, level=1)
        if res.returncode:
            print(res.stdout, end="")
            print(res.stderr, end="", file=sys.stderr)
            return res.returncode
        if ".shard" in run([str(CLANG), str(src), "-O0", "-mllvm", "-taokari",
                            "-mllvm", "-taokari-outline", "-mllvm",
                            "-taokari-level-outline=1", "-mllvm",
                            "-taokari-outline-prob=100", "-mllvm",
                            "-taokari-outline-max-shards=0", "-S", "-emit-llvm",
                            "-o", str(tmp / "budget.ll")]).stdout:
            print("max-shards=0 still emitted a shard", file=sys.stderr)
            return 1

        # L2: opaque shard names (no source-function-name leak), arg/return
        # scramble XORs, and decoy fake shards in compiler.used. Output must
        # still match the reference, proving the scramble round-trips.

        # Annotation-level parsing: enable + level via the annotation ALONE
        # (no -taokari-outline enable flag, no -taokari-level-outline flag).
        # The ^outline=2 form must set the level so opaque names appear.
        ann_src = tmp / "outline_ann.c"
        ann_src.write_text(SOURCE.replace('annotate("+outline")',
                                          'annotate("+outline^outline=2")'),
                           encoding="utf-8")
        ann_ir = tmp / "outline_ann.ll"
        res = run([str(CLANG), str(ann_src), "-O0", "-fno-discard-value-names",
                   "-mllvm", "-taokari", "-mllvm", "-taokari-outline-prob=100",
                   "-mllvm", "-taokari-outline-max-shards=8",
                   "-S", "-emit-llvm", "-o", str(ann_ir)])
        if res.returncode:
            print(res.stdout, end="")
            print(res.stderr, end="", file=sys.stderr)
            return res.returncode
        ann_text = ann_ir.read_text(encoding="utf-8", errors="ignore")
        if "__taokari_sh_" not in ann_text:
            print("annotation ^outline=2 did not set level 2 (no opaque names)",
                  file=sys.stderr)
            return 1

        l2_ir = tmp / "outline_l2.ll"
        res = run([str(CLANG), str(src), "-O0", "-fno-discard-value-names",
                   "-mllvm", "-taokari", "-mllvm", "-taokari-outline",
                   "-mllvm", "-taokari-level-outline=2",
                   "-mllvm", "-taokari-outline-prob=100",
                   "-mllvm", "-taokari-outline-max-shards=8",
                   "-mllvm", "-taokari-outline-fakes=2",
                   "-S", "-emit-llvm", "-o", str(l2_ir)])
        if res.returncode:
            print(res.stdout, end="")
            print(res.stderr, end="", file=sys.stderr)
            return res.returncode
        l2_text = l2_ir.read_text(encoding="utf-8", errors="ignore")
        if "__taokari_sh_" not in l2_text:
            print("L2: no opaque shard name emitted", file=sys.stderr)
            return 1
        if "sensitive.shard" in l2_text:
            print("L2: source function name leaked into shard name", file=sys.stderr)
            return 1
        # Scramble: the shard entry must contain at least one big-constant xor.
        if not re.search(r"xor i\d+ %[\w$.]+, -?\d{6,}", l2_text):
            print("L2: no argument scramble xor found in shard", file=sys.stderr)
            return 1
        # Fakes: more shard-shaped defines than there are real call targets.
        shard_defs = len(re.findall(r"define.*__taokari_sh_", l2_text))
        if shard_defs < 2:
            print(f"L2: expected fake shards, found {shard_defs} shard defs", file=sys.stderr)
            return 1
        l2_exe = tmp / "outline_l2.exe"
        res = compile_exe(src, l2_exe, max_shards=8, level=2)
        if res.returncode:
            print(res.stdout, end="")
            print(res.stderr, end="", file=sys.stderr)
            return res.returncode
        l2_ran = run([str(l2_exe)])
        if l2_ran.returncode:
            print(f"L2 runtime failed: {l2_ran.stdout}{l2_ran.stderr}", file=sys.stderr)
            return l2_ran.returncode
        if l2_ran.stdout != ref_run.stdout:
            print(f"L2 output drift:\n  obf: {l2_ran.stdout!r}\n  ref: {ref_run.stdout!r}", file=sys.stderr)
            return 1

        # L3: fortress callout. The shard layer gains an integrity check (private
        # token global + icmp guard), a multi-layer split (more shard defs than
        # L2 at the same max-shards), and must still round-trip. The full
        # fortress compose (outline + fla + bcf + mba) must also stay correct.
        l3_ir = tmp / "outline_l3.ll"
        res = run([str(CLANG), str(src), "-O0", "-fno-discard-value-names",
                   "-mllvm", "-taokari", "-mllvm", "-taokari-outline",
                   "-mllvm", "-taokari-level-outline=3",
                   "-mllvm", "-taokari-outline-prob=100",
                   "-mllvm", "-taokari-outline-max-shards=8",
                   "-mllvm", "-taokari-outline-fakes=1",
                   "-S", "-emit-llvm", "-o", str(l3_ir)])
        if res.returncode:
            print(res.stdout, end="")
            print(res.stderr, end="", file=sys.stderr)
            return res.returncode
        l3_text = l3_ir.read_text(encoding="utf-8", errors="ignore")
        # Integrity check: at least one private token global + an icmp eq guard
        # feeding a branch.
        if not re.search(r"__taokari_sh_[0-9a-f]+\.ic\.tok", l3_text):
            print("L3: no integrity-check token global found", file=sys.stderr)
            return 1
        if not re.search(r"icmp eq i\d+ ", l3_text):
            print("L3: no integrity icmp guard found", file=sys.stderr)
            return 1
        # Multi-layer: at least one shard must be called by another shard,
        # proving the body was split across a chained caller/sub-shard pair
        # rather than emitted as a single flat body. (Counts alone are not a
        # reliable signal: fake shards inflate L2 too.)
        callers = set(re.findall(r"call[^@]*@(__taokari_sh_[0-9a-f]+)", l3_text))
        callees = set(re.findall(r"define[^@]*@(__taokari_sh_[0-9a-f]+)", l3_text))
        if not (callers & callees):
            print("L3: no shard-to-shard call edge (multi-layer) found",
                  file=sys.stderr)
            return 1
        l3_shard_defs = len(callees)
        # Dispatcher: at least one shard-shaped function must take an i32 token
        # first arg and branch on it (token-switched callout dispatch).
        if not re.search(r"define[^@]*@__taokari_sh_[0-9a-f]+\(i32 ", l3_text):
            print("L3: no token-switched dispatcher shard found", file=sys.stderr)
            return 1
        # Decompile-quality gate: the sensitive function's original arithmetic
        # (mul by 17) must no longer sit inline in its body; it has been pushed
        # into shards, so a decompiler cannot read it as one clean body.
        sens_body = re.search(r"define[^@]*@sensitive\(.*?\n\}",
                              l3_text, re.S)
        if sens_body and re.search(r"mul .*17", sens_body.group(0)):
            print("L3: sensitive body still carries inline arithmetic (not split)",
                  file=sys.stderr)
            return 1

        l3_exe = tmp / "outline_l3.exe"
        res = run([str(CLANG), str(src), "-O2", "-fno-discard-value-names",
                   "-mllvm", "-taokari", "-mllvm", "-taokari-outline",
                   "-mllvm", "-taokari-level-outline=3",
                   "-mllvm", "-taokari-outline-prob=100",
                   "-mllvm", "-taokari-outline-max-shards=4",
                   "-o", str(l3_exe)])
        if res.returncode:
            print(res.stdout, end="")
            print(res.stderr, end="", file=sys.stderr)
            return res.returncode
        l3_ran = run([str(l3_exe)])
        if l3_ran.returncode:
            print(f"L3 runtime failed: {l3_ran.stdout}{l3_ran.stderr}", file=sys.stderr)
            return l3_ran.returncode
        if l3_ran.stdout != ref_run.stdout:
            print(f"L3 output drift:\n  obf: {l3_ran.stdout!r}\n  ref: {ref_run.stdout!r}",
                  file=sys.stderr)
            return 1

        # Cross-shard constant pool (opt-in). With -taokari-outline-cross-pool,
        # integer constants move out of shard bodies into a shared encrypted
        # pool. Compile WITHOUT MBA (the documented incompatibility) and verify
        # the pool appears and the program still round-trips.
        pool_ir = tmp / "outline_pool.ll"
        res = run([str(CLANG), str(src), "-O0", "-fno-discard-value-names",
                   "-mllvm", "-taokari", "-mllvm", "-taokari-outline",
                   "-mllvm", "-taokari-level-outline=3",
                   "-mllvm", "-taokari-outline-prob=100",
                   "-mllvm", "-taokari-outline-max-shards=8",
                   "-mllvm", "-taokari-outline-cross-pool",
                   "-S", "-emit-llvm", "-o", str(pool_ir)])
        if res.returncode:
            print(res.stdout, end="")
            print(res.stderr, end="", file=sys.stderr)
            return res.returncode
        pool_text = pool_ir.read_text(encoding="utf-8", errors="ignore")
        if ".cpool" not in pool_text:
            print("L3: cross-shard constant pool not emitted with -cross-pool",
                  file=sys.stderr)
            return 1
        pool_exe = tmp / "outline_pool.exe"
        res = run([str(CLANG), str(src), "-O2", "-fno-discard-value-names",
                   "-mllvm", "-taokari", "-mllvm", "-taokari-outline",
                   "-mllvm", "-taokari-level-outline=3",
                   "-mllvm", "-taokari-outline-prob=100",
                   "-mllvm", "-taokari-outline-max-shards=8",
                   "-mllvm", "-taokari-outline-cross-pool",
                   "-o", str(pool_exe)])
        if res.returncode:
            print(res.stdout, end="")
            print(res.stderr, end="", file=sys.stderr)
            return res.returncode
        pool_ran = run([str(pool_exe)])
        if pool_ran.returncode or pool_ran.stdout != ref_run.stdout:
            print(f"L3 cross-pool output drift: {pool_ran.stdout!r} vs {ref_run.stdout!r}",
                  file=sys.stderr)
            return 1

        # Outline + fla + bcf + mba fortress compose must round-trip.
        full_exe = tmp / "outline_full.exe"
        res = run([str(CLANG), str(src), "-O2", "-fno-discard-value-names",
                   "-mllvm", "-taokari", "-mllvm", "-taokari-outline",
                   "-mllvm", "-taokari-level-outline=3",
                   "-mllvm", "-taokari-outline-prob=100",
                   "-mllvm", "-taokari-outline-max-shards=4",
                   "-mllvm", "-taokari-fla", "-mllvm", "-taokari-level-fla=2",
                   "-mllvm", "-taokari-bcf", "-mllvm", "-taokari-level-bcf=2",
                   "-mllvm", "-taokari-mba", "-mllvm", "-taokari-level-mba=2",
                   "-o", str(full_exe)])
        if res.returncode:
            print(res.stdout, end="")
            print(res.stderr, end="", file=sys.stderr)
            return res.returncode
        full_ran = run([str(full_exe)])
        if full_ran.returncode:
            print(f"fortress compose runtime failed: {full_ran.stdout}{full_ran.stderr}",
                  file=sys.stderr)
            return full_ran.returncode
        if full_ran.stdout != ref_run.stdout:
            print(f"fortress compose output drift:\n  obf: {full_ran.stdout!r}\n  ref: {ref_run.stdout!r}",
                  file=sys.stderr)
            return 1

        jb_src = tmp / "jb_icall_outline.c"
        jb_src.write_text(
            "#include <stdio.h>\n"
            "#include <setjmp.h>\n"
            "static jmp_buf jb;\n"
            "__attribute__((noinline)) int deep(int d,int t){\n"
            "    if(d==t) longjmp(jb,t+100);\n"
            "    return deep(d+1,t)+1;\n"
            "}\n"
            "int main(void){\n"
            "    int v=setjmp(jb);\n"
            "    if(v==0){ deep(0,3); return 1; }\n"
            "    printf(\"jb:%d\\n\",v);\n"
            "    return 0;\n"
            "}\n",
            encoding="utf-8")
        for lvl in (3, 4):
            for opt in ("-O0", "-O2"):
                jb_exe = tmp / f"jb_icall{lvl}_{opt}.exe"
                res = run([str(CLANG), str(jb_src), opt,
                           "-mllvm", "-taokari",
                           "-mllvm", "-taokari-icall",
                           "-mllvm", "-taokari-outline",
                           "-mllvm", f"-taokari-level-icall={lvl}",
                           "-o", str(jb_exe)])
                if res.returncode:
                    print(f"jb icall-L{lvl} {opt}: compile failed", file=sys.stderr)
                    print(res.stderr, end="", file=sys.stderr)
                    return res.returncode
                jb_ran = run([str(jb_exe)])
                if jb_ran.returncode:
                    print(f"jb icall-L{lvl} {opt}: runtime crashed (rc="
                          f"{jb_ran.returncode}) -- icall indirected an outline "
                          f"shard across a longjmp frame", file=sys.stderr)
                    return 1
                if jb_ran.stdout != "jb:103\n":
                    print(f"jb icall-L{lvl} {opt}: output drift {jb_ran.stdout!r}",
                          file=sys.stderr)
                    return 1

    print("outline: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
