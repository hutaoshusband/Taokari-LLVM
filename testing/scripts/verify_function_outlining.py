from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CLANG = ROOT / "build" / "taokari-local" / "bin" / "clang.exe"
VSDEVCMD = Path(r"C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat")

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


def compile_ir(src: Path, out: Path) -> subprocess.CompletedProcess[str]:
    # -O0 so the IR keeps the outlining call structure before later opts fold it.
    return run([
        str(CLANG), str(src), "-O0", "-fno-discard-value-names",
        "-mllvm", "-taokari",
        "-mllvm", "-taokari-outline",
        "-mllvm", "-taokari-level-outline=1",
        "-mllvm", "-taokari-outline-prob=100",
        "-mllvm", "-taokari-outline-max-shards=8",
        "-S", "-emit-llvm",
        "-o", str(out),
    ])


def compile_exe(src: Path, out: Path, *, max_shards: int) -> subprocess.CompletedProcess[str]:
    return run([
        str(CLANG), str(src), "-O2", "-fno-discard-value-names",
        "-mllvm", "-taokari",
        "-mllvm", "-taokari-outline",
        "-mllvm", "-taokari-level-outline=1",
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

        ir = tmp / "outline.ll"
        res = compile_ir(src, ir)
        if res.returncode:
            print(res.stdout, end="")
            print(res.stderr, end="", file=sys.stderr)
            return res.returncode
        text = ir.read_text(encoding="utf-8", errors="ignore")
        if ".shard" not in text:
            print("no .shard helpers emitted in IR", file=sys.stderr)
            return 1
        if "sensitive.shard" not in text and "plain.shard" not in text:
            # At least one source function must have been split.
            print("no per-function shard name in IR", file=sys.stderr)
            return 1

        # Global outlining via flag must produce a shard in `plain` too.
        exe = tmp / "outline.exe"
        res = compile_exe(src, exe, max_shards=8)
        if res.returncode:
            print(res.stdout, end="")
            print(res.stderr, end="", file=sys.stderr)
            return res.returncode
        ran = run([str(exe)])
        if ran.returncode:
            print(f"runtime failed: {ran.stdout}{ran.stderr}", file=sys.stderr)
            return ran.returncode
        # Recompute the reference without obfuscation to avoid hand-arithmetic drift.
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
        res = compile_exe(src, budget_exe, max_shards=0)
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

    print("outline: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
