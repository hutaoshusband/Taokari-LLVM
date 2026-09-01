"""Verify -taokari-max-no-mir is a whole-layer MIR opt-out under -taokari-max.

parseMirFlag() short-circuits on -taokari-max (enableMax + return), so before
this flag no global MIR opt-out existed and -taokari-mir=/-taokari-mir-*-prob
were silently ignored under max.

Contract:
  * Config A: trivial leaf fixture -> object with -mllvm -taokari-max
    -mllvm -taokari-max-no-vmp; at least one MIR guard-blob byte signature
    (junk / dirty-stack) must be present.
  * Config B: same + -mllvm -taokari-max-no-mir; none of the signatures
    may be present.
  * Config C: hello fixture built+run with max + max-no-vmp + max-no-mir;
    stdout must equal the plain build's.

A rejected -mllvm flag aborts at LLVM option parsing (rc=1, "Unknown
command line argument" on stderr); a silently-ignored flag would leave
config B's object with guard-blob signatures. Config B catches both.

Exit:
  0 + "max no mir: ok"
  1 -- signature contract or output mismatch
  2 -- missing clang
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp
from _mir_signatures import DIRTY_VARIANTS, JUNK

ROOT = tp.ROOT
CLANG = tp.CLANG
VSDEVCMD = tp.VSDEVCMD
EXE = tp.EXE

LEAF_SRC = "int f(int a) { return a + 1; }\nint main(void) { return f(7); }\n"
HELLO_SRC = (
    "#include <stdio.h>\n"
    'int main(void) { printf("hello-max-no-mir\\n"); return 0; }\n'
)


def run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    if VSDEVCMD.exists():
        with tempfile.NamedTemporaryFile("w", suffix=".cmd", delete=False, encoding="utf-8") as handle:
            batch = Path(handle.name)
            handle.write(
                "@echo off\n"
                f'call "{VSDEVCMD}" -arch=x64 -host_arch=x64 >nul\n'
                f"{subprocess.list2cmdline(cmd)}\n"
                "exit /b %ERRORLEVEL%\n"
            )
        try:
            return subprocess.run(["cmd.exe", "/d", "/c", str(batch)], cwd=ROOT, text=True, capture_output=True)
        finally:
            batch.unlink(missing_ok=True)
    return subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True)


def compile_obj(src: Path, obj: Path, flags: list[str]) -> str:
    cmd = [str(CLANG), "-O1", "-std=c17", "-fdeclspec", "-D_GNU_SOURCE", "-c"] \
        + flags + [str(src), "-o", str(obj)]
    r = run(cmd)
    if r.returncode or not obj.exists():
        return f"BUILD_FAIL rc={r.returncode}: {r.stderr[:300]}"
    return ""


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-max-no-mir-") as tmp:
        d = Path(tmp)
        leaf = d / "leaf.c"
        leaf.write_text(LEAF_SRC, encoding="utf-8")
        hello = d / "hello.c"
        hello.write_text(HELLO_SRC, encoding="utf-8")

        max_flags = ["-mllvm", "-taokari-max", "-mllvm", "-taokari-max-no-vmp"]

        obj_a = d / "leaf_max.o"
        if err := compile_obj(leaf, obj_a, max_flags):
            print(f"  [FAIL] config A: {err}", file=sys.stderr)
            return 1
        a_bytes = obj_a.read_bytes()
        if JUNK not in a_bytes and not any(v in a_bytes for v in DIRTY_VARIANTS):
            print("  [FAIL] config A: no MIR guard-blob signature in "
                  "-taokari-max -taokari-max-no-vmp object", file=sys.stderr)
            return 1
        print("  [ok] config A: max + max-no-vmp emits MIR guard blobs")

        obj_b = d / "leaf_max_nomir.o"
        if err := compile_obj(leaf, obj_b, max_flags + ["-mllvm", "-taokari-max-no-mir"]):
            print(f"  [FAIL] config B: {err}", file=sys.stderr)
            return 1
        b_bytes = obj_b.read_bytes()
        if JUNK in b_bytes or any(v in b_bytes for v in DIRTY_VARIANTS):
            print("  [FAIL] config B: guard-blob signature present despite "
                  "-taokari-max-no-mir", file=sys.stderr)
            return 1
        print("  [ok] config B: max-no-mir suppresses every MIR guard blob")

        exe = d / f"hello_nomir{EXE}"
        cmd = [str(CLANG), "-O2", "-std=c17", "-fdeclspec", "-D_GNU_SOURCE"] \
            + max_flags + ["-mllvm", "-taokari-max-no-mir", str(hello), "-o", str(exe)]
        r = run(cmd)
        if r.returncode or not exe.exists():
            print(f"  [FAIL] config C: build rc={r.returncode}: {r.stderr[:300]}", file=sys.stderr)
            return 1
        plain = d / f"hello_plain{EXE}"
        r = run([str(CLANG), "-O2", "-std=c17", "-fdeclspec", "-D_GNU_SOURCE",
                 str(hello), "-o", str(plain)])
        if r.returncode:
            print(f"  [FAIL] config C plain build: rc={r.returncode}", file=sys.stderr)
            return 1
        want = run([str(plain)]).stdout.strip()
        r = run([str(exe)])
        if r.returncode or r.stdout.strip() != want:
            print(f"  [FAIL] config C: rc={r.returncode} out={r.stdout.strip()!r} want={want!r}",
                  file=sys.stderr)
            return 1
        print("  [ok] config C: max + max-no-vmp + max-no-mir binary runs and matches")

    print("max no mir: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
