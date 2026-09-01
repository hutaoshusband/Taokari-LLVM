"""Verify MIR stack-pushing guards never corrupt SysV red-zone spills.

The TaokariMachineObf guard blobs (sse/dirtybytes/junk/sub/unmodelled/
fakebounds/split pushf/popf side-asm) push below RSP. On SysV x86-64 a
function may legally keep live spill slots in the red zone / below RSP
(observed: the cse string decryptor spills the dst pointer at [rsp-8]).
The guards then clobber those spills -> SIGSEGV. The MIR pass must skip
every stack-pushing subpass on functions whose post-PEI machine code keeps
live data below RSP.

Contract:
  * Config A (tightest tripwire): string-heavy fixture compiled with
    -mllvm -taokari-cse -mllvm -taokari-mir=sse, 5 fresh compiles x 2 runs,
    rc 0 and output identical to the plain build each time.
  * Config B: hello-world fixture under -mllvm -taokari-max
    -mllvm -taokari-max-no-vmp at -O0 and -O2 (3 compiles each), output
    identical to the plain build.
  * setjmp/unwind coverage stays in verify_setjmp_unwind_safety.py.

On Windows the configs pass trivially (Win64 has no red zone); on Linux the
pre-fix binary crashes in config A.

Exit:
  0 + "mir redzone safety: ok"
  1 -- crash or output mismatch in any config
  2 -- missing clang
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

ROOT = tp.ROOT
CLANG = tp.CLANG
VSDEVCMD = tp.VSDEVCMD

MLT_SRC = (
    "#include <stdio.h>\n"
    "#include <string.h>\n"
    "__declspec(noinline) int score(const char *s) {\n"
    "  int acc = 0;\n"
    "  for (; s && *s; ++s)\n"
    "    acc = acc * 131 + (unsigned char)*s;\n"
    "  return acc;\n"
    "}\n"
    "__declspec(noinline) int local_ptr(void) {\n"
    '  const char *p = "local-lifetime";\n'
    "  return score(p) + (int)strlen(p);\n"
    "}\n"
    "__declspec(noinline) int used_twice(void) {\n"
    '  const char *p = "used-twice";\n'
    "  return score(p) ^ score(p + 5);\n"
    "}\n"
    "__declspec(noinline) int table_lookup(int i) {\n"
    '  const char *msgs[] = {"alpha", "bravo", "charlie"};\n'
    "  return score(msgs[i % 3]);\n"
    "}\n"
    "__declspec(noinline) const char *pick(int x) {\n"
    '  return x ? "yes-branch" : "no-branch";\n'
    "}\n"
    "int main(void) {\n"
    '  printf("maxstr:%d:%d:%d:%d:%s\\n", local_ptr(), used_twice(),\n'
    '         table_lookup(1), score(pick(1)) + score(pick(0)), "fmt-ok");\n'
    "  return 0;\n"
    "}\n"
)

HELLO_SRC = (
    "#include <stdio.h>\n"
    "#include <string.h>\n"
    "__declspec(noinline) int mix(const char *s, int n) {\n"
    "  return (int)strlen(s) * 31 + n;\n"
    "}\n"
    "int main(void){ printf(\"hello:%d\\n\", mix(\"guarded-world\", 42)); return 0; }\n"
)

WIN_CRASH_RCS = {3221225477, 3221225622, 3221225727, 3765269347}


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


def build(src: Path, exe: Path, flags: list[str], opt: str) -> tuple[int, str]:
    cmd = [str(CLANG), opt, "-std=c17", "-fdeclspec", "-D_GNU_SOURCE"] + flags + [str(src), "-o", str(exe)]
    r = run(cmd)
    if r.returncode or not exe.exists():
        return r.returncode, f"BUILD_FAIL: {r.stderr[:200]}"
    return 0, ""


def exe_out(exe: Path) -> tuple[int, str]:
    rr = run([str(exe)])
    return rr.returncode, rr.stdout.strip()


def check(label: str, rc: int, out: str, want: str, failed: set[str]) -> None:
    crash = isinstance(rc, int) and (rc < 0 or rc in WIN_CRASH_RCS)
    if crash:
        print(f"  [FAIL] {label}: crashed (rc={rc}) -- MIR guard clobbered live "
              f"data below RSP (red zone)", file=sys.stderr)
        failed.add(label)
    elif rc != 0 or out != want:
        print(f"  [FAIL] {label}: rc={rc} out={out!r} want={want!r}", file=sys.stderr)
        failed.add(label)
    else:
        print(f"  [ok] {label}")


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-mir-rz-") as tmp:
        d = Path(tmp)
        mlt_src = d / "mlt.c"
        mlt_src.write_text(MLT_SRC, encoding="utf-8")
        hello_src = d / "hello.c"
        hello_src.write_text(HELLO_SRC, encoding="utf-8")

        failed: set[str] = set()

        rc, msg = build(mlt_src, d / "mlt_base.exe", [], "-O2")
        if rc:
            print(f"  [FAIL] plain mlt build: {msg}", file=sys.stderr)
            return 1
        mlt_want = exe_out(d / "mlt_base.exe")[1]
        rc, msg = build(hello_src, d / "hello_base.exe", [], "-O2")
        if rc:
            print(f"  [FAIL] plain hello build: rc={rc}", file=sys.stderr)
            return 1
        hello_want = exe_out(d / "hello_base.exe")[1]

        for i in range(5):
            exe = d / f"mlt_sse_{i}.exe"
            rc, msg = build(mlt_src, exe,
                            ["-mllvm", "-taokari-cse", "-mllvm", "-taokari-mir=sse"],
                            "-O2")
            if rc:
                print(f"  [FAIL] cse+mir=sse compile {i} -O2: {msg}", file=sys.stderr)
                failed.add(f"cse+mir=sse compile {i}")
                continue
            for r in (1, 2):
                rc, out = exe_out(exe)
                check(f"cse+mir=sse compile {i} -O2 run {r}", rc, out, mlt_want, failed)

        for opt in ("-O0", "-O2"):
            for i in range(3):
                exe = d / f"hello_max_{opt.strip('-')}_{i}.exe"
                rc, msg = build(hello_src, exe,
                                ["-mllvm", "-taokari-max", "-mllvm", "-taokari-max-no-vmp"],
                                opt)
                if rc:
                    print(f"  [FAIL] max-no-vmp {opt} compile {i}: {msg}", file=sys.stderr)
                    failed.add(f"max-no-vmp {opt} compile {i}")
                    continue
                rc, out = exe_out(exe)
                check(f"max-no-vmp {opt} compile {i}", rc, out, hello_want, failed)

    if not failed:
        print("mir redzone safety: ok")
        return 0
    print(f"mir redzone safety: FAIL {sorted(failed)}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
