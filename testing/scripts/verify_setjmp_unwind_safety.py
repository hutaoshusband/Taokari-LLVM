from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
VSDEVCMD = tp.VSDEVCMD
IS_WINDOWS = tp.IS_WINDOWS

SETJMP_SRC = (
    "#include <stdio.h>\n"
    "#include <setjmp.h>\n"
    "static jmp_buf jb;\n"
    "__attribute__((noinline)) int deep(int d, int t){\n"
    "    if (d == t) longjmp(jb, t + 50);\n"
    "    return deep(d + 1, t) + 1;\n"
    "}\n"
    "int main(void){\n"
    "    int j = setjmp(jb);\n"
    "    if (j == 0) { deep(0, 4); return 1; }\n"
    '    printf("jb:%d\\n", j);\n'
    "    return 0;\n"
    "}\n"
)

EH_SRC = (
    "#include <stdio.h>\n"
    "#include <stdexcept>\n"
    "__attribute__((noinline)) int thrower(int x){\n"
    '    if (x < 0) throw std::runtime_error("neg");\n'
    "    return x * 2;\n"
    "}\n"
    "__attribute__((noinline)) int middle(int x){\n"
    "    int r = thrower(x); return r + 1;\n"
    "}\n"
    "__attribute__((noinline)) int outer_wrap(int x){\n"
    "    try { return middle(x); }\n"
    "    catch (const std::exception&) { return -1; }\n"
    "}\n"
    "int main(void){\n"
    '    printf("eh:%d:%d\\n", outer_wrap(5), outer_wrap(-1));\n'
    "    return 0;\n"
    "}\n"
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


def build_run(src: Path, exe: Path, flags: list[str], opt: str) -> tuple[int, str]:
    is_cpp = src.suffix.lower() in {".cpp", ".cc", ".cxx"}
    std = "-std=c++17" if is_cpp else "-std=c17"
    # C++ sources need the clang++ driver so the C++ runtime (libc++/libstdc++
    # and __cxa_allocate_exception for EH) is linked. The C driver leaves the
    # EH runtime unresolved for a .cpp.
    driver = CLANG
    if is_cpp and not IS_WINDOWS:
        cpp_driver = CLANG.with_name(CLANG.name.replace("clang", "clang++"))
        if cpp_driver.exists():
            driver = cpp_driver
    if is_cpp:
        flags = flags + ["-fcxx-exceptions"]
    cmd = [str(driver), opt, std, "-fdeclspec", "-D_GNU_SOURCE"] + flags + [str(src), "-o", str(exe)]
    r = run(cmd)
    if r.returncode or not exe.exists():
        return r.returncode, f"BUILD_FAIL: {r.stderr[:200]}"
    rr = run([str(exe)])
    return rr.returncode, rr.stdout.strip()


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    failures = 0
    with tempfile.TemporaryDirectory(prefix="taokari-setjmp-eh-") as tmp:
        d = Path(tmp)
        jb_src = d / "jb.c"
        jb_src.write_text(SETJMP_SRC, encoding="utf-8")
        eh_src = d / "eh.cpp"
        eh_src.write_text(EH_SRC, encoding="utf-8")

        cases = [
            ("setjmp max -O0", jb_src, ["-mllvm", "-taokari-max"], "-O0", "jb:54"),
            ("setjmp max -O2", jb_src, ["-mllvm", "-taokari-max"], "-O2", "jb:54"),
            ("setjmp max+vmp -O0", jb_src, ["-mllvm", "-taokari-max", "-mllvm", "-taokari-vmp"], "-O0", "jb:54"),
            ("setjmp icall-L4+outline -O0", jb_src,
             ["-mllvm", "-taokari", "-mllvm", "-taokari-icall", "-mllvm", "-taokari-outline",
              "-mllvm", "-taokari-level-icall=4"], "-O0", "jb:54"),
            ("eh vmp -O0", eh_src, ["-mllvm", "-taokari", "-mllvm", "-taokari-vmp"], "-O0", "eh:11:-1"),
            ("eh vmp -O2", eh_src, ["-mllvm", "-taokari", "-mllvm", "-taokari-vmp"], "-O2", "eh:11:-1"),
        ]
        for label, src, flags, opt, want in cases:
            exe = d / f"{label.replace(' ', '_').replace('-', '').replace('+','p')}.exe"
            rc, out = build_run(src, exe, flags, opt)
            crash = isinstance(rc, int) and (rc < 0 or rc in (3221225477, 3221225622, 3221225727, 3765269347))
            if crash:
                print(f"  [FAIL] {label}: crashed (rc={rc}) -- non-local jump / exception "
                      f"unwinding broke through an obfuscated frame", file=sys.stderr)
                failures += 1
            elif rc != 0 or out != want:
                print(f"  [FAIL] {label}: rc={rc} out={out!r} want={want!r}", file=sys.stderr)
                failures += 1
            else:
                print(f"  [ok] {label}: {out!r}")

    if failures:
        print(f"setjmp/eh unwind safety: FAIL ({failures} case(s))", file=sys.stderr)
        return 1
    print("setjmp/eh unwind safety: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
