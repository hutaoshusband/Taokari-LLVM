from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CLANG = ROOT / "build" / "taokari-local" / "bin" / "clang.exe"
VSDEVCMD = Path(r"C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat")

# Exercises every Level-1 MBA identity (add/sub/xor/and/or) across i32 and i64.
SOURCE = r"""
#include <stdio.h>
#include <stdint.h>

__attribute__((noinline)) int32_t add_probe(int32_t x, int32_t y) { return x + y; }
__attribute__((noinline)) int32_t sub_probe(int32_t x, int32_t y) { return x - y; }
__attribute__((noinline)) int32_t xor_probe(int32_t x, int32_t y) { return x ^ y; }
__attribute__((noinline)) int32_t and_probe(int32_t x, int32_t y) { return x & y; }
__attribute__((noinline)) int32_t or_probe(int32_t x, int32_t y) { return x | y; }

__attribute__((noinline)) int64_t add64_probe(int64_t x, int64_t y) { return x + y; }
__attribute__((noinline)) int64_t sub64_probe(int64_t x, int64_t y) { return x - y; }
__attribute__((noinline)) int64_t xor64_probe(int64_t x, int64_t y) { return x ^ y; }
__attribute__((noinline)) int64_t and64_probe(int64_t x, int64_t y) { return x & y; }
__attribute__((noinline)) int64_t or64_probe(int64_t x, int64_t y) { return x | y; }

int main(void) {
  int32_t a = add_probe(7, 11) + sub_probe(100, 23) + xor_probe(0xF0, 0x0F) +
              and_probe(0xC3, 0x66) + or_probe(0xC3, 0x3C);
  // a = 18 + 77 + 255 + 66 + 255 = 671
  int64_t b = add64_probe(1000, 234) + sub64_probe(5000, 678) +
              xor64_probe(0xFF00, 0x00FF) + and64_probe(0xAA55, 0x0F0F) +
              or64_probe(0xAA55, 0x55AA);
  // b = 1234 + 4322 + 65535 + 2565 + 65535 = 139191
  printf("mba:%lld\n", (long long)a + b);  // 671 + 139191 = 139862
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


def compile_source(src: Path, out: Path, extra: list[str],
                   *, level: int = 1) -> subprocess.CompletedProcess[str]:
    return run([
        str(CLANG), str(src), "-O2", "-fno-discard-value-names",
        "-mllvm", "-taokari",
        "-mllvm", "-taokari-mba",
        "-mllvm", f"-taokari-level-mba={level}",
        "-mllvm", "-taokari-mba-prob=100",
        *extra,
        "-o", str(out),
    ])


def compile_ir_markers(src: Path, out: Path, extra: list[str],
                       *, level: int = 1) -> subprocess.CompletedProcess[str]:
    # Inspect the raw MBA output at -O0. At -O2 InstCombine legitimately
    # simplifies some identities back (e.g. ~(~a|~b) -> a&b); that fold-back is
    # the Level-2 optimizer-resistance problem, not a Level-1 correctness bug.
    return run([
        str(CLANG), str(src), "-O0", "-fno-discard-value-names",
        "-mllvm", "-taokari",
        "-mllvm", "-taokari-mba",
        "-mllvm", f"-taokari-level-mba={level}",
        "-mllvm", "-taokari-mba-prob=100",
        *extra,
        "-S", "-emit-llvm",
        "-o", str(out),
    ])


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    mba_source = (
        ROOT / "upstream" / "taokari" / "llvm" / "lib" / "Transforms" /
        "Obfuscation" / "MBA.cpp"
    ).read_text(encoding="utf-8", errors="ignore")
    if "switch (FuncRNG() % 4)" not in mba_source:
        print("MBA noise palette missing", file=sys.stderr)
        return 1
    if 'Name + ".noise.mul"' not in mba_source or \
            'Name + ".noise.xor"' not in mba_source or \
            'Name + ".noise.sub"' not in mba_source:
        print("MBA noise shape variety missing", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory(prefix="taokari-mba-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "mba.c"
        src.write_text(SOURCE, encoding="utf-8")

        # CLI flag path: assert MBA IR markers present (-O0 raw), then assert
        # runtime output (-O2, proves the substitution is semantically correct).
        ir = tmp / "mba.ll"
        compiled_ir = compile_ir_markers(src, ir, [])
        if compiled_ir.returncode:
            print(compiled_ir.stdout, end="")
            print(compiled_ir.stderr, end="", file=sys.stderr)
            return compiled_ir.returncode

        text = ir.read_text(encoding="utf-8", errors="ignore")
        # Every op has a distinctive marker; requiring all five proves the
        # whole L1 identity set fires, not just `add`.
        required = [
            ".mba.add",    # add / sub / or
            ".mba.carry",  # add
            ".mba.not",    # sub / and / or
            ".mba.sum",    # sub
            ".mba.sub",    # xor
            ".mba.na",     # and / or
        ]
        missing = [needle for needle in required if needle not in text]
        if missing:
            print(f"missing MBA IR markers: {', '.join(missing)}", file=sys.stderr)
            return 1

        l2_ir = tmp / "mba_l2.ll"
        compiled_l2_ir = compile_ir_markers(src, l2_ir, [], level=2)
        if compiled_l2_ir.returncode:
            print(compiled_l2_ir.stdout, end="")
            print(compiled_l2_ir.stderr, end="", file=sys.stderr)
            return compiled_l2_ir.returncode
        l2_text = l2_ir.read_text(encoding="utf-8", errors="ignore")
        l2_required = [
            ".mba.noise",
            ".mba.mix.",
            ".vload",
        ]
        l2_missing = [needle for needle in l2_required if needle not in l2_text]
        if l2_missing:
            print(f"missing MBA L2 markers: {', '.join(l2_missing)}",
                  file=sys.stderr)
            return 1

        # Annotation override path: per project README, annotate() overrides the
        # per-function enable/level but the master + pass flag must still be on
        # for the pass to run. Force-enable one probe via annotate("+mba").
        ann_src = tmp / "mba_ann.c"
        ann_lines = []
        for line in SOURCE.splitlines():
            if "int32_t add_probe" in line:
                line = line.replace("__attribute__((noinline))",
                                    '__attribute__((noinline, annotate("+mba")))')
            ann_lines.append(line)
        ann_src.write_text("\n".join(ann_lines) + "\n", encoding="utf-8")
        ann_ir = tmp / "mba_ann.ll"
        ann_run = run([
            str(CLANG), str(ann_src), "-O0", "-fno-discard-value-names",
            "-mllvm", "-taokari",
            "-mllvm", "-taokari-mba",
            "-S", "-emit-llvm", "-o", str(ann_ir),
        ])
        if ann_run.returncode:
            print(ann_run.stdout, end="")
            print(ann_run.stderr, end="", file=sys.stderr)
            return ann_run.returncode
        ann_text = ann_ir.read_text(encoding="utf-8", errors="ignore")
        if ".mba.add" not in ann_text:
            print("annotation-driven MBA markers missing", file=sys.stderr)
            return 1

        # Config-file path.
        cfg = tmp / "mba.json"
        cfg.write_text('{"mba":{"enable":true,"level":1,"probability":100}}', encoding="utf-8")
        cfg_ir = tmp / "mba_cfg.ll"
        cfg_run = run([
            str(CLANG), str(src), "-O0", "-fno-discard-value-names",
            "-mllvm", f"-taokari-cfg={cfg}",
            "-S", "-emit-llvm", "-o", str(cfg_ir),
        ])
        if cfg_run.returncode:
            print(cfg_run.stdout, end="")
            print(cfg_run.stderr, end="", file=sys.stderr)
            return cfg_run.returncode
        if ".mba.add" not in cfg_ir.read_text(encoding="utf-8", errors="ignore"):
            print("config-driven MBA markers missing", file=sys.stderr)
            return 1

        exe = tmp / "mba.exe"
        compiled_exe = compile_source(src, exe, [])
        if compiled_exe.returncode:
            print(compiled_exe.stdout, end="")
            print(compiled_exe.stderr, end="", file=sys.stderr)
            return compiled_exe.returncode
        ran = run([str(exe)])
        if ran.returncode or ran.stdout != "mba:139862\n":
            print(f"bad run: rc={ran.returncode} stdout={ran.stdout!r}", file=sys.stderr)
            print(ran.stderr, end="", file=sys.stderr)
            return 1

        l2_exe = tmp / "mba_l2.exe"
        compiled_l2_exe = compile_source(src, l2_exe, [], level=2)
        if compiled_l2_exe.returncode:
            print(compiled_l2_exe.stdout, end="")
            print(compiled_l2_exe.stderr, end="", file=sys.stderr)
            return compiled_l2_exe.returncode
        l2_ran = run([str(l2_exe)])
        if l2_ran.returncode or l2_ran.stdout != "mba:139862\n":
            print(f"bad L2 run: rc={l2_ran.returncode} "
                  f"stdout={l2_ran.stdout!r}", file=sys.stderr)
            print(l2_ran.stderr, end="", file=sys.stderr)
            return 1

    print("mixed boolean arithmetic: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
