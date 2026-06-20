from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CLANG = ROOT / "build" / "taokari-local" / "bin" / "clang.exe"
VSDEVCMD = Path(r"C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat")

# L1 only exercises `add`; the other ops land in the next commit.
SOURCE = r"""
#include <stdio.h>

__attribute__((noinline)) int add_probe(int x, int y) {
  return x + y;
}

__attribute__((noinline)) long long add_probe64(long long x, long long y) {
  return x + y;
}

int main(void) {
  int a = add_probe(7, 11);            // 18
  long long b = add_probe64(100, 23);  // 123
  printf("mba:%lld\n", (long long)a + b);
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


def compile_source(src: Path, out: Path, extra: list[str]) -> subprocess.CompletedProcess[str]:
    return run([
        str(CLANG), str(src), "-O2", "-fno-discard-value-names",
        "-mllvm", "-taokari",
        "-mllvm", "-taokari-mba",
        "-mllvm", "-taokari-level-mba=1",
        "-mllvm", "-taokari-mba-prob=100",
        *extra,
        "-o", str(out),
    ])


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-mba-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "mba.c"
        src.write_text(SOURCE, encoding="utf-8")

        # CLI flag path: assert MBA IR markers present, then assert runtime output.
        ir = tmp / "mba.ll"
        compiled_ir = compile_source(src, ir, ["-S", "-emit-llvm"])
        if compiled_ir.returncode:
            print(compiled_ir.stdout, end="")
            print(compiled_ir.stderr, end="", file=sys.stderr)
            return compiled_ir.returncode

        text = ir.read_text(encoding="utf-8", errors="ignore")
        required = [".mba.xor", ".mba.and", ".mba.carry", ".mba.add"]
        missing = [needle for needle in required if needle not in text]
        if missing:
            print(f"missing MBA IR markers: {', '.join(missing)}", file=sys.stderr)
            return 1

        # Annotation override path: per project README, annotate() overrides the
        # per-function enable/level but the master + pass flag must still be on
        # for the pass to run. Force-disable at CLI, re-enable via annotate("+mba").
        ann_src = tmp / "mba_ann.c"
        ann_src.write_text(SOURCE.replace(
            "__attribute__((noinline)) int add_probe",
            '__attribute__((noinline, annotate("+mba"))) int add_probe'
        ).replace(
            "__attribute__((noinline)) long long add_probe64",
            '__attribute__((noinline, annotate("+mba"))) long long add_probe64'
        ), encoding="utf-8")
        ann_ir = tmp / "mba_ann.ll"
        ann_run = run([
            str(CLANG), str(ann_src), "-O2", "-fno-discard-value-names",
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
            str(CLANG), str(src), "-O2", "-fno-discard-value-names",
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
        if ran.returncode or ran.stdout != "mba:141\n":
            print(f"bad run: rc={ran.returncode} stdout={ran.stdout!r}", file=sys.stderr)
            print(ran.stderr, end="", file=sys.stderr)
            return 1

    print("mixed boolean arithmetic: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
