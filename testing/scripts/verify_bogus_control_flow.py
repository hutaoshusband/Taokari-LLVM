from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CLANG = ROOT / "build" / "taokari-local" / "bin" / "clang.exe"
VSDEVCMD = Path(r"C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat")

SOURCE = r"""
#include <stdio.h>

volatile int g_sink = 3;

__attribute__((noinline)) int probe(int x) {
  int y = x + g_sink;
  if (x & 1) {
    y = y * 7 + 11;
    g_sink += y;
  } else {
    y = y * 5 - 9;
    g_sink ^= y;
  }
  return y ^ g_sink;
}

int main(void) {
  int a = probe(7);
  int b = probe(10);
  printf("bcf:%d\n", a + b);
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
        "-mllvm", "-taokari-bcf",
        "-mllvm", "-taokari-level-bcf=2",
        "-mllvm", "-taokari-bcf-prob=100",
        "-mllvm", "-taokari-bcf-loops=3",
        *extra,
        "-o", str(out),
    ])


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    source_text = (
        ROOT / "upstream" / "taokari" / "llvm" / "lib" / "Transforms" /
        "Obfuscation" / "BogusControlFlow.cpp"
    ).read_text(encoding="utf-8", errors="ignore")
    seed_choices = [
        "OpaqueSeedKind::Pointer",
        "OpaqueSeedKind::StackAddress",
        "OpaqueSeedKind::Global",
        "OpaqueSeedKind::Environment",
        "OpaqueSeedKind::RuntimeNonce",
    ]
    missing_choices = [choice for choice in seed_choices
                       if choice not in source_text]
    if "FuncRNG() % 5" not in source_text or missing_choices:
        print("BCF seed-source variety missing", file=sys.stderr)
        return 1
    if "getOrCreateJunkFunction(*Fake.getModule(), FuncRNG)" not in source_text:
        print("BCF junk helper is not RNG-shaped", file=sys.stderr)
        return 1
    if "switch (FuncRNG() % 4)" not in source_text:
        print("BCF junk helper palette missing", file=sys.stderr)
        return 1
    if "1103515245" in source_text or "12345" in source_text:
        print("BCF junk helper still uses fixed LCG constants", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory(prefix="taokari-bcf-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "bcf.c"
        src.write_text(SOURCE, encoding="utf-8")

        ir = tmp / "bcf.ll"
        compiled_ir = compile_source(src, ir, ["-S", "-emit-llvm"])
        if compiled_ir.returncode:
            print(compiled_ir.stdout, end="")
            print(compiled_ir.stderr, end="", file=sys.stderr)
            return compiled_ir.returncode

        text = ir.read_text(encoding="utf-8", errors="ignore")
        required = [
            ".bcf.guard",
            ".bcf.fake",
            "__taokari_bcf_nonce",
            "__taokari_bcf_junk",
            "bcf.fake.call",
            "bcf.fake.nonce",
            "bcf.opaque",
        ]
        missing = [needle for needle in required if needle not in text]
        if missing:
            print(f"missing BCF IR markers: {', '.join(missing)}", file=sys.stderr)
            return 1
        seed_markers = (
            "bcf.seed.vload",
            "bcf.seed.p2i",
            "bcf.seed.fp",
            "bcf.seed.env",
        )
        if not any(marker in text for marker in seed_markers):
            print("missing BCF seed-source marker", file=sys.stderr)
            return 1

        cfg = tmp / "bcf.json"
        cfg.write_text('{"bcf":{"enable":true,"level":2,"probability":100,"loopCount":2}}', encoding="utf-8")
        cfg_ir = tmp / "bcf_cfg.ll"
        cfg_run = run([
            str(CLANG), str(src), "-O2", "-fno-discard-value-names",
            "-mllvm", f"-taokari-cfg={cfg}",
            "-S", "-emit-llvm", "-o", str(cfg_ir),
        ])
        if cfg_run.returncode:
            print(cfg_run.stdout, end="")
            print(cfg_run.stderr, end="", file=sys.stderr)
            return cfg_run.returncode
        cfg_text = cfg_ir.read_text(encoding="utf-8", errors="ignore")
        if ".bcf.fake" not in cfg_text or "bcf.fake.call" not in cfg_text:
            print("config-driven BCF markers missing", file=sys.stderr)
            return 1

        exe = tmp / "bcf.exe"
        compiled_exe = compile_source(src, exe, [])
        if compiled_exe.returncode:
            print(compiled_exe.stdout, end="")
            print(compiled_exe.stderr, end="", file=sys.stderr)
            return compiled_exe.returncode
        ran = run([str(exe)])
        if ran.returncode or ran.stdout != "bcf:89\n":
            print(f"bad run: rc={ran.returncode} stdout={ran.stdout!r}", file=sys.stderr)
            print(ran.stderr, end="", file=sys.stderr)
            return 1

        for flag in ("-taokari-bcf-before-fla", "-taokari-bcf-after-fla"):
            checked = compile_source(src, tmp / f"{flag[1:]}.ll", [
                "-S", "-emit-llvm",
                "-mllvm", "-taokari-fla",
                "-mllvm", flag,
            ])
            if checked.returncode:
                print(checked.stdout, end="")
                print(checked.stderr, end="", file=sys.stderr)
                return checked.returncode

    print("bogus control flow: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
