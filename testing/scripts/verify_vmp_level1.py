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
LLVM_NM = tp.tool("llvm-nm")
SRC = ROOT / "testing" / "cases" / "vmp_basic" / "src" / "main.c"
VSDEVCMD = tp.VSDEVCMD
EXPECTED = "vmp-basic:40:25\n"


def attr_group(text: str, number: str) -> str:
    match = re.search(rf"attributes #{number} = \{{([^}}]+)\}}", text)
    return match.group(1) if match else ""


def run(cmd: list[str], *, use_vs_env: bool = False) -> subprocess.CompletedProcess[str]:
    if use_vs_env and VSDEVCMD.exists():
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


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory(prefix="taokari-vmp-") as tmp:
        tmpdir = Path(tmp)
        ll = tmpdir / "vmp_basic.ll"
        obj = tmpdir / "vmp_basic.obj"
        exe = tmpdir / "vmp_basic.exe"
        flags = [
            str(CLANG),
            str(SRC),
            "-O2",
            "-mllvm",
            "-taokari",
            "-mllvm",
            "-taokari-vmp",
        ]

        ir = run([*flags, "-S", "-emit-llvm", "-o", str(ll)], use_vs_env=True)
        if ir.returncode:
            print(ir.stdout, ir.stderr, sep="", file=sys.stderr)
            return ir.returncode
        text = ll.read_text(encoding="utf-8", errors="ignore")
        if "__taokari_vmp_interp_i64" not in text or "__taokari_vmp_bc_" not in text:
            print("VMP helper/bytecode marker missing from generated IR", file=sys.stderr)
            return 1
        wrapper = re.search(
            r"define .* @protected_mix\([^)]*\) #(\d+) \{([\s\S]*?)\n\}",
            text)
        if not wrapper:
            print("VMP wrapper function missing from generated IR", file=sys.stderr)
            return 1
        if "noinline" not in attr_group(text, wrapper.group(1)):
            print("VMP wrapper lost noinline attribute", file=sys.stderr)
            return 1
        if "call i64 @__taokari_vmp_interp_i64_protected_mix_" not in wrapper.group(2):
            print("static VMP function is not a call-boundary wrapper", file=sys.stderr)
            return 1
        interp = re.search(
            r"define internal i64 @__taokari_vmp_interp_i64_protected_mix_"
            r"\d+\([^)]*\) #(\d+) \{",
            text)
        if not interp:
            print("separate internal VMP interpreter missing", file=sys.stderr)
            return 1
        if "noinline" not in attr_group(text, interp.group(1)):
            print("VMP interpreter lost noinline attribute", file=sys.stderr)
            return 1

        compiled = run([*flags, "-c", "-o", str(obj)], use_vs_env=True)
        if compiled.returncode:
            print(compiled.stdout, compiled.stderr, sep="", file=sys.stderr)
            return compiled.returncode
        symbols = run([str(LLVM_NM), str(obj)])
        if "__taokari_vmp_interp_i64" not in symbols.stdout:
            print("VMP interpreter marker missing from object symbols", file=sys.stderr)
            return 1

        build = run([*flags, "-o", str(exe)], use_vs_env=True)
        if build.returncode:
            print(build.stdout, build.stderr, sep="", file=sys.stderr)
            return build.returncode

        result = run([str(exe)])
        if result.returncode:
            print(result.stdout, result.stderr, sep="", file=sys.stderr)
            return result.returncode
        if result.stdout != EXPECTED:
            print(f"unexpected stdout: {result.stdout!r}", file=sys.stderr)
            return 1
    print("VMP L1 verifier passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
