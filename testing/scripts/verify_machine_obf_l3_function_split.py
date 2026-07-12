"""Level-3 MIR function-splitting / boundary-trampoline verification."""
from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
OBJDUMP = tp.tool("llvm-objdump")
VSDEVCMD = tp.VSDEVCMD

SPLIT_MARKER = bytes.fromhex("9c 9d")

ANNOTATIONS = r'''
#if defined(__clang__)
#define TAO_SPLIT __attribute__((annotate("+mir:split")))
#else
#define TAO_SPLIT
#endif
'''

NO_ANNOTATIONS = ANNOTATIONS.replace(
    '__attribute__((annotate("+mir:split")))', ""
)

SOURCE_BODY = r'''
#include <cstdint>
#include <cstdio>

#define NOINLINE __attribute__((noinline))
#define OPTNONE __attribute__((optnone))

extern "C" __declspec(dllexport) NOINLINE OPTNONE TAO_SPLIT
uint32_t split_guarded(uint32_t x) {
  uint32_t y = (x * 17u) ^ 0x77u;
  return y + ((x & 3u) * 5u);
}

int main() {
  std::printf("mir-split:%u\n", split_guarded(31));
  return 0;
}
'''


def run(command: list[str], **kw) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, **kw)


def run_vs(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    if not tp.IS_WINDOWS:
      return subprocess.run(command, cwd=cwd, text=True, capture_output=True)
    with tempfile.NamedTemporaryFile("w", suffix=".cmd", delete=False, encoding="utf-8") as h:
        batch = Path(h.name)
        h.write(
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


def clang(src: Path, out: Path, *args: str) -> None:
    cmd = [str(CLANG), str(src), "-std=c++17", "-O1", *args, "-o", str(out)]
    must(run_vs(cmd, src.parent), out.name)


def disassemble(obj: Path) -> str:
    result = run([str(OBJDUMP), "-d", str(obj)])
    must(result, f"objdump {obj.name}")
    return result.stdout


def function_body(disasm: str, func: str) -> str:
    for name in (func, "_" + func):
        pat = re.compile(
            r"<" + re.escape(name) + r">:\n(.*?)(?:\n\n|\Z)", re.DOTALL
        )
        m = pat.search(disasm)
        if m:
            return m.group(1)
    raise SystemExit(f"could not locate <{func}> in disassembly")


def has_split_trampoline(obj: Path) -> bool:
    data = obj.read_bytes()
    if SPLIT_MARKER not in data:
        return False
    body = function_body(disassemble(obj), "split_guarded").lower()
    lines = [line for line in body.splitlines() if line.strip()]
    if len(lines) < 3:
        return False
    return "pushfq" in lines[0] and "popfq" in lines[1] and "\tjmp" in lines[2]


def run_checks(tmp: Path) -> int:
    annotated = tmp / "mirobf_l3_split.cpp"
    plain_src = tmp / "mirobf_l3_split_plain.cpp"
    annotated.write_text(ANNOTATIONS + SOURCE_BODY, encoding="utf-8")
    plain_src.write_text(NO_ANNOTATIONS + SOURCE_BODY, encoding="utf-8")

    plain = tmp / "plain.exe"
    obf = tmp / "obf.exe"
    annotated_obj = tmp / "annotated.obj"
    flagged_obj = tmp / "flagged.obj"
    default_obj = tmp / "default.obj"

    clang(plain_src, plain)
    clang(annotated, obf)
    clang(annotated, annotated_obj, "-c", "-mllvm", "-verify-machineinstrs")
    clang(plain_src, flagged_obj, "-c", "-mllvm", "-verify-machineinstrs", "-mllvm", "-taokari-mir=split")
    clang(plain_src, default_obj, "-c", "-mllvm", "-verify-machineinstrs", "-mllvm", "-taokari-mir=dirtybytes,junk,sub")

    plain_run = run([str(plain)])
    obf_run = run([str(obf)])
    must(plain_run, "plain run")
    must(obf_run, "obfuscated run")
    if plain_run.stdout != obf_run.stdout:
        raise SystemExit(f"stdout mismatch: {plain_run.stdout!r} != {obf_run.stdout!r}")

    for path in (annotated_obj, flagged_obj):
        if not has_split_trampoline(path):
            raise SystemExit(f"missing MIR split boundary trampoline in {path.name}")
    if SPLIT_MARKER in default_obj.read_bytes():
        raise SystemExit("split boundary marker emitted by default MIR set")

    print("verify_machine_obf_l3_function_split: ok")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    for tool in (CLANG, OBJDUMP):
        if not tool.exists():
            print(f"missing tool: {tool}", file=sys.stderr)
            return 2
    tmp = Path(tempfile.mkdtemp(prefix="taokari-mir-l3-split-"))
    try:
        return run_checks(tmp)
    finally:
        if args.keep:
            print(f"kept temp dir: {tmp}")
        else:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
