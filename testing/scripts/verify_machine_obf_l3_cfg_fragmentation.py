"""Level-3 MIR CFG fragmentation metric."""
from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
OBJDUMP = tp.tool("llvm-objdump")
VSDEVCMD = tp.VSDEVCMD
SOURCE = ROOT / "testing" / "cases" / "c_console" / "src" / "main.c"

IR_AND_MIR_FLAGS = [
    "-O2",
    "-mllvm", "-taokari",
    "-mllvm", "-taokari-fla",
    "-mllvm", "-taokari-bcf",
    "-mllvm", "-taokari-indbr",
    "-mllvm", "-taokari-mir=dirtybytes,junk,sub",
    "-mllvm", "-verify-machineinstrs",
]

INSTR_RE = re.compile(r"^\s*[0-9a-f]+:\s+(?:[0-9a-f]{2}\s+)+\s*([^\s#]+)")
BRANCHES = {"callq", "retq", "jmp", "jmpq", "je", "jne", "ja", "jae", "jb", "jbe", "jg", "jge", "jl", "jle"}
FRAGMENTERS = {"ud2", "int3", "<unknown>"}


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


def compile_pair(tmp: Path) -> tuple[Path, Path, Path, Path]:
    plain_exe, obf_exe = tmp / "plain.exe", tmp / "obf.exe"
    plain_obj, obf_obj = tmp / "plain.obj", tmp / "obf.obj"
    must(run_vs([str(CLANG), str(SOURCE), "-std=c17", "-O2", "-c", "-o", str(plain_obj)], SOURCE.parent), "plain obj")
    must(run_vs([str(CLANG), str(SOURCE), "-std=c17", *IR_AND_MIR_FLAGS, "-c", "-o", str(obf_obj)], SOURCE.parent), "obf obj")
    must(run_vs([str(CLANG), str(SOURCE), "-std=c17", "-O2", "-o", str(plain_exe)], SOURCE.parent), "plain exe")
    must(run_vs([str(CLANG), str(SOURCE), "-std=c17", *IR_AND_MIR_FLAGS, "-o", str(obf_exe)], SOURCE.parent), "obf exe")
    return plain_exe, obf_exe, plain_obj, obf_obj


def disassemble(obj: Path) -> str:
    result = run([str(OBJDUMP), "-d", str(obj)])
    must(result, obj.name)
    return result.stdout


def metrics(text: str) -> tuple[int, int]:
    branches = fragmenters = 0
    for line in text.splitlines():
        match = INSTR_RE.match(line)
        if not match:
            continue
        mnemonic = match.group(1).lower()
        branches += mnemonic in BRANCHES or (mnemonic.startswith("j") and mnemonic != "jmpq")
        fragmenters += mnemonic in FRAGMENTERS
    return branches, fragmenters


def run_checks(tmp: Path) -> int:
    plain_exe, obf_exe, plain_obj, obf_obj = compile_pair(tmp)
    plain_run = run([str(plain_exe)])
    obf_run = run([str(obf_exe)])
    must(plain_run, "plain run")
    must(obf_run, "obfuscated run")
    if plain_run.stdout != obf_run.stdout:
        raise SystemExit(f"stdout mismatch: {plain_run.stdout!r} != {obf_run.stdout!r}")

    plain_branches, plain_frag = metrics(disassemble(plain_obj))
    obf_branches, obf_frag = metrics(disassemble(obf_obj))
    if obf_branches < plain_branches + 2:
        raise SystemExit(f"branch metric too weak: plain={plain_branches} obf={obf_branches}")
    if obf_frag <= plain_frag:
        raise SystemExit(f"fragmenter metric too weak: plain={plain_frag} obf={obf_frag}")

    print(
        "verify_machine_obf_l3_cfg_fragmentation: ok "
        f"branches={plain_branches}->{obf_branches} "
        f"fragmenters={plain_frag}->{obf_frag}"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    for tool in (CLANG, OBJDUMP):
        if not tool.exists():
            print(f"missing tool: {tool}", file=sys.stderr)
            return 2
    tmp = Path(tempfile.mkdtemp(prefix="taokari-mir-l3-cfg-"))
    try:
        return run_checks(tmp)
    finally:
        if args.keep:
            print(f"kept temp dir: {tmp}")
        else:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
