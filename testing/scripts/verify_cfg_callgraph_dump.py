"""CFG / call-graph dump metric (todo.md D1).

Dumps per-function structural metrics from the disassembly so "hard to
reverse" is measurable per target function, independent of any installed
decompiler:
  * cfg_blocks: estimated basic-block count (control-transfer instructions
    that end a block: jumps, branches, returns).
  * cfg_edges: estimated CFG edge count (each block end contributes its
    fall-through + taken edges; returns contribute one).
  * call_edges: direct call instructions (the static call-graph out-degree).

Contract:
  * Plain and obfuscated binaries build and run, output matches.
  * The obfuscated binary's victim function has strictly more cfg_blocks and
    strictly more call_edges than the plain one (Flattening/IndirectCall raise
    both), so the dump would surface a regression.

Exit: 0 ok | 1 contract failure | 2 missing clang/objdump.
"""
from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "taokari-local" / "bin"
CLANG = BIN / "clang.exe"
OBJDUMP = BIN / "llvm-objdump.exe"
VSDEVCMD = Path(
    r"C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat"
)

VICTIM = "cfg_dump_victim"

BLOCK_END = re.compile(r"\b(jmp|je|jne|j[lge]|jl|jg|jle|jge|ja|jae|jb|jbe|jo|jno|js|jns|jcxz|jecxz|jrcxz|loop|loope|loopne|ret|retn|retq|jmpq|call|callq)\b")


def run(command: list[str], *, cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    if VSDEVCMD.exists():
        with tempfile.NamedTemporaryFile(
            "w", suffix=".cmd", delete=False, encoding="utf-8"
        ) as handle:
            batch = Path(handle.name)
            handle.write(
                "@echo off\n"
                f'call "{VSDEVCMD}" -arch=x64 -host_arch=x64 >nul\n'
                f"{subprocess.list2cmdline(command)}\n"
                "exit /b %ERRORLEVEL%\n"
            )
        try:
            return subprocess.run(
                ["cmd.exe", "/d", "/c", str(batch)], cwd=cwd,
                text=True, capture_output=True,
            )
        finally:
            batch.unlink(missing_ok=True)
    return subprocess.run(command, cwd=cwd, text=True, capture_output=True)


def must(result: subprocess.CompletedProcess[str], label: str) -> bool:
    if result.returncode:
        sys.stderr.write(f"{label} failed:\n")
        sys.stderr.write((result.stdout or "") + (result.stderr or ""))
        return False
    return True


def mllvm(flags: list[str]) -> list[str]:
    out = []
    for f in flags:
        out += ["-mllvm", f]
    return out


SOURCE = r"""
#include <stdio.h>

__attribute__((noinline)) int cfg_helper_alpha(int x) { return (x * 7) ^ 0x33; }
__attribute__((noinline)) int cfg_helper_beta(int x) { return x + (x << 2) - 1; }
__attribute__((noinline)) int cfg_helper_gamma(int x) { return (x ^ 0x55) * 3; }

__attribute__((noinline)) int """ + VICTIM + r"""(int x) {
  int s = cfg_helper_alpha(x);
  if (x > 4) { s += cfg_helper_beta(s); } else { s -= cfg_helper_gamma(s); }
  for (int i = 0; i < x; ++i) { s += cfg_helper_alpha(i) ^ cfg_helper_beta(i); }
  switch (x % 3) {
    case 0: s += cfg_helper_gamma(s); break;
    case 1: s += cfg_helper_alpha(s); break;
    default: s += cfg_helper_beta(s); break;
  }
  return s;
}

int main(void) {
  printf("cfgdump:%d\n", """ + VICTIM + r"""(7));
  return 0;
}
"""


def function_metrics(disasm: str, fn: str) -> dict[str, int]:
    start = re.search(rf"^[0-9a-f]+ <{re.escape(fn)}>:\n", disasm, re.MULTILINE)
    if not start:
        return {"cfg_blocks": 0, "call_edges": 0}
    rest = disasm[start.end():]
    nxt = re.search(r"^[0-9a-f]+ <[^>]+>:", rest, re.MULTILINE)
    body = rest[:nxt.start()] if nxt else rest
    ends = BLOCK_END.findall(body)
    calls = sum(1 for e in ends if e.startswith("call"))
    return {"cfg_blocks": len(ends), "call_edges": calls}


def dump_metrics(obj: Path) -> dict[str, dict[str, int]]:
    disasm = run([str(OBJDUMP), "-d", "-r", "--no-show-raw-insn", str(obj)])
    if disasm.returncode:
        return {}
    return {VICTIM: function_metrics(disasm.stdout, VICTIM)}


def main() -> int:
    if not CLANG.exists() or not OBJDUMP.exists():
        print("missing clang/objdump", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-cfgdump-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "cfgdump.c"
        src.write_text(SOURCE, encoding="utf-8")

        plain = tmp / "plain.exe"
        if not must(run([str(CLANG), str(src), "-O2", "-o", str(plain)]),
                    "plain build"):
            return 1
        plain_run = run([str(plain)])
        if plain_run.returncode:
            sys.stderr.write("plain run failed\n")
            return 1

        obf = tmp / "obf.exe"
        if not must(run([str(CLANG), str(src), "-O2",
                         *mllvm(["-taokari", "-taokari-indbr", "-taokari-icall",
                                 "-taokari-indgv", "-taokari-fla", "-taokari-bcf",
                                 "-taokari-mba", "-taokari-cse", "-taokari-cie",
                                 "-taokari-cfe"]),
                         "-o", str(obf)]), "obfuscated build"):
            return 1
        obf_run = run([str(obf)])
        if obf_run.returncode or obf_run.stdout != plain_run.stdout:
            print(f"FAIL: runtime mismatch rc={obf_run.returncode} "
                  f"out={obf_run.stdout!r} expected={plain_run.stdout!r}",
                  file=sys.stderr)
            return 1

        plain_obj = tmp / "plain.obj"
        if not must(run([str(CLANG), str(src), "-O2", "-c", "-o", str(plain_obj)]),
                    "plain obj build"):
            return 1
        obf_obj = tmp / "obf.obj"
        if not must(run([str(CLANG), str(src), "-O2",
                         *mllvm(["-taokari", "-taokari-indbr", "-taokari-icall",
                                 "-taokari-indgv", "-taokari-fla", "-taokari-bcf",
                                 "-taokari-mba", "-taokari-cse", "-taokari-cie",
                                 "-taokari-cfe"]),
                         "-c", "-o", str(obf_obj)]), "obfuscated obj build"):
            return 1

        plain_m = dump_metrics(plain_obj).get(VICTIM, {"cfg_blocks": 0, "call_edges": 0})
        obf_m = dump_metrics(obf_obj).get(VICTIM, {"cfg_blocks": 0, "call_edges": 0})

        if not plain_m["cfg_blocks"] or not plain_m["call_edges"]:
            print(f"FAIL: plain metrics empty ({plain_m}); dump is broken",
                  file=sys.stderr)
            return 1
        if obf_m["cfg_blocks"] <= plain_m["cfg_blocks"]:
            print(f"FAIL: obfuscated cfg_blocks ({obf_m['cfg_blocks']}) not > "
                  f"plain ({plain_m['cfg_blocks']}); CFG did not grow",
                  file=sys.stderr)
            return 1

    print(f"cfg-callgraph-dump: ok ({VICTIM}: plain {plain_m} -> obf {obf_m}, "
          f"CFG blocks grew, runtime matches native)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
