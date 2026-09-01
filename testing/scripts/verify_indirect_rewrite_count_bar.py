"""Indirect-rewrite count gnarliness bar (todo.md D2).

A release-blocking measurement gate for IndirectGlobalVariable. Existing
page-table verifiers prove the machinery exists and survives the optimizer;
this bar proves the pass actually rewrote real global accesses into the
page table (a silent zero-rewrite regression would pass those but fail here).

Contract:
  * A program reads several file-static globals in a noinline function.
  * With indgv on, the obfuscated IR's _IndirectGVs object table holds at
    least MIN_REWRITES real globals (ptrtoint entries); the plain IR holds
    none of those markers.
  * The obfuscated binary runs and matches native output.

Exit: 0 ok | 1 contract failure | 2 missing clang.
"""
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
VSDEVCMD = tp.VSDEVCMD

MIN_REWRITES = 4
MARKER = "_IndirectGVs"

ARRAY_RE = re.compile(
    r"^@(?P<name>[^\s=]+)\s*=[^\r\n]*\[(?P<count>\d+)\s+x\s+i\d+\]\s*"
    r"\[(?P<body>[^\r\n]*)\]",
    re.MULTILINE,
)


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
        sys.stderr.write(result.stdout + result.stderr)
        return False
    return True


def mllvm(flags: list[str]) -> list[str]:
    out = []
    for f in flags:
        out += ["-mllvm", f]
    return out


SOURCE = r"""
#include <stdio.h>

static volatile int g0 = 1, g1 = 3, g2 = 5, g3 = 7, g4 = 11, g5 = 13;

__attribute__((noinline)) int read_globals(int x) {
  int r = g0 + g1;
  if (x & 1) r += g2;
  if (x & 2) r += g3;
  if (x & 4) r += g4;
  if (x & 8) r += g5;
  return r;
}

int main(void) {
  printf("indrew:%d\n", read_globals(15));
  return 0;
}
"""


def real_global_count(ir_text: str) -> int:
    for match in ARRAY_RE.finditer(ir_text):
        name = match.group("name")
        if MARKER not in name or "_objects" not in name or "_objects_share" in name:
            continue
        return match.group("body").count("ptrtoint")
    return 0


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-indrew-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "indrew.c"
        src.write_text(SOURCE, encoding="utf-8")

        plain_ir = tmp / "plain.ll"
        if not must(run([str(CLANG), str(src), "-O2", "-fno-discard-value-names",
                         "-S", "-emit-llvm", "-o", str(plain_ir)]),
                    "plain emit-llvm"):
            return 1
        plain_text = plain_ir.read_text(encoding="utf-8", errors="ignore")
        if MARKER in plain_text:
            print("FAIL: plain IR already carries page-table markers; "
                  "marker is not indgv-specific", file=sys.stderr)
            return 1

        obf_ir = tmp / "indgv.ll"
        if not must(run([str(CLANG), str(src), "-O2", "-fno-discard-value-names",
                         *mllvm(["-taokari", "-taokari-indgv",
                                 "-taokari-level-indgv=3"]),
                         "-S", "-emit-llvm", "-o", str(obf_ir)]),
                    "indgv emit-llvm"):
            return 1
        obf_text = obf_ir.read_text(encoding="utf-8", errors="ignore")
        rewrites = real_global_count(obf_text)
        if rewrites < MIN_REWRITES:
            print(f"FAIL: indgv rewrote only {rewrites} globals into the page "
                  f"table (need >= {MIN_REWRITES}); pass is a silent no-op on "
                  f"real data", file=sys.stderr)
            return 1

        plain_exe = tmp / "plain.exe"
        if not must(run([str(CLANG), str(src), "-O2", "-o", str(plain_exe)]),
                    "plain build"):
            return 1
        plain_run = run([str(plain_exe)])
        if plain_run.returncode:
            sys.stderr.write("plain run failed\n")
            return 1

        obf_exe = tmp / "indgv.exe"
        if not must(run([str(CLANG), str(src), "-O2",
                         *mllvm(["-taokari", "-taokari-indgv",
                                 "-taokari-level-indgv=3"]),
                         "-o", str(obf_exe)]), "indgv build"):
            return 1
        obf_run = run([str(obf_exe)])
        if obf_run.returncode or obf_run.stdout != plain_run.stdout:
            print(f"FAIL: indgv runtime mismatch rc={obf_run.returncode} "
                  f"out={obf_run.stdout!r} expected={plain_run.stdout!r}",
                  file=sys.stderr)
            return 1

    print(f"indirect-rewrite-count-bar: ok ({rewrites} globals rewritten into "
          f"_IndirectGVs page table >= {MIN_REWRITES}, runtime matches native)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
