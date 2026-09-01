"""Verify the per-function VMP overhead budget annotation.

`vmp-budget=N` on a +vmp function overrides the global
-taokari-vmp-max-bytecode-words cap for that one function, so an explicitly
tuned function can raise or lower its own VM bytecode-size ceiling without
touching the global safety cap.

Contract (same victim built three ways):
  * global cap default (2048), no annotation budget: virtualized.
  * vmp-budget=4 (tight): the victim's bytecode exceeds 4 words, so it is
    skipped with reason "bytecode size budget exceeded".
  * vmp-budget=8192 (raised): the victim fits, virtualized again.

This proves the per-function override takes precedence over the global cap
in both directions (lower -> skip, raise -> allow).

Exit: 0 ok | 1 contract failure | 2 missing clang.
"""
from __future__ import annotations

import csv
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
VSDEVCMD = tp.VSDEVCMD

SOURCE = r'''
#include <stdio.h>

VICTIM_ATTR int victim(int a, int b) {
  int x = (a + b + 3) ^ 0x1357;
  x = (x * 5) - (a & 15);
  x = x + (b << 2);
  x = x ^ (a * 3);
  return x - b;
}

int main(void) {
  printf("budget:%d\n", victim(9, 4));
  return 0;
}
'''

BASE_FLAGS = ["-O0", "-Xclang", "-disable-O0-optnone"]


def run(cmd: list[str], use_vs_env: bool = False) -> subprocess.CompletedProcess[str]:
    if use_vs_env and VSDEVCMD.exists():
        with tempfile.NamedTemporaryFile(
            "w", suffix=".cmd", delete=False, encoding="utf-8"
        ) as handle:
            batch = Path(handle.name)
            handle.write(
                "@echo off\n"
                f'call "{VSDEVCMD}" -arch=x64 -host_arch=x64 >nul\n'
                f"{subprocess.list2cmdline(cmd)}\n"
                "exit /b %ERRORLEVEL%\n"
            )
        try:
            return subprocess.run(
                ["cmd.exe", "/d", "/c", str(batch)],
                cwd=ROOT, text=True, capture_output=True,
            )
        finally:
            batch.unlink(missing_ok=True)
    return subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True)


def must(result: subprocess.CompletedProcess[str], label: str) -> bool:
    if result.returncode:
        sys.stderr.write(f"{label} failed:\n")
        sys.stderr.write(result.stdout + result.stderr)
        return False
    return True


def victim_attr(budget: str | None) -> str:
    if budget is None:
        annotate = '+vmp"'
    else:
        annotate = f'+vmp vmp-budget={budget}"'
    return f'-DVICTIM_ATTR=__attribute__((noinline,annotate("{annotate})))'


def build_vmp(src: Path, exe: Path, report: Path, budget: str | None,
              label: str) -> dict[str, str] | None:
    flags = [
        str(CLANG), str(src), victim_attr(budget), *BASE_FLAGS,
        "-mllvm", "-taokari", "-mllvm", "-taokari-vmp",
        "-mllvm", f"-taokari-vmp-compat-report={report}",
        "-o", str(exe),
    ]
    if not must(run(flags, use_vs_env=True), f"build {label}"):
        return None
    if not report.exists():
        sys.stderr.write(f"{label}: compat report missing\n")
        return None
    rows = list(csv.DictReader(report.read_text(encoding="utf-8").splitlines(),
                               delimiter="\t"))
    for row in rows:
        if row["function"] == "victim":
            return row
    sys.stderr.write(f"{label}: victim not in compat report\n")
    return None


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-vmp-budget-") as tmp:
        tmpdir = Path(tmp)
        src = tmpdir / "budget_vmp.c"
        src.write_text(SOURCE, encoding="utf-8")

        native_attr = '-DVICTIM_ATTR=__attribute__((noinline))'
        native_flags = [str(CLANG), str(src), native_attr, *BASE_FLAGS,
                        "-o", str(tmpdir / "native.exe")]
        if not must(run(native_flags, use_vs_env=True), "build native"):
            return 1
        native_run = run([str(tmpdir / "native.exe")])
        if native_run.returncode:
            sys.stderr.write("native run failed\n")
            return 1
        expected_out = native_run.stdout

        default_row = build_vmp(src, tmpdir / "default.exe",
                                tmpdir / "default.tsv", None, "default")
        tight_row = build_vmp(src, tmpdir / "tight.exe",
                              tmpdir / "tight.tsv", "4", "tight")
        raised_row = build_vmp(src, tmpdir / "raised.exe",
                               tmpdir / "raised.tsv", "8192", "raised")
        if default_row is None or tight_row is None or raised_row is None:
            return 1

        if default_row["status"] != "virtualized":
            print(f"FAIL: default cap should virtualize, got "
                  f"{default_row['status']} ({default_row['reason']})",
                  file=sys.stderr)
            return 1
        if tight_row["status"] != "skipped" or \
                tight_row["reason"] != "bytecode size budget exceeded":
            print(f"FAIL: vmp-budget=4 should skip on size, got "
                  f"{tight_row['status']} ({tight_row['reason']})",
                  file=sys.stderr)
            return 1
        if raised_row["status"] != "virtualized":
            print(f"FAIL: vmp-budget=8192 should virtualize, got "
                  f"{raised_row['status']} ({raised_row['reason']})",
                  file=sys.stderr)
            return 1

        default_words = int(default_row.get("words", "0") or 0)
        if not (4 < default_words <= 8192):
            print(f"FAIL: victim bytecode words={default_words} outside the "
                  f"4 < words <= 8192 range this verifier assumes",
                  file=sys.stderr)
            return 1

        for name in ("default.exe", "raised.exe"):
            r = run([str(tmpdir / name)])
            if r.returncode or r.stdout != expected_out:
                print(f"FAIL: {name} runtime mismatch: rc={r.returncode} "
                      f"out={r.stdout!r} expected={expected_out!r}",
                      file=sys.stderr)
                return 1

    print(f"verify_vmp_per_function_budget: ok "
          f"(victim {default_words} words; default=virtualized, "
          f"budget=4=skipped, budget=8192=virtualized)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
