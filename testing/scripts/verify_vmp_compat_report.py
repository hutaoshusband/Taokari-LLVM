"""Verify the VMP per-function compatibility report."""
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

#ifndef VMP_ATTR
#define VMP_ATTR __attribute__((noinline))
#endif

__attribute__((noinline)) double native_noise(double x) {
  return (x * 1.5) + 2.0;
}

VMP_ATTR int full_case(int x, int y) {
  int v = (x + y) ^ 0x55;
  return (v * 3) - x;
}

VMP_ATTR int split_case(int x, int y) {
  double d = native_noise((double)(x + y));
  int seed = (int)d;
  if ((seed ^ x) & 1) {
    int mixed = (seed + y) ^ (x * 3);
    seed = mixed - 7;
  }
  return seed + y;
}

VMP_ATTR int skip_float_only(int x) {
  double d = native_noise((double)x);
  return (int)d;
}

int main(void) {
  printf("vmp-report:%d:%d:%d\n",
         full_case(7, 11), split_case(13, 5), skip_float_only(9));
  return 0;
}
'''

BASE_FLAGS = ["-O0", "-Xclang", "-disable-O0-optnone"]
VMP_ATTR = r'-DVMP_ATTR=__attribute__((noinline,annotate("+vmp")))'


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
                cwd=ROOT,
                text=True,
                capture_output=True,
            )
        finally:
            batch.unlink(missing_ok=True)
    return subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True)


def must(result: subprocess.CompletedProcess[str]) -> bool:
    if result.returncode:
        sys.stderr.write(result.stdout + result.stderr)
        return False
    return True


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-vmp-report-") as tmp:
        tmpdir = Path(tmp)
        src = tmpdir / "report_vmp.c"
        report = tmpdir / "vmp-report.tsv"
        native = tmpdir / "native.exe"
        vmp = tmpdir / "vmp.exe"
        src.write_text(SOURCE, encoding="utf-8")

        if not must(run([str(CLANG), str(src), *BASE_FLAGS, "-o", str(native)],
                        use_vs_env=True)):
            return 1
        vmp_flags = [
            str(CLANG), str(src), VMP_ATTR, *BASE_FLAGS,
            "-mllvm", "-taokari", "-mllvm", "-taokari-vmp",
            "-mllvm", f"-taokari-vmp-compat-report={report}",
        ]
        if not must(run([*vmp_flags, "-o", str(vmp)], use_vs_env=True)):
            return 1
        if not report.exists():
            print("vmp compat report: FAIL (report missing)", file=sys.stderr)
            return 1

        rows = list(csv.DictReader(report.read_text(encoding="utf-8").splitlines(),
                                   delimiter="\t"))
        by_name = {row["function"]: row for row in rows}
        expected = {
            "full_case": "virtualized",
            "split_case": "partially_virtualized",
            "skip_float_only": "skipped",
        }
        for name, status in expected.items():
            if by_name.get(name, {}).get("status") != status:
                print(f"vmp compat report: FAIL ({name} status missing)",
                      file=sys.stderr)
                return 1
        if by_name["skip_float_only"]["reason"] != "unsupported IR":
            print("vmp compat report: FAIL (skip reason not exact)",
                  file=sys.stderr)
            return 1
        if not any(row["status"] == "virtualized" and "vmp.split" in row["function"]
                   for row in rows):
            print("vmp compat report: FAIL (split helper not reported)",
                  file=sys.stderr)
            return 1

        native_run = run([str(native)])
        vmp_run = run([str(vmp)])
        if native_run.returncode or vmp_run.returncode:
            sys.stderr.write(native_run.stdout + native_run.stderr)
            sys.stderr.write(vmp_run.stdout + vmp_run.stderr)
            return 1
        if native_run.stdout != vmp_run.stdout:
            print("vmp compat report: FAIL (stdout mismatch)", file=sys.stderr)
            print(f"native={native_run.stdout!r}", file=sys.stderr)
            print(f"vmp   ={vmp_run.stdout!r}", file=sys.stderr)
            return 1

    print("vmp compat report: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
