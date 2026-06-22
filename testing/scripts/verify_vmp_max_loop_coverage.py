"""Verify Max+VMP keeps common O2 loops virtualizable."""
from __future__ import annotations

import csv
import re
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CLANG = ROOT / "build" / "taokari-local" / "bin" / "clang.exe"
VSDEVCMD = Path(
    r"C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat"
)
HIST_RE = re.compile(
    r"padding histogram \((\d+) opcodes, (\d+) top hits, "
    r"(\d+) bp, (\d+) pad hits\)"
)

SOURCE = r"""
#include <stdio.h>
#include <string.h>

#define VMP __attribute__((noinline, annotate("+vmp")))
#define NO_VMP __attribute__((annotate("-vmp")))

VMP unsigned long vm_counter(unsigned long n) {
  unsigned long acc = 0;
  for (unsigned long i = 0; i < n; ++i)
    acc = (acc * 31) + i;
  return acc;
}

VMP void vm_obfuscate_string(char *buf, int len) {
  for (int i = 0; i < len; ++i)
    buf[i] = (char)((buf[i] ^ 0x5A) + i);
}

NO_VMP int main(void) {
  char tag[] = "Taokari";
  vm_obfuscate_string(tag, (int)strlen(tag));
  unsigned long count = vm_counter(100);
  for (unsigned i = 0; i < sizeof(tag) - 1; ++i)
    printf("%02X", (unsigned char)tag[i]);
  printf(":%lu\n", count);
  return 0;
}
"""


def run(cmd: list[str], *, use_vs_env: bool = False) -> subprocess.CompletedProcess[str]:
    if use_vs_env and VSDEVCMD.exists():
        with tempfile.NamedTemporaryFile("w", suffix=".cmd", delete=False,
                                         encoding="utf-8") as handle:
            batch = Path(handle.name)
            handle.write("@echo off\n")
            handle.write(f'call "{VSDEVCMD}" -arch=x64 -host_arch=x64 >nul\n')
            handle.write(subprocess.list2cmdline(cmd) + "\n")
            handle.write("exit /b %ERRORLEVEL%\n")
        try:
            return subprocess.run(["cmd.exe", "/d", "/c", str(batch)],
                                  cwd=ROOT, text=True, capture_output=True)
        finally:
            batch.unlink(missing_ok=True)
    return subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True)


def compile_exe(src: Path, out: Path, *, report: Path | None) -> subprocess.CompletedProcess[str]:
    cmd = [str(CLANG), "-O2", str(src), "-o", str(out)]
    if report:
        cmd.extend([
            "-mllvm", "-taokari-max",
            "-mllvm", "-taokari-vmp",
            "-mllvm", f"-taokari-vmp-compat-report={report}",
            "-Rpass=taokari-vmp",
            "-Rpass-missed=taokari-vmp",
        ])
    return run(cmd, use_vs_env=True)


def attr_text(ir: str, function: str) -> str:
    match = re.search(rf"define .* @{re.escape(function)}(?:_[0-9]+)?\(.*\) #(\d+)", ir)
    if not match:
        return ""
    attrs = dict(re.findall(r"attributes #(\d+) = \{([^}]*)\}", ir))
    return attrs.get(match.group(1), "")


def padding_hits(remarks: str) -> int:
    return sum(int(pads) for _ops, _top, _bp, pads in HIST_RE.findall(remarks))


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-vmp-loop-") as tmp:
        tmpdir = Path(tmp)
        src = tmpdir / "loop_coverage.c"
        native = tmpdir / "native.exe"
        protected = tmpdir / "protected.exe"
        ll = tmpdir / "protected.ll"
        report = tmpdir / "compat.tsv"
        obj = tmpdir / "probe.obj"
        src.write_text(SOURCE, encoding="utf-8")

        probe = run([
            str(CLANG), "-###", "-O2", "-c", str(src), "-o", str(obj),
            "-mllvm", "-taokari-max", "-mllvm", "-taokari-vmp",
        ], use_vs_env=True)
        probe_text = probe.stdout + probe.stderr
        if probe.returncode or "-fno-unroll-loops" not in probe_text:
            print("vmp max loop coverage: FAIL (missing no-unroll cc1 arg)",
                  file=sys.stderr)
            return 1
        if "-taokari-vmp-padding=5" not in probe_text:
            print("vmp max loop coverage: FAIL (missing max padding cc1 arg)",
                  file=sys.stderr)
            return 1
        if "-vectorize-loops" in probe_text or "-vectorize-slp" in probe_text:
            print("vmp max loop coverage: FAIL (vectorizer still enabled)",
                  file=sys.stderr)
            return 1
        override = run([
            str(CLANG), "-###", "-O2", "-c", str(src), "-o", str(obj),
            "-mllvm", "-taokari-max", "-mllvm", "-taokari-vmp",
            "-mllvm", "-taokari-vmp-padding=0",
        ], use_vs_env=True)
        override_text = override.stdout + override.stderr
        if override.returncode or "-taokari-vmp-padding=5" in override_text:
            print("vmp max loop coverage: FAIL (padding override ignored)",
                  file=sys.stderr)
            return 1

        native_build = compile_exe(src, native, report=None)
        protected_build = compile_exe(src, protected, report=report)
        if native_build.returncode or protected_build.returncode:
            sys.stderr.write(native_build.stdout + native_build.stderr)
            sys.stderr.write(protected_build.stdout + protected_build.stderr)
            return 1
        if not padding_hits(protected_build.stdout + protected_build.stderr):
            print("vmp max loop coverage: FAIL (max emitted no pad opcodes)",
                  file=sys.stderr)
            return 1

        ir_build = run([
            str(CLANG), "-O2", "-S", "-emit-llvm", str(src), "-o", str(ll),
            "-mllvm", "-taokari-vmp",
        ], use_vs_env=True)
        if ir_build.returncode:
            sys.stderr.write(ir_build.stdout + ir_build.stderr)
            return 1
        ir = ll.read_text(encoding="utf-8", errors="ignore")
        for name in ("vm_counter", "vm_obfuscate_string"):
            interp = f"__taokari_vmp_interp_i64_{name}"
            if "noinline" not in attr_text(ir, name):
                print(f"vmp max loop coverage: FAIL ({name} not noinline)",
                      file=sys.stderr)
                return 1
            if "noinline" not in attr_text(ir, interp):
                print(f"vmp max loop coverage: FAIL ({interp} not noinline)",
                      file=sys.stderr)
                return 1

        rows = {row["function"]: row for row in csv.DictReader(
            report.read_text(encoding="utf-8").splitlines(), delimiter="\t"
        )}
        for name in ("vm_counter", "vm_obfuscate_string"):
            if rows.get(name, {}).get("status") != "virtualized":
                print(f"vmp max loop coverage: FAIL ({name} not virtualized)",
                      file=sys.stderr)
                return 1

        native_run = run([str(native)])
        protected_run = run([str(protected)])
        if native_run.returncode or protected_run.returncode:
            sys.stderr.write(native_run.stdout + native_run.stderr)
            sys.stderr.write(protected_run.stdout + protected_run.stderr)
            return 1
        if native_run.stdout != protected_run.stdout:
            print("vmp max loop coverage: FAIL (stdout mismatch)", file=sys.stderr)
            print(f"native={native_run.stdout!r}", file=sys.stderr)
            print(f"protected={protected_run.stdout!r}", file=sys.stderr)
            return 1

    print(f"vmp max loop coverage: ok ({native_run.stdout.strip()})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
