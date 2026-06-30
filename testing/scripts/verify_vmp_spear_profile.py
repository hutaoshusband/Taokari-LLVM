"""vmp-spear profile verifier (todo.md E1).

The vmp-spear profile is annotation-only virtualization: VM machinery is
armed (level 3) but `vmp.enable=false`, so ONLY functions carrying a `+vmp`
annotation are virtualized. Everything else compiles natively. This is the
"surgical strike" profile for protecting a few hot secrets without paying
VMP cost across the whole binary.

Contract:
  * A source with one `+vmp`-annotated function and one plain function.
  * Under the spear profile, the annotated function's VMP interpreter is
    emitted and the plain function's is NOT (annotation-only).
  * The binary runs and matches native output.

Exit: 0 ok | 1 contract failure | 2 missing clang.
"""
from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
SPEAR_CFG = ROOT / "testing" / "configs" / "profile-vmp-spear.json"
VSDEVCMD = tp.VSDEVCMD

VMP_TARGET = "spear_victim"
PLAIN_FN = "spear_plain"


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


SOURCE = f"""
#include <stdio.h>

__attribute__((noinline, annotate("+vmp")))
int {VMP_TARGET}(int x) {{
  int r = x;
  for (int i = 0; i < x; ++i)
    r = (r * 31) ^ (i + 7);
  return r;
}}

__attribute__((noinline))
int {PLAIN_FN}(int x) {{
  int r = x;
  for (int i = 0; i < x; ++i)
    r = (r * 17) ^ (i + 3);
  return r;
}}

int main(void) {{
  printf("spear:%d:%d\\n", {VMP_TARGET}(6), {PLAIN_FN}(6));
  return 0;
}}
"""


def has_vmp_interp(text: str, fn: str) -> bool:
    return bool(re.search(rf"define[^{{]*@__taokari_vmp_interp_i64_[A-Za-z0-9_]*"
                          rf"{re.escape(fn)}[A-Za-z0-9_]*\(", text))


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-vmp-spear-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "spear.c"
        src.write_text(SOURCE, encoding="utf-8")

        plain_exe = tmp / "plain.exe"
        if not must(run([str(CLANG), str(src), "-O1", "-o", str(plain_exe)]),
                    "plain build"):
            return 1
        plain_run = run([str(plain_exe)])
        if plain_run.returncode:
            sys.stderr.write("plain run failed\n")
            return 1

        flags = ["-O1", "-fno-discard-value-names",
                 *mllvm(["-taokari", f"-taokari-cfg={SPEAR_CFG}"])]
        obf_ir = tmp / "spear.ll"
        if not must(run([str(CLANG), str(src), *flags,
                         "-S", "-emit-llvm", "-o", str(obf_ir)]),
                    "spear emit-llvm"):
            return 1
        ir_text = obf_ir.read_text(encoding="utf-8", errors="ignore")

        if not has_vmp_interp(ir_text, VMP_TARGET):
            print(f"FAIL: +vmp annotated function '{VMP_TARGET}' was not "
                  f"virtualized under the spear profile", file=sys.stderr)
            return 1
        if has_vmp_interp(ir_text, PLAIN_FN):
            print(f"FAIL: plain function '{PLAIN_FN}' was virtualized; the "
                  f"spear profile is not annotation-only", file=sys.stderr)
            return 1

        obf_exe = tmp / "spear.exe"
        if not must(run([str(CLANG), str(src),
                         "-O1", *mllvm(["-taokari", f"-taokari-cfg={SPEAR_CFG}"]),
                         "-o", str(obf_exe)]), "spear build"):
            return 1
        obf_run = run([str(obf_exe)])
        if obf_run.returncode or obf_run.stdout != plain_run.stdout:
            print(f"FAIL: spear runtime mismatch rc={obf_run.returncode} "
                  f"out={obf_run.stdout!r} expected={plain_run.stdout!r}",
                  file=sys.stderr)
            return 1

    print(f"vmp-spear-profile: ok (+vmp '{VMP_TARGET}' virtualized, plain "
          f"'{PLAIN_FN}' left native, runtime matches native)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
