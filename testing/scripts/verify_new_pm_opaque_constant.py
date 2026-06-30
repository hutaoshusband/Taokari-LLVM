"""New-PM OpaqueConstant port verifier (todo.md 1.5).

Native new-PM port of the first FunctionPass. OpaqueConstant now has a
PassInfoMixin twin (OpaqueConstantNewPMPass) schedulable standalone via
`opt -passes=opaque-constant-newpm`, proving the function-pass conversion
pattern from docs/NEW_PM_MIGRATION.md (B2) without touching the bridge.

Contract:
  * `-passes=opaque-constant-newpm` is accepted by opt.
  * With ocnst disabled the pass is a no-op: a plain constant survives.
  * With ocnst enabled (prob=100) the pass rewrites the constant, emitting
    the ocnst.val/ocnst.nonce markers exactly like the legacy path.
  * A binary built through the default (legacy bridge) pipeline still runs
    and matches native output.

Exit: 0 ok | 1 contract failure | 2 missing clang/opt.
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
BIN = tp.BIN
CLANG = tp.CLANG
OPT = tp.tool("opt")
VSDEVCMD = tp.VSDEVCMD

PLAIN_CONST = 0x22334455


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
#include <stdint.h>

__attribute__((noinline)) int32_t magic(int x) {{
  int32_t secret = {PLAIN_CONST};
  return (x ^ secret) + secret;
}}

int main(void) {{
  printf("ocnst-newpm:%d\\n", magic(7));
  return 0;
}}
"""


def main() -> int:
    if not CLANG.exists() or not OPT.exists():
        print("missing clang/opt", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-ocnst-newpm-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "ocnst.c"
        src.write_text(SOURCE, encoding="utf-8")

        base_ir = tmp / "base.ll"
        if not must(run([str(CLANG), str(src), "-O0", "-fno-discard-value-names",
                         "-S", "-emit-llvm", "-o", str(base_ir)]),
                    "base emit-llvm"):
            return 1

        disabled = tmp / "disabled.ll"
        if not must(run([str(OPT), "-passes=opaque-constant-newpm", "-S",
                         str(base_ir), "-o", str(disabled)]),
                    "newpm pass (disabled)"):
            return 1
        disabled_text = disabled.read_text(encoding="utf-8", errors="ignore")
        if "ocnst.val" in disabled_text:
            print("FAIL: new-PM pass rewrote constants while ocnst disabled "
                  "(should be a no-op)", file=sys.stderr)
            return 1

        enabled = tmp / "enabled.ll"
        if not must(run([str(OPT), "-taokari", "-taokari-ocnst",
                         "-taokari-ocnst-prob=100",
                         "-passes=opaque-constant-newpm", "-S",
                         str(base_ir), "-o", str(enabled)]),
                    "newpm pass (enabled)"):
            return 1
        enabled_text = enabled.read_text(encoding="utf-8", errors="ignore")
        if "ocnst.val" not in enabled_text or "ocnst.nonce" not in enabled_text:
            print("FAIL: new-PM pass did not emit ocnst.val/ocnst.nonce markers "
                  "with ocnst enabled", file=sys.stderr)
            return 1

        legacy = tmp / "legacy.ll"
        if not must(run([str(CLANG), str(src), "-O0", "-fno-discard-value-names",
                         *mllvm(["-taokari", "-taokari-ocnst",
                                 "-taokari-ocnst-prob=100"]),
                         "-S", "-emit-llvm", "-o", str(legacy)]),
                    "legacy emit-llvm"):
            return 1
        legacy_text = legacy.read_text(encoding="utf-8", errors="ignore")
        if "ocnst.val" not in legacy_text or "ocnst.nonce" not in legacy_text:
            print("FAIL: legacy path did not emit ocnst markers; baseline invalid",
                  file=sys.stderr)
            return 1

        plain_exe = tmp / "plain.exe"
        if not must(run([str(CLANG), str(src), "-O2", "-o", str(plain_exe)]),
                    "plain build"):
            return 1
        plain_run = run([str(plain_exe)])
        if plain_run.returncode:
            sys.stderr.write("plain run failed\n")
            return 1

        obf_exe = tmp / "obf.exe"
        if not must(run([str(CLANG), str(src), "-O2",
                         *mllvm(["-taokari", "-taokari-ocnst",
                                 "-taokari-ocnst-prob=100"]),
                         "-o", str(obf_exe)]), "obfuscated build"):
            return 1
        obf_run = run([str(obf_exe)])
        if obf_run.returncode or obf_run.stdout != plain_run.stdout:
            print(f"FAIL: runtime mismatch rc={obf_run.returncode} "
                  f"out={obf_run.stdout!r} expected={plain_run.stdout!r}",
                  file=sys.stderr)
            return 1

    print("new-pm opaque-constant: ok (pass schedulable, no-op when disabled, "
          "emits ocnst markers like legacy when enabled, binary matches native)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
