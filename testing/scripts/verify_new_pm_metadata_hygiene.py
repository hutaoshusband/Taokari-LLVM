"""New-PM MetadataHygiene port verifier (todo.md 1.5).

Native new-PM port of the first module pass. MetadataHygiene now has a
PassInfoMixin twin (MetadataHygieneNewPMPass) schedulable standalone via
`opt -passes=metadata-hygiene-newpm`, exercising the per-pass conversion
pattern documented in docs/NEW_PM_MIGRATION.md without touching the legacy
bridge recipe.

Contract:
  * `-passes=metadata-hygiene-newpm` is accepted by opt (name registered).
  * With meta disabled the pass is a no-op: a secret internal symbol
    survives untouched.
  * With meta enabled (level 2) the pass renames the secret internal symbol
    exactly like the legacy path (--taokari --taokari-meta), proving the twin
    runs the same body via the shared ObfuscationOptions resolution.
  * A binary built through the default (legacy bridge) pipeline still runs
    and matches native output.

Exit: 0 ok | 1 contract failure | 2 missing clang/opt.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
BIN = tp.BIN
CLANG = tp.CLANG
OPT = tp.tool("opt")
VSDEVCMD = tp.VSDEVCMD

SECRET = "taokari_newpm_secret_helper"


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

static __attribute__((noinline)) int {SECRET}(int x) {{
  return x * 131 + 7;
}}

int main(void) {{
  printf("newpm-mh:%d\\n", {SECRET}(5));
  return 0;
}}
"""


def has_secret(ir_text: str) -> bool:
    return SECRET in ir_text


def main() -> int:
    if not CLANG.exists() or not OPT.exists():
        print("missing clang/opt", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-newpm-mh-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "mh.c"
        src.write_text(SOURCE, encoding="utf-8")

        base_ir = tmp / "base.ll"
        if not must(run([str(CLANG), str(src), "-O0", "-fno-discard-value-names",
                         "-S", "-emit-llvm", "-o", str(base_ir)]),
                    "base emit-llvm"):
            return 1
        base_text = base_ir.read_text(encoding="utf-8", errors="ignore")
        if not has_secret(base_text):
            print("FAIL: base IR does not carry the secret symbol; fixture is "
                  "wrong", file=sys.stderr)
            return 1

        cfg = tmp / "meta2.json"
        cfg.write_text(json.dumps({
            "randomSeed": "newpm-metadata-hygiene-seed",
            "meta": {"enable": True, "level": 2, "releaseStrip": True},
        }), encoding="utf-8")

        disabled = tmp / "disabled.ll"
        if not must(run([str(OPT), "-passes=metadata-hygiene-newpm", "-S",
                         str(base_ir), "-o", str(disabled)]),
                    "newpm pass (disabled)"):
            return 1
        if not has_secret(disabled.read_text(encoding="utf-8", errors="ignore")):
            print("FAIL: new-PM pass renamed the symbol while meta was disabled "
                  "(should be a no-op)", file=sys.stderr)
            return 1

        enabled = tmp / "enabled.ll"
        if not must(run([str(OPT), "-taokari", "-taokari-meta",
                         f"-taokari-cfg={cfg}",
                         "-passes=metadata-hygiene-newpm", "-S",
                         str(base_ir), "-o", str(enabled)]),
                    "newpm pass (enabled)"):
            return 1
        if has_secret(enabled.read_text(encoding="utf-8", errors="ignore")):
            print("FAIL: new-PM pass left the secret symbol un-renamed with "
                  "meta enabled", file=sys.stderr)
            return 1

        legacy = tmp / "legacy.ll"
        if not must(run([str(CLANG), str(src), "-O0", "-fno-discard-value-names",
                         *mllvm(["-taokari", "-taokari-meta",
                                 f"-taokari-cfg={cfg}"]),
                         "-S", "-emit-llvm", "-o", str(legacy)]),
                    "legacy emit-llvm"):
            return 1
        if has_secret(legacy.read_text(encoding="utf-8", errors="ignore")):
            print("FAIL: legacy path left the secret symbol un-renamed",
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
                         *mllvm(["-taokari", "-taokari-meta",
                                 f"-taokari-cfg={cfg}"]),
                         "-o", str(obf_exe)]), "obfuscated build"):
            return 1
        obf_run = run([str(obf_exe)])
        if obf_run.returncode or obf_run.stdout != plain_run.stdout:
            print(f"FAIL: runtime mismatch rc={obf_run.returncode} "
                  f"out={obf_run.stdout!r} expected={plain_run.stdout!r}",
                  file=sys.stderr)
            return 1

    print("new-pm metadata-hygiene: ok (pass schedulable, no-op when "
          "disabled, renames secret symbol like legacy when enabled, "
          "binary matches native)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
