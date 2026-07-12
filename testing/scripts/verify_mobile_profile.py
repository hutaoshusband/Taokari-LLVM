"""Mobile profile verifier (todo.md E1).

The mobile profile is a size-first variant: only the cheap, high-value
passes (meta hygiene, level-1 string encryption, level-1 integer constant
encryption) run, with high thresholds so little data is rewritten. This
verifier makes that contract falsifiable.

Contract:
  * A build with the mobile profile runs and matches native output.
  * The mobile binary is strictly smaller than the balanced-profile binary
    of the same source (mobile drops fla/bcf/mba/indirect/outline and uses
    higher thresholds), so the profile is genuinely size-first.
  * The config wizard emits the mobile profile.

Exit: 0 ok | 1 contract failure | 2 missing clang.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
CONFIGS = ROOT / "testing" / "configs"
WIZARD = ROOT / "scripts" / "taokari-config-wizard.py"
MOBILE_CFG = CONFIGS / "profile-mobile.json"
BALANCED_CFG = CONFIGS / "profile-balanced.json"
VSDEVCMD = tp.VSDEVCMD


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

static const char *banner = "taokari-mobile-profile-check";
static const int table[8] = {1, 2, 3, 5, 8, 13, 21, 34};

int main(void) {
  int h = 0;
  for (const char *p = banner; *p; ++p)
    h = h * 131 + *p;
  for (int i = 0; i < 8; ++i)
    h += table[i];
  printf("mobile:%d\n", h);
  return 0;
}
"""


def build(cfg: Path, src: Path, out: Path) -> bool:
    return must(run([str(CLANG), str(src), "-O2",
                     *mllvm(["-taokari", f"-taokari-cfg={cfg}"]),
                     "-o", str(out)]), f"build with {cfg.name}")


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    wizard = run([sys.executable, str(WIZARD), "--non-interactive",
                  "--platform", "windows-x64", "--goal", "mobile",
                  "--perf", "tight", "--vmp", "off", "--out", "-"])
    if wizard.returncode:
        print("FAIL: wizard exited non-zero", file=sys.stderr)
        return 1
    match = re.search(r"=== config\.json ===\n(\{.*?\n\})\n",
                      wizard.stdout, re.DOTALL)
    if not match:
        print("FAIL: wizard output had no config.json block", file=sys.stderr)
        return 1
    wizard_cfg = json.loads(match.group(1))
    if wizard_cfg.get("cie", {}).get("minConstSize") != 64 or \
            wizard_cfg.get("fla", {}).get("enable") or \
            wizard_cfg.get("bcf", {}).get("enable"):
        print("FAIL: wizard did not emit the size-first mobile shape",
              file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory(prefix="taokari-mobile-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "mobile.c"
        src.write_text(SOURCE, encoding="utf-8")

        plain = tmp / "plain.exe"
        if not must(run([str(CLANG), str(src), "-O2", "-o", str(plain)]),
                    "plain build"):
            return 1
        plain_run = run([str(plain)])
        if plain_run.returncode:
            sys.stderr.write("plain run failed\n")
            return 1

        mobile = tmp / "mobile.exe"
        balanced = tmp / "balanced.exe"
        if not build(MOBILE_CFG, src, mobile) or not build(BALANCED_CFG, src, balanced):
            return 1

        mobile_run = run([str(mobile)])
        if mobile_run.returncode or mobile_run.stdout != plain_run.stdout:
            print(f"FAIL: mobile profile runtime mismatch rc={mobile_run.returncode} "
                  f"out={mobile_run.stdout!r} expected={plain_run.stdout!r}",
                  file=sys.stderr)
            return 1

        mobile_size = mobile.stat().st_size
        balanced_size = balanced.stat().st_size
        if mobile_size >= balanced_size:
            print(f"FAIL: mobile binary ({mobile_size} B) is not smaller than "
                  f"balanced ({balanced_size} B); profile is not size-first",
                  file=sys.stderr)
            return 1

    print(f"mobile-profile: ok (mobile {mobile_size} B < balanced {balanced_size} B, "
          f"runtime matches native, wizard emits profile)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
