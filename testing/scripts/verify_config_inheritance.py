"""Config inheritance verifier (todo.md E1).

A Taokari config may now specify "extends": "<path>" to inherit another
config's settings, with the child's keys deep-merged on top (child wins,
nested pass objects merged). This verifier confirms the loader resolves
extends, the child overrides parent keys, and unmodified parent keys are
inherited.

Contract:
  * A child config extends profile-strong (full strong protection) and
    overrides fla level to 1. The loaded config must show fla enabled +
    level 1, and an inherited pass (e.g. mba) at the parent's level.
  * A cycle (child extends itself) is rejected.
  * A binary built with the child config runs and matches native.

Exit: 0 ok | 1 contract failure | 2 missing clang.
"""
from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CLANG = ROOT / "build" / "taokari-local" / "bin" / "clang.exe"
STRONG_CFG = ROOT / "testing" / "configs" / "profile-strong.json"
VSDEVCMD = Path(
    r"C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat"
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
__attribute__((noinline)) int probe(int x) {
  int s = x;
  for (int i = 0; i < x; ++i) s = (s * 13) ^ i;
  return s;
}
int main(void) { printf("inherit:%d\n", probe(7)); return 0; }
"""


def report_levels(cfg: Path) -> dict[str, int]:
    with tempfile.TemporaryDirectory(prefix="taokari-inh-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "x.c"
        src.write_text(SOURCE, encoding="utf-8")
        r = run([str(CLANG), str(src), "-O2", "-fno-discard-value-names",
                 *mllvm(["-taokari", f"-taokari-cfg={cfg}", "-taokari-report"]),
                 "-S", "-emit-llvm", "-o", str(tmp / "x.ll")])
    levels: dict[str, int] = {}
    for m in re.finditer(r"taokari-report: (\w+) enable=\w+ level=(\d+)",
                         r.stderr):
        levels[m.group(1)] = int(m.group(2))
    return levels


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    child = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    try:
        child.write('{"extends": "' + STRONG_CFG.as_posix() +
                    '", "fla": {"enable": true, "level": 1}}\n')
        child.close()
        child_path = Path(child.name)

        levels = report_levels(child_path)
        if levels.get("fla") != 1:
            print(f"FAIL: child override did not apply (fla level={levels.get('fla')}, "
                  f"want 1). Report levels: {levels}", file=sys.stderr)
            return 1
        if levels.get("mba") != 3:
            print(f"FAIL: parent mba level not inherited (mba={levels.get('mba')}, "
                  f"want 3). Report levels: {levels}", file=sys.stderr)
            return 1

        cyclic = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        cyc_path = Path(cyclic.name)
        cyclic.write('{"extends": "' + cyc_path.as_posix() + '"}\n')
        cyclic.close()
        with tempfile.TemporaryDirectory(prefix="taokari-inh-") as tmp_name:
            tmp = Path(tmp_name)
            src = tmp / "x.c"
            src.write_text(SOURCE, encoding="utf-8")
            cyc_run = run([str(CLANG), str(src), "-O2",
                           *mllvm(["-taokari", f"-taokari-cfg={cyc_path}"]),
                           "-o", str(tmp / "x.exe")])
        cyc_path.unlink(missing_ok=True)
        if cyc_run.returncode == 0:
            print("FAIL: cyclic extends was accepted (should be rejected)",
                  file=sys.stderr)
            return 1

        with tempfile.TemporaryDirectory(prefix="taokari-inh-") as tmp_name:
            tmp = Path(tmp_name)
            src = tmp / "x.c"
            src.write_text(SOURCE, encoding="utf-8")
            plain = run([str(CLANG), str(src), "-O2", "-o", str(tmp / "p.exe")])
            if not must(plain, "plain build"):
                return 1
            plain_run = run([str(tmp / "p.exe")])
            obf = run([str(CLANG), str(src), "-O2",
                       *mllvm(["-taokari", f"-taokari-cfg={child_path}"]),
                       "-o", str(tmp / "o.exe")])
            if not must(obf, "obfuscated build (inherited config)"):
                return 1
            obf_run = run([str(tmp / "o.exe")])
            if obf_run.returncode or obf_run.stdout != plain_run.stdout:
                print(f"FAIL: runtime mismatch {obf_run.stdout!r} != "
                      f"{plain_run.stdout!r}", file=sys.stderr)
                return 1
    finally:
        child_path.unlink(missing_ok=True)

    print(f"config-inheritance: ok (child overrode fla->1, inherited mba->3, "
          f"cycle rejected, binary matches native)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
