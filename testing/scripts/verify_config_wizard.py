"""Verify the taokari config wizard.

Runs scripts/taokari-config-wizard.py non-interactively across all four
profiles, asserts it emits all four deliverables (JSON config, Clang flags,
annotation guide, test command), and that the generated JSON config loads
cleanly into the obfuscator (no "unknown taokari config key" warning) for
at least the strong and fortress profiles.

Contract:
  * Wizard runs non-interactively for each profile.
  * All four output files exist and are non-empty.
  * The generated flags reference -taokari and at least one -taokari-<pass>.
  * The guide documents +vmp / +fla / noobf annotations.
  * For strong + fortress: loading the config via -taokari-cfg emits no
    "unknown taokari config key" warning (config is schema-valid).
  * A small program compiled with the generated config runs and matches
    native output.

Exit: 0 ok | 1 contract failure | 2 missing wizard / clang.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WIZARD = ROOT / "scripts" / "taokari-config-wizard.py"
CLANG = ROOT / "build" / "taokari-local" / "bin" / "clang.exe"
VSDEVCMD = Path(
    r"C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat"
)

SOURCE = r"""
#include <stdio.h>
__attribute__((noinline)) int probe(int x) { return (x * 7) ^ 0x55; }
int main(void) { printf("wizard:%d\n", probe(9)); return 0; }
"""


def run(cmd: list[str], *, cwd: Path = ROOT, use_vs: bool = False,
        timeout: int = 240) -> subprocess.CompletedProcess[str]:
    if use_vs and VSDEVCMD.exists():
        with tempfile.NamedTemporaryFile("w", suffix=".cmd", delete=False,
                                         encoding="utf-8") as handle:
            batch = Path(handle.name)
            handle.write("@echo off\n")
            handle.write(f'call "{VSDEVCMD}" -arch=x64 -host_arch=x64 >nul\n')
            handle.write(subprocess.list2cmdline(cmd) + "\n")
            handle.write("exit /b %ERRORLEVEL%\n")
        try:
            return subprocess.run(["cmd.exe", "/d", "/c", str(batch)],
                                  cwd=cwd, text=True, capture_output=True,
                                  timeout=timeout)
        finally:
            batch.unlink(missing_ok=True)
    return subprocess.run(cmd, cwd=cwd, text=True, capture_output=True,
                          timeout=timeout)


def main() -> int:
    if not WIZARD.exists():
        print(f"missing wizard: {WIZARD}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-wizard-") as tmp_name:
        tmp = Path(tmp_name)
        for goal in ("mobile", "dev", "balanced", "strong", "fortress"):
            stem = tmp / goal
            r = run([sys.executable, str(WIZARD),
                     "--non-interactive",
                     "--platform", "windows-x64",
                     "--goal", goal,
                     "--perf", "balanced",
                     "--vmp", "annotation-only" if goal == "fortress" else "off",
                     "--out", str(stem)])
            if r.returncode:
                sys.stderr.write(f"wizard {goal} failed:\n{r.stderr}")
                return 1

            cfg_path = stem.with_suffix(".json")
            flags_path = stem.with_suffix(".flags.txt")
            guide_path = stem.with_suffix(".guide.md")
            test_path = stem.with_suffix(".test.txt")
            for p in (cfg_path, flags_path, guide_path, test_path):
                if not p.exists() or p.stat().st_size == 0:
                    print(f"FAIL: {goal} missing/empty {p.name}", file=sys.stderr)
                    return 1

            cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
            if not isinstance(cfg, dict) or not cfg:
                print(f"FAIL: {goal} config not a non-empty object",
                      file=sys.stderr)
                return 1
            flags = flags_path.read_text(encoding="utf-8")
            if "-taokari" not in flags or "-taokari-" not in flags:
                print(f"FAIL: {goal} flags missing -taokari / -taokari-<pass>",
                      file=sys.stderr)
                return 1
            guide = guide_path.read_text(encoding="utf-8")
            for token in ("+vmp", "+fla", "noobf"):
                if token not in guide:
                    print(f"FAIL: {goal} guide missing {token}", file=sys.stderr)
                    return 1
            test_cmd = test_path.read_text(encoding="utf-8")
            if "-taokari-cfg" not in test_cmd or "clang" not in test_cmd:
                print(f"FAIL: {goal} test command malformed", file=sys.stderr)
                return 1

        if CLANG.exists():
            src = tmp / "wiz.c"
            src.write_text(SOURCE, encoding="utf-8")
            native = run([str(CLANG), str(src), "-O2", "-o", str(tmp / "native.exe")],
                         use_vs=True)
            if native.returncode:
                sys.stderr.write("native build failed\n")
                return 1
            native_run = run([str(tmp / "native.exe")])

            for goal in ("strong", "fortress"):
                cfg_path = (tmp / goal).with_suffix(".json")
                exe = tmp / f"{goal}.exe"
                build = run([str(CLANG), str(src), "-O2",
                             "-mllvm", "-taokari",
                             "-mllvm", f"-taokari-cfg={cfg_path}",
                             "-o", str(exe)], use_vs=True)
                if build.returncode:
                    sys.stderr.write(f"{goal} build failed:\n{build.stderr}")
                    return 1
                combined = build.stdout + build.stderr
                if "unknown taokari config key" in combined:
                    print(f"FAIL: {goal} config emitted unknown-key warning:\n"
                          f"{combined}", file=sys.stderr)
                    return 1
                run_r = run([str(exe)])
                if run_r.returncode or run_r.stdout != native_run.stdout:
                    print(f"FAIL: {goal} runtime mismatch rc={run_r.returncode} "
                          f"out={run_r.stdout!r}", file=sys.stderr)
                    return 1

    print(f"config wizard: ok (5 profiles, 4 deliverables each, "
          f"strong+fortress configs load clean, runtime matches native)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
