"""debuggable-strong profile verifier (todo.md E1).

The debuggable-strong profile is the strong protection recipe with metadata
hygiene disabled, so the binary stays debuggable (debug info survives) while
fla/bcf/mba/indirect/outline still run. This is the internal-testing
counterpart to the release strong profile.

Contract:
  * A build with debuggable-strong (-g) runs and matches native output.
  * Debug info survives: a -g build under debuggable-strong keeps the IR
    DISubprogram records that the strong profile (meta enabled) strips.
  * Protection is active: the obfuscated IR carries flattening markers, so
    the profile is not a no-op.

Exit: 0 ok | 1 contract failure | 2 missing clang.
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CLANG = ROOT / "build" / "taokari-local" / "bin" / "clang.exe"
CONFIGS = ROOT / "testing" / "configs"
DBG_CFG = CONFIGS / "profile-debuggable-strong.json"
STRONG_CFG = CONFIGS / "profile-strong.json"
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

__attribute__((noinline)) int probe(int x) {
  int s = x;
  for (int i = 0; i < x; ++i)
    s = (s * 13) ^ i;
  return s;
}

int main(void) {
  printf("dbgstrong:%d\n", probe(7));
  return 0;
}
"""


def emit_ir(src: Path, cfg: Path, out: Path) -> str:
    if not must(run([str(CLANG), str(src), "-O1", "-g", "-fno-discard-value-names",
                     *mllvm(["-taokari", f"-taokari-cfg={cfg}"]),
                     "-S", "-emit-llvm", "-o", str(out)]),
                f"emit-llvm {cfg.name}"):
        sys.exit(1)
    return out.read_text(encoding="utf-8", errors="ignore")


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-dbgstrong-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "dbg.c"
        src.write_text(SOURCE, encoding="utf-8")

        plain = tmp / "plain.exe"
        if not must(run([str(CLANG), str(src), "-O2", "-g", "-o", str(plain)]),
                    "plain build"):
            return 1
        plain_run = run([str(plain)])
        if plain_run.returncode:
            sys.stderr.write("plain run failed\n")
            return 1

        dbg_text = emit_ir(src, DBG_CFG, tmp / "dbg.ll")
        if "switchFakeCaseGate" not in dbg_text:
            print("FAIL: debuggable-strong IR has no flattening markers; "
                  "profile is a no-op", file=sys.stderr)
            return 1
        dbg_subprograms = dbg_text.count("DISubprogram")
        if not dbg_subprograms:
            print("FAIL: debuggable-strong IR lost DISubprogram records",
                  file=sys.stderr)
            return 1

        strong_text = emit_ir(src, STRONG_CFG, tmp / "strong.ll")
        strong_subprograms = strong_text.count("DISubprogram")
        if strong_subprograms >= dbg_subprograms:
            print(f"FAIL: strong kept {strong_subprograms} DISubprogram records "
                  f"(>= debuggable-strong {dbg_subprograms}); meta strip is not "
                  f"working, baseline invalid", file=sys.stderr)
            return 1

        dbg_exe = tmp / "dbg.exe"
        if not must(run([str(CLANG), str(src), "-O1", "-g",
                         *mllvm(["-taokari", f"-taokari-cfg={DBG_CFG}"]),
                         "-o", str(dbg_exe)]), "debuggable-strong build"):
            return 1
        dbg_run = run([str(dbg_exe)])
        if dbg_run.returncode or dbg_run.stdout != plain_run.stdout:
            print(f"FAIL: debuggable-strong runtime mismatch rc={dbg_run.returncode} "
                  f"out={dbg_run.stdout!r} expected={plain_run.stdout!r}",
                  file=sys.stderr)
            return 1

    print(f"debuggable-strong-profile: ok (protection active, "
          f"{dbg_subprograms} DISubprogram records kept vs strong "
          f"{strong_subprograms}, runtime matches native)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
