"""Verify context-dependent opaque constants.

-taokari-ocnst now derives each function's XOR nonce from that function's
identity mixed with a per-build seed, instead of a single fixed seed shared
across the whole module. The contract this verifier enforces:

  * Two functions that load the SAME plaintext constant must produce
    DIFFERENT nonce globals (@<func>.ocnst.nonce), so the encrypted form of
    an identical constant diverges across functions. A fixed seed would make
    the two initializers bit-identical and let a reverse engineer correlate
    constants across the binary by a trivial signature.
  * The two nonces are still non-zero (a zero nonce would be a no-op XOR).
  * The obfuscated binary still runs and matches native output exactly.

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
VSDEVCMD = Path(
    r"C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat"
)

PLAIN_CONST = 0x12345678


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

__attribute__((noinline)) int32_t alpha(int x) {{
  int32_t secret = {PLAIN_CONST};
  return (x ^ secret) + secret;
}}

__attribute__((noinline)) int32_t beta(int x) {{
  int32_t secret = {PLAIN_CONST};
  return (x - secret) * secret;
}}

int main(void) {{
  printf("ocnst-ctx:%d:%d\\n", alpha(7), beta(7));
  return 0;
}}
"""


NONCE_RE = re.compile(
    r"@(?P<func>[A-Za-z0-9_]+)\.ocnst\.nonce\s*=\s*.*?i64\s+(?P<val>-?\d+)",
    re.MULTILINE,
)


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-ocnst-ctx-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "ocnst_ctx.c"
        src.write_text(SOURCE, encoding="utf-8")

        ir = tmp / "ocnst_ctx.ll"
        if not must(run([str(CLANG), str(src), "-O2", "-fno-discard-value-names",
                         *mllvm(["-taokari", "-taokari-ocnst",
                                 "-taokari-ocnst-prob=100"]),
                         "-S", "-emit-llvm", "-o", str(ir)]), "emit-llvm"):
            return 1
        ir_text = ir.read_text(encoding="utf-8", errors="ignore")

        nonces = {
            m.group("func"): int(m.group("val")) for m in NONCE_RE.finditer(ir_text)
        }
        if "alpha" not in nonces or "beta" not in nonces:
            print(f"FAIL: expected alpha/beta nonce globals, got {sorted(nonces)}",
                  file=sys.stderr)
            return 1
        if not nonces["alpha"] or not nonces["beta"]:
            print("FAIL: a context nonce evaluated to zero (XOR would be a no-op)",
                  file=sys.stderr)
            return 1
        if nonces["alpha"] == nonces["beta"]:
            print("FAIL: alpha and beta share the same context nonce "
                  "(fixed-seed regression)", file=sys.stderr)
            return 1

        native = run([str(CLANG), str(src), "-O2", "-o", str(tmp / "native.exe")])
        if not must(native, "native build"):
            return 1
        native_run = run([str(tmp / "native.exe")])
        if native_run.returncode:
            sys.stderr.write("native run failed\n")
            return 1

        obf = tmp / "ocnst_ctx.exe"
        if not must(run([str(CLANG), str(src), "-O2",
                         *mllvm(["-taokari", "-taokari-ocnst",
                                 "-taokari-ocnst-prob=100"]),
                         "-o", str(obf)]), "ocnst-ctx exe build"):
            return 1
        obf_run = run([str(obf)])
        if obf_run.returncode or obf_run.stdout != native_run.stdout:
            print(f"FAIL: ocnst-ctx runtime mismatch rc={obf_run.returncode} "
                  f"out={obf_run.stdout!r} expected={native_run.stdout!r}",
                  file=sys.stderr)
            return 1

    print(f"opaque-constant-context: ok (alpha nonce {nonces['alpha']} != "
          f"beta nonce {nonces['beta']}, runtime matches native)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
