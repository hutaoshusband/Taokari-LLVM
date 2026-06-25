from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CLANG = ROOT / "build" / "taokari-local" / "bin" / "clang.exe"
VSDEVCMD = Path(r"C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat")

# Exercises a value, a side effect, and control flow so a check that broke the
# function body would be caught. The function runs in a clean (non-debugged)
# process, so every check must take the normal path and the output must match
# the unobfuscated reference.
SOURCE = r"""
#include <stdio.h>
#include <stdint.h>

static int64_t g_side = 0;

__attribute__((noinline, annotate("+dyn")))
int64_t sensitive(int64_t a, int64_t b) {
    int64_t x = a * 17 + b;
    g_side = x;                 /* side effect must survive the check */
    return x + (a << 2) + 9;
}

int main(void) {
    int64_t s = sensitive(13, 100);
    /* s = 321 + 52 + 9 = 382 ; g_side = 321 */
    printf("dyn:%lld:%lld\n", (long long)s, (long long)g_side);
    return 0;
}
"""


def run(command: list[str], *, cwd: Path = ROOT, input: str | None = None) -> subprocess.CompletedProcess[str]:
    if VSDEVCMD.exists():
        with tempfile.NamedTemporaryFile("w", suffix=".cmd", delete=False, encoding="utf-8") as handle:
            batch = Path(handle.name)
            handle.write(
                "@echo off\n"
                f'call "{VSDEVCMD}" -arch=x64 -host_arch=x64 >nul\n'
                f"{subprocess.list2cmdline(command)}\n"
                "exit /b %ERRORLEVEL%\n"
            )
        try:
            return subprocess.run(["cmd.exe", "/d", "/c", str(batch)], cwd=cwd, text=True, capture_output=True, input=input)
        finally:
            batch.unlink(missing_ok=True)
    return subprocess.run(command, cwd=cwd, text=True, capture_output=True, input=input)


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    cpp = (ROOT / "upstream" / "taokari" / "llvm" / "lib" / "Transforms"
           / "Obfuscation" / "DynamicProtection.cpp").read_text(encoding="utf-8", errors="ignore")
    for needle in ("IsDebuggerPresent", "CreateCondBr", "dynOpt"):
        if needle not in cpp:
            print(f"DynamicProtection.cpp missing {needle}", file=sys.stderr)
            return 1
    if "createDynamicProtectionPass" not in (ROOT / "upstream" / "taokari" / "llvm"
            / "lib" / "Transforms" / "Obfuscation" / "ObfuscationPassManager.cpp"
            ).read_text(encoding="utf-8", errors="ignore"):
        print("dyn pass not wired into PassManager", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory(prefix="taokari-dyn-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "dyn.c"
        src.write_text(SOURCE, encoding="utf-8")

        # IR: the annotated function must carry a check primitive and a
        # conditional branch to a trap path.
        ir = tmp / "dyn.ll"
        res = run([str(CLANG), str(src), "-O0", "-fno-discard-value-names", "-S", "-emit-llvm",
                   "-mllvm", "-taokari", "-mllvm", "-taokari-dyn", "-o", str(ir)])
        if res.returncode:
            print(res.stdout, end="")
            print(res.stderr, end="", file=sys.stderr)
            return res.returncode
        text = ir.read_text(encoding="utf-8", errors="ignore")
        checks = sum(name in text for name in
                     ("IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                      "QueryPerformanceCounter"))
        if checks == 0:
            print("no dynamic check primitive emitted in IR", file=sys.stderr)
            return 1
        if "exit" not in text or "dyn.trap" not in text:
            print("no tamper/exit path emitted in IR", file=sys.stderr)
            return 1

        # Off by default: without -taokari-dyn / annotation the function must
        # compile clean and contain no check primitive.
        plain_ir = tmp / "plain.ll"
        res = run([str(CLANG), str(src), "-O0", "-S", "-emit-llvm", "-o", str(plain_ir)])
        if res.returncode:
            print(res.stdout, end="")
            print(res.stderr, end="", file=sys.stderr)
            return res.returncode
        plain = plain_ir.read_text(encoding="utf-8", errors="ignore")
        if "IsDebuggerPresent" in plain or "QueryPerformanceCounter" in plain:
            print("dyn checks emitted without the flag/annotation (not opt-in)",
                  file=sys.stderr)
            return 1

        # Correctness: a clean run must match the unobfuscated reference.
        obf_exe = tmp / "dyn_obf.exe"
        res = run([str(CLANG), str(src), "-O2", "-mllvm", "-taokari",
                   "-mllvm", "-taokari-dyn", "-o", str(obf_exe)])
        if res.returncode:
            print(res.stdout, end="")
            print(res.stderr, end="", file=sys.stderr)
            return res.returncode
        obf_run = run([str(obf_exe)])
        if obf_run.returncode:
            print(f"obf runtime failed (rc={obf_run.returncode}): "
                  f"{obf_run.stdout}{obf_run.stderr}", file=sys.stderr)
            return obf_run.returncode

        ref_exe = tmp / "dyn_ref.exe"
        res = run([str(CLANG), str(src), "-O2", "-o", str(ref_exe)])
        if res.returncode:
            print(res.stdout, end="")
            print(res.stderr, end="", file=sys.stderr)
            return res.returncode
        ref_run = run([str(ref_exe)])
        if obf_run.stdout != ref_run.stdout:
            print(f"output drift:\n  obf: {obf_run.stdout!r}\n  ref: {ref_run.stdout!r}",
                  file=sys.stderr)
            return 1

        # Compose with the rest of the stack must still round-trip.
        full_exe = tmp / "dyn_full.exe"
        res = run([str(CLANG), str(src), "-O2",
                   "-mllvm", "-taokari", "-mllvm", "-taokari-dyn",
                   "-mllvm", "-taokari-fla", "-mllvm", "-taokari-level-fla=2",
                   "-mllvm", "-taokari-mba", "-mllvm", "-taokari-level-mba=2",
                   "-o", str(full_exe)])
        if res.returncode:
            print(res.stdout, end="")
            print(res.stderr, end="", file=sys.stderr)
            return res.returncode
        full_run = run([str(full_exe)])
        if full_run.returncode:
            print(f"compose runtime failed (rc={full_run.returncode}): "
                  f"{full_run.stdout}{full_run.stderr}", file=sys.stderr)
            return full_run.returncode
        if full_run.stdout != ref_run.stdout:
            print(f"compose output drift:\n  obf: {full_run.stdout!r}\n  ref: {ref_run.stdout!r}",
                  file=sys.stderr)
            return 1

        # L2: distributed checks. At level 2 the entry carries a fake decoy
        # check call and the real detection result is mixed with an unfoldable
        # opaque predicate. A clean run must still round-trip (the opaque side
        # is always false at runtime, so the mix never false-positives).
        l2_src = tmp / "dyn_l2.c"
        l2_src.write_text(SOURCE.replace('annotate("+dyn")',
                                         'annotate("+dyn^dyn=2")'),
                          encoding="utf-8")
        l2_ir = tmp / "dyn_l2.ll"
        res = run([str(CLANG), str(l2_src), "-O0", "-fno-discard-value-names",
                   "-S", "-emit-llvm", "-mllvm", "-taokari",
                   "-mllvm", "-taokari-dyn", "-o", str(l2_ir)])
        if res.returncode:
            print(res.stdout, end="")
            print(res.stderr, end="", file=sys.stderr)
            return res.returncode
        l2_text = l2_ir.read_text(encoding="utf-8", errors="ignore")
        if "__taokari_dyn_fake_" not in l2_text:
            print("L2: no fake decoy check emitted", file=sys.stderr)
            return 1
        if "dyn.mix" not in l2_text and "or i1" not in l2_text:
            print("L2: no opaque-predicate result mixing", file=sys.stderr)
            return 1
        # Tamper flag: a shared module global that every check reads and the
        # trap sets, so detection propagates across checks.
        if "__taokari_dyn_tamper" not in l2_text:
            print("L2: no shared tamper flag emitted", file=sys.stderr)
            return 1
        if not re.search(r"load i8, .*__taokari_dyn_tamper", l2_text):
            print("L2: tamper flag is not read by the check", file=sys.stderr)
            return 1
        # Runtime nonce: the mix predicate must depend on a runtime-unfoldable
        # seed (a volatile global load), not a constant.
        if "load volatile" not in l2_text:
            print("L2: no runtime-unfoldable nonce seed found", file=sys.stderr)
            return 1
        l2_exe = tmp / "dyn_l2.exe"
        res = run([str(CLANG), str(l2_src), "-O2", "-mllvm", "-taokari",
                   "-mllvm", "-taokari-dyn", "-o", str(l2_exe)])
        if res.returncode:
            print(res.stdout, end="")
            print(res.stderr, end="", file=sys.stderr)
            return res.returncode
        l2_run = run([str(l2_exe)])
        if l2_run.returncode:
            print(f"L2 clean run tripped the trap (rc={l2_run.returncode}): "
                  f"opaque-false predicate is not actually false", file=sys.stderr)
            return l2_run.returncode
        if l2_run.stdout != ref_run.stdout:
            print(f"L2 output drift:\n  obf: {l2_run.stdout!r}\n  ref: {ref_run.stdout!r}",
                  file=sys.stderr)
            return 1

    print("dyn: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
