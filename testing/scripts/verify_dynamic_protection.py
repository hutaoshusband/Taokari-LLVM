from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
VSDEVCMD = tp.VSDEVCMD
if tp.IS_WINDOWS:
    DYN_APIS = ("IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                "QueryPerformanceCounter")
else:
    DYN_APIS = ("getppid", "clock_gettime", "TracerPid", "@time(")

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
        checks = sum(name in text for name in DYN_APIS)
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
        if any(api in plain for api in DYN_APIS):
            print("dyn checks emitted without the flag/annotation (not opt-in)",
                  file=sys.stderr)
            return 1

        dynamic_apis = DYN_APIS
        max_src = tmp / "dyn_max_off.c"
        max_src.write_text(SOURCE.replace(
            '__attribute__((noinline, annotate("+dyn")))',
            '__attribute__((noinline))'), encoding="utf-8")
        max_ir = tmp / "dyn_max_off.ll"
        res = run([str(CLANG), str(max_src), "-O0", "-S", "-emit-llvm",
                   "-mllvm", "-taokari", "-mllvm", "-taokari-max",
                   "-mllvm", "-taokari-max-no-vmp",
                   "-mllvm", "-taokari-report", "-o", str(max_ir)])
        if res.returncode:
            print(res.stdout, end="")
            print(res.stderr, end="", file=sys.stderr)
            return res.returncode
        max_report = res.stdout + res.stderr
        if "taokari-report: dyn enable=false" not in max_report:
            print("-taokari-max enabled dyn without explicit selection",
                  file=sys.stderr)
            return 1
        max_text = max_ir.read_text(encoding="utf-8", errors="ignore")
        if "__taokari_dyn" in max_text or any(api in max_text
                                              for api in dynamic_apis):
            print("dyn IR emitted under bare -taokari-max", file=sys.stderr)
            return 1

        max_dyn_ir = tmp / "dyn_max_on.ll"
        res = run([str(CLANG), str(max_src), "-O0", "-S", "-emit-llvm",
                   "-mllvm", "-taokari", "-mllvm", "-taokari-max",
                   "-mllvm", "-taokari-max-no-vmp",
                   "-mllvm", "-taokari-dyn",
                   "-mllvm", "-taokari-report", "-o", str(max_dyn_ir)])
        if res.returncode:
            print(res.stdout, end="")
            print(res.stderr, end="", file=sys.stderr)
            return res.returncode
        max_dyn_report = res.stdout + res.stderr
        if "taokari-report: dyn enable=true" not in max_dyn_report:
            print("explicit -taokari-dyn did not survive -taokari-max",
                  file=sys.stderr)
            return 1
        if not any(api in max_dyn_ir.read_text(
                encoding="utf-8", errors="ignore") for api in dynamic_apis):
            print("explicit -taokari-dyn emitted no dyn IR under max",
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

        # L3: fortress. The detection is built inside a private internal probe
        # function and called indirectly, so the protected function has no
        # direct call to a detection API. Clean run must still round-trip.
        l3_src = tmp / "dyn_l3.c"
        l3_src.write_text(SOURCE.replace('annotate("+dyn")',
                                         'annotate("+dyn^dyn=3")'),
                          encoding="utf-8")
        l3_ir = tmp / "dyn_l3.ll"
        res = run([str(CLANG), str(l3_src), "-O0", "-fno-discard-value-names",
                   "-S", "-emit-llvm", "-mllvm", "-taokari",
                   "-mllvm", "-taokari-dyn", "-o", str(l3_ir)])
        if res.returncode:
            print(res.stdout, end="")
            print(res.stderr, end="", file=sys.stderr)
            return res.returncode
        l3_text = l3_ir.read_text(encoding="utf-8", errors="ignore")
        if "__taokari_dyn_probe_" not in l3_text:
            print("L3: no indirect probe function emitted", file=sys.stderr)
            return 1
        # The protected function body must not call a detection API directly.
        sens_body = re.search(r"define[^@]*@sensitive\(.*?\n\}", l3_text, re.S)
        if sens_body:
            for api in ("IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                        "QueryPerformanceCounter"):
                if api in sens_body.group(0):
                    print(f"L3: detection API {api} still called directly in "
                          "protected body (not hidden behind probe)", file=sys.stderr)
                    return 1
        l3_exe = tmp / "dyn_l3.exe"
        res = run([str(CLANG), str(l3_src), "-O2", "-mllvm", "-taokari",
                   "-mllvm", "-taokari-dyn", "-o", str(l3_exe)])
        if res.returncode:
            print(res.stdout, end="")
            print(res.stderr, end="", file=sys.stderr)
            return res.returncode
        l3_run = run([str(l3_exe)])
        if l3_run.returncode:
            print(f"L3 clean run tripped the trap (rc={l3_run.returncode})",
                  file=sys.stderr)
            return l3_run.returncode
        if l3_run.stdout != ref_run.stdout:
            print(f"L3 output drift:\n  obf: {l3_run.stdout!r}\n  ref: {ref_run.stdout!r}",
                  file=sys.stderr)
            return 1

        # Predicate-family registry: -taokari-opaq-family selects the dyn
        # check's mixing predicate. With family=algebraic the predicate folds
        # over the runtime seed; with family=nested it carries a two-level
        # chain. Either way a clean run must round-trip (the opaque side is
        # always false at runtime). Compile two builds and confirm the flag is
        # accepted and both produce correct output.
        for fam in ("algebraic", "unfoldable", "nested"):
            exe_f = tmp / f"dyn_fam_{fam}.exe"
            res = run([str(CLANG), str(l3_src), "-O2",
                       "-mllvm", "-taokari", "-mllvm", "-taokari-dyn",
                       "-mllvm", f"-taokari-opaq-family={fam}",
                       "-o", str(exe_f)])
            if res.returncode:
                print(f"family={fam}: compile failed", file=sys.stderr)
                print(res.stderr, end="", file=sys.stderr)
                return res.returncode
            ran = run([str(exe_f)])
            if ran.returncode or ran.stdout != ref_run.stdout:
                print(f"family={fam}: clean run drifted "
                      f"({ran.stdout!r} vs {ref_run.stdout!r})", file=sys.stderr)
                return 1

        fla_o0_src = tmp / "dyn_fla_o0.c"
        fla_o0_src.write_text(
            "#include <stdio.h>\n"
            "__attribute__((noinline, annotate(\"+dyn\")))\n"
            "int looper(int n){int s=0;for(int i=0;i<n;i++)s+=i;return s;}\n"
            "int main(void){printf(\"fla-o0:%d\\n\",looper(10));return 0;}\n",
            encoding="utf-8")
        for opt in ("-O0", "-O2"):
            exe_f = tmp / f"dyn_fla_o0_{opt}.exe"
            res = run([str(CLANG), str(fla_o0_src), opt,
                       "-mllvm", "-taokari", "-mllvm", "-taokari-dyn",
                       "-mllvm", "-taokari-fla", "-mllvm", "-taokari-level-fla=4",
                       "-o", str(exe_f)])
            if res.returncode:
                print(f"fla+dyn {opt}: compile failed", file=sys.stderr)
                print(res.stderr, end="", file=sys.stderr)
                return res.returncode
            ran = run([str(exe_f)])
            if ran.returncode:
                print(f"fla+dyn {opt}: runtime crashed (rc={ran.returncode}) -- "
                      f"dyn split a flattened entry", file=sys.stderr)
                return 1
            if ran.stdout != "fla-o0:45\n":
                print(f"fla+dyn {opt}: output drift {ran.stdout!r} vs "
                      f"'fla-o0:45\\n'", file=sys.stderr)
                return 1

        ni_src = tmp / "ni_fla_o0.c"
        ni_src.write_text(
            "#include <stdio.h>\n"
            "__attribute__((noinline, annotate(\"+nativeint\")))\n"
            "int looper(int n){int s=0;for(int i=0;i<n;i++)s+=i;return s;}\n"
            "int main(void){printf(\"ni-o0:%d\\n\",looper(10));return 0;}\n",
            encoding="utf-8")
        for opt in ("-O0", "-O2"):
            exe_n = tmp / f"ni_fla_o0_{opt}.exe"
            res = run([str(CLANG), str(ni_src), opt,
                       "-mllvm", "-taokari",
                       "-mllvm", "-taokari-fla", "-mllvm", "-taokari-level-fla=4",
                       "-o", str(exe_n)])
            if res.returncode:
                print(f"nativeint+fla {opt}: compile failed", file=sys.stderr)
                print(res.stderr, end="", file=sys.stderr)
                return res.returncode
            ran = run([str(exe_n)])
            if ran.returncode:
                print(f"nativeint+fla {opt}: runtime crashed (rc={ran.returncode}) "
                      f"-- nativeint split a flattened entry", file=sys.stderr)
                return 1
            if ran.stdout != "ni-o0:45\n":
                print(f"nativeint+fla {opt}: output drift {ran.stdout!r}",
                      file=sys.stderr)
                return 1

    print("dyn: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
