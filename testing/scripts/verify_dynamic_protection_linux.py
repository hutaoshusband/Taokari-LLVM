from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp


ROOT = tp.ROOT
CLANG = tp.CLANG

SOURCE = r"""
#include <stdio.h>
#include <stdint.h>

static int64_t g_side = 0;

__attribute__((noinline, annotate("+dyn")))
int64_t sensitive(int64_t a, int64_t b) {
    int64_t x = a * 17 + b;
    g_side = x;
    return x + (a << 2) + 9;
}

int main(void) {
    int64_t s = sensitive(13, 100);
    printf("dyn:%lld:%lld\n", (long long)s, (long long)g_side);
    return 0;
}
"""


def main() -> int:
    if tp.IS_WINDOWS:
        print("dyn-linux: skipped on Windows (this gate is Linux-x64 only)")
        return 2
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    cpp = (ROOT / "upstream" / "taokari" / "llvm" / "lib" / "Transforms"
           / "Obfuscation" / "DynamicProtection.cpp").read_text(encoding="utf-8", errors="ignore")
    for needle in ("supportsLinuxX64", "TracerPid", "clock_gettime"):
        if needle not in cpp:
            print(f"DynamicProtection.cpp missing Linux primitive {needle}", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory(prefix="taokari-dyn-linux-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "dyn.c"
        src.write_text(SOURCE, encoding="utf-8")

        ir = tmp / "dyn.ll"
        res = tp.run([str(CLANG), str(src), "-O0", "-fno-discard-value-names",
                      "-S", "-emit-llvm", "-mllvm", "-taokari",
                      "-mllvm", "-taokari-dyn", "-o", str(ir)])
        if res.returncode:
            print(res.stdout, end="")
            print(res.stderr, end="", file=sys.stderr)
            return res.returncode
        text = ir.read_text(encoding="utf-8", errors="ignore")
        linux_checks = sum(name in text for name in
                           ("getppid", "clock_gettime", "TracerPid", "time"))
        if linux_checks == 0:
            print("no Linux dynamic check primitive emitted in IR", file=sys.stderr)
            return 1
        if "exit" not in text or "dyn.trap" not in text:
            print("no tamper/exit path emitted in IR", file=sys.stderr)
            return 1
        for win_api in ("IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                        "QueryPerformanceCounter", "GetTickCount64"):
            if win_api in text:
                print(f"Windows API {win_api} leaked into Linux IR", file=sys.stderr)
                return 1

        obf_exe = tmp / tp.exe_name("dyn_obf")
        res = tp.run([str(CLANG), str(src), "-O2", "-mllvm", "-taokari",
                      "-mllvm", "-taokari-dyn", "-o", str(obf_exe)])
        if res.returncode:
            print(res.stdout, end="")
            print(res.stderr, end="", file=sys.stderr)
            return res.returncode
        obf_run = tp.run([str(obf_exe)])
        if obf_run.returncode:
            print(f"obf runtime tripped trap on a clean run "
                  f"(rc={obf_run.returncode}): {obf_run.stdout}{obf_run.stderr}",
                  file=sys.stderr)
            return obf_run.returncode

        ref_exe = tmp / tp.exe_name("dyn_ref")
        res = tp.run([str(CLANG), str(src), "-O2", "-o", str(ref_exe)])
        if res.returncode:
            print(res.stderr, end="", file=sys.stderr)
            return res.returncode
        ref_run = tp.run([str(ref_exe)])
        if obf_run.stdout != ref_run.stdout:
            print(f"output drift:\n  obf: {obf_run.stdout!r}\n  ref: {ref_run.stdout!r}",
                  file=sys.stderr)
            return 1

        l3_src = tmp / "dyn_l3.c"
        l3_src.write_text(SOURCE.replace('annotate("+dyn")',
                                         'annotate("+dyn^dyn=3")'),
                          encoding="utf-8")
        l3_exe = tmp / tp.exe_name("dyn_l3")
        res = tp.run([str(CLANG), str(l3_src), "-O2", "-mllvm", "-taokari",
                      "-mllvm", "-taokari-dyn", "-o", str(l3_exe)])
        if res.returncode:
            print(res.stderr, end="", file=sys.stderr)
            return res.returncode
        l3_run = tp.run([str(l3_exe)])
        if l3_run.returncode or l3_run.stdout != ref_run.stdout:
            print(f"L3 clean run drifted (rc={l3_run.returncode}): "
                  f"{l3_run.stdout!r}", file=sys.stderr)
            return 1

    print("dyn-linux: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
