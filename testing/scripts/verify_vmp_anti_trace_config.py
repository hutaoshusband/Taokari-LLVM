from __future__ import annotations

import json
import re
import sys
import tempfile
from pathlib import Path
import _taokari_portable as tp

from verify_vmp_basic_block_bytecode import CLANG, run


SOURCE = r"""
#include <stdio.h>

#ifdef FORCE_DYN
#define DYN ",+dyn^dyn=4"
#else
#define DYN ""
#endif

__attribute__((noinline, annotate("+vmp" DYN)))
int guarded(int a, int b) {
  int x = ((a ^ 0x4d) + b) * 5;
  return (x & 1) ? x - a : x + b;
}

int main(void) {
  printf("trace:%d:%d\n", guarded(9, 4), guarded(31, 8));
  return 0;
}
"""

INTERP_RE = re.compile(
    r"define[^{@]*@__taokari_vmp_interp_i64_guarded_[^(]*"
    r"\([^)]*\)[^{]*\{(?P<body>.*?)\n\}",
    re.S,
)


def compat_rows(path: Path) -> dict[str, str]:
    rows: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and not line.startswith("function\t"):
            rows[parts[0]] = parts[1]
    return rows


def build(tmp: Path, mode: str, force_dyn: bool) -> str:
    cfg = tmp / f"{mode}.json"
    src = tmp / f"{mode}.c"
    ll = tmp / f"{mode}.ll"
    exe = tmp / f"{mode}.exe"
    report = tmp / f"{mode}.tsv"
    cfg.write_text(
        json.dumps({"randomSeed": f"vmp-anti-trace-{mode}",
                    "vm": {"anti_trace": mode}}),
        encoding="utf-8",
    )
    src.write_text(SOURCE, encoding="utf-8")
    flags = [
        str(CLANG), str(src), "-O2", "-fno-discard-value-names",
        "-mllvm", "-taokari", "-mllvm", "-taokari-vmp",
        "-mllvm", f"-taokari-cfg={cfg}",
        "-mllvm", f"-taokari-vmp-compat-report={report}",
    ]
    if force_dyn:
        flags.insert(1, "-DFORCE_DYN=1")
        flags.extend(["-mllvm", "-taokari-dyn"])
    ir = run([*flags, "-S", "-emit-llvm", "-o", str(ll)], use_vs_env=True)
    if ir.returncode:
        sys.stderr.write(ir.stdout + ir.stderr)
        raise SystemExit(ir.returncode)
    built = run([*flags, "-o", str(exe)], use_vs_env=True)
    if built.returncode:
        sys.stderr.write(built.stdout + built.stderr)
        raise SystemExit(built.returncode)
    ran = run([str(exe)])
    if ran.returncode or not ran.stdout.startswith("trace:"):
        sys.stderr.write(ran.stdout + ran.stderr)
        raise SystemExit(1)
    if compat_rows(report).get("guarded") != "virtualized":
        raise SystemExit(f"guarded did not virtualize under {mode}")
    match = INTERP_RE.search(ll.read_text(encoding="utf-8", errors="ignore"))
    if not match:
        raise SystemExit(f"missing guarded interpreter under {mode}")
    return match.group("body")


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-vmp-trace-cfg-") as tmp_name:
        tmp = Path(tmp_name)
        off = build(tmp, "off", True)
        light = build(tmp, "light", False)
        strong = build(tmp, "strong", False)

    timing_api = "QueryPerformanceCounter" if tp.IS_WINDOWS else "clock_gettime"
    emu_api = "GetTickCount64" if tp.IS_WINDOWS else "@time("
    if "dyn.loop.trap" in off or emu_api in off:
        raise SystemExit("vm.anti_trace=off did not suppress VMP loop checks")
    if "dyn.loop.trap" not in light or timing_api not in light:
        raise SystemExit("vm.anti_trace=light did not enable timing checks")
    if emu_api in light:
        raise SystemExit("vm.anti_trace=light enabled emulation checks")
    if "dyn.loop.trap" not in strong or emu_api not in strong:
        raise SystemExit("vm.anti_trace=strong did not enable emulation checks")

    print("vmp anti-trace config: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
