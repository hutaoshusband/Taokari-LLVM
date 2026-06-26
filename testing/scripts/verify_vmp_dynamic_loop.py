"""Verify VMP interpreter-loop checks route through DynamicProtection."""
from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

from verify_vmp_basic_block_bytecode import CLANG, ROOT, run


SOURCE = r"""
#include <stdio.h>

#ifdef USE_DYN
#define DYN ",+dyn^dyn=3"
#else
#define DYN ""
#endif

__attribute__((noinline, annotate("+vmp" DYN)))
int guarded(int a, int b) {
  int x = ((a + b) ^ 0x31) * 5;
  if ((x & 3) == 1)
    return x - a;
  return x + b;
}

int main(void) {
  printf("vmp-dyn:%d:%d\n", guarded(17, 9), guarded(4, 21));
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


def build(tmp: Path, label: str, use_dyn: bool) -> tuple[str, str]:
    src = tmp / f"{label}.c"
    ll = tmp / f"{label}.ll"
    exe = tmp / f"{label}.exe"
    report = tmp / f"{label}.tsv"
    src.write_text(SOURCE, encoding="utf-8")
    flags = [
        str(CLANG), str(src), "-O2", "-fno-discard-value-names",
        "-mllvm", "-taokari", "-mllvm", "-taokari-vmp",
        "-mllvm", f"-taokari-vmp-compat-report={report}",
    ]
    if use_dyn:
        flags.insert(1, "-DUSE_DYN=1")
        flags.extend(["-mllvm", "-taokari-dyn"])
    ir = run([*flags, "-S", "-emit-llvm", "-o", str(ll)], use_vs_env=True)
    if ir.returncode:
        sys.stderr.write(ir.stdout + ir.stderr)
        raise SystemExit(ir.returncode)
    build_result = run([*flags, "-o", str(exe)], use_vs_env=True)
    if build_result.returncode:
        sys.stderr.write(build_result.stdout + build_result.stderr)
        raise SystemExit(build_result.returncode)
    ran = run([str(exe)])
    if ran.returncode or not ran.stdout.startswith("vmp-dyn:"):
        sys.stderr.write(ran.stdout + ran.stderr)
        raise SystemExit(1)
    if compat_rows(report).get("guarded") != "virtualized":
        raise SystemExit(f"guarded did not virtualize in {label}")
    text = ll.read_text(encoding="utf-8", errors="ignore")
    match = INTERP_RE.search(text)
    if not match:
        raise SystemExit(f"missing guarded interpreter in {label}")
    return text, match.group("body")


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-vmp-dyn-loop-") as tmp_name:
        tmp = Path(tmp_name)
        off_text, off_body = build(tmp, "off", False)
        on_text, on_body = build(tmp, "on", True)

    dynamic_apis = (
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "QueryPerformanceCounter",
    )
    if "dyn.loop.trap" in off_body or any(api in off_body for api in dynamic_apis):
        raise SystemExit("VMP interpreter emitted dynamic checks without dyn")
    if "dyn.loop.trap" not in on_body or "dyn.loop.ok" not in on_body:
        raise SystemExit("VMP interpreter is missing loop dynamic blocks")
    if not any(api in on_body for api in dynamic_apis):
        raise SystemExit("VMP interpreter loop emitted no dynamic probe API")
    if "__taokari_dyn_tamper" not in on_text:
        raise SystemExit("VMP dynamic loop did not use DynamicProtection tamper flag")
    if "dyn.orig" in on_body:
        raise SystemExit("generic DynamicProtection pass re-instrumented VMP interpreter")

    print("vmp dynamic loop: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
