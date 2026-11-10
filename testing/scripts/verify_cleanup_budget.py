"""Regression for late InstCombine on BCF/FLA-expanded atomic updates.

The pre-budget UI stress build stalls in InstCombine on record_alpha's
25k-instruction CFG. Preserve that trigger in a small native/protected test,
verify the large resulting IR, and exercise three independent random builds.
The regular UI animation gate covers the complete application shape.
"""
from __future__ import annotations

from pathlib import Path
import re
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp
from verify_ui_animation_semantics import PROTECTED_FLAGS


SOURCE = r'''
#include <atomic>
#include <cstdint>
#include <cstdio>
static std::uint32_t trace = 2166136261u;
static std::atomic<std::uint32_t> updates{};
extern "C" __attribute__((noinline)) void record_alpha(std::uint8_t value) {
  trace = (trace ^ value) * 16777619u;
  updates.fetch_add(1, std::memory_order_relaxed);
}
int main() {
  for (unsigned i = 0; i < 32; ++i) record_alpha((std::uint8_t)i);
  std::printf("cleanup:%u:%u\n", trace, updates.load());
}
'''


def checked(command: list[str], *, vs: bool = False):
    result = tp.run(command, vs=vs)
    if result.returncode:
        raise RuntimeError(f"exit {result.returncode}: {' '.join(command)}\n"
                           f"{result.stdout}{result.stderr}")
    return result


def main() -> int:
    opt = tp.tool("opt")
    if not tp.CLANG.exists() or not opt.exists():
        print("missing clang or opt", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(prefix="taokari-cleanup-") as tmp:
        work = Path(tmp)
        src = work / "update.cpp"
        src.write_text(SOURCE, encoding="utf-8")
        native = work / tp.exe_name("native")
        checked([str(tp.CLANG), str(src), "-std=c++20", "-O3", "-o",
                 str(native)], vs=True)
        expected = checked([str(native)]).stdout
        for variant in range(3):
            ir = work / "protected.ll"
            start = time.monotonic()
            checked([str(tp.CLANG), str(src), "-std=c++20", "-O3",
                     *PROTECTED_FLAGS, "-fno-discard-value-names", "-S",
                     "-emit-llvm", "-o", str(ir)], vs=True)
            elapsed = time.monotonic() - start
            checked([str(opt), "-passes=verify", "-disable-output", str(ir)])
            text = ir.read_text(encoding="utf-8")
            match = re.search(r"define[^\n]*@record_alpha\([^\n]*\).*?\n}",
                              text, re.S)
            assert match, "protected function missing"
            # Non-vacuous: exercise a CFG above the default cleanup budget.
            instructions = sum(bool(line.strip()) and not line.lstrip().startswith(";")
                               for line in match.group(0).splitlines())
            assert instructions > 4096, f"trigger too small: {instructions}"
            exe = work / tp.exe_name("protected")
            checked([str(tp.CLANG), str(ir), "-O2", "-Xclang",
                     "-disable-llvm-passes", *PROTECTED_FLAGS, "-o", str(exe)],
                    vs=True)
            assert checked([str(exe)]).stdout == expected, "native output mismatch"
            print(f"cleanup budget: variant {variant}: {instructions} IR lines, "
                  f"IR compile {elapsed:.2f}s, verified and output matched", flush=True)
    print("cleanup budget: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
