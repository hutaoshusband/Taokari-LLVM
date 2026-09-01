"""Native-vs-protected constant encryption EH semantics verifier."""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))

import _taokari_portable as tp


CLANGXX = tp.tool("clang++")

SOURCE = r"""
#include <cstdint>
#include <cstdlib>
#include <cstdio>

#define OBF __attribute__((noinline))

static OBF std::uint32_t throw_leaf(std::uint32_t value) {
  if ((value & 15u) == 7u)
    throw value;
  return value * 33u + 17u;
}

static OBF std::uint32_t bridge(std::uint32_t value) {
  return throw_leaf(value) ^ 0x7f4a7c15u;
}

static OBF std::uint32_t run(std::uint32_t seed) {
  std::uint32_t state = seed | 1u;
  std::uint32_t hash = 2166136261u;
  for (unsigned i = 0; i < 4096; ++i) {
    state = state * 1664525u + 1013904223u;
    try {
      hash = (hash ^ bridge(state)) * 16777619u;
    } catch (std::uint32_t value) {
      hash = (hash ^ value ^ 0xa55aa55au) * 16777619u;
    }
  }
  return hash;
}

int main(int argc, char **argv) {
  const auto seed =
      argc > 1 ? static_cast<std::uint32_t>(std::strtoul(argv[1], nullptr, 0))
               : 1u;
  std::printf("cie-eh:%08x:%08x\n", seed, run(seed));
  return 0;
}
"""

PROTECTED_FLAGS = [
    "-mllvm", "-taokari",
    "-mllvm", "-taokari-cie",
    "-mllvm", "-taokari-level-cie=4",
]

SEEDS = [
    "0",
    "1",
    "7",
    "0x12345678",
    "0x80000000",
    "0xffffffff",
    "0x9e3779b9",
    "0xc001d00d",
]


def compile_exe(
    source: Path,
    output: Path,
    *,
    protected: bool,
) -> subprocess.CompletedProcess[str]:
    command = [str(CLANGXX), str(source), "-std=c++20", "-O3", "-o", str(output)]
    if protected:
        command.extend(PROTECTED_FLAGS)
    return tp.run(command, vs=True)


def main() -> int:
    if not CLANGXX.exists():
        print(f"missing clang++: {CLANGXX}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-cie-eh-") as tmp:
        tmpdir = Path(tmp)
        source = tmpdir / "cie_eh.cpp"
        native = tmpdir / "native.exe"
        protected = tmpdir / "protected.exe"
        source.write_text(SOURCE, encoding="utf-8")

        for output, enabled in ((native, False), (protected, True)):
            result = compile_exe(source, output, protected=enabled)
            if result.returncode:
                sys.stderr.write(result.stdout + result.stderr)
                return 1

        failures = []
        for seed in SEEDS:
            native_run = tp.run([str(native), seed])
            protected_run = tp.run([str(protected), seed])
            if native_run.returncode or protected_run.returncode:
                failures.append(
                    f"{seed}: exit native={native_run.returncode} "
                    f"protected={protected_run.returncode}"
                )
            elif native_run.stdout != protected_run.stdout:
                failures.append(
                    f"{seed}: native={native_run.stdout!r} "
                    f"protected={protected_run.stdout!r}"
                )

        if failures:
            print("cie EH semantics: FAIL", file=sys.stderr)
            for failure in failures:
                print(f"  - {failure}", file=sys.stderr)
            return 1

    print(f"cie EH semantics: ok ({len(SEEDS)} seeds)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
