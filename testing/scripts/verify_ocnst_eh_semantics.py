"""Native-vs-protected opaque-constant EH semantics verifier.

OpaqueConstant historically skipped every function with an EH personality,
so no i32 constant inside a try body was ever substituted. The funclet-safety
argument (site filter skips all terminators; every inserted chain is defined
and consumed in one block) makes the gate unnecessary; this verifier proves
the restored coverage both structurally and at runtime.

Observable:
  * `run` contains the try/catch, so it carries a personality. Once the
    personality gate is gone, ocnst creates `run.ocnst.nonce` (proof the
    pass ENTERED an EH function) and `run.ocnst.enc.*` globals (proof of
    actual substitution, checked in -O0 -fno-discard-value-names IR).
  * The substitution also reaches machine code: ocnst's fingerprint is a
    rip-relative memory-operand XOR (load; xor-of-loads). The -O0 object
    of the protected build must contain several in `run`; the native one
    none. (Name-based symbol gates cannot work: the ocnst globals are
    unnamed_addr private, so the COFF backend merges them into one
    anonymous .data symbol.)
  * Runtime parity: 8 seeds, native vs protected (-O3) stdout byte-exact.

On a pre-fix binary the presence gates fail (ocnst skipped `run`), which is
the expected teeth. A protected compile that crashes instead reports the
old InstCombine-crash class honestly as a failure too.

Exit:
  0 + "ocnst EH semantics: ok (N seeds)"
  1 -- gate violation or runtime mismatch
  2 -- missing clang++
"""
from __future__ import annotations

import re
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
  std::printf("ocnst-eh:%08x:%08x\n", seed, run(seed));
  return 0;
}
"""

PROTECTED_FLAGS = [
    "-mllvm", "-taokari",
    "-mllvm", "-taokari-ocnst",
    "-mllvm", "-taokari-ocnst-prob=100",
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


def run_clang(source: Path, output: Path, extra: list[str]) -> subprocess.CompletedProcess[str]:
    command = [str(CLANGXX), str(source), "-std=c++20", "-o", str(output)]
    command.extend(extra)
    return tp.run(command, vs=True)


def main() -> int:
    if not CLANGXX.exists():
        print(f"missing clang++: {CLANGXX}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-ocnst-eh-") as tmp:
        tmpdir = Path(tmp)
        source = tmpdir / "ocnst_eh.cpp"
        native = tmpdir / "native.exe"
        protected = tmpdir / "protected.exe"
        source.write_text(SOURCE, encoding="utf-8")

        native_result = run_clang(source, native, ["-O3"])
        if native_result.returncode:
            sys.stderr.write(native_result.stdout + native_result.stderr)
            return 1

        protected_result = run_clang(source, protected, ["-O3"] + PROTECTED_FLAGS)
        if protected_result.returncode:
            sys.stderr.write(protected_result.stdout + protected_result.stderr)
            print("ocnst EH semantics: FAIL (protected compile rc="
                  f"{protected_result.returncode})", file=sys.stderr)
            return 1

        ir_path = tmpdir / "ocnst_eh.ll"
        ir_result = run_clang(
            source, ir_path,
            ["-O0", "-fno-discard-value-names", "-S", "-emit-llvm"] + PROTECTED_FLAGS)
        if ir_result.returncode:
            sys.stderr.write(ir_result.stdout + ir_result.stderr)
            print("ocnst EH semantics: FAIL (IR emission rc="
                  f"{ir_result.returncode})", file=sys.stderr)
            return 1
        ir_text = ir_path.read_text(encoding="utf-8", errors="replace")

        # MSVC mangling puts the decorated name first (?run@@YAII@Z.ocnst.*),
        # Itanium puts it first too (_Z3runv.ocnst.*); both contain
        # "run" followed by the .ocnst marker before the closing quote.
        failures = []
        if not re.search(r'run[^"\n]*\.ocnst\.nonce', ir_text):
            failures.append(
                "IR: run*.ocnst.nonce missing -- ocnst never entered the "
                "EH function `run` (personality gate present?)")
        if not re.search(r'run[^"\n]*\.ocnst\.enc\.', ir_text):
            failures.append(
                "IR: no run*.ocnst.enc.* globals -- ocnst created the nonce "
                "but substituted nothing inside `run`")

        # At -O1+ the provably store-free private globals are folded away
        # (pre-existing ocnst behavior, independent of the personality
        # gate), so the machine-code presence gate runs on -O0 objects.
        objdump = tp.tool("llvm-objdump")
        if not objdump.exists():
            print(f"missing llvm-objdump: {objdump}", file=sys.stderr)
            return 2
        # MSVC labels run as <?run@@YAII@Z> and its catch funclet as
        # ?catch$N@?0??run@@...; Itanium uses _Z3runv. Any label containing
        # "run" belongs to the EH function or its funclets.
        run_symbol_re = re.compile(r"run")
        xor_rip_re = re.compile(r"xor[lqb]\s+0x[0-9a-f]+\(%rip\)")

        def count_run_xor_rips(obj: Path) -> int:
            dis = tp.run([str(objdump), "-d", str(obj)])
            if dis.returncode:
                raise RuntimeError(f"objdump failed on {obj}: {dis.stderr}")
            in_run = False
            count = 0
            for line in dis.stdout.splitlines():
                if "<" in line and ">" in line and not line.strip().startswith("#"):
                    match = re.search(r"<([^>]+)>:", line)
                    if match:
                        in_run = bool(run_symbol_re.search(match.group(1)))
                if in_run and xor_rip_re.search(line):
                    count += 1
            return count

        try:
            native_o0_obj = tmpdir / "native_o0.obj"
            protected_o0_obj = tmpdir / "protected_o0.obj"
            native_obj_result = run_clang(source, native_o0_obj, ["-O0", "-c"])
            if native_obj_result.returncode:
                sys.stderr.write(native_obj_result.stdout
                                 + native_obj_result.stderr)
                print("ocnst EH semantics: FAIL (native -O0 -c rc="
                      f"{native_obj_result.returncode})", file=sys.stderr)
                return 1
            protected_obj_result = run_clang(source, protected_o0_obj,
                                             ["-O0", "-c"] + PROTECTED_FLAGS)
            if protected_obj_result.returncode:
                sys.stderr.write(protected_obj_result.stdout
                                 + protected_obj_result.stderr)
                print("ocnst EH semantics: FAIL (protected -O0 -c rc="
                      f"{protected_obj_result.returncode})", file=sys.stderr)
                return 1
            native_xor_rips = count_run_xor_rips(native_o0_obj)
            protected_xor_rips = count_run_xor_rips(protected_o0_obj)
            if native_xor_rips:
                failures.append(
                    f"binary: native -O0 `run` has {native_xor_rips} "
                    "rip-relative xor instructions (fingerprint must be 0)")
            if protected_xor_rips < 3:
                failures.append(
                    "binary: protected -O0 `run` machine code has "
                    f"{protected_xor_rips} rip-relative xor instructions "
                    "(ocnst substitution never reached codegen for the EH "
                    "function)")
        except RuntimeError as error:
            print(error, file=sys.stderr)
            return 1

        for seed in SEEDS:
            native_run = tp.run([str(native), seed])
            protected_run = tp.run([str(protected), seed])
            if native_run.returncode or protected_run.returncode:
                failures.append(
                    f"{seed}: exit native={native_run.returncode} "
                    f"protected={protected_run.returncode}")
            elif native_run.stdout != protected_run.stdout:
                failures.append(
                    f"{seed}: native={native_run.stdout!r} "
                    f"protected={protected_run.stdout!r}")

        if failures:
            print("ocnst EH semantics: FAIL", file=sys.stderr)
            for failure in failures:
                print(f"  - {failure}", file=sys.stderr)
            return 1

    print(f"ocnst EH semantics: ok ({len(SEEDS)} seeds)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
