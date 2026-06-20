"""Level-1 MIR (backend) obfuscation verification.

Checks the new Machine IR obfuscation layer without touching the main test
runner or any other verify_* script:

  * The -mllvm -taokari-mir flag and the `mir` annotation gate both opt a
    function in, and a `-mir` annotation opts it back out.
  * The pass is scheduled in the codegen pipeline: a function annotated
    `+mir` receives the Level-1 entry nop in the final binary, while an
    unannotated sibling does not.
  * Functional correctness holds: obfuscated and plain binaries produce
    identical stdout.

Level 1 is infrastructure only -- the nop is a semantically-neutral marker
that proves the whole plumbing (flag -> annotation reader -> per-function
gate -> addPreEmitPass scheduling -> BuildMI emission -> assembler) works
end to end. Real transforms (dirty bytes, junk instructions, machine
instruction substitution) are Level 2.
"""
from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CLANG = ROOT / "build" / "taokari-local" / "bin" / "clang.exe"
OBJDUMP = ROOT / "build" / "taokari-local" / "bin" / "llvm-objdump.exe"
VSDEVCMD = Path(
    r"C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat"
)


# Two functions: one opts in via the `+mir` annotation, one is plain. The
# annotation is what proves the per-function gate works independently of the
# global flag. optnone+noinline keeps the body intact so the entry nop is
# visible at the top of the function rather than being inlined away.
SOURCE = r'''
#include <cstdint>

// Three sibling functions exercising every gate axis:
//   * annotated_sum  -- "+mir" annotation. Pass MUST run on it even when the
//                       global -taokari-mir flag is off (annotation opt-in).
//   * plain_sum      -- "-mir" annotation. Pass MUST NOT run on it, even when
//                       the global flag is on (annotation opt-out overrides).
//   * flag_sum       -- no annotation. Pass follows the global flag: runs
//                       when -taokari-mir is given, skips otherwise.
//
// External linkage (not static) so the object file keeps the symbol names for
// llvm-objdump to print as "<name>:" headers. noinline+optnone keeps the body
// intact so the marker sits at the very top of the function rather than being
// inlined into the caller.
#if defined(__clang__)
#define TAO_MIR_ON  __attribute__((annotate("+mir")))
#define TAO_MIR_OFF __attribute__((annotate("-mir")))
#else
#define TAO_MIR_ON
#define TAO_MIR_OFF
#endif
#define TAO_NOINLINE __attribute__((noinline))
#define TAO_OPTNONE __attribute__((optnone))

extern "C" {

TAO_NOINLINE TAO_OPTNONE TAO_MIR_ON
uint32_t annotated_sum(uint32_t a, uint32_t b) {
  return a + b + 0x9E3779B9u;
}

TAO_NOINLINE TAO_OPTNONE TAO_MIR_OFF
uint32_t plain_sum(uint32_t a, uint32_t b) {
  return a * 33u + b;
}

TAO_NOINLINE TAO_OPTNONE
uint32_t flag_sum(uint32_t a, uint32_t b) {
  return a ^ (b + 0x12345u);
}

}  // extern "C"

#include <cstdio>

int main() {
  uint32_t a = annotated_sum(1, 2);
  uint32_t b = plain_sum(3, 4);
  uint32_t c = flag_sum(5, 6);
  std::printf("mirobf:%u:%u:%u\n", a, b, c);
  return 0;
}
'''


def run(command: list[str], **kw) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, **kw)


def run_vs(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
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
        return run(["cmd.exe", "/d", "/c", str(batch)], cwd=cwd)
    finally:
        batch.unlink(missing_ok=True)


def must(result: subprocess.CompletedProcess[str], label: str) -> None:
    if result.returncode:
        print(result.stdout, end="")
        print(result.stderr, end="", file=sys.stderr)
        raise SystemExit(f"{label} failed: {result.returncode}")


def compile_exe(
    src: Path, out: Path, *, mir_flag: bool
) -> None:
    cmd = [str(CLANG), str(src), "-std=c++17", "-O1", "-o", str(out)]
    if mir_flag:
        # Global enable as well, so the test exercises BOTH paths:
        # annotated_sum opts in via `+mir`, plain_sum is force-skipped via
        # `-mir` even though the global flag is on.
        cmd += ["-mllvm", "-taokari-mir=1"]
    must(run_vs(cmd, src.parent), f"compile {out.name}")


def compile_obj(
    src: Path, out: Path, *, mir_flag: bool, extra_flags: list[str] | None = None
) -> None:
    # Compile to a relocatable object (.obj). The object retains full symbol
    # names, so llvm-objdump -d prints "<name>:" headers we can slice on.
    # This is the direct output of the codegen pipeline, so it is the most
    # faithful place to look for the MIR pass's entry nop.
    cmd = [str(CLANG), str(src), "-std=c++17", "-O1"]
    if extra_flags:
        cmd += extra_flags
    cmd += ["-c", "-o", str(out)]
    if mir_flag:
        cmd += ["-mllvm", "-taokari-mir=1"]
    must(run_vs(cmd, src.parent), f"compile {out.name}")


def disassemble(obj: Path) -> str:
    # llvm-objdump prints "<name>:\n  ...insns...\n\n" per symbol in an
    # object file. --no-show-raw-insn keeps it readable; intel syntax so the
    # mnemonic is unambiguous (nop stays "nop").
    result = run(
        [
            str(OBJDUMP),
            "-d",
            "--no-show-raw-insn",
            "-M", "intel",
            str(obj),
        ]
    )
    must(result, f"disassemble {obj.name}")
    return result.stdout


def function_body(disasm: str, func: str) -> str:
    """Return the disassembly of one symbol, from its header to the next
    blank-line-delimited symbol or end of file."""
    # llvm-objdump prints: 0000000... <name>:\n  ... instructions ...\n\n
    # Match from the "<func>:" header to the next blank line.
    for name in (func, "_" + func):
        pat = re.compile(
            r"<" + re.escape(name) + r">:\n(.*?)(?:\n\n|\Z)", re.DOTALL
        )
        m = pat.search(disasm)
        if m:
            return m.group(1)
    raise SystemExit(f"could not locate <{func}> in disassembly")


def entry_has_marker(body: str) -> bool:
    """True if the function's first real instruction is the pass's marker.

    The Level 1 pass inserts "lea rax, [rax+0]" (bytes 48 8D 40 00) at the
    entry of every function it opts in. That encoding with the explicit +0
    displacement is not in clang's own prologue/epilogue or alignment
    vocabulary, so its presence at a function's first instruction is a
    reliable, non-vacuous signal that the pass ran. We match on the mnemonic
    form "lea rax, [rax]" (llvm-objdump prints the +0 as a bare [rax]).

    Each objdump instruction line looks like:
        "       0: 48 8d 40 00                  \tlea\trax, [rax]"
    The instruction text is the trailing tab-separated fields after the bytes
    -- here "lea", "rax, [rax]". We join the last two fields so the mnemonic
    and operands are checked together.
    """
    lines = [ln for ln in body.splitlines() if ln.strip()]
    if not lines:
        return False
    # Each objdump line is "<addr>: <bytes> \t<mnemonic>\t<operands>". Take
    # everything after the address+bytes block (the part after the first run
    # of tabs) as the instruction text. llvm-objdump separates bytes from
    # mnemonic with a tab, so splitting on "\t" and dropping the leading
    # "<addr>: <bytes>" field yields the instruction fields.
    fields = lines[0].split("\t")
    insn_fields = [f.strip() for f in fields if f.strip()]
    insn = " ".join(insn_fields).lower()
    # insn is like "0: 48 8d 40 00 lea rax, [rax]". Match the mnemonic+operands
    # form "lea rax, [rax]" anywhere in it (the +0 displacement renders as a
    # bare [rax], which clang's own codegen never produces for a prologue).
    return "lea rax, [rax]" in insn


def run_checks(tmp: Path) -> int:
    src = tmp / "mirobf_level1.cpp"
    plain = tmp / "plain.exe"
    obf = tmp / "obf.exe"
    obj_no_flag = tmp / "no_flag.obj"
    obj_with_flag = tmp / "with_flag.obj"
    obj_x86_32 = tmp / "x86_32.obj"
    src.write_text(SOURCE, encoding="utf-8")

    # --- Functional correctness: linked executables must agree on stdout. ---
    # Both builds are functionally identical because the marker is a no-op;
    # the obfuscated one additionally runs the pass (flag on) but that cannot
    # change observable behavior.
    compile_exe(src, plain, mir_flag=False)
    compile_exe(src, obf, mir_flag=True)
    plain_run = run([str(plain)])
    obf_run = run([str(obf)])
    must(plain_run, "plain run")
    must(obf_run, "obfuscated run")
    if plain_run.stdout != obf_run.stdout:
        raise SystemExit(
            f"stdout mismatch\nplain={plain_run.stdout!r}\nobf={obf_run.stdout!r}"
        )

    # --- Gate checks: disassemble object files (which keep symbols). ---
    compile_obj(src, obj_no_flag, mir_flag=False)
    compile_obj(src, obj_with_flag, mir_flag=True)
    compile_obj(src, obj_x86_32, mir_flag=True, extra_flags=["-m32"])
    no_flag_dis = disassemble(obj_no_flag)
    with_flag_dis = disassemble(obj_with_flag)
    x86_32_dis = disassemble(obj_x86_32)

    def marker(disasm: str, fn: str) -> bool:
        return entry_has_marker(function_body(disasm, fn))

    failures: list[str] = []

    # Axis 1 -- "+mir" annotation: pass runs regardless of the global flag.
    #   no_flag build: annotation opts the function in -> marker present.
    #   with_flag build: still in -> marker present.
    if not marker(no_flag_dis, "annotated_sum"):
        failures.append(
            "no_flag build: +mir annotated_sum did NOT get the marker -- "
            "per-function opt-in (annotation) gate is broken"
        )
    if not marker(with_flag_dis, "annotated_sum"):
        failures.append(
            "with_flag build: +mir annotated_sum did NOT get the marker"
        )

    # Axis 2 -- "-mir" annotation: pass must NOT run, overriding the flag.
    #   no_flag build: skipped (flag off AND opt-out).
    #   with_flag build: skipped (opt-out overrides the on flag).
    if marker(with_flag_dis, "plain_sum"):
        failures.append(
            "with_flag build: -mir plain_sum got the marker despite its "
            "opt-out annotation -- per-function opt-out gate is broken"
        )

    # Axis 3 -- no annotation: pass follows the global flag.
    #   no_flag build: skipped (flag off, no annotation).
    #   with_flag build: runs (flag on, no annotation to override).
    if marker(no_flag_dis, "flag_sum"):
        failures.append(
            "no_flag build: flag_sum got the marker with no flag and no "
            "annotation -- pass should be fully off"
        )
    if not marker(with_flag_dis, "flag_sum"):
        failures.append(
            "with_flag build: flag_sum did NOT get the marker despite the "
            "global flag being on -- flag opt-in gate is broken"
        )

    # Axis 4 -- 32-bit x86 safety: the Level-1 marker bytes are x86-64-only.
    # On i386, 0x48 decodes as "dec eax", so the pass must no-op there.
    for fn in ("annotated_sum", "plain_sum", "flag_sum"):
        if marker(x86_32_dis, fn):
            failures.append(
                f"32-bit x86 build: {fn} got the x86-64 marker -- pass must "
                "skip non-x86-64 targets"
            )

    if failures:
        for f in failures:
            print(f"FAIL: {f}", file=sys.stderr)
        raise SystemExit(
            f"{len(failures)} gate check(s) failed; see stderr"
        )

    print("verify_machine_obf_level1: ok")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()

    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2
    if not OBJDUMP.exists():
        print(f"missing llvm-objdump: {OBJDUMP}", file=sys.stderr)
        return 2

    tmp = Path(tempfile.mkdtemp(prefix="taokari-mir-l1-"))
    try:
        return run_checks(tmp)
    finally:
        if args.keep:
            print(f"kept temp dir: {tmp}")
        else:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
