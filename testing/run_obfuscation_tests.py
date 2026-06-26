from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TESTING = ROOT / "testing"
DEFAULT_CLANG = ROOT / "build" / "taokari-local" / "bin" / "clang.exe"
DEFAULT_CLANG_CL = ROOT / "build" / "taokari-local" / "bin" / "clang-cl.exe"
VSDEVCMD = Path(r"C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat")

# Base obfuscation flags: every IR pass enabled at once. RTTI is added by the
# harness because it needs a randomSeed from a config file.
OBF_FLAGS = [
    "-O2",
    "-mllvm", "-taokari",
    "-mllvm", "-taokari-indbr",
    "-mllvm", "-taokari-icall",
    "-mllvm", "-taokari-indgv",
    "-mllvm", "-taokari-fla",
    "-mllvm", "-taokari-bcf",
    "-mllvm", "-taokari-mba",
    "-mllvm", "-taokari-cse",
    "-mllvm", "-taokari-cie",
    "-mllvm", "-taokari-cfe",
]
# Passes that accept a 0-4 level. Default tests use the strongest level.
LEVEL_PASSES = ["indbr", "icall", "indgv", "fla", "bcf", "mba", "cie", "cfe"]
DEFAULT_LEVEL = 4
RTTI_CONFIG = TESTING / "configs" / "rtti.json"

COLOR = {
    "reset": "\033[0m",
    "blue": "\033[36m",
    "green": "\033[32m",
    "red": "\033[31m",
    "yellow": "\033[33m",
}

# Build modes. Each adds extra compile/link flags; clang-cl swaps the driver.
# -O2 survival, LTO and clang-cl prove the obfuscated IR still folds correctly
# (or stays encrypted) under whole-program and MSVC-ABI pipelines.
MODE_FLAGS: dict[str, list[str]] = {
    "default": [],
    "o2": [],
    "lto": ["-flto", "-fuse-ld=lld"],
    "clangcl": [],
}
MODE_DRIVER: dict[str, Path] = {
    "default": DEFAULT_CLANG,
    "o2": DEFAULT_CLANG,
    "lto": DEFAULT_CLANG,
    "clangcl": DEFAULT_CLANG_CL,
}


@dataclass(frozen=True)
class Case:
    name: str
    sources: tuple[Path, ...]
    expected_stdout: str | None = None
    expected_exit: int = 0
    includes: tuple[Path, ...] = ()
    link_flags: tuple[str, ...] = ()
    obfuscate_sources: set[Path] = field(default_factory=set)
    # Modes this case runs in. None = all modes. Heavy fixtures (imgui) are
    # default-only: they stress the whole obfuscator, not constant folding.
    modes: tuple[str, ...] | None = None
    # RTTI eraser rewrites MSVC type descriptors; cases with none (pure C) or
    # cases it must not touch opt out here so --rtti skips them cleanly.
    no_rtti: bool = False


@dataclass(frozen=True)
class ReleaseGate:
    name: str
    script: Path


def case_path(name: str) -> Path:
    return TESTING / "cases" / name


RELEASE_GATES = [
    ReleaseGate("indirect_call_level3", TESTING / "scripts" / "verify_indirect_call_level3.py"),
    ReleaseGate("vmp_release_smoke", TESTING / "scripts" / "verify_vmp_level1.py"),
    ReleaseGate("vmp_overhead_budget", TESTING / "scripts" / "verify_vmp_benchmark.py"),
    ReleaseGate("vmp_polymorphic_builds", TESTING / "scripts" / "verify_vmp_polymorphic_builds.py"),
    ReleaseGate("vmp_isa_randomization", TESTING / "scripts" / "verify_vmp_isa_randomization.py"),
    ReleaseGate("vmp_basic_block_bytecode", TESTING / "scripts" / "verify_vmp_basic_block_bytecode.py"),
    ReleaseGate("vmp_handler_mba", TESTING / "scripts" / "verify_vmp_handler_mba.py"),
    ReleaseGate("vmp_dll_load_and_manual_map", TESTING / "scripts" / "verify_vmp_dll_load.py"),
    ReleaseGate("semantic_memory_stress", TESTING / "scripts" / "verify_semantic_memory_stress.py"),
    # Section 22 Phase 1/7: prove -taokari-max + VMP no longer hangs.
    # The budget caps refuse runaway functions; -taokari-max-no-vmp is the
    # escape hatch when VMP is off entirely.
    ReleaseGate("max_build_no_vmp_hang", TESTING / "scripts" / "verify_max_build_no_vmp_hang.py"),
    ReleaseGate("max_build_vmp_budgeted", TESTING / "scripts" / "verify_max_build_vmp_budgeted.py"),
    # Section 10/12: the new opt-in passes and their full-stack compose.
    ReleaseGate("function_outlining", TESTING / "scripts" / "verify_function_outlining.py"),
    ReleaseGate("dynamic_protection", TESTING / "scripts" / "verify_dynamic_protection.py"),
    ReleaseGate("outline_dyn_fortress_compose", TESTING / "scripts" / "verify_outline_dyn_fortress_compose.py"),
]

IMGUI = TESTING / "vendor" / "imgui"
CASES = [
    Case("c_console", (case_path("c_console") / "src" / "main.c",), "c-console:104\n"),
    # Arithmetic & logic operator fixture: + - * / %, unary, pre/post
    # inc/dec, all relational operators, short-circuit &&/||/!, ternary on
    # int and FP. Exercises ConstantInt/FP encryption and MBA on add/sub.
    Case("arith_logic", (case_path("arith_logic") / "src" / "main.c",), "arith:6160:5775:42:110:142:301.142857\n"),
    # Bitwise & shift operator fixture: AND/OR/XOR/complement on int and
    # unsigned, << >>, every compound bit-assignment form, set/clear/toggle
    # bit-mask idioms, and a byte-order probe. Validates ConstantIntEncryption
    # and MBA on AND/OR/XOR under -O2/LTO.
    Case("bit_ops", (case_path("bit_ops") / "src" / "main.c",), "bitops:4043304975:253011243:896:31:2\n"),
    # Control-flow & loop fixture: nested if/switch/for/while/do-while,
    # break/continue/goto/return, comma operator, recursive factorial and a
    # recursive BST built with malloc. Stresses Flattening, IndirectBranch,
    # LegacyLowerSwitch and BCF opaque predicates.
    Case("control_flow", (case_path("control_flow") / "src" / "main.cpp",), "ctrlflow:3628800:1:702:2208152:460\n"),
    # Indirect branch fixture: computed goto dispatch (5-way table) and a
    # goto-loop. Stresses IndirectBranch page-table routing of BlockAddress
    # targets, including the no-op fallback for out-of-range indices.
    Case("indirect_branch", (case_path("indirect_branch") / "src" / "main.cpp",), "indbr:17:17:20:255:99:45\n"),
    # Indirect branch + C++ EH compatibility fixture: a throw inside a
    # goto-dispatched block must propagate to the caller's catch, and
    # the goto targets must still resolve after IndirectBranch page-table
    # rewrite. Stresses funclet/EH IR coexisting with indirectbr.
    Case("indirect_branch_eh", (case_path("indirect_branch_eh") / "src" / "main.cpp",), "indbr-eh:42:42:-1:99:1\n"),
    # Indirect globals — extended fixture: large struct, const struct,
    # runtime-indexed array, C++ static local. Stresses
    # IndirectGlobalVariable on a wider range of global shapes than the
    # basic c_globals case.
    Case("indirect_globals_struct", (case_path("indirect_globals_struct") / "src" / "main.cpp",), "indgv-struct:10:-6066930265826625388:101:102:103:0\n"),
    # Cross-pass fixture: IndirectGlobalVariable + StringEncryption +
    # ConstantIntegerEncryption in one function. Stresses all three
    # passes composing correctly.
    Case("indgv_x_strenc_x_constenc", (case_path("indgv_x_strenc_x_constenc") / "src" / "main.cpp",), "xpass:taokari-xpass-secret:-6066930261531658089:107\nxpass:taokari-xpass-secret:-6066930261531658085:118\nxpass-done:-6066930261531658089:-6066930261531658085\n"),
    # Functions & parameter passing fixture: value/reference/pointer params,
    # varying return types (int/double/struct), inline, function pointers,
    # std::function, capturing lambdas, and C varargs. Stresses IndirectCall
    # on every call site, struct return ABI, and varargs ABI.
    Case("functions", (case_path("functions") / "src" / "main.cpp",), "functions:15:14:23:23:36:111:25:105:15:7:16\n"),
    # Inheritance & polymorphism fixture: abstract base, multiple inheritance,
    # a virtual-inheritance diamond, virtual destructor, polymorphic delete
    # via unique_ptr, and catch-by-base (RTTI). Stresses IndirectCall on every
    # virtual call, this-adjustment thunks, and MicrosoftRTTIEraser.
    Case("cpp_inheritance", (case_path("cpp_inheritance") / "src" / "main.cpp",), "inherit:272:140:7\n"),
    # Advanced templates fixture: full + partial specialisations, non-type
    # parameter, variadic template, CRTP base, generic Matrix<T> with operator
    # overloads, and a generic bubble_sort. Each instantiation is its own IR
    # function exercised by ConstantIntEncryption/MBA/IndirectCall.
    Case("cpp_templates_adv", (case_path("cpp_templates_adv") / "src" / "main.cpp",), "templates-adv:3:42:15:6:70:165029893\n"),
    # Exceptions & RAII fixture: standard + custom exceptions, multiple catch
    # clauses (order matters), std::throw_with_nested + rethrow_if_nested,
    # RAII destructor order during unwind, noexcept, and exception_ptr capture
    # /rethrow. C++ exceptions lower to funclets on x64; the unwind tables and
    # the exception_ptr ABI are fragile under Flattening + BCF.
    Case("exceptions_raii", (case_path("exceptions_raii") / "src" / "main.cpp",), "exc:2100:3100:1142:4100:100:105:200:15:-3:50\n"),
    # Dynamic memory fixture: scalar new/delete, array new[]/delete[],
    # malloc/free, placement new, unique_ptr with custom deleter, shared_ptr
    # refcount, and weak_ptr expiry. Smart-pointer control blocks are
    # IndirectGlobalVariable targets; refcount arithmetic must stay
    # MBA/ConstantInt-stable; destructor count must stay leak-free.
    Case("dynamic_memory", (case_path("dynamic_memory") / "src" / "main.cpp",), "dynmem:11:15:30:42:77:3119:1101:14\n"),
    # STL containers & algorithms fixture: vector/list/deque/map/unordered_map/
    # set, forward + reverse iterators, std::sort/accumulate/transform/find/
    # count_if, capturing lambdas, range-for, auto. Allocator-backed growth is
    # an IndirectGlobalVariable surface; inlined comparison functors fold under
    # -O2/LTO.
    Case("stl_containers", (case_path("stl_containers") / "src" / "main.cpp",), "stl:45359:6663465:10017:5120:317450\n"),
    # Multithreading & synchronisation fixture: std::thread pool join,
    # std::mutex + lock_guard contention, producer/consumer on
    # condition_variable, std::async + std::future, std::atomic fetch_add.
    # Thread entry points are indirect calls; mutex/atomic ordering must stay
    # race-free after obfuscation.
    Case("multithreading", (case_path("multithreading") / "src" / "main.cpp",), "thread:1480266:4000:10000:59718:12000\n"),
    # File & stream I/O fixture: ofstream/ifstream/fstream in text + binary,
    # ios::out/app/binary, seekg/seekp, hex/oct formatting, and file lifecycle.
    # Exercises the vtable-backed iostream path (IndirectCall) and the hex/oct
    # manipulator constants (ConstantIntEncryption).
    Case("file_io", (case_path("file_io") / "src" / "main.cpp",), "io:168:150:4399400:0xff 0100 00042\n"),
    # Inline assembler & compiler-specifics fixture: GNU inline asm with
    # input/output/clobber constraints, __attribute__((packed)) and
    # __attribute__((aligned(32))) struct layouts, and a packed/asm mix.
    # Inline asm must pass through unchanged; packed GEP offsets must stay
    # byte-exact after ConstantIntEncryption.
    Case("inline_asm", (case_path("inline_asm") / "src" / "main.cpp",), "asm:6912:260:130:305468953:1111:8710\n"),
    # Preprocessor & macros fixture: token paste (##) with two-level
    # indirection, stringize (#), variadic compound-literal arg counting,
    # multi-line do/while(0) clamp macro, conditional #if selection,
    # __LINE__, and static_assert. Macro expansion feeds the int/string
    # constants that ConstantInt/ConstantString encryption must preserve.
    Case("preprocessor", (case_path("preprocessor") / "src" / "main.c",), "preproc:1170:-564375010:4:100:TAO23\n", no_rtti=True),
    # Security & sanitizer-compat fixture: unsigned wrap-around, signed/unsigned
    # division+modulo rounding, signed/unsigned comparison promotion, strict-
    # aliasing-safe memcpy punning, length-bounded string ops, bounds-clamped
    # stack indexing, and INT_MIN/-1 guard. All well-defined; obfuscation must
    # not introduce UB by reassociating signed overflow.
    Case("security_edge", (case_path("security_edge") / "src" / "main.c",), "sec:4294967295:699:701:10:1065353216:827111744:81:0\n", no_rtti=True),
    Case("cpp_console", (case_path("cpp_console") / "src" / "main.cpp",), "cpp-console:144\n"),
    Case("cpp_classes", (case_path("cpp_classes") / "src" / "main.cpp",), "classes:124:taokari\n"),
    Case("cpp_templates", (case_path("cpp_templates") / "src" / "main.cpp",), "templates:55:29\n"),
    Case("cpp_indirect_calls", (case_path("cpp_indirect_calls") / "src" / "main.cpp",), "indirect-calls:73\n"),
    Case("cpp_mixed", (case_path("cpp_mixed") / "src" / "main.cpp",), "mixed:3628800:1.4142:301\n"),
    Case(
        "realworld_c",
        (case_path("realworld_c") / "src" / "main.cpp",),
        # Ported from FireflyProtector/test64/realworld_c. Output is deterministic.
        "FireflyRealWorldFixture:bf3bec2ca306c59b:d0029f74\n",
    ),
    Case(
        "flattening_stress",
        (case_path("flattening_stress") / "src" / "main.cpp",),
        "flattening-stress:2287845297:2439064602\n",
    ),
    Case("c_seh", (case_path("c_seh") / "src" / "main.c",), "seh:12:16\n"),
    Case("cpp_funclet", (case_path("cpp_funclet") / "src" / "main.cpp",), "funclet:14:24\n"),
    # Constant encryption folding-risk fixture: int/FP constants across widths,
    # switch dispatch and phi feeds. Must stay identical under -O2/LTO/clang-cl.
    Case("const_enc", (case_path("const_enc") / "src" / "main.c",), "const:338181490:4.3442:3\n"),
    # MBA substitution fixture: add/sub/xor/and/or across i32/i64 plus a
    # chained addition block. Output must stay identical under -O2/LTO/clang-cl.
    Case("mba_basic", (case_path("mba_basic") / "src" / "main.c",), "mba-basic:3894:-4:189\n"),
    # Dedicated per-pass stress fixtures. Each targets one obfuscation surface
    # so a regression localises quickly, but all passes still run together.
    # Virtual dispatch -> IndirectCall vtable path.
    Case("cpp_virtual", (case_path("cpp_virtual") / "src" / "main.cpp",), "virtual:61\n"),
    # Mutable + const + function-pointer globals -> IndirectGlobalVariable.
    Case("c_globals", (case_path("c_globals") / "src" / "main.c",), "globals:11:51:18\n"),
    # Literal, format and runtime-built strings -> ConstantStringEncryption.
    Case("c_strings", (case_path("c_strings") / "src" / "main.c",), "strings:FX:108469760:1973234167\n"),
    # Compile-time VM prototype: annotation-selected integer toy function.
    Case("vmp_basic", (case_path("vmp_basic") / "src" / "main.c",), "vmp-basic:40:25\n", no_rtti=True),
    # SSE string-op fixture: a CRT-style vectorised byte search whose plain
    # binary lowers to the exact weakness pattern the obfuscator must defeat --
    # pcmpeqb + pmovmskb + a jump-table dispatch with `psrldq $N` arms (the
    # "case N: shift by N" pattern Hex-Rays models cleanly). Regression target
    # for verify_sse_string_protection.py and the +mir:sse Fortress pass.
    # Pure C (no RTTI to erase), runs in every mode.
    Case("sse_string", (case_path("sse_string") / "src" / "main.c",), "sse-string:1:0:a\n", no_rtti=True),
    Case(
        "imgui_headless",
        (
            case_path("imgui_headless") / "src" / "main.cpp",
            IMGUI / "imgui.cpp",
            IMGUI / "imgui_draw.cpp",
            IMGUI / "imgui_tables.cpp",
            IMGUI / "imgui_widgets.cpp",
        ),
        "imgui:1:1.92.9 WIP\n",
        includes=(IMGUI,),
        obfuscate_sources={case_path("imgui_headless") / "src" / "main.cpp"},
        modes=("default",),
    ),
]


def log(tag: str, message: str, color: str = "reset") -> None:
    print(f"{COLOR[color]}[{tag}]{COLOR['reset']} {message}", flush=True)


def run(command: list[str], *, cwd: Path = ROOT, use_vs_env: bool = False) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    if use_vs_env and VSDEVCMD.exists():
        with tempfile.NamedTemporaryFile("w", suffix=".cmd", delete=False, encoding="utf-8") as handle:
            batch = Path(handle.name)
            handle.write(
                "@echo off\n"
                f'call "{VSDEVCMD}" -arch=x64 -host_arch=x64 >nul\n'
                f"{subprocess.list2cmdline(command)}\n"
                "exit /b %ERRORLEVEL%\n"
            )
        try:
            return subprocess.run(["cmd.exe", "/d", "/c", str(batch)], cwd=cwd, text=True, capture_output=True, env=env)
        finally:
            batch.unlink(missing_ok=True)
    return subprocess.run(command, cwd=cwd, text=True, capture_output=True, env=env)


def object_name(source: Path) -> str:
    return "_".join(source.with_suffix("").parts[-4:]) + ".obj"


def compile_case(
    clang: Path,
    case: Case,
    mode: str = "default",
    *,
    obfuscate: bool = True,
    level: int | None = None,
    rtti: bool = False,
) -> Path:
    case_root = case_path(case.name)
    build = case_root / "build"
    obj = case_root / "obj"
    shutil.rmtree(build, ignore_errors=True)
    shutil.rmtree(obj, ignore_errors=True)
    build.mkdir(parents=True, exist_ok=True)
    obj.mkdir(parents=True, exist_ok=True)

    extra = MODE_FLAGS[mode]
    suffix = "" if mode == "default" else f"_{mode}"
    objects: list[Path] = []
    for source in case.sources:
        out = obj / (f"{os.getpid()}_" + object_name(source).removesuffix(".obj") + suffix + ".obj")
        log("COMPILE", f"{mode}/{case.name}: {source.relative_to(ROOT)}", "blue")
        is_cpp = source.suffix.lower() in {".cpp", ".cc", ".cxx"}
        is_cl = mode == "clangcl"
        if is_cl:
            std_flag = "/std:c++17" if is_cpp else "/std:c11"
        else:
            std_flag = "-std=c++17" if is_cpp else "-std=c17"
        cmd = [str(clang), "-c", str(source), std_flag]
        if is_cl:
            # clang-cl defaults to /EHs-c- (exceptions off); C++ tests need them.
            cmd.append("/EHsc")
        cmd += [f"-I{include}" for include in case.includes]
        if obfuscate and (not case.obfuscate_sources or source in case.obfuscate_sources):
            cmd += OBF_FLAGS
            if level is not None:
                # Apply the requested 0-3 level to every level-aware pass.
                for pass_name in LEVEL_PASSES:
                    cmd += ["-mllvm", f"-taokari-level-{pass_name}={level}"]
            if rtti and not case.no_rtti:
                # RTTI eraser rewrites MSVC ??_R0 type descriptors; it needs a
                # randomSeed from a config file.
                cmd += ["-mllvm", "-taokari-rtti",
                        "-mllvm", f"-taokari-cfg={RTTI_CONFIG}"]
        cmd += extra
        cmd += ["-o", str(out)]
        result = run(cmd, use_vs_env=True)
        if result.returncode:
            raise RuntimeError(f"compile {source}\n{result.stdout}{result.stderr}")
        if not out.exists():
            result = run(cmd, use_vs_env=True)
            if result.returncode or not out.exists():
                raise RuntimeError(f"compile {source} did not create {out}\n{result.stdout}{result.stderr}")
        objects.append(out)

    exe = build / f"{case.name}_{os.getpid()}{suffix}.exe"
    log("LINK", f"{mode}/{case.name}: {exe.relative_to(ROOT)}", "blue")
    result = run([str(clang), *map(str, objects), *case.link_flags, *extra, "-o", str(exe)], use_vs_env=True)
    if result.returncode:
        try:
            exe.unlink(missing_ok=True)
        except OSError:
            pass
        time.sleep(0.2)
        result = run([str(clang), *map(str, objects), *case.link_flags, *extra, "-o", str(exe)], use_vs_env=True)
        if result.returncode:
            raise RuntimeError(f"link {case.name}\n{result.stdout}{result.stderr}")
    if not exe.exists():
        result = run([str(clang), *map(str, objects), *case.link_flags, *extra, "-o", str(exe)], use_vs_env=True)
        if result.returncode or not exe.exists():
            raise RuntimeError(f"link {case.name} did not create {exe}\n{result.stdout}{result.stderr}")
    return exe


def measure_runtime(exe: Path, rounds: int = 3) -> tuple[float, subprocess.CompletedProcess[str]]:
    best = float("inf")
    last = None
    for _ in range(rounds):
        start = time.perf_counter()
        last = run([str(exe)])
        best = min(best, time.perf_counter() - start)
        if last.returncode:
            break
    assert last is not None
    return best, last


def run_release_gates(*, keep_going: bool) -> int:
    failures = 0
    for gate in RELEASE_GATES:
        log("GATE", gate.name, "yellow")
        result = run([sys.executable, str(gate.script)])
        if result.returncode:
            failures += 1
            if result.stdout:
                sys.stdout.write(result.stdout)
            if result.stderr:
                sys.stderr.write(result.stderr)
            log("FAIL", gate.name, "red")
            if not keep_going:
                return failures
            continue
        if result.stdout:
            sys.stdout.write(result.stdout)
        log("PASS", gate.name, "green")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description="Compile and run Taokari obfuscation tests.")
    parser.add_argument("--clang", type=Path, default=DEFAULT_CLANG)
    parser.add_argument("--mode", action="append", choices=list(MODE_FLAGS),
                        help="build mode(s); repeatable. default: all")
    parser.add_argument("--case", action="append",
                        help="case name(s) to run; repeatable. default: all")
    parser.add_argument("--keep-going", action="store_true")
    parser.add_argument("--level", type=int, choices=range(0, 5),
                        default=DEFAULT_LEVEL,
                        help="append -taokari-level-<pass>=N for all 6 level-aware "
                             f"passes (indbr/icall/indgv/fla/cie/cfe); default: {DEFAULT_LEVEL}")
    parser.add_argument("--rtti", action="store_true", default=True,
                        help="enable the RTTI eraser (default; needs configs/rtti.json); "
                             "cases flagged no_rtti are skipped")
    parser.add_argument("--no-rtti", action="store_false", dest="rtti",
                        help="disable the RTTI eraser")
    parser.add_argument("--benchmark-out", type=Path,
                        help="write plain-vs-obfuscated compile/runtime/size CSV")
    parser.add_argument("--benchmark-json", type=Path,
                        help="write the same plain-vs-obfuscated measurements "
                             "as JSON (one record per mode/case)")
    args = parser.parse_args()

    clang = args.clang.resolve()
    if clang != DEFAULT_CLANG.resolve():
        print(f"refusing non-local compiler: {clang}", file=sys.stderr)
        print(f"expected: {DEFAULT_CLANG.resolve()}", file=sys.stderr)
        return 2
    if not clang.exists():
        print(f"missing clang: {clang}", file=sys.stderr)
        return 2

    modes = args.mode or list(MODE_FLAGS)
    benchmark_rows: list[dict[str, str | int | float]] = []
    failures = 0
    for mode in modes:
        driver = MODE_DRIVER[mode]
        if not driver.exists():
            print(f"missing driver for mode {mode}: {driver}", file=sys.stderr)
            return 2
        log("MODE", f"{mode} via {driver.name}", "yellow")
        for case in CASES:
            if case.modes is not None and mode not in case.modes:
                continue
            if args.case and case.name not in args.case:
                continue
            tag = f"{mode}/{case.name}"
            log("RUN", tag, "yellow")
            try:
                if args.benchmark_out or args.benchmark_json:
                    start = time.perf_counter()
                    plain_exe = compile_case(driver, case, mode, obfuscate=False)
                    plain_compile = time.perf_counter() - start
                    plain_runtime, plain_run = measure_runtime(plain_exe)
                    plain_size = plain_exe.stat().st_size
                    if plain_run.returncode != case.expected_exit or (
                        case.expected_stdout is not None and plain_run.stdout != case.expected_stdout
                    ):
                        raise RuntimeError(f"plain benchmark run {tag} failed\n{plain_run.stdout}{plain_run.stderr}")

                    start = time.perf_counter()
                    exe = compile_case(driver, case, mode, level=args.level, rtti=args.rtti)
                    obf_compile = time.perf_counter() - start
                    obf_runtime, ran = measure_runtime(exe)
                    benchmark_rows.append({
                        "mode": mode,
                        "case": case.name,
                        "plain_compile_s": f"{plain_compile:.6f}",
                        "obf_compile_s": f"{obf_compile:.6f}",
                        "compile_overhead": f"{(obf_compile / plain_compile if plain_compile else 0):.6f}",
                        "plain_runtime_s": f"{plain_runtime:.6f}",
                        "obf_runtime_s": f"{obf_runtime:.6f}",
                        "runtime_overhead": f"{(obf_runtime / plain_runtime if plain_runtime else 0):.6f}",
                        "plain_size": plain_size,
                        "obf_size": exe.stat().st_size,
                        "size_overhead": f"{(exe.stat().st_size / plain_size if plain_size else 0):.6f}",
                    })
                else:
                    exe = compile_case(driver, case, mode, level=args.level, rtti=args.rtti)
                    log("EXEC", f"{tag}: {exe.relative_to(ROOT)}", "blue")
                    ran = run([str(exe)])
                if ran.returncode != case.expected_exit or (case.expected_stdout is not None and ran.stdout != case.expected_stdout):
                    raise RuntimeError(
                        f"run {tag}\n"
                        f"exit {ran.returncode} expected {case.expected_exit}\n"
                        f"stdout {ran.stdout!r} expected {case.expected_stdout!r}\n"
                        f"{ran.stderr}"
                    )
                log("PASS", tag, "green")
            except Exception as exc:
                failures += 1
                log("FAIL", f"{tag}: {exc}", "red")
                if not args.keep_going:
                    return 1
    if args.benchmark_out and benchmark_rows:
        args.benchmark_out.parent.mkdir(parents=True, exist_ok=True)
        with args.benchmark_out.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(benchmark_rows[0]))
            writer.writeheader()
            writer.writerows(benchmark_rows)
        log("BENCH", str(args.benchmark_out), "green")
    if args.benchmark_json and benchmark_rows:
        args.benchmark_json.parent.mkdir(parents=True, exist_ok=True)
        with args.benchmark_json.open("w", encoding="utf-8") as handle:
            json.dump(benchmark_rows, handle, indent=2)
        log("BENCH", str(args.benchmark_json), "green")
    if not args.case and not args.benchmark_out and not args.benchmark_json:
        failures += run_release_gates(keep_going=args.keep_going)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
