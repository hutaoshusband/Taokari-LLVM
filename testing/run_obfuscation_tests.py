from __future__ import annotations

import argparse
import csv
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
    ReleaseGate("vmp_exe_full_virtualization", TESTING / "scripts" / "verify_vmp_full_virtualization.py"),
    ReleaseGate("vmp_dll_load_and_manual_map", TESTING / "scripts" / "verify_vmp_dll_load.py"),
]

IMGUI = TESTING / "vendor" / "imgui"
CASES = [
    Case("c_console", (case_path("c_console") / "src" / "main.c",), "c-console:104\n"),
    # Arithmetic & logic operator fixture: + - * / %, unary, pre/post
    # inc/dec, all relational operators, short-circuit &&/||/!, ternary on
    # int and FP. Exercises ConstantInt/FP encryption and MBA on add/sub.
    Case("arith_logic", (case_path("arith_logic") / "src" / "main.c",), "arith:6160:5775:42:110:142:301.142857\n"),
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
                if args.benchmark_out:
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
    if not args.case and not args.benchmark_out:
        failures += run_release_gates(keep_going=args.keep_going)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
