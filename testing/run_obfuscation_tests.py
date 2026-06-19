from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TESTING = ROOT / "testing"
DEFAULT_CLANG = ROOT / "build" / "taokari-ninja" / "bin" / "clang.exe"
VSDEVCMD = Path(r"C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat")

OBF_FLAGS = ["-O2", "-mllvm", "-irobf", "-mllvm", "-irobf-fla", "-mllvm", "-irobf-cse", "-mllvm", "-irobf-cie"]
COLOR = {
    "reset": "\033[0m",
    "blue": "\033[36m",
    "green": "\033[32m",
    "red": "\033[31m",
    "yellow": "\033[33m",
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


def case_path(name: str) -> Path:
    return TESTING / "cases" / name


IMGUI = TESTING / "vendor" / "imgui"
CASES = [
    Case("c_console", (case_path("c_console") / "src" / "main.c",), "c-console:104\n"),
    Case("cpp_console", (case_path("cpp_console") / "src" / "main.cpp",), "cpp-console:144\n"),
    Case("cpp_classes", (case_path("cpp_classes") / "src" / "main.cpp",), "classes:124:taokari\n"),
    Case("cpp_templates", (case_path("cpp_templates") / "src" / "main.cpp",), "templates:55:29\n"),
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
    ),
]


def log(tag: str, message: str, color: str = "reset") -> None:
    print(f"{COLOR[color]}[{tag}]{COLOR['reset']} {message}", flush=True)


def run(command: list[str], *, cwd: Path = ROOT, use_vs_env: bool = False) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    if use_vs_env and VSDEVCMD.exists():
        batch = TESTING / "_with_vs_env.cmd"
        batch.write_text(
            "@echo off\n"
            f'call "{VSDEVCMD}" -arch=x64 -host_arch=x64 >nul\n'
            f"{subprocess.list2cmdline(command)}\n",
            encoding="utf-8",
        )
        command = ["cmd.exe", "/d", "/c", str(batch)]
    return subprocess.run(command, cwd=cwd, text=True, capture_output=True, env=env)


def object_name(source: Path) -> str:
    return "_".join(source.with_suffix("").parts[-4:]) + ".obj"


def compile_case(clang: Path, case: Case) -> Path:
    case_root = case_path(case.name)
    build = case_root / "build"
    obj = case_root / "obj"
    shutil.rmtree(build, ignore_errors=True)
    shutil.rmtree(obj, ignore_errors=True)
    build.mkdir(parents=True)
    obj.mkdir(parents=True)

    objects: list[Path] = []
    for source in case.sources:
        out = obj / object_name(source)
        log("COMPILE", f"{case.name}: {source.relative_to(ROOT)}", "blue")
        is_cpp = source.suffix.lower() in {".cpp", ".cc", ".cxx"}
        cmd = [str(clang), "-c", str(source), "-std=c++17" if is_cpp else "-std=c17"]
        cmd += [f"-I{include}" for include in case.includes]
        if not case.obfuscate_sources or source in case.obfuscate_sources:
            cmd += OBF_FLAGS
        cmd += ["-o", str(out)]
        result = run(cmd, use_vs_env=True)
        if result.returncode:
            raise RuntimeError(f"compile {source}\n{result.stdout}{result.stderr}")
        objects.append(out)

    exe = build / f"{case.name}.exe"
    log("LINK", f"{case.name}: {exe.relative_to(ROOT)}", "blue")
    result = run([str(clang), *map(str, objects), *case.link_flags, "-o", str(exe)], use_vs_env=True)
    if result.returncode:
        raise RuntimeError(f"link {case.name}\n{result.stdout}{result.stderr}")
    return exe


def main() -> int:
    parser = argparse.ArgumentParser(description="Compile and run Taokari obfuscation tests.")
    parser.add_argument("--clang", type=Path, default=DEFAULT_CLANG)
    parser.add_argument("--keep-going", action="store_true")
    args = parser.parse_args()

    clang = args.clang.resolve()
    if not clang.exists():
        print(f"missing clang: {clang}", file=sys.stderr)
        return 2

    failures = 0
    for case in CASES:
        log("RUN", case.name, "yellow")
        try:
            exe = compile_case(clang, case)
            log("EXEC", f"{case.name}: {exe.relative_to(ROOT)}", "blue")
            ran = run([str(exe)])
            if ran.returncode != case.expected_exit or (case.expected_stdout is not None and ran.stdout != case.expected_stdout):
                raise RuntimeError(
                    f"run {case.name}\n"
                    f"exit {ran.returncode} expected {case.expected_exit}\n"
                    f"stdout {ran.stdout!r} expected {case.expected_stdout!r}\n"
                    f"{ran.stderr}"
                )
            log("PASS", case.name, "green")
        except Exception as exc:
            failures += 1
            log("FAIL", f"{case.name}: {exc}", "red")
            if not args.keep_going:
                break
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
