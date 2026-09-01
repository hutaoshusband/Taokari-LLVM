from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
OBJDUMP = tp.tool("llvm-objdump")
VSDEVCMD = tp.VSDEVCMD

SOURCE = r"""
__declspec(dllimport) int imported_callee(int);

static __declspec(noinline) int safe_callee(int x) { return x + 7; }
__declspec(noinline) int public_callee(int x) { return x + 13; }
__declspec(noinline) __attribute__((weak)) int weak_callee(int x) { return x + 11; }
__attribute__((always_inline)) static int always_callee(int x) { return x + 17; }

__declspec(noinline) int entry(int x) {
  return safe_callee(x) + imported_callee(x) + weak_callee(x) +
         public_callee(x) + always_callee(x);
}
"""


def run(command: list[str], *, cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    if VSDEVCMD.exists():
        with tempfile.NamedTemporaryFile("w", suffix=".cmd", delete=False, encoding="utf-8") as handle:
            batch = Path(handle.name)
            handle.write(
                "@echo off\n"
                f'call "{VSDEVCMD}" -arch=x64 -host_arch=x64 >nul\n'
                f"{subprocess.list2cmdline(command)}\n"
                "exit /b %ERRORLEVEL%\n"
            )
        try:
            return subprocess.run(["cmd.exe", "/d", "/c", str(batch)], cwd=cwd, text=True, capture_output=True)
        finally:
            batch.unlink(missing_ok=True)
    return subprocess.run(command, cwd=cwd, text=True, capture_output=True)


def checked(command: list[str]) -> subprocess.CompletedProcess[str]:
    result = run(command)
    if result.returncode:
        print(result.stdout, end="")
        print(result.stderr, end="", file=sys.stderr)
        raise SystemExit(result.returncode)
    return result


def compile_obj(src: Path, out: Path, extra: list[str]) -> None:
    flags = ["-fdeclspec", "-D_GNU_SOURCE"] if not tp.IS_WINDOWS else []
    checked([
        str(CLANG), str(src), "-O2", "-fno-discard-value-names",
        *flags,
        "-mllvm", "-taokari",
        "-mllvm", "-taokari-icall",
        "-mllvm", "-taokari-level-icall=2",
        *extra,
        "-c", "-o", str(out),
    ])


def objdump(obj: Path, *args: str) -> str:
    return checked([str(OBJDUMP), *args, str(obj)]).stdout


def require(text: str, needles: list[str], label: str) -> int:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        print(f"{label} missing: {', '.join(missing)}", file=sys.stderr)
        return 1
    return 0


def reject(text: str, needles: list[str], label: str) -> int:
    present = [needle for needle in needles if needle in text]
    if present:
        print(f"{label} present: {', '.join(present)}", file=sys.stderr)
        return 1
    return 0


def main() -> int:
    if not CLANG.exists() or not OBJDUMP.exists():
        print("missing rebuilt clang/llvm-objdump", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-icall-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "icall_safety.c"
        src.write_text(SOURCE, encoding="utf-8")

        obj = tmp / "icall_safety.obj"
        compile_obj(src, obj, [
            "-mllvm", "-taokari-icall-prob=100",
            "-mllvm", "-taokari-icall-func-prob=100",
        ])
        syms = objdump(obj, "-t")
        relocs = objdump(obj, "-r")
        dis = objdump(obj, "-d")
        if require(syms, [
            "_IndirectCallee_objects",
            "_IndirectCallee_objects_share",
            "__taokari_page_seed",
            "safe_callee",
        ], "symbols"):
            return 1
        if require(relocs, [
            "RELOCATION RECORDS FOR [.data]",
            "IMAGE_REL_AMD64_ADDR64   safe_callee",
            "IMAGE_REL_AMD64_REL32    __imp_imported_callee",
            "IMAGE_REL_AMD64_REL32    weak_callee",
            "IMAGE_REL_AMD64_REL32    public_callee",
        ], "relocations"):
            return 1
        if reject(relocs.split("RELOCATION RECORDS FOR [.data]")[0],
                  ["safe_callee"], "safe direct-call relocation"):
            return 1
        if require(dis, ["callq\t*%rax"], "disassembly"):
            return 1

        for name, extra in {
            "call_prob0": ["-mllvm", "-taokari-icall-prob=0",
                           "-mllvm", "-taokari-icall-func-prob=100"],
            "func_prob0": ["-mllvm", "-taokari-icall-prob=100",
                           "-mllvm", "-taokari-icall-func-prob=0"],
        }.items():
            skipped = tmp / f"{name}.obj"
            compile_obj(src, skipped, extra)
            skipped_syms = objdump(skipped, "-t")
            skipped_dis = objdump(skipped, "-d")
            if reject(skipped_syms + skipped_dis,
                      ["_IndirectCallee_objects", "callq\t*%rax"],
                      name):
                return 1

        cfg = tmp / "icall.json"
        cfg.write_text(
            '{"icall":{"enable":true,"level":2,"probability":0,'
            '"functionProbability":100}}',
            encoding="utf-8",
        )
        cfg_obj = tmp / "icall_cfg.obj"
        compile_obj(src, cfg_obj, ["-mllvm", f"-taokari-cfg={cfg}"])
        if reject(objdump(cfg_obj, "-t") + objdump(cfg_obj, "-d"),
                  ["_IndirectCallee_objects", "callq\t*%rax"],
                  "config probability"):
            return 1

    print("indirect call safety: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
