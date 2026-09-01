from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
BIN = tp.BIN
CLANG = tp.CLANG
CLANG_CL = BIN / "clang-cl.exe"
READOBJ = tp.tool("llvm-readobj")
OBJDUMP = tp.tool("llvm-objdump")
READELF = tp.tool("llvm-readelf")
VSDEVCMD = tp.VSDEVCMD
BUILD_DIR = ROOT / "build" / "taokari-local"

LEAK_PATH = "C:/taokari_meta_source_leak/metadata_fixture.cpp"
SEED = "taokari-metadata-hygiene-test"

CPP_SOURCE = r'''
extern "C" __declspec(dllexport) int exported_api(int x) { return x + 3; }
extern "C" int keep_symbol(int x) { return x + 5; }

namespace {
__declspec(noinline) int taokari_internal_helper(int x) { return x * 7; }
__declspec(noinline) int taokari_decryptor_helper(int x) { return x ^ 0x55; }
int IndirectCallee_table_marker = 41;
}

struct SecretRttiClass {
  virtual ~SecretRttiClass() {}
  virtual int value() const { return 19; }
};

int main() {
  SecretRttiClass obj;
  return exported_api(taokari_internal_helper(2)) +
         taokari_decryptor_helper(obj.value()) + keep_symbol(1) +
         IndirectCallee_table_marker == 134 ? 0 : 1;
}
'''

C_SOURCE = r'''
static int taokari_internal_helper(int x) { return x + 9; }
int exported_api(int x) { return taokari_internal_helper(x); }
'''


def run(command: list[str], *, cwd: Path = ROOT, vs: bool = False) -> subprocess.CompletedProcess[str]:
    if vs and VSDEVCMD.exists():
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


def checked(command: list[str], *, cwd: Path = ROOT, vs: bool = False) -> subprocess.CompletedProcess[str]:
    result = run(command, cwd=cwd, vs=vs)
    if result.returncode:
        print(result.stdout, end="")
        print(result.stderr, end="", file=sys.stderr)
        raise SystemExit(result.returncode)
    return result


def build_compiler() -> None:
    checked([
        "ninja", "-C", str(BUILD_DIR), "clang", "llvm-readobj", "llvm-objdump", "llvm-readelf"
    ], vs=True)


def read_bytes(path: Path) -> bytes:
    return path.read_bytes()


def reject_blob(blob: bytes, needles: list[bytes], label: str) -> None:
    found = [n.decode("utf-8", "ignore") for n in needles if n in blob]
    if found:
        raise SystemExit(f"{label} leaked: {', '.join(found)}")


def require_text(text: str, needles: list[str], label: str) -> None:
    missing = [n for n in needles if n not in text]
    if missing:
        raise SystemExit(f"{label} missing: {', '.join(missing)}")


def reject_text(text: str, needles: list[str], label: str) -> None:
    found = [n for n in needles if n in text]
    if found:
        raise SystemExit(f"{label} leaked: {', '.join(found)}")


def meta_flags(config: Path) -> list[str]:
    return [
        "-mllvm", "-taokari",
        "-mllvm", "-taokari-meta",
        "-mllvm", "-taokari-level-meta=3",
        "-mllvm", "-taokari-rtti",
        "-mllvm", f"-taokari-cfg={config}",
    ]


def compile_ir(src: Path, out: Path, config: Path | None) -> None:
    cmd = [str(CLANG), "-x", "c++", "-std=c++17", "-g", "-O0", "-S", "-emit-llvm", str(src), "-o", str(out)]
    if config:
        cmd[1:1] = meta_flags(config)
    checked(cmd, vs=True)


def compile_obj(src: Path, out: Path, config: Path | None, extra: list[str] | None = None) -> None:
    cmd = [str(CLANG), "-x", "c++", "-std=c++17", "-g", "-O0", str(src), "-c", "-o", str(out)]
    if config:
        cmd[1:1] = meta_flags(config)
    if extra:
        cmd[1:1] = extra
    checked(cmd, vs=True)


def compile_exe(src: Path, out: Path, config: Path) -> None:
    cmd = [str(CLANG), "-x", "c++", "-std=c++17", "-O0", str(src), *meta_flags(config), "-o", str(out)]
    checked(cmd, vs=True)


def main() -> int:
    for tool in (CLANG, CLANG_CL, READOBJ, OBJDUMP, READELF):
        if not tool.exists():
            print(f"missing tool: {tool}", file=sys.stderr)
            return 2

    build_compiler()

    with tempfile.TemporaryDirectory(prefix="taokari-meta-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "metadata_fixture.cpp"
        src.write_text(CPP_SOURCE, encoding="utf-8")
        leak_src = tmp / "leak_path_fixture.cpp"
        leak_src.write_text(f'#line 1 "{LEAK_PATH}"\n' + CPP_SOURCE, encoding="utf-8")
        c_src = tmp / "metadata_c_fixture.c"
        c_src.write_text(C_SOURCE, encoding="utf-8")
        config = tmp / "meta.json"
        config.write_text(json.dumps({
            "randomSeed": SEED,
            "meta": {
                "enable": True,
                "level": 3,
                "releaseStrip": True,
                "randomizeSections": True,
                "exportAllowlist": ["keep_symbol"],
            },
            "rtti": {"enable": True},
        }), encoding="utf-8")

        plain_ir = tmp / "plain.ll"
        protected_ir = tmp / "protected.ll"
        compile_ir(leak_src, plain_ir, None)
        compile_ir(leak_src, protected_ir, config)
        require_text(plain_ir.read_text(encoding="utf-8", errors="ignore"), ["llvm.ident", "!dbg", "DIFile"], "plain IR control")
        reject_text(protected_ir.read_text(encoding="utf-8", errors="ignore"), ["llvm.ident", "llvm.commandline", "!dbg", "DIFile", LEAK_PATH], "protected IR")

        protected_obj = tmp / "protected.obj"
        compile_obj(leak_src, protected_obj, config)
        obj_blob = read_bytes(protected_obj)
        reject_blob(obj_blob, [
            b"taokari_internal_helper", b"taokari_decryptor_helper",
            b"IndirectCallee_table_marker", b".?AUSecretRttiClass",
            b"metadata_fixture.cpp", LEAK_PATH.encode(),
        ], "protected COFF object")
        syms = checked([str(OBJDUMP), "-t", str(protected_obj)]).stdout
        require_text(syms, ["keep_symbol", "exported_api"], "allowlisted/exported symbols")
        reject_text(syms, ["taokari_internal_helper", "taokari_decryptor_helper", "IndirectCallee"], "symbol table")
        sections = checked([str(READOBJ), "--sections", str(protected_obj)]).stdout
        require_text(sections, [".text$", ".data$"], "COFF randomized sections")

        exe = tmp / "protected.exe"
        compile_exe(src, exe, config)
        ran = checked([str(exe)])
        if ran.returncode:
            raise SystemExit("protected exe failed")

        elf_obj = tmp / "protected_elf.o"
        checked([
            str(CLANG), "-target", "x86_64-unknown-linux-gnu", "-x", "c",
            "-g", "-O0", str(c_src), *meta_flags(config), "-c", "-o", str(elf_obj)
        ], vs=True)
        elf_sections = checked([str(READELF), "-S", str(elf_obj)]).stdout
        require_text(elf_sections, [".text.", ".data."], "ELF randomized sections")
        reject_blob(read_bytes(elf_obj), [b"taokari_internal_helper"], "ELF object")

        macho_obj = tmp / "protected_macho.o"
        checked([
            str(CLANG), "-target", "x86_64-apple-macosx10.15", "-x", "c",
            "-g", "-O0", str(c_src), *meta_flags(config), "-c", "-o", str(macho_obj)
        ], vs=True)
        macho_sections = checked([str(READOBJ), "--sections", str(macho_obj)]).stdout
        require_text(macho_sections, ["Segment: __TEXT", "Segment: __DATA", "Name: __"], "Mach-O randomized sections")
        reject_blob(read_bytes(macho_obj), [b"taokari_internal_helper"], "Mach-O object")

    print("metadata hygiene: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
