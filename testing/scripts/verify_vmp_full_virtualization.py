"""Build and validate a fully virtualized max-protection VMP sample."""
from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
import struct
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
STRIP = tp.tool("llvm-strip")
OUT = ROOT / "build" / "vmp-validation"
COMMAND_TIMEOUT_SECONDS = int(os.environ.get("TAOKARI_VMP_VERIFY_TIMEOUT", "180"))
VSDEVCMD = tp.VSDEVCMD
DIRTY_STACK = bytes.fromhex(
    "9c 50 51 48 89 e0 48 8d 48 01 48 0f af c1 a8 01 74 08 0f 0b eb fe cc f1 0f 0b 59 58 9d"
)
DIRTY_STACK_DEC = bytes.fromhex(
    "9c 50 51 48 89 e0 48 8d 48 ff 48 0f af c1 a8 01 74 08 0f 0b eb fe cc f1 0f 0b 59 58 9d"
)
DIRTY_GUARDS = (DIRTY_STACK, DIRTY_STACK_DEC)
OLD_DOUBLE_XOR_DIRTY = bytes.fromhex(
    "9c 50 8a 04 24 34 a7 34 a7 3a 04 24 74 08 0f 0b eb fe cc f1 0f 0b 58 9d"
)
JUNK = bytes.fromhex("9c 50 80 34 24 5a 80 34 24 5a 58 9d")
SUB = bytes.fromhex("9c 50 48 89 e0 48 8d 40 13 48 83 e8 13 58 9d")
UNMODELLED = bytes.fromhex("9c 50 8a 04 24 34 3d 34 3d 3a 04 24 74 08 0f 01 c1 c4 e2 7d 18 c0 58 9d")
FAKEBOUNDS = bytes.fromhex("9c 50 8a 04 24 34 6b 34 6b 3a 04 24 74 0f 55 48 89 e5 48 83 ec 20 c9 c3 55 48 89 e5 5d 58 9d")
SSE_GUARD = bytes.fromhex("9c 50 51 0f c7 f0 8d 48 01 0f af c1 a8 01 74 0d 66 0f 73 d8 07 66 0f 74 c0 66 0f d7 c0 59 58 9d")
MARKER = bytes.fromhex("48 8d 40 00")
SPLIT_MARKER = bytes.fromhex("9c 9d")

SOURCE = r'''
#include <stdint.h>
#include <stdio.h>

#define VMP __attribute__((noinline, annotate("+vmp")))
#define NO_VMP __attribute__((annotate("-vmp")))

VMP int vm_mix(int a, int b) {
  int x = ((a + b) ^ 0x1357) - (a & b);
  return x > 900 ? x - b : x + a;
}

VMP int vm_shift(int a, int b) {
  return (a << (b & 7)) ^ ((uint32_t)a >> (b & 3));
}

VMP int vm_divrem(int a, int b) {
  return b ? (a / b) ^ (a % b) : -99;
}

VMP int vm_cmp(int a, int b) {
  int x = (a ^ b) + 41;
  return x >= 128 ? x - a : x + b;
}

VMP int vm_bits(int a, int b) {
  int x = (a & 0x55AA) | (b ^ 0x33CC);
  return (x ^ (a - b)) + (a | b);
}

VMP int vm_helper(int x) {
  return (x * x) + 17;
}

VMP int vm_call(int a, int b) {
  return vm_helper(a) + vm_helper(b) - vm_helper(a - b);
}

NO_VMP int main(void) {
  int a = 37;
  int b = 11;
  printf("full-vmp:%d:%d:%d:%d:%d:%d:%d\n",
         vm_mix(a, b), vm_shift(a, b), vm_divrem(a, b), vm_cmp(a, b),
         vm_bits(a, b), vm_helper(a), vm_call(a, b));
  return 0;
}
'''

MAX_FLAGS = [
    "-O2",
    "-fno-ident",
    f"-ffile-prefix-map={ROOT}=.",
    f"-fdebug-prefix-map={ROOT}=.",
    f"-fmacro-prefix-map={ROOT}=.",
    "-mllvm", "-taokari-max",
]
if tp.IS_WINDOWS:
    MAX_FLAGS += ["-Wl,/DEBUG:NONE"]

def command_timeout(
    cmd: list[str], timeout: int, exc: subprocess.TimeoutExpired
) -> subprocess.CompletedProcess[str]:
    stdout = exc.stdout or ""
    stderr = exc.stderr or ""
    if isinstance(stdout, bytes):
        stdout = stdout.decode(errors="replace")
    if isinstance(stderr, bytes):
        stderr = stderr.decode(errors="replace")
    stderr += f"\ncommand timed out after {timeout}s: {subprocess.list2cmdline(cmd)}\n"
    return subprocess.CompletedProcess(cmd, 124, stdout, stderr)


def run(
    cmd: list[str], use_vs_env: bool = False, timeout: int = COMMAND_TIMEOUT_SECONDS
) -> subprocess.CompletedProcess[str]:
    if use_vs_env and VSDEVCMD.exists():
        with tempfile.NamedTemporaryFile(
            "w", suffix=".cmd", delete=False, encoding="utf-8"
        ) as handle:
            batch = Path(handle.name)
            handle.write(
                "@echo off\n"
                f'call "{VSDEVCMD}" -arch=x64 -host_arch=x64 >nul\n'
                f"{subprocess.list2cmdline(cmd)}\n"
                "exit /b %ERRORLEVEL%\n"
            )
        try:
            return subprocess.run(
                ["cmd.exe", "/d", "/c", str(batch)],
                cwd=ROOT, text=True, capture_output=True, timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            return command_timeout(cmd, timeout, exc)
        finally:
            batch.unlink(missing_ok=True)
    try:
        return subprocess.run(
            cmd, cwd=ROOT, text=True, capture_output=True, timeout=timeout
        )
    except subprocess.TimeoutExpired as exc:
        return command_timeout(cmd, timeout, exc)


def pe_offsets(data: bytearray) -> tuple[int, int, list[tuple[int, int, int]]]:
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        raise SystemExit("not a PE image")
    sections = struct.unpack_from("<H", data, pe + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe + 20)[0]
    opt = pe + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    data_dirs = opt + (112 if magic == 0x20B else 96)
    sh = opt + opt_size
    ranges: list[tuple[int, int, int]] = []
    for i in range(sections):
        base = sh + i * 40
        virtual_size, rva, raw_size, raw_ptr = struct.unpack_from("<IIII", data, base + 8)
        ranges.append((rva, max(virtual_size, raw_size), raw_ptr))
    return data_dirs + 6 * 8, data_dirs, ranges


def rva_to_offset(rva: int, ranges: list[tuple[int, int, int]]) -> int | None:
    for start, size, raw in ranges:
        if start <= rva < start + size:
            return raw + (rva - start)
    return None


def strip_pe_debug_directory(path: Path) -> None:
    data = bytearray(path.read_bytes())
    debug_dir, _, ranges = pe_offsets(data)
    debug_rva, debug_size = struct.unpack_from("<II", data, debug_dir)
    if debug_rva and debug_size:
        off = rva_to_offset(debug_rva, ranges)
        if off is not None:
            for entry in range(off, off + debug_size, 28):
                if entry + 28 > len(data):
                    break
                size = struct.unpack_from("<I", data, entry + 16)[0]
                ptr = struct.unpack_from("<I", data, entry + 24)[0]
                if ptr and size:
                    for pos in range(ptr, min(ptr + size, len(data))):
                        data[pos] = 0
            for pos in range(off, min(off + debug_size, len(data))):
                data[pos] = 0
        struct.pack_into("<II", data, debug_dir, 0, 0)
        path.write_bytes(data)


def require_no_pe_debug_directory(path: Path) -> None:
    data = bytearray(path.read_bytes())
    debug_dir, _, _ = pe_offsets(data)
    debug_rva, debug_size = struct.unpack_from("<II", data, debug_dir)
    if debug_rva or debug_size:
        raise SystemExit(
            f"PE debug directory still present in {path}: "
            f"rva=0x{debug_rva:x} size=0x{debug_size:x}"
        )


def compile_output(
    src: Path, out: Path, max_protection: bool, *, obj: bool = False
) -> subprocess.CompletedProcess[str]:
    flags = [str(CLANG), str(src), "-o", str(out)]
    if obj:
        flags[2:2] = ["-c"]
    if max_protection:
        flags[2:2] = MAX_FLAGS
        flags[2:2] = ["-Rpass=taokari-vmp", "-Rpass-missed=taokari-vmp"]
    else:
        flags[2:2] = ["-O2"]
    return run(flags, use_vs_env=True)


def require_max_bytes(path: Path) -> None:
    data = path.read_bytes()
    missing = [
        name for name, pattern in (
            ("mir-junk", JUNK),
            ("mir-sub", SUB),
            ("mir-unmodelled", UNMODELLED),
            ("mir-fakebounds", FAKEBOUNDS),
            ("mir-sse", SSE_GUARD),
            ("mir-marker", MARKER),
            ("mir-split", SPLIT_MARKER),
        )
        if pattern not in data
    ]
    if not any(pattern in data for pattern in DIRTY_GUARDS):
        missing.append("mir-dirtybytes")
    if OLD_DOUBLE_XOR_DIRTY in data:
        raise SystemExit(f"old double-xor dirtybytes survived in {path}")
    if missing:
        raise SystemExit(f"missing max-protection bytes in {path}: {', '.join(missing)}")


def require_metadata_clean(path: Path) -> None:
    data = path.read_bytes().lower()
    leaks = [
        item for item in (
            b"c:\\users",
            b"github",
            b"taokari-llvm",
            b"full_vmp_sample.c",
            b"__taokari",
            b"clang version",
        )
        if item in data
    ]
    if leaks:
        names = ", ".join(item.decode("ascii", errors="replace") for item in leaks)
        raise SystemExit(f"metadata leak in {path}: {names}")


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    OUT.mkdir(parents=True, exist_ok=True)
    src = OUT / "full_vmp_sample.c"
    run_id = os.getpid()
    native = OUT / f"full_vmp_native_{run_id}.exe"
    protected = OUT / f"full_vmp_max_vmp_mir_{run_id}.exe"
    protected_obj = OUT / f"full_vmp_max_vmp_mir_{run_id}.obj"
    src.write_text(SOURCE, encoding="utf-8")

    native_build = compile_output(src, native, max_protection=False)
    if native_build.returncode:
        sys.stderr.write(native_build.stdout + native_build.stderr)
        return 1

    max_build = compile_output(src, protected, max_protection=True)
    if max_build.returncode:
        sys.stderr.write(max_build.stdout + max_build.stderr)
        return 1
    strip_run = run([str(STRIP), "--strip-all", str(protected)])
    if strip_run.returncode:
        sys.stderr.write(strip_run.stdout + strip_run.stderr)
        return 1
    if tp.IS_WINDOWS:
        strip_pe_debug_directory(protected)
    obj_build = compile_output(src, protected_obj, max_protection=True, obj=True)
    if obj_build.returncode:
        sys.stderr.write(obj_build.stdout + obj_build.stderr)
        return 1
    require_max_bytes(protected)
    require_max_bytes(protected_obj)
    if tp.IS_WINDOWS:
        require_no_pe_debug_directory(protected)
    require_metadata_clean(protected)

    native_run = run([str(native)])
    max_run = run([str(protected)])
    if native_run.returncode or max_run.returncode:
        sys.stderr.write(native_run.stdout + native_run.stderr)
        sys.stderr.write(max_run.stdout + max_run.stderr)
        return 1
    if native_run.stdout != max_run.stdout:
        print("vmp full virtualization: FAIL (stdout mismatch)", file=sys.stderr)
        print(f"native={native_run.stdout!r}", file=sys.stderr)
        print(f"max   ={max_run.stdout!r}", file=sys.stderr)
        return 1

    target_count = len(re.findall(r"^VMP\s+int\s+vm_", SOURCE, re.MULTILINE))
    remarks = max_build.stdout + max_build.stderr
    virtualized = remarks.count("remark: virtualized")
    skipped = remarks.count("remark: skipped")
    if virtualized != target_count or skipped:
        print(
            f"vmp full virtualization: FAIL ({virtualized}/{target_count} "
            f"virtualized, {skipped} skipped)",
            file=sys.stderr,
        )
        sys.stderr.write(remarks)
        return 1

    print(f"vmp full virtualization: ok ({virtualized}/{target_count})")
    print(f"binary: {protected}")
    print(f"object: {protected_obj}")
    print(max_run.stdout, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
