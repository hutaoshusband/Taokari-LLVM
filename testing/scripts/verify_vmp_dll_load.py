"""Build and load a DLL containing a VMP-protected export."""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
VSDEVCMD = tp.VSDEVCMD

DLL_SOURCE = r"""
#define VMP __attribute__((noinline, annotate("+vmp")))

__declspec(dllexport) VMP int vm_dll_add(int a, int b) {
  int x = (a + b) ^ 0x55;
  x = (x * 3) - (a & 7);
  return x + 11;
}
"""

LOADER_SOURCE = r"""
#include <windows.h>

typedef int (__cdecl *vm_dll_add_t)(int, int);

int main(void) {
  HMODULE dll = LoadLibraryA("vmp_probe.dll");
  if (!dll)
    return 10;
  vm_dll_add_t fn = (vm_dll_add_t)GetProcAddress(dll, "vm_dll_add");
  if (!fn)
    return 11;
  int got = fn(17, 25);
  FreeLibrary(dll);
  return got == ((((17 + 25) ^ 0x55) * 3) - (17 & 7) + 11) ? 0 : 12;
}
"""

MANUAL_LOADER_SOURCE = r"""
#include <stdint.h>
#include <string.h>
#include <windows.h>

#if !defined(_M_X64) && !defined(__x86_64__)
#error manual mapper test expects x64
#endif

typedef int (__cdecl *vm_dll_add_t)(int, int);
typedef BOOL (WINAPI *DllMainT)(HINSTANCE, DWORD, LPVOID);
typedef VOID (NTAPI *TlsCallbackT)(PVOID, DWORD, PVOID);

static DWORD protect_for(DWORD c) {
  int exec = (c & IMAGE_SCN_MEM_EXECUTE) != 0;
  int read = (c & IMAGE_SCN_MEM_READ) != 0;
  int write = (c & IMAGE_SCN_MEM_WRITE) != 0;
  if (exec)
    return write ? PAGE_EXECUTE_READWRITE : (read ? PAGE_EXECUTE_READ : PAGE_EXECUTE);
  return write ? PAGE_READWRITE : (read ? PAGE_READONLY : PAGE_NOACCESS);
}

static BYTE *rva(BYTE *base, DWORD off) {
  return off ? base + off : 0;
}

static BYTE *manual_map(const char *path) {
  HANDLE f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
  if (f == INVALID_HANDLE_VALUE)
    return 0;
  DWORD size = GetFileSize(f, 0);
  BYTE *file = (BYTE *)HeapAlloc(GetProcessHeap(), 0, size);
  DWORD got = 0;
  if (!file || !ReadFile(f, file, size, &got, 0) || got != size) {
    CloseHandle(f);
    return 0;
  }
  CloseHandle(f);

  IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)file;
  IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(file + dos->e_lfanew);
  BYTE *image = (BYTE *)VirtualAlloc(0, nt->OptionalHeader.SizeOfImage,
                                     MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  if (!image)
    return 0;
  memcpy(image, file, nt->OptionalHeader.SizeOfHeaders);

  IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
  for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
    if (sec[i].SizeOfRawData)
      memcpy(image + sec[i].VirtualAddress, file + sec[i].PointerToRawData,
             sec[i].SizeOfRawData);
  }
  HeapFree(GetProcessHeap(), 0, file);

  uint64_t delta = (uint64_t)(image - nt->OptionalHeader.ImageBase);
  IMAGE_DATA_DIRECTORY reloc_dir =
      nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
  for (DWORD off = 0; delta && off < reloc_dir.Size;) {
    IMAGE_BASE_RELOCATION *b = (IMAGE_BASE_RELOCATION *)rva(image, reloc_dir.VirtualAddress + off);
    DWORD n = (b->SizeOfBlock - sizeof(*b)) / sizeof(WORD);
    WORD *item = (WORD *)(b + 1);
    for (DWORD i = 0; i < n; ++i) {
      if ((item[i] >> 12) == IMAGE_REL_BASED_DIR64)
        *(uint64_t *)(image + b->VirtualAddress + (item[i] & 0xfff)) += delta;
    }
    off += b->SizeOfBlock;
  }

  IMAGE_DATA_DIRECTORY imp_dir =
      nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  for (IMAGE_IMPORT_DESCRIPTOR *imp = (IMAGE_IMPORT_DESCRIPTOR *)rva(image, imp_dir.VirtualAddress);
       imp && imp->Name; ++imp) {
    HMODULE mod = LoadLibraryA((char *)rva(image, imp->Name));
    if (!mod)
      return 0;
    IMAGE_THUNK_DATA64 *src = (IMAGE_THUNK_DATA64 *)rva(image, imp->OriginalFirstThunk);
    IMAGE_THUNK_DATA64 *dst = (IMAGE_THUNK_DATA64 *)rva(image, imp->FirstThunk);
    if (!src)
      src = dst;
    for (; src && src->u1.AddressOfData; ++src, ++dst) {
      FARPROC p = IMAGE_SNAP_BY_ORDINAL64(src->u1.Ordinal)
          ? GetProcAddress(mod, (LPCSTR)IMAGE_ORDINAL64(src->u1.Ordinal))
          : GetProcAddress(mod, ((IMAGE_IMPORT_BY_NAME *)rva(image, (DWORD)src->u1.AddressOfData))->Name);
      if (!p)
        return 0;
      dst->u1.Function = (uint64_t)p;
    }
  }

  IMAGE_DATA_DIRECTORY tls_dir =
      nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
  if (tls_dir.VirtualAddress) {
    IMAGE_TLS_DIRECTORY64 *tls = (IMAGE_TLS_DIRECTORY64 *)rva(image, tls_dir.VirtualAddress);
    for (TlsCallbackT *cb = (TlsCallbackT *)tls->AddressOfCallBacks; cb && *cb; ++cb)
      (*cb)(image, DLL_PROCESS_ATTACH, 0);
  }

  for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
    DWORD old = 0;
    if (sec[i].Misc.VirtualSize)
      VirtualProtect(image + sec[i].VirtualAddress, sec[i].Misc.VirtualSize,
                     protect_for(sec[i].Characteristics), &old);
  }
  FlushInstructionCache(GetCurrentProcess(), image, nt->OptionalHeader.SizeOfImage);

  if (nt->OptionalHeader.AddressOfEntryPoint) {
    DllMainT entry = (DllMainT)rva(image, nt->OptionalHeader.AddressOfEntryPoint);
    if (!entry((HINSTANCE)image, DLL_PROCESS_ATTACH, 0))
      return 0;
  }
  return image;
}

static void *manual_export(BYTE *image, const char *name) {
  IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)image;
  IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(image + dos->e_lfanew);
  IMAGE_DATA_DIRECTORY dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY *)rva(image, dir.VirtualAddress);
  DWORD *names = (DWORD *)rva(image, exp->AddressOfNames);
  WORD *ords = (WORD *)rva(image, exp->AddressOfNameOrdinals);
  DWORD *funcs = (DWORD *)rva(image, exp->AddressOfFunctions);
  for (DWORD i = 0; i < exp->NumberOfNames; ++i)
    if (strcmp((char *)rva(image, names[i]), name) == 0)
      return rva(image, funcs[ords[i]]);
  return 0;
}

int main(void) {
  BYTE *dll = manual_map("vmp_probe.dll");
  if (!dll)
    return 20;
  vm_dll_add_t fn = (vm_dll_add_t)manual_export(dll, "vm_dll_add");
  if (!fn)
    return 21;
  int got = fn(17, 25);
  return got == ((((17 + 25) ^ 0x55) * 3) - (17 & 7) + 11) ? 0 : 22;
}
"""


def run(cmd: list[str], *, cwd: Path = ROOT,
        use_vs_env: bool = False) -> subprocess.CompletedProcess[str]:
    if use_vs_env and VSDEVCMD.exists():
        with tempfile.NamedTemporaryFile("w", suffix=".cmd", delete=False,
                                         encoding="utf-8") as handle:
            batch = Path(handle.name)
            handle.write("@echo off\n")
            handle.write(f'call "{VSDEVCMD}" -arch=x64 -host_arch=x64 >nul\n')
            handle.write(subprocess.list2cmdline(cmd) + "\n")
        try:
            return subprocess.run(["cmd.exe", "/c", str(batch)], cwd=cwd,
                                  text=True, capture_output=True)
        finally:
            batch.unlink(missing_ok=True)
    return subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-vmp-dll-") as tmp:
        tmpdir = Path(tmp)
        dll_c = tmpdir / "vmp_probe.c"
        loader_c = tmpdir / "loader.c"
        manual_loader_c = tmpdir / "manual_loader.c"
        dll = tmpdir / "vmp_probe.dll"
        loader = tmpdir / "loader.exe"
        manual_loader = tmpdir / "manual_loader.exe"
        dll_c.write_text(DLL_SOURCE, encoding="utf-8")
        loader_c.write_text(LOADER_SOURCE, encoding="utf-8")
        manual_loader_c.write_text(MANUAL_LOADER_SOURCE, encoding="utf-8")

        build_dll = run([
            str(CLANG), str(dll_c), "-shared", "-o", str(dll),
            "-mllvm", "-taokari", "-mllvm", "-taokari-vmp",
        ], use_vs_env=True)
        if build_dll.returncode:
            sys.stderr.write(build_dll.stdout + build_dll.stderr)
            return 1

        build_loader = run([str(CLANG), str(loader_c), "-o", str(loader)],
                           use_vs_env=True)
        if build_loader.returncode:
            sys.stderr.write(build_loader.stdout + build_loader.stderr)
            return 1

        build_manual_loader = run([
            str(CLANG), str(manual_loader_c), "-o", str(manual_loader)
        ], use_vs_env=True)
        if build_manual_loader.returncode:
            sys.stderr.write(build_manual_loader.stdout + build_manual_loader.stderr)
            return 1

        result = run([str(loader)], cwd=tmpdir)
        if result.returncode:
            sys.stderr.write(result.stdout + result.stderr)
            print(f"vmp dll load: FAIL (loader exited {result.returncode})",
                  file=sys.stderr)
            return 1

        manual_result = run([str(manual_loader)], cwd=tmpdir)
        if manual_result.returncode:
            sys.stderr.write(manual_result.stdout + manual_result.stderr)
            print(
                f"vmp dll load: FAIL (manual loader exited {manual_result.returncode})",
                file=sys.stderr,
            )
            return 1

    print("vmp dll load: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
