# Building Taokari LLVM

Taokari is built as a patched LLVM/Clang tree. The build is Windows
x64-first (clang-cl target) and uses CMake + Ninja.

## Prerequisites

| Tool                     | Version / notes                                |
| ------------------------ | ---------------------------------------------- |
| Visual Studio            | 2022 (MSVC 14.5x), with C++ workload.          |
| CMake                    | 3.20+ (the VS component is fine).              |
| Ninja                    | On `%PATH%` (WinGet: `winget install Ninja-build.Ninja`). |
| Python                   | 3.10+ (used by LLVM tablegen and the test harness). |
| vcpkg                    | Set `VCPKG_ROOT` to a vcpkg checkout with `libxml2` installed for the static triple `x64-windows-static`. |
| Disk space               | ~30 GB free for a Release build with all targets. |

`VCPKG_ROOT` must point at a vcpkg installation because LLVM is
configured with `-DLLVM_ENABLE_LIBXML2=FORCE_ON`; vcpkg supplies the
static libxml2 build.

## Configure

The one-shot configure script wires every flag we need:

```powershell
# From the repo root, in a Developer PowerShell for VS 2022.
$env:VCPKG_ROOT = "C:\path\to\vcpkg"
.\scripts\configure-release.ps1
```

What it does, in order:

1. Verifies `VCPKG_ROOT` is set.
2. Locates Ninja under `%LOCALAPPDATA%\Microsoft\WinGet\Links\ninja.exe`.
3. Runs CMake with:
   * Source: `upstream\taokari\llvm`
   * Build:  `build\taokari-local`
   * Generator: Ninja
   * `CMAKE_C_COMPILER=cl`, `CMAKE_CXX_COMPILER=cl`
   * `CMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded` (static CRT)
   * `CMAKE_BUILD_TYPE=Release`
   * `LLVM_ENABLE_PROJECTS="clang;clang-tools-extra;lld;lldb"`
   * `LLVM_TARGETS_TO_BUILD="X86;AArch64"`
   * `LLVM_ENABLE_RUNTIMES="compiler-rt;openmp"`
   * `LLVM_BUILD_LLVM_C_DYLIB=ON`
   * `LLVM_ENABLE_LIBXML2=FORCE_ON` (uses the vcpkg static libxml2)
   * `LLVM_BUILD_TOOLS=ON`

After configure, `build\taokari-local` is a fully populated Ninja
build tree.

## Build

The driver scripts call Ninja with a focused target list (clang, opt,
llvm-config) so incremental builds are fast:

```cmd
scripts\build-clang.cmd
```

This runs, in a `VsDevCmd.bat -arch=x64 -host_arch=x64` shell:

```cmd
cd /d <repo>\build\taokari-local
ninja clang opt llvm-config
```

The freshly built toolchain lands at:

```
build\taokari-local\bin\clang.exe
build\taokari-local\bin\clang-cl.exe
build\taokari-local\bin\opt.exe
build\taokari-local\bin\llvm-config.exe
```

Dev builds used for gate verification should also build the LLVM bin
tools the release gates invoke: `ninja llvm-nm llvm-objdump
llvm-readobj` (they land in the same `bin\`).

## Verifying the build

Run the obfuscation test harness:

```cmd
python testing\run_obfuscation_tests.py --clang build\taokari-local\bin\clang.exe --keep-going
```

This compiles and runs every fixture across `default` / `o2` / `o3` /
`lto` / `clangcl` modes, then runs the release-gate scripts
(`indirect_call_level3`, `vmp_exe_full_virtualization`,
`vmp_dll_load_and_manual_map`). The expected result is all PASS / 0
FAIL.

## Common issues

* **`vcpkg` not found / `libxml2` not built** — make sure `VCPKG_ROOT`
  is set and `vcpkg install libxml2:x64-windows-static` has been run.
* **`VsDevCmd.bat` not found** — the build scripts hard-code the VS
  2022 Community path; edit `scripts\build-clang.cmd` if you use a
  different edition.
* **Ninja "no such file"** — ensure Ninja is on `%PATH%` or fix the
  path inside `scripts\configure-release.ps1`.
* **Linker errors involving `LLVM-C` or `Remarks`** — these are
  DLLs produced because `LLVM_BUILD_LLVM_C_DYLIB=ON`; the build is
  still self-contained, they just sit beside the executables.

## Out of scope

This build is Windows x64 only. A Linux build is possible (the source
tree is portable) but the test harness and several release gates assume
PE/COFF and the MSVC environment; Linux support is tracked as a
follow-on.
