# Building Taokari LLVM on Linux

Taokari is a patched LLVM/Clang tree and is portable source. The Windows
x64 build is the primary release path (see `BUILD.md`); this documents a
Linux x86-64 build for development and IR-pass testing.

## Scope

The full obfuscation source (`upstream/taokari/llvm/lib/Transforms/Obfuscation`)
builds on Linux. The IR passes, the new-PM bridge, the config wizard and the
profile/validator verifiers all run. What is **Windows-only** on Linux today:

* The Machine IR (MIR / backend) passes — x86 PE/COFF + MSVC-specific.
* The Native Integrity / post-link `.text` hash patching — PE-oriented.
* The Microsoft RTTI eraser — MSVC ABI only.
* Any release gate that compiles to an `.exe` and runs it under Wine or
  expects `LoadLibrary`/COFF.

IR-level obfuscation (`-taokari-fla`, `-taokari-bcf`, `-taokari-mba`,
`-taokari-cse`, `-taokari-cie`, `-taokari-cfe`, `-taokari-indbr`,
`-taokari-icall`, `-taokari-indgv`, `-taokari-ocnst`, `-taokari-meta`) is
fully supported on Linux.

## Prerequisites (Ubuntu 22.04 / 24.04)

| Tool | Version / install |
| --- | --- |
| GCC or Clang | 14+ (`sudo apt install gcc g++` or `clang`) |
| CMake | 3.20+ (`sudo apt install cmake`) |
| Ninja | (`sudo apt install ninja-build`) |
| Python | 3.10+ (`sudo apt install python3`) |
| libxml2 dev | (`sudo apt install libxml2-dev`) |
| Build tools | (`sudo apt install build-essential`) |

Disk: ~25 GB free for a Release build of clang/lld.

## Configure

```sh
# From the repo root.
cmake -S upstream/taokari/llvm -B build/taokari-linux -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_ENABLE_PROJECTS="clang;clang-tools-extra;lld" \
  -DLLVM_TARGETS_TO_BUILD="X86;AArch64" \
  -DLLVM_ENABLE_RUNTIMES="compiler-rt" \
  -DCOMPILER_RT_BUILD_ORC=OFF \
  -DLLVM_BUILD_LLVM_C_DYLIB=ON \
  -DLLVM_BUILD_TOOLS=ON \
  -DLLVM_ENABLE_LIBXML2=FORCE_ON \
  -DCLANG_ENABLE_LIBXML2=OFF \
  -DLLVM_INCLUDE_TESTS=OFF \
  -DLLVM_INCLUDE_EXAMPLES=OFF \
  -DLLVM_INCLUDE_BENCHMARKS=OFF \
  -DLLVM_ENABLE_ASSERTIONS=OFF
```

Notes:
* `CMAKE_C_COMPILER` / `CMAKE_CXX_COMPILER` default to the system compiler;
  pass `-DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++` to build with
  Clang instead of GCC.
* There is no vcpkg on Linux; libxml2 comes from the system `libxml2-dev`.
* `lldb` is omitted from `LLVM_ENABLE_PROJECTS` to keep the build lighter;
  add it back if you need the debugger.

## Build

```sh
cmake --build build/taokari-linux --target clang opt -j$(nproc)
```

The binaries land in `build/taokari-linux/bin/`.

## Verify

```sh
./build/taokari-linux/bin/clang -O2 -mllvm -taokari -mllvm -taokari-fla \
  -mllvm -taokari-bcf -mllvm -taokari-mba \
  my_program.c -o my_program && ./my_program
```

If the program runs and matches the native output, the IR obfuscation passes
are working on Linux. A tiny smoke script that compiles and runs a C program
under a configurable set of IR passes is provided at
`scripts/build-linux.sh`.

## Common issues

* **`libxml2 not found`** — install `libxml2-dev`, or drop
  `-DLLVM_ENABLE_LIBXML2=FORCE_ON`.
* **Out of memory linking `clang`** — reduce parallelism (`-j4`) or add swap.
* **`aarch64` target errors** — drop `AArch64` from
  `LLVM_TARGETS_TO_BUILD` if you only need x86-64.
