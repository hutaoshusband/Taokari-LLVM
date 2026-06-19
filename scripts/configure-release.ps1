Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$Source = Join-Path $Root "upstream\\taokari\llvm"
$Build = Join-Path $Root "build\\taokari-ninja"

if (-not $env:VCPKG_ROOT) {
  throw "VCPKG_ROOT is not set"
}

cmake -S $Source -B $Build -G Ninja `
  -DCMAKE_CXX_FLAGS="-DLIBXML_STATIC /utf-8 /EHsc" `
  -DCMAKE_C_FLAGS="-DLIBXML_STATIC /utf-8" `
  -DCMAKE_INSTALL_PREFIX="$Build\install" `
  -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded `
  -DCMAKE_BUILD_TYPE=Release `
  -DLLVM_ENABLE_PROJECTS="clang;clang-tools-extra;lld;lldb" `
  -DLLVM_TARGETS_TO_BUILD="X86;AArch64" `
  -DLLVM_ENABLE_RUNTIMES="compiler-rt;openmp" `
  -DCOMPILER_RT_BUILD_ORC=OFF `
  -DLLVM_BUILD_LLVM_C_DYLIB=ON `
  -DPython3_FIND_REGISTRY=NEVER `
  -DLLVM_BUILD_TOOLS=ON `
  -DLLVM_ENABLE_LIBXML2=FORCE_ON `
  -DCLANG_ENABLE_LIBXML2=OFF `
  -DLLVM_ENABLE_RPMALLOC=ON `
  -DLLVM_INCLUDE_TESTS=OFF `
  -DLLVM_INCLUDE_EXAMPLES=OFF `
  -DLLVM_INCLUDE_BENCHMARKS=OFF `
  -DLLVM_ENABLE_ASSERTIONS=OFF `
  -DLLVM_RELEASE_ENABLE_LTO=OFF `
  -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_ROOT\scripts\buildsystems\vcpkg.cmake" `
  -DVCPKG_TARGET_TRIPLET="x64-windows-static"
