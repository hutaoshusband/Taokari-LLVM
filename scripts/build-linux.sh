#!/usr/bin/env bash
# Taokari Linux build + smoke test.
# Configures (if needed), builds clang/opt, and runs a tiny C program under
# a configurable set of IR obfuscation passes to confirm the build works.
# See docs/BUILD_LINUX.md for scope (MIR / native-integrity / RTTI-eraser
# are Windows-only).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="${ROOT}/build/taokari-linux"
SRC="${ROOT}/upstream/taokari/llvm"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"

PASS_FLAGS=(
  -taokari -taokari-fla -taokari-bcf -taokari-mba
  -taokari-cse -taokari-cie -taokari-cfe
  -taokari-indbr -taokari-icall -taokari-indgv -taokari-ocnst -taokari-meta
)

mkdir -p "${BUILD}"

if [[ ! -f "${BUILD}/build.ninja" ]]; then
  echo "== configuring =="
  cmake -S "${SRC}" -B "${BUILD}" -G Ninja \
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
fi

echo "== building clang/opt =="
cmake --build "${BUILD}" --target clang opt -j"${JOBS}"

CLANG="${BUILD}/bin/clang"
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT
SRC_C="${TMP}/smoke.c"
cat > "${SRC_C}" <<'EOF'
#include <stdio.h>
__attribute__((noinline)) int probe(int x) {
  int s = x;
  for (int i = 0; i < x; ++i) s = (s * 13) ^ i;
  return s;
}
int main(void) { printf("linux-smoke:%d\n", probe(7)); return 0; }
EOF

mllvm=()
for f in "${PASS_FLAGS[@]}"; do mllvm+=(-mllvm "$f"); done

echo "== native =="
"${CLANG}" -O2 "${SRC_C}" -o "${TMP}/native" && "${TMP}/native"
echo "== obfuscated =="
"${CLANG}" -O2 "${mllvm[@]}" "${SRC_C}" -o "${TMP}/obf" && "${TMP}/obf"

echo "== linux smoke: ok =="
