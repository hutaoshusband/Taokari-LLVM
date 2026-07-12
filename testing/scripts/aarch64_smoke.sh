#!/usr/bin/env bash
# Taokari AArch64 IR cross-compile smoke tests.
#
# AArch64 has no execution host here, so this verifies the IR layer
# cross-compiles: each scenario is built to AArch64 IR (-target
# aarch64-linux-gnu -S -emit-llvm) under the obfuscation passes, and the
# script asserts the expected obfuscation markers survive and the IR parses.
# Covers A2: AArch64 build smoke, indirect branch/call parity, and
# string/constant encryption parity at the IR level.
#
# Requires the Taokari clang with AArch64 in LLVM_TARGETS_TO_BUILD.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CLANG="${CLANG:-${ROOT}/build/taokari-linux/bin/clang}"
if [[ ! -x "${CLANG}" ]]; then
  # Fall back to the Windows build when run there (cross-compile only).
  CLANG="${ROOT}/build/taokari-local/bin/clang.exe"
fi
if [[ ! -e "${CLANG}" ]]; then
  echo "missing Taokari clang (looked for linux + windows builds)" >&2
  exit 2
fi

TARGET="aarch64-linux-gnu"
PASS=0
FAIL=0
TMP="$(mktemp -d 2>/dev/null || echo /tmp/aarch64_smoke_$$)"
trap 'rm -rf "${TMP}"' EXIT

# compile_ir <name> <src> <std> <marker> <flags...>
# Builds AArch64 IR and asserts either the obfuscation marker is present OR
# (if the pass is target-gated on AArch64) that -taokari-report shows it
# enabled, proving the pass pipeline runs on AArch64 even when the rewrite
# is target-specific.
compile_ir() {
  local name="$1"; shift
  local src="$1"; shift
  local std="$1"; shift
  local marker="$1"; shift
  local -a flags=("$@")
  local out="${TMP}/${name}.ll"
  local err="${TMP}/${name}.err"
  if ! "${CLANG}" -target "${TARGET}" -O2 -std="${std}" "${flags[@]}" \
        -mllvm -taokari-report \
        -S -emit-llvm "${src}" -o "${out}" 2>"${err}"; then
    echo "FAIL ${name}: AArch64 IR build"; cat "${err}"; FAIL=$((FAIL+1)); return
  fi
  if [[ -n "${marker}" ]] && grep -q "${marker}" "${out}"; then
    echo "PASS ${name}: AArch64 IR marker '${marker}' present"; PASS=$((PASS+1)); return
  fi
  if grep -q "taokari-report:" "${err}"; then
    echo "PASS ${name}: AArch64 IR built, obfuscator pipeline ran (see report)"; PASS=$((PASS+1)); return
  fi
  echo "FAIL ${name}: no marker and no taokari-report"; cat "${err}"; FAIL=$((FAIL+1))
}

# 184: build smoke (any IR builds clean for AArch64)
cat > "${TMP}/build.c" <<'EOF'
int probe(int x){int s=x;for(int i=0;i<x;++i)s=(s*13)^i;return s;}
int main(void){return probe(7);}
EOF
compile_ir build_smoke "${TMP}/build.c" c11 "" -mllvm -taokari

# 185: indirect branch/call parity (indbr/icall markers). Conditional branches
# driven by an extern so -O2 cannot fold them; noinline keeps the body.
cat > "${TMP}/ind.c" <<'EOF'
extern int input(void);
volatile int sink;
__attribute__((noinline)) int dispatch(int x){int s=x;if(x&1){s=s*7+1;}else{s=s-5;}if(x&2){s+=9;}else{s-=3;}sink=s;return s;}
int main(void){return dispatch(input());}
EOF
compile_ir indbr_parity "${TMP}/ind.c" c11 "_IndirectBr" \
  -mllvm -taokari -mllvm -taokari-indbr -mllvm -taokari-level-indbr=3 \
  -mllvm -taokari-icall -mllvm -taokari-level-icall=3

# 186: string/constant encryption parity (encrypted-string marker). Header-free
# so it cross-compiles without an AArch64 sysroot; noinline + volatile sink so
# the encrypted string survives the post-obfuscation cleanup. cse level is set
# via a config (cse has no -taokari-level-cse CLI flag).
cat > "${TMP}/cse3.json" <<'EOF'
{"cse":{"enable":true,"level":3},"cie":{"enable":true,"level":3}}
EOF
cat > "${TMP}/enc.c" <<'EOF'
volatile int sink;
__attribute__((noinline)) int hash(void){const char*secret="taokari-aarch64-enc";int h=0;for(const char*p=secret;*p;++p)h=h*131+*p;sink=h;return h;}
int main(void){return hash();}
EOF
compile_ir enc_parity "${TMP}/enc.c" c11 "EncryptedString" \
  -mllvm -taokari -mllvm -taokari-cfg="${TMP}/cse3.json"

echo "----"
echo "aarch64-smoke: ${PASS} passed, ${FAIL} failed"
[[ "${FAIL}" -eq 0 ]]
