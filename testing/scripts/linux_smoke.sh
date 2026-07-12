#!/usr/bin/env bash
# Taokari Linux smoke tests.
# Runs under the Linux CI job (see .github/workflows/ci.yml) after
# scripts/build-linux.sh has produced build/taokari-linux/bin/clang.
# Covers the A1 Linux checkboxes: tiny C, tiny C++, exceptions/RTTI,
# string/constant encryption, indirect call/branch/global, and VMP opt-in.
#
# Each subtest compiles a plain and an obfuscated build with the Taokari
# clang and asserts identical stdout. Exit non-zero on any mismatch.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CLANG="${CLANG:-${ROOT}/build/taokari-linux/bin/clang}"
if [[ ! -x "${CLANG}" ]]; then
  echo "missing Taokari clang at ${CLANG}; run scripts/build-linux.sh first" >&2
  exit 2
fi

PASS=0
FAIL=0
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

IR_FLAGS=(-mllvm -taokari -mllvm -taokari-cse -mllvm -taokari-cie -mllvm -taokari-cfe)
CFLOW_FLAGS=(-mllvm -taokari-fla -mllvm -taokari-bcf -mllvm -taokari-mba)
IND_FLAGS=(-mllvm -taokari-indbr -mllvm -taokari-icall -mllvm -taokari-indgv)

check() {
  local name="$1"; shift
  local src="$1"; shift
  local std="$1"; shift
  local -a flags=("$@")
  local driver="${CLANG}"
  case "${src}" in
    *.cpp|*.cc|*.cxx) driver="${CLANG}++" ;;
  esac
  local plain="${TMP}/${name}.plain"
  local obf="${TMP}/${name}.obf"
  if ! "${driver}" -O2 -std="${std}" "${src}" -o "${plain}" 2>"${TMP}/${name}.perr"; then
    echo "FAIL ${name}: plain build"; cat "${TMP}/${name}.perr"; FAIL=$((FAIL+1)); return
  fi
  if ! "${driver}" -O2 -std="${std}" "${flags[@]}" "${src}" -o "${obf}" 2>"${TMP}/${name}.oerr"; then
    echo "FAIL ${name}: obfuscated build"; cat "${TMP}/${name}.oerr"; FAIL=$((FAIL+1)); return
  fi
  local p o
  p="$("${plain}")"; o="$("${obf}")"
  if [[ "${p}" == "${o}" ]]; then
    echo "PASS ${name}: ${p}"; PASS=$((PASS+1))
  else
    echo "FAIL ${name}: plain='${p}' obf='${o}'"; FAIL=$((FAIL+1))
  fi
}

# 173: tiny C program
cat > "${TMP}/c.c" <<'EOF'
#include <stdio.h>
int fold(int n){int s=0;for(int i=0;i<=n;++i)s+=(i*3)^(i+7);return s;}
int main(void){printf("c:%d\n",fold(7));return 0;}
EOF
check c_smoke    "${TMP}/c.c"      c11  "${IR_FLAGS[@]}" "${CFLOW_FLAGS[@]}"

# 174: tiny C++ program
cat > "${TMP}/cpp.cpp" <<'EOF'
#include <cstdio>
struct Acc{int v; Acc(int x):v(x){} int add(int y){return v+y;}};
int main(){Acc a(40);printf("cpp:%d\n",a.add(2));return 0;}
EOF
check cpp_smoke  "${TMP}/cpp.cpp"  c++17 "${IR_FLAGS[@]}" "${CFLOW_FLAGS[@]}"

# 175: exceptions + RTTI
cat > "${TMP}/exc.cpp" <<'EOF'
#include <cstdio>
#include <stdexcept>
int probe(int x){ if(x<0) throw std::runtime_error("neg"); return x*7; }
int main(){ try { printf("exc:%d\n",probe(5)); } catch(...) { printf("exc:caught\n"); } return 0; }
EOF
check exc_smoke  "${TMP}/exc.cpp"  c++17 "${IR_FLAGS[@]}"

# 176: string/constant encryption
cat > "${TMP}/enc.c" <<'EOF'
#include <stdio.h>
static const char *secret="taokari-linux-enc";
int main(void){int h=0;for(const char*p=secret;*p;++p)h=h*131+*p;printf("enc:%d\n",h);return 0;}
EOF
check enc_smoke  "${TMP}/enc.c"    c11  "${IR_FLAGS[@]}"

# 177: indirect call/branch/global
cat > "${TMP}/ind.c" <<'EOF'
#include <stdio.h>
static int g=42;
static int (*fp)(int);
static int dbl(int x){return x*2;}
int main(void){fp=dbl;int v=fp(g);if(v&1){v+=1;}else{v-=1;}printf("ind:%d\n",v);return 0;}
EOF
check ind_smoke  "${TMP}/ind.c"    c11  "${IND_FLAGS[@]}"

# 178: VMP opt-in function (annotation-only)
cat > "${TMP}/vmp.c" <<'EOF'
#include <stdio.h>
__attribute__((noinline,annotate("+vmp")))
int secret(int x){int s=x;for(int i=0;i<x;++i)s=(s*13)^i;return s;}
int main(void){printf("vmp:%d\n",secret(6));return 0;}
EOF
check vmp_smoke  "${TMP}/vmp.c"    c11  -mllvm -taokari -mllvm -taokari-vmp

echo "----"
echo "linux-smoke: ${PASS} passed, ${FAIL} failed"
[[ "${FAIL}" -eq 0 ]]
