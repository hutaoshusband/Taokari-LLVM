"""Verify obfuscated code in a dlopen'd shared library (ELF/Linux).

The Windows analogue (verify_exported_c_api.py) builds a DLL and resolves its
exports through LoadLibrary + GetProcAddress. There was no Linux equivalent,
so ELF shared-library protection was only proven by static linking. This
verifier closes that gap: it builds a .so under full obfuscation, loads it
with dlopen, resolves functions via dlsym, and checks the returned results
match the unobfuscated baseline. It exercises:

  * ELF dynamic symbol resolution (PLT/GOT) for the resolved exports.
  * The library's .init_array constructors (a global with a non-trivial
    initializer is read through dlsym and must reflect static init having
    run at load time).
  * Symbol visibility: the exports must be in the dynamic symbol table, and
    an internal (hidden) symbol must NOT leak.
  * Obfuscated code surviving the full PIC + shared-link path.

Contract:
  * baseline build (plain) and obfuscated build both produce a libxxxx.so.
  * a loader dlopen's each lib, resolves three exports + one global, and
    computes a result that must match across plain and obfuscated.
  * readelf confirms the exports are in .dynsym and the hidden symbol is not.

Exit: 0 ok | 1 contract failure | 2 missing clang / not on ELF target.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))

import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
READELF = tp.READELF

# A shared library with an exported API + a hidden internal symbol + a global
# whose value proves .init_array ran at dlopen time.
LIB_SRC = r"""
#include <stdint.h>

static int64_t initialized_at_load = 0;

__attribute__((constructor)) static void on_load(void) {
  initialized_at_load = 0xCAFEBABEULL;
}

__attribute__((visibility("default"))) int32_t tk_add(int32_t a, int32_t b) {
  return a + b + (int32_t)(initialized_at_load & 0xF);
}

__attribute__((visibility("default"))) int32_t tk_lookup(int32_t idx) {
  static const int32_t table[8] = {3, 1, 4, 1, 5, 9, 2, 6};
  if (idx < 0 || idx > 7) return -1;
  int32_t acc = 0;
  for (int32_t i = 0; i <= idx; ++i) acc = acc * 31 + table[i];
  return acc;
}

__attribute__((visibility("default"))) int64_t tk_accumulate(const int32_t *p, int32_t n) {
  int64_t s = 0;
  for (int32_t i = 0; i < n; ++i) s = s * 131 + p[i];
  return s;
}

__attribute__((visibility("default"))) int64_t tk_load_marker(void) {
  return initialized_at_load;
}

__attribute__((visibility("hidden"))) int64_t tk_internal_secret(void) {
  return 0xDEADBEEFULL;
}
"""

LOADER_SRC = r"""
#include <stdint.h>
#include <dlfcn.h>
#include <stdio.h>

typedef int32_t (*add_fn)(int32_t, int32_t);
typedef int32_t (*lookup_fn)(int32_t);
typedef int64_t (*accum_fn)(const int32_t *, int32_t);
typedef int64_t (*marker_fn)(void);

int main(int argc, char **argv) {
  if (argc < 2) { fprintf(stderr, "usage: loader <lib.so>\n"); return 2; }
  void *h = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!h) { fprintf(stderr, "dlopen failed: %s\n", dlerror()); return 3; }
  add_fn    f_add  = (add_fn)   dlsym(h, "tk_add");
  lookup_fn f_look = (lookup_fn)dlsym(h, "tk_lookup");
  accum_fn  f_acc  = (accum_fn) dlsym(h, "tk_accumulate");
  marker_fn f_mark = (marker_fn)dlsym(h, "tk_load_marker");
  /* The hidden symbol must not be resolvable. */
  void *secret = dlsym(h, "tk_internal_secret");
  if (!f_add || !f_look || !f_acc || !f_mark) {
    fprintf(stderr, "dlsym failed: %s\n", dlerror()); return 4;
  }
  int64_t marker = f_mark();
  int32_t a = f_add(10, 20);
  int32_t b = f_look(5);
  int32_t buf[4] = {1, 2, 3, 4};
  int64_t c = f_acc(buf, 4);
  printf("dlopen:%d:%d:%lld:%lld:%d\n", a, b, (long long)c, (long long)marker, secret ? 1 : 0);
  dlclose(h);
  return 0;
}
"""

OBF = ["-mllvm", "-taokari",
       "-mllvm", "-taokari-fla", "-mllvm", "-taokari-level-fla=4",
       "-mllvm", "-taokari-bcf", "-mllvm", "-taokari-level-bcf=2",
       "-mllvm", "-taokari-cse", "-mllvm", "-taokari-cie", "-mllvm", "-taokari-cfe",
       "-mllvm", "-taokari-icall", "-mllvm", "-taokari-level-icall=3",
       "-mllvm", "-taokari-indgv", "-mllvm", "-taokari-level-indgv=3"]


def run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return tp.run(cmd)


def build_lib(tmp: Path, name: str, obf: bool) -> Path:
    src = tmp / f"lib_{name}.c"
    src.write_text(LIB_SRC, encoding="utf-8")
    out = tmp / f"lib{name}.so"
    flags = ["-O2", "-fPIC", "-shared", "-fvisibility=hidden"]
    if obf:
        flags += OBF
    r = run([str(CLANG), str(src), *flags, "-o", str(out)])
    if r.returncode:
        raise RuntimeError(f"build lib {name} (obf={obf})\n{r.stdout}{r.stderr}")
    return out


def main() -> int:
    if os.name == "nt":
        print("dlopen verifier is ELF/Linux-only; skipping on Windows",
              file=sys.stderr)
        return 2
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-dlopen-") as tmp_name:
        tmp = Path(tmp_name)
        loader = tmp / "loader.exe"
        lsrc = tmp / "loader.c"
        lsrc.write_text(LOADER_SRC, encoding="utf-8")
        r = run([str(CLANG), str(lsrc), "-O2", "-ldl", "-o", str(loader)])
        if r.returncode:
            print(f"loader build failed\n{r.stdout}{r.stderr}", file=sys.stderr)
            return 1

        results: dict[str, str] = {}
        for name, obf in (("plain", False), ("obf", True)):
            lib = build_lib(tmp, name, obf)
            ran = run([str(loader), str(lib)])
            if ran.returncode:
                print(f"FAIL  {name}: loader rc={ran.returncode}\n"
                      f"{ran.stdout}{ran.stderr}", file=sys.stderr)
                return 1
            results[name] = ran.stdout.strip()

        # readelf symbol-table checks on the OBF build.
        obf_lib = build_lib(tmp, "obf2", True)
        ds = run([str(READELF), "--dyn-syms", str(obf_lib)])
        if ds.returncode:
            print(f"readelf failed\n{ds.stdout}{ds.stderr}", file=sys.stderr)
            return 1
        for must_export in ("tk_add", "tk_lookup", "tk_accumulate", "tk_load_marker"):
            if must_export not in ds.stdout:
                print(f"FAIL: export {must_export} missing from .dynsym",
                      file=sys.stderr)
                return 1
        if "tk_internal_secret" in ds.stdout:
            print("FAIL: hidden symbol tk_internal_secret leaked into .dynsym",
                  file=sys.stderr)
            return 1

        if results["plain"] != results["obf"]:
            print(f"FAIL: dlopen result mismatch\n  plain={results['plain']!r}\n"
                  f"  obf  ={results['obf']!r}", file=sys.stderr)
            return 1
        if results["plain"].endswith(":1"):
            print("FAIL: hidden symbol was resolvable via dlsym", file=sys.stderr)
            return 1

        marker_ok = ":3405691582:" in results["plain"]  # 0xCAFEBABE from on_load
        if not marker_ok:
            print(f"FAIL: .init_array constructor did not run "
                  f"(result={results['plain']!r})", file=sys.stderr)
            return 1

    print(f"dlopen/dlsym: ok (plain==obf={results['plain']!r}, exports in "
          f".dynsym, hidden symbol not leaked, .init_array ran)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
