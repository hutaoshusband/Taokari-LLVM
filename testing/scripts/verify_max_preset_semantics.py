"""Native-vs-max-preset differential verifier.

The default corpus compiles with the per-pass IR stack at level 4. That does
*not* enable the max-preset fortress knobs: delayed string decrypt/reencrypt,
outlining at probability 100, opaque constants, BCF before+after flattening,
CIE min-const-size 1, or MIR. Those knobs are exactly what `-taokari-max`
and `build_max_protection.bat` turn on, and they are where wrong codegen has
historically leaked through.

This gate compiles the same sources twice (native vs protected) and requires
identical stdout/stderr/exit. It also bisects with `-taokari-max-no-*` when a
full max build mismatches, so a failure names the pass group.

Configs:
  * `-taokari-max -taokari-max-no-vmp` (IR fortress; VMP is annotation-only
    in the production max recipe and is covered by dedicated VMP gates)
  * the `build_max_protection.bat` flag recipe including MIR

Exit: 0 ok | 1 mismatch or compile failure | 2 missing clang
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import subprocess
import tempfile
import time

import _taokari_portable as tp


CLANG = tp.CLANG
CLANGXX = tp.tool("clang++")

# measured walls post loop-15 (assert Windows build): c-max-ir 223-276s,
# cxx-max-ir ~297s; budget set above the observed ceiling with margin
COMPILE_BUDGET_SECONDS = 480
# max-ir compiles are codegen-bound on the flattened body (measured 223-276s
# on the assert Windows build, 15s Linux NDEBUG post loop-15 fixStack/addDest)
COMPILE_TIMEOUT_SECONDS = 600

VS_ENV: dict[str, str] | None = None

MAX_IR_FLAGS = [
    "-mllvm", "-taokari-max",
    "-mllvm", "-taokari-max-no-vmp",
]

TIER_C_FLAGS = [
    "-mllvm", "-taokari",
    "-mllvm", "-taokari-fla", "-mllvm", "-taokari-level-fla=4",
    "-mllvm", "-taokari-bcf", "-mllvm", "-taokari-level-bcf=2",
    "-mllvm", "-taokari-bcf-before-fla", "-mllvm", "-taokari-bcf-after-fla",
    "-mllvm", "-taokari-mba", "-mllvm", "-taokari-mba-prob=40",
    "-mllvm", "-taokari-cie", "-mllvm", "-taokari-level-cie=2",
    "-mllvm", "-taokari-cfe", "-mllvm", "-taokari-level-cfe=2",
    "-mllvm", "-taokari-cse",
    "-mllvm", "-taokari-icall",
    "-mllvm", "-taokari-indbr",
    "-mllvm", "-taokari-indgv",
    "-mllvm", "-taokari-meta", "-mllvm", "-taokari-level-meta=3",
    "-mllvm", "-taokari-mir=dirtybytes,junk,sub,split,fakeprologue",
    "-mllvm", "-taokari-mir-dirtybytes-prob=100",
    "-mllvm", "-taokari-mir-junk-prob=100",
    "-mllvm", "-taokari-mir-sub-prob=100",
]

ABLATION = [
    ("no-fla", ["-mllvm", "-taokari-max-no-fla"]),
    ("no-mba", ["-mllvm", "-taokari-max-no-mba"]),
    ("no-const", ["-mllvm", "-taokari-max-no-const"]),
    ("no-indirects", ["-mllvm", "-taokari-max-no-indirects"]),
    ("no-bcf-before", ["-mllvm", "-taokari-max-no-bcf-before"]),
    ("no-bcf-after", ["-mllvm", "-taokari-max-no-bcf-after"]),
]

C_SOURCE = r"""
#include <stdio.h>
#include <string.h>
#include <stdint.h>

__attribute__((noinline)) int score(const char *s) {
  int acc = 0;
  for (; s && *s; ++s)
    acc = acc * 131 + (unsigned char)*s;
  return acc;
}

__attribute__((noinline)) int local_ptr(void) {
  const char *p = "local-lifetime";
  int a = score(p);
  int b = (int)strlen(p);
  return a + b;
}

__attribute__((noinline)) int used_twice(void) {
  const char *p = "used-twice";
  return score(p) ^ score(p + 5);
}

__attribute__((noinline)) int table_lookup(int i) {
  const char *msgs[] = {"alpha", "bravo", "charlie"};
  return score(msgs[i % 3]);
}

__attribute__((noinline)) const char *pick(int x) {
  return x ? "yes-branch" : "no-branch";
}

__attribute__((noinline)) int arith(int x) {
  int s = 0;
  for (int i = 0; i < 8; ++i) {
    switch (i & 3) {
    case 0: s += x * 17 + 3; break;
    case 1: s ^= x + 0x5a5a; break;
    case 2: s -= x << 2; break;
    default: s += x / 3 + 9; break;
    }
  }
  return s;
}

typedef int (*cb_t)(int);

__attribute__((noinline)) int add7(int x) { return x + 7; }
__attribute__((noinline)) int mul3(int x) { return x * 3; }

int main(void) {
  cb_t fns[2] = {add7, mul3};
  int cb = fns[0](10) + fns[1](4);
  printf("maxsem:%d:%d:%d:%d:%d:%d:%s\n",
         local_ptr(), used_twice(), table_lookup(1),
         score(pick(1)) + score(pick(0)), arith(42), cb, "fmt-ok");
  return 0;
}
"""

CXX_SOURCE = r"""
#include <cstdio>
#include <cstdint>
#include <stdexcept>
#include <string>

__attribute__((noinline)) int score(const char *s) {
  int acc = 0;
  for (; s && *s; ++s)
    acc = acc * 131 + (unsigned char)*s;
  return acc;
}

struct Base {
  virtual ~Base() = default;
  virtual int tag() const = 0;
};

struct A : Base {
  int tag() const override { return score("virt-A"); }
};
struct B : Base {
  int tag() const override { return score("virt-B"); }
};

__attribute__((noinline)) int throw_if(int x) {
  if ((x & 7) == 3)
    throw x;
  return x * 11 + 5;
}

__attribute__((noinline)) int run(int seed) {
  A a;
  B b;
  Base *p = (seed & 1) ? static_cast<Base *>(&a) : static_cast<Base *>(&b);
  int h = p->tag();
  const char *msg = seed & 2 ? "exc-yes" : "exc-no";
  try {
    h ^= throw_if(seed);
  } catch (int v) {
    h ^= v ^ score(msg);
  }
  std::string s(msg);
  h += score(s.c_str());
  return h;
}

int main() {
  std::printf("maxcxx:%d:%d:%d\n", run(1), run(3), run(8));
  return 0;
}
"""


def vs_env() -> dict[str, str]:
    global VS_ENV
    if VS_ENV is not None:
        return VS_ENV
    env = os.environ.copy()
    if tp.VSDEVCMD.exists():
        dump = subprocess.run(
            ["cmd.exe", "/d", "/c",
             f'call "{tp.VSDEVCMD}" -arch=x64 -host_arch=x64 >nul && set'],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        if dump.returncode == 0:
            for line in dump.stdout.splitlines():
                if "=" in line:
                    key, _, value = line.partition("=")
                    env[key] = value
    VS_ENV = env
    return env


def compile_exe(
    clang: Path,
    source: Path,
    output: Path,
    flags: list[str],
    *,
    cxx: bool,
) -> subprocess.CompletedProcess[str]:
    cmd = [str(clang), str(source), "-O2", "-o", str(output)]
    cmd.append("-std=c++17" if cxx else "-std=c17")
    cmd.extend(flags)
    return subprocess.run(
        cmd, cwd=tp.ROOT, env=vs_env(),
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=COMPILE_TIMEOUT_SECONDS,
    )


def run_pair(
    clang: Path,
    src: Path,
    tmp: Path,
    name: str,
    flags: list[str],
    *,
    cxx: bool,
) -> tuple[str, str, int, int, float]:
    native = tmp / f"{name}_native{tp.EXE}"
    protected = tmp / f"{name}_obf{tp.EXE}"
    nbuild = compile_exe(clang, src, native, [], cxx=cxx)
    if nbuild.returncode:
        raise RuntimeError(f"{name} native compile failed\n{nbuild.stdout}{nbuild.stderr}")
    start = time.monotonic()
    pbuild = compile_exe(clang, src, protected, flags, cxx=cxx)
    elapsed = time.monotonic() - start
    if pbuild.returncode:
        raise RuntimeError(
            f"{name} protected compile failed ({elapsed:.1f}s)\n{pbuild.stdout}{pbuild.stderr}"
        )
    nrun = subprocess.run(
        [str(native)], capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=30,
    )
    prun = subprocess.run(
        [str(protected)], capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=30,
    )
    return nrun.stdout, prun.stdout, nrun.returncode, prun.returncode, elapsed


def bisect(clang: Path, src: Path, tmp: Path, name: str, *, cxx: bool) -> str:
    hits: list[str] = []
    for label, extra in ABLATION:
        flags = list(MAX_IR_FLAGS) + extra
        try:
            nout, pout, nrc, prc, _ = run_pair(
                clang, src, tmp, f"{name}_{label}", flags, cxx=cxx
            )
        except RuntimeError as exc:
            hits.append(f"{label}: compile-fail ({exc})")
            continue
        if nrc != prc or nout != pout:
            hits.append(f"{label}: still-mismatch")
        else:
            hits.append(f"{label}: matches")
    return ", ".join(hits) if hits else "ablation produced no data"


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2
    if not CLANGXX.exists():
        print(f"missing clang++: {CLANGXX}", file=sys.stderr)
        return 2

    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="taokari-maxsem-") as tmp_name:
        tmp = Path(tmp_name)
        cfg = tmp / "maxsem.json"
        cfg.write_text(
            '{"randomSeed":"taokari-maxsem-seed-32b!!",'
            '"meta":{"enable":true,"level":3,"releaseStrip":true},'
            '"cse":{"enable":true,"level":4,"stringDelayedDecrypt":true,'
            '"stringDecryptorFlattening":true}}\n',
            encoding="utf-8",
        )
        flatten_flags = [
            "-mllvm", "-taokari", "-mllvm", "-taokari-cse",
            "-mllvm", f"-taokari-cfg={cfg}",
        ]
        tier_c_flags = list(TIER_C_FLAGS) + ["-mllvm", f"-taokari-cfg={cfg}"]
        jobs = [
            ("c-cse-flatten", CLANG, C_SOURCE, False, flatten_flags, False),
            ("c-max-ir", CLANG, C_SOURCE, False, MAX_IR_FLAGS, True),
            ("c-tier-c", CLANG, C_SOURCE, False, tier_c_flags, False),
            ("cxx-max-ir", CLANGXX, CXX_SOURCE, True, MAX_IR_FLAGS, True),
            ("cxx-tier-c", CLANGXX, CXX_SOURCE, True, tier_c_flags, False),
        ]
        for name, clang, source, cxx, flags, do_budget in jobs:
            src = tmp / (name + (".cpp" if cxx else ".c"))
            src.write_text(source, encoding="utf-8")
            print(f"  {name}: compiling...", flush=True)
            try:
                nout, pout, nrc, prc, elapsed = run_pair(
                    clang, src, tmp, name, flags, cxx=cxx
                )
            except subprocess.TimeoutExpired:
                failures.append(f"{name}: compile timed out after {COMPILE_TIMEOUT_SECONDS}s")
                continue
            except RuntimeError as exc:
                failures.append(f"{name}: {exc}")
                continue
            if nrc != prc or nout != pout:
                failures.append(
                    f"{name}: mismatch rc native={nrc} obf={prc} "
                    f"native={nout!r} obf={pout!r}"
                )
                continue
            if do_budget and elapsed > COMPILE_BUDGET_SECONDS:
                failures.append(
                    f"{name}: compile {elapsed:.1f}s > {COMPILE_BUDGET_SECONDS}s budget"
                )
                continue
            print(f"  {name}: ok ({elapsed:.1f}s) {nout.strip()}")

    if failures:
        print("max preset semantics: FAIL", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    print("max preset semantics: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
