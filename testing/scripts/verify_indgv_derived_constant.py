"""Verify indgv x cse handle derived-constant references to obfuscated globals.

At -Os clang folds `std::string s = "lit"` (range construct) and constant
ptr+offset reads into derived constants -- getelementptr-inbounds constant
expressions of a string global -- instead of bare @.str operand uses. The
indgv page-table rewrite only matches bare GlobalVariable operands and
skips call operands entirely, while cse (ConstantIntEncryption +
StringEncryption) rewrites the global's storage afterwards: a
derived-constant use that escapes the decode rewrite then reads the
encrypted-at-rest bytes. Observed on default/cpp_classes/Os (Linux):
@.str+3 decoded to garbage -> basic_string::_M_create length_error ->
SIGABRT, deterministic 5/5.

Contract:
  * Config A (tightest tripwire): string fixture under
    -mllvm -taokari -mllvm -taokari-cse -mllvm -taokari-indgv with the
    differential sweep's flag order (-O2 then -Os), 3 fresh compiles
    x 1 run each, rc 0 and stdout identical to the plain build.
  * Config B: default full pass stack at -Os (the failing sweep cell), 3 x 1.
  * Config C: default full pass stack at its shipped -O2, 3 x 1.
  * The defect is deterministic; a single crash or mismatch is a failure.

Exit: 0 ok | 1 crash or mismatch | 2 missing toolchain.
"""
from __future__ import annotations

import os
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

CLANGXX = tp.tool("clang++")

SOURCE = """#include <cstdio>
#include <cstring>
#include <string>

__attribute__((noinline)) static unsigned span(const char *beg, const char *end) {
  return (unsigned)(end - beg);
}

int main() {
  std::string name = "taokari";
  const char *lit = "derived-offset-probe";
  unsigned whole = (unsigned)strlen(lit);
  unsigned off = span(lit + 7, lit + whole);
  std::printf("indgv-dc:%zu:%u:%s\\n", name.size(), off, name.c_str());
  return (off != 13 || name != "taokari") ? 7 : 0;
}
"""

MIN_COMBO = ["-taokari", "-taokari-cse", "-taokari-indgv"]
DEFAULT_STACK = ["-taokari", "-taokari-indbr", "-taokari-icall", "-taokari-indgv",
                 "-taokari-fla", "-taokari-bcf", "-taokari-mba", "-taokari-cse",
                 "-taokari-cie", "-taokari-cfe"]
WIN_CRASH_RCS = {3221225477, 3221225622, 3221225727, 3765269347}


def mllvm(flags: list[str]) -> list[str]:
    out = []
    for f in flags:
        out += ["-mllvm", f]
    return out


def compile_exe(src: Path, exe: Path, flags: list[str], tail: list[str]) -> tuple[int, str]:
    obj = exe.with_suffix(".obj" if tp.IS_WINDOWS else ".o")
    r = tp.run([str(CLANGXX), "-c", str(src), "-std=c++17", "-O2",
                *mllvm(flags), *tail, "-o", str(obj)])
    if r.returncode or not obj.exists():
        return r.returncode, f"BUILD_FAIL: {r.stderr[:300]}"
    r = tp.run([str(CLANGXX), str(obj), "-o", str(exe)])
    if r.returncode or not exe.exists():
        return r.returncode, f"LINK_FAIL: {r.stderr[:300]}"
    return 0, ""


def check_case(tmp: Path, src: Path, want_rc: int, want_out: str,
               label: str, flags: list[str], tail: list[str], i: int) -> tuple[str, str]:
    name = f"{label} compile {i}"
    exe = tmp / tp.exe_name(f"{label.replace('+', '_').replace(' ', '_')}_{i}")
    rc, msg = compile_exe(src, exe, flags, tail)
    if rc:
        return name, f"rc={rc} {msg}"
    r = tp.run([str(exe)])
    if r.returncode < 0 or r.returncode in WIN_CRASH_RCS:
        return name, f"crashed rc={r.returncode} out={r.stdout.strip()!r}"
    if r.returncode != want_rc or r.stdout != want_out:
        return name, f"rc={r.returncode} out={r.stdout.strip()!r} want={want_out.strip()!r}"
    return name, ""


def main() -> int:
    if not CLANGXX.exists():
        print(f"missing clang++: {CLANGXX}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-indgv-dc-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "dc.cpp"
        src.write_text(SOURCE, encoding="utf-8")
        plain = tmp / tp.exe_name("plain")
        rc, msg = compile_exe(src, plain, [], [])
        if rc:
            print(f"FAIL plain build rc={rc}: {msg}", file=sys.stderr)
            return 1
        want = tp.run([str(plain)])
        want_rc, want_out = want.returncode, want.stdout
        print(f"  [base] plain rc={want_rc} out={want_out.strip()!r}")

        configs = [
            ("cse+indgv Os", MIN_COMBO, ["-Os"]),
            ("default Os", DEFAULT_STACK, ["-Os"]),
            ("default O2", DEFAULT_STACK, []),
        ]
        jobs = [(tmp, src, want_rc, want_out, label, flags, tail, i)
                for label, flags, tail in configs for i in range(3)]
        failed: list[str] = []
        with ThreadPoolExecutor(max_workers=min(4, (os.cpu_count() or 2))) as pool:
            for name, detail in pool.map(lambda j: check_case(*j), jobs):
                if detail:
                    print(f"  [FAIL] {name}: {detail}", file=sys.stderr)
                    failed.append(name)
                else:
                    print(f"  [ok] {name}")

    if not failed:
        print("indgv derived constant: ok")
        return 0
    print(f"indgv derived constant: FAIL {sorted(failed)}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
