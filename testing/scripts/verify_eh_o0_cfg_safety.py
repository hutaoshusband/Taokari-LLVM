"""EH-heavy C++ must compile and run at -O0 under flattening and BCF.

At -O0, MSVC/Itanium headers emit std:: helpers (current_exception, exception::what)
into the TU. Flattening used to leave a second terminator in the entry block of
those helpers; BCF cloned GEPs without remapping SSA. Both abort codegen.

Contract:
  * exceptions_heavy compiles and matches native under fla-L4, bcf-L4, and the
    full IR stack at -O0.
Exit: 0 ok | 1 contract failure | 2 missing clang.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
SRC = ROOT / "testing" / "cases" / "exceptions_heavy" / "src" / "main.cpp"
WANT = "exc-heavy:123876:30:807:9:8:-103:37:6:-54:12399:43:104:234996\n"


def driver() -> Path:
    if tp.IS_WINDOWS:
        return CLANG
    cpp = CLANG.with_name(CLANG.name.replace("clang", "clang++"))
    return cpp if cpp.exists() else CLANG


def main() -> int:
    if not CLANG.exists() or not SRC.exists():
        print(f"missing clang or fixture: {CLANG} {SRC}", file=sys.stderr)
        return 2

    extra = [] if tp.IS_WINDOWS else ["-fdeclspec", "-D_GNU_SOURCE"]
    configs = [
        ("fla-L4", ["-mllvm", "-taokari", "-mllvm", "-taokari-fla",
                    "-mllvm", "-taokari-level-fla=4"]),
        ("bcf-L4", ["-mllvm", "-taokari", "-mllvm", "-taokari-bcf",
                    "-mllvm", "-taokari-level-bcf=4"]),
        ("full-stack", [
            "-mllvm", "-taokari",
            "-mllvm", "-taokari-fla", "-mllvm", "-taokari-level-fla=4",
            "-mllvm", "-taokari-bcf", "-mllvm", "-taokari-level-bcf=4",
            "-mllvm", "-taokari-mba", "-mllvm", "-taokari-cie",
            "-mllvm", "-taokari-cse", "-mllvm", "-taokari-icall",
            "-mllvm", "-taokari-indbr", "-mllvm", "-taokari-indgv",
        ]),
    ]
    with tempfile.TemporaryDirectory(prefix="taokari-eh-o0-") as tmp_name:
        tmp = Path(tmp_name)
        native = tmp / "native"
        r = tp.run([str(driver()), "-O0", "-std=c++17", *extra, str(SRC),
                    "-o", str(native)])
        if r.returncode:
            print("FAIL native build\n", r.stderr[:400], file=sys.stderr)
            return 1
        nrun = tp.run([str(native)])
        if nrun.returncode or nrun.stdout != WANT:
            print(f"FAIL native run rc={nrun.returncode} out={nrun.stdout!r}",
                  file=sys.stderr)
            return 1
        for label, flags in configs:
            exe = tmp / label
            r = tp.run([str(driver()), "-O0", "-std=c++17", *extra, *flags,
                        str(SRC), "-o", str(exe)])
            if r.returncode:
                print(f"FAIL {label} build\n{r.stderr[:400]}", file=sys.stderr)
                return 1
            ran = tp.run([str(exe)])
            if ran.returncode or ran.stdout != WANT:
                print(f"FAIL {label} rc={ran.returncode} out={ran.stdout!r}",
                      file=sys.stderr)
                return 1
            print(f"ok    {label} -O0 matches native")
    print("eh-o0-cfg-safety: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
