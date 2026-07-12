from __future__ import annotations

import os
import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp


ROOT = tp.ROOT
CLANG = tp.CLANG
READELF = tp.READELF

LEAK_PATH = "/tmp/taokari_meta_source_leak/metadata_fixture.c"
SEED = "taokari-linux-meta-hygiene-test"

C_SOURCE = r"""
#include <stdio.h>
static int internal_helper(int x) { return x * 7 + 1; }
static const int table[4] = {10, 20, 30, 40};
static int counter = 5;
int main(void) {
    counter += internal_helper(3);
    printf("meta:%d:%d\n", counter, table[counter & 3]);
    return 0;
}
"""


def main() -> int:
    if tp.IS_WINDOWS:
        print("meta-linux: skipped on Windows (this gate is Linux-x64 only)")
        return 2
    if not CLANG.exists() or not READELF.exists():
        print(f"missing clang/readelf: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-meta-linux-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "meta.c"
        src.write_text(f'#line 1 "{LEAK_PATH}"\n' + C_SOURCE, encoding="utf-8")
        cfg = tmp / "meta.json"
        cfg.write_text(
            '{"randomSeed":"' + SEED + '",'
            '"meta":{"enabled":true,"level":3,"randomizeSections":true,"releaseStrip":true}}',
            encoding="utf-8",
        )
        flags = ["-mllvm", "-taokari", "-mllvm", "-taokari-meta",
                 "-mllvm", f"-taokari-cfg={cfg}"]

        obf_ir = tmp / "obf.ll"
        r = tp.run([str(CLANG), "-O2", "-fno-discard-value-names", *flags,
                    "-S", "-emit-llvm", str(src), "-o", str(obf_ir)])
        if r.returncode:
            print(r.stderr, end="", file=sys.stderr)
            return r.returncode
        ir = obf_ir.read_text(encoding="utf-8", errors="ignore")

        if LEAK_PATH in ir:
            print(f"source path leaked into IR: {LEAK_PATH}", file=sys.stderr)
            return 1
        if "llvm.ident" in ir or "llvm.commandline" in ir:
            print("llvm.ident / llvm.commandline not stripped", file=sys.stderr)
            return 1
        if re.search(r"DISubprogram|DICompileUnit|llvm.dbg", ir):
            print("debug info not stripped from IR", file=sys.stderr)
            return 1
        if not re.search(r"__mhf_[0-9a-f]+|__mhg_[0-9a-f]+", ir):
            print("private symbols not randomized (no __mhf_/__mhg_ names)", file=sys.stderr)
            return 1

        sec_names = re.findall(r'section "(\.(?:text|rodata|data)\.[0-9a-f]+)"', ir)
        if not sec_names:
            print("section randomization did not fire (no .text.X/.rodata.X/.data.X)", file=sys.stderr)
            return 1
        kinds = {n.split(".")[1] for n in sec_names}
        if not {"text", "rodata", "data"}.issubset(kinds):
            print(f"section randomization incomplete: got {sorted(kinds)}", file=sys.stderr)
            return 1

        obj = tmp / "obf.o"
        r = tp.run([str(CLANG), "-O2", "-fdeclspec", "-D_GNU_SOURCE", *flags,
                    "-c", str(src), "-o", str(obj)])
        if r.returncode:
            print(r.stderr, end="", file=sys.stderr)
            return r.returncode
        if b"internal_helper" in obj.read_bytes():
            print("internal_helper symbol leaked into object", file=sys.stderr)
            return 1

        exe = tmp / "obf"
        r = tp.run([str(CLANG), "-O2", "-fdeclspec", "-D_GNU_SOURCE", *flags,
                    str(src), "-o", str(exe)])
        if r.returncode:
            print(r.stderr, end="", file=sys.stderr)
            return r.returncode
        obf_run = tp.run([str(exe)])
        ref_exe = tmp / "plain"
        tp.run([str(CLANG), "-O2", "-fdeclspec", "-D_GNU_SOURCE", str(src), "-o", str(ref_exe)])
        ref_run = tp.run([str(ref_exe)])
        if obf_run.returncode or obf_run.stdout != ref_run.stdout:
            print(f"output drift: obf={obf_run.stdout!r} ref={ref_run.stdout!r}", file=sys.stderr)
            return 1

    print(f"meta-linux: PASS ({len(sec_names)} randomized sections, "
          f"debug info + source path stripped, runtime matches native)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
