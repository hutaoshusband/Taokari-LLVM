#!/usr/bin/env python3
"""Port verify_*.py gate scripts onto _taokari_portable.

For each matching script: insert `import _taokari_portable as tp` right
after the pathlib import, then rebind CLANG (and LLVM_* tool paths) and
VSDEVCMD to the portable equivalents. Leaves each script's own run() /
checked() helpers in place (they already short-circuit VS env on Linux).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PORT_LINE = "import _taokari_portable as tp\n"

CLANG_WIN = re.compile(
    r'^CLANG\s*=\s*ROOT\s*/\s*"build"\s*/\s*"taokari-local"\s*/\s*"bin"\s*/\s*"clang\.exe"',
    re.M,
)
CLANG_WIN_CL = re.compile(
    r'^CLANG\s*=\s*ROOT\s*/\s*"build"\s*/\s*"taokari-local"\s*/\s*"bin"\s*/\s*"clang-cl\.exe"',
    re.M,
)
CLANG_BIN = re.compile(r'^CLANG\s*=\s*BIN\s*/\s*"clang\.exe"', re.M)
VSDEVCMD = re.compile(
    r'^VSDEVCMD\s*=\s*Path\(\s*r"C:\\Program Files\\Microsoft Visual Studio[^)]*\)',
    re.M,
)
TOOL_WIN = re.compile(
    r'^(LLVM_\w+|OBJDUMP|READELF|READOBJ|NM|AR|OPT)\s*=\s*ROOT\s*/\s*"build"\s*/\s*"taokari-local"\s*/\s*"bin"\s*/\s*"(llvm-\w+|\w+)\.exe"',
    re.M,
)
TOOL_BIN = re.compile(
    r'^(LLVM_\w+|OBJDUMP|READELF|READOBJ|NM|AR|OPT)\s*=\s*BIN\s*/\s*"(llvm-\w+|\w+)\.exe"',
    re.M,
)
BIN_DECL = re.compile(
    r'^BIN\s*=\s*ROOT\s*/\s*"build"\s*/\s*"taokari-local"\s*/\s*"bin"',
    re.M,
)
PATHIMPORT = re.compile(r'^from pathlib import Path\s*$', re.M)


def patch(text: str) -> str:
    if "import _taokari_portable" in text:
        return text
    if not PATHIMPORT.search(text):
        return text
    text = PATHIMPORT.sub("from pathlib import Path\n" + PORT_LINE, text, count=1)

    def clangsub(m):
        return "CLANG = tp.CLANG"

    def clangclsub(m):
        return "CLANG = tp.CLANG_CL"

    def clangbinsub(m):
        return "CLANG = tp.CLANG"

    text = CLANG_WIN.sub(clangsub, text)
    text = CLANG_WIN_CL.sub(clangclsub, text)
    text = CLANG_BIN.sub(clangbinsub, text)

    def toolsub(m):
        var = m.group(1)
        return f'{var} = tp.tool("{m.group(2)}")'

    text = TOOL_WIN.sub(toolsub, text)
    text = TOOL_BIN.sub(toolsub, text)

    def binsub(m):
        return "BIN = tp.BIN"

    text = BIN_DECL.sub(binsub, text)

    def vssub(m):
        return "VSDEVCMD = tp.VSDEVCMD"

    text = VSDEVCMD.sub(vssub, text)

    # Guard run_vs(): on non-Windows there is no cmd.exe / VsDevCmd, so fall
    # back to a plain run(). Detect the function body's own indentation so
    # the injected guard matches (some scripts use 2-space, others 4-space).
    run_vs_sig = re.compile(
        r'^(def run_vs\(command: list\[str\][^)]*\)[^:]*:\s*\n)([ \t]+)',
        re.M,
    )

    def runvssub(m):
        indent = m.group(2)
        inner = " " * (len(indent.expandtabs()) + 2) if len(indent.expandtabs()) <= 2 else indent + "  "
        guard = (
            indent + "if not tp.IS_WINDOWS:\n"
            + inner + "return subprocess.run(command, cwd=cwd, text=True, capture_output=True)\n"
        )
        return m.group(1) + guard + m.group(2)

    text = run_vs_sig.sub(runvssub, text)
    return text


def main(argv):
    targets = sorted(HERE.glob("verify_*.py"))
    if "--apply" not in argv:
        changed = 0
        for t in targets:
            src = t.read_text(encoding="utf-8")
            new = patch(src)
            if new != src:
                changed += 1
        print(f"dry-run: {changed}/{len(targets)} would change")
        return 0
    changed = []
    for t in targets:
        src = t.read_text(encoding="utf-8")
        new = patch(src)
        if new != src:
            t.write_text(new, encoding="utf-8")
            changed.append(t.name)
    print(f"applied to {len(changed)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
