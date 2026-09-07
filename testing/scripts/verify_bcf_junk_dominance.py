"""Verify BCF junk-loop allocas dominate their users after FLA.

addJunkLoop used to place bcf.fake.i / bcf.fake.acc allocas in the BCF fake
block. After Flattening rewires the function into the dispatcher, the fake
block and bcf.fake.loop.* become dispatcher siblings, so the alloca no longer
dominates its loop-block users (verify: "Instruction does not dominate all
uses!"). NDEBUG builds never assert on the downstream InstCombine trip, so the
gate checks the IR text directly instead of relying on an assert build.

Contract (default stack, N=4 compiles, -mllvm -print-changed):
  * Every compile must succeed and print an ObfuscationPassManagerPass dump.
  * At least one dump must contain BCF junk allocas (taokari.bcf.slot marker
    or bcf.fake.* name), otherwise the gate cannot exercise the defect.
  * Every such alloca must sit in the function's entry block, or every
    load/store that references it must live in the alloca's own block.

Zero-eligibility probe (BCF-only flags, no FLA so a single-block function
cannot be fattened into BCF-eligible shape):
  * A single-basic-block function has no BCF-eligible block (the entry block
    is excluded by construction), so BCF must not emit a taokari.bcf.slot
    alloca into it.
  * The same compile must still select >=1 block somewhere in the module,
    proving BCF ran; otherwise the probe cannot exercise the contract.

Exit: 0 ok | 1 contract failure | 2 missing clang.
"""
from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

ROOT = tp.ROOT
CLANG = tp.CLANG
VSDEVCMD = tp.VSDEVCMD

RUNS = 4
DUMP_MARKER = "*** IR Dump After ObfuscationPassManagerPass on [module] ***"

SOURCE = r"""
#include <stdio.h>

volatile int g_sink = 3;

__attribute__((noinline)) int mix(int x) {
  int y = x;
  for (int i = 0; i < 4; ++i) {
    if ((x ^ i) & 1) y = y * 3 + g_sink;
    else y = y * 5 - g_sink;
    switch (y & 3) {
    case 0: y += 7; break;
    case 1: y -= 3; break;
    case 2: y ^= 11; break;
    default: y *= 2; break;
    }
  }
  g_sink += y;
  return y ^ g_sink;
}

__attribute__((noinline)) int flat(int x) {
  return x * 3 + g_sink;
}

int main(void) {
  int a = mix(9);
  int b = mix(14);
  int c = flat(a ^ b);
  if (a > 1000) a = -a;
  printf("bcfjd:%d\n", a + b + c);
  return 0;
}
"""

FLAGS = [
    "-O2", "-std=c17", "-c", "-mllvm", "-taokari",
    "-mllvm", "-taokari-indbr", "-mllvm", "-taokari-icall",
    "-mllvm", "-taokari-indgv", "-mllvm", "-taokari-fla",
    "-mllvm", "-taokari-bcf", "-mllvm", "-taokari-mba",
    "-mllvm", "-taokari-cse", "-mllvm", "-taokari-cie",
    "-mllvm", "-taokari-cfe",
]
for p in ("indbr", "icall", "indgv", "fla", "bcf", "mba", "cie", "cfe"):
    FLAGS += [f"-mllvm", f"-taokari-level-{p}=4"]

BCF_ONLY_FLAGS = [
    "-O2", "-std=c17", "-c", "-mllvm", "-taokari",
    "-mllvm", "-taokari-bcf", "-mllvm", "-taokari-level-bcf=4",
]
ZERO_ELIGIBLE_FN = "flat"
PROBE_RUNS = 2

LABEL_RE = re.compile(r"^\s*([A-Za-z0-9_.$-]+):\s*(;.*)?$")
FUNC_RE = re.compile(r"^define\b[^{]*@([^\s(]+)[^{]*\{")
ALLOCA_RE = re.compile(r"^\s+%([^\s=]+)\s*=\s*alloca\b")


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    if tp.IS_WINDOWS and VSDEVCMD.exists():
        with tempfile.NamedTemporaryFile(
            "w", suffix=".cmd", delete=False, encoding="utf-8"
        ) as handle:
            batch = Path(handle.name)
            handle.write(
                "@echo off\n"
                f'call "{VSDEVCMD}" -arch=x64 -host_arch=x64 >nul\n'
                f"{subprocess.list2cmdline(command)}\n"
                "exit /b %ERRORLEVEL%\n"
            )
        try:
            return subprocess.run(["cmd.exe", "/d", "/c", str(batch)],
                                  cwd=ROOT, text=True, capture_output=True)
        finally:
            batch.unlink(missing_ok=True)
    return subprocess.run(command, cwd=ROOT, text=True, capture_output=True)


def extract_dump(log_text: str) -> str:
    starts = [m.start() for m in re.finditer(
        re.escape(DUMP_MARKER), log_text)]
    if not starts:
        return ""
    body = log_text[starts[-1] + len(DUMP_MARKER):]
    cut = body.find("*** ")
    return body[:cut] if cut >= 0 else body


def split_functions(module: str) -> list[str]:
    fns, cur = [], None
    for line in module.splitlines():
        if FUNC_RE.match(line):
            cur = [line]
        elif cur is not None:
            cur.append(line)
            if line.strip() == "}":
                fns.append("\n".join(cur))
                cur = None
    return fns


def parse_blocks(fn_text: str) -> tuple[str, dict[str, list[str]]]:
    lines = fn_text.splitlines()
    blocks: dict[str, list[str]] = {}
    cur = "__entry__"
    blocks[cur] = []
    for line in lines[1:]:
        m = LABEL_RE.match(line)
        if m:
            cur = m.group(1)
            blocks.setdefault(cur, [])
        else:
            blocks[cur].append(line)
    if not blocks["__entry__"]:
        entry = next(b for b in blocks if b != "__entry__")
        del blocks["__entry__"]
        return entry, blocks
    return "__entry__", blocks


def is_bcf_junk_alloca(name: str, line: str) -> bool:
    # -O2 NDEBUG builds discard value names, so key on the name-independent
    # taokari.bcf.slot marker first; the bcf.fake.* prefix covers assert
    # builds and pre-marker emissions.
    return "taokari.bcf.slot" in line or name.startswith("bcf.fake.")


def check_module(module: str) -> tuple[int, list[str]]:
    violations: list[str] = []
    checked = 0
    for fn in split_functions(module):
        entry, blocks = parse_blocks(fn)
        alloca_home: dict[str, str] = {}
        for blk, body in blocks.items():
            for l in body:
                m = ALLOCA_RE.match(l)
                if m and is_bcf_junk_alloca(m.group(1), l):
                    alloca_home[m.group(1)] = blk
        if not alloca_home:
            continue
        checked += len(alloca_home)
        for name, home in alloca_home.items():
            if home == entry:
                continue
            pat = re.compile("%" + re.escape(name) + r"(?![\w.$-])")
            for blk, body in blocks.items():
                if blk == home:
                    continue
                for l in body:
                    if pat.search(l):
                        violations.append(
                            f"{name}: alloca in '{home}', use in '{blk}': "
                            f"{l.strip()[:80]}")
    return checked, violations


def bcf_slot_allocas(fn_text: str) -> list[str]:
    _, blocks = parse_blocks(fn_text)
    hits = []
    for _, body in blocks.items():
        for l in body:
            m = ALLOCA_RE.match(l)
            if m and is_bcf_junk_alloca(m.group(1), l):
                hits.append(l.strip())
    return hits


def check_zero_eligibility(src: Path, tmp: Path) -> int:
    for i in range(PROBE_RUNS):
        obj = tmp / f"zero{i}.obj"
        result = run([str(CLANG), str(src), *BCF_ONLY_FLAGS,
                      "-mllvm", "-print-changed", "-o", str(obj)])
        if result.returncode:
            print(f"FAIL: zero-eligibility compile {i} "
                  f"rc={result.returncode}", file=sys.stderr)
            sys.stderr.write(result.stdout + result.stderr[-4000:])
            return 1
        module = extract_dump(result.stderr)
        if not module:
            print(f"FAIL: zero-eligibility compile {i} produced no "
                  f"ObfuscationPassManagerPass dump", file=sys.stderr)
            return 1
        zero_fn = [f for f in split_functions(module)
                   if re.search(r"^define[^{]*@" + ZERO_ELIGIBLE_FN + r"\(",
                                f, re.M)]
        if not zero_fn:
            print(f"FAIL: zero-eligibility compile {i}: @{ZERO_ELIGIBLE_FN} "
                  f"missing from dump", file=sys.stderr)
            return 1
        hits = bcf_slot_allocas(zero_fn[0])
        if hits:
            print(f"FAIL: zero-eligibility compile {i}: @{ZERO_ELIGIBLE_FN} "
                  f"has no BCF-eligible block but carries BCF slot allocas:",
                  file=sys.stderr)
            for h in hits[:5]:
                print(f"  {h[:100]}", file=sys.stderr)
            return 1
        selected = any(bcf_slot_allocas(f) for f in split_functions(module))
        if not selected:
            print(f"FAIL: zero-eligibility compile {i} selected no block in "
                  f"the whole module; BCF contract not exercised",
                  file=sys.stderr)
            return 1
    return 0


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-bcf-junk-dom-") as tmp_s:
        tmp = Path(tmp_s)
        src = tmp / "bcf_junk_dom.c"
        src.write_text(SOURCE, encoding="utf-8")

        covered = 0
        for i in range(RUNS):
            log = tmp / f"run{i}.log"
            obj = tmp / f"run{i}.obj"
            result = run([str(CLANG), str(src), *FLAGS,
                          "-mllvm", "-print-changed",
                          "-o", str(obj)])
            if result.returncode:
                print(f"FAIL: compile {i} rc={result.returncode}",
                      file=sys.stderr)
                sys.stderr.write(result.stdout + result.stderr[-4000:])
                return 1
            module = extract_dump(result.stderr)
            if not module:
                print(f"FAIL: compile {i} produced no "
                      f"ObfuscationPassManagerPass dump", file=sys.stderr)
                return 1
            checked, violations = check_module(module)
            if violations:
                print(f"FAIL: compile {i} non-dominating bcf.fake allocas:",
                      file=sys.stderr)
                for v in violations[:10]:
                    print(f"  {v}", file=sys.stderr)
                return 1
            if checked:
                covered += 1

        if not covered:
            print(f"FAIL: no compile in {RUNS} runs emitted bcf.fake allocas; "
                  f"gate cannot exercise the defect", file=sys.stderr)
            return 1

        if rc := check_zero_eligibility(src, tmp):
            return rc

    print(f"bcf junk dominance: ok ({covered}/{RUNS} compiles carried "
          f"bcf.fake allocas, all entry-block or same-block uses; "
          f"zero-eligibility probe {PROBE_RUNS}/{PROBE_RUNS} clean)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
