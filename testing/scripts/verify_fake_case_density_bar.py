"""Fake-case density gnarliness bar (todo.md D2).

A release-blocking measurement gate for control-flow flattening. The pass
inflates a function's CFG with dispatcher machinery and fake cases; this bar
turns that inflation into a hard, falsifiable number instead of a feeling.

Contract (same source, fla L3, -emit-llvm):
  * The obfuscated IR carries flattening-generated blocks
    (switchFakeCaseGate / switchFakeSucc / switchTrap / .tao.clone /
    switchBucket / switchNestedDispatch) while a plain build carries none.
  * The obfuscated CFG is denser than the plain one by at least a threshold
    ratio (fake blocks >= DENSITY * real blocks), so flattening is provably
    adding gnarliness, not a no-op.
  * The obfuscated binary runs and matches native output.

Exit: 0 ok | 1 contract failure | 2 missing clang.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
VSDEVCMD = tp.VSDEVCMD

FAKE_MARKERS = (
    "switchFakeCaseGate",
    "switchFakeSucc",
    "switchTrap",
    ".tao.clone",
    "switchBucket",
    "switchNestedDispatch",
    "switchDefault",
)
LABEL_RE = re.compile(r"^[^\S\n]*(?P<name>[A-Za-z0-9_.$-]+):\s*(?:;.*)?$",
                      re.MULTILINE)
FAKE_RE = re.compile(
    "|".join(re.escape(m) for m in FAKE_MARKERS))

MIN_FAKE_MARKERS = 8
MIN_INFLATION = 1.5


def run(command: list[str], *, cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    if VSDEVCMD.exists():
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
            return subprocess.run(
                ["cmd.exe", "/d", "/c", str(batch)], cwd=cwd,
                text=True, capture_output=True,
            )
        finally:
            batch.unlink(missing_ok=True)
    return subprocess.run(command, cwd=cwd, text=True, capture_output=True)


def must(result: subprocess.CompletedProcess[str], label: str) -> bool:
    if result.returncode:
        sys.stderr.write(f"{label} failed:\n")
        sys.stderr.write(result.stdout + result.stderr)
        return False
    return True


def mllvm(flags: list[str]) -> list[str]:
    out = []
    for f in flags:
        out += ["-mllvm", f]
    return out


SOURCE = r"""
#include <stdio.h>

__attribute__((noinline)) int probe(int x) {
  int s = x;
  if (x > 4) { s = s * 3 + 1; } else { s = s - 2; }
  for (int i = 0; i < x; ++i) { s += (i ^ x); }
  switch (x % 3) {
    case 0: s += 1; break;
    case 1: s += 5; break;
    default: s += 9; break;
  }
  return s;
}

int main(void) {
  printf("fakedens:%d:%d\n", probe(7), probe(10));
  return 0;
}
"""


def block_count(text: str) -> int:
    return len(LABEL_RE.findall(text))


def fake_count(text: str) -> int:
    return len(FAKE_RE.findall(text))


def main() -> int:
    if not CLANG.exists():
        print(f"missing clang: {CLANG}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-fakedens-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "fakedens.c"
        src.write_text(SOURCE, encoding="utf-8")

        plain_ir = tmp / "plain.ll"
        if not must(run([str(CLANG), str(src), "-O2", "-fno-discard-value-names",
                         "-S", "-emit-llvm", "-o", str(plain_ir)]),
                    "plain emit-llvm"):
            return 1
        plain_text = plain_ir.read_text(encoding="utf-8", errors="ignore")
        plain_blocks = block_count(plain_text)
        plain_fakes = fake_count(plain_text)

        cfg = tmp / "fla3.json"
        cfg.write_text(json.dumps({"fla": {"enable": True, "level": 3}}),
                       encoding="utf-8")
        obf_ir = tmp / "fla3.ll"
        if not must(run([str(CLANG), str(src), "-O2", "-fno-discard-value-names",
                         *mllvm(["-taokari", "-taokari-fla",
                                 f"-taokari-cfg={cfg}"]),
                         "-S", "-emit-llvm", "-o", str(obf_ir)]),
                    "fla emit-llvm"):
            return 1
        obf_text = obf_ir.read_text(encoding="utf-8", errors="ignore")
        obf_blocks = block_count(obf_text)
        obf_fakes = fake_count(obf_text)

        if plain_fakes:
            print(f"FAIL: plain IR already contains {plain_fakes} fake markers; "
                  f"marker set is not flattening-specific", file=sys.stderr)
            return 1
        if obf_fakes < MIN_FAKE_MARKERS:
            print(f"FAIL: obfuscated IR has only {obf_fakes} fake markers "
                  f"(need >= {MIN_FAKE_MARKERS}); flattening is not injecting "
                  f"enough fake cases", file=sys.stderr)
            return 1
        if obf_blocks < plain_blocks:
            print(f"FAIL: obfuscated CFG shrank ({obf_blocks} < {plain_blocks} "
                  f"plain blocks)", file=sys.stderr)
            return 1
        inflation = obf_blocks / plain_blocks if plain_blocks else 0.0
        if inflation < MIN_INFLATION:
            print(f"FAIL: fake-case density too low: fla {obf_blocks} blocks vs "
                  f"{plain_blocks} plain = {inflation:.2f}x "
                  f"(need >= {MIN_INFLATION}x)", file=sys.stderr)
            return 1

        plain_exe = tmp / "plain.exe"
        if not must(run([str(CLANG), str(src), "-O2", "-o", str(plain_exe)]),
                    "plain build"):
            return 1
        plain_run = run([str(plain_exe)])
        if plain_run.returncode:
            sys.stderr.write("plain run failed\n")
            return 1

        obf_exe = tmp / "fla3.exe"
        if not must(run([str(CLANG), str(src), "-O2",
                         *mllvm(["-taokari", "-taokari-fla",
                                 f"-taokari-cfg={cfg}"]),
                         "-o", str(obf_exe)]), "fla build"):
            return 1
        obf_run = run([str(obf_exe)])
        if obf_run.returncode or obf_run.stdout != plain_run.stdout:
            print(f"FAIL: fla runtime mismatch rc={obf_run.returncode} "
                  f"out={obf_run.stdout!r} expected={plain_run.stdout!r}",
                  file=sys.stderr)
            return 1

    print(f"fake-case-density-bar: ok (plain {plain_blocks} blocks -> fla "
          f"{obf_blocks} blocks = {inflation:.2f}x, {obf_fakes} fake markers "
          f">= {MIN_FAKE_MARKERS}, runtime matches native)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
