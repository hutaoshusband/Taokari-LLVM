"""Flattening limit pinning determinism (loop-4 follow-up).

Flattening.cpp draws maxInsts/maxBlocks/maxAllocas from an OS-random
per-compile draw ([base-25%, base+25%]) whenever a config leaves a limit
unpinned. A config that pins only SOME limits therefore gets silent random
protection opt-outs on the unpinned ones (the debuggable_strong_profile
2/5 flake was exactly this on maxAllocas).

Contract:
  * Pinning some fla limits forces the unpinned siblings onto the same
    deterministic behavior as explicitly pinning them at the base value:
    config A (maxInsts+maxBlocks pinned, maxAllocas unpinned) must produce
    the same flatten/no-flatten outcome on every compile as config C64
    (same, plus maxAllocas=64 = the deterministic base).
  * A config that pins maxAllocas high flattens the fixture on every
    compile (positive control: fixture and config path alive).
  * The obfuscated binary matches the plain baseline's output.

Pre-fix, A randomly deviates from C64 (the alloca gate flips on the
[48,80] draw while C64 is constant) and this verifier fails within a few
compiles with overwhelming probability (measured: A flattened 3/12 while
C64 flattened 0/12 in one pre-fix Windows session).

Exit: 0 ok | 1 contract failure | 2 missing clang.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
CLANG = tp.CLANG
VSDEVCMD = tp.VSDEVCMD

RUNS_A = 24
RUNS_C = 8
LOCALS = 68

CFG_A = {"fla": {"enable": True, "maxInsts": 5000, "maxBlocks": 200}}
CFG_C64 = {"fla": {"enable": True, "maxInsts": 5000, "maxBlocks": 200,
                   "maxAllocas": 64}}
CFG_C100 = {"fla": {"enable": True, "maxInsts": 5000, "maxBlocks": 200,
                    "maxAllocas": 100}}
CFG_A2 = {"fla": {"enable": True, "maxAllocas": 100}}


def run(command: list[str], *, cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    if VSDEVCMD.exists():
        with tempfile.NamedTemporaryFile(
            "w", suffix=".cmd", delete=False, encoding="utf-8"
        ) as handle:
            batch = Path(handle.name)
            handle.write(
                "@echo off" + chr(10)
                + "call " + chr(34) + str(VSDEVCMD) + chr(34)
                + " -arch=x64 -host_arch=x64 >nul" + chr(10)
                + subprocess.list2cmdline(command) + chr(10)
                + "exit /b %ERRORLEVEL%" + chr(10)
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
        sys.stderr.write(label + " failed:" + chr(10))
        sys.stderr.write(result.stdout + result.stderr)
        return False
    return True


def mllvm(flags: list[str]) -> list[str]:
    out = []
    for f in flags:
        out += ["-mllvm", f]
    return out


def fixture_src() -> str:
    q = chr(34)
    nl = chr(92) + "n"
    lines = ["#include <stdio.h>",
             "__attribute__((noinline)) int probe(int x) {"]
    lines += [f"  int v{i} = x + {i};" for i in range(LOCALS)]
    lines += [
        "  for (int i = 0; i < x; ++i) {",
        "    v0 = v0 ^ (v1 + i); v1 = v1 ^ (v2 + i); "
        "v2 = v2 ^ (v3 - i); v3 = v3 ^ (v4 + i);",
        "    v4 = v4 ^ (v5 - i); v5 = v5 ^ (v6 + i); "
        "v6 = v6 ^ (v7 - i); v7 = v7 ^ (v0 + i);",
        "  }",
        "  return " + "^".join(f"v{i}" for i in range(LOCALS)) + ";",
        "}",
        "int main(void) { printf(" + q + "flapin:%d" + nl + q
        + ", probe(7)); return 0; }",
    ]
    return chr(10).join(lines) + chr(10)


def emit_ir(src: Path, cfg: Path, out: Path) -> str:
    cmd = [str(CLANG), str(src), "-O0",
           *mllvm(["-taokari", "-taokari-cfg=" + str(cfg)]),
           "-S", "-emit-llvm", "-o", str(out)]
    if not must(run(cmd), "emit-llvm " + cfg.name):
        sys.exit(1)
    return out.read_text(encoding="utf-8", errors="ignore")


def flat_flags(src: Path, cfg: Path, tmp: Path, tag: str, runs: int) -> list[int]:
    flags = []
    for i in range(runs):
        text = emit_ir(src, cfg, tmp / (tag + "_" + str(i) + ".ll"))
        flags.append(1 if "taokari-flattened" in text else 0)
    return flags


def write_cfg(tmp: Path, name: str, obj: dict) -> Path:
    p = tmp / name
    p.write_text(json.dumps(obj), encoding="utf-8")
    return p


def fail(msg: str) -> int:
    print("fla-limit-pin-determinism: FAIL (" + msg + ")", file=sys.stderr)
    return 1


def main() -> int:
    if not CLANG.exists():
        print("missing clang: " + str(CLANG), file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="taokari-flapin-") as tmp_name:
        tmp = Path(tmp_name)
        src = tmp / "flapin.c"
        src.write_text(fixture_src(), encoding="utf-8")

        plain_ir = emit_ir(src, write_cfg(tmp, "empty.json", {}),
                           tmp / "plain.ll")
        allocas = plain_ir.count(" = alloca i32")
        if not 65 <= allocas <= 79:
            return fail("fixture calibration drift: probe has " + str(allocas)
                        + " allocas at -O0, needs 65..79 (inside the "
                        "historical draw range [48,80] with margin)")

        cfg_a = write_cfg(tmp, "cfg_a.json", CFG_A)
        cfg_c64 = write_cfg(tmp, "cfg_c64.json", CFG_C64)
        cfg_c100 = write_cfg(tmp, "cfg_c100.json", CFG_C100)

        c100 = flat_flags(src, cfg_c100, tmp, "c100", RUNS_C)
        if any(f != 1 for f in c100):
            return fail("positive control: maxAllocas=100 flattened "
                        + str(sum(c100)) + "/" + str(RUNS_C)
                        + "; fixture or config path broken")

        c64 = flat_flags(src, cfg_c64, tmp, "c64", RUNS_C)
        if len(set(c64)) != 1:
            return fail("control C64 (maxAllocas=64 pinned) varied: "
                        + str(c64) + "; pinned limits must be deterministic")

        a = flat_flags(src, cfg_a, tmp, "a", RUNS_A)
        if set(a) != set(c64):
            return fail("unpinned maxAllocas deviates from the pinned base: "
                        "A=" + str(a) + " vs C64=" + str(c64) + " over "
                        + str(RUNS_A) + "/" + str(RUNS_C) + " compiles; "
                        "varyDefaultLimit is randomizing a pinned-config pass")

        cfg_a2 = write_cfg(tmp, "cfg_a2.json", CFG_A2)
        a2 = flat_flags(src, cfg_a2, tmp, "a2", RUNS_C)
        if any(f != 1 for f in a2):
            return fail("unpinned maxInsts/maxBlocks skip a fixture well "
                        "under the base limits: A2=" + str(a2) + "; the "
                        "deterministic base must keep flattening eligible")

        plain = tmp / "plain.exe"
        if not must(run([str(CLANG), str(src), "-O0", "-o", str(plain)]),
                    "plain build"):
            return 1
        plain_run = run([str(plain)])
        if plain_run.returncode:
            sys.stderr.write("plain run failed" + chr(10))
            return 1
        obf = tmp / "flapin.exe"
        if not must(run([str(CLANG), str(src), "-O0",
                         *mllvm(["-taokari",
                                 "-taokari-cfg=" + str(cfg_c100)]),
                         "-o", str(obf)]), "obfuscated build"):
            return 1
        obf_run = run([str(obf)])
        if obf_run.returncode or obf_run.stdout != plain_run.stdout:
            return fail("runtime mismatch rc=" + str(obf_run.returncode)
                        + " out=" + repr(obf_run.stdout) + " expected="
                        + repr(plain_run.stdout))

    print("fla-limit-pin-determinism: ok (A==C64 over " + str(RUNS_A)
          + " compiles, positive control flattens, runtime matches native)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
