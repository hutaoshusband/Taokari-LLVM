#!/usr/bin/env python3
"""Taokari config wizard.

Generates a JSON config, suggested Clang flags, an annotation guide and an
expected test command from a few high-level answers. Runs interactively
(prompting the user) or non-interactively via CLI flags (for scripting and
the verifier).

Answers:
  platform : windows-x64 | linux-x64 | aarch64
  goal     : dev | balanced | strong | fortress
  perf     : loose | balanced | tight   (compile/runtime budget knob)
  vmp      : off | annotation-only | global

Outputs (written next to --out, or printed if --out is "-"):
  <out>.json        JSON config for -mllvm -taokari-cfg=<path>
  <out>.flags.txt   suggested Clang -mllvm flags (one per line)
  <out>.guide.md    per-function annotation guide
  <out>.test.txt    expected test command

Exit: 0 ok | 1 bad input | 2 missing args.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


PLATFORMS = ("windows-x64", "linux-x64", "aarch64")
GOALS = ("mobile", "dev", "balanced", "strong", "fortress")
PERFS = ("loose", "balanced", "tight")
VMPS = ("off", "annotation-only", "global")


def _pass(enable: bool, level: int, **extra) -> dict:
    out = {"enable": enable, "level": level}
    out.update(extra)
    return out


PROFILES = {
    "mobile": {
        "fla": _pass(False, 0),
        "bcf": _pass(False, 0),
        "mba": _pass(False, 0),
        "icall": _pass(False, 0),
        "indbr": _pass(False, 0),
        "indgv": _pass(False, 0),
        "cie": _pass(True, 1, minConstSize=64),
        "cfe": _pass(False, 0),
        "cse": _pass(True, 1, minStringLength=16),
        "outline": _pass(False, 0),
    },
    "dev": {
        "fla": _pass(False, 0),
        "bcf": _pass(False, 0),
        "mba": _pass(True, 1, probability=30, functionProbability=50),
        "icall": _pass(False, 0),
        "indbr": _pass(False, 0),
        "indgv": _pass(False, 0),
        "cie": _pass(True, 1, minConstSize=16),
        "cfe": _pass(False, 0),
        "cse": _pass(True, 1, minStringLength=8),
        "outline": _pass(False, 0),
    },
    "balanced": {
        "fla": _pass(True, 2, maxInsts=4000),
        "bcf": _pass(True, 1, probability=35, functionProbability=50, loopCount=1),
        "mba": _pass(True, 2, probability=40, functionProbability=100),
        "icall": _pass(True, 2, probability=80),
        "indbr": _pass(True, 2),
        "indgv": _pass(True, 2),
        "cie": _pass(True, 2, minConstSize=8),
        "cfe": _pass(True, 1, minConstSize=8),
        "cse": _pass(True, 2, minStringLength=4),
        "outline": _pass(False, 0),
    },
    "strong": {
        "fla": _pass(True, 3, maxInsts=4000, maxBlocks=200),
        "bcf": _pass(True, 2, probability=50, functionProbability=70, loopCount=2),
        "mba": _pass(True, 2, probability=60, functionProbability=100),
        "icall": _pass(True, 3, probability=90, functionProbability=90),
        "indbr": _pass(True, 3),
        "indgv": _pass(True, 3),
        "cie": _pass(True, 3, minConstSize=8),
        "cfe": _pass(True, 2, minConstSize=8),
        "cse": _pass(True, 3, minStringLength=4, decryptorMba=True,
                     stringDecryptorFlattening=True),
        "outline": _pass(True, 2),
    },
    "fortress": {
        "fla": _pass(True, 4, maxInsts=6000, maxBlocks=300),
        "bcf": _pass(True, 3, probability=70, functionProbability=80, loopCount=3),
        "mba": _pass(True, 3, probability=80, functionProbability=100),
        "icall": _pass(True, 4, probability=100, functionProbability=100),
        "indbr": _pass(True, 4),
        "indgv": _pass(True, 4),
        "cie": _pass(True, 3, minConstSize=8),
        "cfe": _pass(True, 3, minConstSize=8),
        "cse": _pass(True, 3, minStringLength=4, decryptorMba=True,
                     stringDecryptorFlattening=True, stringShardedPool=True,
                     stringFakePools=True, stringDelayedDecrypt=True),
        "outline": _pass(True, 3),
    },
}

PERF_LEVEL_ADJUST = {
    "loose": {"fla": +1, "bcf": +1, "mba": +1},
    "balanced": {},
    "tight": {"fla": -1, "bcf": -1, "mba": -1},
}

PLATFORM_NOTES = {
    "windows-x64": "Windows x64 (full pass support; MIR fortress available).",
    "linux-x64": "Linux x64 (IR passes supported; MIR fortress is x86-only).",
    "aarch64": "AArch64 (IR passes supported; MIR fortress is x86-only; "
               "pointer-auth indirect path available).",
}


def clamp_level(p: dict, delta: int) -> dict:
    if "level" in p and delta:
        p = dict(p)
        p["level"] = max(0, min(4, p["level"] + delta))
    return p


def build_config(goal: str, perf: str, vmp: str) -> dict:
    cfg = {k: dict(v) for k, v in PROFILES[goal].items()}
    adj = PERF_LEVEL_ADJUST[perf]
    for name, delta in adj.items():
        if name in cfg:
            cfg[name] = clamp_level(cfg[name], delta)
    if vmp == "global":
        cfg["vmp"] = _pass(True, 2)
    elif vmp == "annotation-only":
        cfg["vmp"] = _pass(False, 0)
    else:
        cfg["vmp"] = _pass(False, 0)
    return cfg


def config_to_flags(cfg: dict) -> list[str]:
    flags = ["-taokari"]
    for name in ("fla", "bcf", "mba", "icall", "indbr", "indgv", "cie", "cfe",
                 "cse", "outline", "vmp"):
        p = cfg.get(name, {})
        if not p.get("enable"):
            continue
        flags.append(f"-taokari-{name}")
        lvl = p.get("level", 0)
        if lvl:
            flags.append(f"-taokari-level-{name}={lvl}")
    return flags


ANNOTATION_GUIDE = """\
# Taokari annotation guide

Apply annotations to function declarations to override the global config for
a single function. Multiple tokens are space-separated inside one string.

## Common tokens

| Token            | Effect                                                 |
| ---------------- | ------------------------------------------------------ |
| `+vmp`           | Force-enable code virtualisation on this function.    |
| `-vmp`           | Force-disable VMP on this function.                    |
| `+fla` / `-fla`  | Force-enable / disable flattening.                     |
| `^fla=N`         | Set the flattening level (0..4).                       |
| `+bcf` / `-bcf`  | Force-enable / disable bogus control flow.             |
| `+mba` / `-mba`  | Force-enable / disable MBA substitution.               |
| `+icall`         | Force-enable indirect-call indirection.                |
| `+indbr`         | Force-enable indirect-branch indirection.              |
| `+indgv`         | Force-enable indirect-global indirection.              |
| `+strenc`        | Force-enable string encryption.                        |
| `+constenc`      | Force-enable integer-constant encryption.              |
| `noobf`          | Skip ALL obfuscation on this function.                 |

## VMP budget override

`vmp-budget=N` overrides the global bytecode-words cap for one `+vmp`
function only (see docs/CONFIGURATION.md).

## Examples

```cpp
__attribute__((noinline, annotate("+vmp vmp-budget=4096")))
static int sensitive(int x);

__attribute__((noinline, annotate("+fla ^fla=4 +bcf -vmp")))
static int hardened(int x);

__attribute__((annotate("noobf")))
static int hot_path(int x);
```
"""


def build_guide(goal: str, vmp: str) -> str:
    header = (
        f"# Taokari annotation guide (profile: {goal}, vmp: {vmp})\n\n"
        f"This file is generated by taokari-config-wizard.py. It mirrors "
        f"docs/CONFIGURATION.md.\n\n"
    )
    return header + ANNOTATION_GUIDE


def build_test_command(cfg_path: Path, src: str = "main.c") -> str:
    return (
        f'clang {src} -O2 '
        f'-mllvm -taokari-cfg="{cfg_path}" '
        f'-o protected.exe && ./protected.exe\n'
    )


def ask(prompt: str, choices: tuple[str, ...], default: str) -> str:
    while True:
        ans = input(f"{prompt} [{'|'.join(choices)}] (default {default}): ").strip()
        if not ans:
            return default
        if ans in choices:
            return ans
        print(f"  invalid choice: {ans}", file=sys.stderr)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Taokari config wizard")
    parser.add_argument("--platform", choices=PLATFORMS)
    parser.add_argument("--goal", choices=GOALS)
    parser.add_argument("--perf", choices=PERFS)
    parser.add_argument("--vmp", choices=VMPS)
    parser.add_argument("--out", default="-",
                        help="output stem; writes <out>.json/.flags.txt/.guide.md/"
                             ".test.txt. '-' prints to stdout.")
    parser.add_argument("--non-interactive", action="store_true",
                        help="require all of --platform/--goal/--perf/--vmp")
    args = parser.parse_args(argv)

    if args.non_interactive:
        missing = [n for n in ("platform", "goal", "perf", "vmp")
                   if getattr(args, n) is None]
        if missing:
            print(f"non-interactive mode requires: {', '.join('--'+m for m in missing)}",
                  file=sys.stderr)
            return 2

    platform = args.platform or ask("Target platform?", PLATFORMS, "windows-x64")
    goal = args.goal or ask("Protection goal?", GOALS, "balanced")
    perf = args.perf or ask("Performance budget?", PERFS, "balanced")
    vmp = args.vmp or ask("Allow VMP?", VMPS, "off")

    cfg = build_config(goal, perf, vmp)
    flags = config_to_flags(cfg)
    cfg_json = json.dumps(cfg, indent=2, sort_keys=True) + "\n"
    flags_txt = "\n".join(flags) + "\n"
    guide = build_guide(goal, vmp)

    if args.out == "-":
        print("=== config.json ===")
        print(cfg_json)
        print("=== flags.txt ===")
        print(flags_txt)
        print("=== test.txt ===")
        print(build_test_command(Path("taokari-config.json")))
        return 0

    out = Path(args.out)
    cfg_path = out.with_suffix(".json")
    cfg_path.write_text(cfg_json, encoding="utf-8")
    out.with_suffix(".flags.txt").write_text(flags_txt, encoding="utf-8")
    out.with_suffix(".guide.md").write_text(guide, encoding="utf-8")
    out.with_suffix(".test.txt").write_text(build_test_command(cfg_path),
                                            encoding="utf-8")
    print(f"platform: {platform} ({PLATFORM_NOTES[platform]})")
    print(f"profile:  {goal} (perf={perf}, vmp={vmp})")
    print(f"writes:   {cfg_path}, {out.with_suffix('.flags.txt')}, "
          f"{out.with_suffix('.guide.md')}, {out.with_suffix('.test.txt')}")
    print(f"flags:    {' '.join(flags)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
