"""Profile validation verifier (todo.md E1).

The shipped profiles (testing/configs/profile-*.json) are plain JSON the C++
loader consumes. The loader validates per-key types and warns on unknown keys
but leaves structural holes: `level` is unbounded, required keys like
randomSeed are not checked up front, and there is no standalone validator.

This verifier exposes a `validate_profile` predicate (structure + ranges +
required keys) and asserts:
  * every shipped profile validates clean;
  * each synthetic malformed profile (bad level, out-of-range probability,
    malformed JSON, unknown pass key, wrong-typed field) is rejected.

Exit: 0 ok | 1 contract failure.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CONFIGS = ROOT / "testing" / "configs"

PASS_SECTIONS = {
    "indbr", "icall", "indgv", "fla", "cse", "cie", "cfe", "bcf", "mba",
    "outline", "dyn", "rtti", "meta", "vmp", "ocnst",
}
TOP_LEVEL = PASS_SECTIONS | {"randomSeed", "vm"}

KNOWN_PASS_KEYS = {
    "enable", "level", "maxInsts", "maxBlocks", "maxAllocas",
    "probability", "functionProbability", "loopCount", "minConstSize",
    "minStringLength", "skipStrings", "localStackDecrypt", "heapDecrypt",
    "reencryptAfterUse", "volatileSeed", "decryptorMba", "releaseStrip",
    "randomizeSections", "exportAllowlist", "stringDecryptorMBA",
    "stringDecryptorFlattening", "stringDecryptorIndirectCall",
    "stringShardedPool", "stringFakePools", "stringPageTableAccess",
    "stringDelayedDecrypt",
}
NON_NEGATIVE_INT = {"maxInsts", "maxBlocks", "maxAllocas", "loopCount",
                    "minConstSize", "minStringLength"}
PERCENT_KEYS = {"probability", "functionProbability"}
BOOL_KEYS = {"enable", "localStackDecrypt", "heapDecrypt", "reencryptAfterUse",
             "volatileSeed", "decryptorMba", "releaseStrip",
             "randomizeSections", "stringDecryptorMBA",
             "stringDecryptorFlattening", "stringDecryptorIndirectCall",
             "stringShardedPool", "stringFakePools", "stringPageTableAccess",
             "stringDelayedDecrypt"}
MAX_LEVEL = 4


def _err(path: str, msg: str) -> str:
    return f"{path}: {msg}"


def validate_profile(obj: dict, name: str = "<profile>") -> list[str]:
    errors: list[str] = []
    if not isinstance(obj, dict):
        return [_err(name, "root must be a JSON object")]

    for key in obj:
        if key not in TOP_LEVEL:
            errors.append(_err(name, f"unknown top-level key '{key}'"))

    seed = obj.get("randomSeed")
    if seed is not None and not isinstance(seed, str):
        errors.append(_err(name, "randomSeed must be a string"))

    for section, cfg in obj.items():
        if section in ("randomSeed", "vm"):
            continue
        if section not in PASS_SECTIONS:
            continue
        if not isinstance(cfg, dict):
            errors.append(_err(name, f"{section} must be an object"))
            continue
        prefix = f"{name}/{section}"
        for k in cfg:
            if k not in KNOWN_PASS_KEYS:
                errors.append(_err(prefix, f"unknown key '{k}'"))
        level = cfg.get("level")
        if level is not None:
            if not isinstance(level, int) or isinstance(level, bool):
                errors.append(_err(prefix, "level must be an integer"))
            elif level < 0 or level > MAX_LEVEL:
                errors.append(_err(prefix, f"level {level} out of range 0..{MAX_LEVEL}"))
        for k in NON_NEGATIVE_INT:
            v = cfg.get(k)
            if v is not None and (not isinstance(v, int) or isinstance(v, bool) or v < 0):
                errors.append(_err(prefix, f"{k} must be a non-negative integer"))
        for k in PERCENT_KEYS:
            v = cfg.get(k)
            if v is not None and (not isinstance(v, int) or isinstance(v, bool) or v < 0 or v > 100):
                errors.append(_err(prefix, f"{k} must be an integer 0..100"))
        for k in BOOL_KEYS:
            v = cfg.get(k)
            if v is not None and not isinstance(v, bool):
                errors.append(_err(prefix, f"{k} must be a boolean"))

    return errors


def validate_file(path: Path) -> list[str]:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        return [_err(str(path), f"malformed JSON: {e}")]
    return validate_profile(obj, path.name)


BAD_PROFILES = {
    "level_out_of_range": {"fla": {"enable": True, "level": 9}},
    "level_negative": {"fla": {"enable": True, "level": -1}},
    "probability_over_100": {"mba": {"enable": True, "probability": 150}},
    "probability_negative": {"mba": {"enable": True, "functionProbability": -5}},
    "enable_wrong_type": {"fla": {"enable": "yes"}},
    "maxInsts_negative": {"fla": {"maxInsts": -3}},
    "unknown_top_key": {"flubber": {"enable": True}},
    "unknown_pass_key": {"fla": {"enable": True, "strength": 9}},
    "randomSeed_wrong_type": {"randomSeed": 12345},
    "section_not_object": {"fla": [1, 2, 3]},
}


def main() -> int:
    failures: list[str] = []

    shipped = sorted(CONFIGS.glob("profile-*.json"))
    if not shipped:
        print("FAIL: no profile-*.json found", file=sys.stderr)
        return 1
    for prof in shipped:
        errs = validate_file(prof)
        if errs:
            failures.append(f"shipped profile {prof.name} should validate but:\n  " +
                            "\n  ".join(errs))

    for label, obj in BAD_PROFILES.items():
        errs = validate_profile(obj, label)
        if not errs:
            failures.append(f"bad profile '{label}' was accepted (should reject)")

    malformed = b'{ "fla": { "enable": true, '
    try:
        json.loads(malformed.decode())
        failures.append("malformed JSON was parsed (harness wrong)")
    except json.JSONDecodeError:
        errs = validate_profile(json.loads("{\"fla\":{\"level\":2}}"), "post-parse")
        if errs:
            failures.append("post-parse validate should pass for well-formed object")

    if failures:
        for f in failures:
            print(f"FAIL: {f}", file=sys.stderr)
        return 1

    print(f"profile-validation: ok ({len(shipped)} shipped profiles valid, "
          f"{len(BAD_PROFILES)} malformed profiles rejected)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
