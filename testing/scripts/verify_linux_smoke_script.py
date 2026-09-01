"""Linux smoke-test script verifier (todo.md A1).

Confirms testing/scripts/linux_smoke.sh is valid bash and covers all six
Linux smoke scenarios (tiny C, tiny C++, exceptions/RTTI, string/constant
encryption, indirect call/branch/global, VMP opt-in). The script runs on
Linux CI; this verifier checks structure since it cannot execute on Windows.

Exit: 0 ok | 1 contract failure.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "testing" / "scripts" / "linux_smoke.sh"

REQUIRED_SUBTESTS = {
    "c_smoke": "tiny C",
    "cpp_smoke": "tiny C++",
    "exc_smoke": "exceptions/RTTI",
    "enc_smoke": "string/constant encryption",
    "ind_smoke": "indirect call/branch/global",
    "vmp_smoke": "VMP opt-in",
}
REQUIRED_FLAGS = ("-taokari-cse", "-taokari-fla", "-taokari-indbr", "-taokari-vmp")


def main() -> int:
    if not SCRIPT.exists():
        print(f"FAIL: {SCRIPT} missing", file=sys.stderr)
        return 1
    check = subprocess.run(["bash", "-n", "testing/scripts/linux_smoke.sh"], cwd=ROOT)
    if check.returncode:
        print(f"FAIL: {SCRIPT} is not valid bash", file=sys.stderr)
        return 1
    text = SCRIPT.read_text(encoding="utf-8")
    missing = [name for name in REQUIRED_SUBTESTS if f"check {name}" not in text]
    if missing:
        print(f"FAIL: script missing subtests {missing}", file=sys.stderr)
        return 1
    missing_flags = [f for f in REQUIRED_FLAGS if f not in text]
    if missing_flags:
        print(f"FAIL: script missing flags {missing_flags}", file=sys.stderr)
        return 1
    if "plain" not in text or "obf" not in text:
        print("FAIL: script does not compare plain vs obfuscated", file=sys.stderr)
        return 1

    print(f"linux-smoke-script: ok (valid bash; covers {len(REQUIRED_SUBTESTS)} "
          f"Linux scenarios: {', '.join(REQUIRED_SUBTESTS.values())})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
