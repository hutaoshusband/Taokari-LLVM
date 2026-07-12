"""AArch64 smoke-test script verifier (todo.md A2).

Confirms testing/scripts/aarch64_smoke.sh is valid bash and covers the
AArch64 IR cross-compile scenarios: build smoke, indirect branch/call
parity, and string/constant encryption parity. The script runs on CI;
this verifier checks structure (it can also execute locally since it only
cross-compiles IR, no AArch64 host needed).

Exit: 0 ok | 1 contract failure.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "testing" / "scripts" / "aarch64_smoke.sh"

REQUIRED_SUBTESTS = ("build_smoke", "indbr_parity", "enc_parity")
REQUIRED_TOKENS = ("aarch64-linux-gnu", "-S -emit-llvm", "taokari-report")


def main() -> int:
    if not SCRIPT.exists():
        print(f"FAIL: {SCRIPT} missing", file=sys.stderr)
        return 1
    check = subprocess.run(["bash", "-n", "testing/scripts/aarch64_smoke.sh"],
                           cwd=ROOT)
    if check.returncode:
        print(f"FAIL: {SCRIPT} is not valid bash", file=sys.stderr)
        return 1
    text = SCRIPT.read_text(encoding="utf-8")
    missing = [s for s in REQUIRED_SUBTESTS if s not in text]
    if missing:
        print(f"FAIL: script missing subtests {missing}", file=sys.stderr)
        return 1
    missing_tokens = [t for t in REQUIRED_TOKENS if t not in text]
    if missing_tokens:
        print(f"FAIL: script missing tokens {missing_tokens}", file=sys.stderr)
        return 1

    print(f"aarch64-smoke-script: ok (valid bash; covers {len(REQUIRED_SUBTESTS)} "
          f"AArch64 IR scenarios: build, indbr/icall parity, enc parity)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
