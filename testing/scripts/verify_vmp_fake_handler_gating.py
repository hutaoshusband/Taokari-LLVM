"""Verify VMP fake handler blocks are not always emitted as a fixed triple."""
from __future__ import annotations

import re
import sys
from pathlib import Path
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "upstream" / "taokari" / "llvm" / "lib" / "Transforms" / "Obfuscation" / "Virtualization" / "CodeVirtualization.cpp"


def main() -> int:
  text = SOURCE.read_text(encoding="utf-8", errors="ignore")
  checks = {
      "arith gate": r"bool EmitFakeArith = RNG\(\) & 1;",
      "mem gate": r"bool EmitFakeMem = RNG\(\) & 1;",
      "call gate": r"bool EmitFakeCall = RNG\(\) & 1;",
      "force one": r"if \(!EmitFakeArith && !EmitFakeMem && !EmitFakeCall\)",
      "guarded arith": r"if \(EmitFakeArith\)\s*addFakeHandler\(OpFakeArith",
      "guarded mem": r"if \(EmitFakeMem\)\s*addFakeHandler\(OpFakeMem",
      "guarded call": r"if \(EmitFakeCall\)\s*addFakeHandler\(OpFakeCall",
  }
  missing = [name for name, pattern in checks.items()
             if not re.search(pattern, text, re.S)]
  if missing:
    print(f"vmp fake-handler gating verifier: FAIL {missing}",
          file=sys.stderr)
    return 1

  old_block = (
      r"addFakeHandler\(OpFakeArith, \"fakearith\", Schedule\.Step\);\s*"
      r"addFakeHandler\(OpFakeMem, \"fakemem\", Schedule\.RotationDomain\);\s*"
      r"addFakeHandler\(OpFakeCall, \"fakecall\", Schedule\.RouteDomain\);"
  )
  if re.search(old_block, text):
    print("vmp fake-handler gating verifier: FAIL unconditional fake triple",
          file=sys.stderr)
    return 1
  print("vmp fake-handler gating verifier: ok")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
