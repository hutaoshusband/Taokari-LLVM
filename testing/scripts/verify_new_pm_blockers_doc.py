"""Verify the new-PM migration blockers document stays accurate.

docs/NEW_PM_MIGRATION.md makes concrete claims about the current codebase
(the bridge wrapper, its hook site, the legacy pass base classes). This
verifier asserts those claims still hold, so the document does not rot
silently when the bridge or pass layout changes.

Contract:
  * The bridge wrapper class exists and is a PassInfoMixin.
  * The bridge is hooked in PassBuilderPipelines.cpp.
  * Every obfuscation pass named in the doc's blocker table is still a
    legacy FunctionPass or ModulePass (the port has not silently happened).

Exit: 0 ok | 1 a documented claim is now false | 2 missing source tree.
"""
from __future__ import annotations

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _taokari_portable as tp

ROOT = Path(__file__).resolve().parents[2]
OPM_H = ROOT / "upstream" / "taokari" / "llvm" / "include" / "llvm" / "Transforms" / "Obfuscation" / "ObfuscationPassManager.h"
OPM_CPP = ROOT / "upstream" / "taokari" / "llvm" / "lib" / "Transforms" / "Obfuscation" / "ObfuscationPassManager.cpp"
PIPELINES_CPP = ROOT / "upstream" / "taokari" / "llvm" / "lib" / "Passes" / "PassBuilderPipelines.cpp"
OBF_DIR = ROOT / "upstream" / "taokari" / "llvm" / "lib" / "Transforms" / "Obfuscation"
DOC = ROOT / "docs" / "NEW_PM_MIGRATION.md"

LEGACY_PASSES = {
    "BogusControlFlow.cpp": ("struct BogusControlFlow", "FunctionPass"),
    "ConstantIntEncryption.cpp": ("struct ConstantIntEncryption", "FunctionPass"),
    "ConstantFPEncryption.cpp": ("struct ConstantFPEncryption", "FunctionPass"),
    "DynamicProtection.cpp": ("struct DynamicProtection", "FunctionPass"),
    "Flattening.cpp": ("struct Flattening", "FunctionPass"),
    "FunctionOutlining.cpp": ("struct FunctionOutlining", "FunctionPass"),
    "IndirectBranch.cpp": ("struct IndirectBranch", "FunctionPass"),
    "IndirectCall.cpp": ("struct IndirectCall", "FunctionPass"),
    "IndirectGlobalVariable.cpp": ("struct IndirectGlobalVariable", "FunctionPass"),
    "LegacyLowerSwitch.cpp": ("class LowerSwitch", "FunctionPass"),
    "MBA.cpp": ("struct MBA", "FunctionPass"),
    "NativeIntegrity.cpp": ("struct NativeIntegrity", "FunctionPass"),
    "OpaqueConstant.cpp": ("struct OpaqueConstant", "FunctionPass"),
    "MetadataHygiene.cpp": ("class MetadataHygiene", "ModulePass"),
    "MicrosoftRTTIEraser.cpp": ("class MsRttiEraser", "ModulePass"),
    "StringEncryption.cpp": ("struct StringEncryption", "ModulePass"),
    "ObfuscationPassManager.cpp": ("struct ObfuscationPassManager", "ModulePass"),
}


def main() -> int:
    if not DOC.exists():
        print("FAIL: docs/NEW_PM_MIGRATION.md missing", file=sys.stderr)
        return 2
    for p in (OPM_H, OPM_CPP, PIPELINES_CPP):
        if not p.exists():
            print(f"FAIL: missing source {p}", file=sys.stderr)
            return 2

    opm_h = OPM_H.read_text(encoding="utf-8", errors="ignore")
    if "class ObfuscationPassManagerPass" not in opm_h:
        print("FAIL: bridge wrapper class gone from ObfuscationPassManager.h",
              file=sys.stderr)
        return 1
    if "PassInfoMixin<ObfuscationPassManagerPass>" not in opm_h:
        print("FAIL: bridge wrapper is no longer a PassInfoMixin", file=sys.stderr)
        return 1
    if "createObfuscationPassManager()" not in opm_h:
        print("FAIL: createObfuscationPassManager factory gone", file=sys.stderr)
        return 1

    pipelines = PIPELINES_CPP.read_text(encoding="utf-8", errors="ignore")
    if "MPM.addPass(ObfuscationPassManagerPass())" not in pipelines:
        print("FAIL: bridge no longer hooked in PassBuilderPipelines.cpp",
              file=sys.stderr)
        return 1

    opm_cpp = OPM_CPP.read_text(encoding="utf-8", errors="ignore")
    if "struct ObfuscationPassManager : public ModulePass" not in opm_cpp:
        print("FAIL: OPM no longer a legacy ModulePass", file=sys.stderr)
        return 1
    if "bool run(Module &M)" not in opm_cpp:
        print("FAIL: OPM legacy run(Module&) dispatcher gone", file=sys.stderr)
        return 1

    for fname, (struct_decl, base) in LEGACY_PASSES.items():
        src = OBF_DIR / fname
        if not src.exists():
            print(f"FAIL: {fname} missing", file=sys.stderr)
            return 1
        text = src.read_text(encoding="utf-8", errors="ignore")
        needle = f"{struct_decl} : public {base}"
        if needle not in text:
            print(f"FAIL: {fname} no longer '{needle}' (port may have happened; "
                  f"update docs/NEW_PM_MIGRATION.md)", file=sys.stderr)
            return 1

    doc = DOC.read_text(encoding="utf-8", errors="ignore")
    if "Blockers to a native new-PM port" not in doc:
        print("FAIL: doc missing the Blockers section", file=sys.stderr)
        return 1

    print(f"new-PM blockers doc: ok (bridge present, {len(LEGACY_PASSES)} legacy "
          f"passes confirmed, doc structurally complete)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
