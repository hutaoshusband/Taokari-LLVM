//===- llvm/CodeGen/TaokariMachineObf.h -------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Taokari Machine IR (backend) obfuscation pass. Runs in the codegen pipeline
// (scheduled via TargetPassConfig::addPreEmitPass), below the LLVM IR layer,
// so its output reaches the final binary and is invisible to IR-level tools.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CODEGEN_TAOKARIMACHINEOBF_H
#define LLVM_CODEGEN_TAOKARIMACHINEOBF_H

#include "llvm/CodeGen/MachinePassManager.h"

namespace llvm {

class FunctionPass;
class PassRegistry;

// New pass-manager entry (LLVM 22 dual-PM convention, parallel to
// FEntryInserterPass). The legacy codegen PM is the default in clang/llc and
// is what addPreEmitPass hooks today; this wrapper is provided so the new-PM
// codegen pipeline (X86CodeGenPassBuilder) can adopt it without an API
// change.
class TaokariMachineObfPass : public PassInfoMixin<TaokariMachineObfPass> {
public:
  PreservedAnalyses run(MachineFunction &MF,
                        MachineFunctionAnalysisManager &MFAM);
  // Always required: an obfuscation gate cannot be peephole-pruned away.
  static bool isRequired() { return true; }
};

// Legacy pass-manager creator. Scheduled by TargetPassConfig::addPreEmitPass.
FunctionPass *createTaokariMachineObfLegacyPass();
void initializeTaokariMachineObfLegacyPass(PassRegistry &);

} // namespace llvm

#endif // LLVM_CODEGEN_TAOKARIMACHINEOBF_H
