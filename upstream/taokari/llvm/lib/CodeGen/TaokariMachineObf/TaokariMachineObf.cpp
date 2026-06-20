//===- TaokariMachineObf.cpp - Taokari MIR obfuscation pass ---------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements the Taokari Machine IR (backend) obfuscation pass.
//
// It runs in the codegen pipeline, below the LLVM IR layer, in
// TargetPassConfig::addPreEmitPass() -- after register allocation and
// scheduling, so any code it emits survives to the final binary and is never
// seen by an IR-level tool (opt, IR deobfuscators) or by Hex-Rays' microcode
// lifter in clean form. This is the layer that survives where IR-only
// obfuscators (classic OLLVM-class) lose to D810 / the Hex-Rays simplifier.
//
// Level 1 (this file) is infrastructure only: it wires up the
// MachineFunctionPass plumbing, the -mllvm -taokari-mir=<passes> flag, the
// `mir` per-function annotation gate, and proves the pipeline runs by emitting
// one semantically-neutral nop at each enabled function's entry. The real
// transforms (dirty bytes, junk instructions with side effects, machine-level
// instruction substitution, function splitting) are Level 2.
//
//===----------------------------------------------------------------------===//

#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachinePassManager.h"
#include "llvm/CodeGen/TargetInstrInfo.h"
#include "llvm/CodeGen/TargetSubtargetInfo.h"
#include "llvm/CodeGen/TaokariMachineObf.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/Module.h"
#include "llvm/InitializePasses.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

#define DEBUG_TYPE "taokari-mir"
#define PASS_NAME "Taokari Machine IR Obfuscation"

namespace {

// Master flag: -mllvm -taokari-mir=<passes>.
//
// <passes> is intended as a comma-separated list of MIR sub-passes
// (e.g. "dirtybytes,junk,sub"). Level 1 only needs to know whether the flag
// was given a non-empty value at all: any non-empty value means "MIR
// obfuscation layer is on". Parsing the comma-list is a Level 2 concern.
static cl::opt<std::string> TaokariMirFlag(
    "taokari-mir", cl::init(""), cl::Hidden,
    cl::desc("Enable Taokari Machine IR (backend) obfuscation. "
             "Value is a comma-separated list of MIR passes "
             "(e.g. dirtybytes,junk,sub). Level 1 treats any non-empty "
             "value as on."));

// Returns true if the global -taokari-mir flag enables the MIR layer.
static bool mirFlagEnabled() {
  return !TaokariMirFlag.empty();
}

// Reads the `llvm.global.annotations` global (populated by clang from
// __attribute__((annotate("...")))) and returns the annotation strings that
// apply to Function F. Mirrors the IR-layer reader in
// ObfuscationOptions::readAnnotate, but kept local and dependency-free:
// the codegen component must not depend on the IR Obfuscation library.
static SmallVector<std::string> readMirAnnotations(const Function *F) {
  SmallVector<std::string> Annotations;
  if (!F)
    return Annotations;
  const Module *M = F->getParent();
  if (!M)
    return Annotations;
  const GlobalVariable *GV = M->getGlobalVariable("llvm.global.annotations");
  if (!GV)
    return Annotations;
  const Constant *C = dyn_cast<Constant>(GV);
  if (!C || C->getNumOperands() != 1)
    return Annotations;
  C = dyn_cast<Constant>(C->getOperand(0));
  if (!C)
    return Annotations;
  for (unsigned I = 0, E = C->getNumOperands(); I != E; ++I) {
    const ConstantStruct *CS = dyn_cast<ConstantStruct>(C->getOperand(I));
    if (!CS || CS->getNumOperands() < 2)
      continue;
    const Function *AnnotatedFn =
        dyn_cast<Function>(CS->getOperand(0)->stripPointerCasts());
    if (AnnotatedFn != F)
      continue;
    const GlobalValue *StrGV =
        dyn_cast<GlobalValue>(CS->getOperand(1)->stripPointerCasts());
    if (!StrGV)
      continue;
    const ConstantDataSequential *StrData =
        dyn_cast<ConstantDataSequential>(StrGV->getOperand(0));
    if (!StrData)
      continue;
    Annotations.emplace_back(StrData->getAsString());
  }
  return Annotations;
}

// Per-function gate. Resolution order (mirrors the IR-layer toObfuscate):
//   1. Skip declarations / available_externally.
//   2. If a `+mir` annotation is present on the function -> run (overrides
//      a globally-off flag, enabling per-function opt-in).
//   3. If a `-mir` annotation is present -> skip (overrides a globally-on
//      flag, enabling per-function opt-out).
//   4. Otherwise follow the global -taokari-mir flag.
static bool shouldObfuscate(const Function &F) {
  if (F.isDeclaration() || F.hasAvailableExternallyLinkage())
    return false;
  bool AnnotEnable = false;
  bool AnnotDisable = false;
  for (const std::string &A : readMirAnnotations(&F)) {
    if (A.find("+mir") != std::string::npos)
      AnnotEnable = true;
    if (A.find("-mir") != std::string::npos)
      AnnotDisable = true;
  }
  if (AnnotEnable && AnnotDisable) {
    // Conflicting annotations: be conservative and skip rather than guess.
    errs() << "taokari-mir: both +mir and -mir on " << F.getName()
           << ", skipping\n";
    return false;
  }
  if (AnnotDisable)
    return false;
  if (AnnotEnable)
    return true;
  return mirFlagEnabled();
}

// Stateful core shared by the legacy and new-PM wrappers.
struct TaokariMachineObf {
  bool run(MachineFunction &MF);
};

} // namespace

// Level 1 transform: insert one semantically-neutral marker at the entry of
// the function's first basic block. This is a true no-op (it neither reads
// nor writes any observable architectural state), so it cannot change
// program semantics, but it proves the entire plumbing works: the pass is
// scheduled in addPreEmitPass, the flag/annotation gate fires, and BuildMI
// emits machine code that reaches the assembler. Level 2 replaces this with
// dirty-bytes / junk / sub.
//
// The marker is "lea rax, [rax+0]" (bytes 48 8D 40 00). It writes rax with
// rax+0 -- i.e. the same value -- and touches no flags or memory, so it is
// semantically a no-op. We deliberately do NOT use any nop form: clang
// itself emits 0x90 and the multi-byte 0F 1F .. nop family for optnone
// leading bytes and for alignment padding, and it even emits "push rax; pop
// rax" as part of some optnone prologues, so all of those collide with the
// compiler's own output and cannot serve as a "the pass ran" signal.
// "lea rax,[rax+0]" with the explicit +0 displacement is not in clang's
// prologue/epilogue or alignment vocabulary (the optimizer always folds the
// +0 away into a bare [rax]), so detecting the exact 48 8D 40 00 byte
// sequence at a function's entry is a reliable, non-vacuous proof that the
// pass fired.
bool TaokariMachineObf::run(MachineFunction &MF) {
  if (!shouldObfuscate(MF.getFunction()))
    return false;

  const TargetInstrInfo *TII = MF.getSubtarget().getInstrInfo();
  if (!TII)
    return false;

  // INLINEASM operand encoding in LLVM 22 (see FastIsel::lowerCallTo):
  //   operand 0: ExternalSymbol -> the asm string
  //   operand 1: imm            -> ExtraInfo flags
  // Extra_HasSideEffects (=1) prevents later machine passes from deleting
  // this no-output inline asm as dead. The instruction itself is a no-op, so
  // marking it side-effecting cannot change program semantics -- it only
  // prevents deletion, which is what makes the marker survive to the binary
  // and visible to the Level 1 smoke test. Inserting at the front of the
  // entry block lands it at the top of the function body in the final binary.
  MachineBasicBlock &EntryMBB = MF.front();
  BuildMI(EntryMBB, EntryMBB.begin(), DebugLoc(),
          TII->get(TargetOpcode::INLINEASM))
      .addExternalSymbol(".byte 0x48,0x8d,0x40,0x00")
      .addImm(InlineAsm::Extra_HasSideEffects);

  LLVM_DEBUG(dbgs() << "taokari-mir: inserted entry nop in "
                    << MF.getName() << "\n");
  return true;
}

PreservedAnalyses
TaokariMachineObfPass::run(MachineFunction &MF,
                           MachineFunctionAnalysisManager &MFAM) {
  if (!TaokariMachineObf().run(MF))
    return PreservedAnalyses::all();
  return getMachineFunctionPassPreservedAnalyses();
}

namespace {

// Legacy pass-manager wrapper. Scheduled via
// X86PassConfig::addPreEmitPass() -> createTaokariMachineObfLegacyPass().
struct TaokariMachineObfLegacy : public MachineFunctionPass {
  static char ID;
  TaokariMachineObfLegacy() : MachineFunctionPass(ID) {
    initializeTaokariMachineObfLegacyPass(*PassRegistry::getPassRegistry());
  }

  bool runOnMachineFunction(MachineFunction &MF) override {
    return TaokariMachineObf().run(MF);
  }

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    MachineFunctionPass::getAnalysisUsage(AU);
    // We insert a stateless nop and change no control flow or liveness that
    // later passes rely on, so preserve the standard machine-function
    // analyses.
  }
};

} // namespace

char TaokariMachineObfLegacy::ID = 0;
INITIALIZE_PASS(TaokariMachineObfLegacy, "taokari-mir", PASS_NAME, false,
                false)

FunctionPass *llvm::createTaokariMachineObfLegacyPass() {
  return new TaokariMachineObfLegacy();
}
