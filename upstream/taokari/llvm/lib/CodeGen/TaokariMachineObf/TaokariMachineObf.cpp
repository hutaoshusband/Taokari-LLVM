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
// instruction substitution, and gated Fortress byte patterns) live here too.
//
//===----------------------------------------------------------------------===//

#include "llvm/CodeGen/TaokariMachineObf.h"
#include "llvm/ADT/Hashing.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachinePassManager.h"
#include "llvm/CodeGen/TargetInstrInfo.h"
#include "llvm/CodeGen/TargetSubtargetInfo.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/Module.h"
#include "llvm/InitializePasses.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetMachine.h"

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

static cl::opt<unsigned> TaokariMirDirtyProb(
    "taokari-mir-dirtybytes-prob", cl::init(100), cl::Hidden,
    cl::desc("Percent of MIR-enabled functions receiving dirty bytes."));

static cl::opt<unsigned> TaokariMirJunkProb(
    "taokari-mir-junk-prob", cl::init(100), cl::Hidden,
    cl::desc("Percent of MIR-enabled functions receiving MIR junk."));

static cl::opt<unsigned> TaokariMirSubProb(
    "taokari-mir-sub-prob", cl::init(100), cl::Hidden,
    cl::desc("Percent of MIR-enabled functions receiving MIR substitution."));

struct MirSubpasses {
  bool Marker = false;
  bool DirtyBytes = false;
  bool Junk = false;
  bool Substitution = false;
  bool Unmodelled = false;
  bool FakeBounds = false;
  bool FunctionSplit = false;

  bool any() const {
    return Marker || DirtyBytes || Junk || Substitution || Unmodelled ||
           FakeBounds || FunctionSplit;
  }
  void enableAll() {
    Marker = true;
    DirtyBytes = true;
    Junk = true;
    Substitution = true;
  }
};

static MirSubpasses parseMirFlag() {
  MirSubpasses Passes;
  if (TaokariMirFlag.empty())
    return Passes;

  bool SawKnownToken = false;
  SmallVector<StringRef, 8> Tokens;
  StringRef(TaokariMirFlag).split(Tokens, ',', -1, false);
  for (StringRef Token : Tokens) {
    Token = Token.trim();
    Token = Token.take_until([](char C) { return C == ':' || C == '='; });
    if (Token.empty())
      continue;
    if (Token == "1" || Token == "on" || Token == "all" || Token == "max") {
      Passes.enableAll();
      SawKnownToken = true;
      continue;
    }
    if (Token == "marker") {
      Passes.Marker = true;
      SawKnownToken = true;
      continue;
    }
    if (Token == "dirty" || Token == "dirtybytes") {
      Passes.DirtyBytes = true;
      SawKnownToken = true;
      continue;
    }
    if (Token == "junk") {
      Passes.Junk = true;
      SawKnownToken = true;
      continue;
    }
    if (Token == "sub" || Token == "subst" || Token == "substitution") {
      Passes.Substitution = true;
      SawKnownToken = true;
      continue;
    }
    if (Token == "unmodelled" || Token == "unmodeled" ||
        Token == "privileged" || Token == "simd") {
      Passes.Unmodelled = true;
      SawKnownToken = true;
      continue;
    }
    if (Token == "fakebounds" || Token == "fakeboundaries" ||
        Token == "fakeprologue" || Token == "fakeprologues") {
      Passes.FakeBounds = true;
      SawKnownToken = true;
      continue;
    }
    if (Token == "split" || Token == "functionsplit" ||
        Token == "functionsplitting" || Token == "boundary") {
      Passes.FunctionSplit = true;
      SawKnownToken = true;
      continue;
    }
  }

  if (!SawKnownToken)
    Passes.enableAll();
  return Passes;
}

static bool stablePercentHit(const Function &F, StringRef PassName,
                             unsigned Probability) {
  if (Probability >= 100)
    return true;
  if (Probability == 0)
    return false;
  SmallString<128> Key;
  Key += F.getName();
  Key += ":";
  Key += PassName;
  return (static_cast<uint64_t>(hash_value(StringRef(Key))) % 100) <
         Probability;
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

static bool annotationHas(StringRef Annotation, StringRef Needle) {
  return Annotation.contains(Needle);
}

static MirSubpasses resolveSubpasses(const Function &F) {
  MirSubpasses Passes = parseMirFlag();
  if (F.isDeclaration() || F.hasAvailableExternallyLinkage())
    return {};

  bool EnableAll = false;
  bool DisableAll = false;
  for (const std::string &Raw : readMirAnnotations(&F)) {
    StringRef A(Raw);
    if (annotationHas(A, "+mir") && !annotationHas(A, "+mir:"))
      EnableAll = true;
    if (annotationHas(A, "-mir") && !annotationHas(A, "-mir:"))
      DisableAll = true;
    if (annotationHas(A, "+mir:dirtybytes"))
      Passes.DirtyBytes = true;
    if (annotationHas(A, "+mir:junk"))
      Passes.Junk = true;
    if (annotationHas(A, "+mir:sub"))
      Passes.Substitution = true;
    if (annotationHas(A, "+mir:unmodelled") ||
        annotationHas(A, "+mir:unmodeled"))
      Passes.Unmodelled = true;
    if (annotationHas(A, "+mir:fakebounds") ||
        annotationHas(A, "+mir:fakeboundaries") ||
        annotationHas(A, "+mir:fakeprologue") ||
        annotationHas(A, "+mir:fakeprologues"))
      Passes.FakeBounds = true;
    if (annotationHas(A, "+mir:split") ||
        annotationHas(A, "+mir:functionsplit") ||
        annotationHas(A, "+mir:functionsplitting") ||
        annotationHas(A, "+mir:boundary"))
      Passes.FunctionSplit = true;
    if (annotationHas(A, "-mir:dirtybytes"))
      Passes.DirtyBytes = false;
    if (annotationHas(A, "-mir:junk"))
      Passes.Junk = false;
    if (annotationHas(A, "-mir:sub"))
      Passes.Substitution = false;
    if (annotationHas(A, "-mir:unmodelled") ||
        annotationHas(A, "-mir:unmodeled"))
      Passes.Unmodelled = false;
    if (annotationHas(A, "-mir:fakebounds") ||
        annotationHas(A, "-mir:fakeboundaries") ||
        annotationHas(A, "-mir:fakeprologue") ||
        annotationHas(A, "-mir:fakeprologues"))
      Passes.FakeBounds = false;
    if (annotationHas(A, "-mir:split") ||
        annotationHas(A, "-mir:functionsplit") ||
        annotationHas(A, "-mir:functionsplitting") ||
        annotationHas(A, "-mir:boundary"))
      Passes.FunctionSplit = false;
  }

  if (EnableAll && DisableAll) {
    errs() << "taokari-mir: both +mir and -mir on " << F.getName()
           << ", skipping\n";
    return {};
  }
  if (DisableAll)
    return {};
  if (EnableAll && !Passes.any())
    Passes.Marker = true;

  Passes.DirtyBytes &= stablePercentHit(F, "dirtybytes", TaokariMirDirtyProb);
  Passes.Junk &= stablePercentHit(F, "junk", TaokariMirJunkProb);
  Passes.Substitution &= stablePercentHit(F, "sub", TaokariMirSubProb);
  return Passes;
}

// Stateful core shared by the legacy and new-PM wrappers.
struct TaokariMachineObf {
  bool run(MachineFunction &MF);
};

} // namespace

static void insertSideEffectAsm(MachineBasicBlock &MBB,
                                MachineBasicBlock::iterator InsertPt,
                                const TargetInstrInfo &TII, const char *Bytes) {
  BuildMI(MBB, InsertPt, DebugLoc(), TII.get(TargetOpcode::INLINEASM))
      .addExternalSymbol(Bytes)
      .addImm(InlineAsm::Extra_HasSideEffects);
}

static MachineBasicBlock *splitEntryBlock(MachineFunction &MF,
                                          const TargetInstrInfo &TII) {
  MachineBasicBlock &EntryMBB = MF.front();
  if (EntryMBB.empty())
    return nullptr;
  MachineInstr &FirstBodyMI = *EntryMBB.begin();
  MachineBasicBlock *BodyMBB = EntryMBB.splitAt(FirstBodyMI);
  if (!BodyMBB || BodyMBB == &EntryMBB)
    return nullptr;
  insertSideEffectAsm(EntryMBB, EntryMBB.end(), TII, ".byte 0x9c,0x9d");
  TII.insertUnconditionalBranch(EntryMBB, BodyMBB, DebugLoc());
  return BodyMBB;
}

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
  MirSubpasses Passes = resolveSubpasses(MF.getFunction());
  if (!Passes.any())
    return false;

  const TargetInstrInfo *TII = MF.getSubtarget().getInstrInfo();
  if (!TII)
    return false;
  if (!MF.getTarget().getTargetTriple().isX86_64())
    return false;

  MachineBasicBlock *InsertMBB = &MF.front();
  if (Passes.FunctionSplit)
    if (MachineBasicBlock *SplitMBB = splitEntryBlock(MF, *TII))
      InsertMBB = SplitMBB;

  // Insert in reverse: every BuildMI goes before the original first instr.
  // All byte snippets preserve GPRs/RFLAGS they touch, but still survive as
  // side-effecting machine code below the IR layer.
  if (Passes.Substitution)
    insertSideEffectAsm(*InsertMBB, InsertMBB->begin(), *TII,
                        ".byte 0x9c,0x50,0x48,0x89,0xe0,0x48,0x8d,0x40,"
                        "0x13,0x48,0x83,0xe8,0x13,0x58,0x9d");
  if (Passes.Junk)
    insertSideEffectAsm(*InsertMBB, InsertMBB->begin(), *TII,
                        ".byte 0x9c,0x50,0x80,0x34,0x24,0x5a,0x80,0x34,"
                        "0x24,0x5a,0x58,0x9d");
  if (Passes.DirtyBytes)
    insertSideEffectAsm(*InsertMBB, InsertMBB->begin(), *TII,
                        ".byte 0x9c,0x50,0x8a,0x04,0x24,0x34,0xa7,0x34,"
                        "0xa7,0x3a,0x04,0x24,0x74,0x08,0x0f,0x0b,0xeb,"
                        "0xfe,0xcc,0xf1,0x0f,0x0b,0x58,0x9d");
  if (Passes.Unmodelled)
    insertSideEffectAsm(*InsertMBB, InsertMBB->begin(), *TII,
                        ".byte 0x9c,0x50,0x8a,0x04,0x24,0x34,0x3d,0x34,"
                        "0x3d,0x3a,0x04,0x24,0x74,0x08,0x0f,0x01,0xc1,"
                        "0xc4,0xe2,0x7d,0x18,0xc0,0x58,0x9d");
  if (Passes.FakeBounds)
    insertSideEffectAsm(*InsertMBB, InsertMBB->begin(), *TII,
                        ".byte 0x9c,0x50,0x8a,0x04,0x24,0x34,0x6b,0x34,"
                        "0x6b,0x3a,0x04,0x24,0x74,0x0f,0x55,0x48,0x89,"
                        "0xe5,0x48,0x83,0xec,0x20,0xc9,0xc3,0x55,0x48,"
                        "0x89,0xe5,0x5d,0x58,0x9d");
  if (Passes.Marker)
    insertSideEffectAsm(*InsertMBB, InsertMBB->begin(), *TII,
                        ".byte 0x48,0x8d,0x40,0x00");

  LLVM_DEBUG(dbgs() << "taokari-mir: inserted MIR obfuscation in "
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
INITIALIZE_PASS(TaokariMachineObfLegacy, "taokari-mir", PASS_NAME, false, false)

FunctionPass *llvm::createTaokariMachineObfLegacyPass() {
  return new TaokariMachineObfLegacy();
}
