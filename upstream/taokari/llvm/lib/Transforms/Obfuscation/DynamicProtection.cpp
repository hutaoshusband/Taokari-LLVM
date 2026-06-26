#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/Pass.h"
#include "llvm/Support/RandomNumberGenerator.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/Transforms/Obfuscation/DynamicProtection.h"
#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscation/OpaquePredicate.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <random>

#define DEBUG_TYPE "dyn"

using namespace llvm;

namespace llvm {
extern cl::opt<bool> TaokariMaxProtection;
extern cl::opt<bool> EnableDyn;
}

namespace llvm::taokari {

static bool supportsWindowsX64(Module &M) {
  Triple T(M.getTargetTriple());
  return T.isOSWindows() && T.getArch() == Triple::x86_64;
}

GlobalVariable *getOrCreateDynamicTamperFlag(Module &M) {
  if (auto *Existing = M.getGlobalVariable("__taokari_dyn_tamper"))
    return Existing;
  auto *I8 = Type::getInt8Ty(M.getContext());
  auto *Flag = new GlobalVariable(M, I8, false, GlobalValue::PrivateLinkage,
                                  ConstantInt::get(I8, 0),
                                  "__taokari_dyn_tamper");
  Flag->setAlignment(Align(1));
  Flag->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
  Flag->addMetadata("noobf", *MDNode::get(M.getContext(), {}));
  appendToCompilerUsed(M, {Flag});
  return Flag;
}

Value *emitDynamicDebuggerCheck(Module &M, IRBuilder<> &B) {
  if (!supportsWindowsX64(M))
    return B.getFalse();
  auto *I32 = Type::getInt32Ty(M.getContext());
  auto *FTy = FunctionType::get(I32, false);
  FunctionCallee Fn = M.getOrInsertFunction("IsDebuggerPresent", FTy);
  Value *R = B.CreateCall(Fn);
  return B.CreateICmpNE(R, ConstantInt::get(I32, 0));
}

Value *emitDynamicRemoteDebuggerCheck(Module &M, IRBuilder<> &B) {
  if (!supportsWindowsX64(M))
    return B.getFalse();
  auto &Ctx = M.getContext();
  auto *I32 = Type::getInt32Ty(Ctx);
  auto *PtrTy = PointerType::get(Ctx, 0);
  auto *NoArgs = FunctionType::get(PtrTy, false);
  FunctionCallee CurProc = M.getOrInsertFunction("GetCurrentProcess", NoArgs);
  auto *OneArg = FunctionType::get(I32, {PtrTy, PtrTy}, false);
  FunctionCallee Check =
      M.getOrInsertFunction("CheckRemoteDebuggerPresent", OneArg);
  Value *FlagSlot = B.CreateAlloca(I32);
  B.CreateStore(ConstantInt::get(I32, 0), FlagSlot);
  Value *Proc = B.CreateCall(CurProc);
  B.CreateCall(Check, {Proc, FlagSlot});
  Value *Flag = B.CreateLoad(I32, FlagSlot);
  return B.CreateICmpNE(Flag, ConstantInt::get(I32, 0));
}

Value *emitDynamicTimingCheck(Module &M, IRBuilder<> &B, uint64_t Threshold) {
  if (!supportsWindowsX64(M))
    return B.getFalse();
  auto &Ctx = M.getContext();
  auto *I64 = Type::getInt64Ty(Ctx);
  auto *PtrTy = PointerType::get(Ctx, 0);
  auto *FTy = FunctionType::get(Type::getInt32Ty(Ctx), {PtrTy}, false);
  FunctionCallee Qpc = M.getOrInsertFunction("QueryPerformanceCounter", FTy);
  Value *T0 = B.CreateAlloca(I64);
  Value *T1 = B.CreateAlloca(I64);
  B.CreateCall(Qpc, {T0});
  B.CreateCall(Qpc, {T1});
  Value *V0 = B.CreateLoad(I64, T0);
  Value *V1 = B.CreateLoad(I64, T1);
  Value *Delta = B.CreateSub(V1, V0);
  return B.CreateICmpUGT(Delta, ConstantInt::get(I64, Threshold));
}

Value *emitDynamicEmulationCheck(Module &M, IRBuilder<> &B) {
  if (!supportsWindowsX64(M))
    return B.getFalse();
  auto &Ctx = M.getContext();
  auto *I64 = Type::getInt64Ty(Ctx);
  auto *PtrTy = PointerType::get(Ctx, 0);
  auto *QpcTy = FunctionType::get(Type::getInt32Ty(Ctx), {PtrTy}, false);
  FunctionCallee Qpc =
      M.getOrInsertFunction("QueryPerformanceCounter", QpcTy);
  auto *TickTy = FunctionType::get(I64, false);
  FunctionCallee Tick = M.getOrInsertFunction("GetTickCount64", TickTy);
  Value *T0 = B.CreateAlloca(I64);
  Value *T1 = B.CreateAlloca(I64);
  B.CreateCall(Qpc, {T0});
  B.CreateCall(Qpc, {T1});
  Value *V0 = B.CreateLoad(I64, T0);
  Value *V1 = B.CreateLoad(I64, T1);
  Value *Backwards = B.CreateICmpULT(V1, V0, "dyn.emu.qpc.backwards");
  Value *TickValue = B.CreateCall(Tick);
  Value *ZeroTick =
      B.CreateICmpEQ(TickValue, ConstantInt::get(I64, 0), "dyn.emu.tick0");
  Value *ZeroQpc = B.CreateAnd(
      B.CreateICmpEQ(V0, ConstantInt::get(I64, 0), "dyn.emu.qpc0"),
      B.CreateICmpEQ(V1, ConstantInt::get(I64, 0), "dyn.emu.qpc1"),
      "dyn.emu.qpc.zero");
  return B.CreateOr(Backwards, B.CreateAnd(ZeroTick, ZeroQpc),
                    "dyn.emu.trip");
}

Value *emitDynamicRuntimeCheck(Module &M, IRBuilder<> &B, uint32_t Level) {
  auto *I8 = Type::getInt8Ty(M.getContext());
  Value *Tripped = emitDynamicDebuggerCheck(M, B);
  if (Level >= 2)
    Tripped = B.CreateOr(Tripped, emitDynamicRemoteDebuggerCheck(M, B),
                         "dyn.remote");
  if (Level >= 3)
    Tripped = B.CreateOr(Tripped, emitDynamicTimingCheck(M, B),
                         "dyn.timing");
  if (Level >= 4)
    Tripped = B.CreateOr(Tripped, emitDynamicEmulationCheck(M, B),
                         "dyn.emu");
  GlobalVariable *Flag = getOrCreateDynamicTamperFlag(M);
  Value *FlagVal = B.CreateLoad(I8, Flag, "dyn.flag");
  Value *FlagSet =
      B.CreateICmpNE(FlagVal, ConstantInt::get(I8, 0), "dyn.flagset");
  return B.CreateOr(Tripped, FlagSet, "dyn.trip");
}

void markDynamicTamper(Module &M, IRBuilder<> &B) {
  B.CreateStore(ConstantInt::get(Type::getInt8Ty(M.getContext()), 1),
                getOrCreateDynamicTamperFlag(M));
}

}

namespace {

enum CheckKind { CK_Debugger, CK_PEB, CK_Timing };

struct DynamicProtection : public FunctionPass {
  static char ID;
  ObfuscationOptions *ArgsOptions;
  std::mt19937_64 RNG;
  GlobalVariable *TamperFlag = nullptr;

  DynamicProtection(ObfuscationOptions *argsOptions)
      : FunctionPass(ID), ArgsOptions(argsOptions) {
    uint64_t Seed = 0;
    if (auto EC = llvm::getRandomBytes(&Seed, sizeof(Seed)))
      report_fatal_error(Twine("failed to seed DynamicProtection RNG: ") +
                         EC.message());
    RNG = std::mt19937_64(Seed);
  }

  GlobalVariable *getTamperFlag(Module &M) {
    TamperFlag = taokari::getOrCreateDynamicTamperFlag(M);
    return TamperFlag;
  }

  StringRef getPassName() const override { return {"DynamicProtection"}; }

  bool runOnFunction(Function &F) override {
    if (F.isDeclaration())
      return false;
    if (F.getName().starts_with("__taokari_dyn_"))
      return false;
    if (F.getName().starts_with("__taokari_vmp_interp_"))
      return false;

    auto Opt = ArgsOptions->toObfuscate(ArgsOptions->dynOpt(), &F);
    if (!Opt.isEnabled())
      return false;
    if (F.hasFnAttribute(Attribute::AlwaysInline))
      return false;

    Module &M = *F.getParent();
    Triple T(M.getTargetTriple());
    bool Windows = T.isOSWindows() && T.getArch() == Triple::x86_64;

    CheckKind Kind = Windows ? static_cast<CheckKind>(RNG() % 3) : CK_Debugger;
    const uint32_t Level = Opt.level();

    LLVMContext &Ctx = M.getContext();
    IRBuilder<> B(Ctx);

    BasicBlock &OrigEntry = F.getEntryBlock();
    Instruction *SplitBefore = &*OrigEntry.getFirstInsertionPt();
    if (Level >= 2) {
      unsigned Lead = (Level >= 3) ? (RNG() % 9) : (RNG() % 4);
      unsigned Seen = 0;
      for (Instruction &I : OrigEntry) {
        if (I.isTerminator())
          break;
        if (isa<AllocaInst>(&I) || I.isDebugOrPseudoInst())
          continue;
        if (Seen >= Lead) {
          SplitBefore = &I;
          break;
        }
        ++Seen;
        SplitBefore = &I;
      }
    }
    BasicBlock *OrigCode =
        OrigEntry.splitBasicBlock(SplitBefore->getIterator(), "dyn.orig");
    OrigEntry.getTerminator()->eraseFromParent();

    BasicBlock *Trap = BasicBlock::Create(Ctx, "dyn.trap", &F);
    B.SetInsertPoint(&OrigEntry);

    if (Level >= 2 && Windows)
      emitFakeCheck(M, B);

    Value *Detected = nullptr;
    Function *Probe = nullptr;
    if (Level >= 3 && Windows) {
      Probe = createProbe(M, Kind);
      auto *I1 = Type::getInt1Ty(Ctx);
      auto *ProbeTy = FunctionType::get(I1, false);
      Detected = B.CreateCall(ProbeTy, Probe, {});
    } else {
      switch (Kind) {
      case CK_Debugger:
        Detected = emitDebuggerCheck(M, B, Windows);
        break;
      case CK_PEB:
        Detected = emitPEBCheck(M, B, Windows);
        break;
      case CK_Timing:
        Detected = emitTimingCheck(M, B, Windows);
        break;
      }
    }

    if (Level >= 2) {
      auto *I64 = Type::getInt64Ty(Ctx);
      Value *Seed = taokari::makeContextSeed(
          F, B, I64, RNG, taokari::OpaqueSeedKind::RuntimeNonce);
      Value *OpaqueFalse =
          taokari::makeRegistryFalsePredicate(B, Seed, RNG, "dyn.opaq");
      if (Level >= 4) {
        Value *Emu = taokari::emitDynamicEmulationCheck(M, B);
        Detected = B.CreateOr(Detected, Emu, "dyn.emu");
      }
      Value *Mixed = B.CreateOr(Detected, OpaqueFalse, "dyn.mix");
      Value *Tripped = Mixed;
      if (Level >= 3) {
        Value *SentinelTripped = emitSentinelCheck(M, B);
        Tripped = B.CreateOr(Tripped, SentinelTripped, "dyn.sent");
      }
      GlobalVariable *Flag = getTamperFlag(M);
      auto *I8 = Type::getInt8Ty(Ctx);
      Value *FlagVal = B.CreateLoad(I8, Flag, "dyn.flag");
      Value *FlagSet = B.CreateICmpNE(FlagVal, ConstantInt::get(I8, 0),
                                      "dyn.flagset");
      Tripped = B.CreateOr(Tripped, FlagSet, "dyn.trip");
      B.CreateCondBr(Tripped, Trap, OrigCode);
    } else {
      B.CreateCondBr(Detected, Trap, OrigCode);
    }

    B.SetInsertPoint(Trap);
    if (Level >= 2) {
      GlobalVariable *Flag = getTamperFlag(M);
      B.CreateStore(ConstantInt::get(Type::getInt8Ty(Ctx), 1), Flag);
    }
    if (Level >= 3) {
      Function *Stub = getOrCreateTrapStub(M);
      B.CreateCall(FunctionType::get(Type::getVoidTy(Ctx), false), Stub);
    } else {
      Type *I32 = Type::getInt32Ty(Ctx);
      auto *ExitTy = FunctionType::get(Type::getVoidTy(Ctx), {I32}, false);
      FunctionCallee Exit = M.getOrInsertFunction("exit", ExitTy);
      if (auto *ExitFn = dyn_cast<Function>(Exit.getCallee()))
        ExitFn->addFnAttr(Attribute::NoReturn);
      B.CreateCall(Exit, {ConstantInt::get(I32, 87)});
    }
    B.CreateUnreachable();

    return true;
  }

  Function *getOrCreateTrapStub(Module &M) {
    if (auto *Existing = M.getFunction("__taokari_dyn_trap"))
      return Existing;
    auto &Ctx = M.getContext();
    auto *FTy = FunctionType::get(Type::getVoidTy(Ctx), false);
    auto *Stub = Function::Create(FTy, GlobalValue::InternalLinkage,
                                  "__taokari_dyn_trap", M);
    Stub->addFnAttr(Attribute::NoInline);
    Stub->addFnAttr(Attribute::NoReturn);
    BasicBlock *BB = BasicBlock::Create(Ctx, "entry", Stub);
    IRBuilder<> B(BB);
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *ExitTy = FunctionType::get(Type::getVoidTy(Ctx), {I32}, false);
    FunctionCallee Exit = M.getOrInsertFunction("exit", ExitTy);
    if (auto *ExitFn = dyn_cast<Function>(Exit.getCallee()))
      ExitFn->addFnAttr(Attribute::NoReturn);
    B.CreateCall(Exit, {ConstantInt::get(I32, 87)});
    B.CreateUnreachable();
    appendToCompilerUsed(M, {Stub});
    return Stub;
  }

  Value *emitSentinelCheck(Module &M, IRBuilder<> &B) {
    auto &Ctx = M.getContext();
    auto *I8 = Type::getInt8Ty(Ctx);
    auto *ArrTy = ArrayType::get(I8, 4);
    SmallVector<Constant *, 4> Encoded;
    SmallVector<uint8_t, 4> Plain;
    SmallVector<uint8_t, 4> Keys;
    for (unsigned I = 0; I < 4; ++I) {
      uint8_t P = static_cast<uint8_t>(RNG() & 0xff);
      uint8_t K = static_cast<uint8_t>(RNG() & 0xff);
      if (!K)
        K = 0x5a;
      if (!P)
        P = 0x3c;
      Plain.push_back(P);
      Keys.push_back(K);
      Encoded.push_back(ConstantInt::get(I8, static_cast<uint8_t>(P ^ K)));
    }
    auto *Sentinel = new GlobalVariable(
        M, ArrTy, false, GlobalValue::PrivateLinkage,
        ConstantArray::get(ArrTy, Encoded), "__taokari_dyn_sentinel");
    Sentinel->setAlignment(Align(1));
    Sentinel->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    Sentinel->addMetadata("noobf", *MDNode::get(Ctx, {}));
    appendToCompilerUsed(M, {Sentinel});

    Value *Tripped = B.getFalse();
    for (unsigned I = 0; I < 4; ++I) {
      Value *Slot = B.CreateConstInBoundsGEP2_64(ArrTy, Sentinel, 0, I,
                                                 "dyn.sgep");
      Value *Enc = B.CreateLoad(I8, Slot, "dyn.senc");
      Value *Dec = B.CreateXor(Enc, ConstantInt::get(I8, Keys[I]), "dyn.sdec");
      Value *Mismatch = B.CreateICmpNE(
          Dec, ConstantInt::get(I8, Plain[I]), "dyn.scmp");
      Tripped = B.CreateOr(Tripped, Mismatch, "dyn.sor");
    }
    return Tripped;
  }

  Function *createProbe(Module &M, CheckKind Kind) {
    auto &Ctx = M.getContext();
    auto *I1 = Type::getInt1Ty(Ctx);
    auto *FTy = FunctionType::get(I1, false);
    std::string Name = "__taokari_dyn_probe_" + std::to_string(RNG() & 0xfffff);
    auto *Probe = Function::Create(FTy, GlobalValue::InternalLinkage, Name, M);
    Probe->addFnAttr(Attribute::NoInline);
    BasicBlock *BB = BasicBlock::Create(Ctx, "entry", Probe);
    IRBuilder<> PB(BB);
    Value *Result = nullptr;
    switch (Kind) {
    case CK_Debugger:
      Result = emitDebuggerCheck(M, PB, true);
      break;
    case CK_PEB:
      Result = emitPEBCheck(M, PB, true);
      break;
    case CK_Timing:
      Result = emitTimingCheck(M, PB, true);
      break;
    }
    PB.CreateRet(Result);
    appendToCompilerUsed(M, {Probe});
    return Probe;
  }

  void emitFakeCheck(Module &M, IRBuilder<> &B) {
    auto &Ctx = M.getContext();
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *FTy = FunctionType::get(I32, false);
    std::string Name = "__taokari_dyn_fake_" + std::to_string(RNG() & 0xfffff);
    auto *Fake = dyn_cast<Function>(M.getOrInsertFunction(Name, FTy).getCallee());
    if (Fake->empty()) {
      Fake->setLinkage(GlobalValue::InternalLinkage);
      Fake->addFnAttr(Attribute::NoInline);
      BasicBlock *BB = BasicBlock::Create(Ctx, "entry", Fake);
      IRBuilder<> FB(BB);
      FB.CreateRet(ConstantInt::get(I32, 0));
      appendToCompilerUsed(M, {Fake});
    }
    B.CreateCall(Fake);
  }

  Value *emitDebuggerCheck(Module &M, IRBuilder<> &B, bool Windows) {
    if (!Windows)
      return B.getFalse();
    return taokari::emitDynamicDebuggerCheck(M, B);
  }

  Value *emitPEBCheck(Module &M, IRBuilder<> &B, bool Windows) {
    if (!Windows)
      return B.getFalse();
    return taokari::emitDynamicRemoteDebuggerCheck(M, B);
  }

  Value *emitTimingCheck(Module &M, IRBuilder<> &B, bool Windows) {
    if (!Windows)
      return B.getFalse();
    return taokari::emitDynamicTimingCheck(M, B);
  }
};

}

char DynamicProtection::ID = 0;

FunctionPass *llvm::createDynamicProtectionPass(ObfuscationOptions *Opts) {
  return new DynamicProtection(Opts);
}
