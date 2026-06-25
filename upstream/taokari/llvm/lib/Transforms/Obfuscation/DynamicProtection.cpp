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

namespace {

enum CheckKind { CK_Debugger, CK_PEB, CK_Timing };

// Optional dynamic anti-reversing checks. Each annotated function gets one
// entry-block check picked at random from a small Windows set:
//   - IsDebuggerPresent (kernel32)
//   - PEB.BeingDebugged read via the TEB (NtCurrentTeb on x64)
//   - rdtsc timing delta between two reads (single-stepping inflates it)
// A positive detection routes through a tamper path that exits the process;
// a clean (non-debugged) run always takes the normal path. On non-Windows
// targets the check degrades to a benign always-clean path so the function
// still compiles and runs.
struct DynamicProtection : public FunctionPass {
  static char ID;
  ObfuscationOptions *ArgsOptions;
  std::mt19937_64 RNG;
  // Module-level tamper flag shared across every dyn check in the module: any
  // check that trips sets it, and every check also reads it, so removing one
  // check does not fully disable detection (the flag persists for the others).
  GlobalVariable *TamperFlag = nullptr;

  DynamicProtection(ObfuscationOptions *argsOptions)
      : FunctionPass(ID), ArgsOptions(argsOptions) {
    uint64_t Seed = 0;
    if (auto EC = llvm::getRandomBytes(&Seed, sizeof(Seed)))
      report_fatal_error(Twine("failed to seed DynamicProtection RNG: ") +
                         EC.message());
    RNG = std::mt19937_64(Seed);
  }

  // Lazily create the module-private tamper flag (i8, init 0). Once any check
  // trips it becomes nonzero; all subsequent checks read it back and trip too.
  GlobalVariable *getTamperFlag(Module &M) {
    if (TamperFlag && TamperFlag->getParent() == &M)
      return TamperFlag;
    auto *I8 = Type::getInt8Ty(M.getContext());
    TamperFlag = new GlobalVariable(M, I8, false, GlobalValue::PrivateLinkage,
                                    ConstantInt::get(I8, 0),
                                    "__taokari_dyn_tamper");
    TamperFlag->setAlignment(Align(1));
    TamperFlag->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    TamperFlag->addMetadata("noobf", *MDNode::get(M.getContext(), {}));
    appendToCompilerUsed(M, {TamperFlag});
    return TamperFlag;
  }

  StringRef getPassName() const override { return {"DynamicProtection"}; }

  bool runOnFunction(Function &F) override {
    if (F.isDeclaration())
      return false;
    // Never instrument our own exit shim.
    if (F.getName().starts_with("__taokari_dyn_"))
      return false;

    // Opt-in: `+dyn` annotation per function, or the global flag. `-dyn` on a
    // function opts it out even under the flag. toObfuscate handles the
    // annotation parsing for the `dyn` ObfOpt.
    auto Opt = ArgsOptions->toObfuscate(ArgsOptions->dynOpt(), &F);
    if (!Opt.isEnabled() && !EnableDyn)
      return false;
    // Inlining the check everywhere defeats the purpose and bloats code; only
    // standalone functions carry it.
    if (F.hasFnAttribute(Attribute::AlwaysInline))
      return false;

    Module &M = *F.getParent();
    Triple T(M.getTargetTriple());
    // Only Windows x64 has the real detection primitives wired here. On other
    // targets the check is a no-op clean path, so the function still works.
    bool Windows = T.isOSWindows() && T.getArch() == Triple::x86_64;

    CheckKind Kind = Windows ? static_cast<CheckKind>(RNG() % 3) : CK_Debugger;
    const uint32_t Level = Opt.level();

    LLVMContext &Ctx = M.getContext();
    IRBuilder<> B(Ctx);

    BasicBlock &OrigEntry = F.getEntryBlock();
    // Delayed placement (L2+): instead of always guarding the very first
    // instruction, let a small random prefix of real instructions run first,
    // then split and insert the check. This moves the check off the obvious
    // entry point so a reverser cannot find every probe by scanning function
    // entries; the check still runs early in the function.
    Instruction *SplitBefore = &*OrigEntry.getFirstInsertionPt();
    if (Level >= 2) {
      unsigned Lead = RNG() % 4; // 0..3 real instructions of headroom
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

    // L2: emit a decoy check call that looks like a detection primitive but
    // does nothing, so a static cross-reference walk sees several plausible
    // detection sites instead of one obvious one.
    if (Level >= 2 && Windows)
      emitFakeCheck(M, B);

    Value *Detected = nullptr;
    // L3: build the detection inside a private internal probe function and call
    // it indirectly. The real kernel32 edge lives only inside the probe body,
    // so the caller has no direct call to a detection API for icall to expose
    // and for a decompiler to flag. The probe is internal, so the icall page
    // table can further hide the caller->probe edge when both passes are on.
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

    // L2: mix the detection result with an unfoldable opaque-false predicate
    // whose seed is a runtime nonce (frameaddress-derived), and with the
    // shared tamper flag. At runtime the opaque side is always false and the
    // flag starts at 0, so Tripped == Detected on a clean run; but the branch
    // condition cannot be folded to the raw check output, and once any check
    // in the module trips (setting the flag) every later check trips too.
    if (Level >= 2) {
      auto *I64 = Type::getInt64Ty(Ctx);
      Value *Seed = taokari::makeContextSeed(
          F, B, I64, RNG, taokari::OpaqueSeedKind::RuntimeNonce);
      Value *OpaqueFalse = taokari::makeUnfoldableFalsePredicate(B, Seed, RNG);
      Value *Mixed = B.CreateOr(Detected, OpaqueFalse, "dyn.mix");
      GlobalVariable *Flag = getTamperFlag(M);
      auto *I8 = Type::getInt8Ty(Ctx);
      Value *FlagVal = B.CreateLoad(I8, Flag, "dyn.flag");
      Value *FlagSet = B.CreateICmpNE(FlagVal, ConstantInt::get(I8, 0),
                                      "dyn.flagset");
      Value *Tripped = B.CreateOr(Mixed, FlagSet, "dyn.trip");
      B.CreateCondBr(Tripped, Trap, OrigCode);
    } else {
      B.CreateCondBr(Detected, Trap, OrigCode);
    }

    // Tamper path: set the shared tamper flag, then libc exit with a non-zero
    // code, marked NoReturn.
    B.SetInsertPoint(Trap);
    if (Level >= 2) {
      GlobalVariable *Flag = getTamperFlag(M);
      B.CreateStore(ConstantInt::get(Type::getInt8Ty(Ctx), 1), Flag);
    }
    Type *I32 = Type::getInt32Ty(Ctx);
    auto *ExitTy = FunctionType::get(Type::getVoidTy(Ctx), {I32}, false);
    FunctionCallee Exit = M.getOrInsertFunction("exit", ExitTy);
    if (auto *ExitFn = dyn_cast<Function>(Exit.getCallee()))
      ExitFn->addFnAttr(Attribute::NoReturn);
    B.CreateCall(Exit, {ConstantInt::get(I32, 87)});
    B.CreateUnreachable();

    return true;
  }

  // Build (or reuse) a private internal probe function that runs the chosen
  // detection primitive and returns i1. The real kernel32 call edge lives only
  // inside this probe, so the protected function has no direct detection call.
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
      Result = emitDebuggerCheck(M, PB, /*Windows=*/true);
      break;
    case CK_PEB:
      Result = emitPEBCheck(M, PB, /*Windows=*/true);
      break;
    case CK_Timing:
      Result = emitTimingCheck(M, PB, /*Windows=*/true);
      break;
    }
    PB.CreateRet(Result);
    appendToCompilerUsed(M, {Probe});
    return Probe;
  }

  // A decoy detection call: a private internal function with a
  // detection-looking name and signature that simply returns false. Real code
  // ignores the result; it exists only to pollute a decompiler's call graph.
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

  // IsDebuggerPresent() from kernel32. Returns BOOL (i32) nonzero under a
  // debugger, 0 otherwise. On non-Windows we emit a constant false.
  Value *emitDebuggerCheck(Module &M, IRBuilder<> &B, bool Windows) {
    if (!Windows)
      return B.getFalse();
    auto *I32 = Type::getInt32Ty(M.getContext());
    auto *FTy = FunctionType::get(I32, false);
    FunctionCallee Fn = M.getOrInsertFunction("IsDebuggerPresent", FTy);
    Value *R = B.CreateCall(Fn);
    return B.CreateICmpNE(R, ConstantInt::get(I32, 0));
  }

  // CheckRemoteDebuggerPresent(GetCurrentProcess(), &flag). A second, distinct
  // kernel32 debugger probe (covers a different detection path than
  // IsDebuggerPresent). Non-Windows => constant false.
  Value *emitPEBCheck(Module &M, IRBuilder<> &B, bool Windows) {
    if (!Windows)
      return B.getFalse();
    auto &Ctx = M.getContext();
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *PtrTy = PointerType::get(Ctx, 0);
    auto *BoolTy = Type::getInt32Ty(Ctx); // BOOL is int on Win32
    // HANDLE GetCurrentProcess() returns -1 (pseudo handle).
    auto *NoArgs = FunctionType::get(PtrTy, false);
    FunctionCallee CurProc = M.getOrInsertFunction("GetCurrentProcess", NoArgs);
    auto *OneArg = FunctionType::get(I32, {PtrTy, PtrTy}, false);
    FunctionCallee Check =
        M.getOrInsertFunction("CheckRemoteDebuggerPresent", OneArg);
    Value *FlagSlot = B.CreateAlloca(BoolTy);
    B.CreateStore(ConstantInt::get(BoolTy, 0), FlagSlot);
    Value *Proc = B.CreateCall(CurProc);
    B.CreateCall(Check, {Proc, FlagSlot});
    Value *Flag = B.CreateLoad(BoolTy, FlagSlot);
    return B.CreateICmpNE(Flag, ConstantInt::get(BoolTy, 0));
  }

  // Timing check via QueryPerformanceCounter: read the counter twice and flag
  // a delta above a generous threshold (single-stepping a debugger inflates
  // it far above any uninterrupted entry gap). Robust kernel32 call, no inline
  // asm. Non-Windows => constant false.
  Value *emitTimingCheck(Module &M, IRBuilder<> &B, bool Windows) {
    if (!Windows)
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
    // QueryPerformanceCounter ticks are ~hundreds of MHz; 50M ticks is well
    // above any uninterrupted entry-to-entry gap but trips on single-step.
    return B.CreateICmpUGT(Delta, ConstantInt::get(I64, 50000000ULL));
  }
};

} // anonymous namespace

char DynamicProtection::ID = 0;

FunctionPass *llvm::createDynamicProtectionPass(ObfuscationOptions *Opts) {
  return new DynamicProtection(Opts);
}
