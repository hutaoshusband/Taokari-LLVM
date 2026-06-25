#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/Pass.h"
#include "llvm/Support/RandomNumberGenerator.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/Transforms/Obfuscation/DynamicProtection.h"
#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
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

  DynamicProtection(ObfuscationOptions *argsOptions)
      : FunctionPass(ID), ArgsOptions(argsOptions) {
    uint64_t Seed = 0;
    if (auto EC = llvm::getRandomBytes(&Seed, sizeof(Seed)))
      report_fatal_error(Twine("failed to seed DynamicProtection RNG: ") +
                         EC.message());
    RNG = std::mt19937_64(Seed);
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

    LLVMContext &Ctx = M.getContext();
    IRBuilder<> B(Ctx);

    BasicBlock &OrigEntry = F.getEntryBlock();
    BasicBlock *OrigCode = OrigEntry.splitBasicBlock(
        OrigEntry.getFirstInsertionPt(), "dyn.orig");
    OrigEntry.getTerminator()->eraseFromParent();

    BasicBlock *Trap = BasicBlock::Create(Ctx, "dyn.trap", &F);
    B.SetInsertPoint(&OrigEntry);
    Value *Detected = nullptr;
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
    // Detected is true => tampered/debugged => trap. A clean run makes every
    // primitive return false, so the branch always falls through to OrigCode.
    B.CreateCondBr(Detected, Trap, OrigCode);

    // Tamper path: libc exit with a non-zero code, marked NoReturn.
    B.SetInsertPoint(Trap);
    Type *I32 = Type::getInt32Ty(Ctx);
    auto *ExitTy = FunctionType::get(Type::getVoidTy(Ctx), {I32}, false);
    FunctionCallee Exit = M.getOrInsertFunction("exit", ExitTy);
    if (auto *ExitFn = dyn_cast<Function>(Exit.getCallee()))
      ExitFn->addFnAttr(Attribute::NoReturn);
    B.CreateCall(Exit, {ConstantInt::get(I32, 87)});
    B.CreateUnreachable();

    return true;
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
