#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Pass.h"
#include "llvm/Support/RandomNumberGenerator.h"
#include "llvm/Transforms/Obfuscation/NativeIntegrity.h"
#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscation/Utils.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <random>

#define DEBUG_TYPE "native-integrity"

using namespace llvm;

namespace llvm {
extern cl::opt<bool> TaokariMaxProtection;
}

namespace {

// Per-function native-code integrity check. Emits a private pool whose
// bytes are randomly chosen at build time. At function entry, the
// function loads every word of the pool, folds it into a running hash
// with a per-build prime, and compares the result against an expected
// hash baked in as a constant. A patched pool byte (the simplest model
// for "patching a protected native block" without post-link tooling)
// trips the check and routes through a tamper path that exits the
// process. The check is memory-safe: it only reads its own private
// global and never dereferences an attacker-controlled pointer.
struct NativeIntegrity : public FunctionPass {
  static char ID;
  ObfuscationOptions *ArgsOptions;
  std::mt19937_64 RNG;

  NativeIntegrity(ObfuscationOptions *argsOptions)
      : FunctionPass(ID), ArgsOptions(argsOptions) {
    uint64_t Seed = 0;
    if (auto EC = llvm::getRandomBytes(&Seed, sizeof(Seed)))
      report_fatal_error(Twine("failed to seed NativeIntegrity RNG: ") +
                         EC.message());
    RNG = std::mt19937_64(Seed);
  }

  StringRef getPassName() const override {
    return {"NativeIntegrity"};
  }

  uint64_t nextNonZeroKey() {
    uint64_t Key = RNG();
    while (!Key)
      Key = RNG();
    return Key;
  }

  uint64_t nextOddKey() {
    return nextNonZeroKey() | 1ULL;
  }

  bool runOnFunction(Function &F) override {
    if (F.isDeclaration())
      return false;
    if (F.getName().starts_with("__taokari_nativeint_"))
      return false;

    // The prototype runs on functions explicitly marked `+nativeint`,
    // OR (when Taokari Max Protection is enabled) on every non-trivial
    // function in the module. Max mode is the "protect everything"
    // profile, so it extends the integrity check beyond VM bytecode to
    // native compiled functions automatically.
    const bool MaxMode = TaokariMaxProtection;
    bool Annotated = false;
    for (const auto &Annotation : readAnnotate(&F)) {
      if (Annotation.find("+nativeint") != std::string::npos) {
        Annotated = true;
        break;
      }
      if (Annotation.find("-nativeint") != std::string::npos)
        return false;
    }
    if (!Annotated && !MaxMode)
      return false;
    // Skip functions we generated ourselves (the trap exit shim, our
    // own pool globals). AlwaysInline callees would inline the check
    // into every caller, blowing up code size, so skip them too.
    if (F.hasFnAttribute(Attribute::AlwaysInline))
      return false;

    Module &M = *F.getParent();
    LLVMContext &Ctx = M.getContext();
    Type *I64 = Type::getInt64Ty(Ctx);
    Type *I32 = Type::getInt32Ty(Ctx);
    IRBuilder<> B(Ctx);

    // Emit a per-function private constant pool of N i64 words. N is
    // small (8) so the runtime hash loop is bounded; the values are
    // random per build so two builds of the same source produce
    // different pool bytes.
    constexpr unsigned PoolWords = 8;
    SmallVector<Constant *, PoolWords> PoolConsts;
    uint64_t HashOffset = nextNonZeroKey();
    uint64_t HashStep = nextOddKey();
    uint64_t HashPrime = nextOddKey();
    uint64_t Expected = HashOffset;
    for (unsigned I = 0; I < PoolWords; ++I) {
      uint64_t V = RNG();
      PoolConsts.push_back(ConstantInt::get(I64, V));
      uint64_t Mix = V + static_cast<uint64_t>(I) * HashStep;
      Expected = (Expected ^ Mix) * HashPrime;
    }
    auto *PoolTy = ArrayType::get(I64, PoolWords);
    auto *Pool = new GlobalVariable(
        M, PoolTy, true, GlobalValue::PrivateLinkage,
        ConstantArray::get(PoolTy, PoolConsts),
        "__taokari_nativeint_pool_" + F.getName());
    Pool->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    Pool->setAlignment(Align(8));
    Pool->addMetadata("noobf", *MDNode::get(Ctx, {}));
    appendToCompilerUsed(M, {Pool});

    // Split the function entry block so that the original code becomes
    // the lower half. The new upper half (`nativeint.entry`) becomes
    // the function entry and runs the integrity check, branching to
    // the original code on success or to a trap on failure.
    BasicBlock &OrigEntry = F.getEntryBlock();
    BasicBlock *OrigCode = OrigEntry.splitBasicBlock(
        OrigEntry.getFirstInsertionPt(), "nativeint.orig");
    OrigEntry.getTerminator()->eraseFromParent();

    BasicBlock *Trap = BasicBlock::Create(Ctx, "nativeint.trap", &F);
    B.SetInsertPoint(&OrigEntry);
    auto *HashAlloca = B.CreateAlloca(I64, nullptr, "nativeint.hash");
    auto *IdxAlloca = B.CreateAlloca(I32, nullptr, "nativeint.idx");
    B.CreateStore(ConstantInt::get(I64, HashOffset), HashAlloca);
    B.CreateStore(ConstantInt::get(I32, 0), IdxAlloca);
    BasicBlock *LoopHdr = BasicBlock::Create(Ctx, "nativeint.hdr", &F);
    BasicBlock *LoopBody = BasicBlock::Create(Ctx, "nativeint.body", &F);
    BasicBlock *LoopDone = BasicBlock::Create(Ctx, "nativeint.done", &F);
    B.CreateBr(LoopHdr);

    B.SetInsertPoint(LoopHdr);
    Value *CurIdx = B.CreateLoad(I32, IdxAlloca);
    B.CreateCondBr(
        B.CreateICmpULT(CurIdx, ConstantInt::get(I32, PoolWords)),
        LoopBody, LoopDone);

    B.SetInsertPoint(LoopBody);
    Value *Slot = B.CreateGEP(PoolTy, Pool,
                              {ConstantInt::get(I32, 0), CurIdx});
    Value *Entry = B.CreateLoad(I64, Slot);
    Value *CurHash = B.CreateLoad(I64, HashAlloca);
    Value *IdxExt = B.CreateZExt(CurIdx, I64);
    Value *Mix = B.CreateAdd(
        Entry, B.CreateMul(IdxExt, ConstantInt::get(I64, HashStep)));
    Value *NextHash = B.CreateMul(
        B.CreateXor(CurHash, Mix), ConstantInt::get(I64, HashPrime));
    B.CreateStore(NextHash, HashAlloca);
    B.CreateStore(B.CreateAdd(CurIdx, ConstantInt::get(I32, 1)), IdxAlloca);
    B.CreateBr(LoopHdr);

    B.SetInsertPoint(LoopDone);
    Value *FinalHash = B.CreateLoad(I64, HashAlloca);
    B.CreateCondBr(
        B.CreateICmpEQ(FinalHash, ConstantInt::get(I64, Expected)),
        OrigCode, Trap);

    // Trap path: exit with a non-zero code via libc. Marked NoReturn so
    // later optimizers see the unreachable. The trap is a simple libc
    // call (no llvm.trap) so it routes through normal control flow and
    // is not an obvious crash fingerprint.
    B.SetInsertPoint(Trap);
    auto *ExitTy = FunctionType::get(Type::getVoidTy(Ctx), {I32}, false);
    FunctionCallee Exit = M.getOrInsertFunction("exit", ExitTy);
    if (auto *ExitFn = dyn_cast<Function>(Exit.getCallee()))
      ExitFn->addFnAttr(Attribute::NoReturn);
    B.CreateCall(Exit, {ConstantInt::get(I32, 86)});
    B.CreateUnreachable();

    F.addMetadata("noobf", *MDNode::get(Ctx, {}));
    return true;
  }
};

} // anonymous namespace

char NativeIntegrity::ID = 0;

FunctionPass *llvm::createNativeIntegrityPass(ObfuscationOptions *Opts) {
  return new NativeIntegrity(Opts);
}
