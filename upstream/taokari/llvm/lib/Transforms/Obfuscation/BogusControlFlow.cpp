#include "llvm/Transforms/Obfuscation/BogusControlFlow.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/RandomNumberGenerator.h"
#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/Transforms/Utils/Cloning.h"

#include <algorithm>
#include <random>

#define DEBUG_TYPE "bcf"

using namespace llvm;

static cl::opt<uint32_t>
    BCFProbability("taokari-bcf-prob", cl::init(35), cl::NotHidden,
                   cl::desc("BCF block selection probability, 0..100."));
static cl::opt<uint32_t>
    BCFLoopCount("taokari-bcf-loops", cl::init(0), cl::NotHidden,
                 cl::desc("BCF fake-block junk loop count."));

namespace {
struct BogusControlFlow : public FunctionPass {
  static char ID;
  ObfuscationOptions *ArgsOptions;
  std::mt19937_64 RNG;

  BogusControlFlow(ObfuscationOptions *ArgsOptions) : FunctionPass(ID) {
    this->ArgsOptions = ArgsOptions;
    uint64_t Seed = 0;
    if (auto EC = llvm::getRandomBytes(&Seed, sizeof(Seed)))
      report_fatal_error(StringRef("Failed to seed BCF RNG: ") + EC.message());
    RNG = std::mt19937_64(Seed);
  }

  StringRef getPassName() const override { return "BogusControlFlow"; }

  bool runOnFunction(Function &F) override {
    if (F.isDeclaration() || F.isIntrinsic() ||
        F.getName().starts_with("__taokari_bcf_"))
      return false;

    auto Opt = ArgsOptions->toObfuscate(ArgsOptions->bcfOpt(), &F);
    if (!Opt.isEnabled())
      return false;

    const uint32_t Probability =
        BCFProbability.getNumOccurrences()
            ? BCFProbability
            : (Opt.probability() <= 100 ? Opt.probability() : 35);
    const uint32_t Loops =
        BCFLoopCount.getNumOccurrences()
            ? BCFLoopCount
            : (Opt.loopCount() ? Opt.loopCount()
                               : std::max(1u, Opt.level() + 1));
    if (!Probability)
      return false;

    SmallVector<BasicBlock *, 32> Blocks;
    for (BasicBlock &BB : F) {
      if (eligible(BB))
        Blocks.push_back(&BB);
    }

    std::mt19937_64 FuncRNG(RNG());
    bool Changed = false;
    for (BasicBlock *BB : Blocks) {
      if ((FuncRNG() % 100) >= Probability)
        continue;
      Changed |= obfuscateBlock(F, *BB, Opt.level(), Loops, FuncRNG);
    }
    return Changed;
  }

  static bool eligible(BasicBlock &BB) {
    // no PHI repair yet; widen this when BCF must cover join blocks.
    if (isGeneratedBCFBlock(BB) || &BB == &BB.getParent()->getEntryBlock() ||
        BB.empty() || BB.isEHPad() || isa<PHINode>(BB.begin()))
      return false;
    auto *Pred = BB.getSinglePredecessor();
    if (!Pred || !Pred->getTerminator() || Pred->getTerminator()->isEHPad())
      return false;
    return isa<BranchInst>(Pred->getTerminator()) ||
           isa<SwitchInst>(Pred->getTerminator());
  }

  static bool isGeneratedBCFBlock(BasicBlock &BB) {
    StringRef Name = BB.getName();
    return Name.contains(".bcf.guard") || Name.contains(".bcf.fake");
  }

  bool obfuscateBlock(Function &F, BasicBlock &BB, uint32_t Level,
                      uint32_t Loops, std::mt19937_64 &FuncRNG) {
    auto *Pred = BB.getSinglePredecessor();
    if (!Pred)
      return false;

    LLVMContext &Ctx = F.getContext();
    auto &M = *F.getParent();
    auto *Int64 = Type::getInt64Ty(Ctx);
    auto *Nonce = getOrCreateNonce(M, Int64);
    auto *JunkSlot = createEntrySlot(F, Int64);

    BasicBlock *Guard =
        BasicBlock::Create(Ctx, BB.getName() + ".bcf.guard", &F, &BB);

    ValueToValueMapTy VMap;
    BasicBlock *Fake = CloneBasicBlock(&BB, VMap, ".bcf.fake", &F);
    sanitizeFake(*Fake);
    if (Level >= 2)
      mutateFake(*Fake, Level, FuncRNG);
    addJunk(*Fake, BB, *Nonce, *JunkSlot, Loops, Level, FuncRNG);

    Pred->getTerminator()->replaceSuccessorWith(&BB, Guard);

    IRBuilder<> GuardIR(Guard);
    auto *Load =
        GuardIR.CreateAlignedLoad(Int64, Nonce, Align(8), true, "bcf.nonce");
    Value *A = GuardIR.CreateMul(
        Load, GuardIR.CreateAdd(Load, ConstantInt::get(Int64, 1)),
        "bcf.opaque.mul");
    Value *Even = GuardIR.CreateICmpEQ(
        GuardIR.CreateAnd(A, ConstantInt::get(Int64, 1), "bcf.opaque.bit"),
        ConstantInt::get(Int64, 0), "bcf.opaque");
    GuardIR.CreateCondBr(Even, &BB, Fake);
    return true;
  }

  static GlobalVariable *getOrCreateNonce(Module &M, IntegerType *IntTy) {
    if (auto *GV = M.getGlobalVariable("__taokari_bcf_nonce", true))
      return GV;
    auto *Init = ConstantInt::get(IntTy, 0x9e3779b97f4a7c15ull);
    auto *GV = new GlobalVariable(M, IntTy, false, GlobalValue::PrivateLinkage,
                                  Init, "__taokari_bcf_nonce");
    GV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    return GV;
  }

  static AllocaInst *createEntrySlot(Function &F, Type *Ty) {
    IRBuilder<> IRB(&*F.getEntryBlock().getFirstInsertionPt());
    return IRB.CreateAlloca(Ty, nullptr, "bcf.dead.slot");
  }

  static void sanitizeFake(BasicBlock &Fake) {
    SmallVector<Instruction *, 16> ToErase;
    for (Instruction &I : Fake) {
      if (I.isTerminator() || I.isEHPad() || I.mayReadOrWriteMemory() ||
          I.mayHaveSideEffects())
        ToErase.push_back(&I);
    }
    for (Instruction *I : ToErase) {
      if (!I->getType()->isVoidTy())
        I->replaceAllUsesWith(PoisonValue::get(I->getType()));
      I->eraseFromParent();
    }
  }

  void mutateFake(BasicBlock &Fake, uint32_t Level, std::mt19937_64 &FuncRNG) {
    SmallVector<BinaryOperator *, 8> Ops;
    for (Instruction &I : Fake) {
      if (auto *BO = dyn_cast<BinaryOperator>(&I))
        if (BO->getType()->isIntegerTy())
          Ops.push_back(BO);
    }
    for (BinaryOperator *BO : Ops) {
      IRBuilder<> IRB(BO);
      Value *L = BO->getOperand(0);
      Value *R = BO->getOperand(1);
      Value *N = (FuncRNG() % 3 == 0)
                     ? IRB.CreateXor(L, R, BO->getName() + ".mx")
                 : (Level > 2 && FuncRNG() % 2)
                     ? IRB.CreateMul(L, R, BO->getName() + ".mm")
                     : IRB.CreateAdd(L, R, BO->getName() + ".ma");
      BO->replaceAllUsesWith(N);
      BO->eraseFromParent();
    }
  }

  void addJunk(BasicBlock &Fake, BasicBlock &Real, GlobalVariable &Nonce,
               AllocaInst &JunkSlot, uint32_t Loops, uint32_t Level,
               std::mt19937_64 &FuncRNG) {
    IRBuilder<> IRB(&Fake);
    auto *Int64 = Type::getInt64Ty(Fake.getContext());
    Value *V =
        IRB.CreateAlignedLoad(Int64, &Nonce, Align(8), true, "bcf.fake.nonce");
    for (uint32_t I = 0; I < Loops; ++I) {
      V = IRB.CreateXor(V, ConstantInt::get(Int64, FuncRNG()), "bcf.fake.xor");
      V = IRB.CreateMul(V, ConstantInt::get(Int64, (FuncRNG() | 1)),
                        "bcf.fake.mul");
      V = IRB.CreateAdd(V, ConstantInt::get(Int64, FuncRNG()), "bcf.fake.add");
    }
    if (Level >= 2) {
      auto *JunkFn = getOrCreateJunkFunction(*Fake.getModule());
      V = IRB.CreateCall(JunkFn, {V}, "bcf.fake.call");
    }
    IRB.CreateStore(V, &JunkSlot);
    IRB.CreateAlignedStore(V, &JunkSlot, Align(8), true);
    IRB.CreateBr(&Real);
  }

  static Function *getOrCreateJunkFunction(Module &M) {
    if (auto *F = M.getFunction("__taokari_bcf_junk"))
      return F;
    auto *Int64 = Type::getInt64Ty(M.getContext());
    auto *FTy = FunctionType::get(Int64, {Int64}, false);
    auto *F = Function::Create(FTy, GlobalValue::InternalLinkage,
                               "__taokari_bcf_junk", M);
    F->addFnAttr(Attribute::NoInline);
    F->addFnAttr(Attribute::OptimizeNone);
    auto *BB = BasicBlock::Create(M.getContext(), "entry", F);
    IRBuilder<> IRB(BB);
    auto *X = F->getArg(0);
    Value *Y = IRB.CreateMul(X, ConstantInt::get(Int64, 1103515245), "j.mul");
    Y = IRB.CreateAdd(Y, ConstantInt::get(Int64, 12345), "j.add");
    IRB.CreateRet(IRB.CreateXor(Y, IRB.CreateLShr(Y, 17), "j.xor"));
    return F;
  }
};
} // namespace

char BogusControlFlow::ID = 0;

FunctionPass *
llvm::createBogusControlFlowPass(ObfuscationOptions *ArgsOptions) {
  return new BogusControlFlow(ArgsOptions);
}
