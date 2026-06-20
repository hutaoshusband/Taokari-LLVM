#include "llvm/Transforms/Obfuscation/MBA.h"
#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/IR/Type.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/RandomNumberGenerator.h"

#include <random>

#define DEBUG_TYPE "mba"

using namespace llvm;

static cl::opt<uint32_t>
    MBAProbability("taokari-mba-prob", cl::init(40), cl::NotHidden,
                   cl::desc("MBA instruction substitution probability, 0..100."));

namespace {
struct MBA : public FunctionPass {
  static char ID;
  ObfuscationOptions *ArgsOptions;
  std::mt19937_64 RNG;

  MBA(ObfuscationOptions *ArgsOptions) : FunctionPass(ID) {
    this->ArgsOptions = ArgsOptions;
    uint64_t Seed = 0;
    if (auto EC = llvm::getRandomBytes(&Seed, sizeof(Seed)))
      report_fatal_error(StringRef("Failed to seed MBA RNG: ") + EC.message());
    RNG = std::mt19937_64(Seed);
  }

  StringRef getPassName() const override { return "MBA"; }

  bool runOnFunction(Function &F) override {
    if (F.isDeclaration() || F.isIntrinsic())
      return false;

    auto Opt = ArgsOptions->toObfuscate(ArgsOptions->mbaOpt(), &F);
    if (!Opt.isEnabled())
      return false;

    const uint32_t Probability =
        MBAProbability.getNumOccurrences()
            ? MBAProbability
            : (Opt.probability() <= 100 ? Opt.probability() : 40);
    if (!Probability)
      return false;

    // ponytail: Level is reserved for L2 (multi-round, opaque constants). L1
    // applies the basic identity uniformly; new ops land after the snapshot so
    // they cannot grow the worklist.
    (void)Opt.level();

    SmallVector<BinaryOperator *, 16> Candidates;
    for (BasicBlock &BB : F) {
      for (Instruction &I : BB) {
        auto *BO = dyn_cast<BinaryOperator>(&I);
        if (!BO || !BO->getType()->isIntegerTy())
          continue;
        if (BO->getOpcode() == Instruction::Add)
          Candidates.push_back(BO);
      }
    }

    std::mt19937_64 FuncRNG(RNG());
    bool Changed = false;
    for (BinaryOperator *BO : Candidates) {
      if ((FuncRNG() % 100) >= Probability)
        continue;
      Changed |= substituteAdd(*BO);
    }
    return Changed;
  }

  // a + b = (a ^ b) + ((a & b) << 1)
  static bool substituteAdd(BinaryOperator &BO) {
    IRBuilder<NoFolder> IRB(&BO);
    Type *Ty = BO.getType();
    Value *A = BO.getOperand(0);
    Value *B = BO.getOperand(1);
    Value *Xor = IRB.CreateXor(A, B, BO.getName() + ".mba.xor");
    Value *And = IRB.CreateAnd(A, B, BO.getName() + ".mba.and");
    Value *Carry =
        IRB.CreateShl(And, ConstantInt::get(Ty, 1), BO.getName() + ".mba.carry");
    Value *Res = IRB.CreateAdd(Xor, Carry, BO.getName() + ".mba.add");
    BO.replaceAllUsesWith(Res);
    BO.eraseFromParent();
    return true;
  }
};
} // namespace

char MBA::ID = 0;

FunctionPass *llvm::createMbaPass(ObfuscationOptions *ArgsOptions) {
  return new MBA(ArgsOptions);
}
