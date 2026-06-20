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
        switch (BO->getOpcode()) {
        case Instruction::Add:
        case Instruction::Sub:
        case Instruction::Xor:
        case Instruction::And:
        case Instruction::Or:
          Candidates.push_back(BO);
          break;
        default:
          break;
        }
      }
    }

    std::mt19937_64 FuncRNG(RNG());
    bool Changed = false;
    for (BinaryOperator *BO : Candidates) {
      if ((FuncRNG() % 100) >= Probability)
        continue;
      switch (BO->getOpcode()) {
      case Instruction::Add:
        Changed |= substituteAdd(*BO);
        break;
      case Instruction::Sub:
        Changed |= substituteSub(*BO);
        break;
      case Instruction::Xor:
        Changed |= substituteXor(*BO);
        break;
      case Instruction::And:
        Changed |= substituteAnd(*BO);
        break;
      case Instruction::Or:
        Changed |= substituteOr(*BO);
        break;
      default:
        break;
      }
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

  // a - b = (a + ~b) + 1
  static bool substituteSub(BinaryOperator &BO) {
    IRBuilder<NoFolder> IRB(&BO);
    Type *Ty = BO.getType();
    Value *A = BO.getOperand(0);
    Value *B = BO.getOperand(1);
    Value *NotB = IRB.CreateXor(B, ConstantInt::getAllOnesValue(Ty),
                                BO.getName() + ".mba.not");
    Value *Sum = IRB.CreateAdd(A, NotB, BO.getName() + ".mba.sum");
    Value *Res = IRB.CreateAdd(Sum, ConstantInt::get(Ty, 1),
                               BO.getName() + ".mba.add");
    BO.replaceAllUsesWith(Res);
    BO.eraseFromParent();
    return true;
  }

  // a ^ b = (a | b) - (a & b)
  static bool substituteXor(BinaryOperator &BO) {
    IRBuilder<NoFolder> IRB(&BO);
    Value *A = BO.getOperand(0);
    Value *B = BO.getOperand(1);
    Value *Or = IRB.CreateOr(A, B, BO.getName() + ".mba.or");
    Value *And = IRB.CreateAnd(A, B, BO.getName() + ".mba.and");
    Value *Res = IRB.CreateSub(Or, And, BO.getName() + ".mba.sub");
    BO.replaceAllUsesWith(Res);
    BO.eraseFromParent();
    return true;
  }

  // a & b = ~(~a | ~b)  (De Morgan)
  static bool substituteAnd(BinaryOperator &BO) {
    IRBuilder<NoFolder> IRB(&BO);
    Type *Ty = BO.getType();
    Value *A = BO.getOperand(0);
    Value *B = BO.getOperand(1);
    Value *NA = IRB.CreateXor(A, ConstantInt::getAllOnesValue(Ty),
                              BO.getName() + ".mba.na");
    Value *NB = IRB.CreateXor(B, ConstantInt::getAllOnesValue(Ty),
                              BO.getName() + ".mba.nb");
    Value *Or = IRB.CreateOr(NA, NB, BO.getName() + ".mba.or");
    Value *Res = IRB.CreateXor(Or, ConstantInt::getAllOnesValue(Ty),
                               BO.getName() + ".mba.not");
    BO.replaceAllUsesWith(Res);
    BO.eraseFromParent();
    return true;
  }

  // a | b = ~(~a & ~b)  (De Morgan)
  static bool substituteOr(BinaryOperator &BO) {
    IRBuilder<NoFolder> IRB(&BO);
    Type *Ty = BO.getType();
    Value *A = BO.getOperand(0);
    Value *B = BO.getOperand(1);
    Value *NA = IRB.CreateXor(A, ConstantInt::getAllOnesValue(Ty),
                              BO.getName() + ".mba.na");
    Value *NB = IRB.CreateXor(B, ConstantInt::getAllOnesValue(Ty),
                              BO.getName() + ".mba.nb");
    Value *And = IRB.CreateAnd(NA, NB, BO.getName() + ".mba.and");
    Value *Res = IRB.CreateXor(And, ConstantInt::getAllOnesValue(Ty),
                               BO.getName() + ".mba.not");
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
