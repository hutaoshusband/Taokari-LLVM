#include "llvm/Transforms/Obfuscation/MBA.h"
#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
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
static cl::opt<uint32_t>
    MBAMaxSubs("taokari-mba-max-substitutions", cl::init(0), cl::NotHidden,
               cl::desc("Overhead budget: hard cap on MBA substitutions per "
                        "function. 0 = uncapped (probability alone controls "
                        "density). Bounds compile time and binary size on "
                        "huge functions."));

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
    uint32_t EffectiveLevel =
        F.getName().starts_with("__taokari_vmp_interp_") ? 1 : Opt.level();
    // Overhead budget: once MaxSubs substitutions land in this function, stop.
    // The probability already limits density, but a very large function can
    // still produce hundreds of substitutions; this caps the absolute count.
    const uint32_t MaxSubs = MBAMaxSubs.getValue();
    uint32_t SubsDone = 0;
    bool Changed = false;
    for (BinaryOperator *BO : Candidates) {
      if (MaxSubs && SubsDone >= MaxSubs)
        break;
      if ((FuncRNG() % 100) >= Probability)
        continue;
      switch (BO->getOpcode()) {
      case Instruction::Add:
        if (substituteAdd(*BO, EffectiveLevel, FuncRNG)) {
          ++SubsDone;
          Changed = true;
        }
        break;
      case Instruction::Sub:
        if (substituteSub(*BO, EffectiveLevel, FuncRNG)) {
          ++SubsDone;
          Changed = true;
        }
        break;
      case Instruction::Xor:
        if (substituteXor(*BO, EffectiveLevel, FuncRNG)) {
          ++SubsDone;
          Changed = true;
        }
        break;
      case Instruction::And:
        if (substituteAnd(*BO, EffectiveLevel, FuncRNG)) {
          ++SubsDone;
          Changed = true;
        }
        break;
      case Instruction::Or:
        if (substituteOr(*BO, EffectiveLevel, FuncRNG)) {
          ++SubsDone;
          Changed = true;
        }
        break;
      default:
        break;
      }
    }
    return Changed;
  }

  static Value *opaqueNoise(BinaryOperator &BO, IRBuilder<NoFolder> &IRB,
                            std::mt19937_64 &FuncRNG, const Twine &Name) {
    auto *Ty = cast<IntegerType>(BO.getType());
    Module &M = *BO.getModule();
    auto *Init = ConstantInt::get(Ty, FuncRNG());
    auto *Seed = new GlobalVariable(
        M, Ty, false, GlobalValue::PrivateLinkage, Init,
        (BO.getFunction()->getName() + "." + Name + ".seed").str());
    Seed->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    Value *Loaded = IRB.CreateAlignedLoad(Ty, Seed, Align(1), true,
                                          Name + ".vload");
    Value *Odd = IRB.CreateOr(Loaded, ConstantInt::get(Ty, 1),
                              Name + ".odd");
    switch (FuncRNG() % 4) {
    case 0:
      return IRB.CreateMul(Loaded, Odd, Name + ".noise.mul");
    case 1:
      return IRB.CreateXor(IRB.CreateAdd(Loaded, Odd, Name + ".noise.add"),
                           Odd, Name + ".noise.xor");
    case 2:
      return IRB.CreateSub(IRB.CreateOr(Loaded, Odd, Name + ".noise.or"),
                           IRB.CreateAnd(Loaded, Odd, Name + ".noise.and"),
                           Name + ".noise.sub");
    default:
      return IRB.CreateMul(
          IRB.CreateAdd(Loaded, IRB.CreateXor(Loaded, Odd, Name + ".noise.xor"),
                        Name + ".noise.add"),
          Odd, Name + ".noise.mul");
    }
  }

  static Value *hardenResult(BinaryOperator &BO, IRBuilder<NoFolder> &IRB,
                             Value *Result, uint32_t Level,
                             std::mt19937_64 &FuncRNG) {
    if (Level < 2)
      return Result;

    // Higher levels add MBA rounds. Each round folds in a fresh
    // runtime-derived noise value with a randomly selected identity so
    // the expression tree deepens and the optimizer must redo its work.
    // Level 2 = 1 round, Level 3 = 2 rounds, Level 4 = 3 rounds.
    const unsigned Rounds = std::min<unsigned>(Level - 1, 3);
    for (unsigned I = 0; I < Rounds; ++I) {
      Value *Noise = opaqueNoise(BO, IRB, FuncRNG,
                                 BO.getName() + ".mba.noise" + Twine(I));
      switch (FuncRNG() % 3) {
      case 0:
        Result = IRB.CreateSub(
            IRB.CreateAdd(Result, Noise, BO.getName() + ".mba.mix.add"),
            Noise, BO.getName() + ".mba.mix.sub");
        break;
      case 1:
        Result = IRB.CreateXor(
            IRB.CreateXor(Result, Noise, BO.getName() + ".mba.mix.xor"),
            Noise, BO.getName() + ".mba.mix.unxor");
        break;
      default:
        Result = IRB.CreateAdd(
            IRB.CreateSub(Result, Noise, BO.getName() + ".mba.mix.sub"),
            Noise, BO.getName() + ".mba.mix.add");
        break;
      }
    }
    return Result;
  }

  // a + b = (a ^ b) + ((a & b) << 1)
  static bool substituteAdd(BinaryOperator &BO, uint32_t Level,
                            std::mt19937_64 &FuncRNG) {
    IRBuilder<NoFolder> IRB(&BO);
    Type *Ty = BO.getType();
    Value *A = BO.getOperand(0);
    Value *B = BO.getOperand(1);
    Value *Res = nullptr;
    // Polymorphic templates: the same a+b expands differently per use so a
    // reverser cannot match one signature. Both forms are algebraically
    // exact for all integer widths under wraparound.
    if (FuncRNG() & 1) {
      // a + b = (a ^ b) + 2 * (a & b)
      Value *Xor = IRB.CreateXor(A, B, BO.getName() + ".mba.xor");
      Value *And = IRB.CreateAnd(A, B, BO.getName() + ".mba.and");
      Value *Carry = IRB.CreateShl(And, ConstantInt::get(Ty, 1),
                                   BO.getName() + ".mba.carry");
      Res = IRB.CreateAdd(Xor, Carry, BO.getName() + ".mba.add");
    } else {
      // a + b = (a | b) + (a & b)
      Value *Or = IRB.CreateOr(A, B, BO.getName() + ".mba.or");
      Value *And = IRB.CreateAnd(A, B, BO.getName() + ".mba.and");
      Res = IRB.CreateAdd(Or, And, BO.getName() + ".mba.add");
    }
    Res = hardenResult(BO, IRB, Res, Level, FuncRNG);
    BO.replaceAllUsesWith(Res);
    BO.eraseFromParent();
    return true;
  }

  // a - b = (a + ~b) + 1  OR  ~(~a + b)  (polymorphic, both exact)
  static bool substituteSub(BinaryOperator &BO, uint32_t Level,
                            std::mt19937_64 &FuncRNG) {
    IRBuilder<NoFolder> IRB(&BO);
    Type *Ty = BO.getType();
    Value *A = BO.getOperand(0);
    Value *B = BO.getOperand(1);
    Value *Res = nullptr;
    if (FuncRNG() & 1) {
      Value *NotB = IRB.CreateXor(B, ConstantInt::getAllOnesValue(Ty),
                                  BO.getName() + ".mba.not");
      Value *Sum = IRB.CreateAdd(A, NotB, BO.getName() + ".mba.sum");
      Res = IRB.CreateAdd(Sum, ConstantInt::get(Ty, 1),
                          BO.getName() + ".mba.add");
    } else {
      Value *NotA = IRB.CreateXor(A, ConstantInt::getAllOnesValue(Ty),
                                  BO.getName() + ".mba.nota");
      Value *Sum = IRB.CreateAdd(NotA, B, BO.getName() + ".mba.sum");
      Res = IRB.CreateXor(Sum, ConstantInt::getAllOnesValue(Ty),
                          BO.getName() + ".mba.not");
    }
    Res = hardenResult(BO, IRB, Res, Level, FuncRNG);
    BO.replaceAllUsesWith(Res);
    BO.eraseFromParent();
    return true;
  }

  // a ^ b = (a | b) - (a & b)  OR  (a & ~b) | (~a & b)  (polymorphic)
  static bool substituteXor(BinaryOperator &BO, uint32_t Level,
                            std::mt19937_64 &FuncRNG) {
    IRBuilder<NoFolder> IRB(&BO);
    Type *Ty = BO.getType();
    Value *A = BO.getOperand(0);
    Value *B = BO.getOperand(1);
    Value *Res = nullptr;
    if (FuncRNG() & 1) {
      Value *Or = IRB.CreateOr(A, B, BO.getName() + ".mba.or");
      Value *And = IRB.CreateAnd(A, B, BO.getName() + ".mba.and");
      Res = IRB.CreateSub(Or, And, BO.getName() + ".mba.sub");
    } else {
      Value *AllOnes = ConstantInt::getAllOnesValue(Ty);
      Value *NB = IRB.CreateXor(B, AllOnes, BO.getName() + ".mba.nb");
      Value *NA = IRB.CreateXor(A, AllOnes, BO.getName() + ".mba.na");
      Value *L = IRB.CreateAnd(A, NB, BO.getName() + ".mba.l");
      Value *R = IRB.CreateAnd(NA, B, BO.getName() + ".mba.r");
      Res = IRB.CreateOr(L, R, BO.getName() + ".mba.or");
    }
    Res = hardenResult(BO, IRB, Res, Level, FuncRNG);
    BO.replaceAllUsesWith(Res);
    BO.eraseFromParent();
    return true;
  }

  // a & b = ~(~a | ~b)  (De Morgan)
  static bool substituteAnd(BinaryOperator &BO, uint32_t Level,
                            std::mt19937_64 &FuncRNG) {
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
    Res = hardenResult(BO, IRB, Res, Level, FuncRNG);
    BO.replaceAllUsesWith(Res);
    BO.eraseFromParent();
    return true;
  }

  // a | b = ~(~a & ~b)  (De Morgan)
  // a | b = ~(~a & ~b) (De Morgan)  OR  a + b - (a & b)  (polymorphic)
  static bool substituteOr(BinaryOperator &BO, uint32_t Level,
                           std::mt19937_64 &FuncRNG) {
    IRBuilder<NoFolder> IRB(&BO);
    Type *Ty = BO.getType();
    Value *A = BO.getOperand(0);
    Value *B = BO.getOperand(1);
    Value *Res = nullptr;
    if (FuncRNG() & 1) {
      Value *NA = IRB.CreateXor(A, ConstantInt::getAllOnesValue(Ty),
                                BO.getName() + ".mba.na");
      Value *NB = IRB.CreateXor(B, ConstantInt::getAllOnesValue(Ty),
                                BO.getName() + ".mba.nb");
      Value *And = IRB.CreateAnd(NA, NB, BO.getName() + ".mba.and");
      Res = IRB.CreateXor(And, ConstantInt::getAllOnesValue(Ty),
                          BO.getName() + ".mba.not");
    } else {
      // a | b = a + b - (a & b)
      Value *And = IRB.CreateAnd(A, B, BO.getName() + ".mba.and");
      Value *Sum = IRB.CreateAdd(A, B, BO.getName() + ".mba.sum");
      Res = IRB.CreateSub(Sum, And, BO.getName() + ".mba.sub");
    }
    Res = hardenResult(BO, IRB, Res, Level, FuncRNG);
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
