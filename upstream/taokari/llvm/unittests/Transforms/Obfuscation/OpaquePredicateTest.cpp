//===- OpaquePredicateTest.cpp - Opaque predicate tests -------------------===//

#include "llvm/Transforms/Obfuscation/OpaquePredicate.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "gtest/gtest.h"

using namespace llvm;

namespace {
struct TestIR {
  LLVMContext Ctx;
  Module M{"opaque-predicate-test", Ctx};
  Function *F = Function::Create(FunctionType::get(Type::getVoidTy(Ctx), false),
                                 GlobalValue::ExternalLinkage, "f", M);
  BasicBlock *BB = BasicBlock::Create(Ctx, "entry", F);
  IRBuilder<> IRB{BB};
};

ConstantInt *asConstantInt(Value *V) { return dyn_cast<ConstantInt>(V); }

void checkWidth(unsigned Bits) {
  TestIR T;
  auto *Ty = IntegerType::get(T.Ctx, Bits);

  const uint64_t Samples[] = {0, 1, 2, 3, 5, 17, 0x55, 0xaa, ~0ull};
  for (uint64_t Sample : Samples) {
    for (uint64_t Seed = 1; Seed != 32; ++Seed) {
      std::mt19937_64 TrueRNG(Seed);
      auto *True = asConstantInt(taokari::makeTruePredicate(
          T.IRB, ConstantInt::get(Ty, Sample), TrueRNG, "true"));
      ASSERT_NE(nullptr, True);
      EXPECT_TRUE(True->isOne());

      std::mt19937_64 FalseRNG(Seed);
      auto *False = asConstantInt(taokari::makeFalsePredicate(
          T.IRB, ConstantInt::get(Ty, Sample), FalseRNG, "false"));
      ASSERT_NE(nullptr, False);
      EXPECT_TRUE(False->isZero());
    }
  }
}
} // namespace

TEST(OpaquePredicate, AlgebraicFamiliesAreCorrectAcrossIntegerWidths) {
  for (unsigned Bits : {1u, 8u, 16u, 32u, 64u})
    checkWidth(Bits);
}

TEST(OpaquePredicate, FunctionSeedUsesVolatileLoadOfRequestedWidth) {
  TestIR T;
  auto *Ty = Type::getInt32Ty(T.Ctx);
  std::mt19937_64 RNG(7);

  auto *Seed = taokari::makeOpaquePredicateSeed(*T.F, T.IRB, Ty, RNG);
  auto *Load = dyn_cast<LoadInst>(Seed);
  ASSERT_NE(nullptr, Load);
  EXPECT_EQ(Ty, Load->getType());
  EXPECT_TRUE(Load->isVolatile());

  auto *GV = dyn_cast<GlobalVariable>(Load->getPointerOperand());
  ASSERT_NE(nullptr, GV);
  EXPECT_TRUE(GV->isConstant());
  EXPECT_TRUE(GV->hasPrivateLinkage());
}
