//===- OpaquePredicate.cpp - Reusable opaque predicate helpers ------------===//

#include "llvm/Transforms/Obfuscation/OpaquePredicate.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"

using namespace llvm;

namespace {
ConstantInt *randomInt(IntegerType *IntTy, std::mt19937_64 &RNG) {
  return ConstantInt::get(IntTy, RNG());
}

ConstantInt *randomNonZeroInt(IntegerType *IntTy, std::mt19937_64 &RNG) {
  auto *Value = randomInt(IntTy, RNG);
  if (Value->isZero())
    return ConstantInt::get(IntTy, 1);
  return Value;
}

Value *makeEvenLowBit(IRBuilder<> &IRB, Value *Seed, ConstantInt *Salt,
                      const Twine &Name) {
  auto *IntTy = cast<IntegerType>(Seed->getType());
  Value *Mixed = IRB.CreateAdd(Seed, Salt, Name + ".mix");
  Value *Carry =
      IRB.CreateAnd(Mixed, ConstantInt::get(IntTy, 1), Name + ".carry");
  Value *Even = IRB.CreateAdd(Mixed, Carry, Name + ".even");
  return IRB.CreateAnd(Even, ConstantInt::get(IntTy, 1), Name + ".bit");
}

Value *makePartition(IRBuilder<> &IRB, Value *Seed, ConstantInt *Mask,
                     const Twine &Name) {
  Value *Left = IRB.CreateAnd(Seed, Mask, Name + ".left");
  Value *Right =
      IRB.CreateAnd(IRB.CreateNot(Seed, Name + ".not"), Mask, Name + ".right");
  return IRB.CreateOr(Left, Right, Name + ".part");
}
} // namespace

Value *taokari::makeOpaquePredicateSeed(Function &F, IRBuilder<> &IRB,
                                        IntegerType *IntTy,
                                        std::mt19937_64 &RNG,
                                        const Twine &Name) {
  auto &M = *F.getParent();
  auto *Init = randomInt(IntTy, RNG);
  auto *GV = new GlobalVariable(M, IntTy, true, GlobalValue::PrivateLinkage,
                                Init, (F.getName() + "." + Name).str());
  GV->addMetadata("noobf", *MDNode::get(M.getContext(), {}));
  return IRB.CreateAlignedLoad(IntTy, GV, Align{1}, true, Name + ".load");
}

Value *taokari::makeTruePredicate(IRBuilder<> &IRB, Value *Seed,
                                  std::mt19937_64 &RNG, const Twine &Name) {
  auto *IntTy = cast<IntegerType>(Seed->getType());
  if (RNG() & 1)
    return IRB.CreateICmpEQ(
        makeEvenLowBit(IRB, Seed, randomInt(IntTy, RNG), Name),
        ConstantInt::get(IntTy, 0), Name);

  auto *Mask = randomNonZeroInt(IntTy, RNG);
  return IRB.CreateICmpEQ(makePartition(IRB, Seed, Mask, Name), Mask, Name);
}

Value *taokari::makeFalsePredicate(IRBuilder<> &IRB, Value *Seed,
                                   std::mt19937_64 &RNG, const Twine &Name) {
  auto *IntTy = cast<IntegerType>(Seed->getType());
  if (RNG() & 1)
    return IRB.CreateICmpNE(
        makeEvenLowBit(IRB, Seed, randomInt(IntTy, RNG), Name),
        ConstantInt::get(IntTy, 0), Name);

  auto *Mask = randomNonZeroInt(IntTy, RNG);
  return IRB.CreateICmpNE(makePartition(IRB, Seed, Mask, Name), Mask, Name);
}
