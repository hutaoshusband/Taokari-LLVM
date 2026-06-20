//===- OpaquePredicate.h - Reusable opaque predicate helpers ----*- C++ -*-===//

#ifndef LLVM_TRANSFORMS_OBFUSCATION_OPAQUEPREDICATE_H
#define LLVM_TRANSFORMS_OBFUSCATION_OPAQUEPREDICATE_H

#include "llvm/IR/IRBuilder.h"

#include <random>

namespace llvm {
class Function;
class IntegerType;

namespace taokari {

Value *makeOpaquePredicateSeed(Function &F, IRBuilder<> &IRB,
                               IntegerType *IntTy, std::mt19937_64 &RNG,
                               const Twine &Name = "tao.opq.seed");
Value *makeTruePredicate(IRBuilder<> &IRB, Value *Seed, std::mt19937_64 &RNG,
                         const Twine &Name = "tao.opq.true");
Value *makeFalsePredicate(IRBuilder<> &IRB, Value *Seed, std::mt19937_64 &RNG,
                          const Twine &Name = "tao.opq.false");

} // namespace taokari
} // namespace llvm

#endif
