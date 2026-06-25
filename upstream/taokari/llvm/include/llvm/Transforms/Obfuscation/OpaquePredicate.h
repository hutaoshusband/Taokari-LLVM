//===- OpaquePredicate.h - Reusable opaque predicate helpers ----*- C++ -*-===//

#ifndef LLVM_TRANSFORMS_OBFUSCATION_OPAQUEPREDICATE_H
#define LLVM_TRANSFORMS_OBFUSCATION_OPAQUEPREDICATE_H

#include "llvm/IR/IRBuilder.h"

#include <random>

namespace llvm {
class Function;
class IntegerType;
class LoadInst;

namespace taokari {

/// Seed source for an opaque predicate.
///
/// Level 1 only ships the algebraic seed (a constant global + volatile load).
/// Level 2 adds context-based seeds whose value the optimizer cannot compute
/// at compile time, so the predicate cannot be constant-folded away.
enum class OpaqueSeedKind {
  Algebraic,     ///< Constant global + volatile load (Level 1). Foldable.
  Pointer,       ///< ptrtoint of a fresh local alloca. Runtime address.
  StackAddress,  ///< llvm.frameaddress(0). Frame pointer at runtime.
  Global,        ///< Mutable (non-constant) global, read volatilely.
  Environment,   ///< frameaddress XOR a local pointer address.
  RuntimeNonce,  ///< Module nonce global, seeded once from frameaddress.
};

/// Level-1 seed: a constant private global plus a volatile load of it.
/// Foldable by a whole-program optimizer (see docs/CONSTANT_FOLDING_AUDIT.md),
/// so Level 2 callers should prefer \c makeContextSeed instead.
Value *makeOpaquePredicateSeed(Function &F, IRBuilder<> &IRB,
                               IntegerType *IntTy, std::mt19937_64 &RNG,
                               const Twine &Name = "tao.opq.seed");

/// Level-2 context seed. Picks a runtime-only value of the requested kind so
/// that no constant-folding pass can evaluate it. \c IntTy may differ from the
/// pointer width; the seed is zero-extended or truncated to match.
Value *makeContextSeed(Function &F, IRBuilder<> &IRB, IntegerType *IntTy,
                       std::mt19937_64 &RNG, OpaqueSeedKind Kind,
                       const Twine &Name = "tao.opaq.ctx");

/// Resolve the current `-taokari-opaq-kind=<k>` flag value. Defaults to
/// \c Algebraic (Level-1 behaviour) when the flag is absent.
OpaqueSeedKind resolveSeedKind();

/// Resolve the `-taokari-opaq-unfoldable` flag. When true, callers should
/// prefer \c makeUnfoldableTruePredicate / \c makeUnfoldableFalsePredicate.
bool resolveUnfoldable();

/// Convenience: build a seed honouring the current flags. Selects the kind
/// from \c resolveSeedKind so passes do not need to read the flag directly.
Value *makeSeedFromFlags(Function &F, IRBuilder<> &IRB, IntegerType *IntTy,
                         std::mt19937_64 &RNG,
                         const Twine &Name = "tao.opaq.seed");

/// Volatile, align-1 load helper. The volatility pins the load so the
/// optimizer cannot forward a stored initializer into it (the main mechanism
/// Level 2 uses to resist constant folding of global-backed seeds).
LoadInst *makeVolatileLoad(IRBuilder<> &IRB, Type *Ty, Value *Ptr,
                           const Twine &Name = "tao.opq.vload");

/// Level-1 algebraic predicate. Folds to a ConstantInt i1 when the seed is a
/// ConstantInt (used by the unit/verify tests).
Value *makeTruePredicate(IRBuilder<> &IRB, Value *Seed, std::mt19937_64 &RNG,
                         const Twine &Name = "tao.opq.true");
Value *makeFalsePredicate(IRBuilder<> &IRB, Value *Seed, std::mt19937_64 &RNG,
                          const Twine &Name = "tao.opq.false");

/// Level-2 unfoldable always-true predicate.
///
/// Uses identities that hold for every integer x but have no InstCombine
/// simplification rule (e.g. `x*(x+1)` is always even, including under
/// overflow, because parity is preserved modulo 2^k). Combined with a
/// non-constant context seed, neither constant folding nor InstCombine can
/// evaluate the result away.
Value *makeUnfoldableTruePredicate(IRBuilder<> &IRB, Value *Seed,
                                   std::mt19937_64 &RNG,
                                   const Twine &Name = "tao.opq.utrue");
Value *makeUnfoldableFalsePredicate(IRBuilder<> &IRB, Value *Seed,
                                    std::mt19937_64 &RNG,
                                    const Twine &Name = "tao.opq.ufalse");

/// Nested unfoldable predicates (Level 3). Compose two unfoldable identities
/// through a shared seed so the result is a two-level chain: a single
/// simplification step cannot resolve it because the inner value feeds the
/// outer comparison. makeNestedTruePredicate folds to true at runtime,
/// makeNestedFalsePredicate to false. Used as a stronger guard than the
/// single-level unfoldable predicates.
Value *makeNestedTruePredicate(IRBuilder<> &IRB, Value *Seed,
                               std::mt19937_64 &RNG,
                               const Twine &Name = "tao.opq.ntrue");
Value *makeNestedFalsePredicate(IRBuilder<> &IRB, Value *Seed,
                                std::mt19937_64 &RNG,
                                const Twine &Name = "tao.opq.nfalse");

} // namespace taokari
} // namespace llvm

#endif
