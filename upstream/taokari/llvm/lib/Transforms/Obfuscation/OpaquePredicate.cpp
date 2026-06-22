//===- OpaquePredicate.cpp - Reusable opaque predicate helpers ------------===//

#include "llvm/Transforms/Obfuscation/OpaquePredicate.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/CommandLine.h"

using namespace llvm;

// User-facing opaque-predicate flags. Defaults preserve Level-1 behaviour, so
// existing tests are unaffected unless a pass explicitly opts in.
static cl::opt<std::string> OpaqSeedKindFlag(
    "taokari-opaq-kind",
    cl::desc("Opaque predicate seed source: algebraic|pointer|stack|global|"
             "environment|nonce"),
    cl::init("algebraic"));
static cl::opt<bool> OpaqUnfoldableFlag(
    "taokari-opaq-unfoldable",
    cl::desc("Use optimizer-resistant opaque predicates (Level 2)"),
    cl::init(false));

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

/// Fit a pointer-width integer value into the requested (possibly narrower or
/// wider) integer type. NoFold builder keeps the cast as a real instruction
/// so the optimizer cannot immediately fold it back to a constant.
Value *fitToInt(IRBuilder<> &IRB, Value *V, IntegerType *IntTy,
                const Twine &Name) {
  IntegerType *SrcTy = cast<IntegerType>(V->getType());
  if (SrcTy == IntTy)
    return V;
  if (SrcTy->getBitWidth() < IntTy->getBitWidth())
    return IRB.CreateZExt(V, IntTy, Name + ".zext");
  if (SrcTy->getBitWidth() > IntTy->getBitWidth())
    return IRB.CreateTrunc(V, IntTy, Name + ".trunc");
  return V;
}

/// Lower a pointer-typed runtime value into IntTy via ptrtoint.
Value *pointerToSeed(IRBuilder<> &IRB, Value *Ptr, IntegerType *IntTy,
                     const Twine &Name) {
  auto &M = *IRB.GetInsertBlock()->getModule();
  unsigned PtrBits = M.getDataLayout().getPointerSizeInBits();
  auto *PtrIntTy = IntegerType::get(M.getContext(), PtrBits);
  Value *AsInt = IRB.CreatePtrToInt(Ptr, PtrIntTy, Name + ".p2i");
  return fitToInt(IRB, AsInt, IntTy, Name);
}

/// Allocate a small local frame slot and return its address. Its runtime
/// address depends on stack layout, so a `ptrtoint` of it cannot be folded.
Value *freshLocalPointer(IRBuilder<> &IRB, const Twine &Name) {
  auto *Int8Ty = Type::getInt8Ty(IRB.getContext());
  auto *Slot = IRB.CreateAlloca(Int8Ty, nullptr, Name + ".slot");
  return Slot;
}

/// Resolve `llvm.frameaddress(i32 0)`. Returns the C frame pointer, which is
/// a runtime value the compiler cannot reason about.
Value *frameAddress(IRBuilder<> &IRB, const Twine &Name) {
  auto &M = *IRB.GetInsertBlock()->getModule();
  auto *PtrTy = IRB.getPtrTy(M.getDataLayout().getAllocaAddrSpace());
  Value *FP = IRB.CreateIntrinsic(
      Intrinsic::frameaddress, PtrTy,
      {Constant::getNullValue(Type::getInt32Ty(M.getContext()))}, nullptr,
      Name + ".fp");
  return FP;
}

/// Lazy lookup/create of the module-wide nonce global. The global is mutable
/// and read through a volatile load, so callers keep a runtime dependency.
GlobalVariable *getOrCreateRuntimeNonce(Module &M, IRBuilder<> &IRB,
                                        IntegerType *IntTy,
                                        std::mt19937_64 &RNG,
                                        const Twine &Name) {
  // The nonce is keyed off the requested integer width so different callers
  // share a single global of matching width. Multiple widths produce a few
  // small globals; this is a deliberate code/safety trade.
  std::string GVName = (Twine("__taokari_opaq_nonce_") +
                        Twine(IntTy->getBitWidth())).str();
  GlobalVariable *GV = M.getGlobalVariable(GVName, true);
  if (GV)
    return GV;

  auto *Init = randomInt(IntTy, RNG);
  GV = new GlobalVariable(M, IntTy, /*isConstant=*/false,
                          GlobalValue::PrivateLinkage, Init, GVName);
  GV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
  return GV;
}
} // namespace

LoadInst *taokari::makeVolatileLoad(IRBuilder<> &IRB, Type *Ty, Value *Ptr,
                                    const Twine &Name) {
  return IRB.CreateAlignedLoad(Ty, Ptr, Align{1}, /*isVolatile=*/true,
                               Name + ".vload");
}

Value *taokari::makeOpaquePredicateSeed(Function &F, IRBuilder<> &IRB,
                                        IntegerType *IntTy,
                                        std::mt19937_64 &RNG,
                                        const Twine &Name) {
  auto &M = *F.getParent();
  auto *Init = randomInt(IntTy, RNG);
  auto *GV = new GlobalVariable(M, IntTy, true, GlobalValue::PrivateLinkage,
                                Init, (F.getName() + "." + Name).str());
  GV->addMetadata("noobf", *MDNode::get(M.getContext(), {}));
  return makeVolatileLoad(IRB, IntTy, GV, Name);
}

Value *taokari::makeContextSeed(Function &F, IRBuilder<> &IRB,
                                IntegerType *IntTy, std::mt19937_64 &RNG,
                                OpaqueSeedKind Kind, const Twine &Name) {
  switch (Kind) {
  case OpaqueSeedKind::Algebraic:
    return makeOpaquePredicateSeed(F, IRB, IntTy, RNG, Name);

  case OpaqueSeedKind::Pointer: {
    Value *Slot = freshLocalPointer(IRB, Name);
    return pointerToSeed(IRB, Slot, IntTy, Name);
  }

  case OpaqueSeedKind::StackAddress: {
    Value *FP = frameAddress(IRB, Name);
    return pointerToSeed(IRB, FP, IntTy, Name);
  }

  case OpaqueSeedKind::Global: {
    // Mutable global so the optimizer has no constant initializer to fold.
    auto &M = *F.getParent();
    auto *Init = randomInt(IntTy, RNG);
    auto *GV = new GlobalVariable(M, IntTy, /*isConstant=*/false,
                                  GlobalValue::PrivateLinkage, Init,
                                  (F.getName() + "." + Name + ".g").str());
    return makeVolatileLoad(IRB, IntTy, GV, Name);
  }

  case OpaqueSeedKind::Environment: {
    Value *FP = frameAddress(IRB, Name);
    Value *FPInt = pointerToSeed(IRB, FP, IntTy, Name + ".fp");
    Value *Slot = freshLocalPointer(IRB, Name);
    Value *SlotInt = pointerToSeed(IRB, Slot, IntTy, Name + ".slot");
    return IRB.CreateXor(FPInt, SlotInt, Name + ".env");
  }

  case OpaqueSeedKind::RuntimeNonce: {
    auto &M = *F.getParent();
    GlobalVariable *GV = getOrCreateRuntimeNonce(M, IRB, IntTy, RNG, Name);
    return makeVolatileLoad(IRB, IntTy, GV, Name);
  }
  }
  llvm_unreachable("unknown OpaqueSeedKind");
}

namespace llvm::taokari {
OpaqueSeedKind resolveSeedKind() {
  const std::string &V = OpaqSeedKindFlag;
  if (V == "pointer")
    return OpaqueSeedKind::Pointer;
  if (V == "stack")
    return OpaqueSeedKind::StackAddress;
  if (V == "global")
    return OpaqueSeedKind::Global;
  if (V == "environment")
    return OpaqueSeedKind::Environment;
  if (V == "nonce")
    return OpaqueSeedKind::RuntimeNonce;
  return OpaqueSeedKind::Algebraic;
}

bool resolveUnfoldable() { return OpaqUnfoldableFlag; }

Value *makeSeedFromFlags(Function &F, IRBuilder<> &IRB, IntegerType *IntTy,
                         std::mt19937_64 &RNG, const Twine &Name) {
  return makeContextSeed(F, IRB, IntTy, RNG, resolveSeedKind(), Name);
}
} // namespace llvm::taokari

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

Value *taokari::makeUnfoldableTruePredicate(IRBuilder<> &IRB, Value *Seed,
                                            std::mt19937_64 &RNG,
                                            const Twine &Name) {
  // x*(x+1) is always even: among two consecutive integers one is even, so the
  // product is even, including under unsigned wraparound (parity is preserved
  // modulo 2^k). There is no InstCombine rule that proves this, so the only
  // way the optimizer can simplify the comparison is to fold the seed first.
  // Level-2 seeds are runtime values, so the predicate stays.
  auto *IntTy = cast<IntegerType>(Seed->getType());
  Value *Inc = IRB.CreateAdd(Seed, ConstantInt::get(IntTy, 1), Name + ".inc");
  Value *Prod = IRB.CreateMul(Seed, Inc, Name + ".prod");
  Value *Low = IRB.CreateAnd(Prod, ConstantInt::get(IntTy, 1), Name + ".low");
  return IRB.CreateICmpEQ(Low, ConstantInt::get(IntTy, 0), Name);
}

Value *taokari::makeUnfoldableFalsePredicate(IRBuilder<> &IRB, Value *Seed,
                                             std::mt19937_64 &RNG,
                                             const Twine &Name) {
  auto *IntTy = cast<IntegerType>(Seed->getType());
  Value *Inc = IRB.CreateAdd(Seed, ConstantInt::get(IntTy, 1), Name + ".inc");
  Value *Prod = IRB.CreateMul(Seed, Inc, Name + ".prod");
  Value *Low = IRB.CreateAnd(Prod, ConstantInt::get(IntTy, 1), Name + ".low");
  return IRB.CreateICmpNE(Low, ConstantInt::get(IntTy, 1), Name);
}
