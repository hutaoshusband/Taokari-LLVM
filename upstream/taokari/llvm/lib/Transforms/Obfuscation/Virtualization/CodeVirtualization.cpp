#include "llvm/Transforms/Obfuscation/CodeVirtualization.h"
#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/Analysis/OptimizationRemarkEmitter.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/Pass.h"
#include "llvm/Support/Alignment.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/RandomNumberGenerator.h"

#include <algorithm>
#include <cstdint>
#include <functional>
#include <random>
#include <string>

#define DEBUG_TYPE "taokari-vmp"

using namespace llvm;

namespace {

// Opcode encoding is the stable on-the-wire bytecode value. These
// integers must NOT change once bytecode is shipped; the interpreter handler
// table is keyed off them. L2 opcode-mapping/encryption layers will sit on
// top of these values, not replace them.
enum Opcode : int64_t {
  OpInitArg = 1,
  OpPushConst = 2,
  OpLoadSlot = 3,
  OpStoreSlot = 4,
  OpAdd = 5,
  OpSub = 6,
  OpXor = 7,
  OpCmpEq = 8,
  OpCmpNe = 9,
  OpCmpSgt = 10,
  OpCmpSlt = 11,
  OpCmpSge = 12,
  OpCmpSle = 13,
  OpJmp = 14,
  OpBrTrue = 15,
  OpRet = 16,
  OpSelect = 17,
  // L1.5.1 widened integer binary ops. Values 18+ are the new ISA;
  // 1..17 stay stable so existing bytecode keeps working.
  OpMul = 18,
  OpAnd = 19,
  OpOr = 20,
  OpShl = 21,
  OpLShr = 22,
  OpAShr = 23,
  OpSDiv = 24,
  OpUDiv = 25,
  OpSRem = 26,
  OpURem = 27,
  // L1.5.1 unsigned compares. Operands stay in canonical zext form;
  // unsigned comparison is width-agnostic, so these carry no VmTy immediate
  // (like EQ/NE).
  OpCmpUgt = 28,
  OpCmpUlt = 29,
  OpCmpUge = 30,
  OpCmpUle = 31,
  // L1.5.1 VM-local memory (middle way). Frame pointers are static
  // i64 indices into a per-interpreter Frame array; alloca/GEP resolve to
  // compile-time PushConst of the frame index. LoadPtr/StorePtr carry a VmTy
  // for width narrowing.
  OpLoadPtr = 32,
  OpStorePtr = 33,
  // L1.5.1 direct calls. OpCall fetches <calleeIdx> <nargs>
  // <resultVmTy>, pops nargs operand-stack values into a call-args buffer,
  // calls callees[calleeIdx] (resolved by the encoder to a direct Function*),
  // and pushes the i64 return narrowed by resultVmTy. Integer args/return
  // only; pointer/float/vararg callees reject the whole function. Indirect/
  // virtual calls stay rejected.
  OpCall = 34,
  // External pointer argument load/store. Pointers are carried as i64
  // addresses; memory is accessed bytewise at the encoded integer width.
  OpLoadMem = 35,
  OpStoreMem = 36,
  // External pointer GEP with one runtime index: base + index * byte stride.
  OpGep = 37,
  OpPtrConst = 38,
};

// How many operand-stack pops and bytecode immediates a handler
// consumes. The encoder uses these for stack-depth validation; the
// interpreter construction uses them for diagnostics only (each handler
// drives its own fetch()/pop() count for now, since some are data-dependent
// like OpInitArg which fetches two immediates).
struct HandlerStackShape {
  unsigned Pops = 0;
  unsigned Pushes = 0;
  unsigned Immediates = 0;
};

// Per-value width+signedness. The VM stores everything as i64, but
// arithmetic must wrap at the operand's native width and signed/unsigned
// distinctions (compare, shift, div/rem) must be preserved. The encoder
// records VmTy per value and emits it as immediates alongside the opcodes
// that need it; the interpreter narrows results back to the operand width.
//
// This is the L1.5.1 fix for the blind i64-promotion hazard: previously
// `int x = (a+b) ^ 5` with a=INT_MAX,b=1 computed (a+b) in i64 (no overflow)
// and only truncated at return, diverging from native i32 wraparound.
struct VmTy {
  uint8_t Bits = 64;
  bool Signed = true;
};

static VmTy vmTyFromType(Type *Ty) {
  VmTy T;
  if (auto *IntTy = dyn_cast<IntegerType>(Ty))
    T.Bits = IntTy->getBitWidth();
  // Integer types in C are signed by default; the encoder overrides Signed
  // per-use when it knows the signedness from the instruction (e.g. UDiv is
  // unsigned). For plain loads/args the conservative default is signed.
  return T;
}

// Pack VmTy into a single int64 immediate (bits 0..7 = width,
// bit 8 = signed). One word instead of two keeps the bytecode compact.
static int64_t packVmTy(VmTy T) {
  return static_cast<int64_t>(T.Bits) | (T.Signed ? (1LL << 8) : 0);
}
static VmTy unpackVmTy(int64_t V) {
  VmTy T;
  T.Bits = static_cast<uint8_t>(V & 0xFF);
  T.Signed = (V >> 8) & 1;
  return T;
}

struct Fixup {
  size_t Index;
  const BasicBlock *Target;
};

struct BytecodeProgram {
  SmallVector<int64_t, 64> Words;
  SmallVector<Fixup, 8> Fixups;
  SmallVector<Constant *, 8> PointerConsts;
  DenseMap<const Value *, unsigned> PointerConstIndex;
};

// Handler descriptor. The interpreter builder iterates the table
// and emits one switch case per entry; opcode values stay the stable enum.
// This is the L1.5.2 refactor target: previously every opcode was a hand-
// written case in createInterpreter with no arity metadata. Now the
// table is the source of truth for stack shape, and the Emit closure is the
// only opcode-specific code.
//
// E operates on the IRBuilder already positioned at a fresh case block; it
// owns its own pop()/fetch() calls and must terminate the block with a
// branch back to Dispatch (or a ret).
struct Handler {
  Opcode Op;
  StringRef Name;
  HandlerStackShape Shape;
  std::function<void(IRBuilder<> &)> Emit;
};

struct CodeVirtualization : public ModulePass {
  static char ID;
  ObfuscationOptions *ArgsOptions;
  std::mt19937_64 RNG;
  // Per-module direct-callee table (L1.5.1). Populated lazily by
  // buildBytecode as it encounters direct CallInsts; resolved into a
  // __taokari_vmp_callees global by finalizeCalleeTable() before the
  // interpreter is built. OpCall indexes into it.
  DenseMap<Function *, unsigned> CalleeIndex;
  SmallVector<Function *, 8> CalleeOrder;
  GlobalVariable *CalleeTable = nullptr;
  uint64_t CalleeTableKey = 0;

  CodeVirtualization(ObfuscationOptions *ArgsOptions) : ModulePass(ID) {
    this->ArgsOptions = ArgsOptions;
    uint64_t Seed = 0;
    if (auto EC = llvm::getRandomBytes(&Seed, sizeof(Seed)))
      report_fatal_error("failed to initialize VMP RNG");
    RNG = std::mt19937_64(Seed);
  }

  StringRef getPassName() const override {
    return "Taokari Code Virtualization";
  }

  bool isSupportedInt(Type *Ty) const {
    return Ty->isIntegerTy() && Ty->getIntegerBitWidth() <= 64;
  }

  bool isSupportedPointer(Type *Ty, const DataLayout &DL) const {
    if (!Ty->isPointerTy())
      return false;
    auto *PT = cast<PointerType>(Ty);
    return DL.getPointerSizeInBits(PT->getAddressSpace()) <= 64;
  }

  bool isSupportedArg(Type *Ty, const DataLayout &DL) const {
    return isSupportedInt(Ty) || isSupportedPointer(Ty, DL);
  }

  bool isSkippable(const Instruction &I) const {
    return isa<DbgInfoIntrinsic>(I) || isa<AssumeInst>(I);
  }

  // True if a CallInst is virtualizable by the L1.5.1 OpCall path.
  // Requirements: direct callee (Function*, not a function pointer), non-
  // variadic, integer args each <=64 bits, integer-or-void return <=64 bits.
  // Indirect/virtual calls, vararg, pointer/float args reject the caller.
  bool isVMCompatibleCall(const CallInst &CI) const {
    const Function *Callee = dyn_cast<Function>(CI.getCalledOperand());
    if (!Callee)
      return false; // indirect call (function pointer)
    if (Callee->isVarArg())
      return false;
    if (!Callee->getReturnType()->isVoidTy() &&
        !isSupportedInt(Callee->getReturnType()))
      return false;
    for (const Use &Arg : CI.args()) {
      if (!isSupportedInt(Arg->getType()))
        return false;
    }
    if (CI.arg_size() > 8)
      return false;
    return true;
  }

  bool shouldSkip(Function &F) const {
    if (F.isDeclaration() || F.isIntrinsic() || F.isVarArg())
      return true;
    if (F.getName().starts_with("__taokari_vmp_"))
      return true;
    if (!isSupportedInt(F.getReturnType()))
      return true;
    if (F.arg_size() > 8)
      return true;
    const DataLayout &DL = F.getParent()->getDataLayout();
    for (Argument &A : F.args())
      if (!isSupportedArg(A.getType(), DL))
        return true;
    return false;
  }

  bool hasUnsupportedIR(Function &F) const {
    for (BasicBlock &BB : F) {
      for (Instruction &I : BB) {
        if (isSkippable(I))
          continue;
        if (isa<PHINode>(I))
          continue;
        // Level 1 VM is toy integer IR only. Add call/EH support
        // after this compile/run path proves useful. PHI is supported
        // (L1.5.1): lowered to slot copies in predecessors. VM-local alloca/
        // load/store/constant-GEP are supported (L1.5.1 middle way): the
        // pointer-origin check happens in buildBytecode (needs whole-function
        // alloca context, which this const scan lacks). Direct CallInst with
        // integer-only signature is supported (L1.5.1): buildBytecode rejects
        // if the callee is indirect or has non-integer args/return.
        if (isa<InvokeInst>(I) || isa<ResumeInst>(I) ||
            isa<LandingPadInst>(I) ||
            isa<AtomicRMWInst>(I) || isa<AtomicCmpXchgInst>(I) ||
            isa<FenceInst>(I))
          return true;
        if (auto *BO = dyn_cast<BinaryOperator>(&I)) {
          if (!isSupportedInt(BO->getType()))
            return true;
          switch (BO->getOpcode()) {
          case Instruction::Add:
          case Instruction::Sub:
          case Instruction::Xor:
          // L1.5.1 widened integer binary ops.
          case Instruction::Mul:
          case Instruction::And:
          case Instruction::Or:
          case Instruction::Shl:
          case Instruction::LShr:
          case Instruction::AShr:
          case Instruction::SDiv:
          case Instruction::UDiv:
          case Instruction::SRem:
          case Instruction::URem:
            break;
          default:
            return true;
          }
          continue;
        }
        if (auto *Cmp = dyn_cast<ICmpInst>(&I)) {
          if (!isSupportedInt(Cmp->getOperand(0)->getType()) ||
              !isSupportedInt(Cmp->getOperand(1)->getType()))
            return true;
          switch (Cmp->getPredicate()) {
          case CmpInst::ICMP_EQ:
          case CmpInst::ICMP_NE:
          case CmpInst::ICMP_SGT:
          case CmpInst::ICMP_SLT:
          case CmpInst::ICMP_SGE:
          case CmpInst::ICMP_SLE:
          case CmpInst::ICMP_UGT:
          case CmpInst::ICMP_ULT:
          case CmpInst::ICMP_UGE:
          case CmpInst::ICMP_ULE:
            break;
          default:
            return true;
          }
          continue;
        }
        if (auto *Sel = dyn_cast<SelectInst>(&I)) {
          if (!Sel->getCondition()->getType()->isIntegerTy(1) ||
              !isSupportedInt(Sel->getTrueValue()->getType()) ||
              !isSupportedInt(Sel->getFalseValue()->getType()))
            return true;
          continue;
        }
        if (auto *Cast = dyn_cast<CastInst>(&I)) {
          const DataLayout &DL = F.getParent()->getDataLayout();
          switch (Cast->getOpcode()) {
          case Instruction::ZExt:
          case Instruction::Trunc:
            if (!isSupportedInt(Cast->getSrcTy()) ||
                !isSupportedInt(Cast->getDestTy()))
              return true;
            break;
          case Instruction::PtrToInt:
            if (!isSupportedPointer(Cast->getSrcTy(), DL) ||
                !isSupportedInt(Cast->getDestTy()))
              return true;
            break;
          case Instruction::IntToPtr:
            if (!isSupportedInt(Cast->getSrcTy()) ||
                !isSupportedPointer(Cast->getDestTy(), DL))
              return true;
            break;
          default:
            return true;
          }
          continue;
        }
        // VM-local memory (L1.5.1 middle way). Allow AllocaInst,
        // LoadInst, StoreInst, GetElementPtrInst here; buildBytecode rejects
        // the function if any pointer origin is non-VM-local (external arg,
        // global, etc.) -- that check needs whole-function alloca context.
        if (isa<AllocaInst>(I) || isa<LoadInst>(I) || isa<StoreInst>(I) ||
            isa<GetElementPtrInst>(I))
          continue;
        // direct CallInst allowed (L1.5.1); indirect/non-integer
        // signature still rejects via buildBytecode's isVMCompatibleCall.
        if (isa<CallInst>(I))
          continue;
        if (isa<BranchInst>(I) || isa<ReturnInst>(I))
          continue;
        return true;
      }
    }
    return false;
  }

  unsigned slotFor(DenseMap<const Value *, unsigned> &Slots, const Value *V) {
    auto It = Slots.find(V);
    if (It != Slots.end())
      return It->second;
    unsigned Slot = Slots.size();
    Slots[V] = Slot;
    return Slot;
  }

  unsigned pointerConstFor(BytecodeProgram &P, Constant *C) {
    auto It = P.PointerConstIndex.find(C);
    if (It != P.PointerConstIndex.end())
      return It->second;
    unsigned Idx = P.PointerConsts.size();
    P.PointerConstIndex[C] = Idx;
    P.PointerConsts.push_back(C);
    return Idx;
  }

  // True if Ty can live in the VM-local frame (integer scalars,
  // arrays of integers, or simple aggregates of integers -- anything we can
  // bucket into i64 slots). Pointers, floats, and nested pointer/float
  // aggregates are rejected (deferred to the L2 full-pointer step).
  bool isFrameCompatible(Type *Ty) const {
    if (Ty->isIntegerTy())
      return true;
    if (auto *Arr = dyn_cast<ArrayType>(Ty))
      return isFrameCompatible(Arr->getElementType());
    if (auto *St = dyn_cast<StructType>(Ty))
      return St->getNumElements() > 0 &&
             all_of(St->elements(),
                    [this](Type *E) { return isFrameCompatible(E); });
    return false;
  }

  // Emit a value-push that carries the value's VmTy so the
  // interpreter can sign/zero-extend into the i64 slot correctly. For a
  // ConstantInt we encode the full sext/zext value directly; for a slot we
  // emit its index. In both cases a packed VmTy immediate follows so the
  // interpreter narrows/promotes the right way before any consumer sees it.
  // VM-local pointers (alloca-derived) resolve to a PushConst of the frame
  // slot index via resolveFramePtr. Pointer args use their locals slot as a
  // raw host address for OpLoadMem/OpStoreMem.
  bool emitValue(BytecodeProgram &P, DenseMap<const Value *, unsigned> &Slots,
                 DenseMap<const AllocaInst *, unsigned> &AllocaBase,
                 unsigned &NextFrameSlot, Value *V) {
    // VM-local pointer: alloca or constant-offset GEP of an alloca.
    if (V->getType()->isPointerTy()) {
      if (auto *GV = dyn_cast<GlobalVariable>(V)) {
        P.Words.push_back(OpPtrConst);
        P.Words.push_back(pointerConstFor(P, GV));
        return true;
      }
      int64_t FrameIdx = 0;
      if (resolveFramePtr(V, AllocaBase, NextFrameSlot, FrameIdx)) {
        P.Words.push_back(OpPushConst);
        P.Words.push_back(FrameIdx);
      } else {
        auto It = Slots.find(V);
        if (It == Slots.end())
          return false;
        P.Words.push_back(OpLoadSlot);
        P.Words.push_back(It->second);
      }
      P.Words.push_back(packVmTy(VmTy{64, false}));
      return true;
    }
    VmTy Ty = vmTyFromType(V->getType());
    if (auto *CI = dyn_cast<ConstantInt>(V)) {
      if (CI->getBitWidth() > 64)
        return false;
      P.Words.push_back(OpPushConst);
      P.Words.push_back(CI->getSExtValue());
      P.Words.push_back(packVmTy(Ty));
      return true;
    }
    auto It = Slots.find(V);
    if (It == Slots.end())
      return false;
    P.Words.push_back(OpLoadSlot);
    P.Words.push_back(It->second);
    P.Words.push_back(packVmTy(Ty));
    return true;
  }

  // Emit slot copies for every PHI in `Succ` whose incoming value
  // for predecessor `Pred` must be stored into the PHI's slot before control
  // transfers from Pred to Succ. This is the L1.5.1 PHI lowering: the PHI
  // result is materialized as a locals slot, and each predecessor writes its
  // incoming value into that slot just before branching. Handles loop-carry
  // PHIs naturally (the slot holds the previous iteration's value).
  bool emitPhiCopies(BytecodeProgram &P,
                     DenseMap<const Value *, unsigned> &Slots,
                     DenseMap<const AllocaInst *, unsigned> &AllocaBase,
                     unsigned &NextFrameSlot,
                     const BasicBlock *Pred, const BasicBlock *Succ) {
    for (const Instruction &I : *Succ) {
      auto *PN = dyn_cast<PHINode>(&I);
      if (!PN)
        break; // PHIs are always first in the block.
      int Idx = PN->getBasicBlockIndex(Pred);
      if (Idx < 0)
        return false; // malformed: no incoming for this predecessor.
      Value *Incoming = PN->getIncomingValue(Idx);
      // The incoming value may be UndefValue (e.g. unreachable predecessor);
      // skip such copies -- the slot stays whatever it was.
      if (isa<UndefValue>(Incoming))
        continue;
      if (!emitValue(P, Slots, AllocaBase, NextFrameSlot, Incoming))
        return false;
      P.Words.push_back(OpStoreSlot);
      P.Words.push_back(slotFor(Slots, PN));
    }
    return true;
  }

  // Resolve a VM-local pointer to a Frame slot index. Returns false
  // if the pointer origin is not VM-local (external arg, global, etc.) -- in
  // which case buildBytecode rejects the whole function. V must be an
  // AllocaInst result, or a constant-offset GEP whose base is VM-local. The
  // Frame is an i64 array in the interpreter; each alloca reserves a run of
  // consecutive frame slots sized to the alloca's element count.
  //
  // Frame layout is built lazily: AllocaInst encountered during emission
  // reserve slots in `FrameMap` (alloca -> base index). GEP resolves by
  // walking to the base alloca and adding the constant byte offset / 8.
  bool resolveFramePtr(const Value *V,
                       DenseMap<const AllocaInst *, unsigned> &AllocaBase,
                       unsigned &NextFrameSlot, int64_t &OutIdx) const {
    // Strip a constant-offset GEP chain down to its base.
    APInt ByteOffset(64, 0);
    const Value *Base = V;
    while (auto *GEP = dyn_cast<GetElementPtrInst>(Base)) {
      if (!GEP->accumulateConstantOffset(
              GEP->getModule()->getDataLayout(), ByteOffset))
        return false; // non-constant index -> defer to L2
      Base = GEP->getPointerOperand();
    }
    const auto *AI = dyn_cast<AllocaInst>(Base);
    if (!AI)
      return false; // external/global pointer -> defer to L2
    auto It = AllocaBase.find(AI);
    if (It == AllocaBase.end())
      return false; // alloca not yet allocated (shouldn't happen post-scan)
    OutIdx = static_cast<int64_t>(It->second) +
             ByteOffset.getZExtValue() / sizeof(int64_t);
    return true;
  }

  // Build-time operand-stack depth check (L1.5.4). Walks the
  // bytecode simulating the max operand-stack depth using HandlerStackShape.
  // Fails (returns false) if the depth would exceed the fixed 64-slot Stack
  // alloca at any point -- otherwise the interpreter would silently overflow
  // into adjacent memory. Control-flow opcodes (Jmp/BrTrue/Ret) reset or
  // terminate the simulation conservatively; this is a safety bound, not a
  // precise abstract interpreter.
  bool checkStackDepth(const BytecodeProgram &P) const {
    constexpr unsigned kStackCap = 64;
    int64_t Depth = 0;
    int64_t MaxDepth = 0;
    size_t I = 0;
    size_t N = P.Words.size();
    while (I < N) {
      int64_t Op = P.Words[I++];
      if (Op < 0)
        return false;
      HandlerStackShape Shape = shapeOf(static_cast<Opcode>(Op));
      Depth -= static_cast<int64_t>(Shape.Pops);
      if (Depth < 0)
        return false; // underflow: malformed bytecode
      Depth += static_cast<int64_t>(Shape.Pushes);
      if (Depth > MaxDepth)
        MaxDepth = Depth;
      // Skip the trailing immediates this opcode consumes.
      I += Shape.Immediates;
    }
    return MaxDepth <= kStackCap;
  }

  bool buildBytecode(Function &F, BytecodeProgram &P) {
    DenseMap<const Value *, unsigned> Slots;
    DenseMap<const BasicBlock *, size_t> BlockStart;
    // VM-local frame allocator. Each AllocaInst reserves
    // ceil(allocSize / 8) consecutive frame slots (i64 units).
    DenseMap<const AllocaInst *, unsigned> AllocaBase;
    unsigned NextFrameSlot = 0;
    constexpr unsigned kFrameSlotCap = 64;

    // Pre-scan: reserve frame slots for every alloca so any later reference
    // (including a GEP ahead of the alloca in a different block) resolves.
    for (BasicBlock &BB : F) {
      for (Instruction &I : BB) {
        auto *AI = dyn_cast<AllocaInst>(&I);
        if (!AI)
          continue;
        Type *Ty = AI->getAllocatedType();
        // Only scalar/array integer or aggregate-of-integer types we can
        // cleanly bucket into i64 slots. Reject anything with pointers or
        // floats inside (the middle way is integer locals only).
        if (!isFrameCompatible(Ty))
          return false;
        uint64_t SizeBytes =
            Ty->isSized() ? F.getParent()->getDataLayout().getTypeAllocSize(Ty)
                          : 0;
        unsigned SlotsNeeded =
            static_cast<unsigned>((SizeBytes + 7) / 8);
        if (SlotsNeeded == 0)
          SlotsNeeded = 1;
        if (NextFrameSlot + SlotsNeeded > kFrameSlotCap)
          return false; // frame too large -> skip virtualization
        AllocaBase[AI] = NextFrameSlot;
        NextFrameSlot += SlotsNeeded;
      }
    }

    unsigned ArgIndex = 0;
    for (Argument &A : F.args()) {
      unsigned Slot = slotFor(Slots, &A);
      P.Words.append({OpInitArg, static_cast<int64_t>(Slot),
                      static_cast<int64_t>(ArgIndex++)});
    }

    for (BasicBlock &BB : F) {
      BlockStart[&BB] = P.Words.size();
      // pre-register PHI slots so any use of a PHI (including by
      // another PHI in the same block, or by an instruction before the PHI
      // list ends -- they're all at block top) resolves to the right slot.
      for (Instruction &I : BB) {
        auto *PN = dyn_cast<PHINode>(&I);
        if (!PN)
          break; // PHIs are always first; stop at the first non-PHI.
        if (!isSupportedInt(PN->getType()))
          return false;
        slotFor(Slots, PN);
      }
      for (Instruction &I : BB) {
        if (isSkippable(I))
          continue;
        if (isa<PHINode>(I)) {
          // PHI nodes produce no bytecode inline. Their effect is
          // the predecessor-side slot copies emitted by emitPhiCopies below.
          continue;
        }
        if (auto *BO = dyn_cast<BinaryOperator>(&I)) {
          if (!emitValue(P, Slots, AllocaBase, NextFrameSlot, BO->getOperand(0)) ||
              !emitValue(P, Slots, AllocaBase, NextFrameSlot, BO->getOperand(1)))
            return false;
          VmTy ResultTy = vmTyFromType(BO->getType());
          // signedness for the few ops where it matters at encode
          // time. Mul/And/Or/Xor/Add/Sub/Shl are sign-agnostic; the narrowing
          // uses the type width only. AShr is signed (arithmetic) shift, LShr
          // is unsigned (logical) shift; UDiv/URem unsigned, SDiv/SRem signed.
          // The interpreter opcode choice (OpAShr vs OpLShr, OpSDiv vs OpUDiv)
          // already encodes this, so the VmTy.Signed here is only consulted by
          // the narrowing helper, which for these ops behaves the same
          // regardless of Signed (the result fits in width either way).
          switch (BO->getOpcode()) {
          case Instruction::Add:
            P.Words.push_back(OpAdd);
            break;
          case Instruction::Sub:
            P.Words.push_back(OpSub);
            break;
          case Instruction::Xor:
            P.Words.push_back(OpXor);
            break;
          case Instruction::Mul:
            P.Words.push_back(OpMul);
            break;
          case Instruction::And:
            P.Words.push_back(OpAnd);
            break;
          case Instruction::Or:
            P.Words.push_back(OpOr);
            break;
          case Instruction::Shl:
            P.Words.push_back(OpShl);
            break;
          case Instruction::LShr:
            P.Words.push_back(OpLShr);
            break;
          case Instruction::AShr:
            P.Words.push_back(OpAShr);
            break;
          case Instruction::SDiv:
            P.Words.push_back(OpSDiv);
            break;
          case Instruction::UDiv:
            P.Words.push_back(OpUDiv);
            break;
          case Instruction::SRem:
            P.Words.push_back(OpSRem);
            break;
          case Instruction::URem:
            P.Words.push_back(OpURem);
            break;
          default:
            return false;
          }
          // operand/result width so the interpreter truncates the
          // i64 arithmetic back to the native width (fixes i32 wraparound).
          P.Words.push_back(packVmTy(ResultTy));
          P.Words.push_back(OpStoreSlot);
          P.Words.push_back(slotFor(Slots, &I));
          continue;
        }
        if (auto *Cmp = dyn_cast<ICmpInst>(&I)) {
          if (!emitValue(P, Slots, AllocaBase, NextFrameSlot, Cmp->getOperand(0)) ||
              !emitValue(P, Slots, AllocaBase, NextFrameSlot, Cmp->getOperand(1)))
            return false;
          // cmp operands are pushed in canonical zext form. Signed
          // compares (SGT/SLT/SGE/SLE) need the operands sign-extended from
          // their true width first, so the encoder emits a trailing VmTy
          // immediate for the signed variants; the handler fetches it and
          // sign-extends both operands before the ICmp. EQ/NE are sign-
          // agnostic and carry no immediate.
          VmTy OperandTy = vmTyFromType(Cmp->getOperand(0)->getType());
          OperandTy.Signed = Cmp->isSigned();
          switch (Cmp->getPredicate()) {
          case CmpInst::ICMP_EQ:
            P.Words.push_back(OpCmpEq);
            break;
          case CmpInst::ICMP_NE:
            P.Words.push_back(OpCmpNe);
            break;
          case CmpInst::ICMP_SGT:
            P.Words.push_back(OpCmpSgt);
            P.Words.push_back(packVmTy(OperandTy));
            break;
          case CmpInst::ICMP_SLT:
            P.Words.push_back(OpCmpSlt);
            P.Words.push_back(packVmTy(OperandTy));
            break;
          case CmpInst::ICMP_SGE:
            P.Words.push_back(OpCmpSge);
            P.Words.push_back(packVmTy(OperandTy));
            break;
          case CmpInst::ICMP_SLE:
            P.Words.push_back(OpCmpSle);
            P.Words.push_back(packVmTy(OperandTy));
            break;
          // unsigned compares. Operands are already canonical zext;
          // unsigned comparison needs no width info and no immediate.
          case CmpInst::ICMP_UGT:
            P.Words.push_back(OpCmpUgt);
            break;
          case CmpInst::ICMP_ULT:
            P.Words.push_back(OpCmpUlt);
            break;
          case CmpInst::ICMP_UGE:
            P.Words.push_back(OpCmpUge);
            break;
          case CmpInst::ICMP_ULE:
            P.Words.push_back(OpCmpUle);
            break;
          default:
            return false;
          }
          P.Words.push_back(OpStoreSlot);
          P.Words.push_back(slotFor(Slots, &I));
          continue;
        }
        if (auto *Sel = dyn_cast<SelectInst>(&I)) {
          if (!emitValue(P, Slots, AllocaBase, NextFrameSlot, Sel->getCondition()) ||
              !emitValue(P, Slots, AllocaBase, NextFrameSlot, Sel->getTrueValue()) ||
              !emitValue(P, Slots, AllocaBase, NextFrameSlot, Sel->getFalseValue()))
            return false;
          P.Words.push_back(OpSelect);
          P.Words.push_back(OpStoreSlot);
          P.Words.push_back(slotFor(Slots, &I));
          continue;
        }
        if (auto *Cast = dyn_cast<CastInst>(&I)) {
          const DataLayout &DL = F.getParent()->getDataLayout();
          switch (Cast->getOpcode()) {
          case Instruction::ZExt:
          case Instruction::Trunc:
            if (!isSupportedInt(Cast->getSrcTy()) ||
                !isSupportedInt(Cast->getDestTy()))
              return false;
            break;
          case Instruction::PtrToInt:
            if (!isSupportedPointer(Cast->getSrcTy(), DL) ||
                !isSupportedInt(Cast->getDestTy()))
              return false;
            break;
          case Instruction::IntToPtr:
            if (!isSupportedInt(Cast->getSrcTy()) ||
                !isSupportedPointer(Cast->getDestTy(), DL))
              return false;
            break;
          default:
            return false;
          }
          if (!emitValue(P, Slots, AllocaBase, NextFrameSlot,
                         Cast->getOperand(0)))
            return false;
          P.Words.push_back(OpStoreSlot);
          P.Words.push_back(slotFor(Slots, &I));
          continue;
        }
        // VM-local load (L1.5.1 middle way). Emit the VM-local
        // pointer (resolves to a PushConst frame index via emitValue), then
        // OpLoadPtr + VmTy. The handler pops the frame index, loads
        // Frame[idx], narrows, and pushes the result. The load result is
        // then stored into the load's own locals slot like any other def.
        if (auto *LD = dyn_cast<LoadInst>(&I)) {
          if (!isSupportedInt(LD->getType()))
            return false;
          int64_t FrameIdx = 0;
          bool IsFramePtr =
              resolveFramePtr(LD->getPointerOperand(), AllocaBase,
                              NextFrameSlot, FrameIdx);
          if (!IsFramePtr &&
              !isSupportedPointer(LD->getPointerOperand()->getType(),
                                  F.getParent()->getDataLayout()))
            return false;
          if (!emitValue(P, Slots, AllocaBase, NextFrameSlot, LD->getPointerOperand()))
            return false;
          P.Words.push_back(IsFramePtr ? OpLoadPtr : OpLoadMem);
          P.Words.push_back(packVmTy(vmTyFromType(LD->getType())));
          P.Words.push_back(OpStoreSlot);
          P.Words.push_back(slotFor(Slots, &I));
          continue;
        }
        // VM-local store. Emit the value then the VM-local pointer,
        // then OpStorePtr + VmTy. The handler pops the pointer, then the
        // value, narrows the value to VmTy, and stores Frame[ptr] = value.
        if (auto *ST = dyn_cast<StoreInst>(&I)) {
          if (!isSupportedInt(ST->getValueOperand()->getType()))
            return false;
          int64_t FrameIdx = 0;
          bool IsFramePtr =
              resolveFramePtr(ST->getPointerOperand(), AllocaBase,
                              NextFrameSlot, FrameIdx);
          if (!IsFramePtr &&
              !isSupportedPointer(ST->getPointerOperand()->getType(),
                                  F.getParent()->getDataLayout()))
            return false;
          if (!emitValue(P, Slots, AllocaBase, NextFrameSlot, ST->getValueOperand()))
            return false;
          if (!emitValue(P, Slots, AllocaBase, NextFrameSlot, ST->getPointerOperand()))
            return false;
          P.Words.push_back(IsFramePtr ? OpStorePtr : OpStoreMem);
          P.Words.push_back(packVmTy(vmTyFromType(ST->getValueOperand()->getType())));
          continue;
        }
        // VM-local GEPs produce no bytecode; external pointer-arg GEPs compute
        // base + index * stride and store the raw address in a locals slot.
        if (auto *GEP = dyn_cast<GetElementPtrInst>(&I)) {
          int64_t FrameIdx = 0;
          if (resolveFramePtr(GEP, AllocaBase, NextFrameSlot, FrameIdx)) {
            slotFor(Slots, &I);
            continue;
          }
          if (!isSupportedPointer(GEP->getPointerOperandType(),
                                  F.getParent()->getDataLayout()))
            return false;
          if (GEP->getNumIndices() != 1)
            return false;
          Value *Idx = GEP->idx_begin()->get();
          if (!isSupportedInt(Idx->getType()))
            return false;
          Type *ElemTy = GEP->getSourceElementType();
          if (!ElemTy->isSized())
            return false;
          uint64_t Scale =
              F.getParent()->getDataLayout().getTypeAllocSize(ElemTy);
          if (!emitValue(P, Slots, AllocaBase, NextFrameSlot,
                         GEP->getPointerOperand()))
            return false;
          if (!emitValue(P, Slots, AllocaBase, NextFrameSlot, Idx))
            return false;
          P.Words.push_back(OpGep);
          P.Words.push_back(static_cast<int64_t>(Scale));
          P.Words.push_back(OpStoreSlot);
          P.Words.push_back(slotFor(Slots, &I));
          continue;
        }
        // AllocaInst produces no bytecode of its own -- references resolve
        // via emitValue to a PushConst frame index (allocated in pre-scan).
        if (isa<AllocaInst>(I))
          continue;
        // direct CallInst (L1.5.1). Indirect/virtual callees and
        // non-integer args/return reject the whole function.
        if (auto *CI = dyn_cast<CallInst>(&I)) {
          if (!isVMCompatibleCall(*CI))
            return false;
          auto *Callee = cast<Function>(CI->getCalledOperand());
          // register the callee in the per-module callee table and
          // remember its index. The table is finalized before the interpreter
          // is built.
          unsigned Idx;
          auto It = CalleeIndex.find(Callee);
          if (It == CalleeIndex.end()) {
            Idx = CalleeOrder.size();
            CalleeIndex[Callee] = Idx;
            CalleeOrder.push_back(Callee);
          } else {
            Idx = It->second;
          }
          // Push each argument onto the operand stack (reverse order so the
          // handler pops them in declaration order into the call-args buffer).
          unsigned NArgs = CI->arg_size();
          for (unsigned AI = NArgs; AI > 0; --AI) {
            if (!emitValue(P, Slots, AllocaBase, NextFrameSlot,
                           CI->getArgOperand(AI - 1)))
              return false;
          }
          P.Words.push_back(OpCall);
          P.Words.push_back(static_cast<int64_t>(Idx));
          P.Words.push_back(static_cast<int64_t>(CI->arg_size()));
          VmTy RetTy{64, true};
          if (!Callee->getReturnType()->isVoidTy())
            RetTy = vmTyFromType(Callee->getReturnType());
          P.Words.push_back(packVmTy(RetTy));
          if (!Callee->getReturnType()->isVoidTy()) {
            P.Words.push_back(OpStoreSlot);
            P.Words.push_back(slotFor(Slots, &I));
          }
          continue;
        }
        if (auto *Br = dyn_cast<BranchInst>(&I)) {
          if (Br->isUnconditional()) {
            // store PHI incomings for the single successor, then jump.
            if (!emitPhiCopies(P, Slots, AllocaBase, NextFrameSlot, &BB, Br->getSuccessor(0)))
              return false;
            P.Words.push_back(OpJmp);
            P.Fixups.push_back({P.Words.size(), Br->getSuccessor(0)});
            P.Words.push_back(0);
            continue;
          }
          // Conditional: the condition selects which successor's PHI copies
          // run, so the two copy sequences must be in disjoint bytecode
          // regions reached by conditional jumps. Layout:
          //   <cond on stack>
          //   OpBrTrue -> L_true_copies
          //   [false-copies] ; OpJmp -> false-target
          // L_true_copies:
          //   [true-copies]  ; OpJmp -> true-target
          if (!emitValue(P, Slots, AllocaBase, NextFrameSlot, Br->getCondition()))
            return false;
          P.Words.push_back(OpBrTrue);
          // Fixup resolved later to the start of the true-copies region.
          size_t BrTrueFixupIdx = P.Words.size();
          P.Words.push_back(0); // placeholder, patched to L_true_copies
          // False path (fallthrough): copies then jump to false successor.
          if (!emitPhiCopies(P, Slots, AllocaBase, NextFrameSlot, &BB, Br->getSuccessor(1)))
            return false;
          P.Words.push_back(OpJmp);
          P.Fixups.push_back({P.Words.size(), Br->getSuccessor(1)});
          P.Words.push_back(0);
          // True path: now-resolved start of true-copies region.
          P.Words[BrTrueFixupIdx] = static_cast<int64_t>(P.Words.size());
          if (!emitPhiCopies(P, Slots, AllocaBase, NextFrameSlot, &BB, Br->getSuccessor(0)))
            return false;
          P.Words.push_back(OpJmp);
          P.Fixups.push_back({P.Words.size(), Br->getSuccessor(0)});
          P.Words.push_back(0);
          continue;
        }
        if (auto *Ret = dyn_cast<ReturnInst>(&I)) {
          if (!Ret->getReturnValue())
            return false;
          if (!emitValue(P, Slots, AllocaBase, NextFrameSlot, Ret->getReturnValue()))
            return false;
          P.Words.push_back(OpRet);
          continue;
        }
        return false;
      }
    }

    for (const Fixup &Fup : P.Fixups) {
      auto It = BlockStart.find(Fup.Target);
      if (It == BlockStart.end())
        return false;
      P.Words[Fup.Index] = static_cast<int64_t>(It->second);
    }
    return Slots.size() <= 64 && !P.Words.empty() && checkStackDepth(P);
  }

  // Per-opcode stack shape. Used by the build-time depth check
  // (L1.5.4) and as documentation. Data-dependent handlers (OpJmp/OpBrTrue/
  // OpRet) report their shape conservatively.
  HandlerStackShape shapeOf(Opcode Op) const {
    switch (Op) {
    case OpInitArg:
      return {0, 0, 2};
    case OpPushConst:
      // value + VmTy immediate
      return {0, 1, 2};
    case OpLoadSlot:
      // slot + VmTy immediate
      return {0, 1, 2};
    case OpStoreSlot:
      return {1, 0, 1};
    case OpAdd:
    case OpSub:
    case OpXor:
    case OpCmpEq:
    case OpCmpNe:
    case OpCmpUgt:
    case OpCmpUlt:
    case OpCmpUge:
    case OpCmpUle:
      return {2, 1, 0};
    case OpCmpSgt:
    case OpCmpSlt:
    case OpCmpSge:
    case OpCmpSle:
    case OpMul:
    case OpAnd:
    case OpOr:
    case OpShl:
    case OpLShr:
    case OpAShr:
    case OpSDiv:
    case OpUDiv:
    case OpSRem:
    case OpURem:
      return {2, 1, 1};
    case OpSelect:
      return {3, 1, 0};
    case OpLoadPtr:
    case OpLoadMem:
      // pops frame idx, fetches VmTy, pushes value
      return {1, 1, 1};
    case OpStorePtr:
    case OpStoreMem:
      // pops frame idx, pops value, fetches VmTy
      return {2, 0, 1};
    case OpGep:
      return {2, 1, 1};
    case OpPtrConst:
      return {0, 1, 1};
    case OpCall:
      // pops NArgs values (runtime), fetches calleeIdx + nargs + VmTy, pushes
      // 1 result. Pops/Pushes are conservative (actual pop count is data).
      return {0, 1, 3};
    case OpJmp:
      return {0, 0, 1};
    case OpBrTrue:
      return {1, 0, 1};
    case OpRet:
      return {1, 0, 0};
    }
    return {0, 0, 0};
  }

  bool opcodeImmediateCount(int64_t RawOp, unsigned &Count) const {
    if (RawOp <= 0)
      return false;
    auto Op = static_cast<Opcode>(RawOp);
    switch (Op) {
    case OpInitArg:
    case OpPushConst:
    case OpLoadSlot:
      Count = 2;
      return true;
    case OpStoreSlot:
    case OpAdd:
    case OpSub:
    case OpXor:
    case OpCmpSgt:
    case OpCmpSlt:
    case OpCmpSge:
    case OpCmpSle:
    case OpJmp:
    case OpBrTrue:
    case OpMul:
    case OpAnd:
    case OpOr:
    case OpShl:
    case OpLShr:
    case OpAShr:
    case OpSDiv:
    case OpUDiv:
    case OpSRem:
    case OpURem:
    case OpLoadPtr:
    case OpStorePtr:
    case OpLoadMem:
    case OpStoreMem:
    case OpGep:
    case OpPtrConst:
      Count = 1;
      return true;
    case OpCmpEq:
    case OpCmpNe:
    case OpRet:
    case OpSelect:
    case OpCmpUgt:
    case OpCmpUlt:
    case OpCmpUge:
    case OpCmpUle:
      Count = 0;
      return true;
    case OpCall:
      Count = 3;
      return true;
    }
    return false;
  }

  static constexpr unsigned kOpcodeTableSize = 64;

  bool buildOpcodeMaps(SmallVectorImpl<int64_t> &Encode,
                       SmallVectorImpl<int64_t> &Decode) {
    Encode.assign(kOpcodeTableSize, -1);
    Decode.assign(kOpcodeTableSize, -1);
    SmallVector<int64_t, kOpcodeTableSize> Tokens;
    for (unsigned I = 0; I < kOpcodeTableSize; ++I)
      Tokens.push_back(I);
    std::shuffle(Tokens.begin(), Tokens.end(), RNG);

    unsigned TokenI = 0;
    for (unsigned Op = 0; Op < kOpcodeTableSize; ++Op) {
      unsigned Immediates = 0;
      if (!opcodeImmediateCount(static_cast<int64_t>(Op), Immediates))
        continue;
      int64_t Token = Tokens[TokenI++];
      Encode[Op] = Token;
      Decode[Token] = Op;
    }
    return true;
  }

  bool mapOpcodeWords(SmallVectorImpl<int64_t> &Words,
                      ArrayRef<int64_t> OpcodeEncode) const {
    size_t I = 0;
    while (I < Words.size()) {
      unsigned Immediates = 0;
      if (!opcodeImmediateCount(Words[I], Immediates))
        return false;
      if (Words[I] < 0 ||
          static_cast<size_t>(Words[I]) >= OpcodeEncode.size() ||
          OpcodeEncode[Words[I]] < 0)
        return false;
      Words[I] = OpcodeEncode[Words[I]];
      I += 1 + Immediates;
    }
    return I == Words.size();
  }

  bool computePCMapFlags(const SmallVectorImpl<int64_t> &Words,
                         SmallVectorImpl<uint8_t> &Flags,
                         uint8_t RotationStep) const {
    SmallVector<uint8_t, 64> Starts(Words.size(), 0);
    SmallVector<uint8_t, 64> Leaders(Words.size(), 0);
    size_t I = 0;
    if (!Words.empty())
      Leaders[0] = 1;
    while (I < Words.size()) {
      unsigned Immediates = 0;
      if (!opcodeImmediateCount(Words[I], Immediates))
        return false;
      if (I + 1 + Immediates > Words.size())
        return false;
      Starts[I] = 1;
      I += 1 + Immediates;
    }
    if (I != Words.size())
      return false;

    I = 0;
    while (I < Words.size()) {
      unsigned Immediates = 0;
      if (!opcodeImmediateCount(Words[I], Immediates))
        return false;
      size_t Next = I + 1 + Immediates;
      auto MarkTarget = [&](int64_t Target) {
        if (Target >= 0 && static_cast<uint64_t>(Target) < Words.size() &&
            Starts[static_cast<size_t>(Target)])
          Leaders[static_cast<size_t>(Target)] = 1;
      };
      switch (static_cast<Opcode>(Words[I])) {
      case OpJmp:
        MarkTarget(Words[I + 1]);
        break;
      case OpBrTrue:
        MarkTarget(Words[I + 1]);
        if (Next < Words.size())
          Leaders[Next] = 1;
        break;
      default:
        break;
      }
      I = Next;
    }

    Flags.assign(Words.size(), 0);
    uint8_t Rotation = 0;
    for (I = 0; I < Words.size();) {
      unsigned Immediates = 0;
      if (!opcodeImmediateCount(Words[I], Immediates))
        return false;
      if (Leaders[I])
        Rotation = static_cast<uint8_t>((Rotation + RotationStep) & 0x7F);
      uint8_t Packed = static_cast<uint8_t>((Rotation << 1) | 1);
      Flags[I] = Packed;
      for (size_t J = I + 1; J < I + 1 + Immediates; ++J)
        Flags[J] = static_cast<uint8_t>(Rotation << 1);
      I += 1 + Immediates;
    }
    return true;
  }

  uint64_t bytecodeDomain(bool IsOpcodeWord) const {
    return IsOpcodeWord ? 0xA5A5A5A5D3C3B2A1ULL : 0x3C6EF372FE94F82AULL;
  }

  uint64_t bytecodeRotationDomain(uint8_t PCFlags) const {
    return static_cast<uint64_t>(PCFlags >> 1) * 0xD1342543DE82EF95ULL;
  }

  int64_t encryptBytecodeWord(int64_t Word, size_t Index,
                              uint64_t BytecodeKey,
                              uint8_t PCFlags) const {
    return static_cast<int64_t>(
        static_cast<uint64_t>(Word) ^
        bytecodeScheduleWord(BytecodeKey, static_cast<uint64_t>(Index),
                             bytecodeDomain((PCFlags & 1) != 0) ^
                                 bytecodeRotationDomain(PCFlags)));
  }

  uint64_t bytecodeScheduleWord(uint64_t Key, uint64_t Index,
                                uint64_t Domain) const {
    uint64_t X = Key ^ (Index * 0x9E3779B97F4A7C15ULL) ^ Domain;
    X ^= X >> 30;
    X *= 0xBF58476D1CE4E5B9ULL;
    X ^= X >> 27;
    X *= 0x94D049BB133111EBULL;
    X ^= X >> 31;
    return X;
  }

  uint64_t rotl64(uint64_t V, unsigned Rot) const {
    Rot &= 63;
    return Rot ? ((V << Rot) | (V >> (64 - Rot))) : V;
  }

  struct KeyDerivation {
    uint64_t Seed;
    uint64_t XorIn;
    uint64_t AddIn;
    uint64_t XorOut;
    unsigned Rot;
  };

  KeyDerivation makeKeyDerivation(uint64_t Key) {
    constexpr uint64_t Mul = 0xD6E8FEB86659FD93ULL;
    for (;;) {
      KeyDerivation D{RNG(), RNG(), RNG(), 0,
                      static_cast<unsigned>((RNG() % 63) + 1)};
      uint64_t Mixed = rotl64(((D.Seed ^ D.XorIn) * Mul) + D.AddIn, D.Rot);
      D.XorOut = Mixed ^ Key;
      if (D.Seed != Key && D.XorIn != Key && D.AddIn != Key &&
          D.XorOut != Key)
        return D;
    }
  }

  Value *buildRuntimeBytecodeKey(IRBuilder<> &B, Module &M, Function &F,
                                 Type *I64, uint64_t Key) {
    constexpr uint64_t Mul = 0xD6E8FEB86659FD93ULL;
    KeyDerivation D = makeKeyDerivation(Key);
    auto *SeedGlobal = new GlobalVariable(
        M, I64, false, GlobalValue::PrivateLinkage,
        ConstantInt::get(I64, D.Seed), "__taokari_vmp_key_seed_" + F.getName());
    SeedGlobal->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    SeedGlobal->setAlignment(Align(8));

    auto *Seed = B.CreateLoad(I64, SeedGlobal, "vmp.key.seed");
    Seed->setVolatile(true);
    Value *Mixed = B.CreateXor(Seed, ConstantInt::get(I64, D.XorIn));
    Mixed = B.CreateMul(Mixed, ConstantInt::get(I64, Mul));
    Mixed = B.CreateAdd(Mixed, ConstantInt::get(I64, D.AddIn));
    Value *RotL = B.CreateShl(Mixed, ConstantInt::get(I64, D.Rot));
    Value *RotR = B.CreateLShr(Mixed, ConstantInt::get(I64, 64 - D.Rot));
    return B.CreateXor(B.CreateOr(RotL, RotR),
                       ConstantInt::get(I64, D.XorOut), "vmp.bytecode.key");
  }

  uint64_t mixBytecodeTag(uint64_t Tag, uint64_t Word, uint64_t Index) const {
    Tag ^= Word + (Index * 0x9E3779B97F4A7C15ULL);
    return Tag * 0x100000001B3ULL;
  }

  Value *loadWord(IRBuilder<> &B, Type *I64, Value *BC, Value *PC,
                  Value *One) {
    Value *Addr = B.CreateGEP(I64, BC, PC);
    Value *Word = B.CreateLoad(I64, Addr);
    B.CreateStore(B.CreateAdd(PC, One), PC);
    return Word;
  }

  void push(IRBuilder<> &B, Type *I64, Value *Stack, Value *SP, Value *V) {
    Value *Idx = B.CreateLoad(I64, SP);
    Value *Slot = B.CreateGEP(I64, Stack, Idx);
    B.CreateStore(V, Slot);
    B.CreateStore(B.CreateAdd(Idx, ConstantInt::get(I64, 1)), SP);
  }

  Value *pop(IRBuilder<> &B, Type *I64, Value *Stack, Value *SP) {
    Value *Idx = B.CreateSub(B.CreateLoad(I64, SP), ConstantInt::get(I64, 1));
    B.CreateStore(Idx, SP);
    return B.CreateLoad(I64, B.CreateGEP(I64, Stack, Idx));
  }

  // Bundle of interpreter state. Emit closures in the handler
  // table capture a pointer to this struct by value (one pointer copy),
  // which is always valid because the Ctx outlives both the table build and
  // the synchronous Emit pass in createInterpreter. This avoids the
  // lifetime hazard of capturing local helper lambdas (fetch/pop/push) by
  // reference into deferred std::function closures.
  struct InterpCtx {
    Type *I64;
    Function *F;
    LLVMContext *Ctx;
    Value *BC;
    Value *BCLen;
    Value *PCMap;
    Value *PtrTable;
    Value *PtrCount;
    Value *PC;
    Value *SP;
    Value *Stack;
    Value *Locals;
    Value *Frame;
    Value *CallArgs;
    GlobalVariable *CalleeTable;
    unsigned CalleeCount;
    Value *Args;
    Value *ArgLen;
    Value *TamperFlag;
    Value *ExpectedTag;
    Value *OpcodeMap;
    Value *BytecodeKey;
    BasicBlock *Dispatch;
    BasicBlock *Bad;
    bool LittleEndian;
  };

  void branchIfFalse(IRBuilder<> &B, InterpCtx &C, Value *Ok) {
    BasicBlock *Cont = BasicBlock::Create(*C.Ctx, "guard.ok", C.F);
    B.CreateCondBr(Ok, Cont, C.Bad);
    B.SetInsertPoint(Cont);
  }

  Value *checkedWidth(IRBuilder<> &B, InterpCtx &C, Value *PackedTyImm) {
    Value *Width = B.CreateAnd(PackedTyImm, ConstantInt::get(C.I64, 0xFF));
    Value *NonZero =
        B.CreateICmpUGE(Width, ConstantInt::get(C.I64, 1));
    Value *InRange =
        B.CreateICmpULE(Width, ConstantInt::get(C.I64, 64));
    branchIfFalse(B, C, B.CreateAnd(NonZero, InRange));
    return Width;
  }

  Value *bytecodeScheduleWord(IRBuilder<> &B, InterpCtx &C, Value *Index) {
    Type *I8 = Type::getInt8Ty(*C.Ctx);
    Value *PCFlags = B.CreateLoad(I8, B.CreateGEP(I8, C.PCMap, Index));
    Value *IsOpcodeWord = B.CreateICmpNE(
        B.CreateAnd(PCFlags, ConstantInt::get(I8, 1)),
        ConstantInt::get(I8, 0));
    Value *Domain = B.CreateSelect(
        IsOpcodeWord, ConstantInt::get(C.I64, 0xA5A5A5A5D3C3B2A1ULL),
        ConstantInt::get(C.I64, 0x3C6EF372FE94F82AULL));
    Value *Rotation = B.CreateZExt(
        B.CreateLShr(PCFlags, ConstantInt::get(I8, 1)), C.I64);
    Domain = B.CreateXor(
        Domain,
        B.CreateMul(Rotation, ConstantInt::get(C.I64, 0xD1342543DE82EF95ULL)));
    Value *X = B.CreateXor(
        C.BytecodeKey,
        B.CreateMul(Index, ConstantInt::get(C.I64, 0x9E3779B97F4A7C15ULL)));
    X = B.CreateXor(X, Domain);
    X = B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(C.I64, 30)));
    X = B.CreateMul(X, ConstantInt::get(C.I64, 0xBF58476D1CE4E5B9ULL));
    X = B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(C.I64, 27)));
    X = B.CreateMul(X, ConstantInt::get(C.I64, 0x94D049BB133111EBULL));
    return B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(C.I64, 31)));
  }

  uint64_t calleeTableMaskWord(uint64_t Index) const {
    return bytecodeScheduleWord(CalleeTableKey, Index,
                                0x6A09E667F3BCC909ULL);
  }

  Value *calleeTableMaskWord(IRBuilder<> &B, InterpCtx &C, Value *Index) {
    Value *X = B.CreateXor(
        ConstantInt::get(C.I64, CalleeTableKey),
        B.CreateMul(Index, ConstantInt::get(C.I64, 0x9E3779B97F4A7C15ULL)));
    X = B.CreateXor(X, ConstantInt::get(C.I64, 0x6A09E667F3BCC909ULL));
    X = B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(C.I64, 30)));
    X = B.CreateMul(X, ConstantInt::get(C.I64, 0xBF58476D1CE4E5B9ULL));
    X = B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(C.I64, 27)));
    X = B.CreateMul(X, ConstantInt::get(C.I64, 0x94D049BB133111EBULL));
    return B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(C.I64, 31)));
  }

  Value *fetchWord(IRBuilder<> &B, InterpCtx &C) {
    Value *Cur = B.CreateLoad(C.I64, C.PC);
    branchIfFalse(B, C, B.CreateICmpULT(Cur, C.BCLen));
    Value *Enc = B.CreateLoad(C.I64, B.CreateGEP(C.I64, C.BC, Cur));
    B.CreateStore(B.CreateAdd(Cur, ConstantInt::get(C.I64, 1)), C.PC);
    return B.CreateXor(Enc, bytecodeScheduleWord(B, C, Cur));
  }

  void pushStk(IRBuilder<> &B, InterpCtx &C, Value *V) {
    Value *Idx = B.CreateLoad(C.I64, C.SP);
    branchIfFalse(B, C, B.CreateICmpULT(Idx, ConstantInt::get(C.I64, 64)));
    push(B, C.I64, C.Stack, C.SP, V);
  }

  Value *popStk(IRBuilder<> &B, InterpCtx &C) {
    Value *Idx = B.CreateLoad(C.I64, C.SP);
    branchIfFalse(B, C, B.CreateICmpUGT(Idx, ConstantInt::get(C.I64, 0)));
    return pop(B, C.I64, C.Stack, C.SP);
  }

  // Narrow a full i64 value to its native width, returned as the
  // canonical ZERO-EXTENDED bit pattern. The VM stack always holds values in
  // this canonical form: truncate to width, then zext to i64. Signedness is
  // NOT applied here -- it is a property of the consuming operation, not the
  // value. So `-1` (i32) lives on the stack as 0x00000000FFFFFFFF.
  //
  //   Mask = (1 << Width) - 1
  //   Lo   = V & Mask
  //
  // Width=64 is a no-op (Mask = all-ones). PackedTyImm is the runtime VmTy
  // immediate (low 8 bits = width; the signed bit is ignored here).
  Value *narrowTo(IRBuilder<> &B, InterpCtx &C, Value *V,
                  Value *PackedTyImm) {
    Value *Width = checkedWidth(B, C, PackedTyImm);
    // Mask = (1 << Width) - 1
    Value *Is64 = B.CreateICmpEQ(Width, ConstantInt::get(C.I64, 64));
    Value *ShiftWidth =
        B.CreateSelect(Is64, ConstantInt::get(C.I64, 63), Width);
    Value *Mask =
        B.CreateSelect(Is64, ConstantInt::get(C.I64, ~0ULL),
                       B.CreateSub(B.CreateShl(ConstantInt::get(C.I64, 1),
                                               ShiftWidth),
                                   ConstantInt::get(C.I64, 1)));
    return B.CreateAnd(V, Mask);
  }

  // Sign-extend a canonical zext stack value from its native width
  // back to a signed i64, for use by signed operations (signed compare, SDiv,
  // SRem, AShr). Counterpart to narrowTo: narrowTo produces the canonical
  // zext bit pattern; signExtendFor consumes it when the op is signed.
  //
  //   Mask      = (1 << Width) - 1
  //   Lo        = V & Mask            // canonical zext value
  //   SignBit   = 1 << (Width - 1)
  //   Signed    = (Lo ^ SignBit) - SignBit
  Value *signExtendFor(IRBuilder<> &B, InterpCtx &C, Value *V,
                       Value *PackedTyImm) {
    Value *One = ConstantInt::get(C.I64, 1);
    Value *Width = checkedWidth(B, C, PackedTyImm);
    Value *Is64 = B.CreateICmpEQ(Width, ConstantInt::get(C.I64, 64));
    Value *ShiftWidth =
        B.CreateSelect(Is64, ConstantInt::get(C.I64, 63), Width);
    Value *Mask =
        B.CreateSelect(Is64, ConstantInt::get(C.I64, ~0ULL),
                       B.CreateSub(B.CreateShl(One, ShiftWidth),
                                   ConstantInt::get(C.I64, 1)));
    Value *Lo = B.CreateAnd(V, Mask);
    Value *SignBit =
        B.CreateShl(One, B.CreateSub(Width, ConstantInt::get(C.I64, 1)));
    return B.CreateSub(B.CreateXor(Lo, SignBit), SignBit);
  }

  Value *byteCountFor(IRBuilder<> &B, InterpCtx &C, Value *PackedTyImm) {
    Value *Width = checkedWidth(B, C, PackedTyImm);
    return B.CreateUDiv(B.CreateAdd(Width, ConstantInt::get(C.I64, 7)),
                        ConstantInt::get(C.I64, 8));
  }

  Value *loadHostInt(IRBuilder<> &B, InterpCtx &C, Value *AddrInt,
                     Value *PackedTyImm) {
    Type *I8 = Type::getInt8Ty(*C.Ctx);
    Value *Bytes = byteCountFor(B, C, PackedTyImm);
    AllocaInst *Acc = B.CreateAlloca(C.I64, nullptr, "mem.acc");
    AllocaInst *Idx = B.CreateAlloca(C.I64, nullptr, "mem.i");
    B.CreateStore(ConstantInt::get(C.I64, 0), Acc);
    B.CreateStore(ConstantInt::get(C.I64, 0), Idx);
    Value *Base = B.CreateIntToPtr(AddrInt, PointerType::getUnqual(*C.Ctx));
    BasicBlock *Hdr = BasicBlock::Create(*C.Ctx, "memload.hdr", C.F);
    BasicBlock *Body = BasicBlock::Create(*C.Ctx, "memload.body", C.F);
    BasicBlock *Done = BasicBlock::Create(*C.Ctx, "memload.done", C.F);
    B.CreateBr(Hdr);
    B.SetInsertPoint(Hdr);
    Value *Cur = B.CreateLoad(C.I64, Idx);
    B.CreateCondBr(B.CreateICmpULT(Cur, Bytes), Body, Done);
    B.SetInsertPoint(Body);
    Value *Byte = B.CreateZExt(B.CreateLoad(I8, B.CreateGEP(I8, Base, Cur)), C.I64);
    Value *ByteNo = C.LittleEndian
                        ? Cur
                        : B.CreateSub(B.CreateSub(Bytes, ConstantInt::get(C.I64, 1)), Cur);
    Value *Shift = B.CreateMul(ByteNo, ConstantInt::get(C.I64, 8));
    B.CreateStore(B.CreateOr(B.CreateLoad(C.I64, Acc), B.CreateShl(Byte, Shift)),
                  Acc);
    B.CreateStore(B.CreateAdd(Cur, ConstantInt::get(C.I64, 1)), Idx);
    B.CreateBr(Hdr);
    B.SetInsertPoint(Done);
    return narrowTo(B, C, B.CreateLoad(C.I64, Acc), PackedTyImm);
  }

  void storeHostInt(IRBuilder<> &B, InterpCtx &C, Value *AddrInt, Value *V,
                    Value *PackedTyImm) {
    Type *I8 = Type::getInt8Ty(*C.Ctx);
    Value *Bytes = byteCountFor(B, C, PackedTyImm);
    Value *Narrowed = narrowTo(B, C, V, PackedTyImm);
    AllocaInst *Idx = B.CreateAlloca(C.I64, nullptr, "mem.i");
    B.CreateStore(ConstantInt::get(C.I64, 0), Idx);
    Value *Base = B.CreateIntToPtr(AddrInt, PointerType::getUnqual(*C.Ctx));
    BasicBlock *Hdr = BasicBlock::Create(*C.Ctx, "memstore.hdr", C.F);
    BasicBlock *Body = BasicBlock::Create(*C.Ctx, "memstore.body", C.F);
    BasicBlock *Done = BasicBlock::Create(*C.Ctx, "memstore.done", C.F);
    B.CreateBr(Hdr);
    B.SetInsertPoint(Hdr);
    Value *Cur = B.CreateLoad(C.I64, Idx);
    B.CreateCondBr(B.CreateICmpULT(Cur, Bytes), Body, Done);
    B.SetInsertPoint(Body);
    Value *ByteNo = C.LittleEndian
                        ? Cur
                        : B.CreateSub(B.CreateSub(Bytes, ConstantInt::get(C.I64, 1)), Cur);
    Value *Shift = B.CreateMul(ByteNo, ConstantInt::get(C.I64, 8));
    Value *Byte =
        B.CreateTrunc(B.CreateAnd(B.CreateLShr(Narrowed, Shift),
                                  ConstantInt::get(C.I64, 0xFF)), I8);
    B.CreateStore(Byte, B.CreateGEP(I8, Base, Cur));
    B.CreateStore(B.CreateAdd(Cur, ConstantInt::get(C.I64, 1)), Idx);
    B.CreateBr(Hdr);
    B.SetInsertPoint(Done);
  }

  // Build the handler table for the interpreter. Each entry owns
  // its case-block emission, including pop()/fetch() and the branch back to
  // Dispatch. OpRet intentionally does NOT branch back (it returns).
  //
  // Every Emit closure captures `Ctx` (a pointer to InterpCx, by value) and
  // `this` (the pass, for push/pop helpers). IRBuilder& is passed in by the
  // caller at Emit time. No local lambdas are captured — fetch/pop/push go
  // through member functions on `this` + the InterpCx pointer.
  SmallVector<Handler, 24> buildHandlerTable(InterpCtx &C) {
    SmallVector<Handler, 24> H;
    H.push_back({OpInitArg, "initarg", shapeOf(OpInitArg),
                 [this, &C](IRBuilder<> &B) {
                   Value *Slot = fetchWord(B, C);
                   Value *ArgNo = fetchWord(B, C);
                   branchIfFalse(B, C,
                                 B.CreateICmpULT(Slot,
                                                 ConstantInt::get(C.I64, 64)));
                   branchIfFalse(B, C, B.CreateICmpULT(ArgNo, C.ArgLen));
                   Value *ArgVal =
                       B.CreateLoad(C.I64, B.CreateGEP(C.I64, C.Args, ArgNo));
                   B.CreateStore(ArgVal, B.CreateGEP(C.I64, C.Locals, Slot));
                   B.CreateBr(C.Dispatch);
                 }});
    H.push_back({OpPushConst, "pushconst", shapeOf(OpPushConst),
                 [this, &C](IRBuilder<> &B) {
                   Value *V = fetchWord(B, C);
                   Value *Ty = fetchWord(B, C);
                   pushStk(B, C, narrowTo(B, C, V, Ty));
                   B.CreateBr(C.Dispatch);
                 }});
    H.push_back({OpLoadSlot, "loadslot", shapeOf(OpLoadSlot),
                 [this, &C](IRBuilder<> &B) {
                   Value *Slot = fetchWord(B, C);
                   Value *Ty = fetchWord(B, C);
                   branchIfFalse(B, C,
                                 B.CreateICmpULT(Slot,
                                                 ConstantInt::get(C.I64, 64)));
                   Value *V = B.CreateLoad(C.I64, B.CreateGEP(C.I64, C.Locals, Slot));
                   pushStk(B, C, narrowTo(B, C, V, Ty));
                   B.CreateBr(C.Dispatch);
                 }});
    H.push_back({OpStoreSlot, "storeslot", shapeOf(OpStoreSlot),
                 [this, &C](IRBuilder<> &B) {
                   Value *V = popStk(B, C);
                   Value *Slot = fetchWord(B, C);
                   branchIfFalse(B, C,
                                 B.CreateICmpULT(Slot,
                                                 ConstantInt::get(C.I64, 64)));
                   B.CreateStore(V, B.CreateGEP(C.I64, C.Locals, Slot));
                   B.CreateBr(C.Dispatch);
                 }});

    // VM-local memory ops (L1.5.1 middle way). Frame index is on
    // the stack (pushed by emitValue as a PushConst). OpLoadPtr pops the
    // frame index, fetches VmTy, loads Frame[idx], narrows, pushes.
    // OpStorePtr pops the frame index, pops the value, fetches VmTy,
    // narrows, stores Frame[idx] = value. Order: store emits value-then-
    // pointer in the encoder, so the handler pops pointer first, then value.
    H.push_back({OpLoadPtr, "loadptr", shapeOf(OpLoadPtr),
                 [this, &C](IRBuilder<> &B) {
                   Value *FrameIdx = popStk(B, C);
                   Value *Ty = fetchWord(B, C);
                   branchIfFalse(B, C,
                                 B.CreateICmpULT(FrameIdx,
                                                 ConstantInt::get(C.I64, 64)));
                   Value *V = B.CreateLoad(C.I64,
                                           B.CreateGEP(C.I64, C.Frame, FrameIdx));
                   pushStk(B, C, narrowTo(B, C, V, Ty));
                   B.CreateBr(C.Dispatch);
                 }});
    H.push_back({OpStorePtr, "storeptr", shapeOf(OpStorePtr),
                 [this, &C](IRBuilder<> &B) {
                   Value *FrameIdx = popStk(B, C);
                   Value *V = popStk(B, C);
                   Value *Ty = fetchWord(B, C);
                   branchIfFalse(B, C,
                                 B.CreateICmpULT(FrameIdx,
                                                 ConstantInt::get(C.I64, 64)));
                   Value *Narrowed = narrowTo(B, C, V, Ty);
                   B.CreateStore(Narrowed,
                                 B.CreateGEP(C.I64, C.Frame, FrameIdx));
                   B.CreateBr(C.Dispatch);
                 }});
    H.push_back({OpLoadMem, "loadmem", shapeOf(OpLoadMem),
                 [this, &C](IRBuilder<> &B) {
                   Value *Addr = popStk(B, C);
                   Value *Ty = fetchWord(B, C);
                   pushStk(B, C, loadHostInt(B, C, Addr, Ty));
                   B.CreateBr(C.Dispatch);
                 }});
    H.push_back({OpStoreMem, "storemem", shapeOf(OpStoreMem),
                 [this, &C](IRBuilder<> &B) {
                   Value *Addr = popStk(B, C);
                   Value *V = popStk(B, C);
                   Value *Ty = fetchWord(B, C);
                   storeHostInt(B, C, Addr, V, Ty);
                   B.CreateBr(C.Dispatch);
                 }});
    H.push_back({OpGep, "gep", shapeOf(OpGep),
                 [this, &C](IRBuilder<> &B) {
                   Value *Index = popStk(B, C);
                   Value *Base = popStk(B, C);
                   Value *Scale = fetchWord(B, C);
                   pushStk(B, C, B.CreateAdd(Base, B.CreateMul(Index, Scale)));
                   B.CreateBr(C.Dispatch);
                 }});
    H.push_back({OpPtrConst, "ptrconst", shapeOf(OpPtrConst),
                 [this, &C](IRBuilder<> &B) {
                   Type *Ptr = PointerType::getUnqual(*C.Ctx);
                   Value *Idx = fetchWord(B, C);
                   branchIfFalse(B, C, B.CreateICmpULT(Idx, C.PtrCount));
                   Value *PtrVal =
                       B.CreateLoad(Ptr, B.CreateGEP(Ptr, C.PtrTable, Idx));
                   pushStk(B, C, B.CreatePtrToInt(PtrVal, C.I64));
                   B.CreateBr(C.Dispatch);
                 }});

    // direct call (L1.5.1). Only registered when a callee table
    // exists (i.e. at least one direct call was encoded). Modules with no
    // direct calls have CalleeTable == null and the OpCall handler would
    // dereference it during IR emission, so we skip registration entirely
    // in that case -- the switch has no OpCall case and any stray OpCall
    // opcode would hit the Bad default (which never fires because no OpCall
    // was emitted). Fetches <calleeIdx> <nargs> <VmTy>, pops nargs values
    // into the CallArgs buffer (popping yields declaration order because the
    // encoder pushed them in reverse), validates the masked CalleeTable token,
    // calls the matching thunk uniformly as i64(i64*), narrows the i64 result
    // by VmTy, and pushes it.
    if (C.CalleeTable) {
      H.push_back({OpCall, "call", shapeOf(OpCall),
                   [this, &C](IRBuilder<> &B) {
                     Value *CalleeIdx = fetchWord(B, C);
                     Value *NArgs = fetchWord(B, C);
                     Value *Ty = fetchWord(B, C);
                     branchIfFalse(B, C,
                                   B.CreateICmpULT(
                                       CalleeIdx,
                                       ConstantInt::get(C.I64, C.CalleeCount)));
                     branchIfFalse(B, C,
                                   B.CreateICmpULE(NArgs,
                                                   ConstantInt::get(C.I64, 8)));
                     // Pop into CallArgs[0..NArgs-1] via a runtime-indexed
                     // loop (max 8 iters per isVMCompatibleCall's gate).
                     Value *Zero = ConstantInt::get(C.I64, 0);
                     AllocaInst *Counter =
                         B.CreateAlloca(C.I64, nullptr, "call.counter");
                     B.CreateStore(Zero, Counter);
                     BasicBlock *LoopHdr =
                         BasicBlock::Create(*C.Ctx, "call.loop", C.F);
                     BasicBlock *LoopBody =
                         BasicBlock::Create(*C.Ctx, "call.body", C.F);
                     BasicBlock *LoopDone =
                         BasicBlock::Create(*C.Ctx, "call.done", C.F);
                     B.CreateBr(LoopHdr);
                     B.SetInsertPoint(LoopHdr);
                     Value *Cur = B.CreateLoad(C.I64, Counter);
                     B.CreateCondBr(B.CreateICmpULT(Cur, NArgs), LoopBody, LoopDone);
                     B.SetInsertPoint(LoopBody);
                     Value *Arg = popStk(B, C);
                     B.CreateStore(Arg, B.CreateGEP(C.I64, C.CallArgs, Cur));
                     B.CreateStore(B.CreateAdd(Cur, ConstantInt::get(C.I64, 1)),
                                   Counter);
                     B.CreateBr(LoopHdr);
                     B.SetInsertPoint(LoopDone);
                     Value *MaskedCalleeToken = B.CreateLoad(
                         C.I64, B.CreateGEP(C.I64, C.CalleeTable, CalleeIdx));
                     branchIfFalse(
                         B, C,
                         B.CreateICmpEQ(MaskedCalleeToken,
                                        calleeTableMaskWord(B, C, CalleeIdx)));
                     auto *ThunkFnTy = FunctionType::get(
                         C.I64, {PointerType::getUnqual(*C.Ctx)}, false);
                     SwitchInst *CallSwitch = B.CreateSwitch(CalleeIdx, C.Bad,
                                                             C.CalleeCount);
                     Module &M = *C.F->getParent();
                     for (auto [Index, Callee] : llvm::enumerate(CalleeOrder)) {
                       BasicBlock *CallBB =
                           BasicBlock::Create(*C.Ctx, "call.target", C.F);
                       CallSwitch->addCase(
                           ConstantInt::get(cast<IntegerType>(C.I64),
                                            static_cast<uint64_t>(Index)),
                           CallBB);
                       B.SetInsertPoint(CallBB);
                       Function *Thunk = getOrCreateCallThunk(M, Callee);
                       Value *Result =
                           B.CreateCall(ThunkFnTy, Thunk, {C.CallArgs});
                       pushStk(B, C, narrowTo(B, C, Result, Ty));
                       B.CreateBr(C.Dispatch);
                     }
                   }});
    }

    // Binary-op emitter. The opcode-specific IR is produced by an
    // owned std::function (Fn) captured by value into the Emit closure. Fn
    // itself is a by-value parameter of addBinary, so the closure must own a
    // copy; capturing `Fn` by value (init-capture-free, named explicitly)
    // would be ill-formed under /permissive- with a default capture, so we
    // use an explicit capture list with no default and name Fn there.
    //
    // Flags:
    //   NarrowResult  -- fetch a trailing VmTy immediate and narrow the i64
    //                    result back to the operand width (canonical zext).
    //                    True for all arithmetic ops; false for compares.
    //   SignedOperands -- sign-extend both operands from their VmTy width
    //                     before calling Fn. Required for any op whose native
    //                     semantics depend on the operands being signed
    //                     (SDiv/SRem/AShr). Sign-agnostic ops (Add/Sub/Mul/
    //                     And/Or/Xor/Shl/LShr) leave the canonical zext
    //                     operands in place because two's-complement bit ops
    //                     give the same result either way once narrowed.
    auto addBinary = [&](Opcode Op, StringRef Name, bool NarrowResult,
                         bool SignedOperands, bool GuardDivisor,
                         std::function<Value *(IRBuilder<> &, Value *, Value *)>
                             Fn) {
      H.push_back({Op, Name, shapeOf(Op),
                   [this, &C, Fn, NarrowResult, SignedOperands,
                    GuardDivisor](IRBuilder<> &B) {
                     Value *R = popStk(B, C);
                     Value *L = popStk(B, C);
                     Value *Result;
                     if (NarrowResult) {
                       Value *Ty = fetchWord(B, C);
                       if (SignedOperands) {
                         L = signExtendFor(B, C, L, Ty);
                         R = signExtendFor(B, C, R, Ty);
                       }
                       if (GuardDivisor)
                         branchIfFalse(
                             B, C,
                             B.CreateICmpNE(R, ConstantInt::get(C.I64, 0)));
                       Result = Fn(B, L, R);
                       Result = narrowTo(B, C, Result, Ty);
                     } else {
                       Result = Fn(B, L, R);
                     }
                     pushStk(B, C, Result);
                     B.CreateBr(C.Dispatch);
                   }});
    };
    addBinary(OpAdd, "add", /*Narrow=*/true, /*Signed=*/false,
              /*GuardDivisor=*/false,
              [](IRBuilder<> &B, Value *L, Value *R) {
                return B.CreateAdd(L, R);
              });
    addBinary(OpSub, "sub", /*Narrow=*/true, /*Signed=*/false,
              /*GuardDivisor=*/false,
              [](IRBuilder<> &B, Value *L, Value *R) {
                return B.CreateSub(L, R);
              });
    addBinary(OpXor, "xor", /*Narrow=*/true, /*Signed=*/false,
              /*GuardDivisor=*/false,
              [](IRBuilder<> &B, Value *L, Value *R) {
                return B.CreateXor(L, R);
              });
    // L1.5.1 widened integer binary ops. All carry a VmTy immediate
    // and narrow the result. Signedness is encoded in the opcode choice and
    // the SignedOperands flag: AShr/SDiv/SRem sign-extend operands first;
    // the rest operate on the canonical zext bit pattern.
    addBinary(OpMul, "mul", /*Narrow=*/true, /*Signed=*/false,
              /*GuardDivisor=*/false,
              [](IRBuilder<> &B, Value *L, Value *R) {
                return B.CreateMul(L, R);
              });
    addBinary(OpAnd, "and", /*Narrow=*/true, /*Signed=*/false,
              /*GuardDivisor=*/false,
              [](IRBuilder<> &B, Value *L, Value *R) {
                return B.CreateAnd(L, R);
              });
    addBinary(OpOr, "or", /*Narrow=*/true, /*Signed=*/false,
              /*GuardDivisor=*/false,
              [](IRBuilder<> &B, Value *L, Value *R) {
                return B.CreateOr(L, R);
              });
    addBinary(OpShl, "shl", /*Narrow=*/true, /*Signed=*/false,
              /*GuardDivisor=*/false,
              [](IRBuilder<> &B, Value *L, Value *R) {
                return B.CreateShl(L, R);
              });
    addBinary(OpLShr, "lshr", /*Narrow=*/true, /*Signed=*/false,
              /*GuardDivisor=*/false,
              [](IRBuilder<> &B, Value *L, Value *R) {
                return B.CreateLShr(L, R);
              });
    addBinary(OpAShr, "ashr", /*Narrow=*/true, /*Signed=*/true,
              /*GuardDivisor=*/false,
              [](IRBuilder<> &B, Value *L, Value *R) {
                return B.CreateAShr(L, R);
              });
    addBinary(OpSDiv, "sdiv", /*Narrow=*/true, /*Signed=*/true,
              /*GuardDivisor=*/true,
              [](IRBuilder<> &B, Value *L, Value *R) {
                return B.CreateSDiv(L, R);
              });
    addBinary(OpUDiv, "udiv", /*Narrow=*/true, /*Signed=*/false,
              /*GuardDivisor=*/true,
              [](IRBuilder<> &B, Value *L, Value *R) {
                return B.CreateUDiv(L, R);
              });
    addBinary(OpSRem, "srem", /*Narrow=*/true, /*Signed=*/true,
              /*GuardDivisor=*/true,
              [](IRBuilder<> &B, Value *L, Value *R) {
                return B.CreateSRem(L, R);
              });
    addBinary(OpURem, "urem", /*Narrow=*/true, /*Signed=*/false,
              /*GuardDivisor=*/true,
              [](IRBuilder<> &B, Value *L, Value *R) {
                return B.CreateURem(L, R);
              });

    auto addCmp = [&](Opcode Op, StringRef Name, CmpInst::Predicate Pred,
                      bool SignedOperands) {
      // Signed compares (SGT/SLT/SGE/SLE) must sign-extend operands first so
      // that e.g. (-1) < 1 holds. EQ/NE are sign-agnostic. The operand VmTy
      // is carried by the most recent push (LoadSlot/PushConst), but the cmp
      // opcode emits no VmTy immediate of its own, so we re-fetch the width
      // from the value's type -- which we do not have here. Instead the cmp
      // handlers below re-narrow the operands using the type width baked
      // into the comparison by reading it from a separate path.
      //
      // Simpler: re-use addBinary with Narrow=false but inject a sign-extend
      // step. Since addBinary only sign-extends when NarrowResult=true (it
      // needs the Ty immediate), and cmps have no Ty immediate, we handle
      // signed compares by sign-extending unconditionally to 64-bit here --
      // which is correct because every supported integer type fits in 64
      // bits, and the canonical zext value sign-extended from its true width
      // equals the mathematically correct signed value. But we don't know
      // the width at this layer without the immediate.
      //
      // Resolution: signed cmps DO carry a VmTy immediate after all. See the
      // encoder: cmp ops emit packVmTy(OperandTy) for the signed variants.
      // To keep this layer simple we instead sign-extend from the operands'
      // stack form by re-deriving width at encode time and emitting it. For
      // now, EQ/NE (the unsigned/signed-agnostic predicates) work without
      // any immediate; the S* predicates are handled by the encoder emitting
      // a VmTy and the handler fetching it.
      addBinary(Op, Name, /*Narrow=*/SignedOperands, /*Signed=*/SignedOperands,
                /*GuardDivisor=*/false,
                [Pred, I64 = C.I64](IRBuilder<> &B, Value *L, Value *R) {
                  return B.CreateZExt(B.CreateICmp(Pred, L, R), I64);
                });
    };
    addCmp(OpCmpEq, "cmpeq", CmpInst::ICMP_EQ, /*Signed=*/false);
    addCmp(OpCmpNe, "cmpne", CmpInst::ICMP_NE, /*Signed=*/false);
    addCmp(OpCmpSgt, "cmpsgt", CmpInst::ICMP_SGT, /*Signed=*/true);
    addCmp(OpCmpSlt, "cmpslt", CmpInst::ICMP_SLT, /*Signed=*/true);
    addCmp(OpCmpSge, "cmpsge", CmpInst::ICMP_SGE, /*Signed=*/true);
    addCmp(OpCmpSle, "cmpsle", CmpInst::ICMP_SLE, /*Signed=*/true);
    // unsigned compares. Operands stay canonical zext; unsigned
    // ICmp is width-agnostic, no immediate, no sign-extend.
    addCmp(OpCmpUgt, "cmpugt", CmpInst::ICMP_UGT, /*Signed=*/false);
    addCmp(OpCmpUlt, "cmpult", CmpInst::ICMP_ULT, /*Signed=*/false);
    addCmp(OpCmpUge, "cmpuge", CmpInst::ICMP_UGE, /*Signed=*/false);
    addCmp(OpCmpUle, "cmpule", CmpInst::ICMP_ULE, /*Signed=*/false);

    H.push_back({OpSelect, "select", shapeOf(OpSelect),
                 [this, &C](IRBuilder<> &B) {
                   Value *FalseV = popStk(B, C);
                   Value *TrueV = popStk(B, C);
                   Value *CondV = popStk(B, C);
                   pushStk(B, C,
                           B.CreateSelect(
                               B.CreateICmpNE(CondV,
                                              ConstantInt::get(C.I64, 0)),
                               TrueV, FalseV));
                   B.CreateBr(C.Dispatch);
                 }});

    H.push_back({OpJmp, "jmp", shapeOf(OpJmp),
                 [this, &C](IRBuilder<> &B) {
                   Value *Target = fetchWord(B, C);
                   branchIfFalse(B, C, B.CreateICmpULT(Target, C.BCLen));
                   B.CreateStore(Target, C.PC);
                   B.CreateBr(C.Dispatch);
                 }});
    H.push_back({OpBrTrue, "brtrue", shapeOf(OpBrTrue),
                 [this, &C](IRBuilder<> &B) {
                   Value *Target = fetchWord(B, C);
                   Value *Cond = popStk(B, C);
                   BasicBlock *SetTarget =
                       BasicBlock::Create(*C.Ctx, "brtrue.set", C.F);
                   branchIfFalse(B, C, B.CreateICmpULT(Target, C.BCLen));
                   B.CreateCondBr(
                       B.CreateICmpNE(Cond, ConstantInt::get(C.I64, 0)),
                       SetTarget, C.Dispatch);
                   B.SetInsertPoint(SetTarget);
                   B.CreateStore(Target, C.PC);
                   B.CreateBr(C.Dispatch);
                 }});
    H.push_back({OpRet, "ret", shapeOf(OpRet),
                 [this, &C](IRBuilder<> &B) { B.CreateRet(popStk(B, C)); }});

    if (H.size() > 1) {
      std::shuffle(H.begin(), H.end(), RNG);
      if (H.front().Op == OpInitArg)
        std::rotate(H.begin(), H.begin() + 1, H.end());
    }
    return H;
  }

  Function *createInterpreter(Module &M, Function &Source) {
    LLVMContext &Ctx = M.getContext();
    Type *I64 = Type::getInt64Ty(Ctx);
    Type *I8 = Type::getInt8Ty(Ctx);
    Type *Ptr = PointerType::getUnqual(Ctx);
    // signature is i64(i64* bc, i64 bcLen, i8* pcMap, ptr* ptrs,
    // i64 ptrCount, i64* args, i64 argLen, i64* tamper, i64 tag,
    // i64* opcodeMap, i64 key). bcLen is the
    // bytecode word count; the dispatch loop checks PC < bcLen before each
    // fetch so a corrupted PC (relevant once L2 encrypts the bytecode) faults
    // to the Bad block instead of reading out of bounds.
    auto *FTy =
        FunctionType::get(
            I64, {Ptr, I64, Ptr, Ptr, I64, Ptr, I64, Ptr, I64, Ptr, I64},
            false);
    std::string InterpName =
        ("__taokari_vmp_interp_i64_" + Source.getName()).str();
    InterpName += "_";
    InterpName += std::to_string(RNG());
    auto *F = Function::Create(FTy, GlobalValue::InternalLinkage, InterpName, M);
    F->addFnAttr(Attribute::NoUnwind);

    auto ArgIt = F->arg_begin();
    Value *BC = &*ArgIt++;
    BC->setName("bc");
    Value *BCLen = &*ArgIt++;
    BCLen->setName("bclen");
    Value *PCMap = &*ArgIt++;
    PCMap->setName("pc.map");
    Value *PtrTable = &*ArgIt++;
    PtrTable->setName("ptr.table");
    Value *PtrCount = &*ArgIt++;
    PtrCount->setName("ptr.count");
    Value *Args = &*ArgIt++;
    Args->setName("args");
    Value *ArgLen = &*ArgIt++;
    ArgLen->setName("arg.len");
    Value *TamperFlag = &*ArgIt++;
    TamperFlag->setName("tamper");
    Value *ExpectedTag = &*ArgIt++;
    ExpectedTag->setName("bytecode.tag");
    Value *OpcodeMap = &*ArgIt++;
    OpcodeMap->setName("opcode.map");
    Value *BytecodeKey = &*ArgIt++;
    BytecodeKey->setName("bytecode.key");

    BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", F);
    BasicBlock *Dispatch = BasicBlock::Create(Ctx, "dispatch", F);
    BasicBlock *Bad = BasicBlock::Create(Ctx, "bad", F);
    IRBuilder<> B(Entry);
    auto *Stack = B.CreateAlloca(I64, ConstantInt::get(I64, 64), "stack");
    auto *Locals = B.CreateAlloca(I64, ConstantInt::get(I64, 64), "locals");
    // VM-local frame (L1.5.1 middle way). AllocaInst reserves runs
    // of consecutive slots here; LoadPtr/StorePtr index into it via the
    // frame-pointer values pushed by emitValue.
    auto *Frame = B.CreateAlloca(I64, ConstantInt::get(I64, 64), "frame");
    // OpCall argument marshaling buffer (L1.5.1). Up to 8 integer
    // args per call (isVMCompatibleCall gates on arg_size() <= 8).
    auto *CallArgs = B.CreateAlloca(I64, ConstantInt::get(I64, 8), "callargs");
    auto *PC = B.CreateAlloca(I64, nullptr, "pc");
    auto *SP = B.CreateAlloca(I64, nullptr, "sp");
    B.CreateStore(ConstantInt::get(I64, 0), PC);
    B.CreateStore(ConstantInt::get(I64, 0), SP);
    auto *Tag = B.CreateAlloca(I64, nullptr, "tag");
    auto *TagI = B.CreateAlloca(I64, nullptr, "tag.i");
    B.CreateStore(ConstantInt::get(I64, 0xCBF29CE484222325ULL), Tag);
    B.CreateStore(ConstantInt::get(I64, 0), TagI);
    BasicBlock *TagHdr = BasicBlock::Create(Ctx, "tag.hdr", F);
    BasicBlock *TagBody = BasicBlock::Create(Ctx, "tag.body", F);
    BasicBlock *TagDone = BasicBlock::Create(Ctx, "tag.done", F);
    B.CreateBr(TagHdr);
    B.SetInsertPoint(TagHdr);
    Value *CurTagI = B.CreateLoad(I64, TagI);
    B.CreateCondBr(B.CreateICmpULT(CurTagI, BCLen), TagBody, TagDone);
    B.SetInsertPoint(TagBody);
    Value *CurWord = B.CreateLoad(I64, B.CreateGEP(I64, BC, CurTagI));
    Value *CurTag = B.CreateLoad(I64, Tag);
    Value *TagMix =
        B.CreateAdd(CurWord, B.CreateMul(CurTagI, ConstantInt::get(I64, 0x9E3779B97F4A7C15ULL)));
    Value *NextTag =
        B.CreateMul(B.CreateXor(CurTag, TagMix),
                    ConstantInt::get(I64, 0x100000001B3ULL));
    B.CreateStore(NextTag, Tag);
    B.CreateStore(B.CreateAdd(CurTagI, ConstantInt::get(I64, 1)), TagI);
    B.CreateBr(TagHdr);
    B.SetInsertPoint(TagDone);
    B.CreateCondBr(B.CreateICmpEQ(B.CreateLoad(I64, Tag), ExpectedTag),
                   Dispatch, Bad);

    B.SetInsertPoint(Dispatch);
    Value *OpPC = B.CreateLoad(I64, PC);
    // PC bounds check (L1.5.4). If PC has run past the bytecode,
    // fault to Bad rather than reading out of bounds. Matters once L2
    // encrypts the bytecode and a corrupted PC could otherwise escape.
    Value *InBounds = B.CreateICmpULT(OpPC, BCLen);
    BasicBlock *PcMapCheck = BasicBlock::Create(Ctx, "pcmap.check", F);
    BasicBlock *Fetch = BasicBlock::Create(Ctx, "fetch", F);
    B.CreateCondBr(InBounds, PcMapCheck, Bad);
    B.SetInsertPoint(PcMapCheck);
    Value *PCFlags = B.CreateLoad(I8, B.CreateGEP(I8, PCMap, OpPC));
    Value *IsOpStart =
        B.CreateAnd(PCFlags, ConstantInt::get(I8, 1));
    B.CreateCondBr(B.CreateICmpNE(IsOpStart, ConstantInt::get(I8, 0)), Fetch,
                   Bad);
    B.SetInsertPoint(Fetch);
    // Build handler table, then emit one switch case per entry.
    // The table is the source of truth; the switch is generated from it.
    InterpCtx IC{I64,   F,       &Ctx, BC,       BCLen, PCMap, PtrTable, PtrCount, PC,
                 SP,    Stack,   Locals, Frame,  CallArgs,
                 CalleeTable, static_cast<unsigned>(CalleeOrder.size()),
                 Args,  ArgLen,  TamperFlag, ExpectedTag, OpcodeMap, BytecodeKey,
                 Dispatch, Bad, M.getDataLayout().isLittleEndian()};
    Value *MappedOp = fetchWord(B, IC);
    branchIfFalse(B, IC,
                  B.CreateICmpULT(MappedOp,
                                  ConstantInt::get(I64, kOpcodeTableSize)));
    Value *Op = B.CreateLoad(I64, B.CreateGEP(I64, OpcodeMap, MappedOp));
    branchIfFalse(B, IC,
                  B.CreateICmpNE(Op, ConstantInt::getSigned(I64, -1)));
    SmallVector<Handler, 24> Handlers = buildHandlerTable(IC);
    uint64_t DispatchKey = RNG();
    if (!DispatchKey)
      DispatchKey = 0xA0761D6478BD642FULL;
    Value *DispatchToken =
        B.CreateXor(Op, ConstantInt::get(I64, DispatchKey));
    Value *Target = BlockAddress::get(F, Bad);
    SmallVector<BasicBlock *, 24> Dests;
    Dests.push_back(Bad);
    SmallVector<std::pair<Handler *, BasicBlock *>, 24> HandlerBlocks;
    for (Handler &H : Handlers) {
      BasicBlock *CaseBB = BasicBlock::Create(Ctx, H.Name, F);
      uint64_t EncOp = static_cast<uint64_t>(H.Op) ^ DispatchKey;
      Value *Hit = B.CreateICmpEQ(DispatchToken, ConstantInt::get(I64, EncOp));
      Target = B.CreateSelect(Hit, BlockAddress::get(F, CaseBB), Target,
                              "handler.target");
      Dests.push_back(CaseBB);
      HandlerBlocks.push_back({&H, CaseBB});
    }
    auto *IBI = B.CreateIndirectBr(Target, Dests.size());
    for (BasicBlock *Dest : Dests)
      IBI->addDestination(Dest);

    for (auto [H, CaseBB] : HandlerBlocks) {
      B.SetInsertPoint(CaseBB);
      H->Emit(B);
    }

    B.SetInsertPoint(Bad);
    B.CreateStore(ConstantInt::get(I64, 1), TamperFlag);
    B.CreateRet(ConstantInt::get(I64, 0));
    return F;
  }

  bool replaceWithVM(Function &F, BytecodeProgram &P) {
    Module &M = *F.getParent();
    LLVMContext &Ctx = M.getContext();
    Type *I64 = Type::getInt64Ty(Ctx);

    uint64_t BytecodeKey = RNG();
    if (!BytecodeKey)
      BytecodeKey = 0xD1B54A32D192ED03ULL;
    SmallVector<int64_t, kOpcodeTableSize> OpcodeEncode;
    SmallVector<int64_t, kOpcodeTableSize> OpcodeDecode;
    if (!buildOpcodeMaps(OpcodeEncode, OpcodeDecode))
      return false;
    SmallVector<int64_t, 64> EncodedWords(P.Words.begin(), P.Words.end());
    SmallVector<uint8_t, 64> PCFlags;
    uint8_t RotationStep = static_cast<uint8_t>((RNG() % 63) + 1);
    if (!computePCMapFlags(P.Words, PCFlags, RotationStep))
      return false;
    if (!mapOpcodeWords(EncodedWords, OpcodeEncode))
      return false;

    SmallVector<Constant *, 64> Words;
    uint64_t BytecodeTag = 0xCBF29CE484222325ULL;
    for (size_t I = 0; I < EncodedWords.size(); ++I) {
      int64_t Word =
          encryptBytecodeWord(EncodedWords[I], I, BytecodeKey, PCFlags[I]);
      BytecodeTag = mixBytecodeTag(BytecodeTag, static_cast<uint64_t>(Word), I);
      Words.push_back(ConstantInt::get(I64, static_cast<uint64_t>(Word), true));
    }
    auto *ArrayTy = ArrayType::get(I64, Words.size());
    auto *Bytecode = new GlobalVariable(
        M, ArrayTy, true, GlobalValue::PrivateLinkage,
        ConstantArray::get(ArrayTy, Words),
        "__taokari_vmp_bc_" + F.getName());
    Bytecode->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    Bytecode->setAlignment(Align(8));

    Type *I8 = Type::getInt8Ty(Ctx);
    SmallVector<Constant *, 64> Starts;
    for (uint8_t V : PCFlags)
      Starts.push_back(ConstantInt::get(I8, V));
    auto *PCMapArrayTy = ArrayType::get(I8, Starts.size());
    auto *PCMap = new GlobalVariable(
        M, PCMapArrayTy, true, GlobalValue::PrivateLinkage,
        ConstantArray::get(PCMapArrayTy, Starts),
        "__taokari_vmp_pcmap_" + F.getName());
    PCMap->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    PCMap->setAlignment(Align(1));

    SmallVector<Constant *, kOpcodeTableSize> OpcodeMapEntries;
    for (int64_t V : OpcodeDecode)
      OpcodeMapEntries.push_back(ConstantInt::getSigned(I64, V));
    auto *OpcodeMapArrayTy = ArrayType::get(I64, OpcodeMapEntries.size());
    auto *OpcodeMap = new GlobalVariable(
        M, OpcodeMapArrayTy, true, GlobalValue::PrivateLinkage,
        ConstantArray::get(OpcodeMapArrayTy, OpcodeMapEntries),
        "__taokari_vmp_opmap_" + F.getName());
    OpcodeMap->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    OpcodeMap->setAlignment(Align(8));

    Function *Interp = createInterpreter(M, F);
    F.deleteBody();
    BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", &F);
    BasicBlock *Ok = BasicBlock::Create(Ctx, "vmp.ok", &F);
    BasicBlock *Trap = BasicBlock::Create(Ctx, "vmp.trap", &F);
    IRBuilder<> B(Entry);
    Value *Zero = ConstantInt::get(I64, 0);
    Value *BCPtr = B.CreateGEP(ArrayTy, Bytecode, {Zero, Zero});
    Value *PCMapPtr = B.CreateGEP(PCMapArrayTy, PCMap, {Zero, Zero});
    Value *OpcodeMapPtr = B.CreateGEP(OpcodeMapArrayTy, OpcodeMap, {Zero, Zero});
    Type *Ptr = PointerType::getUnqual(Ctx);
    Value *PtrTablePtr = ConstantPointerNull::get(PointerType::getUnqual(Ctx));
    Value *PtrCount = ConstantInt::get(I64, 0);
    if (!P.PointerConsts.empty()) {
      auto *PtrArrayTy = ArrayType::get(Ptr, P.PointerConsts.size());
      auto *PtrTable = new GlobalVariable(
          M, PtrArrayTy, true, GlobalValue::PrivateLinkage,
          ConstantArray::get(PtrArrayTy, P.PointerConsts),
          "__taokari_vmp_ptrs_" + F.getName());
      PtrTable->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
      PtrTable->setAlignment(Align(8));
      PtrTablePtr = B.CreateGEP(PtrArrayTy, PtrTable, {Zero, Zero});
      PtrCount = ConstantInt::get(I64, P.PointerConsts.size());
    }

    auto *ArgsArrayTy = ArrayType::get(I64, std::max<unsigned>(1, F.arg_size()));
    auto *Args = B.CreateAlloca(ArgsArrayTy, nullptr, "vmp.args");
    unsigned I = 0;
    for (Argument &A : F.args()) {
      Value *ArgPtr = B.CreateGEP(ArgsArrayTy, Args,
                                  {Zero, ConstantInt::get(I64, I++)});
      Value *ArgVal = A.getType()->isPointerTy()
                          ? B.CreatePtrToInt(&A, I64)
                          : B.CreateSExtOrTrunc(&A, I64);
      B.CreateStore(ArgVal, ArgPtr);
    }
    Value *ArgsPtr = B.CreateGEP(ArgsArrayTy, Args, {Zero, Zero});
    auto *TamperFlag = B.CreateAlloca(I64, nullptr, "vmp.tamper");
    B.CreateStore(Zero, TamperFlag);
    // pass the bytecode word count as the bcLen argument so the
    // interpreter can bound-check PC (L1.5.4).
    Value *BCLen = ConstantInt::get(I64, Words.size());
    Value *RuntimeKey = buildRuntimeBytecodeKey(B, M, F, I64, BytecodeKey);
    Value *Result = B.CreateCall(
        Interp, {BCPtr, BCLen, PCMapPtr, PtrTablePtr, PtrCount, ArgsPtr,
                 ConstantInt::get(I64, F.arg_size()), TamperFlag,
                 ConstantInt::get(I64, BytecodeTag), OpcodeMapPtr,
                 RuntimeKey});
    Value *Tampered = B.CreateLoad(I64, TamperFlag);
    B.CreateCondBr(B.CreateICmpNE(Tampered, Zero), Trap, Ok);
    B.SetInsertPoint(Trap);
    auto *ExitTy =
        FunctionType::get(Type::getVoidTy(Ctx), {Type::getInt32Ty(Ctx)}, false);
    FunctionCallee Exit = M.getOrInsertFunction("exit", ExitTy);
    if (auto *ExitFn = dyn_cast<Function>(Exit.getCallee()))
      ExitFn->addFnAttr(Attribute::NoReturn);
    B.CreateCall(Exit, {ConstantInt::get(Type::getInt32Ty(Ctx), 86)});
    B.CreateUnreachable();
    B.SetInsertPoint(Ok);
    B.CreateRet(B.CreateTruncOrBitCast(Result, F.getReturnType()));
    return true;
  }

  // Materialize the per-module direct-callee table as a global
  // i64 array of call-thunk function pointers (ptrtoint). Each direct
  // callee gets a thunk i64(i64* %args) that loads typed args, calls the
  // real callee, and returns the i64 result (0 for void). This abstracts
  // per-callee signatures away from the generic interpreter, which calls
  // every thunk uniformly as i64(i64*). Built after all targets have been
  // encoded and before the interpreter is constructed.
  Function *getOrCreateCallThunk(Module &M, Function *Callee) {
    // One thunk per distinct callee. Name encodes the callee so the get-or-
    // create lookup works.
    std::string ThunkName = "__taokari_vmp_callthunk_" +
                            std::string(Callee->getName());
    if (auto *Existing = M.getFunction(ThunkName))
      return Existing;

    LLVMContext &Ctx = M.getContext();
    Type *I64 = Type::getInt64Ty(Ctx);
    Type *I64Ptr = PointerType::getUnqual(Ctx);
    auto *ThunkTy = FunctionType::get(I64, {I64Ptr}, false);
    auto *Thunk = Function::Create(ThunkTy, GlobalValue::InternalLinkage,
                                   ThunkName, M);
    Thunk->addFnAttr(Attribute::NoUnwind);

    BasicBlock *BB = BasicBlock::Create(Ctx, "entry", Thunk);
    IRBuilder<> B(BB);
    Argument *ArgsPtr = Thunk->getArg(0);
    ArgsPtr->setName("args");

    // Build typed argument values by loading each i64 slot and truncating to
    // the callee's declared arg type.
    SmallVector<Value *, 8> CallArgs;
    unsigned I = 0;
    Value *Zero = ConstantInt::get(I64, 0);
    for (Argument &A : Callee->args()) {
      Value *SlotPtr = B.CreateGEP(
          ArrayType::get(I64, std::max<unsigned>(1, Callee->arg_size())),
          ArgsPtr, {Zero, ConstantInt::get(I64, I++)});
      Value *Raw = B.CreateLoad(I64, SlotPtr);
      // Truncate the canonical i64 down to the declared arg width.
      CallArgs.push_back(B.CreateTrunc(Raw, A.getType()));
    }

    if (Callee->getReturnType()->isVoidTy()) {
      B.CreateCall(Callee, CallArgs);
      B.CreateRet(ConstantInt::get(I64, 0));
    } else {
      Value *Result = B.CreateCall(Callee, CallArgs);
      // ZExt to i64 -- the call result is already in canonical form when the
      // callee is itself virtualized; for external callees we trust the
      // declared type. Sign vs zero: zext is safe because the OpCall handler
      // narrows via VmTy afterward.
      B.CreateRet(B.CreateZExt(Result, I64));
    }
    return Thunk;
  }

  void finalizeCalleeTable(Module &M) {
    if (CalleeOrder.empty()) {
      CalleeTable = nullptr;
      CalleeTableKey = 0;
      return;
    }
    // Store masked per-index callee tokens; OpCall validates them before
    // dispatching to the generated call-thunk case.
    CalleeTableKey = RNG();
    if (!CalleeTableKey)
      CalleeTableKey = 0xD6E8FEB86659FD93ULL;
    LLVMContext &Ctx = M.getContext();
    Type *I64 = Type::getInt64Ty(Ctx);
    SmallVector<Constant *, 8> Entries;
    for (auto [Index, Callee] : llvm::enumerate(CalleeOrder)) {
      (void)getOrCreateCallThunk(M, Callee);
      Entries.push_back(
          ConstantInt::get(I64, calleeTableMaskWord(static_cast<uint64_t>(Index))));
    }
    auto *ArrayTy = ArrayType::get(I64, Entries.size());
    CalleeTable = new GlobalVariable(
        M, ArrayTy, true, GlobalValue::PrivateLinkage,
        ConstantArray::get(ArrayTy, Entries), "__taokari_vmp_callees");
    CalleeTable->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    CalleeTable->setAlignment(Align(8));
  }

  bool runOnModule(Module &M) override {
    // reset per-module state -- ModulePass instances can be reused
    // across modules by the legacy pass manager.
    CalleeIndex.clear();
    CalleeOrder.clear();
    CalleeTable = nullptr;

    SmallVector<Function *, 8> Targets;
    for (Function &F : M) {
      if (shouldSkip(F))
        continue;
      auto Opt = ArgsOptions->toObfuscate(ArgsOptions->vmpOpt(), &F);
      if (!Opt.isEnabled())
        continue;
      Targets.push_back(&F);
    }

    // L2 selection diagnostics: emit one remark per +vmp target so users can
    // see which functions virtualized and why skipped functions were rejected.
    unsigned Virtualized = 0;
    unsigned Skipped = 0;

    // Phase 1: encode every target. This populates CalleeOrder with the
    // direct callees referenced across all virtualized functions.
    SmallVector<std::pair<Function *, BytecodeProgram>, 8> Encoded;
    for (Function *F : Targets) {
      OptimizationRemarkEmitter ORE(F);
      if (hasUnsupportedIR(*F)) {
        OptimizationRemarkMissed R(DEBUG_TYPE, "UnsupportedIR", F);
        R << "skipped: unsupported IR (PHI/call/EH/memory pattern outside "
             "the L1.5 ISA)";
        ORE.emit(R);
        ++Skipped;
        continue;
      }
      BytecodeProgram P;
      if (!buildBytecode(*F, P)) {
        OptimizationRemarkMissed R(DEBUG_TYPE, "EncodeFailed", F);
        R << "skipped: bytecode encoding failed (frame overflow, stack "
             "depth, or unsupported operand pattern)";
        ORE.emit(R);
        ++Skipped;
        continue;
      }
      Encoded.emplace_back(F, std::move(P));
    }

    // Phase 2: finalize the callee table now that all callees are known.
    finalizeCalleeTable(M);

    // Phase 3: build the interpreter (uses CalleeTable) and replace bodies.
    bool Changed = false;
    for (auto &[F, P] : Encoded) {
      Changed |= replaceWithVM(*F, P);
      OptimizationRemarkEmitter ORE(F);
      OptimizationRemark R(DEBUG_TYPE, "Virtualized", F);
      R << "virtualized ("
        << ore::NV("Words", (unsigned)P.Words.size())
        << " bytecode words)";
      ORE.emit(R);
      ++Virtualized;
    }

    LLVM_DEBUG(dbgs() << "taokari-vmp: " << Virtualized << " virtualized, "
                      << Skipped << " skipped\n");
    return Changed;
  }
};
} // namespace

char CodeVirtualization::ID = 0;

ModulePass *llvm::createCodeVirtualizationPass(ObfuscationOptions *ArgsOptions) {
  return new CodeVirtualization(ArgsOptions);
}
