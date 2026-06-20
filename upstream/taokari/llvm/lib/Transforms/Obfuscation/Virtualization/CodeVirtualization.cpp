#include "llvm/Transforms/Obfuscation/CodeVirtualization.h"
#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
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

#include <cstdint>
#include <functional>

#define DEBUG_TYPE "taokari-vmp"

using namespace llvm;

namespace {

// ponytail: Opcode encoding is the stable on-the-wire bytecode value. These
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
  // ponytail: L1.5.1 widened integer binary ops. Values 18+ are the new ISA;
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
  // ponytail: L1.5.1 unsigned compares. Operands stay in canonical zext form;
  // unsigned comparison is width-agnostic, so these carry no VmTy immediate
  // (like EQ/NE).
  OpCmpUgt = 28,
  OpCmpUlt = 29,
  OpCmpUge = 30,
  OpCmpUle = 31,
  // ponytail: L1.5.1 VM-local memory (middle way). Frame pointers are static
  // i64 indices into a per-interpreter Frame array; alloca/GEP resolve to
  // compile-time PushConst of the frame index. LoadPtr/StorePtr carry a VmTy
  // for width narrowing. External pointer args/globals are NOT supported --
  // they stay rejected and defer to the L2 full-pointer step.
  OpLoadPtr = 32,
  OpStorePtr = 33,
  // ponytail: L1.5.1 direct calls. OpCall fetches <calleeIdx> <nargs>
  // <resultVmTy>, pops nargs operand-stack values into a call-args buffer,
  // calls callees[calleeIdx] (resolved by the encoder to a direct Function*),
  // and pushes the i64 return narrowed by resultVmTy. Integer args/return
  // only; pointer/float/vararg callees reject the whole function. Indirect/
  // virtual calls stay rejected.
  OpCall = 34,
};

// ponytail: How many operand-stack pops and bytecode immediates a handler
// consumes. The encoder uses these for stack-depth validation; the
// interpreter construction uses them for diagnostics only (each handler
// drives its own fetch()/pop() count for now, since some are data-dependent
// like OpInitArg which fetches two immediates).
struct HandlerStackShape {
  unsigned Pops = 0;
  unsigned Pushes = 0;
  unsigned Immediates = 0;
};

// ponytail: Per-value width+signedness. The VM stores everything as i64, but
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

// ponytail: Pack VmTy into a single int64 immediate (bits 0..7 = width,
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
};

// ponytail: Handler descriptor. The interpreter builder iterates the table
// and emits one switch case per entry; opcode values stay the stable enum.
// This is the L1.5.2 refactor target: previously every opcode was a hand-
// written case in getOrCreateInterpreter with no arity metadata. Now the
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
  // ponytail: Per-module direct-callee table (L1.5.1). Populated lazily by
  // buildBytecode as it encounters direct CallInsts; resolved into a
  // __taokari_vmp_callees global by finalizeCalleeTable() before the
  // interpreter is built. OpCall indexes into it.
  DenseMap<Function *, unsigned> CalleeIndex;
  SmallVector<Function *, 8> CalleeOrder;
  GlobalVariable *CalleeTable = nullptr;

  CodeVirtualization(ObfuscationOptions *ArgsOptions) : ModulePass(ID) {
    this->ArgsOptions = ArgsOptions;
  }

  StringRef getPassName() const override {
    return "Taokari Code Virtualization";
  }

  bool isSupportedInt(Type *Ty) const {
    return Ty->isIntegerTy() && Ty->getIntegerBitWidth() <= 64;
  }

  bool isSkippable(const Instruction &I) const {
    return isa<DbgInfoIntrinsic>(I);
  }

  // ponytail: True if a CallInst is virtualizable by the L1.5.1 OpCall path.
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
    for (Argument &A : F.args())
      if (!isSupportedInt(A.getType()))
        return true;
    return false;
  }

  bool hasUnsupportedIR(Function &F) const {
    for (BasicBlock &BB : F) {
      for (Instruction &I : BB) {
        if (isSkippable(I))
          continue;
        // ponytail: Level 1 VM is toy integer IR only. Add call/EH support
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
          // ponytail: L1.5.1 widened integer binary ops.
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
        // ponytail: VM-local memory (L1.5.1 middle way). Allow AllocaInst,
        // LoadInst, StoreInst, GetElementPtrInst here; buildBytecode rejects
        // the function if any pointer origin is non-VM-local (external arg,
        // global, etc.) -- that check needs whole-function alloca context.
        if (isa<AllocaInst>(I) || isa<LoadInst>(I) || isa<StoreInst>(I) ||
            isa<GetElementPtrInst>(I))
          continue;
        // ponytail: direct CallInst allowed (L1.5.1); indirect/non-integer
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

  // ponytail: True if Ty can live in the VM-local frame (integer scalars,
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

  // ponytail: Emit a value-push that carries the value's VmTy so the
  // interpreter can sign/zero-extend into the i64 slot correctly. For a
  // ConstantInt we encode the full sext/zext value directly; for a slot we
  // emit its index. In both cases a packed VmTy immediate follows so the
  // interpreter narrows/promotes the right way before any consumer sees it.
  // VM-local pointers (alloca-derived) resolve to a PushConst of the frame
  // slot index via resolveFramePtr; non-VM-local pointers fail here, which
  // buildBytecode turns into a skip-virtualization.
  bool emitValue(BytecodeProgram &P, DenseMap<const Value *, unsigned> &Slots,
                 DenseMap<const AllocaInst *, unsigned> &AllocaBase,
                 unsigned &NextFrameSlot, Value *V) {
    // VM-local pointer: alloca or constant-offset GEP of an alloca.
    if (V->getType()->isPointerTy()) {
      int64_t FrameIdx = 0;
      if (!resolveFramePtr(V, AllocaBase, NextFrameSlot, FrameIdx))
        return false;
      P.Words.push_back(OpPushConst);
      P.Words.push_back(FrameIdx);
      // Frame pointers are width-agnostic unsigned indices.
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

  // ponytail: Emit slot copies for every PHI in `Succ` whose incoming value
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

  // ponytail: Resolve a VM-local pointer to a Frame slot index. Returns false
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

  bool buildBytecode(Function &F, BytecodeProgram &P) {
    DenseMap<const Value *, unsigned> Slots;
    DenseMap<const BasicBlock *, size_t> BlockStart;
    // ponytail: VM-local frame allocator. Each AllocaInst reserves
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
      // ponytail: pre-register PHI slots so any use of a PHI (including by
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
          // ponytail: PHI nodes produce no bytecode inline. Their effect is
          // the predecessor-side slot copies emitted by emitPhiCopies below.
          continue;
        }
        if (auto *BO = dyn_cast<BinaryOperator>(&I)) {
          if (!emitValue(P, Slots, AllocaBase, NextFrameSlot, BO->getOperand(0)) ||
              !emitValue(P, Slots, AllocaBase, NextFrameSlot, BO->getOperand(1)))
            return false;
          VmTy ResultTy = vmTyFromType(BO->getType());
          // ponytail: signedness for the few ops where it matters at encode
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
          // ponytail: operand/result width so the interpreter truncates the
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
          // ponytail: cmp operands are pushed in canonical zext form. Signed
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
          // ponytail: unsigned compares. Operands are already canonical zext;
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
        // ponytail: VM-local load (L1.5.1 middle way). Emit the VM-local
        // pointer (resolves to a PushConst frame index via emitValue), then
        // OpLoadPtr + VmTy. The handler pops the frame index, loads
        // Frame[idx], narrows, and pushes the result. The load result is
        // then stored into the load's own locals slot like any other def.
        if (auto *LD = dyn_cast<LoadInst>(&I)) {
          if (!isSupportedInt(LD->getType()))
            return false;
          if (!emitValue(P, Slots, AllocaBase, NextFrameSlot, LD->getPointerOperand()))
            return false;
          P.Words.push_back(OpLoadPtr);
          P.Words.push_back(packVmTy(vmTyFromType(LD->getType())));
          P.Words.push_back(OpStoreSlot);
          P.Words.push_back(slotFor(Slots, &I));
          continue;
        }
        // ponytail: VM-local store. Emit the value then the VM-local pointer,
        // then OpStorePtr + VmTy. The handler pops the pointer, then the
        // value, narrows the value to VmTy, and stores Frame[ptr] = value.
        if (auto *ST = dyn_cast<StoreInst>(&I)) {
          if (!isSupportedInt(ST->getValueOperand()->getType()))
            return false;
          if (!emitValue(P, Slots, AllocaBase, NextFrameSlot, ST->getValueOperand()))
            return false;
          if (!emitValue(P, Slots, AllocaBase, NextFrameSlot, ST->getPointerOperand()))
            return false;
          P.Words.push_back(OpStorePtr);
          P.Words.push_back(packVmTy(vmTyFromType(ST->getValueOperand()->getType())));
          continue;
        }
        // GetElementPtrInst produces no bytecode of its own -- emitValue
        // resolves it to a PushConst frame index when the pointer is used.
        if (isa<GetElementPtrInst>(I)) {
          slotFor(Slots, &I); // register so emitValue(GEP) can re-resolve
          continue;
        }
        // AllocaInst produces no bytecode of its own -- references resolve
        // via emitValue to a PushConst frame index (allocated in pre-scan).
        if (isa<AllocaInst>(I))
          continue;
        // ponytail: direct CallInst (L1.5.1). Indirect/virtual callees and
        // non-integer args/return reject the whole function.
        if (auto *CI = dyn_cast<CallInst>(&I)) {
          if (!isVMCompatibleCall(*CI))
            return false;
          auto *Callee = cast<Function>(CI->getCalledOperand());
          // ponytail: register the callee in the per-module callee table and
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
            // ponytail: store PHI incomings for the single successor, then jump.
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
    return Slots.size() <= 64 && !P.Words.empty();
  }

  // ponytail: Per-opcode stack shape. Used by the build-time depth check
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
    case OpCmpSgt:
    case OpCmpSlt:
    case OpCmpSge:
    case OpCmpSle:
    case OpCmpUgt:
    case OpCmpUlt:
    case OpCmpUge:
    case OpCmpUle:
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
      // binary ops now carry a VmTy immediate (result width) for narrowing.
      // Cmp ops in this list carry no immediate (NarrowResult=false), but the
      // shape is reported conservatively uniform here; the actual fetch count
      // is driven by NarrowResult in the handler, not by this metadata.
      return {2, 1, 1};
    case OpSelect:
      return {3, 1, 0};
    case OpLoadPtr:
      // pops frame idx, fetches VmTy, pushes value
      return {1, 1, 1};
    case OpStorePtr:
      // pops frame idx, pops value, fetches VmTy
      return {2, 0, 1};
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

  // ponytail: Bundle of interpreter state. Emit closures in the handler
  // table capture a pointer to this struct by value (one pointer copy),
  // which is always valid because the Ctx outlives both the table build and
  // the synchronous Emit pass in getOrCreateInterpreter. This avoids the
  // lifetime hazard of capturing local helper lambdas (fetch/pop/push) by
  // reference into deferred std::function closures.
  struct InterpCtx {
    Type *I64;
    Function *F;
    LLVMContext *Ctx;
    Value *BC;
    Value *PC;
    Value *SP;
    Value *Stack;
    Value *Locals;
    Value *Frame;
    Value *CallArgs;
    GlobalVariable *CalleeTable;
    Value *Args;
    BasicBlock *Dispatch;
  };

  Value *fetchWord(IRBuilder<> &B, InterpCtx &C) {
    Value *Cur = B.CreateLoad(C.I64, C.PC);
    Value *Word = B.CreateLoad(C.I64, B.CreateGEP(C.I64, C.BC, Cur));
    B.CreateStore(B.CreateAdd(Cur, ConstantInt::get(C.I64, 1)), C.PC);
    return Word;
  }

  void pushStk(IRBuilder<> &B, InterpCtx &C, Value *V) {
    push(B, C.I64, C.Stack, C.SP, V);
  }

  Value *popStk(IRBuilder<> &B, InterpCtx &C) {
    return pop(B, C.I64, C.Stack, C.SP);
  }

  // ponytail: Narrow a full i64 value to its native width, returned as the
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
    Value *Width = B.CreateAnd(PackedTyImm, ConstantInt::get(C.I64, 0xFF));
    // Mask = (1 << Width) - 1
    Value *Mask =
        B.CreateSub(B.CreateShl(ConstantInt::get(C.I64, 1), Width),
                    ConstantInt::get(C.I64, 1));
    return B.CreateAnd(V, Mask);
  }

  // ponytail: Sign-extend a canonical zext stack value from its native width
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
    Value *Width = B.CreateAnd(PackedTyImm, ConstantInt::get(C.I64, 0xFF));
    Value *Mask =
        B.CreateSub(B.CreateShl(One, Width), ConstantInt::get(C.I64, 1));
    Value *Lo = B.CreateAnd(V, Mask);
    Value *SignBit =
        B.CreateShl(One, B.CreateSub(Width, ConstantInt::get(C.I64, 1)));
    return B.CreateSub(B.CreateXor(Lo, SignBit), SignBit);
  }

  // ponytail: Build the handler table for the interpreter. Each entry owns
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
                   Value *V = B.CreateLoad(C.I64, B.CreateGEP(C.I64, C.Locals, Slot));
                   pushStk(B, C, narrowTo(B, C, V, Ty));
                   B.CreateBr(C.Dispatch);
                 }});
    H.push_back({OpStoreSlot, "storeslot", shapeOf(OpStoreSlot),
                 [this, &C](IRBuilder<> &B) {
                   B.CreateStore(popStk(B, C),
                                 B.CreateGEP(C.I64, C.Locals, fetchWord(B, C)));
                   B.CreateBr(C.Dispatch);
                 }});

    // ponytail: VM-local memory ops (L1.5.1 middle way). Frame index is on
    // the stack (pushed by emitValue as a PushConst). OpLoadPtr pops the
    // frame index, fetches VmTy, loads Frame[idx], narrows, pushes.
    // OpStorePtr pops the frame index, pops the value, fetches VmTy,
    // narrows, stores Frame[idx] = value. Order: store emits value-then-
    // pointer in the encoder, so the handler pops pointer first, then value.
    H.push_back({OpLoadPtr, "loadptr", shapeOf(OpLoadPtr),
                 [this, &C](IRBuilder<> &B) {
                   Value *FrameIdx = popStk(B, C);
                   Value *Ty = fetchWord(B, C);
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
                   Value *Narrowed = narrowTo(B, C, V, Ty);
                   B.CreateStore(Narrowed,
                                 B.CreateGEP(C.I64, C.Frame, FrameIdx));
                   B.CreateBr(C.Dispatch);
                 }});

    // ponytail: direct call (L1.5.1). Only registered when a callee table
    // exists (i.e. at least one direct call was encoded). Modules with no
    // direct calls have CalleeTable == null and the OpCall handler would
    // dereference it during IR emission, so we skip registration entirely
    // in that case -- the switch has no OpCall case and any stray OpCall
    // opcode would hit the Bad default (which never fires because no OpCall
    // was emitted). Fetches <calleeIdx> <nargs> <VmTy>, pops nargs values
    // into the CallArgs buffer (popping yields declaration order because the
    // encoder pushed them in reverse), loads the call-thunk pointer from
    // CalleeTable[calleeIdx], calls it uniformly as i64(i64*), narrows the
    // i64 result by VmTy, and pushes it.
    if (C.CalleeTable) {
      H.push_back({OpCall, "call", shapeOf(OpCall),
                   [this, &C](IRBuilder<> &B) {
                     Value *CalleeIdx = fetchWord(B, C);
                     Value *NArgs = fetchWord(B, C);
                     Value *Ty = fetchWord(B, C);
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
                     B.CreateCondBr(B.CreateICmpSLT(Cur, NArgs), LoopBody, LoopDone);
                     B.SetInsertPoint(LoopBody);
                     Value *Arg = popStk(B, C);
                     B.CreateStore(Arg, B.CreateGEP(C.I64, C.CallArgs, Cur));
                     B.CreateStore(B.CreateAdd(Cur, ConstantInt::get(C.I64, 1)),
                                   Counter);
                     B.CreateBr(LoopHdr);
                     B.SetInsertPoint(LoopDone);
                     Value *ThunkPtrInt = B.CreateLoad(
                         C.I64, B.CreateGEP(C.I64, C.CalleeTable, CalleeIdx));
                     Value *ThunkPtr = B.CreateIntToPtr(
                         ThunkPtrInt, PointerType::getUnqual(*C.Ctx));
                     auto *ThunkFnTy = FunctionType::get(
                         C.I64, {PointerType::getUnqual(*C.Ctx)}, false);
                     Value *Result =
                         B.CreateCall(ThunkFnTy, ThunkPtr, {C.CallArgs});
                     pushStk(B, C, narrowTo(B, C, Result, Ty));
                     B.CreateBr(C.Dispatch);
                   }});
    }

    // ponytail: Binary-op emitter. The opcode-specific IR is produced by an
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
                         bool SignedOperands,
                         std::function<Value *(IRBuilder<> &, Value *, Value *)>
                             Fn) {
      H.push_back({Op, Name, shapeOf(Op),
                   [this, &C, Fn, NarrowResult, SignedOperands](IRBuilder<> &B) {
                     Value *R = popStk(B, C);
                     Value *L = popStk(B, C);
                     Value *Result;
                     if (NarrowResult) {
                       Value *Ty = fetchWord(B, C);
                       if (SignedOperands) {
                         L = signExtendFor(B, C, L, Ty);
                         R = signExtendFor(B, C, R, Ty);
                       }
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
              [](IRBuilder<> &B, Value *L, Value *R) {
                return B.CreateAdd(L, R);
              });
    addBinary(OpSub, "sub", /*Narrow=*/true, /*Signed=*/false,
              [](IRBuilder<> &B, Value *L, Value *R) {
                return B.CreateSub(L, R);
              });
    addBinary(OpXor, "xor", /*Narrow=*/true, /*Signed=*/false,
              [](IRBuilder<> &B, Value *L, Value *R) {
                return B.CreateXor(L, R);
              });
    // ponytail: L1.5.1 widened integer binary ops. All carry a VmTy immediate
    // and narrow the result. Signedness is encoded in the opcode choice and
    // the SignedOperands flag: AShr/SDiv/SRem sign-extend operands first;
    // the rest operate on the canonical zext bit pattern.
    addBinary(OpMul, "mul", /*Narrow=*/true, /*Signed=*/false,
              [](IRBuilder<> &B, Value *L, Value *R) {
                return B.CreateMul(L, R);
              });
    addBinary(OpAnd, "and", /*Narrow=*/true, /*Signed=*/false,
              [](IRBuilder<> &B, Value *L, Value *R) {
                return B.CreateAnd(L, R);
              });
    addBinary(OpOr, "or", /*Narrow=*/true, /*Signed=*/false,
              [](IRBuilder<> &B, Value *L, Value *R) {
                return B.CreateOr(L, R);
              });
    addBinary(OpShl, "shl", /*Narrow=*/true, /*Signed=*/false,
              [](IRBuilder<> &B, Value *L, Value *R) {
                return B.CreateShl(L, R);
              });
    addBinary(OpLShr, "lshr", /*Narrow=*/true, /*Signed=*/false,
              [](IRBuilder<> &B, Value *L, Value *R) {
                return B.CreateLShr(L, R);
              });
    addBinary(OpAShr, "ashr", /*Narrow=*/true, /*Signed=*/true,
              [](IRBuilder<> &B, Value *L, Value *R) {
                return B.CreateAShr(L, R);
              });
    addBinary(OpSDiv, "sdiv", /*Narrow=*/true, /*Signed=*/true,
              [](IRBuilder<> &B, Value *L, Value *R) {
                return B.CreateSDiv(L, R);
              });
    addBinary(OpUDiv, "udiv", /*Narrow=*/true, /*Signed=*/false,
              [](IRBuilder<> &B, Value *L, Value *R) {
                return B.CreateUDiv(L, R);
              });
    addBinary(OpSRem, "srem", /*Narrow=*/true, /*Signed=*/true,
              [](IRBuilder<> &B, Value *L, Value *R) {
                return B.CreateSRem(L, R);
              });
    addBinary(OpURem, "urem", /*Narrow=*/true, /*Signed=*/false,
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
    // ponytail: unsigned compares. Operands stay canonical zext; unsigned
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
                   B.CreateStore(fetchWord(B, C), C.PC);
                   B.CreateBr(C.Dispatch);
                 }});
    H.push_back({OpBrTrue, "brtrue", shapeOf(OpBrTrue),
                 [this, &C](IRBuilder<> &B) {
                   Value *Target = fetchWord(B, C);
                   Value *Cond = popStk(B, C);
                   BasicBlock *SetTarget =
                       BasicBlock::Create(*C.Ctx, "brtrue.set", C.F);
                   B.CreateCondBr(
                       B.CreateICmpNE(Cond, ConstantInt::get(C.I64, 0)),
                       SetTarget, C.Dispatch);
                   B.SetInsertPoint(SetTarget);
                   B.CreateStore(Target, C.PC);
                   B.CreateBr(C.Dispatch);
                 }});
    H.push_back({OpRet, "ret", shapeOf(OpRet),
                 [this, &C](IRBuilder<> &B) { B.CreateRet(popStk(B, C)); }});

    return H;
  }

  Function *getOrCreateInterpreter(Module &M) {
    if (auto *F = M.getFunction("__taokari_vmp_interp_i64"))
      return F;

    LLVMContext &Ctx = M.getContext();
    Type *I64 = Type::getInt64Ty(Ctx);
    Type *Ptr = PointerType::getUnqual(Ctx);
    auto *FTy = FunctionType::get(I64, {Ptr, Ptr}, false);
    auto *F = Function::Create(FTy, GlobalValue::InternalLinkage,
                               "__taokari_vmp_interp_i64", M);
    F->addFnAttr(Attribute::NoUnwind);

    auto ArgIt = F->arg_begin();
    Value *BC = &*ArgIt++;
    BC->setName("bc");
    Value *Args = &*ArgIt;
    Args->setName("args");

    BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", F);
    BasicBlock *Dispatch = BasicBlock::Create(Ctx, "dispatch", F);
    BasicBlock *Bad = BasicBlock::Create(Ctx, "bad", F);
    IRBuilder<> B(Entry);
    auto *Stack = B.CreateAlloca(I64, ConstantInt::get(I64, 64), "stack");
    auto *Locals = B.CreateAlloca(I64, ConstantInt::get(I64, 64), "locals");
    // ponytail: VM-local frame (L1.5.1 middle way). AllocaInst reserves runs
    // of consecutive slots here; LoadPtr/StorePtr index into it via the
    // frame-pointer values pushed by emitValue.
    auto *Frame = B.CreateAlloca(I64, ConstantInt::get(I64, 64), "frame");
    // ponytail: OpCall argument marshaling buffer (L1.5.1). Up to 8 integer
    // args per call (isVMCompatibleCall gates on arg_size() <= 8).
    auto *CallArgs = B.CreateAlloca(I64, ConstantInt::get(I64, 8), "callargs");
    auto *PC = B.CreateAlloca(I64, nullptr, "pc");
    auto *SP = B.CreateAlloca(I64, nullptr, "sp");
    B.CreateStore(ConstantInt::get(I64, 0), PC);
    B.CreateStore(ConstantInt::get(I64, 0), SP);
    B.CreateBr(Dispatch);

    B.SetInsertPoint(Dispatch);
    Value *OpPC = B.CreateLoad(I64, PC);
    Value *Op = B.CreateLoad(I64, B.CreateGEP(I64, BC, OpPC));
    B.CreateStore(B.CreateAdd(OpPC, ConstantInt::get(I64, 1)), PC);

    // ponytail: Build handler table, then emit one switch case per entry.
    // The table is the source of truth; the switch is generated from it.
    InterpCtx IC{I64, F,     &Ctx, BC,     PC,     SP,
                Stack, Locals, Frame, CallArgs, CalleeTable, Args, Dispatch};
    SmallVector<Handler, 24> Handlers = buildHandlerTable(IC);
    auto *Sw = B.CreateSwitch(Op, Bad, Handlers.size());

    for (Handler &H : Handlers) {
      BasicBlock *CaseBB = BasicBlock::Create(Ctx, H.Name, F);
      Sw->addCase(cast<ConstantInt>(ConstantInt::get(I64, H.Op)), CaseBB);
      B.SetInsertPoint(CaseBB);
      H.Emit(B);
    }

    B.SetInsertPoint(Bad);
    B.CreateRet(ConstantInt::get(I64, 0));
    return F;
  }

  bool replaceWithVM(Function &F, BytecodeProgram &P) {
    Module &M = *F.getParent();
    LLVMContext &Ctx = M.getContext();
    Type *I64 = Type::getInt64Ty(Ctx);

    SmallVector<Constant *, 64> Words;
    for (int64_t Word : P.Words)
      Words.push_back(ConstantInt::get(I64, static_cast<uint64_t>(Word), true));
    auto *ArrayTy = ArrayType::get(I64, Words.size());
    auto *Bytecode = new GlobalVariable(
        M, ArrayTy, true, GlobalValue::PrivateLinkage,
        ConstantArray::get(ArrayTy, Words),
        "__taokari_vmp_bc_" + F.getName());
    Bytecode->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    Bytecode->setAlignment(Align(8));

    Function *Interp = getOrCreateInterpreter(M);
    F.deleteBody();
    BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", &F);
    IRBuilder<> B(Entry);
    Value *Zero = ConstantInt::get(I64, 0);
    Value *BCPtr = B.CreateGEP(ArrayTy, Bytecode, {Zero, Zero});

    auto *ArgsArrayTy = ArrayType::get(I64, std::max<unsigned>(1, F.arg_size()));
    auto *Args = B.CreateAlloca(ArgsArrayTy, nullptr, "vmp.args");
    unsigned I = 0;
    for (Argument &A : F.args()) {
      Value *ArgPtr = B.CreateGEP(ArgsArrayTy, Args,
                                  {Zero, ConstantInt::get(I64, I++)});
      B.CreateStore(B.CreateSExtOrTrunc(&A, I64), ArgPtr);
    }
    Value *ArgsPtr = B.CreateGEP(ArgsArrayTy, Args, {Zero, Zero});
    Value *Result = B.CreateCall(Interp, {BCPtr, ArgsPtr});
    B.CreateRet(B.CreateTruncOrBitCast(Result, F.getReturnType()));
    return true;
  }

  // ponytail: Materialize the per-module direct-callee table as a global
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
      return;
    }
    // Replace each direct callee with its call-thunk in the table.
    LLVMContext &Ctx = M.getContext();
    Type *I64 = Type::getInt64Ty(Ctx);
    SmallVector<Constant *, 8> Entries;
    for (Function *Callee : CalleeOrder) {
      Function *Thunk = getOrCreateCallThunk(M, Callee);
      Entries.push_back(ConstantExpr::getPtrToInt(Thunk, I64));
    }
    auto *ArrayTy = ArrayType::get(I64, Entries.size());
    CalleeTable = new GlobalVariable(
        M, ArrayTy, true, GlobalValue::PrivateLinkage,
        ConstantArray::get(ArrayTy, Entries), "__taokari_vmp_callees");
    CalleeTable->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    CalleeTable->setAlignment(Align(8));
  }

  bool runOnModule(Module &M) override {
    // ponytail: reset per-module state -- ModulePass instances can be reused
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

    // Phase 1: encode every target. This populates CalleeOrder with the
    // direct callees referenced across all virtualized functions.
    SmallVector<std::pair<Function *, BytecodeProgram>, 8> Encoded;
    for (Function *F : Targets) {
      if (hasUnsupportedIR(*F))
        continue;
      BytecodeProgram P;
      if (!buildBytecode(*F, P))
        continue;
      Encoded.emplace_back(F, std::move(P));
    }

    // Phase 2: finalize the callee table now that all callees are known.
    finalizeCalleeTable(M);

    // Phase 3: build the interpreter (uses CalleeTable) and replace bodies.
    bool Changed = false;
    for (auto &[F, P] : Encoded)
      Changed |= replaceWithVM(*F, P);
    return Changed;
  }
};
} // namespace

char CodeVirtualization::ID = 0;

ModulePass *llvm::createCodeVirtualizationPass(ObfuscationOptions *ArgsOptions) {
  return new CodeVirtualization(ArgsOptions);
}
