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
        // ponytail: Level 1 VM is toy integer IR only. Add pointer/call/EH
        // support after this compile/run path proves useful.
        if (isa<PHINode>(I) || isa<CallBase>(I) || isa<InvokeInst>(I) ||
            isa<ResumeInst>(I) || isa<LandingPadInst>(I) ||
            isa<AllocaInst>(I) || isa<LoadInst>(I) || isa<StoreInst>(I) ||
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

  bool emitValue(BytecodeProgram &P, DenseMap<const Value *, unsigned> &Slots,
                 Value *V) {
    if (auto *CI = dyn_cast<ConstantInt>(V)) {
      if (CI->getBitWidth() > 64)
        return false;
      P.Words.push_back(OpPushConst);
      P.Words.push_back(CI->getSExtValue());
      return true;
    }
    auto It = Slots.find(V);
    if (It == Slots.end())
      return false;
    P.Words.push_back(OpLoadSlot);
    P.Words.push_back(It->second);
    return true;
  }

  bool buildBytecode(Function &F, BytecodeProgram &P) {
    DenseMap<const Value *, unsigned> Slots;
    DenseMap<const BasicBlock *, size_t> BlockStart;

    unsigned ArgIndex = 0;
    for (Argument &A : F.args()) {
      unsigned Slot = slotFor(Slots, &A);
      P.Words.append({OpInitArg, static_cast<int64_t>(Slot),
                      static_cast<int64_t>(ArgIndex++)});
    }

    for (BasicBlock &BB : F) {
      BlockStart[&BB] = P.Words.size();
      for (Instruction &I : BB) {
        if (isSkippable(I))
          continue;
        if (auto *BO = dyn_cast<BinaryOperator>(&I)) {
          if (!emitValue(P, Slots, BO->getOperand(0)) ||
              !emitValue(P, Slots, BO->getOperand(1)))
            return false;
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
          default:
            return false;
          }
          P.Words.push_back(OpStoreSlot);
          P.Words.push_back(slotFor(Slots, &I));
          continue;
        }
        if (auto *Cmp = dyn_cast<ICmpInst>(&I)) {
          if (!emitValue(P, Slots, Cmp->getOperand(0)) ||
              !emitValue(P, Slots, Cmp->getOperand(1)))
            return false;
          switch (Cmp->getPredicate()) {
          case CmpInst::ICMP_EQ:
            P.Words.push_back(OpCmpEq);
            break;
          case CmpInst::ICMP_NE:
            P.Words.push_back(OpCmpNe);
            break;
          case CmpInst::ICMP_SGT:
            P.Words.push_back(OpCmpSgt);
            break;
          case CmpInst::ICMP_SLT:
            P.Words.push_back(OpCmpSlt);
            break;
          case CmpInst::ICMP_SGE:
            P.Words.push_back(OpCmpSge);
            break;
          case CmpInst::ICMP_SLE:
            P.Words.push_back(OpCmpSle);
            break;
          default:
            return false;
          }
          P.Words.push_back(OpStoreSlot);
          P.Words.push_back(slotFor(Slots, &I));
          continue;
        }
        if (auto *Sel = dyn_cast<SelectInst>(&I)) {
          if (!emitValue(P, Slots, Sel->getCondition()) ||
              !emitValue(P, Slots, Sel->getTrueValue()) ||
              !emitValue(P, Slots, Sel->getFalseValue()))
            return false;
          P.Words.push_back(OpSelect);
          P.Words.push_back(OpStoreSlot);
          P.Words.push_back(slotFor(Slots, &I));
          continue;
        }
        if (auto *Br = dyn_cast<BranchInst>(&I)) {
          if (Br->isUnconditional()) {
            P.Words.push_back(OpJmp);
            P.Fixups.push_back({P.Words.size(), Br->getSuccessor(0)});
            P.Words.push_back(0);
            continue;
          }
          if (!emitValue(P, Slots, Br->getCondition()))
            return false;
          P.Words.push_back(OpBrTrue);
          P.Fixups.push_back({P.Words.size(), Br->getSuccessor(0)});
          P.Words.push_back(0);
          P.Words.push_back(OpJmp);
          P.Fixups.push_back({P.Words.size(), Br->getSuccessor(1)});
          P.Words.push_back(0);
          continue;
        }
        if (auto *Ret = dyn_cast<ReturnInst>(&I)) {
          if (!Ret->getReturnValue())
            return false;
          if (!emitValue(P, Slots, Ret->getReturnValue()))
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
      return {0, 1, 1};
    case OpLoadSlot:
      return {0, 1, 1};
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
      return {2, 1, 0};
    case OpSelect:
      return {3, 1, 0};
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
                   pushStk(B, C, fetchWord(B, C));
                   B.CreateBr(C.Dispatch);
                 }});
    H.push_back({OpLoadSlot, "loadslot", shapeOf(OpLoadSlot),
                 [this, &C](IRBuilder<> &B) {
                   pushStk(B, C, B.CreateLoad(C.I64, B.CreateGEP(
                                                      C.I64, C.Locals,
                                                      fetchWord(B, C))));
                   B.CreateBr(C.Dispatch);
                 }});
    H.push_back({OpStoreSlot, "storeslot", shapeOf(OpStoreSlot),
                 [this, &C](IRBuilder<> &B) {
                   B.CreateStore(popStk(B, C),
                                 B.CreateGEP(C.I64, C.Locals, fetchWord(B, C)));
                   B.CreateBr(C.Dispatch);
                 }});

    // ponytail: Binary-op emitter. The opcode-specific IR is produced by an
    // owned std::function (Fn) captured by value into the Emit closure. Fn
    // itself is a by-value parameter of addBinary, so the closure must own a
    // copy; capturing `Fn` by value (init-capture-free, named explicitly)
    // would be ill-formed under /permissive- with a default capture, so we
    // use an explicit capture list with no default and name Fn there.
    auto addBinary = [&](Opcode Op, StringRef Name,
                         std::function<Value *(IRBuilder<> &, Value *, Value *)>
                             Fn) {
      H.push_back({Op, Name, shapeOf(Op), [this, &C, Fn](IRBuilder<> &B) {
                     Value *R = popStk(B, C);
                     Value *L = popStk(B, C);
                     pushStk(B, C, Fn(B, L, R));
                     B.CreateBr(C.Dispatch);
                   }});
    };
    addBinary(OpAdd, "add",
              [](IRBuilder<> &B, Value *L, Value *R) {
                return B.CreateAdd(L, R);
              });
    addBinary(OpSub, "sub",
              [](IRBuilder<> &B, Value *L, Value *R) {
                return B.CreateSub(L, R);
              });
    addBinary(OpXor, "xor",
              [](IRBuilder<> &B, Value *L, Value *R) {
                return B.CreateXor(L, R);
              });

    auto addCmp = [&](Opcode Op, StringRef Name, CmpInst::Predicate Pred) {
      // Pred (by-value param) and C.I64 are captured by value into the
      // owned std::function so they survive after addCmp returns.
      addBinary(Op, Name,
                [Pred, I64 = C.I64](IRBuilder<> &B, Value *L, Value *R) {
                  return B.CreateZExt(B.CreateICmp(Pred, L, R), I64);
                });
    };
    addCmp(OpCmpEq, "cmpeq", CmpInst::ICMP_EQ);
    addCmp(OpCmpNe, "cmpne", CmpInst::ICMP_NE);
    addCmp(OpCmpSgt, "cmpsgt", CmpInst::ICMP_SGT);
    addCmp(OpCmpSlt, "cmpslt", CmpInst::ICMP_SLT);
    addCmp(OpCmpSge, "cmpsge", CmpInst::ICMP_SGE);
    addCmp(OpCmpSle, "cmpsle", CmpInst::ICMP_SLE);

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
                Stack, Locals, Args, Dispatch};
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

  bool runOnModule(Module &M) override {
    SmallVector<Function *, 8> Targets;
    for (Function &F : M) {
      if (shouldSkip(F))
        continue;
      auto Opt = ArgsOptions->toObfuscate(ArgsOptions->vmpOpt(), &F);
      if (!Opt.isEnabled())
        continue;
      Targets.push_back(&F);
    }

    bool Changed = false;
    for (Function *F : Targets) {
      if (hasUnsupportedIR(*F))
        continue;
      BytecodeProgram P;
      if (!buildBytecode(*F, P))
        continue;
      Changed |= replaceWithVM(*F, P);
    }
    return Changed;
  }
};
} // namespace

char CodeVirtualization::ID = 0;

ModulePass *llvm::createCodeVirtualizationPass(ObfuscationOptions *ArgsOptions) {
  return new CodeVirtualization(ArgsOptions);
}
