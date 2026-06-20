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

#define DEBUG_TYPE "taokari-vmp"

using namespace llvm;

namespace {
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

struct Fixup {
  size_t Index;
  const BasicBlock *Target;
};

struct BytecodeProgram {
  SmallVector<int64_t, 64> Words;
  SmallVector<Fixup, 8> Fixups;
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
    auto *Sw = B.CreateSwitch(Op, Bad, 17);

    auto makeCase = [&](Opcode OpCode, StringRef Name) {
      BasicBlock *BB = BasicBlock::Create(Ctx, Name, F);
      Sw->addCase(cast<ConstantInt>(ConstantInt::get(I64, OpCode)), BB);
      B.SetInsertPoint(BB);
      return BB;
    };
    auto fetch = [&]() {
      Value *Cur = B.CreateLoad(I64, PC);
      Value *Word = B.CreateLoad(I64, B.CreateGEP(I64, BC, Cur));
      B.CreateStore(B.CreateAdd(Cur, ConstantInt::get(I64, 1)), PC);
      return Word;
    };

    makeCase(OpInitArg, "initarg");
    Value *Slot = fetch();
    Value *ArgNo = fetch();
    Value *ArgVal = B.CreateLoad(I64, B.CreateGEP(I64, Args, ArgNo));
    B.CreateStore(ArgVal, B.CreateGEP(I64, Locals, Slot));
    B.CreateBr(Dispatch);

    makeCase(OpPushConst, "pushconst");
    push(B, I64, Stack, SP, fetch());
    B.CreateBr(Dispatch);

    makeCase(OpLoadSlot, "loadslot");
    push(B, I64, Stack, SP, B.CreateLoad(I64, B.CreateGEP(I64, Locals, fetch())));
    B.CreateBr(Dispatch);

    makeCase(OpStoreSlot, "storeslot");
    B.CreateStore(pop(B, I64, Stack, SP), B.CreateGEP(I64, Locals, fetch()));
    B.CreateBr(Dispatch);

    auto makeBinary = [&](Opcode OpCode, StringRef Name,
                          function_ref<Value *(Value *, Value *)> Fn) {
      makeCase(OpCode, Name);
      Value *R = pop(B, I64, Stack, SP);
      Value *L = pop(B, I64, Stack, SP);
      push(B, I64, Stack, SP, Fn(L, R));
      B.CreateBr(Dispatch);
    };
    makeBinary(OpAdd, "add", [&](Value *L, Value *R) {
      return B.CreateAdd(L, R);
    });
    makeBinary(OpSub, "sub", [&](Value *L, Value *R) {
      return B.CreateSub(L, R);
    });
    makeBinary(OpXor, "xor", [&](Value *L, Value *R) {
      return B.CreateXor(L, R);
    });

    auto makeCmp = [&](Opcode OpCode, StringRef Name, CmpInst::Predicate Pred) {
      makeBinary(OpCode, Name, [&](Value *L, Value *R) {
        return B.CreateZExt(B.CreateICmp(Pred, L, R), I64);
      });
    };
    makeCmp(OpCmpEq, "cmpeq", CmpInst::ICMP_EQ);
    makeCmp(OpCmpNe, "cmpne", CmpInst::ICMP_NE);
    makeCmp(OpCmpSgt, "cmpsgt", CmpInst::ICMP_SGT);
    makeCmp(OpCmpSlt, "cmpslt", CmpInst::ICMP_SLT);
    makeCmp(OpCmpSge, "cmpsge", CmpInst::ICMP_SGE);
    makeCmp(OpCmpSle, "cmpsle", CmpInst::ICMP_SLE);

    makeCase(OpSelect, "select");
    Value *FalseV = pop(B, I64, Stack, SP);
    Value *TrueV = pop(B, I64, Stack, SP);
    Value *CondV = pop(B, I64, Stack, SP);
    push(B, I64, Stack, SP,
         B.CreateSelect(B.CreateICmpNE(CondV, ConstantInt::get(I64, 0)), TrueV,
                        FalseV));
    B.CreateBr(Dispatch);

    makeCase(OpJmp, "jmp");
    B.CreateStore(fetch(), PC);
    B.CreateBr(Dispatch);

    makeCase(OpBrTrue, "brtrue");
    Value *Target = fetch();
    Value *Cond = pop(B, I64, Stack, SP);
    B.CreateCondBr(B.CreateICmpNE(Cond, ConstantInt::get(I64, 0)),
                   BasicBlock::Create(Ctx, "brtrue.set", F), Dispatch);
    BasicBlock *SetTarget = &F->back();
    B.SetInsertPoint(SetTarget);
    B.CreateStore(Target, PC);
    B.CreateBr(Dispatch);

    makeCase(OpRet, "ret");
    B.CreateRet(pop(B, I64, Stack, SP));

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
