#include "llvm/Transforms/Obfuscation/BogusControlFlow.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/RandomNumberGenerator.h"
#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscation/OpaquePredicate.h"
#include "llvm/Transforms/Obfuscation/Utils.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/ValueMapper.h"

#include <algorithm>
#include <random>

#define DEBUG_TYPE "bcf"

using namespace llvm;

static cl::opt<uint32_t>
    BCFProbability("taokari-bcf-prob", cl::init(35), cl::NotHidden,
                   cl::desc("BCF block selection probability, 0..100."));
static cl::opt<uint32_t>
    BCFLoopCount("taokari-bcf-loops", cl::init(0), cl::NotHidden,
                 cl::desc("BCF fake-block junk loop count."));
static cl::opt<uint32_t>
    BCFMaxInsts("taokari-bcf-max-insts", cl::init(5000), cl::NotHidden,
                cl::desc("Skip functions larger than this many instructions. Matches "
                         "the flattening guard so BCF cannot blow up on functions "
                         "FLA already expanded into a giant dispatcher."));
static cl::opt<uint32_t>
    BCFMaxBlocks("taokari-bcf-max-blocks", cl::init(200), cl::NotHidden,
                 cl::desc("Skip functions with more than this many basic blocks."));

namespace {
struct BogusControlFlow : public FunctionPass {
  static char ID;
  ObfuscationOptions *ArgsOptions;
  std::mt19937_64 RNG;

  BogusControlFlow(ObfuscationOptions *ArgsOptions) : FunctionPass(ID) {
    this->ArgsOptions = ArgsOptions;
    uint64_t Seed = 0;
    if (auto EC = llvm::getRandomBytes(&Seed, sizeof(Seed)))
      report_fatal_error(StringRef("Failed to seed BCF RNG: ") + EC.message());
    RNG = std::mt19937_64(Seed);
  }

  StringRef getPassName() const override { return "BogusControlFlow"; }

  bool runOnFunction(Function &F) override {
    if (F.isDeclaration() || F.isIntrinsic() || F.hasPersonalityFn() ||
        F.getName().starts_with("__taokari_bcf_") ||
        functionIsStdOrEhRuntime(F) || functionParticipatesInNonLocalJump(F))
      return false;

    auto Opt = ArgsOptions->toObfuscate(ArgsOptions->bcfOpt(), &F);
    if (!Opt.isEnabled())
      return false;

    const uint32_t Probability =
        BCFProbability.getNumOccurrences()
            ? BCFProbability
            : (Opt.probability() <= 100 ? Opt.probability() : 35);
    const uint32_t Loops =
        BCFLoopCount.getNumOccurrences()
            ? BCFLoopCount
            : (Opt.loopCount() ? Opt.loopCount()
                               : std::max(1u, Opt.level() + 1));
    if (!Probability)
      return false;

    if (F.getInstructionCount() > BCFMaxInsts || F.size() > BCFMaxBlocks)
      return false;

    SmallVector<BasicBlock *, 32> Blocks;
    for (BasicBlock &BB : F) {
      if (eligible(BB))
        Blocks.push_back(&BB);
    }

    std::mt19937_64 FuncRNG(RNG());
    AllocaInst *JunkSlot = nullptr;
    bool Changed = false;
    for (BasicBlock *BB : Blocks) {
      if ((FuncRNG() % 100) >= Probability)
        continue;
      if (!JunkSlot)
        JunkSlot = createEntrySlot(F, Type::getInt64Ty(F.getContext()));
      Changed |= obfuscateBlock(F, *BB, Opt.level(), Loops, FuncRNG,
                                *JunkSlot);
    }
    return Changed;
  }

  static bool eligible(BasicBlock &BB) {
    if (isGeneratedBCFBlock(BB) || &BB == &BB.getParent()->getEntryBlock() ||
        BB.empty() || BB.isEHPad() || isa<PHINode>(BB.begin()))
      return false;
    auto *Pred = BB.getSinglePredecessor();
    if (!Pred || !Pred->getTerminator() || Pred->getTerminator()->isEHPad())
      return false;
    return isa<BranchInst>(Pred->getTerminator()) ||
           isa<SwitchInst>(Pred->getTerminator());
  }

  static bool isGeneratedBCFBlock(BasicBlock &BB) {
    StringRef Name = BB.getName();
    return Name.contains(".bcf.guard") || Name.contains(".bcf.fake")
        || Name.contains(".bcf.exh");
  }

  bool obfuscateBlock(Function &F, BasicBlock &BB, uint32_t Level,
                      uint32_t Loops, std::mt19937_64 &FuncRNG,
                      AllocaInst &JunkSlot) {
    auto *Pred = BB.getSinglePredecessor();
    if (!Pred)
      return false;

    LLVMContext &Ctx = F.getContext();
    auto &M = *F.getParent();
    auto *Int64 = Type::getInt64Ty(Ctx);
    auto *Nonce = getOrCreateNonce(M, Int64);

    ValueToValueMapTy VMap;
    BasicBlock *Fake = CloneBasicBlock(&BB, VMap, ".bcf.fake", &F);
    for (Instruction &I : *Fake)
      RemapInstruction(&I, VMap,
                       RF_NoModuleLevelChanges | RF_IgnoreMissingLocals);
    sanitizeFake(*Fake);
    if (Level >= 2)
      mutateFake(*Fake, Level, FuncRNG);

    unsigned Layers = Level >= 4 ? 3 : (Level >= 3 ? 2 : 1);
    BasicBlock *CurrentTarget = &BB;
    for (unsigned Layer = Layers; Layer >= 1; --Layer) {
      BasicBlock *Guard = BasicBlock::Create(
          Ctx, BB.getName() + ".bcf.guard" + Twine(Layer), &F, CurrentTarget);

      IRBuilder<> GuardIR(Guard);
      Value *Opaque = nullptr;
      if (Level >= 2) {
        taokari::OpaqueSeedKind SeedKind = taokari::OpaqueSeedKind::Global;
        switch (FuncRNG() % 5) {
        case 0:
          SeedKind = taokari::OpaqueSeedKind::Pointer;
          break;
        case 1:
          SeedKind = taokari::OpaqueSeedKind::StackAddress;
          break;
        case 2:
          SeedKind = taokari::OpaqueSeedKind::Environment;
          break;
        case 3:
          SeedKind = taokari::OpaqueSeedKind::RuntimeNonce;
          break;
        default:
          break;
        }
        Value *Seed = taokari::makeContextSeed(
            F, GuardIR, Int64, FuncRNG, SeedKind, "bcf.seed");
        Opaque = taokari::makeUnfoldableTruePredicate(GuardIR, Seed, FuncRNG,
                                                      "bcf.opaque");
      } else {
        auto *Load = GuardIR.CreateAlignedLoad(Int64, Nonce, Align(8), true,
                                               "bcf.nonce");
        Value *A = GuardIR.CreateMul(
            Load, GuardIR.CreateAdd(Load, ConstantInt::get(Int64, 1)),
            "bcf.opaque.mul");
        Opaque = GuardIR.CreateICmpEQ(
            GuardIR.CreateAnd(A, ConstantInt::get(Int64, 1), "bcf.opaque.bit"),
            ConstantInt::get(Int64, 0), "bcf.opaque");
      }

      BasicBlock *InnerFake = Fake;
      if (Layer == 1) {
        addJunk(*Fake, CurrentTarget, *Nonce, JunkSlot, Loops, Level, FuncRNG);
      } else {
        InnerFake = BasicBlock::Create(
            Ctx, BB.getName() + ".bcf.fake.layer" + Twine(Layer), &F,
            CurrentTarget);
        addJunk(*InnerFake, CurrentTarget, *Nonce, JunkSlot, Loops, Level,
                FuncRNG);
      }

      if (Layer == 1 && Level >= 3 && (FuncRNG() % 2)) {
        auto *I64 = Type::getInt64Ty(Ctx);
        auto *I32 = Type::getInt32Ty(Ctx);
        Value *Seed = GuardIR.CreateAlignedLoad(I64, Nonce, Align(8), true,
                                                "bcf.sw.seed");
        Value *Idx = GuardIR.CreateAnd(Seed, ConstantInt::get(I64, 3),
                                       "bcf.sw.idx");
        Value *Bias = GuardIR.CreateSub(ConstantInt::get(I64, 1), Idx,
                                        "bcf.sw.bias");
        Value *Real = GuardIR.CreateAdd(Idx, Bias, "bcf.sw.real");
        Value *Sel = GuardIR.CreateTrunc(Real, I32, "bcf.sel");
        auto *Sw = GuardIR.CreateSwitch(Sel, InnerFake, 1);
        Sw->addCase(ConstantInt::get(I32, 1), CurrentTarget);
        Function *ErrStub = getOrCreateErrorStub(M);
        Function *CleanupStub = getOrCreateCleanupStub(M);
        unsigned Extra = 1 + (FuncRNG() % 3);
        for (unsigned I = 0; I < Extra; ++I) {
          BasicBlock *Path = BasicBlock::Create(
              Ctx, BB.getName() + ".bcf.fakepath", &F, CurrentTarget);
          IRBuilder<> E(Path);
          Function *Stub = (FuncRNG() & 1) ? ErrStub : CleanupStub;
          E.CreateCall(FunctionType::get(Type::getVoidTy(Ctx), false), Stub);
          E.CreateBr(CurrentTarget);
          Sw->addCase(ConstantInt::get(I32, static_cast<uint32_t>(2 + I)), Path);
        }
      } else {
        GuardIR.CreateCondBr(Opaque, CurrentTarget, InnerFake);
      }
      CurrentTarget = Guard;
    }

    if (Level >= 3 && !F.hasPersonalityFn() && (FuncRNG() % 2)) {
      emitFakeExceptionRegion(F, CurrentTarget, BB, *Nonce, FuncRNG);
    }

    Pred->getTerminator()->replaceSuccessorWith(&BB, CurrentTarget);
    return true;
  }

  static GlobalVariable *getOrCreateNonce(Module &M, IntegerType *IntTy) {
    if (auto *GV = M.getGlobalVariable("__taokari_bcf_nonce", true))
      return GV;
    auto *Init = ConstantInt::get(IntTy, 0x9e3779b97f4a7c15ull);
    auto *GV = new GlobalVariable(M, IntTy, false, GlobalValue::PrivateLinkage,
                                  Init, "__taokari_bcf_nonce");
    GV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    return GV;
  }

  static Function *getOrCreateErrorStub(Module &M) {
    if (auto *Existing = M.getFunction("__taokari_bcf_err"))
      return Existing;
    auto &Ctx = M.getContext();
    auto *I8 = Type::getInt8Ty(Ctx);
    auto *FTy = FunctionType::get(Type::getVoidTy(Ctx), false);
    auto *Stub = Function::Create(FTy, GlobalValue::InternalLinkage,
                                  "__taokari_bcf_err", M);
    Stub->addFnAttr(Attribute::NoInline);
    auto *Flag = new GlobalVariable(M, I8, false, GlobalValue::PrivateLinkage,
                                    ConstantInt::get(I8, 0),
                                    "__taokari_bcf_errflag");
    Flag->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    Flag->setAlignment(Align(1));
    BasicBlock *BB = BasicBlock::Create(Ctx, "entry", Stub);
    IRBuilder<> B(BB);
    B.CreateStore(ConstantInt::get(I8, 1), Flag);
    B.CreateRetVoid();
    appendToCompilerUsed(M, {Stub, Flag});
    return Stub;
  }

  static Function *getOrCreateCleanupStub(Module &M) {
    if (auto *Existing = M.getFunction("__taokari_bcf_cleanup"))
      return Existing;
    auto &Ctx = M.getContext();
    auto *I8 = Type::getInt8Ty(Ctx);
    auto *FTy = FunctionType::get(Type::getVoidTy(Ctx), false);
    auto *Stub = Function::Create(FTy, GlobalValue::InternalLinkage,
                                  "__taokari_bcf_cleanup", M);
    Stub->addFnAttr(Attribute::NoInline);
    auto *Slot = new GlobalVariable(M, I8, false, GlobalValue::PrivateLinkage,
                                    ConstantInt::get(I8, 0x5a),
                                    "__taokari_bcf_resource");
    Slot->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    Slot->setAlignment(Align(1));
    BasicBlock *BB = BasicBlock::Create(Ctx, "entry", Stub);
    IRBuilder<> B(BB);
    B.CreateStore(ConstantInt::get(I8, 0), Slot);
    B.CreateRetVoid();
    appendToCompilerUsed(M, {Stub, Slot});
    return Stub;
  }

  static AllocaInst *createEntrySlot(Function &F, Type *Ty) {
    IRBuilder<> IRB(&*F.getEntryBlock().getFirstInsertionPt());
    auto *Slot = IRB.CreateAlloca(Ty, nullptr, "bcf.dead.slot");
    // Name-independent marker: -O2 discards instruction names, and
    // Flattening's alloca gate must exempt these slots in every build.
    Slot->setMetadata("taokari.bcf.slot", MDNode::get(F.getContext(), {}));
    return Slot;
  }

  void emitFakeExceptionRegion(Function &F, BasicBlock *&Entry,
                               BasicBlock &Real, GlobalVariable &Nonce,
                               std::mt19937_64 &FuncRNG) {
    LLVMContext &Ctx = F.getContext();
    auto *Int64 = Type::getInt64Ty(Ctx);
    Module &M = *F.getParent();

    BasicBlock *Exh = BasicBlock::Create(
        Ctx, F.getName() + ".bcf.exh", &F, &Real);
    IRBuilder<> EIRB(Exh);
    auto *RecSlot = new GlobalVariable(
        M, Int64, false, GlobalValue::PrivateLinkage,
        ConstantInt::get(Int64, FuncRNG()),
        Twine(F.getName()) + ".bcf.exh.rec");
    RecSlot->setAlignment(Align(8));
    Value *Rec = EIRB.CreateAlignedLoad(Int64, RecSlot, Align(8), true,
                                        "bcf.exh.rec.ld");
    Value *Code = EIRB.CreateAnd(Rec, ConstantInt::get(Int64, 0xFFFF),
                                 "bcf.exh.code");
    Value *Addr = EIRB.CreateAlignedLoad(Int64, &Nonce, Align(8), true,
                                         "bcf.exh.frame");
    Value *Mix = EIRB.CreateXor(Addr, Code, "bcf.exh.mix");
    EIRB.CreateStore(Mix, RecSlot);
    Function *Cleanup = getOrCreateCleanupStub(M);
    EIRB.CreateCall(FunctionType::get(Type::getVoidTy(Ctx), false), Cleanup);
    EIRB.CreateBr(&Real);

    BasicBlock *Gate = BasicBlock::Create(
        Ctx, F.getName() + ".bcf.exh.gate", &F, Exh);
    IRBuilder<> GIRB(Gate);
    taokari::OpaqueSeedKind SeedKind = taokari::OpaqueSeedKind::Global;
    switch (FuncRNG() % 4) {
    case 0: SeedKind = taokari::OpaqueSeedKind::StackAddress; break;
    case 1: SeedKind = taokari::OpaqueSeedKind::Pointer; break;
    case 2: SeedKind = taokari::OpaqueSeedKind::Environment; break;
    default: break;
    }
    Value *Seed = taokari::makeContextSeed(F, GIRB, Int64, FuncRNG, SeedKind,
                                           "bcf.exh.seed");
    Value *False = taokari::makeUnfoldableFalsePredicate(GIRB, Seed, FuncRNG,
                                                         "bcf.exh.opaque");
    GIRB.CreateCondBr(False, Exh, Entry);
    Entry = Gate;
  }

  static void sanitizeFake(BasicBlock &Fake) {
    SmallVector<Instruction *, 16> ToErase;
    for (Instruction &I : Fake) {
      if (I.isTerminator() || I.isEHPad() || I.mayReadOrWriteMemory() ||
          I.mayHaveSideEffects())
        ToErase.push_back(&I);
    }
    for (Instruction *I : ToErase) {
      if (!I->getType()->isVoidTy())
        I->replaceAllUsesWith(PoisonValue::get(I->getType()));
      I->eraseFromParent();
    }
  }

  void mutateFake(BasicBlock &Fake, uint32_t Level, std::mt19937_64 &FuncRNG) {
    SmallVector<BinaryOperator *, 8> Ops;
    for (Instruction &I : Fake) {
      if (auto *BO = dyn_cast<BinaryOperator>(&I))
        if (BO->getType()->isIntegerTy())
          Ops.push_back(BO);
    }
    for (BinaryOperator *BO : Ops) {
      IRBuilder<> IRB(BO);
      Value *L = BO->getOperand(0);
      Value *R = BO->getOperand(1);
      Value *N = (FuncRNG() % 3 == 0)
                     ? IRB.CreateXor(L, R, BO->getName() + ".mx")
                 : (Level > 2 && FuncRNG() % 2)
                     ? IRB.CreateMul(L, R, BO->getName() + ".mm")
                     : IRB.CreateAdd(L, R, BO->getName() + ".ma");
      BO->replaceAllUsesWith(N);
      BO->eraseFromParent();
    }
  }

  void addJunk(BasicBlock &Fake, BasicBlock *BranchTarget,
               GlobalVariable &Nonce, AllocaInst &JunkSlot, uint32_t Loops,
               uint32_t Level, std::mt19937_64 &FuncRNG) {
    auto *Int64 = Type::getInt64Ty(Fake.getContext());

    bool InEHFunction = Fake.getParent()->hasPersonalityFn();
    if (Level >= 3 && Loops > 1 && !InEHFunction) {
      addJunkLoop(Fake, BranchTarget, Nonce, JunkSlot, Loops, FuncRNG);
      return;
    }

    IRBuilder<> IRB(&Fake);
    Value *V =
        IRB.CreateAlignedLoad(Int64, &Nonce, Align(8), true, "bcf.fake.nonce");
    if (Level >= 2) {
      Module &Mod = *Fake.getModule();
      auto *FakeMemInit = ConstantInt::get(Int64, FuncRNG());
      auto *FakeMem = new GlobalVariable(
          Mod, Int64, false, GlobalValue::PrivateLinkage, FakeMemInit,
          Twine(Fake.getParent()->getName()) + ".bcf.fake.mem");
      FakeMem->setAlignment(Align(8));
      Value *FakeLd = IRB.CreateAlignedLoad(Int64, FakeMem, Align(8), true,
                                            "bcf.fake.mem.ld");
      V = IRB.CreateXor(V, FakeLd, "bcf.fake.mem.mix");
    }
    for (uint32_t I = 0; I < Loops; ++I) {
      V = IRB.CreateXor(V, ConstantInt::get(Int64, FuncRNG()), "bcf.fake.xor");
      V = IRB.CreateMul(V, ConstantInt::get(Int64, (FuncRNG() | 1)),
                        "bcf.fake.mul");
      V = IRB.CreateAdd(V, ConstantInt::get(Int64, FuncRNG()), "bcf.fake.add");
    }
    if (Level >= 2) {
      auto *JunkFn = getOrCreateJunkFunction(*Fake.getModule(), FuncRNG);
      V = IRB.CreateCall(JunkFn, {V}, "bcf.fake.call");
    }
    IRB.CreateAlignedStore(V, &JunkSlot, Align(8), true);
    IRB.CreateBr(BranchTarget);
  }

  void addJunkLoop(BasicBlock &Fake, BasicBlock *BranchTarget,
                   GlobalVariable &Nonce, AllocaInst &JunkSlot, uint32_t Loops,
                   std::mt19937_64 &FuncRNG) {
    auto *Int64 = Type::getInt64Ty(Fake.getContext());
    auto *Int32 = Type::getInt32Ty(Fake.getContext());
    Module &M = *Fake.getModule();
    auto *BoundGV = new GlobalVariable(
        M, Int32, false, GlobalValue::PrivateLinkage,
        ConstantInt::get(Int32, static_cast<uint32_t>(Loops)),
        Twine(Fake.getParent()->getName()) + ".bcf.fake.bound");
    BoundGV->setAlignment(Align(4));

    // The loop slots must live in the entry block: after FLA the fake block
    // and bcf.fake.loop.* become dispatcher siblings, so an alloca there no
    // longer dominates its loop-block users.
    IRBuilder<> SlotIRB(
        &*Fake.getParent()->getEntryBlock().getFirstInsertionPt());
    auto *CounterSlot = SlotIRB.CreateAlloca(Int32, nullptr, "bcf.fake.i");
    auto *AccSlot = SlotIRB.CreateAlloca(Int64, nullptr, "bcf.fake.acc");
    CounterSlot->setMetadata("taokari.bcf.slot",
                             MDNode::get(Fake.getContext(), {}));
    AccSlot->setMetadata("taokari.bcf.slot",
                         MDNode::get(Fake.getContext(), {}));

    IRBuilder<> Entry(&Fake);
    Value *V =
        Entry.CreateAlignedLoad(Int64, &Nonce, Align(8), true, "bcf.fake.nonce");
    Entry.CreateStore(ConstantInt::get(Int32, 0), CounterSlot);
    Entry.CreateStore(V, AccSlot);

    BasicBlock *LoopHdr =
        BasicBlock::Create(Fake.getContext(), "bcf.fake.loop.hdr",
                           Fake.getParent(), BranchTarget);
    BasicBlock *LoopBody =
        BasicBlock::Create(Fake.getContext(), "bcf.fake.loop.body",
                           Fake.getParent(), BranchTarget);
    BasicBlock *LoopExit =
        BasicBlock::Create(Fake.getContext(), "bcf.fake.loop.exit",
                           Fake.getParent(), BranchTarget);
    Entry.CreateBr(LoopHdr);

    IRBuilder<> Hdr(LoopHdr);
    Value *CurI = Hdr.CreateLoad(Int32, CounterSlot, "bcf.fake.i.ld");
    Value *Bound =
        Hdr.CreateAlignedLoad(Int32, BoundGV, Align(4), true, "bcf.fake.bound.ld");
    Hdr.CreateCondBr(Hdr.CreateICmpULT(CurI, Bound), LoopBody, LoopExit);

    IRBuilder<> Body(LoopBody);
    Value *Acc = Body.CreateLoad(Int64, AccSlot, "bcf.fake.acc.ld");
    Acc = Body.CreateXor(Acc, ConstantInt::get(Int64, FuncRNG()),
                         "bcf.fake.xor");
    Acc = Body.CreateMul(Acc, ConstantInt::get(Int64, FuncRNG() | 1),
                         "bcf.fake.mul");
    Acc = Body.CreateAdd(Acc, ConstantInt::get(Int64, FuncRNG()),
                         "bcf.fake.add");
    Body.CreateStore(Acc, AccSlot);
    Body.CreateStore(Body.CreateAdd(CurI, ConstantInt::get(Int32, 1)),
                     CounterSlot);
    Body.CreateBr(LoopHdr);

    IRBuilder<> Exit(LoopExit);
    Value *FinalAcc = Exit.CreateLoad(Int64, AccSlot, "bcf.fake.final");
    Exit.CreateAlignedStore(FinalAcc, &JunkSlot, Align(8), true);
    Exit.CreateBr(BranchTarget);
  }

  static Function *getOrCreateJunkFunction(Module &M,
                                           std::mt19937_64 &FuncRNG) {
    if (auto *F = M.getFunction("__taokari_bcf_junk"))
      return F;
    auto *Int64 = Type::getInt64Ty(M.getContext());
    auto *FTy = FunctionType::get(Int64, {Int64}, false);
    auto *F = Function::Create(FTy, GlobalValue::InternalLinkage,
                               "__taokari_bcf_junk", M);
    F->addFnAttr(Attribute::NoInline);
    F->addFnAttr(Attribute::OptimizeNone);
    auto *BB = BasicBlock::Create(M.getContext(), "entry", F);
    IRBuilder<> IRB(BB);
    auto *X = F->getArg(0);
    Value *Y = X;
    switch (FuncRNG() % 4) {
    case 0:
      Y = IRB.CreateMul(Y, ConstantInt::get(Int64, FuncRNG() | 1), "j.mul");
      Y = IRB.CreateAdd(Y, ConstantInt::get(Int64, FuncRNG()), "j.add");
      Y = IRB.CreateXor(
          Y, IRB.CreateLShr(Y, (FuncRNG() % 31) + 1, "j.shr"), "j.xor");
      break;
    case 1:
      Y = IRB.CreateXor(Y, ConstantInt::get(Int64, FuncRNG()), "j.xor");
      Y = IRB.CreateOr(IRB.CreateShl(Y, 13, "j.shl"),
                       IRB.CreateLShr(Y, 51, "j.shr"), "j.rot");
      Y = IRB.CreateAdd(Y, ConstantInt::get(Int64, FuncRNG()), "j.add");
      break;
    case 2: {
      Value *A = IRB.CreateAdd(Y, ConstantInt::get(Int64, FuncRNG()), "j.a");
      Value *B = IRB.CreateXor(Y, ConstantInt::get(Int64, FuncRNG()), "j.b");
      Y = IRB.CreateSub(IRB.CreateOr(A, B, "j.or"),
                        IRB.CreateAnd(A, B, "j.and"), "j.sub");
      break;
    }
    default:
      Y = IRB.CreateXor(Y, ConstantInt::get(Int64, FuncRNG()), "j.xor");
      Y = IRB.CreateMul(Y, ConstantInt::get(Int64, FuncRNG() | 1), "j.mul");
      Y = IRB.CreateAdd(
          Y, IRB.CreateLShr(Y, (FuncRNG() % 31) + 1, "j.shr"), "j.add");
      break;
    }
    IRB.CreateRet(Y);
    return F;
  }
};
}

char BogusControlFlow::ID = 0;

FunctionPass *
llvm::createBogusControlFlowPass(ObfuscationOptions *ArgsOptions) {
  return new BogusControlFlow(ArgsOptions);
}
