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
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/RandomNumberGenerator.h"
#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscation/OpaquePredicate.h"
#include "llvm/Transforms/Utils/Cloning.h"

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
    if (F.isDeclaration() || F.isIntrinsic() ||
        F.getName().starts_with("__taokari_bcf_"))
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

    SmallVector<BasicBlock *, 32> Blocks;
    for (BasicBlock &BB : F) {
      if (eligible(BB))
        Blocks.push_back(&BB);
    }

    std::mt19937_64 FuncRNG(RNG());
    bool Changed = false;
    for (BasicBlock *BB : Blocks) {
      if ((FuncRNG() % 100) >= Probability)
        continue;
      Changed |= obfuscateBlock(F, *BB, Opt.level(), Loops, FuncRNG);
    }
    return Changed;
  }

  static bool eligible(BasicBlock &BB) {
    // no PHI repair yet; widen this when BCF must cover join blocks.
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
    return Name.contains(".bcf.guard") || Name.contains(".bcf.fake");
  }

  bool obfuscateBlock(Function &F, BasicBlock &BB, uint32_t Level,
                      uint32_t Loops, std::mt19937_64 &FuncRNG) {
    auto *Pred = BB.getSinglePredecessor();
    if (!Pred)
      return false;

    LLVMContext &Ctx = F.getContext();
    auto &M = *F.getParent();
    auto *Int64 = Type::getInt64Ty(Ctx);
    auto *Nonce = getOrCreateNonce(M, Int64);
    auto *JunkSlot = createEntrySlot(F, Int64);

    BasicBlock *Guard =
        BasicBlock::Create(Ctx, BB.getName() + ".bcf.guard", &F, &BB);

    ValueToValueMapTy VMap;
    BasicBlock *Fake = CloneBasicBlock(&BB, VMap, ".bcf.fake", &F);
    sanitizeFake(*Fake);
    if (Level >= 2)
      mutateFake(*Fake, Level, FuncRNG);
    addJunk(*Fake, BB, *Nonce, *JunkSlot, Loops, Level, FuncRNG);

    Pred->getTerminator()->replaceSuccessorWith(&BB, Guard);

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
      auto *Load =
          GuardIR.CreateAlignedLoad(Int64, Nonce, Align(8), true, "bcf.nonce");
      Value *A = GuardIR.CreateMul(
          Load, GuardIR.CreateAdd(Load, ConstantInt::get(Int64, 1)),
          "bcf.opaque.mul");
      Opaque = GuardIR.CreateICmpEQ(
          GuardIR.CreateAnd(A, ConstantInt::get(Int64, 1), "bcf.opaque.bit"),
          ConstantInt::get(Int64, 0), "bcf.opaque");
    }
    GuardIR.CreateCondBr(Opaque, &BB, Fake);
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

  static AllocaInst *createEntrySlot(Function &F, Type *Ty) {
    IRBuilder<> IRB(&*F.getEntryBlock().getFirstInsertionPt());
    return IRB.CreateAlloca(Ty, nullptr, "bcf.dead.slot");
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

  void addJunk(BasicBlock &Fake, BasicBlock &Real, GlobalVariable &Nonce,
               AllocaInst &JunkSlot, uint32_t Loops, uint32_t Level,
               std::mt19937_64 &FuncRNG) {
    auto *Int64 = Type::getInt64Ty(Fake.getContext());

    // L3+: wrap the junk chain in a real back-edge so the fake block
    // reads as a loop to a static analyzer.
    // The loop runs exactly `Loops` iterations via a counter compared
    // against a runtime volatile-loaded bound; the body is the same
    // xor/mul/add chain as the linear version, so the CFG now carries
    // a fake loop header + latch in addition to the junk math.
    // Skip the loop shape on functions that participate in EH (any
    // funclet or personality): a cloned fake block in an EH function
    // can inherit funclet colouring, and the extra back-edge then
    // breaks liveness during codegen. The linear junk chain remains
    // safe because it stays in one block.
    bool InEHFunction = Fake.getParent()->hasPersonalityFn();
    if (Level >= 3 && Loops > 1 && !InEHFunction) {
      addJunkLoop(Fake, Real, Nonce, JunkSlot, Loops, FuncRNG);
      return;
    }

    IRBuilder<> IRB(&Fake);
    Value *V =
        IRB.CreateAlignedLoad(Int64, &Nonce, Align(8), true, "bcf.fake.nonce");
    // L2+: add a volatile private-global load so dataflow analysis has
    // a fake memory dependency to trace. The loaded value feeds the junk
    // chain so it cannot be DCE'd.
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
    IRB.CreateStore(V, &JunkSlot);
    IRB.CreateAlignedStore(V, &JunkSlot, Align(8), true);
    IRB.CreateBr(&Real);
  }

  // Build a fake-loop version of the junk chain. Layout:
  //   Fake:        load nonce; counter = 0; br LoopHdr
  //   LoopHdr:     if counter < bound br LoopBody else LoopExit
  //   LoopBody:    xor/mul/add chain; counter++; br LoopHdr
  //   LoopExit:    store result; br Real
  // The bound is a fresh volatile-loaded global so the optimizer cannot
  // unroll the loop away. The loop is semantically dead because the
  // result only feeds the JunkSlot dead store, but it is a real CFG
  // loop with a back-edge.
  void addJunkLoop(BasicBlock &Fake, BasicBlock &Real, GlobalVariable &Nonce,
                   AllocaInst &JunkSlot, uint32_t Loops,
                   std::mt19937_64 &FuncRNG) {
    auto *Int64 = Type::getInt64Ty(Fake.getContext());
    auto *Int32 = Type::getInt32Ty(Fake.getContext());
    Module &M = *Fake.getModule();
    auto *BoundGV = new GlobalVariable(
        M, Int32, false, GlobalValue::PrivateLinkage,
        ConstantInt::get(Int32, static_cast<uint32_t>(Loops)),
        Twine(Fake.getParent()->getName()) + ".bcf.fake.bound");
    BoundGV->setAlignment(Align(4));

    IRBuilder<> Entry(&Fake);
    Value *V =
        Entry.CreateAlignedLoad(Int64, &Nonce, Align(8), true, "bcf.fake.nonce");
    auto *CounterSlot = Entry.CreateAlloca(Int32, nullptr, "bcf.fake.i");
    Entry.CreateStore(ConstantInt::get(Int32, 0), CounterSlot);
    auto *AccSlot = Entry.CreateAlloca(Int64, nullptr, "bcf.fake.acc");
    Entry.CreateStore(V, AccSlot);

    BasicBlock *LoopHdr =
        BasicBlock::Create(Fake.getContext(), "bcf.fake.loop.hdr",
                           Fake.getParent(), &Real);
    BasicBlock *LoopBody =
        BasicBlock::Create(Fake.getContext(), "bcf.fake.loop.body",
                           Fake.getParent(), &Real);
    BasicBlock *LoopExit =
        BasicBlock::Create(Fake.getContext(), "bcf.fake.loop.exit",
                           Fake.getParent(), &Real);
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
    Exit.CreateStore(FinalAcc, &JunkSlot);
    Exit.CreateAlignedStore(FinalAcc, &JunkSlot, Align(8), true);
    Exit.CreateBr(&Real);
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
} // namespace

char BogusControlFlow::ID = 0;

FunctionPass *
llvm::createBogusControlFlowPass(ObfuscationOptions *ArgsOptions) {
  return new BogusControlFlow(ArgsOptions);
}
