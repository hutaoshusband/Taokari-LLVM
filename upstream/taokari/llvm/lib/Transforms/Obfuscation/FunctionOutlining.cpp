#include "llvm/Transforms/Obfuscation/FunctionOutlining.h"
#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/MapVector.h"
#include "llvm/Analysis/AssumptionCache.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/RandomNumberGenerator.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/CodeExtractor.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <random>

#define DEBUG_TYPE "outline"

using namespace llvm;

static cl::opt<uint32_t> OutlineProbability(
    "taokari-outline-prob", cl::init(35), cl::NotHidden,
    cl::desc("Function outlining block selection probability, 0..100."));
static cl::opt<uint32_t> OutlineMaxShards(
    "taokari-outline-max-shards", cl::init(4), cl::NotHidden,
    cl::desc("Hard cap on outlined helper functions per source function."));
static cl::opt<uint32_t> OutlineMinSize(
    "taokari-outline-min-size", cl::init(3), cl::NotHidden,
    cl::desc("Minimum instruction count for a block to be worth outlining."));
static cl::opt<uint32_t> OutlineMaxInsts(
    "taokari-outline-max-insts", cl::init(0), cl::NotHidden,
    cl::desc("Skip blocks larger than this many real instructions; 0 = "
             "uncapped. Keeps shard bodies bounded for compile/runtime cost."));
static cl::opt<uint32_t> OutlineFakes(
    "taokari-outline-fakes", cl::init(1), cl::NotHidden,
    cl::desc("L2: decoy shard functions emitted per real shard to pollute the "
             "static call graph. 0 disables."));
static cl::opt<uint32_t> OutlineScramble(
    "taokari-outline-scramble", cl::init(1), cl::NotHidden,
    cl::desc("L2: XOR-scramble integer shard arguments and the return value "
             "with a per-call key. 0 disables."));
static cl::opt<bool> OutlineCrossPool(
    "taokari-outline-cross-pool", cl::init(false), cl::NotHidden,
    cl::desc("L3: move integer constants out of shard bodies into a shared "
             "encrypted cross-shard pool. OFF BY DEFAULT: rewriting shard "
             "operands into runtime loads is not compatible with MBA on the "
             "same functions (MBA cannot analyse the rewritten shape). Enable "
             "only on functions that are outlined but not MBA-substituted."));

namespace {
struct FunctionOutlining : public FunctionPass {
  static char ID;
  ObfuscationOptions *ArgsOptions;
  std::mt19937_64 RNG;

  FunctionOutlining(ObfuscationOptions *ArgsOptions) : FunctionPass(ID) {
    this->ArgsOptions = ArgsOptions;
    uint64_t Seed = 0;
    if (auto EC = llvm::getRandomBytes(&Seed, sizeof(Seed)))
      report_fatal_error(StringRef("Failed to seed outlining RNG: ") +
                         EC.message());
    RNG = std::mt19937_64(Seed);
  }

  StringRef getPassName() const override { return "FunctionOutlining"; }

  // Opaque shard name. Deliberately drops the source-function name so a
  // decompiler cannot reconstruct the original call structure from symbol
  // strings alone.
  std::string shardName(std::mt19937_64 &FuncRNG) {
    std::string S;
    raw_string_ostream OS(S);
    OS << "__taokari_sh_" << format_hex_no_prefix(FuncRNG(), 12, false);
    OS.flush();
    return S;
  }

  uint64_t nextNonZero(std::mt19937_64 &FuncRNG) {
    uint64_t K = FuncRNG();
    while (!K)
      K = FuncRNG();
    return K;
  }

  bool runOnFunction(Function &F) override {
    if (F.isDeclaration() || F.isIntrinsic())
      return false;
    // Never re-outline anything this pass emitted, otherwise each shard becomes
    // an outlining target itself and the call graph explodes exponentially.
    // Covers real shards, fake shards, and scramble helpers.
    if (F.getName().starts_with("__taokari_sh_") ||
        F.getName().contains(".shard"))
      return false;
    // Outlining a function that participates in EH splits funclet colouring
    // and breaks codegen; leave EH functions alone.
    if (F.hasPersonalityFn())
      return false;
    // CodeExtractor rewrites varargs handling; only safe on fixed-arity.
    if (F.isVarArg())
      return false;

    auto Opt = ArgsOptions->toObfuscate(ArgsOptions->outlineOpt(), &F);
    if (!Opt.isEnabled())
      return false;

    const uint32_t Probability =
        OutlineProbability.getNumOccurrences()
            ? OutlineProbability.getValue()
            : (Opt.probability() <= 100 ? Opt.probability() : 35);
    if (!Probability)
      return false;

    const uint32_t MaxShards = Opt.maxBlocks()
                                   ? Opt.maxBlocks()
                                   : OutlineMaxShards.getNumOccurrences()
                                         ? OutlineMaxShards.getValue()
                                         : 4;
    const uint32_t MinSize = OutlineMinSize.getValue();
    const uint32_t MaxInsts = OutlineMaxInsts.getValue();
    const uint32_t Level = Opt.level();

    DominatorTree DT(F);
    AssumptionCache AC(F);
    CodeExtractorAnalysisCache CEAC(F);

    SmallVector<BasicBlock *, 32> Candidates;
    for (BasicBlock &BB : F) {
      if (hasOutlinableTail(BB, MinSize, MaxInsts))
        Candidates.push_back(&BB);
    }

    std::mt19937_64 FuncRNG(RNG());
    uint32_t Shards = 0;
    bool Changed = false;
    for (BasicBlock *BB : Candidates) {
      if (Shards >= MaxShards)
        goto finish;
      if ((FuncRNG() % 100) >= Probability)
        continue;
      if (!hasOutlinableTail(*BB, MinSize, MaxInsts))
        continue;
      if (outlineTail(F, *BB, DT, AC, CEAC, MinSize, Level, FuncRNG)) {
        ++Shards;
        Changed = true;
        DT.recalculate(F);
      }
    }

  finish:
    if (Changed && Level >= 3 && OutlineCrossPool)
      buildCrossShardPool(F, FuncRNG);
    return Changed;
  }

  static uint32_t realSize(BasicBlock &BB) {
    uint32_t N = 0;
    for (Instruction &I : BB) {
      if (I.isTerminator() || I.isDebugOrPseudoInst())
        continue;
      ++N;
    }
    return N;
  }

  static bool hasOutlinableTail(BasicBlock &BB, uint32_t MinSize,
                                uint32_t MaxInsts) {
    if (BB.empty() || BB.isEHPad())
      return false;
    if (isa<PHINode>(BB.begin()))
      return false;
    auto *Term = BB.getTerminator();
    if (!Term)
      return false;

    if (auto *Br = dyn_cast<BranchInst>(Term)) {
      if (!Br->isUnconditional())
        return false;
    } else if (isa<SwitchInst>(Term)) {
      return false;
    } else if (isa<UnreachableInst>(Term)) {
      return false;
    } else if (!isa<BranchInst>(Term) && !isa<ReturnInst>(Term)) {
      return false;
    }

    uint32_t Size = realSize(BB);
    if (Size < MinSize + 1)
      return false;
    // Guardrail: a single huge block dragged wholesale into a shard bloats the
    // binary and compile time without adding call-graph value.
    if (MaxInsts && Size > MaxInsts)
      return false;

    for (BasicBlock *Pred : predecessors(&BB)) {
      auto *PT = Pred->getTerminator();
      if (isa<InvokeInst>(PT) || isa<CatchSwitchInst>(PT) ||
          isa<CatchReturnInst>(PT) || isa<ResumeInst>(PT) ||
          isa<CleanupReturnInst>(PT))
        return false;
    }
    return true;
  }

  bool outlineTail(Function &F, BasicBlock &BB, DominatorTree &DT,
                   AssumptionCache &AC, CodeExtractorAnalysisCache &CEAC,
                   uint32_t MinSize, uint32_t Level,
                   std::mt19937_64 &FuncRNG) {
    Instruction *Anchor = nullptr;
    Instruction *SplitPt = nullptr;
    for (Instruction &I : BB) {
      if (I.isTerminator() || I.isDebugOrPseudoInst() || isa<AllocaInst>(&I))
        continue;
      if (!Anchor) {
        Anchor = &I;
        continue;
      }
      SplitPt = &I;
      break;
    }
    if (!SplitPt)
      return false;

    BasicBlock *Tail = SplitBlock(&BB, SplitPt, &DT, nullptr, nullptr,
                                  BB.getName() + ".outline.tail");
    if (!Tail)
      return false;

    SmallVector<BasicBlock *, 1> Blocks{Tail};
    CodeExtractor Ext(Blocks, &DT, /*AggregateArgs=*/false, nullptr, nullptr,
                      &AC, /*AllowVarArgs=*/false, /*AllowAlloca=*/false,
                      /*AllocationBlock=*/nullptr,
                      /*Suffix=*/".outline",
                      /*ArgsInZeroAddressSpace=*/false);
    if (!Ext.isEligible())
      return false;

    Function *Shard = Ext.extractCodeRegion(CEAC);
    if (!Shard)
      return false;

    Shard->setLinkage(GlobalValue::InternalLinkage);
    Shard->addFnAttr(Attribute::NoInline);
    // L1 keeps a readable name (easier to debug); L2 swaps it for an opaque
    // token so the source-function name no longer leaks into the symbol table.
    if (Level >= 2)
      Shard->setName(shardName(FuncRNG));
    else
      Shard->setName(F.getName() + ".shard" + Twine(FuncRNG() & 0xffff));

    Module &M = *F.getParent();
    if (Level >= 2) {
      if (OutlineScramble.getValue())
        scrambleShard(F, *Shard, FuncRNG);
      if (OutlineFakes.getValue())
        emitFakeShards(M, Shard->getFunctionType(), FuncRNG);
    }
    if (Level >= 3)
      fortressShard(M, *Shard, FuncRNG);
    return true;
  }

  // XOR-wrap every integer shard parameter at the call site, unwrap inside the
  // shard entry, and XOR the shard's return value (unwrapped at the caller).
  // The shard signature itself is unchanged, so later passes (icall page table,
  // flattening) keep working; only the data on the edge is masked.
  void scrambleShard(Function &Caller, Function &Shard,
                     std::mt19937_64 &FuncRNG) {
    auto &Ctx = Caller.getContext();
    auto *I64 = Type::getInt64Ty(Ctx);

    // Per-parameter keys: a real key for ints, zero (identity) otherwise.
    SmallVector<uint64_t> Keys;
    for (Argument &A : Shard.args()) {
      Type *Ty = A.getType();
      if (Ty->isIntegerTy() && Ty->getIntegerBitWidth() <= 64)
        Keys.push_back(nextNonZero(FuncRNG));
      else
        Keys.push_back(0);
    }

    // Unwrap each integer parameter at shard entry: arg becomes
    // trunc(zext(arg) ^ key). Snapshot the real users of the argument first so
    // the freshly-built unwrap chain is not folded onto itself.
    BasicBlock &Entry = Shard.getEntryBlock();
    for (size_t I = 0; I < Keys.size(); ++I) {
      if (!Keys[I])
        continue;
      Argument &A = *Shard.getArg(I);
      SmallVector<Use *, 8> Uses;
      for (Use &U : A.uses())
        Uses.push_back(&U);

      IRBuilder<> EB(&Entry.front());
      Value *Wide = EB.CreateZExt(&A, I64, A.getName() + ".z");
      Value *Unmasked = EB.CreateXor(Wide, ConstantInt::get(I64, Keys[I]),
                                     A.getName() + ".unm");
      Value *Narrow =
          EB.CreateTrunc(Unmasked, A.getType(), A.getName() + ".clr");
      for (Use *U : Uses)
        if (U->getUser() != Wide)
          U->set(Narrow);
    }

    // Wrap each integer argument at every call site so the shard's unwrap
    // recovers the original value.
    SmallVector<CallInst *, 4> Calls;
    for (User *U : Shard.users())
      if (auto *CI = dyn_cast<CallInst>(U))
        if (CI->getCalledFunction() == &Shard)
          Calls.push_back(CI);
    for (CallInst *CI : Calls) {
      IRBuilder<> CB(CI);
      for (size_t I = 0; I < Keys.size(); ++I) {
        if (!Keys[I])
          continue;
        Value *Arg = CI->getArgOperand(I);
        Value *Wide = CB.CreateZExt(Arg, I64, Arg->getName() + ".wz");
        Value *Masked =
            CB.CreateXor(Wide, ConstantInt::get(I64, Keys[I]), Arg->getName() + ".wm");
        Value *Narrow =
            CB.CreateTrunc(Masked, Arg->getType(), Arg->getName() + ".w");
        CI->setArgOperand(I, Narrow);
      }
    }

    // Rewrap the return value, then unwrap at every call site. Same
    // build-snapshot-RAUW-fixup pattern as the parameter case.
    Type *RetTy = Shard.getReturnType();
    if (!RetTy->isIntegerTy() || RetTy->getIntegerBitWidth() > 64)
      return;
    uint64_t RetKey = nextNonZero(FuncRNG);

    for (BasicBlock &BB : Shard) {
      auto *Ret = dyn_cast<ReturnInst>(BB.getTerminator());
      if (!Ret || !Ret->getReturnValue())
        continue;
      IRBuilder<> RB(Ret);
      Value *Wide = RB.CreateZExt(Ret->getReturnValue(), I64, "ret.z");
      Value *Masked = RB.CreateXor(Wide, ConstantInt::get(I64, RetKey), "ret.m");
      Value *Narrow = RB.CreateTrunc(Masked, RetTy, "ret.s");
      Ret->setOperand(0, Narrow);
    }

    for (CallInst *CI : Calls) {
      SmallVector<Use *, 8> Uses;
      for (Use &U : CI->uses())
        Uses.push_back(&U);
      IRBuilder<> CB(CI->getNextNode());
      Value *Wide = CB.CreateZExt(CI, I64, CI->getName() + ".rz");
      Value *Unmasked =
          CB.CreateXor(Wide, ConstantInt::get(I64, RetKey), CI->getName() + ".ru");
      Value *Narrow = CB.CreateTrunc(Unmasked, RetTy, CI->getName() + ".r");
      for (Use *U : Uses)
        if (U->getUser() != Wide)
          U->set(Narrow);
    }
  }

  // Emit decpy shard-shaped functions that take the same type but return a
  // neutral value. They are never reachable from real code, so the binary only
  // pays size; the static call graph gains plausible-but-dead targets that
  // distract a decompiler's cross-reference walk.
  void emitFakeShards(Module &M, FunctionType *FTy,
                      std::mt19937_64 &FuncRNG) {
    unsigned Count = OutlineFakes.getValue();
    for (unsigned I = 0; I < Count; ++I) {
      auto *Fake = Function::Create(FTy, GlobalValue::InternalLinkage,
                                    shardName(FuncRNG), M);
      Fake->addFnAttr(Attribute::NoInline);
      BasicBlock *BB = BasicBlock::Create(M.getContext(), "entry", Fake);
      IRBuilder<> B(BB);
      Type *RetTy = FTy->getReturnType();
      if (RetTy->isVoidTy())
        B.CreateRetVoid();
      else
        B.CreateRet(Constant::getNullValue(RetTy));
      appendToCompilerUsed(M, {Fake});
    }
  }

  // Fortress hardening for a single shard (level >= 3). Adds three layers so a
  // decompiler can no longer read the shard as one clean body:
  //   1. Multi-layer split: the shard's own body tail is extracted into a
  //      sub-shard, so the work is spread across a chained caller/sub-shard pair
  //      instead of a single static body.
  //   2. Entry integrity check: the shard verifies a private checksum before
  //      running real code; a mismatch diverts to a dead junk block.
  //   3. A fake call edge to a sibling fake shard, polluting xref walks so the
  //      real control flow is not distinguishable from the decoy graph.
  void fortressShard(Module &M, Function &Shard, std::mt19937_64 &FuncRNG) {
    if (Shard.empty())
      return;
    splitShardIntoLayers(M, Shard, FuncRNG);
    addIntegrityCheck(Shard, FuncRNG);
    addFakeCallEdge(M, Shard, FuncRNG);
  }

  // Build a private global holding a random 64-bit token, then guard the shard
  // entry on (a^salt)==(b^salt) where a and b both load that global. The
  // predicate is always true at runtime, but the comparison + branch to a dead
  // junk block reads as a tamper check in a decompiler and adds a CFG edge that
  // never executes.
  void addIntegrityCheck(Function &Shard, std::mt19937_64 &FuncRNG) {
    Module &M = *Shard.getParent();
    auto &Ctx = Shard.getContext();
    auto *I64 = Type::getInt64Ty(Ctx);
    uint64_t Token = nextNonZero(FuncRNG);
    uint64_t Salt = nextNonZero(FuncRNG);

    auto *TokenGV = new GlobalVariable(
        M, I64, false, GlobalValue::PrivateLinkage,
        ConstantInt::get(I64, Token), Shard.getName() + ".ic.tok");
    TokenGV->setAlignment(Align(8));

    BasicBlock &Entry = Shard.getEntryBlock();
    // Split before the first real (non-alloca, non-debug) instruction so the
    // integrity check runs in the fresh entry and real code lands in Real.
    Instruction *RealStart = &Entry.front();
    for (Instruction &I : Entry) {
      if (isa<AllocaInst>(&I) || I.isDebugOrPseudoInst())
        continue;
      RealStart = &I;
      break;
    }
    BasicBlock *Real = Entry.splitBasicBlock(RealStart->getIterator(),
                                             Shard.getName() + ".ic.real");
    BasicBlock *Junk = BasicBlock::Create(Ctx, Shard.getName() + ".ic.junk",
                                          &Shard, Real);

    // splitBasicBlock appended an unconditional branch Entry -> Real; drop it so
    // the integrity predicate drives the branch instead.
    Entry.getTerminator()->eraseFromParent();

    IRBuilder<> B(&Entry, Entry.getFirstInsertionPt());
    // Load the token twice and compare both XOR-salted copies. Both loads read
    // the same private global, so (a^salt)==(b^salt) is always true at runtime,
    // but a decompiler reads it as a checksum verification guarding real work.
    Value *A = B.CreateAlignedLoad(I64, TokenGV, Align(8), true, "ic.a");
    Value *Bv = B.CreateAlignedLoad(I64, TokenGV, Align(8), true, "ic.b");
    auto *SaltC = ConstantInt::get(I64, Salt);
    Value *L = B.CreateXor(A, SaltC, "ic.l");
    Value *R = B.CreateXor(Bv, SaltC, "ic.r");
    Value *Pred = B.CreateICmpEQ(L, R, "ic.p");
    B.CreateCondBr(Pred, Real, Junk);

    // Junk block: dead-end so a tampered shard cannot fall through to real
    // work. Unreachable keeps the ABI intact for later passes.
    IRBuilder<> J(Junk);
    J.CreateUnreachable();
    appendToCompilerUsed(M, {TokenGV});
  }

  // Insert a call to a freshly-created fake shard at the shard entry, then drop
  // the result. The fake has the shard's own signature so the static call graph
  // shows the real shard calling a plausible sibling that does nothing.
  void addFakeCallEdge(Module &M, Function &Shard, std::mt19937_64 &FuncRNG) {
    auto *FTy = Shard.getFunctionType();
    auto *Fake = Function::Create(FTy, GlobalValue::InternalLinkage,
                                  shardName(FuncRNG), M);
    Fake->addFnAttr(Attribute::NoInline);
    BasicBlock *FBB = BasicBlock::Create(M.getContext(), "entry", Fake);
    IRBuilder<> FB(FBB);
    Type *RetTy = FTy->getReturnType();
    if (RetTy->isVoidTy())
      FB.CreateRetVoid();
    else
      FB.CreateRet(Constant::getNullValue(RetTy));
    appendToCompilerUsed(M, {Fake});

    BasicBlock &Entry = Shard.getEntryBlock();
    IRBuilder<> B(&Entry, Entry.getFirstInsertionPt());
    SmallVector<Value *, 8> Args;
    for (Argument &A : Shard.args())
      Args.push_back(&A);
    B.CreateCall(Fake, Args);
  }

  // Extract the shard's own tail into a sub-shard so the body is split across a
  // chained pair. Runs only when the shard is still a single straight-line
  // block; later fortress steps (integrity check) add more blocks afterwards.
  void splitShardIntoLayers(Module &M, Function &Shard,
                            std::mt19937_64 &FuncRNG) {
    // Pick the block with the most real code (the work usually lives in a
    // non-entry block after CodeExtractor splits allocas/stores off). Splitting
    // that block spreads the work across a chained caller/sub-shard pair.
    BasicBlock *Best = nullptr;
    uint32_t BestSize = 0;
    for (BasicBlock &BB : Shard) {
      if (!hasOutlinableTail(BB, OutlineMinSize.getValue(),
                             OutlineMaxInsts.getValue()))
        continue;
      uint32_t S = realSize(BB);
      if (S > BestSize) {
        BestSize = S;
        Best = &BB;
      }
    }
    if (!Best)
      return;
    BasicBlock *BB = Best;

    DominatorTree DT(Shard);
    AssumptionCache AC(Shard);
    CodeExtractorAnalysisCache CEAC(Shard);

    Instruction *Anchor = nullptr;
    Instruction *SplitPt = nullptr;
    for (Instruction &I : *BB) {
      if (I.isTerminator() || I.isDebugOrPseudoInst() || isa<AllocaInst>(&I))
        continue;
      if (!Anchor) {
        Anchor = &I;
        continue;
      }
      SplitPt = &I;
      break;
    }
    if (!SplitPt)
      return;

    BasicBlock *Tail =
        SplitBlock(BB, SplitPt, &DT, nullptr, nullptr,
                   BB->getName() + ".layer.tail");
    if (!Tail)
      return;

    SmallVector<BasicBlock *, 1> Blocks{Tail};
    CodeExtractor Ext(Blocks, &DT, false, nullptr, nullptr, &AC, false, false,
                      nullptr, ".layer", false);
    if (!Ext.isEligible())
      return;
    Function *Sub = Ext.extractCodeRegion(CEAC);
    if (!Sub)
      return;
    Sub->setLinkage(GlobalValue::InternalLinkage);
    Sub->addFnAttr(Attribute::NoInline);
    Sub->setName(shardName(FuncRNG));

    wrapWithDispatcher(M, Shard, Sub, FuncRNG);
  }

  // Insert a token-switched dispatcher between the parent shard and the sub-shard
  // it just extracted. The parent no longer calls the sub-shard directly; it
  // calls a dispatcher that switches on a token between the real sub-shard and a
  // fake, so the real edge is hidden behind an indirect dispatch.
  void wrapWithDispatcher(Module &M, Function &Parent, Function *Sub,
                          std::mt19937_64 &FuncRNG) {
    // Find the call site inside the parent that targets the sub-shard.
    CallInst *CallToSub = nullptr;
    for (BasicBlock &BB : Parent) {
      for (Instruction &I : BB) {
        if (auto *CI = dyn_cast<CallInst>(&I))
          if (CI->getCalledFunction() == Sub) {
            CallToSub = CI;
            break;
          }
      }
      if (CallToSub)
        break;
    }
    if (!CallToSub)
      return;

    auto &Ctx = M.getContext();
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *FTy = Sub->getFunctionType();

    // Fake target with the sub-shard's signature.
    auto *Fake = Function::Create(FTy, GlobalValue::InternalLinkage,
                                  shardName(FuncRNG), M);
    Fake->addFnAttr(Attribute::NoInline);
    BasicBlock *FBB = BasicBlock::Create(Ctx, "entry", Fake);
    IRBuilder<> FB(FBB);
    Type *RetTy = FTy->getReturnType();
    if (RetTy->isVoidTy())
      FB.CreateRetVoid();
    else
      FB.CreateRet(Constant::getNullValue(RetTy));
    appendToCompilerUsed(M, {Fake});

    // Dispatcher(i32 token, <sub-shard args>): switch token -> real | default fake.
    SmallVector<Type *, 8> DispArgTys;
    DispArgTys.push_back(I32);
    for (Type *Ty : FTy->params())
      DispArgTys.push_back(Ty);
    auto *DispFTy =
        FunctionType::get(FTy->getReturnType(), DispArgTys, false);
    auto *Disp = Function::Create(DispFTy, GlobalValue::InternalLinkage,
                                  shardName(FuncRNG), M);
    Disp->addFnAttr(Attribute::NoInline);
    BasicBlock *DispEntry = BasicBlock::Create(Ctx, "entry", Disp);
    BasicBlock *RealBB = BasicBlock::Create(Ctx, "real", Disp);
    BasicBlock *FakeBB = BasicBlock::Create(Ctx, "fake", Disp);

    Argument *TokenArg = Disp->getArg(0);
    uint32_t RealToken = FuncRNG() & 0xffff;
    IRBuilder<> DE(DispEntry);
    Value *Pred = DE.CreateICmpEQ(TokenArg, ConstantInt::get(I32, RealToken),
                                  "disp.tok");
    DE.CreateCondBr(Pred, RealBB, FakeBB);

    // Real branch forwards args to the sub-shard.
    IRBuilder<> RB(RealBB);
    SmallVector<Value *, 8> RealArgs;
    for (unsigned A = 1; A < Disp->arg_size(); ++A)
      RealArgs.push_back(Disp->getArg(A));
    Value *RealRes = RB.CreateCall(Sub, RealArgs);
    if (RetTy->isVoidTy())
      RB.CreateRetVoid();
    else
      RB.CreateRet(RealRes);

    // Fake branch forwards args to the fake shard.
    IRBuilder<> FKB(FakeBB);
    SmallVector<Value *, 8> FakeArgs(RealArgs);
    Value *FakeRes = FKB.CreateCall(Fake, FakeArgs);
    if (RetTy->isVoidTy())
      FKB.CreateRetVoid();
    else
      FKB.CreateRet(FakeRes);

    // Rewrite the parent's call: disp(realToken, <original args>).
    SmallVector<Value *, 8> NewArgs;
    NewArgs.push_back(ConstantInt::get(I32, RealToken));
    for (unsigned A = 0; A < CallToSub->arg_size(); ++A)
      NewArgs.push_back(CallToSub->getArgOperand(A));
    IRBuilder<> CB(CallToSub);
    CallInst *NewCall = CB.CreateCall(Disp, NewArgs, CallToSub->getName());
    NewCall->setCallingConv(CallToSub->getCallingConv());
    CallToSub->replaceAllUsesWith(NewCall);
    CallToSub->eraseFromParent();
  }

  // A constant operand is safe to move into the cross-shard pool only if it is
  // real data, not a control token: skip operands of comparisons, branches,
  // calls (args must keep matching the callee) and GEP indices. Only operands
  // of plain arithmetic/store instructions are pooled so later passes (notably
  // MBA) still see a shape they can analyse.
  static bool isPoolableUse(const Use &U) {
    auto *User = dyn_cast<Instruction>(U.getUser());
    if (!User)
      return false;
    if (isa<ICmpInst>(User) || isa<FCmpInst>(User))
      return false;
    if (User->isTerminator())
      return false;
    if (isa<CallBase>(User) || isa<GetElementPtrInst>(User))
      return false;
    return true;
  }

  // Move integer constants out of the real computation shards into a single
  // private encrypted pool global, then rewrite each shard's data use of such a
  // constant into a load + XOR-decrypt from the pool. The constants no longer
  // sit inline in any shard body. OPT-IN: rewriting operands into runtime loads
  // is not MBA-compatible on the same functions.
  void buildCrossShardPool(Function &F, std::mt19937_64 &FuncRNG) {
    Module &M = *F.getParent();
    auto &Ctx = M.getContext();
    auto *I64 = Type::getInt64Ty(Ctx);

    // Gather shards transitively reachable from F's shard calls. Skip
    // dispatchers (i32 token first arg) -- their token literal must stay inline
    // or it desyncs from the caller's token.
    SmallPtrSet<Function *, 32> Seen;
    SmallVector<Function *, 32> Work;
    auto PushCallees = [&](Function *Caller) {
      for (BasicBlock &CBB : *Caller)
        for (Instruction &I : CBB)
          if (auto *CI = dyn_cast<CallInst>(&I))
            if (auto *Callee = CI->getCalledFunction())
              if (Callee->getName().starts_with("__taokari_sh_"))
                if (Seen.insert(Callee).second)
                  Work.push_back(Callee);
    };
    PushCallees(&F);
    for (unsigned I = 0; I < Work.size(); ++I)
      PushCallees(Work[I]);

    SmallVector<Function *, 16> Targets;
    for (Function *Sh : Work) {
      if (Sh->empty() || Sh->isDeclaration())
        continue;
      if (!Sh->arg_empty() && Sh->getArg(0)->getType()->isIntegerTy(32))
        continue;
      Targets.push_back(Sh);
    }
    if (Targets.empty())
      return;

    MapVector<uint64_t, unsigned> ConstIndex;
    for (Function *Sh : Targets)
      for (BasicBlock &BB : *Sh)
        for (Instruction &I : BB)
          for (Use &Op : I.operands()) {
            auto *C = dyn_cast<ConstantInt>(Op.get());
            if (!C || C->getBitWidth() > 64 || C->getBitWidth() < 8)
              continue;
            if (!isPoolableUse(Op))
              continue;
            uint64_t V = C->getZExtValue();
            if (V <= 1)
              continue;
            if (!ConstIndex.count(V))
              ConstIndex[V] = 0;
          }
    if (ConstIndex.empty())
      return;

    uint64_t Key = nextNonZero(FuncRNG);
    auto *ArrTy = ArrayType::get(I64, ConstIndex.size());
    SmallVector<Constant *, 16> Encoded;
    unsigned Idx = 0;
    for (auto &KV : ConstIndex) {
      KV.second = Idx++;
      Encoded.push_back(ConstantInt::get(I64, KV.first ^ Key));
    }
    auto *PoolGV = new GlobalVariable(M, ArrTy, true, GlobalValue::PrivateLinkage,
                                      ConstantArray::get(ArrTy, Encoded),
                                      F.getName() + ".cpool");
    PoolGV->setAlignment(Align(8));
    auto *KeyGV = new GlobalVariable(M, I64, false, GlobalValue::PrivateLinkage,
                                     ConstantInt::get(I64, Key),
                                     F.getName() + ".cpool.key");
    KeyGV->setAlignment(Align(8));
    appendToCompilerUsed(M, {PoolGV, KeyGV});

    for (Function *Sh : Targets)
      rewriteConstUses(*Sh, PoolGV, KeyGV, I64, ConstIndex);
  }

  void rewriteConstUses(Function &Shard, GlobalVariable *PoolGV,
                        GlobalVariable *KeyGV, Type *I64,
                        const MapVector<uint64_t, unsigned> &ConstIndex) {
    SmallVector<std::pair<Use *, unsigned>, 32> ToRewrite;
    for (BasicBlock &BB : Shard)
      for (Instruction &I : BB)
        for (Use &Op : I.operands()) {
          auto *C = dyn_cast<ConstantInt>(Op.get());
          if (!C || C->getBitWidth() > 64 || C->getBitWidth() < 8)
            continue;
          if (!isPoolableUse(Op))
            continue;
          auto It = ConstIndex.find(C->getZExtValue());
          if (It == ConstIndex.end())
            continue;
          ToRewrite.emplace_back(&Op, It->second);
        }
    for (auto &P : ToRewrite) {
      Use *U = P.first;
      unsigned Idx = P.second;
      auto *User = cast<Instruction>(U->getUser());
      IRBuilder<> B(User);
      Value *GEP = B.CreateConstInBoundsGEP2_64(PoolGV->getValueType(),
                                                PoolGV, 0, Idx, "cpool.gep");
      Value *Enc = B.CreateAlignedLoad(I64, GEP, Align(8), true, "cpool.enc");
      Value *Key = B.CreateAlignedLoad(I64, KeyGV, Align(8), true, "cpool.key");
      Value *Dec = B.CreateXor(Enc, Key, "cpool.dec");
      auto *OrigTy = cast<ConstantInt>(U->get())->getType();
      Value *Narrow = OrigTy == I64 ? Dec : B.CreateTrunc(Dec, OrigTy, "cpool.t");
      U->set(Narrow);
    }
  }
};
} // namespace

char FunctionOutlining::ID = 0;

FunctionPass *
llvm::createFunctionOutliningPass(ObfuscationOptions *ArgsOptions) {
  return new FunctionOutlining(ArgsOptions);
}
