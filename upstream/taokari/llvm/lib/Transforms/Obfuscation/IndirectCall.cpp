#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/Transforms/Obfuscation/IndirectCall.h"
#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscation/Utils.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/IR/Module.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/APInt.h"
#include "llvm/Support/RandomNumberGenerator.h"
#include "llvm/TargetParser/Triple.h"

#include <algorithm>
#include <random>

#define DEBUG_TYPE "icall"

using namespace llvm;

namespace {
Function *getDirectCallee(CallBase &CB) {
  if (auto *Callee = CB.getCalledFunction())
    return Callee;
  return dyn_cast<Function>(CB.getCalledOperand()->stripPointerCasts());
}

bool isGeneratedIcallFunction(Function &F) {
  return F.getName().starts_with("__taokari_icall_shard_") ||
         F.getName().starts_with("__taokari_icall_fake_");
}

bool isOutlinedShard(Function &Callee) {
  return Callee.hasLocalLinkage() && Callee.getName().contains(".shard");
}

bool isNonLocalJumpFn(StringRef Name) {
  return Name == "setjmp" || Name == "_setjmp" || Name == "longjmp" ||
         Name == "sigsetjmp" || Name == "siglongjmp" ||
         Name == "__llvm_sjlj_setjmp";
}

bool moduleUsesNonLocalJumps(Module &M) {
  for (Function &F : M) {
    if (!F.hasName())
      continue;
    if (isNonLocalJumpFn(F.getName()))
      return true;
  }
  for (Function &F : M) {
    if (F.isDeclaration())
      continue;
    for (Instruction &I : instructions(F)) {
      auto *CB = dyn_cast<CallBase>(&I);
      if (!CB)
        continue;
      Function *Callee = CB->getCalledFunction();
      if (Callee && isNonLocalJumpFn(Callee->getName()))
        return true;
    }
  }
  return false;
}

bool isSafeCallee(CallBase &CB, Function *Callee) {
  if (!Callee || Callee->isIntrinsic())
    return false;
  if (Callee->isDeclarationForLinker() || Callee->isWeakForLinker() ||
      Callee->hasDLLImportStorageClass() || Callee->isInterposable() ||
      (!Callee->hasLocalLinkage() && !Callee->hasHiddenVisibility()))
    return false;
  if (Callee->hasFnAttribute(Attribute::AlwaysInline) ||
      CB.hasFnAttr(Attribute::AlwaysInline))
    return false;
  return true;
}

unsigned probabilityOrFull(uint32_t Probability) {
  return Probability <= 100 ? Probability : 100;
}

struct IndirectCall : public FunctionPass {
  static char         ID;
  ObfuscationOptions *ArgsOptions;

  DenseMap<Function *, SmallPtrSet<CallInst *, 8>> FunctionCallSites;

  std::vector<Constant *>        Callees;
  DenseMap<Constant *, unsigned> CalleeIndex;
  // 63 - 32====31 - 0
  //  Mask=======Key
  DenseMap<Constant *, uint64_t>   CalleeKeys;
  DenseMap<Function *, Function *> CalleeShards;
  SmallVector<GlobalVariable *, 8> CalleePageTable;
  GlobalVariable *                 CalleeObjectShareTable = nullptr;
  std::mt19937_64                  RNG;
  uint64_t                         PtrEncKey = 0;
  uint64_t                         ModulePacSeed = 0;
  uint64_t                         ModulePacSalt = 0;

  bool RunOnFuncChanged = false;
  bool SkipOutlinedShards = false;

  IndirectCall(ObfuscationOptions *argsOptions) : FunctionPass(ID) {
    this->ArgsOptions = argsOptions;
    uint64_t seed = 0;
    if (auto errorCode = llvm::getRandomBytes(&seed, sizeof(seed))) {
      llvm::report_fatal_error(
          StringRef("Failed to get random bytes for page table generation") +
          errorCode.message());
    }

    RNG = std::mt19937_64(seed);
  }

  StringRef getPassName() const override {
    return {"IndirectCall"};
  }

  uint64_t nextNonZeroKey() {
    uint64_t Key = RNG();
    while (!Key)
      Key = RNG();
    return Key;
  }

  Value *zeroFor(Type *Ty) {
    if (Ty->isVoidTy())
      return nullptr;
    if (Ty->isPointerTy())
      return ConstantPointerNull::get(cast<PointerType>(Ty));
    if (Ty->isIntegerTy() || Ty->isFloatingPointTy() || Ty->isVectorTy())
      return Constant::getNullValue(Ty);
    return PoisonValue::get(Ty);
  }

  Function *getOrCreateCallShard(Module &M, Function *Callee) {
    auto It = CalleeShards.find(Callee);
    if (It != CalleeShards.end())
      return It->second;

    std::string Name = "__taokari_icall_shard_" + std::string(Callee->getName());
    if (auto *Existing = M.getFunction(Name)) {
      CalleeShards[Callee] = Existing;
      return Existing;
    }

    auto *Shard = Function::Create(Callee->getFunctionType(),
                                   GlobalValue::InternalLinkage, Name, M);
    Shard->addFnAttr(Attribute::NoInline);
    Shard->addFnAttr(Attribute::NoUnwind);
    Shard->setCallingConv(Callee->getCallingConv());

    auto *FakeTarget = Function::Create(
        Callee->getFunctionType(), GlobalValue::InternalLinkage,
        "__taokari_icall_fake_" + std::string(Callee->getName()), M);
    FakeTarget->addFnAttr(Attribute::NoInline);
    FakeTarget->addFnAttr(Attribute::NoUnwind);
    FakeTarget->setCallingConv(Callee->getCallingConv());
    appendToCompilerUsed(M, {Callee});

    auto &Ctx = M.getContext();
    auto *I64 = Type::getInt64Ty(Ctx);
    auto *PtrTy = PointerType::getUnqual(Ctx);
    uint64_t Seed = nextNonZeroKey();
    auto *SeedGV = new GlobalVariable(
        M, I64, false, GlobalValue::PrivateLinkage,
        ConstantInt::get(I64, Seed),
        "__taokari_icall_shard_seed_" + Callee->getName());
    SeedGV->setAlignment(Align(8));

    // Pointer tables. The shard body has no direct call edge to the real
    // callee: the address is loaded from a private global as an i64 (the
    // linker fills the slot with an IMAGE_REL_AMD64_ADDR64 reloc, exactly
    // like the existing IndirectCall page-table entries), inttoptr'd to a
    // function pointer and called indirectly. The IR has no `call @callee`
    // edge for Hex-Rays or a static disassembler to lift directly; the
    // absolute address lives in .data as a reloc, the same place every
    // other IndirectCall entry already lives, so no new leakage is added.
    Constant *CalleePtrInt = ConstantExpr::getPtrToInt(Callee, I64);
    auto *CalleePtrGV = new GlobalVariable(
        M, I64, false, GlobalValue::PrivateLinkage, CalleePtrInt,
        "__taokari_icall_shard_ptr_" + Callee->getName());
    CalleePtrGV->setAlignment(Align(8));

    Constant *FakePtrInt = ConstantExpr::getPtrToInt(FakeTarget, I64);
    auto *FakePtrGV = new GlobalVariable(
        M, I64, false, GlobalValue::PrivateLinkage, FakePtrInt,
        "__taokari_icall_shard_fptr_" + Callee->getName());
    FakePtrGV->setAlignment(Align(8));

    BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", Shard);
    BasicBlock *Real = BasicBlock::Create(Ctx, "real", Shard);
    BasicBlock *Fake = BasicBlock::Create(Ctx, "fake", Shard);
    BasicBlock *FakeEntry = BasicBlock::Create(Ctx, "entry", FakeTarget);
    IRBuilder<> FB(FakeEntry);
    if (Value *FakeResult = zeroFor(Callee->getReturnType()))
      FB.CreateRet(FakeResult);
    else
      FB.CreateRetVoid();

    IRBuilder<> B(Entry);
    auto *A = B.CreateAlignedLoad(I64, SeedGV, Align(8), true);
    auto *Bv = B.CreateAlignedLoad(I64, SeedGV, Align(8), true);
    Value *Pred = nullptr;
    switch (RNG() % 3) {
    case 1: {
      auto *Salt = ConstantInt::get(I64, nextNonZeroKey());
      Value *L = B.CreateXor(A, Salt, "shard.pred.xor.l");
      Value *R = B.CreateAdd(B.CreateXor(Bv, Salt, "shard.pred.xor.r"),
                             ConstantInt::get(I64, 1), "shard.pred.xor.inc");
      Pred = B.CreateICmpEQ(L, R, "shard.pred");
      break;
    }
    case 2: {
      auto *Salt = ConstantInt::get(I64, nextNonZeroKey());
      Value *L = B.CreateAdd(A, Salt, "shard.pred.add.l");
      Value *R = B.CreateXor(B.CreateAdd(Bv, Salt, "shard.pred.add.r"),
                             ConstantInt::get(I64, 1), "shard.pred.add.flip");
      Pred = B.CreateICmpEQ(L, R, "shard.pred");
      break;
    }
    default: {
      Value *R = B.CreateAdd(Bv, ConstantInt::get(I64, 1),
                             "shard.pred.inc");
      Pred = B.CreateICmpEQ(A, R, "shard.pred");
      break;
    }
    }
    B.CreateCondBr(Pred, Fake, Real);

    SmallVector<Value *, 8> Args;
    for (Argument &Arg : Shard->args())
      Args.push_back(&Arg);

    // Runtime pointer reconstruction: load the absolute address from the
    // private pointer table, inttoptr to a function pointer, then an
    // indirect call. The called operand is a runtime value, so the IR has
    // no direct call edge to the real callee for Hex-Rays or a static
    // disassembler to lift.
    auto emitIndirectShardCall = [&](BasicBlock *BB, GlobalVariable *PtrGV,
                                     FunctionType *FTy) -> CallInst * {
      IRBuilder<> B2(BB);
      auto *AddrInt = B2.CreateAlignedLoad(I64, PtrGV, Align(8), true,
                                           "shard.addr");
      Value *DecPtr = B2.CreateIntToPtr(AddrInt, PtrTy, "shard.ptr");
      auto *Call = B2.CreateCall(FTy, DecPtr, Args);
      return Call;
    };

    B.SetInsertPoint(Fake);
    {
      auto *FakeCall =
          emitIndirectShardCall(Fake, FakePtrGV, FakeTarget->getFunctionType());
      if (Callee->getReturnType()->isVoidTy())
        B.CreateRetVoid();
      else
        B.CreateRet(FakeCall);
    }

    B.SetInsertPoint(Real);
    {
      auto *RealCall =
          emitIndirectShardCall(Real, CalleePtrGV, Callee->getFunctionType());
      if (Callee->getReturnType()->isVoidTy()) {
        B.CreateRetVoid();
      } else {
        B.CreateRet(RealCall);
      }
    }

    CalleeShards[Callee] = Shard;
    return Shard;
  }

  Function *fortressCallee(Module &M, Function *Callee) {
    if (ArgsOptions->iCallOpt()->level() <= 2 || SkipOutlinedShards)
      return Callee;
    return getOrCreateCallShard(M, Callee);
  }

  uint64_t pacDiscriminator(Function *Fn, Function *Callee) const {
    uint64_t H = ModulePacSeed ^ CalleeKeys.lookup(Callee);
    H ^= static_cast<uint64_t>(hash_value(Fn->getName())) << 1;
    H ^= static_cast<uint64_t>(hash_value(Callee->getName())) << 33;
    H ^= ModulePacSalt;
    return H ? H : ModulePacSalt;
  }

  void NumberCallees(Module &M) {
    for (auto &F : M) {
      if (F.isIntrinsic() || isGeneratedIcallFunction(F)) {
        continue;
      }

      for (auto &BB : F) {
        for (auto &I : BB) {
          if (auto CI = dyn_cast<CallInst>(&I)) {
            auto CB = dyn_cast<CallBase>(&I);
            auto Callee = getDirectCallee(*CB);
            if (!isSafeCallee(*CB, Callee)) {
              continue;
            }
            if (SkipOutlinedShards && Callee && isOutlinedShard(*Callee)) {
              continue;
            }

            FunctionCallSites[&F].insert(CI);

            Function *TableCallee = fortressCallee(M, Callee);
            if (CalleeKeys.count(TableCallee) == 0) {
              Callees.push_back(TableCallee);
              CalleeKeys[TableCallee] = nextNonZeroKey();
            }
          }
        }
      }
    }
  }

  bool doInitialization(Module &M) override {
    CalleeIndex.clear();
    FunctionCallSites.clear();
    Callees.clear();
    CalleePageTable.clear();
    CalleeObjectShareTable = nullptr;
    CalleeKeys.clear();
    CalleeShards.clear();
    ModulePacSeed = nextNonZeroKey();
    ModulePacSalt = nextNonZeroKey();
    SkipOutlinedShards = moduleUsesNonLocalJumps(M);

    NumberCallees(M);
    if (!Callees.size()) {
      return false;
    }

    PtrEncKey = RNG();

    CreatePageTableArgs createPageTableArgs;
    createPageTableArgs.CountLoop = chooseModulePageTableDepth(RNG);
    createPageTableArgs.GVNamePrefix = M.getName().str() + "_IndirectCallee";
    createPageTableArgs.RNG = &RNG;
    createPageTableArgs.M = &M;
    createPageTableArgs.Objects = &Callees;
    createPageTableArgs.IndexMap = &CalleeIndex;
    createPageTableArgs.ObjectKeys = &CalleeKeys;
    createPageTableArgs.OutPageTable = &CalleePageTable;
    createPageTableArgs.PtrEncKey = PtrEncKey;
    if (ArgsOptions->iCallOpt()->level() > 1) {
      createPageTableArgs.FakeEntries =
          chooseFakeEntryCount(RNG, static_cast<unsigned>(Callees.size()));
      createPageTableArgs.TwoShare = true;
      createPageTableArgs.OutObjectShareTable = &CalleeObjectShareTable;
    }

    createPageTable(createPageTableArgs);
    return false;
  }

  bool runOnFunction(Function &Fn) override {
    if (isGeneratedIcallFunction(Fn))
      return false;

    const auto opt = ArgsOptions->toObfuscate(ArgsOptions->iCallOpt(), &Fn);
    if (!opt.isEnabled()) {
      return false;
    }

    auto &M = *Fn.getParent();

    if (Callees.empty()) {
      return false;
    }
    if (std::uniform_int_distribution<unsigned>(1, 100)(RNG) >
        probabilityOrFull(opt.functionProbability()))
      return false;

    SmallVector<CallInst *, 8> SelectedCallSites;
    SmallPtrSet<Function *, 8> SelectedCallees;
    for (auto *CI : FunctionCallSites[&Fn]) {
      CallBase *CB = CI;
      auto *Callee = getDirectCallee(*CB);
      if (!isSafeCallee(*CB, Callee))
        continue;
      if (SkipOutlinedShards && Callee && isOutlinedShard(*Callee))
        continue;
      if (std::uniform_int_distribution<unsigned>(1, 100)(RNG) >
          probabilityOrFull(opt.probability()))
        continue;
      SelectedCallSites.push_back(CI);
      SelectedCallees.insert(Callee);
    }

    if (SelectedCallSites.empty() || SelectedCallees.empty()) {
      return false;
    }

    std::vector<Constant *>        FuncCallees;
    DenseMap<Constant *, uint64_t> FuncKeys;
    for (auto callee : SelectedCallees) {
      Function *TableCallee = fortressCallee(M, callee);
      FuncCallees.push_back(TableCallee);
      FuncKeys[TableCallee] = RNG();
    }

    SmallVector<GlobalVariable *, 8> FuncCalleePageTable;
    DenseMap<Constant *, unsigned>   FuncCalleeIndex;
    unsigned                         FuncPageDepth = 0;

    if (opt.level()) {
      FuncPageDepth = choosePageTableDepth(RNG, opt.level());
      CreatePageTableArgs createPageTableArgs;
      createPageTableArgs.CountLoop = FuncPageDepth;
      createPageTableArgs.GVNamePrefix =
          M.getName().str() + Fn.getName().str() + "_IndirectCallee";
      createPageTableArgs.RNG = &RNG;
      createPageTableArgs.M = &M;
      createPageTableArgs.Objects = &FuncCallees;
      createPageTableArgs.IndexMap = &CalleeIndex;
      createPageTableArgs.ObjectKeys = &FuncKeys;
      createPageTableArgs.OutPageTable = &FuncCalleePageTable;
      createPageTableArgs.PtrEncKey = PtrEncKey;
      if (opt.level() > 1)
        createPageTableArgs.FakeEntries =
            chooseFakeEntryCount(RNG,
                                 static_cast<unsigned>(FuncCallees.size()));

      enhancedPageTable(createPageTableArgs, &FuncCalleeIndex);
    }

    // Count callee references for deduplication
    DenseMap<Function *, unsigned> CalleeUseCount;
    for (auto CI : SelectedCallSites) {
      CallBase *CB = CI;
      Function *Callee = getDirectCallee(*CB);
      if (Callee)
        CalleeUseCount[Callee]++;
    }

    // Pre-decrypt duplicate callees at function entry
    DenseMap<Function *, AllocaInst *> CalleeDedupCache;
    auto &EntryBB = Fn.getEntryBlock();
    Instruction *AllocaInsertPt = &*EntryBB.begin();
    auto *PtrTy = PointerType::getUnqual(Fn.getContext());
    for (auto &KV : CalleeUseCount) {
      if (KV.second <= 1)
        continue;
      IRBuilder<> AIB(AllocaInsertPt);
      CalleeDedupCache[KV.first] = AIB.CreateAlloca(PtrTy, nullptr);
    }

    if (!CalleeDedupCache.empty()) {
      Instruction *DecryptPt = nullptr;
      for (auto &I : EntryBB) {
        if (!isa<AllocaInst>(&I)) {
          DecryptPt = &I;
          break;
        }
      }
      if (!DecryptPt)
        DecryptPt = EntryBB.getTerminator();
      Triple T(M.getTargetTriple());
      for (auto &KV : CalleeDedupCache) {
        Function *       Callee = KV.first;
        Function *       TableCallee = fortressCallee(M, Callee);
        BuildDecryptArgs buildDecrypt;
        buildDecrypt.FuncLoopCount = FuncPageDepth;
        buildDecrypt.NextIndex = opt.level()
                                   ? FuncCalleeIndex[TableCallee]
                                   : CalleeIndex[TableCallee];
        buildDecrypt.NextIndexValue = nullptr;
        buildDecrypt.Fn = &Fn;
        buildDecrypt.InsertBefore = DecryptPt;
        buildDecrypt.LoadTy = Callee->getType();
        buildDecrypt.ModulePageTable = &CalleePageTable;
        buildDecrypt.FuncPageTable = &FuncCalleePageTable;
        buildDecrypt.ModuleKey = CalleeKeys[TableCallee];
        buildDecrypt.FuncKey = FuncKeys[TableCallee];
        buildDecrypt.PtrEncKey = PtrEncKey;
        buildDecrypt.ObjectShareTable = CalleeObjectShareTable;
        buildDecrypt.RuntimeSeed = opt.level() > 1 ? RNG() : 0;
        buildDecrypt.UseMBA = opt.level() > 1;
        buildDecrypt.IntegrityCheck = opt.level() > 1;
        buildDecrypt.PtrAuthKey = T.isAArch64() ? 0 : -1;
        buildDecrypt.PtrAuthDisc = pacDiscriminator(&Fn, TableCallee);
        auto        DecPtr = buildPageTableDecryptIR(buildDecrypt);
        IRBuilder<> SIB(DecryptPt);
        SIB.CreateAlignedStore(DecPtr, KV.second, Align{1}, true);
      }
    }

    for (auto CI : SelectedCallSites) {

      CallBase *CB = CI;

      Function *Callee = getDirectCallee(*CB);
      if (!isSafeCallee(*CB, Callee))
        continue;
      if (SkipOutlinedShards && Callee && isOutlinedShard(*Callee))
        continue;

      auto CacheIt = CalleeDedupCache.find(Callee);
      if (CacheIt != CalleeDedupCache.end()) {
        IRBuilder<> IRB(CB);
        auto        FnPtr = IRB.CreateAlignedLoad(
            Callee->getType(), CacheIt->second, Align{1}, true);
        FnPtr->setName("Call_" + Callee->getName());
        CB->setCalledOperand(FnPtr);
      } else {
        Function *TableCallee = fortressCallee(M, Callee);
        BuildDecryptArgs buildDecrypt;
        buildDecrypt.FuncLoopCount = FuncPageDepth;
        buildDecrypt.NextIndex = opt.level()
                                   ? FuncCalleeIndex[TableCallee]
                                   : CalleeIndex[TableCallee];
        buildDecrypt.NextIndexValue = nullptr;
        buildDecrypt.Fn = &Fn;
        buildDecrypt.InsertBefore = CB;
        buildDecrypt.LoadTy = Callee->getType();
        buildDecrypt.ModulePageTable = &CalleePageTable;
        buildDecrypt.FuncPageTable = &FuncCalleePageTable;
        buildDecrypt.ModuleKey = CalleeKeys[TableCallee];
        buildDecrypt.FuncKey = FuncKeys[TableCallee];
        buildDecrypt.PtrEncKey = PtrEncKey;
        buildDecrypt.ObjectShareTable = CalleeObjectShareTable;
        buildDecrypt.RuntimeSeed = opt.level() > 1 ? RNG() : 0;
        buildDecrypt.UseMBA = opt.level() > 1;
        buildDecrypt.IntegrityCheck = opt.level() > 1;
        Triple T(M.getTargetTriple());
        buildDecrypt.PtrAuthKey = T.isAArch64() ? 0 : -1;
        buildDecrypt.PtrAuthDisc = pacDiscriminator(&Fn, TableCallee);
        auto FnPtr = buildPageTableDecryptIR(buildDecrypt);
        FnPtr->setName("Call_" + Callee->getName());
        CB->setCalledOperand(FnPtr);
      }
    }

    RunOnFuncChanged = true;
    return true;
  }

  bool doFinalization(Module &M) override {
    if (!RunOnFuncChanged || CalleePageTable.empty()) {
      return false;
    }
    for (auto calleePage : CalleePageTable) {
      appendToCompilerUsed(M, {calleePage});
    }
    if (CalleeObjectShareTable)
      appendToCompilerUsed(M, {CalleeObjectShareTable});
    return true;
  }

};
} // anonymous namespace

char IndirectCall::ID = 0;

FunctionPass *llvm::createIndirectCallPass(ObfuscationOptions *argsOptions) {
  return new IndirectCall(argsOptions);
}

INITIALIZE_PASS(IndirectCall, "icall", "Enable IR Indirect Call Obfuscation",
                false, false)
