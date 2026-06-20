#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
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
  SmallVector<GlobalVariable *, 8> CalleePageTable;
  GlobalVariable *                 CalleeObjectShareTable = nullptr;
  std::mt19937_64                  RNG;
  uint64_t                         PtrEncKey = 0;

  bool RunOnFuncChanged = false;

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

  void NumberCallees(Module &M) {
    for (auto &F : M) {
      if (F.isIntrinsic()) {
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

            FunctionCallSites[&F].insert(CI);

            if (CalleeKeys.count(Callee) == 0) {
              Callees.push_back(Callee);
              CalleeKeys[Callee] = RNG();
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

    NumberCallees(M);
    if (!Callees.size()) {
      return false;
    }

    PtrEncKey = RNG();

    CreatePageTableArgs createPageTableArgs;
    createPageTableArgs.CountLoop = 1;
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
          std::max<unsigned>(1, Callees.size() / 2);
      createPageTableArgs.TwoShare = true;
      createPageTableArgs.OutObjectShareTable = &CalleeObjectShareTable;
    }

    createPageTable(createPageTableArgs);
    return false;
  }

  bool runOnFunction(Function &Fn) override {
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
      FuncCallees.push_back(callee);
      FuncKeys[callee] = RNG();
    }

    SmallVector<GlobalVariable *, 8> FuncCalleePageTable;
    DenseMap<Constant *, unsigned>   FuncCalleeIndex;

    if (opt.level()) {
      CreatePageTableArgs createPageTableArgs;
      createPageTableArgs.CountLoop = opt.level();
      createPageTableArgs.GVNamePrefix =
          M.getName().str() + Fn.getName().str() + "_IndirectCallee";
      createPageTableArgs.RNG = &RNG;
      createPageTableArgs.M = &M;
      createPageTableArgs.Objects = &FuncCallees;
      createPageTableArgs.IndexMap = &CalleeIndex;
      createPageTableArgs.ObjectKeys = &FuncKeys;
      createPageTableArgs.OutPageTable = &FuncCalleePageTable;
      if (opt.level() > 1)
        createPageTableArgs.FakeEntries =
            std::max<unsigned>(1, FuncCallees.size() / 2);

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
        BuildDecryptArgs buildDecrypt;
        buildDecrypt.FuncLoopCount = opt.level();
        buildDecrypt.NextIndex = opt.level()
                                   ? FuncCalleeIndex[Callee]
                                   : CalleeIndex[Callee];
        buildDecrypt.NextIndexValue = nullptr;
        buildDecrypt.Fn = &Fn;
        buildDecrypt.InsertBefore = DecryptPt;
        buildDecrypt.LoadTy = Callee->getType();
        buildDecrypt.ModulePageTable = &CalleePageTable;
        buildDecrypt.FuncPageTable = &FuncCalleePageTable;
        buildDecrypt.ModuleKey = CalleeKeys[Callee];
        buildDecrypt.FuncKey = FuncKeys[Callee];
        buildDecrypt.PtrEncKey = PtrEncKey;
        buildDecrypt.ObjectShareTable = CalleeObjectShareTable;
        buildDecrypt.RuntimeSeed = opt.level() > 1 ? RNG() : 0;
        buildDecrypt.UseMBA = opt.level() > 1;
        buildDecrypt.IntegrityCheck = opt.level() > 1;
        buildDecrypt.PtrAuthKey = T.isAArch64() ? 0 : -1;
        buildDecrypt.PtrAuthDisc = 0;
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

      auto CacheIt = CalleeDedupCache.find(Callee);
      if (CacheIt != CalleeDedupCache.end()) {
        IRBuilder<> IRB(CB);
        auto        FnPtr = IRB.CreateAlignedLoad(
            Callee->getType(), CacheIt->second, Align{1}, true);
        FnPtr->setName("Call_" + Callee->getName());
        CB->setCalledOperand(FnPtr);
      } else {
        BuildDecryptArgs buildDecrypt;
        buildDecrypt.FuncLoopCount = opt.level();
        buildDecrypt.NextIndex = opt.level()
                                   ? FuncCalleeIndex[Callee]
                                   : CalleeIndex[Callee];
        buildDecrypt.NextIndexValue = nullptr;
        buildDecrypt.Fn = &Fn;
        buildDecrypt.InsertBefore = CB;
        buildDecrypt.LoadTy = Callee->getType();
        buildDecrypt.ModulePageTable = &CalleePageTable;
        buildDecrypt.FuncPageTable = &FuncCalleePageTable;
        buildDecrypt.ModuleKey = CalleeKeys[Callee];
        buildDecrypt.FuncKey = FuncKeys[Callee];
        buildDecrypt.PtrEncKey = PtrEncKey;
        buildDecrypt.ObjectShareTable = CalleeObjectShareTable;
        buildDecrypt.RuntimeSeed = opt.level() > 1 ? RNG() : 0;
        buildDecrypt.UseMBA = opt.level() > 1;
        buildDecrypt.IntegrityCheck = opt.level() > 1;
        Triple T(M.getTargetTriple());
        buildDecrypt.PtrAuthKey = T.isAArch64() ? 0 : -1;
        buildDecrypt.PtrAuthDisc = 0;
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
