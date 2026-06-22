#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Obfuscation/IndirectBranch.h"
#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscation/Utils.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/IR/Module.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/Support/RandomNumberGenerator.h"
#include "llvm/TargetParser/Triple.h"

#include <random>

#define DEBUG_TYPE "indbr"

using namespace llvm;

namespace {
bool hasFlatteningDispatcher(Function &F) {
  bool HasLoop = false;
  bool HasSwitch = false;
  bool HasClone = false;
  for (BasicBlock &BB : F) {
    StringRef Name = BB.getName();
    HasLoop |= Name.starts_with("loopEntry") || Name.starts_with("loopEnd");
    HasSwitch |= Name.starts_with("switchDefault") ||
                 Name.starts_with("switchFakeCaseGate") ||
                 Name.starts_with("switchFakeSucc") ||
                 Name.starts_with("switchTrap") ||
                 Name.starts_with("switchDispatch") ||
                 Name.starts_with("switchNestedDispatch") ||
                 Name.starts_with("switchBucket");
    HasClone |= Name.contains(".tao.clone");
  }
  return HasLoop && (HasSwitch || HasClone);
}

bool hasTrapLikeTerminator(Function &F) {
  for (BasicBlock &BB : F) {
    if (isa<UnreachableInst>(BB.getTerminator()))
      return true;
    for (Instruction &I : BB) {
      auto *II = dyn_cast<IntrinsicInst>(&I);
      if (!II)
        continue;
      switch (II->getIntrinsicID()) {
      case Intrinsic::trap:
      case Intrinsic::debugtrap:
      case Intrinsic::ubsantrap:
        return true;
      default:
        break;
      }
    }
  }
  return false;
}

bool isAssertLikeCall(const CallBase &CB) {
  if (CB.isInlineAsm())
    return true;
  const Function *Callee = CB.getCalledFunction();
  if (!Callee)
    return false;
  StringRef Name = Callee->getName();
  return Name == "_wassert" || Name == "__assert" ||
         Name == "__assert_fail" || Name == "_CrtDbgReport" ||
         Name == "_CrtDbgReportW" || Name.contains("assert") ||
         Name.contains("Assert");
}

bool isTrapLikeBlock(const BasicBlock *BB) {
  if (isa<UnreachableInst>(BB->getTerminator()))
    return true;
  for (const Instruction &I : *BB) {
    auto *II = dyn_cast<IntrinsicInst>(&I);
    if (II) {
      switch (II->getIntrinsicID()) {
      case Intrinsic::trap:
      case Intrinsic::debugtrap:
      case Intrinsic::ubsantrap:
        return true;
      default:
        break;
      }
    }
    auto *CB = dyn_cast<CallBase>(&I);
    if (CB && isAssertLikeCall(*CB))
      return true;
  }
  return false;
}

bool hasAssertLikeCall(Function &F) {
  for (BasicBlock &BB : F)
    for (Instruction &I : BB)
      if (auto *CB = dyn_cast<CallBase>(&I))
        if (isAssertLikeCall(*CB))
          return true;
  return false;
}

bool hasNoObfMetadata(Function &F) {
  if (F.getMetadata("noobf"))
    return true;
  for (BasicBlock &BB : F)
    for (Instruction &I : BB)
      if (I.hasMetadata("noobf"))
        return true;
  return false;
}

struct IndirectBranch : public FunctionPass {
  static char         ID;
  ObfuscationOptions *ArgsOptions;

  DenseMap<Function *, SmallPtrSet<Constant *, 8>>   FunctionBBs;
  DenseMap<Function *, SmallPtrSet<BranchInst *, 8>> FunctionBrs;

  std::vector<Constant *>          BBAddrTargets;
  DenseMap<Constant *, unsigned>   BBIndex;
  DenseMap<Constant *, uint64_t>   BBKeys;
  SmallVector<GlobalVariable *, 8> BBPageTable;
  std::mt19937_64                  RNG;
  uint64_t                         PtrEncKey = 0;

  bool RunOnFuncChanged = false;

  IndirectBranch(ObfuscationOptions *argsOptions) : FunctionPass(ID) {
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
    return {"IndirectBranch"};
  }

  void NumberBasicBlock(Module &M) {
    for (auto &F : M) {
      if (F.empty() || F.isWeakForLinker() ||
          F.getSection() == ".text.startup" ||
          F.isIntrinsic()) {
        continue;
      }
      const auto opt = ArgsOptions->toObfuscate(ArgsOptions->indBrOpt(), &F);
      if (!opt.isEnabled()) {
        continue;
      }
      if (hasFlatteningDispatcher(F)) {
        continue;
      }
      if (hasTrapLikeTerminator(F)) {
        continue;
      }
      if (hasAssertLikeCall(F)) {
        continue;
      }
      if (hasNoObfMetadata(F)) {
        continue;
      }
      SplitAllCriticalEdges(F, CriticalEdgeSplittingOptions(nullptr, nullptr));

      const uint64_t BBKey = RNG();

      for (auto &BB : F) {
        if (auto *BI = dyn_cast<BranchInst>(BB.getTerminator())) {
          if (BI->isConditional()) {
            if (isTrapLikeBlock(BI->getSuccessor(0)) ||
                isTrapLikeBlock(BI->getSuccessor(1))) {
              continue;
            }
            FunctionBrs[&F].insert(BI);
            unsigned N = BI->getNumSuccessors();
            for (unsigned I = 0; I < N; I++) {
              BasicBlock *Successor = BI->getSuccessor(I);
              auto        BBAddr = BlockAddress::get(Successor);
              FunctionBBs[&F].insert(BBAddr);
              if (BBKeys.count(BBAddr) == 0) {
                BBAddrTargets.push_back(BBAddr);
                BBKeys[BBAddr] = BBKey;
              }
            }
          }
        }
      }
    }
  }

  bool doInitialization(Module &M) override {
    BBIndex.clear();
    BBPageTable.clear();
    FunctionBBs.clear();
    FunctionBrs.clear();
    BBAddrTargets.clear();
    BBKeys.clear();

    NumberBasicBlock(M);
    if (BBAddrTargets.empty()) {
      return false;
    }

    PtrEncKey = RNG();

    CreatePageTableArgs createPageTableArgs;
    createPageTableArgs.CountLoop = 1;
    createPageTableArgs.GVNamePrefix = M.getName().str() + "_IndirectBr";
    createPageTableArgs.RNG = &RNG;
    createPageTableArgs.M = &M;
    createPageTableArgs.Objects = &BBAddrTargets;
    createPageTableArgs.IndexMap = &BBIndex;
    createPageTableArgs.ObjectKeys = &BBKeys;
    createPageTableArgs.OutPageTable = &BBPageTable;
    createPageTableArgs.PtrEncKey = PtrEncKey;
    // L2+: pad with a per-build decoy count so table size does not expose
    // a fixed real-target ratio.
    createPageTableArgs.FakeEntries = chooseFakeEntryCount(
        RNG, static_cast<unsigned>(BBAddrTargets.size()));

    createPageTable(createPageTableArgs);
    return false;
  }


  bool runOnFunction(Function &Fn) override {
    const auto opt = ArgsOptions->toObfuscate(ArgsOptions->indBrOpt(), &Fn);
    if (!opt.isEnabled()) {
      return false;
    }
    if (hasFlatteningDispatcher(Fn)) {
      return false;
    }
    if (hasTrapLikeTerminator(Fn)) {
      return false;
    }
    if (hasAssertLikeCall(Fn)) {
      return false;
    }
    if (hasNoObfMetadata(Fn)) {
      return false;
    }

    LLVMContext &Ctx = Fn.getContext();
    auto &       M = *Fn.getParent();

    if (BBAddrTargets.empty()) {
      return false;
    }

    auto &FuncBBsSet = FunctionBBs[&Fn];
    auto &FuncBrs = FunctionBrs[&Fn];
    if (FuncBBsSet.empty() || FuncBrs.empty()) {
      return false;
    }

    std::vector<Constant *>        FuncBBs;
    DenseMap<Constant *, uint64_t> FuncKeys;
    auto                           FuncKey = RNG();

    for (auto bb : FuncBBsSet) {
      FuncBBs.push_back(bb);
      FuncKeys[bb] = FuncKey;
    }

    SmallVector<GlobalVariable *, 8> FuncBBPageTable;
    DenseMap<Constant *, unsigned>   FuncBBIndex;

    if (opt.level()) {
      CreatePageTableArgs createPageTableArgs;
      createPageTableArgs.CountLoop = opt.level();
      createPageTableArgs.GVNamePrefix =
          M.getName().str() + Fn.getName().str() + "_IndirectBr";
      createPageTableArgs.M = &M;
      createPageTableArgs.RNG = &RNG;
      createPageTableArgs.Objects = &FuncBBs;
      createPageTableArgs.IndexMap = &BBIndex;
      createPageTableArgs.ObjectKeys = &FuncKeys;
      createPageTableArgs.OutPageTable = &FuncBBPageTable;
      createPageTableArgs.PtrEncKey = PtrEncKey;
      // L2+ fake entries: same idea as the module-level padding but on
      // the per-function page table, so function-local tables vary too.
      createPageTableArgs.FakeEntries = chooseFakeEntryCount(
          RNG, static_cast<unsigned>(FuncBBs.size()));

      enhancedPageTable(createPageTableArgs, &FuncBBIndex);
    }

    auto *IntTy = getPageTableIntTy(M);
    for (auto BI : FuncBrs) {
      if (BI && BI->isConditional()) {
        if (isTrapLikeBlock(BI->getSuccessor(0)) ||
            isTrapLikeBlock(BI->getSuccessor(1))) {
          continue;
        }
        IRBuilder<> IRB(BI);

        auto Cond = BI->getCondition();

        auto TBB = BI->getSuccessor(0);
        auto FBB = BI->getSuccessor(1);
        auto AddrTBB = BlockAddress::get(TBB);
        auto AddrFBB = BlockAddress::get(FBB);

        auto TIndex = opt.level()
                        ? ConstantInt::get(IntTy, FuncBBIndex[AddrTBB])
                        : ConstantInt::get(IntTy, BBIndex[AddrTBB]);

        auto FIndex = opt.level()
                        ? ConstantInt::get(IntTy, FuncBBIndex[AddrFBB])
                        : ConstantInt::get(IntTy, BBIndex[AddrFBB]);

        auto NextIndex = IRB.CreateSelect(Cond, TIndex, FIndex);

        BuildDecryptArgs buildDecrypt;
        buildDecrypt.FuncLoopCount = opt.level();
        buildDecrypt.NextIndex = 0;
        buildDecrypt.NextIndexValue = NextIndex;
        buildDecrypt.Fn = &Fn;
        buildDecrypt.InsertBefore = BI;
        buildDecrypt.LoadTy = PointerType::getUnqual(Ctx);
        buildDecrypt.ModulePageTable = &BBPageTable;
        buildDecrypt.FuncPageTable = &FuncBBPageTable;
        buildDecrypt.ModuleKey = BBKeys[AddrTBB];
        buildDecrypt.FuncKey = FuncKeys[AddrTBB];
        buildDecrypt.PtrEncKey = PtrEncKey;
        // L2+: match IndirectCall's nonce mixing, MBA index decrypt,
        // and branch target verification.
        buildDecrypt.RuntimeSeed = opt.level() > 1 ? RNG() : 0;
        buildDecrypt.UseMBA = opt.level() > 1;
        buildDecrypt.IntegrityCheck = opt.level() > 1;
        Triple T(M.getTargetTriple());
        buildDecrypt.PtrAuthKey = T.isAArch64() ? 0 : -1;
        buildDecrypt.PtrAuthDisc = 0;

        auto            TargetPtr = buildPageTableDecryptIR(buildDecrypt);
        IndirectBrInst *IBI = IndirectBrInst::Create(TargetPtr, 2);
        ReplaceInstWithInst(BI, IBI);
        IBI->addDestination(TBB);
        IBI->addDestination(FBB);

        RunOnFuncChanged = true;
      }
    }

    return true;
  }

  bool doFinalization(Module &M) override {
    if (!RunOnFuncChanged || BBPageTable.empty()) {
      return false;
    }
    for (auto bbPage : BBPageTable) {
      appendToCompilerUsed(M, {bbPage});
    }
    return true;
  }

};
} // anonymous namespace

char IndirectBranch::ID = 0;

FunctionPass *llvm::createIndirectBranchPass(ObfuscationOptions *argsOptions) {
  return new IndirectBranch(argsOptions);
}

INITIALIZE_PASS(IndirectBranch, "indbr",
                "Enable IR Indirect Branch Obfuscation", false, false)
