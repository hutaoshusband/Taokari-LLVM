#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Transforms/Obfuscation/IndirectGlobalVariable.h"
#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscation/Utils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/IR/Module.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/APInt.h"
#include "llvm/Support/RandomNumberGenerator.h"
#include "llvm/Support/CommandLine.h"

#include <random>

#define DEBUG_TYPE "indgv"

using namespace llvm;

static cl::opt<uint32_t> IndGvMinSize(
    "taokari-indgv-min-size", cl::init(0), cl::NotHidden,
    cl::desc("Only indirect globals whose storage is at least this many bytes. "
             "0 = all eligible globals. Skips low-value small globals so the "
             "page-table cost lands on the sensitive (larger) ones."));
static cl::opt<bool> IndGvNoDedup(
    "taokari-indgv-no-dedup", cl::init(false), cl::NotHidden,
    cl::desc("Per-use global decrypt: skip the entry-block dedup cache so "
             "every access to a global gets its own decrypt sequence. More "
             "resilient (no shared slot to patch) at the cost of larger code."));

namespace {
struct IndirectGlobalVariable : public FunctionPass {
  static char         ID;
  ObfuscationOptions *ArgsOptions;

  DenseMap<Function *, SmallPtrSet<GlobalVariable *, 8>> FunctionGVs;

  std::vector<Constant *>          GlobalVariables;
  DenseMap<Constant *, unsigned>   GVIndex;
  DenseMap<Constant *, uint64_t>   GVKeys;
  SmallVector<GlobalVariable *, 8> GVPageTable;
  GlobalVariable *                 GVObjectShareTable = nullptr;
  SmallPtrSet<GlobalVariable *, 16> CseStringGVs;

  std::mt19937_64 RNG;
  uint64_t        PtrEncKey = 0;
  // Module-seeded PAC discriminator material (AArch64 only; mirrors icall).
  uint64_t        ModulePacSeed = 0;
  uint64_t        ModulePacSalt = 0;
  bool            RunOnFuncChanged = false;

  IndirectGlobalVariable(ObfuscationOptions *argsOptions) : FunctionPass(ID) {
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
    return {"IndirectGlobalVariable"};
  }

  uint64_t nextNonZeroKey() {
    uint64_t K = RNG();
    while (!K)
      K = RNG();
    return K;
  }

  // Per-global PAC discriminator (AArch64 only). Mixes the module seed, the
  // global's page-table key, and a name hash so each global gets a distinct
  // signing context -- a signed pointer forged for one global does not
  // authenticate for another.
  uint64_t pacDiscriminator(Function &Fn, GlobalVariable *GV) const {
    uint64_t H = ModulePacSeed ^ GVKeys.lookup(GV);
    H ^= static_cast<uint64_t>(hash_value(GV->getName())) << 1;
    H ^= ModulePacSalt;
    return H ? H : ModulePacSalt;
  }

  void NumberGlobalVariable(Module &M) {
    for (auto &F : M) {
      if (F.isIntrinsic()) {
        continue;
      }
      LowerConstantExpr(F);
      for (inst_iterator I = inst_begin(F), E = inst_end(F); I != E; ++I) {
        Instruction *Inst = &*I;

        if (Inst->isEHPad() || isa<CallInst>(Inst)) {
          continue;
        }

        for (auto op = Inst->op_begin(); op != Inst->op_end(); ++op) {
          Value *val = *op;
          if (auto GV = dyn_cast<GlobalVariable>(val)) {
            if (GV->isThreadLocal() || GV->isDLLImportDependent()) {
              continue;
            }
            if (GV->getMetadata("noobf")) {
              continue;
            }
            if (GV->hasName()) {
              StringRef N = GV->getName();
              if (N.starts_with("_ZTV") || N.starts_with("_ZTI") ||
                  N.starts_with("_ZTS"))
                continue;
            }
            if (CseStringGVs.count(GV))
              continue; //cse owns string globals; indgv decode would split identity
            // Sensitive-globals filter: skip globals smaller than the
            // configured threshold so the page-table cost lands on the larger
            // (more interesting) globals, not low-value single-byte flags.
            if (IndGvMinSize) {
              uint64_t Sz = M.getDataLayout().getTypeAllocSize(
                  GV->getValueType());
              if (Sz < IndGvMinSize)
                continue;
            }

            FunctionGVs[&F].insert(GV);
            if (GVKeys.count(GV) == 0) {
              GlobalVariables.push_back(GV);
              GVKeys[GV] = RNG();
            }
          }
        }
      }
    }
  }

  bool doInitialization(Module &M) override {
    GVIndex.clear();
    GVPageTable.clear();
    GVObjectShareTable = nullptr;
    FunctionGVs.clear();
    GlobalVariables.clear();
    GVKeys.clear();
    CseStringGVs.clear();

    if (ArgsOptions->cseOpt()->isEnabled()) {
      for (GlobalVariable &GV : M.globals()) {
        if (!GV.isConstant() || !GV.hasInitializer() ||
            GV.hasDLLExportStorageClass() || GV.isDLLImportDependent()) {
          continue;
        }
        auto *CDS = dyn_cast<ConstantDataSequential>(GV.getInitializer());
        if (!CDS || !(CDS->isCString() ||
                      CDS->getElementType()->isIntegerTy(16))) {
          continue;
        }
        CseStringGVs.insert(&GV);
        collectConstantStringUser(&GV, CseStringGVs);
      }
    }

    NumberGlobalVariable(M);
    if (GlobalVariables.empty()) {
      return false;
    }

    PtrEncKey = RNG();
    ModulePacSeed = nextNonZeroKey();
    ModulePacSalt = nextNonZeroKey();

    CreatePageTableArgs createPageTableArgs;
    createPageTableArgs.CountLoop = chooseModulePageTableDepth(RNG);
    createPageTableArgs.GVNamePrefix = M.getName().str() + "_IndirectGVs";
    createPageTableArgs.RNG = &RNG;
    createPageTableArgs.M = &M;
    createPageTableArgs.Objects = &GlobalVariables;
    createPageTableArgs.IndexMap = &GVIndex;
    createPageTableArgs.ObjectKeys = &GVKeys;
    createPageTableArgs.OutPageTable = &GVPageTable;
    createPageTableArgs.PtrEncKey = PtrEncKey;
    // L2+: pad with a per-build decoy count so table size does not expose
    // a fixed real-global ratio.
    createPageTableArgs.FakeEntries = chooseFakeEntryCount(
        RNG, static_cast<unsigned>(GlobalVariables.size()));
    if (ArgsOptions->indGvOpt()->level() > 1) {
      createPageTableArgs.TwoShare = true;
      createPageTableArgs.OutObjectShareTable = &GVObjectShareTable;
    }

    createPageTable(createPageTableArgs);

    // L3+: emit entirely separate decoy global pools -- private internal
    // arrays of random bytes that look like real data storage but are never
    // referenced by real code. They pollute the global-variable view so a
    // reverser cannot tell the real globals from the decoys by listing them.
    if (ArgsOptions->indGvOpt()->level() >= 3) {
      auto &Ctx = M.getContext();
      auto *I64 = Type::getInt64Ty(Ctx);
      unsigned Pools = 1 + (RNG() % 3);
      for (unsigned P = 0; P < Pools; ++P) {
        unsigned Words = 2 + (RNG() % 4);
        SmallVector<Constant *, 8> Vals;
        for (unsigned W = 0; W < Words; ++W)
          Vals.push_back(ConstantInt::get(I64, RNG()));
        auto *ArrTy = ArrayType::get(I64, Words);
        auto *Pool = new GlobalVariable(M, ArrTy, true,
                                        GlobalValue::PrivateLinkage,
                                        ConstantArray::get(ArrTy, Vals),
                                        M.getName() + "_IndirectGV_fakepool");
        Pool->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
        Pool->setAlignment(Align(8));
        Pool->addMetadata("noobf", *MDNode::get(Ctx, {}));
        appendToCompilerUsed(M, {Pool});
      }
    }
    return false;
  }


  bool runOnFunction(Function &Fn) override {
    const auto opt = ArgsOptions->toObfuscate(ArgsOptions->indGvOpt(), &Fn);
    if (!opt.isEnabled()) {
      return false;
    }
    if (functionIsStdOrEhRuntime(Fn) || functionParticipatesInNonLocalJump(Fn))
      return false;

    auto &M = *Fn.getParent();

    if (GlobalVariables.empty()) {
      return false;
    }

    auto &FuncGVSet = FunctionGVs[&Fn];
    if (FuncGVSet.empty()) {
      return false;
    }

    std::vector<Constant *>        FuncGVs;
    DenseMap<Constant *, uint64_t> FuncKeys;
    for (auto GV : FuncGVSet) {
      FuncGVs.push_back(GV);
      FuncKeys[GV] = RNG();
    }

    SmallVector<GlobalVariable *, 8> FuncGVPageTable;
    DenseMap<Constant *, unsigned>   FuncGVIndex;
    unsigned                         FuncPageDepth = 0;

    if (opt.level()) {
      FuncPageDepth = choosePageTableDepth(RNG, opt.level());
      CreatePageTableArgs createPageTableArgs;
      createPageTableArgs.CountLoop = FuncPageDepth;
      createPageTableArgs.GVNamePrefix =
          M.getName().str() + Fn.getName().str() + "_IndirectGVs";
      createPageTableArgs.RNG = &RNG;
      createPageTableArgs.M = &M;
      createPageTableArgs.Objects = &FuncGVs;
      createPageTableArgs.IndexMap = &GVIndex;
      createPageTableArgs.ObjectKeys = &FuncKeys;
      createPageTableArgs.OutPageTable = &FuncGVPageTable;

      enhancedPageTable(createPageTableArgs, &FuncGVIndex);
    }

    // Count GV references for deduplication
    DenseMap<GlobalVariable *, unsigned> GVUseCount;
    for (inst_iterator I = inst_begin(Fn), E = inst_end(Fn); I != E; ++I) {
      Instruction *Inst = &*I;
      if (isa<CallInst>(Inst) || isa<CatchReturnInst>(Inst) ||
          isa<ResumeInst>(Inst) || Inst->isEHPad())
        continue;
      for (unsigned i = 0; i < Inst->getNumOperands(); ++i) {
        if (auto *GV = dyn_cast<GlobalVariable>(Inst->getOperand(i))) {
          if (GVIndex.count(GV))
            GVUseCount[GV]++;
        }
      }
    }

    // Pre-decrypt duplicate GVs at function entry
    DenseMap<GlobalVariable *, AllocaInst *> GVDedupCache;
    auto &EntryBB = Fn.getEntryBlock();
    Instruction *AllocaInsertPt = &*EntryBB.begin();
    auto *PtrTy = PointerType::getUnqual(Fn.getContext());
    for (auto &KV : GVUseCount) {
      // Per-use decrypt option: skip the dedup cache so every global access
      // gets its own decrypt (no shared slot a reverser can patch once).
      if (IndGvNoDedup || KV.second <= 1)
        continue;
      IRBuilder<> AIB(AllocaInsertPt);
      GVDedupCache[KV.first] = AIB.CreateAlloca(PtrTy, nullptr);
    }

    if (!GVDedupCache.empty()) {
      Instruction *DecryptPt = nullptr;
      for (auto &I : EntryBB) {
        if (!isa<AllocaInst>(&I)) {
          DecryptPt = &I;
          break;
        }
      }
      if (!DecryptPt)
        DecryptPt = EntryBB.getTerminator();
      for (auto &KV : GVDedupCache) {
        auto *           GV = KV.first;
        BuildDecryptArgs buildDecrypt;
        buildDecrypt.FuncLoopCount = FuncPageDepth;
        buildDecrypt.NextIndex = opt.level() ? FuncGVIndex[GV] : GVIndex[GV];
        buildDecrypt.NextIndexValue = nullptr;
        buildDecrypt.Fn = &Fn;
        buildDecrypt.InsertBefore = DecryptPt;
        buildDecrypt.LoadTy = GV->getType();
        buildDecrypt.ModulePageTable = &GVPageTable;
        buildDecrypt.FuncPageTable = &FuncGVPageTable;
        buildDecrypt.ModuleKey = GVKeys[GV];
        buildDecrypt.FuncKey = FuncKeys[GV];
        buildDecrypt.PtrEncKey = PtrEncKey;
        buildDecrypt.ObjectShareTable = GVObjectShareTable;
        buildDecrypt.RuntimeSeed = opt.level() > 1 ? RNG() : 0;
        buildDecrypt.UseMBA = opt.level() > 1;
        buildDecrypt.IntegrityCheck = opt.level() > 1;
        buildDecrypt.PtrAuthKey = targetHasPAuth(Fn) ? 2 : -1;
        buildDecrypt.PtrAuthDisc = pacDiscriminator(Fn, GV);
        auto        GVPtr = buildPageTableDecryptIR(buildDecrypt);
        IRBuilder<> SIB(DecryptPt);
        SIB.CreateAlignedStore(GVPtr, KV.second, Align{1}, true);
      }
    }

    for (inst_iterator I = inst_begin(Fn), E = inst_end(Fn); I != E; ++I) {
      Instruction *Inst = &*I;
      if (isa<CallInst>(Inst) || isa<CatchReturnInst>(Inst) || isa<
            ResumeInst>(Inst) || Inst->isEHPad()) {
        continue;
      }

      for (unsigned i = 0; i < Inst->getNumOperands(); ++i) {
        if (GlobalVariable *GV = dyn_cast<
          GlobalVariable>(Inst->getOperand(i))) {
          if (!GVIndex.count(GV)) {
            continue;
          }

          auto PHI = dyn_cast<PHINode>(Inst);
          auto InsertPoint = PHI
                               ? PHI->getIncomingBlock(i)->getTerminator()
                               : Inst;

          Value *GVPtr;
          auto   CacheIt = GVDedupCache.find(GV);
          if (CacheIt != GVDedupCache.end()) {
            IRBuilder<> IRB(InsertPoint);
            GVPtr = IRB.CreateAlignedLoad(
                GV->getType(), CacheIt->second, Align{1}, true);
          } else {
            BuildDecryptArgs buildDecrypt;
            buildDecrypt.FuncLoopCount = FuncPageDepth;
            buildDecrypt.NextIndex =
                opt.level() ? FuncGVIndex[GV] : GVIndex[GV];
            buildDecrypt.NextIndexValue = nullptr;
            buildDecrypt.Fn = &Fn;
            buildDecrypt.InsertBefore = InsertPoint;
            buildDecrypt.LoadTy = GV->getType();
            buildDecrypt.ModulePageTable = &GVPageTable;
            buildDecrypt.FuncPageTable = &FuncGVPageTable;
            buildDecrypt.ModuleKey = GVKeys[GV];
            buildDecrypt.FuncKey = FuncKeys[GV];
            buildDecrypt.PtrEncKey = PtrEncKey;
            buildDecrypt.ObjectShareTable = GVObjectShareTable;
            buildDecrypt.PtrAuthKey = targetHasPAuth(Fn) ? 2 : -1;
            buildDecrypt.PtrAuthDisc = pacDiscriminator(Fn, GV);
            GVPtr = buildPageTableDecryptIR(buildDecrypt);
          }

          if (PHI)
            PHI->setIncomingValue(i, GVPtr);
          else
            Inst->replaceUsesOfWith(GV, GVPtr);
          RunOnFuncChanged = true;
        }
      }
    }

    return true;
  }

  bool doFinalization(Module &M) override {
    if (!RunOnFuncChanged || GVPageTable.empty()) {
      return false;
    }
    for (auto gvPage : GVPageTable) {
      appendToCompilerUsed(M, {gvPage});
    }
    if (GVObjectShareTable)
      appendToCompilerUsed(M, {GVObjectShareTable});
    return true;
  }

};
} // anonymous namespace

char IndirectGlobalVariable::ID = 0;

FunctionPass *llvm::createIndirectGlobalVariablePass(
    ObfuscationOptions *argsOptions) {
  return new IndirectGlobalVariable(argsOptions);
}

INITIALIZE_PASS(IndirectGlobalVariable, "indgv",
                "Enable IR Indirect Global Variable Obfuscation", false, false)
