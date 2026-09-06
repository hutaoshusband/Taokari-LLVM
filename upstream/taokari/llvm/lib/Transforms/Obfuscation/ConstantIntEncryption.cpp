#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscation/ConstantIntEncryption.h"
#include "llvm/Transforms/Obfuscation/Utils.h"
#include "llvm/Transforms/Utils/GlobalStatus.h"
#include "llvm/Transforms/IPO/Attributor.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Support/RandomNumberGenerator.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallPtrSet.h"
#include <algorithm>

#define DEBUG_TYPE "constant-int-encryption"

using namespace llvm;

namespace {
static cl::opt<bool> CIENoDedup(
    "taokari-cie-no-dedup", cl::init(false), cl::NotHidden,
    cl::desc("Per-use decrypt: skip the entry-block dedup cache so every use "
             "of a constant gets its own decrypt sequence. More resilient "
             "(no shared slot to patch) at the cost of larger code."));

struct ConstantIntEncryption : public FunctionPass {
  static char         ID;
  ObfuscationOptions *ArgsOptions;

  DenseMap<Function *, SmallPtrSet<Instruction *, 16>> FunctionModifyIRs;
  std::mt19937_64                                      RNG;

  ConstantIntEncryption(ObfuscationOptions *argsOptions) : FunctionPass(ID) {
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
    return "ConstantIntEncryption";
  }

  bool doInitialization(Module &M) override {
    bool Changed = false;
    for (auto &F : M) {
      if (F.hasPersonalityFn() || isTaokariGeneratedHelper(F))
        continue;
      const auto opt = ArgsOptions->toObfuscate(ArgsOptions->cieOpt(), &F);
      if (!opt.isEnabled()) {
        continue;
      }
      // Effective minimum constant width: built-in floor (8 bits) raised by
      // the user-configured minConstSize. Narrower constants are skipped.
      const unsigned MinBits = std::max(8u, opt.minConstSize());
      Changed |= expandConstantExpr(F);
      for (auto &BB : F) {
        for (auto &I : BB) {
          if (I.hasMetadata("noobf")) {
            continue;
          }
          if (I.isEHPad() || isa<AllocaInst>(&I) ||
              isa<IntrinsicInst>(&I) || isa<SwitchInst>(I) ||
              I.isAtomic()) {
            continue;
          }
          auto CI = dyn_cast<CallInst>(&I);
          auto GEP = dyn_cast<GetElementPtrInst>(&I);
          auto PHI = dyn_cast<PHINode>(&I);

          for (unsigned i = 0; i < (PHI
                                      ? PHI->getNumIncomingValues()
                                      : I.getNumOperands()); ++i) {
            if (CI && CI->isBundleOperand(i)) {
              continue;
            }
            if (GEP && (i < 2 || GEP->getSourceElementType()->isStructTy())) {
              continue;
            }
            if (PHI && isa<SwitchInst>(
                    PHI->getIncomingBlock(i)->getTerminator())) {
              continue;
            }
            Value *Opr = PHI ? PHI->getIncomingValue(i) : I.getOperand(i);
            auto   CTI = dyn_cast<ConstantInt>(Opr);
            if (CTI && CTI->getBitWidth() >= MinBits) {
              FunctionModifyIRs[&F].insert(&I);
              break;
            }
          }
        }
      }
    }
    return Changed;
  }

  bool runOnFunction(Function &F) override {
    const auto opt = ArgsOptions->toObfuscate(ArgsOptions->cieOpt(), &F);
    if (!opt.isEnabled()) {
      return false;
    }
    auto &FuncModifyIRs = FunctionModifyIRs[&F];
    if (FuncModifyIRs.empty()) {
      return false;
    }
    const unsigned MinBits = std::max(8u, opt.minConstSize());
    // The runtime (volatile) seed is read into a stack-local nonce each call.
    // Across a setjmp/longjmp boundary the nonce can change, so a constant
    // decrypted before setjmp is re-decrypted with a different seed after
    // longjmp returns -> wrong value (often a bad page-table index -> crash).
    // Functions that call a returnsTwice function (setjmp/getcontext) must use
    // a static seed instead.
    const bool CallsReturnsTwice = functionParticipatesInNonLocalJump(F);
    const bool UseRuntimeSeed = opt.level() >= 2 && !CallsReturnsTwice;
    AllocaInst *SeedCache = UseRuntimeSeed
                                 ? createConstantSeedCache(F, RNG,
                                                           opt.volatileSeed())
                                 : nullptr;

    const bool UsePool =
        opt.constPerFunctionPool() || opt.level() >= 3;
    const bool UseShards =
        UsePool && (opt.constHelperShards() || opt.level() >= 3);
    struct PoolEntry {
      Constant *Enc;
      ConstantInt *Key;
      Constant *XorKey;
      unsigned BitWidth;
      unsigned Offset;
      Function *Shard = nullptr;
    };
    DenseMap<ConstantInt *, PoolEntry> Pool;
    GlobalVariable *PoolGV = nullptr;
    if (UsePool) {
      auto collectTarget = [&](ConstantInt *CTI) -> PoolEntry * {
        auto It = Pool.find(CTI);
        if (It != Pool.end())
          return &It->second;
        auto *IntTy = cast<IntegerType>(CTI->getType());
        unsigned BW = IntTy->getBitWidth();
        auto *Key = ConstantInt::get(IntTy, RNG());
        auto *PlainCast = ConstantExpr::getBitCast(CTI, IntTy);
        Constant *Enc = ConstantExpr::getSub(PlainCast, Key);
        Constant *XorKey = nullptr;
        if (opt.level()) {
          XorKey = ConstantInt::get(IntTy, RNG());
          Enc = ConstantExpr::getXor(Enc, XorKey);
          if (opt.level() > 1)
            Enc = ConstantExpr::getXor(
                Enc, ConstantExpr::get(Instruction::Add, XorKey, Key));
          if (opt.level() > 2)
            Enc = ConstantExpr::getXor(Enc, ConstantExpr::getNeg(XorKey));
        }
        auto Result = Pool.try_emplace(CTI, PoolEntry{Enc, Key, XorKey, BW, 0});
        return &Result.first->second;
      };

      SmallVector<Constant *, 32> PoolBytes;
      unsigned Offset = 0;
      for (auto I : FuncModifyIRs) {
        if (I->hasMetadata("noobf"))
          continue;
        auto *CI = dyn_cast<CallInst>(I);
        auto *GEP = dyn_cast<GetElementPtrInst>(I);
        auto *PHI = dyn_cast<PHINode>(I);
        for (unsigned i = 0; i < I->getNumOperands(); ++i) {
          if (CI && CI->isBundleOperand(i))
            continue;
          if (GEP && i < 2)
            continue;
          auto *CTI = dyn_cast<ConstantInt>(I->getOperand(i));
          if (!CTI || CTI->getBitWidth() < MinBits)
            continue;
          if (PHI && isa<SwitchInst>(
                          PHI->getIncomingBlock(i)->getTerminator()))
            continue;
          PoolEntry *E = collectTarget(CTI);
          (void)E;
        }
      }

      for (auto &KV : Pool) {
        PoolEntry &E = KV.second;
        E.Offset = Offset;
        unsigned ByteCount = (E.BitWidth + 7) / 8;
        auto *ByteTy = Type::getInt8Ty(F.getContext());
        const APInt &V = cast<ConstantInt>(E.Enc)->getValue();
        APInt VBytes = V.zext(ByteCount * 8);
        for (unsigned B = 0; B < ByteCount; ++B)
          PoolBytes.push_back(ConstantInt::get(
              ByteTy, (uint8_t)VBytes.extractBitsAsZExtValue(8, 8 * B)));
        Offset += ByteCount;
      }
      if (!PoolBytes.empty()) {
        auto *ByteTy = Type::getInt8Ty(F.getContext());
        auto *PoolArr = ConstantArray::get(
            ArrayType::get(ByteTy, PoolBytes.size()), PoolBytes);
        PoolGV = new GlobalVariable(*F.getParent(), PoolArr->getType(), true,
                                    GlobalValue::PrivateLinkage, PoolArr,
                                    F.getName() + ".cie.pool");
        PoolGV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
        PoolGV->addMetadata("noobf", *MDNode::get(F.getContext(), {}));
      }
    }

    const bool UsePageTableRef =
        PoolGV && (opt.constPageTableRef() || opt.level() >= 4) &&
        !CallsReturnsTwice;
    const bool UseIndirectRef =
        PoolGV && (opt.constIndirectPoolRef() || opt.level() >= 3) &&
        !CallsReturnsTwice && !UsePageTableRef;
    GlobalVariable *PoolRefGV = nullptr;
    if (UseIndirectRef) {
      auto *PtrTy = PointerType::getUnqual(F.getContext());
      PoolRefGV = new GlobalVariable(*F.getParent(), PtrTy, false,
                                     GlobalValue::PrivateLinkage, PoolGV,
                                     F.getName() + ".cie.pool.ref");
      PoolRefGV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
      PoolRefGV->addMetadata("noobf", *MDNode::get(F.getContext(), {}));
    }

    SmallVector<GlobalVariable *, 8> PoolPageTable;
    DenseMap<Constant *, unsigned> PoolPageIndex;
    DenseMap<Constant *, uint64_t> PoolPageKeys;
    uint64_t PoolPtrEncKey = 0;
    if (UsePageTableRef) {
      std::vector<Constant *> PoolObjs{PoolGV};
      PoolPageKeys[PoolGV] = RNG();
      PoolPtrEncKey = RNG();
      CreatePageTableArgs PTA{};
      PTA.CountLoop = choosePageTableDepth(RNG, opt.level());
      PTA.GVNamePrefix = F.getName().str() + ".cie.pt";
      PTA.RNG = &RNG;
      PTA.M = F.getParent();
      PTA.Objects = &PoolObjs;
      PTA.IndexMap = &PoolPageIndex;
      PTA.ObjectKeys = &PoolPageKeys;
      PTA.OutPageTable = &PoolPageTable;
      PTA.PtrEncKey = PoolPtrEncKey;
      PTA.FakeEntries = chooseFakeEntryCount(RNG, 1);
      createPageTable(PTA);
      for (GlobalVariable *GV : PoolPageTable)
        appendToCompilerUsed(*F.getParent(), {GV});
    }

    auto resolvePoolBase = [&](IRBuilder<NoFolder> &B, Function *Host,
                               Instruction *InsertBefore) -> Value * {
      if (UsePageTableRef && !PoolPageTable.empty()) {
        BuildDecryptArgs BDA{};
        BDA.FuncLoopCount = 0;
        BDA.NextIndex = PoolPageIndex[PoolGV];
        BDA.NextIndexValue = nullptr;
        BDA.Fn = Host;
        BDA.InsertBefore = InsertBefore;
        BDA.LoadTy = PointerType::getUnqual(Host->getContext());
        BDA.ModulePageTable = &PoolPageTable;
        BDA.FuncPageTable = &PoolPageTable;
        BDA.ModuleKey = PoolPageKeys[PoolGV];
        BDA.FuncKey = 0;
        BDA.PtrEncKey = PoolPtrEncKey;
        BDA.RuntimeSeed = 0;
        BDA.UseMBA = false;
        BDA.IntegrityCheck = false;
        BDA.PtrAuthKey = -1;
        BDA.PtrAuthDisc = 0;
        return buildPageTableDecryptIR(BDA);
      }
      if (PoolRefGV) {
        return B.CreateAlignedLoad(
            PointerType::getUnqual(Host->getContext()), PoolRefGV, Align{1},
            true,
            Host == &F ? "cie.pool.ref.ld" : "cie.shard.ref.ld");
      }
      return PoolGV;
    };

    // Every pool-base decode chain here derives from one input tuple, so emit
    // it once at entry; shards take the resolved base as an argument.
    Value *PoolBaseSlot = nullptr;
    if (UsePageTableRef && !PoolPageTable.empty() && !CIENoDedup) {
      auto *BaseTy = PointerType::getUnqual(F.getContext());
      auto &EntryBB = F.getEntryBlock();
      IRBuilder<NoFolder> AIB(&*EntryBB.begin());
      PoolBaseSlot = AIB.CreateAlloca(BaseTy, nullptr);
      Instruction *DecryptPt = nullptr;
      for (auto &I : EntryBB) {
        if (!isa<AllocaInst>(&I)) {
          DecryptPt = &I;
          break;
        }
      }
      if (!DecryptPt)
        DecryptPt = EntryBB.getTerminator();
      IRBuilder<NoFolder> IRB(DecryptPt);
      Value *Base = resolvePoolBase(IRB, &F, DecryptPt);
      IRB.CreateAlignedStore(Base, PoolBaseSlot, Align{1}, true);
    }

    if (UseShards && PoolGV) {
      auto *I64 = Type::getInt64Ty(F.getContext());
      auto *BaseTy = PointerType::getUnqual(F.getContext());
      auto *ShardFTy = PoolBaseSlot
                           ? FunctionType::get(I64, {BaseTy}, false)
                           : FunctionType::get(I64, false);
      unsigned ShardIdx = 0;
      for (auto &KV : Pool) {
        PoolEntry &E = KV.second;
        auto *Shard = Function::Create(
            ShardFTy, GlobalValue::InternalLinkage,
            F.getName() + ".cie.shard." + Twine(ShardIdx++), F.getParent());
        Shard->addFnAttr(Attribute::NoInline);
        Shard->addMetadata("noobf", *MDNode::get(F.getContext(), {}));
        auto *BB = BasicBlock::Create(F.getContext(), "entry", Shard);
        IRBuilder<NoFolder> SIRB(BB);
        SIRB.CreateRet(ConstantInt::get(I64, 0));
        Instruction *Ret = BB->getTerminator();

        IRBuilder<NoFolder> B(Ret);
        Value *PoolBase = PoolBaseSlot ? &*Shard->arg_begin()
                                       : resolvePoolBase(B, Shard, Ret);
        auto *I8 = Type::getInt8Ty(F.getContext());
        Value *BytePtr = B.CreateInBoundsGEP(
            ArrayType::get(I8, 1), PoolBase,
            {ConstantInt::get(Type::getInt32Ty(F.getContext()), 0),
             ConstantInt::get(Type::getInt32Ty(F.getContext()), E.Offset)},
            "cie.shard.ptr");
        auto *LoadTy = IntegerType::get(F.getContext(), E.BitWidth);
        auto *PoolLoad = B.CreateAlignedLoad(LoadTy, BytePtr, Align{1}, true,
                                             "cie.shard.ld");
        Value *Dec = decryptConstantCipher(
            PoolLoad, E.Key, E.XorKey, E.BitWidth, LoadTy, Ret, RNG,
            opt.level(), nullptr, opt.volatileSeed(),
            opt.constDecryptorMBA());
        Value *RetVal = Dec;
        if (E.BitWidth < 64) {
          RetVal = B.CreateZExt(Dec, I64, "cie.shard.zext");
        } else if (E.BitWidth > 64) {
          RetVal = B.CreateTrunc(Dec, I64, "cie.shard.trunc");
        }
        cast<ReturnInst>(Ret)->setOperand(0, RetVal);
        E.Shard = Shard;
      }
    }

    // Count constant occurrences for deduplication
    DenseMap<ConstantInt *, unsigned> ConstUseCount;
    for (auto I : FuncModifyIRs) {
      if (I->hasMetadata("noobf"))
        continue;
      auto CI = dyn_cast<CallInst>(I);
      auto GEP = dyn_cast<GetElementPtrInst>(I);
      auto PHI = dyn_cast<PHINode>(I);
      for (unsigned i = 0; i < I->getNumOperands(); ++i) {
        if (CI && CI->isBundleOperand(i))
          continue;
        if (GEP && i < 2)
          continue;
        if (auto CTI = dyn_cast<ConstantInt>(I->getOperand(i))) {
          if (CTI->getBitWidth() < MinBits)
            continue;
          if (PHI &&
              isa<SwitchInst>(PHI->getIncomingBlock(i)->getTerminator()))
            continue;
          ConstUseCount[CTI]++;
        }
      }
    }

    // Pre-encrypt duplicate constants at function entry to avoid
    // creating redundant GlobalVariables and decrypt sequences
    DenseMap<ConstantInt *, AllocaInst *> DedupCache;
    if (!UsePool) {
    auto &EntryBB = F.getEntryBlock();
    Instruction *AllocaInsertPt = &*EntryBB.begin();
    for (auto &KV : ConstUseCount) {
      // Per-use decrypt option: skip the dedup cache entirely so every use
      // gets its own decrypt (no shared slot a reverser can patch once).
      if (CIENoDedup || KV.second <= 1)
        continue;
      auto *CTI = KV.first;
      auto *Ty = CTI->getType();
      auto BitWidth = Ty->getPrimitiveSizeInBits().getFixedValue();
      if (BitWidth < MinBits)
        continue;
      IRBuilder<NoFolder> AIB(AllocaInsertPt);
      DedupCache[CTI] = AIB.CreateAlloca(Ty, nullptr);
    }

    if (!DedupCache.empty()) {
      Instruction *DecryptPt = nullptr;
      for (auto &I : EntryBB) {
        if (!isa<AllocaInst>(&I)) {
          DecryptPt = &I;
          break;
        }
      }
      if (!DecryptPt)
        DecryptPt = EntryBB.getTerminator();
      for (auto &KV : DedupCache) {
        Value *Dec = encryptConstant(KV.first, DecryptPt, RNG, opt.level(),
                                     SeedCache, opt.volatileSeed(),
                                     opt.constDecryptorMBA());
        IRBuilder<NoFolder> SIB(DecryptPt);
        auto *Store = SIB.CreateAlignedStore(Dec, KV.second, Align{1}, true);
        Store->setMetadata("noobf", MDNode::get(F.getContext(), {}));
      }
    }
    }

    for (auto I : FuncModifyIRs) {
      if (I->hasMetadata("noobf"))
        continue;
      auto CI = dyn_cast<CallInst>(I);
      auto GEP = dyn_cast<GetElementPtrInst>(I);
      auto PHI = dyn_cast<PHINode>(I);

      for (unsigned i = 0; i < I->getNumOperands(); ++i) {
        if (CI && CI->isBundleOperand(i)) {
          continue;
        }
        if (GEP && i < 2) {
          continue;
        }
        Value *Opr = I->getOperand(i);
        if (auto CTI = dyn_cast<ConstantInt>(Opr)) {
          if (CTI->getBitWidth() < MinBits) {
            continue;
          }
          if (PHI && isa<
                SwitchInst>(PHI->getIncomingBlock(i)->getTerminator())) {
            continue;
          }

          auto InsertPoint =
              PHI ? PHI->getIncomingBlock(i)->getTerminator() : I;
          Value *CipherConstant;
          if (UsePool && PoolGV) {
            auto &Entry = Pool[CTI];
            auto *IntTy = cast<IntegerType>(CTI->getType());
            IRBuilder<NoFolder> IRB(InsertPoint);
            if (Entry.Shard) {
              Value *BaseLd = nullptr;
              if (PoolBaseSlot)
                BaseLd = IRB.CreateAlignedLoad(
                    PointerType::getUnqual(F.getContext()), PoolBaseSlot,
                    Align{1}, true);
              auto *Call = IRB.CreateCall(
                  Entry.Shard,
                  BaseLd ? ArrayRef<Value *>{BaseLd} : ArrayRef<Value *>{},
                  "cie.shard.call");
              if (IntTy->getBitWidth() < 64) {
                CipherConstant =
                    IRB.CreateTrunc(Call, IntTy, "cie.shard.trunc");
              } else if (IntTy->getBitWidth() > 64) {
                CipherConstant =
                    IRB.CreateZExt(Call, IntTy, "cie.shard.zext");
              } else {
                CipherConstant = Call;
              }
            } else {
            auto *I8 = Type::getInt8Ty(F.getContext());
            Value *PoolBase =
                PoolBaseSlot
                    ? IRB.CreateAlignedLoad(PointerType::getUnqual(F.getContext()),
                                            PoolBaseSlot, Align{1}, true)
                    : resolvePoolBase(IRB, &F, InsertPoint);
            Value *BytePtr = IRB.CreateInBoundsGEP(
                ArrayType::get(I8, 1), PoolBase,
                {ConstantInt::get(Type::getInt32Ty(F.getContext()), 0),
                 ConstantInt::get(Type::getInt32Ty(F.getContext()),
                                  Entry.Offset)},
                "cie.pool.ptr");
            auto *PoolLoad = IRB.CreateAlignedLoad(IntTy, BytePtr,
                                                  Align{1}, true,
                                                  "cie.pool.ld");
            CipherConstant = decryptConstantCipher(
                PoolLoad, Entry.Key, Entry.XorKey, Entry.BitWidth,
                CTI->getType(), InsertPoint, RNG, opt.level(), SeedCache,
                opt.volatileSeed(), opt.constDecryptorMBA());
            }
          } else {
            auto CacheIt = DedupCache.find(CTI);
            if (CacheIt != DedupCache.end()) {
              IRBuilder<NoFolder> IRB(InsertPoint);
              CipherConstant = IRB.CreateAlignedLoad(
                  CTI->getType(), CacheIt->second, Align{1}, true);
            } else {
              CipherConstant = encryptConstant(CTI, InsertPoint, RNG,
                                               opt.level(), SeedCache,
                                               opt.volatileSeed(),
                                               opt.constDecryptorMBA());
            }
          }
          if (PHI)
            PHI->setIncomingValue(i, CipherConstant);
          else
            I->setOperand(i, CipherConstant);
        }
      }
    }
    return true;
  }
};
} // anonymous namespace

char ConstantIntEncryption::ID = 0;

FunctionPass *llvm::createConstantIntEncryptionPass(
    ObfuscationOptions *argsOptions) {
  return new ConstantIntEncryption(argsOptions);
}

INITIALIZE_PASS(ConstantIntEncryption, "cie",
                "Enable IR Constant Integer Encryption", false, false)
