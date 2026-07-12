#include "llvm/Transforms/Obfuscation/StringEncryption.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/Support/RandomNumberGenerator.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/Attributor.h"
#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscation/Utils.h"
#include "llvm/Transforms/Utils/GlobalStatus.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include <algorithm>
#include <limits>
#include <set>
#include <utility>

#define DEBUG_TYPE "string-encryption"

using namespace llvm;

// MBA addition helper lives in Utils.cpp (non-static so ConstantInt/FP and
// String decryptors all share one implementation). Forward-declared here to
// avoid pulling NoFolder into the public Utils.h header.
namespace llvm {
Value *buildMBAAdd(IRBuilder<NoFolder> &IRB, Value *A, Value *B,
                   const Twine &Name, uint64_t Salt);
} // namespace llvm

// Number of distinct decryptor loop shapes the polymorphic decryptor builder
// cycles through per build. Higher = more variance across builds, but each
// extra variant is a fresh private function that bloats the binary, so this
// stays small.
static constexpr unsigned DecryptorVariantCount = 4;

namespace {

// Mark an instruction/module-global as off-limits for downstream obfuscation
// passes. Mirrors the private helper used in Utils.cpp.
static void markNoObf(Value *V) {
  if (auto *I = dyn_cast<Instruction>(V))
    I->setMetadata("noobf", MDNode::get(I->getContext(), {}));
}

// CreateCall needs a FunctionType alongside the callee pointer when the callee
// is a plain Value (the indirect path). This wraps the lookup so call sites
// stay uniform: direct callee uses the FunctionCallee overload, indirect
// callee passes the function type explicitly.
static CallInst *createDecryptorCall(IRBuilder<> &IRB, Value *Callee,
                                     Function *DecFunc,
                                     ArrayRef<Value *> Args) {
  if (Callee == DecFunc)
    return IRB.CreateCall(DecFunc, Args);
  return IRB.CreateCall(DecFunc->getFunctionType(), Callee, Args);
}

static uint32_t deriveStringMix(uint32_t BuildNonce, unsigned Shift,
                                uint32_t Mask) {
  return ((BuildNonce >> Shift) & Mask) | 1u;
}

struct StringEncryption : public ModulePass {
  static char ID;

  struct CSPEntry {
    CSPEntry()
        : ID(0), Offset(0), EncGapBytes(0), DecGV(nullptr), DecStatus(nullptr),
          PendingStatus(0), DoneStatus(0), IsUTF16(false), PoolIndex(0) {}

    unsigned ID;
    unsigned Offset;
    unsigned EncGapBytes;
    GlobalVariable *DecGV;
    GlobalVariable *DecStatus; // is decrypted or not
    uint32_t PendingStatus;
    uint32_t DoneStatus;
    // for 8-bit strings
    std::vector<uint8_t> Data;
    std::vector<uint8_t> EncKey;
    // for 16-bit strings (UTF-16)
    bool IsUTF16;
    std::vector<uint16_t> Data16;
    std::vector<uint16_t> EncKey16;
    // L3: which shard pool this entry was emitted into.
    unsigned PoolIndex;
  };

  struct CSUser {
    CSUser(Type *ETy, GlobalVariable *User, GlobalVariable *NewGV)
        : Ty(ETy), GV(User), DecGV(NewGV), DecStatus(nullptr), PendingStatus(0),
          DoneStatus(0), InitFunc(nullptr) {}

    Type *Ty;
    GlobalVariable *GV;
    GlobalVariable *DecGV;
    GlobalVariable *DecStatus; // is decrypted or not
    uint32_t PendingStatus;
    uint32_t DoneStatus;
    Function *InitFunc; // InitFunc will use decryted string to initialize DecGV
  };

  ObfuscationOptions *ArgsOptions;
  std::mt19937_64 RNG;
  std::vector<CSPEntry *> ConstantStringPool;
  DenseMap<GlobalVariable *, CSPEntry *> CSPEntryMap;
  DenseMap<GlobalVariable *, CSUser *> CSUserMap;
  // L3: the encrypted pool may be split across multiple globals.
  SmallVector<GlobalVariable *, 4> EncryptedStringTables;
  GlobalVariable *EncryptedStringTable = nullptr; // backwards-compat single
  // L3: page-table indirection over the pool globals (stringPageTableAccess).
  SmallVector<GlobalVariable *, 4> PoolPageTable;
  DenseMap<Constant *, unsigned> PoolPageIndex;
  DenseMap<Constant *, uint64_t> PoolPageKeys;
  uint64_t PoolPtrEncKey = 0;
  // L3: opaque callee slots (stringDecryptorIndirectCall).
  DenseMap<Function *, GlobalVariable *> DecryptorSlots;
  Function *SharedDecFuncI8 = nullptr;
  Function *SharedDecFuncI16 = nullptr;
  Function *SharedScrubFuncI8 = nullptr;
  Function *SharedScrubFuncI16 = nullptr;
  std::set<GlobalVariable *> MaybeDeadGlobalVars;
  uint32_t BuildNonce = 0;
  // L3 fortress knobs resolved once per module (cse level >= 3).
  bool UseDecryptorMBA = false;
  bool UseDecryptorFlattening = false;
  bool UseDecryptorIndirectCall = false;
  bool UseShardedPool = false;
  bool UseFakePools = false;
  bool UsePageTableAccess = false;
  bool UseDelayedDecrypt = false;

  StringEncryption(ObfuscationOptions *argsOptions) : ModulePass(ID) {
    this->ArgsOptions = argsOptions;
    initializeStringEncryptionPass(*PassRegistry::getPassRegistry());
    uint64_t seed = 0;
    if (auto errorCode = llvm::getRandomBytes(&seed, sizeof(seed))) {
      llvm::report_fatal_error(
          StringRef("Failed to get random bytes for page table generation") +
          errorCode.message());
    }

    RNG = std::mt19937_64(seed);
  }

  bool doFinalization(Module &) override {
    for (CSPEntry *Entry : ConstantStringPool) {
      delete (Entry);
    }
    for (auto &I : CSUserMap) {
      CSUser *User = I.second;
      delete (User);
    }
    ConstantStringPool.clear();
    CSPEntryMap.clear();
    CSUserMap.clear();
    MaybeDeadGlobalVars.clear();
    return false;
  }

  StringRef getPassName() const override { return {"StringEncryption"}; }

  bool runOnModule(Module &M) override;
  static void
  collectConstantStringUser(GlobalVariable *CString,
                            SmallPtrSetImpl<GlobalVariable *> &Users);
  static bool isValidToEncrypt(GlobalVariable *GV);
  bool processConstantStringUse(Function *F);
  void deleteUnusedGlobalVariable();
  static Function *buildSharedDecryptFunction(Module *M, bool IsUTF16,
                                              unsigned Variant,
                                              bool UseDecryptorMBA,
                                              bool UseFlattening,
                                              uint32_t BuildNonce);
  static Function *buildSharedScrubFunction(Module *M, bool IsUTF16);
  Function *buildInitFunction(Module *M, const CSUser *User);
  uint32_t getRandomStatusValue();
  uint8_t mixKey8(uint8_t Key, uint32_t KeyIndex, uint32_t Position,
                  const CSPEntry *Entry) const;
  uint16_t mixKey16(uint16_t Key, uint32_t KeyIndex, uint32_t Position,
                    const CSPEntry *Entry) const;
  bool shouldSkipString(ArrayRef<uint8_t> Data) const;
  bool shouldSkipString(ArrayRef<uint16_t> Data) const;
  template <typename T>
  void getRandomBytes(std::vector<T> &Bytes, uint32_t MinSize,
                      uint32_t MaxSize);
  void lowerGlobalConstant(Constant *CV, IRBuilder<> &IRB, Value *Ptr,
                           Type *Ty);
  void lowerGlobalConstantStruct(ConstantStruct *CS, IRBuilder<> &IRB,
                                 Value *Ptr, Type *Ty);
  void lowerGlobalConstantArray(ConstantArray *CA, IRBuilder<> &IRB, Value *Ptr,
                                Type *Ty);
  // L3 helpers.
  void emitShardedPools(Module &M);
  GlobalVariable *emitFakePool(Module &M, ArrayRef<uint8_t> Bytes,
                               const Twine &Name);
  Value *resolvePoolBase(IRBuilder<> &IRB, unsigned PoolIndex);
  Value *resolveDecryptorCallee(IRBuilder<> &IRB, Function *DecFunc);
  // Convert the decryptor's natural CFG into a switch dispatcher. The body is
  // tiny and acyclic (one loop), so the rewrite is local and safe.
  static void flattenDecryptor(Function &F, uint32_t BuildNonce);
};

} // anonymous namespace

char StringEncryption::ID = 0;

bool StringEncryption::runOnModule(Module &M) {
  SmallPtrSet<GlobalVariable *, 16> ConstantStringUsers;

  // Resolve Fortress knobs once. They only take effect at cse level >= 3 so
  // lower levels keep the proven L2 behavior byte-for-byte.
  const bool Fortress = ArgsOptions->cseOpt()->level() >= 3;
  UseDecryptorMBA = Fortress && ArgsOptions->cseOpt()->stringDecryptorMBA();
  UseDecryptorFlattening =
      Fortress && ArgsOptions->cseOpt()->stringDecryptorFlattening();
  UseDecryptorIndirectCall =
      Fortress && ArgsOptions->cseOpt()->stringDecryptorIndirectCall();
  UseShardedPool = Fortress && ArgsOptions->cseOpt()->stringShardedPool();
  UseFakePools = Fortress && ArgsOptions->cseOpt()->stringFakePools();
  UsePageTableAccess =
      Fortress && ArgsOptions->cseOpt()->stringPageTableAccess();
  UseDelayedDecrypt = Fortress && ArgsOptions->cseOpt()->stringDelayedDecrypt();

  // collect all c strings

  LLVMContext &Ctx = M.getContext();
  BuildNonce = getRandomStatusValue();
  for (GlobalVariable &GV : M.globals()) {
    if (!GV.isConstant() || !GV.hasInitializer() ||
        GV.hasDLLExportStorageClass() || GV.isDLLImportDependent()) {
      continue;
    }
    Constant *Init = GV.getInitializer();
    if (Init == nullptr)
      continue;
    if (ConstantDataSequential *CDS = dyn_cast<ConstantDataSequential>(Init)) {
      if (CDS->isCString()) {
        StringRef Data = CDS->getRawDataValues();
        std::vector<uint8_t> PlainData;
        PlainData.reserve(Data.size());
        for (unsigned i = 0; i < Data.size(); ++i) {
          PlainData.push_back(static_cast<uint8_t>(Data[i]));
        }
        if (shouldSkipString(PlainData)) {
          continue;
        }
        CSPEntry *Entry = new CSPEntry();
        Entry->IsUTF16 = false;
        Entry->Data = std::move(PlainData);
        Entry->ID = static_cast<unsigned>(ConstantStringPool.size());
        Entry->PendingStatus = getRandomStatusValue();
        do {
          Entry->DoneStatus = getRandomStatusValue();
        } while (Entry->DoneStatus == Entry->PendingStatus);
        Constant *ZeroInit = Constant::getNullValue(CDS->getType());
        Constant *StatusInit =
            ConstantInt::get(Type::getInt32Ty(Ctx), Entry->PendingStatus);
        GlobalVariable *DecGV = new GlobalVariable(
            M, CDS->getType(), false, GlobalValue::PrivateLinkage, ZeroInit,
            "dec" + Twine::utohexstr(Entry->ID) + GV.getName());
        GlobalVariable *DecStatus = new GlobalVariable(
            M, Type::getInt32Ty(Ctx), false, GlobalValue::PrivateLinkage,
            StatusInit,
            "dec_status_" + Twine::utohexstr(Entry->ID) + GV.getName());
        DecGV->setAlignment(GV.getAlign());
        Entry->DecGV = DecGV;
        Entry->DecStatus = DecStatus;
        ConstantStringPool.push_back(Entry);
        CSPEntryMap[&GV] = Entry;
        collectConstantStringUser(&GV, ConstantStringUsers);
      } else {
        // treat arrays of i16 as UTF-16 constant strings
        Type *EltTy = CDS->getElementType();
        if (EltTy->isIntegerTy(16)) {
          unsigned NumElems = CDS->getNumElements();
          std::vector<uint16_t> PlainData;
          PlainData.reserve(NumElems);
          for (unsigned i = 0; i < NumElems; ++i) {
            // getElementAsInteger returns uint64_t, safe to cast to uint16_t
            uint64_t v = CDS->getElementAsInteger(i);
            PlainData.push_back(static_cast<uint16_t>(v));
          }
          if (shouldSkipString(PlainData)) {
            continue;
          }
          CSPEntry *Entry = new CSPEntry();
          Entry->IsUTF16 = true;
          Entry->Data16 = std::move(PlainData);
          Entry->ID = static_cast<unsigned>(ConstantStringPool.size());
          Entry->PendingStatus = getRandomStatusValue();
          do {
            Entry->DoneStatus = getRandomStatusValue();
          } while (Entry->DoneStatus == Entry->PendingStatus);
          Constant *ZeroInit = Constant::getNullValue(CDS->getType());
          Constant *StatusInit =
              ConstantInt::get(Type::getInt32Ty(Ctx), Entry->PendingStatus);
          GlobalVariable *DecGV = new GlobalVariable(
              M, CDS->getType(), false, GlobalValue::PrivateLinkage, ZeroInit,
              "dec" + Twine::utohexstr(Entry->ID) + GV.getName());
          GlobalVariable *DecStatus = new GlobalVariable(
              M, Type::getInt32Ty(Ctx), false, GlobalValue::PrivateLinkage,
              StatusInit,
              "dec_status_" + Twine::utohexstr(Entry->ID) + GV.getName());
          DecGV->setAlignment(GV.getAlign());
          Entry->DecGV = DecGV;
          Entry->DecStatus = DecStatus;
          ConstantStringPool.push_back(Entry);
          CSPEntryMap[&GV] = Entry;
          collectConstantStringUser(&GV, ConstantStringUsers);
        }
      }
    }
  }

  if (ConstantStringPool.empty()) {
    return false;
  }

  // encrypt those strings, build corresponding decrypt function
  bool hasI8Strings = false, hasI16Strings = false;
  for (CSPEntry *Entry : ConstantStringPool) {
    if (Entry->IsUTF16)
      hasI16Strings = true;
    else
      hasI8Strings = true;
  }
  // L3: per-build polymorphic decryptor variant. The variant index is derived
  // from the build nonce so the same secret+config yields a deterministic
  // shape across both compile and re-emission, while different builds vary.
  const unsigned I8Variant =
      UseDecryptorFlattening
          ? (DecryptorVariantCount + (BuildNonce >> 4) % 2)
          : ((BuildNonce >> 4) % DecryptorVariantCount);
  const unsigned I16Variant =
      UseDecryptorFlattening
          ? (DecryptorVariantCount + (BuildNonce >> 6) % 2)
          : ((BuildNonce >> 6) % DecryptorVariantCount);
  if (hasI8Strings)
    SharedDecFuncI8 = buildSharedDecryptFunction(
        &M, false, I8Variant, UseDecryptorMBA, UseDecryptorFlattening, BuildNonce);
  if (hasI16Strings)
    SharedDecFuncI16 =
        buildSharedDecryptFunction(&M, true, I16Variant, UseDecryptorMBA,
                                   UseDecryptorFlattening, BuildNonce);
  if (ArgsOptions->cseOpt()->stringReencryptAfterUse() || UseDelayedDecrypt) {
    if (hasI8Strings)
      SharedScrubFuncI8 = buildSharedScrubFunction(&M, false);
    if (hasI16Strings)
      SharedScrubFuncI16 = buildSharedScrubFunction(&M, true);
  }

  for (CSPEntry *Entry : ConstantStringPool) {
    if (!Entry->IsUTF16) {
      getRandomBytes(Entry->EncKey, 16, 32);
      uint8_t LastPlainChar = 0;
      for (unsigned i = 0; i < Entry->Data.size(); ++i) {
        const uint32_t KeyIndex = i % Entry->EncKey.size();
        const uint8_t CurrentKey =
            mixKey8(Entry->EncKey[KeyIndex], KeyIndex, i, Entry);
        const uint8_t CurrentPlainChar = Entry->Data[i];
        uint8_t val = CurrentPlainChar;
        val ^= CurrentKey;
        if ((KeyIndex * CurrentKey) % 2 == 0) {
          val = ~val;
          val ^= CurrentKey;
          val = val - LastPlainChar;
        } else {
          val = -val;
          val ^= CurrentKey;
          val = val + LastPlainChar;
        }
        Entry->Data[i] = val;
        LastPlainChar = CurrentPlainChar;
      }
    } else {
      // 16-bit oriented keys for UTF-16
      getRandomBytes(Entry->EncKey16, 8, 16); // key length in 16-bit words
      uint16_t LastPlainChar = 0;
      for (unsigned i = 0; i < Entry->Data16.size(); ++i) {
        const uint32_t KeyIndex = i % Entry->EncKey16.size();
        const uint16_t CurrentKey =
            mixKey16(Entry->EncKey16[KeyIndex], KeyIndex, i, Entry);
        const uint16_t CurrentPlainChar = Entry->Data16[i];
        uint16_t val = CurrentPlainChar;
        val ^= CurrentKey;
        if (((KeyIndex * CurrentKey) % 2) == 0) {
          val = ~val;
          val ^= CurrentKey;
          val = static_cast<uint16_t>(val - LastPlainChar);
        } else {
          val = static_cast<uint16_t>(-static_cast<int16_t>(val));
          val ^= CurrentKey;
          val = static_cast<uint16_t>(val + LastPlainChar);
        }
        Entry->Data16[i] = val;
        LastPlainChar = CurrentPlainChar;
      }
    }
  }

  // build initialization function for supported constant string users
  for (GlobalVariable *GV : ConstantStringUsers) {
    if (isValidToEncrypt(GV)) {
      Type *EltType = GV->getValueType();
      Constant *ZeroInit = Constant::getNullValue(EltType);
      GlobalVariable *DecGV =
          new GlobalVariable(M, EltType, false, GlobalValue::PrivateLinkage,
                             ZeroInit, "dec_" + GV->getName());
      DecGV->setAlignment(GV->getAlign());
      CSUser *User = new CSUser(EltType, GV, DecGV);
      User->PendingStatus = getRandomStatusValue();
      do {
        User->DoneStatus = getRandomStatusValue();
      } while (User->DoneStatus == User->PendingStatus);
      GlobalVariable *DecStatus = new GlobalVariable(
          M, Type::getInt32Ty(Ctx), false, GlobalValue::PrivateLinkage,
          ConstantInt::get(Type::getInt32Ty(Ctx), User->PendingStatus),
          "dec_status_" + GV->getName());
      User->DecStatus = DecStatus;
      User->InitFunc = buildInitFunction(&M, User);
      CSUserMap[GV] = User;
    }
  }

  // emit the constant string pool. In Fortress mode the pool may be split
  // across multiple globals (stringShardedPool) and wrapped by a page-table
  // indirection (stringPageTableAccess); decoy pools (stringFakePools) are
  // emitted alongside and pinned via llvm.compiler.used.
  emitShardedPools(M);

  // decrypt string back at every use, change the plain string use to the
  // decrypted one
  bool Changed = false;
  for (Function &F : M) {
    if (F.isDeclaration())
      continue;
    Changed |= processConstantStringUse(&F);
  }

  for (auto &I : CSUserMap) {
    CSUser *User = I.second;
    Changed |= processConstantStringUse(User->InitFunc);
  }

  // L3: pin pools + page tables so the linker does not GC them. The
  // MetadataHygiene pass also recognises these via the noobf metadata set at
  // creation.
  if (!EncryptedStringTables.empty()) {
    SmallVector<GlobalValue *, 8> Used;
    for (GlobalVariable *GV : EncryptedStringTables)
      Used.push_back(GV);
    for (GlobalVariable *GV : PoolPageTable)
      Used.push_back(GV);
    if (!Used.empty())
      appendToCompilerUsed(M, Used);
  }

  // delete unused global variables
  deleteUnusedGlobalVariable();
  return Changed;
}

void StringEncryption::emitShardedPools(Module &M) {
  // Each pool is a separate global when sharding is enabled; otherwise
  // everything lands in one global. Per-entry head/tail junk breaks the old
  // repeated |junk|key|cipher| cadence without changing the decryptor ABI.
  const unsigned PoolCount = UseShardedPool ? 4u : 1u;
  std::vector<std::vector<uint8_t>> PoolBytes(PoolCount);
  std::vector<uint8_t> JunkBytes;
  JunkBytes.reserve(32);

  for (CSPEntry *Entry : ConstantStringPool) {
    Entry->PoolIndex = UseShardedPool ? (Entry->ID % PoolCount) : 0;
    auto &Data = PoolBytes[Entry->PoolIndex];

    JunkBytes.clear();
    getRandomBytes(JunkBytes, 16, 32);
    Data.insert(Data.end(), JunkBytes.begin(), JunkBytes.end());

    // For UTF-16: ensure 2-byte alignment to avoid misaligned i16 loads
    if (Entry->IsUTF16 && (Data.size() % 2) != 0) {
      Data.push_back(0);
    }

    Entry->Offset = static_cast<unsigned>(Data.size());
    if (!Entry->IsUTF16) {
      Data.insert(Data.end(), Entry->EncKey.begin(), Entry->EncKey.end());
    } else {
      // for UTF-16: write keys as little-endian uint16_t bytes
      for (uint16_t w : Entry->EncKey16) {
        Data.push_back(static_cast<uint8_t>(w & 0xff));
        Data.push_back(static_cast<uint8_t>((w >> 8) & 0xff));
      }
    }

    Entry->EncGapBytes = 1u + static_cast<unsigned>(RNG() % 16u);
    if (Entry->IsUTF16 && (Entry->EncGapBytes % 2u) != 0)
      ++Entry->EncGapBytes;
    JunkBytes.clear();
    getRandomBytes(JunkBytes, Entry->EncGapBytes, Entry->EncGapBytes);
    Data.insert(Data.end(), JunkBytes.begin(), JunkBytes.end());

    if (!Entry->IsUTF16) {
      Data.insert(Data.end(), Entry->Data.begin(), Entry->Data.end());
    } else {
      // append Data16 as little-endian bytes
      for (uint16_t w : Entry->Data16) {
        Data.push_back(static_cast<uint8_t>(w & 0xff));
        Data.push_back(static_cast<uint8_t>((w >> 8) & 0xff));
      }
    }

    JunkBytes.clear();
    getRandomBytes(JunkBytes, 1, 16);
    Data.insert(Data.end(), JunkBytes.begin(), JunkBytes.end());
  }

  LLVMContext &Ctx = M.getContext();
  for (unsigned P = 0; P < PoolCount; ++P) {
    Constant *CDA = ConstantDataArray::get(
        Ctx, ArrayRef<uint8_t>(PoolBytes[P].empty() ? std::vector<uint8_t>{0}
                                                    : PoolBytes[P]));
    Twine Name =
        PoolCount > 1 ? ("EncryptedStringTable_" + Twine(P))
                      : Twine("EncryptedStringTable");
    auto *GV = new GlobalVariable(M, CDA->getType(), false,
                                  GlobalValue::PrivateLinkage, CDA, Name);
    GV->addMetadata("noobf", *MDNode::get(Ctx, {}));
    EncryptedStringTables.push_back(GV);
  }
  EncryptedStringTable = EncryptedStringTables.front();

  // L3: page-table indirection over pool globals. Treat each pool global as
  // an "object" and reuse the same page-table machinery as IndirectGV. The
  // pool base address at every use site is then reconstructed via
  // buildPageTableDecryptIR, so the encrypted pools are never referenced by a
  // plain @EncryptedStringTable symbol in the function body.
  if (UsePageTableAccess) {
    std::vector<Constant *> Pools;
    for (GlobalVariable *GV : EncryptedStringTables)
      Pools.push_back(GV);
    for (Constant *C : Pools)
      PoolPageKeys[C] = RNG();
    PoolPtrEncKey = RNG();
    CreatePageTableArgs Args{};
    Args.CountLoop = chooseModulePageTableDepth(RNG);
    Args.GVNamePrefix = M.getName().str() + "_StringPools";
    Args.RNG = &RNG;
    Args.M = &M;
    Args.Objects = &Pools;
    Args.IndexMap = &PoolPageIndex;
    Args.ObjectKeys = &PoolPageKeys;
    Args.OutPageTable = &PoolPageTable;
    Args.PtrEncKey = PoolPtrEncKey;
    createPageTable(Args);
  }

  // L3: decoy pools. These never decrypt to anything meaningful; they exist
  // so an analyst hunting for string storage finds multiple candidates and
  // cannot trivially identify the real pool by symbol count or section.
  if (UseFakePools) {
    const unsigned FakeCount =
        std::max<unsigned>(2u, static_cast<unsigned>(EncryptedStringTables.size()));
    for (unsigned I = 0; I < FakeCount; ++I) {
      std::vector<uint8_t> Junk;
      getRandomBytes(Junk, 256, 1024);
      emitFakePool(M, Junk, "FakeStringPool_" + Twine(I));
    }
  }
}

GlobalVariable *StringEncryption::emitFakePool(Module &M,
                                               ArrayRef<uint8_t> Bytes,
                                               const Twine &Name) {
  LLVMContext &Ctx = M.getContext();
  Constant *CDA = ConstantDataArray::get(Ctx, Bytes);
  auto *GV = new GlobalVariable(M, CDA->getType(), false,
                                GlobalValue::PrivateLinkage, CDA, Name);
  GV->addMetadata("noobf", *MDNode::get(Ctx, {}));
  appendToCompilerUsed(M, {GV});
  return GV;
}

Value *StringEncryption::resolvePoolBase(IRBuilder<> &IRBInsert,
                                         unsigned PoolIndex) {
  GlobalVariable *GV = EncryptedStringTables[PoolIndex];
  if (!UsePageTableAccess) {
    auto *GEP = IRBInsert.CreateInBoundsGEP(
        GV->getValueType(), GV, {IRBInsert.getInt32(0), IRBInsert.getInt32(0)});
    return GEP;
  }
  // Build the decrypt IR at the current insert point. We need a real
  // Instruction as the insertion anchor; if the builder points at an
  // instruction use that, otherwise use the entry-block terminator.
  Instruction *InsertPt;
  BasicBlock::iterator PtIt = IRBInsert.GetInsertPoint();
  if (PtIt != IRBInsert.GetInsertBlock()->end())
    InsertPt = &*PtIt;
  else
    InsertPt = IRBInsert.GetInsertBlock()->getTerminator();
  // page-table decryption needs a Function context; derive it from
  // the insertion block.
  Function *Fn = InsertPt->getFunction();
  BuildDecryptArgs BDA{};
  BDA.FuncLoopCount = 0;
  BDA.NextIndex = PoolPageIndex[GV];
  BDA.NextIndexValue = nullptr;
  BDA.Fn = Fn;
  BDA.InsertBefore = InsertPt;
  BDA.LoadTy = PointerType::getUnqual(Fn->getContext());
  BDA.ModulePageTable = &PoolPageTable;
  BDA.FuncPageTable = &PoolPageTable; // empty when level 0
  BDA.ModuleKey = PoolPageKeys[GV];
  BDA.FuncKey = 0;
  BDA.PtrEncKey = PoolPtrEncKey;
  BDA.RuntimeSeed = 0;
  BDA.UseMBA = false;
  BDA.IntegrityCheck = false;
  BDA.PtrAuthKey = -1;
  BDA.PtrAuthDisc = 0;
  Value *Base = buildPageTableDecryptIR(BDA);
  markNoObf(Base);
  IRBInsert.SetInsertPoint(InsertPt->getParent(), InsertPt->getIterator());
  return Base;
}

static unsigned getPlainLength(ArrayRef<uint8_t> Data) {
  return !Data.empty() && Data.back() == 0 ? Data.size() - 1 : Data.size();
}

static unsigned getPlainLength(ArrayRef<uint16_t> Data) {
  return !Data.empty() && Data.back() == 0 ? Data.size() - 1 : Data.size();
}

uint32_t StringEncryption::getRandomStatusValue() {
  uint32_t Value = 0;
  do {
    Value = static_cast<uint32_t>(RNG() & std::numeric_limits<uint32_t>::max());
  } while (Value <= 1);
  return Value;
}

uint8_t StringEncryption::mixKey8(uint8_t Key, uint32_t KeyIndex,
                                  uint32_t Position,
                                  const CSPEntry *Entry) const {
  uint32_t Mixed = Key;
  Mixed ^= (BuildNonce >> ((Position & 3) * 8)) & 0xffu;
  Mixed ^= ((Entry->ID + 1u) * deriveStringMix(BuildNonce, 0, 0xffu)) & 0xffu;
  Mixed ^= ((Position + 1u) * deriveStringMix(BuildNonce, 8, 0xffu) +
            KeyIndex * deriveStringMix(BuildNonce, 16, 0xffu)) & 0xffu;
  return static_cast<uint8_t>(Mixed);
}

uint16_t StringEncryption::mixKey16(uint16_t Key, uint32_t KeyIndex,
                                    uint32_t Position,
                                    const CSPEntry *Entry) const {
  uint32_t Mixed = Key;
  Mixed ^= (BuildNonce >> ((Position & 1) * 16)) & 0xffffu;
  Mixed ^= ((Entry->ID + 1u) * deriveStringMix(BuildNonce, 0, 0xffffu)) &
           0xffffu;
  Mixed ^= ((Position + 1u) * deriveStringMix(BuildNonce, 16, 0xffffu) +
            KeyIndex * deriveStringMix(BuildNonce, 8, 0xffffu)) & 0xffffu;
  return static_cast<uint16_t>(Mixed);
}

bool StringEncryption::shouldSkipString(ArrayRef<uint8_t> Data) const {
  const unsigned Len = getPlainLength(Data);
  const auto Opt = ArgsOptions->cseOpt();
  if (Opt->minStringLength() && Len < Opt->minStringLength()) {
    return true;
  }
  StringRef Plain(reinterpret_cast<const char *>(Data.data()), Len);
  return std::any_of(Opt->skipStrings().begin(), Opt->skipStrings().end(),
                     [&](const std::string &Skip) { return Plain == Skip; });
}

bool StringEncryption::shouldSkipString(ArrayRef<uint16_t> Data) const {
  const unsigned Len = getPlainLength(Data);
  const auto Opt = ArgsOptions->cseOpt();
  if (Opt->minStringLength() && Len < Opt->minStringLength()) {
    return true;
  }

  std::string Plain;
  Plain.reserve(Len);
  for (unsigned I = 0; I < Len; ++I) {
    if (Data[I] > 0x7f) {
      return false;
    }
    Plain.push_back(static_cast<char>(Data[I]));
  }
  return std::any_of(Opt->skipStrings().begin(), Opt->skipStrings().end(),
                     [&](const std::string &Skip) { return Plain == Skip; });
}

template <typename T>
void StringEncryption::getRandomBytes(std::vector<T> &Bytes, uint32_t MinSize,
                                      uint32_t MaxSize) {
  uint32_t N = static_cast<uint32_t>(RNG());
  uint32_t Len;

  assert(MaxSize >= MinSize);

  if (MinSize == MaxSize) {
    Len = MinSize;
  } else {
    Len = MinSize + (N % (MaxSize - MinSize));
  }

  char *Buffer = new char[Len * sizeof(T)];
  if (auto errorCode = llvm::getRandomBytes(Buffer, Len * sizeof(T))) {
    llvm::report_fatal_error(
        StringRef("Failed to get random bytes for page table generation") +
        errorCode.message());
  }
  for (uint32_t i = 0; i < Len; ++i) {
    if constexpr (std::is_same_v<T, uint8_t>) {
      Bytes.push_back(static_cast<uint8_t>(Buffer[i]));
    } else {
      uint8_t b0 = static_cast<uint8_t>(Buffer[i * 2]);
      uint8_t b1 = static_cast<uint8_t>(Buffer[i * 2 + 1]);
      // little-endian combine
      uint16_t w = static_cast<uint16_t>(b0 | (b1 << 8));
      Bytes.push_back(w);
    }
  }

  delete[] Buffer;
}

// The decrypt function reverse of the encrypt loop above. Variant and MBA
// flags only change the *shape* of the IR, not the math, so every variant
// decrypts the same ciphertext to the same plaintext.
//
// Shared signature:
//   void @goron_decrypt_string_iN(
//       ptr plain_string, ptr data, i32 key_elem_size, i32 data_size,
//       i32 enc_gap_bytes, ptr dec_status, i32 done_status,
//       i32 string_id, i32 build_nonce)
Function *StringEncryption::buildSharedDecryptFunction(
    Module *M, bool IsUTF16, unsigned Variant, bool UseDecryptorMBA,
    bool UseFlattening, uint32_t BuildNonce) {
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> IRB(Ctx);

  Type *PlainEltTy = IsUTF16 ? Type::getInt16Ty(Ctx) : Type::getInt8Ty(Ctx);
  PointerType *PtrTy = PointerType::getUnqual(Ctx);
  Type *I32Ty = Type::getInt32Ty(Ctx);

  FunctionType *FuncTy = FunctionType::get(
      Type::getVoidTy(Ctx),
      {PtrTy, PtrTy, I32Ty, I32Ty, I32Ty, PtrTy, I32Ty, I32Ty, I32Ty}, false);
  // The base name is kept stable across variants so the L1 verifier (and any
  // external symbol matchers) still find the decryptor; the variant only
  // changes the IR shape, not the symbol name.
  Twine FName = IsUTF16 ? "goron_decrypt_string_i16" : "goron_decrypt_string_i8";
  Function *DecFunc =
      Function::Create(FuncTy, GlobalValue::PrivateLinkage, FName, M);
  DecFunc->addMetadata("noobf", *MDNode::get(Ctx, {}));
  DecFunc->addFnAttr(Attribute::NoInline);
  DecFunc->addFnAttr(Attribute::OptimizeForSize);

  auto ArgIt = DecFunc->arg_begin();
  Argument *PlainString = ArgIt++;
  Argument *Data = ArgIt++;
  Argument *KeyElemSizeArg = ArgIt++;
  Argument *DataSizeArg = ArgIt++;
  Argument *EncGapBytesArg = ArgIt++;
  Argument *DecStatusArg = ArgIt++;
  Argument *DoneStatusArg = ArgIt++;
  Argument *StringIDArg = ArgIt++;
  Argument *BuildNonceArg = ArgIt;

  AttrBuilder NoCaptureAttrBuilder{Ctx};
  NoCaptureAttrBuilder.addCapturesAttr(
      llvm::CaptureInfo(llvm::CaptureComponents::None));

  PlainString->setName("plain_string");
  PlainString->addAttrs(NoCaptureAttrBuilder);
  Data->setName("data");
  Data->addAttrs(NoCaptureAttrBuilder);
  KeyElemSizeArg->setName("key_elem_size");
  DataSizeArg->setName("data_size");
  EncGapBytesArg->setName("enc_gap_bytes");
  DecStatusArg->setName("dec_status");
  DecStatusArg->addAttrs(NoCaptureAttrBuilder);
  DoneStatusArg->setName("done_status");
  StringIDArg->setName("string_id");
  BuildNonceArg->setName("build_nonce");

  BasicBlock *Enter = BasicBlock::Create(Ctx, "Enter", DecFunc);
  BasicBlock *LoopBody = BasicBlock::Create(Ctx, "LoopBody", DecFunc);
  BasicBlock *LoopBr0 = BasicBlock::Create(Ctx, "LoopBr0", DecFunc);
  BasicBlock *LoopBr1 = BasicBlock::Create(Ctx, "LoopBr1", DecFunc);
  BasicBlock *LoopEnd = BasicBlock::Create(Ctx, "LoopEnd", DecFunc);
  BasicBlock *UpdateDecStatus =
      BasicBlock::Create(Ctx, "UpdateDecStatus", DecFunc);
  BasicBlock *Exit = BasicBlock::Create(Ctx, "Exit", DecFunc);

  IRB.SetInsertPoint(Enter);
  // Compute key size in bytes: for i8 it equals key_elem_size, for i16 it's
  // key_elem_size * 2
  Value *KeySizeBytesVal = IsUTF16 ? IRB.CreateShl(KeyElemSizeArg, 1)
                                   : static_cast<Value *>(KeyElemSizeArg);
  Value *EncOffset = IRB.CreateAdd(KeySizeBytesVal, EncGapBytesArg);

  Value *EncPtr = IRB.CreateInBoundsGEP(IRB.getInt8Ty(), Data, EncOffset);
  Value *DecStatus = IRB.CreateLoad(I32Ty, DecStatusArg);
  // Variant 0: plain status load. Variant 1: volatile status load (extra
  // memory dependency an analyst must follow). Both compare against
  // done_status.
  if (Variant == 1) {
    IRB.CreateLoad(I32Ty, DecStatusArg, true);
  }
  Value *IsDecrypted = IRB.CreateICmpEQ(DecStatus, DoneStatusArg);
  IRB.CreateCondBr(IsDecrypted, Exit, LoopBody);

  IRB.SetInsertPoint(LoopBody);
  PHINode *LoopCounter = IRB.CreatePHI(IRB.getInt32Ty(), 2);
  LoopCounter->addIncoming(IRB.getInt32(0), Enter);

  PHINode *LastDecrypted = IRB.CreatePHI(PlainEltTy, 2);
  LastDecrypted->addIncoming(Constant::getNullValue(PlainEltTy), Enter);

  Value *KeyIdx = IRB.CreateURem(LoopCounter, KeyElemSizeArg);

  Value *KeyChar = nullptr;
  if (!IsUTF16) {
    Value *KeyCharPtr = IRB.CreateInBoundsGEP(IRB.getInt8Ty(), Data, KeyIdx);
    KeyChar = IRB.CreateLoad(IRB.getInt8Ty(), KeyCharPtr);
  } else {
    Value *KeyCharPtr =
        IRB.CreateInBoundsGEP(Type::getInt16Ty(Ctx), Data, KeyIdx);
    KeyChar = IRB.CreateLoad(Type::getInt16Ty(Ctx), KeyCharPtr);
  }

  Value *KeyCharZext = IRB.CreateZExt(KeyChar, IRB.getInt32Ty());
  Value *ShiftIndex =
      IRB.CreateAnd(LoopCounter, IRB.getInt32(IsUTF16 ? 1 : 3));
  Value *Shift = IRB.CreateShl(ShiftIndex, IRB.getInt32(IsUTF16 ? 4 : 3));
  Value *NoncePart = IRB.CreateLShr(BuildNonceArg, Shift);
  Value *Mask = IRB.getInt32(IsUTF16 ? 0xffff : 0xff);
  NoncePart = IRB.CreateAnd(NoncePart, Mask);

  auto BuildMix = [&](unsigned ShiftBits) -> Value * {
    Value *Part = IRB.CreateLShr(BuildNonceArg, IRB.getInt32(ShiftBits));
    Part = IRB.CreateAnd(Part, Mask);
    return IRB.CreateOr(Part, IRB.getInt32(1));
  };
  const unsigned PositionMixShift = IsUTF16 ? 16 : 8;
  const unsigned KeyIndexMixShift = IsUTF16 ? 8 : 16;
  Value *StringPart = IRB.CreateMul(IRB.CreateAdd(StringIDArg, IRB.getInt32(1)),
                                    BuildMix(0));
  StringPart = IRB.CreateAnd(StringPart, Mask);
  Value *PositionPart =
      IRB.CreateMul(IRB.CreateAdd(LoopCounter, IRB.getInt32(1)),
                    BuildMix(PositionMixShift));
  Value *KeyIndexPart = IRB.CreateMul(KeyIdx, BuildMix(KeyIndexMixShift));
  PositionPart = IRB.CreateAnd(IRB.CreateAdd(PositionPart, KeyIndexPart), Mask);
  Value *MixedKey = IRB.CreateXor(KeyCharZext, NoncePart);
  MixedKey = IRB.CreateXor(MixedKey, StringPart);
  MixedKey = IRB.CreateXor(MixedKey, PositionPart);
  KeyChar = IRB.CreateTrunc(MixedKey, PlainEltTy);

  Value *EncChar = nullptr;
  if (!IsUTF16) {
    Value *EncCharPtr =
        IRB.CreateInBoundsGEP(IRB.getInt8Ty(), EncPtr, LoopCounter);
    EncChar = IRB.CreateLoad(IRB.getInt8Ty(), EncCharPtr, true);
  } else {
    Value *IdxBytes = IRB.CreateShl(LoopCounter, 1);
    Value *EncCharBytePtr =
        IRB.CreateInBoundsGEP(IRB.getInt8Ty(), EncPtr, IdxBytes);
    EncChar = IRB.CreateLoad(Type::getInt16Ty(Ctx), EncCharBytePtr, true);
  }

  Value *KeyIdxZext = IRB.CreateZExt(KeyIdx, IRB.getInt32Ty());
  KeyCharZext = IRB.CreateZExt(KeyChar, IRB.getInt32Ty());
  Value *Mul = IRB.CreateMul(KeyIdxZext, KeyCharZext);
  Value *BrKey = IRB.CreateAnd(Mul, IRB.getInt32(1));
  // Variant 2 swaps which branch handles which math family. Math identical,
  // control flow differs.
  const bool InvertBranchShape = (Variant == 2) || (Variant == 3);
  Value *BrCond = InvertBranchShape
                      ? IRB.CreateICmpNE(BrKey, IRB.getInt32(0))
                      : IRB.CreateICmpEQ(BrKey, IRB.getInt32(0));
  IRB.CreateCondBr(BrCond, InvertBranchShape ? LoopBr1 : LoopBr0,
                   InvertBranchShape ? LoopBr0 : LoopBr1);

  IRB.SetInsertPoint(LoopBr0);
  Value *DecChar0;
  {
    if (UseDecryptorMBA) {
      // Original math: ~((enc+last) ^ key). The xor is rewritten with the MBA
      // identity a^b == (a|b)-(a&b) so the xor pattern recogniser cannot fold
      // it back. Built in a NoFolder builder for the whole block.
      IRBuilder<NoFolder> NF(LoopBr0);
      Value *Sum = NF.CreateAdd(EncChar, LastDecrypted, "strenc.dec.sum0");
      Value *Or = NF.CreateOr(Sum, KeyChar, "strenc.dec.xor0.or");
      markNoObf(Or);
      Value *And = NF.CreateAnd(Sum, KeyChar, "strenc.dec.xor0.and");
      markNoObf(And);
      Value *Xored = NF.CreateSub(Or, And, "strenc.dec.add0");
      markNoObf(Xored);
      DecChar0 = NF.CreateNot(Xored, "strenc.dec.not0");
      NF.CreateBr(LoopEnd);
      IRB.SetInsertPoint(LoopEnd);
    } else {
      Value *Tmp = IRB.CreateAdd(EncChar, LastDecrypted);
      Tmp = IRB.CreateXor(Tmp, KeyChar);
      Tmp = IRB.CreateNot(Tmp);
      DecChar0 = Tmp;
      IRB.CreateBr(LoopEnd);
    }
  }

  IRB.SetInsertPoint(LoopBr1);
  Value *DecChar1;
  {
    if (UseDecryptorMBA) {
      // Original math: -((enc-last) ^ key). xor rewritten as (a|b)-(a&b).
      IRBuilder<NoFolder> NF(LoopBr1);
      Value *Sub = NF.CreateSub(EncChar, LastDecrypted, "strenc.dec.sub1");
      Value *Or = NF.CreateOr(Sub, KeyChar, "strenc.dec.xor1.or");
      markNoObf(Or);
      Value *And = NF.CreateAnd(Sub, KeyChar, "strenc.dec.xor1.and");
      markNoObf(And);
      Value *Xored = NF.CreateSub(Or, And, "strenc.dec.add1");
      markNoObf(Xored);
      DecChar1 = NF.CreateNeg(Xored, "strenc.dec.neg1");
      NF.CreateBr(LoopEnd);
      IRB.SetInsertPoint(LoopEnd);
    } else {
      Value *Tmp = IRB.CreateSub(EncChar, LastDecrypted);
      Tmp = IRB.CreateXor(Tmp, KeyChar);
      Tmp = IRB.CreateNeg(Tmp);
      DecChar1 = Tmp;
      IRB.CreateBr(LoopEnd);
    }
  }

  IRB.SetInsertPoint(LoopEnd);
  PHINode *BrDecChar = IRB.CreatePHI(PlainEltTy, 2);
  BrDecChar->addIncoming(DecChar0, LoopBr0);
  BrDecChar->addIncoming(DecChar1, LoopBr1);
  Value *DecChar;
  if (UseDecryptorMBA) {
    // Final xor is materialised as MBA: a^k == (a^k) [already a pure xor; we
    // rewrite as a + k - 2*(a&k) to break the xor pattern recogniser].
    IRBuilder<NoFolder> NF(LoopEnd);
    Value *And = NF.CreateAnd(BrDecChar, KeyChar, "strenc.dec.xor.and");
    markNoObf(And);
    Value *Shl = NF.CreateShl(And, ConstantInt::get(PlainEltTy, 1),
                              "strenc.dec.xor.shl");
    markNoObf(Shl);
    Value *A = NF.CreateAdd(BrDecChar, KeyChar, "strenc.dec.xor.a");
    markNoObf(A);
    DecChar = NF.CreateSub(A, Shl, "strenc.dec.xor");
    markNoObf(DecChar);
    IRB.SetInsertPoint(LoopEnd);
  } else {
    DecChar = IRB.CreateXor(BrDecChar, KeyChar);
  }

  LastDecrypted->addIncoming(DecChar, LoopEnd);
  Value *DecCharPtr =
      IRB.CreateInBoundsGEP(PlainEltTy, PlainString, LoopCounter);
  IRB.CreateStore(DecChar, DecCharPtr);

  Value *NewCounter =
      IRB.CreateAdd(LoopCounter, IRB.getInt32(1), "", true, true);
  LoopCounter->addIncoming(NewCounter, LoopEnd);

  Value *Cond = IRB.CreateICmpEQ(NewCounter, DataSizeArg);
  IRB.CreateCondBr(Cond, UpdateDecStatus, LoopBody);

  IRB.SetInsertPoint(UpdateDecStatus);
  IRB.CreateStore(DoneStatusArg, DecStatusArg);
  IRB.CreateBr(Exit);

  IRB.SetInsertPoint(Exit);
  IRB.CreateRetVoid();

  // L3: flatten the decryptor body into a dispatcher. We do this with a
  // lightweight state-machine rewrite that lowers each original block into a
  // case of a switch on a per-call state variable. This is the same idea as
  // Flattening.cpp but local to the decryptor and guaranteed safe because the
  // body is small and acyclic (loop aside).
  if (UseFlattening)
    flattenDecryptor(*DecFunc, BuildNonce);
  return DecFunc;
}

Function *StringEncryption::buildSharedScrubFunction(Module *M, bool IsUTF16) {
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> IRB(Ctx);

  Type *PlainEltTy = IsUTF16 ? Type::getInt16Ty(Ctx) : Type::getInt8Ty(Ctx);
  PointerType *PtrTy = PointerType::getUnqual(Ctx);
  Type *I32Ty = Type::getInt32Ty(Ctx);
  FunctionType *FuncTy = FunctionType::get(
      Type::getVoidTy(Ctx), {PtrTy, PtrTy, I32Ty, I32Ty, I32Ty, PtrTy, I32Ty},
      false);
  Function *ScrubFunc = Function::Create(
      FuncTy, GlobalValue::PrivateLinkage,
      IsUTF16 ? "goron_scrub_string_i16" : "goron_scrub_string_i8", M);
  ScrubFunc->addFnAttr(Attribute::NoInline);
  ScrubFunc->addFnAttr(Attribute::OptimizeForSize);

  auto ArgIt = ScrubFunc->arg_begin();
  Argument *PlainString = ArgIt++;
  Argument *Data = ArgIt++;
  Argument *KeyElemSizeArg = ArgIt++;
  Argument *DataSizeArg = ArgIt++;
  Argument *EncGapBytesArg = ArgIt++;
  Argument *DecStatusArg = ArgIt++;
  Argument *PendingStatusArg = ArgIt;

  PlainString->setName("plain_string");
  Data->setName("data");
  KeyElemSizeArg->setName("key_elem_size");
  DataSizeArg->setName("data_size");
  EncGapBytesArg->setName("enc_gap_bytes");
  DecStatusArg->setName("dec_status");
  PendingStatusArg->setName("pending_status");

  BasicBlock *Enter = BasicBlock::Create(Ctx, "Enter", ScrubFunc);
  BasicBlock *LoopBody = BasicBlock::Create(Ctx, "LoopBody", ScrubFunc);
  BasicBlock *Exit = BasicBlock::Create(Ctx, "Exit", ScrubFunc);

  IRB.SetInsertPoint(Enter);
  Value *KeySizeBytesVal = IsUTF16 ? IRB.CreateShl(KeyElemSizeArg, 1)
                                   : static_cast<Value *>(KeyElemSizeArg);
  Value *EncOffset = IRB.CreateAdd(KeySizeBytesVal, EncGapBytesArg);
  Value *EncPtr = IRB.CreateInBoundsGEP(IRB.getInt8Ty(), Data, EncOffset);
  IRB.CreateBr(LoopBody);

  IRB.SetInsertPoint(LoopBody);
  PHINode *LoopCounter = IRB.CreatePHI(IRB.getInt32Ty(), 2);
  LoopCounter->addIncoming(IRB.getInt32(0), Enter);
  Value *EncChar = nullptr;
  if (!IsUTF16) {
    Value *EncCharPtr =
        IRB.CreateInBoundsGEP(IRB.getInt8Ty(), EncPtr, LoopCounter);
    EncChar = IRB.CreateLoad(IRB.getInt8Ty(), EncCharPtr, true);
  } else {
    Value *IdxBytes = IRB.CreateShl(LoopCounter, 1);
    Value *EncCharBytePtr =
        IRB.CreateInBoundsGEP(IRB.getInt8Ty(), EncPtr, IdxBytes);
    EncChar = IRB.CreateLoad(Type::getInt16Ty(Ctx), EncCharBytePtr, true);
  }
  Value *OutPtr =
      IRB.CreateInBoundsGEP(PlainEltTy, PlainString, LoopCounter);
  IRB.CreateStore(EncChar, OutPtr);
  Value *NewCounter =
      IRB.CreateAdd(LoopCounter, IRB.getInt32(1), "", true, true);
  LoopCounter->addIncoming(NewCounter, LoopBody);
  Value *Cond = IRB.CreateICmpEQ(NewCounter, DataSizeArg);
  IRB.CreateCondBr(Cond, Exit, LoopBody);

  IRB.SetInsertPoint(Exit);
  IRB.CreateStore(PendingStatusArg, DecStatusArg);
  IRB.CreateRetVoid();
  return ScrubFunc;
}

Function *
StringEncryption::buildInitFunction(Module *M,
                                    const StringEncryption::CSUser *User) {
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> IRB(Ctx);
  FunctionType *FuncTy =
      FunctionType::get(Type::getVoidTy(Ctx), {User->DecGV->getType()}, false);
  Function *InitFunc = Function::Create(
      FuncTy, GlobalValue::PrivateLinkage,
      "__global_variable_initializer_" + User->GV->getName(), M);

  auto ArgIt = InitFunc->arg_begin();
  Argument *thiz = ArgIt;

  AttrBuilder NoCaptureAttrBuilder{Ctx};
  NoCaptureAttrBuilder.addCapturesAttr(
      llvm::CaptureInfo(llvm::CaptureComponents::None));
  thiz->setName("this");
  thiz->addAttrs(NoCaptureAttrBuilder);

  // convert constant initializer into a series of instructions
  BasicBlock *Enter = BasicBlock::Create(Ctx, "Enter", InitFunc);
  BasicBlock *InitBlock = BasicBlock::Create(Ctx, "InitBlock", InitFunc);
  BasicBlock *Exit = BasicBlock::Create(Ctx, "Exit", InitFunc);

  IRB.SetInsertPoint(Enter);
  Value *DecStatus =
      IRB.CreateLoad(User->DecStatus->getValueType(), User->DecStatus);
  Value *IsDecrypted =
      IRB.CreateICmpEQ(DecStatus, IRB.getInt32(User->DoneStatus));
  IRB.CreateCondBr(IsDecrypted, Exit, InitBlock);

  IRB.SetInsertPoint(InitBlock);
  Constant *Init = User->GV->getInitializer();
  lowerGlobalConstant(Init, IRB, User->DecGV, User->Ty);
  IRB.CreateStore(IRB.getInt32(User->DoneStatus), User->DecStatus);
  IRB.CreateBr(Exit);

  IRB.SetInsertPoint(Exit);
  IRB.CreateRetVoid();
  return InitFunc;
}

void StringEncryption::lowerGlobalConstant(Constant *CV, IRBuilder<> &IRB,
                                           Value *Ptr, Type *Ty) {
  if (isa<ConstantAggregateZero>(CV)) {
    IRB.CreateStore(CV, Ptr);
    return;
  }

  if (ConstantArray *CA = dyn_cast<ConstantArray>(CV)) {
    lowerGlobalConstantArray(CA, IRB, Ptr, Ty);
  } else if (ConstantStruct *CS = dyn_cast<ConstantStruct>(CV)) {
    lowerGlobalConstantStruct(CS, IRB, Ptr, Ty);
  } else {
    IRB.CreateStore(CV, Ptr);
  }
}

void StringEncryption::lowerGlobalConstantArray(ConstantArray *CA,
                                                IRBuilder<> &IRB, Value *Ptr,
                                                Type *Ty) {
  for (unsigned i = 0, e = CA->getNumOperands(); i != e; ++i) {
    Constant *CV = CA->getOperand(i);
    Value *GEP = IRB.CreateGEP(Ty, Ptr, {IRB.getInt32(0), IRB.getInt32(i)});
    lowerGlobalConstant(CV, IRB, GEP, CV->getType());
  }
}

void StringEncryption::lowerGlobalConstantStruct(ConstantStruct *CS,
                                                 IRBuilder<> &IRB, Value *Ptr,
                                                 Type *Ty) {
  for (unsigned i = 0, e = CS->getNumOperands(); i != e; ++i) {
    Constant *CV = CS->getOperand(i);
    Value *GEP = IRB.CreateGEP(Ty, Ptr, {IRB.getInt32(0), IRB.getInt32(i)});
    lowerGlobalConstant(CV, IRB, GEP, CV->getType());
  }
}

bool StringEncryption::processConstantStringUse(Function *F) {
  auto opt = ArgsOptions->toObfuscate(ArgsOptions->cseOpt(), F);
  if (!opt.isEnabled()) {
    return false;
  }
  LowerConstantExpr(*F);
  SmallPtrSet<GlobalVariable *, 16> DecryptedGV;
  // if GV has multiple use in a block, decrypt only at the first use
  bool Changed = false;
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();
  Type *I32Ty = Type::getInt32Ty(Ctx);
  Type *I64Ty = Type::getInt64Ty(Ctx);
  PointerType *PtrTy = PointerType::getUnqual(Ctx);
  // L3: delayed-decrypt forces every use onto a scratch buffer that is
  // scrubbed before the function returns, regardless of the cache path.
  const bool UseHeap = opt.stringHeapDecrypt();
  const bool UseStack = (opt.stringLocalStackDecrypt() && !UseHeap) ||
                        UseDelayedDecrypt;
  const bool ReencryptAfterUse = opt.stringReencryptAfterUse() || UseDelayedDecrypt;
  FunctionCallee MallocFn;
  FunctionCallee FreeFn;
  SmallVector<Value *, 16> HeapAllocs;
  if (UseHeap) {
    MallocFn = M->getOrInsertFunction(
        "malloc", FunctionType::get(PtrTy, {I64Ty}, false));
    FreeFn = M->getOrInsertFunction("free",
                                    FunctionType::get(Type::getVoidTy(Ctx),
                                                      {PtrTy}, false));
  }

  auto emitDecrypt = [&](IRBuilder<> &IRB, CSPEntry *Entry, Value *&Data,
                         bool Temporary) -> Value * {
    // L3: pool base may be resolved through a page table; otherwise use the
    // direct global GEP. The per-entry offset indexes into the chosen shard.
    Value *PoolBase = resolvePoolBase(IRB, Entry->PoolIndex);
    Data = IRB.CreateInBoundsGEP(
        IRB.getInt8Ty(), PoolBase, IRB.getInt32(Entry->Offset));
    Function *DecFunc = Entry->IsUTF16 ? SharedDecFuncI16 : SharedDecFuncI8;
    uint32_t KeyElemSize = Entry->IsUTF16
                               ? static_cast<uint32_t>(Entry->EncKey16.size())
                               : static_cast<uint32_t>(Entry->EncKey.size());
    uint32_t DataSize = Entry->IsUTF16
                            ? static_cast<uint32_t>(Entry->Data16.size())
                            : static_cast<uint32_t>(Entry->Data.size());
    Value *OutBuf = Entry->DecGV;
    Value *StatusPtr = Entry->DecStatus;
    if (Temporary) {
      StatusPtr = IRB.CreateAlloca(I32Ty);
      IRB.CreateStore(IRB.getInt32(Entry->PendingStatus), StatusPtr);
      if (UseHeap) {
        uint64_t Bytes = DataSize * (Entry->IsUTF16 ? 2ull : 1ull);
        IRBuilder<> EntryIRB(&*F->getEntryBlock().getFirstInsertionPt());
        OutBuf = EntryIRB.CreateCall(MallocFn, {EntryIRB.getInt64(Bytes)});
        HeapAllocs.push_back(OutBuf);
      } else {
        OutBuf = IRB.CreateAlloca(Entry->DecGV->getValueType());
      }
    }
    Value *Callee = resolveDecryptorCallee(IRB, DecFunc);
    fixEH(createDecryptorCall(IRB, Callee, DecFunc,
                              {OutBuf, Data, IRB.getInt32(KeyElemSize),
                               IRB.getInt32(DataSize),
                               IRB.getInt32(Entry->EncGapBytes), StatusPtr,
                               IRB.getInt32(Entry->DoneStatus),
                               IRB.getInt32(Entry->ID),
                               IRB.getInt32(BuildNonce)}));
    return OutBuf;
  };

  auto emitAfterUse = [&](Instruction &Inst, CSPEntry *Entry, Value *OutBuf,
                          Value *Data, bool Temporary) {
    Instruction *Next = Inst.getNextNode();
    if (!Next)
      return;
    Instruction *InsertAfter = &Inst;
    if (ReencryptAfterUse && Inst.getType()->isPointerTy()) {
      Instruction *OnlyConsumer = nullptr;
      for (User *U : Inst.users()) {
        auto *UserInst = dyn_cast<Instruction>(U);
        if (!UserInst || UserInst->getType()->isPointerTy())
          return;
        if (OnlyConsumer && OnlyConsumer != UserInst)
          return;
        OnlyConsumer = UserInst;
      }
      if (!OnlyConsumer)
        return;
      InsertAfter = OnlyConsumer;
      Next = InsertAfter->getNextNode();
      if (!Next)
        return;
    }
    IRBuilder<> IRB(Next);
    uint32_t KeyElemSize = Entry->IsUTF16
                               ? static_cast<uint32_t>(Entry->EncKey16.size())
                               : static_cast<uint32_t>(Entry->EncKey.size());
    uint32_t DataSize = Entry->IsUTF16
                            ? static_cast<uint32_t>(Entry->Data16.size())
                            : static_cast<uint32_t>(Entry->Data.size());
    if (!Temporary && ReencryptAfterUse) {
      Function *ScrubFunc =
          Entry->IsUTF16 ? SharedScrubFuncI16 : SharedScrubFuncI8;
      fixEH(IRB.CreateCall(ScrubFunc,
                           {OutBuf, Data, IRB.getInt32(KeyElemSize),
                            IRB.getInt32(DataSize),
                            IRB.getInt32(Entry->EncGapBytes), Entry->DecStatus,
                            IRB.getInt32(Entry->PendingStatus)}));
    }
    // L3 delayed-decrypt: always scrub the temporary buffer (stack or heap)
    // so the plaintext never outlives the use. The scrub writes the ciphertext
    // back over the buffer, defeating a memory dump taken after the call.
    if (Temporary && UseDelayedDecrypt) {
      Function *ScrubFunc =
          Entry->IsUTF16 ? SharedScrubFuncI16 : SharedScrubFuncI8;
      Value *TmpStatus = IRB.CreateAlloca(I32Ty);
      IRB.CreateStore(IRB.getInt32(Entry->PendingStatus), TmpStatus);
      fixEH(IRB.CreateCall(ScrubFunc,
                           {OutBuf, Data, IRB.getInt32(KeyElemSize),
                            IRB.getInt32(DataSize),
                            IRB.getInt32(Entry->EncGapBytes), TmpStatus,
                            IRB.getInt32(Entry->PendingStatus)}));
    }
  };

  for (BasicBlock &BB : *F) {
    DecryptedGV.clear();
    for (Instruction &Inst : BB) {
      if (PHINode *PHI = dyn_cast<PHINode>(&Inst)) {
        for (unsigned int i = 0; i < PHI->getNumIncomingValues(); ++i) {
          if (GlobalVariable *GV =
                  dyn_cast<GlobalVariable>(PHI->getIncomingValue(i))) {
            auto Iter1 = CSPEntryMap.find(GV);
            auto Iter2 = CSUserMap.find(GV);
            if (Iter2 != CSUserMap.end()) {
              // GV is a constant string user
              CSUser *User = Iter2->second;
              if (DecryptedGV.count(GV) > 0) {
                Inst.replaceUsesOfWith(GV, User->DecGV);
              } else {
                Instruction *InsertPoint =
                    PHI->getIncomingBlock(i)->getTerminator();
                IRBuilder<> IRB(InsertPoint);
                fixEH(IRB.CreateCall(User->InitFunc, {User->DecGV}));
                Inst.replaceUsesOfWith(GV, User->DecGV);
                MaybeDeadGlobalVars.insert(GV);
                DecryptedGV.insert(GV);
              }
              Changed = true;
            } else if (Iter1 != CSPEntryMap.end()) {
              // GV is a constant string
              CSPEntry *Entry = Iter1->second;
              if (DecryptedGV.count(GV) > 0) {
                Inst.replaceUsesOfWith(GV, Entry->DecGV);
              } else {
                Instruction *InsertPoint =
                    PHI->getIncomingBlock(i)->getTerminator();
                IRBuilder<> IRB(InsertPoint);

                Value *OutBuf = Entry->DecGV;
                Value *PoolBase = resolvePoolBase(IRB, Entry->PoolIndex);
                Value *Data = IRB.CreateInBoundsGEP(
                    IRB.getInt8Ty(), PoolBase, IRB.getInt32(Entry->Offset));
                Function *DecFunc =
                    Entry->IsUTF16 ? SharedDecFuncI16 : SharedDecFuncI8;
                uint32_t KeyElemSize =
                    Entry->IsUTF16
                        ? static_cast<uint32_t>(Entry->EncKey16.size())
                        : static_cast<uint32_t>(Entry->EncKey.size());
                uint32_t DataSize =
                    Entry->IsUTF16 ? static_cast<uint32_t>(Entry->Data16.size())
                                   : static_cast<uint32_t>(Entry->Data.size());
                Value *Callee = resolveDecryptorCallee(IRB, DecFunc);
                fixEH(createDecryptorCall(
                    IRB, Callee, DecFunc,
                    {OutBuf, Data, IRB.getInt32(KeyElemSize),
                     IRB.getInt32(DataSize), IRB.getInt32(Entry->EncGapBytes),
                     Entry->DecStatus,
                     IRB.getInt32(Entry->DoneStatus), IRB.getInt32(Entry->ID),
                     IRB.getInt32(BuildNonce)}));

                Inst.replaceUsesOfWith(GV, Entry->DecGV);
                MaybeDeadGlobalVars.insert(GV);
                DecryptedGV.insert(GV);
              }
              Changed = true;
            }
          }
        }
      } else {
        for (User::op_iterator op = Inst.op_begin(); op != Inst.op_end();
             ++op) {
          if (GlobalVariable *GV = dyn_cast<GlobalVariable>(*op)) {
            auto Iter1 = CSPEntryMap.find(GV);
            auto Iter2 = CSUserMap.find(GV);
            if (Iter2 != CSUserMap.end()) {
              CSUser *User = Iter2->second;
              if (DecryptedGV.count(GV) > 0) {
                Inst.replaceUsesOfWith(GV, User->DecGV);
              } else {

                IRBuilder<> IRB(Inst.isEHPad() ? &*Inst.getParent()
                                                       ->getPrevNode()
                                                       ->getFirstInsertionPt()
                                               : &Inst);
                fixEH(IRB.CreateCall(User->InitFunc, {User->DecGV}));
                Inst.replaceUsesOfWith(GV, User->DecGV);
                MaybeDeadGlobalVars.insert(GV);
                DecryptedGV.insert(GV);
              }
              Changed = true;
            } else if (Iter1 != CSPEntryMap.end()) {
              CSPEntry *Entry = Iter1->second;
              // L3: delayed-decrypt never reuses the cached DecGV; every use
              // gets a fresh temporary that is scrubbed afterwards.
              const bool Temporary = UseStack || UseHeap;
              const bool CacheGlobal = !Temporary && !ReencryptAfterUse;
              if (CacheGlobal && DecryptedGV.count(GV) > 0) {
                Inst.replaceUsesOfWith(GV, Entry->DecGV);
              } else {
                IRBuilder<> IRB(Inst.isEHPad() ? &*Inst.getParent()
                                                       ->getPrevNode()
                                                       ->getFirstInsertionPt()
                                               : &Inst);

                Value *Data = nullptr;
                Value *OutBuf = emitDecrypt(IRB, Entry, Data, Temporary);

                Inst.replaceUsesOfWith(GV, OutBuf);
                emitAfterUse(Inst, Entry, OutBuf, Data, Temporary);
                MaybeDeadGlobalVars.insert(GV);
                if (CacheGlobal)
                  DecryptedGV.insert(GV);
              }
              Changed = true;
            }
          }
        }
      }
    }
  }
  if (UseHeap) {
    for (BasicBlock &BB : *F) {
      if (ReturnInst *Ret = dyn_cast<ReturnInst>(BB.getTerminator())) {
        IRBuilder<> IRB(Ret);
        for (Value *HeapAlloc : HeapAllocs)
          IRB.CreateCall(FreeFn, {HeapAlloc});
      }
    }
  }
  if (Changed)
    F->addMetadata("noobf", *MDNode::get(F->getContext(), {}));
  return Changed;
}

Value *StringEncryption::resolveDecryptorCallee(IRBuilder<> &IRBInsert,
                                                Function *DecFunc) {
  if (!UseDecryptorIndirectCall)
    return DecFunc;
  // indirect-call hardening is owned by the dedicated IndirectCall
  // pass downstream. Rather than duplicate its page-table machinery here
  // (which would race the global CalleeIndex map), we route the call through
  // an opaque pointer loaded from a private global. The IndirectCall pass
  // later picks this up as a normal indirect call site if it is enabled.
  Module *M = DecFunc->getParent();
  GlobalVariable *&Slot = DecryptorSlots[DecFunc];
  if (!Slot) {
    auto *PtrTy = PointerType::getUnqual(M->getContext());
    Slot = new GlobalVariable(*M, PtrTy, false, GlobalValue::PrivateLinkage,
                              ConstantExpr::getBitCast(DecFunc, PtrTy),
                              "strenc.decslot." + DecFunc->getName());
    Slot->addMetadata("noobf", *MDNode::get(M->getContext(), {}));
    // Pin the slot so the linker does not GC it and so the constant folder
    // sees a real external use it cannot collapse.
    appendToCompilerUsed(*M, {Slot});
  }
  Value *Loaded = IRBInsert.CreateAlignedLoad(
      Slot->getValueType(), Slot, Align{1}, true, "strenc.deccallee");
  markNoObf(Loaded);
  return Loaded;
}

void StringEncryption::flattenDecryptor(Function &F, uint32_t BuildNonce) {
  // Local, self-contained control-flow flattening of the decryptor body. The
  // decryptor has exactly one conditional branch (the two-way loop body
  // split). We rewrite that cond_br into a switch dispatcher with a junk
  // default case, so the CFG no longer looks like a clean if/else loop.
  //
  // Semantics are preserved because the switch covers exactly the two real
  // successors plus an unreachable trap default.
  BasicBlock *LoopBody = nullptr;
  BranchInst *LoopBodyTerm = nullptr;
  for (BasicBlock &BB : F) {
    if (BB.getName() == "LoopBody") {
      LoopBody = &BB;
      LoopBodyTerm = dyn_cast<BranchInst>(BB.getTerminator());
      break;
    }
  }
  if (!LoopBodyTerm || !LoopBodyTerm->isConditional())
    return;
  BasicBlock *Succ0 = LoopBodyTerm->getSuccessor(0);
  BasicBlock *Succ1 = LoopBodyTerm->getSuccessor(1);
  Value *BrKey = LoopBodyTerm->getCondition();

  IRBuilder<> IRB(LoopBody);
  IRB.SetInsertPoint(LoopBodyTerm);
  // ZExt the i1 condition to i32 so it can drive a switch. The two real cases
  // are 0 and 1; everything else falls through to a trap.
  Value *KeyI32 = IRB.CreateZExt(BrKey, IRB.getInt32Ty(), "strenc.flat.key");
  BasicBlock *Trap = BasicBlock::Create(F.getContext(), "Trap", &F);
  IRBuilder<> TrapB(Trap);
  TrapB.CreateCall(
      Intrinsic::getOrInsertDeclaration(F.getParent(), Intrinsic::trap));
  TrapB.CreateUnreachable();
  auto *Switch = IRB.CreateSwitch(KeyI32, Trap, 2);
  Switch->addCase(IRB.getInt32(0), Succ0);
  Switch->addCase(IRB.getInt32(1), Succ1);
  // Add a couple of junk cases pointing at the trap to bulk out the table
  // without changing reachability. Mask junk values out of the real range.
  unsigned JunkSeed = (BuildNonce >> 8) ^ (BuildNonce << 7) ^ (BuildNonce | 1u);
  for (unsigned I = 0; I < 3; ++I) {
    unsigned Junk = 2u + ((JunkSeed + I * deriveStringMix(BuildNonce, 16, 0xffu)) &
                          0x7fffffu);
    if (Junk <= 1)
      continue;
    Switch->addCase(IRB.getInt32(Junk), Trap);
  }
  LoopBodyTerm->eraseFromParent();
}

void StringEncryption::collectConstantStringUser(
    GlobalVariable *CString, SmallPtrSetImpl<GlobalVariable *> &Users) {
  SmallPtrSet<Value *, 16> Visited;
  SmallVector<Value *, 16> ToVisit;

  ToVisit.push_back(CString);
  while (!ToVisit.empty()) {
    Value *V = ToVisit.pop_back_val();
    if (Visited.count(V) > 0)
      continue;
    Visited.insert(V);
    for (Value *User : V->users()) {
      if (auto *GV = dyn_cast<GlobalVariable>(User)) {
        Users.insert(GV);
      } else {
        ToVisit.push_back(User);
      }
    }
  }
}

bool StringEncryption::isValidToEncrypt(GlobalVariable *GV) {
  if (GV->isConstant() && GV->hasInitializer()) {
    return GV->getInitializer() != nullptr;
  } else {
    return false;
  }
}

void StringEncryption::deleteUnusedGlobalVariable() {
  bool Changed = true;
  while (Changed) {
    Changed = false;
    for (auto Iter = MaybeDeadGlobalVars.begin();
         Iter != MaybeDeadGlobalVars.end();) {
      GlobalVariable *GV = *Iter;
      if (!GV->hasLocalLinkage()) {
        ++Iter;
        continue;
      }

      GV->removeDeadConstantUsers();
      if (GV->use_empty()) {
        if (GV->hasInitializer()) {
          Constant *Init = GV->getInitializer();
          GV->setInitializer(nullptr);
          if (isSafeToDestroyConstant(Init))
            Init->destroyConstant();
        }
        Iter = MaybeDeadGlobalVars.erase(Iter);
        GV->eraseFromParent();
        Changed = true;
      } else {
        ++Iter;
      }
    }
  }
}

ModulePass *llvm::createStringEncryptionPass(ObfuscationOptions *argsOptions) {
  return new StringEncryption(argsOptions);
}

INITIALIZE_PASS(StringEncryption, "string-encryption",
                "Enable IR String Encryption", false, false)
