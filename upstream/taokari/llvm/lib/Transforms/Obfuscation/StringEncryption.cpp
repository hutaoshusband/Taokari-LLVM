#include "llvm/Transforms/Obfuscation/StringEncryption.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/Support/RandomNumberGenerator.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/Attributor.h"
#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscation/Utils.h"
#include "llvm/Transforms/Utils/GlobalStatus.h"
#include <algorithm>
#include <limits>
#include <set>
#include <utility>

#define DEBUG_TYPE "string-encryption"

using namespace llvm;

namespace {
struct StringEncryption : public ModulePass {
  static char ID;

  struct CSPEntry {
    CSPEntry()
        : ID(0), Offset(0), DecGV(nullptr), DecStatus(nullptr),
          PendingStatus(0), DoneStatus(0), IsUTF16(false) {}

    unsigned ID;
    unsigned Offset;
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
  GlobalVariable *EncryptedStringTable = nullptr;
  Function *SharedDecFuncI8 = nullptr;
  Function *SharedDecFuncI16 = nullptr;
  Function *SharedScrubFuncI8 = nullptr;
  Function *SharedScrubFuncI16 = nullptr;
  std::set<GlobalVariable *> MaybeDeadGlobalVars;
  uint32_t BuildNonce = 0;

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
                                              bool InvertBranchShape);
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
};
} // anonymous namespace

char StringEncryption::ID = 0;

bool StringEncryption::runOnModule(Module &M) {
  SmallPtrSet<GlobalVariable *, 16> ConstantStringUsers;

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
  if (hasI8Strings)
    SharedDecFuncI8 =
        buildSharedDecryptFunction(&M, false, (BuildNonce & 1) != 0);
  if (hasI16Strings)
    SharedDecFuncI16 =
        buildSharedDecryptFunction(&M, true, (BuildNonce & 2) != 0);
  if (ArgsOptions->cseOpt()->stringReencryptAfterUse()) {
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

  // emit the constant string pool
  // | junk bytes | key 1 | encrypted string 1 | junk bytes | key 2 | encrypted
  // string 2 | ...
  std::vector<uint8_t> Data;
  std::vector<uint8_t> JunkBytes;

  JunkBytes.reserve(32);
  for (CSPEntry *Entry : ConstantStringPool) {
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
      Data.insert(Data.end(), Entry->Data.begin(), Entry->Data.end());
    } else {
      // for UTF-16: write keys as little-endian uint16_t bytes
      for (uint16_t w : Entry->EncKey16) {
        Data.push_back(static_cast<uint8_t>(w & 0xff));
        Data.push_back(static_cast<uint8_t>((w >> 8) & 0xff));
      }
      // append Data16 as little-endian bytes
      for (uint16_t w : Entry->Data16) {
        Data.push_back(static_cast<uint8_t>(w & 0xff));
        Data.push_back(static_cast<uint8_t>((w >> 8) & 0xff));
      }
    }
  }

  Constant *CDA =
      ConstantDataArray::get(M.getContext(), ArrayRef<uint8_t>(Data));
  EncryptedStringTable =
      new GlobalVariable(M, CDA->getType(), false, GlobalValue::PrivateLinkage,
                         CDA, "EncryptedStringTable");

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

  // delete unused global variables
  deleteUnusedGlobalVariable();
  return Changed;
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
  Mixed ^= ((Entry->ID + 1u) * 0x5du) & 0xffu;
  Mixed ^= ((Position + 1u) * 0x3bu + KeyIndex * 0x11u) & 0xffu;
  return static_cast<uint8_t>(Mixed);
}

uint16_t StringEncryption::mixKey16(uint16_t Key, uint32_t KeyIndex,
                                    uint32_t Position,
                                    const CSPEntry *Entry) const {
  uint32_t Mixed = Key;
  Mixed ^= (BuildNonce >> ((Position & 1) * 16)) & 0xffffu;
  Mixed ^= ((Entry->ID + 1u) * 0x45d9u) & 0xffffu;
  Mixed ^= ((Position + 1u) * 0x9e37u + KeyIndex * 0x0101u) & 0xffffu;
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

//
// static void goron_decrypt_string(uint8_t *plain_string, const uint8_t *data)
//{
//  const uint8_t *key = data;
//  uint32_t key_size = 1234;
//  uint8_t *es = (uint8_t *) &data[key_size];
//  uint32_t i;
//  uint8_t last_decrypted_char = 0;
//  for (i = 0;i < 5678;i ++) {
//    uint32_t key_index = i % key_size;
//    uint8_t current_key = key[key_index];
//    uint8_t ds;
//    if ((key_index * current_key) % 2 == 0) {
//      ds = es[i] + last_decrypted_char;
//      ds = ds ^ current_key;
//      ds = ~ds;
//    } else {
//      ds = es[i] - last_decrypted_char;
//      ds = ds ^ current_key;
//      ds = -ds;
//    }
//    ds = ds ^ current_key;
//    last_decrypted_char = ds;
//    plain_string[i] = ds;
//  }
//}

Function *StringEncryption::buildSharedDecryptFunction(Module *M, bool IsUTF16,
                                                       bool InvertBranchShape) {
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> IRB(Ctx);

  Type *PlainEltTy = IsUTF16 ? Type::getInt16Ty(Ctx) : Type::getInt8Ty(Ctx);
  PointerType *PtrTy = PointerType::getUnqual(Ctx);
  Type *I32Ty = Type::getInt32Ty(Ctx);

  // Shared signature: void(ptr plain_string, ptr data, i32 key_elem_size, i32
  // data_size, ptr dec_status, i32 done_status, i32 string_id, i32 build_nonce)
  FunctionType *FuncTy = FunctionType::get(
      Type::getVoidTy(Ctx),
      {PtrTy, PtrTy, I32Ty, I32Ty, PtrTy, I32Ty, I32Ty, I32Ty}, false);
  Function *DecFunc = Function::Create(
      FuncTy, GlobalValue::PrivateLinkage,
      IsUTF16 ? "goron_decrypt_string_i16" : "goron_decrypt_string_i8", M);
  DecFunc->addFnAttr(Attribute::NoInline);
  DecFunc->addFnAttr(Attribute::OptimizeForSize);

  auto ArgIt = DecFunc->arg_begin();
  Argument *PlainString = ArgIt++;
  Argument *Data = ArgIt++;
  Argument *KeyElemSizeArg = ArgIt++;
  Argument *DataSizeArg = ArgIt++;
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

  Value *EncPtr = IRB.CreateInBoundsGEP(IRB.getInt8Ty(), Data, KeySizeBytesVal);
  Value *DecStatus = IRB.CreateLoad(I32Ty, DecStatusArg);
  if (InvertBranchShape) {
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
  Value *StringPart = IRB.CreateMul(IRB.CreateAdd(StringIDArg, IRB.getInt32(1)),
                                    IRB.getInt32(IsUTF16 ? 0x45d9 : 0x5d));
  StringPart = IRB.CreateAnd(StringPart, Mask);
  Value *PositionPart =
      IRB.CreateMul(IRB.CreateAdd(LoopCounter, IRB.getInt32(1)),
                    IRB.getInt32(IsUTF16 ? 0x9e37 : 0x3b));
  Value *KeyIndexPart =
      IRB.CreateMul(KeyIdx, IRB.getInt32(IsUTF16 ? 0x0101 : 0x11));
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
  Value *BrCond = InvertBranchShape
                      ? IRB.CreateICmpNE(BrKey, IRB.getInt32(0))
                      : IRB.CreateICmpEQ(BrKey, IRB.getInt32(0));
  IRB.CreateCondBr(BrCond, InvertBranchShape ? LoopBr1 : LoopBr0,
                   InvertBranchShape ? LoopBr0 : LoopBr1);

  IRB.SetInsertPoint(LoopBr0);
  {
    Value *Tmp = IRB.CreateAdd(EncChar, LastDecrypted);
    Tmp = IRB.CreateXor(Tmp, KeyChar);
    Tmp = IRB.CreateNot(Tmp);
    IRB.CreateBr(LoopEnd);
  }
  Value *DecChar0 = &*std::prev(LoopBr0->end(), 2); // the Not instruction

  IRB.SetInsertPoint(LoopBr1);
  {
    Value *Tmp = IRB.CreateSub(EncChar, LastDecrypted);
    Tmp = IRB.CreateXor(Tmp, KeyChar);
    Tmp = IRB.CreateNeg(Tmp);
    IRB.CreateBr(LoopEnd);
  }
  Value *DecChar1 = &*std::prev(LoopBr1->end(), 2); // the Neg instruction

  IRB.SetInsertPoint(LoopEnd);
  PHINode *BrDecChar = IRB.CreatePHI(PlainEltTy, 2);
  BrDecChar->addIncoming(DecChar0, LoopBr0);
  BrDecChar->addIncoming(DecChar1, LoopBr1);
  Value *DecChar = IRB.CreateXor(BrDecChar, KeyChar);

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

  return DecFunc;
}

Function *StringEncryption::buildSharedScrubFunction(Module *M, bool IsUTF16) {
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> IRB(Ctx);

  Type *PlainEltTy = IsUTF16 ? Type::getInt16Ty(Ctx) : Type::getInt8Ty(Ctx);
  PointerType *PtrTy = PointerType::getUnqual(Ctx);
  Type *I32Ty = Type::getInt32Ty(Ctx);
  FunctionType *FuncTy = FunctionType::get(
      Type::getVoidTy(Ctx), {PtrTy, PtrTy, I32Ty, I32Ty, PtrTy, I32Ty}, false);
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
  Argument *DecStatusArg = ArgIt++;
  Argument *PendingStatusArg = ArgIt;

  PlainString->setName("plain_string");
  Data->setName("data");
  KeyElemSizeArg->setName("key_elem_size");
  DataSizeArg->setName("data_size");
  DecStatusArg->setName("dec_status");
  PendingStatusArg->setName("pending_status");

  BasicBlock *Enter = BasicBlock::Create(Ctx, "Enter", ScrubFunc);
  BasicBlock *LoopBody = BasicBlock::Create(Ctx, "LoopBody", ScrubFunc);
  BasicBlock *Exit = BasicBlock::Create(Ctx, "Exit", ScrubFunc);

  IRB.SetInsertPoint(Enter);
  Value *KeySizeBytesVal = IsUTF16 ? IRB.CreateShl(KeyElemSizeArg, 1)
                                   : static_cast<Value *>(KeyElemSizeArg);
  Value *EncPtr = IRB.CreateInBoundsGEP(IRB.getInt8Ty(), Data, KeySizeBytesVal);
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
  const bool UseHeap = opt.stringHeapDecrypt();
  const bool UseStack = opt.stringLocalStackDecrypt() && !UseHeap;
  const bool ReencryptAfterUse = opt.stringReencryptAfterUse();
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
    Data = IRB.CreateInBoundsGEP(
        EncryptedStringTable->getValueType(), EncryptedStringTable,
        {IRB.getInt32(0), IRB.getInt32(Entry->Offset)});
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
    fixEH(IRB.CreateCall(DecFunc, {OutBuf, Data, IRB.getInt32(KeyElemSize),
                                   IRB.getInt32(DataSize), StatusPtr,
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
                            IRB.getInt32(DataSize), Entry->DecStatus,
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
                Value *Data = IRB.CreateInBoundsGEP(
                    EncryptedStringTable->getValueType(), EncryptedStringTable,
                    {IRB.getInt32(0), IRB.getInt32(Entry->Offset)});
                Function *DecFunc =
                    Entry->IsUTF16 ? SharedDecFuncI16 : SharedDecFuncI8;
                uint32_t KeyElemSize =
                    Entry->IsUTF16
                        ? static_cast<uint32_t>(Entry->EncKey16.size())
                        : static_cast<uint32_t>(Entry->EncKey.size());
                uint32_t DataSize =
                    Entry->IsUTF16 ? static_cast<uint32_t>(Entry->Data16.size())
                                   : static_cast<uint32_t>(Entry->Data.size());
                fixEH(IRB.CreateCall(DecFunc,
                                     {OutBuf, Data, IRB.getInt32(KeyElemSize),
                                      IRB.getInt32(DataSize), Entry->DecStatus,
                                      IRB.getInt32(Entry->DoneStatus),
                                      IRB.getInt32(Entry->ID),
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
  return Changed;
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
