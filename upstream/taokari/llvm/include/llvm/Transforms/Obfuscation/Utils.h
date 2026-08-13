#ifndef __UTILS_OBF__
#define __UTILS_OBF__

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"

#include <random>
#include <vector>

using namespace llvm;

struct CreatePageTableArgs {
  unsigned                           CountLoop;
  std::string                        GVNamePrefix;
  std::mt19937_64 *                  RNG;
  Module *                           M;
  std::vector<Constant *> *          Objects;
  DenseMap<Constant *, unsigned> *   IndexMap;
  DenseMap<Constant *, uint64_t> *   ObjectKeys;
  SmallVectorImpl<GlobalVariable *> *OutPageTable;
  uint64_t                           PtrEncKey = 0;
  unsigned                           FakeEntries = 0;
  bool                               TwoShare = false;
  GlobalVariable **                  OutObjectShareTable = nullptr;
  Constant *                         FakeFill = nullptr;
};


struct BuildDecryptArgs {
  unsigned FuncLoopCount;
  unsigned NextIndex;
  Value *NextIndexValue;
  Function *Fn;
  Instruction *InsertBefore;
  Type *LoadTy;
  SmallVectorImpl<GlobalVariable *> *ModulePageTable;
  SmallVectorImpl<GlobalVariable *> *FuncPageTable;
  uint64_t ModuleKey;
  uint64_t FuncKey;
  uint64_t PtrEncKey;
  GlobalVariable *ObjectShareTable = nullptr;
  uint64_t RuntimeSeed = 0;
  bool UseMBA = false;
  bool IntegrityCheck = false;
  int PtrAuthKey; // -1 = no PAC, 0 = IA (code), 2 = DA (data)
  uint64_t PtrAuthDisc; // ptrauth discriminator
};

IntegerType *getPageTableIntTy(Module &M);
bool valueEscapes(Instruction *Inst);
void fixStack(Function *f);
CallBase *fixEH(CallBase *CB);
void LowerConstantExpr(Function &F);
bool expandConstantExpr(Function &F);
AllocaInst *createConstantSeedCache(Function &F, std::mt19937_64 &rng,
                                    bool volatileSeed);
unsigned chooseFakeEntryCount(std::mt19937_64 &rng, unsigned realEntries);
unsigned choosePageTableDepth(std::mt19937_64 &rng, unsigned level);
unsigned chooseModulePageTableDepth(std::mt19937_64 &rng);
void createPageTable(const CreatePageTableArgs &args);
void enhancedPageTable(const CreatePageTableArgs &args,
                       DenseMap<Constant *, unsigned> *FuncIndexMap);
// True iff the function's target is AArch64 with pointer-authentication
// support (+pauth / armv8.3a+ / v9a). ptrauth.sign only lowers on such
// targets, so callers must gate PAC signing on this to avoid an
// unselectable intrinsic.
bool targetHasPAuth(const Function &F);
bool isTaokariGeneratedHelper(const Function &F,
                              bool IncludeOutlinedShards = true);
bool functionParticipatesInNonLocalJump(const Function &F);
bool functionIsStdOrEhRuntime(const Function &F);
Value *buildPageTableDecryptIR(const BuildDecryptArgs &args);
Value *encryptConstant(Constant *plainConstant, Instruction *insertBefore,
                       std::mt19937_64 &rng, unsigned level,
                       AllocaInst *SeedCache = nullptr,
                       bool volatileSeed = true,
                       bool decryptorMBA = false);
Value *decryptConstantCipher(Value *EncLoad, ConstantInt *Key,
                             Constant *XorKey, unsigned BitWidth,
                             Type *OriginValTy, Instruction *insertBefore,
                             std::mt19937_64 &rng, unsigned level,
                             AllocaInst *SeedCache = nullptr,
                             bool volatileSeed = true,
                             bool decryptorMBA = false);
#endif
