//===- Flattening.cpp - Flattening Obfuscation pass------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements the flattening pass
//
//===----------------------------------------------------------------------===//

#include "llvm/IR/Constants.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/Transforms/Obfuscation/Flattening.h"
#include "llvm/Transforms/Obfuscation/LegacyLowerSwitch.h"
#include "llvm/Transforms/Obfuscation/Utils.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/ValueMapper.h"
#include "llvm/Support/RandomNumberGenerator.h"

#include <memory>
#include <random>
#include "llvm/ADT/DenseSet.h"

#define DEBUG_TYPE "flattening"

using namespace std;
using namespace llvm;

static constexpr uint32_t DefaultMaxInsts = 5000;
static constexpr uint32_t DefaultMaxBlocks = 200;
static constexpr uint32_t DefaultMaxAllocas = 64;

// Stats
STATISTIC(Flattened, "Functions flattened");

namespace {
struct Flattening : public FunctionPass {
  unsigned    pointerSize;
  static char ID; // Pass identification, replacement for typeid

  ObfuscationOptions *ArgsOptions;
  std::mt19937_64     RNG;

  Flattening(unsigned            pointerSize,
             ObfuscationOptions *argsOptions) : FunctionPass(ID) {
    this->pointerSize = pointerSize;
    this->ArgsOptions = argsOptions;
    uint64_t seed = 0;
    if (auto errorCode = llvm::getRandomBytes(&seed, sizeof(seed))) {
      llvm::report_fatal_error(
          StringRef("Failed to get random bytes for page table generation") +
          errorCode.message());
    }

    RNG = std::mt19937_64(seed);
  }

  bool runOnFunction(Function &F) override;
  bool flatten(Function *f);
};
}

bool Flattening::runOnFunction(Function &F) {
  if (F.isIntrinsic()) {
    return false;
  }
  Function *tmp = &F;
  bool      result = false;

  for (const auto &annotation : readAnnotate(&F)) {
    if (annotation.find("tao-noobf-fla") != std::string::npos) {
      return result;
    }
  }

  // Do we obfuscate
  const auto opt = ArgsOptions->toObfuscate(ArgsOptions->flaOpt(), &F);
  if (!opt.isEnabled()) {
    return result;
  }
  if (flatten(tmp)) {
    ++Flattened;
    result = true;
  }

  return result;
}

bool Flattening::flatten(Function *f) {
  SmallVector<BasicBlock *, 32> origBB;
  const auto flaOpt = ArgsOptions->flaOpt();
  const uint32_t maxInsts =
      flaOpt->maxInsts() ? flaOpt->maxInsts() : DefaultMaxInsts;
  const uint32_t maxBlocks =
      flaOpt->maxBlocks() ? flaOpt->maxBlocks() : DefaultMaxBlocks;
  const uint32_t maxAllocas =
      flaOpt->maxAllocas() ? flaOpt->maxAllocas() : DefaultMaxAllocas;
  const uint32_t flaLevel = flaOpt->level();
  const bool fortressMode = flaLevel >= 3;

  if (f->getInstructionCount() > maxInsts || f->size() > maxBlocks ||
      f->hasPersonalityFn()) {
    return false;
  }

  uint32_t allocaCount = 0;
  for (Instruction &I : instructions(f)) {
    if (isa<AllocaInst>(&I) && ++allocaCount > maxAllocas) {
      return false;
    }
    if (isa<InvokeInst>(&I) || isa<CleanupPadInst>(&I) ||
        isa<CatchPadInst>(&I) || isa<CatchSwitchInst>(&I)) {
      return false;
    }
  }

  auto &Ctx = f->getContext();
  Type *intType = Type::getInt32Ty(Ctx);
  if (pointerSize == 8) {
    intType = Type::getInt64Ty(Ctx);
  }
  auto *IntTy = cast<IntegerType>(intType);

  auto randWord = [&]() ->uint64_t {
    uint64_t v = RNG();
    if (pointerSize != 8)
      v &= 0xffffffffull;
    return v;
  };

  auto randConst = [&]() ->ConstantInt * {
    return ConstantInt::get(IntTy, randWord());
  };

  const uint64_t functionStateKey = randWord();
  auto randStateKey = [&]() ->ConstantInt * {
    return ConstantInt::get(IntTy, randWord() ^ functionStateKey);
  };

  // Lower switch
  auto lower = std::unique_ptr<FunctionPass>(createLegacyLowerSwitchPass());
  lower->runOnFunction(*f);

  // Save all original BB
  for (auto i = f->begin(); i != f->end(); ++i) {
    auto bb = &*i;
    origBB.push_back(bb);

    if (isa<InvokeInst>(bb->getTerminator()) || bb->isEHPad()) {
      return false;
    }
  }

  // Nothing to flatten
  if (origBB.size() <= 1) {
    return false;
  }

  // Remove first BB
  origBB.erase(origBB.begin());

  // Get a pointer on the first BB
  auto insertBlock = &*(f->begin());
  auto splitPos = insertBlock->getFirstNonPHIOrDbgOrAlloca();

  std::shuffle(origBB.begin(), origBB.end(), RNG);

  auto bbEndOfEntry = insertBlock->splitBasicBlock(splitPos, "first");
  origBB.insert(origBB.begin(), bbEndOfEntry);

  DenseSet<uint64_t>                    UsedCases;
  DenseMap<BasicBlock *, ConstantInt *> CaseVal;

  for (BasicBlock *BB : origBB) {
    uint64_t v;
    do {
      v = randWord();
    } while (v == 0 || UsedCases.count(v));
    UsedCases.insert(v);
    CaseVal[BB] = ConstantInt::get(IntTy, v);
  }

  ConstantInt *EntryCase = CaseVal[bbEndOfEntry];

  // Create switch variable and set as it
  IRBuilder<> IRB{insertBlock};
  const auto  switchVar = IRB.CreateAlloca(IntTy, nullptr, "switchVar");
  const auto  switchXorVar = IRB.CreateAlloca(IntTy, nullptr, "switchXor");
  AllocaInst *switchBogusVar = nullptr;
  if (fortressMode) {
    switchBogusVar = IRB.CreateAlloca(IntTy, nullptr, "switchBogus");
  }

  auto buildOpaqueEven = [&](IRBuilder<> &Builder, const Twine &Name) -> Value * {
    Value *seed = Builder.CreateLoad(IntTy, switchXorVar, true,
                                     Name + ".seed");
    Value *pair = Builder.CreateAdd(Builder.CreateMul(seed, seed),
                                    seed, Name + ".pair");
    return Builder.CreateAnd(pair, ConstantInt::get(IntTy, 1), Name + ".bit");
  };

  auto buildOpaqueTrue = [&](IRBuilder<> &Builder,
                             const Twine &Name) -> Value * {
    return Builder.CreateICmpEQ(buildOpaqueEven(Builder, Name),
                                ConstantInt::get(IntTy, 0), Name + ".true");
  };

  auto buildOpaqueFalse = [&](IRBuilder<> &Builder,
                              const Twine &Name) -> Value * {
    return Builder.CreateICmpNE(buildOpaqueEven(Builder, Name),
                                ConstantInt::get(IntTy, 0), Name + ".false");
  };

  auto buildXorExpr = [&](IRBuilder<> &Builder, Value *LHS, Value *RHS,
                          const Twine &Name) -> Value * {
    switch (fortressMode ? RNG() % 3 : RNG() % 2) {
    case 1: {
      Value *orV = Builder.CreateOr(LHS, RHS);
      Value *andV = Builder.CreateAnd(LHS, RHS);
      return Builder.CreateAnd(orV, Builder.CreateNot(andV), Name);
    }
    case 2: {
      Value *andV = Builder.CreateAnd(LHS, RHS);
      return Builder.CreateSub(Builder.CreateAdd(LHS, RHS),
                               Builder.CreateShl(andV, ConstantInt::get(IntTy, 1)),
                               Name);
    }
    default:
      return Builder.CreateXor(LHS, RHS, Name);
    }
  };

  // init：Encoded = EntryCase ^ XorKey
  ConstantInt *entryXor = randStateKey();
  Value *      entryEnc = IRB.CreateXor(EntryCase, entryXor);
  IRB.CreateStore(entryEnc, switchVar, true);
  IRB.CreateStore(entryXor, switchXorVar, true);

  // Create main loop
  auto bbLoopEntry =
      BasicBlock::Create(f->getContext(), "loopEntry", f, insertBlock);
  auto bbLoopEnd =
      BasicBlock::Create(f->getContext(), "loopEnd", f, insertBlock);

  // loopEntry
  IRB.SetInsertPoint(bbLoopEntry);
  Value *enc0 = IRB.CreateLoad(IntTy, switchVar, "switchVar.enc0");
  Value *xor0 = IRB.CreateLoad(IntTy, switchXorVar, "switchXor.xor0");

  Value *switchCondition = nullptr;
  if (flaLevel > 0) {
    ConstantInt *delta = randStateKey();
    Value *      enc1 = IRB.CreateXor(enc0, delta, "switchVar.enc1");
    Value *      xor1 = IRB.CreateXor(xor0, delta, "switchXor.xor1");
    IRB.CreateStore(enc1, switchVar, true);
    IRB.CreateStore(xor1, switchXorVar, true);
    switchCondition = IRB.CreateXor(enc1, xor1, "switchCond");
  } else {
    switchCondition = IRB.CreateXor(enc0, xor0, "switchCond");
  }

  // Move first BB on top
  insertBlock->moveBefore(bbLoopEntry);
  BranchInst::Create(bbLoopEntry, insertBlock);

  // loopEnd jump to loopEntry
  BranchInst::Create(bbLoopEntry, bbLoopEnd);

  auto swDefault =
      BasicBlock::Create(f->getContext(), "switchDefault", f, bbLoopEnd);
  auto swFakeCaseGate =
      BasicBlock::Create(f->getContext(), "switchFakeCaseGate", f, bbLoopEnd);
  auto swFakeSucc0 =
      fortressMode ? BasicBlock::Create(f->getContext(), "switchFakeSucc0", f,
                                        bbLoopEnd)
                   : nullptr;
  auto swFakeSucc1 =
      fortressMode ? BasicBlock::Create(f->getContext(), "switchFakeSucc1", f,
                                        bbLoopEnd)
                   : nullptr;
  auto swFakeSucc2 =
      fortressMode ? BasicBlock::Create(f->getContext(), "switchFakeSucc2", f,
                                        bbLoopEnd)
                   : nullptr;
  auto swDefaultJunk =
      BasicBlock::Create(f->getContext(), "switchDefaultJunk", f, bbLoopEnd);
  auto swTrap =
      BasicBlock::Create(f->getContext(), "switchTrap", f, bbLoopEnd);
  IRB.SetInsertPoint(swDefault);
  Value *junkA = IRB.CreateXor(randConst(), randConst(), "defaultJunkA");
  Value *junkB = IRB.CreateAdd(junkA, randConst(), "defaultJunkB");
  IRB.CreateStore(junkB, switchXorVar, true);
  IRB.CreateBr(swDefaultJunk);

  IRB.SetInsertPoint(swFakeCaseGate);
  if (fortressMode) {
    Value *fakeState = buildXorExpr(IRB, randConst(), randConst(), "fakeState");
    IRB.CreateStore(fakeState, switchBogusVar, true);
    IRB.CreateCondBr(buildOpaqueTrue(IRB, "fakeCaseGate"), swFakeSucc0, swTrap);
  } else {
    IRB.CreateCondBr(buildOpaqueTrue(IRB, "fakePred"), swDefaultJunk, swTrap);
  }

  if (fortressMode) {
    IRB.SetInsertPoint(swFakeSucc0);
    Value *fakeNext = buildXorExpr(IRB,
                                   IRB.CreateLoad(IntTy, switchBogusVar, true,
                                                  "fakeSucc0.load"),
                                   randConst(), "fakeSucc0.next");
    IRB.CreateStore(fakeNext, switchBogusVar, true);
    IRB.CreateCondBr(buildOpaqueTrue(IRB, "fakeSucc0.pred"), swFakeSucc1,
                     swTrap);

    IRB.SetInsertPoint(swFakeSucc1);
    Value *fakeMix = IRB.CreateAdd(IRB.CreateLoad(IntTy, switchBogusVar, true,
                                                  "fakeSucc1.load"),
                                   randConst(), "fakeSucc1.mix");
    IRB.CreateStore(fakeMix, switchBogusVar, true);
    IRB.CreateCondBr(buildOpaqueFalse(IRB, "fakeSucc1.pred"), swTrap,
                     swFakeSucc2);

    IRB.SetInsertPoint(swFakeSucc2);
    Value *fakeFinal = buildXorExpr(IRB,
                                    IRB.CreateLoad(IntTy, switchBogusVar, true,
                                                   "fakeSucc2.load"),
                                    randConst(), "fakeSucc2.final");
    IRB.CreateStore(fakeFinal, switchBogusVar, true);
    IRB.CreateBr(swDefaultJunk);
  }

  IRB.SetInsertPoint(swDefaultJunk);
  Value *junkC = IRB.CreateXor(
      IRB.CreateLoad(IntTy, switchXorVar, "defaultJunkC"), randConst(),
      "defaultJunkD");
  IRB.CreateStore(junkC, switchXorVar, true);
  IRB.CreateBr(swTrap);

  IRB.SetInsertPoint(swTrap);
  Function *trap =
      Intrinsic::getOrInsertDeclaration(f->getParent(), Intrinsic::trap);
  IRB.CreateCall(trap);
  IRB.CreateUnreachable();

  BasicBlock *switchBlock = bbLoopEntry;
  if (fortressMode) {
    auto dispatchLayout = RNG() % 3;
    switchBlock =
        BasicBlock::Create(f->getContext(), "switchDispatch", f, bbLoopEnd);

    if (dispatchLayout == 0) {
      BranchInst::Create(switchBlock, bbLoopEntry);
    } else if (dispatchLayout == 1) {
      auto dispatchGate =
          BasicBlock::Create(f->getContext(), "switchDispatchGate", f,
                             bbLoopEnd);
      IRB.SetInsertPoint(bbLoopEntry);
      IRB.CreateCondBr(buildOpaqueTrue(IRB, "dispatchGate.pred"),
                       dispatchGate, swFakeCaseGate);
      IRB.SetInsertPoint(dispatchGate);
      Value *gateMix = buildXorExpr(IRB, switchCondition,
                                    ConstantInt::get(IntTy, 0),
                                    "dispatchGate.mix");
      switchCondition = gateMix;
      IRB.CreateBr(switchBlock);
    } else {
      auto nestedOuter =
          BasicBlock::Create(f->getContext(), "switchNestedDispatch", f,
                             bbLoopEnd);
      IRB.SetInsertPoint(bbLoopEntry);
      IRB.CreateBr(nestedOuter);
      IRB.SetInsertPoint(nestedOuter);
      auto *outerSwitch = SwitchInst::Create(buildOpaqueEven(IRB, "nestedKey"),
                                             swFakeCaseGate, 1, nestedOuter);
      outerSwitch->addCase(ConstantInt::get(IntTy, 0), switchBlock);
    }
  }

  SmallVector<std::pair<ConstantInt *, BasicBlock *>, 64> DispatchCases;

  auto isCloneableForFakePath = [](BasicBlock *BB) -> bool {
    if (BB->isEHPad()) {
      return false;
    }
    for (Instruction &I : *BB) {
      if (isa<PHINode>(&I) || I.isEHPad() || I.isAtomic() ||
          I.mayHaveSideEffects() ||
          I.mayReadOrWriteMemory()) {
        return false;
      }
      if (auto *LI = dyn_cast<LoadInst>(&I)) {
        if (LI->isVolatile()) {
          return false;
        }
      }
      if (I.isTerminator()) {
        continue;
      }
      for (Value *Op : I.operands()) {
        if (auto *OpI = dyn_cast<Instruction>(Op)) {
          if (OpI->getParent() != BB) {
            return false;
          }
        }
      }
    }
    return true;
  };

  BasicBlock *fakeCaseTarget = swFakeCaseGate;
  if (fortressMode) {
    unsigned cloned = 0;
    for (BasicBlock *BB : origBB) {
      if (cloned >= 2) {
        break;
      }
      if (!isCloneableForFakePath(BB)) {
        continue;
      }
      ValueToValueMapTy VMap;
      BasicBlock *Clone = CloneBasicBlock(BB, VMap, ".tao.clone", f);
      for (Instruction &I : *Clone) {
        RemapInstruction(&I, VMap,
                         RF_NoModuleLevelChanges | RF_IgnoreMissingLocals);
      }
      Clone->getTerminator()->eraseFromParent();
      IRBuilder<> CloneIRB(Clone);
      Value *cloneJunk = buildXorExpr(CloneIRB, randConst(), randConst(),
                                      "cloneJunk");
      CloneIRB.CreateStore(cloneJunk, switchBogusVar, true);
      CloneIRB.CreateBr(fakeCaseTarget);
      fakeCaseTarget = Clone;
      ++cloned;
    }
  }

  // Remove branch jump from 1st BB and make a jump to the while
  ReplaceInstWithInst(f->begin()->getTerminator(),
                      BranchInst::Create(bbLoopEntry));

  // Put all BB in the switch (case 值使用纯随机表)
  for (auto bi = origBB.begin(); bi != origBB.end(); ++bi) {
    auto bb = *bi;

    // Move the BB inside the switch (only visual, no code logic)
    bb->moveBefore(bbLoopEnd);

    DispatchCases.push_back({CaseVal[bb], bb});
  }

  constexpr size_t DispatchBucketCount = 4;
  const uint64_t dispatchBucketSalt = randWord();
  auto forceDispatchBucket = [&](uint64_t value, uint64_t bucket) {
    return (value & ~(DispatchBucketCount - 1)) |
           ((bucket ^ dispatchBucketSalt) & (DispatchBucketCount - 1));
  };

  const size_t fakeCaseCount =
      flaLevel >= 4 ? std::max<size_t>(origBB.size(), 4)
                    : std::max<size_t>(1, origBB.size() / 2);
  for (size_t i = 0; i < fakeCaseCount; ++i) {
    uint64_t v;
    const uint64_t bucket =
        (CaseVal[origBB[i % origBB.size()]]->getLimitedValue() ^
         dispatchBucketSalt) & (DispatchBucketCount - 1);
    do {
      v = flaLevel >= 4 ? forceDispatchBucket(randWord(), bucket) : randWord();
    } while (v == 0 || UsedCases.count(v));
    UsedCases.insert(v);
    DispatchCases.push_back({ConstantInt::get(IntTy, v), fakeCaseTarget});
  }

  auto emitNoJumpTableDispatcher =
      [&](const SmallVectorImpl<std::pair<ConstantInt *, BasicBlock *>> &Cases) {
    constexpr size_t BucketCount = DispatchBucketCount;
    const uint64_t bucketSalt = dispatchBucketSalt;
    SmallVector<std::pair<ConstantInt *, BasicBlock *>, 16> Buckets[BucketCount];
    SmallVector<size_t, BucketCount> LiveBuckets;

    for (const auto &Case : Cases) {
      size_t bucket =
          ((Case.first->getLimitedValue() ^ bucketSalt) & (BucketCount - 1));
      if (Buckets[bucket].empty()) {
        LiveBuckets.push_back(bucket);
      }
      Buckets[bucket].push_back(Case);
    }

    IRB.SetInsertPoint(switchBlock);
    Value *bucketValue = IRB.CreateAnd(
        IRB.CreateXor(switchCondition, ConstantInt::get(IntTy, bucketSalt),
                      "switchBucketMix"),
        ConstantInt::get(IntTy, BucketCount - 1), "switchBucket");

    BasicBlock *bucketProbe = switchBlock;
    for (size_t i = 0; i < LiveBuckets.size(); ++i) {
      const size_t bucket = LiveBuckets[i];
      BasicBlock *bucketBody =
          BasicBlock::Create(Ctx, "switchBucketBody", f, bbLoopEnd);
      BasicBlock *nextBucket =
          i + 1 == LiveBuckets.size()
              ? swDefault
              : BasicBlock::Create(Ctx, "switchBucketProbe", f, bbLoopEnd);

      IRB.SetInsertPoint(bucketProbe);
      Value *bucketHit = IRB.CreateICmpEQ(
          bucketValue, ConstantInt::get(IntTy, bucket), "switchBucketHit");
      IRB.CreateCondBr(bucketHit, bucketBody, nextBucket);

      BasicBlock *caseProbe = bucketBody;
      for (size_t j = 0; j < Buckets[bucket].size(); ++j) {
        IRB.SetInsertPoint(caseProbe);
        BasicBlock *nextCase =
            j + 1 == Buckets[bucket].size()
                ? swDefault
                : BasicBlock::Create(Ctx, "switchDispatchProbe", f,
                                     bbLoopEnd);
        Value *hit = IRB.CreateICmpEQ(switchCondition,
                                      Buckets[bucket][j].first, "switchHit");
        IRB.CreateCondBr(hit, Buckets[bucket][j].second, nextCase);
        caseProbe = nextCase;
      }

      bucketProbe = nextBucket;
    }
  };

  if (flaLevel >= 4) {
    emitNoJumpTableDispatcher(DispatchCases);
  } else {
    auto switchI = SwitchInst::Create(switchCondition, swDefault, 0, switchBlock);
    for (const auto &Case : DispatchCases) {
      switchI->addCase(Case.first, Case.second);
    }
  }

  // Recalculate switchVar
  for (auto bi = origBB.begin(); bi != origBB.end(); ++bi) {
    const auto bb = *bi;

    // Ret BB
    if (bb->getTerminator()->getNumSuccessors() == 0) {
      continue;
    }

    IRB.SetInsertPoint(bb->getTerminator());

    auto writeNextEncoded = [&](Value *NextCaseVal) {
      Value *nextXor = randStateKey();
      switch (fortressMode ? RNG() % 5 : RNG() % 3) {
      case 1:
        nextXor = IRB.CreateNot(nextXor, "nextXor.not");
        break;
      case 2:
        nextXor = buildXorExpr(IRB, nextXor, randConst(), "nextXor.mix");
        break;
      case 3:
        nextXor = IRB.CreateAdd(nextXor, randConst(), "nextXor.addmix");
        break;
      case 4:
        nextXor = IRB.CreateSub(randConst(), nextXor, "nextXor.submix");
        break;
      default:
        break;
      }
      Value *nextEnc = buildXorExpr(IRB, NextCaseVal, nextXor, "nextEnc");

      if (fortressMode) {
        Value *bogusXor = randStateKey();
        Value *bogusState = buildXorExpr(IRB, randConst(), bogusXor,
                                         "bogusNextEnc");
        IRB.CreateStore(bogusState, switchBogusVar, true);
      }

      IRB.CreateStore(nextEnc, switchVar, true);
      IRB.CreateStore(nextXor, switchXorVar, true);

      IRB.CreateBr(bbLoopEnd);
      bb->getTerminator()->eraseFromParent();
    };

    // If it's a non-conditional jump
    if (bb->getTerminator()->getNumSuccessors() == 1) {
      auto tbb = bb->getTerminator()->getSuccessor(0);

      Value *nextCase = nullptr;
      if (CaseVal.count(tbb)) {
        nextCase = CaseVal[tbb];
      } else {
        nextCase = EntryCase;
      }

      writeNextEncoded(nextCase);
      continue;
    }

    // If it's a conditional jump
    if (bb->getTerminator()->getNumSuccessors() == 2 &&
        isa<BranchInst>(bb->getTerminator())) {
      auto *br = cast<BranchInst>(bb->getTerminator());

      auto *succT = br->getSuccessor(0);
      auto *succF = br->getSuccessor(1);

      Value *caseT =
          CaseVal.count(succT) ? CaseVal[succT] : EntryCase;
      Value *caseF =
          CaseVal.count(succF) ? CaseVal[succF] : EntryCase;

      Value *selectedCase =
          IRB.CreateSelect(br->getCondition(), caseT, caseF, "nextCase");

      writeNextEncoded(selectedCase);
      continue;
    }
  }

  fixStack(f);

  return true;
}


char                            Flattening::ID = 0;
static RegisterPass<Flattening> X("flattening", "Call graph flattening");

FunctionPass *llvm::createFlatteningPass(unsigned            pointerSize,
                                         ObfuscationOptions *argsOptions) {
  return new Flattening(pointerSize, argsOptions);
}
