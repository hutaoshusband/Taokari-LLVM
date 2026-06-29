#include "llvm/Transforms/Obfuscation/OpaqueConstant.h"
#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscation/ObfuscationPassManager.h"
#include "llvm/ADT/Hashing.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/RandomNumberGenerator.h"

#include <algorithm>
#include <random>

#define DEBUG_TYPE "opaque-constant"

using namespace llvm;

static cl::opt<uint32_t> OcnstProbability(
    "taokari-ocnst-prob", cl::init(35), cl::NotHidden,
    cl::desc("Opaque-constant substitution probability, 0..100."));
static cl::opt<uint32_t> OcnstMinBits(
    "taokari-ocnst-min-bits", cl::init(16), cl::NotHidden,
    cl::desc("Minimum integer constant bit-width to substitute (default 16)."));

namespace {
struct OpaqueConstant : public FunctionPass {
  static char ID;
  ObfuscationOptions *ArgsOptions;
  std::mt19937_64 RNG;
  uint64_t BuildSeed = 0;

  OpaqueConstant(ObfuscationOptions *argsOptions) : FunctionPass(ID) {
    this->ArgsOptions = argsOptions;
    uint64_t Seed = 0;
    if (auto EC = getRandomBytes(&Seed, sizeof(Seed)))
      report_fatal_error(StringRef("Failed to seed ocnst RNG: ") + EC.message());
    RNG = std::mt19937_64(Seed);
    BuildSeed = RNG();
  }

  StringRef getPassName() const override { return "OpaqueConstant"; }

  static uint64_t deriveNonceValue(Function &F, uint64_t BuildSeed) {
    uint64_t NameHash = static_cast<uint64_t>(hash_value(F.getName()));
    std::mt19937_64 Gen(NameHash ^ BuildSeed);
    uint64_t Value = Gen();
    if (!Value)
      Value = 0x9e3779b97f4a7c15ull;
    return Value;
  }

  static GlobalVariable *getOrCreateNonce(Module &M, IntegerType *Int64,
                                          Function &F, uint64_t BuildSeed) {
    Twine Name = Twine(F.getName()) + ".ocnst.nonce";
    if (auto *GV = M.getGlobalVariable(Name.str(), true))
      return GV;
    auto *Init = ConstantInt::get(Int64, deriveNonceValue(F, BuildSeed));
    auto *GV = new GlobalVariable(M, Int64, false, GlobalValue::PrivateLinkage,
                                  Init, Name.str(), nullptr,
                                  GlobalVariable::NotThreadLocal, 8, true);
    GV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    return GV;
  }

  bool runOnFunction(Function &F) override {
    if (F.isDeclaration() || F.isIntrinsic())
      return false;

    auto Opt = ArgsOptions->toObfuscate(ArgsOptions->ocnstOpt(), &F);
    if (!Opt.isEnabled())
      return false;

    const uint32_t Probability =
        OcnstProbability.getNumOccurrences()
            ? OcnstProbability
            : (Opt.probability() <= 100 ? Opt.probability() : 35);
    const unsigned MinBits =
        OcnstMinBits.getNumOccurrences() ? OcnstMinBits : 16;
    if (!Probability)
      return false;

    std::mt19937_64 FuncRNG(RNG());
    auto *Int64 = Type::getInt64Ty(F.getContext());
    GlobalVariable *Nonce =
        getOrCreateNonce(*F.getParent(), Int64, F, BuildSeed);
    bool Changed = false;

    for (BasicBlock &BB : F) {
      SmallVector<std::pair<Instruction *, unsigned>, 16> Sites;
      for (Instruction &I : BB) {
        if (I.hasMetadata("noobf") || I.isEHPad() || I.isTerminator())
          continue;
        if (isa<GetElementPtrInst>(&I) || isa<PHINode>(&I))
          continue;
        for (unsigned Op = 0; Op < I.getNumOperands(); ++Op) {
          auto *CI = dyn_cast<ConstantInt>(I.getOperand(Op));
          if (!CI)
            continue;
          if (CI->getBitWidth() < MinBits)
            continue;
          if ((FuncRNG() % 100) >= Probability)
            continue;
          Sites.emplace_back(&I, Op);
        }
      }
      for (auto &[I, Op] : Sites) {
        auto *CI = cast<ConstantInt>(I->getOperand(Op));
        auto *IntTy = cast<IntegerType>(CI->getType());
        uint64_t C = CI->getZExtValue();

        IRBuilder<NoFolder> IRB(I);
        Constant *Enc = ConstantExpr::getXor(
            ConstantInt::get(Int64, C),
            Nonce->getInitializer());
        GlobalVariable *EncGV = new GlobalVariable(
            *F.getParent(), Int64, false, GlobalValue::PrivateLinkage, Enc,
            Twine(F.getName()) + ".ocnst.enc." + Twine(FuncRNG() & 0xFFFF),
            nullptr, GlobalVariable::NotThreadLocal, 8, true);
        EncGV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
        Value *EncLoad = IRB.CreateAlignedLoad(Int64, EncGV, Align(8),
                                               "ocnst.enc.ld");
        Value *NonceLoad = IRB.CreateAlignedLoad(Int64, Nonce, Align(8),
                                                 "ocnst.nonce.ld");
        Value *Plain = IRB.CreateXor(EncLoad, NonceLoad, "ocnst.plain");
        Value *Result = IRB.CreateTrunc(Plain, IntTy, "ocnst.val");
        I->setOperand(Op, Result);
        Changed = true;
      }
    }
    return Changed;
  }
};
} // namespace

char OpaqueConstant::ID = 0;

FunctionPass *llvm::createOpaqueConstantPass(ObfuscationOptions *argsOptions) {
  return new OpaqueConstant(argsOptions);
}

PreservedAnalyses
llvm::OpaqueConstantNewPMPass::run(Function &F, FunctionAnalysisManager &) {
  if (!Options) {
    Options = getTaokariObfuscationOptions();
    Legacy = std::unique_ptr<FunctionPass>(
        createOpaqueConstantPass(Options.get()));
  }
  if (!Options->ocnstOpt()->isEnabled())
    return PreservedAnalyses::all();
  bool Changed = Legacy->runOnFunction(F);
  return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}
