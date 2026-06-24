#include "llvm/Transforms/Obfuscation/FunctionOutlining.h"
#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Analysis/AssumptionCache.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/RandomNumberGenerator.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/CodeExtractor.h"
#include "llvm/Transforms/Utils/Cloning.h"

#include <random>

#define DEBUG_TYPE "outline"

using namespace llvm;

static cl::opt<uint32_t> OutlineProbability(
    "taokari-outline-prob", cl::init(35), cl::NotHidden,
    cl::desc("Function outlining block selection probability, 0..100."));
static cl::opt<uint32_t> OutlineMaxShards(
    "taokari-outline-max-shards", cl::init(4), cl::NotHidden,
    cl::desc("Hard cap on outlined helper functions per source function."));
static cl::opt<uint32_t> OutlineMinSize(
    "taokari-outline-min-size", cl::init(3), cl::NotHidden,
    cl::desc("Minimum instruction count for a block to be worth outlining."));

namespace {
struct FunctionOutlining : public FunctionPass {
  static char ID;
  ObfuscationOptions *ArgsOptions;
  std::mt19937_64 RNG;

  FunctionOutlining(ObfuscationOptions *ArgsOptions) : FunctionPass(ID) {
    this->ArgsOptions = ArgsOptions;
    uint64_t Seed = 0;
    if (auto EC = llvm::getRandomBytes(&Seed, sizeof(Seed)))
      report_fatal_error(StringRef("Failed to seed outlining RNG: ") +
                         EC.message());
    RNG = std::mt19937_64(Seed);
  }

  StringRef getPassName() const override { return "FunctionOutlining"; }

  bool runOnFunction(Function &F) override {
    if (F.isDeclaration() || F.isIntrinsic())
      return false;
    // Never re-outline a shard we just produced, otherwise each shard becomes
    // an outlining target itself and the call graph explodes exponentially.
    if (F.getName().contains(".shard"))
      return false;
    // Outlining a function that participates in EH splits funclet colouring
    // and breaks codegen; leave EH functions alone.
    if (F.hasPersonalityFn())
      return false;
    // CodeExtractor rewrites varargs handling; only safe on fixed-arity.
    if (F.isVarArg())
      return false;

    auto Opt = ArgsOptions->toObfuscate(ArgsOptions->outlineOpt(), &F);
    if (!Opt.isEnabled())
      return false;

    const uint32_t Probability =
        OutlineProbability.getNumOccurrences()
            ? OutlineProbability.getValue()
            : (Opt.probability() <= 100 ? Opt.probability() : 35);
    if (!Probability)
      return false;

    const uint32_t MaxShards = Opt.maxBlocks()
                                   ? Opt.maxBlocks()
                                   : OutlineMaxShards.getNumOccurrences()
                                         ? OutlineMaxShards.getValue()
                                         : 4;
    const uint32_t MinSize = OutlineMinSize.getValue();

    // Outlining needs a dominator tree so CodeExtractor can verify the
    // candidate region is well-formed.
    DominatorTree DT(F);
    AssumptionCache AC(F);
    CodeExtractorAnalysisCache CEAC(F);

    // Find blocks with enough real instructions to be worth splitting. We
    // carve a tail region out of each candidate and extract that tail into a
    // shard, so even a straight-line single-block function becomes a caller
    // + helper pair.
    SmallVector<BasicBlock *, 32> Candidates;
    for (BasicBlock &BB : F) {
      if (hasOutlinableTail(BB, MinSize))
        Candidates.push_back(&BB);
    }

    std::mt19937_64 FuncRNG(RNG());
    uint32_t Shards = 0;
    bool Changed = false;
    for (BasicBlock *BB : Candidates) {
      if (Shards >= MaxShards)
        goto finish;
      if ((FuncRNG() % 100) >= Probability)
        continue;
      if (!hasOutlinableTail(*BB, MinSize))
        continue;
      if (outlineTail(F, *BB, DT, AC, CEAC, MinSize, FuncRNG)) {
        ++Shards;
        Changed = true;
        DT.recalculate(F);
      }
    }

  finish:
    return Changed;
  }

  // Count real (non-terminator, non-debug) instructions in a block.
  static uint32_t realSize(BasicBlock &BB) {
    uint32_t N = 0;
    for (Instruction &I : BB) {
      if (I.isTerminator() || I.isDebugOrPseudoInst())
        continue;
      ++N;
    }
    return N;
  }

  // A block has an outlinable tail when it is real code, not the entry / EH /
  // PHI / landing-pad shapes CodeExtractor cannot safely carry, and has at
  // least MinSize+1 real instructions: one stays behind as the split anchor,
  // MinSize move into the shard.
  static bool hasOutlinableTail(BasicBlock &BB, uint32_t MinSize) {
    if (BB.empty() || BB.isEHPad())
      return false;
    if (isa<PHINode>(BB.begin()))
      return false;
    auto *Term = BB.getTerminator();
    if (!Term)
      return false;

    // The tail must end in a single successor so the extracted region has one
    // exit and no return dispatch. A ret terminator leaves the function, which
    // is fine: the shard's single exit is the (empty) remainder of the caller
    // block.
    if (auto *Br = dyn_cast<BranchInst>(Term)) {
      if (!Br->isUnconditional())
        return false;
    } else if (isa<SwitchInst>(Term)) {
      return false;
    } else if (isa<UnreachableInst>(Term)) {
      return false;
    } else if (!isa<BranchInst>(Term) && !isa<ReturnInst>(Term)) {
      return false;
    }

    if (realSize(BB) < MinSize + 1)
      return false;

    // Reject blocks that are EH unwind targets: they carry funclet colouring.
    for (BasicBlock *Pred : predecessors(&BB)) {
      auto *PT = Pred->getTerminator();
      if (isa<InvokeInst>(PT) || isa<CatchSwitchInst>(PT) ||
          isa<CatchReturnInst>(PT) || isa<ResumeInst>(PT) ||
          isa<CleanupReturnInst>(PT))
        return false;
    }
    return true;
  }

  // Split BB so a tail of at least MinSize real instructions becomes its own
  // single-predecessor / single-successor block, then extract that tail.
  bool outlineTail(Function &F, BasicBlock &BB, DominatorTree &DT,
                   AssumptionCache &AC, CodeExtractorAnalysisCache &CEAC,
                   uint32_t MinSize, std::mt19937_64 &FuncRNG) {
    // Choose a split point past the allocas / pseudo / debug prologue so the
    // tail carries only real computation. Leave at least one real instruction
    // in the caller half as the anchor for the call site.
    Instruction *Anchor = nullptr;
    Instruction *SplitPt = nullptr;
    for (Instruction &I : BB) {
      if (I.isTerminator() || I.isDebugOrPseudoInst() || isa<AllocaInst>(&I))
        continue;
      if (!Anchor) {
        Anchor = &I;       // first real instruction stays in the caller
        continue;
      }
      SplitPt = &I;        // tail starts at the second real instruction
      break;
    }
    if (!SplitPt)
      return false;

    BasicBlock *Tail = SplitBlock(&BB, SplitPt, &DT, nullptr, nullptr,
                                  BB.getName() + ".outline.tail");
    if (!Tail)
      return false;

    SmallVector<BasicBlock *, 1> Blocks{Tail};
    CodeExtractor Ext(Blocks, &DT, /*AggregateArgs=*/false, nullptr, nullptr,
                      &AC, /*AllowVarArgs=*/false, /*AllowAlloca=*/false,
                      /*AllocationBlock=*/nullptr,
                      /*Suffix=*/".outline",
                      /*ArgsInZeroAddressSpace=*/false);
    if (!Ext.isEligible())
      return false;

    Function *Shard = Ext.extractCodeRegion(CEAC);
    if (!Shard)
      return false;

    // Keep the shard private to this TU and mark it noinline so it survives as
    // a separate call target for the decompiler to chase.
    Shard->setLinkage(GlobalValue::InternalLinkage);
    Shard->addFnAttr(Attribute::NoInline);
    Shard->setName(F.getName() + ".shard" + Twine(FuncRNG() & 0xffff));
    return true;
  }
};
} // namespace

char FunctionOutlining::ID = 0;

FunctionPass *
llvm::createFunctionOutliningPass(ObfuscationOptions *ArgsOptions) {
  return new FunctionOutlining(ArgsOptions);
}
