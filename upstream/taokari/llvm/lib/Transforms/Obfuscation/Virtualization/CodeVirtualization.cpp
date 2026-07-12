#include "llvm/Transforms/Obfuscation/CodeVirtualization.h"
#include "llvm/Transforms/Obfuscation/DynamicProtection.h"
#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/MapVector.h"
#include "llvm/ADT/SetVector.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/Analysis/OptimizationRemarkEmitter.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/Pass.h"
#include "llvm/Support/Alignment.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/RandomNumberGenerator.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/CodeExtractor.h"

#include <algorithm>
#include <cstdint>
#include <functional>
#include <random>
#include <string>

#define DEBUG_TYPE "taokari-vmp"

using namespace llvm;

namespace {

static cl::opt<uint32_t> VMPMaxBytecodeWords(
    "taokari-vmp-max-bytecode-words", cl::init(2048), cl::NotHidden,
    cl::desc("Maximum bytecode words per VMP function before virtualization "
             "is refused; 0 disables the limit. SAFETY BUDGET: caps how "
             "large a single VM'd function can grow. Lower = faster compile "
             "and smaller binary; too low refuses big functions. Default "
             "2048 is the sane starting point; raise to 4096 or 8192 only "
             "for a single hand-picked +vmp function that needs the room "
             "(see Tier D in docs/TIERS.md)."));

static cl::opt<uint32_t> VMPPaddingPercent(
    "taokari-vmp-padding", cl::init(0), cl::NotHidden,
    cl::desc("Percent of VMP instructions followed by a semantic no-op "
             "padding opcode, 0..100. ANTI-FREQUENCY-ANALYSIS: flattens the "
             "handler-hit histogram a tracer records. 0 = off (fastest); "
             "5 = light noise (Max Protection default); 15 = heavy fortress "
             "noise (very expensive)."));

static cl::opt<uint32_t> VMPMaxBackEdges(
    "taokari-vmp-max-back-edges", cl::init(64), cl::NotHidden,
    cl::desc("Maximum CFG back edges allowed before VMP refuses a function; "
             "UINT32_MAX disables the limit. HOT-LOOP GUARD: virtualizing a "
             "tight loop makes it run under an interpreter and is "
             "catastrophic for runtime. Default 64 refuses hot-loop "
             "functions automatically; pass a larger value to override on a "
             "single +vmp function only. A function refused here is recorded "
             "as 'skipped' in the -taokari-vmp-compat-report."));

static cl::opt<uint32_t> VMPMaxBytecodeExpansion(
    "taokari-vmp-max-bytecode-expansion", cl::init(32), cl::NotHidden,
    cl::desc("Maximum bytecode words per original IR instruction before VMP "
             "refuses a function; 0 disables the limit. BLOW-UP BUDGET: "
             "caps how much the VM bytecode can exceed native IR size. "
             "Default 32 refuses pathological functions automatically under "
             "-taokari-max; pass 0 to disable for a single explicitly "
             "tuned +vmp function. A function refused here is recorded as "
             "'skipped' in the -taokari-vmp-compat-report."));

static cl::opt<std::string> VMPCompatReportPath(
    "taokari-vmp-compat-report", cl::init(""), cl::NotHidden,
    cl::desc("Write a TSV VMP compatibility report to this path. "
             "DIAGNOSTICS: one row per +vmp function with status "
             "(virtualized / partially virtualized / skipped), reason, "
             "bytecode word count, and split-region count. Use this to "
             "verify your +vmp functions actually virtualize."));

static cl::opt<bool> VMPTestIsolatedState(
    "taokari-vmp-test-isolated-state", cl::init(false), cl::NotHidden,
    cl::desc("Use per-function VM state for isolated VMP tests."));

struct VMPCompatEntry {
  std::string FunctionName;
  std::string Status;
  std::string Reason;
  unsigned Words = 0;
  unsigned SplitRegions = 0;
};

// Opcode encoding is the stable on-the-wire bytecode value. These
// integers must NOT change once bytecode is shipped; the interpreter handler
// table is keyed off them. L2 opcode-mapping/encryption layers will sit on
// top of these values, not replace them.
enum Opcode : int64_t {
  OpInitArg = 1,
  OpPushConst = 2,
  OpLoadSlot = 3,
  OpStoreSlot = 4,
  OpAdd = 5,
  OpSub = 6,
  OpXor = 7,
  OpCmpEq = 8,
  OpCmpNe = 9,
  OpCmpSgt = 10,
  OpCmpSlt = 11,
  OpCmpSge = 12,
  OpCmpSle = 13,
  OpJmp = 14,
  OpBrTrue = 15,
  OpRet = 16,
  OpSelect = 17,
  // L1.5.1 widened integer binary ops. Values 18+ are the new ISA;
  // 1..17 stay stable so existing bytecode keeps working.
  OpMul = 18,
  OpAnd = 19,
  OpOr = 20,
  OpShl = 21,
  OpLShr = 22,
  OpAShr = 23,
  OpSDiv = 24,
  OpUDiv = 25,
  OpSRem = 26,
  OpURem = 27,
  // L1.5.1 unsigned compares. Operands stay in canonical zext form;
  // unsigned comparison is width-agnostic, so these carry no VmTy immediate
  // (like EQ/NE).
  OpCmpUgt = 28,
  OpCmpUlt = 29,
  OpCmpUge = 30,
  OpCmpUle = 31,
  // L1.5.1 VM-local memory (middle way). Frame pointers are static
  // i64 indices into a per-interpreter Frame array; alloca/GEP resolve to
  // compile-time PushConst of the frame index. LoadPtr/StorePtr carry a VmTy
  // for width narrowing.
  OpLoadPtr = 32,
  OpStorePtr = 33,
  // L1.5.1 direct calls. OpCall fetches <calleeIdx> <nargs>
  // <resultVmTy>, pops nargs operand-stack values into a call-args buffer,
  // calls callees[calleeIdx] (resolved by the encoder to a direct Function*),
  // and pushes the i64 return narrowed by resultVmTy. Integer and pointer
  // args/returns are carried as i64; float/aggregate/vararg callees reject
  // the whole function. Indirect/virtual calls stay rejected.
  OpCall = 34,
  // External pointer argument load/store. Pointers are carried as i64
  // addresses; memory is accessed bytewise at the encoded integer width.
  OpLoadMem = 35,
  OpStoreMem = 36,
  // External pointer GEP with one runtime index: base + index * byte stride.
  OpGep = 37,
  OpPtrConst = 38,
  OpPad = 39,
  OpPad2 = 40,
  OpPad3 = 41,
  OpMemCpy = 42,
  OpMemSet = 43,
  OpMemMove = 44,
  // Dead anti-analysis handlers. They are emitted into the interpreter
  // dispatcher but never encoded into valid opcode maps.
  OpFakeArith = 48,
  OpFakeMem = 49,
  OpFakeCall = 50,
};

// How many operand-stack pops and bytecode immediates a handler
// consumes. The encoder uses these for stack-depth validation; the
// interpreter construction uses them for diagnostics only (each handler
// drives its own fetch()/pop() count for now, since some are data-dependent
// like OpInitArg which fetches two immediates).
struct HandlerStackShape {
  unsigned Pops = 0;
  unsigned Pushes = 0;
  unsigned Immediates = 0;
};

// Per-value width+signedness. The VM stores everything as i64, but
// arithmetic must wrap at the operand's native width and signed/unsigned
// distinctions (compare, shift, div/rem) must be preserved. The encoder
// records VmTy per value and emits it as immediates alongside the opcodes
// that need it; the interpreter narrows results back to the operand width.
//
// This is the L1.5.1 fix for the blind i64-promotion hazard: previously
// `int x = (a+b) ^ 5` with a=INT_MAX,b=1 computed (a+b) in i64 (no overflow)
// and only truncated at return, diverging from native i32 wraparound.
struct VmTy {
  uint8_t Bits = 64;
  bool Signed = true;
};

static VmTy vmTyFromType(Type *Ty) {
  VmTy T;
  if (auto *IntTy = dyn_cast<IntegerType>(Ty))
    T.Bits = IntTy->getBitWidth();
  // Integer types in C are signed by default; the encoder overrides Signed
  // per-use when it knows the signedness from the instruction (e.g. UDiv is
  // unsigned). For plain loads/args the conservative default is signed.
  return T;
}

static VmTy vmTyFromStackType(Type *Ty) {
  if (Ty->isPointerTy())
    return {64, false};
  return vmTyFromType(Ty);
}

// Pack VmTy into a single int64 immediate (bits 0..7 = width,
// bit 8 = signed). One word instead of two keeps the bytecode compact.
static int64_t packVmTy(VmTy T) {
  return static_cast<int64_t>(T.Bits) | (T.Signed ? (1LL << 8) : 0);
}
static VmTy unpackVmTy(int64_t V) {
  VmTy T;
  T.Bits = static_cast<uint8_t>(V & 0xFF);
  T.Signed = (V >> 8) & 1;
  return T;
}

struct Fixup {
  size_t Index;
  const BasicBlock *Target;
};

struct BytecodeProgram {
  SmallVector<int64_t, 64> Words;
  SmallVector<Fixup, 8> Fixups;
  SmallVector<size_t, 8> BlockStarts;
  SmallVector<Constant *, 8> PointerConsts;
  DenseMap<const Value *, unsigned> PointerConstIndex;
  uint64_t CrossTagSeed = 0;
};

// Handler descriptor. The interpreter builder iterates the table
// and emits one switch case per entry; opcode values stay the stable enum.
// This is the L1.5.2 refactor target: previously every opcode was a hand-
// written case in createInterpreter with no arity metadata. Now the
// table is the source of truth for stack shape, and the Emit closure is the
// only opcode-specific code.
//
// E operates on the IRBuilder already positioned at a fresh case block; it
// owns its own pop()/fetch() calls and must terminate the block with a
// branch back to Dispatch (or a ret).
struct Handler {
  Opcode Op;
  StringRef Name;
  HandlerStackShape Shape;
  std::function<void(IRBuilder<> &)> Emit;
};

struct CodeVirtualization : public ModulePass {
  static char ID;
  ObfuscationOptions *ArgsOptions;
  std::mt19937_64 RNG;
  // Per-module call-target table (L1.5.1). Populated lazily by
  // buildBytecode as it encounters direct callees or indirect-call stubs;
  // resolved into a __taokari_vmp_callees global by finalizeCalleeTable()
  // before the
  // interpreter is built. OpCall indexes into it.
  DenseMap<Function *, unsigned> CalleeIndex;
  SmallVector<Function *, 8> CalleeOrder;
  GlobalVariable *CalleeTable = nullptr;
  GlobalVariable *VMState = nullptr;
  uint64_t CalleeTableKey = 0;
  unsigned IndirectCallStubCounter = 0;
  struct ScheduleConstants {
    uint64_t Step = 0;
    uint64_t Mix1 = 0;
    uint64_t Mix2 = 0;
    uint64_t OpcodeDomain = 0;
    uint64_t OperandDomain = 0;
    uint64_t RotationDomain = 0;
    uint64_t CalleeDomain = 0;
    uint64_t RouteDomain = 0;
    uint64_t HashOffset = 0;
    uint64_t HashPrime = 0;
    uint64_t KeyMul = 0;
  } Schedule;

  enum class InterpParam {
    BC,
    BCTail,
    BCSplit,
    BCLen,
    PCMap,
    PtrTable,
    PtrCount,
    Args,
    ArgLen,
    Tamper,
    Tag,
    OpcodeMap,
    VMState,
    Key,
    Dummy
  };

  struct InterpreterInstance {
    Function *Fn;
    SmallVector<InterpParam, 16> Params;
  };

  CodeVirtualization(ObfuscationOptions *ArgsOptions) : ModulePass(ID) {
    this->ArgsOptions = ArgsOptions;
    uint64_t Seed = 0;
    if (auto EC = llvm::getRandomBytes(&Seed, sizeof(Seed)))
      report_fatal_error("failed to initialize VMP RNG");
    RNG = std::mt19937_64(Seed);
  }

  StringRef getPassName() const override {
    return "Taokari Code Virtualization";
  }

  uint64_t nextNonZeroKey() {
    uint64_t Key = 0;
    while (!Key)
      Key = RNG();
    return Key;
  }

  uint64_t nextOddKey() {
    uint64_t Key = 1;
    while (Key == 1)
      Key = nextNonZeroKey() | 1ULL;
    return Key;
  }

  void initScheduleConstants() {
    Schedule.Step = nextOddKey();
    Schedule.Mix1 = nextOddKey();
    Schedule.Mix2 = nextOddKey();
    Schedule.OpcodeDomain = nextNonZeroKey();
    Schedule.OperandDomain = nextNonZeroKey();
    Schedule.RotationDomain = nextOddKey();
    Schedule.CalleeDomain = nextNonZeroKey();
    Schedule.RouteDomain = nextNonZeroKey();
    Schedule.HashOffset = nextNonZeroKey();
    Schedule.HashPrime = nextOddKey();
    Schedule.KeyMul = nextOddKey();
  }

  bool isSupportedInt(Type *Ty) const {
    return Ty->isIntegerTy() && Ty->getIntegerBitWidth() <= 64;
  }

  bool isSupportedPointer(Type *Ty, const DataLayout &DL) const {
    if (!Ty->isPointerTy())
      return false;
    auto *PT = cast<PointerType>(Ty);
    return DL.getPointerSizeInBits(PT->getAddressSpace()) <= 64;
  }

  bool isSupportedArg(Type *Ty, const DataLayout &DL) const {
    return isSupportedInt(Ty) || isSupportedPointer(Ty, DL);
  }

  bool isSkippable(const Instruction &I) const {
    return isa<DbgInfoIntrinsic>(I) || isa<AssumeInst>(I);
  }

  bool isVMCompatibleCallSignature(const CallInst &CI,
                                   unsigned ExtraArgs) const {
    FunctionType *FT = CI.getFunctionType();
    if (FT->isVarArg())
      return false;
    const DataLayout &DL = CI.getFunction()->getParent()->getDataLayout();
    if (!FT->getReturnType()->isVoidTy() &&
        !isSupportedArg(FT->getReturnType(), DL))
      return false;
    for (const Use &Arg : CI.args()) {
      if (!isSupportedArg(Arg->getType(), DL))
        return false;
    }
    if (CI.arg_size() + ExtraArgs > 8)
      return false;
    return true;
  }

  // True if a direct CallInst is virtualizable by the L1.5.1 OpCall path.
  // Requirements: direct callee (Function*, not a function pointer), non-
  // variadic, int/pointer args, and int/pointer/void return.
  // Float/vector/aggregate args reject the caller.
  bool isVMCompatibleCall(const CallInst &CI) const {
    const Function *Callee = dyn_cast<Function>(CI.getCalledOperand());
    if (!Callee)
      return false;
    return isVMCompatibleCallSignature(CI, 0);
  }

  bool isVMCompatibleIndirectCall(const CallInst &CI) const {
    if (isa<Function>(CI.getCalledOperand()))
      return false;
    if (!CI.getCalledOperand()->getType()->isPointerTy())
      return false;
    // The generated stub receives the runtime callee pointer as arg 0.
    return isVMCompatibleCallSignature(CI, 1);
  }

  bool isSplitCandidateInstruction(Instruction &I) const {
    if (isSkippable(I) || isa<PHINode>(I) || I.isTerminator())
      return true;
    if (auto *BO = dyn_cast<BinaryOperator>(&I)) {
      if (!isSupportedInt(BO->getType()))
        return false;
      switch (BO->getOpcode()) {
      case Instruction::Add:
      case Instruction::Sub:
      case Instruction::Xor:
      case Instruction::Mul:
      case Instruction::And:
      case Instruction::Or:
      case Instruction::Shl:
      case Instruction::LShr:
      case Instruction::AShr:
      case Instruction::SDiv:
      case Instruction::UDiv:
      case Instruction::SRem:
      case Instruction::URem:
        return true;
      default:
        return false;
      }
    }
    if (auto *Cmp = dyn_cast<ICmpInst>(&I)) {
      if (!isSupportedInt(Cmp->getOperand(0)->getType()) ||
          !isSupportedInt(Cmp->getOperand(1)->getType()))
        return false;
      switch (Cmp->getPredicate()) {
      case CmpInst::ICMP_EQ:
      case CmpInst::ICMP_NE:
      case CmpInst::ICMP_SGT:
      case CmpInst::ICMP_SLT:
      case CmpInst::ICMP_SGE:
      case CmpInst::ICMP_SLE:
      case CmpInst::ICMP_UGT:
      case CmpInst::ICMP_ULT:
      case CmpInst::ICMP_UGE:
      case CmpInst::ICMP_ULE:
        return true;
      default:
        return false;
      }
    }
    if (auto *Sel = dyn_cast<SelectInst>(&I))
      return Sel->getCondition()->getType()->isIntegerTy(1) &&
             isSupportedInt(Sel->getTrueValue()->getType()) &&
             isSupportedInt(Sel->getFalseValue()->getType());
    if (auto *Cast = dyn_cast<CastInst>(&I)) {
      switch (Cast->getOpcode()) {
      case Instruction::SExt:
      case Instruction::ZExt:
      case Instruction::Trunc:
        return isSupportedInt(Cast->getSrcTy()) &&
               isSupportedInt(Cast->getDestTy());
      default:
        return false;
      }
    }
    if (auto *LD = dyn_cast<LoadInst>(&I))
      return isSupportedInt(LD->getType());
    if (auto *ST = dyn_cast<StoreInst>(&I))
      return isSupportedInt(ST->getValueOperand()->getType());
    if (isa<GetElementPtrInst>(I))
      return true;
    return false;
  }

  bool tryExtractVMSplitRegion(Function &F,
                               SmallVectorImpl<Function *> &SplitTargets) {
    for (BasicBlock &BB : F) {
      if (&BB == &F.getEntryBlock() || BB.isEHPad())
        continue;
      auto *Br = dyn_cast<BranchInst>(BB.getTerminator());
      if (!Br || !Br->isUnconditional())
        continue;

      bool HasWork = false;
      bool Supported = true;
      for (Instruction &I : BB) {
        if (!isSplitCandidateInstruction(I)) {
          Supported = false;
          break;
        }
        if (!isSkippable(I) && !isa<PHINode>(I) && !I.isTerminator())
          HasWork = true;
      }
      if (!Supported || !HasWork)
        continue;

      SmallVector<BasicBlock *, 1> Blocks{&BB};
      CodeExtractor Extractor(Blocks, nullptr, false, nullptr, nullptr,
                              nullptr, false, false, nullptr, "vmp.split");
      if (!Extractor.isEligible())
        continue;

      SetVector<Value *> Inputs, Outputs, Allocas;
      Extractor.findInputsOutputs(Inputs, Outputs, Allocas);
      if (Outputs.size() > 1)
        continue;

      CodeExtractorAnalysisCache CEAC(F);
      Function *Split = Extractor.extractCodeRegion(CEAC);
      if (!Split)
        continue;
      Split->addFnAttr(Attribute::NoInline);
      SplitTargets.push_back(Split);
      return true;
    }
    return false;
  }

  void addCompatEntry(SmallVectorImpl<VMPCompatEntry> &Entries, Function &F,
                      StringRef Status, StringRef Reason, unsigned Words = 0,
                      unsigned SplitRegions = 0) const {
    VMPCompatEntry Entry;
    Entry.FunctionName = std::string(F.getName());
    Entry.Status = std::string(Status);
    Entry.Reason = std::string(Reason);
    Entry.Words = Words;
    Entry.SplitRegions = SplitRegions;
    Entries.push_back(std::move(Entry));
  }

  void writeCompatReport(ArrayRef<VMPCompatEntry> Entries) const {
    if (VMPCompatReportPath.empty())
      return;
    std::error_code EC;
    raw_fd_ostream OS(VMPCompatReportPath, EC, sys::fs::OF_Text);
    if (EC) {
      errs() << "taokari-vmp: failed to write compatibility report '"
             << VMPCompatReportPath << "': " << EC.message() << "\n";
      return;
    }
    OS << "function\tstatus\treason\twords\tsplit_regions\n";
    for (const VMPCompatEntry &Entry : Entries) {
      OS << Entry.FunctionName << '\t' << Entry.Status << '\t'
         << Entry.Reason << '\t' << Entry.Words << '\t'
         << Entry.SplitRegions << '\n';
    }
  }

  bool shouldSkip(Function &F) const {
    if (F.isDeclaration() || F.isIntrinsic() || F.isVarArg())
      return true;
    if (F.getName().starts_with("__taokari_vmp_"))
      return true;
    if (!F.getReturnType()->isVoidTy() && !isSupportedInt(F.getReturnType()))
      return true;
    if (F.arg_size() > 8)
      return true;
    const DataLayout &DL = F.getParent()->getDataLayout();
    for (Argument &A : F.args())
      if (!isSupportedArg(A.getType(), DL))
        return true;
    return false;
  }

  bool hasUnsupportedIR(Function &F) const {
    for (BasicBlock &BB : F) {
      for (Instruction &I : BB) {
        if (isSkippable(I))
          continue;
        if (isa<PHINode>(I))
          continue;
        // Level 1 VM is toy integer IR only. Add EH support after this
        // compile/run path proves useful. PHI is supported
        // (L1.5.1): lowered to slot copies in predecessors. VM-local alloca/
        // load/store/constant-GEP are supported (L1.5.1 middle way): the
        // pointer-origin check happens in buildBytecode (needs whole-function
        // alloca context, which this const scan lacks). Direct CallInst with
        // int/pointer signature is supported (L1.5.1): buildBytecode rejects
        // incompatible direct or indirect callees.
        if (isa<InvokeInst>(I) || isa<ResumeInst>(I) ||
            isa<LandingPadInst>(I) ||
            isa<AtomicRMWInst>(I) || isa<AtomicCmpXchgInst>(I) ||
            isa<FenceInst>(I))
          return true;
        if (auto *BO = dyn_cast<BinaryOperator>(&I)) {
          if (!isSupportedInt(BO->getType()))
            return true;
          switch (BO->getOpcode()) {
          case Instruction::Add:
          case Instruction::Sub:
          case Instruction::Xor:
          // L1.5.1 widened integer binary ops.
          case Instruction::Mul:
          case Instruction::And:
          case Instruction::Or:
          case Instruction::Shl:
          case Instruction::LShr:
          case Instruction::AShr:
          case Instruction::SDiv:
          case Instruction::UDiv:
          case Instruction::SRem:
          case Instruction::URem:
            break;
          default:
            return true;
          }
          continue;
        }
        if (auto *Cmp = dyn_cast<ICmpInst>(&I)) {
          if (!isSupportedInt(Cmp->getOperand(0)->getType()) ||
              !isSupportedInt(Cmp->getOperand(1)->getType()))
            return true;
          switch (Cmp->getPredicate()) {
          case CmpInst::ICMP_EQ:
          case CmpInst::ICMP_NE:
          case CmpInst::ICMP_SGT:
          case CmpInst::ICMP_SLT:
          case CmpInst::ICMP_SGE:
          case CmpInst::ICMP_SLE:
          case CmpInst::ICMP_UGT:
          case CmpInst::ICMP_ULT:
          case CmpInst::ICMP_UGE:
          case CmpInst::ICMP_ULE:
            break;
          default:
            return true;
          }
          continue;
        }
        if (auto *Sel = dyn_cast<SelectInst>(&I)) {
          if (!Sel->getCondition()->getType()->isIntegerTy(1) ||
              !isSupportedInt(Sel->getTrueValue()->getType()) ||
              !isSupportedInt(Sel->getFalseValue()->getType()))
            return true;
          continue;
        }
        if (auto *Cast = dyn_cast<CastInst>(&I)) {
          const DataLayout &DL = F.getParent()->getDataLayout();
          switch (Cast->getOpcode()) {
          case Instruction::SExt:
          case Instruction::ZExt:
          case Instruction::Trunc:
            if (!isSupportedInt(Cast->getSrcTy()) ||
                !isSupportedInt(Cast->getDestTy()))
              return true;
            break;
          case Instruction::PtrToInt:
            if (!isSupportedPointer(Cast->getSrcTy(), DL) ||
                !isSupportedInt(Cast->getDestTy()))
              return true;
            break;
          case Instruction::IntToPtr:
            if (!isSupportedInt(Cast->getSrcTy()) ||
                !isSupportedPointer(Cast->getDestTy(), DL))
              return true;
            break;
          default:
            return true;
          }
          continue;
        }
        // VM-local memory (L1.5.1 middle way). Allow AllocaInst,
        // LoadInst, StoreInst, GetElementPtrInst here; buildBytecode rejects
        // the function if any pointer origin is non-VM-local (external arg,
        // global, etc.) -- that check needs whole-function alloca context.
        if (isa<AllocaInst>(I) || isa<LoadInst>(I) || isa<StoreInst>(I) ||
            isa<GetElementPtrInst>(I))
          continue;
        if (auto *SI = dyn_cast<SwitchInst>(&I)) {
          if (!isSupportedInt(SI->getCondition()->getType()))
            return true;
          for (auto Case : SI->cases())
            if (!isSupportedInt(Case.getCaseValue()->getType()))
              return true;
          continue;
        }
        // CallInst allowed (L1.5.1); incompatible signatures still reject via
        // buildBytecode's call gates.
        if (isa<CallInst>(I))
          continue;
        if (isa<BranchInst>(I) || isa<ReturnInst>(I))
          continue;
        return true;
      }
    }
    return false;
  }

  unsigned slotFor(DenseMap<const Value *, unsigned> &Slots, const Value *V) {
    auto It = Slots.find(V);
    if (It != Slots.end())
      return It->second;
    unsigned Slot = Slots.size();
    Slots[V] = Slot;
    return Slot;
  }

  unsigned pointerConstFor(BytecodeProgram &P, Constant *C) {
    auto It = P.PointerConstIndex.find(C);
    if (It != P.PointerConstIndex.end())
      return It->second;
    unsigned Idx = P.PointerConsts.size();
    P.PointerConstIndex[C] = Idx;
    P.PointerConsts.push_back(C);
    return Idx;
  }

  // True if Ty can live in the VM-local frame (integer scalars,
  // arrays of integers, or simple aggregates of integers -- anything we can
  // bucket into i64 slots). Pointers, floats, and nested pointer/float
  // aggregates are rejected (deferred to the L2 full-pointer step).
  bool isFrameCompatible(Type *Ty) const {
    if (Ty->isIntegerTy())
      return true;
    if (auto *Arr = dyn_cast<ArrayType>(Ty))
      return isFrameCompatible(Arr->getElementType());
    if (auto *St = dyn_cast<StructType>(Ty))
      return St->getNumElements() > 0 &&
             all_of(St->elements(),
                    [this](Type *E) { return isFrameCompatible(E); });
    return false;
  }

  // Emit a value-push that carries the value's VmTy so the
  // interpreter can sign/zero-extend into the i64 slot correctly. For a
  // ConstantInt we encode the full sext/zext value directly; for a slot we
  // emit its index. In both cases a packed VmTy immediate follows so the
  // interpreter narrows/promotes the right way before any consumer sees it.
  // VM-local pointers (alloca-derived) resolve to a PushConst of the frame
  // slot index via resolveFramePtr. Pointer args use their locals slot as a
  // raw host address for OpLoadMem/OpStoreMem.
  bool emitValue(BytecodeProgram &P, DenseMap<const Value *, unsigned> &Slots,
                 DenseMap<const AllocaInst *, unsigned> &AllocaBase,
                 unsigned &NextFrameSlot, Value *V) {
    // VM-local pointer: alloca or constant-offset GEP of an alloca.
    if (V->getType()->isPointerTy()) {
      if (auto *GV = dyn_cast<GlobalVariable>(V)) {
        P.Words.push_back(OpPtrConst);
        P.Words.push_back(pointerConstFor(P, GV));
        return true;
      }
      int64_t FrameIdx = 0;
      if (resolveFramePtr(V, AllocaBase, NextFrameSlot, FrameIdx)) {
        P.Words.push_back(OpPushConst);
        P.Words.push_back(FrameIdx);
      } else {
        auto It = Slots.find(V);
        if (It == Slots.end())
          return false;
        P.Words.push_back(OpLoadSlot);
        P.Words.push_back(It->second);
      }
      P.Words.push_back(packVmTy(VmTy{64, false}));
      return true;
    }
    VmTy Ty = vmTyFromType(V->getType());
    if (auto *CI = dyn_cast<ConstantInt>(V)) {
      if (CI->getBitWidth() > 64)
        return false;
      P.Words.push_back(OpPushConst);
      P.Words.push_back(CI->getSExtValue());
      P.Words.push_back(packVmTy(Ty));
      return true;
    }
    auto It = Slots.find(V);
    if (It == Slots.end())
      return false;
    P.Words.push_back(OpLoadSlot);
    P.Words.push_back(It->second);
    P.Words.push_back(packVmTy(Ty));
    return true;
  }

  // Emit slot copies for every PHI in `Succ` whose incoming value
  // for predecessor `Pred` must be stored into the PHI's slot before control
  // transfers from Pred to Succ. This is the L1.5.1 PHI lowering: the PHI
  // result is materialized as a locals slot, and each predecessor writes its
  // incoming value into that slot just before branching. Handles loop-carry
  // PHIs naturally (the slot holds the previous iteration's value).
  bool emitPhiCopies(BytecodeProgram &P,
                     DenseMap<const Value *, unsigned> &Slots,
                     DenseMap<const AllocaInst *, unsigned> &AllocaBase,
                     unsigned &NextFrameSlot,
                     const BasicBlock *Pred, const BasicBlock *Succ) {
    for (const Instruction &I : *Succ) {
      auto *PN = dyn_cast<PHINode>(&I);
      if (!PN)
        break; // PHIs are always first in the block.
      int Idx = PN->getBasicBlockIndex(Pred);
      if (Idx < 0)
        return false; // malformed: no incoming for this predecessor.
      Value *Incoming = PN->getIncomingValue(Idx);
      // The incoming value may be UndefValue (e.g. unreachable predecessor);
      // skip such copies -- the slot stays whatever it was.
      if (isa<UndefValue>(Incoming))
        continue;
      if (!emitValue(P, Slots, AllocaBase, NextFrameSlot, Incoming))
        return false;
      P.Words.push_back(OpStoreSlot);
      P.Words.push_back(slotFor(Slots, PN));
    }
    return true;
  }

  // Resolve a VM-local pointer to a Frame slot index. Returns false
  // if the pointer origin is not VM-local (external arg, global, etc.) -- in
  // which case buildBytecode rejects the whole function. V must be an
  // AllocaInst result, or a constant-offset GEP whose base is VM-local. The
  // Frame is an i64 array in the interpreter; each alloca reserves a run of
  // consecutive frame slots sized to the alloca's element count.
  //
  // Frame layout is built lazily: AllocaInst encountered during emission
  // reserve slots in `FrameMap` (alloca -> base index). GEP resolves by
  // walking to the base alloca and adding the constant byte offset / 8.
  bool resolveFramePtr(const Value *V,
                       DenseMap<const AllocaInst *, unsigned> &AllocaBase,
                       unsigned &NextFrameSlot, int64_t &OutIdx) const {
    // Strip a constant-offset GEP chain down to its base.
    APInt ByteOffset(64, 0);
    const Value *Base = V;
    while (auto *GEP = dyn_cast<GetElementPtrInst>(Base)) {
      if (!GEP->accumulateConstantOffset(
              GEP->getModule()->getDataLayout(), ByteOffset))
        return false; // non-constant index -> defer to L2
      Base = GEP->getPointerOperand();
    }
    const auto *AI = dyn_cast<AllocaInst>(Base);
    if (!AI)
      return false; // external/global pointer -> defer to L2
    auto It = AllocaBase.find(AI);
    if (It == AllocaBase.end())
      return false; // alloca not yet allocated (shouldn't happen post-scan)
    OutIdx = static_cast<int64_t>(It->second) +
             ByteOffset.getZExtValue() / sizeof(int64_t);
    return true;
  }

  bool isHostPointer(Value *V,
                     DenseMap<const AllocaInst *, unsigned> &AllocaBase,
                     unsigned &NextFrameSlot, const DataLayout &DL) const {
    int64_t FrameIdx = 0;
    return V->getType()->isPointerTy() &&
           !resolveFramePtr(V, AllocaBase, NextFrameSlot, FrameIdx) &&
           isSupportedPointer(V->getType(), DL);
  }

  // Build-time operand-stack depth check (L1.5.4). Walks the
  // bytecode simulating the max operand-stack depth using HandlerStackShape.
  // Fails (returns false) if the depth would exceed the fixed 64-slot Stack
  // alloca at any point -- otherwise the interpreter would silently overflow
  // into adjacent memory. Control-flow opcodes (Jmp/BrTrue/Ret) reset or
  // terminate the simulation conservatively; this is a safety bound, not a
  // precise abstract interpreter.
  bool checkStackDepth(const BytecodeProgram &P) const {
    constexpr unsigned kStackCap = 64;
    int64_t Depth = 0;
    int64_t MaxDepth = 0;
    size_t I = 0;
    size_t N = P.Words.size();
    while (I < N) {
      int64_t Op = P.Words[I++];
      if (Op < 0)
        return false;
      HandlerStackShape Shape = shapeOf(static_cast<Opcode>(Op));
      Depth -= static_cast<int64_t>(Shape.Pops);
      if (Depth < 0)
        return false; // underflow: malformed bytecode
      Depth += static_cast<int64_t>(Shape.Pushes);
      if (Depth > MaxDepth)
        MaxDepth = Depth;
      // Skip the trailing immediates this opcode consumes.
      I += Shape.Immediates;
    }
    return MaxDepth <= kStackCap;
  }

  bool buildBytecode(Function &F, BytecodeProgram &P) {
    DenseMap<const Value *, unsigned> Slots;
    DenseMap<const BasicBlock *, size_t> BlockStart;
    // VM-local frame allocator. Each AllocaInst reserves
    // ceil(allocSize / 8) consecutive frame slots (i64 units).
    DenseMap<const AllocaInst *, unsigned> AllocaBase;
    unsigned NextFrameSlot = 0;
    constexpr unsigned kFrameSlotCap = 64;

    // Pre-scan: reserve frame slots for every alloca so any later reference
    // (including a GEP ahead of the alloca in a different block) resolves.
    for (BasicBlock &BB : F) {
      for (Instruction &I : BB) {
        auto *AI = dyn_cast<AllocaInst>(&I);
        if (!AI)
          continue;
        Type *Ty = AI->getAllocatedType();
        // Only scalar/array integer or aggregate-of-integer types we can
        // cleanly bucket into i64 slots. Reject anything with pointers or
        // floats inside (the middle way is integer locals only).
        if (!isFrameCompatible(Ty))
          return false;
        uint64_t SizeBytes =
            Ty->isSized() ? F.getParent()->getDataLayout().getTypeAllocSize(Ty)
                          : 0;
        unsigned SlotsNeeded =
            static_cast<unsigned>((SizeBytes + 7) / 8);
        if (SlotsNeeded == 0)
          SlotsNeeded = 1;
        if (NextFrameSlot + SlotsNeeded > kFrameSlotCap)
          return false; // frame too large -> skip virtualization
        AllocaBase[AI] = NextFrameSlot;
        NextFrameSlot += SlotsNeeded;
      }
    }

    unsigned ArgIndex = 0;
    for (Argument &A : F.args()) {
      unsigned Slot = slotFor(Slots, &A);
      P.Words.append({OpInitArg, static_cast<int64_t>(Slot),
                      static_cast<int64_t>(ArgIndex++)});
    }

    for (BasicBlock &BB : F) {
      BlockStart[&BB] = P.Words.size();
      P.BlockStarts.push_back(P.Words.size());
      // pre-register PHI slots so any use of a PHI (including by
      // another PHI in the same block, or by an instruction before the PHI
      // list ends -- they're all at block top) resolves to the right slot.
      for (Instruction &I : BB) {
        auto *PN = dyn_cast<PHINode>(&I);
        if (!PN)
          break; // PHIs are always first; stop at the first non-PHI.
        if (!isSupportedInt(PN->getType()))
          return false;
        slotFor(Slots, PN);
      }
      for (Instruction &I : BB) {
        if (isSkippable(I))
          continue;
        if (isa<PHINode>(I)) {
          // PHI nodes produce no bytecode inline. Their effect is
          // the predecessor-side slot copies emitted by emitPhiCopies below.
          continue;
        }
        if (auto *BO = dyn_cast<BinaryOperator>(&I)) {
          if (!emitValue(P, Slots, AllocaBase, NextFrameSlot, BO->getOperand(0)) ||
              !emitValue(P, Slots, AllocaBase, NextFrameSlot, BO->getOperand(1)))
            return false;
          VmTy ResultTy = vmTyFromType(BO->getType());
          // signedness for the few ops where it matters at encode
          // time. Mul/And/Or/Xor/Add/Sub/Shl are sign-agnostic; the narrowing
          // uses the type width only. AShr is signed (arithmetic) shift, LShr
          // is unsigned (logical) shift; UDiv/URem unsigned, SDiv/SRem signed.
          // The interpreter opcode choice (OpAShr vs OpLShr, OpSDiv vs OpUDiv)
          // already encodes this, so the VmTy.Signed here is only consulted by
          // the narrowing helper, which for these ops behaves the same
          // regardless of Signed (the result fits in width either way).
          switch (BO->getOpcode()) {
          case Instruction::Add:
            P.Words.push_back(OpAdd);
            break;
          case Instruction::Sub:
            P.Words.push_back(OpSub);
            break;
          case Instruction::Xor:
            P.Words.push_back(OpXor);
            break;
          case Instruction::Mul:
            P.Words.push_back(OpMul);
            break;
          case Instruction::And:
            P.Words.push_back(OpAnd);
            break;
          case Instruction::Or:
            P.Words.push_back(OpOr);
            break;
          case Instruction::Shl:
            P.Words.push_back(OpShl);
            break;
          case Instruction::LShr:
            P.Words.push_back(OpLShr);
            break;
          case Instruction::AShr:
            P.Words.push_back(OpAShr);
            break;
          case Instruction::SDiv:
            P.Words.push_back(OpSDiv);
            break;
          case Instruction::UDiv:
            P.Words.push_back(OpUDiv);
            break;
          case Instruction::SRem:
            P.Words.push_back(OpSRem);
            break;
          case Instruction::URem:
            P.Words.push_back(OpURem);
            break;
          default:
            return false;
          }
          // operand/result width so the interpreter truncates the
          // i64 arithmetic back to the native width (fixes i32 wraparound).
          P.Words.push_back(packVmTy(ResultTy));
          P.Words.push_back(OpStoreSlot);
          P.Words.push_back(slotFor(Slots, &I));
          continue;
        }
        if (auto *Cmp = dyn_cast<ICmpInst>(&I)) {
          if (!emitValue(P, Slots, AllocaBase, NextFrameSlot, Cmp->getOperand(0)) ||
              !emitValue(P, Slots, AllocaBase, NextFrameSlot, Cmp->getOperand(1)))
            return false;
          // cmp operands are pushed in canonical zext form. Signed
          // compares (SGT/SLT/SGE/SLE) need the operands sign-extended from
          // their true width first, so the encoder emits a trailing VmTy
          // immediate for the signed variants; the handler fetches it and
          // sign-extends both operands before the ICmp. EQ/NE are sign-
          // agnostic and carry no immediate.
          VmTy OperandTy = vmTyFromType(Cmp->getOperand(0)->getType());
          OperandTy.Signed = Cmp->isSigned();
          switch (Cmp->getPredicate()) {
          case CmpInst::ICMP_EQ:
            P.Words.push_back(OpCmpEq);
            break;
          case CmpInst::ICMP_NE:
            P.Words.push_back(OpCmpNe);
            break;
          case CmpInst::ICMP_SGT:
            P.Words.push_back(OpCmpSgt);
            P.Words.push_back(packVmTy(OperandTy));
            break;
          case CmpInst::ICMP_SLT:
            P.Words.push_back(OpCmpSlt);
            P.Words.push_back(packVmTy(OperandTy));
            break;
          case CmpInst::ICMP_SGE:
            P.Words.push_back(OpCmpSge);
            P.Words.push_back(packVmTy(OperandTy));
            break;
          case CmpInst::ICMP_SLE:
            P.Words.push_back(OpCmpSle);
            P.Words.push_back(packVmTy(OperandTy));
            break;
          // unsigned compares. Operands are already canonical zext;
          // unsigned comparison needs no width info and no immediate.
          case CmpInst::ICMP_UGT:
            P.Words.push_back(OpCmpUgt);
            break;
          case CmpInst::ICMP_ULT:
            P.Words.push_back(OpCmpUlt);
            break;
          case CmpInst::ICMP_UGE:
            P.Words.push_back(OpCmpUge);
            break;
          case CmpInst::ICMP_ULE:
            P.Words.push_back(OpCmpUle);
            break;
          default:
            return false;
          }
          P.Words.push_back(OpStoreSlot);
          P.Words.push_back(slotFor(Slots, &I));
          continue;
        }
        if (auto *Sel = dyn_cast<SelectInst>(&I)) {
          if (!emitValue(P, Slots, AllocaBase, NextFrameSlot, Sel->getCondition()) ||
              !emitValue(P, Slots, AllocaBase, NextFrameSlot, Sel->getTrueValue()) ||
              !emitValue(P, Slots, AllocaBase, NextFrameSlot, Sel->getFalseValue()))
            return false;
          P.Words.push_back(OpSelect);
          P.Words.push_back(OpStoreSlot);
          P.Words.push_back(slotFor(Slots, &I));
          continue;
        }
        if (auto *Cast = dyn_cast<CastInst>(&I)) {
          const DataLayout &DL = F.getParent()->getDataLayout();
          switch (Cast->getOpcode()) {
          case Instruction::SExt:
          case Instruction::ZExt:
          case Instruction::Trunc:
            if (!isSupportedInt(Cast->getSrcTy()) ||
                !isSupportedInt(Cast->getDestTy()))
              return false;
            break;
          case Instruction::PtrToInt:
            if (!isSupportedPointer(Cast->getSrcTy(), DL) ||
                !isSupportedInt(Cast->getDestTy()))
              return false;
            break;
          case Instruction::IntToPtr:
            if (!isSupportedInt(Cast->getSrcTy()) ||
                !isSupportedPointer(Cast->getDestTy(), DL))
              return false;
            break;
          default:
            return false;
          }
          if (!emitValue(P, Slots, AllocaBase, NextFrameSlot,
                         Cast->getOperand(0)))
            return false;
          P.Words.push_back(OpStoreSlot);
          P.Words.push_back(slotFor(Slots, &I));
          continue;
        }
        // VM-local load (L1.5.1 middle way). Emit the VM-local
        // pointer (resolves to a PushConst frame index via emitValue), then
        // OpLoadPtr + VmTy. The handler pops the frame index, loads
        // Frame[idx], narrows, and pushes the result. The load result is
        // then stored into the load's own locals slot like any other def.
        if (auto *LD = dyn_cast<LoadInst>(&I)) {
          if (!isSupportedInt(LD->getType()))
            return false;
          int64_t FrameIdx = 0;
          bool IsFramePtr =
              resolveFramePtr(LD->getPointerOperand(), AllocaBase,
                              NextFrameSlot, FrameIdx);
          if (!IsFramePtr &&
              !isSupportedPointer(LD->getPointerOperand()->getType(),
                                  F.getParent()->getDataLayout()))
            return false;
          if (!emitValue(P, Slots, AllocaBase, NextFrameSlot, LD->getPointerOperand()))
            return false;
          P.Words.push_back(IsFramePtr ? OpLoadPtr : OpLoadMem);
          P.Words.push_back(packVmTy(vmTyFromType(LD->getType())));
          P.Words.push_back(OpStoreSlot);
          P.Words.push_back(slotFor(Slots, &I));
          continue;
        }
        // VM-local store. Emit the value then the VM-local pointer,
        // then OpStorePtr + VmTy. The handler pops the pointer, then the
        // value, narrows the value to VmTy, and stores Frame[ptr] = value.
        if (auto *ST = dyn_cast<StoreInst>(&I)) {
          if (!isSupportedInt(ST->getValueOperand()->getType()))
            return false;
          int64_t FrameIdx = 0;
          bool IsFramePtr =
              resolveFramePtr(ST->getPointerOperand(), AllocaBase,
                              NextFrameSlot, FrameIdx);
          if (!IsFramePtr &&
              !isSupportedPointer(ST->getPointerOperand()->getType(),
                                  F.getParent()->getDataLayout()))
            return false;
          if (!emitValue(P, Slots, AllocaBase, NextFrameSlot, ST->getValueOperand()))
            return false;
          if (!emitValue(P, Slots, AllocaBase, NextFrameSlot, ST->getPointerOperand()))
            return false;
          P.Words.push_back(IsFramePtr ? OpStorePtr : OpStoreMem);
          P.Words.push_back(packVmTy(vmTyFromType(ST->getValueOperand()->getType())));
          continue;
        }
        // VM-local GEPs produce no bytecode; external pointer GEPs compute
        // base + variable scaled offsets + constant field offsets.
        if (auto *GEP = dyn_cast<GetElementPtrInst>(&I)) {
          int64_t FrameIdx = 0;
          if (resolveFramePtr(GEP, AllocaBase, NextFrameSlot, FrameIdx)) {
            slotFor(Slots, &I);
            continue;
          }
          const DataLayout &DL = F.getParent()->getDataLayout();
          if (!isHostPointer(GEP->getPointerOperand(), AllocaBase,
                             NextFrameSlot, DL))
            return false;
          unsigned PtrBits = DL.getPointerSizeInBits(
              GEP->getPointerAddressSpace());
          SmallMapVector<Value *, APInt, 4> VariableOffsets;
          APInt ConstantOffset(PtrBits, 0);
          if (!GEP->collectOffset(DL, PtrBits, VariableOffsets,
                                  ConstantOffset))
            return false;
          if (!emitValue(P, Slots, AllocaBase, NextFrameSlot,
                         GEP->getPointerOperand()))
            return false;
          for (auto &[Idx, Scale] : VariableOffsets) {
            if (!isSupportedInt(Idx->getType()) ||
                !emitValue(P, Slots, AllocaBase, NextFrameSlot, Idx))
              return false;
            P.Words.push_back(OpGep);
            P.Words.push_back(Scale.getSExtValue());
          }
          if (ConstantOffset != 0) {
            P.Words.push_back(OpPushConst);
            P.Words.push_back(1);
            P.Words.push_back(packVmTy({64, true}));
            P.Words.push_back(OpGep);
            P.Words.push_back(ConstantOffset.getSExtValue());
          }
          P.Words.push_back(OpStoreSlot);
          P.Words.push_back(slotFor(Slots, &I));
          continue;
        }
        // AllocaInst produces no bytecode of its own -- references resolve
        // via emitValue to a PushConst frame index (allocated in pre-scan).
        if (isa<AllocaInst>(I))
          continue;
        // CallInst (L1.5.1). Direct callees use the callee table; compatible
        // indirect calls route through generated typed stubs.
        if (auto *CI = dyn_cast<CallInst>(&I)) {
          if (auto *MS = dyn_cast<MemSetInst>(CI)) {
            if (MS->isVolatile())
              return false;
            auto *Len = dyn_cast<ConstantInt>(MS->getLength());
            if (!Len)
              return false;
            const DataLayout &DL = F.getParent()->getDataLayout();
            if (!isHostPointer(MS->getDest(), AllocaBase, NextFrameSlot, DL))
              return false;
            if (!emitValue(P, Slots, AllocaBase, NextFrameSlot, MS->getDest()) ||
                !emitValue(P, Slots, AllocaBase, NextFrameSlot, MS->getValue()))
              return false;
            P.Words.push_back(OpMemSet);
            P.Words.push_back(static_cast<int64_t>(Len->getZExtValue()));
            continue;
          }
          if (auto *MT = dyn_cast<MemTransferInst>(CI)) {
            if (MT->isVolatile())
              return false;
            auto *Len = dyn_cast<ConstantInt>(MT->getLength());
            if (!Len)
              return false;
            const DataLayout &DL = F.getParent()->getDataLayout();
            if (!isHostPointer(MT->getDest(), AllocaBase, NextFrameSlot, DL) ||
                !isHostPointer(MT->getSource(), AllocaBase, NextFrameSlot, DL))
              return false;
            if (!emitValue(P, Slots, AllocaBase, NextFrameSlot, MT->getDest()) ||
                !emitValue(P, Slots, AllocaBase, NextFrameSlot, MT->getSource()))
              return false;
            P.Words.push_back(isa<MemMoveInst>(MT) ? OpMemMove : OpMemCpy);
            P.Words.push_back(static_cast<int64_t>(Len->getZExtValue()));
            continue;
          }
          Function *Callee = dyn_cast<Function>(CI->getCalledOperand());
          bool Indirect = !Callee;
          if (Indirect) {
            if (!isVMCompatibleIndirectCall(*CI))
              return false;
            Callee = getOrCreateIndirectCallStub(*F.getParent(), *CI);
          } else if (!isVMCompatibleCall(*CI)) {
            return false;
          }
          // register the callee in the per-module callee table and
          // remember its index. The table is finalized before the interpreter
          // is built.
          unsigned Idx;
          auto It = CalleeIndex.find(Callee);
          if (It == CalleeIndex.end()) {
            Idx = CalleeOrder.size();
            CalleeIndex[Callee] = Idx;
            CalleeOrder.push_back(Callee);
          } else {
            Idx = It->second;
          }
          // Push each argument onto the operand stack (reverse order so the
          // handler pops them in declaration order into the call-args buffer).
          unsigned NArgs = CI->arg_size() + (Indirect ? 1 : 0);
          for (unsigned AI = CI->arg_size(); AI > 0; --AI) {
            if (!emitValue(P, Slots, AllocaBase, NextFrameSlot,
                           CI->getArgOperand(AI - 1)))
              return false;
          }
          if (Indirect &&
              !emitValue(P, Slots, AllocaBase, NextFrameSlot,
                         CI->getCalledOperand()))
            return false;
          P.Words.push_back(OpCall);
          P.Words.push_back(static_cast<int64_t>(Idx));
          P.Words.push_back(static_cast<int64_t>(NArgs));
          VmTy RetTy{64, true};
          if (!CI->getType()->isVoidTy())
            RetTy = vmTyFromStackType(CI->getType());
          P.Words.push_back(packVmTy(RetTy));
          if (!CI->getType()->isVoidTy()) {
            P.Words.push_back(OpStoreSlot);
            P.Words.push_back(slotFor(Slots, &I));
          }
          continue;
        }
        if (auto *Br = dyn_cast<BranchInst>(&I)) {
          if (Br->isUnconditional()) {
            // store PHI incomings for the single successor, then jump.
            if (!emitPhiCopies(P, Slots, AllocaBase, NextFrameSlot, &BB, Br->getSuccessor(0)))
              return false;
            P.Words.push_back(OpJmp);
            P.Fixups.push_back({P.Words.size(), Br->getSuccessor(0)});
            P.Words.push_back(0);
            continue;
          }
          // Conditional: the condition selects which successor's PHI copies
          // run, so the two copy sequences must be in disjoint bytecode
          // regions reached by conditional jumps. Layout:
          //   <cond on stack>
          //   OpBrTrue -> L_true_copies
          //   [false-copies] ; OpJmp -> false-target
          // L_true_copies:
          //   [true-copies]  ; OpJmp -> true-target
          if (!emitValue(P, Slots, AllocaBase, NextFrameSlot, Br->getCondition()))
            return false;
          P.Words.push_back(OpBrTrue);
          // Fixup resolved later to the start of the true-copies region.
          size_t BrTrueFixupIdx = P.Words.size();
          P.Words.push_back(0); // placeholder, patched to L_true_copies
          // False path (fallthrough): copies then jump to false successor.
          if (!emitPhiCopies(P, Slots, AllocaBase, NextFrameSlot, &BB, Br->getSuccessor(1)))
            return false;
          P.Words.push_back(OpJmp);
          P.Fixups.push_back({P.Words.size(), Br->getSuccessor(1)});
          P.Words.push_back(0);
          // True path: now-resolved start of true-copies region.
          P.Words[BrTrueFixupIdx] = static_cast<int64_t>(P.Words.size());
          if (!emitPhiCopies(P, Slots, AllocaBase, NextFrameSlot, &BB, Br->getSuccessor(0)))
            return false;
          P.Words.push_back(OpJmp);
          P.Fixups.push_back({P.Words.size(), Br->getSuccessor(0)});
          P.Words.push_back(0);
          continue;
        }
        if (auto *SW = dyn_cast<SwitchInst>(&I)) {
          if (!isSupportedInt(SW->getCondition()->getType()))
            return false;
          SmallVector<std::pair<ConstantInt *, BasicBlock *>, 8> Cases;
          SmallVector<size_t, 8> CaseFixups;
          for (auto Case : SW->cases()) {
            if (!isSupportedInt(Case.getCaseValue()->getType()))
              return false;
            Cases.push_back({Case.getCaseValue(), Case.getCaseSuccessor()});
          }
          for (auto &[CaseValue, Succ] : Cases) {
            (void)Succ;
            if (!emitValue(P, Slots, AllocaBase, NextFrameSlot,
                           SW->getCondition()) ||
                !emitValue(P, Slots, AllocaBase, NextFrameSlot, CaseValue))
              return false;
            P.Words.push_back(OpCmpEq);
            P.Words.push_back(OpBrTrue);
            CaseFixups.push_back(P.Words.size());
            P.Words.push_back(0);
          }
          if (!emitPhiCopies(P, Slots, AllocaBase, NextFrameSlot, &BB,
                             SW->getDefaultDest()))
            return false;
          P.Words.push_back(OpJmp);
          P.Fixups.push_back({P.Words.size(), SW->getDefaultDest()});
          P.Words.push_back(0);
          for (unsigned CaseIdx = 0; CaseIdx < Cases.size(); ++CaseIdx) {
            BasicBlock *Succ = Cases[CaseIdx].second;
            P.Words[CaseFixups[CaseIdx]] =
                static_cast<int64_t>(P.Words.size());
            if (!emitPhiCopies(P, Slots, AllocaBase, NextFrameSlot, &BB, Succ))
              return false;
            P.Words.push_back(OpJmp);
            P.Fixups.push_back({P.Words.size(), Succ});
            P.Words.push_back(0);
          }
          continue;
        }
        if (auto *Ret = dyn_cast<ReturnInst>(&I)) {
          if (Value *RetVal = Ret->getReturnValue()) {
            if (!emitValue(P, Slots, AllocaBase, NextFrameSlot, RetVal))
              return false;
          } else {
            P.Words.append({OpPushConst, 0, packVmTy({64, true})});
          }
          P.Words.push_back(OpRet);
          continue;
        }
        return false;
      }
    }

    for (const Fixup &Fup : P.Fixups) {
      auto It = BlockStart.find(Fup.Target);
      if (It == BlockStart.end())
        return false;
      P.Words[Fup.Index] = static_cast<int64_t>(It->second);
    }
    return Slots.size() <= 64 && !P.Words.empty() && checkStackDepth(P);
  }

  // Per-opcode stack shape. Used by the build-time depth check
  // (L1.5.4) and as documentation. Data-dependent handlers (OpJmp/OpBrTrue/
  // OpRet) report their shape conservatively.
  HandlerStackShape shapeOf(Opcode Op) const {
    switch (Op) {
    case OpInitArg:
      return {0, 0, 2};
    case OpPushConst:
      // value + VmTy immediate
      return {0, 1, 2};
    case OpLoadSlot:
      // slot + VmTy immediate
      return {0, 1, 2};
    case OpStoreSlot:
      return {1, 0, 1};
    case OpAdd:
    case OpSub:
    case OpXor:
    case OpCmpEq:
    case OpCmpNe:
    case OpCmpUgt:
    case OpCmpUlt:
    case OpCmpUge:
    case OpCmpUle:
      return {2, 1, 0};
    case OpCmpSgt:
    case OpCmpSlt:
    case OpCmpSge:
    case OpCmpSle:
    case OpMul:
    case OpAnd:
    case OpOr:
    case OpShl:
    case OpLShr:
    case OpAShr:
    case OpSDiv:
    case OpUDiv:
    case OpSRem:
    case OpURem:
      return {2, 1, 1};
    case OpSelect:
      return {3, 1, 0};
    case OpLoadPtr:
    case OpLoadMem:
      // pops frame idx, fetches VmTy, pushes value
      return {1, 1, 1};
    case OpStorePtr:
    case OpStoreMem:
      // pops frame idx, pops value, fetches VmTy
      return {2, 0, 1};
    case OpGep:
      return {2, 1, 1};
    case OpPtrConst:
      return {0, 1, 1};
    case OpPad:
    case OpPad2:
    case OpPad3:
      return {0, 0, 1};
    case OpMemCpy:
    case OpMemMove:
      return {2, 0, 1};
    case OpMemSet:
      return {2, 0, 1};
    case OpCall:
      // pops NArgs values (runtime), fetches calleeIdx + nargs + VmTy, pushes
      // 1 result. Pops/Pushes are conservative (actual pop count is data).
      return {0, 1, 3};
    case OpFakeArith:
    case OpFakeMem:
    case OpFakeCall:
      return {0, 0, 0};
    case OpJmp:
      return {0, 0, 1};
    case OpBrTrue:
      return {1, 0, 1};
    case OpRet:
      return {1, 0, 0};
    }
    return {0, 0, 0};
  }

  bool opcodeImmediateCount(int64_t RawOp, unsigned &Count) const {
    if (RawOp <= 0)
      return false;
    auto Op = static_cast<Opcode>(RawOp);
    switch (Op) {
    case OpInitArg:
    case OpPushConst:
    case OpLoadSlot:
      Count = 2;
      return true;
    case OpStoreSlot:
    case OpAdd:
    case OpSub:
    case OpXor:
    case OpCmpSgt:
    case OpCmpSlt:
    case OpCmpSge:
    case OpCmpSle:
    case OpJmp:
    case OpBrTrue:
    case OpMul:
    case OpAnd:
    case OpOr:
    case OpShl:
    case OpLShr:
    case OpAShr:
    case OpSDiv:
    case OpUDiv:
    case OpSRem:
    case OpURem:
    case OpLoadPtr:
    case OpStorePtr:
    case OpLoadMem:
    case OpStoreMem:
    case OpGep:
    case OpPtrConst:
    case OpPad:
    case OpPad2:
    case OpPad3:
    case OpMemCpy:
    case OpMemSet:
    case OpMemMove:
      Count = 1;
      return true;
    case OpCmpEq:
    case OpCmpNe:
    case OpRet:
    case OpSelect:
    case OpCmpUgt:
    case OpCmpUlt:
    case OpCmpUge:
    case OpCmpUle:
      Count = 0;
      return true;
    case OpCall:
      Count = 3;
      return true;
    case OpFakeArith:
    case OpFakeMem:
    case OpFakeCall:
      return false;
    }
    return false;
  }

  static constexpr unsigned kOpcodeTableSize = 64;

  bool isPadOpcode(int64_t Op) const {
    return Op == OpPad || Op == OpPad2 || Op == OpPad3;
  }

  struct OpcodeHistogram {
    unsigned Total = 0;
    unsigned TopHits = 0;
    unsigned PadHits = 0;
    unsigned TopShareBp = 0;
  };

  OpcodeHistogram opcodeHistogram(ArrayRef<int64_t> Words) const {
    unsigned Counts[kOpcodeTableSize] = {};
    size_t I = 0;
    while (I < Words.size()) {
      unsigned Immediates = 0;
      if (!opcodeImmediateCount(Words[I], Immediates) ||
          I + 1 + Immediates > Words.size())
        break;
      int64_t Op = Words[I];
      if (Op >= 0 && static_cast<size_t>(Op) < kOpcodeTableSize) {
        ++Counts[static_cast<size_t>(Op)];
        if (isPadOpcode(Op))
          ++Counts[0];
      }
      I += 1 + Immediates;
    }

    OpcodeHistogram H;
    for (unsigned Op = 1; Op < kOpcodeTableSize; ++Op) {
      H.Total += Counts[Op];
      H.TopHits = std::max(H.TopHits, Counts[Op]);
    }
    H.PadHits = Counts[0];
    H.TopShareBp = H.Total ? (H.TopHits * 10000U) / H.Total : 0;
    return H;
  }

  bool buildOpcodeMaps(SmallVectorImpl<int64_t> &Encode,
                       SmallVectorImpl<int64_t> &Decode) {
    Encode.assign(kOpcodeTableSize, -1);
    Decode.assign(kOpcodeTableSize, -1);
    SmallVector<int64_t, kOpcodeTableSize> Tokens;
    for (unsigned I = 0; I < kOpcodeTableSize; ++I)
      Tokens.push_back(I);
    std::shuffle(Tokens.begin(), Tokens.end(), RNG);

    unsigned TokenI = 0;
    for (unsigned Op = 0; Op < kOpcodeTableSize; ++Op) {
      unsigned Immediates = 0;
      if (!opcodeImmediateCount(static_cast<int64_t>(Op), Immediates))
        continue;
      int64_t Token = Tokens[TokenI++];
      Encode[Op] = Token;
      Decode[Token] = Op;
    }
    return true;
  }

  bool buildOpcodeRuntimeTokens(SmallVectorImpl<int64_t> &Tokens) {
    Tokens.assign(kOpcodeTableSize, -1);
    SmallVector<unsigned, kOpcodeTableSize> Ops;
    for (unsigned Op = 1; Op < kOpcodeTableSize; ++Op) {
      unsigned Immediates = 0;
      if (!opcodeImmediateCount(static_cast<int64_t>(Op), Immediates) &&
          Op != OpFakeArith && Op != OpFakeMem && Op != OpFakeCall)
        continue;
      Ops.push_back(Op);
    }
    SmallVector<int64_t, kOpcodeTableSize> Pool;
    for (unsigned I = OpMemMove + 1; I < kOpcodeTableSize; ++I)
      Pool.push_back(I);
    unsigned HighEnd = Pool.size();
    for (unsigned I = 1; I <= OpMemMove; ++I)
      Pool.push_back(I);
    std::shuffle(Ops.begin(), Ops.end(), RNG);
    std::shuffle(Pool.begin(), Pool.begin() + HighEnd, RNG);
    std::shuffle(Pool.begin() + HighEnd, Pool.end(), RNG);
    if (Ops.size() > Pool.size())
      return false;
    for (unsigned I = 0; I < Ops.size(); ++I)
      Tokens[Ops[I]] = Pool[I];
    return true;
  }

  void addOpcodeMapDecoys(SmallVectorImpl<int64_t> &Decode) {
    SmallVector<unsigned, kOpcodeTableSize> Empty;
    for (unsigned I = 0; I < Decode.size(); ++I)
      if (Decode[I] < 0)
        Empty.push_back(I);
    std::shuffle(Empty.begin(), Empty.end(), RNG);

    static constexpr Opcode Pads[] = {OpPad, OpPad2, OpPad3};
    unsigned Count = std::min<unsigned>(Empty.size(), 1 + (RNG() % 8));
    for (unsigned I = 0; I < Count; ++I)
      Decode[Empty[I]] = Pads[RNG() % 3];
  }

  bool mapOpcodeWords(SmallVectorImpl<int64_t> &Words,
                      ArrayRef<int64_t> OpcodeEncode) const {
    size_t I = 0;
    while (I < Words.size()) {
      unsigned Immediates = 0;
      if (!opcodeImmediateCount(Words[I], Immediates))
        return false;
      if (Words[I] < 0 ||
          static_cast<size_t>(Words[I]) >= OpcodeEncode.size() ||
          OpcodeEncode[Words[I]] < 0)
        return false;
      Words[I] = OpcodeEncode[Words[I]];
      I += 1 + Immediates;
    }
    return I == Words.size();
  }

  bool computePCMapFlags(const SmallVectorImpl<int64_t> &Words,
                         ArrayRef<size_t> BlockStarts,
                         SmallVectorImpl<uint8_t> &Flags,
                         uint8_t RotationStep) const {
    SmallVector<uint8_t, 64> Starts(Words.size(), 0);
    SmallVector<uint8_t, 64> Leaders(Words.size(), 0);
    size_t I = 0;
    if (!Words.empty())
      Leaders[0] = 1;
    while (I < Words.size()) {
      unsigned Immediates = 0;
      if (!opcodeImmediateCount(Words[I], Immediates))
        return false;
      if (I + 1 + Immediates > Words.size())
        return false;
      Starts[I] = 1;
      I += 1 + Immediates;
    }
    if (I != Words.size())
      return false;

    for (size_t Start : BlockStarts)
      if (Start < Words.size() && Starts[Start])
        Leaders[Start] = 1;

    I = 0;
    while (I < Words.size()) {
      unsigned Immediates = 0;
      if (!opcodeImmediateCount(Words[I], Immediates))
        return false;
      size_t Next = I + 1 + Immediates;
      auto MarkTarget = [&](int64_t Target) {
        if (Target >= 0 && static_cast<uint64_t>(Target) < Words.size() &&
            Starts[static_cast<size_t>(Target)])
          Leaders[static_cast<size_t>(Target)] = 1;
      };
      switch (static_cast<Opcode>(Words[I])) {
      case OpJmp:
        MarkTarget(Words[I + 1]);
        break;
      case OpBrTrue:
        MarkTarget(Words[I + 1]);
        if (Next < Words.size())
          Leaders[Next] = 1;
        break;
      default:
        break;
      }
      I = Next;
    }

    Flags.assign(Words.size(), 0);
    uint8_t Rotation = 0;
    for (I = 0; I < Words.size();) {
      unsigned Immediates = 0;
      if (!opcodeImmediateCount(Words[I], Immediates))
        return false;
      if (Leaders[I])
        Rotation = static_cast<uint8_t>((Rotation + RotationStep) & 0x7F);
      uint8_t Packed = static_cast<uint8_t>((Rotation << 1) | 1);
      Flags[I] = Packed;
      for (size_t J = I + 1; J < I + 1 + Immediates; ++J)
        Flags[J] = static_cast<uint8_t>(Rotation << 1);
      I += 1 + Immediates;
    }
    return true;
  }

  bool insertDummyPadding(BytecodeProgram &P) {
    unsigned Percent = std::min<uint32_t>(VMPPaddingPercent, 100);
    if (!Percent)
      return true;

    SmallVector<int64_t, 64> Old(P.Words.begin(), P.Words.end());
    SmallVector<int64_t, 64> Padded;
    DenseMap<size_t, size_t> Remap;
    static constexpr Opcode Pads[] = {OpPad, OpPad2, OpPad3};
    static constexpr unsigned NumPads = sizeof(Pads) / sizeof(Pads[0]);
    unsigned PadCounts[NumPads] = {};
    size_t I = 0;
    while (I < Old.size()) {
      unsigned Immediates = 0;
      if (!opcodeImmediateCount(Old[I], Immediates) ||
          I + 1 + Immediates > Old.size())
        return false;
      Remap[I] = Padded.size();
      for (size_t J = I; J < I + 1 + Immediates; ++J)
        Padded.push_back(Old[J]);
      if (std::uniform_int_distribution<unsigned>(1, 100)(RNG) <= Percent) {
        unsigned Best = 0;
        for (unsigned K = 1; K < NumPads; ++K)
          if (PadCounts[K] < PadCounts[Best])
            Best = K;
        Padded.push_back(Pads[Best]);
        ++PadCounts[Best];
        Padded.push_back(static_cast<int64_t>(RNG()));
      }
      I += 1 + Immediates;
    }
    if (I != Old.size())
      return false;

    SmallVector<size_t, 8> PaddedBlockStarts;
    for (size_t Start : P.BlockStarts) {
      auto It = Remap.find(Start);
      if (It != Remap.end())
        PaddedBlockStarts.push_back(It->second);
    }
    std::sort(PaddedBlockStarts.begin(), PaddedBlockStarts.end());
    PaddedBlockStarts.erase(
        std::unique(PaddedBlockStarts.begin(), PaddedBlockStarts.end()),
        PaddedBlockStarts.end());

    I = 0;
    while (I < Padded.size()) {
      unsigned Immediates = 0;
      if (!opcodeImmediateCount(Padded[I], Immediates) ||
          I + 1 + Immediates > Padded.size())
        return false;
      if (Padded[I] == OpJmp || Padded[I] == OpBrTrue) {
        auto It = Remap.find(static_cast<size_t>(Padded[I + 1]));
        if (It == Remap.end())
          return false;
        Padded[I + 1] = static_cast<int64_t>(It->second);
      }
      I += 1 + Immediates;
    }

    P.Words = std::move(Padded);
    P.BlockStarts = std::move(PaddedBlockStarts);
    return checkStackDepth(P);
  }

  unsigned countBackEdges(Function &F) const {
    DenseMap<const BasicBlock *, unsigned> Order;
    unsigned Index = 0;
    for (BasicBlock &BB : F)
      Order[&BB] = Index++;

    unsigned BackEdges = 0;
    for (BasicBlock &BB : F) {
      unsigned From = Order[&BB];
      for (BasicBlock *Succ : successors(&BB)) {
        auto It = Order.find(Succ);
        if (It != Order.end() && It->second <= From)
          ++BackEdges;
      }
    }
    return BackEdges;
  }

  unsigned countInstructions(Function &F) const {
    unsigned Count = 0;
    for (BasicBlock &BB : F)
      for (Instruction &I : BB) {
        (void)I;
        ++Count;
      }
    return Count;
  }

  uint64_t integrityHashStep(uint64_t Tag, uint64_t Value,
                             uint64_t Index) const {
    uint64_t Mix = Value + Index * Schedule.Step;
    return (Tag ^ Mix) * Schedule.HashPrime;
  }

  uint64_t crossFunctionBytecodeSeed(
      ArrayRef<std::pair<Function *, BytecodeProgram>> Encoded) const {
    uint64_t Tag = integrityHashStep(Schedule.HashOffset, Encoded.size(), 0);
    uint64_t Index = 1;
    for (const auto &Entry : Encoded) {
      for (char Ch : Entry.first->getName())
        Tag = integrityHashStep(Tag, static_cast<unsigned char>(Ch), Index++);
      Tag = integrityHashStep(Tag, Entry.second.Words.size(), Index++);
      for (int64_t Word : Entry.second.Words)
        Tag = integrityHashStep(Tag, static_cast<uint64_t>(Word), Index++);
    }
    return Tag ? Tag : Schedule.HashPrime;
  }

  uint64_t bytecodeDomain(bool IsOpcodeWord) const {
    return IsOpcodeWord ? Schedule.OpcodeDomain : Schedule.OperandDomain;
  }

  uint64_t bytecodeRotationDomain(uint8_t PCFlags) const {
    return static_cast<uint64_t>(PCFlags >> 1) * Schedule.RotationDomain;
  }

  int64_t encryptBytecodeWord(int64_t Word, size_t Index,
                              uint64_t BytecodeKey,
                              uint8_t PCFlags) const {
    return static_cast<int64_t>(
        static_cast<uint64_t>(Word) ^
        bytecodeScheduleWord(BytecodeKey, static_cast<uint64_t>(Index),
                             bytecodeDomain((PCFlags & 1) != 0) ^
                                 bytecodeRotationDomain(PCFlags)));
  }

  uint64_t bytecodeScheduleWord(uint64_t Key, uint64_t Index,
                                uint64_t Domain) const {
    uint64_t X = Key ^ (Index * Schedule.Step) ^ Domain;
    X ^= X >> 30;
    X *= Schedule.Mix1;
    X ^= X >> 27;
    X *= Schedule.Mix2;
    X ^= X >> 31;
    return X;
  }

  uint64_t rotl64(uint64_t V, unsigned Rot) const {
    Rot &= 63;
    return Rot ? ((V << Rot) | (V >> (64 - Rot))) : V;
  }

  struct KeyDerivation {
    uint64_t Seed;
    uint64_t XorIn;
    uint64_t AddIn;
    uint64_t XorOut;
    unsigned Rot;
  };

  KeyDerivation makeKeyDerivation(uint64_t Key) {
    for (;;) {
      KeyDerivation D{RNG(), RNG(), RNG(), 0,
                      static_cast<unsigned>((RNG() % 63) + 1)};
      uint64_t Mixed =
          rotl64(((D.Seed ^ D.XorIn) * Schedule.KeyMul) + D.AddIn, D.Rot);
      D.XorOut = Mixed ^ Key;
      if (D.Seed != Key && D.XorIn != Key && D.AddIn != Key &&
          D.XorOut != Key)
        return D;
    }
  }

  Value *buildRuntimeBytecodeKey(IRBuilder<> &B, Module &M, Function &F,
                                 Type *I64, uint64_t Key) {
    KeyDerivation D = makeKeyDerivation(Key);
    auto *SeedGlobal = new GlobalVariable(
        M, I64, false, GlobalValue::PrivateLinkage,
        ConstantInt::get(I64, D.Seed), "__taokari_vmp_key_seed_" + F.getName());
    SeedGlobal->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    SeedGlobal->setAlignment(Align(8));

    auto *Seed = B.CreateLoad(I64, SeedGlobal, "vmp.key.seed");
    Seed->setVolatile(true);
    Value *Mixed = B.CreateXor(Seed, ConstantInt::get(I64, D.XorIn));
    Mixed = B.CreateMul(Mixed, ConstantInt::get(I64, Schedule.KeyMul));
    Mixed = B.CreateAdd(Mixed, ConstantInt::get(I64, D.AddIn));
    Value *RotL = B.CreateShl(Mixed, ConstantInt::get(I64, D.Rot));
    Value *RotR = B.CreateLShr(Mixed, ConstantInt::get(I64, 64 - D.Rot));
    return B.CreateXor(B.CreateOr(RotL, RotR),
                       ConstantInt::get(I64, D.XorOut), "vmp.bytecode.key");
  }

  Value *mixRuntimeEntropy(IRBuilder<> &B, Type *I64, Value *V,
                           const Twine &Name) {
    V = B.CreateXor(V, B.CreateLShr(V, ConstantInt::get(I64, 33)),
                    Name + ".x1");
    V = B.CreateMul(V, ConstantInt::get(I64, Schedule.Mix1), Name + ".m1");
    V = B.CreateXor(V, B.CreateLShr(V, ConstantInt::get(I64, 33)),
                    Name + ".x2");
    V = B.CreateMul(V, ConstantInt::get(I64, Schedule.Mix2), Name + ".m2");
    return B.CreateXor(V, B.CreateLShr(V, ConstantInt::get(I64, 33)),
                       Name + ".x3");
  }

  Value *buildRuntimeBytecodeSalt(IRBuilder<> &B, Function &F, Value *BCPtr,
                                  Value *ArgsPtr, Value *TamperFlag,
                                  Type *I64) {
    uint64_t Domain = RNG();
    if (!Domain)
      Domain = 0xA24BAED4963EE407ULL;
    Value *Salt = ConstantInt::get(I64, Domain);
    auto FoldPtr = [&](Value *Ptr, const Twine &Name) {
      Value *Addr = B.CreatePtrToInt(Ptr, I64, Name + ".addr");
      Salt = mixRuntimeEntropy(B, I64, B.CreateXor(Salt, Addr), Name + ".mix");
    };
    FoldPtr(&F, "vmp.salt.fn");
    FoldPtr(BCPtr, "vmp.salt.bc");
    FoldPtr(ArgsPtr, "vmp.salt.args");
    FoldPtr(TamperFlag, "vmp.salt.stack");
    return Salt;
  }

  GlobalVariable *createVMState(Module &M, const Twine &Name) {
    Type *I64 = Type::getInt64Ty(M.getContext());
    SmallVector<Constant *, 4> Init;
    for (unsigned I = 0; I < 4; ++I)
      Init.push_back(ConstantInt::get(I64, nextNonZeroKey()));
    auto *ArrayTy = ArrayType::get(I64, Init.size());
    auto *State =
        new GlobalVariable(M, ArrayTy, false, GlobalValue::PrivateLinkage,
                           ConstantArray::get(ArrayTy, Init), Name);
    State->setAlignment(Align(8));
    return State;
  }

  GlobalVariable *getOrCreateVMState(Module &M) {
    if (VMState)
      return VMState;
    VMState = createVMState(M, "__taokari_vmp_xstate");
    return VMState;
  }

  GlobalVariable *getVMStateForFunction(Module &M, Function &F) {
    if (!VMPTestIsolatedState)
      return getOrCreateVMState(M);
    std::string Name = ("__taokari_vmp_xstate_" + F.getName()).str();
    if (auto *Existing = M.getGlobalVariable(Name))
      return Existing;
    return createVMState(M, Name);
  }

  Value *loadWord(IRBuilder<> &B, Type *I64, Value *BC, Value *PC,
                  Value *One) {
    Value *Addr = B.CreateGEP(I64, BC, PC);
    Value *Word = B.CreateLoad(I64, Addr);
    B.CreateStore(B.CreateAdd(PC, One), PC);
    return Word;
  }

  void push(IRBuilder<> &B, Type *I64, Value *Stack, Value *SP, Value *V) {
    Value *Idx = B.CreateLoad(I64, SP);
    Value *Slot = B.CreateGEP(I64, Stack, Idx);
    B.CreateStore(V, Slot);
    B.CreateStore(B.CreateAdd(Idx, ConstantInt::get(I64, 1)), SP);
  }

  Value *pop(IRBuilder<> &B, Type *I64, Value *Stack, Value *SP) {
    Value *Idx = B.CreateSub(B.CreateLoad(I64, SP), ConstantInt::get(I64, 1));
    B.CreateStore(Idx, SP);
    return B.CreateLoad(I64, B.CreateGEP(I64, Stack, Idx));
  }

  // Bundle of interpreter state. Emit closures in the handler
  // table capture a pointer to this struct by value (one pointer copy),
  // which is always valid because the Ctx outlives both the table build and
  // the synchronous Emit pass in createInterpreter. This avoids the
  // lifetime hazard of capturing local helper lambdas (fetch/pop/push) by
  // reference into deferred std::function closures.
  struct InterpCtx {
    Type *I64;
    Function *F;
    LLVMContext *Ctx;
    Value *BC;
    Value *BCTail;
    Value *BCSplit;
    Value *BCLen;
    Value *PCMap;
    Value *PtrTable;
    Value *PtrCount;
    Value *PC;
    Value *SP;
    Value *Stack;
    Value *StackTail;
    Value *StackSplit;
    Value *Locals;
    Value *LocalsTail;
    Value *LocalsSplit;
    Value *Frame;
    Value *FrameTail;
    Value *FrameSplit;
    Value *CallArgs;
    GlobalVariable *CalleeTable;
    unsigned CalleeCount;
    Value *Args;
    Value *ArgLen;
    Value *TamperFlag;
    Value *ExpectedTag;
    Value *OpcodeMap;
    Value *VMState;
    Value *BytecodeKey;
    Value *PcKey;
    Value *StackKey;
    BasicBlock *Dispatch;
    BasicBlock *Bad;
    bool LittleEndian;
  };

  void updateVMState(IRBuilder<> &B, InterpCtx &C, uint64_t Slot,
                     uint64_t Salt) {
    Value *Ptr =
        B.CreateGEP(C.I64, C.VMState, ConstantInt::get(C.I64, Slot),
                    "vmp.xstate.ptr");
    auto *Old = B.CreateLoad(C.I64, Ptr, "vmp.xstate.old");
    Old->setVolatile(true);
    Value *Mixed =
        mixRuntimeEntropy(B, C.I64, B.CreateXor(Old, C.BytecodeKey),
                          "vmp.xstate.mix");
    auto *Store = B.CreateStore(
        B.CreateXor(Mixed, ConstantInt::get(C.I64, Salt),
                    "vmp.xstate.next"),
        Ptr);
    Store->setVolatile(true);
  }

  Value *stackSlot(IRBuilder<> &B, InterpCtx &C, Value *Idx) {
    Value *UseHead = B.CreateICmpULT(Idx, C.StackSplit);
    Value *TailIdx = B.CreateSub(Idx, C.StackSplit);
    Value *HeadPtr = B.CreateGEP(C.I64, C.Stack, Idx, "stk.a.ptr");
    Value *TailPtr = B.CreateGEP(C.I64, C.StackTail, TailIdx, "stk.b.ptr");
    return B.CreateSelect(UseHead, HeadPtr, TailPtr, "stk.ptr");
  }

  Value *localSlot(IRBuilder<> &B, InterpCtx &C, Value *Idx) {
    Value *UseHead = B.CreateICmpULT(Idx, C.LocalsSplit);
    Value *TailIdx = B.CreateSub(Idx, C.LocalsSplit);
    Value *HeadPtr = B.CreateGEP(C.I64, C.Locals, Idx, "loc.a.ptr");
    Value *TailPtr = B.CreateGEP(C.I64, C.LocalsTail, TailIdx, "loc.b.ptr");
    return B.CreateSelect(UseHead, HeadPtr, TailPtr, "loc.ptr");
  }

  Value *frameSlot(IRBuilder<> &B, InterpCtx &C, Value *Idx) {
    Value *UseHead = B.CreateICmpULT(Idx, C.FrameSplit);
    Value *TailIdx = B.CreateSub(Idx, C.FrameSplit);
    Value *HeadPtr = B.CreateGEP(C.I64, C.Frame, Idx, "frm.a.ptr");
    Value *TailPtr = B.CreateGEP(C.I64, C.FrameTail, TailIdx, "frm.b.ptr");
    return B.CreateSelect(UseHead, HeadPtr, TailPtr, "frm.ptr");
  }

  void branchIfFalse(IRBuilder<> &B, InterpCtx &C, Value *Ok) {
    BasicBlock *Cont = BasicBlock::Create(*C.Ctx, "guard.ok", C.F);
    B.CreateCondBr(Ok, Cont, C.Bad);
    B.SetInsertPoint(Cont);
  }

  // Encrypted push/pop for the VM operand stack. Values are XOR'd with
  // StackKey before they land in the stack alloca and de-XOR'd on pop.
  void pushEnc(IRBuilder<> &B, InterpCtx &C, Value *V) {
    Value *Idx = B.CreateLoad(C.I64, C.SP);
    Value *Slot = stackSlot(B, C, Idx);
    Value *Key = B.CreateAlignedLoad(C.I64, C.StackKey, Align(8),
                                     "stk.key.ld");
    Value *Enc = B.CreateXor(V, Key, "stk.enc");
    B.CreateStore(Enc, Slot);
    B.CreateStore(B.CreateAdd(Idx, ConstantInt::get(C.I64, 1)), C.SP);
  }

  Value *popEnc(IRBuilder<> &B, InterpCtx &C) {
    Value *Idx = B.CreateSub(B.CreateLoad(C.I64, C.SP),
                             ConstantInt::get(C.I64, 1));
    B.CreateStore(Idx, C.SP);
    Value *Enc = B.CreateLoad(C.I64, stackSlot(B, C, Idx), "stk.enc.ld");
    Value *Key = B.CreateAlignedLoad(C.I64, C.StackKey, Align(8),
                                     "stk.key.ld");
    return B.CreateXor(Enc, Key, "stk.plain");
  }

  // The PC alloca holds PC XOR PcKey; these helpers are the only legal
  // way to touch it. fetchWord, dispatch and init all go through them.
  Value *pcLoad(IRBuilder<> &B, InterpCtx &C) {
    Value *Enc = B.CreateLoad(C.I64, C.PC, "pc.enc");
    Value *Key = B.CreateAlignedLoad(C.I64, C.PcKey, Align(8), "pc.key.ld");
    return B.CreateXor(Enc, Key, "pc.plain");
  }

  void pcStore(IRBuilder<> &B, InterpCtx &C, Value *Plain) {
    Value *Key = B.CreateAlignedLoad(C.I64, C.PcKey, Align(8), "pc.key.ld");
    Value *Enc = B.CreateXor(Plain, Key, "pc.enc.new");
    B.CreateStore(Enc, C.PC);
  }

  Value *checkedWidth(IRBuilder<> &B, InterpCtx &C, Value *PackedTyImm) {
    Value *Width = B.CreateAnd(PackedTyImm, ConstantInt::get(C.I64, 0xFF));
    Value *NonZero =
        B.CreateICmpUGE(Width, ConstantInt::get(C.I64, 1));
    Value *InRange =
        B.CreateICmpULE(Width, ConstantInt::get(C.I64, 64));
    branchIfFalse(B, C, B.CreateAnd(NonZero, InRange));
    return Width;
  }

  Value *bytecodeScheduleWord(IRBuilder<> &B, Type *I64, Value *PCMap,
                              Value *BytecodeKey, Value *Index) {
    Type *I8 = Type::getInt8Ty(I64->getContext());
    Value *PCFlags = B.CreateLoad(I8, B.CreateGEP(I8, PCMap, Index));
    Value *IsOpcodeWord = B.CreateICmpNE(
        B.CreateAnd(PCFlags, ConstantInt::get(I8, 1)),
        ConstantInt::get(I8, 0));
    Value *Domain = B.CreateSelect(
        IsOpcodeWord, ConstantInt::get(I64, Schedule.OpcodeDomain),
        ConstantInt::get(I64, Schedule.OperandDomain));
    Value *Rotation = B.CreateZExt(
        B.CreateLShr(PCFlags, ConstantInt::get(I8, 1)), I64);
    Domain = B.CreateXor(
        Domain,
        B.CreateMul(Rotation,
                    ConstantInt::get(I64, Schedule.RotationDomain)));
    Value *X = B.CreateXor(
        BytecodeKey,
        B.CreateMul(Index, ConstantInt::get(I64, Schedule.Step)));
    X = B.CreateXor(X, Domain);
    X = B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I64, 30)));
    X = B.CreateMul(X, ConstantInt::get(I64, Schedule.Mix1));
    X = B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I64, 27)));
    X = B.CreateMul(X, ConstantInt::get(I64, Schedule.Mix2));
    return B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I64, 31)));
  }

  Value *bytecodeScheduleWord(IRBuilder<> &B, InterpCtx &C, Value *Index) {
    return bytecodeScheduleWord(B, C.I64, C.PCMap, C.BytecodeKey, Index);
  }

  Value *loadBytecodeWord(IRBuilder<> &B, InterpCtx &C, Value *Index) {
    Value *UseHead = B.CreateICmpULT(Index, C.BCSplit);
    Value *TailIndex = B.CreateSub(Index, C.BCSplit);
    Value *HeadPtr = B.CreateGEP(C.I64, C.BC, Index, "bc.a.ptr");
    Value *TailPtr = B.CreateGEP(C.I64, C.BCTail, TailIndex, "bc.b.ptr");
    Value *Ptr = B.CreateSelect(UseHead, HeadPtr, TailPtr, "bc.ptr");
    return B.CreateLoad(C.I64, Ptr, "bc.word");
  }

  uint64_t calleeTableMaskWord(uint64_t Index) const {
    return bytecodeScheduleWord(CalleeTableKey, Index, Schedule.CalleeDomain);
  }

  Value *calleeTableMaskWord(IRBuilder<> &B, InterpCtx &C, Value *Index) {
    Value *X = B.CreateXor(
        ConstantInt::get(C.I64, CalleeTableKey),
        B.CreateMul(Index, ConstantInt::get(C.I64, Schedule.Step)));
    X = B.CreateXor(X, ConstantInt::get(C.I64, Schedule.CalleeDomain));
    X = B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(C.I64, 30)));
    X = B.CreateMul(X, ConstantInt::get(C.I64, Schedule.Mix1));
    X = B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(C.I64, 27)));
    X = B.CreateMul(X, ConstantInt::get(C.I64, Schedule.Mix2));
    return B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(C.I64, 31)));
  }

  Value *fetchWord(IRBuilder<> &B, InterpCtx &C) {
    Value *Cur = pcLoad(B, C);
    branchIfFalse(B, C, B.CreateICmpULT(Cur, C.BCLen));
    Value *Enc = loadBytecodeWord(B, C, Cur);
    pcStore(B, C, B.CreateAdd(Cur, ConstantInt::get(C.I64, 1)));
    return B.CreateXor(Enc, bytecodeScheduleWord(B, C, Cur));
  }

  void pushStk(IRBuilder<> &B, InterpCtx &C, Value *V) {
    Value *Idx = B.CreateLoad(C.I64, C.SP);
    branchIfFalse(B, C, B.CreateICmpULT(Idx, ConstantInt::get(C.I64, 64)));
    pushEnc(B, C, V);
  }

  Value *popStk(IRBuilder<> &B, InterpCtx &C) {
    Value *Idx = B.CreateLoad(C.I64, C.SP);
    branchIfFalse(B, C, B.CreateICmpUGT(Idx, ConstantInt::get(C.I64, 0)));
    return popEnc(B, C);
  }

  // Narrow a full i64 value to its native width, returned as the
  // canonical ZERO-EXTENDED bit pattern. The VM stack always holds values in
  // this canonical form: truncate to width, then zext to i64. Signedness is
  // NOT applied here -- it is a property of the consuming operation, not the
  // value. So `-1` (i32) lives on the stack as 0x00000000FFFFFFFF.
  //
  //   Mask = (1 << Width) - 1
  //   Lo   = V & Mask
  //
  // Width=64 is a no-op (Mask = all-ones). PackedTyImm is the runtime VmTy
  // immediate (low 8 bits = width; the signed bit is ignored here).
  Value *narrowTo(IRBuilder<> &B, InterpCtx &C, Value *V,
                  Value *PackedTyImm) {
    Value *Width = checkedWidth(B, C, PackedTyImm);
    // Mask = (1 << Width) - 1
    Value *Is64 = B.CreateICmpEQ(Width, ConstantInt::get(C.I64, 64));
    Value *ShiftWidth =
        B.CreateSelect(Is64, ConstantInt::get(C.I64, 63), Width);
    Value *Mask =
        B.CreateSelect(Is64, ConstantInt::get(C.I64, ~0ULL),
                       B.CreateSub(B.CreateShl(ConstantInt::get(C.I64, 1),
                                               ShiftWidth),
                                   ConstantInt::get(C.I64, 1)));
    return B.CreateAnd(V, Mask);
  }

  // Sign-extend a canonical zext stack value from its native width
  // back to a signed i64, for use by signed operations (signed compare, SDiv,
  // SRem, AShr). Counterpart to narrowTo: narrowTo produces the canonical
  // zext bit pattern; signExtendFor consumes it when the op is signed.
  //
  //   Mask      = (1 << Width) - 1
  //   Lo        = V & Mask            // canonical zext value
  //   SignBit   = 1 << (Width - 1)
  //   Signed    = (Lo ^ SignBit) - SignBit
  Value *signExtendFor(IRBuilder<> &B, InterpCtx &C, Value *V,
                       Value *PackedTyImm) {
    Value *One = ConstantInt::get(C.I64, 1);
    Value *Width = checkedWidth(B, C, PackedTyImm);
    Value *Is64 = B.CreateICmpEQ(Width, ConstantInt::get(C.I64, 64));
    Value *ShiftWidth =
        B.CreateSelect(Is64, ConstantInt::get(C.I64, 63), Width);
    Value *Mask =
        B.CreateSelect(Is64, ConstantInt::get(C.I64, ~0ULL),
                       B.CreateSub(B.CreateShl(One, ShiftWidth),
                                   ConstantInt::get(C.I64, 1)));
    Value *Lo = B.CreateAnd(V, Mask);
    Value *SignBit =
        B.CreateShl(One, B.CreateSub(Width, ConstantInt::get(C.I64, 1)));
    return B.CreateSub(B.CreateXor(Lo, SignBit), SignBit);
  }

  Value *byteCountFor(IRBuilder<> &B, InterpCtx &C, Value *PackedTyImm) {
    Value *Width = checkedWidth(B, C, PackedTyImm);
    return B.CreateUDiv(B.CreateAdd(Width, ConstantInt::get(C.I64, 7)),
                        ConstantInt::get(C.I64, 8));
  }

  Value *loadHostInt(IRBuilder<> &B, InterpCtx &C, Value *AddrInt,
                     Value *PackedTyImm) {
    Type *I8 = Type::getInt8Ty(*C.Ctx);
    Value *Bytes = byteCountFor(B, C, PackedTyImm);
    AllocaInst *Acc = B.CreateAlloca(C.I64, nullptr, "mem.acc");
    AllocaInst *Idx = B.CreateAlloca(C.I64, nullptr, "mem.i");
    B.CreateStore(ConstantInt::get(C.I64, 0), Acc);
    B.CreateStore(ConstantInt::get(C.I64, 0), Idx);
    Value *Base = B.CreateIntToPtr(AddrInt, PointerType::getUnqual(*C.Ctx));
    BasicBlock *Hdr = BasicBlock::Create(*C.Ctx, "memload.hdr", C.F);
    BasicBlock *Body = BasicBlock::Create(*C.Ctx, "memload.body", C.F);
    BasicBlock *Done = BasicBlock::Create(*C.Ctx, "memload.done", C.F);
    B.CreateBr(Hdr);
    B.SetInsertPoint(Hdr);
    Value *Cur = B.CreateLoad(C.I64, Idx);
    B.CreateCondBr(B.CreateICmpULT(Cur, Bytes), Body, Done);
    B.SetInsertPoint(Body);
    Value *Byte = B.CreateZExt(B.CreateLoad(I8, B.CreateGEP(I8, Base, Cur)), C.I64);
    Value *ByteNo = C.LittleEndian
                        ? Cur
                        : B.CreateSub(B.CreateSub(Bytes, ConstantInt::get(C.I64, 1)), Cur);
    Value *Shift = B.CreateMul(ByteNo, ConstantInt::get(C.I64, 8));
    B.CreateStore(B.CreateOr(B.CreateLoad(C.I64, Acc), B.CreateShl(Byte, Shift)),
                  Acc);
    B.CreateStore(B.CreateAdd(Cur, ConstantInt::get(C.I64, 1)), Idx);
    B.CreateBr(Hdr);
    B.SetInsertPoint(Done);
    return narrowTo(B, C, B.CreateLoad(C.I64, Acc), PackedTyImm);
  }

  void storeHostInt(IRBuilder<> &B, InterpCtx &C, Value *AddrInt, Value *V,
                    Value *PackedTyImm) {
    Type *I8 = Type::getInt8Ty(*C.Ctx);
    Value *Bytes = byteCountFor(B, C, PackedTyImm);
    Value *Narrowed = narrowTo(B, C, V, PackedTyImm);
    AllocaInst *Idx = B.CreateAlloca(C.I64, nullptr, "mem.i");
    B.CreateStore(ConstantInt::get(C.I64, 0), Idx);
    Value *Base = B.CreateIntToPtr(AddrInt, PointerType::getUnqual(*C.Ctx));
    BasicBlock *Hdr = BasicBlock::Create(*C.Ctx, "memstore.hdr", C.F);
    BasicBlock *Body = BasicBlock::Create(*C.Ctx, "memstore.body", C.F);
    BasicBlock *Done = BasicBlock::Create(*C.Ctx, "memstore.done", C.F);
    B.CreateBr(Hdr);
    B.SetInsertPoint(Hdr);
    Value *Cur = B.CreateLoad(C.I64, Idx);
    B.CreateCondBr(B.CreateICmpULT(Cur, Bytes), Body, Done);
    B.SetInsertPoint(Body);
    Value *ByteNo = C.LittleEndian
                        ? Cur
                        : B.CreateSub(B.CreateSub(Bytes, ConstantInt::get(C.I64, 1)), Cur);
    Value *Shift = B.CreateMul(ByteNo, ConstantInt::get(C.I64, 8));
    Value *Byte =
        B.CreateTrunc(B.CreateAnd(B.CreateLShr(Narrowed, Shift),
                                  ConstantInt::get(C.I64, 0xFF)), I8);
    B.CreateStore(Byte, B.CreateGEP(I8, Base, Cur));
    B.CreateStore(B.CreateAdd(Cur, ConstantInt::get(C.I64, 1)), Idx);
    B.CreateBr(Hdr);
    B.SetInsertPoint(Done);
  }

  // Build the handler table for the interpreter. Each entry owns
  // its case-block emission, including pop()/fetch() and the branch back to
  // Dispatch. OpRet intentionally does NOT branch back (it returns).
  //
  // Every Emit closure captures `Ctx` (a pointer to InterpCx, by value) and
  // `this` (the pass, for push/pop helpers). IRBuilder& is passed in by the
  // caller at Emit time. No local lambdas are captured — fetch/pop/push go
  // through member functions on `this` + the InterpCx pointer.
  SmallVector<Handler, 24> buildHandlerTable(InterpCtx &C) {
    SmallVector<Handler, 24> H;
    H.push_back({OpInitArg, "initarg", shapeOf(OpInitArg),
                 [this, &C](IRBuilder<> &B) {
                   Value *Slot = fetchWord(B, C);
                   Value *ArgNo = fetchWord(B, C);
                   branchIfFalse(B, C,
                                 B.CreateICmpULT(Slot,
                                                 ConstantInt::get(C.I64, 64)));
                   branchIfFalse(B, C, B.CreateICmpULT(ArgNo, C.ArgLen));
                   Value *ArgVal =
                       B.CreateLoad(C.I64, B.CreateGEP(C.I64, C.Args, ArgNo));
                   B.CreateStore(ArgVal, localSlot(B, C, Slot));
                   B.CreateBr(C.Dispatch);
                 }});
    H.push_back({OpPushConst, "pushconst", shapeOf(OpPushConst),
                 [this, &C](IRBuilder<> &B) {
                   Value *V = fetchWord(B, C);
                   Value *Ty = fetchWord(B, C);
                   pushStk(B, C, narrowTo(B, C, V, Ty));
                   B.CreateBr(C.Dispatch);
                 }});
    H.push_back({OpLoadSlot, "loadslot", shapeOf(OpLoadSlot),
                 [this, &C](IRBuilder<> &B) {
                   Value *Slot = fetchWord(B, C);
                   Value *Ty = fetchWord(B, C);
                   branchIfFalse(B, C,
                                 B.CreateICmpULT(Slot,
                                                 ConstantInt::get(C.I64, 64)));
                   Value *V =
                       B.CreateLoad(C.I64, localSlot(B, C, Slot));
                   pushStk(B, C, narrowTo(B, C, V, Ty));
                   B.CreateBr(C.Dispatch);
                 }});
    H.push_back({OpStoreSlot, "storeslot", shapeOf(OpStoreSlot),
                 [this, &C](IRBuilder<> &B) {
                   Value *V = popStk(B, C);
                   Value *Slot = fetchWord(B, C);
                   branchIfFalse(B, C,
                                 B.CreateICmpULT(Slot,
                                                 ConstantInt::get(C.I64, 64)));
                   B.CreateStore(V, localSlot(B, C, Slot));
                   B.CreateBr(C.Dispatch);
                 }});

    // VM-local memory ops (L1.5.1 middle way). Frame index is on
    // the stack (pushed by emitValue as a PushConst). OpLoadPtr pops the
    // frame index, fetches VmTy, loads Frame[idx], narrows, pushes.
    // OpStorePtr pops the frame index, pops the value, fetches VmTy,
    // narrows, stores Frame[idx] = value. Order: store emits value-then-
    // pointer in the encoder, so the handler pops pointer first, then value.
    H.push_back({OpLoadPtr, "loadptr", shapeOf(OpLoadPtr),
                 [this, &C](IRBuilder<> &B) {
                   Value *FrameIdx = popStk(B, C);
                   Value *Ty = fetchWord(B, C);
                   branchIfFalse(B, C,
                                 B.CreateICmpULT(FrameIdx,
                                                 ConstantInt::get(C.I64, 64)));
                   Value *V =
                       B.CreateLoad(C.I64, frameSlot(B, C, FrameIdx));
                   pushStk(B, C, narrowTo(B, C, V, Ty));
                   B.CreateBr(C.Dispatch);
                 }});
    H.push_back({OpStorePtr, "storeptr", shapeOf(OpStorePtr),
                 [this, &C](IRBuilder<> &B) {
                   Value *FrameIdx = popStk(B, C);
                   Value *V = popStk(B, C);
                   Value *Ty = fetchWord(B, C);
                   branchIfFalse(B, C,
                                 B.CreateICmpULT(FrameIdx,
                                                 ConstantInt::get(C.I64, 64)));
                   Value *Narrowed = narrowTo(B, C, V, Ty);
                   B.CreateStore(Narrowed, frameSlot(B, C, FrameIdx));
                   B.CreateBr(C.Dispatch);
                 }});
    H.push_back({OpLoadMem, "loadmem", shapeOf(OpLoadMem),
                 [this, &C](IRBuilder<> &B) {
                   Value *Addr = popStk(B, C);
                   Value *Ty = fetchWord(B, C);
                   pushStk(B, C, loadHostInt(B, C, Addr, Ty));
                   B.CreateBr(C.Dispatch);
                 }});
    H.push_back({OpStoreMem, "storemem", shapeOf(OpStoreMem),
                 [this, &C](IRBuilder<> &B) {
                   Value *Addr = popStk(B, C);
                   Value *V = popStk(B, C);
                   Value *Ty = fetchWord(B, C);
                   storeHostInt(B, C, Addr, V, Ty);
                   B.CreateBr(C.Dispatch);
                 }});
    H.push_back({OpGep, "gep", shapeOf(OpGep),
                 [this, &C](IRBuilder<> &B) {
                   Value *Index = popStk(B, C);
                   Value *Base = popStk(B, C);
                   Value *Scale = fetchWord(B, C);
                   pushStk(B, C, B.CreateAdd(Base, B.CreateMul(Index, Scale)));
                   B.CreateBr(C.Dispatch);
                 }});
    H.push_back({OpPtrConst, "ptrconst", shapeOf(OpPtrConst),
                 [this, &C](IRBuilder<> &B) {
                   Type *Ptr = PointerType::getUnqual(*C.Ctx);
                   Value *Idx = fetchWord(B, C);
                   branchIfFalse(B, C, B.CreateICmpULT(Idx, C.PtrCount));
                   Value *PtrVal =
                       B.CreateLoad(Ptr, B.CreateGEP(Ptr, C.PtrTable, Idx));
                   pushStk(B, C, B.CreatePtrToInt(PtrVal, C.I64));
                   B.CreateBr(C.Dispatch);
                 }});
    auto addPad = [&](Opcode Op, StringRef Name) {
      H.push_back({Op, Name, shapeOf(Op), [this, &C](IRBuilder<> &B) {
                     (void)fetchWord(B, C);
                     B.CreateBr(C.Dispatch);
                   }});
    };
    addPad(OpPad, "pad");
    addPad(OpPad2, "pad2");
    addPad(OpPad3, "pad3");

    // calls (L1.5.1). Only registered when a callee table
    // exists (i.e. at least one direct call was encoded). Modules with no
    // direct calls have CalleeTable == null and the OpCall handler would
    // dereference it during IR emission, so we skip registration entirely
    // in that case -- the switch has no OpCall case and any stray OpCall
    // opcode would hit the Bad default (which never fires because no OpCall
    // was emitted). Fetches <calleeIdx> <nargs> <VmTy>, pops nargs values
    // into the CallArgs buffer (popping yields declaration order because the
    // encoder pushed them in reverse), validates the masked CalleeTable token,
    // calls the matching thunk uniformly as i64(i64*), narrows the i64 result
    // by VmTy, and pushes it.
    if (C.CalleeTable) {
      H.push_back({OpCall, "call", shapeOf(OpCall),
                   [this, &C](IRBuilder<> &B) {
                     Value *CalleeIdx = fetchWord(B, C);
                     Value *NArgs = fetchWord(B, C);
                     Value *Ty = fetchWord(B, C);
                     branchIfFalse(B, C,
                                   B.CreateICmpULT(
                                       CalleeIdx,
                                       ConstantInt::get(C.I64, C.CalleeCount)));
                     branchIfFalse(B, C,
                                   B.CreateICmpULE(NArgs,
                                                   ConstantInt::get(C.I64, 8)));
                     // Pop into CallArgs[0..NArgs-1] via a runtime-indexed
                     // loop (max 8 iters per isVMCompatibleCall's gate).
                     Value *Zero = ConstantInt::get(C.I64, 0);
                     AllocaInst *Counter =
                         B.CreateAlloca(C.I64, nullptr, "call.counter");
                     B.CreateStore(Zero, Counter);
                     BasicBlock *LoopHdr =
                         BasicBlock::Create(*C.Ctx, "call.loop", C.F);
                     BasicBlock *LoopBody =
                         BasicBlock::Create(*C.Ctx, "call.body", C.F);
                     BasicBlock *LoopDone =
                         BasicBlock::Create(*C.Ctx, "call.done", C.F);
                     B.CreateBr(LoopHdr);
                     B.SetInsertPoint(LoopHdr);
                     Value *Cur = B.CreateLoad(C.I64, Counter);
                     B.CreateCondBr(B.CreateICmpULT(Cur, NArgs), LoopBody, LoopDone);
                     B.SetInsertPoint(LoopBody);
                     Value *Arg = popStk(B, C);
                     B.CreateStore(Arg, B.CreateGEP(C.I64, C.CallArgs, Cur));
                     B.CreateStore(B.CreateAdd(Cur, ConstantInt::get(C.I64, 1)),
                                   Counter);
                     B.CreateBr(LoopHdr);
                     B.SetInsertPoint(LoopDone);
                     Value *MaskedCalleeToken = B.CreateLoad(
                         C.I64, B.CreateGEP(C.I64, C.CalleeTable, CalleeIdx));
                     branchIfFalse(
                         B, C,
                         B.CreateICmpEQ(MaskedCalleeToken,
                                        calleeTableMaskWord(B, C, CalleeIdx)));
                     auto *ThunkFnTy = FunctionType::get(
                         C.I64, {PointerType::getUnqual(*C.Ctx)}, false);
                     SwitchInst *CallSwitch = B.CreateSwitch(CalleeIdx, C.Bad,
                                                             C.CalleeCount);
                     Module &M = *C.F->getParent();
                     for (auto [Index, Callee] : llvm::enumerate(CalleeOrder)) {
                       BasicBlock *CallBB =
                           BasicBlock::Create(*C.Ctx, "call.target", C.F);
                       CallSwitch->addCase(
                           ConstantInt::get(cast<IntegerType>(C.I64),
                                            static_cast<uint64_t>(Index)),
                           CallBB);
                       B.SetInsertPoint(CallBB);
                       Function *Thunk = getOrCreateCallThunk(M, Callee);
                       Value *Result =
                           B.CreateCall(ThunkFnTy, Thunk, {C.CallArgs});
                       pushStk(B, C, narrowTo(B, C, Result, Ty));
                       B.CreateBr(C.Dispatch);
                     }
                   }});
    }

    // Binary-op emitter. The opcode-specific IR is produced by an
    // owned std::function (Fn) captured by value into the Emit closure. Fn
    // itself is a by-value parameter of addBinary, so the closure must own a
    // copy; capturing `Fn` by value (init-capture-free, named explicitly)
    // would be ill-formed under /permissive- with a default capture, so we
    // use an explicit capture list with no default and name Fn there.
    //
    // Flags:
    //   NarrowResult  -- fetch a trailing VmTy immediate and narrow the i64
    //                    result back to the operand width (canonical zext).
    //                    True for all arithmetic ops; false for compares.
    //   SignedOperands -- sign-extend both operands from their VmTy width
    //                     before calling Fn. Required for any op whose native
    //                     semantics depend on the operands being signed
    //                     (SDiv/SRem/AShr). Sign-agnostic ops (Add/Sub/Mul/
    //                     And/Or/Xor/Shl/LShr) leave the canonical zext
    //                     operands in place because two's-complement bit ops
    //                     give the same result either way once narrowed.
    auto addBinary = [&](Opcode Op, StringRef Name, bool NarrowResult,
                         bool SignedOperands, bool GuardDivisor,
                         std::function<Value *(IRBuilder<> &, Value *, Value *)>
                             Fn) {
      H.push_back({Op, Name, shapeOf(Op),
                   [this, &C, Fn, NarrowResult, SignedOperands,
                    GuardDivisor](IRBuilder<> &B) {
                     Value *R = popStk(B, C);
                     Value *L = popStk(B, C);
                     Value *Result;
                     if (NarrowResult) {
                       Value *Ty = fetchWord(B, C);
                       if (SignedOperands) {
                         L = signExtendFor(B, C, L, Ty);
                         R = signExtendFor(B, C, R, Ty);
                       }
                      if (GuardDivisor) {
                        branchIfFalse(
                            B, C,
                            B.CreateICmpNE(R, ConstantInt::get(C.I64, 0)));
                        if (SignedOperands) {
                          // INT_MIN / -1 (and INT_MIN % -1) overflow in
                          // signed div/rem. LLVM would produce poison; trap
                          // to Bad instead.
                          Value *Width =
                              B.CreateAnd(Ty, ConstantInt::get(C.I64, 0xFF));
                          Value *SignBit = B.CreateShl(
                              ConstantInt::get(C.I64, 1),
                              B.CreateSub(Width, ConstantInt::get(C.I64, 1)));
                          Value *MinSigned = B.CreateSub(
                              ConstantInt::get(C.I64, 0), SignBit);
                          Value *Overflow = B.CreateAnd(
                              B.CreateICmpEQ(L, MinSigned),
                              B.CreateICmpEQ(R,
                                             ConstantInt::getSigned(C.I64, -1)));
                          branchIfFalse(B, C, B.CreateNot(Overflow));
                        }
                      }
                      Result = Fn(B, L, R);
                       Result = narrowTo(B, C, Result, Ty);
                     } else {
                       Result = Fn(B, L, R);
                     }
                     pushStk(B, C, Result);
                     B.CreateBr(C.Dispatch);
                   }});
    };
    addBinary(OpAdd, "add", /*Narrow=*/true, /*Signed=*/false,
              /*GuardDivisor=*/false,
              [](IRBuilder<> &B, Value *L, Value *R) {
                return B.CreateAdd(L, R);
              });
    addBinary(OpSub, "sub", /*Narrow=*/true, /*Signed=*/false,
              /*GuardDivisor=*/false,
              [](IRBuilder<> &B, Value *L, Value *R) {
                return B.CreateSub(L, R);
              });
    addBinary(OpXor, "xor", /*Narrow=*/true, /*Signed=*/false,
              /*GuardDivisor=*/false,
              [](IRBuilder<> &B, Value *L, Value *R) {
                return B.CreateXor(L, R);
              });
    // L1.5.1 widened integer binary ops. All carry a VmTy immediate
    // and narrow the result. Signedness is encoded in the opcode choice and
    // the SignedOperands flag: AShr/SDiv/SRem sign-extend operands first;
    // the rest operate on the canonical zext bit pattern.
    addBinary(OpMul, "mul", /*Narrow=*/true, /*Signed=*/false,
              /*GuardDivisor=*/false,
              [](IRBuilder<> &B, Value *L, Value *R) {
                return B.CreateMul(L, R);
              });
    addBinary(OpAnd, "and", /*Narrow=*/true, /*Signed=*/false,
              /*GuardDivisor=*/false,
              [](IRBuilder<> &B, Value *L, Value *R) {
                return B.CreateAnd(L, R);
              });
    addBinary(OpOr, "or", /*Narrow=*/true, /*Signed=*/false,
              /*GuardDivisor=*/false,
              [](IRBuilder<> &B, Value *L, Value *R) {
                return B.CreateOr(L, R);
              });
    addBinary(OpShl, "shl", /*Narrow=*/true, /*Signed=*/false,
              /*GuardDivisor=*/false,
              [](IRBuilder<> &B, Value *L, Value *R) {
                return B.CreateShl(L, R);
              });
    addBinary(OpLShr, "lshr", /*Narrow=*/true, /*Signed=*/false,
              /*GuardDivisor=*/false,
              [](IRBuilder<> &B, Value *L, Value *R) {
                return B.CreateLShr(L, R);
              });
    addBinary(OpAShr, "ashr", /*Narrow=*/true, /*Signed=*/true,
              /*GuardDivisor=*/false,
              [](IRBuilder<> &B, Value *L, Value *R) {
                return B.CreateAShr(L, R);
              });
    addBinary(OpSDiv, "sdiv", /*Narrow=*/true, /*Signed=*/true,
              /*GuardDivisor=*/true,
              [](IRBuilder<> &B, Value *L, Value *R) {
                return B.CreateSDiv(L, R);
              });
    addBinary(OpUDiv, "udiv", /*Narrow=*/true, /*Signed=*/false,
              /*GuardDivisor=*/true,
              [](IRBuilder<> &B, Value *L, Value *R) {
                return B.CreateUDiv(L, R);
              });
    addBinary(OpSRem, "srem", /*Narrow=*/true, /*Signed=*/true,
              /*GuardDivisor=*/true,
              [](IRBuilder<> &B, Value *L, Value *R) {
                return B.CreateSRem(L, R);
              });
    addBinary(OpURem, "urem", /*Narrow=*/true, /*Signed=*/false,
              /*GuardDivisor=*/true,
              [](IRBuilder<> &B, Value *L, Value *R) {
                return B.CreateURem(L, R);
              });

    auto addCmp = [&](Opcode Op, StringRef Name, CmpInst::Predicate Pred,
                      bool SignedOperands) {
      // Signed compares (SGT/SLT/SGE/SLE) must sign-extend operands first so
      // that e.g. (-1) < 1 holds. EQ/NE are sign-agnostic. The operand VmTy
      // is carried by the most recent push (LoadSlot/PushConst), but the cmp
      // opcode emits no VmTy immediate of its own, so we re-fetch the width
      // from the value's type -- which we do not have here. Instead the cmp
      // handlers below re-narrow the operands using the type width baked
      // into the comparison by reading it from a separate path.
      //
      // Simpler: re-use addBinary with Narrow=false but inject a sign-extend
      // step. Since addBinary only sign-extends when NarrowResult=true (it
      // needs the Ty immediate), and cmps have no Ty immediate, we handle
      // signed compares by sign-extending unconditionally to 64-bit here --
      // which is correct because every supported integer type fits in 64
      // bits, and the canonical zext value sign-extended from its true width
      // equals the mathematically correct signed value. But we don't know
      // the width at this layer without the immediate.
      //
      // Resolution: signed cmps DO carry a VmTy immediate after all. See the
      // encoder: cmp ops emit packVmTy(OperandTy) for the signed variants.
      // To keep this layer simple we instead sign-extend from the operands'
      // stack form by re-deriving width at encode time and emitting it. For
      // now, EQ/NE (the unsigned/signed-agnostic predicates) work without
      // any immediate; the S* predicates are handled by the encoder emitting
      // a VmTy and the handler fetching it.
      addBinary(Op, Name, /*Narrow=*/SignedOperands, /*Signed=*/SignedOperands,
                /*GuardDivisor=*/false,
                [Pred, I64 = C.I64](IRBuilder<> &B, Value *L, Value *R) {
                  return B.CreateZExt(B.CreateICmp(Pred, L, R), I64);
                });
    };
    addCmp(OpCmpEq, "cmpeq", CmpInst::ICMP_EQ, /*Signed=*/false);
    addCmp(OpCmpNe, "cmpne", CmpInst::ICMP_NE, /*Signed=*/false);
    addCmp(OpCmpSgt, "cmpsgt", CmpInst::ICMP_SGT, /*Signed=*/true);
    addCmp(OpCmpSlt, "cmpslt", CmpInst::ICMP_SLT, /*Signed=*/true);
    addCmp(OpCmpSge, "cmpsge", CmpInst::ICMP_SGE, /*Signed=*/true);
    addCmp(OpCmpSle, "cmpsle", CmpInst::ICMP_SLE, /*Signed=*/true);
    // unsigned compares. Operands stay canonical zext; unsigned
    // ICmp is width-agnostic, no immediate, no sign-extend.
    addCmp(OpCmpUgt, "cmpugt", CmpInst::ICMP_UGT, /*Signed=*/false);
    addCmp(OpCmpUlt, "cmpult", CmpInst::ICMP_ULT, /*Signed=*/false);
    addCmp(OpCmpUge, "cmpuge", CmpInst::ICMP_UGE, /*Signed=*/false);
    addCmp(OpCmpUle, "cmpule", CmpInst::ICMP_ULE, /*Signed=*/false);

    H.push_back({OpSelect, "select", shapeOf(OpSelect),
                 [this, &C](IRBuilder<> &B) {
                   Value *FalseV = popStk(B, C);
                   Value *TrueV = popStk(B, C);
                   Value *CondV = popStk(B, C);
                   pushStk(B, C,
                           B.CreateSelect(
                               B.CreateICmpNE(CondV,
                                              ConstantInt::get(C.I64, 0)),
                               TrueV, FalseV));
                   B.CreateBr(C.Dispatch);
                 }});

    H.push_back({OpJmp, "jmp", shapeOf(OpJmp),
                 [this, &C](IRBuilder<> &B) {
                   Value *Target = fetchWord(B, C);
                   branchIfFalse(B, C, B.CreateICmpULT(Target, C.BCLen));
                   pcStore(B, C, Target);
                   B.CreateBr(C.Dispatch);
                 }});
    H.push_back({OpBrTrue, "brtrue", shapeOf(OpBrTrue),
                 [this, &C](IRBuilder<> &B) {
                   Value *Target = fetchWord(B, C);
                   Value *Cond = popStk(B, C);
                   BasicBlock *SetTarget =
                       BasicBlock::Create(*C.Ctx, "brtrue.set", C.F);
                   branchIfFalse(B, C, B.CreateICmpULT(Target, C.BCLen));
                   B.CreateCondBr(
                       B.CreateICmpNE(Cond, ConstantInt::get(C.I64, 0)),
                       SetTarget, C.Dispatch);
                   B.SetInsertPoint(SetTarget);
                   pcStore(B, C, Target);
                   B.CreateBr(C.Dispatch);
                 }});
    H.push_back({OpRet, "ret", shapeOf(OpRet),
                 [this, &C](IRBuilder<> &B) { B.CreateRet(popStk(B, C)); }});

    auto addFakeHandler = [&](Opcode Op, StringRef Name, uint64_t Salt) {
      H.push_back({Op, Name, {0, 0, 0}, [&C, Salt](IRBuilder<> &B) {
                     Value *PCVal = B.CreateLoad(C.I64, C.PC);
                     Value *SPVal = B.CreateLoad(C.I64, C.SP);
                     Value *Mix = B.CreateXor(
                         B.CreateMul(PCVal, ConstantInt::get(C.I64, Salt)),
                         B.CreateAdd(SPVal,
                                     ConstantInt::get(C.I64, Salt >> 1)));
                     Value *Flag = B.CreateOr(
                         B.CreateLoad(C.I64, C.TamperFlag),
                         B.CreateAnd(Mix, ConstantInt::get(C.I64, 1)));
                     B.CreateStore(Flag, C.TamperFlag);
                     B.CreateBr(C.Bad);
                   }});
    };
    bool EmitFakeArith = RNG() & 1;
    bool EmitFakeMem = RNG() & 1;
    bool EmitFakeCall = RNG() & 1;
    if (!EmitFakeArith && !EmitFakeMem && !EmitFakeCall) {
      switch (RNG() % 3) {
      case 0:
        EmitFakeArith = true;
        break;
      case 1:
        EmitFakeMem = true;
        break;
      default:
        EmitFakeCall = true;
        break;
      }
    }
    if (EmitFakeArith)
      addFakeHandler(OpFakeArith, "fakearith", Schedule.Step);
    if (EmitFakeMem)
      addFakeHandler(OpFakeMem, "fakemem", Schedule.RotationDomain);
    if (EmitFakeCall)
      addFakeHandler(OpFakeCall, "fakecall", Schedule.RouteDomain);

    H.push_back({OpMemCpy, "memcpy", shapeOf(OpMemCpy),
                 [this, &C](IRBuilder<> &B) {
                   Value *Len = fetchWord(B, C);
                   Value *Src = B.CreateIntToPtr(popStk(B, C),
                                                 PointerType::getUnqual(*C.Ctx));
                   Value *Dst = B.CreateIntToPtr(popStk(B, C),
                                                 PointerType::getUnqual(*C.Ctx));
                   B.CreateMemCpy(Dst, MaybeAlign(1), Src, MaybeAlign(1),
                                  Len);
                   B.CreateBr(C.Dispatch);
                 }});
    H.push_back({OpMemSet, "memset", shapeOf(OpMemSet),
                 [this, &C](IRBuilder<> &B) {
                   Value *Len = fetchWord(B, C);
                   Type *I8 = Type::getInt8Ty(*C.Ctx);
                   Value *Val = B.CreateTrunc(popStk(B, C), I8);
                   Value *Dst = B.CreateIntToPtr(popStk(B, C),
                                                 PointerType::getUnqual(*C.Ctx));
                   B.CreateMemSet(Dst, Val, Len, MaybeAlign(1));
                   B.CreateBr(C.Dispatch);
                 }});
    H.push_back({OpMemMove, "memmove", shapeOf(OpMemMove),
                 [this, &C](IRBuilder<> &B) {
                   Value *Len = fetchWord(B, C);
                   Value *Src = B.CreateIntToPtr(popStk(B, C),
                                                 PointerType::getUnqual(*C.Ctx));
                   Value *Dst = B.CreateIntToPtr(popStk(B, C),
                                                 PointerType::getUnqual(*C.Ctx));
                   B.CreateMemMove(Dst, MaybeAlign(1), Src, MaybeAlign(1), Len);
                   B.CreateBr(C.Dispatch);
                 }});

    if (H.size() > 1) {
      std::shuffle(H.begin(), H.end(), RNG);
      if (H.front().Op == OpInitArg)
        std::rotate(H.begin(), H.begin() + 1, H.end());
    }
    return H;
  }

  InterpreterInstance createInterpreter(Module &M, Function &Source,
                                        uint64_t ExpectedOpMapHash,
                                        uint64_t BytecodeTagSeed,
                                        ArrayRef<int64_t> OpcodeRuntimeTokens) {
    LLVMContext &Ctx = M.getContext();
    Type *I64 = Type::getInt64Ty(Ctx);
    Type *I8 = Type::getInt8Ty(Ctx);
    Type *Ptr = PointerType::getUnqual(Ctx);
    // ParamLayout drives both the interpreter signature and the wrapper call.
    // Shuffling it keeps semantics intact while changing the visible
    // interpreter ABI. bcLen is the
    // bytecode word count; the dispatch loop checks PC < bcLen before each
    // fetch so a corrupted PC (relevant once L2 encrypts the bytecode) faults
    // to the Bad block instead of reading out of bounds.
    SmallVector<InterpParam, 16> ParamLayout = {
        InterpParam::BC,       InterpParam::BCTail,   InterpParam::BCSplit,
        InterpParam::BCLen,    InterpParam::PCMap,    InterpParam::PtrTable,
        InterpParam::PtrCount, InterpParam::Args,     InterpParam::ArgLen,
        InterpParam::Tamper,   InterpParam::Tag,      InterpParam::OpcodeMap,
        InterpParam::VMState,  InterpParam::Key};
    for (unsigned I = ParamLayout.size() - 1; I > 0; --I)
      std::swap(ParamLayout[I], ParamLayout[RNG() % (I + 1)]);
    unsigned DummyCount = 1 + static_cast<unsigned>(RNG() % 4);
    for (unsigned I = 0; I < DummyCount; ++I) {
      unsigned Pos = static_cast<unsigned>(RNG() % (ParamLayout.size() + 1));
      ParamLayout.insert(ParamLayout.begin() + Pos, InterpParam::Dummy);
    }
    SmallVector<Type *, 16> ParamTypes;
    for (InterpParam P : ParamLayout) {
      switch (P) {
      case InterpParam::BC:
      case InterpParam::BCTail:
      case InterpParam::PCMap:
      case InterpParam::PtrTable:
      case InterpParam::Args:
      case InterpParam::Tamper:
      case InterpParam::OpcodeMap:
      case InterpParam::VMState:
        ParamTypes.push_back(Ptr);
        break;
      case InterpParam::BCLen:
      case InterpParam::BCSplit:
      case InterpParam::PtrCount:
      case InterpParam::ArgLen:
      case InterpParam::Tag:
      case InterpParam::Key:
      case InterpParam::Dummy:
        ParamTypes.push_back(I64);
        break;
      }
    }
    auto *FTy = FunctionType::get(I64, ParamTypes, false);
    auto DynOpt = ArgsOptions->toObfuscate(ArgsOptions->dynOpt(), &Source);
    switch (ArgsOptions->vmpAntiTraceMode()) {
    case 1:
      DynOpt.setEnable(false);
      DynOpt.setLevel(0);
      break;
    case 2:
      DynOpt.setEnable(true);
      DynOpt.setLevel(3);
      break;
    case 3:
      DynOpt.setEnable(true);
      DynOpt.setLevel(4);
      break;
    default:
      break;
    }
    std::string InterpName =
        ("__taokari_vmp_interp_i64_" + Source.getName()).str();
    InterpName += "_";
    InterpName += std::to_string(RNG());
    auto *F = Function::Create(FTy, GlobalValue::InternalLinkage, InterpName, M);
    F->addFnAttr(Attribute::NoUnwind);
    F->addFnAttr(Attribute::NoInline);

    Value *BC = nullptr;
    Value *BCTail = nullptr;
    Value *BCSplit = nullptr;
    Value *BCLen = nullptr;
    Value *PCMap = nullptr;
    Value *PtrTable = nullptr;
    Value *PtrCount = nullptr;
    Value *Args = nullptr;
    Value *ArgLen = nullptr;
    Value *TamperFlag = nullptr;
    Value *ExpectedTag = nullptr;
    Value *OpcodeMap = nullptr;
    Value *VMStateArg = nullptr;
    Value *BytecodeKey = nullptr;
    for (unsigned I = 0; I < ParamLayout.size(); ++I) {
      Argument *Arg = F->getArg(I);
      switch (ParamLayout[I]) {
      case InterpParam::BC:
        BC = Arg;
        BC->setName("bc.a");
        break;
      case InterpParam::BCTail:
        BCTail = Arg;
        BCTail->setName("bc.b");
        break;
      case InterpParam::BCSplit:
        BCSplit = Arg;
        BCSplit->setName("bc.split");
        break;
      case InterpParam::BCLen:
        BCLen = Arg;
        BCLen->setName("bclen");
        break;
      case InterpParam::PCMap:
        PCMap = Arg;
        PCMap->setName("pc.map");
        break;
      case InterpParam::PtrTable:
        PtrTable = Arg;
        PtrTable->setName("ptr.table");
        break;
      case InterpParam::PtrCount:
        PtrCount = Arg;
        PtrCount->setName("ptr.count");
        break;
      case InterpParam::Args:
        Args = Arg;
        Args->setName("args");
        break;
      case InterpParam::ArgLen:
        ArgLen = Arg;
        ArgLen->setName("arg.len");
        break;
      case InterpParam::Tamper:
        TamperFlag = Arg;
        TamperFlag->setName("tamper");
        break;
      case InterpParam::Tag:
        ExpectedTag = Arg;
        ExpectedTag->setName("bytecode.tag");
        break;
      case InterpParam::OpcodeMap:
        OpcodeMap = Arg;
        OpcodeMap->setName("opcode.map");
        break;
      case InterpParam::VMState:
        VMStateArg = Arg;
        VMStateArg->setName("vmp.xstate");
        break;
      case InterpParam::Key:
        BytecodeKey = Arg;
        BytecodeKey->setName("bytecode.key");
        break;
      case InterpParam::Dummy:
        Arg->setName("vmp.dummy");
        break;
      }
    }

    BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", F);
    BasicBlock *Dispatch = BasicBlock::Create(Ctx, "dispatch", F);
    BasicBlock *Bad = BasicBlock::Create(Ctx, "bad", F);
    IRBuilder<> B(Entry);
    auto RandomSlots = [&](uint64_t Base, uint64_t Spread) {
      return ConstantInt::get(I64, Base + (RNG() % (Spread + 1)));
    };
    uint64_t StackTotal = 64 + (RNG() % 65);
    uint64_t StackSplit = 16 + (RNG() % 33);
    if (StackSplit >= StackTotal)
      StackSplit = StackTotal / 2;
    auto *StackHeadSlots = ConstantInt::get(I64, StackSplit);
    auto *StackTailSlots = ConstantInt::get(I64, StackTotal - StackSplit);
    auto *StackSplitValue = ConstantInt::get(I64, StackSplit);
    uint64_t LocalsTotal = 64 + (RNG() % 65);
    uint64_t LocalsSplit = 16 + (RNG() % 33);
    if (LocalsSplit >= LocalsTotal)
      LocalsSplit = LocalsTotal / 2;
    auto *LocalsHeadSlots = ConstantInt::get(I64, LocalsSplit);
    auto *LocalsTailSlots = ConstantInt::get(I64, LocalsTotal - LocalsSplit);
    auto *LocalsSplitValue = ConstantInt::get(I64, LocalsSplit);
    uint64_t FrameTotal = 64 + (RNG() % 65);
    uint64_t FrameSplit = 16 + (RNG() % 33);
    if (FrameSplit >= FrameTotal)
      FrameSplit = FrameTotal / 2;
    auto *FrameHeadSlots = ConstantInt::get(I64, FrameSplit);
    auto *FrameTailSlots = ConstantInt::get(I64, FrameTotal - FrameSplit);
    auto *FrameSplitValue = ConstantInt::get(I64, FrameSplit);
    auto *CallArgSlots = RandomSlots(8, 8);
    AllocaInst *Stack = nullptr;
    AllocaInst *StackTail = nullptr;
    AllocaInst *Locals = nullptr;
    AllocaInst *LocalsTail = nullptr;
    AllocaInst *Frame = nullptr;
    AllocaInst *FrameTail = nullptr;
    AllocaInst *CallArgs = nullptr;
    SmallVector<unsigned, 7> FrameOrder = {0, 1, 2, 3, 4, 5, 6};
    for (unsigned I = FrameOrder.size() - 1; I > 0; --I)
      std::swap(FrameOrder[I], FrameOrder[RNG() % (I + 1)]);
    for (unsigned Region : FrameOrder) {
      switch (Region) {
      case 0:
        Stack = B.CreateAlloca(I64, StackHeadSlots, "stack.a");
        break;
      case 1:
        Locals = B.CreateAlloca(I64, LocalsHeadSlots, "locals.a");
        break;
      case 2:
        Frame = B.CreateAlloca(I64, FrameHeadSlots, "frame.a");
        break;
      case 3:
        CallArgs = B.CreateAlloca(I64, CallArgSlots, "callargs");
        break;
      case 4:
        StackTail = B.CreateAlloca(I64, StackTailSlots, "stack.b");
        break;
      case 5:
        LocalsTail = B.CreateAlloca(I64, LocalsTailSlots, "locals.b");
        break;
      case 6:
        FrameTail = B.CreateAlloca(I64, FrameTailSlots, "frame.b");
        break;
      }
    }
    auto *PC = B.CreateAlloca(I64, nullptr, "pc");
    auto *SP = B.CreateAlloca(I64, nullptr, "sp");
    auto *HandlerState = B.CreateAlloca(I64, nullptr, "handler.state");
    // The PC alloca holds the program counter XOR'd
    // with a per-interp key derived from the runtime bytecode key (an
    // interpreter argument) mixed with a per-build random constant. The
    // runtime mixing defeats constant-folding: a debugger reading the PC
    // alloca sees only the encrypted form and must reproduce the key
    // schedule to recover the real PC. fetchWord / dispatch / init all go
    // through pcLoad/pcStore helpers defined below.
    uint64_t PcKeyConst = nextNonZeroKey();
    auto *PcKey = B.CreateAlloca(I64, nullptr, "pc.key");
    B.CreateStore(
        B.CreateXor(BytecodeKey, ConstantInt::get(I64, PcKeyConst)), PcKey);
    // The stack alloca holds every pushed
    // value XOR StackKey, so a memory snapshot between handler dispatches
    // reveals no plaintext operand values. StackKey is derived from the
    // runtime bytecode key mixed with a distinct per-build constant so
    // the optimizer cannot fold it.
    uint64_t StackKeyConst = nextNonZeroKey();
    auto *StackKey = B.CreateAlloca(I64, nullptr, "stk.key");
    B.CreateStore(
        B.CreateXor(BytecodeKey, ConstantInt::get(I64, StackKeyConst)),
        StackKey);
    B.CreateStore(
        B.CreateXor(ConstantInt::get(I64, 0),
                    B.CreateAlignedLoad(I64, PcKey, Align(8))),
        PC);
    B.CreateStore(ConstantInt::get(I64, 0), SP);
    B.CreateStore(ConstantInt::get(I64, 0), HandlerState);
    auto *Tag = B.CreateAlloca(I64, nullptr, "tag");
    auto *TagI = B.CreateAlloca(I64, nullptr, "tag.i");
    B.CreateStore(ConstantInt::get(I64, BytecodeTagSeed), Tag);
    B.CreateStore(ConstantInt::get(I64, 0), TagI);
    BasicBlock *TagHdr = BasicBlock::Create(Ctx, "tag.hdr", F);
    BasicBlock *TagBody = BasicBlock::Create(Ctx, "tag.body", F);
    BasicBlock *TagDone = BasicBlock::Create(Ctx, "tag.done", F);
    B.CreateBr(TagHdr);
    B.SetInsertPoint(TagHdr);
    Value *CurTagI = B.CreateLoad(I64, TagI);
    B.CreateCondBr(B.CreateICmpULT(CurTagI, BCLen), TagBody, TagDone);
    B.SetInsertPoint(TagBody);
    InterpCtx TagCtx{I64,   F,       &Ctx, BC,      BCTail, BCSplit, BCLen,
                     PCMap, PtrTable, PtrCount, PC, SP,     Stack,
                     StackTail, StackSplitValue, Locals, LocalsTail,
                     LocalsSplitValue, Frame, FrameTail, FrameSplitValue,
                     CallArgs, CalleeTable,
                     static_cast<unsigned>(CalleeOrder.size()), Args, ArgLen,
                     TamperFlag, ExpectedTag, OpcodeMap, VMStateArg,
                     BytecodeKey, PcKey, StackKey, Dispatch, Bad,
                     M.getDataLayout().isLittleEndian()};
    Value *CurWord = loadBytecodeWord(B, TagCtx, CurTagI);
    Value *CurTag = B.CreateLoad(I64, Tag);
    Value *TagMix =
        B.CreateAdd(CurWord,
                    B.CreateMul(CurTagI,
                                ConstantInt::get(I64, Schedule.Step)));
    Value *NextTag =
        B.CreateMul(B.CreateXor(CurTag, TagMix),
                    ConstantInt::get(I64, Schedule.HashPrime));
    B.CreateStore(NextTag, Tag);
    B.CreateStore(B.CreateAdd(CurTagI, ConstantInt::get(I64, 1)), TagI);
    B.CreateBr(TagHdr);
    B.SetInsertPoint(TagDone);
    BasicBlock *OpMapCheck = BasicBlock::Create(Ctx, "opmap.check", F);
    B.CreateCondBr(B.CreateICmpEQ(B.CreateLoad(I64, Tag), ExpectedTag),
                   OpMapCheck, Bad);

    // Self-verification of the handler-dispatch opcode map.
    // The interpreter folds every entry of OpcodeMap[0..63] into a
    // running hash with a per-build prime and compares the result
    // against a per-interp expected value baked in as a constant. A
    // patched map entry (e.g. swapping two opcodes to remap the
    // dispatch) trips the check and routes through the Bad block. The
    // expected value is computed at build time by hashing the runtime map
    // in replaceWithVM (passed in via a private global), so the check
    // survives the optimizer because the runtime hash depends on the
    // actual loaded bytes.
    B.SetInsertPoint(OpMapCheck);
    updateVMState(B, TagCtx, RNG() % 4, nextNonZeroKey());
    auto *OpMapHash = B.CreateAlloca(I64, nullptr, "opmap.hash");
    auto *OpMapHashI = B.CreateAlloca(I64, nullptr, "opmap.hash.i");
    Value *ExpectedOpMapHashV =
        ConstantInt::get(I64, ExpectedOpMapHash);
    B.CreateStore(ConstantInt::get(I64, Schedule.HashOffset), OpMapHash);
    B.CreateStore(ConstantInt::get(I64, 0), OpMapHashI);
    BasicBlock *OpMapHdr = BasicBlock::Create(Ctx, "opmap.hdr", F);
    BasicBlock *OpMapBody = BasicBlock::Create(Ctx, "opmap.body", F);
    BasicBlock *OpMapDone = BasicBlock::Create(Ctx, "opmap.done", F);
    B.CreateBr(OpMapHdr);
    B.SetInsertPoint(OpMapHdr);
    Value *OpMapHashIVal = B.CreateLoad(I64, OpMapHashI);
    B.CreateCondBr(
        B.CreateICmpULT(OpMapHashIVal,
                        ConstantInt::get(I64, kOpcodeTableSize)),
        OpMapBody, OpMapDone);
    B.SetInsertPoint(OpMapBody);
    Value *OpMapEntry = B.CreateLoad(
        I64, B.CreateGEP(I64, OpcodeMap, OpMapHashIVal));
    Value *CurOpMapHash = B.CreateLoad(I64, OpMapHash);
    Value *OpMapMix = B.CreateAdd(
        OpMapEntry, B.CreateMul(OpMapHashIVal,
                                ConstantInt::get(I64, Schedule.Step)));
    Value *NextOpMapHash = B.CreateMul(
        B.CreateXor(CurOpMapHash, OpMapMix),
        ConstantInt::get(I64, Schedule.HashPrime));
    B.CreateStore(NextOpMapHash, OpMapHash);
    B.CreateStore(B.CreateAdd(OpMapHashIVal, ConstantInt::get(I64, 1)),
                  OpMapHashI);
    B.CreateBr(OpMapHdr);
    B.SetInsertPoint(OpMapDone);
    B.CreateCondBr(
        B.CreateICmpEQ(B.CreateLoad(I64, OpMapHash), ExpectedOpMapHashV),
        Dispatch, Bad);

    B.SetInsertPoint(Dispatch);
    if (DynOpt.isEnabled()) {
      BasicBlock *DynTrap = BasicBlock::Create(Ctx, "dyn.loop.trap", F);
      BasicBlock *DynOk = BasicBlock::Create(Ctx, "dyn.loop.ok", F);
      Value *DynHit = taokari::emitDynamicRuntimeCheck(M, B, DynOpt.level());
      B.CreateCondBr(DynHit, DynTrap, DynOk);
      B.SetInsertPoint(DynTrap);
      taokari::markDynamicTamper(M, B);
      B.CreateBr(Bad);
      B.SetInsertPoint(DynOk);
    }
    // Inline PC decrypt (PcKey is the alloca created above). IC is not
    // constructed yet at this point in the IR, so we touch PcKey/PC
    // directly rather than via pcLoad.
    Value *OpPCEnc = B.CreateLoad(I64, PC, "pc.enc.ld");
    Value *OpPCKey = B.CreateAlignedLoad(I64, PcKey, Align(8), "pc.key.ld");
    Value *OpPC = B.CreateXor(OpPCEnc, OpPCKey, "pc.plain");
    // PC bounds check (L1.5.4). If PC has run past the bytecode,
    // fault to Bad rather than reading out of bounds. Matters once L2
    // encrypts the bytecode and a corrupted PC could otherwise escape.
    Value *InBounds = B.CreateICmpULT(OpPC, BCLen);
    BasicBlock *PcMapCheck = BasicBlock::Create(Ctx, "pcmap.check", F);
    BasicBlock *Fetch = BasicBlock::Create(Ctx, "fetch", F);
    B.CreateCondBr(InBounds, PcMapCheck, Bad);
    B.SetInsertPoint(PcMapCheck);
    Value *PCFlags = B.CreateLoad(I8, B.CreateGEP(I8, PCMap, OpPC));
    Value *IsOpStart =
        B.CreateAnd(PCFlags, ConstantInt::get(I8, 1));
    B.CreateCondBr(B.CreateICmpNE(IsOpStart, ConstantInt::get(I8, 0)), Fetch,
                   Bad);
    B.SetInsertPoint(Fetch);
    // Build handler table, then emit one switch case per entry.
    // The table is the source of truth; the switch is generated from it.
    InterpCtx IC{I64,   F,       &Ctx, BC,      BCTail, BCSplit, BCLen,
                 PCMap, PtrTable, PtrCount, PC, SP,     Stack,
                 StackTail, StackSplitValue, Locals, LocalsTail,
                 LocalsSplitValue, Frame, FrameTail, FrameSplitValue,
                 CallArgs, CalleeTable,
                 static_cast<unsigned>(CalleeOrder.size()), Args, ArgLen,
                 TamperFlag, ExpectedTag, OpcodeMap, VMStateArg, BytecodeKey,
                 PcKey, StackKey, Dispatch, Bad,
                 M.getDataLayout().isLittleEndian()};
    Value *MappedOp = fetchWord(B, IC);
    branchIfFalse(B, IC,
                  B.CreateICmpULT(MappedOp,
                                  ConstantInt::get(I64, kOpcodeTableSize)));
    Value *Op = B.CreateLoad(I64, B.CreateGEP(I64, OpcodeMap, MappedOp));
    branchIfFalse(B, IC,
                  B.CreateICmpNE(Op, ConstantInt::getSigned(I64, -1)));
    SmallVector<Handler, 24> Handlers = buildHandlerTable(IC);
    uint64_t DispatchKey = nextNonZeroKey();
    Value *DispatchToken =
        B.CreateXor(Op, ConstantInt::get(I64, DispatchKey));
    Value *Target = BlockAddress::get(F, Bad);
    SmallVector<BasicBlock *, 24> Dests;
    Dests.push_back(Bad);
    BasicBlock *HandlerRoute = BasicBlock::Create(Ctx, "handler.route", F);
    SmallVector<std::tuple<Handler *, BasicBlock *, BasicBlock *, uint64_t>, 24>
        HandlerBlocks;
    for (Handler &H : Handlers) {
      BasicBlock *CaseBB = BasicBlock::Create(Ctx, H.Name + ".entry", F);
      BasicBlock *BodyBB = BasicBlock::Create(Ctx, H.Name + ".body", F);
      int64_t RuntimeOp = OpcodeRuntimeTokens[static_cast<unsigned>(H.Op)];
      if (RuntimeOp < 0)
        report_fatal_error("missing VMP runtime opcode token");
      uint64_t RuntimeOpU = static_cast<uint64_t>(RuntimeOp);
      uint64_t EncOp = RuntimeOpU ^ DispatchKey;
      Value *Hit = B.CreateICmpEQ(DispatchToken, ConstantInt::get(I64, EncOp));
      Target = B.CreateSelect(Hit, BlockAddress::get(F, CaseBB), Target,
                              "handler.target");
      Dests.push_back(CaseBB);
      uint64_t RouteToken =
          (RuntimeOpU * Schedule.Step) ^ DispatchKey ^ Schedule.RouteDomain;
      HandlerBlocks.push_back({&H, CaseBB, BodyBB, RouteToken});
    }
    auto *IBI = B.CreateIndirectBr(Target, Dests.size());
    for (BasicBlock *Dest : Dests)
      IBI->addDestination(Dest);

    for (auto [H, CaseBB, BodyBB, RouteToken] : HandlerBlocks) {
      B.SetInsertPoint(CaseBB);
      B.CreateStore(ConstantInt::get(I64, RouteToken), HandlerState);
      B.CreateBr(HandlerRoute);
    }

    B.SetInsertPoint(HandlerRoute);
    Value *RouteState = B.CreateLoad(I64, HandlerState);
    Value *BodyTarget = BlockAddress::get(F, Bad);
    SmallVector<BasicBlock *, 24> BodyDests;
    BodyDests.push_back(Bad);
    for (auto [H, CaseBB, BodyBB, RouteToken] : HandlerBlocks) {
      Value *Hit =
          B.CreateICmpEQ(RouteState, ConstantInt::get(I64, RouteToken));
      BodyTarget = B.CreateSelect(Hit, BlockAddress::get(F, BodyBB),
                                  BodyTarget, "handler.body.target");
      BodyDests.push_back(BodyBB);
    }
    auto *HandlerIBI = B.CreateIndirectBr(BodyTarget, BodyDests.size());
    for (BasicBlock *Dest : BodyDests)
      HandlerIBI->addDestination(Dest);

    // Per-interpreter junk sink. Every handler body writes a MBA-shaped
    // value derived from its own stack pointer into this global, so each
    // handler body carries visible non-trivial arithmetic that a static
    // lifter cannot trivially prune. The store is semantically dead from
    // the program's perspective (the global is private and never read by
    // the VM), but it cannot be DCE'd because it has a memory side effect.
    // This applies safe MBA noise to handler bodies without changing
    // VM semantics.
    GlobalVariable *HandlerNoiseGV = new GlobalVariable(
        M, I64, false, GlobalValue::PrivateLinkage,
        ConstantInt::get(I64, RNG()),
        ("__taokari_vmp_handler_noise_" + Source.getName() + "_" +
         Twine::utohexstr(RNG())).str());
    HandlerNoiseGV->setAlignment(Align(8));

    for (auto [H, CaseBB, BodyBB, RouteToken] : HandlerBlocks) {
      B.SetInsertPoint(BodyBB);
      BasicBlock *RealBody =
          BasicBlock::Create(Ctx, H->Name + ".bcf.real", F);
      BasicBlock *FakeBody =
          BasicBlock::Create(Ctx, H->Name + ".bcf.fake", F);
      Value *BcfSp = B.CreateLoad(I64, SP, "h.bcf.sp");
      Value *BcfN = B.CreateXor(BcfSp, ConstantInt::get(I64, nextNonZeroKey()),
                                "h.bcf.n");
      Value *BcfNext = B.CreateAdd(BcfN, ConstantInt::get(I64, 1),
                                   "h.bcf.next");
      Value *BcfProd = B.CreateMul(BcfN, BcfNext, "h.bcf.prod");
      Value *BcfBit = B.CreateAnd(BcfProd, ConstantInt::get(I64, 1),
                                  "h.bcf.bit");
      Value *BcfTakeReal =
          B.CreateICmpEQ(BcfBit, ConstantInt::get(I64, 0), "h.bcf.cond");
      B.CreateCondBr(BcfTakeReal, RealBody, FakeBody);

      B.SetInsertPoint(FakeBody);
      Value *FakeMix =
          B.CreateXor(BcfProd, ConstantInt::get(I64, nextNonZeroKey()),
                      "h.bcf.fake.mix");
      B.CreateStore(FakeMix, HandlerNoiseGV);
      B.CreateBr(RealBody);

      B.SetInsertPoint(RealBody);
      // MBA noise on the live SP runs at the start of the body, before
      // the handler's real work. (sp ^ k1) + 2 * ((sp ^ k1) & (sp ^ k2))
      // is the MBA identity for a+b applied to two keyed copies of sp.
      // Resulting value is junk (k1, k2 are per-handler random) but the
      // arithmetic shape looks real to a decompiler. Written to the
      // private noise global so the store is not removable; the handler
      // semantics are untouched because nothing reads the global.
      uint64_t K1 = nextNonZeroKey();
      uint64_t K2 = nextNonZeroKey();
      uint64_t K3 = nextNonZeroKey();
      Value *Sp = B.CreateLoad(I64, SP, "h.sp");
      Value *A = B.CreateXor(Sp, ConstantInt::get(I64, K1), "h.a");
      Value *BSeed = B.CreateAdd(Sp, ConstantInt::get(I64, K2), "h.b.seed");
      Value *Bv = B.CreateXor(BSeed, ConstantInt::get(I64, K3), "h.b");
      Value *And = B.CreateAnd(A, Bv, "h.and");
      Value *Shl = B.CreateShl(And, ConstantInt::get(I64, 1), "h.shl");
      Value *Xor = B.CreateXor(A, Bv, "h.xor");
      Value *Sum = B.CreateAdd(Xor, Shl, "h.sum");
      B.CreateStore(Sum, HandlerNoiseGV);
      H->Emit(B);
    }

    B.SetInsertPoint(Bad);
    B.CreateStore(ConstantInt::get(I64, 1), TamperFlag);
    B.CreateRet(ConstantInt::get(I64, 0));
    return {F, ParamLayout};
  }

  bool replaceWithVM(Function &F, BytecodeProgram &P) {
    Module &M = *F.getParent();
    LLVMContext &Ctx = M.getContext();
    Type *I64 = Type::getInt64Ty(Ctx);

    uint64_t BytecodeKey = nextNonZeroKey();
    SmallVector<int64_t, kOpcodeTableSize> OpcodeEncode;
    SmallVector<int64_t, kOpcodeTableSize> OpcodeDecode;
    SmallVector<int64_t, kOpcodeTableSize> OpcodeRuntimeTokens;
    if (!buildOpcodeMaps(OpcodeEncode, OpcodeDecode))
      return false;
    if (!buildOpcodeRuntimeTokens(OpcodeRuntimeTokens))
      return false;
    SmallVector<int64_t, 64> EncodedWords(P.Words.begin(), P.Words.end());
    SmallVector<uint8_t, 64> PCFlags;
    uint8_t RotationStep = static_cast<uint8_t>((RNG() % 63) + 1);
    if (!computePCMapFlags(P.Words, P.BlockStarts, PCFlags, RotationStep))
      return false;
    if (!mapOpcodeWords(EncodedWords, OpcodeEncode))
      return false;
    addOpcodeMapDecoys(OpcodeDecode);

    SmallVector<Constant *, 64> Words;
    for (size_t I = 0; I < EncodedWords.size(); ++I) {
      int64_t Word =
          encryptBytecodeWord(EncodedWords[I], I, BytecodeKey, PCFlags[I]);
      Words.push_back(ConstantInt::get(I64, static_cast<uint64_t>(Word), true));
    }
    auto *ArrayTy = ArrayType::get(I64, Words.size());
    auto *Bytecode = new GlobalVariable(
        M, ArrayTy, true, GlobalValue::PrivateLinkage,
        ConstantArray::get(ArrayTy, Words),
        "__taokari_vmp_bc_" + F.getName());
    Bytecode->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    Bytecode->setAlignment(Align(8));

    Type *I8 = Type::getInt8Ty(Ctx);
    SmallVector<Constant *, 64> Starts;
    for (uint8_t V : PCFlags)
      Starts.push_back(ConstantInt::get(I8, V));
    auto *PCMapArrayTy = ArrayType::get(I8, Starts.size());
    auto *PCMap = new GlobalVariable(
        M, PCMapArrayTy, true, GlobalValue::PrivateLinkage,
        ConstantArray::get(PCMapArrayTy, Starts),
        "__taokari_vmp_pcmap_" + F.getName());
    PCMap->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    PCMap->setAlignment(Align(1));

    SmallVector<Constant *, kOpcodeTableSize> OpcodeMapEntries;
    SmallVector<int64_t, kOpcodeTableSize> OpcodeMapRuntime;
    for (int64_t V : OpcodeDecode) {
      int64_t RuntimeV = -1;
      if (V >= 0)
        RuntimeV = OpcodeRuntimeTokens[static_cast<unsigned>(V)];
      OpcodeMapRuntime.push_back(RuntimeV);
      OpcodeMapEntries.push_back(ConstantInt::getSigned(I64, RuntimeV));
    }
    auto *OpcodeMapArrayTy = ArrayType::get(I64, OpcodeMapEntries.size());
    auto *OpcodeMap = new GlobalVariable(
        M, OpcodeMapArrayTy, true, GlobalValue::PrivateLinkage,
        ConstantArray::get(OpcodeMapArrayTy, OpcodeMapEntries),
        "__taokari_vmp_opmap_" + F.getName());
    OpcodeMap->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    OpcodeMap->setAlignment(Align(8));

    // Compute the expected opcode-map hash that the interpreter will
    // re-derive at entry. The hash mirrors the runtime fold: start from
    // a per-build offset and for each entry compute
    //   next = (cur ^ (entry + index * step)) * per-build prime
    // using 64-bit wrapping arithmetic. The runtime check then catches
    // any patch to a single OpcodeMap entry.
    uint64_t ExpectedOpMapHash = Schedule.HashOffset;
    for (unsigned I = 0; I < OpcodeMapRuntime.size(); ++I) {
      uint64_t Entry =
          static_cast<uint64_t>(static_cast<int64_t>(OpcodeMapRuntime[I]));
      uint64_t Mix = Entry +
                     static_cast<uint64_t>(I) * Schedule.Step;
      ExpectedOpMapHash =
          (ExpectedOpMapHash ^ Mix) * Schedule.HashPrime;
    }

    uint64_t BytecodeTagSeed =
        P.CrossTagSeed ? P.CrossTagSeed : Schedule.HashOffset;
    InterpreterInstance Interp =
        createInterpreter(M, F, ExpectedOpMapHash, BytecodeTagSeed,
                          OpcodeRuntimeTokens);
    F.removeFnAttr(Attribute::AlwaysInline);
    F.removeFnAttr(Attribute::InlineHint);
    F.addFnAttr(Attribute::NoInline);
    F.deleteBody();
    BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", &F);
    BasicBlock *Ok = BasicBlock::Create(Ctx, "vmp.ok", &F);
    BasicBlock *Trap = BasicBlock::Create(Ctx, "vmp.trap", &F);
    IRBuilder<> B(Entry);
    Value *Zero = ConstantInt::get(I64, 0);
    Value *BCPtr = B.CreateGEP(ArrayTy, Bytecode, {Zero, Zero});
    Value *PCMapPtr = B.CreateGEP(PCMapArrayTy, PCMap, {Zero, Zero});
    Value *OpcodeMapPtr = B.CreateGEP(OpcodeMapArrayTy, OpcodeMap, {Zero, Zero});
    auto *VMStateGV = getVMStateForFunction(M, F);
    auto *VMStateArrayTy = cast<ArrayType>(VMStateGV->getValueType());
    Value *VMStatePtr =
        B.CreateGEP(VMStateArrayTy, VMStateGV, {Zero, Zero}, "vmp.xstate.ptr");
    Type *Ptr = PointerType::getUnqual(Ctx);
    Value *PtrTablePtr = ConstantPointerNull::get(PointerType::getUnqual(Ctx));
    Value *PtrCount = ConstantInt::get(I64, 0);
    if (!P.PointerConsts.empty()) {
      auto *PtrArrayTy = ArrayType::get(Ptr, P.PointerConsts.size());
      auto *PtrTable = new GlobalVariable(
          M, PtrArrayTy, true, GlobalValue::PrivateLinkage,
          ConstantArray::get(PtrArrayTy, P.PointerConsts),
          "__taokari_vmp_ptrs_" + F.getName());
      PtrTable->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
      PtrTable->setAlignment(Align(8));
      PtrTablePtr = B.CreateGEP(PtrArrayTy, PtrTable, {Zero, Zero});
      PtrCount = ConstantInt::get(I64, P.PointerConsts.size());
    }

    auto *ArgsArrayTy = ArrayType::get(I64, std::max<unsigned>(1, F.arg_size()));
    auto *Args = B.CreateAlloca(ArgsArrayTy, nullptr, "vmp.args");
    unsigned I = 0;
    for (Argument &A : F.args()) {
      Value *ArgPtr = B.CreateGEP(ArgsArrayTy, Args,
                                  {Zero, ConstantInt::get(I64, I++)});
      Value *ArgVal = A.getType()->isPointerTy()
                          ? B.CreatePtrToInt(&A, I64)
                          : B.CreateSExtOrTrunc(&A, I64);
      B.CreateStore(ArgVal, ArgPtr);
    }
    Value *ArgsPtr = B.CreateGEP(ArgsArrayTy, Args, {Zero, Zero});
    auto *TamperFlag = B.CreateAlloca(I64, nullptr, "vmp.tamper");
    B.CreateStore(Zero, TamperFlag);
    // pass the bytecode word count as the bcLen argument so the
    // interpreter can bound-check PC (L1.5.4).
    Value *BCLen = ConstantInt::get(I64, Words.size());
    Value *BaseKey = buildRuntimeBytecodeKey(B, M, F, I64, BytecodeKey);
    Value *RuntimeSalt =
        buildRuntimeBytecodeSalt(B, F, BCPtr, ArgsPtr, TamperFlag, I64);
    Value *RuntimeKey =
        B.CreateXor(BaseKey, RuntimeSalt, "vmp.runtime.bytecode.key");
    auto *RuntimeBC = B.CreateAlloca(ArrayTy, nullptr, "vmp.bc.runtime");
    Value *RuntimeBCPtr =
        B.CreateGEP(ArrayTy, RuntimeBC, {Zero, Zero}, "vmp.bc.runtime.ptr");
    uint64_t BytecodeSplit =
        Words.size() > 1 ? 1 + (RNG() % (Words.size() - 1)) : 1;
    Value *RuntimeBCTail =
        B.CreateGEP(I64, RuntimeBCPtr, ConstantInt::get(I64, BytecodeSplit),
                    "vmp.bc.runtime.tail");
    Value *RuntimeBCSplit = ConstantInt::get(I64, BytecodeSplit);
    auto *RekeyI = B.CreateAlloca(I64, nullptr, "vmp.rekey.i");
    auto *RuntimeTag = B.CreateAlloca(I64, nullptr, "vmp.rekey.tag");
    B.CreateStore(Zero, RekeyI);
    B.CreateStore(ConstantInt::get(I64, BytecodeTagSeed), RuntimeTag);
    BasicBlock *RekeyHdr = BasicBlock::Create(Ctx, "vmp.rekey.hdr", &F);
    BasicBlock *RekeyBody = BasicBlock::Create(Ctx, "vmp.rekey.body", &F);
    BasicBlock *RekeyDone = BasicBlock::Create(Ctx, "vmp.rekey.done", &F);
    B.CreateBr(RekeyHdr);
    B.SetInsertPoint(RekeyHdr);
    Value *CurRekeyI = B.CreateLoad(I64, RekeyI);
    B.CreateCondBr(B.CreateICmpULT(CurRekeyI, BCLen), RekeyBody, RekeyDone);
    B.SetInsertPoint(RekeyBody);
    Value *StaticWord =
        B.CreateLoad(I64, B.CreateGEP(I64, BCPtr, CurRekeyI),
                     "vmp.rekey.static");
    Value *PlainWord =
        B.CreateXor(StaticWord,
                    bytecodeScheduleWord(B, I64, PCMapPtr, BaseKey, CurRekeyI),
                    "vmp.rekey.plain");
    Value *RuntimeWord = B.CreateXor(
        PlainWord, bytecodeScheduleWord(B, I64, PCMapPtr, RuntimeKey, CurRekeyI),
        "vmp.rekey.word");
    B.CreateStore(RuntimeWord, B.CreateGEP(I64, RuntimeBCPtr, CurRekeyI));
    Value *CurTag = B.CreateLoad(I64, RuntimeTag);
    Value *TagMix =
        B.CreateAdd(RuntimeWord,
                    B.CreateMul(CurRekeyI,
                                ConstantInt::get(I64, Schedule.Step)));
    Value *NextTag =
        B.CreateMul(B.CreateXor(CurTag, TagMix),
                    ConstantInt::get(I64, Schedule.HashPrime));
    B.CreateStore(NextTag, RuntimeTag);
    B.CreateStore(B.CreateAdd(CurRekeyI, ConstantInt::get(I64, 1)), RekeyI);
    B.CreateBr(RekeyHdr);
    B.SetInsertPoint(RekeyDone);
    Value *RuntimeTagValue = B.CreateLoad(I64, RuntimeTag);
    SmallVector<Value *, 16> InterpArgs;
    for (InterpParam P : Interp.Params) {
      switch (P) {
      case InterpParam::BC:
        InterpArgs.push_back(RuntimeBCPtr);
        break;
      case InterpParam::BCTail:
        InterpArgs.push_back(RuntimeBCTail);
        break;
      case InterpParam::BCSplit:
        InterpArgs.push_back(RuntimeBCSplit);
        break;
      case InterpParam::BCLen:
        InterpArgs.push_back(BCLen);
        break;
      case InterpParam::PCMap:
        InterpArgs.push_back(PCMapPtr);
        break;
      case InterpParam::PtrTable:
        InterpArgs.push_back(PtrTablePtr);
        break;
      case InterpParam::PtrCount:
        InterpArgs.push_back(PtrCount);
        break;
      case InterpParam::Args:
        InterpArgs.push_back(ArgsPtr);
        break;
      case InterpParam::ArgLen:
        InterpArgs.push_back(ConstantInt::get(I64, F.arg_size()));
        break;
      case InterpParam::Tamper:
        InterpArgs.push_back(TamperFlag);
        break;
      case InterpParam::Tag:
        InterpArgs.push_back(RuntimeTagValue);
        break;
      case InterpParam::OpcodeMap:
        InterpArgs.push_back(OpcodeMapPtr);
        break;
      case InterpParam::VMState:
        InterpArgs.push_back(VMStatePtr);
        break;
      case InterpParam::Key:
        InterpArgs.push_back(RuntimeKey);
        break;
      case InterpParam::Dummy:
        InterpArgs.push_back(ConstantInt::get(I64, RNG()));
        break;
      }
    }
    Value *Result = B.CreateCall(Interp.Fn, InterpArgs);
    Value *Tampered = B.CreateLoad(I64, TamperFlag);
    B.CreateCondBr(B.CreateICmpNE(Tampered, Zero), Trap, Ok);
    B.SetInsertPoint(Trap);
    // Per-build tamper-response policy. The pass picks one of four
    // response shapes per function
    // from the per-module RNG, so two builds of the same source produce
    // different tamper responses and an analyst cannot fingerprint the
    // trap by exit code or by control flow. None of the modes produce an
    // obvious "you hit a check" crash: all route through ordinary libc
    // (exit) or an opaque spin.
    enum TamperResponse : uint8_t {
      TRExitLoud = 0,    // exit(86) — current loud mode
      TRExitSilent = 1,  // exit(0) — silent wrong results
      TRSpin = 2,        // tight spin — slow-decay hang
      TRExitRandom = 3,  // exit(<random>) — non-fingerprintable code
    };
    TamperResponse Mode = static_cast<TamperResponse>(RNG() % 4);
    auto *ExitTy =
        FunctionType::get(Type::getVoidTy(Ctx), {Type::getInt32Ty(Ctx)}, false);
    FunctionCallee Exit = M.getOrInsertFunction("exit", ExitTy);
    if (auto *ExitFn = dyn_cast<Function>(Exit.getCallee()))
      ExitFn->addFnAttr(Attribute::NoReturn);
    switch (Mode) {
    case TRExitSilent:
      B.CreateCall(Exit, {ConstantInt::get(Type::getInt32Ty(Ctx), 0)});
      B.CreateUnreachable();
      break;
    case TRSpin: {
      // A back-edge that re-checks the (already-set) tamper flag. The
      // branch is always taken so the loop never escapes, but it is not
      // a trap instruction and reads as ordinary control flow.
      BasicBlock *SpinHdr = BasicBlock::Create(Ctx, "tamper.spin.hdr", &F);
      BasicBlock *SpinBody = BasicBlock::Create(Ctx, "tamper.spin.body", &F);
      B.CreateBr(SpinHdr);
      B.SetInsertPoint(SpinHdr);
      B.CreateCondBr(
          B.CreateICmpNE(B.CreateLoad(I64, TamperFlag), Zero), SpinBody,
          SpinBody);
      B.SetInsertPoint(SpinBody);
      B.CreateBr(SpinHdr);
      break;
    }
    case TRExitRandom: {
      uint32_t RandomCode =
          static_cast<uint32_t>(RNG() & 0x7fffffffu) | 1u;
      B.CreateCall(Exit,
                   {ConstantInt::get(Type::getInt32Ty(Ctx), RandomCode)});
      B.CreateUnreachable();
      break;
    }
    case TRExitLoud:
    default:
      B.CreateCall(Exit, {ConstantInt::get(Type::getInt32Ty(Ctx), 86)});
      B.CreateUnreachable();
      break;
    }
    B.SetInsertPoint(Ok);
    if (F.getReturnType()->isVoidTy())
      B.CreateRetVoid();
    else
      B.CreateRet(B.CreateTruncOrBitCast(Result, F.getReturnType()));
    return true;
  }

  GlobalVariable *getOrCreateThunkSeed(Module &M) {
    if (auto *Existing = M.getGlobalVariable("__taokari_vmp_thunk_seed"))
      return Existing;
    Type *I64 = Type::getInt64Ty(M.getContext());
    uint64_t Seed = nextNonZeroKey();
    auto *GV = new GlobalVariable(M, I64, false, GlobalValue::PrivateLinkage,
                                  ConstantInt::get(I64, Seed),
                                  "__taokari_vmp_thunk_seed");
    GV->setAlignment(Align(8));
    return GV;
  }

  Value *maskThunkResult(IRBuilder<> &B, Module &M, Value *Result) {
    Type *I64 = Type::getInt64Ty(M.getContext());
    Value *Key = B.CreateAlignedLoad(I64, getOrCreateThunkSeed(M), Align(8),
                                     true, "thunk.ret.key");
    return B.CreateXor(B.CreateXor(Result, Key, "thunk.ret.xor"), Key,
                       "thunk.ret.unxor");
  }

  Function *getOrCreateIndirectCallStub(Module &M, const CallInst &CI) {
    LLVMContext &Ctx = M.getContext();
    SmallVector<Type *, 8> Params;
    Params.push_back(CI.getCalledOperand()->getType());
    for (const Use &Arg : CI.args())
      Params.push_back(Arg->getType());

    auto *StubTy = FunctionType::get(CI.getType(), Params, false);
    std::string StubName = "__taokari_vmp_indcall_stub_" +
                           std::to_string(IndirectCallStubCounter++);
    auto *Stub = Function::Create(StubTy, GlobalValue::InternalLinkage,
                                  StubName, M);
    Stub->addFnAttr(Attribute::NoUnwind);
    Stub->addFnAttr(Attribute::NoInline);

    BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", Stub);
    IRBuilder<> B(Entry);
    auto ArgIt = Stub->arg_begin();
    Value *Callee = &*ArgIt++;
    SmallVector<Value *, 8> CallArgs;
    for (; ArgIt != Stub->arg_end(); ++ArgIt)
      CallArgs.push_back(&*ArgIt);

    Value *Result = B.CreateCall(CI.getFunctionType(), Callee, CallArgs);
    if (CI.getType()->isVoidTy())
      B.CreateRetVoid();
    else
      B.CreateRet(Result);
    return Stub;
  }

  // Materialize the per-module call-target table as masked tokens.
  // Each callee or indirect-call stub gets a thunk i64(i64* %args) that
  // loads typed args, calls the real callee, and returns the i64 result
  // (0 for void). This abstracts
  // per-callee signatures away from the generic interpreter, which calls
  // every thunk uniformly as i64(i64*). The later IndirectCall pass can then
  // route these uniform thunk calls through its page table when enabled.
  Function *getOrCreateCallThunk(Module &M, Function *Callee) {
    // One thunk per distinct callee. Name encodes the callee so the get-or-
    // create lookup works.
    std::string ThunkName = "__taokari_vmp_callthunk_" +
                            std::string(Callee->getName());
    if (auto *Existing = M.getFunction(ThunkName))
      return Existing;

    LLVMContext &Ctx = M.getContext();
    Type *I64 = Type::getInt64Ty(Ctx);
    Type *I64Ptr = PointerType::getUnqual(Ctx);
    auto *ThunkTy = FunctionType::get(I64, {I64Ptr}, false);
    auto *Thunk = Function::Create(ThunkTy, GlobalValue::InternalLinkage,
                                   ThunkName, M);
    Thunk->addFnAttr(Attribute::NoUnwind);
    Thunk->addFnAttr(Attribute::NoInline);

    BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", Thunk);
    BasicBlock *Body = BasicBlock::Create(Ctx, "body", Thunk);
    IRBuilder<> B(Entry);
    B.CreateBr(Body);
    B.SetInsertPoint(Body);
    Argument *ArgsPtr = Thunk->getArg(0);
    ArgsPtr->setName("args");

    // Build typed argument values by loading each i64 slot and truncating to
    // the callee's declared arg type, or inttoptr-ing raw pointer addresses.
    SmallVector<Value *, 8> CallArgs;
    unsigned I = 0;
    Value *Zero = ConstantInt::get(I64, 0);
    for (Argument &A : Callee->args()) {
      Value *SlotPtr = B.CreateGEP(
          ArrayType::get(I64, std::max<unsigned>(1, Callee->arg_size())),
          ArgsPtr, {Zero, ConstantInt::get(I64, I++)});
      Value *Raw = B.CreateLoad(I64, SlotPtr);
      if (A.getType()->isPointerTy())
        CallArgs.push_back(B.CreateIntToPtr(Raw, A.getType()));
      else
        // Truncate the canonical i64 down to the declared arg width.
        CallArgs.push_back(B.CreateTrunc(Raw, A.getType()));
    }

    if (Callee->getReturnType()->isVoidTy()) {
      B.CreateCall(Callee, CallArgs);
      B.CreateRet(maskThunkResult(B, M, ConstantInt::get(I64, 0)));
    } else {
      Value *Result = B.CreateCall(Callee, CallArgs);
      Value *Wide = Callee->getReturnType()->isPointerTy()
                        ? B.CreatePtrToInt(Result, I64)
                        : B.CreateZExtOrTrunc(Result, I64);
      B.CreateRet(maskThunkResult(B, M, Wide));
    }
    return Thunk;
  }

  void finalizeCalleeTable(Module &M) {
    if (CalleeOrder.empty()) {
      CalleeTable = nullptr;
      CalleeTableKey = 0;
      return;
    }
    // Store masked per-index callee tokens; OpCall validates them before
    // dispatching to the generated call-thunk case.
    CalleeTableKey = nextNonZeroKey();
    LLVMContext &Ctx = M.getContext();
    Type *I64 = Type::getInt64Ty(Ctx);
    SmallVector<Constant *, 8> Entries;
    for (auto [Index, Callee] : llvm::enumerate(CalleeOrder)) {
      (void)getOrCreateCallThunk(M, Callee);
      Entries.push_back(
          ConstantInt::get(I64, calleeTableMaskWord(static_cast<uint64_t>(Index))));
    }
    auto *ArrayTy = ArrayType::get(I64, Entries.size());
    CalleeTable = new GlobalVariable(
        M, ArrayTy, true, GlobalValue::PrivateLinkage,
        ConstantArray::get(ArrayTy, Entries), "__taokari_vmp_callees");
    CalleeTable->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    CalleeTable->setAlignment(Align(8));
  }

  bool runOnModule(Module &M) override {
    // reset per-module state -- ModulePass instances can be reused
    // across modules by the legacy pass manager.
    CalleeIndex.clear();
    CalleeOrder.clear();
    CalleeTable = nullptr;
    VMState = nullptr;
    CalleeTableKey = 0;
    IndirectCallStubCounter = 0;
    initScheduleConstants();

    SmallVector<Function *, 8> Targets;
    DenseSet<Function *> InvokedCallees;
    for (Function &F : M) {
      for (BasicBlock &BB : F) {
        for (Instruction &I : BB) {
          auto *II = dyn_cast<InvokeInst>(&I);
          if (!II)
            continue;
          if (Function *Callee = II->getCalledFunction())
            InvokedCallees.insert(Callee);
        }
      }
    }
    auto isThrowCallee = [](Function *Callee) {
      if (!Callee || !Callee->hasName())
        return false;
      StringRef N = Callee->getName();
      return N == "_CxxThrowException" || N == "__CxxThrowException" ||
             N == "__cxa_throw" || N == "RaiseException" ||
             N == "RtlRaiseException" || N == "throw";
    };
    for (Function &F : M) {
      if (shouldSkip(F))
        continue;
      auto Opt = ArgsOptions->toObfuscate(ArgsOptions->vmpOpt(), &F);
      if (!Opt.isEnabled())
        continue;
      if (InvokedCallees.count(&F))
        continue;
      bool CallsThrow = false;
      for (BasicBlock &BB : F) {
        for (Instruction &I : BB) {
          auto *CB = dyn_cast<CallBase>(&I);
          if (!CB)
            continue;
          if (isThrowCallee(CB->getCalledFunction())) {
            CallsThrow = true;
            break;
          }
        }
        if (CallsThrow)
          break;
      }
      if (CallsThrow)
        continue;
      Targets.push_back(&F);
    }

    // L2 selection diagnostics: emit one remark per +vmp target so users can
    // see which functions virtualized and why skipped functions were rejected.
    unsigned Virtualized = 0;
    unsigned Skipped = 0;
    SmallVector<VMPCompatEntry, 8> CompatReport;

    // Phase 1: encode every target. This populates CalleeOrder with the
    // call targets referenced across all virtualized functions.
    SmallVector<std::pair<Function *, BytecodeProgram>, 8> Encoded;
    for (size_t TargetIdx = 0; TargetIdx < Targets.size(); ++TargetIdx) {
      Function *F = Targets[TargetIdx];
      OptimizationRemarkEmitter ORE(F);
      auto Opt = ArgsOptions->toObfuscate(ArgsOptions->vmpOpt(), F);
      uint32_t BytecodeWordsLimit = VMPMaxBytecodeWords;
      if (Opt.vmpBudget() != UINT32_MAX)
        BytecodeWordsLimit = Opt.vmpBudget();
      unsigned BackEdges = countBackEdges(*F);
      if (BackEdges > VMPMaxBackEdges) {
        OptimizationRemarkMissed R(DEBUG_TYPE, "HotLoopBudgetExceeded", F);
        R << "skipped: hot-loop budget exceeded ("
          << ore::NV("BackEdges", BackEdges) << " > "
          << ore::NV("Limit", VMPMaxBackEdges.getValue()) << ")";
        ORE.emit(R);
        addCompatEntry(CompatReport, *F, "skipped",
                       "hot-loop budget exceeded");
        ++Skipped;
        continue;
      }
      if (hasUnsupportedIR(*F)) {
        SmallVector<Function *, 2> SplitTargets;
        if (tryExtractVMSplitRegion(*F, SplitTargets)) {
          for (Function *Split : SplitTargets)
            Targets.push_back(Split);
          OptimizationRemark R(DEBUG_TYPE, "PartialVirtualized", F);
          R << "partially virtualized ("
            << ore::NV("SplitRegions", (unsigned)SplitTargets.size())
            << " split region(s))";
          ORE.emit(R);
          addCompatEntry(CompatReport, *F, "partially_virtualized",
                         "unsupported islands stay native",
                         0, SplitTargets.size());
          continue;
        }
        OptimizationRemarkMissed R(DEBUG_TYPE, "UnsupportedIR", F);
        R << "skipped: unsupported IR (PHI/call/EH/memory pattern outside "
             "the L1.5 ISA)";
        ORE.emit(R);
        addCompatEntry(CompatReport, *F, "skipped", "unsupported IR");
        ++Skipped;
        continue;
      }
      BytecodeProgram P;
      if (!buildBytecode(*F, P)) {
        OptimizationRemarkMissed R(DEBUG_TYPE, "EncodeFailed", F);
        R << "skipped: bytecode encoding failed (frame overflow, stack "
             "depth, or unsupported operand pattern)";
        ORE.emit(R);
        addCompatEntry(CompatReport, *F, "skipped",
                       "bytecode encoding failed");
        ++Skipped;
        continue;
      }
      if (!insertDummyPadding(P)) {
        OptimizationRemarkMissed R(DEBUG_TYPE, "PaddingFailed", F);
        R << "skipped: bytecode padding failed (invalid branch target or "
             "opcode shape)";
        ORE.emit(R);
        addCompatEntry(CompatReport, *F, "skipped",
                       "bytecode padding failed");
        ++Skipped;
        continue;
      }
      OpcodeHistogram Hist = opcodeHistogram(P.Words);
      OptimizationRemark HR(DEBUG_TYPE, "PaddingHistogram", F);
      HR << "padding histogram ("
         << ore::NV("Opcodes", Hist.Total) << " opcodes, "
         << ore::NV("TopHits", Hist.TopHits) << " top hits, "
         << ore::NV("TopShareBp", Hist.TopShareBp) << " bp, "
         << ore::NV("PadHits", Hist.PadHits) << " pad hits)";
      ORE.emit(HR);
      unsigned InstCount = countInstructions(*F);
      if (VMPMaxBytecodeExpansion && InstCount &&
          P.Words.size() >
              static_cast<uint64_t>(InstCount) * VMPMaxBytecodeExpansion) {
        OptimizationRemarkMissed R(DEBUG_TYPE, "ExpansionBudgetExceeded", F);
        R << "skipped: bytecode expansion budget exceeded ("
          << ore::NV("Words", (unsigned)P.Words.size()) << " > "
          << ore::NV("Instructions", InstCount) << " * "
          << ore::NV("Multiplier", VMPMaxBytecodeExpansion.getValue()) << ")";
        ORE.emit(R);
        addCompatEntry(CompatReport, *F, "skipped",
                       "bytecode expansion budget exceeded",
                       (unsigned)P.Words.size());
        ++Skipped;
        continue;
      }
      if (BytecodeWordsLimit &&
          P.Words.size() > static_cast<size_t>(BytecodeWordsLimit)) {
        OptimizationRemarkMissed R(DEBUG_TYPE, "BytecodeBudgetExceeded", F);
        R << "skipped: bytecode size budget exceeded ("
          << ore::NV("Words", (unsigned)P.Words.size()) << " > "
          << ore::NV("Limit", BytecodeWordsLimit) << ")";
        ORE.emit(R);
        addCompatEntry(CompatReport, *F, "skipped",
                       "bytecode size budget exceeded",
                       (unsigned)P.Words.size());
        ++Skipped;
        continue;
      }
      Encoded.emplace_back(F, std::move(P));
    }

    // Phase 2: finalize the callee table now that all callees are known.
    finalizeCalleeTable(M);
    uint64_t CrossTagSeed = crossFunctionBytecodeSeed(Encoded);
    for (auto &Entry : Encoded)
      Entry.second.CrossTagSeed = CrossTagSeed;

    // Phase 3: build the interpreter (uses CalleeTable) and replace bodies.
    bool Changed = false;
    for (auto &[F, P] : Encoded) {
      Changed |= replaceWithVM(*F, P);
      OptimizationRemarkEmitter ORE(F);
      OptimizationRemark R(DEBUG_TYPE, "Virtualized", F);
      R << "virtualized ("
        << ore::NV("Words", (unsigned)P.Words.size())
        << " bytecode words)";
      ORE.emit(R);
      addCompatEntry(CompatReport, *F, "virtualized", "ok",
                     (unsigned)P.Words.size());
      ++Virtualized;
    }

    LLVM_DEBUG(dbgs() << "taokari-vmp: " << Virtualized << " virtualized, "
                      << Skipped << " skipped\n");
    writeCompatReport(CompatReport);
    return Changed;
  }
};
} // namespace

char CodeVirtualization::ID = 0;

ModulePass *llvm::createCodeVirtualizationPass(ObfuscationOptions *ArgsOptions) {
  return new CodeVirtualization(ArgsOptions);
}
