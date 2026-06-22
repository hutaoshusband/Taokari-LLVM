#include "llvm/Transforms/Obfuscation/ObfuscationPassManager.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Obfuscation/BogusControlFlow.h"
#include "llvm/Transforms/Obfuscation/CodeVirtualization.h"
#include "llvm/Transforms/Obfuscation/MBA.h"
#include "llvm/Transforms/Obfuscation/NativeIntegrity.h"
#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"

#define DEBUG_TYPE "ir-obfuscation"

using namespace llvm;

namespace llvm {
extern cl::opt<bool> TaokariMaxProtection;
}

static cl::opt<bool>
    EnableIRObfuscation("irobf", cl::init(false), cl::NotHidden,
                        cl::desc("Enable IR Code Obfuscation."));

// Taokari alias of the master -irobf flag.
static cl::alias TaokariIRObfuscation("taokari", cl::desc("Alias for -irobf"),
                                      cl::aliasopt(EnableIRObfuscation));

static cl::opt<bool>
    EnableIndirectBr("irobf-indbr", cl::init(false), cl::NotHidden,
                     cl::desc("Enable IR Indirect Branch Obfuscation."));
static cl::opt<uint32_t>
    LevelIndirectBr("level-indbr", cl::init(0), cl::NotHidden,
                    cl::desc("Set IR Indirect Branch Obfuscation Level."));

static cl::alias TaokariIndirectBr("taokari-indbr",
                                   cl::desc("Alias for -irobf-indbr"),
                                   cl::aliasopt(EnableIndirectBr));
static cl::alias TaokariLevelIndirectBr("taokari-level-indbr",
                                        cl::desc("Alias for -level-indbr"),
                                        cl::aliasopt(LevelIndirectBr));

static cl::opt<bool>
    EnableIndirectCall("irobf-icall", cl::init(false), cl::NotHidden,
                       cl::desc("Enable IR Indirect Call Obfuscation."));
static cl::opt<uint32_t>
    LevelIndirectCall("level-icall", cl::init(0), cl::NotHidden,
                      cl::desc("Set IR Indirect Call Obfuscation Level."));
static cl::opt<uint32_t> TaokariIndirectCallProbability(
    "taokari-icall-prob", cl::init(101), cl::NotHidden,
    cl::desc("Indirect call-site probability, 0..100."));
static cl::opt<uint32_t> TaokariIndirectCallFunctionProbability(
    "taokari-icall-func-prob", cl::init(101), cl::NotHidden,
    cl::desc("Indirect call per-function probability, 0..100."));

static cl::alias TaokariIndirectCall("taokari-icall",
                                     cl::desc("Alias for -irobf-icall"),
                                     cl::aliasopt(EnableIndirectCall));
static cl::alias TaokariLevelIndirectCall("taokari-level-icall",
                                          cl::desc("Alias for -level-icall"),
                                          cl::aliasopt(LevelIndirectCall));

static cl::opt<bool> EnableIndirectGV(
    "irobf-indgv", cl::init(false), cl::NotHidden,
    cl::desc("Enable IR Indirect Global Variable Obfuscation."));
static cl::opt<uint32_t> LevelIndirectGV(
    "level-indgv", cl::init(0), cl::NotHidden,
    cl::desc("Set IR Indirect Global Variable Obfuscation Level."));

static cl::alias TaokariIndirectGV("taokari-indgv",
                                   cl::desc("Alias for -irobf-indgv"),
                                   cl::aliasopt(EnableIndirectGV));
static cl::alias TaokariLevelIndirectGV("taokari-level-indgv",
                                        cl::desc("Alias for -level-indgv"),
                                        cl::aliasopt(LevelIndirectGV));

static cl::opt<bool> EnableIRFlattening(
    "irobf-fla", cl::init(false), cl::NotHidden,
    cl::desc("Enable IR Control Flow Flattening Obfuscation."));
static cl::opt<uint32_t> LevelIRFlattening(
    "level-fla", cl::init(0), cl::NotHidden,
    cl::desc("Set IR Control Flow Flattening Obfuscation Level."));

static cl::alias TaokariIRFlattening("taokari-fla",
                                     cl::desc("Alias for -irobf-fla"),
                                     cl::aliasopt(EnableIRFlattening));
static cl::alias TaokariLevelIRFlattening("taokari-level-fla",
                                          cl::desc("Alias for -level-fla"),
                                          cl::aliasopt(LevelIRFlattening));

static cl::opt<bool>
    EnableIRStringEncryption("irobf-cse", cl::init(false), cl::NotHidden,
                             cl::desc("Enable IR Constant String Encryption."));

static cl::alias
    TaokariIRStringEncryption("taokari-cse", cl::desc("Alias for -irobf-cse"),
                              cl::aliasopt(EnableIRStringEncryption));

static cl::opt<bool> EnableIRConstantIntEncryption(
    "irobf-cie", cl::init(false), cl::NotHidden,
    cl::desc("Enable IR Constant Integer Encryption."));
static cl::opt<uint32_t> LevelIRConstantIntEncryption(
    "level-cie", cl::init(0), cl::NotHidden,
    cl::desc("Set IR Constant Integer Encryption Level."));

static cl::alias
    TaokariIRConstantIntEncryption("taokari-cie",
                                   cl::desc("Alias for -irobf-cie"),
                                   cl::aliasopt(EnableIRConstantIntEncryption));
static cl::alias TaokariLevelIRConstantIntEncryption(
    "taokari-level-cie", cl::desc("Alias for -level-cie"),
    cl::aliasopt(LevelIRConstantIntEncryption));

static cl::opt<bool>
    EnableIRConstantFPEncryption("irobf-cfe", cl::init(false), cl::NotHidden,
                                 cl::desc("Enable IR Constant FP Encryption."));

static cl::opt<uint32_t> LevelIRConstantFPEncryption(
    "level-cfe", cl::init(0), cl::NotHidden,
    cl::desc("Set IR Constant FP Encryption Level."));

static cl::alias
    TaokariIRConstantFPEncryption("taokari-cfe",
                                  cl::desc("Alias for -irobf-cfe"),
                                  cl::aliasopt(EnableIRConstantFPEncryption));
static cl::alias TaokariLevelIRConstantFPEncryption(
    "taokari-level-cfe", cl::desc("Alias for -level-cfe"),
    cl::aliasopt(LevelIRConstantFPEncryption));

static cl::opt<bool> TaokariConstVolatileSeed(
    "taokari-const-volatile-seed", cl::init(true), cl::NotHidden,
    cl::desc("Use volatile runtime seed loads in constant decryptors."));
static cl::opt<bool> TaokariConstDecryptorMBA(
    "taokari-const-decryptor-mba", cl::init(false), cl::NotHidden,
    cl::desc("Use MBA for final constant decryptor add."));

static cl::opt<bool> EnableRttiEraser("irobf-rtti", cl::init(false),
                                      cl::NotHidden,
                                      cl::desc("Enable RTTI Eraser."));

static cl::alias TaokariRttiEraser("taokari-rtti",
                                   cl::desc("Alias for -irobf-rtti"),
                                   cl::aliasopt(EnableRttiEraser));

static cl::opt<bool>
    EnableMetadataHygiene("irobf-meta", cl::init(false), cl::NotHidden,
                          cl::desc("Enable metadata and symbol hygiene."));
static cl::opt<uint32_t>
    LevelMetadataHygiene("level-meta", cl::init(0), cl::NotHidden,
                         cl::desc("Set metadata hygiene level."));

static cl::alias TaokariMetadataHygiene("taokari-meta",
                                        cl::desc("Alias for -irobf-meta"),
                                        cl::aliasopt(EnableMetadataHygiene));
static cl::alias
    TaokariLevelMetadataHygiene("taokari-level-meta",
                                cl::desc("Alias for -level-meta"),
                                cl::aliasopt(LevelMetadataHygiene));

static cl::opt<bool>
    EnableBogusControlFlow("irobf-bcf", cl::init(false), cl::NotHidden,
                           cl::desc("Enable IR Bogus Control Flow."));
static cl::opt<uint32_t>
    LevelBogusControlFlow("level-bcf", cl::init(0), cl::NotHidden,
                          cl::desc("Set IR Bogus Control Flow Level."));

static cl::alias TaokariBogusControlFlow("taokari-bcf",
                                         cl::desc("Alias for -irobf-bcf"),
                                         cl::aliasopt(EnableBogusControlFlow));
static cl::alias
    TaokariLevelBogusControlFlow("taokari-level-bcf",
                                 cl::desc("Alias for -level-bcf"),
                                 cl::aliasopt(LevelBogusControlFlow));

static cl::opt<bool> TaokariBCFBeforeFlattening(
    "taokari-bcf-before-fla", cl::init(false), cl::NotHidden,
    cl::desc("Run BCF before control-flow flattening."));
static cl::opt<bool> TaokariBCFAfterFlattening(
    "taokari-bcf-after-fla", cl::init(false), cl::NotHidden,
    cl::desc("Run BCF after control-flow flattening."));

static cl::opt<bool> TaokariMaxNoBCFBefore(
    "taokari-max-no-bcf-before", cl::init(false), cl::NotHidden,
    cl::desc("Benchmark helper: disable max BCF before flattening."));
static cl::opt<bool> TaokariMaxNoBCFAfter(
    "taokari-max-no-bcf-after", cl::init(false), cl::NotHidden,
    cl::desc("Benchmark helper: disable max BCF after flattening."));
static cl::opt<bool> TaokariMaxNoFlattening(
    "taokari-max-no-fla", cl::init(false), cl::NotHidden,
    cl::desc("Benchmark helper: disable max flattening."));
static cl::opt<bool>
    TaokariMaxNoMBA("taokari-max-no-mba", cl::init(false), cl::NotHidden,
                    cl::desc("Benchmark helper: disable max MBA."));
static cl::opt<bool> TaokariMaxNoConst(
    "taokari-max-no-const", cl::init(false), cl::NotHidden,
    cl::desc("Benchmark helper: disable max constant encryption."));
static cl::opt<bool> TaokariMaxNoIndirects(
    "taokari-max-no-indirects", cl::init(false), cl::NotHidden,
    cl::desc("Benchmark helper: disable max indirect passes."));

static cl::opt<bool>
    EnableMBA("irobf-mba", cl::init(false), cl::NotHidden,
              cl::desc("Enable IR Mixed Boolean Arithmetic substitution."));
static cl::opt<uint32_t>
    LevelMBA("level-mba", cl::init(0), cl::NotHidden,
             cl::desc("Set IR Mixed Boolean Arithmetic Level."));

static cl::alias TaokariMBA("taokari-mba", cl::desc("Alias for -irobf-mba"),
                            cl::aliasopt(EnableMBA));
static cl::alias TaokariLevelMBA("taokari-level-mba",
                                 cl::desc("Alias for -level-mba"),
                                 cl::aliasopt(LevelMBA));

static cl::opt<bool>
    EnableVMP("irobf-vmp", cl::init(false), cl::NotHidden,
              cl::desc("Enable IR code virtualization prototype."));
static cl::opt<uint32_t>
    LevelVMP("level-vmp", cl::init(0), cl::NotHidden,
             cl::desc("Set IR code virtualization level."));

static cl::alias TaokariVMP("taokari-vmp", cl::desc("Alias for -irobf-vmp"),
                            cl::aliasopt(EnableVMP));
static cl::alias TaokariLevelVMP("taokari-level-vmp",
                                 cl::desc("Alias for -level-vmp"),
                                 cl::aliasopt(LevelVMP));

static cl::opt<std::string> TaokariConfigPath("taokari-cfg",
                                              cl::init(std::string{}),
                                              cl::NotHidden,
                                              cl::desc("Taokari config path."));

static cl::opt<bool> TaokariReport(
    "taokari-report", cl::init(false), cl::NotHidden,
    cl::desc("Print the resolved obfuscation configuration to stderr "
             "at the start of the pass pipeline (todo.md item: config "
             "report output)."));

static cl::opt<std::string>
    ArkariConfigPath("arkari-cfg", cl::init(std::string{}), cl::NotHidden,
                     cl::desc("Arkari config path compatibility alias."));

namespace llvm {

struct ObfuscationPassManager : public ModulePass {
  static char ID; // Pass identification
  SmallVector<Pass *, 8> Passes;
  std::shared_ptr<ObfuscationOptions> Options;

  ObfuscationPassManager() : ModulePass(ID) {
    initializeObfuscationPassManagerPass(*PassRegistry::getPassRegistry());
  };

  StringRef getPassName() const override { return "Obfuscation Pass Manager"; }

  bool doFinalization(Module &M) override {
    bool Change = false;
    for (Pass *P : Passes) {
      Change |= P->doFinalization(M);
      delete (P);
    }
    Options.reset();
    return Change;
  }

  void add(Pass *P) { Passes.push_back(P); }

  bool run(Module &M) {
    bool Change = false;
    for (Pass *P : Passes) {
      switch (P->getPassKind()) {
      case PassKind::PT_Function:
        Change |= runFunctionPass(M, (FunctionPass *)P);
        break;
      case PassKind::PT_Module:
        Change |= runModulePass(M, (ModulePass *)P);
        break;
      default:
        continue;
      }
    }
    return Change;
  }

  bool runFunctionPass(Module &M, FunctionPass *P) {
    bool Changed = false;
    Changed |= P->doInitialization(M);
    for (Function &F : M) {
      Changed |= P->runOnFunction(F);
    }
    return Changed;
  }

  bool runModulePass(Module &M, ModulePass *P) {
    return P->doInitialization(M) || P->runOnModule(M);
  }

  static std::shared_ptr<ObfuscationOptions> getOptions() {
    auto Opt = ObfuscationOptions::readConfigFile(
        TaokariConfigPath.empty() ? ArkariConfigPath : TaokariConfigPath);

    Opt->indBrOpt()->readOpt(EnableIndirectBr, LevelIndirectBr);
    Opt->iCallOpt()->readOpt(EnableIndirectCall, LevelIndirectCall);
    if (TaokariIndirectCallProbability.getNumOccurrences())
      Opt->iCallOpt()->setProbability(TaokariIndirectCallProbability);
    if (TaokariIndirectCallFunctionProbability.getNumOccurrences())
      Opt->iCallOpt()->setFunctionProbability(
          TaokariIndirectCallFunctionProbability);
    Opt->indGvOpt()->readOpt(EnableIndirectGV, LevelIndirectGV);
    Opt->flaOpt()->readOpt(EnableIRFlattening, LevelIRFlattening);
    Opt->cseOpt()->readOpt(EnableIRStringEncryption);
    Opt->cieOpt()->readOpt(EnableIRConstantIntEncryption,
                           LevelIRConstantIntEncryption);
    Opt->cfeOpt()->readOpt(EnableIRConstantFPEncryption,
                           LevelIRConstantFPEncryption);
    if (TaokariConstVolatileSeed.getNumOccurrences()) {
      Opt->cieOpt()->setVolatileSeed(TaokariConstVolatileSeed);
      Opt->cfeOpt()->setVolatileSeed(TaokariConstVolatileSeed);
    }
    if (TaokariConstDecryptorMBA.getNumOccurrences()) {
      Opt->cieOpt()->setConstDecryptorMBA(TaokariConstDecryptorMBA);
      Opt->cfeOpt()->setConstDecryptorMBA(TaokariConstDecryptorMBA);
    }
    Opt->bcfOpt()->readOpt(EnableBogusControlFlow, LevelBogusControlFlow);
    Opt->mbaOpt()->readOpt(EnableMBA, LevelMBA);
    Opt->rttiOpt()->readOpt(EnableRttiEraser);
    Opt->metaOpt()->readOpt(EnableMetadataHygiene, LevelMetadataHygiene);
    Opt->vmpOpt()->readOpt(EnableVMP, LevelVMP);

    if (TaokariMaxProtection) {
      for (const auto &O : Opt->getAllOpt()) {
        O->setEnable(true);
        O->setLevel(4);
        O->setProbability(100);
        O->setFunctionProbability(100);
      }
      Opt->bcfOpt()->setLoopCount(3);
      Opt->cseOpt()->setMinStringLength(1);
      Opt->cseOpt()->setStringLocalStackDecrypt(true);
      Opt->cseOpt()->setStringHeapDecrypt(true);
      Opt->cseOpt()->setStringReencryptAfterUse(true);
      Opt->cseOpt()->setStringDecryptorMBA(true);
      Opt->cseOpt()->setStringDecryptorFlattening(true);
      Opt->cseOpt()->setStringDecryptorIndirectCall(true);
      Opt->cseOpt()->setStringShardedPool(true);
      Opt->cseOpt()->setStringFakePools(true);
      Opt->cseOpt()->setStringPageTableAccess(true);
      Opt->cseOpt()->setStringDelayedDecrypt(true);
      Opt->cieOpt()->setMinConstSize(1);
      Opt->cieOpt()->setVolatileSeed(true);
      Opt->cieOpt()->setConstDecryptorMBA(true);
      Opt->cfeOpt()->setVolatileSeed(true);
      Opt->cfeOpt()->setConstDecryptorMBA(true);
      Opt->metaOpt()->setReleaseStrip(true);
      Opt->metaOpt()->setRandomizeSections(true);
      if (Opt->randomSeed().empty())
        Opt->randomSeed().append("taokari-max-default-seed");
      TaokariBCFBeforeFlattening = !TaokariMaxNoBCFBefore;
      TaokariBCFAfterFlattening = !TaokariMaxNoBCFAfter;
      if (TaokariMaxNoFlattening)
        Opt->flaOpt()->setEnable(false);
      if (TaokariMaxNoMBA)
        Opt->mbaOpt()->setEnable(false);
      if (TaokariMaxNoConst) {
        Opt->cieOpt()->setEnable(false);
        Opt->cfeOpt()->setEnable(false);
      }
      if (TaokariMaxNoIndirects) {
        Opt->indBrOpt()->setEnable(false);
        Opt->iCallOpt()->setEnable(false);
        Opt->indGvOpt()->setEnable(false);
      }
    }
    return Opt;
  }

  bool runOnModule(Module &M) override {

    if (EnableIndirectBr || EnableIndirectCall || EnableIndirectGV ||
        EnableIRFlattening || EnableIRStringEncryption ||
        EnableIRConstantIntEncryption || EnableIRConstantFPEncryption ||
        EnableBogusControlFlow || EnableMBA || EnableRttiEraser ||
        EnableMetadataHygiene || EnableVMP || TaokariMaxProtection ||
        !TaokariConfigPath.empty() || !ArkariConfigPath.empty()) {
      EnableIRObfuscation = true;
    }

    if (!EnableIRObfuscation) {
      return false;
    }

    const auto Options(getOptions());
    this->Options = Options;
    unsigned pointerSize = M.getDataLayout().getTypeAllocSize(
        PointerType::getUnqual(M.getContext()));

    if (TaokariReport) {
      auto PrintOpt = [](const char *Name, const std::shared_ptr<ObfOpt> &O) {
        errs() << "taokari-report: " << Name
               << " enable=" << (O->isEnabled() ? "true" : "false")
               << " level=" << O->level() << "\n";
      };
      PrintOpt("indbr", Options->indBrOpt());
      PrintOpt("icall", Options->iCallOpt());
      PrintOpt("indgv", Options->indGvOpt());
      PrintOpt("fla", Options->flaOpt());
      PrintOpt("cse", Options->cseOpt());
      PrintOpt("cie", Options->cieOpt());
      PrintOpt("cfe", Options->cfeOpt());
      PrintOpt("bcf", Options->bcfOpt());
      PrintOpt("mba", Options->mbaOpt());
      PrintOpt("meta", Options->metaOpt());
      PrintOpt("vmp", Options->vmpOpt());
    }

    // VMP runs before hardening passes so the interpreter IR can be flattened,
    // dirtied and encrypted by the normal Taokari stack.
    add(llvm::createCodeVirtualizationPass(Options.get()));
    add(llvm::createMbaPass(Options.get()));

    add(llvm::createConstantIntEncryptionPass(Options.get()));

    add(llvm::createIndirectGlobalVariablePass(Options.get()));

    add(llvm::createConstantFPEncryptionPass(Options.get()));

    if (EnableIRStringEncryption || Options->cseOpt()->isEnabled()) {
      add(llvm::createStringEncryptionPass(Options.get()));
    }

    add(llvm::createIndirectCallPass(Options.get()));
    if (!TaokariBCFAfterFlattening || TaokariBCFBeforeFlattening)
      add(llvm::createBogusControlFlowPass(Options.get()));
    add(llvm::createFlatteningPass(pointerSize, Options.get()));
    if (TaokariBCFAfterFlattening)
      add(llvm::createBogusControlFlowPass(Options.get()));
    add(llvm::createIndirectBranchPass(Options.get()));

    if (EnableRttiEraser || Options->rttiOpt()->isEnabled()) {
      add(llvm::createMsRttiEraserPass(Options.get()));
    }
    if (EnableMetadataHygiene || Options->metaOpt()->isEnabled()) {
      add(llvm::createMetadataHygienePass(Options.get()));
    }
    // Native per-function integrity prototype. Opt-in via the
    // `+nativeint` annotation; the pass is cheap on non-annotated
    // functions (one annotation lookup and return).
    add(llvm::createNativeIntegrityPass(Options.get()));
    bool Changed = run(M);

    return Changed;
  }
};
} // namespace llvm

char ObfuscationPassManager::ID = 0;

ModulePass *llvm::createObfuscationPassManager() {
  return new ObfuscationPassManager();
}

INITIALIZE_PASS_BEGIN(ObfuscationPassManager, "irobf", "Enable IR Obfuscation",
                      false, false)
INITIALIZE_PASS_END(ObfuscationPassManager, "irobf", "Enable IR Obfuscation",
                    false, false)
