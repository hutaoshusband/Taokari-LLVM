#include "llvm/Transforms/Obfuscation/ObfuscationPassManager.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Obfuscation/BogusControlFlow.h"
#include "llvm/Transforms/Obfuscation/CodeVirtualization.h"
#include "llvm/Transforms/Obfuscation/DynamicProtection.h"
#include "llvm/Transforms/Obfuscation/FunctionOutlining.h"
#include "llvm/Transforms/Obfuscation/MBA.h"
#include "llvm/Transforms/Obfuscation/NativeIntegrity.h"
#include "llvm/Transforms/Obfuscation/OpaqueConstant.h"
#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"

#define DEBUG_TYPE "ir-obfuscation"

using namespace llvm;

namespace llvm {
extern cl::opt<bool> TaokariMaxProtection;
}

static cl::opt<bool>
    EnableIRObfuscation("irobf", cl::init(false), cl::NotHidden,
                        cl::desc("Enable IR Code Obfuscation. Master switch "
                                 "for the Taokari obfuscator. Set to enable "
                                 "any combination of the per-pass -irobf-* / "
                                 "-taokari-* flags below. Use -taokari-cfg "
                                 "to drive configuration from a JSON file, "
                                 "or -taokari-max for the all-on preset."));

// Taokari alias of the master -irobf flag.
static cl::alias TaokariIRObfuscation("taokari", cl::desc("Alias for -irobf"),
                                      cl::aliasopt(EnableIRObfuscation));

static cl::opt<bool>
    EnableIndirectBr("irobf-indbr", cl::init(false), cl::NotHidden,
                     cl::desc("Enable IR Indirect Branch Obfuscation."));
static cl::opt<uint32_t>
    LevelIndirectBr("level-indbr", cl::init(0), cl::NotHidden,
                    cl::desc("Set IR Indirect Branch Obfuscation Level "
                             "(0=off, 1=basic, 2=strong, 3=fortress, "
                             "4=fortress+). Each level compounds the others: "
                             "compile time and binary size grow roughly "
                             "linearly with level."));

static cl::alias TaokariIndirectBr("taokari-indbr",
                                   cl::desc("Alias for -irobf-indbr"),
                                   cl::aliasopt(EnableIndirectBr));
static cl::alias TaokariLevelIndirectBr("taokari-level-indbr",
                                        cl::desc("Alias for -level-indbr"),
                                        cl::aliasopt(LevelIndirectBr));
static cl::opt<uint32_t> TaokariIndirectBrProbability(
    "taokari-indbr-prob", cl::init(101), cl::NotHidden,
    cl::desc("Indirect branch conversion probability, 0..100. Caps how many "
             "conditional branches per function get rewritten as page-table "
             "indirect branches, bounding compile time and binary size."));

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
    cl::desc("Enable IR Control Flow Flattening Obfuscation. Replaces the "
             "real CFG with a switch-dispatch state machine so a decompiler "
             "cannot follow the original block order. CHEAP on compile time; "
             "the cost is binary size and (with level>=3) decompiler visual "
             "noise. Use -taokari-level-fla to set the strength (0..4)."));
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

static cl::opt<bool> EnableOpaqueConstant(
    "irobf-ocnst", cl::init(false), cl::NotHidden,
    cl::desc("Enable IR Opaque Constant substitution. Rewrites plain "
             "integer constants as opaque XOR-of-runtime-values "
             "expressions that survive InstCombine but evaluate to the "
             "exact original value. Distinct from -taokari-cie (which "
             "encrypts via a global pool); ocnst is lighter-weight and "
             "composable with cie."));
static cl::alias
    TaokariOpaqueConstant("taokari-ocnst",
                          cl::desc("Alias for -irobf-ocnst"),
                          cl::aliasopt(EnableOpaqueConstant));

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
                           cl::desc("Enable IR Bogus Control Flow. Inserts "
                                    "fake basic blocks guarded by opaque "
                                    "predicates so a decompiler sees "
                                    "plausible-but-dead control flow. CHEAP "
                                    "on compile time; cost is binary size "
                                    "(scales with -taokari-bcf-loops and "
                                    "selection probability). Use "
                                    "-taokari-bcf-before-fla and "
                                    "-taokari-bcf-after-fla to wrap the "
                                    "flattened dispatcher on both sides "
                                    "(biggest single IDA visual win)."));
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
static cl::opt<bool> TaokariMaxNoVMP(
    "taokari-max-no-vmp", cl::init(false), cl::NotHidden,
    cl::desc("Escape hatch for -taokari-max + -taokari-vmp: keep every other "
             "max-strength pass on but force vmp off so the build cannot hang "
             "on per-function VM work. Without this, -taokari-max sets vmp "
             "globally enabled, so every non-trivial function becomes a VMP "
             "candidate with no budget cap and the compile hangs."));

static cl::opt<bool>
    EnableMBA("irobf-mba", cl::init(false), cl::NotHidden,
              cl::desc("Enable IR Mixed Boolean Arithmetic substitution. "
                       "Rewrites simple arithmetic (a+b, a^b, a&b, ...) as "
                       "equivalent MBA expressions that survive InstCombine "
                       "and GVN. CHEAP on compile time; cost is binary size "
                       "and instruction count (scales with -taokari-mba-prob "
                       "0..100)."));
static cl::opt<uint32_t>
    LevelMBA("level-mba", cl::init(0), cl::NotHidden,
             cl::desc("Set IR Mixed Boolean Arithmetic Level."));

static cl::alias TaokariMBA("taokari-mba", cl::desc("Alias for -irobf-mba"),
                            cl::aliasopt(EnableMBA));
static cl::alias TaokariLevelMBA("taokari-level-mba",
                                 cl::desc("Alias for -level-mba"),
                                 cl::aliasopt(LevelMBA));

static cl::opt<bool>
    EnableOutline("irobf-outline", cl::init(false), cl::NotHidden,
                  cl::desc("Enable IR Function Outlining. Splits selected "
                           "single-successor basic blocks out into internal "
                           "helper functions so a sensitive function no "
                           "longer reads as one static body in a decompiler. "
                           "CHEAP on compile time; cost is call overhead and "
                           "binary size (scales with -taokari-outline-prob "
                           "0..100 and -taokari-outline-max-shards)."));
static cl::opt<uint32_t>
    LevelOutline("level-outline", cl::init(0), cl::NotHidden,
                 cl::desc("Set IR Function Outlining Level."));

static cl::alias
    TaokariOutline("taokari-outline", cl::desc("Alias for -irobf-outline"),
                   cl::aliasopt(EnableOutline));
static cl::alias TaokariLevelOutline("taokari-level-outline",
                                     cl::desc("Alias for -level-outline"),
                                     cl::aliasopt(LevelOutline));

namespace llvm {
cl::opt<bool>
    EnableDyn("irobf-dyn", cl::init(false), cl::NotHidden,
              cl::desc("Enable dynamic anti-reversing checks (debugger / "
                       "timing / PEB). OFF BY DEFAULT and intentionally not "
                       "part of -taokari-max: these checks read process state "
                       "and could misfire under unusual tooling. Opt-in per "
                       "function via the `dyn` annotation or this flag. SAFE: "
                       "never trips on a process that is not actually being "
                       "debugged, so a normal test run is unaffected."));
} // namespace llvm
static cl::alias TaokariDyn("taokari-dyn", cl::desc("Alias for -irobf-dyn"),
                            cl::aliasopt(EnableDyn));

static cl::opt<bool>
    EnableVMP("irobf-vmp", cl::init(false), cl::NotHidden,
              cl::desc("Enable IR code virtualization prototype. Compiles "
                       "annotated functions to a per-function VM bytecode "
                       "interpreter so the original logic is no longer "
                       "readable as native code. VERY EXPENSIVE on compile "
                       "AND runtime: do not virtualize hot loops (use "
                       "-taokari-vmp-max-back-edges to refuse them), and do "
                       "not enable globally under -taokari-max without "
                       "budget caps (-taokari-vmp-max-bytecode-words, "
                       "-taokari-vmp-max-bytecode-expansion). Recommended "
                       "production path: annotation-only via "
                       "__attribute__((annotate(\"+vmp\"))) on a few "
                       "hand-picked sensitive functions, with -vmp on "
                       "CRT/main."));
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
                                              cl::desc("Taokari config path. "
                                                       "JSON file that drives "
                                                       "every per-pass toggle "
                                                       "and level. Overrides "
                                                       "implied defaults; "
                                                       "command-line -taokari-* "
                                                       "flags override the "
                                                       "config in turn. See "
                                                       "docs/CONFIGURATION.md "
                                                       "for the schema."));

static cl::opt<bool> TaokariReport(
    "taokari-report", cl::init(false), cl::NotHidden,
    cl::desc("Print the resolved obfuscation configuration to stderr "
             "at the start of the pass pipeline. DIAGNOSTICS: use this to "
             "verify which passes are actually enabled and at what level "
             "after -taokari-max / -taokari-cfg / command-line flags are "
             "all merged. No effect on output."));

static cl::opt<std::string>
    ArkariConfigPath("arkari-cfg", cl::init(std::string{}), cl::NotHidden,
                     cl::desc("Arkari config path compatibility alias."));

namespace llvm {

static bool isTaokariHelper(const Function &F) {
  StringRef N = F.getName();
  return N.starts_with("__taokari_icall_fake_") ||
         N.starts_with("__taokari_icall_shard_") ||
         N.starts_with("__taokari_sh_") ||
         N.starts_with("__taokari_bcf_") ||
         N.starts_with("__taokari_dyn_") ||
         N.starts_with("__taokari_vmp_interp_") ||
         N.starts_with("__taokari_nativeint_") ||
         N.starts_with("__mhf_") ||
         N.starts_with("goron_scrub_string_") ||
         N.starts_with("__global_variable_initializer_") ||
         N.contains(".cie.shard.") || N.contains(".shard");
}

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
    SmallVector<Function *, 0> Snapshot;
    Snapshot.reserve(M.size());
    for (Function &F : M)
      Snapshot.push_back(&F);
    for (Function *F : Snapshot) {
      if (F->isDeclaration() || isTaokariHelper(*F))
        continue;
      Changed |= P->runOnFunction(*F);
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
    if (TaokariIndirectBrProbability.getNumOccurrences())
      Opt->indBrOpt()->setProbability(TaokariIndirectBrProbability);
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
    Opt->ocnstOpt()->readOpt(EnableOpaqueConstant);
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
    Opt->outlineOpt()->readOpt(EnableOutline, LevelOutline);
    Opt->dynOpt()->readOpt(EnableDyn);
    Opt->rttiOpt()->readOpt(EnableRttiEraser);
    Opt->metaOpt()->readOpt(EnableMetadataHygiene, LevelMetadataHygiene);
    Opt->vmpOpt()->readOpt(EnableVMP, LevelVMP);
    const bool DynSelected = Opt->dynOpt()->isEnabled();

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
      if (!DynSelected)
        Opt->dynOpt()->setEnable(false);
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
      // -taokari-max-no-vmp: leave every other max pass at L4/prob 100 but
      // force VMP off so the compile cannot hang on per-function VM work.
      // The existing -taokari-max-no-* helpers (bcf/fla/mba/const/indirects)
      // cover the cheap passes; VMP is the one pass expensive enough to need
      // its own opt-out under -taokari-max. See docs/CONFIGURATION.md
      // "Max Protection + VMP budget".
      if (TaokariMaxNoVMP)
        Opt->vmpOpt()->setEnable(false);
    }
    return Opt;
  }

  bool runOnModule(Module &M) override {

    if (EnableIndirectBr || EnableIndirectCall || EnableIndirectGV ||
        EnableIRFlattening || EnableIRStringEncryption ||
        EnableIRConstantIntEncryption || EnableIRConstantFPEncryption ||
        EnableBogusControlFlow || EnableMBA || EnableOutline || EnableDyn ||
        EnableRttiEraser ||
        EnableMetadataHygiene || EnableVMP || TaokariMaxProtection ||
        EnableOpaqueConstant ||
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
      PrintOpt("outline", Options->outlineOpt());
      PrintOpt("dyn", Options->dynOpt());
      PrintOpt("meta", Options->metaOpt());
      PrintOpt("vmp", Options->vmpOpt());
    }

    // VMP runs before hardening passes so the interpreter IR can be flattened,
    // dirtied and encrypted by the normal Taokari stack.
    add(llvm::createCodeVirtualizationPass(Options.get()));
    add(llvm::createMbaPass(Options.get()));
    // Outline before flattening/indirect-branch: the candidate block shape
    // (single successor, no PHI) is only stable this early in the pipeline.
    add(llvm::createFunctionOutliningPass(Options.get()));

    add(llvm::createConstantIntEncryptionPass(Options.get()));
    add(llvm::createOpaqueConstantPass(Options.get()));

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
    // Dynamic anti-reversing checks (debugger / timing / PEB). Off by default;
    // opt-in per function via the `dyn` annotation or -taokari-dyn.
    add(llvm::createDynamicProtectionPass(Options.get()));
    bool Changed = run(M);

    return Changed;
  }
};
} // namespace llvm

char ObfuscationPassManager::ID = 0;

ModulePass *llvm::createObfuscationPassManager() {
  return new ObfuscationPassManager();
}

std::shared_ptr<ObfuscationOptions>
llvm::getTaokariObfuscationOptions() {
  return ObfuscationPassManager::getOptions();
}

INITIALIZE_PASS_BEGIN(ObfuscationPassManager, "irobf", "Enable IR Obfuscation",
                      false, false)
INITIALIZE_PASS_END(ObfuscationPassManager, "irobf", "Enable IR Obfuscation",
                    false, false)
