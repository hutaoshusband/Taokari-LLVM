#include "llvm/Transforms/Obfuscation/ObfuscationPassManager.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"
#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/IR/Module.h"


#define DEBUG_TYPE "ir-obfuscation"

using namespace llvm;

static cl::opt<bool>
EnableIRObfuscation("irobf", cl::init(false), cl::NotHidden,
                    cl::desc("Enable IR Code Obfuscation."));

// Taokari alias of the master -irobf flag.
static cl::alias
TaokariIRObfuscation("taokari", cl::desc("Alias for -irobf"),
                     cl::aliasopt(EnableIRObfuscation));


static cl::opt<bool>
EnableIndirectBr("irobf-indbr", cl::init(false), cl::NotHidden,
                 cl::desc("Enable IR Indirect Branch Obfuscation."));
static cl::opt<uint32_t>
LevelIndirectBr("level-indbr", cl::init(0), cl::NotHidden,
                cl::desc("Set IR Indirect Branch Obfuscation Level."));

static cl::alias
TaokariIndirectBr("taokari-indbr", cl::desc("Alias for -irobf-indbr"),
                  cl::aliasopt(EnableIndirectBr));
static cl::alias
TaokariLevelIndirectBr("taokari-level-indbr",
                       cl::desc("Alias for -level-indbr"),
                       cl::aliasopt(LevelIndirectBr));


static cl::opt<bool>
EnableIndirectCall("irobf-icall", cl::init(false), cl::NotHidden,
                   cl::desc("Enable IR Indirect Call Obfuscation."));
static cl::opt<uint32_t>
LevelIndirectCall("level-icall", cl::init(0), cl::NotHidden,
                  cl::desc("Set IR Indirect Call Obfuscation Level."));

static cl::alias
TaokariIndirectCall("taokari-icall", cl::desc("Alias for -irobf-icall"),
                    cl::aliasopt(EnableIndirectCall));
static cl::alias
TaokariLevelIndirectCall("taokari-level-icall",
                         cl::desc("Alias for -level-icall"),
                         cl::aliasopt(LevelIndirectCall));


static cl::opt<bool> EnableIndirectGV(
    "irobf-indgv", cl::init(false), cl::NotHidden,
    cl::desc("Enable IR Indirect Global Variable Obfuscation."));
static cl::opt<uint32_t> LevelIndirectGV(
    "level-indgv", cl::init(0), cl::NotHidden,
    cl::desc("Set IR Indirect Global Variable Obfuscation Level."));

static cl::alias
TaokariIndirectGV("taokari-indgv", cl::desc("Alias for -irobf-indgv"),
                  cl::aliasopt(EnableIndirectGV));
static cl::alias
TaokariLevelIndirectGV("taokari-level-indgv",
                       cl::desc("Alias for -level-indgv"),
                       cl::aliasopt(LevelIndirectGV));


static cl::opt<bool> EnableIRFlattening(
    "irobf-fla", cl::init(false), cl::NotHidden,
    cl::desc("Enable IR Control Flow Flattening Obfuscation."));
static cl::opt<uint32_t> LevelIRFlattening(
    "level-fla", cl::init(0), cl::NotHidden,
    cl::desc("Set IR Control Flow Flattening Obfuscation Level."));

static cl::alias
TaokariIRFlattening("taokari-fla", cl::desc("Alias for -irobf-fla"),
                    cl::aliasopt(EnableIRFlattening));
static cl::alias
TaokariLevelIRFlattening("taokari-level-fla",
                         cl::desc("Alias for -level-fla"),
                         cl::aliasopt(LevelIRFlattening));


static cl::opt<bool>
EnableIRStringEncryption("irobf-cse", cl::init(false), cl::NotHidden,
                         cl::desc("Enable IR Constant String Encryption."));

static cl::alias
TaokariIRStringEncryption("taokari-cse",
                          cl::desc("Alias for -irobf-cse"),
                          cl::aliasopt(EnableIRStringEncryption));


static cl::opt<bool>
EnableIRConstantIntEncryption("irobf-cie", cl::init(false), cl::NotHidden,
                              cl::desc(
                                  "Enable IR Constant Integer Encryption."));
static cl::opt<uint32_t> LevelIRConstantIntEncryption(
    "level-cie", cl::init(0), cl::NotHidden,
    cl::desc("Set IR Constant Integer Encryption Level."));

static cl::alias
TaokariIRConstantIntEncryption("taokari-cie",
                               cl::desc("Alias for -irobf-cie"),
                               cl::aliasopt(EnableIRConstantIntEncryption));
static cl::alias
TaokariLevelIRConstantIntEncryption("taokari-level-cie",
                                    cl::desc("Alias for -level-cie"),
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
static cl::alias
TaokariLevelIRConstantFPEncryption("taokari-level-cfe",
                                   cl::desc("Alias for -level-cfe"),
                                   cl::aliasopt(LevelIRConstantFPEncryption));


static cl::opt<bool>
EnableRttiEraser("irobf-rtti", cl::init(false), cl::NotHidden,
                 cl::desc("Enable RTTI Eraser."));

static cl::alias
TaokariRttiEraser("taokari-rtti", cl::desc("Alias for -irobf-rtti"),
                  cl::aliasopt(EnableRttiEraser));


static cl::opt<std::string>
TaokariConfigPath("taokari-cfg", cl::init(std::string{}), cl::NotHidden,
                  cl::desc("Taokari config path."));

static cl::opt<std::string>
ArkariConfigPath("arkari-cfg", cl::init(std::string{}), cl::NotHidden,
                 cl::desc("Arkari config path compatibility alias."));

namespace llvm {

struct ObfuscationPassManager : public ModulePass {
  static char            ID; // Pass identification
  SmallVector<Pass *, 8> Passes;
  std::shared_ptr<ObfuscationOptions> Options;

  ObfuscationPassManager() : ModulePass(ID) {
    initializeObfuscationPassManagerPass(*PassRegistry::getPassRegistry());
  };

  StringRef getPassName() const override {
    return "Obfuscation Pass Manager";
  }

  bool doFinalization(Module &M) override {
    bool Change = false;
    for (Pass *P : Passes) {
      Change |= P->doFinalization(M);
      delete (P);
    }
    Options.reset();
    return Change;
  }

  void add(Pass *P) {
    Passes.push_back(P);
  }

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
    Opt->indGvOpt()->readOpt(EnableIndirectGV, LevelIndirectGV);
    Opt->flaOpt()->readOpt(EnableIRFlattening, LevelIRFlattening);
    Opt->cseOpt()->readOpt(EnableIRStringEncryption);
    Opt->cieOpt()->readOpt(EnableIRConstantIntEncryption,
                           LevelIRConstantIntEncryption);
    Opt->cfeOpt()->readOpt(EnableIRConstantFPEncryption,
                           LevelIRConstantFPEncryption);
    Opt->rttiOpt()->readOpt(EnableRttiEraser);
    return Opt;
  }

  bool runOnModule(Module &M) override {

    if (EnableIndirectBr || EnableIndirectCall || EnableIndirectGV ||
        EnableIRFlattening || EnableIRStringEncryption ||
        EnableIRConstantIntEncryption || EnableIRConstantFPEncryption ||
        EnableRttiEraser || !TaokariConfigPath.empty() ||
        !ArkariConfigPath.empty()) {
      EnableIRObfuscation = true;
    }

    if (!EnableIRObfuscation) {
      return false;
    }

    const auto Options(getOptions());
    this->Options = Options;
    unsigned   pointerSize = M.getDataLayout().getTypeAllocSize(
        PointerType::getUnqual(M.getContext()));

    add(llvm::createConstantIntEncryptionPass(Options.get()));

    add(llvm::createIndirectGlobalVariablePass(Options.get()));

    add(llvm::createConstantFPEncryptionPass(Options.get()));

    if (EnableIRStringEncryption || Options->cseOpt()->isEnabled()) {
      add(llvm::createStringEncryptionPass(Options.get()));
    }

    add(llvm::createIndirectCallPass(Options.get()));
    add(llvm::createFlatteningPass(pointerSize, Options.get()));
    add(llvm::createIndirectBranchPass(Options.get()));

    if (EnableRttiEraser || Options->rttiOpt()->isEnabled()) {
      add(llvm::createMsRttiEraserPass(Options.get()));
    }
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
