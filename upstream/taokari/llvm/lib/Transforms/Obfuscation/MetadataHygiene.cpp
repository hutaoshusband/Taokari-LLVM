#include "llvm/Transforms/Obfuscation/MetadataHygiene.h"
#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/GlobalObject.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/BLAKE3.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#define DEBUG_TYPE "metadata-hygiene"

using namespace llvm;

namespace llvm {
extern cl::opt<bool> TaokariMaxProtection;
}

namespace {

class MetadataHygiene : public ModulePass {
  ObfuscationOptions *ArgsOptions;
  llvm::BLAKE3 Blake3;

public:
  static char ID;

  MetadataHygiene(ObfuscationOptions *ArgsOptions) : ModulePass(ID) {
    this->ArgsOptions = ArgsOptions;
    initializeMetadataHygienePass(*PassRegistry::getPassRegistry());
  }

  StringRef getPassName() const override { return "MetadataHygiene"; }

  bool runOnModule(Module &M) override {
    auto Opt = ArgsOptions->metaOpt();
    if (!Opt->isEnabled())
      return false;
    if (Opt->level() > 1 && ArgsOptions->randomSeed().empty())
      report_fatal_error(
          "No random seed found in config file, but metadata hygiene enabled.");

    bool Changed = stripMetadata(M, *Opt);
    if (Opt->level() > 1) {
      Changed |= addFakeHelpers(M);
      Changed |= renamePrivateSymbols(M, *Opt);
    }
    if (Opt->level() > 2 &&
        (Opt->releaseStrip() || Opt->randomizeSections()))
      Changed |= randomizeSections(M);
    return Changed;
  }

  bool stripMetadata(Module &M, const ObfOpt &Opt) {
    bool Changed = StripDebugInfo(M);
    for (StringRef Name : {"llvm.ident", "llvm.commandline"}) {
      if (auto *NMD = M.getNamedMetadata(Name)) {
        M.eraseNamedMetadata(NMD);
        Changed = true;
      }
    }
    if (TaokariMaxProtection || Opt.releaseStrip()) {
      if (auto *Annotations = M.getGlobalVariable("llvm.global.annotations")) {
        Annotations->eraseFromParent();
        Changed = true;
      }
    }
    return Changed;
  }

  bool isAllowlisted(StringRef Name, const ObfOpt &Opt) const {
    if (Name == "main" || Name == "wmain" || Name == "WinMain" ||
        Name == "wWinMain" || Name == "DllMain")
      return true;
    for (const auto &Allowed : Opt.exportAllowlist())
      if (Name == Allowed)
        return true;
    return false;
  }

  bool canRename(const GlobalValue &GV, const ObfOpt &Opt) const {
    if (!GV.hasName() || GV.isDeclarationForLinker() ||
        GV.hasComdat() || GV.hasDLLExportStorageClass() ||
        GV.hasExternalWeakLinkage() || GV.hasAvailableExternallyLinkage())
      return false;
    if (auto *F = dyn_cast<Function>(&GV))
      if (F->isIntrinsic())
        return false;
    if (isAllowlisted(GV.getName(), Opt))
      return false;
    return GV.hasLocalLinkage() || GV.hasHiddenVisibility() ||
           GV.isDiscardableIfUnused() || GV.getName().contains("RTTI");
  }

  std::string digestName(StringRef Prefix, StringRef Name) {
    SmallString<256> Input;
    Input.append(ArgsOptions->randomSeed());
    Input.append(Prefix);
    Input.append(Name);
    Blake3.init();
    Blake3.update(Input);
    auto Hash = Blake3.final();
    std::string Out = Prefix.str();
    constexpr char Hex[] = "0123456789abcdef";
    for (unsigned I = 0; I < 10; ++I) {
      Out.push_back(Hex[(Hash[I] >> 4) & 0xf]);
      Out.push_back(Hex[Hash[I] & 0xf]);
    }
    return Out;
  }

  void renameGlobal(GlobalValue &GV, StringRef Prefix) {
    std::string NewName = digestName(Prefix, GV.getName());
    if (auto *GO = dyn_cast<GlobalObject>(&GV)) {
      if (Comdat *OldComdat = GO->getComdat()) {
        Comdat *NewComdat = GV.getParent()->getOrInsertComdat(NewName);
        NewComdat->setSelectionKind(OldComdat->getSelectionKind());
        GO->setComdat(NewComdat);
      }
    }
    GV.setName(NewName);
  }

  bool renamePrivateSymbols(Module &M, const ObfOpt &Opt) {
    bool Changed = false;
    for (Function &F : M) {
      if (!canRename(F, Opt))
        continue;
      renameGlobal(F, "__mhf_");
      Changed = true;
    }
    for (GlobalVariable &GV : M.globals()) {
      if (!canRename(GV, Opt))
        continue;
      renameGlobal(GV, "__mhg_");
      Changed = true;
    }
    return Changed;
  }

  bool addFakeHelpers(Module &M) {
    auto &Ctx = M.getContext();
    SmallVector<GlobalValue *, 4> Used;
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *FnTy = FunctionType::get(I32, {I32}, false);
    auto *F = Function::Create(FnTy, GlobalValue::InternalLinkage,
                               digestName("__mhf_", "fake_helper"), M);
    F->addFnAttr(Attribute::NoInline);
    auto *BB = BasicBlock::Create(Ctx, "entry", F);
    IRBuilder<> IRB(BB);
    auto *Arg = F->getArg(0);
    auto *Val = IRB.CreateXor(Arg, ConstantInt::get(I32, 0x5a5a5a5a));
    Val = IRB.CreateXor(Val, ConstantInt::get(I32, 0x5a5a5a5a));
    IRB.CreateRet(Val);
    Used.push_back(F);

    auto *GV = new GlobalVariable(
        M, I32, false, GlobalValue::InternalLinkage,
        ConstantInt::get(I32, 0x6d657461), digestName("__mhg_", "fake_state"));
    Used.push_back(GV);
    appendToCompilerUsed(M, Used);
    return true;
  }

  std::string sectionFor(const Module &M, const GlobalObject &GO) {
    Triple T(M.getTargetTriple());
    StringRef Kind = isa<Function>(GO) ? "text" : "data";
    if (auto *GV = dyn_cast<GlobalVariable>(&GO))
      if (GV->isConstant())
        Kind = "rdata";
    std::string Suffix = digestName("", GO.getName()).substr(0, 8);
    if (T.isOSBinFormatMachO())
      return (Kind == "text" ? "__TEXT,__" : "__DATA,__") + Suffix;
    if (T.isOSBinFormatCOFF())
      return (Kind == "text" ? ".text$" : Kind == "rdata" ? ".rdata$"
                                                            : ".data$") +
             Suffix;
    return (Kind == "text" ? ".text." : Kind == "rdata" ? ".rodata."
                                                          : ".data.") +
           Suffix;
  }

  bool randomizeSections(Module &M) {
    bool Changed = false;
    for (Function &F : M) {
      if (!F.hasLocalLinkage() || F.isDeclaration())
        continue;
      F.setSection(sectionFor(M, F));
      Changed = true;
    }
    for (GlobalVariable &GV : M.globals()) {
      if (!GV.hasLocalLinkage() || GV.isDeclaration())
        continue;
      GV.setSection(sectionFor(M, GV));
      Changed = true;
    }
    return Changed;
  }
};

} // namespace

char MetadataHygiene::ID = 0;

ModulePass *llvm::createMetadataHygienePass(ObfuscationOptions *ArgsOptions) {
  return new MetadataHygiene(ArgsOptions);
}

INITIALIZE_PASS(MetadataHygiene, "metadata-hygiene",
                "Enable metadata and symbol hygiene", false, false)
