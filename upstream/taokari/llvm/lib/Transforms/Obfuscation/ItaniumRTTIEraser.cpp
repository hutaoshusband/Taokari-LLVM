#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscation/ItaniumRTTIEraser.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/PassRegistry.h"
#include "llvm/Support/BLAKE3.h"
#include "llvm/TargetParser/Triple.h"

#define DEBUG_TYPE "itanium_rtti_eraser"

using namespace llvm;

namespace {

class ItaniumRttiEraser : public ModulePass {
protected:
  ObfuscationOptions *ArgsOptions;
  BLAKE3 Blake3;

public:
  static char ID;

  ItaniumRttiEraser(ObfuscationOptions *argsOptions) : ModulePass(ID) {
    this->ArgsOptions = argsOptions;
    initializeItaniumRttiEraserPass(*PassRegistry::getPassRegistry());
  }

  StringRef getPassName() const override { return "ItaniumRttiEraser"; }

  bool runOnModule(Module &M) override {
    Triple T(M.getTargetTriple());
    if (T.isOSBinFormatCOFF() || T.isOSWindows())
      return false;
    if (ArgsOptions->randomSeed().empty()) {
      report_fatal_error(
          "No random seed found in config file, but rtti eraser enabled.");
    }
    bool Changed = false;
    LLVMContext &Ctx = M.getContext();
    for (GlobalVariable &GV : M.globals()) {
      if (!GV.isConstant() || !GV.hasInitializer() || !GV.hasName())
        continue;
      if (!GV.getName().starts_with("_ZTS"))
        continue;
      auto *Arr = dyn_cast<ConstantDataArray>(GV.getInitializer());
      if (!Arr || !Arr->isString())
        continue;
      StringRef Body = Arr->getAsString();
      std::string Demangled = demangleItaniumName(Body);
      if (Demangled.empty())
        continue;
      std::string Encoded = remangleName(GV.getName(), Body);
      Constant *New = ConstantDataArray::getString(
          Ctx, Encoded, Encoded.back() != '\0');
      GV.setInitializer(New);
      Changed = true;
    }
    return Changed;
  }

  static unsigned readNumber(StringRef S, unsigned &Pos) {
    unsigned N = 0;
    bool Any = false;
    while (Pos < S.size() && S[Pos] >= '0' && S[Pos] <= '9') {
      N = N * 10 + (S[Pos] - '0');
      ++Pos;
      Any = true;
    }
    return Any ? N : 0;
  }

  static std::string demangleItaniumName(StringRef S) {
    std::string Out;
    unsigned Pos = 0;
    while (Pos < S.size()) {
      if (S[Pos] == 'E')
        break;
      if (Pos + 1 < S.size() && S[Pos] == 'N')
        ++Pos;
      unsigned Len = readNumber(S, Pos);
      if (Len == 0 || Pos + Len > S.size())
        return "";
      if (!Out.empty())
        Out.push_back(':');
      Out.append(S.substr(Pos, Len));
      Pos += Len;
    }
    return Out;
  }

  std::string remangleName(StringRef Symbol, StringRef Body) {
    SmallString<256> Input;
    Input.append(ArgsOptions->randomSeed());
    Input.append(Symbol);
    Input.append(Body);
    Blake3.init();
    Blake3.update(Input);
    auto Hash = Blake3.final();

    constexpr char Table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789";
    std::string Out = Body.str();
    unsigned H = 0;
    for (size_t I = 0; I < Out.size(); ++I) {
      char C = Out[I];
      if (C >= '0' && C <= '9') {
        Out[I] = Table[(Hash[H % Hash.size()] + C) % (sizeof(Table) - 1)];
        ++H;
      } else if ((C >= 'A' && C <= 'Z') || (C >= 'a' && C <= 'z')) {
        Out[I] = Table[(Hash[H % Hash.size()] ^ C) % (sizeof(Table) - 1)];
        ++H;
      }
    }
    return Out;
  }
};

} // namespace

char ItaniumRttiEraser::ID = 0;

ModulePass *llvm::createItaniumRttiEraserPass(ObfuscationOptions *argsOptions) {
  return new ItaniumRttiEraser(argsOptions);
}

INITIALIZE_PASS(ItaniumRttiEraser, "itanium_rtti_eraser",
                "Enable Itanium RTTI Eraser", false, false)
