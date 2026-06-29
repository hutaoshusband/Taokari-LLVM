#ifndef LLVM_TRANSFORMS_OBFUSCATION_OPAQUECONSTANT_H
#define LLVM_TRANSFORMS_OBFUSCATION_OPAQUECONSTANT_H

#include "llvm/IR/PassManager.h"

#include <memory>

namespace llvm {
class FunctionPass;
class ObfuscationOptions;

FunctionPass *createOpaqueConstantPass(ObfuscationOptions *argsOptions);

class OpaqueConstantNewPMPass
    : public PassInfoMixin<OpaqueConstantNewPMPass> {
public:
  PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM);
  static bool isRequired() { return true; }

private:
  std::shared_ptr<ObfuscationOptions> Options;
  std::unique_ptr<FunctionPass> Legacy;
};

} // namespace llvm

#endif
