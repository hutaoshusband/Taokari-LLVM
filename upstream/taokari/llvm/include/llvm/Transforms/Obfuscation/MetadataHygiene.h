#ifndef OBFUSCATION_METADATAHYGIENE_H
#define OBFUSCATION_METADATAHYGIENE_H

#include "llvm/IR/PassManager.h"

namespace llvm {

class ModulePass;
class PassRegistry;
class ObfuscationOptions;

ModulePass *createMetadataHygienePass(ObfuscationOptions *argsOptions);
void initializeMetadataHygienePass(PassRegistry &Registry);

} // namespace llvm

#endif
