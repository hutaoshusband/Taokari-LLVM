#ifndef LLVM_TRANSFORMS_OBFUSCATION_CODE_VIRTUALIZATION_H
#define LLVM_TRANSFORMS_OBFUSCATION_CODE_VIRTUALIZATION_H

namespace llvm {
class ModulePass;
class ObfuscationOptions;

ModulePass *createCodeVirtualizationPass(ObfuscationOptions *argsOptions);
}

#endif
