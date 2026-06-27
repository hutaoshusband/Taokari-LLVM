#ifndef LLVM_TRANSFORMS_OBFUSCATION_OPAQUECONSTANT_H
#define LLVM_TRANSFORMS_OBFUSCATION_OPAQUECONSTANT_H

namespace llvm {
class FunctionPass;
class ObfuscationOptions;

FunctionPass *createOpaqueConstantPass(ObfuscationOptions *argsOptions);
}

#endif
