#ifndef LLVM_TRANSFORMS_OBFUSCATION_MBA_H
#define LLVM_TRANSFORMS_OBFUSCATION_MBA_H

namespace llvm {
class FunctionPass;
class ObfuscationOptions;

FunctionPass *createMbaPass(ObfuscationOptions *argsOptions);
}

#endif
