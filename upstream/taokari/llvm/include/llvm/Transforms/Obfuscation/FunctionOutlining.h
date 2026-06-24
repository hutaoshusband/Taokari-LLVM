#ifndef LLVM_TRANSFORMS_OBFUSCATION_FUNCTIONOUTLINING_H
#define LLVM_TRANSFORMS_OBFUSCATION_FUNCTIONOUTLINING_H

namespace llvm {
class FunctionPass;
class ObfuscationOptions;

FunctionPass *createFunctionOutliningPass(ObfuscationOptions *argsOptions);
}

#endif
