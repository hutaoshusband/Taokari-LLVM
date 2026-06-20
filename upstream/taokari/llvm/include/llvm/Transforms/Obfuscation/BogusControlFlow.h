#ifndef LLVM_TRANSFORMS_OBFUSCATION_BOGUSCONTROLFLOW_H
#define LLVM_TRANSFORMS_OBFUSCATION_BOGUSCONTROLFLOW_H

namespace llvm {
class FunctionPass;
class ObfuscationOptions;

FunctionPass *createBogusControlFlowPass(ObfuscationOptions *argsOptions);
}

#endif
