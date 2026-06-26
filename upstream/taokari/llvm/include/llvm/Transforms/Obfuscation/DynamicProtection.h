#ifndef LLVM_TRANSFORMS_OBFUSCATION_DYNAMICPROTECTION_H
#define LLVM_TRANSFORMS_OBFUSCATION_DYNAMICPROTECTION_H

#include "llvm/IR/IRBuilder.h"

#include <cstdint>

namespace llvm {
class FunctionPass;
class GlobalVariable;
class Module;
class ObfuscationOptions;
class Value;

namespace taokari {
GlobalVariable *getOrCreateDynamicTamperFlag(Module &M);
Value *emitDynamicDebuggerCheck(Module &M, IRBuilder<> &B);
Value *emitDynamicRemoteDebuggerCheck(Module &M, IRBuilder<> &B);
Value *emitDynamicTimingCheck(Module &M, IRBuilder<> &B,
                              uint64_t Threshold = 50000000ULL);
Value *emitDynamicRuntimeCheck(Module &M, IRBuilder<> &B, uint32_t Level);
void markDynamicTamper(Module &M, IRBuilder<> &B);
}

// Optional dynamic anti-reversing checks (debugger / timing / breakpoint / PEB).
// Opt-in per function via the `dyn` annotation or globally via -taokari-dyn.
// Off by default; never crashes a process that is not actually being debugged.
FunctionPass *createDynamicProtectionPass(ObfuscationOptions *argsOptions);
}

#endif
