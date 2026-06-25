#ifndef LLVM_TRANSFORMS_OBFUSCATION_DYNAMICPROTECTION_H
#define LLVM_TRANSFORMS_OBFUSCATION_DYNAMICPROTECTION_H

namespace llvm {
class FunctionPass;
class ObfuscationOptions;

// Optional dynamic anti-reversing checks (debugger / timing / breakpoint / PEB).
// Opt-in per function via the `dyn` annotation or globally via -taokari-dyn.
// Off by default; never crashes a process that is not actually being debugged.
FunctionPass *createDynamicProtectionPass(ObfuscationOptions *argsOptions);
}

#endif
