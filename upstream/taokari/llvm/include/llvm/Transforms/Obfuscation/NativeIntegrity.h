#ifndef LLVM_TRANSFORMS_OBFUSCATION_NATIVEINTEGRITY_H
#define LLVM_TRANSFORMS_OBFUSCATION_NATIVEINTEGRITY_H

namespace llvm {
class FunctionPass;
class ObfuscationOptions;

// Per-function native-code integrity prototype. Emits a per-function
// private constant pool global and an entry-block hash check that
// routes to a tamper path (libc exit) if any pool byte is patched.
FunctionPass *createNativeIntegrityPass(ObfuscationOptions *argsOptions);
}

#endif
