#ifndef _ITANIUM_RTTI_ERASER_INCLUDES_
#define _ITANIUM_RTTI_ERASER_INCLUDES_

namespace llvm {
class ModulePass;
class PassRegistry;
class ObfuscationOptions;

ModulePass *createItaniumRttiEraserPass(ObfuscationOptions *argsOptions);
void        initializeItaniumRttiEraserPass(PassRegistry &Registry);

}

#endif
