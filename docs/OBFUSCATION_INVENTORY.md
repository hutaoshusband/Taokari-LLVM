# Obfuscation Inventory

Arkari's obfuscation implementation is already concentrated in one LLVM component:

```text
upstream/taokari/llvm/lib/Transforms/Obfuscation
upstream/taokari/llvm/include/llvm/Transforms/Obfuscation
```

Current pass surface:

- `ObfuscationPassManager.cpp` - owns the public command-line flags and pass dispatch.
- `ObfuscationOptions.cpp` - reads JSON config and per-pass options.
- `IndirectBranch.cpp` - indirect branch obfuscation.
- `IndirectCall.cpp` - indirect call obfuscation.
- `IndirectGlobalVariable.cpp` - indirect global variable access.
- `StringEncryption.cpp` - C string encryption.
- `Flattening.cpp` - control-flow flattening.
- `ConstantIntEncryption.cpp` - integer constant encryption.
- `ConstantFPEncryption.cpp` - floating-point constant encryption.
- `MicrosoftRTTIEraser.cpp` - MS C++ RTTI name erasure.

Strong base points:

- The obfuscator is integrated into LLVM's normal pass pipeline instead of a loose plugin.
- Options support command-line flags, annotations, and JSON config.
- Windows-focused fixes already exist for SEH, DLL-import globals, x86 indirect calls,
  and Visual Studio plugin duplicate arguments.

Good Taokari next steps:

- Add Taokari aliases while keeping Arkari flags compatible.
- Add small lit tests for each pass before changing behavior.
- Split config parsing errors into clear diagnostics.
- Build a tiny sample-driven verification script for `clang -mllvm -irobf`.
