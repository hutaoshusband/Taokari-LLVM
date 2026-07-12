# Obfuscation Inventory

Arkari's obfuscation implementation is already concentrated in one LLVM component:

```text
upstream/taokari/llvm/lib/Transforms/Obfuscation
upstream/taokari/llvm/include/llvm/Transforms/Obfuscation
```

Current pass surface:

- `ObfuscationPassManager.cpp` - owns the public command-line flags and pass dispatch.
- `ObfuscationOptions.cpp` - reads JSON config and per-pass options.
- `OpaquePredicate.cpp` - reusable opaque-predicate families (always-true/false, context-seeded, unfoldable).
- `BogusControlFlow.cpp` - bogus control flow with fake blocks, junk math, fake loops, fake memory accesses, L3 fake switch structures and fake error paths.
- `MBA.cpp` - mixed boolean/arithmetic substitution with per-function noise, multi-round hardening, and a per-function substitution budget.
- `IndirectBranch.cpp` - indirect branch obfuscation with per-branch conversion probability.
- `IndirectCall.cpp` - indirect call obfuscation with L3 call-shard thunks.
- `IndirectGlobalVariable.cpp` - indirect global variable access with a sensitive-globals size threshold.
- `StringEncryption.cpp` - C string encryption with L3 fortress knobs (MBA, flatten, indirect, shards, fakes, page-table, delayed-decrypt).
- `Flattening.cpp` - control-flow flattening with fake cases + opaque predicates.
- `ConstantIntEncryption.cpp` - integer constant encryption.
- `ConstantFPEncryption.cpp` - floating-point constant encryption.
- `MicrosoftRTTIEraser.cpp` - MS C++ RTTI name erasure.
- `MetadataHygiene.cpp` - source-path / debug-info / compiler-identifier stripping.
- `NativeIntegrity.cpp` - per-function native-code integrity prototype (entry-block hash check + tamper path).
- `FunctionOutlining.cpp` - callout obfuscation: splits basic-block tails into internal shard helpers (L1), opaque names + arg/return XOR scramble + fake shards (L2), multi-layer split + token-switched dispatcher + integrity guard + fake call graph (L3).
- `DynamicProtection.cpp` - opt-in dynamic anti-reversing checks (IsDebuggerPresent / CheckRemoteDebuggerPresent / QueryPerformanceCounter timing) with opaque-predicate mixing, runtime-nonce seed, shared tamper flag, delayed placement, indirect probe functions, and an anti-patch sentinel. Off by default.
- `Virtualization/CodeVirtualization.cpp` - bytecode VM with encrypted bytecode, PC/stack encryption, handler-body MBA noise, opcode-map self-verification, per-function interpreter cloning, and per-build tamper-response policy.

A second obfuscation component runs below the IR layer, in the codegen
pipeline (after register allocation and scheduling) — invisible to IR-level
tools and to the Hex-Rays microcode lifter in clean form. See
`docs/MACHINE_IR_OBFUSCATION.md`:

- `lib/CodeGen/TaokariMachineObf/TaokariMachineObf.cpp` - MachineFunctionPass
  scheduled via `X86PassConfig::addPreEmitPass()`, gated by
  `-mllvm -taokari-mir=<passes>` and the `mir` annotation. Level 1 is the
  infrastructure (flag, annotation reader, per-function gate, pipeline hook);
  the real transforms (dirty bytes, junk instructions, machine instruction
  substitution) are Level 2.

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
