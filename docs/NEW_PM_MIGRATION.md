# Taokari — New Pass Manager Migration Blockers

Status of running Taokari under LLVM's new pass manager (new-PM), the
remaining blockers to a *native* new-PM port (not the legacy-bridge that
ships today), and the smallest viable migration path.

## Current state: a legacy bridge, not a port

Taokari already runs under the new-PM via a **bridge wrapper**, not a native
port:

- `llvm/include/llvm/Transforms/Obfuscation/ObfuscationPassManager.h`
  defines `ObfuscationPassManagerPass : public PassInfoMixin<...>`. Its
  `run(Module&, ModuleAnalysisManager&)` allocates the legacy
  `ObfuscationPassManager` (`ModulePass`), calls `runOnModule` +
  `doFinalization`, and returns `PreservedAnalyses`.
- That wrapper is hooked into the default pipeline at
  `llvm/lib/Passes/PassBuilderPipelines.cpp:392`
  (`MPM.addPass(ObfuscationPassManagerPass())` inside
  `invokeOptimizerLastEPCallbacks`), immediately before the cleanup
  `SimplifyCFG`/`InstCombine`/`ADCE` passes.

So the new-PM pipeline entry point exists and the obfuscator fires under
`clang -fpasses=...` / the default backend pipeline. What does **not** exist
is a native port: every individual obfuscation pass is still a legacy
`FunctionPass` / `ModulePass`, and the OPM schedules them through a legacy
dispatcher.

## Blockers to a native new-PM port

### B1. Every pass is legacy `FunctionPass` / `ModulePass`

Every obfuscation pass derives from the legacy pass base classes, which the
new-PM does not schedule directly:

| Pass | Base | File |
| --- | --- | --- |
| `BogusControlFlow` | `FunctionPass` | `BogusControlFlow.cpp:33` |
| `ConstantIntEncryption` | `FunctionPass` | `ConstantIntEncryption.cpp:31` |
| `ConstantFPEncryption` | `FunctionPass` | `ConstantFPEncryption.cpp:25` |
| `DynamicProtection` | `FunctionPass` | `DynamicProtection.cpp:156` |
| `Flattening` | `FunctionPass` | `Flattening.cpp:78` |
| `FunctionOutlining` | `FunctionPass` | `FunctionOutlining.cpp:57` |
| `IndirectBranch` | `FunctionPass` | `IndirectBranch.cpp:117` |
| `IndirectCall` | `FunctionPass` | `IndirectCall.cpp:51` |
| `IndirectGlobalVariable` | `FunctionPass` | `IndirectGlobalVariable.cpp:34` |
| `LowerSwitch` (internal) | `FunctionPass` | `LegacyLowerSwitch.cpp:71` |
| `MBA` | `FunctionPass` | `MBA.cpp:33` |
| `NativeIntegrity` | `FunctionPass` | `NativeIntegrity.cpp:39` |
| `OpaqueConstant` | `FunctionPass` | `OpaqueConstant.cpp:60` |
| `MetadataHygiene` | `ModulePass` | `MetadataHygiene.cpp:24` |
| `MsRttiEraser` | `ModulePass` | `MicrosoftRTTIEraser.cpp:21` |
| `StringEncryption` | `ModulePass` | `StringEncryption.cpp:66` |
| `ObfuscationPassManager` | `ModulePass` | `ObfuscationPassManager.cpp:344` |

A native port means converting each `FunctionPass` to
`PassInfoMixin<...>` with `run(Function&, FunctionAnalysisManager&)`, and
each `ModulePass` to `run(Module&, ModuleAnalysisManager&)`.

### B2. The OPM owns legacy pass scheduling and order-sensitive interaction

`ObfuscationPassManager` (`ModulePass`) holds a `SmallVector<Pass*, 8>` of
legacy passes and dispatches them by `PassKind`
(`ObfuscationPassManager.cpp:367` `run`), wrapping `FunctionPass` runs in a
`FunctionPassManager`-style helper (`runFunctionPass`). The obfuscation
recipe is **order-sensitive** and must survive the port:

- BCF wraps flattening: `-taokari-bcf-before-fla` / `-taokari-bcf-after-fla`
  decide whether BCF runs before, after, or both sides of fla
  (`ObfuscationPassManager.cpp:552-556`). A native new-PM port must preserve
  this relative ordering, which new-PM expresses only via explicit
  `MPM.addPass` / `FPM.addPass` sequencing — not via a containing manager.
- Per-function state (`std::mt19937_64` RNG seeded per function,
  `ObfuscationOptions` shared pointer) is threaded through the legacy
  `FunctionPass` ctors (`createBogusControlFlowPass(Options.get())` etc.).
  New-PM passes have no ctor arguments — state must move to a module-level
  analysis or an immutable options struct read from `cl::opt` / the
  `PassBuilder` plugin.

### B3. `cl::opt` configuration surface

All Taokari flags (`-taokari`, `-taokari-max`, `-taokari-bcf-prob`,
`-taokari-vmp-max-bytecode-words`, the JSON config path, etc.) are
`llvm::cl::opt`. Under new-PM these still parse (global `cl` registry), but
the idiomatic new-PM path passes options through the `PassBuilder` /
pipeline text (`-passes=...`) and plugin callbacks. The bridge reads `cl`
directly, which works but is not how new-PM-native passes receive
parameters. Migrating the config plumbing is a separate, large task
(`ObfuscationOptions::readConfigFile`, `getOptions`).

### B4. Legacy lifecycle hooks

Several passes rely on `doInitialization(Module&)` / `doFinalization(Module&)`
to build module-wide structures once (e.g.
`ConstantIntEncryption::doInitialization` scans all target functions and
populates `FunctionModifyIRs`; `StringEncryption` builds the global pool).
New-PM has no per-pass init/finalize; the equivalent is a module analysis
that the function passes depend on, or folding the scan into the module
pass body. Each init-heavy pass needs its module scan repackaged.

### B5. Analysis dependencies

The passes consume legacy analyses (DominatorTree, PostDominatorTree,
LoopInfo, AssumptionCache, OptimizationRemarkEmitter, TargetLibraryInfo).
These all have new-PM equivalents obtained from the
`FunctionAnalysisManager` / `ModuleAnalysisManager`, but every
`getAnalysisUsage` / `getAnalysis<>()` call site must be rewritten to
`AM.getResult<...>(F)`.

### B6. `INITIALIZE_PASS` and registration

Each pass ends with `INITIALIZE_PASS(...)` and is created via a
`createXxxPass(ObfuscationOptions*)` factory. The new-PM registration model
is `PassPluginLibraryInfo` + `registerPipelineParsingCallback` (plugin) or
direct `addPass` in `PassBuilderPipelines.cpp`. The factories and
`INITIALIZE_PASS` blocks are legacy-only.

## Smallest viable migration step

Per todo 1.5 the migration is intentionally incremental. The recommended
first concrete port (smallest blast radius, validates the pattern) —
**DONE**:

1. **Pick one leaf `ModulePass` with no function-pass dependencies.** DONE:
   `MetadataHygiene` (`MetadataHygiene.cpp:24`) — module-scoped, no order
   interaction with the IR-obfuscation recipe, consumes no analyses.
2. **Add a `PassInfoMixin` twin** (`MetadataHygieneNewPMPass`,
   `MetadataHygiene.cpp`) with `run(Module&, ModuleAnalysisManager&)` that
   reuses the legacy `runOnModule` body via `createMetadataHygienePass`. The
   resolved options come from the shared `llvm::getTaokariObfuscationOptions()`
   (exposed from the OPM) so the twin sees the same `-taokari` / `-taokari-cfg`
   / `-taokari-max` resolution as the bridge. The legacy pass is kept for the
   bridge.
3. **Wire it** behind the existing bridge so the recipe still runs the legacy
   OPM, and the ported pass is *also* schedulable standalone via
   `-passes=metadata-hygiene-newpm` (registered as a module pipeline-parsing
   callback in `PassBuilder.cpp`) for differential testing.
4. **Validate** with `testing/scripts/verify_new_pm_metadata_hygiene.py`:
   exercises the standalone new-PM pass, confirms it is a no-op when meta is
   disabled and renames a secret internal symbol identically to the legacy
   path when enabled, and that the linked binary matches native output.

This does not unblock the OPM ordering problem (B2), but it proves the
per-pass conversion pattern and the options plumbing before attacking the
order-sensitive core. The next ports (MsRttiEraser, then the leaf
FunctionPasses) follow the same twin-with-shared-options shape.

### First FunctionPass port: OpaqueConstant (B2 progress)

The same twin-with-shared-options shape extends to function passes.
`OpaqueConstant` (`OpaqueConstant.cpp:32`, `FunctionPass`) gains
`OpaqueConstantNewPMPass` (`run(Function&, FunctionAnalysisManager&)`) that
lazily constructs the legacy pass once per pipeline and reuses it across
functions, so the per-module RNG/BuildSeed lifetime matches the legacy
path. The twin holds the resolved `ObfuscationOptions` as a member so the
legacy pass's raw options pointer stays valid for the whole module.
Schedulable standalone via `-passes=opaque-constant-newpm` (registered as a
module-level callback that wraps the function pass in
`createModuleToFunctionPassAdaptor`). Verified by
`testing/scripts/verify_new_pm_opaque_constant.py`.

This validates the function-pass conversion pattern. The remaining B2 risk
(order-sensitive passes threaded through the OPM recipe) still applies to
the *production* scheduling of function passes; standalone twins like this
one are for differential testing, not recipe scheduling.



## What does NOT block today

- The default `clang` pipeline already invokes the obfuscator under new-PM
  via the bridge (`PassBuilderPipelines.cpp:392`), so production builds are
  not blocked on a native port.
- `cl::opt` flags continue to work under new-PM (the bridge reads them).
- The bridge correctly returns `PreservedAnalyses::none()` on change, so
  downstream new-PM analyses are invalidated.

The native port is a code-hygiene / future-LLVM-removal task, not a
functional blocker. Track it under todo 1.5 ("Identify new pass-manager
migration blockers" → done by this document; "Create new-PM wrapper
prototype" → already shipped as the bridge; the remaining four items are
the incremental port work).
