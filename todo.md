# Taokari LLVM — Compressed Checkbox Roadmap

Living development roadmap for Taokari LLVM Obfuscator.

Goal: keep the roadmap small enough to actually use while still preserving the current finished work and making future expansion easy.

## Legend

| Mark | Meaning |
|---|---|
| `[x]` | Done / inherited / verified |
| `[ ]` | Open task |
| `🚧` | Partial / needs hardening |
| `🧪` | Test / verifier task |
| `📚` | Documentation task |
| `⚙️` | Build / tooling task |

## Working Rule

- [x] Keep this roadmap checkbox-based.
- [x] Keep finished work ticked.
- [x] Prefer one seam per commit.
- [x] Every implementation task needs a focused verifier.
- [x] Every new pass must prove correctness, overhead and optimizer/decompiler survival.
- [ ] When a task grows beyond one commit, split it into a child checklist before coding.

---

# 0. Current Completion Snapshot

This section is intentionally compressed. It marks the big systems that are already done so the roadmap does not keep re-listing hundreds of finished subtasks.

## 0.1 Baseline / Arkari Inheritance

- [x] Legacy pass manager integration.
- [x] `ObfuscationPassManager` and `-mllvm -irobf*` compatibility.
- [x] JSON config support.
- [x] `noobf` metadata support.
- [x] Existing Arkari passes preserved: flattening, indirect branches, indirect calls, indirect globals, constant encryption, string encryption, RTTI erasing.
- [x] Dedup caches preserved for constants, calls and globals.
- [x] Per-function CSPRNG seed preserved.
- [x] Existing test harness preserved.

## 0.2 IR Obfuscation Core

- [x] Control-flow flattening L3/L4: encoded state, fake cases, nested variants, anti-switch-recovery.
- [x] Opaque predicate engine L3: algebraic, context-based, registry, optimizer survival tests.
- [x] Bogus Control Flow L1/L2: fake paths, fake arithmetic, fake memory, BCF before/after flattening.
- [x] MBA L1/L2: randomized identities, multiple rounds, runtime nonce mixing, optimizer survival tests.
- [x] String encryption L3: polymorphic decryptors, string shards, fake pools, delayed decrypt, memory lifetime tests.
- [x] Function outlining L3: shards, fake shard graph, shard dispatcher, integrity checks, cross-shard pools.
- [x] Metadata hygiene L3: source path stripping, symbol randomization, section/helper randomization, leak tests.

## 0.3 Indirection Layer

- [x] Indirect calls L3: pointer reconstruction, fake edges, shard calls, AArch64 and Windows x64 tests.
- [x] Indirect branches L2/L3 mostly done: fake targets, shuffled tables, nonce mixing, integrity checks.
- [x] Indirect globals L2/L3 mostly done: fake pools, encrypted pools, per-use decrypt option, integrity checks.

## 0.4 Runtime / Integrity / Dynamic Protections

- [x] Dynamic protections L1/L2: anti-debug, timing, fake checks, delayed checks, tamper flag propagation.
- [x] Dynamic protections L3 mostly done: function integrity, encrypted hash table, randomized placement, tamper policy.
- [x] Native integrity prototype and verifier: patched protected native byte trips tamper path without memory unsafety.

## 0.5 Code Virtualization

- [x] VM L1 prototype: bytecode format, annotation, minimal interpreter, toy function.
- [x] VM L1.5: widened IR coverage, handler table refactor, differential harness, baseline benchmark.
- [x] VM L2 Phase A: runtime memory safety checks.
- [x] VM L2 Phase B: pointer support, globals, GEP, alignment, aliasing tests.
- [x] VM L2 Phase C: runtime key derivation, stronger stream/key schedule, immediates encryption, opcode permutation, integrity tag.
- [x] VM L2 Phase D: per-function interpreter clone, indirect handler dispatch, handler flattening.
- [x] VM L2 Phase E: callee table hardening and thunk obfuscation.
- [x] VM L2 Phase F: anti-frequency padding, fake opcodes, fake handlers.
- [x] VM L2 Phase G mostly done: mutation fuzzing, property-based differential tests, optimizer survival tests.
- [x] VM L2 extra hardening: PC encryption, stack/locals encryption, opmap self-verification, varied tamper responses.

## 0.6 Machine IR / Backend Layer

- [x] Machine IR infrastructure added under `llvm/lib/CodeGen/`.
- [x] X86 pre-emit hook and `-mllvm -taokari-mir=<passes>` flag.
- [x] MIR dirty bytes, junk instructions, instruction substitution.
- [x] MIR opaque predicate guard.
- [x] MIR fortress: function splitting, fake prologue/epilogue bytes, unmodelled instruction emission, decompiler snapshot tests.

## 0.7 Tier / Build Strategy

- [x] Tier A/B/C/D recipes defined.
- [x] `-taokari-max-no-vmp` added.
- [x] VMP budget caps added.
- [x] Strong blanket recipe includes BCF around flattening and MIR fortress.
- [x] Build timing capture added.
- [x] Tier verifiers added.
- [x] Max + VMP hang mitigated by caps.

---

# 1. Active Cleanup Backlog

These are the remaining small gaps from the current roadmap. Do these before starting large new research tracks.

## 1.1 Control Flow / BCF / MBA

- [x] 🚧 Finish BCF L3 multi-layer bogus graphs.
- [x] 🚧 Add fake exception-looking BCF regions where safe.
- [x] 🚧 Integrate BCF fake regions with flattening dispatcher fake cases.
- [x] 🚧 Add MBA on flattening dispatch-state updates.

## 1.2 Constants / Globals / Branches

- [x] Add opaque constant pass.
- [x] Add context-dependent constants.
- [x] Add per-function constant pool.
- [x] Add encrypted constant pool.
- [ ] Add page-table-backed constants.
- [x] Add indirect constant references.
- [x] Add constant access through helper shards.
- [ ] Add fake recovery paths for indirect branches.
- [ ] Add split global storage.

## 1.3 Dynamic / Integrity

- [x] Add post-link hash patching.
- [x] Add whole-binary or section-range checksum after function-level integrity.
- [x] Add a verifier for final `.text` section hashing.
- [x] Ensure dynamic protection remains optional and off by default unless explicitly selected by profile.

## 1.4 VM Remaining L2/L3 Items

- [x] 🧪 Add decompiler-lift test for VMP functions.
- [x] Add per-function overhead budget for VMP.
- [x] 🧪 Add decompiler/IDA snapshot proof for runtime rekey and DirtyBytes guard shape when IDA is available.
- [x] Add polymorphic VM builds.
- [x] Add per-function ISA randomization beyond opcode permutation.
- [x] Add encrypted basic-block bytecode.
- [x] Add handler MBA.
- [x] Add handler BCF.
- [x] Add stronger rolling/cross-function bytecode integrity checks.
- [x] Add VM devirtualization test samples.
- [x] Add anti-debug/anti-trace inside the interpreter loop through the DynamicProtection framework.
- [x] Add anti-emulation checks suitable for protected commercial builds.
- [x] Add cross-function VM state.
- [x] Add per-build handler-table obfuscation seed verification.

## 1.5 Config / Build / Testing

- [ ] Add max binary-size growth limit.
- [ ] Add max compile-time growth limit.
- [ ] Add max runtime overhead target.
- [x] 🧪 Add decompiler snapshot tests to the normal release-blocking suite.
- [ ] 📚 Add clean Linux build instructions.
- [ ] ⚙️ Add CI build check.
- [x] Identify new pass-manager migration blockers.
- [x] Create new-PM wrapper prototype.
- [x] Port one simple module pass to new-PM.
- [ ] Port one simple function pass to new-PM.
- [x] Test Taokari under the current LLVM new-PM pipeline.
- [x] Finish MIR config keys per sub-pass.
- [x] 📚 Document that `-taokari-max` is budgeted and how VMP opt-in behaves.

---

# 2. Expansion Track A — Cross-Platform Support

Goal: make Taokari less Windows-only without losing the current Windows x64 stability.

## A1. Linux Build Path

- [ ] 📚 Write clean Linux build instructions.
- [ ] ⚙️ Add Ubuntu build script.
- [ ] ⚙️ Add Ninja/CMake preset for Linux.
- [ ] 🧪 Add Linux smoke test with a tiny C program.
- [ ] 🧪 Add Linux smoke test with a tiny C++ program.
- [ ] 🧪 Add Linux test for exceptions and RTTI if supported.
- [ ] 🧪 Add Linux string/constant encryption test.
- [ ] 🧪 Add Linux indirect call/branch/global test.
- [ ] 🧪 Add Linux VMP opt-in function test.

## A2. AArch64 / ARM64 Expansion

- [x] AArch64 pointer-auth path exists.
- [x] AArch64 MIR parity planning exists.
- [ ] Add AArch64 build smoke test.
- [ ] Add AArch64 indirect branch/call parity test.
- [ ] Add AArch64 string/constant encryption parity test.
- [ ] Add AArch64 MIR no-op infrastructure smoke test.
- [ ] Add AArch64 MIR dirtybytes equivalent only if architecture-safe.
- [ ] Document which MIR sub-passes are x86-only.

## A3. Platform Feature Matrix

- [ ] 📚 Create `docs/PLATFORM_MATRIX.md`.
- [ ] List Windows x64 pass support.
- [ ] List Linux x64 pass support.
- [ ] List AArch64 pass support.
- [ ] Mark unsupported combinations explicitly.
- [ ] Add release-blocking tests per supported platform.

---

# 3. Expansion Track B — VM Fortress Evolution

Goal: make the VM harder to signature, harder to lift and safer to ship.

## B1. VM Polymorphism

- [x] Add per-build interpreter layout randomization.
- [x] Randomize alloca layout.
- [x] Randomize spill/register strategy where safe.
- [x] Randomize handler order and handler grouping per function.
- [x] Randomize operand encoding per function.
- [x] 🧪 Add two-build structural-diff verifier.
- [x] 🧪 Assert two builds do not share a VM signature.

## B2. Per-Function ISA Randomization

- [x] Split stable VM opcodes into opcode families.
- [x] Allow equivalent handlers with different operand formats.
- [x] Add per-function opcode-set generation.
- [x] Add absent/decoy handlers so functions do not share the same ISA surface.
- [x] 🧪 Add verifier that two `+vmp` functions cannot reuse the same opcode map.
- [x] 🧪 Add differential harness coverage for each opcode family.

## B3. Encrypted Basic-Block Bytecode

- [x] Add per-basic-block bytecode key.
- [x] Add per-basic-block integrity tag.
- [x] Decrypt block only on edge transfer.
- [x] Re-key state after each virtual edge.
- [x] Refuse malformed block transfers with a clean tamper path.
- [x] 🧪 Add bytecode block mutation fuzzer.
- [x] 🧪 Add optimizer survival test for per-block encryption.

## B4. Handler Obfuscation

- [x] Apply MBA inside arithmetic handlers.
- [x] Apply BCF to selected handler bodies.
- [x] Apply MIR noise to generated handler code where safe.
- [x] Add fake but reachable handler bodies.
- [x] Avoid breaking VM correctness or liveness.
- [x] 🧪 Add native-vs-VMP differential test after handler obfuscation.
- [x] 🧪 Add decompiler snapshot test for handler bodies.

## B5. Anti-Trace / Anti-Emulation

- [x] Route interpreter-loop checks through DynamicProtection.
- [x] Add configurable anti-trace gate.
- [x] Add configurable anti-emulation gate.
- [x] Add safe false-positive mode for development.
- [x] Add profile knob: `vm.anti_trace = off/light/strong`.
- [x] 🧪 Add false-positive benchmark.
- [x] 🧪 Add clean execution test on normal hardware.

## B6. Cross-Function VM State

- [x] Add shared obfuscated module state.
- [x] Make selected handlers depend on module state.
- [x] Update state through opaque transitions.
- [x] Keep isolated function testing possible through a test-only mode.
- [x] 🧪 Add verifier that lifting one function alone is incomplete.
- [x] 🧪 Add regression tests for multi-function VMP programs.

---

# 4. Expansion Track C — Machine IR / Backend Evolution

Goal: make protection survive below the IR layer and keep decompilers from repairing classic LLVM patterns.

## C1. MIR Configuration

- [x] Finish config keys for each MIR sub-pass.
- [x] Add probability config for `dirtybytes`.
- [x] Add probability config for `junk`.
- [x] Add probability config for `sub`.
- [x] Add probability config for `split`.
- [x] Add probability config for `fakeprologue`.
- [x] Add per-function annotation parsing for MIR sub-pass selection.
- [x] 🧪 Add config validation tests.

## C2. MIR Safety

- [x] Add liveness regression tests for every MIR sub-pass.
- [x] Add post-RA verifier gate to release mode.
- [x] Add fallback when a machine function is unsafe for MIR transformation.
- [x] Add crash reproducer minimizer for MIR failures.
- [x] 🧪 Add large C++ binary smoke test.

## C3. MIR Decompiler Resistance

- [x] Add more anti-microcode instruction substitutions.
- [x] Add architecture-safe dirty-byte patterns.
- [x] Add function-boundary confusion variants.
- [x] Add fake call/prologue patterns where safe.
- [x] 🧪 Add IDA snapshot comparison.
- [x] 🧪 Add Ghidra headless snapshot comparison.
- [x] 🧪 Add binary-level metric for function boundary fragmentation.

---

# 5. Expansion Track D — Testing, Decompiler Snapshots & Metrics

Goal: make “hard to reverse” measurable instead of based on feeling.

## D1. Decompiler Snapshot Pipeline

- [x] IDA snapshot path exists for later.
- [x] 🧪 Add optional IDA runner detection.
- [x] 🧪 Add optional Ghidra headless runner detection.
- [ ] Dump CFG node/edge count per target function.
- [ ] Dump decompiler pseudocode length per target function.
- [ ] Dump switch-recovery result if available.
- [ ] Dump call-graph recovery result.
- [x] Store snapshots as JSON artifacts.
- [x] Skip gracefully when IDA/Ghidra is not installed.

## D2. Gnarliness Gates

- [x] Node/edge ratio bars exist for Tier B/C/D.
- [x] `.text` entropy is measured but not used as hard bar.
- [x] Add fake-case density bar.
- [x] Add indirect rewrite count bar.
- [x] Add call-graph breakage bar.
- [x] Add string leak bar.
- [x] Add symbol leak bar.
- [x] Add VMP signature-divergence bar.
- [x] Add MIR survival bar.

## D3. Release Dashboard

- [x] Regression dashboard exists.
- [x] Add per-tier dashboard summary.
- [x] Add pass cost summary.
- [x] Add slowest pass summary.
- [x] Add transformed function count summary.
- [x] Add VM compatibility summary.
- [x] Add skipped-function reason summary.
- [x] Add output path for CI artifacts.

---

# 6. Expansion Track E — Developer UX / Profiles / Tooling

Goal: make Taokari easy to use without turning protection into an all-or-nothing chaos button.

## E1. Profiles

- [x] Dev profile exists.
- [x] Balanced profile exists.
- [x] Strong profile exists.
- [x] Fortress profile exists.
- [x] Add `mobile` profile for smaller binaries.
- [ ] Add `debuggable-strong` profile for internal testing.
- [x] Add `vmp-spear` profile for annotation-only virtualization.
- [ ] Add profile inheritance in config.
- [x] Add profile validation.

## E2. Budget System

- [x] Per-pass budget system exists.
- [ ] Add global binary-size growth budget.
- [ ] Add global compile-time budget.
- [ ] Add global runtime overhead target.
- [x] Add per-function VMP budget override.
- [ ] Add warning when profile exceeds budget.
- [ ] Add hard-fail mode when budget exceeds limit.

## E3. Config Generator

- [x] Add `taokari-config-wizard.py`.
- [x] Ask for target platform.
- [x] Ask for protection goal.
- [x] Ask for performance budget.
- [x] Ask whether VMP should be allowed.
- [x] Generate JSON config.
- [x] Generate suggested Clang flags.
- [x] Generate annotation guide.
- [x] Generate expected test command.

## E4. Build Integration

- [ ] Add CMake helper module.
- [ ] Add Ninja example.
- [ ] Add Visual Studio project example.
- [ ] Add `build_strong.bat` docs.
- [ ] Add `build_fortress.bat` docs.
- [ ] Add example with selected `+vmp` function.
- [ ] Add example with `-vmp` wrapper function.

---

# 7. Expansion Track F — Real-World Compatibility Suite

Goal: avoid building a beautiful obfuscator that breaks real programs.

## F1. C / C++ Feature Fixtures

- [ ] Add pointer-heavy C fixture.
- [ ] Add template-heavy C++ fixture.
- [ ] Add exception-heavy C++ fixture.
- [ ] Add virtual dispatch fixture.
- [ ] Add static local initialization fixture.
- [ ] Add thread-local storage fixture.
- [ ] Add atomics fixture.
- [ ] Add SIMD/intrinsics fixture.
- [ ] Add large switch fixture.
- [ ] Add callback/function-pointer fixture.

## F2. Binary Type Fixtures

- [x] EXE startup gate exists.
- [x] DLL LoadLibrary gate exists.
- [x] Manual-map DLL gate exists.
- [ ] Add static library fixture.
- [ ] Add plugin-style DLL fixture.
- [ ] Add exported C API fixture.
- [ ] Add C++ class export fixture.
- [ ] Add mixed C/C++ build fixture.

## F3. Third-Party Library Fixtures

- [ ] Add tiny AES fixture.
- [ ] Add hashing fixture.
- [ ] Add compression fixture.
- [ ] Add JSON parser fixture.
- [ ] Add allocator-heavy fixture.
- [ ] Add math-heavy fixture.
- [ ] Add parser/state-machine fixture.

---

# 8. Suggested Next 15 Development Commits

This is the “do this next without thinking too much” queue.

1. [x] 📚 Document `-taokari-max`, `-taokari-max-no-vmp` and VMP budget behaviour in `docs/CONFIGURATION.md`.
2. [x] Finish MIR config keys per sub-pass.
3. [x] Add per-function VMP overhead budget.
4. [x] Add VMP decompiler snapshot verifier that skips if IDA/Ghidra is unavailable.
5. [x] Add BCF multi-layer bogus graphs.
6. [x] Add BCF dispatcher fake-case integration.
7. [x] Add MBA on flattening dispatch-state updates.
8. [x] Add constant encryption per-function pool.
9. [x] Add encrypted constant pool.
10. [x] Add indirect constant references through helper shards.
11. [x] Add post-link `.text` hash patching prototype.
12. [ ] Add Linux build instructions and smoke test.
13. [x] Add new-PM blocker document.
14. [x] Add config wizard prototype.
15. [x] Add release dashboard summary for Tier A/B/C/D.

---

# 9. Definition of Done for the Next Roadmap Version

- [ ] Every open task belongs to exactly one track.
- [ ] Every track has a clear goal.
- [ ] Every implementation task has a verifier task nearby.
- [ ] Every partial item is either completed or split into smaller checkboxes.
- [ ] Every profile has a compile-time, runtime and size budget.
- [ ] Every tier has a correctness gate and a gnarliness gate.
- [ ] The roadmap stays short enough to fit in one readable GitHub issue or project board.
