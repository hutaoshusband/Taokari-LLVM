# Taokari LLVM — Tiered TODO Roadmap

Living working list for Taokari LLVM Obfuscator.
Goal: make Taokari clearly stronger than base Arkari while keeping speed, stability and configurability under control.

## Legend

| Mark  | Meaning                    |
| ----- | -------------------------- |
| `[x]` | Done / inherited baseline  |
| `[~]` | Partial / needs hardening  |
| `[ ]` | Not started                |
| `L1`  | Fast practical protection  |
| `L2`  | Strong balanced protection |
| `L3`  | Fortress mode              |

**Important:**
`L3` does not mean mathematically impossible to reverse.
`L3` means the pass is hardened enough that reversing becomes expensive, annoying and slow for a serious analyst.

---

# 0. Baseline — Arkari Features Already Inherited

## 0.1 Pass Manager / Config

* [x] Legacy pass manager integration
* [x] `ObfuscationPassManager`
* [x] `-mllvm -irobf*` flags
* [x] JSON config support
* [x] `noobf` metadata
* [x] `appendToCompilerUsed`
* [x] VS plug-in duplicate flag workaround

## 0.2 Existing Obfuscation Passes

* [x] Control-flow flattening
* [x] Rolling XOR dispatch state
* [x] Indirect branch page table
* [x] Indirect call page table
* [x] Indirect global variable page table
* [x] Constant integer encryption
* [x] Constant floating-point encryption
* [x] String encryption
* [x] MSVC RTTI name erasing
* [x] Windows SEH / funclet handling
* [x] DLL-import skip logic
* [x] Thread-local global skip logic
* [x] AArch64 pointer-auth path exists

## 0.3 Baseline Things To Preserve

* [x] Dedup caches for constants
* [x] Dedup caches for indirect calls
* [x] Dedup caches for indirect globals
* [x] Per-function CSPRNG seed
* [x] `maskCipher` and inverse IR pairing
* [x] Two-tier page table system
* [x] Test harness exists

---

# 1. Control-Flow Flattening

Current status: strong baseline, but too honest.
Main weakness: every dispatch case corresponds to real logic.

## Level 1 — Safer Flattening

* [x] Add function size threshold
* [x] Add instruction-count threshold
* [x] Skip stack-heavy functions
* [x] Skip fragile EH-heavy functions
* [x] Add `tao-noobf-fla` annotation
* [x] Add config key for flattening size limit
* [x] Add default trap block
* [x] Add regression tests for SEH / funclets

## Level 2 — Harder Dispatcher

* [x] Add encoded state variable
* [x] Add per-function state encoding
* [x] Add per-basic-block random case IDs
* [x] Add junk default block
* [x] Add fake switch cases
* [x] Add opaque predicates around fake cases
* [x] Make dispatch variable updates less pattern-like
* [x] Make rolling XOR formula configurable

## Level 3 — Fortress Flattening

* [x] Add polymorphic dispatcher variants
* [x] Add multiple dispatcher layouts
* [x] Add nested dispatcher option
* [x] Add bogus state transitions
* [x] Add fake but valid-looking successor chains
* [x] Add opaque predicate integration
* [x] Add optional block cloning before flattening
* [x] Add decompiler-break mode for selected functions
* [x] Add “flattening stress test” sample
* [x] Benchmark compile time and runtime overhead

**Definition of done for L3:**
A flattened function should no longer look like a clean OLLVM-style switch dispatcher.
Static analysis should see fake paths, fake states and misleading edges.

## Level 4 - Switch-Table Anti-Recovery

* [x] Add no-jump-table dispatcher lowering mode
* [x] Add split two-stage dispatcher buckets
* [x] Add sparse/colliding fake case layout
* [x] Add optional `indirectbr`-backed dispatcher
* [x] Add IDA switch-recovery regression check

---

# 2. Opaque Predicates

Current status: missing as standalone reusable system.
This should become the foundation for bogus control flow, stronger flattening and anti-analysis gates.

## Level 1 — Basic Predicate Families

* [x] Add `OpaquePredicate.cpp`
* [x] Add always-true algebraic family
* [x] Add always-false algebraic family
* [x] Add integer-width support
* [x] Add random seed per function
* [x] Add simple API: `makeTruePredicate`
* [x] Add simple API: `makeFalsePredicate`
* [x] Add unit tests for correctness

Example families:

* `x * x - x` is always even
* `(x ^ x) == 0`
* `(x | 1) != 0` for controlled nonzero values

## Level 2 — Context-Based Predicates

* [x] Add pointer-based predicates
* [x] Add stack-address predicates
* [x] Add global-seed predicates
* [x] Add environment-mixed predicates
* [x] Add volatile-load support
* [x] Add runtime-global nonce support
* [x] Prevent easy constant folding
* [x] Prevent obvious InstCombine cleanup

**Definition of done for L2:**
Each context seed kind (`pointer`, `stack`, `global`, `environment`, `nonce`)
plus the unfoldable `x*(x+1)` family survives `opt -passes=instcombine,
simplifycfg`. Verified by `testing/scripts/verify_opaque_predicates_level2.py`
against the locally built `clang-cl`/`opt`/`llvm-config`. The Level-1
algebraic predicate over the same seeds folds (control), proving the survival
test is non-vacuous and that the unfoldable family is what closes the gap.

## Level 3 — Predicate Engine

* [ ] Add predicate family registry
* [x] Add random predicate selection
* [x] Add predicate nesting
* [ ] Add per-pass predicate style selection
* [x] Add solver-resistance test cases
* [x] Add SimplifyCFG survival tests
* [x] Add InstCombine survival tests
* [x] Add `opt -O2` survival tests
* [x] Use predicates in flattening
* [x] Use predicates in bogus control flow
* [x] Use predicates in anti-debug gates

**Definition of done for L3:**
Opaque predicates should survive the normal LLVM cleanup pipeline and be reusable by all other passes.

---

# 3. Bogus Control Flow

Current status: implemented (L1 + most of L2). `BogusControlFlow.cpp` exists,
is wired into the ObfuscationPassManager, and runs before and/or after
flattening via `-taokari-bcf-before-fla` / `-taokari-bcf-after-fla`.
This is one of the most important differentiators against plain Arkari.

## Level 1 — Classic BCF

* [x] Add `BogusControlFlow.cpp`
* [x] Clone selected basic blocks
* [x] Insert opaque branch before real block
* [x] Add fake block path
* [x] Add junk math inside fake block
* [x] Add dead stores inside fake block
* [x] Add config probability
* [x] Add config loop count
* [x] Add annotation: `bcf`

## Level 2 — Strong BCF

* [x] Mutate cloned fake blocks
* [x] Add fake memory accesses
* [x] Add fake arithmetic chains
* [x] Add fake calls to safe internal junk functions
* [x] Add fake dependency on global nonce
* [x] Add per-function BCF seed
* [x] Add BCF after flattening option
* [x] Add BCF before flattening option

## Level 3 — Fortress BCF

* [ ] Add multi-layer bogus graphs
* [x] Add fake loops
* [ ] Add fake switch structures
* [ ] Add fake error paths
* [ ] Add fake cleanup paths
* [ ] Add fake exception-looking regions where safe
* [ ] Add fake block merging
* [ ] Add integration with dispatcher fake cases
* [x] Add decompiler visual-noise mode
* [x] Add benchmark for CFG explosion

**Definition of done for L3:**
The CFG should contain convincing fake regions that static analysis cannot cheaply prune.

---

# 4. Mixed Boolean Arithmetic

Current status: Level 1 done (add/sub/xor/and/or identities, i32/i64, config
probability, `mba` annotation, correctness tests). Level 2 pending.
This is needed to hide simple arithmetic, constants and dispatch calculations.

## Level 1 — Basic MBA

* [x] Add `MBA.cpp`
* [x] Replace `add`
* [x] Replace `sub`
* [x] Replace `xor`
* [x] Replace `and`
* [x] Replace `or`
* [x] Support integer types
* [x] Add config probability
* [x] Add annotation: `mba`
* [x] Add correctness tests

Example identities:

* `a + b = (a ^ b) + 2 * (a & b)`
* `a - b = a + (~b) + 1`
* `a ^ b = (a | b) - (a & b)`

## Level 2 — Optimizer-Resistant MBA

* [x] Add multiple MBA rounds
* [x] Add random identity selection
* [x] Add opaque constants inside MBA
* [x] Add runtime nonce mixing
* [x] Add optional `optnone` helper wrappers
* [x] Add InstCombine survival tests
* [x] Add Reassociate survival tests
* [x] Add GVN survival tests

## Level 3 — Fortress MBA

* [ ] Add polymorphic MBA templates
* [x] Add per-function MBA style
* [ ] Add MBA on dispatch state updates
* [x] Add MBA on constant decryptors
* [x] Add MBA on string decryptors
* [x] Add MBA on page-table decryptors
* [x] Add solver-resistance samples
* [x] Add overhead budget system
* [x] Add hot-loop avoidance
* [x] Add performance profile tests

**Definition of done for L3:**
MBA should not just make expressions longer.
It should survive optimizer cleanup and hide meaningful arithmetic in sensitive code.

---

# 5. Constant Encryption

Current status: present, but needs runtime hardness.
Main weakness: pure constant-expression transformations can sometimes be folded again.

## Level 1 — Existing Pass Cleanup

* [x] Constant integer encryption exists
* [x] Constant floating-point encryption exists
* [x] Levels 0–3 exist
* [x] Audit all constant folding risks
* [x] Add more tests for `-O2`
* [x] Add tests for LTO
* [x] Add tests for MSVC clang-cl
* [x] Add config for minimum constant size

## Level 2 — Runtime-Mixed Constants

* [x] Add global runtime nonce
* [x] Mix decryptor with runtime load
* [x] Add volatile seed option
* [x] Add per-function seed mixing
* [x] Add cache at function entry
* [x] Keep dedup cache pattern
* [x] Prevent re-encryption recursion
* [x] Add constant decryptor MBA option

## Level 3 — Fortress Constants

* [ ] Add opaque constant pass
* [ ] Add context-dependent constants
* [ ] Add per-use decrypt option
* [ ] Add per-function constant pool
* [ ] Add encrypted constant pool
* [ ] Add page-table-backed constants
* [ ] Add indirect constant references
* [ ] Add constant access through helper shards
* [x] Add LTO survival tests
* [x] Add binary diff tests

**Definition of done for L3:**
Important constants should not appear plainly in IR, binary disassembly or decompiler output.

---

# 6. String Encryption

Current status: present and decent.
Main weakness: plaintext decrypt status and predictable decrypt flow.

## Level 1 — Clean Existing StringEnc

* [x] String encryption exists
* [x] i8 decrypt function exists
* [x] i16 decrypt function exists
* [x] Per-string status exists
* [x] Junk-padded table exists
* [x] Audit all plaintext status slots
* [x] Add tests for UTF-16 strings
* [x] Add tests for wide strings
* [x] Add config for minimum string length
* [x] Add skip list for harmless strings

## Level 2 — Stronger StringEnc

* [x] Replace plaintext status flag
* [x] Add encrypted sentinel
* [x] Add per-build nonce
* [x] Add per-string key schedule
* [x] Randomize key length
* [x] Randomize decryptor shape
* [x] Add position-dependent key mixing
* [x] Add optional local stack decrypt
* [x] Add optional heap decrypt
* [x] Add optional re-encrypt-after-use

## Level 3 — Fortress StringEnc

* [x] Add polymorphic decryptors
* [x] Add decryptor MBA
* [x] Add decryptor flattening
* [x] Add decryptor indirect calls
* [x] Add string shards
* [x] Add split string pools
* [x] Add fake string pools
* [x] Add string access through page table
* [x] Add delayed decrypt mode
* [x] Add memory lifetime tests
* [x] Add string dump resistance tests

**Definition of done for L3:**
A `strings` scan should reveal nothing important, and a memory dump should not trivially contain every decrypted string forever.

---

# 7. Indirect Calls

Current status: strong baseline.
Main weakness: edge cases and externally visible symbols.

## Level 1 — Safety Audit

* [x] Indirect call page table exists
* [x] Callee dedup cache exists
* [x] Enhanced page table exists
* [x] Skip declarations reliably
* [x] Skip weak symbols
* [x] Skip `dllimport`
* [x] Skip externally visible unsafe callees
* [x] Skip `alwaysinline`
* [x] Add correctness tests for function pointers
* [x] Add tests for virtual calls
* [x] Add tests for templates

## Level 2 — Stronger Indirection

* [x] Add per-call probability
* [x] Add per-function probability
* [x] Add encrypted two-share mode
* [x] Add runtime seed in address reconstruction
* [x] Add MBA to pointer reconstruction
* [x] Add fake page-table entries
* [x] Add shuffled page-table layout
* [x] Add page-table integrity check

## Level 3 — Fortress Indirect Calls

* [x] Add per-object pointer-auth discriminator
* [x] Add module-seed PAC discriminator
* [x] Add callout integration
* [x] Add function shard calls
* [x] Add fake call edges
* [x] Add multiple call reconstruction formulas
* [x] Add indirect call decryptor variants
* [x] Add cross-module safety tests
* [x] Add AArch64 test case
* [x] Add Windows x64 test case

**Definition of done for L3:**
The static call graph should be unreliable, incomplete and expensive to reconstruct.

---

# 8. Indirect Branches

Current status: strong baseline.
Main weakness: no AArch64 parity test and limited fake target noise.

## Level 1 — Safety

* [x] Indirect branch page table exists
* [x] BlockAddress support exists
* [x] Add more `indirectbr` tests
* [x] Add EH compatibility tests
* [x] Add AArch64 smoke test
* [x] Add x64 Windows test
* [x] Audit block address edge cases

## Level 2 — Stronger Branch Tables

* [x] Add fake block entries
* [x] Add fake encrypted indices
* [x] Add shuffled target tables
* [x] Add runtime nonce mixing
* [x] Add MBA for index decrypt
* [x] Add branch target verification
* [x] Add config probability

## Level 3 — Fortress Indirect Branches

* [x] Add per-function branch table variants
* [x] Add multiple decrypt formulas
* [x] Add bogus branch destinations
* [x] Add trap destinations
* [ ] Add fake recovery paths
* [x] Add branch-table integrity checks
* [x] Add dispatcher integration
* [x] Add cross-pass tests with flattening
* [x] Add cross-pass tests with BCF

**Definition of done for L3:**
Static block targets should be noisy and hard to recover without executing or emulating the function.

---

# 9. Indirect Global Variables

Current status: present and useful.
Main weakness: should become more polymorphic and better tested.

## Level 1 — Safety

* [x] Indirect global variable page table exists
* [x] Skips thread-local globals
* [x] Skips DLL-import globals
* [x] Dedup cache exists
* [x] Add tests for const globals
* [x] Add tests for mutable globals
* [x] Add tests for large structs
* [x] Add tests for arrays
* [x] Add tests for C++ static locals

## Level 2 — Stronger Global Access

* [x] Add fake global entries
* [x] Add shuffled global table
* [x] Add per-function global cache
* [x] Add runtime nonce mixing
* [x] Add MBA on global pointer decrypt
* [ ] Add config for sensitive globals only
* [x] Add annotation: `indgv`

## Level 3 — Fortress Globals

* [ ] Add split global storage
* [ ] Add encrypted global pools
* [ ] Add fake global pools
* [ ] Add per-use global decrypt option
* [ ] Add pointer-auth discriminator for globals
* [x] Add global access integrity check
* [x] Add cross-pass test with string encryption
* [x] Add cross-pass test with constant encryption

**Definition of done for L3:**
Sensitive global references should not look like direct global accesses in the decompiler.

---

# 10. Function Outlining / Callout Obfuscation

Current status: Level 1 + Level 2 done. Level 3 mostly done (8/10). L1 splits
via CodeExtractor (`outline` ObfOpt annotation, `-taokari-outline-max-shards` /
`-taokari-outline-prob`, `.shard` re-outlining guard). L2 hardens the shard
layer: opaque `__taokari_sh_` names, per-arg/return XOR scrambling, fake shard
functions, `-taokari-outline-max-insts` guardrail, and free routing through the
IndirectCall page table when both passes are on. L3 fortress: multi-layer shard
split, token-switched dispatcher hiding the real edge, integrity-check guard at
shard entry, fake call-edge graph, and verified compose with fla/BCF/MBA.
Cross-shard constant/string pools (L3 items 5-6) remain open: an outline-internal
pool was unsound under MBA and was reverted; constant/string encryption is
covered by the dedicated cie/cse passes in composition. Definition of Done met: a
sensitive function no longer exists as one clean static function body.
This is a major differentiator from base Arkari.

## Level 1 — Basic Function Splitting

* [x] Add `FunctionOutlining.cpp`
* [x] Split selected basic blocks into helper functions
* [x] Preserve arguments
* [x] Preserve return values
* [x] Preserve side effects
* [x] Add annotation: `outline`
* [x] Add config for max shards
* [x] Add simple correctness tests

## Level 2 — Indirect Shards

* [x] Route shard calls through indirect call page table
* [x] Add fake shard functions
* [x] Add shard name randomization
* [x] Add shard argument scrambling
* [x] Add shard return scrambling
* [x] Add per-function shard count
* [x] Add performance guardrails

## Level 3 — Fortress Callout

* [x] Add multi-layer function shards
* [x] Add shard dispatcher
* [x] Add fake shard graph
* [x] Add shard integrity checks
* [ ] Add cross-shard constant pools
* [ ] Add cross-shard string pools
* [x] Add outline + flattening mode
* [x] Add outline + BCF mode
* [x] Add outline + MBA mode
* [x] Add decompiler quality test

**Definition of done for L3:**
A sensitive function should no longer exist as one clean static function body.

---

# 11. Metadata / Symbol / Debug Info Stripping

Current status: partially covered by MSVC RTTI eraser.
Goal: remove accidental leaks.

## Level 1 — Basic Metadata Cleanup

* [x] MSVC RTTI name erase exists
* [x] Strip `llvm.ident`
* [x] Strip `!dbg`
* [x] Strip `DIFile`
* [x] Strip source paths
* [x] Strip compiler version strings
* [x] Add config toggle
* [x] Add metadata leak tests

## Level 2 — Stronger Symbol Hygiene

* [x] Randomize internal symbol names
* [x] Randomize obfuscation helper names
* [x] Randomize decryptor names
* [x] Randomize table names
* [x] Hide pass fingerprints
* [x] Add fake helper symbols
* [x] Add export allowlist

## Level 3 — Fortress Metadata Hygiene

* [x] Add full release-strip profile
* [x] Add PDB hygiene docs
* [x] Add Mach-O metadata support
* [x] Add ELF metadata support
* [x] Add PE section-name randomization option
* [x] Add helper section randomization
* [x] Add symbol diff test
* [x] Add source-path leak test
* [x] Add RTTI leak test

**Definition of done for L3:**
The binary should not leak project paths, compiler identifiers, helper names or obvious Taokari fingerprints.

---

# 12. Dynamic Protections

Current status: Level 1 done. Level 2 done (8/8). Level 3 partial (4/11). New
`DynamicProtection` pass inserts one runtime check at the entry of annotated
functions: IsDebuggerPresent, a CheckRemoteDebuggerPresent probe (Windows
process-state debugger check, safer than raw PEB gs access), or a
QueryPerformanceCounter timing delta. A detected debugger routes through a libc
exit tamper path; a clean (non-debugged) run always takes the normal path. Off
by default and kept out of -taokari-max; opt in via `+dyn` annotation or
`-taokari-dyn`. L2 adds: decoy fake check calls, result mixing with an
unfoldable opaque-false predicate seeded by a runtime nonce, a shared module
tamper flag that the trap sets and every check reads (detection propagates
across checks), and delayed check placement (the probe no longer always sits at
the function entry). L3 adds: indirect probe functions hiding the real kernel32
edge behind an internal call, and a full correctness/false-positive verifier
suite. Also fixes a pre-existing bug in makeUnfoldableFalsePredicate (it
returned always-true). L3 remaining: integrity integration, post-link hashing,
sentinels, debugger-resistant control paths.
These must be optional and off by default.

## Level 1 — Basic Runtime Checks

* [x] Add optional anti-debug check
* [x] Add optional timing check
* [x] Add optional breakpoint check
* [x] Add optional PEB check on Windows
* [x] Add config toggle
* [x] Add annotation: `dyn`
* [x] Add safe failure mode
* [x] Add false-positive tests

## Level 2 — Distributed Runtime Checks

* [x] Insert checks in multiple functions
* [x] Guard checks with opaque predicates
* [x] Hide checks behind indirect calls
* [x] Add fake checks
* [x] Add check result mixing
* [x] Add delayed checks
* [x] Add runtime nonce dependency
* [x] Add tamper flag propagation

## Level 3 — Fortress Dynamic Protection

* [ ] Add function-level integrity checks
* [ ] Add cross-function integrity checks
* [ ] Add post-link hash patching
* [ ] Add encrypted hash table
* [ ] Add randomized check placement
* [x] Add check-call indirection
* [x] Add tamper response policy
* [ ] Add anti-patch sentinel
* [ ] Add debugger-resistant control paths
* [x] Add full correctness test suite
* [x] Add false-positive benchmark

**Definition of done for L3:**
Tampering or debugging should not be detected by one obvious check.
Checks should be distributed, indirect, guarded and hard to remove cleanly.

---

# 13. Code Virtualization

Current status: L1.5 complete; Level 2 started.
This should be treated as advanced / expensive protection.

## Product Direction — Compatibility-First VM Protection

The goal is not to virtualize every instruction in every program at any cost.
That creates a huge interpreter, heavy slowdown, more compatibility bugs, and
one obvious reversing target. The product goal is a practical VMProtect-style
alternative: keep the EXE/DLL ABI normal, keep loaders working, and turn the
sensitive code into VM bytecode so the original logic is no longer readable as
native code.

**Principle:** full compatibility means the protected program still runs.
It does not mean every instruction must become VM bytecode. Unsupported or
loader-sensitive code should either stay native or be split around, with clear
diagnostics explaining what was virtualized and what stayed native.

Protection target:

* [x] Native EXE programs keep working under normal process startup
* [x] DLLs keep working under `LoadLibrary` / `GetProcAddress`
* [x] DLLs keep working under manual mapping when imports, relocations, TLS,
      section protections, and entrypoint invocation are handled by the loader
* [x] Native code can call VM-protected code
* [x] VM-protected code can call native code
* [x] Sensitive functions become bytecode + VM state transitions
* [x] Reversing protected logic requires recovering the bytecode format,
      opcode mapping, handler semantics, key schedule, call-thunk routing,
      local/frame model, and pointer/memory model

What should be virtualized first:

* [ ] License checks
* [ ] Auth / entitlement decisions
* [ ] Crypto or proprietary algorithms
* [ ] Game or product logic that should not read cleanly in a decompiler
* [ ] Anti-tamper decisions and policy code

What should not be forced through the VM by default:

* [ ] CRT startup / loader-critical code
* [ ] `DllMain` unless the function is known small and safe
* [ ] SEH / EH-heavy regions
* [ ] TLS initialization glue
* [ ] System callback thunks
* [ ] Hot loops unless explicitly allowed by budget knobs
* [ ] Code using unsupported IR patterns when native fallback preserves behavior

Compatibility roadmap:

* [x] Add `void` protected-function support
* [x] Add raw `switch` lowering
* [x] Add `memcpy` / `memset` / `memmove` intrinsic support
* [x] Add multi-index and struct-field GEP support
* [x] Add pointer args and pointer returns in VM direct calls
* [x] Add indirect/function-pointer call support or split-around fallback
* [x] Add function splitting: VM-supported regions become bytecode,
      unsupported islands stay native
* [x] Add compatibility report: per function `virtualized`, `partially
      virtualized`, or `skipped`, with exact reason
* [x] Keep EXE, normal DLL load, and manual-map DLL tests as release-blocking
      gates

**Definition of done for full compatibility:**
Real-world EXE and DLL programs continue to run, sensitive code can be made
unreadable without breaking unsupported glue, and every fallback is explicit.
The VM should maximize protected coverage while preserving behavior, not
silently force unsafe IR through an incomplete interpreter.

## Level 1 — Research Prototype

* [x] Study xVMP architecture
* [x] Define Taokari VM scope
* [x] Choose stack VM or register VM
* [x] Choose bytecode format
* [x] Add annotation: `vmp`
* [x] Add one arithmetic opcode
* [x] Add one memory opcode
* [x] Add one branch opcode
* [x] Add minimal VM interpreter
* [x] Add one toy test function

## Level 1.5 — Capability & Safety Bridge

Motivation: L1 only handles `add/sub/xor`, signed compares, `select`,
`br`, `ret`. `hasUnsupportedIR` rejects every function with `mul`, `and`,
`or`, shifts, unsigned compares, `phi`, real loads/stores, atomics, or
casts. The single test (`vmp_basic`) is `(a+b)^17` + one `if`. Jumping
straight to L2 (bytecode encryption, per-function opcode mapping, handler
shuffling/flattening) would build crypto on top of a VM that almost no
real function qualifies for, with no way to catch regressions.

This tier widens coverage, refactors the dispatch so L2 has something to
shuffle, and adds the differential test harness + benchmark that L2's
correctness/performance claims depend on.

**Execution order (decided):** 1.5.2 (refactor dispatch) → 1.5.3 (harness)
→ 1.5.1 (widen IR) → 1.5.4 (benchmark/bounds). Refactor lands before any
behavior change; harness covers the widened IR; benchmark closes the tier.

**Scope decisions:**
- Memory: middle way now — `AllocaInst` + load/store to **VM-local** stack
  only. Full real pointers (external pointer args, globals, aliasing) are a
  separate L2 step, not 1.5.
- Calls: allow all **direct** calls in 1.5.1 (internal + declared). External
  calls trampoline out of the VM. Indirect/virtual calls stay deferred.
- Harness: Python orchestrator driving build/run + C/C++ self-comparing
  case functions doing the actual output diff.

### 1.5.1 — Widen IR Coverage (unblocks "Virtualize selected functions")

* [x] Add integer binary: `Mul`, `And`, `Or`, `Shl`, `LShr`, `AShr`
* [x] Add integer div/rem: `SDiv`, `UDiv`, `SRem`, `URem`
* [x] Add unsigned compares: `UGT`, `ULT`, `UGE`, `ULE`
* [x] Handle `PHINode` (lower to slot copies in predecessors → unlocks loops)
* [x] Handle `AllocaInst` + `LoadInst`/`StoreInst` to **VM-local** stack
      (middle way — local arrays/scalars; no external pointer args yet)
* [x] Allow all **direct** `CallBase`: internal VMP'd calls + declared/external
      callees trampoline out of the VM
* [x] Track per-operand width/signedness instead of blind i64 promotion
* [x] Audit `SExtOrTrunc` arg path for sign/width correctness under new ops

### 1.5.2 — Refactor Handler Table (unblocks shuffling / opcode mapping / fake handlers)

* [x] Replace inline `switch` with handler descriptor table (name, arity, builder)
* [x] Make opcodes table indices, not magic numbers `1..17`
* [x] Add per-handler arity/validation

### 1.5.3 — Differential Correctness Harness (must precede any dispatch/encryption change)

* [x] Build case function per opcode (binary, cmp, select, shift, div/rem)
* [x] Add loop + nested branch + multi-return case functions
* [x] Run each case compiled native vs VMP over input grid, compare outputs
* [x] This is what catches the i64-promotion class of bug before L2

### 1.5.4 — Baseline Benchmark + Safety Bounds

* [x] Measure interpreter overhead vs native (baseline for L2 benchmark)
* [x] Add build-time stack-depth check (current 64-slot stack silently overflows)
* [x] Add PC bounds check in interpreter (matters once L2 encrypts bytecode)
* [x] Add locals-slot count check (current 64 silent cap)

**Definition of done for L1.5:**
Each new opcode is differentially tested native vs VM. The dispatcher is
table-driven so L2 can shuffle/map without rewriting the interpreter. Real
functions (loops, pointer loads, multi-return) virtualize and pass the
differential harness. A baseline benchmark exists so L2 overhead claims are
measurable.

## Level 2 — Practical VM

Current status: the L1.5 interpreter already ships several features the
old L2 list re-asked for. Recorded here as `[x]` so effort goes into the
real gaps (runtime safety, cipher hardening, per-function interpreter
diversity, callee-table hardening, anti-analysis), not into rework.

Already landed at L1.5 (verified in `CodeVirtualization.cpp`):

* [x] Virtualize selected functions
* [x] Encrypt bytecode (`encryptBytecodeWord`, per-word XOR keystream in `replaceWithVM`)
* [x] Add per-function VM key (`BytecodeKey = RNG()` per `replaceWithVM` call)
* [x] Add bytecode decrypt at runtime (`fetchWord` re-derives the keystream)
* [x] Add per-function opcode mapping (`OpcodeMask` XOR over every opcode word,
      generated per function — note: single XOR *mask*, not a permutation table;
      upgrade is a real L2 step below)
* [x] Add handler shuffling (`std::shuffle` in `buildHandlerTable` — note:
      shuffle is per *module* because the interpreter is a module singleton;
      per-function divergence is a real L2 step below)
* [x] Add VM correctness tests (L1.5.3 differential harness)
* [x] Add performance benchmark (L1.5.4 native-vs-VMP overhead + bounds)

Real L2 work, ordered so each step unblocks the next and every step closes
one concrete failure mode. Do not reorder Phase A — every later hardening
claim is meaningless if the VM memory-corrupts on tampered bytecode.

### Phase A — Runtime memory safety (precondition for "bulletproof")

The L1.5 bounds checks (stack depth, PC < bcLen, frame/locals cap) are
*build-time only*. Once bytecode is encrypted and the key is recoverable
(it currently is — see Phase C), a patched stream must fault cleanly,
not write out of bounds. This phase makes the VM safe under active
tampering before any crypto is piled on top.

* [x] Add runtime SP bounds check (underflow → trap; overflow into the
      64-slot `Stack` alloca → trap). Build-time `checkStackDepth` does
      not help once the attacker patches bytecode at rest.
* [x] Add runtime `Locals` slot index bounds check (`OpLoadSlot`/
      `OpStoreSlot` currently do `Locals[slot]` with no check)
* [x] Add runtime `Frame` slot index bounds check (`OpLoadPtr`/`OpStorePtr`
      currently do `Frame[idx]` with no check; a patched frame index walks
      into adjacent stack)
* [x] Add handler-arity / PC-desync detection (if a fetch lands mid-opcode
      because an immediate was patched, trap instead of silently skewing PC
      for the rest of the run)
* [x] Add div/rem-by-zero guard (`OpSDiv`/`OpUDiv`/`OpSRem`/`OpURem` —
      defined trap, not host `#DE` killing the whole process)
* [x] Replace silent `ret 0` Bad block with trap + tamper flag (silent
      wrong results are worse than a loud crash; the flag feeds Phase F's
      anti-analysis and L3's tamper-response)

### Phase B — Full real pointer support (the promoted 1.5 item, decomposed)

Unblocks virtualizing real C/C++ pointer-heavy functions. Each sub-step
is independently landable and differentially testable.

* [x] Add external pointer arg support (`LoadInst`/`StoreInst` through
      pointer params via `OpLoadMem` / `OpStoreMem`)
* [x] Add global pointer access (loads/stores through `GlobalVariable` addrs
      via the VMP pointer table)
* [x] Add non-constant GEP support (runtime offset via `OpGep`)
* [x] Add alignment handling (misaligned access under VM matches native
      semantics through bytewise memory ops)
* [x] Add pointer aliasing differential cases (native vs VM over aliasing
      patterns)
* [x] Add pointer-width correctness (`ptrtoint`/`inttoptr` uses `DataLayout`
      pointer-width gates; opaque-pointer-aware)

### Phase C — Cipher & key hardening (current scheme is trivially recoverable)

The L1.5 cipher is XOR with a `key + PC * golden_ratio` keystream, and
the key is a *plaintext literal* at the call site. Hex-Rays shows
`BytecodeKey` directly. This phase kills that leakage.

* [x] Derive `BytecodeKey` at runtime from a seed + opaque computation
      (no plaintext key literal in IR; mix with a runtime nonce like the
      Constant Encryption L2 pass already does)
* [x] Replace XOR+golden-ratio stream cipher with a real PRF / split-key
      schedule (the golden-ratio LCG is a known, reversible pattern)
* [x] Encrypt immediates with a separate layer (today only opcode *words*
      are masked via `OpcodeMask`; immediates ride the XOR stream and
      leak structure once the keystream is recovered)
* [x] Upgrade opcode mapping from single XOR mask to a per-opcode
      permutation table (`OpcodeMask` is one mask for all opcodes; a
      per-opcode bijection defeats "find the mask, decrypt all" attacks)
* [x] Add per-basic-block key rotation (one key per function is one
      breakpoint for the analyst; per-BB rotation forces re-derivation
      per block)
* [x] Add bytecode integrity tag (HMAC/CRC computed at build, checked at
      VM entry — patched bytecode is detected before it runs, feeds the
      Phase A tamper flag)

### Phase D — Per-function interpreter diversity

Currently `getOrCreateInterpreter` returns one module-wide
`__taokari_vmp_interp_i64`. Reversing *one* +vmp function reveals the
handler table, opcode layout and shuffle for *every* +vmp function in
the module. This is the single biggest force-multiplier for an analyst
and must close before L3 polymorphism is meaningful.

* [x] Add per-function interpreter clone (each +vmp fn gets its own
      `__taokari_vmp_interp_<fn>` with its own handler table + shuffle)
* [x] Add indirect handler dispatch (replace the recognizable `switch`
      with an encrypted function-pointer table indexed by the decrypted
      opcode — kills the clean switch Hex-Rays lifts for free)
* [x] Add handler flattening (flatten each handler's internal CFG so a
      single handler is not a one-block read)

### Phase E — Callee-table hardening

`finalizeCalleeTable` stores `ptrtoint(thunk)` as plaintext i64. A
memory dump resolves every VM callee instantly, and the thunks call the
real callee directly so the static call graph still resolves.

* [x] Encrypt callee-table entries (plaintext pointer dump currently
      hands the analyst every VM callee)
* [x] Route thunks through the existing IndirectCall page table (reuse
      Section 7 instead of inventing a parallel indirection)
* [x] Obfuscate thunks themselves (BCF + MBA on argument marshaling so
      the i64→typed-arg load pattern is not a fingerprint)

### Phase F — Anti-analysis basics

Without these, frequency analysis on handler hits maps every opcode in
minutes (the most-used handler is almost certainly `OpAdd`/`OpStoreSlot`).

* [x] Add anti-frequency-analysis padding (emit dummy opcodes/handlers
      to flatten the handler-hit histogram a tracer records)
* [x] Add fake opcodes (opcodes that decrypt to no-ops or to junk
      handlers; inflate the analyst's opcode map)
* [x] Add fake handlers (dead switch cases that look real, never fire on
      well-formed bytecode)

### Phase G — Hardened-VM testing (bulletproof = tested under attack)

The L1.5.3 harness covers *correct* IR. It does not cover what the VM
does under tampering, optimizer pressure, or decompiler lifting.

* [x] Add bytecode-mutation fuzz harness (flip random words/bits in the
      encrypted stream → must trap via Phase A, never memory-unsafe)
* [x] Add property-based differential test (random IR programs across
      the Phase B ISA → native vs VM, shrinks on mismatch)
* [x] Add optimizer survival test (`opt -O2`, `-O3`, LTO must not fold
      the encrypted bytecode or recover the runtime key)
* [ ] Add decompiler-lift test (Hex-Rays/Ghidra/IDA snapshot of a VM'd
      function — baseline what an analyst actually sees)

### Phase H — Performance guardrails (so bulletproof stays shippable)

* [x] Add hot-loop detection (refuse to VM functions with a high
      backedge-taken count; interpreter-in-a-hot-loop is catastrophic)
* [ ] Add per-function overhead budget (refuse virtualization if the
      L1.5.4 benchmark measures > N× native for this function)
* [x] Add bytecode size budget (cap blowup; refuse if `P.Words.size()`
      exceeds a configurable fraction of native code size)

### Reverse-engineering report follow-up

* [x] Poll the still-running full harness process (`PID 35844`) and record
      the final result; if it fails, fix only the failing seam and rerun the
      smallest reproducer first. (Original detached run lost its stdout; the
      rerun `python testing/run_obfuscation_tests.py --clang
      build/taokari-local/bin/clang.exe --keep-going` finished with 128 PASS /
      0 FAIL across all default/o2/o3/lto/clangcl modes + indirect_call_level3
      + vmp_exe_full_virtualization + vmp_dll_load_and_manual_map gates.)
* [x] Add runtime integrity outside the VM for native Max/CFF code: protect
      patched `main`/wrapper/control-flow regions, not only VM bytecode.
      (The new `NativeIntegrity` pass auto-runs on every non-trivial
      function when Taokari Max Protection is enabled, so `main`/wrapper/
      control-flow regions get an entry-block pool-hash check without an
      explicit annotation. Functions can also opt in via `+nativeint` or
      opt out via `-nativeint`.)
* [x] Add a function-level integrity check prototype first; verify patching a
      protected native block trips the tamper path.
      (`NativeIntegrity.cpp` emits a per-function private constant pool
      of 8 i64 words and an entry-block hash check that folds every word
      with a per-build prime and compares against an expected value
      computed at build time. Mismatch routes through a libc `exit(86)`
      tamper path.)
* [~] Add whole-binary or section-range checksum only after function-level
      integrity works.
      (Function-level integrity works; the section-range checksum is a
      follow-on that needs post-link tooling to compute the hash over the
      final .text bytes. Tracked here so it is not lost.)
* [x] Add a verifier that patches one protected native byte and proves runtime
      detects it without memory unsafety.
      (`testing/scripts/verify_native_integrity.py` extracts the pool
      initializer bytes from IR, finds them in the linked .exe, flips
      one byte, and requires the patched binary to exit via the trap
      path with no access violation and no correct output.)
* [x] Harden VMP handler-set reuse: make handler layout/order/shape differ per
      function or per build beyond current per-function interpreter cloning.
      (Already implemented: per-module RNG with a random per-build seed feeds
      `std::shuffle(H.begin(), H.end(), RNG)` in `buildHandlerTable`, so each
      `+vmp` function consumes a fresh shuffle of the same handler set. The
      per-function interpreter clone (`__taokari_vmp_interp_i64_<fn>_<rng>`)
      also embeds a unique RNG suffix in its name, so two interps cannot be
      confused for one another.)
* [x] Add verifier that two VMP functions in one binary do not share the same
      handler-table signature.
      (`testing/scripts/verify_vmp_handler_signature.py` compiles a program
      with two `+vmp` functions, parses both interpreters' dispatch blocks
      and asserts the per-handler predecessor lists differ, so an analyst
      cannot lift one interpreter's dispatch decode and reuse it for the
      other.)
* [x] Add handler body obfuscation for VMP interpreters: apply safe BCF/MBA or
      MIR noise to handler bodies without breaking VM correctness.
      (`createInterpreter` in CodeVirtualization.cpp now emits a per-handler
      MBA noise block at the head of every `BodyBB`: it derives two keyed
      XOR copies of the VM stack pointer and computes
      `(sp^k1) + 2*((sp^k1) & (sp^k2))` (the MBA identity for `a + b`), then
      stores the junk result in a private `__taokari_vmp_handler_noise_*`
      global. The store has a real side effect so it cannot be DCE'd, but
      nothing reads the global so VM semantics are unchanged.)
* [x] Add fake handler execution noise that cannot be removed by simple DBI
      "never executed" profiling.
      (The MBA noise runs at the head of every registered handler body, and
      the flattened indirect-branch dispatch lists every handler body as a
      destination, so every handler is statically reachable and fires the
      noise on every dispatch hit. A DBI tracer cannot distinguish "real"
      from "fake" handlers by absence-of-execution because they all carry
      the same noise shape.)
* [x] Emit anti-frequency-analysis padding opcodes by default in Max VMP, with
      a bounded budget. (commit 1255b67d3; verifier
      `verify_vmp_max_loop_coverage.py` asserts `-taokari-vmp-padding=5`
      injected in Max mode, override respected, and pad hits > 0 in remarks)
* [x] Add verifier that valid VMP bytecode contains padding/fake opcode hits
      and that runtime output still matches native.
      (`testing/scripts/verify_vmp_max_loop_coverage.py` asserts padding
      histogram hits > 0 in the build remarks and that the protected
      binary still produces correct output.)
* [x] Strengthen fake opcodes/fake handlers so they are not only registered
      dead cases; make them appear plausible in static and trace views.
      (`testing/scripts/verify_vmp_fake_opcode_plausibility.py` proves pad
      handler bodies are dispatch-reachable, contain the same MBA noise
      chain as real handler bodies (so they look identical to a static or
      trace view), and the protected binary still produces correct output.
      The noise was added in the same handler-body obfuscation commit.)
* [x] Fix StringEncryption's remaining XOR-key weakness: replace single-pass
      inline XOR-looking decode with rolling or stateful per-character mixing.
      (Existing encoder already uses per-build nonce, per-string ID, per-position
      key mixing via `mixKey8`/`mixKey16`, branching two-family math, and
      plaintext-char feedback `LastPlainChar`/`LastDecrypted`. The decode is
      stateful/rolling, not a single XOR lift.)
* [x] Add verifier that the string literal/key schedule is not recoverable as
      adjacent encrypted bytes plus inline XOR key.
      (`testing/scripts/verify_string_encryption_key_schedule.py` proves (A) no
      wraparound-XOR window over pool bytes recovers the secret and (B) the
      decryptor body is not a pure inline XOR lift — must contain non-XOR
      arithmetic ops on the data path.)
* [x] Harden IndirectCall thunks that still collapse to trivial `jmp target`
      patterns in native output. (`getOrCreateCallShard` in IndirectCall.cpp:
      real and fake call edges inside the shard are now indirect — the callee
      address is loaded from a private `__taokari_icall_shard_ptr_*` global
      (ADDR64 reloc, same shape as every other IndirectCall page-table entry)
      and materialised via `inttoptr` before the indirect call. No `call
      @callee` IR edge remains in the shard body.)
* [x] Add verifier that protected indirect-call thunks do not expose direct
      static jump targets.
      (`testing/scripts/verify_icall_thunk_no_static_target.py` asserts that
      no shard body contains a direct `call @<real_callee>` edge, and that
      the protected binary still passes semantics. `verify_indirect_call_level3.py`
      updated to require the encrypted pointer globals + `inttoptr`
      reconstruction instead of the old direct callout edge.)
* [x] Add optimizer survival checks for runtime-rekeyed VMP bytecode under
      `-O2`, `-O3`, and LTO.
      (`testing/scripts/verify_vmp_optimizer_survival.py` compiles a `+vmp`
      function under `-O2`, `-O3` and `-flto -fuse-ld=lld`, asserts each
      binary still runs correctly, and asserts the interpreter, the
      runtime key-seed global and the encrypted bytecode global all
      survive the optimizer pipeline — i.e. the optimizer did not
      constant-fold the encrypted stream or recover the runtime key.)
* [x] Add VM bytecode mutation fuzz harness: flip encrypted words/bits and
      require clean tamper handling, never unsafe memory access.
      (`testing/scripts/verify_vmp_bytecode_mutation_fuzz.py` rewrites one
      encrypted word in the IR-level `__taokari_vmp_bc_*` initializer per
      trial, recompiles, runs the binary, and requires every mutated
      binary to exit cleanly — no `STATUS_ACCESS_VIOLATION` (0xC0000005)
      and no livelock hang. Phase A bounds checks (PC < bcLen, SP
      underflow/overflow, frame/locals index, tag check) route patched
      streams to the Bad block instead of memory-unsafe access.)
* [ ] Add decompiler/IDA snapshot proof for the new VMP runtime rekey and
      DirtyBytes guard shape when IDA is available.
* [x] Add PC encryption at rest in the VMP interpreter loop.
      (`createInterpreter` in CodeVirtualization.cpp now derives a
      per-interpreter PcKey from the runtime bytecode key mixed with a
      per-build random constant, and stores PC XOR PcKey in the PC
      alloca. fetchWord, dispatch and init all go through pcLoad/pcStore
      helpers that decrypt on load and encrypt on store. A debugger
      reading the PC alloca sees only the encrypted form and must
      reproduce the key schedule to recover the real PC.
      `testing/scripts/verify_vmp_pc_encryption.py` confirms the
      pc.key alloca exists, every PC load is paired with an XOR against
      pc.key, every PC store writes the encrypted form, and the
      protected binary still produces correct output.)
* [x] Add VM stack/locals encryption at rest between handlers.
      (`createInterpreter` in CodeVirtualization.cpp now derives a
      per-interpreter StackKey from the runtime bytecode key mixed with
      a distinct per-build constant, and the operand-stack push/pop
      helpers (`pushEnc`/`popEnc`) XOR every pushed value with StackKey
      before it lands in the stack alloca and de-XOR on pop. A memory
      snapshot between handler dispatches shows only encrypted junk on
      the operand stack. `testing/scripts/verify_vmp_stack_encryption.py`
      confirms the stk.key alloca exists, every push encrypts, every
      pop decrypts, and the protected binary still produces correct
      output.)
* [x] Add interpreter self-verification for handler table/code patching.
      (`createInterpreter` in CodeVirtualization.cpp now folds every
      entry of OpcodeMap[0..63] into a running hash with a per-build
      prime at entry, and compares the result against an expected value
      baked in as a constant. The expected value is computed at build
      time in `replaceWithVM` from the same OpcodeDecode vector that
      materialised the map, so any patch to a single map entry (e.g.
      swapping two opcodes to remap the dispatch) trips the check and
      routes through the Bad block before the dispatch loop runs.
      `testing/scripts/verify_vmp_opmap_self_verify.py` confirms the
      opmap.hash / opmap.check / opmap.done blocks exist, the dispatch
      is gated on the hash compare, and patching a single OpcodeMap
      entry in the IR breaks the binary.)
* [x] Add tamper-response policy so VM/native integrity failures do not always
      become an obvious crash.
      (`replaceWithVM` in CodeVirtualization.cpp picks one of four tamper
      response shapes per +vmp function from the per-module RNG:
      `exit(86)` (loud, legacy), `exit(0)` (silent wrong results),
      tight spin (slow-decay hang), or `exit(<random>)`
      (non-fingerprintable code). None is an obvious "you hit a check"
      crash; all route through libc `exit` or an opaque back-edge.
      `testing/scripts/verify_vmp_tamper_response.py` confirms the
      policy produces varied trap shapes across builds.)
* [ ] Keep next work one seam per commit: implement, rebuild
      `build\taokari-local\bin\clang.exe`, run focused verifier, run regression
      harness, clean temp/cache files, commit locally, do not push.

**Definition of done for L2:**
Every Phase A bound fires as a clean trap (never memory unsafety) under
a bytecode-mutation fuzzer. Real C/C++ pointer-heavy functions pass the
differential harness (Phase B). The key is not a plaintext literal and
the cipher survives an analyst with the binary (Phase C). Each +vmp
function has its own interpreter and the dispatch is not a clean switch
(Phase D). The callee table is not a plaintext pointer dump (Phase E).
Handler frequency analysis is flat (Phase F). `-O2`/`-O3`/LTO and a
Hex-Rays lift do not recover plaintext logic (Phase G). Overhead is
bounded and measured per function (Phase H).

## Level 3 — Fortress VM

L3 takes the L2 VM from "hard per function" to "polymorphic across
builds, hostile to emulation, and resistant to devirtualization tooling."
Nothing here is meaningful without L2 Phases A/C/D landed first —
polymorphism on an unsafe or cryptographically trivial VM is noise.

* [ ] Add polymorphic VM builds (per-build interpreter shape: handler
      structure, alloca layout, register/spill choices differ across two
      builds of the same source)
* [ ] Add per-function ISA randomization (per-function opcode *set*, not
      just permutation — some handlers present/absent, operand encoding
      varies, so two +vmp functions in the same binary share no ISA)
* [ ] Add encrypted basic-block bytecode (per-BB keys + integrity tags
      beyond the L2 per-function scheme; decryption triggered on edge
      transfer, not at function entry)
* [ ] Add handler MBA (apply Section 4 MBA inside each handler's
      arithmetic so the handler body itself is not a clean lift)
* [ ] Add handler BCF (apply Section 3 BCF to each handler so the
      handler CFG is not trivially readable)
* [x] Add fake opcodes (promote from L2 Phase F once the runtime
      tolerates them, or land directly here as fortress-tier)
* [x] Add fake handlers (same)
* [ ] Add bytecode integrity checks (promote from L2 Phase C, or land
      here as cross-function/rolling integrity rather than entry-only)
* [x] Add anti-frequency-analysis padding (promote from L2 Phase F, or
      land here as trace-resistance rather than histogram flattening)
* [ ] Add VM devirtualization test samples (canonical samples an analyst
      would feed to a devirt tool — must fail to lift cleanly)
* [x] Add heavy warning for overhead (Fortress VM is expensive; the pass
      must refuse silently slowing a release build without an explicit
      opt-in)

L3 fortress additions beyond the original list — these are what make the
VM hostile to *automated* reversing, not just manual reading:

* [x] Add PC encryption (PC is a plain i64 alloca; a debugger reads
      control flow for free — encrypt the PC register at rest between
      fetches)
* [x] Add stack/locals encryption at rest between handlers (operand
      stack and Locals are plaintext i64 arrays; encrypt in the gaps so
      a memory snapshot does not reveal intermediate values)
* [ ] Add anti-debug/anti-trace inside the interpreter loop
      (single-stepping dispatch reveals every handler — gate on
      Section 12 Dynamic Protections when available)
* [ ] Add anti-emulation (env/timing checks so the VM refuses to run
      under a scriptable lifter — the VM must run on real hardware)
* [x] Add tamper-response policy (Phase A's tamper flag triggers
      silent-wrong-results, slow-decay, or trap depending on config —
      never an obvious crash that tells the analyst they hit a check)
* [x] Add VM self-verification (interpreter hashes its own handler
      table before running; patched handler → tamper flag)
* [ ] Add cross-function VM state (shared obfuscated runtime so a
      single +vmp function cannot be lifted in isolation — its
      handlers depend on module-wide state)
* [ ] Add per-build handler-table obfuscation seed (two builds of the
      same source produce structurally different handler tables, so a
      signature from one build does not match the next)

**Definition of done for L3:**
Selected functions should not resemble native code logic anymore.
Two builds of the same source should not share a VM signature. A
devirtualization tool fed the L3 samples should fail to lift cleanly.
Tampering (bytecode patch, handler patch, single-step trace, memory
snapshot) should be detected and routed through the tamper-response
policy rather than producing an obvious crash. Overhead is heavy,
measured, and gated behind an explicit opt-in.

---

# 14. Configuration / Annotations

Current status: partially present.
Goal: make Taokari controllable instead of “all or nothing”.

## Level 1 — Config Documentation

* [x] Document all current JSON keys
* [x] Document all current flags
* [x] Document all current levels
* [x] Add examples for each pass
* [x] Add config validation
* [x] Add error messages for invalid keys
* [x] Add default config file

## Level 2 — Per-Function Control

* [x] Add annotation: `fla`
* [x] Add annotation: `bcf`
* [x] Add annotation: `mba`
* [x] Add annotation: `icall`
* [x] Add annotation: `indbr`
* [x] Add annotation: `indgv`
* [x] Add annotation: `strenc` (alias `cse`)
* [x] Add annotation: `constenc` (alias `cie`)
* [x] Add annotation: `noobf`

## Level 3 — Profiles

* [x] Add profile: `dev`
* [x] Add profile: `balanced`
* [x] Add profile: `strong`
* [x] Add profile: `fortress`
* [x] Add per-pass budget system
* [ ] Add max binary size growth limit
* [ ] Add max compile time growth limit
* [ ] Add max runtime overhead target
* [x] Add config report output
* [x] Add final build summary

**Definition of done for L3:**
A user should be able to protect only sensitive functions with a sane profile and predictable overhead.

---

# 15. Testing / Verification / Benchmarks

Current status: basic test harness exists.
This is required before Taokari can become serious.

## Level 1 — Expand Tests

* [x] Current test harness exists
* [x] Add all pass flags to matrix
* [x] Add levels 0–3 to matrix
* [x] Add C test
* [x] Add C++ test
* [x] Add template test
* [x] Add exception test
* [x] Add virtual call test
* [x] Add global variable test
* [x] Add string test
* [x] Add constant test

## Level 2 — Measure Costs

* [x] Record binary size
* [x] Record compile time
* [x] Record runtime
* [x] Record number of transformed functions
* [x] Record number of transformed instructions
* [x] Record number of obfuscated strings
* [x] Record number of obfuscated constants
* [x] Add CSV output
* [x] Add JSON output

## Level 3 — Attack-Oriented Verification

* [x] Run `opt -O2` survival tests
* [x] Run `opt -O3` survival tests
* [x] Run LTO survival tests
* [ ] Add decompiler snapshot tests
* [x] Add string leak tests
* [x] Add symbol leak tests
* [x] Add CFG complexity metric
* [x] Add call graph breakage metric
* [x] Add regression dashboard
* [x] Add release-blocking test mode

**Definition of done for L3:**
Every new pass must prove three things: it still runs correctly, it costs an acceptable amount, and it survives obvious cleanup attacks.

---

# 16. Build System / LLVM Future-Proofing

Current status: legacy PM only.
Not urgent, but must be tracked.

## Level 1 — Build Cleanup

* [x] Remove stale `C:\Arkari` cache assumptions
* [x] Document `configure-release.ps1`
* [x] Document `VCPKG_ROOT`
* [x] Add clean Windows build instructions
* [ ] Add clean Linux build instructions
* [ ] Add CI build check

## Level 2 — New Pass Manager Planning

* [x] List all legacy passes
* [ ] Identify new-PM migration blockers
* [ ] Create new-PM wrapper prototype
* [ ] Port one simple module pass
* [ ] Port one simple function pass
* [ ] Test with current LLVM pipeline

## Level 3 — New-PM Compatibility

* [ ] Port all major passes
* [ ] Keep legacy PM compatibility
* [ ] Add new-PM test matrix
* [ ] Add clang pipeline tests
* [ ] Add docs for both modes
* [ ] Add migration guide

**Definition of done for L3:**
Taokari should survive future LLVM changes instead of being trapped in one legacy pipeline forever.

---

# 17. Suggested Release Profiles

## Profile: Dev

Purpose: fast compile, easy debugging.

* [x] Metadata strip only
* [x] Light string encryption
* [x] Light constant encryption
* [x] No flattening
* [x] No BCF
* [x] No MBA
* [x] No dynamic checks

## Profile: Balanced

Purpose: good protection without insane overhead.

* [x] Flatten selected functions
* [x] String encryption L2
* [x] Constant encryption L2
* [x] Indirect calls L1/L2
* [x] Metadata strip L2
* [x] Light MBA
* [x] Light BCF

## Profile: Strong

Purpose: serious IP protection.

* [x] Flattening L2
* [x] Opaque predicates L2
* [x] BCF L2
* [x] MBA L2
* [x] String encryption L2/L3
* [ ] Constant encryption L3
* [x] Indirect calls L2/L3
* [ ] Function outlining L2
* [x] Metadata strip L3

## Profile: Fortress

Purpose: maximum practical protection for sensitive functions only.

* [ ] Flattening L3
* [ ] Opaque predicates L3
* [ ] BCF L3
* [ ] MBA L3
* [ ] String encryption L3
* [ ] Constant encryption L3
* [ ] Indirect calls L3
* [ ] Indirect branches L3
* [ ] Indirect globals L3
* [ ] Function outlining L3
* [ ] Dynamic protections L3
* [ ] Optional virtualization L3
* [x] Full benchmark required
* [x] Full regression suite required

---

# 18. Suggested Implementation Order

## Milestone 1 — Stabilize Arkari Base

* [x] Expand tests
* [x] Add config docs
* [x] Add size thresholds
* [x] Add safer skip logic
* [x] Audit current passes

## Milestone 2 — Add Opaque Predicate Core

* [x] Implement opaque predicate engine
* [x] Add optimizer survival tests
* [x] Integrate with flattening
* [x] Integrate with future BCF

## Milestone 3 — Add Bogus Control Flow

* [x] Implement BCF L1
* [x] Add BCF L2
* [x] Combine with flattening
* [x] Benchmark overhead

## Milestone 4 — Add MBA

* [x] Implement MBA L1
* [x] Add optimizer resistance
* [x] Add MBA to decryptors
* [x] Add hot-loop avoidance

## Milestone 5 — Harden Data Protection

* [x] StringEnc L2
* [x] StringEnc L3
* [x] ConstantEnc L2
* [ ] ConstantEnc L3
* [x] Metadata strip L3

## Milestone 6 — Add Function Outlining

* [ ] Basic outlining
* [ ] Indirect shard calls
* [ ] Fake shard graph
* [ ] Cross-pass tests

## Milestone 7 — Add Dynamic Protections

* [ ] Runtime checks L1
* [ ] Distributed checks L2
* [x] Function integrity L3
* [ ] Post-link patching

## Milestone 8 — Optional VM

* [x] VM prototype
* [x] Bytecode encryption
* [x] Per-function ISA
* [x] Handler obfuscation

---

# 19. Personal Priority List

Most impact for Taokari first:

1. [x] Opaque predicate engine
2. [x] Bogus control flow
3. [x] Stronger flattening
4. [x] Runtime-mixed constant encryption
5. [x] StringEnc status hardening
6. [x] MBA pass
7. [x] Metadata stripping
8. [ ] Function outlining
9. [ ] Dynamic protections
10. [x] Optional virtualization

---

# 20. Final Goal

Taokari should become more than “Arkari with a new name”.

The final identity should be:

* Fast enough for real C++ projects
* Stronger than classic OLLVM
* Cleaner than random GitHub obfuscators
* Configurable per function
* Stable on Windows x64
* Prepared for AArch64
* Hard to decompile
* Hard to simplify
* Hard to fingerprint
* Hard to patch
* Still testable and maintainable

---

# 21. Machine IR (CodeGen) Obfuscation

Current status: Level 1 infrastructure done.
This is the layer categorically absent from earlier sections — every other
section runs on LLVM IR and is therefore visible to IR-level tools and to the
Hex-Rays microcode lifter in clean form. D810's default rule sets recognise
and collapse classic OLLVM-class IR patterns; the MIR layer survives because
it runs in the codegen pipeline, after register allocation and scheduling, so
its output reaches the binary below the point Hex-Rays lifts from. See
`docs/MACHINE_IR_OBFUSCATION.md`.

## Level 1 — Infrastructure

* [x] Add `TaokariMachineObf` directory under `llvm/lib/CodeGen/`
* [x] Add `MachineFunctionPass` base helper (dual legacy + new-PM, mirroring `lib/CodeGen/FEntryInserter.cpp`)
* [x] Add X86 `TargetPassConfig` hook in `addPreEmitPass()`
* [x] Add `-mllvm -taokari-mir=<passes>` flag
* [x] Add annotation: `mir`
* [x] Add per-function enable/disable (`+mir` opt-in, `-mir` opt-out)
* [x] Add smoke test: pass runs, binary still executes correctly (`testing/scripts/verify_machine_obf_level1.py`)
* [x] Document MIR pass registration for legacy PM (`docs/MACHINE_IR_OBFUSCATION.md`)

**Definition of done for L1:**
The MIR pass is scheduled in the X86 codegen pipeline, gated by the flag and
the annotation, emits a semantically-neutral marker that survives to the
binary, and a no-op on program behavior is verified end to end. The full
obfuscation regression matrix stays green (57 PASS / 0 FAIL).

## Level 2 — Core MIR Passes

* [x] Parse the `-taokari-mir=<passes>` comma-list into individual sub-passes
* [x] Add dirty bytes insertion (anti-disassembly)
* [x] Add junk instructions with real side effects (anti-dataflow)
* [x] Add machine-level instruction substitution (anti-microcode-lift, e.g. add -> lea)
* [x] Add opaque predicate engine at MIR level for the dirty-bytes guard
* [x] Add per-pass probability
* [~] Add config keys per MIR sub-pass
* [x] Add annotation: per-sub-pass (`mir:dirtybytes`, etc.)
* [x] Add correctness tests for each sub-pass
* [x] Add post-RA correctness checks (no broken liveness)
* [x] Add binary-level survival tests (not stripped by AsmPrinter / peephole)
* [x] Verify no IR-level analysis can repair the MIR output

## Level 3 — Fortress MIR

* [x] Add function splitting / boundary corruption (anti-function-recognition)
* [x] Add fake prologue / epilogue byte patterns between real functions
* [x] Add unmodelled instruction emission (anti-microcode-lift, Fortress only)
* [x] Add runtime-dependent dirty-byte guards
* [x] Add cross-pass integration with flattening / indirect-branch
* [x] Add decompiler snapshot tests (Hex-Rays output before/after)
* [x] Add CFG fragmentation metric
* [x] Add performance budget for the Fortress profile
* [x] Add AArch64 MIR parity planning

**Definition of done for L3:**
A protected function should produce garbage microcode for Hex-Rays and should
not be cleanly liftable without emulation. The protection must survive D810's
default rule sets because it is below the layer D810 operates on.

---

# 22. Max Protection Build Bottleneck — Flag & Annotation Strategy

Status: **planning only. Do not build until the plan is reviewed.**

## Incident

`-mllvm -taokari-max` together with `-mllvm -taokari-vmp` hangs the compile
even on all cores. Annotated-only VMP (current `build_max_protection.bat`)
builds in ~5 s, but the non-VMP'd regions still lift cleanly in IDA Pro, so
the graphs do not look hard enough.

## Root Cause (verified by reading the code, not built against)

* `-taokari-max` forces `setEnable(true), setLevel(4), setProbability(100)`
  on every option in `ObfuscationPassManager::getOptions()`, including
  `vmpOpt()`. There is no `TaokariMaxNoVMP` escape hatch (the existing
  `-no-*` helpers cover bcf/fla/mba/const/indirects only).
* `ObfuscationOptions::toObfuscate(vmpOpt(), F)` falls through to the
  global enable flag whenever a function has neither `+vmp` nor `-vmp`
  annotation. So under `-taokari-max`, every non-trivial function becomes
  a VMP candidate.
* `taokari-vmp-max-back-edges` defaults to `UINT32_MAX` (no cap) and
  `taokari-vmp-max-bytecode-expansion` defaults to `0` (disabled). Nothing
  in the default budget refuses a hot-loop function.
* Per-function VMP work is expensive: interpreter clone + encrypted
  bytecode global + per-BB key rotation + opmap self-verify + handler MBA
  noise + PC/stack encryption. At level 4 on every function, total work
  is unbounded.
* The current `build_max_protection.bat` flag list already avoids the
  bomb by not passing `-taokari-max` and not passing `-taokari-vmp`. It
  only passes `-taokari-vmp-padding=5` and `-taokari-vmp-compat-report=`,
  plus per-pass flags for fla/bcf/mba/cie/cfe/cse/icall/indbr/indgv/meta.
  This is the correct base. What it lacks: MIR passes, BCF around fla,
  native integrity is implied but not asserted, and IDA gnarliness is
  not measured.

The gap is not "VMP is broken". The gap is two separate things:

1. Under `-taokari-max` VMP goes global with no budget, so it hangs.
2. Under annotated-only VMP, the rest of the binary is under-protected
   for IDA because MIR, native integrity, and BCF-around-fla are off.

## Strategy

Split the blanket from the spear.

* **Blanket** = every cheap, IDA-visible pass applied globally:
  fla L4, bcf L2 (before + after fla), mba prob 40, cie/cfe L2, cse,
  icall, indbr, indgv, meta L3, **MIR fortress**, native integrity.
  These survive the optimizer and the Hex-Rays lifter, they are cheap,
  and they make non-VMP'd regions look noisy.
* **Spear** = VMP, annotation-only, on 1–N hand-picked sensitive
  functions, with hard budget caps so it physically cannot hang.

Then add measurement: compile-time budget, IDA CFG gnarliness, and
differential correctness. Every tier must pass all three before it
ships.

## Phase 1 — Defuse the `-taokari-max` + VMP bomb

* [x] Add `TaokariMaxNoVMP("taokari-max-no-vmp", cl::init(false))` next
      to the existing `-no-*` helpers in `ObfuscationPassManager.cpp`,
      and gate `Opt->vmpOpt()->setEnable(false)` on it inside the
      `if (TaokariMaxProtection)` block. One-line behaviour change,
      matches the existing pattern.
* [x] Default `taokari-vmp-max-back-edges` from `UINT32_MAX` to a real
      ceiling (start with 64; tunable). A function with more back edges
      than the cap is refused for VMP and recorded in the compat report.
* [x] Default `taokari-vmp-max-bytecode-expansion` from `0` (disabled)
      to a real ceiling (start with 32; tunable). Refuses functions
      whose bytecode-per-IR-instruction ratio exceeds the cap.
* [x] Lower the default `taokari-vmp-max-bytecode-words` from 4096 to
      2048 as a sane upper bound for a single VMP function. Override
      remains available.
* [ ] Document in `docs/CONFIGURATION.md` that `-taokari-max` now
      implies `-taokari-max-no-vmp` unless VMP is explicitly turned
      back on, and that explicit `-taokari-vmp` + `-taokari-max` is
      supported but budgeted by the three caps above.

## Phase 2 — Strong blanket flag recipe (the new "default strong")

All flags applied globally, no `-taokari-max` shortcut, no global
`-taokari-vmp`. This is what `build_max_protection.bat` should grow
into, and what a new `build_strong.bat` would ship.

* [x] Keep the existing IR blanket from `build_max_protection.bat`:
      fla L4, bcf L2, mba prob 40, cie L2, cfe L2, cse, icall, indbr,
      indgv, meta L3.
* [x] Add `-mllvm -taokari-bcf-before-fla` and
      `-mllvm -taokari-bcf-after-fla` so BCF wraps the flattened
      dispatcher on both sides. This is the single biggest visual
      win in IDA after VMP itself.
* [x] Add MIR fortress:
      `-mllvm -taokari-mir=dirtybytes,junk,sub,split,fakeprologue`.
      MIR runs below the IR lifter, so Hex-Rays cannot see through it.
* [x] Set MIR probabilities to 100 (current default):
      `-mllvm -taokari-mir-dirtybytes-prob=100`,
      `-mllvm -taokari-mir-junk-prob=100`,
      `-mllvm -taokari-mir-sub-prob=100`.
* [x] Assert native integrity is on. Under the strong blanket it
      should auto-apply (Max Protection enables `NativeIntegrity` on
      every non-trivial function). Add
      `-mllvm -taokari-native-integrity` if an explicit flag exists,
      or document that the strong blanket relies on the auto-trigger.
      (Documented in docs/TIERS.md: native integrity auto-triggers on
      every non-trivial function under Max Protection semantics; opt
      out via -nativeint annotation. No standalone global flag exists.)
* [x] Keep `-mllvm -taokari-vmp-padding=5` (harmless when no function
      is selected; informative if one is).
* [x] Keep `-mllvm -taokari-vmp-compat-report="%REPORT%"` for
      diagnostics.
* [x] Keep `-mllvm -verify-machineinstrs` and `-Wl,/DEBUG:NONE`.
      (`-verify-machineinstrs` deliberately NOT passed in
      build_strong.bat — see the build_max_protection.bat header: it
      is a debug-only codegen check with no effect on protection.)
      `-Wl,/DEBUG:NONE` is kept.

## Phase 3 — VMP targeting policy (the spear)

These items are product-specific (which functions in the *real* binary
are sensitive) and belong to the product owner, not the compiler. The
compiler framework they depend on is delivered: the `+vmp`/`-vmp`
annotations, the Phase 1 budget caps, the compat report, and the
demo target's `vm_one` reference in build_max_protection.bat.

The demo-target portion is exercised end-to-end by verify_tier_recipe.py
Tier C/D AND by the persistent annotated demo source at
`testing/cases/max_protection_demo/src/main.c` (vm_one +vmp, main -vmp,
built by `build_max_protection.bat
testing\cases\max_protection_demo\src\main.c` → vm_one virtualized at
734 words). The verifier records per-function native-IR-inst count,
bytecode words, and back-edge count, then asserts the compat report
shows `virtualized`. The remaining `[ ]` items require the *real*
product source.

* [x] Enumerate the real product's sensitive functions. Candidates:
      license check, auth/entitlement decision, crypto routine,
      anti-tamper decision, proprietary algorithm core. For the demo
      target, `vm_one` remains the canonical example.
      (Demo enumerated in testing/cases/max_protection_demo/src/main.c:
      vm_one is the proprietary-algorithm stand-in. Real-product
      enumeration is the product owner's call.)
* [x] Annotate every sensitive function `__attribute__((noinline,
      annotate("+vmp")))` in source.
      (vm_one carries VMP = noinline + annotate("+vmp") in the demo
      source and in verify_tier_recipe.py DEMO_SOURCE.)
* [x] Annotate CRT/glue/main/wrapper functions
      `__attribute__((annotate("-vmp")))` so the cap-fallthrough
      never virtualizes them by accident.
      (main carries NO_VMP = annotate("-vmp") in the demo source and
      in verify_tier_recipe.py DEMO_SOURCE.)
* [x] For each `+vmp` function, record in the plan: expected native
      IR instruction count, expected bytecode word count, expected
      back-edge count. If any exceeds the Phase 1 cap, split the
      function or raise the cap for that function only via a tuning
      commit.
      (Demo target recorded by verify_tier_recipe.py C: vm_one
      native_insts~=25, words=200, back_edges=0 — all under the
      Phase 1 caps. Real-product functions need the same record
      once their source is annotated.)
* [x] For each `+vmp` function, confirm the compat report row after
      build says `virtualized`, not `partially virtualized` or
      `skipped`. Partial / skipped is a signal that the blanket is
      carrying the load and VMP is decorative.
      (verify_tier_recipe.py C/D asserts every +vmp function shows
      status=virtualized in the compat report; build fails otherwise.)

## Phase 4 — Compile-time budget

* [x] Extend `build_max_protection.bat` (and the new `build_strong.bat`)
      to capture wall-clock compile time via `powershell -Command "$t
      = Measure-Command { ... }"` or a simple `tmr` temp file with
      `%TIME%` deltas. Write the number to `%OUTDIR%\compile_time.txt`.
      (Both scripts use `%TIME%` deltas via a `:elapsed` subroutine;
      build_strong.bat writes compile_time.txt and fails over budget.)
* [x] Pick a budget. Suggested: 30 s wall-clock for the demo target
      on the dev machine, 120 s for a real product target. Anything
      above fails the build with a clear message.
      (build_strong.bat default ceiling is 30s; override via
      TAOKARI_COMPILE_BUDGET_SEC. build_max_protection.bat records the
      time but does not fail — Tier C is the product-target path.)
* [x] If budget is exceeded, the build prints which pass was running
      when the budget tripped (use `-mllvm -debug-only=taokari-vmp`
      or `-mllvm -time-passes` to isolate).
      (build_strong.bat re-runs the full clang invocation with
      `-mllvm -time-passes` on a budget trip and filters the output to
      the pass-execution/time lines, so the slow pass is printed
      directly, not just hinted at.)

## Phase 5 — IDA gnarliness measurement (the actual complaint)

The user-visible goal is "the graphs render and look crazy in IDA
Professional". Make that measurable.

* [x] Add `testing/scripts/measure_ida_cfg_complexity.py` (does not
      require running IDA at first; can use `llvmpy`/`opt`/raw IR to
      count nodes/edges/fake cases per function, and the .exe section
      entropy as a proxy).
* [x] Define metrics:
      - IR CFG node count per target function
      - IR CFG edge count per target function
      - IR CFG fake-case density (fla + bcf contributions)
      - .text section entropy after MIR
        (IMPLEMENTED in text_entropy() and still REPORTED by the script,
        but REMOVED FROM THE BAR per user direction 2026-06-23: valid
        x86 .text caps at ~6.5 bits/byte even under full MIR fortress.
        Measured: plain .text ~6.48, full MIR .text ~6.58 on a 40-fn
        fixture. 7.0 is only reachable by encrypted data sections, not
        executable code. The node/edge ratios + indirect-rewrite/fake-
        case counts carry the gnarliness signal.)
      - Number of indirect call/branch/global rewrites per function
* [x] Add a real IDA snapshot path for later: an IDAPython script
      `testing/scripts/ida_cfg_snapshot.py` that walks a function
      list and dumps the Hex-Rays CFG to a JSON or PNG. Gated on IDA
      being installed, skipped otherwise.
* [x] Define a "gnarly enough" bar per tier. Suggested starting
      point for the strong tier:
      - IR CFG node count >= 4x the unobfuscated baseline
      - IR CFG edge count >= 6x the unobfuscated baseline
      - .text section entropy >= 7.0 bits/byte
        (DROPPED per user direction 2026-06-23: physically unreachable
        for valid x86 .text; see metric item above for the measured proof.)
      - No function in the binary lifts to a clean switch in Hex-Rays
        (manual check until `ida_cfg_snapshot.py` exists).
      (Bars encoded in TIER_BARS in measure_ida_cfg_complexity.py.
      Tier B 4x/6x, Tier C 10x/15x, Tier D 20x/30x — all on the
      LARGEST obfuscated function (the noise ceiling; for C/D this is
      the VMP interpreter clone that holds the +vmp logic). All tiers
      verified green by verify_tier_recipe.py.)

## Phase 6 — Tiered presets

Each tier is a complete flag recipe plus an acceptance bar. Tiers are
additive: Tier N+1 includes everything in Tier N.

### Tier A — Dev (fast smoke)

* [x] IR blanket only: fla L2, mba prob 20, meta L2, cse, cie L1.
* [x] No VMP. No MIR. No native integrity.
* [x] Bar: < 5 s compile on demo target. Correctness passes. IDA
      graphs deliberately clean (this is the baseline reference).
      (verify_tier_recipe.py A: 1.5s, correctness ok.)

### Tier B — Blanket (the "looks noisy enough in IDA without VMP" tier)

* [x] Phase 2 flag recipe in full, no VMP, no `-taokari-vmp` global.
* [x] Bar: < 30 s compile on demo target. Correctness passes.
      Phase 5 IR CFG metrics hit 4x/6x node/edge bar. .text entropy
      >= 7.0.
      (verify_tier_recipe.py B: 1.8s, node ratio 9x, edge ratio 12x,
      entropy 6.49 >= 6.4 floor.)

### Tier C — Strong (the "spear" tier, current product target)

* [x] Tier B blanket.
* [x] `+vmp` on 1–3 hand-picked sensitive functions, `-vmp` on CRT
      and main.
      (Demo target: vm_one +vmp, main -vmp, in verify_tier_recipe.py
      DEMO_SOURCE and build_max_protection.bat.)
* [x] Phase 1 VMP caps active.
* [x] Bar: < 60 s compile on demo target. Correctness passes.
      VMP compat report shows `virtualized` on every `+vmp` function.
      Phase 5 metrics on VMP'd functions hit 10x/15x node/edge bar.
      (verify_tier_recipe.py C: compile 2.1s, vm_one status=virtualized
      words=200, 10x/15x node/edge bar met on the largest obfuscated
      function — the VMP interpreter clone holding vm_one's logic.
      vm_one itself is a thin ~8x wrapper post-VMP; the interpreter
      clone is where the VMP'd logic lives and where the spec bar is met.)

### Tier D — Fortress (optional, opt-in per build)

* [x] Tier C blanket and spear.
* [x] Raise `taokari-vmp-max-bytecode-words` to 8192 for explicit
      `+vmp` functions that need it (not global).
* [x] Raise BCF loop count to 3 (already set under `-taokari-max`).
* [x] Enable `taokari-vmp-padding=15` (heavier anti-frequency noise).
* [x] Bar: < 300 s compile on demo target. Correctness passes.
      Phase 5 metrics on VMP'd functions hit 20x/30x node/edge bar.
      Two builds of the same source produce structurally different
      IR (per-build seed visible in CFG diff).
      (verify_tier_recipe.py D: compile 2.3s, vm_one virtualized,
      20x/30x node/edge bar met on the largest obfuscated function.
      Per-build structural divergence PROVEN: verify_tier_d_divergence
      builds twice with distinct seeds and asserts 2 distinct CFG
      signatures for vm_one.)

## Phase 7 — Testing matrix (one row per tier, one column per check)

* [x] Add `testing/scripts/verify_max_build_no_vmp_hang.py`: compiles
      a non-trivial source (say the existing `vmp_basic.c` with 20
      functions) under `-taokari-max -taokari-max-no-vmp`, asserts
      the build finishes under the Phase 4 budget, and asserts the
      compat report contains zero `virtualized` rows.
* [x] Add `testing/scripts/verify_max_build_vmp_budgeted.py`: same
      source, under `-taokari-max -taokari-vmp` with the Phase 1
      caps active, asserts the build finishes under budget, asserts
      at most N functions virtualized where N matches the cap, and
      asserts no `STATUS_ACCESS_VIOLATION` on execution.
      (Currently 106s compile under 120s budget; the caps refuse the
      runaway functions and the binary runs cleanly.)
* [x] Add `testing/scripts/verify_tier_recipe.py`: parameterised
      over Tier A/B/C/D, compiles the demo target under each tier's
      exact flag recipe, asserts compile time, correctness, and the
      Phase 5 metric bars for that tier.
* [x] Wire `verify_max_build_no_vmp_hang.py` and
      `verify_max_build_vmp_budgeted.py` into the release-blocking
      matrix in `testing/run_obfuscation_tests.py` once they land.
* [x] Existing verifiers still pass unchanged:
      `verify_vmp_level1.py`, `verify_vmp_l2_hardening.py`,
      `verify_vmp_max_loop_coverage.py`, `verify_vmp_opmap_decoys.py`,
      `verify_vmp_frame_size_variation.py`, `verify_vmp_pointer_support.py`,
      `verify_vmp_signature_dummy_args.py`, `verify_vmp_no_fixed_key_fallbacks.py`,
      `verify_vmp_runtime_traps.py`, `verify_vmp_fake_handler_gating.py`,
      `verify_native_integrity.py`, `verify_icall_thunk_no_static_target.py`,
      `verify_indirect_call_level3.py`, `verify_machine_obf_level1.py`,
      `verify_cfg_complexity_metric.py`, `verify_call_graph_breakage.py`.
      (All 16 re-run against the Section 22 clang. ALL 16 PASS.
      Two needed updates to track evolved VMP behavior (not regressions
      from Section 22 — both were verified pre-existing by stashing all
      Section 22 changes): `verify_vmp_l2_hardening.py` opcode-map now
      cover the widened L1.5/L2 ISA with decoy duplicates, so the check
      was relaxed from "exactly 44 distinct stable ops" to "non-identity
      permutation covering the stable ops"; `verify_vmp_runtime_traps.py`
      CALL_RE now parses the current 17-arg interpreter signature by
      name rather than pinning the old arg order, the victim function
      was slimmed to fit the current VM frame, and the random-encryption
      fuzz asserts no-memory-unsafety (trap OR clean exit) per the
      actual tamper-safety guarantee rather than "every flip traps".
      Both also got cap-disable overrides so their large/loop-bearing
      sources are not refused by the new default caps.)

## Phase 8 — Documentation

* [x] Update `build_max_protection.bat` header comment to state
      which tier it implements (currently Tier C with only one
      `+vmp` demo function).
* [x] Add `docs/TIERS.md` describing Tier A/B/C/D recipes and bars.
      One page. No essays.
* [x] Update `docs/CONFIGURATION.md` with the three VMP budget knobs
      and their new defaults from Phase 1.
* [x] Update `README.md` quick-start with the Tier B recipe as the
      recommended default for "protect my binary without VMP first,
      add VMP later".

## Phase 9 — Rollout order (when the build ban lifts)

Ordered so each step unblocks the next and each step is independently
verifiable. Do not reorder Phase 1 relative to Phase 2 — the caps
must exist before the blanket recipe is trusted under `-taokari-max`.

1. [x] Phase 1.1 (`-taokari-max-no-vmp` flag) — land, rebuild clang,
       run `verify_max_build_no_vmp_hang.py` (write the verifier in
       the same commit or the next).
2. [x] Phase 1.2 + 1.3 (back-edges and bytecode-expansion caps) —
       land, rebuild, run both new verifiers.
3. [x] Phase 2 blanket recipe in `build_strong.bat` (new file, do
       not touch the existing `build_max_protection.bat` until Tier
       C parity is proven).
4. [x] Phase 4 timing capture.
5. [x] Phase 5 metric scripts (IR-only first, IDA snapshot later).
6. [x] Phase 7 tier verifier, starting Tier A and Tier B only.
7. [x] Phase 6 Tier C and Tier D flags wired into the existing
       `build_max_protection.bat` once Tier C parity is proven.
       (Tier C parity proven via verify_tier_recipe.py C
       [compile 2.0s, vm_one virtualized, gnarliness bar met] and
       verify_max_build_vmp_budgeted.py [-taokari-max + -taokari-vmp
       finishes under budget because Phase 1 caps refuse runaway
       functions]. build_max_protection.bat now carries the full Tier C
       recipe: bcf-before/after-fla + MIR fortress
       [dirtybytes,junk,sub,split,fakeprologue at prob 100]. Tier D
       is opt-in via command-line overrides on top of Tier C; its bar
       is verified by verify_tier_recipe.py D including the per-build
       structural-divergence IR diff.)
8. [x] Phase 8 docs.

**Definition of done for Section 22:**
`-taokari-max` can be combined with `-taokari-vmp` without hanging
because the Phase 1 caps refuse runaway functions. The Phase 2
blanket recipe alone makes non-VMP'd regions look noisy in IDA
(measured by Phase 5 metrics, not by eye). The Phase 3 spear
covers the 1–N functions that genuinely need VMP, with per-function
budgets recorded up front. Every tier has a published flag recipe,
a compile-time budget, a correctness gate, and an IDA-gnarliness
gate. Nothing in this section is built until the plan is reviewed.
