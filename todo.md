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
* [ ] Add random predicate selection
* [ ] Add predicate nesting
* [ ] Add per-pass predicate style selection
* [ ] Add solver-resistance test cases
* [ ] Add SimplifyCFG survival tests
* [ ] Add InstCombine survival tests
* [ ] Add `opt -O2` survival tests
* [ ] Use predicates in flattening
* [ ] Use predicates in bogus control flow
* [ ] Use predicates in anti-debug gates

**Definition of done for L3:**
Opaque predicates should survive the normal LLVM cleanup pipeline and be reusable by all other passes.

---

# 3. Bogus Control Flow

Current status: missing.
This is one of the most important differentiators against plain Arkari.

## Level 1 — Classic BCF

* [ ] Add `BogusControlFlow.cpp`
* [ ] Clone selected basic blocks
* [ ] Insert opaque branch before real block
* [ ] Add fake block path
* [ ] Add junk math inside fake block
* [ ] Add dead stores inside fake block
* [ ] Add config probability
* [ ] Add config loop count
* [ ] Add annotation: `bcf`

## Level 2 — Strong BCF

* [ ] Mutate cloned fake blocks
* [ ] Add fake memory accesses
* [ ] Add fake arithmetic chains
* [ ] Add fake calls to safe internal junk functions
* [ ] Add fake dependency on global nonce
* [ ] Add per-function BCF seed
* [ ] Add BCF after flattening option
* [ ] Add BCF before flattening option

## Level 3 — Fortress BCF

* [ ] Add multi-layer bogus graphs
* [ ] Add fake loops
* [ ] Add fake switch structures
* [ ] Add fake error paths
* [ ] Add fake cleanup paths
* [ ] Add fake exception-looking regions where safe
* [ ] Add fake block merging
* [ ] Add integration with dispatcher fake cases
* [ ] Add decompiler visual-noise mode
* [ ] Add benchmark for CFG explosion

**Definition of done for L3:**
The CFG should contain convincing fake regions that static analysis cannot cheaply prune.

---

# 4. Mixed Boolean Arithmetic

Current status: missing.
This is needed to hide simple arithmetic, constants and dispatch calculations.

## Level 1 — Basic MBA

* [ ] Add `MBA.cpp`
* [ ] Replace `add`
* [ ] Replace `sub`
* [ ] Replace `xor`
* [ ] Replace `and`
* [ ] Replace `or`
* [ ] Support integer types
* [ ] Add config probability
* [ ] Add annotation: `mba`
* [ ] Add correctness tests

Example identities:

* `a + b = (a ^ b) + 2 * (a & b)`
* `a - b = a + (~b) + 1`
* `a ^ b = (a | b) - (a & b)`

## Level 2 — Optimizer-Resistant MBA

* [ ] Add multiple MBA rounds
* [ ] Add random identity selection
* [ ] Add opaque constants inside MBA
* [ ] Add runtime nonce mixing
* [ ] Add optional `optnone` helper wrappers
* [ ] Add InstCombine survival tests
* [ ] Add Reassociate survival tests
* [ ] Add GVN survival tests

## Level 3 — Fortress MBA

* [ ] Add polymorphic MBA templates
* [ ] Add per-function MBA style
* [ ] Add MBA on dispatch state updates
* [ ] Add MBA on constant decryptors
* [ ] Add MBA on string decryptors
* [ ] Add MBA on page-table decryptors
* [ ] Add solver-resistance samples
* [ ] Add overhead budget system
* [ ] Add hot-loop avoidance
* [ ] Add performance profile tests

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

* [ ] Add global runtime nonce
* [ ] Mix decryptor with runtime load
* [ ] Add volatile seed option
* [ ] Add per-function seed mixing
* [ ] Add cache at function entry
* [ ] Keep dedup cache pattern
* [ ] Prevent re-encryption recursion
* [ ] Add constant decryptor MBA option

## Level 3 — Fortress Constants

* [ ] Add opaque constant pass
* [ ] Add context-dependent constants
* [ ] Add per-use decrypt option
* [ ] Add per-function constant pool
* [ ] Add encrypted constant pool
* [ ] Add page-table-backed constants
* [ ] Add indirect constant references
* [ ] Add constant access through helper shards
* [ ] Add LTO survival tests
* [ ] Add binary diff tests

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
* [ ] Audit all plaintext status slots
* [ ] Add tests for UTF-16 strings
* [ ] Add tests for wide strings
* [ ] Add config for minimum string length
* [ ] Add skip list for harmless strings

## Level 2 — Stronger StringEnc

* [ ] Replace plaintext status flag
* [ ] Add encrypted sentinel
* [ ] Add per-build nonce
* [ ] Add per-string key schedule
* [ ] Randomize key length
* [ ] Randomize decryptor shape
* [ ] Add position-dependent key mixing
* [ ] Add optional local stack decrypt
* [ ] Add optional heap decrypt
* [ ] Add optional re-encrypt-after-use

## Level 3 — Fortress StringEnc

* [ ] Add polymorphic decryptors
* [ ] Add decryptor MBA
* [ ] Add decryptor flattening
* [ ] Add decryptor indirect calls
* [ ] Add string shards
* [ ] Add split string pools
* [ ] Add fake string pools
* [ ] Add string access through page table
* [ ] Add delayed decrypt mode
* [ ] Add memory lifetime tests
* [ ] Add string dump resistance tests

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
* [ ] Skip declarations reliably
* [ ] Skip weak symbols
* [ ] Skip `dllimport`
* [ ] Skip externally visible unsafe callees
* [ ] Skip `alwaysinline`
* [ ] Add correctness tests for function pointers
* [ ] Add tests for virtual calls
* [ ] Add tests for templates

## Level 2 — Stronger Indirection

* [ ] Add per-call probability
* [ ] Add per-function probability
* [ ] Add encrypted two-share mode
* [ ] Add runtime seed in address reconstruction
* [ ] Add MBA to pointer reconstruction
* [ ] Add fake page-table entries
* [ ] Add shuffled page-table layout
* [ ] Add page-table integrity check

## Level 3 — Fortress Indirect Calls

* [ ] Add per-object pointer-auth discriminator
* [ ] Add module-seed PAC discriminator
* [ ] Add callout integration
* [ ] Add function shard calls
* [ ] Add fake call edges
* [ ] Add multiple call reconstruction formulas
* [ ] Add indirect call decryptor variants
* [ ] Add cross-module safety tests
* [ ] Add AArch64 test case
* [ ] Add Windows x64 test case

**Definition of done for L3:**
The static call graph should be unreliable, incomplete and expensive to reconstruct.

---

# 8. Indirect Branches

Current status: strong baseline.
Main weakness: no AArch64 parity test and limited fake target noise.

## Level 1 — Safety

* [x] Indirect branch page table exists
* [x] BlockAddress support exists
* [ ] Add more `indirectbr` tests
* [ ] Add EH compatibility tests
* [ ] Add AArch64 smoke test
* [ ] Add x64 Windows test
* [ ] Audit block address edge cases

## Level 2 — Stronger Branch Tables

* [ ] Add fake block entries
* [ ] Add fake encrypted indices
* [ ] Add shuffled target tables
* [ ] Add runtime nonce mixing
* [ ] Add MBA for index decrypt
* [ ] Add branch target verification
* [ ] Add config probability

## Level 3 — Fortress Indirect Branches

* [ ] Add per-function branch table variants
* [ ] Add multiple decrypt formulas
* [ ] Add bogus branch destinations
* [ ] Add trap destinations
* [ ] Add fake recovery paths
* [ ] Add branch-table integrity checks
* [ ] Add dispatcher integration
* [ ] Add cross-pass tests with flattening
* [ ] Add cross-pass tests with BCF

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
* [ ] Add tests for const globals
* [ ] Add tests for mutable globals
* [ ] Add tests for large structs
* [ ] Add tests for arrays
* [ ] Add tests for C++ static locals

## Level 2 — Stronger Global Access

* [ ] Add fake global entries
* [ ] Add shuffled global table
* [ ] Add per-function global cache
* [ ] Add runtime nonce mixing
* [ ] Add MBA on global pointer decrypt
* [ ] Add config for sensitive globals only
* [ ] Add annotation: `indgv`

## Level 3 — Fortress Globals

* [ ] Add split global storage
* [ ] Add encrypted global pools
* [ ] Add fake global pools
* [ ] Add per-use global decrypt option
* [ ] Add pointer-auth discriminator for globals
* [ ] Add global access integrity check
* [ ] Add cross-pass test with string encryption
* [ ] Add cross-pass test with constant encryption

**Definition of done for L3:**
Sensitive global references should not look like direct global accesses in the decompiler.

---

# 10. Function Outlining / Callout Obfuscation

Current status: missing.
This is a major differentiator from base Arkari.

## Level 1 — Basic Function Splitting

* [ ] Add `FunctionOutlining.cpp`
* [ ] Split selected basic blocks into helper functions
* [ ] Preserve arguments
* [ ] Preserve return values
* [ ] Preserve side effects
* [ ] Add annotation: `outline`
* [ ] Add config for max shards
* [ ] Add simple correctness tests

## Level 2 — Indirect Shards

* [ ] Route shard calls through indirect call page table
* [ ] Add fake shard functions
* [ ] Add shard name randomization
* [ ] Add shard argument scrambling
* [ ] Add shard return scrambling
* [ ] Add per-function shard count
* [ ] Add performance guardrails

## Level 3 — Fortress Callout

* [ ] Add multi-layer function shards
* [ ] Add shard dispatcher
* [ ] Add fake shard graph
* [ ] Add shard integrity checks
* [ ] Add cross-shard constant pools
* [ ] Add cross-shard string pools
* [ ] Add outline + flattening mode
* [ ] Add outline + BCF mode
* [ ] Add outline + MBA mode
* [ ] Add decompiler quality test

**Definition of done for L3:**
A sensitive function should no longer exist as one clean static function body.

---

# 11. Metadata / Symbol / Debug Info Stripping

Current status: partially covered by MSVC RTTI eraser.
Goal: remove accidental leaks.

## Level 1 — Basic Metadata Cleanup

* [x] MSVC RTTI name erase exists
* [ ] Strip `llvm.ident`
* [ ] Strip `!dbg`
* [ ] Strip `DIFile`
* [ ] Strip source paths
* [ ] Strip compiler version strings
* [ ] Add config toggle
* [ ] Add metadata leak tests

## Level 2 — Stronger Symbol Hygiene

* [ ] Randomize internal symbol names
* [ ] Randomize obfuscation helper names
* [ ] Randomize decryptor names
* [ ] Randomize table names
* [ ] Hide pass fingerprints
* [ ] Add fake helper symbols
* [ ] Add export allowlist

## Level 3 — Fortress Metadata Hygiene

* [ ] Add full release-strip profile
* [ ] Add PDB hygiene docs
* [ ] Add Mach-O metadata support
* [ ] Add ELF metadata support
* [ ] Add PE section-name randomization option
* [ ] Add helper section randomization
* [ ] Add symbol diff test
* [ ] Add source-path leak test
* [ ] Add RTTI leak test

**Definition of done for L3:**
The binary should not leak project paths, compiler identifiers, helper names or obvious Taokari fingerprints.

---

# 12. Dynamic Protections

Current status: not implemented.
These must be optional and off by default.

## Level 1 — Basic Runtime Checks

* [ ] Add optional anti-debug check
* [ ] Add optional timing check
* [ ] Add optional breakpoint check
* [ ] Add optional PEB check on Windows
* [ ] Add config toggle
* [ ] Add annotation: `dyn`
* [ ] Add safe failure mode
* [ ] Add false-positive tests

## Level 2 — Distributed Runtime Checks

* [ ] Insert checks in multiple functions
* [ ] Guard checks with opaque predicates
* [ ] Hide checks behind indirect calls
* [ ] Add fake checks
* [ ] Add check result mixing
* [ ] Add delayed checks
* [ ] Add runtime nonce dependency
* [ ] Add tamper flag propagation

## Level 3 — Fortress Dynamic Protection

* [ ] Add function-level integrity checks
* [ ] Add cross-function integrity checks
* [ ] Add post-link hash patching
* [ ] Add encrypted hash table
* [ ] Add randomized check placement
* [ ] Add check-call indirection
* [ ] Add tamper response policy
* [ ] Add anti-patch sentinel
* [ ] Add debugger-resistant control paths
* [ ] Add full correctness test suite
* [ ] Add false-positive benchmark

**Definition of done for L3:**
Tampering or debugging should not be detected by one obvious check.
Checks should be distributed, indirect, guarded and hard to remove cleanly.

---

# 13. Code Virtualization

Current status: missing.
This should be treated as advanced / expensive protection.

## Level 1 — Research Prototype

* [ ] Study xVMP architecture
* [ ] Define Taokari VM scope
* [ ] Choose stack VM or register VM
* [ ] Choose bytecode format
* [ ] Add annotation: `vmp`
* [ ] Add one arithmetic opcode
* [ ] Add one memory opcode
* [ ] Add one branch opcode
* [ ] Add minimal VM interpreter
* [ ] Add one toy test function

## Level 2 — Practical VM

* [ ] Virtualize selected functions
* [ ] Encrypt bytecode
* [ ] Add per-function VM key
* [ ] Add per-function opcode mapping
* [ ] Add handler shuffling
* [ ] Add handler flattening
* [ ] Add bytecode decrypt at runtime
* [ ] Add indirect handler dispatch
* [ ] Add VM correctness tests
* [ ] Add performance benchmark

## Level 3 — Fortress VM

* [ ] Add polymorphic VM builds
* [ ] Add per-function ISA randomization
* [ ] Add encrypted basic-block bytecode
* [ ] Add handler MBA
* [ ] Add handler BCF
* [ ] Add fake opcodes
* [ ] Add fake handlers
* [ ] Add bytecode integrity checks
* [ ] Add anti-frequency-analysis padding
* [ ] Add VM devirtualization test samples
* [ ] Add heavy warning for overhead

**Definition of done for L3:**
Selected functions should not resemble native code logic anymore.
They should require VM reversing before normal logic reversing.

---

# 14. Configuration / Annotations

Current status: partially present.
Goal: make Taokari controllable instead of “all or nothing”.

## Level 1 — Config Documentation

* [ ] Document all current JSON keys
* [ ] Document all current flags
* [ ] Document all current levels
* [ ] Add examples for each pass
* [ ] Add config validation
* [ ] Add error messages for invalid keys
* [ ] Add default config file

## Level 2 — Per-Function Control

* [ ] Add annotation: `fla`
* [ ] Add annotation: `bcf`
* [ ] Add annotation: `mba`
* [ ] Add annotation: `icall`
* [ ] Add annotation: `indbr`
* [ ] Add annotation: `indgv`
* [ ] Add annotation: `strenc`
* [ ] Add annotation: `constenc`
* [ ] Add annotation: `outline`
* [ ] Add annotation: `vmp`
* [ ] Add annotation: `noobf`

## Level 3 — Profiles

* [ ] Add profile: `dev`
* [ ] Add profile: `balanced`
* [ ] Add profile: `strong`
* [ ] Add profile: `fortress`
* [ ] Add per-pass budget system
* [ ] Add max binary size growth limit
* [ ] Add max compile time growth limit
* [ ] Add max runtime overhead target
* [ ] Add config report output
* [ ] Add final build summary

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

* [ ] Record binary size
* [ ] Record compile time
* [ ] Record runtime
* [ ] Record number of transformed functions
* [ ] Record number of transformed instructions
* [ ] Record number of obfuscated strings
* [ ] Record number of obfuscated constants
* [ ] Add CSV output
* [ ] Add JSON output

## Level 3 — Attack-Oriented Verification

* [ ] Run `opt -O2` survival tests
* [ ] Run `opt -O3` survival tests
* [ ] Run LTO survival tests
* [ ] Add decompiler snapshot tests
* [ ] Add string leak tests
* [ ] Add symbol leak tests
* [ ] Add CFG complexity metric
* [ ] Add call graph breakage metric
* [ ] Add regression dashboard
* [ ] Add release-blocking test mode

**Definition of done for L3:**
Every new pass must prove three things: it still runs correctly, it costs an acceptable amount, and it survives obvious cleanup attacks.

---

# 16. Build System / LLVM Future-Proofing

Current status: legacy PM only.
Not urgent, but must be tracked.

## Level 1 — Build Cleanup

* [ ] Remove stale `C:\Arkari` cache assumptions
* [ ] Document `configure-release.ps1`
* [ ] Document `VCPKG_ROOT`
* [ ] Add clean Windows build instructions
* [ ] Add clean Linux build instructions
* [ ] Add CI build check

## Level 2 — New Pass Manager Planning

* [ ] List all legacy passes
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

* [ ] Metadata strip only
* [ ] Light string encryption
* [ ] Light constant encryption
* [ ] No flattening
* [ ] No BCF
* [ ] No MBA
* [ ] No dynamic checks

## Profile: Balanced

Purpose: good protection without insane overhead.

* [ ] Flatten selected functions
* [ ] String encryption L2
* [ ] Constant encryption L2
* [ ] Indirect calls L1/L2
* [ ] Metadata strip L2
* [ ] Light MBA
* [ ] Light BCF

## Profile: Strong

Purpose: serious IP protection.

* [ ] Flattening L2
* [ ] Opaque predicates L2
* [ ] BCF L2
* [ ] MBA L2
* [ ] String encryption L2/L3
* [ ] Constant encryption L3
* [ ] Indirect calls L2/L3
* [ ] Function outlining L2
* [ ] Metadata strip L3

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
* [ ] Full benchmark required
* [ ] Full regression suite required

---

# 18. Suggested Implementation Order

## Milestone 1 — Stabilize Arkari Base

* [ ] Expand tests
* [ ] Add config docs
* [ ] Add size thresholds
* [ ] Add safer skip logic
* [ ] Audit current passes

## Milestone 2 — Add Opaque Predicate Core

* [ ] Implement opaque predicate engine
* [ ] Add optimizer survival tests
* [ ] Integrate with flattening
* [ ] Integrate with future BCF

## Milestone 3 — Add Bogus Control Flow

* [ ] Implement BCF L1
* [ ] Add BCF L2
* [ ] Combine with flattening
* [ ] Benchmark overhead

## Milestone 4 — Add MBA

* [ ] Implement MBA L1
* [ ] Add optimizer resistance
* [ ] Add MBA to decryptors
* [ ] Add hot-loop avoidance

## Milestone 5 — Harden Data Protection

* [ ] StringEnc L2
* [ ] StringEnc L3
* [ ] ConstantEnc L2
* [ ] ConstantEnc L3
* [ ] Metadata strip L3

## Milestone 6 — Add Function Outlining

* [ ] Basic outlining
* [ ] Indirect shard calls
* [ ] Fake shard graph
* [ ] Cross-pass tests

## Milestone 7 — Add Dynamic Protections

* [ ] Runtime checks L1
* [ ] Distributed checks L2
* [ ] Function integrity L3
* [ ] Post-link patching

## Milestone 8 — Optional VM

* [ ] VM prototype
* [ ] Bytecode encryption
* [ ] Per-function ISA
* [ ] Handler obfuscation

---

# 19. Personal Priority List

Most impact for Taokari first:

1. [ ] Opaque predicate engine
2. [ ] Bogus control flow
3. [ ] Stronger flattening
4. [ ] Runtime-mixed constant encryption
5. [ ] StringEnc status hardening
6. [ ] MBA pass
7. [ ] Metadata stripping
8. [ ] Function outlining
9. [ ] Dynamic protections
10. [ ] Optional virtualization

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
