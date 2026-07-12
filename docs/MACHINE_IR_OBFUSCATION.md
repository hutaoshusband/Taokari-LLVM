# Machine IR (Backend) Obfuscation

This is the obfuscation layer that runs **below** the LLVM IR layer, in the
codegen pipeline on `MachineFunction` / `MachineInstr`. It is categorically
distinct from every pass under `lib/Transforms/Obfuscation/`, which all run on
LLVM IR and are therefore visible to IR-level tools (`opt`, IR deobfuscators)
and to the Hex-Rays microcode lifter in clean form.

The moat against a professional on IDA Pro 9.2 + D810 is not stronger IR
passes — D810's default rule sets recognise and collapse the classic
OLLVM-class IR patterns. The moat is the MIR layer: passes scheduled in
`TargetPassConfig::addPreEmitPass()` run after register allocation and
scheduling, so any code they emit reaches the final binary and is never given
to an IR-level simplifier in clean form.

## Scope of this document

Level 1 through Level 3. It documents how the MIR pass is registered into the
legacy pass manager, what flag and annotation control it, what the Level 1
marker is, and which byte-level Fortress MIR transforms are emitted below LLVM
IR.

## Where the code lives

```
upstream/taokari/llvm/lib/CodeGen/TaokariMachineObf/
  CMakeLists.txt          builds the LLVMTaokariMachineObf component
  TaokariMachineObf.cpp   the pass (core + legacy wrapper + new-PM wrapper)

upstream/taokari/llvm/include/llvm/CodeGen/
  TaokariMachineObf.h     create*LegacyPass(), initialize*Pass(), new-PM mixin
```

## Legacy pass-manager registration

Taokari is legacy-PM for the codegen pipeline (per `todo.md` §16). The codegen
pipeline is legacy PM by default in LLVM 22, so this is the active path for
`clang` / `llc`.

Registration follows the LLVM-22 dual-PM convention (see
`lib/CodeGen/FEntryInserter.cpp`):

1. `struct TaokariMachineObf { bool run(MachineFunction&); }` — stateful core
   with the gate and the transform.
2. `struct TaokariMachineObfLegacy : public MachineFunctionPass` — legacy
   wrapper. Constructor calls
   `initializeTaokariMachineObfLegacyPass(*PassRegistry::getPassRegistry())`.
   `INITIALIZE_PASS(TaokariMachineObfLegacy, "taokari-mir", ...)` at the
   bottom.
3. `FunctionPass *createTaokariMachineObfLegacyPass()` — the factory called by
   the target's `TargetPassConfig`.
4. `class TaokariMachineObfPass : public PassInfoMixin<...>` — the new-PM
   companion, so the new-PM codegen pipeline (`X86CodeGenPassBuilder`) can
   adopt it without an API change. `isRequired()` is true so an obfuscation
   gate cannot be peephole-pruned away.

The initializer is declared in `include/llvm/InitializePasses.h`:

```cpp
LLVM_ABI void initializeTaokariMachineObfLegacyPass(PassRegistry &);
```

## Pipeline hook

The pass is scheduled in
`lib/Target/X86/X86TargetMachine.cpp`, `X86PassConfig::addPreEmitPass()`,
as the first pass in that stage:

```cpp
void X86PassConfig::addPreEmitPass() {
  addPass(createTaokariMachineObfLegacyPass());
  // ... existing pre-emit passes ...
}
```

`addPreEmitPass()` runs after register allocation and scheduling, so emitted
code survives to the assembler and is not optimised away by IR-level passes.

The X86 target links against the new component via `LINK_COMPONENTS` in
`lib/Target/X86/CMakeLists.txt` (`TaokariMachineObf`), so
`createTaokariMachineObfLegacyPass()` resolves at link time.

## Flag and annotation

### Flag

`-mllvm -taokari-mir=<passes>` — `cl::opt<std::string>`. The value is parsed as
a comma-separated list of MIR sub-passes:

- `dirtybytes`
- `junk`
- `sub`
- `unmodelled` (`unmodeled`, `privileged`, `simd` aliases)
- `fakebounds` (`fakeboundaries`, `fakeprologue`, `fakeprologues` aliases)
- `split` (`functionsplit`, `functionsplitting`, `boundary` aliases)
- `marker`
- `1`, `on`, `all` for all Level 2 passes plus the legacy marker
- `max` for every current MIR sub-pass, including Fortress-only passes

Per-pass probabilities are controlled by:

- `-mllvm -taokari-mir-dirtybytes-prob=<0-100>`
- `-mllvm -taokari-mir-junk-prob=<0-100>`
- `-mllvm -taokari-mir-sub-prob=<0-100>`
- `-mllvm -taokari-mir-sse-prob=<0-100>` (Fortress-only body-walking anti-lift)
- `-mllvm -taokari-mir-split-prob=<0-100>`
- `-mllvm -taokari-mir-fakeprologue-prob=<0-100>`

Every probability is an integer in `0..100`; out-of-range values fail
compilation with an actionable diagnostic. `0` means the sub-pass never fires,
`100` means every MIR-enabled function is considered. Decisions are
deterministic: `stablePercentHit` hashes `<function>:<subpass>` so a fixed
seed/module/triple reproduces the same set of transformed functions.

Safety and diagnostics flags:

- `-mllvm -taokari-mir-verbose` — emit human-readable skip/fallback diagnostics
  (default off; release builds stay silent).
- `-mllvm -taokari-mir-release-verify` — run the MachineVerifier after every
  MIR transform and report failures (default on; belt-and-suspenders
  post-condition). The pre-emit safety gate is what guarantees no corrupted
  output.
- `-mllvm -taokari-mir-strict` — make a post-transform verifier failure fatal
  (CI/lab use; default off).
- `-mllvm -taokari-mir-reproducer-dir=<dir>` — on a verifier failure, write a
  reduced `.mir` dump plus a JSON metadata sidecar (function, target triple,
  source module basename, MIR flag, strict mode) with absolute paths stripped.

### Annotation

Per-function control via the standard `llvm.global.annotations` mechanism
(populated by `__attribute__((annotate("...")))`):

- `+mir` — opt the function in, even when the global flag is off.
- `-mir` — opt the function out, overriding a globally-on flag.
- `+mir:dirtybytes`, `+mir:junk`, `+mir:sub` — opt into one MIR sub-pass.
- `+mir:unmodelled` — opt into Fortress-only unmodelled instruction emission.
- `+mir:fakebounds` — opt into Fortress-only fake prologue/epilogue bytes.
- `+mir:split` — opt into Fortress-only entry block splitting / boundary
  trampoline emission.
- `-mir:dirtybytes`, `-mir:junk`, `-mir:sub`, `-mir:unmodelled`,
  `-mir:fakebounds`, `-mir:split` — opt out of one MIR sub-pass.
- Both on the same function — the pass logs a warning and skips (conservative).

The annotation reader (`readMirAnnotations`) mirrors the IR-layer
`ObfuscationOptions::readAnnotate` but is kept local and dependency-free: the
codegen component must not depend on the IR Obfuscation library.

### Gate resolution

`shouldObfuscate(Function &)`:

1. Skip declarations and `available_externally`.
2. `+mir` present → run (annotation opt-in).
3. `-mir` present → skip (annotation opt-out).
4. Otherwise follow the global `-taokari-mir` flag.

## Level 1 marker

Level 1 is **infrastructure only**. To prove the entire plumbing (flag →
annotation reader → gate → `addPreEmitPass` scheduling → `BuildMI` emission →
assembler) works without changing program semantics, the pass inserts one
semantically-neutral marker at the entry of every opted-in function:

```
lea rax, [rax+0]    ; bytes 48 8D 40 00
```

This writes `rax` with `rax+0` (the same value) and touches no flags or
memory, so it is a no-op. The `+0` displacement encoding is deliberately
chosen: clang's own prologue/epilogue and alignment padding never produce
`lea rax, [rax]` (the optimizer folds the `+0` away into a bare `[rax]`),
and every nop encoding (0x90, the 0F 1F .. family) collides with the
compiler's own optnone leading bytes and alignment padding. Detecting
`lea rax, [rax]` as the first instruction of a function is therefore a
reliable, non-vacuous signal that the pass fired.

The marker is marked `InlineAsm::Extra_HasSideEffects` so later machine-level
passes cannot delete this no-output inline asm as dead. The instruction is
still a no-op, so the side-effect flag cannot change program semantics.

Specific Level 2 sub-pass lists omit this marker. Legacy `1`/`all`/`max` keep it
for the Level 1 smoke test while also enabling the real transforms.

## Level 2 transforms

Level 2 emits x86-64 inline-asm byte snippets at the function entry, after
register allocation and before final emission. The snippets preserve the GPRs
and RFLAGS they touch while still surviving as side-effecting machine code.

- **Dirty bytes:** `pushfq; push rax; mov al, [rsp]; xor al, imm8; xor al, imm8;
  cmp al, [rsp]; je +8; <dead invalid/trap bytes>; pop rax; popfq`. The guard
  depends on runtime stack contents while remaining net-neutral, and the skipped
  bytes survive in the binary.
- **Junk with side effects:** `pushfq; push rax; xor byte ptr [rsp], imm8; xor
  byte ptr [rsp], imm8; pop rax; popfq`. The stack writes are real but net
  neutral.
- **Substitution:** `pushfq; push rax; mov rax, rsp; lea rax, [rax+0x13]; sub
  rax, 0x13; pop rax; popfq`. The `lea` performs machine-level add-like address
  arithmetic below the IR simplifier.
- **Unmodelled instructions:** explicit `unmodelled` opt-in emits a skipped
  `vmcall` plus VEX-coded SIMD byte sequence. The guard preserves runtime
  behavior; the bytes exist only to poison lifters that decode through them.
- **Fake bounds:** explicit `fakebounds` opt-in emits a skipped
  `push rbp; mov rbp, rsp; sub rsp, 0x20; leave; ret; push rbp; ...` byte
  sequence. Runtime skips it, but disassemblers see plausible function prologue
  and epilogue patterns in the final code stream.
- **Function split / boundary trampoline:** explicit `split` opt-in creates a
  new machine body block after register allocation and moves the original entry
  instructions into it. The first block becomes a tiny
  side-effecting `pushfq; popfq` marker plus an unconditional jump to the real
  body. This is distinct from IR outlining: the split is introduced after IR
  optimizers and IR deobfuscators have already lost visibility.

## Verification

`testing/scripts/verify_machine_obf_level1.py` exercises every gate axis plus
functional correctness:

- Plain vs obfuscated linked executables produce identical stdout (the marker
  is a no-op).
- `+mir` annotation: marker present with and without the global flag.
- `-mir` annotation: marker absent even with the global flag on.
- No annotation: marker present iff the global flag is on.

It disassembles the `.obj` (which keeps symbol names, unlike a stripped PE)
and checks the first instruction of each function.

`testing/scripts/verify_machine_obf_level2.py` checks:

- plain and MIR-obfuscated executables produce identical stdout.
- each sub-pass emits its byte signature and no other sub-pass signature.
- `+mir:<subpass>` annotations work without the global flag.
- `-mllvm -verify-machineinstrs` accepts the post-RA output.
- optimized LLVM IR contains none of the MIR byte signatures, while the object
  file does.

`testing/scripts/verify_machine_obf_l3_budget.py` gates the Fortress MIR budget:

- plain and MIR-obfuscated executables produce identical stdout.
- the MIR path compiles with `-verify-machineinstrs`.
- obfuscated compile time must stay under `6x + 15s` versus plain by default.
- obfuscated binary size must stay under `1.25x + 32 KiB` versus plain by
  default.

`testing/scripts/verify_machine_obf_l3_dirty_guard.py` checks the Fortress
dirty-byte guard:

- plain and MIR-obfuscated executables produce identical stdout.
- the object contains the runtime stack-byte guard.
- the old fixed `cmp rsp, rsp` guard is absent.

`testing/scripts/verify_machine_obf_l3_unmodelled.py` checks the Fortress
unmodelled-instruction gate:

- plain and MIR-obfuscated executables produce identical stdout.
- `+mir:unmodelled` emits the privileged/SIMD byte sequence.
- the normal `dirtybytes,junk,sub` MIR set does not emit it.

`testing/scripts/verify_machine_obf_l3_fakebounds.py` checks the Fortress fake
prologue/epilogue gate:

- plain and MIR-obfuscated executables produce identical stdout.
- `+mir:fakebounds` and `-taokari-mir=fakebounds` emit the fake frame byte
  sequence.
- the normal `dirtybytes,junk,sub` MIR set does not emit fake boundary bytes.

`testing/scripts/verify_machine_obf_l3_function_split.py` checks the Fortress
function-splitting / boundary-trampoline gate:

- plain and MIR-split executables produce identical stdout.
- `+mir:split` and `-taokari-mir=split` emit a split entry trampoline.
- the normal `dirtybytes,junk,sub` MIR set does not emit the split boundary
  marker.

`testing/scripts/verify_machine_obf_l3_ida_snapshot.py` checks the local
Hex-Rays before/after snapshot:

- a plain exported fixture function decompiles to the clean source-like return.
- the Fortress MIR build decompiles to a longer pseudocode snapshot with
  visible flags noise.
- the verifier uses `TAOKARI_IDA` when set, otherwise the local IDA install.
- `--require-ida92-d810` turns the smoke test into the exact lab gate and fails
  unless IDA reports kernel version 9.2 and D810 is visible to IDAPython.
- `--require-function-confusion` gates the final DoD shape: the protected
  export must stop being recognized as a function or must fail decompilation.

`testing/scripts/verify_machine_obf_l3_cross_pass.py` checks cross-pass
integration:

- a branch/switch-heavy fixture compiles and runs with IR flattening, BCF,
  indirect-branch obfuscation, and MIR `dirtybytes,junk,sub`.
- `-verify-machineinstrs` accepts the combined pipeline.
- the final object still contains all requested MIR byte signatures after the
  IR passes run.

`testing/scripts/verify_machine_obf_l3_cfg_fragmentation.py` checks the local
CFG-fragmentation proxy:

- plain and IR+MIR-obfuscated executables produce identical stdout.
- `llvm-objdump -d` on the final objects shows increased branch-like control
  transfers.
- the obfuscated object contains trap/unknown fragmenters from skipped dirty
  bytes.

`testing/scripts/verify_machine_obf_l3_aarch64_plan.py` checks the tracked
AArch64 parity plan in `docs/MACHINE_IR_AARCH64_PARITY.md`.

## Level 3 roadmap (backlog)

The remaining MIR transforms that attack Hex-Rays function recovery, per the
IDA-Pro research doc §A Level 3:

- **Function splitting / boundary corruption** — `+mir:split` splits the
  machine entry block into a trampoline plus real body after register
  allocation. Full multi-shard dispatcher splitting remains a later hardening
  step.
- **Fake prologue/epilogue byte patterns** — `+mir:fakebounds` emits guarded
  frame-looking bytes that survive into the binary while preserving runtime
  behavior.
- **Hex-Rays snapshot gate** — `verify_machine_obf_l3_ida_snapshot.py` records
  plain vs Fortress MIR pseudocode and gates on measurable decompiler noise.
  `--fixture sse` snapshots the SSE string-op fixture (`testing/cases/
  sse_string`) whose plain decompile shows the textbook `case N: shift by N`
  SSE dispatch, and asserts the obfuscated function has zero IDA
  `switch_sites` plus substantial pseudocode growth.
- **SSE body-walking anti-microcode-lift** — planned `+mir:sse` Fortress
  sub-pass. The current `unmodelled` blob emits guarded bytes at function
  entry only; Hex-Rays' CFG-directed microcode lifter skips past it and
  cleanly lifts the SSE ops (`psrldq`/`pcmpeqb`/`pmovmskb`) inside the body.
  `+mir:sse` will scatter non-foldable `rdrand`-seeded `x*(x+1)` guards plus
  modeled-SSE dead bytes across the function body so the lifter cannot prune
  them. Tracked as the §21 L3 backlog item.
- **Unmodelled instruction emission** — explicit `unmodelled` opt-in emits
  skipped privileged/SIMD bytes the microcode lifter may not model.
- **Runtime-dependent dirty-byte guards** — dirty-byte branches depend on live
  architectural state instead of a fixed `cmp rsp, rsp` signature.
- **Cross-pass integration** — `verify_machine_obf_l3_cross_pass.py` proves MIR
  emission survives alongside IR flattening, BCF and indirect branches.
- **CFG fragmentation metric** — `verify_machine_obf_l3_cfg_fragmentation.py`
  gates an object-level branch/fragmenter count as a local proxy for harder
  graph recovery.
- **Budget gate** — `verify_machine_obf_l3_budget.py` blocks pathological
  compile-time and binary-size growth while Fortress MIR expands.
- **AArch64 parity plan** — `docs/MACHINE_IR_AARCH64_PARITY.md` defines the
  target-native port sequence and safety gates.

These remain gated future work, not part of the current Level 2 pass.

## Phase A: IR-stack coverage for SSE string functions

The MIR layer only attacks code that survives below the IR layer; the IR
obfuscation stack (`-taokari-fla` L4, `-taokari-bcf`, `-taokari-mba`,
`-taokari-cie` L2, `-taokari-icall`) destroys the *dispatch* of an SSE
string function at the IR layer before it ever reaches codegen. The
full-stack recipe that addresses complaints 1, 3, 4, 5, 6, 7, 8 of the SSE
audit is captured in `testing/scripts/verify_sse_string_protection.py`:

```
-mllvm -taokari \
  -mllvm -taokari-fla -mllvm -taokari-level-fla=4 \
  -mllvm -taokari-bcf  -mllvm -taokari-level-bcf=2 \
  -mllvm -taokari-mba  -mllvm -taokari-level-mba=1 \
  -mllvm -taokari-cie  -mllvm -taokari-level-cie=2 \
  -mllvm -taokari-icall \
  -mllvm -taokari-mir=split
```

Verified against `testing/cases/sse_string/src/main.c`: the obfuscated IR
contains no `switch`, the obfuscated `.obj` no longer exposes the clean
`psrldq $N` jump-table dispatch, and the IDA Hex-Rays decompile grows
7x+ with zero `switch_sites` remaining. Complaint 2 (SSE intrinsics still
modeled cleanly inside each flattened block) is the remaining gap that
the `+mir:sse` Phase B pass above closes.

## Level 4: config, safety, and decompiler-resistance hardening

Level 4 completes the per-sub-pass config surface, adds the release-mode
safety framework, extends the decompiler-resistance families, and adds the
snapshot / metric tooling. It is conservative by default: every new behaviour
either preserves the previous output or is gated behind an explicit flag.

### Per-sub-pass probability config

Every transform-bearing sub-pass now has a `-taokari-mir-<pass>-prob` knob
(`dirtybytes`, `junk`, `sub`, `sse`, `split`, `fakeprologue`). Probabilities
are validated at `0..100`; out-of-range values fail compilation with an
actionable `out of range` diagnostic before any transformation runs
(`validateMirProbabilities`).

### Per-function annotation selection

`+mir:<pass>` / `-mir:<pass>` are parsed by a table-driven reader
(`mirSubpassNames` / `applySubpassToken`). Multiple sub-passes can be selected
on one function. Unknown sub-pass names emit a `warning: taokari-mir: unknown
+mir:<name> annotation` diagnostic per the repo unknown-key policy
(matching `ObfuscationOptions`).

Precedence:

1. Hard safety gate (`assessMirSafety`) always wins — an unsafe function is
   never transformed.
2. `-mir` (bare) or any `-mir:<pass>` disables that transform.
3. `+mir:<pass>` enables that transform for the function.
4. The global `-taokari-mir=<passes>` flag applies when no annotation
   overrides.
5. Documented defaults apply last.

### Safety gate and unsafe-function fallback

`assessMirSafety(MF, Passes)` runs before any transform and refuses functions
that are unsafe to transform. An unsafe skip is a successful outcome: the
function is left untouched, compilation continues, and the skip is observable
with `-taokari-mir-verbose`.

Refused function shapes:

- non-x86-64 targets (the byte blobs are x86-64 specific);
- missing target instr info;
- EH/funclet/personality functions for structure-sensitive sub-passes
  (`split`, `fakeprologue`, `sse`, `unmodelled`) — their unwind tables and
  funclet ABI constrain instruction placement;
- an EH-pad entry block for `split`.

### Post-RA verifier gate (release mode)

When `-taokari-mir-release-verify` is on (default), the pass runs
`MF.verify(..., AbortOnError=false)` after every transform. A failure is
reported with an actionable diagnostic naming the function; with
`-taokari-mir-strict` it becomes a hard abort for CI/lab use. The pre-emit
safety gate is what guarantees no corrupted output reaches the assembler; the
verifier gate is the belt-and-suspenders post-condition.

Debug builds already get the verifier via `-verify-machineinstrs`; the explicit
flag makes it a release-mode contract.

### Crash reproducer minimizer

With `-taokari-mir-reproducer-dir=<dir>`, a post-transform verifier failure
writes `<dir>/<function>.mir` (a `MachineFunction::print` dump) plus
`<dir>/<function>.repro.json` (function name, fail reason, target triple,
source module basename, MIR flag, strict mode). Absolute paths are stripped to
the basename so the artifact does not leak local layout. The `.mir` reproducer
feeds straight back into `llc` / `llvm-mca` for reduction.

### Substitution and dirty-byte families

The `sub` and `dirtybytes` sub-passes now rotate across a family of
semantically-neutral, verifier-clean variants per function (hash-selected, so
deterministic under a fixed module name):

- `sub`: `lea +0x13 / sub 0x13` (add-via-lea identity), double-`neg`
  identity, double-`not` identity (the `not` form is flag-free).
- `dirtybytes`: `rsp*(rsp+1)` even-parity guard, `rsp*(rsp-1)` variant,
  `rsp<<1` low-bit-clear guard — all runtime-dependent (rsp unknown to static
  analysis), each preserving the GPRs/RFLAGS they touch via push/pop framing.

Function-boundary confusion (`split`) and fake prologue/epilogue patterns
(`fakebounds`) are the existing Fortress sub-passes; they are target-gated,
refuse EH/funclet functions via the safety gate, and pass the verifier gate.

### Snapshot comparison and the boundary fragmentation metric

- `verify_machine_obf_l3_ida_structural.py` runs IDA headlessly on plain vs
  MIR-obfuscated builds and captures module-wide structural metrics (function
  count, total function bytes, mean size, decompiler success/fail) as JSON,
  asserting the MIR build grows total function bytes without breaking
  decompilation. Honours `TAOKARI_IDA`; skips with exit 2 when absent.
- `verify_machine_obf_l3_ghidra_structural.py` mirrors the above on Ghidra
  `analyzeHeadless`. Honours `TAOKARI_GHIDRA` or `analyzeHeadless` on PATH;
  skips gracefully when Ghidra is absent (optional / tool-dependent).
- `verify_machine_obf_l3_boundary_metric.py` is the binary-level function
  boundary fragmentation metric: it counts entry-point unconditional-jump
  trampolines (the `split` signature) and guarded fake-prologue byte sequences
  (the `fakebounds` signature) from symbol-bearing `.obj` artifacts. The
  metric distinguishes intended fragmentation (plain = 0, MIR > 0) from noise
  and from correctness failure (identical stdout).

### Test inventory (Level 4)

| Test | Covers |
| --- | --- |
| `verify_machine_obf_l3_subpass_config.py` | C1.5/C1.6 split + fakeprologue probability |
| `verify_machine_obf_l3_annotation.py` | C1.7 per-function annotation selection |
| `verify_machine_obf_l3_config_validation.py` | C1.8 probability bounds validation |
| `verify_machine_obf_l3_unsafe_fallback.py` | C2.3 safety gate + fallback |
| `verify_machine_obf_l3_release_verifier.py` | C2.2 release verifier gate |
| `verify_machine_obf_l3_reproducer.py` | C2.4 reproducer minimizer |
| `verify_machine_obf_l3_liveness.py` | C2.1 liveness across every sub-pass |
| `verify_machine_obf_l3_large_smoke.py` | C2.5 large C++ binary smoke (extended) |
| `verify_machine_obf_l3_substitution_family.py` | C3.1 substitution family |
| `verify_machine_obf_l3_dirty_family.py` | C3.2 dirty-byte family |
| `verify_machine_obf_l3_boundary_metric.py` | C3.3/C3.4/C3.7 boundary metric |
| `verify_machine_obf_l3_ida_structural.py` | C3.5 IDA structural snapshot |
| `verify_machine_obf_l3_ghidra_structural.py` | C3.6 Ghidra structural snapshot |

### Known unsupported targets / function shapes

- Non-x86-64 targets: every byte blob is x86-64 specific; the pass is a no-op
  elsewhere (AArch64 parity is tracked in `MACHINE_IR_AARCH64_PARITY.md`).
- EH / funclet / personality functions: refused for `split`, `fakeprologue`,
  `sse`, `unmodelled` (unwind-table / funclet-ABI constraints).
- EH-pad entry blocks: refused for `split`.

