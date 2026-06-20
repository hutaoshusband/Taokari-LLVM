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

Level 1 and Level 2. It documents how the MIR pass is registered into the
legacy pass manager, what flag and annotation control it, what the Level 1
marker is, and which Level 2 byte-level transforms are emitted below LLVM IR.

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
- `marker`
- `1`, `on`, `all`, `max` for all Level 2 passes plus the legacy marker

Per-pass probabilities are controlled by:

- `-mllvm -taokari-mir-dirtybytes-prob=<0-100>`
- `-mllvm -taokari-mir-junk-prob=<0-100>`
- `-mllvm -taokari-mir-sub-prob=<0-100>`

### Annotation

Per-function control via the standard `llvm.global.annotations` mechanism
(populated by `__attribute__((annotate("...")))`):

- `+mir` — opt the function in, even when the global flag is off.
- `-mir` — opt the function out, overriding a globally-on flag.
- `+mir:dirtybytes`, `+mir:junk`, `+mir:sub` — opt into one MIR sub-pass.
- `+mir:unmodelled` — opt into Fortress-only unmodelled instruction emission.
- `+mir:fakebounds` — opt into Fortress-only fake prologue/epilogue bytes.
- `-mir:dirtybytes`, `-mir:junk`, `-mir:sub`, `-mir:unmodelled`,
  `-mir:fakebounds` — opt out of one MIR sub-pass.
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

- **Function splitting / boundary corruption** — split one function into a
  dispatcher plus shards reachable only via computed jumps, with fake
  prologue/epilogue byte patterns between real functions.
- **Fake prologue/epilogue byte patterns** — `+mir:fakebounds` emits guarded
  frame-looking bytes that survive into the binary while preserving runtime
  behavior.
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
