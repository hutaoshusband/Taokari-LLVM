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

Level 1 (infrastructure) only. It documents how the MIR pass is registered
into the legacy pass manager, what flag and annotation control it, what the
Level 1 marker is, and the L2 roadmap. Real transforms (dirty bytes, junk
instructions with side effects, machine instruction substitution, function
splitting) are Level 2 and documented here as the backlog.

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

`-mllvm -taokari-mir=<passes>` — `cl::opt<std::string>`. The value is intended
as a comma-separated list of MIR sub-passes (e.g. `dirtybytes,junk,sub`).
Level 1 treats any non-empty value as "the MIR layer is on".

### Annotation

Per-function control via the standard `llvm.global.annotations` mechanism
(populated by `__attribute__((annotate("...")))`):

- `+mir` — opt the function in, even when the global flag is off.
- `-mir` — opt the function out, overriding a globally-on flag.
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

Level 2 replaces this marker with the real transforms.

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

## Level 2 roadmap (backlog)

The MIR transforms that actually attack Hex-Rays, per the IDA-Pro research
doc §A Level 2:

- **Dirty bytes insertion** — a region of non-instruction bytes guarded by an
  always-taken opaque conditional jump; IDA's linear sweep desynchronises.
- **Junk instructions with real side effects** — valid instructions that write
  scratch state chained into real-looking computation, polluting the
  decompiler's dataflow graph.
- **Machine-level instruction substitution** — replace a single instruction
  with a semantically-equivalent sequence (e.g. `add` → `lea`) at MIR level,
  below the IR simplifier.
- **Function splitting / boundary corruption** — split one function into a
  dispatcher plus shards reachable only via computed jumps, with fake
  prologue/epilogue byte patterns between real functions.
- **Unmodelled instruction emission** — Fortress-profile only; emit
  instructions the microcode lifter has no rule for.

These are gated by the `-taokari-mir=<passes>` comma-list, parsed in Level 2.
