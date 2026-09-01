# AArch64 MIR Parity Plan

This plan tracks how the x86-64 Taokari MIR layer becomes an AArch64 MIR layer
without pretending raw x86 byte snippets are portable.

## Scope

AArch64 parity means the MIR framework, gates and tests work for AArch64, with
target-native snippets for each sub-pass. It does not mean byte-for-byte parity.
The same user-facing controls must work:

- `-mllvm -taokari-mir=<passes>`
- `+mir` / `-mir`
- `+mir:<subpass>` / `-mir:<subpass>`
- `-mllvm -verify-machineinstrs`

## Current x86-64 Sub-Passes

| Sub-pass | Current x86-64 behavior | AArch64 parity target |
| --- | --- | --- |
| `marker` | `lea rax, [rax+0]` marker bytes | Side-effecting `hint`/identity marker that survives emission |
| `dirtybytes` | Runtime stack-byte guard over invalid/trap bytes | Conditional branch over unreachable `brk`/raw bytes with NZCV preserved |
| `junk` | Stack byte xor/xor with GPR/RFLAGS preserved | SP-safe paired store/load or scratch-register chain with NZCV preserved |
| `sub` | `lea`/`sub` address arithmetic chain | `add`/`sub` or address-generation chain below IR |
| `unmodelled` | Skipped privileged/SIMD bytes | Explicitly gated skipped system/SIMD bytes, feature checked |
| `split` | Post-RA entry block split into trampoline plus real body | Later target-native block split after branch/liveness rules are audited |

## Implementation Order

1. Split target byte snippets out of `TaokariMachineObf.cpp`.
   Keep the parser and annotation reader target-neutral.
2. Add an AArch64 emission backend.
   It must reject unsupported sub-passes instead of emitting x86 bytes.
3. Hook `TaokariMachineObf` from AArch64 `addPreEmitPass()`.
   Use the same pipeline slot as X86: after register allocation and scheduling.
4. Add AArch64 compile-only tests first.
   Use `-target aarch64-pc-windows-msvc` and `-mllvm -verify-machineinstrs`.
5. Add binary-signature tests for emitted AArch64 snippets.
   Check object bytes, not IR.
6. Add an execution test only when a local AArch64 runner or emulator is present.
   Until then, execution parity is not claimed.

## Safety Rules

- No x86 registers, x86 flags, or x86 raw byte blobs may be shared with AArch64.
- Every AArch64 snippet must either preserve NZCV and touched GPRs or declare a
  safe clobber model.
- `unmodelled` remains explicit opt-in and must stay unreachable at runtime.
- Pointer-auth and branch-target-identification features must be detected before
  any snippet uses related instructions.
- Unsupported feature combinations must skip conservatively, not guess.

## Verification Gates

Required before checking off AArch64 implementation:

- AArch64 target build includes the MIR component and schedules the pass.
- `+mir` annotation emits an AArch64 marker in an object file.
- `-mir` suppresses emission under global `-taokari-mir`.
- Each AArch64 sub-pass has a byte-level object test.
- `-verify-machineinstrs` passes for every AArch64 sub-pass.
- No AArch64 object contains x86 MIR byte signatures.
- Docs list any sub-pass intentionally missing on AArch64.

## Non-Goals

- Do not port `split` in the first AArch64 step.
- Do not use AArch64-only features for x86 parity.
- Do not claim IDA/D810 parity until an AArch64 IDA snapshot exists.

## Status (2026-08-31)

- Step 3 (AArch64 `addPreEmitPass()` hook registration) is done
  (commit `6fbf7db9c`): the pass is scheduled on AArch64 and the
  pre-emission safety gate rejects every sub-pass on non-x86-64
  targets, so the hook is a verified no-op there.
- Steps 1-2 (target-neutral snippet split + AArch64 emission backend)
  are open; no AArch64 byte emission exists.
- Step 6 (execution test) is blocked: this environment has no AArch64
  runtime or qemu user emulation.
