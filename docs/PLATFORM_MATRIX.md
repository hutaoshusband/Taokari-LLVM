# Taokari Platform Feature Matrix

Which obfuscation passes are supported per target platform. The Windows
x64 path is the primary, fully-tested release target. Linux x64 covers the
IR layer. AArch64 covers IR passes; pointer authentication (PAC) on the
indirect path is emitted only when the target actually has the `+pauth`
feature (`armv8.3-a+`), so the indirect passes work on default
`aarch64-linux-gnu` and gain PAC signing on PAC-enabled targets. The
MIR layer is x86-64-only by emission: on Linux x64 (ELF) it is
best-effort — stack-pushing sub-passes are skipped for any function
whose post-PEI code keeps live data below RSP (SysV red zone); the
COFF/Windows path is complete.

Legend: ✅ supported · ⚠️ partial · ❌ unsupported (Windows-only by design)

## IR passes (cross-platform by construction)

These run at the LLVM IR level and are target-independent. They work on any
target once the obfuscator is built for it.

| Pass | Flag | Windows x64 | Linux x64 | AArch64 |
| --- | --- | :---: | :---: | :---: |
| Control-flow flattening | `-taokari-fla` | ✅ | ✅ | ✅ |
| Bogus control flow | `-taokari-bcf` | ✅ | ✅ | ✅ |
| MBA | `-taokari-mba` | ✅ | ✅ | ✅ |
| Opaque predicate engine | (internal) | ✅ | ✅ | ✅ |
| Opaque constants | `-taokari-ocnst` | ✅ | ✅ | ✅ |
| Indirect branch | `-taokari-indbr` | ✅ | ✅ | ✅ |
| Indirect call | `-taokari-icall` | ✅ | ✅ | ⚠️ (pointer-auth path available) |
| Indirect global variable | `-taokari-indgv` | ✅ | ✅ | ✅ |
| String encryption | `-taokari-cse` | ✅ | ✅ | ✅ |
| Integer constant encryption | `-taokari-cie` | ✅ | ✅ | ✅ |
| FP constant encryption | `-taokari-cfe` | ✅ | ✅ | ✅ |
| Function outlining | `-taokari-outline` | ✅ | ✅ | ✅ |
| Metadata / symbol hygiene | `-taokari-meta` | ✅ | ✅ | ✅ |
| Dynamic protections | `-taokari-dyn` | ⚠️ (Win32 APIs) | ⚠️ (ptrace / clock_gettime / `/proc/self/status`) | ❌ (Linux/Win-only) |
| Code virtualization (VM) | `-taokari-vmp` | ✅ | ✅ | ✅ |

## Backend / native passes (target-specific)

| Pass | Flag | Windows x64 | Linux x64 | AArch64 |
| --- | --- | :---: | :---: | :---: |
| MIR fortress (`dirtybytes`,`junk`,`sub`,`split`,`fakeprologue`) | `-taokari-mir=...` | ✅ | ⚠️ (best-effort; red-zone-gated) | ❌ (hook registered, emission x86-only; parity planned, see `MACHINE_IR_AARCH64_PARITY.md`) |
| Native integrity (per-function hash, post-link `.text` patch) | (internal/`-taokari-max`) | ✅ | ⚠️ (ELF `.text` patch via `taokari_postlink_hash.py`) | ❌ |
| Microsoft RTTI eraser | `-taokari-rtti` | ✅ (MSVC ABI) | ❌ (Itanium ABI; no MS RTTI) | ⚠️ (Windows-on-ARM MSVC only) |
| Itanium RTTI eraser | `-taokari-rtti` | ❌ (no Itanium RTTI) | ✅ (rewrites `_ZTS` type-name strings) | ⚠️ (ELF on AArch64) |

## Build & verification status

| Capability | Windows x64 | Linux x64 | AArch64 |
| --- | :---: | :---: | :---: |
| Build (clang/opt) | ✅ | ✅ | ⚠️ (compile; smoke pending) |
| Release-gate suite runs | ✅ | ✅ (cross-platform gates; PE/`LoadLibrary` gates skip) | ❌ |
| Decompiler snapshots (IDA/Ghidra) | ✅ (when installed) | ⚠️ (skips without tool) | ⚠️ |

## Unsupported combinations (explicit)

* **Dynamic protections on AArch64**: the Linux x64 dynamic-protection path
  uses `ptrace`, `clock_gettime` and `/proc/self/status`; only Win32 and
  Linux x64 are emitted today. The pass is off by default everywhere.
* **MIR fortress on Linux/AArch64**: the pre-emission safety gate
  (`assessMirSafety`) rejects, per function: any non-x86-64 target
  (all sub-passes); EH/funclet-shaped functions for the
  structure-sensitive sub-passes (`split`/`fakeprologue`/`sse`/
  `unmodelled`); functions whose entry block is an EH pad for `split`;
  and, on non-COFF (ELF) targets, every stack-pushing sub-pass when
  post-PEI code keeps live values below RSP (SysV red-zone spills).
* **RTTI eraser is ABI-selected**: the MSVC eraser fires on COFF targets,
  the Itanium eraser on ELF targets; each is a no-op on the wrong ABI.

## Notes

* AArch64 indirect-call has a pointer-authentication path; the non-PAC path
  shares the IR-level shard machinery.
* The new-PM bridge (`ObfuscationPassManagerPass`) and the native new-PM
  twins (`MetadataHygieneNewPMPass`, `OpaqueConstantNewPMPass`) are
  target-independent; they fire under the default pipeline on every
  platform the obfuscator is built for.
