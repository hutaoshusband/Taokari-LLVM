# Taokari Platform Feature Matrix

Which obfuscation passes are supported per target platform. The Windows
x64 path is the primary, fully-tested release target. Linux x64 covers the
IR layer. AArch64 covers IR passes (the pointer-auth indirect path) with the
MIR layer still x86-only.

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
| Dynamic protections | `-taokari-dyn` | ⚠️ (Win32 APIs) | ❌ (Win32-only) | ❌ (Win32-only) |
| Code virtualization (VM) | `-taokari-vmp` | ✅ | ✅ | ✅ |

## Backend / native passes (target-specific)

| Pass | Flag | Windows x64 | Linux x64 | AArch64 |
| --- | --- | :---: | :---: | :---: |
| MIR fortress (`dirtybytes`,`junk`,`sub`,`split`,`fakeprologue`) | `-taokari-mir=...` | ✅ | ❌ (x86/COFF-only) | ❌ (x86-only; parity planned, see `MACHINE_IR_AARCH64_PARITY.md`) |
| Native integrity (per-function hash, post-link `.text` patch) | (internal/`-taokari-max`) | ✅ | ❌ (PE-oriented) | ❌ |
| Microsoft RTTI eraser | `-taokari-rtti` | ✅ (MSVC ABI) | ❌ (Itanium ABI; no MS RTTI) | ⚠️ (Windows-on-ARM MSVC only) |

## Build & verification status

| Capability | Windows x64 | Linux x64 | AArch64 |
| --- | :---: | :---: | :---: |
| Build (clang/opt) | ✅ | ✅ | ⚠️ (compile; smoke pending) |
| Release-gate suite runs | ✅ | ⚠️ (IR-only gates; PE/`LoadLibrary` gates skip) | ❌ |
| Decompiler snapshots (IDA/Ghidra) | ✅ (when installed) | ⚠️ (skips without tool) | ⚠️ |

## Unsupported combinations (explicit)

* **Dynamic protections on non-Windows**: `IsDebuggerPresent`,
  `CheckRemoteDebuggerPresent`, `QueryPerformanceCounter` are Win32; the
  pass is Windows-only and off by default everywhere.
* **MIR fortress on Linux/AArch64**: emits x86 byte snippets and relies on
  COFF section layout; rejected on other targets.
* **Microsoft RTTI eraser on Linux**: there is no MSVC RTTI to erase under
  the Itanium C++ ABI.
* **Native integrity post-link patching on Linux/AArch64**: assumes PE
  `.text` layout and a patched protected native byte trip.

## Notes

* AArch64 indirect-call has a pointer-authentication path; the non-PAC path
  shares the IR-level shard machinery.
* The new-PM bridge (`ObfuscationPassManagerPass`) and the native new-PM
  twins (`MetadataHygieneNewPMPass`, `OpaqueConstantNewPMPass`) are
  target-independent; they fire under the default pipeline on every
  platform the obfuscator is built for.
