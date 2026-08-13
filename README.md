# Taokari LLVM - Built to survive the post-D810 era

![Taokari](docs/Taokari_Banner.png)

![LLVM](https://img.shields.io/badge/LLVM-22.1.2-blue)
![Platform](https://img.shields.io/badge/platform-Windows%20x64%20%28clang--cl%29-informational)
![Pass Manager](https://img.shields.io/badge/codegen-legacy%20PM%20%2B%20new--PM%20wrapper-orange)
![License](https://img.shields.io/badge/license-Apache--2.0%20%2B%20LLVM%20exceptions-green)

Taokari is my fork of [Arkari](https://github.com/komimoe/Arkari), itself in
the Goron / Hikari / OLLVM lineage, focused on one question:

> **What makes an obfuscator survive a serious analyst on IDA Pro 9.2 + D810?**

Not more IR passes — D810 folds those, and the Hex-Rays microcode lifter sees every IR
pass clean. Taokari moves the fight somewhere they can't reach: below the IR optimizer,
into a bytecode VM, and behind runtime integrity checks that refuse to be patched.

---

## Why Taokari and not Arkari?

I started from Arkari and kept the parts that matter: flattening, indirect calls,
indirect branches, indirect globals, constant and string encryption, MSVC RTTI hiding,
and the Windows SEH / funclet handling. Then I added the parts Arkari does not have:
backend obfuscation after register allocation, stronger IR transforms, metadata cleanup,
literal max protection, and selected-function VM protection.

### Machine-IR backend obfuscation

This is a `MachineFunctionPass` scheduled in `X86PassConfig::addPreEmitPass()`,
after register allocation and scheduling. The emitted bytes are produced below the LLVM
IR optimizer, so IR cleanup passes cannot simplify them away before code generation.

| Sub-pass | What it emits (x86-64, net-neutral, side-effecting) | Defeats |
| --- | --- | --- |
| `dirtybytes` | `pushfq; push rax; mov al,[rsp]; xor al,imm8; xor al,imm8; cmp al,[rsp]; je +8; <dead ud2/int3/lock bytes>; pop rax; popfq` | Linear-sweep disassemblers (the skipped trap bytes desync them); the `je` is a true runtime opaque predicate — `al` was XOR'd with the same value twice |
| `junk` | `pushfq; push rax; xor byte ptr [rsp],imm8; xor byte ptr [rsp],imm8; pop rax; popfq` | Naive dataflow that assumes stores are meaningful |
| `sub` | `pushfq; push rax; mov rax,rsp; lea rax,[rax+0x13]; sub rax,0x13; pop rax; popfq` | Microcode lifters that must model `lea`+`sub` as address arithmetic |
| `unmodelled` *(Fortress only)* | Same runtime guard, then a skipped `vmcall` + a VEX-coded SIMD byte sequence | Microcode lifters with incomplete privileged/VEX modelling |

```text
lib/CodeGen/TaokariMachineObf/TaokariMachineObf.cpp        # the pass (legacy + new-PM wrappers)
include/llvm/CodeGen/TaokariMachineObf.h                    # create*LegacyPass(), isRequired()=true
lib/Target/X86/X86TargetMachine.cpp  :: addPreEmitPass()    # the pipeline hook
```

Notes:

- **x86_64-only.** Gated by `getTargetTriple().isX86_64()`; the emitted bytes use REX
  prefixes and 64-bit registers. No AArch64 hook exists yet.
- **Per-sub-pass config.** `-taokari-mir=dirtybytes:75,junk:50,sub:40,split,
  fakeprologue` — the numeric suffix is the apply probability, and per-function
  annotation parsing (`+mir:dirtybytes`) selects sub-passes per function.
- **Dual pass-manager registration**: legacy `MachineFunctionPass` (the live codegen path
  today) plus a new-PM `PassInfoMixin` companion with `isRequired() = true`, so an
  obfuscation gate cannot be peephole-pruned away. The new-PM codegen pipeline hook is
  not yet wired in `X86CodeGenPassBuilder` — only the legacy `addPreEmitPass` path is
  live. See [`docs/MACHINE_IR_OBFUSCATION.md`](docs/MACHINE_IR_OBFUSCATION.md).

### Optimizer-resistant IR transforms

Arkari's IR passes are strong but honest — a clean switch dispatcher, pure
constant-expression encryption that an aggressive optimizer can re-fold. Taokari adds
transforms that survive the LLVM cleanup pipeline:

- **Opaque predicates that survive `opt -passes=instcombine,simplifycfg`.** The unfoldable
  family is `x*(x+1)` is always even (among two consecutive integers one is even) — there
  is no InstCombine rule that proves it, and at Level 2 the seed is a runtime value so it
  cannot be folded. Seeded from six context kinds: algebraic / pointer / stack /
  global / environment / runtime-nonce. Verified non-vacuously by
  `testing/scripts/verify_opaque_predicates_level2.py` (an algebraic predicate over a
  constant global *must* fold — the control — proving the survival test is real).
- **Runtime-mixed constant encryption.** A module-wide mutable nonce
  (`__taokari_const_nonce`, no constant initializer to fold against) loaded **volatilely**,
  mixed into the decryptor twice plus an optional MBA-wrapped final add. This is what makes
  constant encryption survive `-O2`/LTO; the level 0-1 chain alone does not.
- **String encryption with an encrypted sentinel and a per-string key schedule.** No
  plaintext "decrypted?" flag — two random non-equal status tokens. Per-build nonce, random
  key length (8-32 bytes), position- and key-index-dependent mixing, randomised
  decryptor branch shape, optional stack/heap/re-encrypt-after-use placement.
- **Level-4 flattening with no jump table.** A bucketed two-stage probe dispatcher, or an
  `indirectbr`-backed dispatcher, that emits nothing IDA's switch-info recovery can grab —
  regression-checked inside IDA (`ida_switch_recovery_check.py` asserts zero switch-info
  sites). Plus per-function state encoding, per-basic-block random case IDs, opaque-gated
  fake cases, and a Fortress (Level 3) mode with polymorphic dispatcher layouts and cloned
  fake-successor chains.
- **Bogus control flow** with the unfoldable `x*(x+1)` guard, Level-2 fake-body mutation,
  and configurable placement before/after flattening (`-taokari-bcf-before-fla` /
  `-taokari-bcf-after-fla`).
- **MBA** — `add`/`sub`/`xor`/`and`/`or` substitution with `IRBuilder<NoFolder>`;
  L2 adds multi-round, opaque-constant, and runtime-nonce-mixed identities.

---

## IR obfuscation passes

All passes live under `upstream/taokari/llvm/lib/Transforms/Obfuscation/`. Enable flags
exist in two namespaces: `-irobf-*` (Arkari-compatible, canonical) and `-taokari-*`
(aliases pointing at the same `cl::opt`). Level-aware passes take `-level-<pass>=N`,
capped at 4.

| Pass | Enable | Level | What's beyond stock Arkari |
| --- | --- | --- | --- |
| **fla** — control-flow flattening | `-irobf-fla` | 0-4 | Rolling-XOR dispatch state, per-function state key, random per-BB case IDs, opaque-gated fake cases, Fortress polymorphic dispatchers (L3), **no-jump-table / indirectbr dispatchers (L4)** that defeat IDA switch recovery |
| **bcf** — bogus control flow | `-irobf-bcf` | 0-4 | *(Taokari addition)* Unfoldable `x*(x+1)` guard seeded from a runtime nonce, L2 fake-body mutation, before/after-fla placement, internal `NoInline`+`OptimizeNone` junk function |
| **mba** — mixed boolean arithmetic | `-irobf-mba` | 0-4 | *(Taokari addition)* `add`/`sub`/`xor`/`and`/`or` identities, `IRBuilder<NoFolder>`, `-taokari-mba-prob`, multi-round L2 with runtime-nonce-mixed identities, applied to flattening dispatch-state updates |
| **cie** — constant int encryption | `-irobf-cie` | 0-3 | Runtime-mixed decryptor (`-taokari-const-volatile-seed`), optional `-taokari-const-decryptor-mba`, per-function dedup cache |
| **cfe** — constant FP encryption | `-irobf-cfe` | 0-3 | Same runtime-mixing and MBA decryptor as `cie` |
| **cse** — string encryption | `-irobf-cse` | — | Encrypted sentinel, per-build nonce, per-string key schedule, randomised decryptor shape, stack/heap/re-encrypt placement, UTF-16 support |
| **icall** — indirect calls | `-irobf-icall` | 0-4 | Two-tier page table, `maskCipher` 16-transform cipher, AArch64 PAC re-signing path (key 0), per-function dedup cache |
| **indbr** — indirect branches | `-irobf-indbr` | 0-4 | Two-tier page table, critical-edge splitting, AArch64 PAC path |
| **indgv** — indirect globals | `-irobf-indgv` | 0-4 | Two-tier page table, skips thread-local/DLL-import/EH globals, AArch64 PAC key 2 (data) |
| **rtti** — MSVC RTTI eraser | `-irobf-rtti` | — | BLAKE3-keyed type-name rewrite (requires `randomSeed` in config) |
| **meta** — metadata hygiene | `-irobf-meta` | 0-4 | Strips `llvm.ident`/debug/source-path metadata, renames internal helper symbols, supports export allowlists, and randomizes helper sections for PE/ELF/Mach-O at L3 |
| **vmp** — selected-function virtualization | `-irobf-vmp` | 0-3 | *(Taokari addition)* `+vmp` functions lower to bytecode and an interpreter; current work includes pointer support, per-function interpreter diversity, runtime-derived keys, opcode permutation tables, indirect handler dispatch, fake handlers, runtime traps, INT_MIN/-1 div/rem overflow guards, memcpy/memset/memmove intrinsics, multi-index/struct GEP, raw switch lowering, void functions, direct + indirect pointer calls, function splitting around unsupported IR, a per-function compatibility report, DLL load + manual-map validation, and IDA/Hex-Rays inspection gates |

### Per-function control

Standard LLVM annotation mechanism, resolved by `toObfuscate`:

```c
// Enable + force level 4 on one function:
__attribute__((annotate("+fla ^fla=4")))

// Opt out of a pass on one function:
__attribute__((annotate("-mba")))

// The MIR layer has its own grammar (+mir / -mir / +mir:dirtybytes / +mir:unmodelled):
__attribute__((annotate("+mir:unmodelled")))
```

### A worked example

Literal maximum protection, including every current IR pass, VMP,
metadata/RTTI hygiene, and every current MIR/backend sub-pass:

```bat
clang -O2 -mllvm -taokari-max main.c -o main_max.exe
```

```bat
:: IR layer: enable flattening, bogus control flow, MBA, constant/string encryption,
:: and indirect call/branch/globals — all at the max capped level.
clang -O2 -mllvm -taokari ^
    -mllvm -taokari-fla  -mllvm -taokari-level-fla=4 ^
    -mllvm -taokari-bcf  -mllvm -taokari-level-bcf=2 ^
    -mllvm -taokari-mba  -mllvm -taokari-mba-prob=40 ^
    -mllvm -taokari-cie  -mllvm -taokari-level-cie=2 ^
    -mllvm -taokari-cfe  -mllvm -taokari-level-cfe=2 ^
    -mllvm -taokari-cse  -mllvm -taokari-icall -mllvm -taokari-indbr ^
    -mllvm -taokari-indgv -mllvm -taokari-rtti ^
    -mllvm -taokari-meta -mllvm -taokari-level-meta=3 ^
    -mllvm -taokari-cfg=configs/my_project.json ^
    main.c -o main_obf.exe

:: Machine-IR layer: dirty bytes + junk + instruction substitution (below the IR layer).
clang -O2 -mllvm -taokari-mir=dirtybytes,junk,sub main.c -o main_mir.exe
```

Or via the MSVC ABI driver: swap `clang` for `clang-cl` and use `/std:` / `/EHsc`.

### Recommended default: Tier B (strong blanket, no VMP)

For most binaries the right starting point is the **strong blanket**
recipe (Tier B in `docs/TIERS.md`): every cheap, IDA-visible pass applied
globally, VMP off. The blanket makes non-VMP'd regions look noisy in IDA
without paying for VM virtualisation. The one-line entry point is
`build_strong.bat`:

```bat
build_strong.bat               :: demo target
build_strong.bat my_app.c      :: your source
```

Add VMP later by annotating 1-N sensitive functions in source with
`__attribute__((noinline, annotate("+vmp")))` and re-running the script;
the VMP budget caps (Section 22 Phase 1) refuse runaway functions for
you. That grows the build toward Tier C (`build_max_protection.bat`).

`-mllvm -taokari-max` is safe to combine with `-mllvm -taokari-vmp`
since Section 22 Phase 1: the same caps budget it. Pass
`-mllvm -taokari-max-no-vmp` to keep every other max-strength pass on
while forcing VMP off entirely.

---

## Build

Taokari builds with CMake + Ninja against `upstream/taokari/llvm` into
`build/taokari-local/`. The build cache is git-ignored (several GB, machine-specific).

**Prerequisites:** Visual Studio 2026 with the C++ workload, Ninja, and a configured
`VCPKG_ROOT` pointing at the static `x64-windows-static` triplet (for `zlib`/`libLZMA`/
`libxml2`).

| Script | When to use |
| --- | --- |
| `scripts\configure-release.ps1` | **First-time configure.** Sets up CMake (Ninja, Release, `clang;clang-tools-extra;lld;lldb`, targets `X86;AArch64`, runtimes `compiler-rt;openmp`, MultiThreaded static runtime). Requires `VCPKG_ROOT`. |
| `scripts\build-cached.ps1` | Incremental build once the cache exists. Errors if `build\taokari-local` is missing. Prints `clang --version` on success. |
| `scripts\build-clang.cmd` | One-shot `ninja clang opt llvm-config` after sourcing `VsDevCmd.bat`. |
| `scripts\build-external.cmd [JOBS]` | Spawn a background build in its own console window. |
| `scripts\build-status.cmd` | Print the most recent `build-logs\taokari-build-*.log`. |
| `scripts\build-stop.cmd` | Kill running `ninja`/`cl`/`cmake` processes. |

```bat
:: 1. Configure (once) — from a VS x64 Native Tools shell, with VCPKG_ROOT set:
powershell -ExecutionPolicy Bypass -File scripts\configure-release.ps1

:: 2. Incremental build:
scripts\build-clang.cmd
```

---

## Testing

The harness compiles every case twice (plain + obfuscated) with the locally-built Taokari
clang, runs the binaries, and checks stdout + exit code against golden strings. It refuses
any compiler that isn't `build\taokari-local\bin\clang.exe`.

```powershell
python testing\run_obfuscation_tests.py --keep-going
```

**Matrix axes:**

- `--mode {default|o2|lto|clangcl}` (repeatable; default: all) — `-O2`, `-flto -fuse-ld=lld`,
  and the `clang-cl` MSVC-ABI driver prove the obfuscated IR still folds correctly (or stays
  encrypted) under whole-program and MSVC pipelines.
- `--level {0..4}` (default 4) — appends `-taokari-level-<pass>=N` for every level-aware
  pass.
- `--rtti` / `--no-rtti` — toggles the RTTI eraser via `testing\configs\rtti.json`.
- `--benchmark-out report.csv` — records compile time, runtime, and binary-size overhead.

**35 cases** cover C, C++, templates (basic and advanced), inheritance / polymorphism /
virtual dispatch, exceptions & RAII, SEH / funclets, globals, strings, constants, MBA,
arithmetic / logic / bitwise / shift operators, control flow & loops, functions &
parameter passing, dynamic memory, file & stream I/O, multithreading &
synchronisation, STL containers & algorithms, inline asm & compiler-specifics,
preprocessor & macros, security & sanitizer-compat edge cases, a FLA stress test, a
real-world fixture, and a whole-obfuscator **ImGui** stress case. See
[`testing/README.md`](testing/README.md).

**Per-pass verification scripts** under `testing\scripts\` gate the harder claims:

- `verify_opaque_predicates_level2.py` — the unfoldable family survives
  `opt -passes=instcombine,simplifycfg` (with a non-vacuous folding control).
- `verify_machine_obf_level1.py` / `_level2.py` — MIR marker + sub-pass byte signatures,
  `-verify-machineinstrs` acceptance, and proof the byte signatures appear in the `.obj`
  but **not** in the optimized IR.
- `verify_machine_obf_l3_budget.py` — Fortress compile-time (`6x + 15s`) and binary-size
  (`1.25x + 32 KiB`) budget gate.
- `verify_machine_obf_l3_dirty_guard.py` — the runtime stack-byte guard is present and the
  old fixed `cmp rsp, rsp` signature is gone.
- `verify_machine_obf_l3_unmodelled.py` — `+mir:unmodelled` emits the privileged/SIMD
  bytes; the normal set does not.
- `verify_mba.py`, `verify_bogus_control_flow.py`, `verify_string_encryption_level1.py`,
  `verify_constant_runtime_mix.py` — per-pass correctness.
- `verify_page_table_ptr_key.py` — indirect-branch page-table pointer key (regression
  gate for the decryptor-IR fix).
- `verify_vmp_*.py` (void / switch / memintrin / struct-gep / call-pointer / indirect-call
  / function-split / compat-report / runtime-traps / dll-load / ida-l2 / guardrails /
  padding / differential / benchmark) — VMP capability, compatibility, and overhead gates.
- `ida_switch_recovery_check.py` — runs *inside IDA* and asserts the Level-4 target has
  zero switch-info sites.

---

## Roadmap status: detailed in the todo.md!

Taokari ships a **tiered L1 → L2 → L3** progression per pass. `L3` here means "hardened
enough that reversing is expensive, annoying, and slow for a serious analyst" — not
mathematically impossible. The full living list is in [`todo.md`](todo.md).

**Shipped:**

- IR-layer L1/L2/L3 across all passes (opaque predicates L1+L2 with a shared L3
  engine — registry, nesting, solver-resistance suites; flattening L1-L4; BCF
  L1+L2 with multi-layer bogus graphs and fake exception-looking regions
  integrated with the flattening dispatcher; MBA L1+L2 with multi-round
  identities and runtime-nonce mixing applied to flattening dispatch-state
  updates; runtime-mixed constant encryption L1+L2 with per-function encrypted
  pools and indirect-constant-via-helper-shard access; string encryption L1+L2;
  page tables L1; MSVC RTTI eraser; post-link `.text` hash patching).
- MIR L1 infrastructure, L2 core passes (`dirtybytes`, `junk`, `sub`,
  `unmodelled`), and per-sub-pass config keys (probability + per-function
  annotation parsing, validated).
- MIR L3 hardening: runtime-dependent dirty-byte guards, Fortress performance
  budget, function splitting, fake prologue/epilogue bytes, and decompiler
  snapshot tests.
- Metadata hygiene L3: `-irobf-meta` / `-taokari-meta`, helper renaming, export
  allowlists, section/helper randomization, source-path stripping, and leak
  tests.
- Function outlining L3: shards, fake shard graph, shard dispatcher, integrity
  checks, and cross-shard pools; shard calls route through the icall page table
  when both passes are on.
- Dynamic / anti-debug runtime protections L1/L2/L3: anti-debug, timing, fake
  checks, delayed checks, tamper-flag propagation, function integrity,
  encrypted hash table, randomized placement, tamper policy, and a native
  integrity prototype.
- Literal maximum protection flag: `-mllvm -taokari-max` and
  `-mllvm -taokari-max-no-vmp`.
- Release profiles: `dev` / `balanced` / `strong` / `fortress`, plus `mobile`,
  `debuggable-strong`, and `vmp-spear`, with profile inheritance and
  validation.
- Budget system: per-pass, global binary-size, global compile-time, global
  runtime-overhead, and per-function VMP budgets, with hard-fail mode.
- Config generator (`taokari-config-wizard.py`), tier recipes (A/B/C/D), and the
  release dashboard (per-tier summary, pass cost, slowest pass, transformed
  function count, VM compatibility, skipped-function reasons, CI artifacts).
- Decompiler snapshot pipeline (IDA + Ghidra headless, with CFG / pseudocode /
  switch-recovery / call-graph metrics) and gnarliness gates.
- VMP L1, L1.5, and full L2: selected-function virtualization, arithmetic /
  memory / branch opcodes, PHI lowering, VM-local loads/stores, direct-call
  trampolines, differential tests, baseline benchmark, build-time bounds,
  pointer support, globals, GEP, alignment, aliasing tests, runtime key
  derivation, separate immediate streams, opcode permutation tables, integrity
  tags, per-function interpreter clones, indirect handler dispatch, handler
  flattening, callee-table hardening, per-block keys, fake handlers, anti-
  frequency padding, mutation fuzzing, and property-based differential tests.
- VMP L3 hardening: PC encryption, stack/locals encryption between handlers,
  opmap self-verification, varied tamper responses, anti-debug/anti-trace and
  anti-emulation inside the interpreter loop (through the DynamicProtection
  framework, with `off/light/strong` knobs), cross-function VM state, and
  per-build handler-table obfuscation seed verification.
- VMP compatibility coverage: `void` functions, raw `switch` lowering,
  `memcpy`/`memset`/`memmove` intrinsics, multi-index / struct-field GEP,
  pointer args and pointer returns in direct calls, indirect/function-pointer
  call stubs with split-around fallback, function splitting, a per-function
  compatibility report, the `INT_MIN / -1` signed div/rem overflow guard, and
  release-blocking EXE / normal-DLL / manual-map / native↔VM interop gates.

**Partial**

- New-PM codegen wiring for MIR: the new-PM `TaokariMachineObfPass` class is
  registered but not yet plugged into `X86CodeGenPassBuilder` — only the legacy
  `addPreEmitPass` hook is live. (The IR passes have new-PM prototypes and run
  under the new-PM pipeline; full new-PM migration of every IR pass is still
  work.)
- VMP is strong selected-function protection with L3 hardening, but it is still
  not full-program virtualization: wider aggregate coverage and a few remaining
  hardening items below are still work.

**Now implemented (newly landed):**

- **Function outlining / callout obfuscation** — splits basic-block tails into
  internal shard helpers (L1), then hardens the shard layer with opaque names,
  per-arg/return XOR scrambling, fake shards and a max-insts guardrail (L2),
  and a fortress callout with multi-layer split, token-switched dispatcher,
  integrity-check guard and fake call graph (L3). Shard calls route through the
  icall page table for free when both passes are on. Opt in via `+outline` /
  `-taokari-outline`.
- **Dynamic / anti-debug runtime protections** — opt-in per-function
  debugger/timing probes (IsDebuggerPresent / CheckRemoteDebuggerPresent /
  QueryPerformanceCounter) with opaque-predicate result mixing, a runtime-nonce
  seed, a shared module tamper flag, delayed placement, indirect probe
  functions and an anti-patch sentinel. Off by default (kept out of
  `-taokari-max`). Opt in via `+dyn` / `-taokari-dyn`.

**Backlog (not implemented yet):**

- Full symbol / debug-info cleanup beyond the current metadata hygiene pass.
- AArch64 MIR port (no-op infrastructure + a dirtybytes-equivalent), and full
  new-PM migration of the remaining IR passes.

---

## Caveats right now

- **Constant encryption at level 0-1 is intra-unit and re-foldable.** The decrypt IR is
  built from constants and a `constant` global, so any re-running optimizer can fold it
  back. Runtime-mixing (level 2) is what survives; `minConstSize` also skips narrow
  immediates. See [`docs/CONSTANT_FOLDING_AUDIT.md`](docs/CONSTANT_FOLDING_AUDIT.md).
- **MBA is multi-round at L2.** Single-round basic identities ship at L1; L2
  adds multi-round, opaque-constant, and runtime-nonce-mixed identities.
- **The MIR layer is x86_64-only.** No 32-bit x86, no AArch64.
- **VMP is selected-function protection, not automatic whole-program protection.** Loader
  glue, CRT startup, EH-heavy code, TLS setup, hot loops, and unsupported IR stay native
  or are split around — the compatibility report (`-taokari-vmp-compat-report=<path>`)
  says exactly which functions were virtualized, partially virtualized, or skipped, and
  why.
- **Flattening refuses EH-heavy functions** (`hasPersonalityFn`, invoke/cleanup/catch
  pads) and oversized/alloca-heavy functions — the `c_seh` and `cpp_funclet` test cases
  exist precisely to guard this.

---

## License & credits

Apache License 2.0 **with LLVM Exceptions** — see [`LICENSE.TXT`](LICENSE.TXT).

Taokari is a fork of [Arkari](https://github.com/komimoe/Arkari), itself based on
[Goron](https://github.com/amimo/goron), [Hikari](https://github.com/HikariObfuscator/Hikari),
and [OLLVM](https://github.com/obfuscator-llvm/obfuscator). The imported upstream source
keeps its original licenses. See [`NOTICE.md`](NOTICE.md).
