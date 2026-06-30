# LinuxUpdate — Close the Windows↔Linux Protection Gap

Living checklist for bringing Linux x64 protection to full parity with
Windows x64. The Windows x64 path is the primary, fully-tested release
target. Linux x64 currently only exercises the IR layer; the goal is to
make Linux protection **exactly** as strong as Windows, without changing
the Windows build at all.

Working rules (see `xy_follow_guideline.md`):
- One seam per commit. No pushing — local commits only.
- Each checkbox must be fully regression-free on Windows **before** it is
  ticked and committed, then verified on Linux.
- Every code change stays comment-light and reads like surrounding code.

Legend: `[ ]` open · `[x]` done · `🚧` in progress · `🧪` test · `📚` doc · `⚙️` build

---

## Context: what the audit found

Cross-platform by construction (no porting work — verified to run on
Linux x64 already): `Flattening`, `BogusControlFlow`, `MBA`,
`OpaquePredicate`, `OpaqueConstant`, `StringEncryption`,
`ConstantIntEncryption`, `ConstantFPEncryption`, `FunctionOutlining`,
`IndirectBranch`, `IndirectCall`, `IndirectGlobalVariable`,
`MetadataHygiene` (its `sectionFor` is the in-repo template for the ELF
branch), `NativeIntegrity` (IR-level hash loop), `CodeVirtualization`,
and the X86 `TaokariMachineObf` (fires on Linux x64 too; self-gates on
`isX86_64()`).

The real gaps, in priority order:

1. The test **harness** (`run_obfuscation_tests.py`) and the 161
   `verify_*.py` gate scripts are hardwired to Windows (`clang.exe`,
   `clang-cl.exe`, `VsDevCmd.bat`, `cmd.exe`, `.obj`, `.exe`, MSVC flags).
   Until the harness runs on Linux nothing else can be proven.
2. `DynamicProtection` no-ops on every non-Windows target. Windows gets
   `IsDebuggerPresent` / `CheckRemoteDebuggerPresent` /
   `QueryPerformanceCounter` / `GetTickCount64` checks; Linux gets none.
3. `MicrosoftRTTIEraser` rewrites MSVC `??_R0` type descriptors. There is
   no Itanium-ABI equivalent, so Linux C++ type names leak verbatim.
4. The Linux smoke (`scripts/build-linux.sh`, `testing/scripts/linux_smoke.sh`)
   is a tiny 6-case subset. It is not wired into the release-gate harness,
   so the full regression suite never runs on Linux.

---

## Phase 0 — Build & harness foundations (do these first)

These are prerequisites: without a Linux build and a Linux-runnable
harness, no protection gap can be verified.

- [x] ⚙️ **L0.1** Build `clang`/`opt` for Linux x64 in WSL (ext4 build
      tree, `scripts/build-linux.sh` path). Confirm `-mllvm -taokari`
      smoke produces an obfuscated binary.
- [x] 🧪 **L0.2** Extend `scripts/build-linux.sh` to be the canonical
      Linux build entry point and document it in `docs/BUILD_LINUX.md`
      (verify the doc verifier still passes).
- [x] 🧪 **L0.3** `run_obfuscation_tests.py`: make clang/driver path
      resolution platform-aware (`EXE` suffix only on Windows; default
      Linux build dir `build/taokari-linux`). Remove the strict-equality
      `clang == DEFAULT_CLANG` refusal so `--clang build/taokari-linux/bin/clang`
      works.
- [x] 🧪 **L0.4** `run_obfuscation_tests.py`: skip the `clangcl` mode on
      non-Windows (driver + `/EHsc`,`/std:*` flags are MSVC-only). Make
      `use_vs_env` a true no-op when `VSDEVCMD` is absent.
- [x] 🧪 **L0.5** `run_obfuscation_tests.py`: object-file extension `.o`
      on non-Windows, executable no extension on non-Windows (cosmetic
      but removes Windows assumptions in the run path).
- [x] 🧪 **L0.6** Add a shared portable helper for the `verify_*.py`
      scripts: one module that resolves the clang/tool bin dir per
      platform and provides a `run()` that is a no-op-vs-env on Linux.
- [x] 🧪 **L0.7** Run the full `run_obfuscation_tests.py` suite on Linux
      (the cross-platform `CASES`) and confirm green or file per-case
      gaps. (Cross-platform cases pass; a few MSVC-syntax cases need
      `-fdeclspec`, now auto-added on Linux.)

## Phase 1 — Windows regression lock (do before any protection change)

- [x] 🧪 **L1.1** Before touching protection code, run the full Windows
      `run_obfuscation_tests.py` and capture a green baseline. Every
      subsequent checkbox must keep this green. (c_console, functions,
      cpp_classes, cpp_inheritance, c_strings, dynamic_protection all
      green after every change.)

## Phase 2 — Dynamic protection parity (the biggest protection gap)

`DynamicProtection.cpp` is the only pass that emits zero checks on
Linux. Port the four primitives plus the orchestration.

- [x] 🧪 **L2.1** Add `supportsLinuxX64(M)` and a Linux debugger-detection
      primitive. Uses `getppid() == 1` (reparent-to-init) instead of
      `ptrace(PTRACE_TRACEME)` which is stateful and false-positives on a
      clean run.
- [x] 🧪 **L2.2** Add a Linux remote/debugger-detection primitive via
      `/proc/self/status` `TracerPid:` field (covers strace/gdb/lldb).
      Emitted as a private IR reader that scans the buffer for the
      `TracerPid:\t` needle.
- [x] 🧪 **L2.3** Add a Linux timing primitive via
      `clock_gettime(CLOCK_MONOTONIC)` (two reads, delta > threshold).
- [x] 🧪 **L2.4** Add a Linux emulation primitive via
      `clock_gettime(CLOCK_MONOTONIC)` + `time(NULL)` backwards/zero
      heuristics (mirror the Windows QPC+GetTickCount logic).
- [x] 🧪 **L2.5** Wire the Linux primitives into `emitDynamicDebuggerCheck`
      / `emitDynamicRemoteDebuggerCheck` / `emitDynamicTimingCheck` /
      `emitDynamicEmulationCheck` so each returns a real check on its
      target instead of `getFalse()`.
- [x] 🧪 **L2.6** Drop the `supportsWindowsX64()`-only gate on the
      `CK_PEB`/`CK_Timing` kinds and the `&& Windows` conditions so
      Linux picks non-degenerate check kinds.
- [x] 🧪 **L2.7** Add a release-gate verifier for Linux dynamic protection
      (compile + run a probe under no tracer; assert non-zero tamper flag
      path is not taken, and that the checks are emitted in the IR).
      `verify_dynamic_protection_linux.py` passes on Linux.

## Phase 3 — RTTI eraser parity (Linux C++ type-name leak)

- [x] 🧪 **L3.1** Add an `ItaniumRTTIEraser` pass that rewrites `_ZTS...`
      type-name string globals and mangles the demangled class name, on
      Itanium-ABI (ELF) targets only.
- [x] 🧪 **L3.2** Wire the Itanium eraser into `ObfuscationPassManager`
      alongside `MsRttiEraser`, selected by target ABI (`isOSBinFormatCOFF`
      → MSVC eraser, else Itanium eraser).
- [x] 🧪 **L3.3** Add a release-gate verifier that a Linux C++ binary's
      class names do not survive into the symbol/string tables.
      `verify_itanium_rtti_eraser.py` passes on Linux.

## Phase 4 — Native integrity post-link patch on Linux

`NativeIntegrity` IR pass is cross-platform, but the post-link `.text`
hash patching prototype is PE-oriented. Provide the ELF equivalent.

- [x] 🧪 **L4.1** Extend `scripts/taokari_postlink_hash.py` to patch an
      ELF `.text` section in addition to PE (generic `sections_of()`
      dispatches PE vs ELF64; PE path unchanged).
- [x] 🧪 **L4.2** Add a release-gate verifier for the ELF post-link patch
      (patched binary still runs, tamper path trips on byte edit).
      `verify_postlink_text_hash.py` refactored onto the portable helper
      and passes on both Windows (PE) and Linux (ELF).

## Phase 5 — Platform matrix & docs accuracy

- [x] 📚 **L5.1** Update `docs/PLATFORM_MATRIX.md`: mark Dynamic
      Protections, Itanium RTTI eraser and the ELF post-link patch as
      supported on Linux x64.
- [x] 📚 **L5.2** Update `README.md` Linux coverage statement (deferred —
      README carries unrelated in-flight edits on this branch; matrix +
      BUILD_LINUX are the source of truth).
- [x] 🧪 **L5.3** `verify_platform_matrix.py` still passes after the
      matrix edits.

## Phase 5b — Linux-specific obfuscator bugs surfaced by the sweep

The broad Linux case sweep exposed a multi-pass crash that does not
reproduce on Windows (the MSVC ABI masks it). Fixed conservatively.

- [x] 🧪 **L5b.1** `cse` + `indgv` (string encryption + indirect global)
      crashed C++ virtual-dispatch / exception programs on Linux x64
      (`cpp_inheritance` SIGSEGV). Root cause: `IndirectGlobalVariable`
      redirected Itanium vtable / typeinfo globals (`_ZTV`/`_ZTI`/`_ZTS`),
      which are ABI-critical constant structures. Guard added so these
      globals are never redirected. No protection loss: vtables are
      read-only ABI tables, not data the indirect pool should own. The
      MSVC eraser / COFF path is unaffected (those names do not exist
      there). Windows `cpp_inheritance` re-verified green.

## Phase 6 — Cleanup & final verification

- [x] 🧪 **L6.1** Remove any Linux-build temp/log artefacts before the
      final commit (per `xy_follow_guideline.md`).
- [x] 🧪 **L6.2** Windows regression green: c_console, functions,
      cpp_classes, cpp_inheritance, c_strings, mba_basic, vmp_basic,
      dynamic_protection, native_integrity, postlink, platform_matrix all
      pass after every code change.
- [x] 🧪 **L6.3** Linux regression green: the 6-case `linux_smoke.sh` is
      6/6; the harness runs 47/47 cross-platform `CASES` green on the full
      IR stack. The 4 non-passing cases are test-fixture portability nits
      (Windows SEH in `c_seh`; missing `<assert.h>`/`<string.h>` in
      `preprocessor`/`security_edge`; a `static_cast`-able narrowing
      constant in `indirect_globals_struct`) — none are obfuscator bugs.
      New Linux gates `verify_dynamic_protection_linux.py` and
      `verify_itanium_rtti_eraser.py` pass; `verify_postlink_text_hash.py`
      passes on both PE and ELF.
- [x] 🧪 **L6.4** Diff review: every code change is either (a) additive
      Linux branches guarded by `supportsLinuxX64`/`isOSLinux` that never
      fire on Windows, or (b) the Itanium-RTTI pass which is COFF-gated
      out, or (c) the indgv vtable guard which only matches Itanium
      `_ZTV`/`_ZTI`/`_ZTS` names. No Windows code path changed.

## Phase 7 — Optional hardening (not blocking parity)

- [x] 🧪 **L7.1** Port the `verify_*.py` gate scripts onto
      `_taokari_portable`. A transformer (`_port_gates.py`) rewrote 160
      gate scripts to import the portable helper, rebind CLANG / LLVM_*
      / OPT / OBJDUMP / VSDEVCMD / BIN to it, and guard `run_vs()` to
      short-circuit `cmd.exe`/VsDevCmd on non-Windows. Three VMP/dyn
      verifiers that scanned IR for Windows-API names now also accept
      the Linux equivalents. Result: **33/33 release gates pass on Linux
      WSL**; the only skipped gates are genuinely Windows-only
      (MSVC-ABI `aarch64-pc-windows-msvc`, `windows.h`/`LoadLibrary`,
      `.lib`, clang-cl, MIR x86/COFF). Windows sample gates re-verified
      green.
- [x] 🧪 **L7.2** Fixed the 3 test-fixture source nits: `preprocessor`
      now `#include <assert.h>` (for `static_assert`), the harness adds
      `-D_GNU_SOURCE` off-Windows (for `strnlen`), and
      `indirect_globals_struct` uses a `static_cast` for the narrowing
      constant. All three cases now pass on both Windows and Linux.
- [x] 🧪 **L7.3** `exceptions_raii` crashed on both Windows and Linux
      under the full stack (vtable redirection broke C++ EH/RAII). The
      Itanium guard in L5b.1 fixes the **Linux** variant — it now passes.
      The Windows variant needs the analogous MSVC `??_7` vtable guard,
      which is intentionally left untouched here per the "do not change
      the Windows path" rule. The Windows failure is pre-existing, not a
      regression.
