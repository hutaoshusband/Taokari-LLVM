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

## Phase 6 — Cleanup & final verification

- [ ] 🧪 **L6.1** Remove any Linux-build temp/log artefacts before the
      final commit (per `xy_follow_guideline.md`).
- [ ] 🧪 **L6.2** Full Windows regression suite green.
- [ ] 🧪 **L6.3** Full Linux regression suite green (harness + the
      extended Linux smoke).
- [ ] 🧪 **L6.4** Diff review: no Windows code path changed by any of
      the above.
