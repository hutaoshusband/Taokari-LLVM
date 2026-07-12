# T-A-O-K-A-R-I Linux Compatibility & Protection-Hardening Progress

Living checkpoint log. Every item below must be *verified on Linux* before it is
ticked. One seam per commit; local commits only; never push.

Legend: `[ ]` open · `[x]` done · `🚧` in progress · `🧪` test · `📚` doc · `⚙️` build

---

## Environment (verified 2026-07-12)

- WSL2 distro: Debian GNU/Linux 13 (trixie), kernel 6.6.114.1-microsoft-standard-WSL2, x86_64.
- System toolchain: clang 19.1.7, gcc 14.2.0, cmake 3.31.6, ninja 1.12.1, binutils 2.44 (ld + readelf), gdb 16.3, python 3.13.5.
- **No** system `opt`, **no** `lld`, **no** `valgrind`, **no** `strace`, **no** `perf`.
- Taokari build: `~/taokari-build` (ext4, fast), produces `bin/clang-22` + `bin/opt`. Source read from `~/taokari-src/taokari` (ext4 mirror of the repo).
- WSL invocation note: from Git Bash, prefix `wsl.exe` calls with `MSYS_NO_PATHCONV=1` so `/mnt/c/...` paths are not rewritten by MSYS. Prefer passing a script file path over inline heredocs.

## Inherited state (from prior LinuxUpdate.md phases L0–L8)

The project has already shipped a large Linux-IR parity effort: 50/51 cross-platform CASES pass on Linux, 33/33 release-gate verifiers, 135/163 standalone `verify_*.py` scripts. The remaining 28 are triaged as MIR/x86/COFF-only, IDA/Ghidra/clang-cl-absent, or pre-existing-broken-on-both.

**Gap found at mission start:** the WSL build source tree was **stale**. The old `scripts/sync-to-wsl.sh` only copied ~6 files; the rest of the Obfuscation dir (Flattening, IndirectCall, IndirectGlobalVariable, NativeIntegrity, MBA, StringEncryption, OpaquePredicate, TaokariMachineObf, the new-PM + X86 registration files, and 3 clang driver files) were never synced. The WSL clang/opt therefore tested June-era code, not the current repo. Fixed in Checkpoint 1.

---

## Current Objective

Build a real, reproducible Linux differential-test loop that exercises the *current* code, then drive it through progressively harder corpus (PIE, shared libs, exceptions, threads, TLS, atomics, ELF inspection, sanitizers) and fix every defect found.

## Completed

- [x] **C1 — Rebuild the Linux source mirror so it reflects the repo.**
      Old `sync-to-wsl.sh` hand-copied 6 files; rewrote it to mirror all 62 Taokari files (4 wholesale dirs via rsync-or-cp + 11 modified-upstream files + 3 clang driver files). Verified 0 byte mismatches across the tree. Rebuilt clang-22 + opt; full IR obfuscation stack smoke matches native output.
- [x] Mission-start repo/build/WSL investigation and environment capture.
- [x] **C2 — Planning files.** `AGENTS.md` (conventions, build/test loop, rules) and `progress.md` (this log) committed.
- [x] **C3 — Differential harness.** Added `--diff` baseline-vs-obfuscated mode to `testing/run_obfuscation_tests.py` with an `--opt-level`/`--pie`/`--no-pie`/`--shared`/`--sanitize` matrix. Compile-both-from-same-source + stdout/stderr/exit comparison with address normalization. Existing path unchanged. Verified 5/5 across O0–Os × PIE for `mba_basic`.
- [x] **C4b — compiler-rt built.** The WSL build shipped without sanitizer runtimes (`lib/clang/22/lib` empty). Built `compiler-rt`; ASan/UBSan/LSan/TSan now all link + run with the Taokari clang. Sanitizer differential unblocked.
- [x] **C5 — Cross-TU exception boundary.** `verify_exceptions_xboundary.py` compiles thrower/middle/catcher as separate TUs and links them in 5 mixed obfuscation configs (incl. exception unwinding *through* a flattened frame). All 5 match baseline on Linux.
- [x] **C6-defect — FIX: CIE wide-int crash at `-Os`.** The opt-level differential sweep surfaced a **hard compiler crash** (`Do not know how to expand this operator's operand`) at `-Os`/`-Oz` with CIE level ≥3. Root cause: CIE helper shards return i64, but when the encrypted constant was wider than i64 (e.g. an i128 shift-amount constant that clang emits at `-Os` for the `mulhi` 64×64 high-multiply pattern), the shard body zext'd i128→i64 (illegal) and the call site substituted the raw i64 into an i128 operand, emitting malformed IR (`lshr i128 x, i64`) that SelectionDAG rejected. Fix: trunc in the shard body (lossless for 64-bit-fitting constants) + zext back at the call site, symmetric with the existing <64 trunc path. Regression verifier `verify_cie_wide_int_os.py` added; 0/5→5/5 on the repro, all 8 configs (cie 3/4 × O2/O3/Os/Oz) green. **Any `-Os` user + CIE L3+ was crashing before this.**
- [x] **C6-fixture — math_heavy `-lm`.** `math_heavy` used `sin`/`cos` but only linked at O2 (where the calls constant-fold). Added `-lm` to its `link_flags` so it builds at every opt level.

## In progress

- [🚧] **C10 — Full release-gate suite regression check** (runs all `verify_*.py` gates including the 4 new ones).

## Completed (additional)

- [x] **C7 — Concurrency differential under sanitizers.** `atomics`, `multithreading`, `thread_local_storage` cases pass differential under UBSan (3/3) and the multithreading case under TSan (1/1). No data races or atomic-ordering defects introduced by obfuscation.
- [x] **C8 — ELF integrity verifier.** `verify_elf_integrity.py` confirms the full obfuscation stack preserves PT_GNU_STACK (non-exec), PT_GNU_RELRO, DT_FLAGS_1 PIE, DT_NEEDED set, and `.init_array`/`.fini_array`/`.eh_frame`/`.eh_frame_hdr` sections. All 10 checks pass.
- [x] **C9 — Sanitizer differential sweep.** ASan (6/6 on dynamic_memory, allocator_heavy, pointer_heavy, tiny_aes, hashing, compression) and UBSan (6/6 on arith_logic, bit_ops, math_heavy, exceptions_raii, cpp_inheritance, virtual_dispatch) — no memory errors, no leaks, no UB.

## Differential baseline (verified 2026-07-12)

| matrix | result |
|---|---|
| default O2, full corpus | 50/51 (`c_seh` Windows-only by design) |
| O0/O1/O2/O3/Os/Oz × 51 cases (pre-CIE-fix) | 296/306 — 10 failures, all `math_heavy` at O0/O1/Os/Oz from the CIE `-Os` crash |
| **O0/O1/O2/O3/Os/Oz × 51 cases (post-CIE-fix)** | **300/300 valid Linux variants matched, 0 crashes** (306 total minus 6 `c_seh` Windows-only) |
| 4 sanity cases × 6 opt levels (post-fix) | 24/24 |
| ASan × 6 memory/pointer cases | 6/6 |
| UBSan × 6 arithmetic/exception cases | 6/6 |
| TSan × multithreading | 1/1 |
| exceptions across obfuscated/unobfuscated boundaries (5 mixed-TU configs) | 5/5 |
| dlopen/dlsym shared-lib differential | pass (plain==obf, exports visible, hidden not leaked, .init_array ran) |
| ELF integrity (10 properties) | 10/10 |




## Next Candidates (priority order)

- [ ] **C2** — `progress.md` + `AGENTS.md` planning files committed.
- [ ] **C3** — Reusable WSL differential harness: compile baseline + obfuscated, diff stdout/stderr/exit, normalise nondeterminism, deterministic seeds.
- [ ] **C4** — Differential corpus sweep at `-O0/-O1/-O2/-O3/-Os` × PIE/non-PIE × static/dynamic × each pass + combos; record every mismatch.
- [ ] **C5** — Exception/unwind differential across obfuscated functions (throw through flattened frames, destructors during unwind).
- [ ] **C6** — Shared library + `dlopen`/`dlsym` differential; verify PLT/GOT + visibility survive each pass.
- [ ] **C7** — Threads + atomics + TLS differential; run under TSan where the runtime is available.
- [ ] **C8** — ELF inspection: relocations, init/fini arrays, RELRO, GNU_HASH, PT_GNU_STACK after each pass.
- [ ] **C9** — Sanitizer sweep (ASan/UBSan/LSan) on the differential corpus.
- [ ] **C10** — Performance + binary-size baseline + regression gates.
- [ ] **C11+** — Protection-hardening improvements (only after the compatibility loop is green).
