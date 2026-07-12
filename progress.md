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
      Old `sync-to-wsl.sh` hand-copied 6 files; rewrote it to mirror all 62 Taokari files (4 wholesale dirs via rsync-or-cp + 11 modified-upstream files + 3 clang driver files). Verified 0 byte mismatches across the tree. Rebuild pending.
- [x] Mission-start repo/build/WSL investigation and environment capture.

## In progress

- [🚧] Rebuild `clang` + `opt` against the synced sources, then re-smoke the IR obfuscation stack.

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
