# AGENTS.md — Taokari LLVM

Engineering conventions for autonomous agents working on this repository.
Read this before making changes. See `xy_follow_guideline.md` for the full
style guide and `progress.md` for the living checkpoint log.

## Project shape

Taokari is an LLVM **monorepo fork** (`upstream/taokari/` = a full LLVM+clang
tree, currently based on LLVM 22). The obfuscation surface is concentrated in:

- `upstream/taokari/llvm/lib/Transforms/Obfuscation/` — IR-level passes.
- `upstream/taokari/llvm/lib/CodeGen/TaokariMachineObf/` — Machine-IR pass.
- `upstream/taokari/llvm/include/llvm/Transforms/Obfuscation/` — pass headers.
- `upstream/taokari/clang/lib/Driver/` — driver flag passthrough (`-taokari-*`, `-irobf-*`).

The Windows x64 path is the primary, fully-tested target. Linux x64 is being
brought to parity without altering any Windows code path. Every Linux change
must be guarded (`supportsLinuxX64` / `isOSLinux` / `isOSBinFormatCOFF` /
Itanium-name guards) so it never fires on Windows.

## Build & test loop

- **Windows build:** `build_strong.bat` / `build_max_protection.bat` (MSVC).
- **Linux build (WSL2):** sources are mirrored from the repo into the ext4
  tree `~/taokari-src/taokari` (building over the `/mnt/c` 9P mount is too
  slow). Always run `scripts/sync-to-wsl.sh` after editing any Taokari source
  before rebuilding. Then `cmake --build ~/taokari-build --target clang opt`.
  `scripts/link-linux-build.sh` symlinks the built tools into
  `build/taokari-linux/bin/` so the Python harness can find them.
- **Harness:** `testing/run_obfuscation_tests.py` (platform-aware; clang-cl /
  VsDevCmd auto-skipped on Linux). Differential corpus in `testing/cases/`.
- **WSL invocation:** from Git Bash, prefix `wsl.exe` with `MSYS_NO_PATHCONV=1`
  so `/mnt/c/...` paths are not rewritten. Pass script-file paths rather than
  inline heredocs to avoid double-shell quoting issues.

## Rules (non-negotiable)

1. **Correctness first.** An obfuscated binary must match its baseline's
   observable behavior (stdout/stderr/exit/files). A binary that "runs" is not
   a pass. Never weaken a test to make it green.
2. **Smallest coherent change.** Fix the root cause, not the symptom. No
   speculative rewrites. One seam per commit.
3. **Comment-light code.** No comments unless describing genuinely complex
   math or an unavoidable non-obvious invariant. Code must read like the
   surrounding file.
4. **Local commits only.** Never push, never force-push, never open a PR
   unless explicitly asked. Remove temp files / logs / build artefacts
   before committing (`git status` + diff review every time).
5. **Preserve Windows.** Re-run the Windows regression sampled gates after
   any protection change. A Linux fix must not touch a Windows code path.
6. **Test every change.** Reproduce → fix → focused test → wider suite →
   sanitizer where relevant → commit. Add a regression test for every
   fixed defect.
7. **`goto` policy:** forward jumps to `finish`/`cleanup`/`unsupported`
   labels are fine; backward jumps that drive hidden loops are not.
8. **Don't claim completion.** Tick a `progress.md` box only after the
   behavior is verified on Linux. Continue to the next checkpoint
   automatically — do not stop and wait.

## File map

- `progress.md` — living checkpoint log (the source of truth for status).
- `LinuxUpdate.md` — Linux parity work through Phase L8.
- `todo.md` — compressed feature roadmap.
- `docs/PLATFORM_MATRIX.md` — per-OS × per-arch pass support matrix.
- `docs/BUILD_LINUX.md` — Linux build instructions.
- `testing/run_obfuscation_tests.py` — main differential harness.
- `testing/cases/` — differential corpus fixtures.
- `scripts/sync-to-wsl.sh` — repo → WSL ext4 source mirror.
- `scripts/link-linux-build.sh` — WSL build → `build/taokari-linux/bin/`.
