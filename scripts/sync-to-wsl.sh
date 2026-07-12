#!/bin/bash
# Mirror all Taokari obfuscation sources from the Windows mount into the
# WSL ext4 source tree used by the Linux build (~/taokari-src/taokari).
#
# The Linux build (~/taokari-build) reads sources from ~/taokari-src/taokari,
# NOT from the /mnt/c mount, because building LLVM over 9P (DrvFs) is far
# too slow. This script keeps that ext4 copy in sync with the repo.
#
# It mirrors the complete Taokari footprint (62 files, identified by the
# source inventory): the four dedicated directories are synced wholesale
# with rsync, and the eleven modified-upstream files are copied
# individually. Idempotent; only recompiles what actually changed.
#
# Usage from the repo root (Git Bash or WSL):
#   bash scripts/sync-to-wsl.sh            # sync sources only
#   bash scripts/sync-to-wsl.sh --rebuild  # sync, then rebuild clang + opt
set -euo pipefail

SRC="/mnt/c/Users/hutao/Documents/GitHub/Taokari-LLVM/upstream/taokari"
DST="$HOME/taokari-src/taokari"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"

if [ ! -d "$DST" ]; then
  echo "error: destination $DST does not exist." >&2
  echo "       The Linux source tree must be bootstrapped first." >&2
  exit 1
fi

echo "== syncing Taokari sources: $SRC -> $DST =="

# Prefer rsync (faster, timestamp-based); fall back to cp -a if absent. The
# wholesale directories are mirrored with --delete so files removed from the
# repo do not linger in the build tree.
mirror_dir() {
  local d="$1"
  mkdir -p "$DST/$d"
  if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete "$SRC/$d/" "$DST/$d/"
  else
    cp -af "$SRC/$d/." "$DST/$d/"
    # best-effort prune: remove files in DST that no longer exist in SRC
    if [ -d "$DST/$d" ]; then
      ( cd "$SRC/$d" && find . -type f -print ) | sort > /tmp/.taokari_src_list.$$
      ( cd "$DST/$d" && find . -type f -print ) | sort > /tmp/.taokari_dst_list.$$
      comm -13 /tmp/.taokari_src_list.$$ /tmp/.taokari_dst_list.$$ | \
        while read -r stale; do rm -f "$DST/$d/$stale"; done
      rm -f /tmp/.taokari_src_list.$$ /tmp/.taokari_dst_list.$$
    fi
  fi
}

# --- Wholesale directories (Taokari-owned, full mirror) ----------------------
for d in \
  llvm/lib/Transforms/Obfuscation \
  llvm/lib/CodeGen/TaokariMachineObf \
  llvm/include/llvm/Transforms/Obfuscation \
  llvm/unittests/Transforms/Obfuscation
do
  mirror_dir "$d"
done

# --- Single modified-upstream LLVM files (paths relative to taokari/) --------
UPSTREAM_FILES=(
  llvm/include/llvm/InitializePasses.h
  llvm/include/llvm/CodeGen/TaokariMachineObf.h
  llvm/lib/CodeGen/CMakeLists.txt
  llvm/lib/Passes/CMakeLists.txt
  llvm/lib/Passes/PassBuilder.cpp
  llvm/lib/Passes/PassBuilderPipelines.cpp
  llvm/lib/Transforms/CMakeLists.txt
  llvm/lib/Target/X86/CMakeLists.txt
  llvm/lib/Target/X86/X86TargetMachine.cpp
  llvm/unittests/Transforms/CMakeLists.txt
)
for f in "${UPSTREAM_FILES[@]}"; do
  mkdir -p "$DST/$(dirname "$f")"
  cp -f "$SRC/$f" "$DST/$f"
done

# --- clang driver files (3 modified files, passthrough flag handling) --------
CLANG_FILES=(
  clang/lib/Driver/ToolChain.cpp
  clang/lib/Driver/ToolChains/Clang.cpp
  clang/lib/Driver/ToolChains/MSVC.cpp
)
for f in "${CLANG_FILES[@]}"; do
  mkdir -p "$DST/$(dirname "$f")"
  cp -f "$SRC/$f" "$DST/$f"
done

echo "== synced =="
ls -la "$DST/llvm/lib/Transforms/Obfuscation/ObfuscationPassManager.cpp" \
       "$DST/llvm/lib/CodeGen/TaokariMachineObf/TaokariMachineObf.cpp"

# --- Optional rebuild --------------------------------------------------------
if [ "${1:-}" = "--rebuild" ]; then
  BUILD="$HOME/taokari-build"
  echo "== rebuilding clang + opt (-j${JOBS}) =="
  cmake --build "$BUILD" --target clang opt -j"$JOBS"
  echo "== rebuild done =="
  "$BUILD/bin/clang" --version | head -1
fi
