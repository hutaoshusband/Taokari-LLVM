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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SRC="${TAOKARI_WIN_SRC:-$REPO_ROOT/upstream/taokari}"
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
  local src_root="$1"; shift
  local d="$1"; shift
  mkdir -p "$DST/$d"
  if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete "$@" "$src_root/$d/" "$DST/$d/"
  else
    cp -af "$src_root/$d/." "$DST/$d/"
    # best-effort prune: remove files in DST that no longer exist in SRC
    if [ -d "$DST/$d" ]; then
      ( cd "$src_root/$d" && find . -type f -print ) | sort > /tmp/.taokari_src_list.$$
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
  mirror_dir "$SRC" "$d"
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

# --- Testing harness (lets the gates run fully on ext4) ----------------------
# The harness and perf gate are __file__-relative, so mirroring testing/ into
# the ext4 tree is enough; build/taokari-linux/bin points at the built tools.
# The repo copy of testing/performance/baseline.json stays the source of truth.
mirror_dir "$REPO_ROOT" testing \
  --exclude='__pycache__' \
  --exclude='cases/*/build_*' \
  --exclude='cases/*/obj_*'
# cp fallback has no exclude support; prune the excluded artifacts directly.
find "$DST/testing" -type d -name '__pycache__' -prune -exec rm -rf {} +
find "$DST/testing/cases" -maxdepth 2 \( -name 'build_*' -o -name 'obj_*' \) -exec rm -rf {} +
mkdir -p "$DST/build/taokari-linux"
ln -sfn "$HOME/taokari-build/bin" "$DST/build/taokari-linux/bin"

# Gates also read repo-root files outside testing/ (config wizard, doc gates,
# todo.md DoD check, upstream obfuscation sources). Link them read-only.
for link in scripts docs todo.md upstream; do
  [ -L "$DST/$link" ] || ln -sfn "$REPO_ROOT/$link" "$DST/$link"
done

# --- Optional rebuild --------------------------------------------------------
if [ "${1:-}" = "--rebuild" ]; then
  BUILD="$HOME/taokari-build"
  echo "== rebuilding clang + opt (-j${JOBS}) =="
  cmake --build "$BUILD" --target clang opt -j"$JOBS"
  echo "== rebuild done =="
  "$BUILD/bin/clang" --version | head -1
fi
