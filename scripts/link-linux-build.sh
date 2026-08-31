#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD="$HOME/taokari-build/bin"
DEST="$ROOT/build/taokari-linux/bin"
mkdir -p "$DEST"
for t in clang clang++ opt lld ld.lld \
         llvm-readobj llvm-readelf llvm-objdump llvm-nm llvm-ar \
         llvm-objcopy llvm-strip llvm-symbolizer; do
  if [ -e "$BUILD/$t" ]; then
    ln -sf "$BUILD/$t" "$DEST/$t"
  fi
done
echo "linked:"
ls -la "$DEST/clang" "$DEST/opt"
