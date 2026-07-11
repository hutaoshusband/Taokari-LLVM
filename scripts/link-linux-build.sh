#!/bin/bash
set -e
BUILD="$HOME/taokari-build/bin"
ROOT="/mnt/c/Users/hutao/Documents/GitHub/Taokari-LLVM"
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
