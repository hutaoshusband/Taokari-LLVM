#!/bin/bash
set -e
S=/mnt/c/Users/hutao/Documents/GitHub/Taokari-LLVM/upstream/taokari/llvm
D=/home/hutaoshusband/taokari-src/taokari/llvm
cp "$S/lib/Transforms/Obfuscation/ItaniumRTTIEraser.cpp" "$D/lib/Transforms/Obfuscation/"
cp "$S/lib/Transforms/Obfuscation/DynamicProtection.cpp" "$D/lib/Transforms/Obfuscation/"
cp "$S/lib/Transforms/Obfuscation/MetadataHygiene.cpp" "$D/lib/Transforms/Obfuscation/"
cp "$S/lib/Transforms/Obfuscation/CMakeLists.txt" "$D/lib/Transforms/Obfuscation/"
cp "$S/lib/Transforms/Obfuscation/ObfuscationPassManager.cpp" "$D/lib/Transforms/Obfuscation/"
cp "$S/include/llvm/Transforms/Obfuscation/ItaniumRTTIEraser.h" "$D/include/llvm/Transforms/Obfuscation/"
cp "$S/include/llvm/Transforms/Obfuscation/DynamicProtection.h" "$D/include/llvm/Transforms/Obfuscation/"
echo synced
ls -la "$D/lib/Transforms/Obfuscation/ItaniumRTTIEraser.cpp"
