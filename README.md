# Taokari LLVM

Taokari LLVM is an LLVM obfuscator fork based on Arkari.

This repository keeps the imported LLVM tree separate from Taokari-owned files:

- `upstream/taokari/` - Taokari LLVM source tree, copied from `C:\Arkari`.
- `build/taokari-ninja/` - copied Taokari Ninja build cache and objects.
- `scripts/` - Taokari helper commands.
- `docs/` - project notes and source inventory.

## Build

Fast path, using the copied object cache:

```powershell
.\scripts\build-cached.ps1
```

Clean configure path, when the copied cache stops matching the source:

```powershell
.\scripts\configure-release.ps1
ninja -C build\\taokari-ninja
```

## Arkari Credit

Taokari is a fork of Arkari by KomiMoe, itself based on Goron, Hikari, and OLLVM ideas.
The imported source keeps Arkari's original license files in `upstream/taokari/`.

## Current Obfuscation Core

The useful starting point is:

```text
upstream/taokari/llvm/lib/Transforms/Obfuscation
upstream/taokari/llvm/include/llvm/Transforms/Obfuscation
```

Existing user-facing flags are still Arkari-compatible for now, including `-mllvm -irobf`
and `-mllvm -taokari-cfg=...`.
