# Taokari LLVM

Taokari LLVM is an LLVM obfuscator fork based on Arkari.

This repository keeps the imported LLVM tree separate from Taokari-owned files:

- `upstream/taokari/` - Taokari LLVM source tree, copied from `C:\Arkari`.
- `build/taokari-local/` - local Taokari Ninja build output.
- `scripts/` - Taokari helper commands.
- `docs/` - project notes and source inventory.

## Build

External build:

```bat
scripts\build-external.cmd
```

Show the current log:

```bat
scripts\build-status.cmd
```

Stop the build:

```bat
scripts\build-stop.cmd
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
