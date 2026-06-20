# Taokari Obfuscation Tests

Run:

```powershell
python testing\run_obfuscation_tests.py --keep-going
```

Each case owns:

- `src/` - checked-in test source
- `obj/` - generated object files, git-ignored
- `build/` - generated executable, git-ignored

The ImGui test uses the vendored source in `testing/vendor/imgui`.

## Matrix axes

The harness runs every selected case across independent obfuscation axes:

- **Mode** (`--mode`, repeatable): `default`, `o2`, `lto` (`-flto -fuse-ld=lld`),
  `clangcl` (clang-cl driver, `/std:` + `/EHsc`). Default: all. The ImGui case
  is `default`-only. -O2/LTO/clang-cl prove the obfuscated IR still folds (or
  stays encrypted) under whole-program and MSVC-ABI pipelines.
- **Level** (`--level {0,1,2,3}`): appends `-taokari-level-<pass>=N` for every
  level-aware pass (`indbr`, `icall`, `indgv`, `fla`, `cie`, `cfe`). The pass
  manager caps each level internally at 3.
- **RTTI** (`--rtti`): also enables the RTTI eraser via
  `testing/configs/rtti.json` (which supplies the required `randomSeed`).
  Cases flagged `no_rtti` are skipped on this axis.

Example: strongest practical sweep of the sensitive cases:

```powershell
python testing\run_obfuscation_tests.py `
  --mode default --mode o2 --mode lto --mode clangcl `
  --level 3 --rtti --keep-going
```

## Benchmark

`--benchmark-out report.csv` compiles each case plain and obfuscated and records
compile time, runtime and binary-size overhead.
