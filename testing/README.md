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
- **Level** (`--level {0,1,2,3,4}`): appends `-taokari-level-<pass>=N` for every
  level-aware pass (`indbr`, `icall`, `indgv`, `fla`, `bcf`, `cie`, `cfe`). The pass
  manager caps each level internally at 4. Default: 4.
- **RTTI** (`--rtti`/`--no-rtti`): enables the RTTI eraser via
  `testing/configs/rtti.json` (which supplies the required `randomSeed`).
  Default: on. Cases flagged `no_rtti` are skipped on this axis.

Example: strongest practical sweep of the sensitive cases:

```powershell
python testing\run_obfuscation_tests.py --keep-going
```

## Benchmark

`--benchmark-out report.csv` compiles each case plain and obfuscated and records
compile time, runtime and binary-size overhead.

## MIR Budget

Run the Level-3 MIR budget gate:

```powershell
python testing\scripts\verify_machine_obf_l3_budget.py
```

It compares plain vs `-taokari-mir=dirtybytes,junk,sub`, checks identical output,
and fails if compile time or binary size exceeds the default budget.

Run the runtime dirty-byte guard gate:

```powershell
python testing\scripts\verify_machine_obf_l3_dirty_guard.py
```

It checks that dirty-byte emission uses the runtime stack-byte guard and no
longer emits the old fixed `cmp rsp, rsp` guard.

Run the unmodelled-instruction gate:

```powershell
python testing\scripts\verify_machine_obf_l3_unmodelled.py
```

It checks explicit `+mir:unmodelled` emission and proves the normal MIR set does
not emit the privileged/SIMD bytes.

Run the MIR + IR cross-pass gate:

```powershell
python testing\scripts\verify_machine_obf_l3_cross_pass.py
```

It checks that MIR `dirtybytes,junk,sub` survives with IR flattening, BCF and
indirect-branch obfuscation enabled.
