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

## Differential mode

`--diff` compiles a fresh plain baseline per case and compares stdout/stderr/exit
against the obfuscated build. `--variants N` does N fresh obfuscated compiles per
matrix cell (fresh RNG keys each) and `--runs N` executes each variant N times;
every run must match the baseline, closing the one-sample RNG blind spot:

```powershell
python testing\run_obfuscation_tests.py --diff --variants 2 --runs 2 --case exceptions_heavy
```

## Performance gate

`testing/performance/run_perf_gate.py` compiles the 10 baseline-corpus cases
plain vs obfuscated (default stack, level 4; median of 3 obfuscated builds for
compile/size), correctness-gates every obfuscated run against the plain output,
then checks compile/runtime/size ratios against
`testing/performance/baseline.json`. Windows tolerances: compile +40%, runtime
+20% with a +0.25 absolute floor, size +30% (calibrated: arith_logic obfuscated-build sizes span 676-861KB across sessions, max/min 1.27 around the 7-sample anchor, same methodology as the linux calibration). Linux: compile +40%, runtime
+75%, size +40%, no floor (calibrated to measured per-compile RNG size swings
and small-fixture runtime jitter). Exit 0 pass / 1 regression or usage error /
2 skip. `--update-baseline` re-seeds the current platform's section; `--quick`
runs a 3-case subset.
Wrapped as the skippable `perf_baseline` release gate via
`testing/scripts/verify_perf_baseline.py`.

## Release gates

After the case matrix, the harness runs a set of standalone verifier scripts
(see `RELEASE_GATES` in `run_obfuscation_tests.py`) that prove specific
hardening properties end-to-end. Each runs the locally built clang and exits
0/nonzero:

- `verify_function_outlining.py` — Section 10 function outlining (L1/L2/L3
  callout fortress + opt-in cross-shard pools).
- `verify_dynamic_protection.py` — Section 12 dynamic anti-reversing checks
  (L1/L2/L3 probes, opaque mixing, tamper flag, indirect probes, sentinel).
- `verify_outline_dyn_fortress_compose.py` — the full IR stack (outline + dyn +
  fla + bcf + mba + indirects + string/constant encryption) round-trips on one
  sensitive function.
- `verify_max_build_no_vmp_hang.py` / `verify_max_build_vmp_budgeted.py` —
  `-taokari-max` builds do not hang (VMP budget caps).
- `verify_vmp_full_virtualization.py` / `verify_vmp_dll_load.py` — VMP coverage.

Skippable gate scripts exit 2 when their precondition is absent, so they sit
harmlessly in CI until the toolchain is ready; the runner treats that as a
skip. `--gates-only` runs the gate suite without the case-matrix pass.

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

Run the fake prologue/epilogue boundary-byte gate:

```powershell
python testing\scripts\verify_machine_obf_l3_fakebounds.py
```

It checks explicit `+mir:fakebounds`/flag emission and proves the normal MIR set
does not emit fake boundary bytes.

Run the function-splitting / boundary-trampoline gate:

```powershell
python testing\scripts\verify_machine_obf_l3_function_split.py
```

It checks explicit `+mir:split`/flag emission and proves the normal MIR set does
not emit the split boundary marker.

Run the local IDA/Hex-Rays snapshot gate:

```powershell
python testing\scripts\verify_machine_obf_l3_ida_snapshot.py
```

It uses `TAOKARI_IDA` or the local IDA install, snapshots plain vs Fortress MIR
Hex-Rays output, and fails unless the protected function gains visible
decompiler noise.

For the exact IDA 9.2 + D810 lab gate:

```powershell
python testing\scripts\verify_machine_obf_l3_ida_snapshot.py --require-ida92-d810 --require-function-confusion
```

Run the MIR + IR cross-pass gate:

```powershell
python testing\scripts\verify_machine_obf_l3_cross_pass.py
```

It checks that MIR `dirtybytes,junk,sub` survives with IR flattening, BCF and
indirect-branch obfuscation enabled.

Run the CFG fragmentation metric:

```powershell
python testing\scripts\verify_machine_obf_l3_cfg_fragmentation.py
```

Run the metadata hygiene gate:

```powershell
python testing\scripts\verify_metadata_hygiene.py
```

It rebuilds the touched compiler/tool targets, then checks `-taokari-meta`
against IR metadata leaks, COFF symbols, PE runtime behavior, ELF sections and
Mach-O sections.

It compares plain vs IR+MIR object disassembly and fails if final machine code
does not add branch-like control transfers and trap/unknown fragmenters.

Run the AArch64 MIR parity-plan gate:

```powershell
python testing\scripts\verify_machine_obf_l3_aarch64_plan.py
```

It checks that the AArch64 port plan names the target hook, sub-pass mapping,
safety rules and verification gates.
