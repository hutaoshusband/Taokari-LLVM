# Taokari Obfuscator — Configuration Reference

Taokari is driven from three layers, applied in increasing precedence
order:

1. Built-in defaults (see "Defaults" below).
2. A JSON config file passed via `-mllvm -taokari-cfg=<path>`.
3. Per-function annotations (`__attribute__((annotate("...")))`) that
   override the JSON config for a single function.

A function is obfuscated by a pass only when (a) the master `-taokari`
flag is on, AND (b) the pass is enabled either by config or by a
`+<pass>` annotation, AND (c) the function is not skipped by `-<pass>`
or by `noobf`.

## Master flags

| Flag                              | Purpose                                                  |
| --------------------------------- | -------------------------------------------------------- |
| `-mllvm -taokari`                 | Master IR obfuscation switch (alias of `-irobf`).        |
| `-mllvm -taokari-max`             | Taokari Max Protection profile (all passes on, level 4). |
| `-mllvm -taokari-cfg=<path>`      | Load JSON config from `<path>`.                          |
| `-mllvm -taokari-vmp`             | Enable code virtualisation (off by default).             |
| `-mllvm -taokari-vmp-padding=N`   | Probability (0..100) of inserting pad opcodes in VM bytecode. |
| `-mllvm -taokari-mir=<passes>`    | Comma-list of MIR passes (`dirtybytes,junk,sub,...`).    |
| `-mllvm -taokari-level-<p>=N`     | Per-pass level override (0..4). `<p>` is one of `indbr`, `icall`, `indgv`, `fla`, `bcf`, `mba`, `cie`, `cfe`. |
| `-mllvm -taokari-<p>-prob=N`      | Per-pass probability (0..100).                           |
| `-mllvm -taokari-<p>-func-prob=N` | Per-pass per-function probability (0..100).              |

## Per-function annotations

Annotations are emitted as `__attribute__((annotate("<tokens>")))` on
the function declaration. Multiple tokens are space-separated inside a
single string.

| Token          | Effect                                                              |
| -------------- | ------------------------------------------------------------------- |
| `+fla`         | Force-enable flattening on this function.                          |
| `-fla`         | Force-disable flattening on this function.                         |
| `^fla=N`       | Set the flattening level (0..4).                                    |
| `+bcf`         | Force-enable bogus control flow.                                   |
| `+mba`         | Force-enable mixed boolean/arithmetic substitution.                |
| `+icall`       | Force-enable indirect-call page-table indirection.                 |
| `+indbr`       | Force-enable indirect-branch page-table indirection.               |
| `+indgv`       | Force-enable indirect-global-variable page-table indirection.     |
| `+strenc` / `+cse` | Force-enable string encryption.                                |
| `+constenc` / `+cie` | Force-enable integer-constant encryption.                    |
| `+vmp`         | Force-enable code virtualisation.                                  |
| `+nativeint`   | Force-enable the per-function native integrity prototype.         |
| `-nativeint`   | Force-disable the native integrity prototype (overrides Max mode).|
| `+mir` / `+mir:dirtybytes` | Opt into specific MIR sub-passes.                       |
| `noobf`        | Skip ALL IR obfuscation passes on this function.                   |

Every pass accepts the matching `+`/`-`/`^=N` forms.

## Levels

Most passes accept a level in 0..4. Higher levels add stronger (and
more expensive) protection; level 0 disables the pass entirely.

| Level | Meaning                                                       |
| ----- | ------------------------------------------------------------- |
| 0     | Disabled.                                                     |
| 1     | Baseline protection (single-round substitution, basic page table). |
| 2     | Adds reconstruction-formula variation, runtime seed mixing, fake entries. |
| 3     | Fortress tier (per-function page tables, integrity checks, MBA on decryptors). |
| 4     | Maximum (everything in 3 plus polymorphism and per-build diversification). |

## JSON config keys

The JSON file is a flat object whose top-level keys are pass names
(`indbr`, `icall`, `indgv`, `fla`, `bcf`, `mba`, `cie`, `cfe`, `cse`,
`meta`, `rtti`, `vmp`). Each value is an object with any of the
following keys.

### Common keys (every pass)

| Key                  | Type    | Default | Notes                                                |
| -------------------- | ------- | ------- | ---------------------------------------------------- |
| `enable`             | bool    | `false` | Master switch for this pass.                         |
| `level`              | int 0..4| `0`     | Per-pass protection level.                           |
| `maxInsts`           | int     | pass-specific | Skip functions larger than this instruction count. |
| `maxBlocks`          | int     | pass-specific | Skip functions with more basic blocks than this.   |
| `maxAllocas`         | int     | pass-specific | Skip functions with more allocas than this.        |
| `probability`        | int 0..100 | `100` | Per-call-site probability.                           |
| `functionProbability`| int 0..100 | `100` | Per-function probability.                            |

### BCF / Flattening

| Key         | Type | Default | Notes                                            |
| ----------- | ---- | ------- | ------------------------------------------------ |
| `loopCount` | int  | `1`     | Number of bogus-control-flow iterations per site. |

### Constant encryption (`cie`, `cfe`)

| Key           | Type | Default | Notes                                                |
| ------------- | ---- | ------- | ---------------------------------------------------- |
| `minConstSize`| int  | `0`     | Encrypt integer/FP constants whose bit-width >= this.|

### String encryption (`cse`)

| Key                | Type         | Default | Notes                                                |
| ------------------ | ------------ | ------- | ---------------------------------------------------- |
| `minStringLength`  | int          | `0`     | Encrypt strings at least this long.                  |
| `skipStrings`      | array<str>   | `[]`    | Plaintext strings that are never encrypted.          |
| `localStackDecrypt`| bool         | `false` | Decrypt into a per-use stack alloca.                 |
| `heapDecrypt`      | bool         | `false` | Decrypt into a per-use heap buffer.                  |
| `reencryptAfterUse`| bool         | `false` | Scrub the plaintext after the consuming call.        |
| `volatileSeed`     | bool         | `false` | Use a volatile load as the runtime nonce seed.       |
| `decryptorMba`     | bool         | `false` | L3: rewrite decryptor arithmetic with MBA identities.|
| `stringDecryptorFlattening` | bool | `false` | L3: flatten the decryptor body.                |
| `stringDecryptorIndirectCall`| bool| `false` | L3: route decryptor calls through an opaque slot.|
| `stringShardedPool`| bool         | `false` | L3: split the encrypted pool across multiple globals.|
| `stringFakePools`  | bool         | `false` | L3: emit decoy pools alongside the real one.         |
| `stringPageTableAccess`| bool     | `false` | L3: resolve pool base through a page table.          |
| `stringDelayedDecrypt`| bool      | `false` | L3: per-use alloca + scrub before function return.   |

### Metadata / RTTI

| Key                | Type         | Default | Notes                                            |
| ------------------ | ------------ | ------- | ------------------------------------------------ |
| `releaseStrip`     | bool         | `false` | Strip debug info, paths, and compiler identifiers. |
| `randomizeSections`| bool         | `false` | Randomise PE section names.                       |
| `exportAllowlist`  | array<str>   | `[]`    | Symbols that remain exported; everything else is hidden. |

## Examples

### Minimum: encrypt strings in `main`

```json
{
  "cse": {
    "enable": true,
    "level": 2,
    "minStringLength": 5
  }
}
```

### Fortress string encryption (all L3 knobs on)

```json
{
  "cse": {
    "enable": true,
    "level": 3,
    "minStringLength": 4,
    "decryptorMba": true,
    "decryptorFlattening": true,
    "decryptorIndirectCall": true,
    "shardedPool": true,
    "fakePools": true,
    "pageTableAccess": true,
    "delayedDecrypt": true
  }
}
```

### Per-function opt-in via annotation

```cpp
__attribute__((annotate("+mba ^mba=3 +bcf -fla")))
static int sensitive(int x) { ... }
```

This forces MBA at level 3 and BCF on `sensitive`, while disabling
flattening for it, regardless of the JSON config.

## Validation

Unknown top-level nodes and unknown per-pass keys both emit a warning
to `stderr` at config-load time (`warning: unknown taokari config
key: <pass>.<key>`), so typos surface during the build instead of
silently being ignored.

A complete reference config covering every pass with conservative
defaults lives at
[`testing/configs/taokari-default.json`](../testing/configs/taokari-default.json).
Copy it as a starting point and edit per build.

## Compile-time cost reference

This section is the authoritative answer to *"which flags cost compile
time, and which don't?"* All numbers are wall-clock on a representative
Max Protection target (~100-line C source, full fla/bcf/mba/cie/cfe/
cse/icall/indbr/indgv/meta recipe) measured by
`testing/scripts/verify_max_compile_time_verify_flag.py`.

### What is visible in `-help` (and what is not)

Taokari flags are LLVM `cl::opt` options. They are **not** listed by
`clang -help` (clang does not enumerate LLVM pass options). They are
listed by:

- `opt -help` — all visible Taokari flags (the ones marked
  `cl::NotHidden`, which is the default for the per-pass flags).
- `opt -help-hidden` — adds the `cl::Hidden` flags too, including the
  debug-only checks listed below.

Every flag's short description comes from its `cl::desc` string in the
source; this document restates the cost-relevant ones.

### Compile-time-safe (no measurable cost)

These flags do not add measurable compile time on their own:

| Flag / category                    | Why it is free                                                  |
| ---------------------------------- | --------------------------------------------------------------- |
| `-mllvm -taokari-<p>-prob=N`       | Selection probability. No extra work, just a per-instruction coin flip. |
| `-mllvm -taokari-bcf-before-fla` / `-taokari-bcf-after-fla` | Just controls *when* BCF runs relative to fla. Same total work either way. |
| `-mllvm -taokari-report`           | Diagnostic print to stderr. Does not transform IR. |
| `-mllvm -taokari-vmp-compat-report=<path>` | Diagnostic TSV report. Does not transform IR. |
| `-Wl,/DEBUG:NONE`                  | Linker flag. Strips PDB/CodeView from the output so the binary carries no debug info. Saves link time, costs nothing. |

### Compile-time-cheap passes (per TU: tens of milliseconds)

These are the IR-layer obfuscators. On the reference target they add
roughly 10–60 ms each to a single-TU compile. They compound when
stacked (BCF on a flattened function clones a much larger CFG), but the
total IR-obfuscation cost measured by `-ftime-report` is still well
under 100 ms:

| Pass flag             | Layer | Typical per-TU cost | What raises its cost                   |
| --------------------- | ----- | ------------------- | -------------------------------------- |
| `-taokari-fla`        | IR    | ~10–30 ms           | Level (4 ≫ 1), function size threshold |
| `-taokari-bcf`        | IR    | ~10–30 ms           | `-taokari-bcf-loops` (3 ≫ 1), level 2  |
| `-taokari-mba`        | IR    | ~5–15 ms            | `-taokari-mba-prob` (100 ≫ 20)         |
| `-taokari-cie` / `-taokari-cfe` | IR | ~5–15 ms each    | Level (2 ≫ 1), number of constants     |
| `-taokari-cse`        | IR    | ~5–20 ms            | Number and length of string literals   |
| `-taokari-icall` / `-taokari-indbr` / `-taokari-indgv` | IR | ~5–15 ms each | Level (3 ≫ 1)            |
| `-taokari-meta`       | IR    | ~5–10 ms            | Level (3 ≫ 1), number of globals       |
| `-taokari-mir=...`    | Codegen | ~200 ms (full set) | Binary size, not compile time          |

### Compile-time-expensive (avoid in tight loops)

| Flag                                  | Cost | Why | Mitigation |
| ------------------------------------- | ---- | --- | ---------- |
| `-mllvm -verify-machineinstrs`        | **~2.6× compile time** | Debug-only safety check: re-runs the MachineVerifier after every codegen pass. Has zero effect on the generated code. **Never enable in production.** | Just do not pass it. |
| `-mllvm -taokari-max`                 | All passes at level 4 + probability 100 + BCF loop 3 | Forces the heaviest possible recipe. Can hang the compile when combined with global `-taokari-vmp`. | Use the explicit per-pass recipe in `build_max_protection.bat` instead. |
| `-mllvm -taokari-vmp` (global)        | Very high; can hang under `-taokari-max` | Every non-trivial function becomes a VM candidate with no budget. | Use annotation-only `+vmp` on a few functions; `-vmp` on CRT/main; budget caps below. |
| `-mllvm -taokari-vmp-padding=N` (high) | Scales with N | Padding opcodes inflate the bytecode. 5 = light, 15 = heavy. | Default 0; Max Protection uses 5. |
| `-flto`                               | ~8× compile time vs `-O2` | Whole-program LTO link-time optimisation on top of obfuscation. | Only use when cross-module obfuscation is required. |

### VMP budget caps (set these when using `-taokari-max`)

These four knobs refuse to virtualise functions that would blow up
compile time or runtime. They default to *off*; **under `-taokari-max`
you should set at least the first three** or a hot-loop function will
hang the build:

| Flag                                   | Default | Recommended under `-taokari-max` | What it does |
| -------------------------------------- | ------- | -------------------------------- | ------------ |
| `-taokari-vmp-max-back-edges=N`        | `UINT32_MAX` (off) | `64` | Refuses functions with more than N CFG back edges (hot loops). |
| `-taokari-vmp-max-bytecode-expansion=N`| `0` (off) | `32` | Refuses functions whose bytecode-per-IR-instruction ratio exceeds N. |
| `-taokari-vmp-max-bytecode-words=N`    | `4096` | `2048` | Caps the bytecode size of a single VM'd function. |
| `-taokari-vmp-compat-report=<path>`    | (off) | (recommended) | Emits a TSV showing which `+vmp` functions virtualised vs skipped — use this to verify your `+vmp` functions actually virtualised. |

### Quick sanity recipes

Use `-mllvm -taokari-report` to see exactly which passes merged into
the final pipeline after all flags and config are applied. The output
goes to stderr and looks like:

```
taokari-report: fla enable=true level=4
taokari-report: bcf enable=true level=2
taokari-report: vmp enable=false level=0
...
```

If you are tuning compile time, run the
`testing/scripts/verify_max_compile_time_verify_flag.py` A/B benchmark
to confirm your recipe is faster than the debug-flag baseline.
