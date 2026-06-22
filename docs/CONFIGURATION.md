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
