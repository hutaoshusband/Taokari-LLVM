# Constant Encryption — Constant Folding Audit

Scope: `ConstantIntEncryption`, `ConstantFPEncryption`, and the shared
`encryptConstant` helper in `Utils.cpp`. This is the Level-1 "audit all
constant folding risks" deliverable from `TODO.md` section 5.

The passes run **early** in the clang pipeline. Every later pass (and the
whole-program LTO link) gets a second chance to fold the emitted decrypt IR
back to a plain constant. This document lists every place that can happen and
what currently prevents (or fails to prevent) it.

## 1. Decrypt-IR is statically computable from a `constant` global

`encryptConstant` (Utils.cpp:535) stores the ciphertext in a
`GlobalVariable` that is:

* `constant` (read-only initializer),
* `InternalLinkage` (fully visible to the optimizer),
* has a known initializer built entirely from `ConstantExpr`.

The decrypt sequence is `load(global) ^ XorKey ^ (XorKey+Key) ^ (~XorKey) + Key`
and a final `bitcast`. Because every operand except the load is a
`ConstantInt`, and the load has a known initializer, **InstCombine / GVN /
ConstantFolding can compute the whole chain back to `plainConstant`** once
they see it.

Mitigation today: `IRBuilder<NoFolder>` is used while emitting, so the chain
is *not* folded at emission time. That only protects against the obfuscation
pass itself — it does **not** protect against the `-O2`/`-O3`/LTO pipeline
that runs afterward.

This is the single largest folding risk and the reason the `-O2` / LTO test
modes exist: they prove the IR stays correct (and, for now, that the chain is
recoverable — see "Open risk" below).

## 2. Level 0 is trivially invertible

At `level == 0` the ciphertext is just `plain - Key` and the decrypt is
`load + Key`. A single InstCombine add-fold undoes it. Only `level >= 1`
adds the `XorKey` chain, and even that is fully determined by constants.

Risk: at any level the math is reversible by constant propagation. The
strength today is "obfuscation inside the compile unit, broken by any
optimizer that re-runs", not "post-compile protection".

## 3. Dedup cache alloca is mem2reg-able

Both passes cache a decrypted constant into a stack `AllocaInst` at function
entry, then reload it at each use (`DedupCache`). After the pass:

* `mem2reg` / `PromoteMemToReg` promotes the alloca to an SSA value,
* the store of `(load global) ^ ... + Key` becomes a single SSA def,
* InstCombine then folds that def as in risk #1.

So the dedup cache does not add folding resistance; it only dedups code size.

## 4. `expandConstantExpr` materializes `ConstantExpr` operands

`expandConstantExpr` (Utils.cpp:151) turns operand `ConstantExpr`s into real
instructions so the encryption pass can see their integer sub-operands. This
is correct, but the materialized instructions are themselves foldable: a GEP
turned into `ptrtoint`/`add`/`inttoptr` can be re-folded by InstCombine back
into a `ConstantExpr`, undoing the materialization. Not a correctness bug,
but it means the pass's view of "what is a foldable constant" is fragile.

## 5. Width floor is a code-size guard, not a security guard

Constants narrower than 8 bits (`> 7` / `< 8` / `< 4`, now unified to
`MinBits = max(8, minConstSize)`) are skipped. This is correct for code size
(encryption costs more than the constant) but means small immediates such as
`0`, `1`, loop strides and shift amounts are **never** encrypted and survive
folding trivially. Documented, not a bug.

## 6. Skipped instruction classes (by design, listed for completeness)

The passes skip `EHPad`, `AllocaInst`, `IntrinsicInst`, `SwitchInst`, atomic
instructions, GEP indices < 2, struct GEPs, operand bundles, and PHI values
flowing from a `SwitchInst`. These skips avoid miscompiles; they also mean
those constants are left in plain form and fold normally.

## Open risk (the real one this audit is here to track)

Risk #1/#2/#3 are all the same root cause: **the decrypt IR is built entirely
from constants and a `constant` global, so any subsequent optimizer pass can
fold it back to plaintext.** The Level-1 work does not fix that (that is
Level-2 "Runtime-Mixed Constants"). The Level-1 deliverable is:

1. This audit (this file).
2. Test coverage that **proves the obfuscated program still produces correct
   output** under `-O2`, LTO, and the MSVC `clang-cl` driver
   (`run_obfuscation_tests.py --mode o2|lto|clangcl`), so regressions in the
   decrypt IR (e.g. a fold that produces a wrong value) are caught.
3. A configurable minimum constant size (`minConstSize` config key) so users
   can trade code size for coverage.

What Level-1 does **not** claim: that the constants stay encrypted in the
final binary. That is explicitly a Level-2/Level-3 goal.
