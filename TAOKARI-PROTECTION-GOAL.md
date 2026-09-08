# TAOKARI-PROTECTION-GOAL — Protection Hardening Without Correctness or Compile-Time Regression

Living goal document for the protection-hardening orchestration loop.
Started 2026-09-07 from HEAD `7f97945b1` (master, clean, 8 ahead of origin/master).

Contract per work item (all required before `[x]`):

- **Weakness** — what is broken / weak, with reproducible evidence.
- **Root cause** — verified against current source, not docs.
- **Seam** — smallest coherent change.
- **Protection req** — the protection property to prove.
- **Correctness req** — differential matrix that must match.
- **Compile-time req** — parent-vs-candidate interleaved A/B, medians, N>=3-5.
- **Verifier** — focused verifier with proven teeth (negative control).
- **Windows / Linux / AArch64 status** — per-platform evidence.
- **Checkpoint** — local commit hash.

Status legend: `[ ]` open · `[~]` in progress · `[x]` done (contract satisfied) ·
evidence recorded under each item as it arrives.

---

## Baseline items (must complete before product changes)

### TK-001 — Build/repo inventory and binary-freshness proof — DONE 2026-09-07
- HEAD `7f97945b1`, clean tree, last `upstream/` source commit `365b4be9e`.
- Windows `build/taokari-local/bin/clang.exe` sha256
  `0ef5c03a8e1cf82150923971fac8c97f2b8aaff46bdc5bd144ad8cb2db9d17f0` —
  matches loop-22 fixed-build prefix; `git log 365b4be9e..HEAD -- upstream/`
  empty → fresh. llvm-objdump `992a98e2…`, opt `d12cc6bc…`. Smoke ok.
- Linux: ext4 sync byte-identical (combined obf-surface hash
  `c76d6f8234e2f6a92fa62771f078a0f9`), incremental rebuild rc=0 (328 steps,
  145 s — sync timestamps re-dirtied objects, not a full rebuild).
- Note: clang.exe embeds git rev `c2e2e5ef9` + `+assertions`; loop-22 built
  from the dirty tree that became `365b4be9e` — hash prefix is the freshness
  source of truth. CMakeCache `LLVM_ENABLE_ASSERTIONS:BOOL=OFF` is a recorded
  footgun (binary verifiably has assertions).

### TK-002 — Windows x64 full release-gate baseline at HEAD — RUNNING
- Full case matrix + release gates + perf gate, recorded as the goal's
  Windows reference.
- Partial evidence (two interrupted runs, combined): **130 unique cells
  PASS, 0 FAIL** — default 53/53, o2 52/52, lto 25/52 partial. Logs
  `build/taokari-local/tmp_goal/win-full-suite{,-resume}.log`.
- Relaunched 2026-09-08 as a detached host process (full suite + quick perf
  gate → `win-full-suite3.log` / `win-perf-quick3.log`) after two
  agent-driven runs died mid-suite across session interruptions.
- Final evidence: (pending)

### TK-003 — Linux x64 full release-gate baseline at HEAD (ext4) — DONE 2026-09-07
- Full suite 37 min: **case matrix 154/154 valid cells** (3 `c_seh` fails are
  the documented MSVC-SEH by-design exclusions; no `windows_only` flag exists
  for cases), **release gates pass=82 fail=0** skip-pre=1 (decompiler
  snapshot) skip-win=7 (Windows-only gates). Log scan for crash
  signals/mismatches: zero hits.
- Perf: suite `perf_baseline` gate PASS (mba_basic 9.50x/0.95x/6.56x,
  hashing 12.60x/0.90x/7.05x, arith_logic 81.62x/0.95x/39.62x);
  `run_perf_gate.py --quick` rc=0 (13.88x/1.04x/8.13x, 13.66x/0.91x/7.82x,
  93.18x/1.02x/41.99x). baseline.json untouched.
- Logs: `build/taokari-local/tmp_goal/linux-full-suite.log`,
  `linux-perf-quick.log` + WSL `~/gate-goal-baseline.log`, `~/perf-goal-quick.log`.

### TK-004 — Per-family protection-coverage inventory — DONE (Windows first pass) 2026-09-07
- Method: scratch drivers on 9-case corpus (Tier-B strong recipe, pinned seed)
  + VMP compat report + MIR verbose. Full table in agent report; headline:
  - Fires broadly: MBA (32 fn/1547 ops), icall (13/14 fn, 9/9 cases), CSE
    (39 decrypt calls, 9/9), CIE (38 fn, 9/9), indgv (9/9), BCF (14 fn),
    FLA (10 fn), outlining (6 shards, 3/9), VMP 51/56 (`+vmp` fns).
  - **ocnst: 0 transformed under full stack** — CIE runs first and consumes
    eligible constants (→ TK-017).
  - **indbr: 1/9 cases only** (dynamic_memory 66 occ.), eligibility opaque
    (→ TK-019).
  - **CSE left `c_str "taokari-secret"` plaintext** in c_strings while
    encrypting printf formats (→ TK-018).
  - VMP skips: 5/56, all `bytecode encoding failed` incl. 4× `main`
    (feeds TK-007).
  - MIR: EH/funclet MFs get zero MIR obf (22 skips, `EH/funclet function`)
    (feeds TK-009).
- Measurement gaps: CFE has no structural marker at any level; all IR passes
  skip silently (no LLVM_DEBUG/errs()); `-taokari-report` omits ocnst;
  NativeIntegrity/DynamicProtection have no corpus candidates/counters; MIR
  success counters unobservable; `verify_transformed_counts.py` unpinned
  seed → non-reproducible counts, passed while 6 families reported 0
  (vacuous) (→ TK-020).
- Bare `-taokari-<pass>` = level 0 (near-inert without `-taokari-level-*`).
- Scratch: `build/taokari-local/tmp_goal_cov/` (measure_corpus.py,
  measure_vmp.py, corpus_results.json, vmp_results.json).

---

## Product work items

### TK-005 — P1: VMP protection-contract failures (goal TK-B) — IN PROGRESS 2026-09-07
- Weakness: `verify_vmp_icall_route` and `verify_vmp_signature_dummy_args`
  documented as genuine VMP contract failures on both platforms
  (progress.md 2026-07-12). Both re-run at HEAD on Windows: rc=1 / rc=1
  (logs `build/taokari-local/tmp_goal/{icall_route,sig_dummy}.{out,err}`).
- Root cause (verified against source, agent report 2026-09-07):
  1. **icall_route = implementation defect.** The pass-manager helper
     skip-net (commit `740b5900e`, 2026-06-30 O(N²) fix) makes
     `runFunctionPass` skip `isTaokariHelper` functions
     (ObfuscationPassManager.cpp:422-425; `Utils.cpp:162` matches
     `__taokari_vmp_interp_`), so `IndirectCall::runOnFunction` never reaches
     the interpreters. Thunks ARE registered in the objects table
     (`doInitialization` is module-wide) but 36 direct
     `call @__taokari_vmp_callthunk_*` remain (4 per interpreter × 9).
     `CodeVirtualization.cpp:3658-3718` (getOrCreateCallThunk + comment)
     intended the icall pass to route them. Commit `740b5900e`'s verification
     list did not include this verifier (created `839e0b8da`).
  2. **sig_dummy_args = verifier drift.** Implementation has **14 real
     params** (`VMState`/`vmp.xstate` added by `aba4e343a` 2026-06-26,
     CodeVirtualization.cpp:2817-2829); verifier hardcodes base 13 → arity
     window 14..17 should be 15..18, delta `arity-13` should be `arity-14`.
     All randomized-signature properties (1..4 dummies, shuffled orders,
     split bc, no legacy `bc`) hold at HEAD.
- Selected seams (Phase B):
  1. Product: exempt the IndirectCall pass from the `__taokari_vmp_interp_`
     component of the skip-net in the pass manager (interpreters still skip
     BCF/MBA/FLA) → re-run verifier (all 4 gates + build+run), sampled
     Windows regression gates, Linux mirror, compile-time A/B on a VMP-heavy
     case (the skip was an O(N²) fix — must not regress).
  2. Verifier: update sig_dummy_args to 14-real-param ABI (window 15..18,
     delta arity-14, assert `vmp.xstate` present). Strictness preserved;
     current rc=1 at HEAD is the teeth evidence for the arity assertion.
- Evidence: (implementation pending)

### TK-006 — P0/P1: Linux `-taokari-max` runtime SIGSEGV family — RESOLVED AT HEAD 2026-09-07
- The 2026-08-31 failing family (`setjmp_eh_unwind_safety`,
  `max_build_no_vmp_hang`, `max_build_vmp_budgeted`, `max_preset_semantics`;
  SIGSEGV rc=-11) **all PASS at HEAD `7f97945b1`** (TK-003 full-suite run:
  6/6 setjmp subchecks, max builds compile+run within budget, 6/6 max-preset
  semantic fingerprints). Intervening loops fixed it; no new work needed.
  Historical record corrected.

### TK-007 — VMP unsupported-surface inventory + reduction (goal TK-A)
- Generated compatibility inventory from real corpus functions; classify every
  unsupported/rejection cause (ISA / lowering / ABI / semantic impossibility /
  performance guard / verifier deficiency); reduce sound classes.
- Evidence: (pending)

### TK-008 — VMP native-island leakage measurement + hardening (goal TK-C)
- Measure % native left in selected VMP functions, CFG location of islands,
  whether islands expose calls/constants/branch conditions; harden where safe.
- Evidence: (pending)

### TK-009 — MIR coverage/safety inventory (goal TK-D)
- Audit every MIR sub-pass vs Windows/Linux x64, EH/funclets/personality,
  red-zone, VMP interpreters, SSE-heavy bodies. Inventory current safety skips.
- Evidence: (pending)

### TK-010 — AArch64 MIR parity (goal TK-E)
- The one open todo.md item: AArch64 MIR dirtybytes equivalent only if
  architecture-safe; verify docs/PLATFORM_MATRIX + AARCH64_PARITY vs source;
  document limitations honestly (no qemu execution available).
- Evidence: (pending)

### TK-011 — Decompiler resistance of emitted output (goal TK-G)
- Verify existing gnarliness/structural gates are non-vacuous at HEAD; audit
  final-object output (not IR) for universal signatures, dispatcher repair,
  direct-call leakage, clean constants.
- Evidence: (pending)

### TK-012 — Randomization quality audit (goal TK-H)
- Where RNG can turn protection fully off, or cause pathological compile
  outliers; multi-seed stability evidence.
- Evidence: (pending)

### TK-013 — Compile-complexity guard (goal TK-F)
- Loops 20-23 concluded: IR-pass compute and NDEBUG backend lanes EXHAUSTED;
  post-obf cleanup tail is RUNTIME-RISK requiring explicit user sign-off.
  This item stays closed unless new evidence reopens it; any new protection
  work must preserve the ≤5%/10% compile-time contract.
- Evidence: loop 20-23 records in progress.md.

### TK-014 — Fast-compiler track (goal Section 14)
- `build/taokari-fast` Release/no-assert/lld build died at ~[959/3332]
  (no ninja process running). Resume per loop-23 recipe, verify, measure
  compile-time win. ADOPTION IS A USER DECISION; do not reconfigure
  taokari-local. Do not resume while exclusive perf measurements are running.
- Evidence: (pending)

### TK-015 — Documentation/status sync (goal TK-I)
- After protection work lands: sync CONFIGURATION.md / PLATFORM_MATRIX.md /
  MACHINE_IR_*.md / todo.md to reality. Never claim unverified support.
- Evidence: (pending)

### TK-017 — P1: opaque-constants starved under full stack (from TK-004)
- Weakness: ocnst transforms **0 constants** when composed after CIE (CIE
  consumes eligible constants first); measured on 9-case corpus at HEAD.
  Its config help advertises composability with CIE. Protection silently
  not applying in composed profiles.
- Plan: explorer to confirm pipeline order + consumption rules, then choose
  seam (e.g. reserve a share of constants for ocnst, or have CIE leave
  ocnst-eligible constants alone when both enabled) with protection-shape and
  compile-time proof. Must not reduce CIE coverage without compensation.
- Evidence: (pending)

### TK-018 — P1?: CSE plaintext leak of `taokari-secret` string (from TK-004)
- Weakness: in the c_strings case, `c_str "taokari-secret"` (private const)
  remains plaintext in obfuscated IR while printf formats get encrypted.
  Need root cause: min-size filter? private-linkage rule? by-design?
  If a secret-looking string class is silently skipped, that is a protection
  gap; if by-design, document the rule.
- Evidence: (pending)

### TK-019 — indbr coverage 1/9 cases (from TK-004)
- Weakness: indirect-branch obfuscation fired in only 1/9 corpus cases
  (dynamic_memory, 66 occurrences); zero elsewhere; passes skip silently so
  "no candidates" vs "skipped" is indistinguishable. Establish eligibility
  truth on the corpus, then either widen sound eligibility or document.
- Evidence: (pending)

### TK-020 — Measurement quality: silent skips, CFE marker, vacuous counts gate (from TK-004)
- Weakness: all IR passes skip silently (no LLVM_DEBUG/skip counters), so
  coverage claims cannot be measured in release builds; CFE has no structural
  marker at any level; `verify_transformed_counts.py` has an unpinned seed
  (non-reproducible counts) and passed while 6 families reported 0 (vacuous);
  `-taokari-report` omits ocnst; MIR has no success counters;
  `tier_release_dashboard.py` `transformed_functions` actually counts enabled
  passes.
- Plan: one measurement-infra seam (skip-reason reporting hook in the pass
  manager or per-pass LLVM_DEBUG + a coverage-dashboard tool), pinned-seed
  fix for the counts gate, CFE marker. Non-vacuousness required (teeth
  proof). This unblocks honest DoD claims for TK-011 and others.
- Evidence: (pending)

### TK-016 — Goal-close sweep
- Definition-of-Done verification sweep (Section 16 of the goal brief):
  full suites green on Win+Linux, inventories current, docs synced,
  `git status` clean, all boxes carry proof + commit hash.

---

## Decision log

- 2026-09-07: Fast build (TK-014) not resumed during baseline measurement
  windows (CPU contention would pollute gate/perf timings on the documented
  bimodal-noise machine).
- 2026-09-07: Post-obf cleanup-tail trim remains blocked on explicit user
  sign-off (loop-23 decision, carried forward).
- 2026-09-08: Background-agent orchestration proved fragile across session
  interruptions (two Windows suite runs died mid-matrix); long suites now run
  as detached host processes with file logs, polled by the orchestrator.

## Completion Definition

Mirrors Section 16 of the goal brief; verified in TK-016 before this document
is declared complete.
