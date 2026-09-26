# ADR-0073 — Falsification discipline: immutable genomes, preregistration before evaluation, one Bonferroni batch per held-out split

- **Status:** Accepted
- **Date:** 2026-09-26
- **Stage:** 8
- **Deciders:** Stage 8 integrator (spec D8.3, D8.11, D8.18; one integration-session finding recorded below)
- **Supersedes / superseded by:** none

> Contract ADR: the kill switch the lead requires.

## Context

The lead: every hypothesis has a pre-registered test and a kill criterion recorded BEFORE the
data is looked at; the ledger is append-only; a hypothesis cannot be edited after its test runs;
a hypothesis true on TRAIN by construction and false held out must be killed.

## Decision

1. A `HypothesisGenome` is immutable and content-addressed (`hyp-` + sha256 prefix); it has no
   status field and no free-text field. An edit is a new id with a parent link.
2. Every genome carries `MANDATORY_FALSIFIERS ⊇ {HOLDOUT_ENRICHMENT, HOLDOUT_FALSE_POSITIVES,
   REPLICATION}`, registered at birth; construction refuses anything else.
3. `TheoryLedger` is append-only and digest-chained. A `PREREGISTER` entry is required before a
   `TEST_RESULT`; a second preregistration, a second result, and re-registration of a tested id
   are refused (`LedgerError`, counted). The preregistration's prediction and α must equal the
   genome's.
4. Each held-out split is evaluated once, in `HoldoutVault`, as one batch of size m with the
   exact binomial test at α/m.
5. **Integration finding (recorded, not re-worded).** In `run_discovery` the trap
   `SINGLE(SPAWN)` is refuted by the pre-holdout `COUNTERFACTUAL_INVARIANCE` screen
   (`DECOY_INSERTION` copies fork steps) before it can be registered. G8.1(d) as written requires
   "generated AND registered AND refuted" in the loop, so G8.1 FAILS on that clause. The vault
   is exercised in isolation by `probe_trap_at_holdout`, whose result G8.1 reports beside it.
   Changing G8.1(d) to read the probe instead would be re-operationalising a criterion to pass,
   which the spec (§12) forbids; the lead decides whether to restate it.

## Options considered

| Option | Security cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|
| A. Mutable genome with a status field | edit-after-test possible | low | not built | the lead forbids it |
| **B. Immutable genome + ledger + vault (chosen)** | none | medium | edit-after-test refusals fire 3/3 in G8.1(c) | — |
| C. Evaluate each hypothesis in its own held-out batch (no Bonferroni) | the family-wise error grows with the batch | low | the `bonferroni` ablation row measures it | kept only as a control |
| D. Bind G8.1(d) to the vault probe | a criterion re-worded into a pass | low | the probe refutes the trap at HOLDOUT | forbidden (spec §12); reported instead |

## Consequences

**Accepted costs.** G8.1 fails on a literal clause while the trap is refuted.

**Bounded state.** `MAX_LEDGER_ENTRIES` 16384 (windowed with CHECKPOINT), `MAX_THEORIES` 2048
(terminal records fold into negative memory, 1024).

**Reversibility.** In-memory per run; nothing is persisted.

**Authority.** None.

## Verification

`tests/test_stage8_integrity.py` (preregistration refusals, edit-after-test, chain tamper),
`tests/test_stage8_experiments.py` (trap), G8.1.

## Prior art

No novelty claim (standard preregistration and Bonferroni).

## Amendment 2026-09-27 — fix wave: where the trap really dies, per-reading memory, refuted ids stay refuted

- **Status of this amendment:** Accepted (code and regression tests in this wave; measurements in
  `docs/stage-8-findings.md` §F). The text above is kept; block 0070–0079 is full, so this is an
  amendment, not a new ADR.

### What was found (review findings F1, F4, F5, F1-medium)

1. **The in-loop trap kill was a vocabulary artefact (F1).** DECOY_INSERTION was PRESERVING for
   every hypothesis and adds non-escalating donor steps under new actors; a SINGLE over a
   non-escalating step fires on such a decoy actor. So the invariance screen refuted every
   hypothesis over a non-escalating step and none over an escalating one. Measured this session
   (`benchmarks/stage8/trap_placement.py`, PLANTED content 0, `RunConfig(seed=0)`): on the pre-fix
   tree the authored trap `SINGLE(SPAWN)` scored 0.492 under the decoy relation (1.0 under the
   other four) and was refuted at `challenge:COUNTERFACTUAL_INVARIANCE`; the same trap placed on
   an escalating step (`setuid uid 0`, `SINGLE(IMPERSONATE^privilege)`) scored 1.0 under every
   relation.
2. **Negative memory was direction-blind (F4)**: a refuted MALICIOUS:M suppressed BENIGN:M.
3. **A retirement overwrote a refutation and a folded refuted id could be born again (F5).**
4. **A killed reading could be re-born under a new id and re-tested on the same split (F1-medium).**

### Decision

1. DECOY_INSERTION is PRESERVING only relative to a hypothesis none of whose predicates a decoy
   step matches (`laboratory.counterfactual.decoy_is_neutral`). The invariance screen, the
   Reproducibility Gate's metamorphic check and ORACLE's decoy designs skip decoyed worlds the
   hypothesis names; they are not applicable, never counted as flips. After the fix, the same
   script measures the authored trap at 1.0 under all five relations; it is **registered and
   refuted at HOLDOUT by the vault** (`TrapOutcome(generated=True, registered=True, refuted=True,
   refuted_at='HOLDOUT')`). The escalating-placement trap is **not generated** by the engine on
   either tree (why is UNMEASURED; the Φ-oracle explaining the escalating step so that it never
   reaches a residual cluster is the untested candidate reason); the vault-alone probe refutes it
   at HOLDOUT on both. So the in-loop evidence that the discipline
   kills a TRAIN-only hypothesis is now the vault's, and it rests on one placement.
2. `NegativeResult` carries its `Direction`; memory is keyed by (mechanism digest, direction).
3. A retirement never replaces a refutation for the same reading (`dead_end_kept`). The ledger
   keeps a bounded tombstone (id → terminal status, `MAX_TOMBSTONES` = 8 × `MAX_THEORIES`,
   evictions counted) for every folded id: a folded id is refused re-birth and `status()` still
   answers for it.
4. The ledger refuses a preregistration whose (split digest, mechanism digest, direction) already
   has a result under another id (`refused_retest_on_split`; bounded like the tombstones).

### Not fixed (accepted known defects, reported)

- **One batch per split across runs (F6 / S8-FALS-03).** The rule is enforced per vault and, now,
  per reading within one ledger. Separate `run_discovery` calls build fresh ledgers over the same
  corpus HOLDOUT and REPLICATION, and the gate's ablation, search, ORACLE and sensitivity runs all
  look at the same held-out splits; the defaults chosen from those comparisons were chosen on
  held-out data. Enforcing it across runs needs a persistent split registry, which the stage
  deliberately does not write (lesson 7). Stated, not fixed.
- **The ledger does not re-derive `survived` from the stored counts (S8-FALS-02).** SURVIVED and
  REPRODUCED rest on the vault's `TestOutcome`; the ledger backs a status with the vault's
  outcome, not with its own recomputation of the refutation rules.
- **Vacuous screens (F12).** A genome firing on nothing in LAB_POOL passes NECESSARY_STEP_ABLATION
  with `drop=None`, and invariance is agreement over all pairs, so a genome firing on ≤ 2 of 120
  passes at 0.98 whatever it does on them. The ledger has no PROPOSED → INSUFFICIENT_EVIDENCE
  transition, and recording these as failures would turn "unknown" into "refuted" (DL-06), which
  negative memory would then treat as a dead end.

### Options considered (amendment)

| Option | Security cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|
| A. Keep DECOY_INSERTION PRESERVING for every hypothesis | the trap's kill is decided by where it was authored | none | trap refuted at the screen (0.492), escalating trap untestable by the screen | author confound (lesson 6) |
| B. Drop DECOY_INSERTION from the invariance screen | loses a real nuisance test for hypotheses the decoy cannot touch | trivial | not measured | throws away the relation where it is valid |
| **C. Judge decoys relative to the hypothesis (chosen)** | none | low | trap 1.0 under every relation; registered; refuted at HOLDOUT | — |

## Verification (amendment)

`tests/test_stage8_regressions.py`: `test_f1_decoys_matching_the_hypothesis_do_not_decide_invariance`,
`test_f4_*`, `test_f5_*`, `test_f1_medium_a_reading_is_tested_once_per_split_whatever_its_id`.
