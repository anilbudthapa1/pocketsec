# ADR-0079 — FORGE verdict: compression preservation, deployability, DCR, direct-model baseline, endpoint footprint

- **Status:** Accepted (written from measurement; the figures are the gate run recorded in `docs/stage-8-findings.md` §M.5)
- **Date:** 2026-09-26
- **Stage:** 8
- **Deciders:** Stage 8 integrator
- **Supersedes / superseded by:** none

> Measured-verdict ADR.

## Context

The lead: a compressed candidate must preserve measured security quality within a stated tolerance
AND cost less, or it is not deployable; check the target can EXPRESS the function first.

## Decision

1. FORGE's selection is a pure function of recorded measurements (`reselect`), tolerance 0.02 on
   recall and precision, 0.0 on FPR, agreement ≥ 0.98, artifact ≤ 64 KiB, and "costs less" against
   TYPED_RULE on work units per event and artifact bytes. The gate re-derives it (G8.7(b),(d)).
2. Expressibility fires: PM2 (`REPEATED`) compiled directly is refused by `MOTIF` with
   `MOTIF_CANNOT_EXPRESS_REPEATED`; tournaments over `CO_OCCURS` theories record
   `MOTIF_CANNOT_EXPRESS_CO_OCCURS`.
3. **Finding (forge builder, confirmed as a convention, lesson 5):** `FSM` is charged for its state
   transitions while the genome evaluator is not charged for its own bookkeeping, so the
   work-unit axis is decided by the accounting convention for REPEATED theories.
4. **Finding (lesson 5):** `run_tournament` judges fidelity to the theory it is given, not the
   theory's quality; the only barrier to packaging a refuted theory is upstream
   (`Stage6Adapter` refuses anything not REPRODUCED; `run_discovery` packages REPRODUCED only).
5. **Against the direct model** (LOGISTIC on TRAIN labels, pooled features): the selected
   representation of a single-mechanism package recalls only its own family, so the §7 rule
   "recall ≥ direct − 0.02 at ≤ its FPR" is not met; the direct model pays far more work units per
   event at a far higher FPR. Recorded in G8.12, not re-worded.
6. The endpoint footprint of every shipped artifact is measured in-process with Stage 0's
   sampler (G8.11(c)); device figures are UNMEASURED.

## Options considered

| Option | Security cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|
| A. Ship TYPED_RULE always | none | none | never cheaper by construction | FORGE would be inert |
| **B. Measured Pareto selection with tolerance (chosen)** | none | medium | G8.7 deployable counts in the findings | — |
| C. Select by wall time | a contended-host artefact decides | low | not built | timings transfer only as within-run ratios |

## Consequences

**Accepted costs.** Deployability of REPEATED theories depends on the work-unit convention.

**Bounded state.** Artifacts ≤ 64 KiB; endpoint incremental RSS ceiling 20 MiB (measured per run).

**Reversibility.** A package is evidence only; Stage 6 owns adoption.

**Authority.** None.

## Verification

G8.7, G8.11(c), `tests/test_stage8_forge.py`.

## Prior art

No novelty claim.

## Amendment 2026-09-27 — measurement session: the direct-model comparison, retracted and re-measured

- **Status of this amendment:** Accepted (figures and commands in `docs/stage-8-findings.md` §M.1,
  §M.6 and Appendix A). The text above is kept unchanged; block 0070–0079 is full, so this is an
  amendment.

### What was measured

1. **Decision 5 above is retracted in part.** "The direct model pays far more work units per event
   at a far higher FPR" compared FORGE against a direct model fitted on TRAIN labels alone, where
   the trap is a perfect positive feature (REPLICATION FPR 0.2532). Fitted on TRAIN + HOLDOUT (the
   labels the loop reads), the same model reaches REPLICATION recall 1.0 at FPR 0.0 (AP 1.0000) on
   3/3 content seeds.
2. **Through `run_benchmark`** (REPLICATION as a checksum-bound Stage 0 dataset; 240 sequences,
   1324 events; loadavg ~23), cells are recall / FPR / PR-AUC and CPU s per event:
   - Φ ∪ FSM: 0.6463 / 0.0 / 0.7672 at 5.12e-06;
   - FSM alone: 0.3537 / 0.0 / 0.5745 at 4.68e-06;
   - equal-information direct model: 1.0 / 0.0 / 1.0000 at 2.53e-05 (4.93× Φ ∪ FSM, within-run).
3. **FORGE by its own rule works.** The FSM (216 B, 10.24 wu/event) equals TYPED_RULE (recall
   0.3537, FPR 0.0, agreement 1.0; 11.03 wu/event, 2475 B). MOTIF is refused
   (`MOTIF_CANNOT_EXPRESS_CO_OCCURS`). The deployed artefact adds 4096 B of RSS
   (`measure_endpoint_footprint`).

### Decision

FORGE's compression step is kept: it is expressibility-checked, measured, cheaper, and loses nothing
against the rule it compresses. **The FORGE output is NOT-YET-JUSTIFIED against training a small
model directly** (the §7 "direct model" row): the direct model with equal information recalls every
REPLICATION positive at FPR 0.0 on this corpus, for about 5× the CPU per event. On a saturated corpus
this comparison cannot favour a rule compiled from one mechanism; it must be repeated on a
non-saturated corpus (ADR-0077 amendment).

### Options considered (amendment)

| Option | Security cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|
| A. Keep the trap-poisoned direct-model comparison | a flattering baseline | none | FPR 0.2532 is an artefact of TRAIN-only fitting | lesson 4: include the isolating control |
| **B. Compare against the equal-information direct model (chosen)** | none | trivial | recall 1.0 vs 0.6463 at 4.93× CPU/event | — |

## Amendment 2 2026-09-27 — fix wave: "costs less" was self-charged; "measured, cheaper" is RETRACTED

- **Status of this amendment:** Accepted (code and tests in this wave; figures in
  `docs/stage-8-findings.md` §F). The text above is kept; block 0070–0079 is full.

### What was found (F2, honesty lens)

Amendment 1's "FORGE's compression step is kept: it is ... measured, cheaper" and findings §M.6's
"the FSM ... is 7 % cheaper per event and 91 % smaller" are **RETRACTED**. "Costs less" was decided
only by the work units each representation charges itself and by artifact bytes in which
TYPED_RULE serialised its whole genome (provenance, competitors, falsifiers, scope; the reviewer
measured 1566-2475 B against about 63 B of decision-relevant content, not re-measured here). The reviewer measured the shipped FSM 1.23-1.26x
*slower* in CPU than the rule it replaced (identical decisions), and an FSM patched with a 200 us
busy-wait (17.9-21.6x slower; reviewer's figures) was still selected, deployable, and passed G8.7.
This wave reproduces the second case as a regression test on MOTIF (see Verification).

### Decision

1. "Costs less" additionally needs the recorded within-run wall ratio to TYPED_RULE to be at most
   `FORGE_WALL_RATIO_MAX` = 1.0. The ratio is the median over `WALL_REPEATS` = 9 interleaved
   (reference, entrant) passes, alternating order, same meter kind; an unmeasured ratio is
   `cost_unmeasured`, never cheaper. Selection still reads only recorded measurements, so
   `reselect` stays a pure function of a stored `TournamentResult`. The gate's (G8.7(d)) and the
   sensitivity sweep's restatements include the same condition.
2. TYPED_RULE's `artifact_bytes` in a tournament is its **decision-relevant** size
   (`tournament.decision_relevant_bytes`: kind, direction, mechanism DSL, forbidden predicates).
3. Measured this session on PM1, PLANTED content 3 (60 REPLICATION episodes, loadavg ~11): per
   entrant, 20 re-measurements of the ratio at 5 pairs gave MOTIF median 0.965 (min 0.745, max
   1.004; 1 of 20 above 1.0) and FSM median 1.099 (min 0.91, max 1.309; 18 of 20 above 1.0); at
   240 episodes MOTIF 0.959 (2/20 above 1.0), FSM 1.081 (19/20 above 1.0). So the FSM is slower
   than the rule it compresses, and MOTIF (where it can express the theory) is not measurably
   slower. With the fix, PM1's tournament selects MOTIF (89 B vs the rule's 132 decision-relevant
   bytes, equal work units); the FSM is refused `not_cheaper_than_reference` (194 B > 132 B).
   Selection near a ratio of 1.0 is a timing measurement and can flip between runs; that is
   stated, not hidden (the test fixtures that need a deployable tournament re-measure up to 5
   times and say so).

### Options considered (amendment 2)

| Option | Security cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|
| A. Keep self-charged work units as the cost axis | a slower detector ships as "cheaper" | none | 21.6x slower stub passes G8.7 | the claim was false |
| B. Replace work units by CPU time | selection nondeterministic on every axis | medium | not done | work units stay useful as the budget axis |
| **C. Keep work units and bytes, add the within-run wall ratio, fix the reference's bytes (chosen)** | none | low | stub refused; FSM refused; MOTIF selected where expressible | — |

## Verification (amendment 2)

`tests/test_stage8_regressions.py::test_f2_honesty_a_deliberately_slow_compressed_form_is_not_deployable`,
`tests/test_stage8_forge.py::test_the_selection_rule_bites_at_its_exact_edges` (wall-ratio rows),
`test_typed_rule_is_never_deployed_and_a_slower_entrant_never_costs_less`.
