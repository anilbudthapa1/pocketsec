# ADR-0058 — Anti-forgetting verdict: the Stage 6 learner acquires nothing, so it beats neither never-update nor full retrain; recommend never-update + calibration-only

- **Status:** Accepted (measurement)
- **Date:** 2026-09-26
- **Stage:** 6
- **Deciders:** Stage 6 integrator
- **Supersedes / superseded by:** none

> Measurement ADR. Figures from `python -m pocketsec.stage6.cli gate` in the integration
> session (12-month timeline, seed 11, 16 sessions/month, 8 eval sessions per class;
> loadavg 5.0-5.3 during the endurance run). Synthetic corpus: not a detection result.

## Context

Spec §7: the Stage 6 learner must beat `NeverUpdate` on acquisition (R_new on F2, F3) by
≥ 0.10 while keeping F1 retention within `EPS_SECURITY`, and beat `FullRetrain` on cost at
comparable recall; value-aware rehearsal must beat reservoir replay at equal bytes.

**Measured (G6.5, G6.11, G6.13):**

| learner | F1 acq M01 | F2/F3 acq | F1 retention M12 | final FP rate | work units | stored bytes |
|---|---|---|---|---|---|---|
| Stage 6 | 0.0 | 0.0 / 0.0 | 0.0 | 1.0 | 2992 | 7049317 |
| FullRetrain | — | — | — | — | 252579 | 3348005 |

Stage 6 at each replay budget (16384 / 65536 / 262144 B) and reservoir replay at the same
budgets: F1 retention 0.0 in all six runs. Stage 6 at detector capacities 4 and 8:
**UNMEASURED** — the chamber and consolidator take no capacity parameter.

Why the learner acquires nothing, measured in the same session:
- The genesis state alerts on every session with an unexplained step: `DEFAULT_THRESHOLD`
  (0.5) equals `UNEXPLAINED_WEIGHT` (0.5) and the alert rule is `score >= threshold`, so
  the M01 benign FP rate is 1.0 and no detector can add recall.
- Diagnostic (scratch script, no code change): with the genesis threshold at 0.6 the benign
  FP rate is 0.0 in every month, **and the learner still promotes no learned item** — the
  threshold equality is not the only blocker.
- Across the 12 months the chamber was asked to spawn twice (learning deferred 7 months for a
  short replay ring, 3 for probation); one spawn returned `None`, one candidate was refused by
  the conservation gate, one (no learned items) was promoted. The drift discriminator
  classified all 3 corroborated context changes as POISON_SUSPECT and dropped 13 admissions.

## Decision

The anti-forgetting stack is **NOT YET JUSTIFIED**: it neither acquires (F6: R_new 0.0, not
above NeverUpdate's 0.0) nor forgets less than anything, because it never learns. Per spec §7
the recommendation is **never-update + calibration-only** until a corpus and constants exist
on which the learner learns at all. The FullRetrain work ratio (84.4x Stage 6's work) is not a
cost win: Stage 6 did less work because it did nothing.

## Options considered

| Option | Measured consequence | Why not chosen |
|---|---|---|
| A. Claim "no forgetting" | retention 0.0 of nothing acquired | vacuous |
| B. Retune constants until it learns | a spec change (§4.21 values) | STOP condition: needs the lead and an ADR |
| **C. NOT YET JUSTIFIED; recommend never-update + calibration-only (chosen)** | — | — |

## Consequences

The boundary properties (single writer, rollback, lineage, bounded stores) stand on their own
(G6.1, G6.6-G6.8, G6.11). The learning claim does not.

## Addendum — measurement wave, 2026-09-26: the learner as built is REJECTED

- **Status:** Accepted (measurement). Appended, not rewritten: everything above is kept as
  the record of what the integration wave decided. The ADR block 0050-0059 is fully
  assigned, so the measurement verdict lives here rather than under a new number.
- **Evidence:** `docs/stage-6-findings.md` Part M; experiments
  PS-S6-20260926-H6-learnability-0002, -refusal-census-0003, -slow-drip-0004/-0005,
  -poison-suite-0006/-0007, -resources-compare-0010, -candidate-quality-0012 and -v2-0014.
  Every corpus synthetic, seed 11.

### What was measured

1. The Stage 6 learner installs **0 learned items** in all eight runs: 16 and 64
   sessions/month x shipped threshold 0.5 and diagnostic 0.6 x {all mechanisms, all six
   OPTIONAL mechanisms off}. AP over every eval session 0.5000 (the base rate) in all eight.
2. The chamber issued 7 candidates carrying learned items (4 DETECTORs each) across the four
   configurations; the boundary refused **7 of 7** (G3 recall gain 0.0 or no holdout at 0.5;
   G8 shadow disagreement 0.96875-1.0 at 0.6). Scored on every held-out eval session, those
   candidates alert on every benign session: the motif induced is `IMPERSONATE` with no
   property requirement, which the corpus (correctly) puts into benign traffic. **The
   refusals were right; the learner is what fails.**
3. On the same stream `FullRetrain` (same `induce_motifs`, all retained labelled history)
   reaches AP 0.8790, acquisition 1.0/1.0/1.0 on F1/F2/F3, F1 retention 1.0 at M12 through
   the M09 twin (per-month recall at FPR 0.05) — and 12 poisoned items (20 at 64/month).
   Its "benign FP 0.0" is not precision: its refitted threshold (0.900001) sits above its own
   detector weight (0.9), so at its operating point it alerts on nothing; the same holds for
   `Stage2Only` (threshold 0.666668, AP 0.7302, 0 poisoned items)
   (PS-S6-20260926-H6-candidate-quality-v2-0014). Ranking, not the operating point, is the
   valid comparison until `labs/continual_baselines.py`'s threshold refit is repaired. `NeverUpdate`'s F1 retention falls from 1.0 to
   0.0 at M09 (the T3 twin), so "never-update" is not a best choice on this corpus either.
4. Stage 6 stores 2.1x full-retrain's bytes (7049317 vs 3348005 B) and costs 1/1.49-1/1.72
   of its CPU because it learns nothing; the G6.11 work-unit ratio (84.4) omits every
   unmetered Stage 6 subsystem and is not a cost figure.

### Decision (amends the Decision above)

| Option | Measured consequence | Verdict |
|---|---|---|
| A. Keep "never-update + calibration-only" as the recommendation | never-update F1 retention 0.0 from M09; calibration-only acquires no F2/F3 | kept only as the *safe default* (it installs nothing unsafe), no longer described as the best learner |
| B. Ship the Stage 6 learner | 0 items, AP 0.5000 in 8/8 runs | **REJECTED (as built)** |
| C. Ship FullRetrain ungated | best security figures, 12-20 poisoned items | refused: it is the unguarded baseline |
| **D. Keep the boundary as the only writer; rebuild the learner and measure FullRetrain *inside* the boundary next (chosen)** | boundary refused 7/7 bad candidates, 0 spurious rollbacks in 720 sessions, 28/28 byte-identical rollbacks | — |

The anti-forgetting stack stays **NOT-YET-JUSTIFIED**; the OPTIONAL `HEL-F*` mechanisms are
recommended default-off (all-optional-off gives the identical outcome in 4/4 configurations);
the drift discriminator is observed harmful to learning (3/3 false POISON_SUSPECT; 8-65
legitimate normality admissions dropped per run). Changing any §4.21 constant, or the
threshold defect (`DEFAULT_THRESHOLD == UNEXPLAINED_WEIGHT`), remains the project lead's
decision.

## Addendum — review-fix session, 2026-09-26: the HEL-F19 "harmful" verdict is RETRACTED

- **Status:** Accepted (correction). Appended, not rewritten; the addendum above is kept as the
  record of what the measurement wave concluded. Block 0050-0059 is still fully assigned.
- **Evidence:** `docs/stage-6-findings.md` M.15; regression test
  `tests/test_stage6_endurance.py::test_the_drift_window_holds_verdicts_from_before_its_pivot`.

The measurement addendum called the drift discriminator "observed harmful to learning (3/3
false POISON_SUSPECT; 8-65 legitimate normality admissions dropped per run)". An independent
review found, and this session reproduced, that the harness gave `drift_signals` a window
holding **no verdict from before the change** (`StageSixLearner.on_epoch` started it empty at
the pivot), so every pattern key counted as "changed", any protected-anchor traffic made
semantics "unstable", and POISON_SUSPECT was forced. That measured the wiring, not the
mechanism. With the window fixed (the last `DRIFT_ALIGN_WINDOW` verdicts before the pivot plus
those after), the 12-month run classes 3/3 corroborated changes UNDETERMINED
(`too_few_independent_groups`: breadth 0.0, no changed pattern), drops **0** admissions, and
the HEL-F19 ablation row is delta 0.0 with no outcome changed. **Verdict: NOT-YET-JUSTIFIED
(inert on this corpus), not harmful.** The same addendum's "Stage 6 stores 2.1x full-retrain's
bytes" is also retracted as a memory figure: the two sides use different estimators (M.15).
Nothing else in the decision above changes.
