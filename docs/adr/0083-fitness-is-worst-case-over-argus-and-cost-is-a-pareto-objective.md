# ADR-0083 — Fitness is worst-case over the ARGUS scenario attacks; cost is a Pareto objective, never a tiebreak or a weighted sum

- **Status:** Accepted
- **Date:** 2026-09-26
- **Stage:** 9
- **Deciders:** Stage 9 integrator (decided at spec time, `docs/stage-9-spec.md` §4.1, §4.6; the lead's "adversarial testing is part of fitness" and "minimum sufficient means cost is an objective")
- **Supersedes / superseded by:** none

> Measurement-contract ADR. It fixes what "fitter" means for every Stage 9 selection.

## Context

The lead's orders: every surviving genome is attacked, fitness is worst-case over the attack
set (not average), and "minimum sufficient" makes cost an objective, not a tiebreak. Two
failure modes this rules out:

- An average over attacks lets one catastrophic attack hide behind five benign ones. A detector
  that a single renaming defeats is not robust, however good its mean.
- A weighted sum of quality and cost has to price a unit of AP in work units. The price is
  a hidden parameter that decides every selection (lesson 5: an uncalibrated threshold is a
  parameter).

## Decision

1. `ontogenesis.fitness.evaluate` scores a genome on a suite (clean plus the six
   `SCENARIO_ATTACKS`: rename_binaries, reorder_across_actors, benign_duplicate_flood,
   timing_stretch, sensor_drop_10, lineage_table_flood). `worst_case_ap` is the **minimum** AP
   over the seven variants. An abstaining session ranks at 0.0 and is counted.
2. Selection inside every search uses **train** worst-case AP only. Held-out (seed 11, the same
   seven variants) is evaluated after the search and never chosen on.
3. Dominance is on (worst-case AP ↑, WU/event ↓, state bytes ↓) (`spec.mssc.dominates`,
   `pareto_front`). Description length is reported, not a dominance axis. `beats` requires a
   margin on one axis (+0.02 AP, or 10% less WU or bytes), no hard-constraint violation, and not
   being dominated. MSDL's scalar exists only as the measured alternative that
   `compare_msdl_selection` tests against the Pareto choice (G9.9).
4. The MSSC hard constraints (`MSSCConstraints`: worst-case AP ≥ base rate + 0.05, worst/clean ≥
   0.85, ≤ 65,536 state bytes, ≤ 64 WU/event) are **chosen**, not measured. A run's winner is
   the best train worst-case genome that satisfies all of them. A run with none has **no
   winner**, and that is reported rather than relaxed.
5. The integrator's reading of spec §4.9 when a run has no winner: a missing winner never
   counts as beating (see ADR-0085 for the measured case).

## Options considered

| Option | Security cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|
| A. Mean AP over variants | one catastrophic attack can hide | low | not measured: the spec fixed worst-case before any run | the lead's order |
| B. Worst case over variants (chosen) | the most conservative | low | on the gate run, the held-out worst case differs from clean for H1 and H2 but not for the Φ-oracle (docs/stage-9-findings.md) | chosen |
| C. A weighted quality-cost scalar | an unmeasured price decides selection | low | the only scalar, MSDL, is measured against the Pareto choice in G9.9 | a hidden parameter |
| D. Pareto on (AP, WU, bytes) (chosen) | none | medium | the Pareto placement of every winner and the references is printed in G9.1 | chosen |

## Consequences

**Accepted costs.** Worst-case fitness is harsh. Under a 0.85 robustness floor it can leave a
random or evolved search with no admissible genome at all (ADR-0085), and that outcome is
reported, not softened.

**Bounded state.** `EvaluationCache` is bounded at 4096 entries, with evictions counted.

**Reversibility.** The constraints are one frozen dataclass. Changing them needs this ADR
superseded.

**Authority.** None.

## Verification

`tests/test_stage9_evaluation.py`, `tests/test_stage9_genome.py` (dominance, `beats`), gate check
G9.1 (the beats rows and the Pareto placement) and G9.8 (fittest-under-attack).

## Prior art

None claimed. Worst-case-over-perturbation evaluation is standard robustness practice.

## Addendum A (2026-09-26, measurement-engineer session): the robustness ratio silently decides the answer

Lesson 5 ("an uncalibrated threshold is a parameter; check whether one threshold decides every
outcome") applies to decision 4. With worst-case AP already the fitness, the extra constraint
`worst/clean ≥ r_min` rejects genomes whose worst case is *higher* than the admitted winner's:

- `r' = r + ΔΦ` (MAX over lineages): train worst-case 0.5940 at a worst/clean ratio of 0.816, so it
  is refused at 0.85. The admitted Φ-oracle has train worst-case 0.5872 at a ratio of 0.996.
- Held-out worst-case, refused against admitted: 0.6256 vs 0.5975 (seed 11) and 0.6883 vs 0.5705
  (seed 17), at identical cost (3 WU/event, 1184 B).
- The exhaustive winner is the refused genome for every `r_min ≤ 0.81`, and the Φ-oracle for
  every `r_min ≥ 0.82` (sweep 0.70-0.95, and with the ratio removed;
  `PS-S9-20260926-H5-robustness-threshold-sweep-0001`).
- Random search at 4x draws the same genome on seed 202 (draw #172) and discards it for the same
  reason.

This addendum changes no code and no constraint: the constraints are frozen until this ADR is
superseded. The lead must decide whether the ratio stays. Until then every "minimum sufficient
computation" statement must carry "under r_min = 0.85", and the unconstrained answer is reported
beside it.

## Addendum B (2026-09-26, review-wave fixes): what "died under attack" counts, and why cap padding is not a fitness attack

`fittest_die_under_attack` killed any top-k genome whose worst case fell below the Φ-oracle's
train worst case (0.5872). A worst case is never above its clean AP, so every genome that was
merely weaker than the incumbent on clean data "died" with every attack a no-op. The gate's
"10/10 of the fittest died under attack" in each evolutionary run measured that, not the
attacks (S9-R2, S9-FC-01, S9-CX-03). `FittestAttrition` now reports `died_under_attack` (clean −
worst > 0.05, or pushed from at/above the reference to below it) as the headline, beside
`died_without_attack` (the same rule with the attack set removed) and the old disjunctive
`died`. G9.8 prints all three.

Head padding past `MAX_SESSION_EVENTS` (ADR-0082 addendum A) is a lifecycle DEFENCE, not a
scenario attack in the fitness set. Every bounded-window genome abstains on every padded
session, so as a fitness attack it would pin every genome's worst case at the same chance
level: one attack silently deciding every outcome (lesson 5). The worst-case-over-attacks claim
therefore does **not** cover cap padding, and the documents say so.
