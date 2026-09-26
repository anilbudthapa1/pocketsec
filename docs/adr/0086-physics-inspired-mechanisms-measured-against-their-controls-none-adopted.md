# ADR-0086 — Physics-inspired and law-discovery mechanisms, measured against their controls: five removed, three JUSTIFIED on the letter and none adopted

- **Status:** Accepted
- **Date:** 2026-09-26
- **Stage:** 9
- **Deciders:** Stage 9 integrator, from the gate run (`python -m pocketsec.stage9.cli gate`, 2026-09-26; saved evidence `summary.evidence.comparisons`)
- **Supersedes / superseded by:** none

> Measured-verdict ADR. It decides eleven `*_DEFAULT_ENABLED` flags. All stay `False`.

## Context

Phase gate G9.9: "Novel physics-inspired mechanisms must beat simpler baselines or be removed."
Each mechanism's `compare_*` ran on the gate context and returned one `DetectorComparison`. The
subject genome was chosen on train: the best winner of any arm, the Φ-oracle rediscovered by
exhaustive enumeration, because the evolutionary arm had no winner. Figures are held-out
(ambiguous 240, seed 11) unless stated. For context, the clean held-out APs of the hand rules
are: Φ-oracle 0.5975, H1 0.7680, H2 0.8111.

## Decision: the verdicts, and why the three JUSTIFIED ones are not adopted

| mechanism (flag) | verdict | value vs controls | fired | decision |
|---|---|---|---|---|
| symmetry breaking | REJECTED | 0.3583 vs rarity 0.3333, Φ-oracle 0.5975 | 34 | removed (flag `False`) |
| conservation / Noether | REJECTED | 0.5975 vs Φ-oracle 0.5975, H2 0.8111 | 45 | removed |
| MSDL selection | REJECTED | 0.3333 vs Pareto choice 0.3648 (−0.0315) | 3 | removed; Pareto selection stays |
| algorithmic / probabilistic surprise | REJECTED | 0.3636 vs novelty peak 0.3333, Φ-oracle 0.5975 | 35 | removed |
| morphogenesis / speciation | REJECTED | all 4 measurable niches UNIVERSAL_SUFFICES; 5 host-role niches UNMEASURED | 0 (INERT) | removed |
| phase observatory | NOT_YET_JUSTIFIED | 0.5971 vs CUSUM 0.5863, Φ-oracle 0.5975 | 4 | off |
| learning-law search | NOT_YET_JUSTIFIED | benign FP 0.0 for every law and for NO_LEARNING | 15 | off; see note A |
| hysteresis | NOT_YET_JUSTIFIED | transitions 17 → 9 (47% fewer, bar 50%); 8.8% of steps held lower (bar ≤ 10%) | 35 | off |
| **causal geometry** | **JUSTIFIED** | 0.6672 vs pooled kNN 0.4313, Φ-oracle 0.5975 | 57 | **not adopted**: note B |
| **renormalization** | **JUSTIFIED** | R4 conserves AP 0.5975 with 1,380,096 of 13,745,664 feature bytes; random group drop 0.3333 | 240 representations changed, **0 scores changed** | **not adopted**: note C |
| **learned forgetting** | **JUSTIFIED** | EXPONENTIAL_DECAY λ=0.9: AP 0.5830 at 72 B/lineage, utility/byte 0.0035; EXACT_RING (ring 8): 0.5583 at 128 B, 0.0018 | 2 | **not adopted**: note D |

**A. Learning laws: a blind spot in the §4.14 rule, reported, not re-ruled.** On Stage 2's drift
corpus (count 120, seed 11) the control and every law already sit at benign FP 0.0, so an FP-only
rule cannot justify anything. Two laws raise recall from 0.1481 to 0.7037 at the same FP 0.0
(`THRESHOLD_QUANTILE`, `EWMA_THRESHOLD`). A recall-aware rule would likely call that a win. Whether
to change the rule is the lead's decision; changing it after seeing the result would be a
forking-paths choice.

**B. Causal geometry** beats its two spec controls, but H2 (clean held-out 0.8111) and H1 (0.7680),
two one-register rules costing 3-4 WU/event, beat it by 0.10 to 0.14 on the same split. It beats
the baselines it was assigned, not the simpler baselines that exist. The physics package asked for
H2 to become a control. This ADR records that request instead of adopting the mechanism.

**C. Renormalization** is JUSTIFIED because the subject genome reads only ΔΦ. Any coarse-graining
that keeps the ΔΦ slots keeps its scores (0 of 240 score changes), while an equal-byte *random*
group drop can remove them. That measures the subject's input set, not a property of
renormalization.

**D. Learned forgetting** beats its control, EXACT_RING, but both are *rewrites* of the subject's
register, and both lose to the unrewritten subject: the plain per-lineage running maximum, the
Φ-oracle itself, scores 0.5975 held-out worst-case at the same 72 B per lineage the
one-register families are charged (one 8-byte value plus the 64-byte lineage overhead). The isolating control
(lesson 4) was missing from the grid, and the "win" is the less-bad of two degradations. One
subject, one corpus, one seed.

## Options considered

| Option | Security cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|
| A. Switch on every JUSTIFIED flag | ships three mechanisms that simpler rules beat or that measure the subject | low | B, C, D above | lesson 4, lesson 6 |
| B. Keep every flag off, record JUSTIFIED verdicts with their caveats (chosen) | none | low | G9.9 reads `False` for all 16 flags | chosen |
| C. Re-run the three with added controls (H1/H2 for causal geometry, the unrewritten register for forgetting) | none | medium | not run this session | a post-hoc control change needs the lead's sign-off; recorded as the next measurement |

## Consequences

**Accepted costs.** None of the physics-inspired layer is adopted, so architecture §68's
"physics-inspired layer removed wholesale" branch holds on this corpus.

**Bounded state.** None changed.

**Reversibility.** Each flag is one module constant. It turns on only with a JUSTIFIED verdict
against the added controls, cited in a successor ADR.

**Authority.** None.

## Verification

Gate G9.9 rows; `pocketsec-stage9 gate --save` evidence `comparisons`.

## Prior art

None claimed.
