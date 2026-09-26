# ADR-0085 — Evolutionary search versus random search and exhaustive enumeration: NOT-YET-JUSTIFIED; exhaustive enumeration rediscovers the Φ-oracle

- **Status:** Accepted
- **Date:** 2026-09-26
- **Stage:** 9
- **Deciders:** Stage 9 integrator, from the gate run (`python -m pocketsec.stage9.cli gate`, 2026-09-26)
- **Supersedes / superseded by:** none

> Measured-verdict ADR. It decides `EVOLUTIONARY_SEARCH_DEFAULT_ENABLED` (stays `False`) and
> records how a run with no admissible winner is scored.

## Context

The lead's order: "If evolutionary/structured search does not beat random search at equal
budget, it is NOT-YET-JUSTIFIED." Spec §4.9 adds exhaustive enumeration of the 126-genome
≤2-node space as a second control. The metric is the held-out (seed 11) worst-case AP of each
run's winner, where a winner is the best *train* worst-case genome that satisfies every MSSC
constraint (ADR-0083).

The gate ran each arm on ambiguous count 240, train seed 3, at a 96,000,000 WU budget per
(strategy, seed), with seeds 101, 202 and 303, main arm with every flag at its shipped `False`:

| arm | evaluations per run (probe, seed 101) | MSSC-satisfying winners | held-out worst-case AP |
|---|---|---|---|
| exhaustive (1 run) | 126, 65,577,033 WU | 1/1: **the Φ-oracle genome** (digest `sha256:717e9f47…`) | 0.5975 |
| random (3 runs) | 67 | 1/3 (seed 202) | 0.4262 (17 WU/event) |
| evolutionary (3 runs) | 72 | **0/3** | — |

The per-run evaluation counts come from this session's timing probe on seed 101 (load 3.7-5.5).
The winner counts come from the gate run. One random genome costs about 1.4M WU to evaluate on 7
variants of 240 sessions, so a 96M budget buys about 70 evaluations.

**Why nothing was admissible** (a second probe, seed 101, `check_constraints` on every evaluated
record). The binding constraint is quality, not robustness:

| strategy | records | violate detection quality (worst-case AP < base rate + 0.05 = 0.3833) | violate robustness | constant-output genomes | best train worst-case AP |
|---|---|---|---|---|---|
| random | 67 | 67 | 3 | 30 | 0.3747 |
| evolutionary | 72 | 72 | 1 | 43 | 0.3747: the same genome as random's best (both arms draw their initial genomes from one generator on seed 101), so variation improved nothing |

Random genomes of up to 3 registers and depth 3 land near the 0.3333 base rate, and 30-43 of
about 70 compute a constant. The variation operators' firing count (winners found after the
initial population) is **0 of 3**: about 40 variation steps did not climb out of that region.

## Decision

1. **Verdict: NOT_YET_JUSTIFIED.** Evolution beat neither control. On seed 202 random search
   found an admissible genome and evolution did not; exhaustive enumeration found the Φ-oracle and
   evolution found nothing. `EVOLUTIONARY_SEARCH_DEFAULT_ENABLED` stays `False`. **The
   exhaustive result is the answer:** the minimum sufficient computation in the ≤2-node space, on
   this split, is the zero-parameter Φ-oracle. The prediction written before any measurement
   (spec §1: "exhaustive enumeration ties or beats evolution") held.
2. **Scoring a run with no admissible winner.** The search package returned UNMEASURED whenever a
   median could not be computed, and left the choice to the integrator. Spec §4.9's rule has no
   UNMEASURED branch: a run with no winner has no delta, so it cannot be "positive on every seed",
   and the rule's else-branch gives NOT_YET_JUSTIFIED. `strategy_verdict` now implements that,
   and a computable median of −0.02 or below still gives REJECTED. UNMEASURED remains, but only
   when **no run of any strategy** produced a winner, because then nothing was comparable.
   `tests/test_stage9_search.py` asserts all three cases. This changed the reported verdict for
   this flag from UNMEASURED to NOT_YET_JUSTIFIED. It did not change G9.9's outcome, which still
   fails on the three ablation arms that produced nothing at all.
3. **The three ablation arms stay UNMEASURED** (subtractive bias, QD niches, fossil avoidance). Main
   and arm produced no winner on any seed, so there is no delta and no cost to compare. G9.9 fails
   on them, and that is correct: a mechanism never exercised to an outcome is not a measured
   mechanism.

## Options considered

| Option | Security cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|
| A. Keep UNMEASURED for a missing winner | none | none | reports a loss to exhaustive as "not measured" | contradicts spec §4.9 and the lead's rule |
| B. Treat a missing winner as AP = base rate, or 0 | invents a number | low | would manufacture a REJECTED from no data | "unmeasured is not measured"; no invented figures |
| C. §4.9's literal rule, UNMEASURED only with no winner anywhere (chosen) | none | low | NOT_YET_JUSTIFIED on this run | chosen |
| D. Raise the budget until evolution finds something | a forking-paths choice made after seeing the result | — | not run | the budget is a spec parameter fixed before measurement |

## Consequences

**Accepted costs.** At the spec's budget the evolutionary machinery (13 variation operators, the
GAIA archive, fossils) never changed an outcome. It is research code with no measured value on
this corpus.

**Bounded state.** Records ≤ 8192, population ≤ 64, cache ≤ 4096, fossils ≤ 2048, all counted.

**Reversibility.** A larger budget or a second corpus can re-open the question. The flag cannot
turn on without a JUSTIFIED verdict cited here.

**Authority.** None.

## Verification

Gate G9.9 (`EVOLUTIONARY_SEARCH_DEFAULT_ENABLED` row) and the saved evidence
(`summary.evidence.runs`, `strategy`); `tests/test_stage9_search.py::test_compare_strategies_verdict_rule_on_synthetic_winner_reports`.

## Prior art

Random search as a strong baseline for architecture search is well established; this ADR claims
no novelty.

## Addendum A (2026-09-26, measurement-engineer session): budget sensitivity, and the verdict at 4x is REJECTED

**Status of the decision above: unchanged for the gate's budget, sharpened beyond it.** The
Stage 9 ADR block (0080-0089) has no free number, so this rejection is recorded here, in the
ADR that owns the flag, and not in a new ADR.

Option D above ("raise the budget until evolution finds something") was declined as a forking
path. This addendum runs it **as a sensitivity check only**. The gate's verdict still comes from
the 96M-WU budget. A larger budget could only have helped evolution, and it did not:

| budget per (strategy, seed) | evolutionary held-out worst-case AP of the winner (s101/s202/s303) | random | `strategy_verdict` |
|---|---|---|---|
| 96,000,000 (the gate) | none/none/none | none/0.4262/none | NOT_YET_JUSTIFIED (no deltas) |
| 384,000,000 (4x) | 0.3328 / 0.3149 / 0.3937 | 0.4819 / 0.3628 / 0.4819 | **REJECTED**: vs random −0.1491/−0.0479/−0.0882 (median −0.0882); vs exhaustive median −0.2647 |
| 1,536,000,000 (16x, seed 101 only) | 0.3376 | 0.4819 | (one seed; evolution below random again) |

At 4x and 16x the variation operators fire (improved_archive > 0), and every evolutionary winner
comes from variation. Those winners score at chance on held-out data (base rate 0.3333):
train worst-case 0.4049/0.3869/0.3975 falls to 0.3328/0.3149/0.3937 on held-out. The loop
climbs train noise. Two operators, `MOVE` and `MACRO_INSERT`, produced **0 valid children in every
run at every budget** (INERT).

Recommendation: keep `EVOLUTIONARY_SEARCH_DEFAULT_ENABLED = False`, and treat evolution as
REJECTED on this corpus at every budget measured. Remove `MOVE` and `MACRO_INSERT`, or repair them
before any further run. Evidence: `PS-S9-20260926-H5-search-budget-sensitivity-0001`;
`docs/stage-9-findings.md` §3.3.

## Addendum B (2026-09-26, measurement-engineer session): "the exhaustive result is the answer" depends on r_min

Decision 1 says the minimum sufficient computation in the ≤2-node space is the Φ-oracle. That is
true only under the MSSC robustness floor `r_min = 0.85` (ADR-0083, a chosen value). The top four
exhaustive genomes by train worst-case AP are all excluded by that ratio alone. The first is
`r' = r + ΔΦ`, MAX over lineages (`sha256:59a57874…`). On held-out it scores worst-case 0.6256
against the Φ-oracle's 0.5975 (seed 11) and 0.6883 against 0.5705 (seed 17), at the same
3 WU/event and 1184 B. The winner flips between `r_min = 0.81` and `0.82`
(`PS-S9-20260926-H5-robustness-threshold-sweep-0001`). ΔΦ is never negative on this corpus
(0 of 138,643 train steps), so this genome is H1 with its clamp removed. Its held-out score
vector is identical to H1's.

The sentence "the binding constraint is quality, not robustness" holds for the random and
evolutionary records at 1x. For the exhaustive answer, the binding constraint is robustness.

## Addendum C (2026-09-26, review-wave fixes): fossil avoidance is INERT by construction; re-proposals are refused before evaluation

A genome becomes a fossil only after it was evaluated and recorded. The main arm already refused
a recorded digest at 0 WU with no rng draw (the cache-hit path), so skipping it as a fossil left
the trajectory identical. `compare_arm` nevertheless reported `fired = fossils_avoided` (4 in the
gate), a count of skips rather than of changed outcomes (S9-R1, S9-CX-05). `fired` now counts
seeds whose trajectory (recorded digests, WU at each record, winner, WU spent) differs from the
main arm's; an arm that replays the main arm on every seed is **REJECTED as INERT**. The flag
stays `False`, and the recommendation is removal.

The search also checked "already recorded" only *after* `evaluate`, so a duplicate evicted from
the 4096-entry evaluation cache was re-scored at full suite cost and thrown away, a tax on the
strategy that re-proposes most (S9-R7, S9-CX-07). The check now runs before evaluation, against
the `known` set bounded by `MAX_RECORDS`; the per-run cache, which could no longer be hit, is
gone. Below 4096 evaluations (every reported 1x/4x/16x run) nothing changes: same WU, same
records, same determinism digest. With both fixes, avoidance is inert at every budget.
