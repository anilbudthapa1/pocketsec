# ADR-0007 — D1.13 field freeze: narrow, and only what measurement supports

- **Status:** Accepted
- **Date:** 2026-09-24
- **Stage:** 1
- **Deciders:** Stage 1 implementation session

## Context

D1.13 asks Stage 1 to freeze a justified field set. The first attempt could not:
the Information Guillotine produced a **degenerate** frontier on the original
corpus, where 8 of 9 cuts cost nothing because benign and malicious scenarios
shared almost no operations. That measured the corpus, not the representation.

Three methodology defects had to be fixed before the frontier meant anything:

1. **The probe used hand-picked weights.** Removing the novelty and timing
   families *raised* PR-AUC, which says the weights were wrong, not that the
   fields are useless. The probe is now a plain L2 logistic regression **fitted
   per ablation** on a split disjoint from the one it scores.
2. **The fit split was benign-only.** A supervised probe with no positive
   examples produced an inverted ranking and a baseline PR-AUC of 0.23 against
   a 0.355 base rate — worse than random. `LogisticProbe.fit` now refuses a
   single-class split rather than silently producing a misleading frontier.
3. **`time_bucket` was constant corpus-wide.** `emit` hard-coded a 1 ms gap
   between every event, so the temporal field carried zero information for
   reasons of our own making. Behaviours can now declare a gap.

A fourth defect was in the corpus itself: the "timing" discriminator pair
returned the *same* behaviours for both labels, making it pure label noise.

## Decision

**Freeze only `exact_identity` out of the model-facing SSIR encoding**, and
only at representation levels L0–L2.

Measured over 5 independent corpus draws (`measure_stability`):

| Family | Redundant on | Leave-one-out cost (min/mean/max) |
|---|---|---|
| `exact_identity` | **100%** of draws | 0.0000 / 0.0000 / 0.0000 |
| `evidence_link` | **100%** of draws | 0.0000 / 0.0000 / 0.0000 |
| `actor_semantics` | 60% — **unstable** | 0.0000 / 0.0019 / 0.0094 |
| `object_semantics` | **0%** | 0.0024 / 0.0053 / 0.0115 |
| `capability_delta` | 0% | 0.0084 / 0.0260 / 0.0494 |
| `uncertainty` | 0% | 0.0265 / 0.0296 / 0.0377 |
| `novelty` | 0% | 0.0216 / 0.0469 / 0.0677 |
| `timing` | 0% | 0.0067 / 0.0127 / 0.0253 |
| `causal_memory` | 0% | 0.0000 / 0.0000 / 0.0000 |

`evidence_link` is free **for detection** and is nonetheless **retained**: it
carries the investigator's path back to raw evidence, which is a Stage 0
invariant and not a detection question. Measurement does not get to overrule it.

`actor_semantics` is the finding that justifies this ADR's caution. A single
draw reported it redundant and the knee recommended dropping it; across draws it
is redundant only 60% of the time. **A single-frontier freeze would have removed
a load-bearing field.**

`causal_memory` has a leave-one-out cost of zero but a *cumulative* cost of
0.513 — it is the last carrier standing once everything else is gone, not a
unique contributor. Retained: a family that alone sustains PR-AUC 0.33 vs a
0.35 base rate is what the representation degrades to, not something to drop.

## What is NOT frozen

The **knee at 21 bytes is not the freeze basis.** It is a cumulative-path
optimum that passes through `object_semantics`, which is never redundant. The
cumulative knee and the per-family stability disagree, and where they disagree
the conservative reading wins.

Field *widths* remain provisional. Only the presence/absence decision above is
settled.

## Consequences

**Accepted costs.** The saving is modest: 8 bytes of 37 at L1/L2. A larger cut
was available on paper and is not justified by measurement.

**Reversibility.** `exact_identity` remains in the L3 representation, so the
hub keeps runtime correlation and investigation. Only the model-facing encoding
loses it, which is consistent with the Stage 1 non-goal forbidding executable
names as mandatory model vocabulary.

**Authority.** None.

## Verification

`tests/test_stage1_guillotine.py`, gate checks `G1.9` and `G1.11`, and
`pocketsec-stage1 stability`.

## Prior art

No novelty claimed. Ablation studies and the Information Bottleneck framing are
standard; see ledger entries H2 and H7.
