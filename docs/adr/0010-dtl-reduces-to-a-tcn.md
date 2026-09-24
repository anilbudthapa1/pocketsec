# ADR-0010 — DTL is rejected; the Stage 2 core reduces to a TCN

- **Status:** Accepted
- **Date:** 2026-09-24
- **Stage:** 2
- **Deciders:** Stage 2 implementation session
- **Supersedes:** ADR-0009's retention of the router, surprise vector and
  lineage pool

## Context

Stage 2 spec section 36 lists hard falsification criteria and requires DTL to be
simplified or rejected when they are met. Four corpora and six registered
experiments later, they are met on every axis DTL was allowed to win on.

**Detection.** DTL never beat a simple baseline. On long-horizon sessions the
recurrent core lost by 0.53 PR-AUC. The convolutional rebuild (ADR-0009) reached
parity — 1.0000, the same as a plain TCN — but parity is not an advantage.

**Compute.** Criterion 1 allows DTL to survive on wake rate, attribution or
robustness instead. The sleeping-brain benchmark measured the first of those and
DTL is *dominated*:

| model | PR-AUC | µs/event | params |
|---|---|---|---|
| **tcn** | **1.0000** | **6.6** | 6,961 |
| dtl-conv | 1.0000 | 22.3 | 19,851 |
| mlp-pooled | 0.9415 | 3.2 | 4,657 |
| phi-oracle | 0.7484 | **0.0** | 0 |

Same detection, **3.4× the per-event cost and 2.8× the parameters**.

Worse, the Need router reports 100% of events resolved on cheap paths (P0–P2)
while the model is still 3.4× slower than the TCN. The path accounting is
notional: every branch is computed regardless of its gate, so routing labels
work rather than avoiding it. The mechanism that was supposed to deliver
"computation proportional to novelty" does not reduce computation at all.

**Components.** Every DTL-specific mechanism has now been measured, and none
survives:

| component | verdict |
|---|---|
| multi-timescale dilations | +0.068 once, 0.000 after corpus fixes |
| Need router | −0.115, and saves no real compute |
| structured surprise vector | −0.073 |
| per-lineage pooling | 0.000 — retracted; Stage 1 already attributes |
| predictive heads (joint) | −0.67; usable only when detached |
| max-pool over time | **+0.66 — the one load-bearing component** |

## Decision

**Reject DTL as a distinct architecture.** The Stage 2 core is a causal
temporal convolution with max-over-time pooling — a TCN — optionally carrying
*detached* auxiliary prediction heads for the Stage 3 compile-candidate path.

`DTLConvModel` is retained as the research vehicle with its components
defaulted off, because Stage 3 needs the head machinery and because a future
non-saturated corpus may revive one of them. It is no longer the proposed
deployment architecture.

## Consequences

**Stage 2's thesis does not hold as stated.** "Detection emerges from
prediction" was contradicted directly: joint predictive training costs −0.67
PR-AUC. Prediction may still earn its place for Stage 3 compilation, hazard
estimation or active perception — none of which is detection, and none of which
is yet measured.

**Stage 1 is vindicated.** The phi-oracle — no model, no parameters, zero
measurable inference time — reaches 0.7484 PR-AUC purely from Stage 1's
lineage-scoped state calculus. Roughly three quarters of the task is solved by
the *representation*, before any Stage 2 model exists. That is the strongest
result in the project so far and it is an argument for investing in Stage 1's
ontology over Stage 2's machinery.

**D2.6–D2.15 should not be built as specified.** Behaviour Atoms, the lattice,
merge/fission, Future Cones and the counterfactual twin all sit on top of a
predictive core that has no measured reason to exist. They need a task where
prediction demonstrably helps before they can be justified.

## What would reopen this

A corpus — ideally real telemetry — that is neither saturated nor impossible,
on which a predictive model beats a TCN on detection, compute or attribution.
Four synthetic corpora produced only trivial or impossible tasks; that pattern
is itself evidence that synthetic data cannot settle this question.

## Verification

`tests/test_stage2_sleeping_brain.py`, experiment
`PS-S2-20260924-H3-sleeping-brain-0006`, and `docs/stage-2-dtl-findings.md`.

## Prior art

No novelty claimed. The outcome matches the spec's own cited warning (Bilot et
al., "Sometimes Simpler is Better", USENIX Security 2025): simple neural
networks match or exceed far more complex provenance-IDS designs while being
lighter and real-time.
