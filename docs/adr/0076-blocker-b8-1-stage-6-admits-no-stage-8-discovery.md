# ADR-0076 — Blocker B8-1: Stage 6 admits no Stage 8 discovery as TRUSTED_CANDIDATE; Stage 8 measures at its own boundary

- **Status:** Accepted (blocker recorded; the decision to change Stage 6 is the lead's)
- **Date:** 2026-09-26
- **Stage:** 8
- **Deciders:** Stage 8 integrator (spec §0 M0.2; the gate's G8.9 reports its own figures)
- **Supersedes / superseded by:** none

> Gate-criterion ADR. It records why realised adoption is 0 and what Stage 8 measures instead.

## Context

Spec M0.2 (measured at spec time): Stage 1 `build_corpus(count=40, seed=7, split="eval")`, the
12 malicious sessions as `DERIVED_INFERENCE` capsules with an `INFERENCE` label, one
independence group → UNCERTAIN 12, TRUSTED_CANDIDATE 0, `score_provenance` 0.5, reason
`awaiting_label_quorum`; three groups (36 capsules) → TRUSTED_CANDIDATE 0; with
`SIMULATED_RECORD` the score is 0.4 < `MIN_PROVENANCE_SCORE` 0.5, TRUSTED_CANDIDATE 0.

## Decision

1. Stage 8 does not edit Stage 6. A discovery reaches Stage 6 only as evidence (ADR-0071), and
   under Stage 6's current parameters realised endpoint adoption is 0 by construction.
2. Every detection gain is measured at Stage 8's own boundary (the REPRODUCED
   `DiscoveryPackageV1` handed to `Stage6Adapter.hand_over`) and labelled
   `counterfactual_at_boundary`; Stage 6's buckets are reported verbatim beside it (G8.9(c)).
3. Architecture falsifier "all endpoint adoption passes Stage 6" is met as a path property.
   Spec falsifier F15 ("realised adoption stays 0") fires today.

## Options considered

| Option | Security cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|
| A. Mint independence groups to reach quorum | a sender-built promotion gate | low | not built | ADR-0067 option B |
| B. Drop `SIMULATED_RECORD` to clear the 0.5 floor | a false provenance claim | trivial | M0.2: the unflagged score is 0.5 and still awaits quorum | dishonest, and insufficient |
| **C. Measure at the boundary, report Stage 6 verbatim (chosen)** | none | low | G8.9 reports the buckets and scores of the gate run | — |
| D. Change Stage 6's inference prior | Stage 6's decision | — | not in this wave | the lead decides |

## Consequences

**Accepted costs.** The value path from discovery to endpoint is closed.

**Bounded state.** None.

**Reversibility.** Opening the path is a Stage 6 decision.

**Authority.** None moves.

## Verification

G8.9 detail: `Realised adoption (TRUSTED_CANDIDATE) = …`.

## Prior art

No novelty claim.
