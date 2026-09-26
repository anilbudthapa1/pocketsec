# ADR-0055 — Stage 6 mints no hypothesis and binds to H6 (and H8 for ablation)

- **Status:** Accepted
- **Date:** 2026-09-26
- **Stage:** 6
- **Deciders:** Stage 6 integrator
- **Supersedes / superseded by:** none

## Context

Integration plan §5.2 pre-assigned H12 via an ADR-0012 that was never written. `HYPOTHESES`
holds H0-H8, and `tests/test_harness_and_gate.py` couples it to the prior-art ledger.

## Decision

Stage 6 binds to **H6** ("Hierarchical reversible forgetting: bound memory while retaining
recognisable behaviour"), the anti-forgetting and bounded-memory claim, and to **H8** for
ablation rows. `STAGE6_HYPOTHESIS = "H6"`, `EXPERIMENT_ID = "PS-S6-20260926-H6-helios-gate-0001"`
(`pocketsec/stage6/gate.py`). Ablation rows are registered as `PS-S6-<date>-H8-ablation-NNNN`,
and only by `pocketsec-stage6 experiments --register`.

## Options considered

| Option | Consequence | Why not chosen |
|---|---|---|
| A. Mint H12 | edits the hypothesis table and the prior-art coupling | no ADR-0012; not this wave's to add |
| **B. Bind to H6/H8 (chosen)** | G6.13 asserts `set(HYPOTHESES) == {H0..H8}` | — |

## Verification

Gate G6.13 (HYPOTHESES and registry byte-identity).
