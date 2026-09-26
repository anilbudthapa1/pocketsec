# ADR-0047 — D3FEND is vocabulary, never a decision oracle; a mapping needs a committed dated snapshot, and 0 of 14 operators are mapped

- **Status:** Accepted
- **Date:** 2026-09-26
- **Stage:** 5
- **Deciders:** Stage 5 integrator (the operators package built the adapter)
- **Supersedes / superseded by:** none

## Context

The lead: "map to the published technique identifiers you are confident of and mark the rest
UNMAPPED rather than inventing plausible ids — a wrong external identifier is worse than an
absent one." No network access is assumed, so no D3FEND release can be fetched and
committed.

Measured this session: `operators.d3fend.mapped_fraction()` = **0.0** (every one of the 14
catalog operators carries `d3fend_technique_id="UNMAPPED"`), `load_snapshot()` returns `None`.
B5 `d3fend_lookup_only` therefore takes **0** actions and contains **0** of 10 hostile
incidents on the shared corpus (`pocketsec-stage5 baselines`). Experiment S5X-40 is blocked
with `NEEDS_D3FEND_SNAPSHOT`.

## Decision

1. A technique id may be attached to an operator only through a committed, dated
   `D3FENDSnapshot` with a real release string; everything else is `UNMAPPED`.
2. No module under `executor/`, `sentinel/` or `authority/` imports the adapter (measured by
   `grep` this session: the only importers are `operators/catalog.py` and
   `operators/algebra.py`, which read the `UNMAPPED` sentinel and the id pattern, and the
   B5 baseline and the gate). It informs a human-readable contract, never a decision.
3. `enable_d3fend` (SAFE-F23) is carried on `PlannerConfig` and the planner does not branch
   on it; its measured ablation delta is 0.0, which is the expected result, not a finding.

## Options considered

| Option | Security cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|
| A. Hand-map from memory | wrong external identifiers presented as facts | low | not done | explicitly forbidden by the lead |
| **B. UNMAPPED until a dated snapshot is committed (chosen)** | none | low | 0/14 mapped; B5 acts never | — |

## Consequences

**Accepted costs.** No external vocabulary on any operator. That is MITRE's own statement
about D3FEND as a decision tool, measured here as B5's degeneracy.

**Bounded state.** `MAX_SNAPSHOT_TECHNIQUES = 1024` for a future snapshot.

**Reversibility.** Commit a snapshot; mappings appear with it.

**Authority.** None.

## Verification

G5.15 in `pocketsec-stage5 gate` ("D3FEND mapped_fraction 0.0"); `tests/test_stage5_operators.py` (the D3FEND cases).

## Prior art

No novelty claim is made.
