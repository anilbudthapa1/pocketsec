# ADR-0023 — Oracle A is frozen data; Oracle B is Stage 1's existing invariants

- **Status:** Accepted
- **Date:** 2026-09-25
- **Stage:** 3
- **Deciders:** Stage 3 integrator
- **Supersedes / superseded by:** none

## Context

The Stage 3 architecture document assumes the dual oracle compares a cell against
a live DTL forward pass. **There is no DTL** (ADR-0010), and the thing Stage 3
compiles here *is* the teacher, so a single oracle that is just the teacher
catches nothing by construction.

## Decision

- **Oracle A is data, never a live forward pass.** A frozen `TeacherSnapshotV1`:
  a pinned-seed, offline-produced map from a canonical frame digest to a teacher
  score. `frame_digest` is the join key and has exactly one definition, in
  `pocketsec/stage3/cells/frame.py`, beside the fields it digests.
- **Oracle B is Stage 1's explicit invariants, which already exist in code:**
  `phi`/`delta_phi` (`stage1/state/potential.py`), the `INTERACTIONS` table,
  `SecurityStateV1.join` monotonicity and `StateDelta`.
- `DualOracleEvaluator.evaluate` **never** passes on Oracle B alone and never on
  Oracle A alone; when the teacher is unavailable the verdict FAILS with reason
  `TEACHER_UNAVAILABLE`, and `teacher_divergence` is `None`, never 0.0.
- `SecurityDivergence.d_future_hazard` is typed `None` permanently, so a future
  contributor cannot quietly restore the mechanism ADR-0116 rejected on measured
  calibration.

## Options considered

| Option | Security cost | Resource cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|---|
| A: frozen snapshot + Stage 1 invariants | none | a bounded response map | medium | all three constructed teacher-error cases refused; a teacher-only control accepts all three | **chosen** |
| B: teacher only | **high** — catches nothing when the teacher is the thing compiled | lower | lowest | measured: the teacher-only control passes cases a, b and c | it is the failure mode the dual oracle exists to prevent |
| C: live forward pass as Oracle A | high — a model in the runtime | a model on a 2 GB host | high | there is no DTL to call | rejected by ADR-0010 |

## Consequences

**Accepted costs.** Every dual-oracle result this wave is against the
`"phi-oracle"` source; the `"tcn"` snapshot is UNMEASURED (ADR-0020).
Teacher-error resistance is demonstrated against **constructed** corrupted
snapshots — a valid mechanism test, not evidence about a real TCN's error modes.

**Bounded state.** The snapshot is a bounded map keyed by digest, built offline.

**Reversibility.** A `"tcn"` snapshot can be produced later and loaded without
touching the evaluator.

**Authority.** No model output gains response authority. The oracle gates
crystallisation; it grants nothing.

## Verification

Gate criterion G3.5 (PASS): three constructed cases, each refused, each accepted
by the teacher-only control. `tests/test_stage3_oracles.py`.

## Prior art

No novelty claim. `docs/prior-art/ledger.json`, entry H4.
