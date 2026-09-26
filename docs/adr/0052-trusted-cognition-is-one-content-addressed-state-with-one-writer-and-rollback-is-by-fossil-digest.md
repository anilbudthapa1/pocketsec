# ADR-0052 — Trusted cognition is one content-addressed state with one writer; rollback is by fossil digest and bounded in depth

- **Status:** Accepted
- **Date:** 2026-09-26
- **Stage:** 6
- **Deciders:** Stage 6 integrator
- **Supersedes / superseded by:** none

## Context

Stage 6 is where learning may change trusted state. The non-negotiables: raw telemetry never
rewrites trusted state; exactly one write path; every promotion reversible to a byte-identical
prior state named by digest; a canary regression triggers rollback rather than a log line.

## Decision

1. Trusted cognition is one immutable `TrustedKnowledgeState` with canonical bytes and a
   `sha256:` digest, held by one `TrustedMind` owned by one `LearningPromotionController`
   (`promotion/controller.py`). `TrustedMind._install_trusted` is the only mutation, and it
   consumes a decision minted by that controller for that mind, bound to exact before/after
   digests, re-reading the state from bytes *with the lineage DAG*.
2. `shadow/rollback.py` is folded into the controller: rollback writes trusted state and
   there is one writer. Rollback restores the first fossil that verifies (requested target,
   probation target, newest known-good), byte-identically, records ROLLBACK and REJECTION
   lineage, and deletes nothing.
3. Rollback depth is bounded by `MAX_FOSSILS` (32); older states are unrecoverable by design
   and the store's tombstone says so.
4. The installer's name, `_trusted_state` and any `TrustedMind(...)` construction appear only
   in `promotion/controller.py` across all of `pocketsec/` (boundary rule 4). The controller
   declares these names in `SEALED_NAMES` so the gate can scan for them without spelling them.

## Options considered

| Option | Measured consequence | Why not chosen |
|---|---|---|
| A. Mutable per-item stores, rollback by undo log | no single digest to compare; "byte-identical" unprovable | fails the reversibility requirement by construction |
| B. A separate rollback module | a second writer | violates single-writer |
| **C. One state, one writer, fossil-digest rollback (chosen)** | G6.8: automatic probation rollback restores the pre-promotion digest, `restored_bytes_identical=True` | — |

## Verification

`tests/test_stage6_boundary.py::test_trusted_state_has_exactly_one_writer_across_the_repository`;
`tests/test_stage6_promotion.py::test_private_installer_refuses_an_unminted_decision`,
`::test_probation_regression_rolls_back_automatically_to_the_identical_fossil`; gate G6.1(a), G6.8.
