# ADR-0029 — Field bounds, GC retention and the §38 resource budget

- **Status:** Accepted
- **Date:** 2026-09-25
- **Stage:** 3
- **Deciders:** Stage 3 integrator
- **Supersedes / superseded by:** none

## Context

The 2 GB host target is a hard constraint, and architecture §39 names "knowledge
explosion" as a threat: a field that grows a cell per observation, or one cell
wide enough to claim the whole host, is the same failure from two directions.

Measured this session through Stage 0's `ResourceSampler` over 256 frames at
loadavg 12.05: `boundary_index` 5,944 B, `knowledge_cells` 1,904 B, `cell_vm`
488 B, `audit_state` 183 B, `counterexample_hot` 0 B, incremental RSS 167,936 B
against the 25 MB normal ceiling.

## Decision

**Enforced constants.** `MAX_CELLS = 512`, `MAX_FIELD_BYTES = 20 MB`,
`MAX_INDEX_KEYS = 8192`, `MAX_INDEX_BYTES = 8 MB`, `MAX_KEYS_PER_CELL = 64`,
`MAX_FORBIDDEN_COMBINATIONS = 16`, `MAX_FISSION_DEPTH = 3`,
`MAX_HOT_COUNTEREXAMPLES = 2048`, `MAX_HOT_BYTES = 15 MB`, and `STAGE3_BUDGET`
per component. Every one **refuses** at its cap rather than evicting silently: a
cell only partly indexed answers in some of its region and misses in the rest,
and nothing downstream can tell which.

**`MAX_KEYS_PER_CELL = 64` is the knowledge-explosion cap, and it binds on the
product that actually multiplies** — declared relation families × actor
predicate masks. Breadth over `state_dimensions` is *not* an explosion vector
under this boundary representation: `CellBoundary.keys` folds the declared
dimensions into a single union delta mask, so a boundary over all nine
dimensions claims exactly as many keys as one over two (measured: 8 keys either
way). The T7 threat case was rewritten accordingly; the original attacked the
dimension axis and reported "stopped" while nothing had stopped it.

**GC retention.** A cell whose `CellUtility` is `None` (UNMEASURED) is
**retained** and counted in `GCReport.unmeasured_skipped`. It is exempt from the
duplicate and obsolete-epoch rules too, not only from the cost rule: those two
are structural rather than cost-based, but "it looked like a duplicate" is
exactly the reasoning that turns an unmeasured basis into a deletion. A
*measured* duplicate is still collected.

**Incident-linked evidence is preserved independently of cell GC and melting.**
`CounterexampleStore` has **no delete API**; `supersede` marks and keeps the
lineage, and the archive is append-only. At capacity with every entry
incident-linked the store **raises** rather than dropping one, and a store
constructed with `cold_archive=None` refuses at capacity rather than spilling —
spilling with nowhere to spill to would be deletion.

## Options considered

| Option | Security cost | Resource cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|---|
| A: refuse at every cap; retain the unmeasured | none | bounded by the caps | medium | all five components far inside budget; incremental RSS 167,936 B of 25 MB | **chosen** |
| B: evict silently at the cap | **high** — the index and the field disagree about coverage | lower | lower | a partly-indexed cell answers in part of its region and misses in the rest | silence is the defect |
| C: collect cells with no measured utility | **high** — deletes on an unmeasured basis | lower | lower | `unmeasured_skipped` would always be 0 and hide the gap | UNMEASURED is not "worthless" |

## Consequences

**Accepted costs.** A field can refuse a legitimate promotion when full;
`promote_cell` returns `REFUSED_FIELD_FULL` and the insertion is rolled back from
both the field and the index, so a cell is never in one and not the other.

**Bounded state.** This ADR *is* the bounded-state statement. Every figure above
was measured, not estimated; the components are small because the field held one
cell, so these are the machinery's bytes and not a populated field's.

**Reversibility.** Raising a cap is a constant edit plus a re-measurement. GC
compacts; it does not delete evidence.

**Authority.** No change.

## Verification

Gate criterion G3.10 (PASS) with the per-component table in its detail;
`pocketsec-stage3 resources`; `pocketsec-stage3 threats` case T7;
`tests/test_stage3_runtime.py`.

## Prior art

No novelty claim. `docs/prior-art/ledger.json`, entry H4.
