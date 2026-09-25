# ADR-0025 — Melting is localised on the measured run (F2 does not fire)

- **Status:** Accepted
- **Date:** 2026-09-25
- **Stage:** 3
- **Deciders:** Stage 3 integrator
- **Supersedes / superseded by:** none

## Context

Melting is the load-bearing feature of this stage, not crystallisation. Anyone
can compile a model into a table; the claim that would distinguish AICT is that
localised drift reopens a **subregion** without discarding unrelated
crystallised knowledge. Falsifier F2 says that if partial melt reopens cells
outside the drifted region, or the melted region keeps answering from a stale
cell, the stage reduces to ordinary distillation plus cache invalidation.

Measured this session (gate criterion G3.7, PASS). Four cells across four
boundary regions, drift driven into one region `(2, 16, 5)`:

- `reopened_keys` = `[(2, 16, 5)]`, non-empty and a subset of the drifted region's
  keys
- unrelated cells keep their **exact** index footprint, key for key
- the stale cell is gone from the field; the survivor is live in the field and the
  index and keeps `[(1, 16, 5)]`, the half that did not drift — a **proper subset**
  of the original's two keys, sharing no satisfiable frame with the drifted region
- a frame the index answered with the pre-melt cell routes to **abstention** after
  the melt
- `MeltReport.repair_locality` = **1.0** (3 of 3 unrelated cells retained)

### Correction, 2026-09-25 — what G3.7 actually asserted, and what `repair_locality` is worth

Added by the Stage 3 defect-repair wave. Two things in the list above were cited
from a criterion that did not check them.

**`repair_locality` is not the number that falsifies F2.** `partial_melt` touches
exactly two ids — the melted cell's and its successor's — and
`KnowledgeField.insert` refuses rather than evicting, so no statement in its
success path can remove a bystander. The ratio is therefore 1.0 (or `None`) by
construction on every report that exists. Demonstrated by running it: with
`narrow_boundary` stubbed to return the boundary unchanged, so the survivor is
re-indexed *still claiming the drifted key*, `repair_locality` is still 1.0 (3/3)
and the pre-repair G3.7 predicate still returned PASS — a melt in which "the melted
region keeps answering from a stale cell", which is F2's own second clause
verbatim. It is a bystander-count sanity check, and a weak one: the single code
path that *can* delete a bystander raises before a report is built, so the metric
cannot see it. `partial.py`'s claim that the number "cannot be flattered" is
withdrawn.

**Two of G3.7's five conjuncts were vacuous.** `set(report.reopened_keys) <=
region_keys` is satisfied by the empty set, and `report.surviving_cell is not None`
checks only that an object was returned — not that it is in the field, in the
index, non-empty, narrower than the original, or that the drifted region stopped
being answered. Measured: a stub that removed the cell from both containers and
returned `reopened_keys=()` with the original as "survivor" passed G3.7, and so did
the real narrowing with its two re-insert lines deleted. The bullets above about
the survivor's footprint were true of the run, but the criterion cited for them did
not assert them. G3.7's pass condition now carries all of them, including the
abstention routing the spec asks for, and this ADR's claim rests on that.

**The decision is unchanged.** The mechanism is correct — `tests/test_stage3_lifecycle.py`
already asserted the narrowing and the abstention routing, which is why the shipped
behaviour was right while the gate's evidence for it was not.

**The repaired criterion is shown to be able to fail.** Three regressions were
introduced one at a time, by rebinding `gate.partial_melt`, and G3.7 re-run against
the real gate context after each:

| `partial_melt` replaced by | G3.7 before the repair | G3.7 after |
|---|---|---|
| the real implementation | PASS | PASS |
| a whole-cell discard that reopens nothing and names the original as "survivor" | PASS | **FAIL** |
| the real narrowing with its two re-insert lines deleted | PASS | **FAIL** |
| `narrow_boundary` returning the boundary unchanged, so the survivor is re-indexed still claiming the drifted key | PASS | **FAIL** |

The last row is F2's second clause verbatim, and the old predicate granted it a PASS.

## Decision

**F2 does not fire.** Localised repair is real in the mechanism, and the melting
path is kept. Two qualifications are recorded with the result and must travel
with any restatement of it:

1. The cells were constructed by `pocketsec/stage3/labs/cell_path.py:phi_oracle_cell`,
   not by `crystallize`, because CRYSTAL refuses on this corpus (G3.6). What is
   demonstrated is the **melting mechanism**, not a full compile-then-melt cycle.
2. The drift was planted by the corpus designer. A drift we authored is easier to
   localise than a drift reality plants. This is a mechanism demonstration and
   **not a field claim**.

The boundary representation that makes a key-disjoint proper subregion
expressible is `pocketsec/stage3/boundary/index.py`'s `CellBoundary`, which
treats declared relation families as a membership set and folds the declared
state dimensions into a single union delta mask. **The flip side of that fold, not
recorded here originally:** because `contains` matches declared dimensions by
*subset*, key-disjointness does not imply frame-disjointness, and a region scoped
to one of a cell's two dimensions shared no key with it while reaching every frame
it answered. `partial_melt` reported that as `REGION_DISJOINT` and left the stale
cell live and indexed — F2's own failure condition, on a reachable public path. Both
the overlap test and the narrowing search now ask
`CellBoundary.intersects` / `CellBoundary.accepts_no_more_than` instead of comparing
key sets. The competing definition that
briefly existed in `cells/boundary.py` expanded the delta component over every
*subset* of `state_dimensions`, which put the empty-delta mask in every boundary
and made two boundaries sharing a family and an actor mask impossible to
separate — under it, a proper subregion was inexpressible and this experiment
could not have been run at all.

## Options considered

| Option | Security cost | Resource cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|---|
| A: keep partial melt; report the two qualifications | none | none | medium | survivor's keys a proper subset of the original's, disjoint from the drifted region, and the reopened region routes to abstention | **chosen** |
| B: full melt only | **high** — every drift discards unrelated knowledge | lower | lowest | B5's repair locality is 0.0 by construction | it is the baseline this mechanism must beat, and it does |
| C: claim localised repair without the qualifications | high — a mechanism demo read as a field result | none | none | the cells did not come from `crystallize` | it would overstate what was run |

## Consequences

**Accepted costs.** The full compile→promote→drift→melt→recrystallise cycle is
**not** demonstrated; G3.6 FAILS and says where it stops.

**Bounded state.** Partial melt narrows a boundary and re-inserts a successor
cell; the field's cell count and bytes stayed inside `MAX_CELLS` and
`MAX_FIELD_BYTES` at every step of the gate's sequence.

**Reversibility.** `MeltReport` carries `melted_cell` and `rollback_version`, and
`melting/full.py:rollback` restores. A report naming a version with nothing to
roll back to would be a promise rather than a mechanism.

**Authority.** No change.

## Verification

Gate criterion G3.7 (PASS, on the eight-conjunct predicate described in the
correction above); `pocketsec-stage3 melt`; `tests/test_stage3_lifecycle.py`,
including `test_melted_region_routes_to_abstention_not_to_a_stale_cell`,
`test_narrow_boundary_accepts_no_frame_the_original_refused` and
`test_partial_melt_does_not_report_a_dimension_scoped_drift_as_disjoint`.

## Prior art

No novelty claim. `docs/prior-art/ledger.json`, entry H4.
