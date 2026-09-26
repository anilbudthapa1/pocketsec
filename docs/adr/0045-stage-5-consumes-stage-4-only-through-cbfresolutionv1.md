# ADR-0045 — Stage 5 consumes Stage 4 only through `CBFResolutionV1`; `ResponseRecordV1` is the only artefact Stage 6 sees

- **Status:** Accepted
- **Date:** 2026-09-26
- **Stage:** 5
- **Deciders:** Stage 5 integrator
- **Supersedes / superseded by:** none

## Context

Stage 4 is being built concurrently in this working tree, and its own seam docstring warns
that its multi-world machinery may be deleted (ADR-0036). Coupling Stage 5 to Stage 4 class
names would couple Stage 5's lifetime to that redesign, and would route around the refusals
`CBFResolutionV1.to_dict()` performs for Stage 5's benefit.

Measured this session by `pocketsec-stage5 gate`, G5.1: all **53** upstream seam symbols in
`gate_construction.SEAM_SYMBOLS` resolve; the five pinned upstream schema versions match
`SCHEMA_REGISTRY` (5/5 at 1.0.0); **0** Stage 5 modules import any `pocketsec.stage4.*`
module other than `pocketsec.stage4.stage5_interface`. (The spec's §0 table says "83 of 83";
the gate's table is the §3.0 script's list plus the §3.1 harness and dataset symbols, minus
`stage2.gate_criteria.imported_modules`, which Stage 5 runtime may not import. 53 is what
this table resolves; the difference is a difference of list, not a missing symbol.)

## Decision

1. The only Stage 4 import anywhere under `pocketsec/stage5/` is
   `pocketsec.stage4.stage5_interface` (`CBFResolutionV1`, `IncidentHypothesis`,
   `InformationGap`, and the seam constants).
2. `identifiability` is read as a string against a closed set; every unrecognised value is
   `UNKNOWN`.
3. `ResponseRecordV1` (`stage6_interface.py`) is the only artefact Stage 6 sees: plain JSON,
   a canonical digest, no Stage 5 class name as a key, the four enumerated authority-token
   exemptions only, `simulated` required and cross-checked against `host_kind`, and no
   unverified outcome exportable as verified. `sentinel_denials` is derived from the
   receipts, so a refusal cannot be left out of the record.
4. The gate does not diff Stage 4's source (§2.6).

## Options considered

| Option | Security cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|
| A. Import Stage 4 world/claim types directly | bypasses Stage 4's export-time refusals | low | eleven chances to be broken mid-build by another wave | couples lifetimes |
| **B. One seam module each way (chosen)** | none | low | 0 T1 violations; 53/53 seam symbols; G5.8's refusal appears in `ResponseRecordV1.sentinel_denials` 6/6 | — |

## Consequences

**Accepted costs.** A `CBFResolutionV1` carries no `StateDelta` bitmask, so the response-cell
lookup key (`incident_invariant_key(mechanism_id, state_delta_mask, target_kind)`) cannot be
derived at planning time; the field records a truncation instead of guessing (§4.9 Rule A),
and `enable_response_cells` therefore measures a delta of exactly 0.0 (ADR-0048).

**Bounded state.** Upstream bounds respected: `MAX_HYPOTHESES_PER_RESOLUTION = 16`,
`MAX_GAPS_PER_RESOLUTION = 8`.

**Reversibility.** Adding a field to the seam needs a new schema `$id`.

**Authority.** `information_gaps` are questions: an O0 operator may be selected by a closed
signal table, never by parsing prose.

## Verification

G5.1 in `pocketsec-stage5 gate`; `tests/test_stage5_boundary.py::test_stage5_imports_stage4_through_exactly_one_module`;
`tests/test_stage5_benchmarks.py` (the record refusals).

## Prior art

No novelty claim is made.

## Measurement addendum — 2026-09-26, Stage 5 measurement wave

Appended, not rewritten. **The seam resolves and carries nothing Stage 5 can act on.**
Stage 4's own gate corpus (60 incidents, count 60, seed 11), driven through Stage 4's own
`gate_criteria.drive_engine`, exported by `close_incident`, and put in front of Stage 5
(`benchmarks/stage5/stage4_seam.py`, PS-S5-20260926-BASE-stage4-seam-0006, exports digest
`309dd1fc80db17a386dcc71d6a53814403c3dd77a04be720005bde59ce46bd3c`):

| quantity | value |
|---|---|
| `identifiability` / `verdict` | `UNKNOWN` on 60 of 60 / `UNKNOWN` on 60 of 60 |
| `evidence_lineage` keys across all exports | `store`, `locator`, `digest` — 3764 rows each |
| rows carrying any of Stage 5's `LINEAGE_TARGET_KEYS` (`target_pid`, `target_unit`, `target_session`, `target_socket`) | **0 of 3764** |
| Stage 5 candidates generated over all 60 exports | **0** (not even an O0 observation: "no observable process target") |
| full-planner decisions | `NO_ACTION` on 60 of 60 |

`export_incident_world_record` writes `{store, locator, digest}` per `EvidenceRef`; Stage 5's
field resolves targets only from the four `target_*` keys, which only Stage 5's own fixture
(`labs/response_corpus.py:_lineage_row`) writes. The two key spaces never meet — the defect
class this project has now hit three times (S2-FC-01). Every containment figure Stage 5 has
published is therefore a figure about resolutions Stage 4 does not produce. G5.1 passes on
"53 of 53 seam symbols resolve", which is a check that a type exists, not that the seam
carries a target.

**What would close it** (not done here — it changes Stage 4's export, another wave's file,
and needs a new schema `$id`): Stage 4's exporter names the process lineage it already
attributes, in the four keys; and a joint test asserts that a Stage 4 export for an incident
with a known process lineage yields at least one Stage 5 target.
