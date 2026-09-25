# ADR-0039 — The Stage 5 handoff is plain JSON with an export-time claim walk

- **Status:** Accepted
- **Date:** 2026-09-25
- **Stage:** 4
- **Deciders:** Stage 4 integrator
- **Supersedes / superseded by:** none

## Context

Stage 4 hands Stage 5 the surviving belief field, its evidence lineage and its information
gaps (CBF-F20, D4.16). Stage 5 is the only stage that may touch privilege, through typed
operators, so this seam is the one place where a mistake would let cognition reach for
authority. Three constraints bear on it and they pull in the same direction:

- **ADR-0003:** no model output carries response authority. Stage 4 emits no instruction.
- **Trust rule T5:** no Stage 4 dataclass field name may contain any of thirteen
  `FORBIDDEN_AUTHORITY_FIELDS` tokens. This bites Stage 4 harder than any other stage — the
  architecture's own §9 writes `do(block privilege transition)` and both `block` and
  `privilege` are forbidden.
- **ADR-0021 is live** for the *other* seam: Stage 3's cell format may be withdrawn, and
  `pocketsec/stage3/stage4_interface.py` already shipped its side as plain JSON for that
  reason.

Stage 4's incoming Stage 3 seam and outgoing Stage 5 seam were therefore built the same way,
and `tests/test_stage4_boundary.py` asserts the incoming half structurally: **zero**
`import pocketsec.stage3` anywhere under `pocketsec/stage4/`.

**What was measured this session.** Over 60 exported `CBFResolutionV1` records covering 240
authoritative claims (`build_incident_corpus(count=60, seed=11)`):

| quantity | value |
|---|---|
| `ClaimGraph.unsupported_authoritative()` | **0** |
| `amplification_violations()` | **0** |
| authoritative claims of kind INF / CF / EXT / UNK | **0** |
| authoritative claims whose premise chain did not reach a digest-valid `ObservedClaim` | **0** |
| Stage 4 dataclass fields naming a forbidden authority token | **0** |

Three field names had to be renamed to reach that last zero, and the spec's own listings
named all three the forbidden way: `UpdateOutcome.killed` → `retired`,
`WorldTombstone.killed_at_sequence` → `retired_at_sequence`,
`ObservationRequest.action` → `sensor_method`, and `ExperimentSpec.blocked_reason` →
`refusal_reason`. Each was caught by the boundary test rather than by review.

## Decision

**The Stage 5 handoff is `CBFResolutionV1` serialised as plain JSON with a canonical
`sha256:` digest, and the unsupported-authoritative-claim walk runs at export time, not only
in the gate.**

1. **Plain JSON in both directions.** Stage 4 imports nothing from `pocketsec.stage3` and
   Stage 5 need import nothing from `pocketsec.stage4`. The Stage 3→4 reader is
   `crystal/handoff.py`; the 4→5 writer is `stage5_interface.py:write_resolution`. The
   reverse feedback channel (D4.14, cell stress) is also plain JSON: Stage 4 *writes*
   `CellStressSignalV1` records and a later Stage 3 session reads them.
2. **The export refuses rather than annotates.** `export_incident_world_record` performs four
   refusals at export time, including `unsupported_authoritative_rows`. A resolution carrying
   an unsupported authoritative claim does not cross the seam with a warning attached; it
   does not cross.
3. **A gap is a question, not an instruction.** The field is
   `information_gaps: tuple[InformationGap, ...]`. There is no `recommended_action`, no
   `remediation`, no `next_step`. `FORBIDDEN_SEAM_TOKENS` and `IMPERATIVE_TOKENS` are checked
   against the emitted payload, so an imperative cannot arrive through a free-text field
   either.
4. **The T5 check carries no exemption list, deliberately.** The moment it acquires one,
   every future collision is resolved by appending to it rather than by renaming, and the
   rule stops being a rule. Stage 3 set the precedent: its spec mandated
   `CellResult.steps_executed`, the field granted nothing, and it was renamed anyway.

## Options considered

| Option | Security cost | Resource cost | Complexity | Why not chosen |
|---|---|---|---|---|
| **A. Plain JSON + canonical digest + export-time walk** (chosen) | lowest: no import path exists for authority to travel along | one canonical serialisation per resolution; bounded by `MAX_HYPOTHESES_PER_RESOLUTION` and `MAX_GAPS_PER_RESOLUTION` | low | — |
| B. Stage 5 imports `CBFResolutionV1` directly | moderate: couples the privileged stage to Stage 4's type, so a Stage 4 refactor reaches into the stage that holds authority | none | lower | The stage that may touch privilege must not have to be redeployed because cognition changed shape. The same argument Stage 3 made for its own outgoing seam, and ADR-0021 is the live proof it was right |
| C. Walk the claim graph only in the gate | **high**: an unsupported claim reaches Stage 5 on every run that is not a gate run | cheaper per export | lower | A criterion enforced only by its own test is enforced nowhere in production. G4.8 and the export refusal check the same property at two places on purpose |
| D. Emit a `recommended_action` field for Stage 5's convenience | **highest**: this is precisely the natural-language-to-privileged-shell path ADR-0003 forbids | none | lower | Refused outright. A gap is a question. Stage 5's typed operators are the only thing entitled to decide what follows from one |
| E. Keep the spec's own field names (`killed`, `action`, `blocked_reason`) | **high**: T5 violated in four places, and a field named `action` is one review away from being treated as one | none | none | The boundary test has no exemption list. The spec's §2.4 forbids the tokens its own §D4.2/§D4.9/§D4.16 listings use; §2.4 outranks the sketches and the renames are recorded here |

## Consequences

**Accepted costs.** Two serialisation boundaries instead of two imports, so a schema change
is caught by a digest mismatch and a refusal rather than by a type error at import time.
Stage 5 must parse JSON it could have imported. That is the cost, and the thing it buys is
that Stage 3 can be redesigned and Stage 4 can be rewritten without touching the stage that
holds privilege.

**Bounded state.** `CBFResolutionV1` is bounded in every repeated field:
`MAX_HYPOTHESES_PER_RESOLUTION`, `MAX_GAPS_PER_RESOLUTION`, `MAX_EXPORT_CHAIN_DEPTH`, and
the claim graph it carries is bounded at `MAX_CLAIMS_PER_GRAPH = 256`. Measured peak incident
state under the adversarial flood: 29651 B against a `MAX_INCIDENT_BYTES` of 8388608.
Truncation is explicit — 5028 `Truncation` records over 1120 flood steps.

**Reversibility.** The seam is a file. A breaking change takes a new `schema_id` and a new
ADR (Stage 0's registry rule); `crystal/handoff.py` already demonstrates the reader side of
that discipline, accepting any `1.x` `interface_version` under the same id and refusing a
`2.x`, because a major bump under an unchanged id is an upstream contract violation rather
than something to coerce.

**Authority.** This ADR is specifically about *not* moving anything closer to execution
authority, and the mechanism is structural rather than procedural: no field may be named
after an action (AST-checked, no exemptions), no imperative may appear in the payload
(token-checked), and no unsupported authoritative claim may cross (graph-walked at export).
Stage 5 review is appropriate before this is relied on, and the seam is deliberately
parse-only so that review has one file to read.

## Verification

- `tests/test_stage4_boundary.py::test_no_stage4_dataclass_field_names_response_authority` —
  AST over every module, no exemption list.
- `tests/test_stage4_boundary.py::test_stage4_never_imports_stage3` and
  `::test_no_earlier_stage_imports_stage4` — both directions, with a committed negative
  fixture of ten relative-import forms, because a relative import was invisible to two
  checkers at once in Stage 2 (S2-AUTH-01).
- `python -m pocketsec.stage4.cli gate` — G4.8 reports the unsupported count over every
  exported record, and its vacuity guard fails the check if no authoritative claim was
  emitted at all.
- `tests/test_stage4_runtime.py` — the four export-time refusals, and the two renames locked
  so they cannot be "fixed" back.

## Prior art

No novelty claim is made. Versioned JSON interfaces between components are ordinary
engineering; nothing here asserts priority. Stage 4's ledger bindings are H3 and H7, both
`NOT_REVIEWED` in `docs/prior-art/ledger.json`.
