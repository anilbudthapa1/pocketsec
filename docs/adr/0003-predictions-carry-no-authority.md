# ADR-0003 — Predictions structurally cannot carry response authority

- **Status:** Accepted
- **Date:** 2026-09-24
- **Stage:** 0
- **Deciders:** Stage 0 implementation session

## Context

Two MEMORY.md invariants: "model confidence never grants execution authority"
and "no arbitrary natural-language-to-privileged-shell path." Stage 5
(SAFE/AEGIS/SENTINEL) owns response under hard authority, reversibility and
evidence-preservation constraints.

Prose invariants erode. The realistic failure mode is not someone deciding to
bypass SENTINEL; it is a well-meaning field — `suggested_action`, or a
`response_hint` for the UI — that becomes load-bearing three stages later, at
which point the authority boundary has already moved.

## Decision

`ThreatPredictionV1` carries **no** action, remediation, command, shell,
privilege, quarantine or authorisation field, and this is enforced structurally
rather than by review:

1. The JSON Schema sets `additionalProperties: false`, so an unknown field is a
   validation failure, not an extension.
2. `FORBIDDEN_AUTHORITY_FIELDS` enumerates the banned name fragments.
3. `tests/test_authority_boundary.py` introspects the dataclass and the schema
   and fails if any field name matches.

Anything a response path needs must be derived by Stage 5 from the verdict plus
the referenced evidence, under SENTINEL's constraints — never handed over
pre-authorised by the model.

## Consequences

**Accepted costs.** A future stage that genuinely needs to convey a *suggestion*
must add a separate, explicitly-unprivileged contract and argue for it in its
own ADR. That friction is the point.

**Bounded state.** No effect.

**Reversibility.** Reversing this requires deleting a test whose name states the
invariant — deliberately hard to do by accident.

**Authority.** This ADR *is* the authority boundary at the Stage 0 level.

## Verification

`tests/test_authority_boundary.py`, plus gate check `G0.3` which keeps the JSON
Schema and the Python contract in agreement.

## Prior art

No novelty claimed. Standard capability-security separation of decision from
authorisation.
