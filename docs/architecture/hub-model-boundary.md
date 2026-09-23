# The stable hub / model-slot boundary

**Status:** frozen for Stage 0 (acceptance clause 17.2). Changing this boundary
requires an ADR and a new schema `$id`, never a version bump in place.

## Why the boundary exists

PocketSec is a long-lived product wrapped around a short-lived model. Telemetry
normalisation, deterministic rules, IOC and host metadata, evidence storage,
correlation, risk and presentation all outlive any particular learned component.
If the hub takes a dependency on a model family, replacing that model becomes a
rewrite — and the Stage 0 hypothesis (that expensive inference can be
progressively *eliminated*) becomes untestable, because there would be nothing
to swap it out for.

## Shape

```
Linux telemetry
      |
      v
Normalizer  ->  SecurityEventV1
      |
      +--> deterministic rules / IOC / host metadata     (never enters the model)
      |
      v
pocketsec.security_event_sequence.v1                      [frozen input contract]
      |
      v
+-------------------+
|    MODEL SLOT     |  <--- replaceable, may be absent
+-------------------+
      |
      v
pocketsec.threat_prediction.v1                            [frozen output contract]
      |
      v
Correlation / Risk / Evidence
      |
      v
CLI / local API / alert presentation
```

## What crosses the boundary

**In:** `pocketsec.security_event_sequence.v1` — a bounded, host-local,
time-ordered window. The security ontology is deliberately *not* frozen here; it
travels in the opaque `attributes` map so Stage 1 can formalise it without
touching Stage 0's measurement rules.

**Out:** `pocketsec.threat_prediction.v1` — verdict, confidence, novelty,
uncertainty, evidence relevance, optional next-event surprise, compute path and
model state version.

## What must never cross it

1. **Response authority.** The output contract has no action, remediation,
   command, shell, privilege or quarantine field, and its JSON Schema sets
   `additionalProperties: false` so one cannot be added by accident. Model
   confidence never grants execution authority. Response is Stage 5's, gated by
   SENTINEL. Enforced by `tests/test_authority_boundary.py`.

2. **Raw evidence.** Evidence is *referenced* by digest, never inlined. Raw
   evidence stays distinct from any compressed or model representation, and the
   digest lets a later stage prove the bytes it reads are the bytes the
   prediction was made from.

3. **Unbounded state.** `window_capacity` is capped at 4096 events and
   `truncated` is explicit, so a bounded buffer cannot silently become a false
   negative.

4. **Deterministic knowledge.** Anything exactly representable by rules, host
   metadata or external knowledge belongs on the deterministic path, not in the
   model. "Do not learn what can be represented exactly."

## Degradation

`NullModelSlot` always abstains. It is not scaffolding to delete: it is the
proof that the hub runs with **no** learned intelligence and still emits
well-formed, honestly non-committal output. It is also the floor every proposed
mechanism must clear before it is worth its cost.

## Compatibility rule

A slot declares `input_schema` and `output_schema`. `validate_slot` refuses to
wire a mismatch rather than coercing at runtime, because a silently-coerced
contract is how a measurement framework starts lying.
