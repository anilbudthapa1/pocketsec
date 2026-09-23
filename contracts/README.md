# contracts/

Language-neutral JSON Schema for the frozen hub/model boundary.

| Schema | Direction |
|---|---|
| `security_event_sequence_v1.schema.json` | hub -> model slot |
| `threat_prediction_v1.schema.json` | model slot -> hub |

The Python implementations in `pocketsec/stage0/contracts/` must agree with
these files; gate check `G0.3` fails if the `$id` or `version` drifts.

**A breaking change takes a new `$id` (`...v2`), never a version bump in place.**
The prediction schema sets `additionalProperties: false` so a field conveying
response authority cannot be added by accident (ADR-0003).
