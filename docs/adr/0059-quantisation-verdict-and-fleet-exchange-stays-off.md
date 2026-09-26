# ADR-0059 — Quantisation is UNMEASURED on any state this stage learned; fleet exchange stays off by default

- **Status:** Accepted (measurement)
- **Date:** 2026-09-26
- **Stage:** 6
- **Deciders:** Stage 6 integrator
- **Supersedes / superseded by:** none

## Context

D6.18 quantises the float-bearing parts of a symbolic trusted state (BASELINE anchors,
DETECTOR weights, the THRESHOLD) with stdlib `array`, and `evaluate_quantized` accepts a
variant only when recall drop, FP-rate increase and consistency agreement were all measured.

**Measured in the integration session** (scratch script over `evaluate_quantized`):

| state | bits | fp bytes | quantised bytes | recall fp / q | FP rate fp / q | agreement | accepted |
|---|---|---|---|---|---|---|---|
| gate rig F1+F3 detectors (threshold 0.6) | 8 | 24 | 15 | 1.0 / 1.0 | 0.0 / 0.0 | None | no (UNMEASURED) |
| gate rig F1+F3 detectors | 4 | 24 | 14 | 1.0 / 1.0 | 0.0 / 0.0 | None | no (UNMEASURED) |
| 12-month Stage 6 state (threshold only) | 8 | 8 | 13 | 1.0 / 1.0 | None | None | no (UNMEASURED) |

Consistency agreement needs BASELINE items; no state holds one, so every variant is refused
as unmeasured. On the only learned state the "quantised" form is larger than the float form
(13 vs 8 bytes: metadata dominates one float). The lineage package's own tests measured that
INT8 at `DEFAULT_THRESHOLD = 0.5` dequantises the threshold to 64/127 and loses every
U-only alert; that is a statement about the quantiser on a fixture.

## Decision

1. Quantisation is **UNMEASURED** on every state Stage 6 produced; no variant is accepted and
   none is exported. ONNX export is UNMEASURED (ADR-0050).
2. `FLEET_EXCHANGE_ENABLED` stays `False`. Fleet packages are import-side only and always
   enter as `FOREIGN_PACKAGE` capsules through `QuarantineGateway.admit`.

## Verification

`tests/test_stage6_lineage.py` (quantiser tests); `tests/test_stage6_capsule.py` (fleet off by default).
