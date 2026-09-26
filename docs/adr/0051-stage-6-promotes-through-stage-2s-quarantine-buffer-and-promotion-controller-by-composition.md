# ADR-0051 — Stage 6 promotes normality through Stage 2's quarantine buffer and promotion controller, by composition

- **Status:** Accepted
- **Date:** 2026-09-26
- **Stage:** 6
- **Deciders:** Stage 6 integrator
- **Supersedes / superseded by:** none

## Context

Stage 2 built the only two learned-side components that survived measurement:
`QuarantineBuffer` (`stage2/adaptation/quarantine.py`) and the gated, delayed, audited
`PromotionController` (`stage2/adaptation/promotion.py`). The project lead's standing order
is that a second, parallel promotion gate is a defect. Spec §0 measured that Stage 2's gate
already stops Stage 2's poison suite (18 promotions, 0 escalating, 0 attack-lineage), and that
it promotes one source's escalation-free repetition once it spans two corroborated epochs
(3 promotions in the probe).

## Decision

1. `capsule/quarantine.py` owns exactly one `QuarantineBuffer` and exactly one
   `PromotionController`. Every normality step becomes an `AdaptationSample` through
   `quarantine_adaptation_sample`; Stage 2's risk, fixed-anchor and epoch rules are not
   reimplemented.
2. Stage 2's `PromotionController.promote` is the QUARANTINED -> CANDIDATE transition for
   normality; its quantizer is Stage 6's `_CandidateRegister`, so Stage 2's "write" lands in
   Stage 6's bounded candidate register, never in trusted memory.
3. Stage 6 adds only what Stage 2 cannot see (source independence, ADR-0054), in series
   before `promote`, and the conservation/shadow/canary gates on candidates, which Stage 2
   has no notion of.
4. Threat learning does not pass through Stage 2's controller (it refuses evidence by
   design); it still enters through `QuarantineGateway.admit` and nowhere else.
5. There is exactly one trusted writer (ADR-0052).

## Options considered

| Option | Measured consequence | Why not chosen |
|---|---|---|
| A. A Stage 6 re-implementation of epoch/frequency/delay | a second gate to keep consistent with the first | forbidden by the lead; boundary rule 11 fails it |
| B. Stage 2's gate alone | promotes single-source repetition across epochs (3/240, §0) | leaves the P1 hole open |
| **C. Composition, Stage 6 checks in series (chosen)** | P1 through `admit`: 0 admissions (G6.1(b)) | — |

## Verification

`tests/test_stage6_boundary.py::test_stage6_defines_no_second_epoch_or_delay_gate`;
`tests/test_stage6_gateway.py::test_single_source_repetition_across_corroborated_epochs_is_never_admitted`;
gate G6.1(a) rule 11 and G6.1(b) P1 probe.
