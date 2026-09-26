# ADR-0053 — Stage 6 consumes Stages 4 and 5 only through their JSON handoffs and does not consume Knowledge Cells; `action_outcome` is `response_outcome`

- **Status:** Accepted
- **Date:** 2026-09-26
- **Stage:** 6
- **Deciders:** Stage 6 integrator
- **Supersedes / superseded by:** none

## Context

Stage 5 was being finished by another wave while Stage 6 was built. Integration plan §3.2
lists `KnowledgeCellV1` as a Stage 6 input, but Stage 6 has no executor for cell bytecode and
ADR-0021 measured that the cell format loses to the rule it wraps.

## Decision

1. Upstream allow-list: Stage 2 `encoder.ssir_encoder`, `adaptation.{quarantine,promotion,
   epoch_guard}` (and `labs.{drift_corpus,poison_suite}` from `stage6/labs/` only); Stage 3
   nothing; Stage 4 `stage5_interface` only; Stage 5 `stage6_interface` only; Stages 7-12
   only from `capsule/quarantine.py` (T3).
2. `KnowledgeCellV1` is not consumed: a capsule kind with no consumer is the lesson-3 defect.
3. The architecture's `ExperienceCapsule.action_outcome` is named `response_outcome`: the T5
   screen refuses any dataclass field containing an authority word, with no exemption list.
4. Stage 6's own exports (Shadow, Canary, Conservation and LearningRecord payloads) pass
   Stage 5's `authority_violations` and `seam_violations` screens.

## Options considered

| Option | Measured consequence | Why not chosen |
|---|---|---|
| A. Import Stage 5 internals (receipts, executor types) | couples to a module being edited by another wave | the seam exists precisely to avoid this |
| B. Consume Knowledge Cells | no executor; ADR-0021 loss | lesson 3 |
| **C. JSON handoffs only (chosen)** | 0 allow-list violations; 0 authority/seam hits (G6.7) | — |

## Verification

`tests/test_stage6_boundary.py::test_stage6_imports_upstream_only_through_the_allow_list`,
`::test_no_stage6_dataclass_field_carries_an_authority_word`; gate G6.7(a)(b).
