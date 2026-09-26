# ADR-0050 — Stage 6 ships no research package and no numpy; the neural continual-learning families and ONNX are unmeasured

- **Status:** Accepted
- **Date:** 2026-09-26
- **Stage:** 6
- **Deciders:** Stage 6 integrator
- **Supersedes / superseded by:** none

## Context

Integration plan §2.4 permits `stage6/research/`. It cannot exist in this wave:
`RESEARCH_PREFIX` in `tests/test_repository_structure.py` is still the single literal
`"pocketsec/stage2/research/"`, ADR-0011 (which was to widen it) was never written, and this
wave may not edit that shared test. A numpy import anywhere under `pocketsec/stage6/`
therefore fails `test_runtime_has_no_third_party_imports`.

## Decision

1. Every module under `pocketsec/stage6/` imports only stdlib roots or `pocketsec`;
   `pocketsec/stage6/research/` does not exist (`tests/test_stage6_boundary.py` rules 1-2,
   re-checked in-gate by `gate_construction.import_violations`, G6.7(a)).
2. Every learner — the Stage 6 learner and all §7 baselines — is stdlib and symbolic
   (motifs over Stage 2 encoded steps, Stage 2 meaning anchors, verified procedures).
3. The §47 neural families (EWC/SI, LwF distillation, adapter isolation, dynamic expansion)
   have no parameters to act on and are reported `UNMEASURED — not applicable to a
   parameter-free learner` (S6X-13/14/15), never as passed.
4. ONNX export and ONNX Runtime quantisation are UNMEASURED; D6.18 quantises the
   float-bearing parts of the symbolic state with stdlib `array` (ADR-0059).

## Options considered

| Option | Measured consequence | Why not chosen |
|---|---|---|
| A. A `stage6/research/` package with numpy | fails `test_runtime_has_no_third_party_imports` (the prefix is Stage 2's literal) | would require editing a shared test another wave is using |
| B. Hand-rolled stdlib EWC/LwF over a toy network | none — not built | a broken baseline flatters the mechanism (MEMORY trap 3) |
| **C. No research package; neural families UNMEASURED (chosen)** | 0 import violations in-gate | — |

## Consequences

No claim about neural continual learning can come out of Stage 6. The anti-forgetting
comparison (ADR-0058) is between symbolic learners only.

## Verification

`tests/test_stage6_boundary.py::test_stage6_has_no_third_party_imports`,
`::test_stage6_never_imports_research_code_and_ships_no_research_package`; gate G6.7(a).
