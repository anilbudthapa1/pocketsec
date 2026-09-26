# ADR-0056 — Candidate kinds are exactly those with an executor; no classifier, adapter or structural kind

- **Status:** Accepted
- **Date:** 2026-09-26
- **Stage:** 6
- **Deciders:** Stage 6 integrator
- **Supersedes / superseded by:** none

## Context

Lesson 3 of Stages 2-5: never define a catalogue richer than its consumer. With no neural
model (ADR-0050) there is nothing that could execute a `classifier`, `adapter` or
`structural` candidate.

## Decision

`chamber.evolution.CandidateKind` names only kinds the chamber builds and the controller can
install: symbolic detectors, statistical baselines, calibration, procedural records,
consolidation and resurrection. The STRUCTURAL timescale is recorded in
`constitution.learning.TIMESCALES` as `UNMEASURED: no structural candidate kind exists`.

## Options considered

| Option | Consequence | Why not chosen |
|---|---|---|
| A. The architecture's full kind list | enum members with no executor | lesson 3 |
| **B. Executor-backed kinds only (chosen)** | every kind has a builder and an install path | — |

## Verification

`tests/test_stage6_evolution.py`; `tests/test_stage6_foundation.py` (TIMESCALES).
