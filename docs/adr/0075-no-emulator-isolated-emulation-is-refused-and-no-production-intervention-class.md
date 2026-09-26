# ADR-0075 — Active emulation: no emulator exists; ISOLATED_EMULATION needs clearance and is refused REFUSED_NO_EMULATOR; no production-intervention class

- **Status:** Accepted
- **Date:** 2026-09-26
- **Stage:** 8
- **Deciders:** Stage 8 integrator (spec D8.18)
- **Supersedes / superseded by:** none

> Authority-boundary ADR: architecture §54 "All active emulation is isolated and authorized".

## Context

The architecture allows active experiments in an isolated lab (CALDERA-style emulation). This
repository has no emulator, no network (the boundary forbids every network and process module),
and the lead forbids offensive tooling.

## Decision

1. `ExperimentClass` has exactly the six production-safe classes (`HISTORICAL_REPLAY`,
   `COUNTERFACTUAL_MUTATION`, `TELEMETRY_DROPOUT`, `METAMORPHIC_TRANSFORM`, `BENIGN_ALTERNATIVE`,
   `SYNTHETIC_EVENT_WORLD`) plus `ISOLATED_EMULATION`. There is no production-intervention member.
2. `ResearchSandbox.decide` allows the safe classes (they only read recorded or synthetic
   episodes) and, for `ISOLATED_EMULATION`, requires a `LabClearance` for that class and scope,
   not expired — and then answers `REFUSED_NO_EMULATOR` unconditionally
   (`EMULATOR_AVAILABLE = False`). Every decision is audited in a bounded ring.
3. The ORACLE planner never runs an emulation design; a plan with only emulation left stops
   `SAFETY`.

## Options considered

| Option | Security cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|
| A. A stub emulator that "runs" in-process | a pretend isolation claim | low | not built | a stub would make G8.3 pass on a fiction |
| **B. Refuse always, audit every decision (chosen)** | none | low | G8.3(b): 4 refusals, one per clause, all audited | — |
| C. Allow emulation with clearance | a real execution path | high | not built | no emulator; the boundary forbids process/network modules |

## Consequences

**Accepted costs.** Isolation of a real emulation is UNMEASURED; G8.3 holds by construction.

**Bounded state.** Audit ring ≤ 4096.

**Reversibility.** Nothing runs.

**Authority.** None.

## Verification

`tests/test_stage8_integrity.py` (every decision), G8.3, boundary rule 8.

## Prior art

No novelty claim.
