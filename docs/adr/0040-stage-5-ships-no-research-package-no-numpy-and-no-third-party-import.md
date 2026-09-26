# ADR-0040 — Stage 5 ships no `research/` package, no numpy and no third-party import — permanently

- **Status:** Accepted
- **Date:** 2026-09-26
- **Stage:** 5
- **Deciders:** Stage 5 integrator
- **Supersedes / superseded by:** none

## Context

Stage 5 is the only stage that touches privilege. Integration plan §2.4 already answered
"may Stage 5 have a research package?" with "no, permanently — privilege. A numpy import here
is a supply-chain path into the executor." Stage 2 (ADR-0008) and Stage 3 kept numpy behind
a `research/` boundary; Stage 4 shipped none (ADR-0030). For Stage 5 the question is not a
budget one: the executor's trusted computing base is small only if nothing outside the
standard library can reach it.

Measured this session: `stage5_import_violations()` (the gate's G5.1 re-check of rules R1, R2
and T1 over every module under `pocketsec/stage5/`) reports **0** violations, and
`tests/test_stage5_boundary.py` (rules 1, 2 and 8) passes; `pocketsec/stage5/research/` does
not exist.

## Decision

1. Every module under `pocketsec/stage5/` imports only roots in `sys.stdlib_module_names` or
   `pocketsec`.
2. `pocketsec/stage5/research/` must not exist, and no Stage 5 module imports any
   `pocketsec.stage*.research*`.
3. No learned baseline that needs gradient descent is built for Stage 5 (the §40 RL planner
   and learned "model-free safe controller" rows are declared UNMEASURED in the findings,
   not approximated with a hand-rolled stdlib learner).

## Options considered

| Option | Security cost | Resource cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|---|
| A. A `research/` package behind the ADR-0008 boundary, as Stage 2 | a third-party import one relative-import bug away from the executor (S2-AUTH-01 was exactly that bug) | numpy in the dev extra only | a second boundary to police | none measured — not built | the boundary has already failed once in this repository |
| B. Stdlib reimplementation of an RL baseline | none | small | high | none measured — not built | a broken baseline flatters the mechanism (MEMORY.md trap 3: a detached projection scored 0.55, 0.94 once fixed) |
| **C. No research package, ever (chosen)** | none added | none | none | 0 import violations; boundary tests pass | — |

## Consequences

**Accepted costs.** No learned response-planning baseline exists; §40's RL row is UNMEASURED.

**Bounded state.** Unchanged.

**Reversibility.** Reversing this needs a new ADR outside the 0040–0049 block and a
security review of the import path into `executor/`.

**Authority.** Moves nothing towards model authority; it removes a path.

## Verification

- `tests/test_stage5_boundary.py::test_stage5_has_no_third_party_imports`,
  `::test_stage5_never_imports_research_code`, `::test_stage5_does_not_hold_a_forbidden_directory`
- `pocketsec-stage5 gate`, G5.1 detail: "0 R1/R2/T1 import violations under pocketsec/stage5"

## Prior art

No novelty claim is made.
