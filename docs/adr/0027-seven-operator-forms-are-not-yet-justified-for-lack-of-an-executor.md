# ADR-0027 — Seven operator forms are NOT_YET_JUSTIFIED for lack of an executor

- **Status:** Accepted
- **Date:** 2026-09-25
- **Stage:** 3
- **Deciders:** Stage 3 integrator
- **Supersedes / superseded by:** none

## Context

D3.7 asks for a measured Pareto frontier over the eight `OperatorForm` members,
and for the selector to pick "the cheapest candidate satisfying" the constraints.

Measured this session on the drift corpus's second-largest boundary region, 24
samples, one run:

| form | fitted a program | µs/event | bytes | dual oracle |
|---|---|---|---|---|
| `CONSTANT` | yes | **UNMEASURED** | 82 | passed |
| `LOOKUP_TABLE` | yes | **UNMEASURED** | 59 | passed |
| `BITSET_PREDICATE` | no fit | — | — | — |
| `DECISION_DAG` | yes | **UNMEASURED** | 84 | passed |
| `FSM_FRAGMENT` | yes | **UNMEASURED** | 77 | passed |
| `WEIGHTED_TRANSITION` | yes | **UNMEASURED** | 86 | passed |
| `LINEAR_EXPRESSION` | yes | **UNMEASURED** | 77 | passed |
| `BYTECODE` | yes | 20.80 | 50 | **refused**: `NEVER_NORMALISE_HIGH_CONSEQUENCE` |

`CellVM` executes `BYTECODE` and returns `REASON_NOT_EXECUTABLE_FORM` for every
other form, so `measure_candidate` reports `microseconds_per_event=None` for the
seven. Timing the refusal and calling it the operator's cost would hand the
selector a cheap candidate that never answers.

## Decision

The seven non-`BYTECODE` forms are **NOT_YET_JUSTIFIED**, explicitly *for lack of
an executor* and **not** for lack of value. The measured Pareto frontier over
eight forms **cannot be produced** in this wave, and G3.6 records the
consequence: `crystallize` refuses every region, because the only admissible
candidates carry no measured cost and the only measured candidate is refused by
Oracle B.

`UNMEASURED is not cheap` stays the selector's rule. A candidate whose
`microseconds_per_event is None` is never selected.

**NOT_YET_JUSTIFIED is not REJECTED.** These forms have not been shown to be
worthless; they have not been tested. A later wave gives `CellVM` table-form
interpreters, or the forms are retired with a successor ADR carrying a
measurement.

## Options considered

| Option | Security cost | Resource cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|---|
| A: report the seven as NOT_YET_JUSTIFIED | none | none | none | 7 forms UNMEASURED; selector picks nothing; G3.6 FAILS with that reason | **chosen** |
| B: time the VM's refusal as the form's cost | **high** — the selector prefers a form that never answers | none | none | would produce a near-zero µs/event for a program that abstains | it is the exact failure "UNMEASURED is not cheap" exists to stop |
| C: delete the seven forms | none | none | lower | no measurement supports deletion | NOT_YET_JUSTIFIED is not REJECTED |

## Consequences

**Accepted costs.** D3.7's selector can only ever pick `BYTECODE`, so the
multi-operator claim is unsupported this wave.

**Bounded state.** Each form's declared `max_state_bytes` is still statically
checked against `MAX_OPERATOR_STATE_BYTES`; nothing here relaxes a bound.

**Reversibility.** Adding an interpreter per form is additive; the synthesisers,
the candidates and the selector all already exist and are exercised.

**Authority.** No change.

## Verification

`pocketsec-stage3 crystallize`; gate criterion G3.6 (FAIL) and its stop reason;
`tests/test_stage3_synthesis.py::test_a_form_the_vm_will_not_execute_is_unmeasured_not_cheap`.

## Prior art

No novelty claim. `docs/prior-art/ledger.json`, entry H4.
