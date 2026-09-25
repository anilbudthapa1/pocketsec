# ADR-0035 — Active sensing routes through Stage 1's AOP and nowhere else

- **Status:** Accepted
- **Date:** 2026-09-25
- **Stage:** 4
- **Deciders:** Stage 4 integrator
- **Supersedes / superseded by:** none

## Context

Stage 4 wants more telemetry, sometimes. "Go and gather the specific observation that would
discriminate between the survivors" is one of the four things the stage exists to do. That
makes it the one place in Stage 4 that asks the system to *do* something to the host rather
than to reason about it, and therefore the place where an authority boundary can erode without
anyone deciding to erode it.

Stage 1 already owns observation. `AdaptiveObservationPolicy` exists, with an `AOPBudget`
carrying `max_concurrent`, `max_duration_ns`, `max_escalations_per_window`,
`max_extra_events_per_second`, `max_memory_bytes` and an `escalation_threshold`; a budget of
`U x Phi x CausalRelevance`; and a measured result — escalation fires on an uncertain,
high-potential, causally-relevant actor and stays quiet on routine traffic, inside its caps,
with mandatory signals collected unconditionally.

A second planner in Stage 4 would mean two components deciding what the host collects, with
two budgets, and no single place where a cap is enforced.

**What was measured this session**, over 60 incidents:

| quantity | value |
|---|---|
| `ObservationRequest`s the planner issued | **0** |
| refusals for expected discrimination below `MIN_DISCRIMINATION_TO_SPEND = 0.10` | 360 |
| refusals for any other reason | 0 |
| best expected discrimination any action reached | 0.0922 |
| AOP caps raised by Stage 4 code | **0** |
| Stage 4 code paths that enable a sensor directly | **0** |

The refusal strings are worth reading as the record of two wiring traps this seam has: with
`observation=None` every action is refused with "no observation policy", and with the
UNMEASURED default cost table every action is refused with "no measured cost". Both produce a
plan that looks like a reasoned decision and is not. See ADR-0037.

## Decision

**Stage 4 builds no second observation planner. It computes *which* observation would
discriminate, and Stage 1's AOP decides whether it happens.**

1. **`plan_discriminating_observation` returns requests; it does not collect.** Each request
   goes to `AdaptiveObservationPolicy` and the AOP returns an `EscalationDecision`. Stage 4
   contains no code that enables a sensor.
2. **`observation=None` is legal and means no sensing is possible.** Every request is refused
   and nothing escalates. That is the honest degradation, and it is also why the gate must pass
   a real AOP — a planner with nothing to escalate through refuses for a reason about the
   wiring rather than about the evidence.
3. **Stage 4 raises no AOP cap, ever.** Not `max_concurrent`, not `max_extra_events_per_second`,
   not `max_memory_bytes`, not `escalation_threshold`. If the AOP says no, the answer is no and
   the incident resolves with an `InformationGap` recording what was not learned.
4. **A request is not an instruction, and its field names say so.** The spec's own D4.9 sketch
   wrote `ObservationRequest.action`; `action` is a `FORBIDDEN_AUTHORITY_FIELDS` token and the
   field is `sensor_method`. `tests/test_stage4_boundary.py` caught it rather than a reviewer.
5. **An unmeasured cost is refused, not defaulted.** `SensorCost` fields are `float | None`
   with a `provenance` string, `total()` returns `None` when unmeasured, and
   `ObservationRequest.__post_init__` refuses an unmeasured cost. A zero cost would make every
   action look free and the utility ordering a fabricated result (ADR-0004).
6. **`authority_risk_units` is a declared parameter, not a measurement.** How much authority a
   collection method needs is a policy judgement. `measure_sensor_costs` measures cpu, bytes and
   memory and carries the risk figure through unchanged, with its provenance saying so.

## Options considered

| Option | Security cost | Resource cost | Complexity | Why not chosen |
|---|---|---|---|---|
| **A. Stage 4 ranks, Stage 1's AOP decides** (chosen) | lowest: one budget, one enforcement point, measured 0 caps raised and 0 direct sensor enables | one cached cost table per engine (5.38 ms, measured) plus six candidate evaluations per step | moderate | — |
| B. A Stage 4 observation planner with its own budget | **high**: two components deciding host collection, two budgets, and no single place a cap is enforced. The AOP's measured selectivity result would no longer describe the system | duplicated escalation bookkeeping | higher | The architecture's own §16 budget is `U x Phi x CausalRelevance`, which is the AOP's budget. Rebuilding it in Stage 4 would fork a measured component |
| C. Let Stage 4 raise the AOP's caps when a world is high-consequence | **highest**: "the reasoning decided it was important" is exactly the model-output-grants-authority path ADR-0003 forbids, and consequence is attacker-influenceable | unbounded collection under the right incident | lower | Refused outright. A cap a caller can raise is not a cap |
| D. Default `SENSOR_COSTS` to plausible measured-looking values | **high** | none | lower | ADR-0004. A guessed cost makes the utility ordering a fabricated result, and `provenance` exists so this cannot pass unnoticed |
| E. Keep the spec's `ObservationRequest.action` field name | **high**: a field named `action` is one review away from being treated as one | none | none | T5, no exemption list. Renamed to `sensor_method` |

## Consequences

**Accepted costs.** Stage 4 cannot get an observation it believes it needs if the AOP's budget
is spent. The incident then resolves less certainly and says why, through
`information_gaps` — which is the correct outcome and is what makes the gap a *question* rather
than an instruction.

**Bounded state.** All escalation bounds are Stage 1's `AOPBudget` and Stage 4 adds none.
Stage 4's own addition is the cached six-entry cost table, plus
`DEFAULT_MAX_SENSOR_ESCALATIONS = 4` charged against the entropy budget per incident.

**Reversibility.** Removing active sensing is deleting `sensing/` and the `plan_observation`
step; `enable_active_sensing` already gates it and the ablation runs with it off. Stage 1's AOP
is untouched by Stage 4 either way, which is the point.

**Authority.** This is the seam that comes closest, and the answer is no in three independent
ways: Stage 4 cannot enable a sensor, cannot raise a cap, and cannot name a field after an
action. A Stage 5 review of this ADR is appropriate, and the seam is deliberately narrow so
that review has one function to read.

## Verification

- `python -m pocketsec.stage4.cli sensing` — the request count and every refusal, by reason.
- `tests/test_stage4_resolution.py` — the AOP seam, the unmeasured-cost refusal, and the
  `sensor_method` rename.
- `tests/test_stage4_boundary.py::test_no_stage4_dataclass_field_names_response_authority` —
  AST over every module, no exemption list.
- `grep -rn "AOPBudget(" pocketsec/stage4/` returns nothing: Stage 4 constructs no budget of
  its own and therefore cannot widen one.

## Prior art

No novelty claim is made. Cost-aware active sensing and expected-information-gain observation
selection are long-standing. Ledger bindings are H3 and H7, both `NOT_REVIEWED`.
