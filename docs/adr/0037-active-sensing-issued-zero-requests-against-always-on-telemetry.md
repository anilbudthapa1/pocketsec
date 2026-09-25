# ADR-0037 — Active sensing issued zero requests against always-on telemetry

- **Status:** Accepted
- **Date:** 2026-09-25
- **Stage:** 4
- **Deciders:** Stage 4 integrator
- **Supersedes / superseded by:** none

> A **measurement ADR** (ADR-0125). Every figure below came from
> `python -m pocketsec.stage4.cli gate` and `python -m pocketsec.stage4.cli sensing` in the
> session that wrote this file.

## Context

Gate criterion G4.5 asks whether at least one active sensing method reduces bytes and CPU
against always-on rich telemetry at comparable resolution quality. The control is B3
`AlwaysOnRichTelemetry`, which is literally "turn everything on all the time": every optional
signal, every lineage, the whole incident, no planning. Architecture §18 and falsifier F7
both say plainly that D4.9 is removed if it does not win.

**The measurement, same run, same process, `/proc/loadavg` 1.86 1.48 1.55, over
`build_incident_corpus(count=60, seed=11)`:**

| quantity | CBF_LUCID | B3 AlwaysOnRichTelemetry | ratio |
|---|---|---|---|
| telemetry bytes | 37024 | 29760 | **1.2441** |
| cpu_units | — | — | **69399.77** |
| world-set recall (signal coverage) | 0.9000 | 1.0000 | — |

**Observation requests the planner issued across 60 incidents: 0.** It refused 360 actions,
every one of them for expected discrimination below `MIN_DISCRIMINATION_TO_SPEND = 0.10`.
The best expected discrimination any action reached was **0.0922**.

Targeted sensing loses on both axes it was supposed to win on, and it loses while asking for
nothing at all. That second fact is what this ADR is really about, because two separate
defects were found behind it and only one has been fixed.

**Defect 1, found and fixed in this session.** `engine/lucid_steps.py:plan_observation`
called `plan_discriminating_observation` without a `costs` argument. The module default,
`active_plan.SENSOR_COSTS`, is UNMEASURED by design — `SensorCost.cpu_units` and friends are
`None` so that an unmeasured cost cannot be mistaken for a free one (ADR-0004) — and
`ObservationRequest.__post_init__` refuses an unmeasured cost rather than ranking on a guess.
The engine therefore produced **6 refusals per step reading "no measured cost"** and CBF-F13
and CBF-F14 could not fire at all, on any input. The planner's own test file always injected
a measured table; the engine never did, and no test asserted that the engine had ever granted
an escalation. Fixed by measuring the table once per engine via
`sensing/simulate.py:measure_sensor_costs` and caching it.

**Defect 2, found and NOT fixed.** With costs measured, the refusals became honest —
"expected discrimination 0.0922 below MIN_DISCRIMINATION_TO_SPEND 0.10" — and that number is
computed over `field.support_vector()`, which **never moves**: no step of the LUCID loop
writes support back into the field (ADR-0036). Discrimination is a Jensen–Shannon distance
between a posterior and a prior support field, and on a permanently uniform prior it cannot
exceed what two mechanically-different emission probabilities buy. 0.0922 is that ceiling.

## Decision

**Active sensing is recorded as NOT-YET-JUSTIFIED. D4.9 is retained, the AOP seam is kept,
and `MIN_DISCRIMINATION_TO_SPEND` is not lowered.**

1. **The threshold stays at 0.10.** Moving it to 0.09 would make G4.5 issue requests and
   would measure nothing except the threshold. ADR-0113; and this is the Stage 2 defect class
   where four gate numbers could not have come out differently.
2. **Stage 4 still builds no second observation planner** (ADR-0035). Every escalation goes
   through Stage 1's `AdaptiveObservationPolicy` and no Stage 4 code raises an AOP cap. The
   measured consequence of that seam is visible in the refusal strings: with
   `observation=None` the planner refuses every action with "no observation policy", which is
   the correct behaviour and was a third wiring trap the gate had to avoid.
3. **The cost table must be measured, never defaulted.** `LucidEngine` takes
   `sensor_costs=None` meaning "measure on first plan and cache". `SENSOR_COSTS` remains
   UNMEASURED and remains refused. A future caller that passes a guessed table reintroduces
   defect 1 in a form no test would catch, so the engine measures rather than accepting a
   default.
4. **`_COST_REPEATS = 64`, not 8.** A first draft cut it to 8 to save time and asserted the
   rankings were unchanged. When measured, the two cheapest actions **swapped** between 8 and
   64 repeats (0.81 ms against 5.38 ms per engine, `/proc/loadavg` 0.90 1.69 3.28). A cost
   table whose ranking depends on how hard it was measured is not a measurement. The
   retracted claim is kept beside the measurement that killed it, in the constant's docstring
   and in `docs/stage-4-findings.md`'s RETRACTED table.

## Options considered

| Option | Security cost | Resource cost | Complexity | Why not chosen |
|---|---|---|---|---|
| **A. NOT-YET-JUSTIFIED, retain, threshold unchanged** (chosen) | none; G4.5 fails and names the number | the planner runs and refuses: 6 priced candidates per step | unchanged | — |
| B. Remove D4.9 and fall back to Stage 1 AOP unchanged, as F7 prescribes | none | saves the planner's per-step cost | large reduction | The measured loss is downstream of ADR-0036's static support vector, so this would remove a component on evidence that measures a different defect. F7's consequence is correct *once the support vector moves*; until then removal would be untested |
| C. Lower `MIN_DISCRIMINATION_TO_SPEND` to 0.09 | **high**: a criterion restated until it passes | none | none | 0.0922 is a ceiling imposed by a uniform prior, not a property of the evidence. Crossing it would produce requests that discriminate nothing and a G4.5 pass that means nothing |
| D. Leave the engine calling the planner without a cost table | **high**: CBF-F13/F14 unexercisable on any input, while the gate reported a sensing comparison | none | none | A component that cannot fire cannot be measured, and the refusal string blamed the evidence for a missing argument. This is the defect fixed above |
| E. Give the engine a hardcoded plausible cost table | **highest** | none | none | ADR-0004: a guessed cost makes every action look comparably priced and the utility ordering a fabricated result. `SensorCost` carries a `provenance` field precisely so this cannot pass unnoticed |

## Consequences

**Accepted costs.** Stage 4 pays for a planner that currently asks for nothing. The per-step
cost is six candidate evaluations plus one cached cost measurement per engine (5.38 ms,
measured). The gate reports the refusal count and the reason on every run, so the cost is
visible rather than silent.

**Bounded state.** Unchanged. The cached cost table is six `SensorCost` records. Escalations
remain bounded by `AOPBudget` — `max_concurrent`, `max_memory_bytes`,
`max_extra_events_per_second` — which is Stage 1's, not Stage 4's, and Stage 4 raises none
of them.

**Reversibility.** Removal is deleting `sensing/` and the `plan_observation` step; the
`enable_active_sensing` flag already gates it, and the ablation runs with it off. Nothing is
persisted, so there is no rollback artefact.

**Authority.** This is the part of Stage 4 that comes closest, and the answer is still no.
An `ObservationRequest` asks Stage 1's AOP to *collect more*; it cannot enable a sensor
itself, cannot raise a cap, and carries no field naming a `FORBIDDEN_AUTHORITY_FIELDS` token
— the spec's own D4.9 sketch wrote `ObservationRequest.action`, which is a forbidden token,
and it is `sensor_method` in the code because `tests/test_stage4_boundary.py` caught it.

## Verification

- `python -m pocketsec.stage4.cli sensing` — the request count and every refusal, by reason.
  A refusal naming a threshold is the planner deciding; one naming a missing cost table or a
  missing observation policy is the wiring, and both were real defects here.
- `python -m pocketsec.stage4.cli gate` — G4.5 reports FAIL with both ratios and the request
  count.
- `tests/test_stage4_gate.py::test_g4_5_says_whether_the_planner_asked_for_anything` fails if
  the detail string stops reporting the request count or the threshold's immovability.
- `tests/test_stage4_resolution.py` pins that `SENSOR_COSTS` ships unmeasured and that the
  planner refuses it.

## Prior art

No novelty claim is made. Stage 4 binds to H3, "Computation can be budgeted by informational
surprise so cost scales with novelty rather than event volume"
(`docs/prior-art/ledger.json`, `literature_status = NOT_REVIEWED`). H3 is the hypothesis this
ADR reports a negative interim result against; it remains unreviewed and no claim about the
literature is made here.


## Amendment — 2026-09-26, review-fix wave (S4-FC-07, S4-MEAS-05)

**The byte and CPU ratios in the Context table are withdrawn as measurements.** Neither side counts
collected telemetry. The CBF figure is `signal_payload_bytes` over the distinct signal names each
replay already contained, fixed by `replay_corpus` before the engine runs — it is identical whether
the planner issues 0 requests or 1000. B3's figure is a constant 8-name list per incident (29760 =
60 × 496), which even omits eight signal families the passive stream carries, and B3's CPU is the
time to sum those constants. "Targeted sensing loses on both axes" cannot be concluded from numbers
that cannot respond to the mechanism; nor could a win.

What stands: the planner issued **0** requests over 60 incidents in the gate run, so D4.9 has still
not been shown to pay for itself — that is a statement about the planner, not about bytes. G4.5
now reports the ratios as labelled proxies and the telemetry clause as UNMEASURED, and cannot pass
until bytes are counted per collected event (plus the bytes of granted requests over the rest of
the incident) and B3 is modelled as every sensor on for every transition.
