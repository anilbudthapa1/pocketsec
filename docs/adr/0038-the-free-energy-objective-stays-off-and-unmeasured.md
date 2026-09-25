# ADR-0038 — The security free-energy objective stays off and unmeasured

- **Status:** Accepted
- **Date:** 2026-09-25
- **Stage:** 4
- **Deciders:** Stage 4 integrator
- **Supersedes / superseded by:** none

> A **measurement ADR** (ADR-0125), and the measurement it records is largely an *absence*.
> That is stated up front rather than dressed as a result.

## Context

Architecture §18 defines a security free-energy objective and is explicit about its own
fate: "If this objective does not outperform simpler information-gain planning, it is
removed." The simpler control is B7 `InformationGainPlanner`, which chooses the observation
with maximum expected entropy reduction over the world support vector and ignores both
consequence and cost.

**What was measured, over `build_incident_corpus(count=60, seed=11)`, `/proc/loadavg`
1.86 1.48 1.55:**

| row | value |
|---|---|
| `LucidConfig.enable_free_energy` default | `False` |
| Ablation rows returned by `run_ablation` | 9 |
| Rows with verdict `JUSTIFIED` | **0** |
| Verdict tally | `{'DEGENERATE': 9}` |
| B7 `InformationGainPlanner` detection accuracy | 0.6667 (above the 0.3333 base rate, so admitted) |
| B7 telemetry bytes / cpu_units | 1914 / 3.3937 |
| CBF_LUCID telemetry bytes / cpu_units | 18426 / 4.0358 |
| `saturation_guard` over the baseline table | **DEGENERATE** — best 0.6667 within 0.01 of median 0.6667 |

**`enable_free_energy` has never been turned on in a measurement.** It is off by default,
the ablation's nine rows cover the nine flags that are on by default, and there is no tenth
row for it. So the comparison §18 demands — free energy against B7 — **was not run**, and
this ADR says so rather than inferring an answer from the rows that were.

Two reasons it was not run, both of which matter more than the omission:

1. **The split cannot separate mechanisms.** All nine flags that *were* ablated came out
   `DEGENERATE` at `world_set_recall`. A tenth degenerate row would have added a number and
   no information.
2. **The objective is computed over a support vector that never moves.** No step of the
   LUCID loop writes support back into the field (ADR-0036). Free energy and information gain
   are both functionals of that support field; on a permanently uniform one they are
   functionals of a constant, and any difference measured between them would be a difference
   between two ways of computing zero.

`engine/lucid_steps.py:free_energy_term` exists, is reachable, and is charged against the
`sensor_plan` budget kind — a mapping named as an approximation in `BUDGET_KIND_FOR` rather
than left implicit.

## Decision

**`enable_free_energy` stays `False`. The objective is recorded as UNMEASURED, not as
rejected, and the measurement that would settle it is named.**

1. **No claim is made in either direction.** §18's removal clause is not triggered, because a
   loss was not measured; and the objective is not retained on merit, because a win was not
   measured either. `docs/stage-4-findings.md` carries it in the UNMEASURED table with
   "what would measure it" filled in.
2. **The default stays off.** A flag defaulting on without a measured win is how an
   unjustified mechanism becomes load-bearing. The ablation harness reads the flag list from
   `LucidConfig.flag_names()`, so turning it on would add a row automatically — the
   measurement is one default away, deliberately.
3. **The condition for revisiting is explicit.** The support-update defect of ADR-0036 must
   be fixed first. Measuring free energy against B7 on a static support vector would produce
   a figure that looks like a result, and publishing it would be the Stage 2 defect class
   where a number could not have come out differently.

## Options considered

| Option | Security cost | Resource cost | Complexity | Why not chosen |
|---|---|---|---|---|
| **A. Keep off, record UNMEASURED, name the condition** (chosen) | none; no claim is made | `free_energy_term` sits unexercised | unchanged | — |
| B. Remove the objective now, as §18's clause prescribes on a loss | none | small saving | small reduction | No loss was measured. §18's clause fires on a measured loss against B7, and that comparison was not run. Removing on the *absence* of a measurement would be ADR-0125's forbidden rejection branch: a flag and a filename standing in for a reproduced result |
| C. Turn it on, add the tenth ablation row, publish the delta | **high** | one more engine walk per ablation | none | The row would come out `DEGENERATE` like the other nine, and the delta would be a difference between two functionals of a constant support vector. A measurement that cannot come out differently is not a measurement (ADR-0113) |
| D. Default it on because the architecture describes it | **high** | per-step cost on every incident | none | The architecture describing a mechanism is not evidence the mechanism helps. This project's own record is that documentation existing is never evidence that a component is justified |

## Consequences

**Accepted costs.** Stage 4 ships a §18 objective that has never been exercised in a
measurement. A reader looking for the free-energy result does not have one, and the findings
document says so in the UNMEASURED table rather than leaving a gap for a reader to fill
optimistically.

**Bounded state.** None. `free_energy_term` is a pure function over the current field and
allocates nothing retained.

**Reversibility.** Trivial in both directions: the flag is the switch, the ablation harness
picks up flags from `LucidConfig.flag_names()`, and removal is deleting one step body plus
its `BUDGET_KIND_FOR` entry.

**Authority.** No. The objective ranks candidate *observations*; it cannot enable one. Every
escalation still routes through Stage 1's AOP (ADR-0035).

## Verification

- `python -m pocketsec.stage4.cli ablation` — nine rows, their verdicts, and the corpus
  saturation verdict printed first. There is no `enable_free_energy` row, which is the
  measurement this ADR records.
- `LucidConfig().enable_free_energy is False` — asserted in `tests/test_stage4_runtime.py`.
- `python -m pocketsec.stage4.cli gate` — G4.10's detail carries the verdict tally
  `{'DEGENERATE': 9}` and the count of flags that came out JUSTIFIED.
- `tests/test_stage4_gate.py::test_g4_10_runs_the_saturation_guard_before_recording_a_comparison`
  pins that a degenerate split records no comparison, which is why a tenth row was not added
  to produce one.

## Prior art

No novelty claim is made, so no prior-art entry is required. Free-energy and
expected-information-gain formulations of active sensing are long-standing in the
literature; Stage 4 asserts nothing about priority. Stage 4's ledger bindings are H3 and H7,
both `NOT_REVIEWED` in `docs/prior-art/ledger.json`.
