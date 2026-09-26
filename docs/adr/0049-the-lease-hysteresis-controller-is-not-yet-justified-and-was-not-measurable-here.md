# ADR-0049 — The lease/hysteresis controller versus immediate action: NOT YET JUSTIFIED, because this corpus cannot measure it

- **Status:** Accepted (measurement)
- **Date:** 2026-09-26
- **Stage:** 5
- **Deciders:** Stage 5 integrator
- **Supersedes / superseded by:** none

> Measurement ADR. Figures from `python -m pocketsec.stage5.cli gate` (G5.14) and
> `python -m pocketsec.stage5.cli baselines` in the session that wrote this file.

## Context

§7's B8 `no_hysteresis` is the control for D5.12: immediate action on every threshold
crossing, no dwell, no cooldown, no lease sweep. The controller must take strictly fewer
actions at no loss of containment on a corpus whose belief fluctuates around the threshold,
or this ADR reports it as not justified.

**The measurement**, `build_response_corpus(count=20, seed=11)`:

| arm | contained | actions | collateral_per_1000 | work units |
|---|---|---|---|---|
| AEGIS (hysteresis on) | 0 | 10 | 0.0 | 2700 |
| B8 no hysteresis | 0 | 10 | 0.0 | 2700 |
| AEGIS, memory primed in-simulator | 0 | 10 | 0.0 | 2700 |
| B8, memory primed in-simulator | 0 | 10 | 0.0 | 2700 |

`run_ablation(flag="enable_hysteresis")` → delta **0.0**, `NOT_YET_JUSTIFIED`.

Two reasons the comparison cannot discriminate, both measured:

1. Neither arm takes an autonomous intervention (ADR-0048: cold, reliability is `None`;
   primed, the shadow gate refuses every intervention), so there is no action cycle for a
   controller to damp.
2. The corpus is single-shot: each case is planned once, from one resolution. There is no
   sequence of beliefs fluctuating around `DEFAULT_HYSTERESIS.enter_threshold`, and the
   `ACTION_OSCILLATION` monitor's fire count on such a sequence is **UNMEASURED**.

## Decision

The lease/hysteresis controller is recorded **NOT YET JUSTIFIED — not measurable on this
corpus**, not REJECTED. The lease half of D5.12 is not in question: leases are what make an
autonomous intervention expire and roll back (ADR-0044, G5.6 10/10). What is unmeasured is
whether the *hysteresis* half (dwell, cooldown, `max_action_cycles`) reduces actions. What
would measure it: a corpus of incidents replayed as belief sequences that cross the enter and
exit thresholds repeatedly, planned at every step, with B8 on the same sequences.

## Options considered

| Option | Measured consequence | Why not chosen |
|---|---|---|
| A. Report "hysteresis reduces actions" | 10 vs 10 actions — no reduction observed | would be a claim with no measurement behind it |
| B. REJECT hysteresis | delta 0.0 on a corpus that cannot show a difference | ADR-0009's lesson: no headroom is NOT_YET_JUSTIFIED, not REJECTED |
| **C. NOT YET JUSTIFIED, with the missing corpus named (chosen)** | — | — |

## Consequences

`enable_hysteresis` stays on (no negative delta). The fluctuating-belief corpus is the next
measurement this stage owes.

## Verification

G5.14 detail (`SAFE-F18: enable_hysteresis:NOT_YET_JUSTIFIED(0.0)`, and the primed B8 row).

## Prior art

No novelty claim is made.

## Measurement addendum — 2026-09-26, Stage 5 measurement wave

Appended, not rewritten. **In isolation** (`benchmarks/stage5/hysteresis_isolated.py`,
PS-S5-20260926-BASE-hysteresis-isolated-0009; real `HysteresisController`,
`DEFAULT_HYSTERESIS`, 240 samples 30 s apart, against a single 6.0 threshold):

| Phi trace | hysteresis acts / releases | single threshold acts / releases | time to act |
|---|---|---|---|
| S1 alternating 5.5 / 6.5 | 1 / 0 | 120 / 119 | 30 s / 30 s |
| S2 uniform [3.5, 8.5], seed 11 | 1 / 0 | 64 / 63 | 30 s / 30 s |
| S3 step 4.0 → 10.0 at 600 s | 1 / 0 | 1 / 0 | 600 s / 600 s |

The mechanism removes thrash at no latency cost on a step, and under noise it never releases
(Phi never reaches the 3.0 exit threshold), so containment length is set by the lease, not
the controller. **End to end** it remains NOT-YET-JUSTIFIED: the full planner never reaches
it (the shadow gate refuses first), and on primed B7 over the decoupled counter-corpus C2 it
HOLDs 5 of 10 hostile cases whose host Phi is 4.0, costing 5 containments at unchanged
collateral (B7 `[5, 0]` vs B7 without hysteresis `[10, 0]`,
PS-S5-20260926-BASE-arms-counter-corpora-0002, -b7-identifiability-0010). Its enter threshold
reads host Phi at 6.0 — the fixed playbook's own signal and threshold.

## Fix-wave addendum — 2026-09-26, Stage 5 fix wave (finding R1; not fixed)

The measurement addendum's isolated result ("1 act vs 120") measured a wiring the stage
does not have. `HysteresisController.note_outcome` is the controller's only state update,
and nothing under `pocketsec/` calls it. `grep -rn note_outcome pocketsec` this wave finds
only its definition. Only `benchmarks/stage5/hysteresis_isolated.py` and two tests call it,
by hand. In every loop the package runs (the gate arms and the labs), each target's history
is empty, so `cooldown_seconds`, `max_action_cycles` and `escalate_after_rollbacks` never
apply. The controller then reduces to "ACT iff host Phi >= 6.0", which is the fixed
playbook's rule. `EffectivenessMemory.observe` has the same gap: its only callers are the
gate's LAB_SANDBOX priming and drills (`gate_runtime.py`). Outside those drills
`rollback_reliability` stays `None`, and autonomy is blocked permanently.

**Not fixed here.** Wiring either one needs a response loop that owns the executor, the
sweeper, the controller and the memory across incidents. Stage 5 ships none (M.9: nothing
outside the gate and the labs schedules the sweeper). Building one is new architecture, not
a defect fix. The verdict stays NOT-YET-JUSTIFIED. The isolated figures describe the class,
not the stage.
