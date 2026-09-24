# ADR-0125 — A rejection branch needs a reproduced measurement, and G2.6 does not have one

- **Status:** Accepted
- **Date:** 2026-09-25
- **Stage:** 2
- **Deciders:** Stage 2 defect-repair wave, integrator
- **Supersedes / superseded by:** none. Enforces ADR-0113 rules 1 and 3 against
  G2.6, which was exempt from them in code while claiming to obey them in prose.

## Context

`gate.py`'s module docstring says the two rejection-branch criteria "pass in
their rejection branch only when this run reproduces the measurement that
rejected the mechanism and the mechanism is off in code — never on the strength
of an ADR alone". ADR-0113 rules 1 and 3 say the same.

That was true of G2.4, which computes `rejection_reproduced = control_loss <
learned_loss` and requires it. It was **false of G2.6**, whose removal branch was:

```python
passed = ((cone_better or hazard_better) and enabled) or (removed and bool(adr))
```

`removed` is two hardcoded module constants being `False`. `adr` comes from
`adr_naming("future-cone")`, which matches a `docs/adr/*.md` **filename**
containing both "future-cone" and "rejected" and never opens the file — an empty
file of that name satisfied it. Meanwhile `cone_briers` and `hazard_scores` were
computed at real cost (4,297 continuations and 52,284 hazard predictions on this
corpus) and then discarded. Verified by execution: the branch passed identically
when the cone scored better than its control, when it scored worse, and when both
sides returned `UNMEASURED` (S2-FC-07).

A second, separate defect made the same detail string false. It asserted
"Neither mechanism may reach a verdict, a score or a compile candidate while
those flags are off", and **no runtime code read either constant**.
`gate_measures._deep_step` called `predict_future_cone` on every deep event, and
the cone's output then supplied 0.45 of the uncertainty weight that decides
abstention (`CONE_AMBIGUITY` 0.20 plus `ENTROPY` 0.25, whose source is
`cone_heads(cone)`). A rejected mechanism that still runs and still moves the
number is not off.

## Measurement

Both fixed, then re-measured. `python -m pocketsec.stage2.cli gate` this session
(ambiguous, count=60, train seed 3, eval seed 11):

| figure | value | direction |
|---|---|---|
| cone branch Brier (depth 1, most favourable) | 1.566994 | lower better |
| `marginal_cone` control | 1.850148 | — |
| cone improvement | **True** | — |
| hazard Brier | 0.117936 | lower better |
| `constant_hazard` control | 0.078202 | — |
| hazard ECE | 0.116860 | vs 0.003438 |
| hazard improvement | False | — |

So on this split the **cone beats its control**, which means this run does not
reproduce the measurement that rejected it. ADR-0116's absolute figures are not
comparable — that measurement used its own truth definition and corpus size — and
a single saturated split is not grounds to overturn an ADR. But it is also not
grounds to *claim* the rejection was reproduced.

## Decision

1. G2.6's removal branch requires `rejection_reproduced`: both sides of both
   comparisons measured (not `None`) **and** neither mechanism beating its
   control. Flags and an ADR filename are necessary and no longer sufficient.
2. `_deep_step` expands the cone only while `FUTURE_CONE_DEFAULT_ENABLED` is
   true. With the flag off no `CONE_EXPANSION` work is charged and
   `estimate_uncertainty` records `cone=not_evaluated` / `heads=not_evaluated`,
   which is what that function was built to do. The detail string's claim is now
   true of the code.
3. G2.6 therefore reports **FAIL**: the mechanism is off in code (so the
   "adds value" branch is unavailable) and this run does not reproduce the
   rejection (so the removal branch is unavailable either).

## Consequences

- G2.6 moves from PASS to **FAIL**, and the gate total from 7 failures to 9
  (G2.10 is the other, see ADR-0124). Neither is a regression; both are criteria
  that were passing on something nobody had checked.
- ADR-0116 stands. Nothing here overturns it, and the honest reading of the cone
  scoring better on one degenerate split (G2.2: `ORDER_FREE_BASELINE_TIES_BEST`)
  is that this split cannot settle the question in either direction.
- The route to a PASS is a non-degenerate corpus on which the rejection either
  reproduces or does not. It is **not** a change to this criterion.
- Removing the cone from `_deep_step` lowered the measured runtime cost, so the
  µs/event figures in this wave's gate output are not comparable with earlier
  ones. They now measure Stage 2 in the configuration it actually ships.

## Alternatives considered

**Delete the docstring claim instead.** The finding offered this: if the intent
really is flags-only, say so and stop paying for two measurements the verdict
discards. Rejected, because the claim is also ADR-0113's rule, and the rule is
right — the alternative is a gate that grades a rejection on a filename.

**Let the cone's win flip G2.6 to PASS via the "adds value" branch.** Rejected.
The mechanism is off in code, so it adds nothing at runtime however it scores,
and a cone that beats its control on one saturated split has not earned its
place.
