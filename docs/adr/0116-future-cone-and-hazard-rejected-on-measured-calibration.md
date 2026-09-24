# ADR-0116 — The Future Cone and the hazard heads are rejected; both default off

- **Status:** Accepted
- **Date:** 2026-09-24
- **Stage:** 2
- **Deciders:** Stage 2 completion wave, `predictors` package
- **Relates to:** Stage 2 acceptance criterion 6 (§38), gate check G2.6,
  falsifiers F7 and F8 in `docs/stage-2-spec.md` §6, ADR-0009, ADR-0010

## Context

Stage 2 spec section 7 proposes a bounded **Future Cone** instead of single
next-event prediction, and section 22 proposes compact **multi-horizon hazard**
heads. Acceptance criterion 6 is explicit that these must "add measurable value
beyond next-event prediction, **or** be removed", and the specification names the
controls they have to beat: `marginal_cone` — the epoch-marginal continuation
distribution with the current atom removed — and `constant_hazard`, the empirical
base rate per `(outcome, horizon)` bucket with no state and no cone.

Both mechanisms are now implemented in stdlib-only runtime code
(`pocketsec/stage2/predictors/future_cone.py`, `…/hazard.py`), and both controls
are implemented beside them, in the same module, so the comparison cannot drift
apart. They were then measured.

### What was measured

Fixed split, all three coordinates recorded as §0.1 of the specification
requires: **`corpus='ambiguous'`, `count=240`, `seed=11`**, Python 3.14.7, Linux
7.1.5+kali-amd64, `synthetic_data=True`.

```
cd /home/anil/Documents/Research/pocketsec && PYTHONHASHSEED=0 \
  python -m pytest tests/test_stage2_predictors.py -q -k measured -s
```

Lattice: 14 behaviour atoms from the specification's own `HashBucketQuantizer`
rule — a deterministic bucket of `(relation_family, state_delta_mask,
object_property_mask)`. Bigram transition counts fitted on the first 120
scenarios, scored on 3000 contexts drawn from the last 120. Label space: the
seven `CONE_LABELS`, of which `unknown` carries `unresolved_mass`. Brier is the
multiclass sum of squared errors over all seven labels, so it ranges [0, 2].

**Future Cone, against a one-step truth:**

| mechanism | bounds | Brier (lower is better) |
|---|---|---|
| `predict_future_cone` (as specified) | width 4, depth 3 | **1.458259** |
| `predict_future_cone` | width 4, depth 1 | **0.169505** |
| `predict_future_cone` (argmax control, spec §5) | width 1, depth 1 | 0.818529 |
| **`marginal_cone` (the control)** | width 4, depth 1 | **0.175982** |

Mean `unresolved_mass` of the as-specified cone: **0.848074**.

**Future Cone, against a depth-3 truth** — added so the deep cone is not
penalised merely for being scored on a question it was not asked:

| mechanism | Brier |
|---|---|
| `predict_future_cone` (width 4, depth 3) | **1.484908** |
| `marginal_cone` | **0.301033** |

**Hazard, 36 000 points (3000 contexts × 4 outcomes × 3 horizons), positive rate
0.189722:**

| mechanism | Brier | ECE (10 bins) |
|---|---|---|
| `estimate_security_hazard` | **0.189552** | **0.189625** |
| **`constant_hazard` (the control)** | **0.077958** | **0.036822** |

**Runtime cost of this package's surface**, CPU time via `time.process_time()`
(the clock `stage0/benchmark/resource_metrics.py:133` uses):

| figure | value |
|---|---|
| full 8-head parameter count (derived from Stage 1 vocabularies) | **8 245** |
| full 8-head `memory_bytes` (`sys.getsizeof`, measured) | **269 368** |
| CPU µs per full 8-head `predict` over a 64-step window | 1 143.2 |
| CPU µs per `predict_future_cone` | 432.55 |
| one-minute load average during the timing | **50.52** |

The two CPU figures were taken on a host under load average 50.5 (seven packages
of this wave were building in the same tree) and are therefore **indicative
only**; the parameter and byte counts are deterministic and are not.

### What the numbers say

**The cone as specified is decisively worse than the control**, by 1.28 Brier
against a one-step truth and by 1.18 against a depth-3 truth. The cause is
measured, not guessed: the 14 atoms have a **mean out-degree of 9.5 and a maximum
of 14** on this split, so a beam of `MAX_BRANCHES = 4` leaves most of the
probability unnamed at every level and the loss compounds with depth. Mean
unresolved mass is **0.848074** — the cone spends 85 % of its confidence on
"unknown". That is *honest* (the unresolved branch is
explicit and never folded away, which is the one property of this design worth
keeping) but it is not useful, and calling it useful would be the failure this
repository exists to avoid.

**Depth is where the cone loses.** Collapsed to depth 1 the cone reaches 0.169505
against the control's 0.175982 — an improvement of **0.006477 Brier, 3.7 %
relative**, on synthetic data whose zero-parameter baseline already swings 0.4025
PR-AUC with corpus size alone (§0.1). That margin is not a finding. It is inside
the corpus noise this specification measured and warned about, and a mechanism
cannot be retained on it.

**The single-branch argmax cone (0.818529) is worse than either**, which confirms
the bound is not the problem: the problem is that conditioning on the current
atom adds almost nothing a marginal does not already have.

**The hazard heads are worse than a base rate on both metrics**, by 2.4× on Brier
and 5.2× on ECE. The compounded per-event rate `1 − (1 − λ)^H` inherits the
cone's overconfidence and then amplifies it across horizons. A mechanism whose
calibration error is five times a constant's cannot support abstention or AOP
decisions, which is the only reason section 22 wanted it.

## Decision

**Reject DTL-F05 (`predict_future_cone`) and DTL-F08
(`estimate_security_hazard`) as runtime mechanisms. Both are default off.**
Neither may contribute to a detection score, a verdict, a hazard-driven
escalation, or a compile candidate, and no downstream package may enable them
without a new measurement that changes the table above.

Both remain in the tree, implemented and unit-tested, for four reasons:

1. `marginal_cone` and `constant_hazard` are the controls that produced this
   rejection, and deleting the mechanism would delete its own falsifier.
2. The mass-conservation contract (`sum(branch probabilities) +
   unresolved_mass == 1.0 ± 1e-9`) and the explicit unknown branch are reusable
   and correct regardless of this verdict.
3. `FutureCone.label_distribution()` is what any future re-measurement scores,
   on real telemetry rather than on a fourth synthetic corpus.
4. Deleting a measured negative result destroys the provenance this repository
   treats as a first-class artefact.

`CoreFunction` already classes both DTL-F05 and DTL-F08 as `OPTIONAL`
(`core_ids.py`), so this rejection needs no interface change: criterion 12 is
satisfied by a default-off mechanism with a `REJECTED` verdict, which is exactly
what this ADR records.

## Options considered

| Option | Measured consequence |
|---|---|
| Retain the cone as specified (width 4, depth 3) | Brier **1.458259** vs control **0.175982** on a one-step truth; **1.484908** vs **0.301033** on a depth-3 truth. 8.3× worse. Rejected. |
| Retain the cone collapsed to depth 1 | Brier **0.169505** vs control **0.175982**: +0.006477, 3.7 % relative, on a corpus whose free baseline moves 0.4025 with sample count. Inside the noise; a depth-1 "cone" is also just next-event prediction, which is the thing criterion 6 requires it to beat. Rejected. |
| Retain the 1-branch argmax cone | Brier **0.818529**, worse than both the depth-1 cone and the control. Rejected. |
| Retain the hazard heads | Brier **0.189552** vs **0.077958**; ECE **0.189625** vs **0.036822**. Worse than a base rate on both. Rejected. |
| Widen `MAX_BRANCHES` past 4 to recover the unresolved mass | Not measured, and not permitted: spec section 7 fixes the cone as "deliberately shallow and bounded" and the endpoint is a 2 GB host. Raising the bound to win a Brier score would trade the resource invariant for a metric, which is the one trade this project does not make. Declared **UNMEASURED**, not "would probably work". |
| Delete both modules | Deletes the controls that produced the rejection, and the mass-conservation contract with them. Rejected in favour of default-off. |

## Consequences

**G2.6 passes in its REMOVED branch.** Criterion 6 is met by removal plus this
ADR, not by a value claim. The gate must read this as a pass *because* the
mechanism is off, and must fail if anything later turns it on without a new
measurement.

**Hazard estimates carry `calibration_id = None`, permanently for now.** Every
`HazardEstimate` this module produces is an uncalibrated compounded rate. D2.9's
isotonic calibrator could in principle fit a map for it, but calibrating a
mechanism that is worse than its own base rate would put a real identifier on a
number nobody should use. `None` is the correct value and it is not a gap.

**Stage 3 receives no cone.** Per integration plan §6.5 the cone was never a
Stage 3 prerequisite; this decision confirms it is not a Stage 3 *candidate*
either. Nothing in `compile_candidates/` may export a cone-derived branch, a
hazard probability, or a `ConeBranch` label as a compile candidate.

**The negative-space residual (DTL-F09) is unaffected but also stays off.** It was
already default-off at −0.073 PR-AUC (ADR-0010); this ADR does not rehabilitate
it and does not add a second reason to remove it.

**This is the third mechanism in Stage 2 to fail against a zero- or
near-zero-parameter control**, after the Need router (−0.115) and the surprise
vector (−0.073), and it fails against a control that is *simpler still*: a
marginal that never looks at where the lineage is standing. Read together with
the Φ-oracle's 0.7484 PR-AUC at zero parameters, the pattern is now consistent
enough to be the finding: on this representation, structure in Stage 1 is
outperforming machinery in Stage 2.

## What would reopen this

All three at once, not any one of them:

1. **Real telemetry**, not a fifth synthetic corpus. Every number above carries
   `synthetic_data=True`, and §0.1 measured a 0.4025 PR-AUC swing in a
   zero-parameter baseline from sample count alone on this very generator.
2. A branching factor the bound can actually cover. Measured here: mean
   out-degree 9.5, maximum 14, against `MAX_BRANCHES = 4`. The cone needs a
   lattice whose atoms have on the order of 4 live successors at the operating
   epoch, so `unresolved_mass` is small enough for the cone to be making a claim
   rather than abstaining.
3. A margin over `marginal_cone` and `constant_hazard` that is **larger than the
   corpus-size instability of the free baseline on the same split**, measured at
   two seeds, not one.

## Verification

- `tests/test_stage2_predictors.py::test_measured_cone_brier_against_the_marginal_control`
- `tests/test_stage2_predictors.py::test_measured_hazard_against_the_constant_control`
- `tests/test_stage2_predictors.py::test_measured_runtime_cost_of_the_predictor_surface`

Both print their full result dictionary including `corpus`, `count`, `seed`,
`contexts` and `synthetic_data`, and **neither asserts a winner** — they assert
only that each reported figure is a real Brier/ECE over a real distribution. The
verdict lives in this ADR, where it can be argued with, rather than inside an
assertion that would quietly decide it.

## Honest limits of this ADR

1. The lattice and quantizer used for the measurement are minimal local
   stand-ins implementing the published signatures from `docs/stage-2-spec.md`,
   because `pocketsec/stage2/lattice/` was being written concurrently with this
   package. The atoms follow the specification's own `HashBucketQuantizer` rule,
   and 14 distinct `(relation_family, state_delta_mask, object_property_mask)`
   triples were measured on this corpus, so nothing was truncated by the atom
   bound. A re-measurement against the real `BehaviourQuantizer` and
   `TransitionLattice` is owed, and this ADR should be revisited if it moves the
   cone past `marginal_cone` by more than the noise floor in §"What would reopen
   this".
2. The ECE above was computed by a local 10-bin implementation in the test file,
   not by `uncertainty/calibration.py`, which is a sibling package in the same
   wave. The `report` package must recompute it with the real metric before the
   number enters the findings ledger.
3. `Stage2Sample.final_phi` is `ScenarioResult.peak_phi` (`dataset.py:143`) and
   is **not** a terminal value. It was not used as hazard ground truth anywhere
   in this measurement; the ground truth is whether the relevant capability
   dimension was actually raised within the next H transitions of the same
   scenario.

## Prior art

No novelty claimed. Beam-truncated forward search losing probability mass with
depth is a standard result; the contribution here is only that PocketSec measured
it against the dumbest available control before shipping it, and took the
answer.
