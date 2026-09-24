# ADR-0117 — Stage 2 carries a real `calibration_id`, and says when it is honestly `None`

- **Status:** Accepted
- **Date:** 2026-09-24
- **Stage:** 2
- **Deciders:** Stage 2 completion wave, `uncertainty` work package (D2.9, DTL-F07)
- **Supersedes / superseded by:** none. Closes Stage 1 known gap 3
  ("confidence is uncalibrated in both Stage 1 slots, `calibration_id=None`,
  honestly") for **Stage 2's own outputs only**.

## Context

Both Stage 1 slots ship `calibration_id=None`. That was honest — nothing in
Stage 0 or Stage 1 ever fitted a map from a raw score to an empirical event rate,
so no slot could name one — but it leaves every Stage 2 consumer unable to tell a
score of 0.7 that means "70 % of the time" from one that means "higher than 0.6".
G2.5 requires calibration good enough to support abstention and AOP, so Stage 2
has to either produce a real id or state why it cannot.

Stage 0 provides no calibration machinery at all: `benchmark/security_metrics.py`
measures *ranking* (PR-AUC, recall at an FP budget) and has no ECE, no Brier
score, no reliability bins and no conformal quantile. Ranking and calibration are
independent: an isotonic map is monotone, so it **cannot change a ranking**, and
a perfect ranker can be arbitrarily miscalibrated. Implementing the metric family
in `stage2/uncertainty/` is therefore not a duplicate harness (spec §3.1).

Three measurements forced the shape of this decision. All were produced in this
session on Python 3.14.7 / Linux 7.1.5+kali-amd64, on synthetic data
(`synthetic_data=True`), with `corpus`, `count` and `seed` fixed as the spec
requires.

**1. The calibration itself works on this split.** Scorer under test: the
deterministic Φ window score (max over the lineage window of encoder feature 73,
the squashed |ΔΦ| slot) — the zero-parameter baseline everything in Stage 2 must
beat. Split `corpus=ambiguous, count=240, seed=11`, even indices calibrate, odd
indices evaluate, 120 samples each, base rate 0.3333, window-score PR-AUC 0.5975
(which reproduces the Φ-oracle figure recorded in the spec for this split).

| quantity | raw score | isotonic-calibrated | measured by |
|---|---|---|---|
| ECE (10 bins, held out) | 0.0849 | **0.0064** | `tests/test_stage2_uncertainty.py::test_measured_calibration_against_the_one_minus_max_control` |
| Brier (held out) | 0.2034 | **0.1588** | same |
| MCE (held out) | — | 0.0073 | same |
| risk–coverage AUC (lower better) | 0.2734 (`one_minus_max` control) | **0.0900** | same |
| `calibration_id` | — | `stage2-isotonic-f99542426f4c` | same |

**2. A fitted map's in-sample ECE is 0.0 by construction, so it is not
evidence.** Isotonic regression assigns every point its own pooled block's
empirical rate, so every occupied reliability bin is a union of complete blocks
and every gap cancels exactly. Measured: `fit(...).expected_calibration_error ==
0.0` on 300 Bernoulli draws *and* on the 120-sample calibration split. A gate
that read the number returned by `fit` would pass G2.5 on an algebraic identity.

**3. Split conformal is honest but vacuous on a binary detection score.** On
exchangeable synthetic residuals the implementation is correct: nominal 0.90 →
empirical 0.8990 (n=512 calibration, 2000 fresh residuals), and 0.9133 on a
labelled synthetic set. On Stage 2's *own* calibrated detection score the fitted
radius is 0.7692, so the interval is 1.54 wide over a label in [0, 1] and covers
**1.0000** of the evaluation set against a 0.90 nominal.

A fourth measurement came out of profiling rather than statistics: computing
`calibration_id` lazily (hash the knots on every read) cost **636 µs/event**
against 15 µs with the id computed once at fit time — 40× the entire rest of the
estimate, for a string that changes only when the map does.

## Decision

1. **`calibration_id` identifies the fitted knots and nothing else.** It is
   `stage2-isotonic-<first 12 hex of sha256 of the knot list, rounded to 6
   decimals>`. Same knots → same id, across processes and reruns; different knots
   → different id. It does **not** encode the corpus, the split, the seed or the
   scorer: those belong to the experiment id that accompanies the report. The id
   answers one question — "is this the same map?" — and refuses to imply more.
   It is computed once when the knots are installed, never on the hot path.
2. **`calibration_id` is `None` in exactly these cases**, each with a
   non-empty `refusal_reason` (a `CalibrationReport` with `None` and no reason
   raises `ContractError` — a refusal that does not say why is a silence):
   an empty fit; fewer than `MIN_FIT_SAMPLES = 8` samples; a **single-class**
   fit; and any `evaluate` on an unfitted map or a single-class evaluation split.
   An unfitted calibrator's `apply` **raises** rather than returning the score
   unchanged, because a pass-through wearing a calibrated coat is
   indistinguishable downstream from a real map.
3. **The single-class refusal is not negotiable.** It is the Stage 1 Information
   Guillotine's trap 2 (`planning/MEMORY.md`): a benign-only fit split produced
   an inverted ranking and a PR-AUC *below* the base rate. A map fitted on one
   class is indistinguishable from a constant.
4. **A metric that could not be computed is `None`; a metric measured as zero is
   `0.0`.** `expected_calibration_error`, `max_calibration_error` and
   `brier_score` return `None` on empty or single-class input and `0.0` when zero
   is the measured answer. Both directions are tested; ADR-0004's reasoning cuts
   both ways.
5. **Held-out reports are the only evidence.** `fit` returns
   `in_sample=True`; `IsotonicCalibrator.evaluate(labels, scores)` returns
   `in_sample=False` and is the method a gate must use. This is a deviation from
   the field list in `docs/stage-2-spec.md` §D2.9 (one added defaulted field and
   one added method) and it exists to make the measured trap above unusable.
6. **Novelty, Φ and uncertainty stay three separate signals.**
   `UncertaintyEstimate.value` is built only from evaluated uncertainty sources.
   Φ arrives as a separate argument and selects the quadrant only; novelty is not
   an argument at all. Two tests fail if either leaks in.
7. **A source that was never evaluated is absent from `sources`, not present at
   1.0.** A source that ran and found nothing is present at a low value and
   *lowers* the estimate. That is Stage 1's modelling distinction ("no properties
   asserted" is not "maximally uncertain"), and conflating the two drove constant
   AOP escalation once already. `transition.observation_incomplete` is the only
   driver of `EVIDENCE_INCOMPLETE`.

## Options considered

| Option | Security cost | Resource cost | Complexity | Why not chosen |
|---|---|---|---|---|
| **Isotonic (PAV) + held-out evaluation** — chosen | Held-out ECE **0.0064**, Brier **0.1588**, risk–coverage AUC **0.0900** | 148 knots = **2396 B** measured; **~15.3 µs/event** calibrated (min of 8 runs, load average 40) | ~200 lines, stdlib | — |
| Keep `calibration_id=None` (Stage 1's honest status quo) | ECE stays **0.0849** raw; abstention ranks by an uncalibrated score, risk–coverage AUC **0.2734** | **~1.2 µs/event** (`one_minus_max` control, measured) | zero | Fails G2.5's first clause outright, and the measured ECE gain (0.0849 → 0.0064) is real on this split |
| Platt scaling (a 2-parameter sigmoid) | not measured — **UNMEASURED** | smaller than 2396 B | needs an optimiser or a hand-rolled IRLS | Rejected without measurement, and recorded as such: the Φ window score takes only 5 distinct values on this split, which a sigmoid cannot follow but a step function can. Reopen with a continuous scorer |
| Temperature scaling over head logits | not measured — **UNMEASURED** | ~1 float | small | Requires logits from `predictors`, which are optional and detached (ADR-0009); Stage 2's honest outputs must calibrate without them |
| Conformal intervals on the detection score | Coverage **1.0000** vs 0.90 nominal, radius 0.7692 → the interval is wider than the label range | 8232 B at n=1024, measured | small | Kept in the codebase, **not claimed as calibration of detection.** Vacuous on a binary label; it belongs on a continuous output |

## Consequences

**Accepted costs.** The calibrated estimate costs about **15.3 µs/event**
(uncalibrated **12.6 µs/event**, `one_minus_max` control **1.2 µs/event**; min of
8 runs on a host at load average 40.08 — these are noisy minima, not a clean
benchmark). That is roughly **12× the control** and above the accepted TCN core's
6.6 µs/event inference (ADR-0010). Uncertainty estimation is therefore not free,
and the `report` package must weigh it as a real per-event cost rather than
assuming a calibration layer is negligible.

**Bounded state.** Endpoint state added by D2.9 is two bounded objects, both with
computed `memory_bytes()`: the calibrator at 16 B per knot (measured **2396 B**
for a 148-knot map fitted on 1024 samples) and `SplitConformal` at 8 B per
retained residual, capped at `max_calibration=1024` (measured **8232 B**). The
conformal reservoir evicts the **median-closest** residual when full — measured
3744 evictions on a 4000-residual stream at capacity 256 — which keeps both tails
and therefore biases the quantile *upward*: saturated coverage measured 0.9905
against 0.90 nominal. Conservative, counted (`evictions()`, `saturated()`), and
never silent.

**Reversibility.** The map ships as plain JSON (`to_json` / `from_json`, exact
round-trip, and `from_json` recomputes the id and raises if the payload's
declared id does not match the knots it claims to identify). Deleting the file
returns Stage 2 to `calibration_id=None`, which every consumer already has to
handle.

## G2.5 status — reported, not restated

| G2.5 clause | Measured | Verdict |
|---|---|---|
| `IsotonicCalibrator.fit` on a held-out split yields `calibration_id is not None` | `stage2-isotonic-f99542426f4c` | **MET** |
| `expected_calibration_error <= 0.10` | 0.0064 held out (0.0849 uncalibrated) | **MET** |
| `brier_score` reported | 0.1588 held out | **MET** |
| `SplitConformal.coverage` within ±0.05 of nominal | 0.8990 / 0.9133 on exchangeable synthetic residuals; **1.0000** on Stage 2's own calibrated detection score, radius 0.7692 | **NOT MET on Stage 2's own output** |

**The gate owner should treat G2.5 as failing on its conformal clause.** The
threshold is not to be loosened and the criterion is not to be restated. The
mechanism is correct — it reproduces nominal coverage on exchangeable residuals
to within 0.001 — but a two-sided interval on a binary label is vacuous by
construction. G2.5's conformal clause becomes meetable when Stage 2 has a
*continuous* output to wrap, the obvious candidate being a hazard probability at
a horizon (D2.8), which this package does not own.

## Honest limits

1. **This is calibration on this distribution only.** One synthetic corpus, one
   split, one scorer. A valid `calibration_id` on synthetic data says nothing
   about a real host; conformal coverage transfers only under exchangeability,
   which a real host violates (spec §9.4).
2. **The ECE gain is measured on a scorer with five distinct values.** The
   calibration split holds 5 distinct window scores and the fitted map has 3
   knots. A step function is the right family for that and a sigmoid is the wrong
   one, which is *why* Platt scaling was not run — not evidence that isotonic is
   better in general.
3. **`count=240, seed=11` is fixed because it has to be.** The Φ-oracle's PR-AUC
   on this generator moves 0.4025 with corpus size alone (1.0000 → 0.5975). Every
   number above is void if quoted without corpus, count and seed.
4. **The per-event timings were taken on a host at load average ~40** while other
   work packages ran in the same tree. They are reported as minima across 8 runs
   and should be re-measured on a quiet host before any Pareto claim rests on
   them.
5. **`ruff` and `mypy` have still never run** on this repository, so lint and
   type status of these three modules is UNVERIFIED.

## Verification

`tests/test_stage2_uncertainty.py` — 31 tests, all passing
(`PYTHONHASHSEED=0 python -m pytest tests/test_stage2_uncertainty.py -q`).
The tests that pin this ADR's decisions specifically:
`test_single_class_fit_is_refused_and_the_calibrator_stays_unfitted`,
`test_brier_distinguishes_measured_zero_from_unmeasurable`,
`test_in_sample_ece_is_structurally_zero_so_evaluate_is_the_honest_report`,
`test_calibration_id_tracks_the_knots_and_nothing_else`,
`test_from_json_rejects_a_tampered_id_and_non_monotone_knots`,
`test_uncertainty_value_is_invariant_to_novelty`,
`test_uncertainty_value_ignores_phi`,
`test_an_unevaluated_source_is_absent_not_maximal`,
`test_measured_calibration_against_the_one_minus_max_control`.

No experiment id was registered for this ADR: D2.9's numbers are unit-level
measurements inside the test suite, not a `run_benchmark` slot result. The
`report` package owns registering the Stage 2 experiment entries, and the figures
above are reproducible from the named tests.

## Prior art

No novelty claimed. Pool-adjacent-violators isotonic calibration (Zadrozny &
Elkan), ECE over reliability bins (Guo et al., *On Calibration of Modern Neural
Networks*), the Brier score, and split-conformal prediction (Vovk; Lei et al.)
are all standard. What is specific to this project is the refusal behaviour: the
single-class refusal, the `None`-versus-0.0 discipline, and treating an in-sample
ECE as a structural identity rather than as evidence.
