# ADR-0120 — A corpus degeneracy guard, and the measured Φ-oracle corpus-size instability

- **Status:** Accepted
- **Date:** 2026-09-24
- **Stage:** 2
- **Deciders:** Stage 2 completion wave, `report` work package
- **Supersedes:** nothing. **Extends:** ADR-0008 (research/runtime dependency boundary),
  ADR-0009 and ADR-0010 (the recurrent core is rejected; the Stage 2 core is a TCN),
  and the Stage 1 precedent `ParetoReport.degenerate`
  (`pocketsec/stage1/guillotine/ablation.py:180`), which reached the same
  conclusion about the Stage 1 field frontier.

## Context

Stage 2 acceptance criterion 12 requires every surviving component to have an
**ablation-supported reason to exist**. This wave implements eleven of them at
once. If the corpus those ablations are measured on cannot discriminate between
mechanisms, then criterion 12 is satisfied by an artefact and the whole stage
rests on noise.

Two measurements taken this session say that is the live risk, not a hypothetical
one.

**1. A zero-parameter scorer's PR-AUC moves 0.4025 with corpus size alone.**
`PhiOracleBaseline` has no parameters and no training — it scores a session by the
largest squashed |ΔΦ| in it (feature slot 73). Run on the *same generator* with
only `count` changed:

```
cd /home/anil/Documents/Research/pocketsec
PYTHONHASHSEED=0 python -c "
from pocketsec.stage2.dataset import build_dataset
from pocketsec.stage2.research.baselines import PhiOracleBaseline
from pocketsec.stage0.benchmark.security_metrics import average_precision
for corpus,count,seed in [('ambiguous',60,11),('ambiguous',120,11),('ambiguous',240,11),('long',240,11),('hard',60,11)]:
    d=build_dataset(name='t',count=count,seed=seed,corpus=corpus)
    s=PhiOracleBaseline().fit(d).predict_scores(d)
    print(corpus,count,seed,len(d),round(d.base_rate,4),round(average_precision(list(d.labels),s) or 0.0,4))
"
```

```
ambiguous 60 11 60 0.3333 1.0
ambiguous 120 11 120 0.3333 0.8495
ambiguous 240 11 240 0.3333 0.5975
long 240 11 240 0.3333 0.3172
hard 60 11 60 0.4 0.76
```

(109.44 s user CPU, Python 3.14.7, Linux 7.1.5+kali-amd64, `synthetic_data=True`.)

Three things follow. The `ambiguous` corpus is **saturated at count=60**: a model
with zero parameters is perfect. At count=240 the same scorer reaches 0.5975, so a
component measured at +0.04 on that corpus is measured against a background that
moves by ten times as much for reasons that have nothing to do with the
component. And on `long` the Φ-oracle sits at **0.3172 against a 0.3333 base
rate** — *below chance* — while a TCN reaches 1.0000 (ADR-0009): the two corpora
disagree about what the task is.

**2. A large spread is not evidence that a corpus discriminates.** Measured this
session with the full nine-baseline suite at one shared budget (hidden=24,
epochs=40):

| split | base rate | best | median | spread | mlp-pooled (order-free) | Φ-oracle (0 params) |
|---|---|---|---|---|---|---|
| `ambiguous` count=30 seed=11 | 0.3333 | **1.0000** (phi-oracle) | 0.5814 | 0.4186 | **1.0000** | **1.0000** |
| `hard` count=6 seed=11 (26 samples) | 0.5000 | **0.9682** (mlp-pooled) | 0.9477 | 0.0205 | **0.9682** | 0.6859 |

The `ambiguous` split has a **spread of 0.42** — it looks informative — and is
nonetheless useless for judging any sequential mechanism, because a pooled
bag-of-features model that cannot see event order at all reaches the same 1.0000
as the best model. A spread test alone would have passed it. The `hard` split has
a spread of 0.0205, also above the 0.01 threshold, and is likewise tied by the
order-free baseline. **Both of the obvious single tests miss both of these
corpora.**

Stage 2 has already been burned by the general form of this: ADR-0009 records that
the `hard` corpus ties five architectures at 0.9992, so "multiscale, router and
surprise show no measured benefit" could not be read as evidence about those
mechanisms.

## Decision

`pocketsec/stage2/research/saturation.py` implements a guard that runs **before**
any component delta is recorded, and `pocketsec/stage2/research/stage2_report.py`
refuses to record one when it fires.

`saturation_check(train, test)` fits the whole `BASELINE_REGISTRY` suite once, at
one shared budget, on the split the ablation would use, and returns a
`SaturationVerdict` whose every numeric field is a measured PR-AUC or `None`. A
split is **degenerate** when any of four conditions holds:

1. `best - median < DEGENERATE_SPREAD` (0.01) — the architectures agree, so there
   is no headroom in which a mechanism could show an effect.
2. `MLPBaseline` — pooled features, **order-free** — lands within
   `ORDER_FREE_TOLERANCE` (0.02) of the best score. The task is then not a
   sequence task, and no sequential mechanism may be credited for solving it.
3. `PhiOracleBaseline` — **zero parameters** — lands within the same tolerance of
   the best score. Stage 1's representation already solved it, and the learning is
   not where the value is (ADR-0010's F3).
4. Any baseline scores **at or below the base rate**. A model below chance is a
   bug, not a weak architecture (`planning/MEMORY.md`, benchmarking trap 2), and a
   split that produces one cannot rank anything. The offending names are recorded
   in `below_base_rate`.

`refuse_if_degenerate(verdict)` **raises** `CorpusDegenerate`. It does not warn: a
warning printed next to a number gets quoted without the warning.

`build_report` runs the guard first. When it refuses, every component row that
depends on the detection split is recorded as **`UNMEASURABLE`** — never
`NOT_YET_JUSTIFIED`, which would imply a measurement was taken, and never
`JUSTIFIED` — with the refusal reason in `detail`, and `latent_frontier` is
skipped rather than fitted, so no knee is reported for a corpus-size artefact
(spec §4.1, G2.2 `DEGENERATE_CORPUS`). `ComponentVerdict.__post_init__` refuses a
`JUSTIFIED` verdict that carries no experiment id and refuses any measured verdict
with no delta, so the four-word vocabulary cannot be widened by accident.

Rows measured on their **own** fixtures — the drift corpus, the poison suite, the
sleeping-brain frontier — are not refused by a degenerate *detection* split, and
are listed explicitly in `SPLIT_DEPENDENT_COMPONENTS` so the distinction is data
rather than a comment.

## Options considered

| Option | Security cost | Resource cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|---|
| **A. No guard: record every delta and caveat it in prose** | None directly, but a component kept on an artefact becomes machinery a later stage trusts | Zero | lowest | **Measured: the `ambiguous` count=30 split would have recorded nine component deltas against a background where a 0-parameter scorer already scores 1.0000.** The same generator moves 0.4025 on `count` alone | Rejected. This is precisely how criterion 12 gets satisfied by noise, and the prose caveat is the part that does not travel |
| **B. Spread test only (`best - median < 0.01`)** | Same failure mode, narrower | One suite fit | low | **Measured: it passes both degenerate splits.** `ambiguous`/30 spread **0.4186**, `hard`/6 spread **0.0205**, both above the threshold, both tied by the order-free baseline at **1.0000** and **0.9682** | Rejected on measurement. The obvious test is not sufficient |
| **C. Four conditions: spread, order-free tie, zero-parameter tie, below-base-rate (chosen)** | None. Refuses rather than records | One suite fit per report (measured: 101.1 s for the whole `build_report` at `ambiguous` count=30, of which the suite is the bulk) | moderate — 247 lines, one dataclass, two functions | **Measured: catches both splits, and names *which* condition fired (`ORDER_FREE_BASELINE_TIES_BEST` for both)** | Chosen | — |
| **D. Require a new, harder corpus before measuring anything** | None | A corpus build the wave cannot validate | high | **Not measured.** `planning/MEMORY.md` already records four synthetic corpora producing only trivial or impossible tasks, never a middle band | Rejected as a *precondition*; retained as the recommendation the guard's refusal produces. Real telemetry, not a fifth synthetic corpus, is the blocker |

The simplest option that could work (B) was rejected because it was **measured to
fail on the actual corpora**, not because it seemed weak.

## Consequences

**What this costs.** One full baseline-suite fit before any ablation is recorded.
Measured: `build_report(corpus="ambiguous", count=30, robustness_count=12)`
completes in **101.1 s** end to end on this host, and the suite dominates that.
The guard therefore roughly doubles the cost of a report that would otherwise fit
only the ablation arms — and it deletes the report's headline instead of
delivering it, which is the point.

**What it produced immediately.** On the corpora this repository has, the guard
refuses. That makes G2.2 `FAILED` with reason `DEGENERATE_CORPUS` and leaves nine
of the thirteen §5 rows `UNMEASURABLE`. That is the honest state of Stage 2's
evidence, and it is the same conclusion ADR-0010 reached from the other direction.

**What is still measured, because none of it is a component delta:**

* **Resource.** `ResourceSampler` around the whole stdlib runtime path
  (`WindowStore` → `BehaviourQuantizer` → `TransitionLattice` → `TransitionCache`
  → `predict_future_cone` → `estimate_uncertainty`) on `hard`/count=6, 120 events:
  `check_profile(..., "edge")` `within_target=True`, ΔRSS **376 832 B**,
  component bytes window_store **195 952** + quantizer **45 872** + lattice
  **9 432**, cache **14 506 B** — well inside the 80 MB Stage 2 incremental
  ceiling (spec §31).
* **Cost.** The same path costs **570.99 µs/event** wall clock, per-`WorkKind`
  means: `LATTICE_LOOKUP` **243.24 µs** (the quantizer's prototype search),
  `WINDOW_UPDATE` **52.80**, `CONE_EXPANSION` **35.49**, `CORE_INFERENCE`
  **24.46**, `CACHE_LOOKUP` **20.38**. Normalised to the cheapest kind the
  measured ladder is `CACHE_LOOKUP 1.0, CORE_INFERENCE 1.2, CONE_EXPANSION 1.74,
  WINDOW_UPDATE 2.59, LATTICE_LOOKUP 11.94`, against `PATH_COST_UNITS`' declared
  `P0 1.0, P1 2.0, P2 8.0, P3 40.0, P4 200.0`. **The declared ladder is not merely
  uncalibrated, it is inverted with respect to measurement**: the "expensive"
  inference is 1.2× a cache lookup, and the most expensive thing on the path is
  the prototype lookup the ladder prices at 2.0. `PATH_COST_UNITS`' docstring
  claims calibration from measured CPU time and **no calibration code exists in
  this repository**, so the report records it as `UNMEASURED` and reports
  wall-clock µs/event beside it.
* **Robustness.** On the drift corpus at count=6 seed=11, the quarantine gate
  normalised **0** malicious patterns and recovered after **1** transition, where
  `ACCEPT_EVERYTHING` normalised **93**; on the poison suite the gate promoted
  **0** attack-lineage samples against `ACCEPT_EVERYTHING`'s **16**. At
  robustness_count=12 the same comparison was **0 vs 186** and **0 vs 24**.
* **Attribution.** The causal credit ledger inspected **0** nodes at
  `chain_recall` **0.0** where full naive ancestry reached **1.0** on **18**
  nodes, and the zero-parameter `phi_only_probe` control also reached **0.0**.
  Fewer nodes at lower recall is not conciseness, so `_credit_verdict` reports the
  metric that failed (`chain_recall`) rather than the node count, and the verdict
  is `REJECTED`. This is consistent with ADR-0122.
* **Cost of the export candidate.** On `ambiguous` count=30, the cheapest learned
  candidate (`mlp-pooled`) costs **9.02 µs/event** at 1.0000 PR-AUC against the
  Φ-oracle's **0.08 µs/event** at the same 1.0000. No learned candidate beats the
  zero-parameter one on cost at equal quality — ADR-0010's F3, reproduced.

**Honest limits.**

1. Every figure above is on **synthetic** corpora (`synthetic_data=True` travels
   with every dataset provenance block) on this development host. None is a
   detection result.
2. The four thresholds (0.01, 0.02) are **conventions, not measured optima**. They
   were chosen to catch the two corpora above and are asserted at their stated
   values in `tests/test_stage2_report.py::test_every_degeneracy_condition_is_enforced_at_its_stated_threshold`.
3. The guard proves a corpus **cannot** support a conclusion. It can never prove
   one can: a split that passes all four conditions may still be degenerate in a
   way none of them models.
4. Experiment ids for this wave are **minted, not registered**
   (`provenance["experiment_ids_registered"] is False`). `experiments/registry.jsonl`
   is digest-chained and append-only and eight packages were writing in parallel,
   so this module does not append to it; the integrator's CLI records the run.
   Until then, a `JUSTIFIED` verdict here names a measurement that exists in the
   report and not yet in the ledger, and G2.12's registry check correctly fails it.
5. `PATH_COST_UNITS` remains **UNMEASURED**. The per-`WorkKind` figures above are
   a measurement of this implementation on this path, not a calibration of the
   five-rung `ExecutionPath` ladder, which has no runtime implementation for P4.

**Reversibility.** Both modules are additive, live under `research/` (numpy
permitted, ADR-0008) and are imported by nothing in the runtime. Deleting
`saturation.py` removes the guard and the refusal; deleting `stage2_report.py`
removes the report. Neither deletes or weakens a prior result, and no retracted
result was edited: the Φ-oracle figures here **supersede nothing** — they are the
first measurement of corpus-size sensitivity in this repository.

**Authority.** None. A verdict word is a research finding; it grants nothing and
touches no privilege.

## Verification

`cd /home/anil/Documents/Research/pocketsec && PYTHONHASHSEED=0 python -m pytest tests/test_stage2_report.py -q`
— **46 passed** this session (121 s). The tests that pin this decision:

- `test_saturation_marks_a_trivial_corpus_degenerate` — a real corpus, not a stub.
- `test_every_degeneracy_condition_is_enforced_at_its_stated_threshold` — all four
  conditions, each just inside and just outside its threshold.
- `test_refuse_if_degenerate_raises_and_names_the_reason`,
  `test_a_baseline_below_the_base_rate_refuses_the_split`.
- `test_phi_oracle_regression_fast` and `test_phi_oracle_corpus_size_regression`
  (`slow`) — the five measured figures above, to ±5e-5. If the generator moves
  them, every delta measured on these corpora is void and this test says so first.
- `test_degenerate_corpus_cannot_produce_a_justified_component` — walks a real
  refused report and asserts every split-dependent row is `UNMEASURABLE` with no
  delta and no experiment id, and that no component appears twice.
- `test_report_numbers_are_floats_or_none_with_a_named_producer` — every figure is
  a float or `None`, and every section names the `module:function` that produced
  it.
- `test_an_unmeasured_profile_is_none_and_never_true` — `ProfileReport.within_target`
  stays `None`, the Stage 0 invariant.
- `test_path_cost_units_are_reported_unmeasured`.
- `test_default_latent_dimensions_never_build_a_degenerate_block` and
  `test_block_width_floor_is_measured_not_assumed` — measured: `latent=8` gives
  `fast=-2` (numpy: "negative dimensions are not allowed"), `latent=10` gives
  `fast=0`, a **silently zero-width fastest timescale**, and `latent=11` gives 1.
  `DEFAULT_LATENT_DIMENSIONS` therefore starts at **12**;
  `research/experiments.py::latent_sweep` still defaults to 8 and still crashes on
  its first point.
- `test_refitting_a_model_twice_is_detected` — `_TorchLikeModule.fit` continues
  training rather than restarting, which is why no already-fitted model is handed
  to `sleeping_brain_report` or to a frontier point.
- `test_every_core_function_resolves_to_real_code` — the D2.1 audit: all **20**
  `CoreFunction` ids, including all **8** REQUIRED, resolve by import to a
  stdlib-only implementation outside `research/`. Before this wave only DTL-F01
  did.

## Prior art

No novelty claimed. Checking that a benchmark can discriminate before drawing a
conclusion from it is ordinary experimental hygiene; the specific form here —
compare against an order-free and a zero-parameter control, and refuse rather than
caveat — follows this repository's own Stage 1 precedent
(`ParetoReport.degenerate`, ADR-0007's frontier work) and the unified
provenance-IDS finding already cited in `research/baselines.py` that simple models
match far more complex ones. No `docs/prior-art/ledger.json` entry is required
because no novelty is claimed.
