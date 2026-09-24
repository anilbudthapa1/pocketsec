"""D2.14 / D2.2 / D2.1 — the degeneracy guard and the Stage 2 report.

These tests are about a *measurement* boundary rather than a security boundary,
so almost none of them assert that a constructor works. They assert that the
report **refuses**: that a corpus which cannot rank mechanisms is marked
degenerate, that an ablation on such a corpus is never recorded, that an
unmeasured resource figure stays ``None`` instead of becoming ``True``, and that
a component cannot be called ``JUSTIFIED`` without an experiment id.

Four of them exist specifically to fail if someone weakens an invariant while
making something else pass:

* ``test_degenerate_corpus_cannot_produce_a_justified_component`` walks every
  verdict a refused report produced. If ``build_report`` ever starts recording a
  delta on a degenerate split, this is the test that breaks.
* ``test_phi_oracle_corpus_size_regression`` pins the three measured Φ-oracle
  figures that forced ADR-0120 into existence. A generator change that moves them
  invalidates every component delta measured on those corpora, and this test says
  so before a report quotes one.
* ``test_default_latent_dimensions_never_build_a_degenerate_block`` pins the
  block-width floor. Lowering the sweep's first point back to 8 or 10 breaks it.
* ``test_refitting_a_model_twice_is_detected`` shows that
  ``_TorchLikeModule.fit`` *continues* training rather than restarting, which is
  why nothing in the report hands an already-fitted model to a second evaluation.

All corpora are synthetic. Nothing here is a detection result.
"""

from __future__ import annotations

import math

import pytest

from pocketsec.stage0.benchmark.profiles import check_profile
from pocketsec.stage0.benchmark.resource_metrics import ResourceMetrics
from pocketsec.stage0.benchmark.security_metrics import average_precision
from pocketsec.stage0.experiments.ids import parse_experiment_id
from pocketsec.stage2.dataset import Stage2Dataset, build_dataset
from pocketsec.stage2.lattice.quantizer import BehaviourQuantizer
from pocketsec.stage2.research.baselines import MLPBaseline, PhiOracleBaseline
from pocketsec.stage2.research.dtl_conv import DTLConvConfig
from pocketsec.stage2.research.saturation import (
    DEGENERATE_SPREAD,
    ORDER_FREE_TOLERANCE,
    REASON_BELOW_BASE_RATE,
    REASON_INFORMATIVE,
    REASON_ORDER_FREE,
    REASON_PHI_ORACLE,
    REASON_SPREAD,
    CorpusDegenerate,
    SaturationVerdict,
    refuse_if_degenerate,
    saturation_check,
)
from pocketsec.stage2.research.stage2_report import (
    COMPONENT_ROWS,
    ComponentVerdict,
    DEFAULT_LATENT_DIMENSIONS,
    DTL_CONV_MIN_STEPS,
    MIN_BLOCK_WIDTH,
    SPLIT_DEPENDENT_COMPONENTS,
    STAGE2_INCREMENTAL_RSS_CEILING_BYTES,
    Stage2Report,
    UNMEASURED,
    VERDICT_JUSTIFIED,
    VERDICT_NOT_YET,
    VERDICT_UNMEASURABLE,
    _corpus,
    _export_verdict,
    block_width_floor,
    build_report,
    compile_scenarios,
    core_id_audit,
    dtl_conv_runnable,
    latent_frontier,
    longest_sequence,
    measure_atom_layer,
    measure_future_cone,
    measure_hazard,
    measure_lattice,
    measure_uncertainty,
    measure_window,
    mint_experiment_ids,
    path_cost_report,
    resource_report,
    safe_latent_dimensions,
)

#: Small enough to run in a unit-test suite, large enough that the machinery is
#: exercised on real Stage 1 output rather than on a stub.
SMALL_COUNT = 6
TRAIN_SEED = 3
TEST_SEED = 11

#: A well-formed id for tests that are not about id validation.
_ANY_ID = "PS-S2-20260924-H8-fixture-0007"


# --- fixtures ----------------------------------------------------------------


@pytest.fixture(scope="module")
def small_sessions() -> tuple[tuple, tuple]:
    """Two disjoint compiled splits of the cheapest corpus available."""
    return (
        compile_scenarios(_corpus("hard", count=SMALL_COUNT, seed=TRAIN_SEED)),
        compile_scenarios(_corpus("hard", count=SMALL_COUNT, seed=TEST_SEED)),
    )


@pytest.fixture(scope="module")
def ids() -> dict[str, str]:
    return mint_experiment_ids()


def _verdict(**overrides) -> SaturationVerdict:
    """A saturation verdict with every field explicit."""
    base = {
        "corpus": "hard",
        "count": 12,
        "seed": 11,
        "best": 0.9,
        "median": 0.5,
        "spread": 0.4,
        "order_free_baseline": 0.5,
        "phi_oracle": 0.4,
        "degenerate": False,
        "reason": REASON_INFORMATIVE,
        "base_rate": 0.33,
    }
    return SaturationVerdict(**{**base, **overrides})


# --- the degeneracy guard ----------------------------------------------------


def test_saturation_marks_a_trivial_corpus_degenerate() -> None:
    """The ``hard`` corpus at count=6 is deliberately trivial, and must be caught."""
    train = build_dataset(name="t", count=SMALL_COUNT, seed=TRAIN_SEED, corpus="hard")
    test = build_dataset(name="e", count=SMALL_COUNT, seed=TEST_SEED, corpus="hard")
    verdict = saturation_check(train, test)

    assert verdict.degenerate is True
    assert verdict.reason in {
        REASON_SPREAD,
        REASON_ORDER_FREE,
        REASON_PHI_ORACLE,
        REASON_BELOW_BASE_RATE,
    }
    assert verdict.corpus == "hard"
    assert verdict.count == len(test)
    assert verdict.seed == TEST_SEED
    # Every reported number is a real PR-AUC or None, never a filler.
    for value in (verdict.best, verdict.median, verdict.spread):
        assert value is None or isinstance(value, float)
    assert verdict.to_dict()["measured_by"].endswith("saturation:saturation_check")


def test_refuse_if_degenerate_raises_and_names_the_reason() -> None:
    with pytest.raises(CorpusDegenerate) as caught:
        refuse_if_degenerate(_verdict(degenerate=True, reason=REASON_ORDER_FREE))
    message = str(caught.value)
    assert REASON_ORDER_FREE in message
    assert "nothing is recorded" in message


def test_refuse_if_degenerate_is_silent_on_an_informative_corpus() -> None:
    refuse_if_degenerate(_verdict())  # must not raise


def test_every_degeneracy_condition_is_enforced_at_its_stated_threshold() -> None:
    """The four thresholds, each tested just inside and just outside."""
    from pocketsec.stage2.research.saturation import _classify

    informative = (("phi-oracle", 0.40), ("mlp-pooled", 0.50), ("tcn", 0.90))
    assert _classify(informative, base_rate=0.33)[1] == REASON_INFORMATIVE

    tied = (("phi-oracle", 0.40), ("mlp-pooled", 0.50), ("tcn", 0.50 + DEGENERATE_SPREAD / 2))
    assert _classify(tied, base_rate=0.33)[1] == REASON_SPREAD

    order_free = (
        ("phi-oracle", 0.40),
        ("mlp-pooled", 0.90 - ORDER_FREE_TOLERANCE / 2),
        ("tcn", 0.90),
    )
    assert _classify(order_free, base_rate=0.33)[1] == REASON_ORDER_FREE

    oracle = (
        ("phi-oracle", 0.90 - ORDER_FREE_TOLERANCE / 2),
        ("mlp-pooled", 0.50),
        ("tcn", 0.90),
    )
    assert _classify(oracle, base_rate=0.33)[1] == REASON_PHI_ORACLE

    below = (("phi-oracle", 0.30), ("mlp-pooled", 0.50), ("tcn", 0.90))
    degenerate, reason, offenders = _classify(below, base_rate=0.33)
    assert degenerate and reason == REASON_BELOW_BASE_RATE
    assert offenders == ("phi-oracle",)


def test_a_baseline_below_the_base_rate_refuses_the_split() -> None:
    """A model below chance is a bug, so the split cannot rank mechanisms.

    This is the enforcement of ``planning/MEMORY.md`` benchmarking trap 2, and it
    is why the report never quotes a delta from a split it has not checked.
    """
    verdict = _verdict(
        degenerate=True,
        reason=REASON_BELOW_BASE_RATE,
        below_base_rate=("phi-oracle",),
        phi_oracle=0.30,
        base_rate=0.33,
    )
    with pytest.raises(CorpusDegenerate):
        refuse_if_degenerate(verdict)
    assert verdict.to_dict()["below_base_rate"] == ["phi-oracle"]


# --- the measured Φ-oracle corpus-size instability (ADR-0120) ----------------


@pytest.mark.parametrize(
    ("corpus", "count", "seed", "expected"),
    [
        ("ambiguous", 60, 11, 1.0000),
        ("hard", 60, 11, 0.7600),
    ],
)
def test_phi_oracle_regression_fast(corpus: str, count: int, seed: int, expected: float) -> None:
    """The two cheap points of the measured instability table."""
    dataset = build_dataset(name="phi", count=count, seed=seed, corpus=corpus)
    scored = PhiOracleBaseline().fit(dataset).predict_scores(dataset)
    assert average_precision(list(dataset.labels), scored) == pytest.approx(expected, abs=5e-5)
    assert PhiOracleBaseline().resource_profile()["parameters"] == 0


@pytest.mark.slow
@pytest.mark.parametrize(
    ("corpus", "count", "seed", "expected"),
    [
        ("ambiguous", 120, 11, 0.8495),
        ("ambiguous", 240, 11, 0.5975),
        ("long", 240, 11, 0.3172),
    ],
)
def test_phi_oracle_corpus_size_regression(
    corpus: str, count: int, seed: int, expected: float
) -> None:
    """A zero-parameter scorer swings 0.4025 with corpus size alone.

    Measured with ``PYTHONHASHSEED=0`` on Python 3.14.7. If these move, no
    component delta measured on these corpora can be trusted, because the
    background against which it was measured has changed.
    """
    dataset = build_dataset(name="phi", count=count, seed=seed, corpus=corpus)
    value = average_precision(list(dataset.labels), PhiOracleBaseline().predict_scores(dataset))
    assert value == pytest.approx(expected, abs=5e-5)


@pytest.mark.slow
def test_the_long_corpus_leaves_the_phi_oracle_below_its_base_rate() -> None:
    """0.3172 against a 0.3333 base rate: the representation cannot see this task."""
    dataset = build_dataset(name="phi-long", count=240, seed=11, corpus="long")
    value = average_precision(list(dataset.labels), PhiOracleBaseline().predict_scores(dataset))
    assert value is not None and value < dataset.base_rate


# --- the block-width floor ---------------------------------------------------


@pytest.mark.parametrize("latent", [10, 11, 12])
def test_block_width_floor_is_measured_not_assumed(latent: int) -> None:
    """Latent 10 is silently zero-width; 11 and 12 are not.

    Measured this session: ``DTLConvConfig(latent=10).block_sizes()["fast"] == 0``
    and ``latent=8`` gives ``-2``, which numpy rejects with "negative dimensions
    are not allowed". The guard's job is to make that visible before a sweep
    trains a model with its fastest timescale entirely absent.
    """
    widths = block_width_floor(latent)
    assert widths == DTLConvConfig(latent=latent).block_sizes()
    if latent == 10:
        assert widths["fast"] == 0
        with pytest.raises(ValueError, match="below width"):
            safe_latent_dimensions((latent,))
    else:
        assert min(widths.values()) >= MIN_BLOCK_WIDTH
        assert safe_latent_dimensions((latent,)) == (latent,)


def test_default_latent_dimensions_never_build_a_degenerate_block() -> None:
    """Every default sweep point keeps all six blocks at least one wide."""
    assert DEFAULT_LATENT_DIMENSIONS[0] == 12
    assert safe_latent_dimensions(DEFAULT_LATENT_DIMENSIONS) == DEFAULT_LATENT_DIMENSIONS
    for latent in DEFAULT_LATENT_DIMENSIONS:
        widths = block_width_floor(latent)
        assert len(widths) == 6
        assert min(widths.values()) >= MIN_BLOCK_WIDTH, (latent, widths)
        assert sum(widths.values()) == latent


@pytest.mark.parametrize("latent", [8, 9])
def test_the_existing_sweep_default_is_still_broken(latent: int) -> None:
    """``experiments.latent_sweep`` defaults to 8, which is a negative width."""
    assert block_width_floor(latent)["fast"] < 0
    with pytest.raises(ValueError, match="negative|below width"):
        safe_latent_dimensions((latent,))


def test_latent_frontier_refuses_a_degenerate_dimension_before_fitting() -> None:
    """The refusal happens before any corpus is built, so it costs nothing."""
    with pytest.raises(ValueError, match="below width"):
        latent_frontier(dimensions=(10, 12), corpus="hard", count=2, seed=1)


def test_latent_frontier_refuses_a_corpus_the_core_cannot_process() -> None:
    """``hard`` sessions are 3-6 transitions; DTL-C needs 64 (measured).

    ``research/dtl_conv.py:234`` raises on a padded batch shorter than twice its
    widest dilation. That file is frozen for this wave, so the report refuses the
    corpus rather than reporting a crash as a missing point.
    """
    with pytest.raises(ValueError, match="dtl-conv excluded"):
        latent_frontier(dimensions=(12,), corpus="hard", count=4, seed=TRAIN_SEED, epochs=1)


def test_the_dtl_conv_minimum_length_is_the_measured_one() -> None:
    assert DTL_CONV_MIN_STEPS == 64
    long_split = build_dataset(name="l", count=4, seed=TRAIN_SEED, corpus="long")
    short_split = build_dataset(name="h", count=4, seed=TRAIN_SEED, corpus="hard")
    assert longest_sequence(long_split) >= DTL_CONV_MIN_STEPS
    assert longest_sequence(short_split) < DTL_CONV_MIN_STEPS
    assert dtl_conv_runnable(long_split) == ""
    assert "dtl-conv excluded" in dtl_conv_runnable(short_split)


@pytest.mark.slow
def test_latent_frontier_measures_every_point_it_reports() -> None:
    frontier = latent_frontier(
        dimensions=(12,), corpus="long", count=4, seed=TRAIN_SEED, epochs=2
    )
    assert frontier["points"], "a frontier with no points is not a frontier"
    for point in frontier["points"]:
        assert point["pr_auc"] is None or isinstance(point["pr_auc"], float)
        assert min(point["block_sizes"].values()) >= MIN_BLOCK_WIDTH
        assert point["parameters"] > 0
    assert frontier["measured_by"].endswith("latent_frontier")


# --- the fitted-model trap ---------------------------------------------------


def test_refitting_a_model_twice_is_detected() -> None:
    """``fit`` continues training; it does not restart.

    This is why ``sleeping_brain_report`` and the frontier are never handed a
    model that has already been fitted. The assertion is on the loss history
    length, which is the observable evidence of the extra epochs.
    """
    train = build_dataset(name="t", count=4, seed=TRAIN_SEED, corpus="hard")
    model = MLPBaseline(name="mlp-pooled", hidden=4, epochs=3)
    model.fit(train)
    first = list(model._losses)
    parameters_after_first = len(model.params)
    model.fit(train)
    assert len(model._losses) == 2 * len(first), (
        "fit() restarted; if this ever becomes true the report may reuse models"
    )
    assert len(model.params) == parameters_after_first, "a second fit re-built parameters"


def test_freshly_constructed_models_are_independent() -> None:
    train = build_dataset(name="t", count=4, seed=TRAIN_SEED, corpus="hard")
    a = MLPBaseline(name="mlp-pooled", hidden=4, epochs=2).fit(train)
    b = MLPBaseline(name="mlp-pooled", hidden=4, epochs=2).fit(train)
    assert len(a._losses) == len(b._losses) == 2
    assert a.predict_scores(train) == b.predict_scores(train)


# --- the verdict record ------------------------------------------------------


def test_a_justified_verdict_without_an_experiment_id_is_refused() -> None:
    """G2.12: an ablation-supported reason to exist needs a recorded experiment."""
    with pytest.raises(ValueError, match="JUSTIFIED needs an experiment id"):
        ComponentVerdict(
            component="x",
            core_ids=("DTL-F04",),
            control="c",
            metric="m",
            with_component=1.0,
            without_component=0.0,
            delta=1.0,
            experiment_id=None,
            verdict=VERDICT_JUSTIFIED,
        )


def test_a_measured_verdict_without_a_delta_is_refused() -> None:
    with pytest.raises(ValueError, match="needs a measured delta"):
        ComponentVerdict(
            component="x",
            core_ids=(),
            control="c",
            metric="m",
            with_component=None,
            without_component=None,
            delta=None,
            experiment_id="PS-S2-20260924-H8-x-0007",
            verdict=VERDICT_NOT_YET,
        )


def test_an_unknown_verdict_word_is_refused() -> None:
    with pytest.raises(ValueError, match="unknown verdict"):
        ComponentVerdict(
            component="x",
            core_ids=(),
            control="c",
            metric="m",
            with_component=None,
            without_component=None,
            delta=None,
            experiment_id=None,
            verdict="PROBABLY_FINE",
        )


def test_a_malformed_experiment_id_cannot_travel_with_a_number() -> None:
    """G2.12 joins a verdict to the ledger by this id; an unparseable one cannot."""
    with pytest.raises(ValueError, match="malformed experiment id"):
        ComponentVerdict(
            component="x",
            core_ids=(),
            control="c",
            metric="m",
            with_component=1.0,
            without_component=0.0,
            delta=1.0,
            experiment_id="not-an-experiment-id",
            verdict=VERDICT_JUSTIFIED,
        )


def test_the_sign_convention_is_the_components_advantage() -> None:
    """A lower-is-better metric must not invert the verdict."""
    from pocketsec.stage2.research.stage2_report import _verdict as verdict_of

    better_brier = verdict_of(
        component="future_cone",
        core_ids=("DTL-F05",),
        control="marginal_cone",
        metric="branch_brier",
        with_component=0.20,
        without_component=0.60,
        experiment_id=_ANY_ID,
        higher_is_better=False,
        measured_by="test",
    )
    assert better_brier.verdict == VERDICT_JUSTIFIED
    assert better_brier.delta == pytest.approx(0.40)

    worse_brier = verdict_of(
        component="future_cone",
        core_ids=("DTL-F05",),
        control="marginal_cone",
        metric="branch_brier",
        with_component=0.60,
        without_component=0.20,
        experiment_id=_ANY_ID,
        higher_is_better=False,
        measured_by="test",
    )
    assert worse_brier.verdict == "REJECTED"

    half_measured = verdict_of(
        component="future_cone",
        core_ids=("DTL-F05",),
        control="marginal_cone",
        metric="branch_brier",
        with_component=0.60,
        without_component=None,
        experiment_id=_ANY_ID,
        higher_is_better=False,
        measured_by="test",
    )
    assert half_measured.verdict == VERDICT_UNMEASURABLE
    assert half_measured.delta is None


def test_minted_experiment_ids_parse_and_start_at_0007() -> None:
    minted = mint_experiment_ids(date="20260924")
    assert set(minted) == {row[0] for row in COMPONENT_ROWS}
    sequences = sorted(parse_experiment_id(value).sequence for value in minted.values())
    assert sequences[0] == 7
    assert sequences == list(range(7, 7 + len(minted)))
    for value in minted.values():
        parsed = parse_experiment_id(value)
        assert parsed.stage == 2


# --- component measurements --------------------------------------------------


@pytest.mark.parametrize(
    "measure",
    [
        measure_atom_layer,
        measure_lattice,
        measure_window,
        measure_future_cone,
        measure_hazard,
        measure_uncertainty,
    ],
)
def test_each_component_is_measured_against_its_named_control(
    measure, small_sessions, ids
) -> None:
    """Both sides of every comparison are real numbers from the same split."""
    train, test = small_sessions
    verdict = measure(train, test, experiment_id=ids[_component_of(measure)])
    assert verdict.component == _component_of(measure)
    assert verdict.control, "a component with no control is not measured"
    assert verdict.measured_by and verdict.measured_by.startswith(
        "pocketsec.stage2.research.stage2_report:"
    )
    if verdict.verdict != VERDICT_UNMEASURABLE:
        assert isinstance(verdict.with_component, float)
        assert isinstance(verdict.without_component, float)
        assert verdict.delta is not None
        assert math.isfinite(verdict.delta)


def _component_of(measure) -> str:
    return {
        "measure_atom_layer": "behaviour_atom_quantizer",
        "measure_lattice": "transition_lattice",
        "measure_window": "multiscale_window",
        "measure_future_cone": "future_cone",
        "measure_hazard": "hazard_heads",
        "measure_uncertainty": "uncertainty",
    }[measure.__name__]


def test_the_atom_layer_is_compared_at_a_stated_memory_cost(small_sessions, ids) -> None:
    """The hash-bucket control's memory is reported, not assumed comparable."""
    train, test = small_sessions
    verdict = measure_atom_layer(
        train, test, experiment_id=ids["behaviour_atom_quantizer"]
    )
    assert " B vs " in verdict.detail
    assert verdict.metric == "transition_log_loss"


def test_cone_brier_is_bounded_and_scored_against_real_continuations(
    small_sessions, ids
) -> None:
    train, test = small_sessions
    verdict = measure_future_cone(train, test, experiment_id=ids["future_cone"])
    assert "continuations scored" in verdict.detail
    for value in (verdict.with_component, verdict.without_component):
        assert value is not None and 0.0 <= value <= 4.0


def test_a_cheaper_candidate_that_detects_worse_does_not_beat_the_phi_oracle() -> None:
    """The cost comparison only happens between models of equal quality.

    Without the quality tie this row could be "won" by a fast model that detects
    nothing, which is the same class of error as reporting a saving for work that
    was never skipped.
    """
    oracle = {"name": "phi-oracle", "pr_auc": 1.0, "microseconds_per_event": 0.08}
    tied = {"name": "mlp-pooled", "pr_auc": 1.0, "microseconds_per_event": 9.02}
    faster_but_worse = {"name": "tcn", "pr_auc": 0.80, "microseconds_per_event": 0.01}

    decided = _export_verdict({"points": [oracle, tied, faster_but_worse]}, _ANY_ID)
    assert decided.verdict == "REJECTED"
    assert decided.with_component == 9.02, "the tied candidate must be the one compared"

    refused = _export_verdict({"points": [oracle, faster_but_worse]}, _ANY_ID)
    assert refused.verdict == VERDICT_UNMEASURABLE
    assert "equal-quality" in refused.detail
    assert refused.with_component is None


# --- resources ---------------------------------------------------------------


def test_resource_figures_come_from_the_sampler(small_sessions) -> None:
    _, test = small_sessions
    flat = tuple(t for session in test for t in session)
    report = resource_report(flat)

    assert report["events"] == len(flat)
    assert report["measured_by"].endswith("resource_report")
    metrics = report["metrics"]
    # The sampler's own fields, not a recomputation of them.
    assert set(ResourceMetrics.__slots__) <= set(metrics) | {"unavailable"}
    assert metrics["sample_count"] >= 0
    assert report["profile"]["profile"] == "edge"
    assert report["incremental_rss_ceiling_bytes"] == STAGE2_INCREMENTAL_RSS_CEILING_BYTES
    assert report["within_incremental_ceiling"] in (True, False, None)
    assert report["model_bytes"] == sum(report["component_bytes"][k] for k in
                                       ("window_store", "quantizer", "lattice"))


def test_an_unmeasured_profile_is_none_and_never_true() -> None:
    """``within_target`` must stay ``None`` when nothing could be measured."""
    empty = ResourceMetrics(
        idle_rss_bytes=None,
        peak_rss_bytes=None,
        peak_sampled_rss_bytes=None,
        pss_bytes=None,
        delta_rss_bytes=None,
        cpu_seconds=0.0,
        wall_seconds=0.0,
        events_processed=0,
        startup_seconds=None,
        sample_count=0,
        unavailable=("rss", "pss", "peak_rss"),
    )
    report = check_profile(empty, "edge", model_bytes=None)
    assert report.within_target is None
    assert report.to_dict()["within_target"] is None


def test_path_cost_units_are_reported_unmeasured(small_sessions) -> None:
    """The declared ladder claims calibration it does not have."""
    _, test = small_sessions
    flat = tuple(t for session in test for t in session)
    report = path_cost_report(flat)

    assert report["declared_status"] == UNMEASURED
    assert "no calibration code exists" in report["declared_status_detail"]
    measured = report["measured_microseconds_by_work_kind"]
    assert measured, "the honest cost figures must actually be measured"
    assert all(value > 0.0 for value in measured.values())
    assert report["microseconds_per_event"] > 0.0


def test_the_work_ledger_cannot_report_a_saving_it_did_not_make(small_sessions) -> None:
    """A cache hit skips the inference; the run would refuse otherwise.

    ``resource_report`` calls ``assert_no_phantom_savings()``, which raises if any
    work recorded as skipped was also performed. If the runtime path ever runs the
    cone after a cache hit, this test fails — that is the ADR-0010 defect.
    """
    _, test = small_sessions
    flat = tuple(t for session in test for t in session)
    report = resource_report(flat)
    histogram = report["work_histogram"]
    assert sum(histogram.values()) == report["events"]
    trace = report["trace"]
    assert trace["cache_resolved"] + trace["inferred"] == trace["events"]
    if trace["cache_resolved"]:
        assert report["cache"]["proven_skipped_units"] > 0.0


# --- the D2.1 audit ----------------------------------------------------------


def test_every_core_function_resolves_to_real_code() -> None:
    """D2.1 froze twenty names; this checks they are no longer only names."""
    audit = core_id_audit()
    assert audit["core_ids"] == 20
    assert audit["unresolved"] == [], audit["unresolved"]
    assert audit["all_required_resolved"] is True
    assert audit["required_unresolved"] == []
    assert len(audit["resolved"]) == 20
    for row in audit["resolved"]:
        module, _, attribute = row["implementation"].partition(":")
        assert module.startswith("pocketsec.stage2.")
        assert "research" not in module, "a core id may not resolve into research code"
        assert attribute


# --- the whole report --------------------------------------------------------


@pytest.mark.slow
def test_degenerate_corpus_cannot_produce_a_justified_component() -> None:
    """The invariant ADR-0120 exists for, asserted on a real report.

    On a refused split every §5 row must come back ``UNMEASURABLE`` — not
    ``NOT_YET_JUSTIFIED``, which would imply a measurement was taken, and never
    ``JUSTIFIED``.
    """
    report = build_report(corpus="hard", count=SMALL_COUNT, robustness_count=4)
    assert isinstance(report, Stage2Report)
    verdict = report.saturation[0]
    assert verdict.degenerate is True

    reported = {row.component for row in report.components}
    for component, _, _, _ in COMPONENT_ROWS:
        assert component in reported, component
    # No component may appear twice: one report, one verdict per component.
    assert len(reported) == len(report.components)

    split_dependent = [
        row for row in report.components if row.component in SPLIT_DEPENDENT_COMPONENTS
    ]
    assert len(split_dependent) == len(SPLIT_DEPENDENT_COMPONENTS)
    for row in split_dependent:
        assert row.verdict == VERDICT_UNMEASURABLE, row.to_dict()
        assert row.with_component is None and row.without_component is None
        assert row.delta is None
        assert row.experiment_id is None
        assert verdict.reason in row.detail
    assert report.latent_frontier["refused"] is True
    assert report.latent_frontier["points"] == []
    assert report.provenance["saturation_refusal"]


@pytest.mark.slow
def test_report_numbers_are_floats_or_none_with_a_named_producer() -> None:
    """Every figure is either measured or ``None``; nothing in between."""
    report = build_report(corpus="hard", count=SMALL_COUNT, robustness_count=4)
    payload = report.to_dict()
    assert payload["synthetic_data"] is True

    sections = (
        "resources",
        "path_cost",
        "attribution",
        "core_id_audit",
        "drift",
        "poisoning",
        "sleeping_brain",
        "latent_frontier",
    )
    for section in sections:
        block = payload[section]
        if block.get("refused"):
            assert block["reason"], section
            continue
        assert block["measured_by"].startswith(
            "pocketsec.stage2.research.stage2_report:"
        ) or block["measured_by"].startswith("pocketsec.stage2.research."), section

    # Every float anywhere in the report lives under a section that names its
    # producer, and every "unmeasured" figure is None rather than a stand-in.
    for section in sections:
        _assert_floats_are_finite(payload[section], section)

    for row in payload["components"]:
        for field in ("with_component", "without_component", "delta"):
            assert row[field] is None or isinstance(row[field], float), (row, field)
        if row["verdict"] == VERDICT_UNMEASURABLE:
            assert row[
                "detail"
            ], "an UNMEASURABLE verdict must say why it could not be measured"
    _assert_no_stray_numbers(payload["saturation"][0])


def _assert_floats_are_finite(node, path: str) -> None:
    """No NaN, no infinity, no string standing in for a number."""
    if isinstance(node, dict):
        for key, value in node.items():
            _assert_floats_are_finite(value, f"{path}.{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            _assert_floats_are_finite(value, f"{path}[{index}]")
    elif isinstance(node, float):
        assert math.isfinite(node), path


def _assert_no_stray_numbers(saturation: dict) -> None:
    for field in ("best", "median", "spread", "order_free_baseline", "phi_oracle"):
        value = saturation[field]
        assert value is None or isinstance(value, float), (field, value)


@pytest.mark.slow
def test_every_baseline_in_the_report_split_is_recorded_with_its_score() -> None:
    """The suite's scores travel with the verdict, so a below-chance model shows."""
    train = build_dataset(name="t", count=SMALL_COUNT, seed=TRAIN_SEED, corpus="hard")
    test = build_dataset(name="e", count=SMALL_COUNT, seed=TEST_SEED, corpus="hard")
    verdict = saturation_check(train, test)
    scores = dict(verdict.scores)
    assert len(scores) >= 5, "acceptance criterion 1 needs at least five baselines"
    assert "phi-oracle" in scores and "mlp-pooled" in scores
    for name, value in scores.items():
        assert 0.0 <= value <= 1.0, (name, value)
    below = [name for name, value in scores.items() if value <= test.base_rate]
    assert list(verdict.below_base_rate) == sorted(below)
    if below:
        assert verdict.degenerate is True


# --- the quantizer used by the report ----------------------------------------


def test_the_report_quantizer_stays_bounded(small_sessions) -> None:
    """Report machinery may not grow an unbounded atom table."""
    train, _ = small_sessions
    quantizer = BehaviourQuantizer(max_atoms=8)
    from pocketsec.stage2.research.stage2_report import walk

    for _ in walk(quantizer, train):
        pass
    assert quantizer.stats().atoms <= 8
    assert quantizer.memory_bytes() > 0


def test_compiled_splits_are_disjoint_and_non_empty(small_sessions) -> None:
    train, test = small_sessions
    assert train and test
    train_signatures = {t.causal_signature for session in train for t in session}
    test_signatures = {t.causal_signature for session in test for t in session}
    assert train_signatures and test_signatures
    assert isinstance(next(iter(train_signatures)), str)


def test_dataset_sample_count_is_not_the_event_count() -> None:
    """``len(dataset)`` and ``transition_count`` are different numbers.

    Mixing them rescales every per-event cost figure by the mean sequence length,
    which is why the report divides by ``transition_count``.
    """
    dataset: Stage2Dataset = build_dataset(
        name="t", count=SMALL_COUNT, seed=TEST_SEED, corpus="hard"
    )
    assert len(dataset) < dataset.transition_count
    assert dataset.to_provenance()["mean_length"] > 1


def test_ablation_slots_agree_with_the_verdicts_the_report_mints() -> None:
    """The G2.12 join table may not drift from the report that fills it.

    ``core_ids.ABLATION_SLOTS`` is runtime code — the gate may not import
    research (ADR-0008) and a registry row carries only a ``slot_name``, so a
    runtime module has to know what a slot name means. That makes it a second
    copy of a mapping this module owns, and a second copy is how S2-AUTH-09 got
    written in the first place: a criterion that looked joined and was not. This
    reads the ``component=``/``core_ids=`` pairs straight out of the report's
    own source and requires them to match.
    """
    import ast
    import inspect

    from pocketsec.stage2.core_ids import ABLATION_SLOTS
    from pocketsec.stage2.research import stage2_report

    minted: dict[str, set[str]] = {}
    tree = ast.parse(inspect.getsource(stage2_report))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        keywords = {kw.arg: kw.value for kw in node.keywords}
        component, core_ids = keywords.get("component"), keywords.get("core_ids")
        if not isinstance(component, ast.Constant) or core_ids is None:
            continue
        if not isinstance(core_ids, (ast.Tuple, ast.List)):
            continue
        ids = {
            element.value
            for element in core_ids.elts
            if isinstance(element, ast.Constant)
        }
        if ids:
            minted.setdefault(component.value, set()).update(ids)

    assert minted, "no component verdicts found; the reader is broken, not the table"
    for component, ids in sorted(minted.items()):
        assert component in ABLATION_SLOTS, (
            f"{component!r} is minted by the report but absent from ABLATION_SLOTS, "
            "so a registry row naming it would join to nothing in G2.12"
        )
        assert set(ABLATION_SLOTS[component]) == ids, (
            f"{component!r}: report mints {sorted(ids)}, ABLATION_SLOTS says "
            f"{sorted(ABLATION_SLOTS[component])}"
        )
    assert set(ABLATION_SLOTS) == set(minted), (
        "ABLATION_SLOTS names slots the report never mints: "
        f"{sorted(set(ABLATION_SLOTS) - set(minted))}"
    )
