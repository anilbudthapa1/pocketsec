"""D1.11 — the Information Guillotine, its probe, and freeze stability.

These tests exist because the first guillotine implementation produced a
confident and wrong answer. They pin down the three methodology defects that
made it wrong, so none of them can return quietly.
"""

from __future__ import annotations

import pytest

from pocketsec.stage1.guillotine.ablation import ABLATIONS, run_guillotine
from pocketsec.stage1.guillotine.features import (
    FEATURE_FAMILIES,
    LogisticProbe,
    extract_features,
    feature_names,
)
from pocketsec.stage1.guillotine.stability import measure_stability
from pocketsec.stage1.labs.corpus import Behaviour, Scenario
from pocketsec.stage1.labs.hard_corpus import DISCRIMINATOR_PAIRS, build_hard_corpus
from pocketsec.stage1.pipeline import Stage1Pipeline
from pocketsec.stage1.ssir.codec import LAYOUTS

CORPUS = 140


def _compile(count: int, seed: int) -> list:  # type: ignore[type-arg]
    pipeline = Stage1Pipeline()
    return [
        pipeline.run_scenario(scenario, offset=index)
        for index, scenario in enumerate(
            build_hard_corpus(count=count, seed=seed, split="eval")
        )
    ]


@pytest.fixture(scope="module")
def splits() -> tuple[list, list]:  # type: ignore[type-arg]
    return _compile(CORPUS, 3), _compile(CORPUS, 11)


# --- the probe ---------------------------------------------------------------


def test_probe_refuses_a_single_class_fit() -> None:
    """Defect 2: a benign-only fit split produced a worse-than-random frontier.

    The probe learned nothing, ranked the eval split in an arbitrary direction,
    and the frontier read as "the representation is useless".
    """
    with pytest.raises(ValueError, match="both classes"):
        LogisticProbe().fit([[1.0], [2.0]], [0, 0])


def test_probe_separates_a_linearly_separable_problem() -> None:
    rows = [[float(i)] for i in range(20)]
    labels = [0] * 10 + [1] * 10
    scores = LogisticProbe().fit(rows, labels).predict(rows)
    assert scores[0] < scores[-1]


def test_probe_is_deterministic() -> None:
    rows = [[float(i), float(i % 3)] for i in range(30)]
    labels = [i % 2 for i in range(30)]
    first = LogisticProbe().fit(rows, labels).predict(rows)
    second = LogisticProbe().fit(rows, labels).predict(rows)
    assert first == second


def test_probe_standardises_so_scale_does_not_decide() -> None:
    """A Φ sum and a bucket index live on different scales.

    Without standardisation the larger-magnitude feature dominates regardless
    of information content.
    """
    rows = [[float(i), float(i) * 10_000.0] for i in range(20)]
    labels = [0] * 10 + [1] * 10
    scores = LogisticProbe().fit(rows, labels).predict(rows)
    assert scores[0] < scores[-1]


# --- features ----------------------------------------------------------------


def test_every_feature_maps_to_a_real_ssir_field() -> None:
    assert set(FEATURE_FAMILIES.values()) <= set(LAYOUTS)


def test_removing_a_family_removes_its_features() -> None:
    everything = feature_names(frozenset(LAYOUTS))
    without_novelty = feature_names(frozenset(LAYOUTS) - {"novelty_host"})
    assert len(without_novelty) < len(everything)
    assert "novelty_peak" not in without_novelty


def test_features_of_an_empty_scenario_are_zero() -> None:
    result = Stage1Pipeline().run_scenario(
        Scenario("none", (Behaviour("quantum_entangle", {}),), 0)
    )
    assert result.transitions == ()
    names = feature_names(frozenset(LAYOUTS))
    assert extract_features(result, names) == [0.0] * len(names)


# --- the corpus --------------------------------------------------------------


def test_hard_corpus_has_overlapping_distributions() -> None:
    """The original corpus was degenerate because the classes barely overlapped."""
    results = _compile(CORPUS, 11)
    benign = [r.peak_phi for r in results if r.scenario.label == 0]
    attack = [r.peak_phi for r in results if r.scenario.label == 1]
    assert max(benign) > min(attack), "classes must overlap in security potential"


def test_hard_corpus_contains_both_classes() -> None:
    results = _compile(CORPUS, 11)
    labels = {r.scenario.label for r in results}
    assert labels == {0, 1}


def test_timing_pair_actually_differs_in_timing() -> None:
    """Defect 3 + a corpus bug: the pair was identical inputs with opposite labels.

    And `emit` hard-coded a 1 ms gap, pinning time_bucket to one value
    corpus-wide, so timing measured as useless for reasons of our own making.
    """
    from pocketsec.stage1.labs.hard_corpus import _timing_pair

    spread, burst = _timing_pair(0)
    assert spread != burst
    pipeline = Stage1Pipeline()
    slow = pipeline.run_scenario(Scenario("slow", spread, 0), offset=0)
    fast = pipeline.run_scenario(Scenario("fast", burst, 1), offset=1)
    slow_buckets = [t.temporal.since_actor_bucket for t in slow.transitions]
    fast_buckets = [t.temporal.since_actor_bucket for t in fast.transitions]
    assert max(slow_buckets) > max(fast_buckets)


def test_novelty_pair_is_not_confounded_with_capability() -> None:
    """An earlier draft gave the malicious side an extra external connect.

    That made the pair separable by capability_delta, so it isolated nothing.
    """
    from pocketsec.stage1.labs.hard_corpus import _novelty_pair

    familiar, sweeping = _novelty_pair(0)
    assert {b.operation for b in familiar} == {b.operation for b in sweeping}


def test_discriminator_pairs_differ() -> None:
    for family, benign, malicious in DISCRIMINATOR_PAIRS:
        assert benign != malicious, f"{family} pair does not differ"


# --- the frontier ------------------------------------------------------------


def test_frontier_is_held_out_and_not_degenerate(splits) -> None:  # type: ignore[no-untyped-def]
    fit, score = splits
    report = run_guillotine(score, train=fit)
    assert report.held_out
    assert not report.degenerate
    assert report.informative_cuts >= 2


def test_frontier_flags_an_optimistic_fit(splits) -> None:  # type: ignore[no-untyped-def]
    """Fitting and scoring on the same split must be reported, not hidden."""
    _, score = splits
    report = run_guillotine(score)
    assert not report.held_out
    assert "OPTIMISTIC" in report.caveat


def test_baseline_beats_the_base_rate(splits) -> None:  # type: ignore[no-untyped-def]
    """A frontier whose baseline is below chance is a broken probe, not a result."""
    fit, score = splits
    report = run_guillotine(score, train=fit)
    base_rate = sum(1 for r in score if r.scenario.label == 1) / len(score)
    assert report.baseline.pr_auc is not None
    assert report.baseline.pr_auc > base_rate


def test_cumulative_ablation_sheds_bytes(splits) -> None:  # type: ignore[no-untyped-def]
    fit, score = splits
    report = run_guillotine(score, train=fit)
    costs = [p.bytes_per_transition for p in report.points]
    assert costs == sorted(costs, reverse=True)


def test_leave_one_out_covers_every_family(splits) -> None:  # type: ignore[no-untyped-def]
    fit, score = splits
    report = run_guillotine(score, train=fit)
    assert set(report.leave_one_out) == {family.name for family in ABLATIONS}


def test_removing_everything_collapses_to_near_chance(splits) -> None:  # type: ignore[no-untyped-def]
    fit, score = splits
    report = run_guillotine(score, train=fit)
    final = report.points[-1]
    assert final.pr_auc is not None
    assert final.pr_auc < (report.baseline.pr_auc or 1.0) - 0.3


# --- freeze stability --------------------------------------------------------


def test_stability_requires_unanimity_for_a_freeze_candidate() -> None:
    report = measure_stability(draws=3, corpus_size=120)
    for name in report.freeze_candidates:
        assert report.redundancy_rate[name] == 1.0


def test_unstable_families_are_not_freeze_candidates() -> None:
    """The headline finding: a single draw would have dropped a live field."""
    report = measure_stability(draws=3, corpus_size=120)
    assert not (report.unstable & report.freeze_candidates)


def test_exact_identity_is_measurably_redundant() -> None:
    """ADR-0007: behaviour alone suffices; identity handles are not needed."""
    report = measure_stability(draws=3, corpus_size=120)
    assert report.redundancy_rate["exact_identity"] == 1.0
    assert report.loo_spread["exact_identity"][2] == 0.0


def test_stability_reports_a_spread_not_a_point_estimate() -> None:
    report = measure_stability(draws=3, corpus_size=120)
    low, mean, high = report.baseline_pr_auc
    assert low <= mean <= high
    for spread in report.loo_spread.values():
        assert spread[0] <= spread[1] <= spread[2]
