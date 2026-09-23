"""Hand-written metrics need real tests (ADR-0001 accepted that cost)."""

from __future__ import annotations

import pytest

from pocketsec.stage0.benchmark.harness import _detection_score
from pocketsec.stage0.benchmark.security_metrics import (
    average_precision,
    confusion_at_threshold,
    evaluate_scores,
    false_positives_per_host_day,
    percentiles,
    recall_at_max_fpr,
)
from pocketsec.stage0.contracts.threat_prediction_v1 import (
    ComputePath,
    ThreatPredictionV1,
    Verdict,
)

# --- confusion ---------------------------------------------------------------


def test_confusion_counts_at_threshold() -> None:
    matrix = confusion_at_threshold([1, 1, 0, 0], [0.9, 0.2, 0.8, 0.1], threshold=0.5)
    assert (matrix.true_positives, matrix.false_negatives) == (1, 1)
    assert (matrix.false_positives, matrix.true_negatives) == (1, 1)
    assert matrix.precision == 0.5
    assert matrix.recall == 0.5
    assert matrix.f1 == 0.5


def test_metrics_are_none_not_zero_when_undefined() -> None:
    """An undefined metric is reported as undefined, never as a plausible zero."""
    matrix = confusion_at_threshold([0, 0], [0.1, 0.2], threshold=0.5)
    assert matrix.recall is None  # no actual positives
    assert matrix.precision is None  # no predicted positives
    assert matrix.f1 is None


# --- average precision -------------------------------------------------------


def test_average_precision_is_one_for_perfect_separation() -> None:
    assert average_precision([1, 1, 0, 0], [0.9, 0.8, 0.2, 0.1]) == pytest.approx(1.0)


def test_average_precision_is_none_without_positives() -> None:
    assert average_precision([0, 0], [0.5, 0.4]) is None


def test_average_precision_does_not_order_ties_favourably() -> None:
    """All-tied scores carry no ranking information: AP must equal the base rate."""
    labels = [1, 0, 1, 0]
    assert average_precision(labels, [0.5] * 4) == pytest.approx(0.5)


def test_average_precision_penalises_inverted_ranking() -> None:
    good = average_precision([1, 1, 0, 0], [0.9, 0.8, 0.2, 0.1])
    bad = average_precision([1, 1, 0, 0], [0.1, 0.2, 0.8, 0.9])
    assert good is not None and bad is not None and bad < good


# --- recall at a false-positive budget ---------------------------------------


def test_recall_at_budget_respects_the_budget() -> None:
    labels = [1, 1, 0, 0, 0, 0]
    scores = [0.9, 0.8, 0.7, 0.1, 0.1, 0.1]
    recall, threshold = recall_at_max_fpr(labels, scores, max_fpr=0.25)
    assert recall == pytest.approx(1.0)
    assert threshold == pytest.approx(0.8)


def test_recall_at_budget_is_zero_not_none_when_unachievable() -> None:
    """ADR-0004: None means 'not computable', never 'scored zero'.

    Here the top-ranked item is a false positive, so no threshold can fire even
    once inside the budget. The honest answer is zero recall.
    """
    labels = [0, 1]
    scores = [0.9, 0.1]
    recall, _ = recall_at_max_fpr(labels, scores, max_fpr=0.0)
    assert recall == 0.0


def test_recall_at_budget_is_none_when_a_class_is_absent() -> None:
    assert recall_at_max_fpr([1, 1], [0.9, 0.8], max_fpr=0.1) == (None, None)


def test_recall_at_budget_rejects_an_out_of_range_budget() -> None:
    with pytest.raises(ValueError, match="max_fpr"):
        recall_at_max_fpr([1, 0], [0.9, 0.1], max_fpr=1.5)


# --- normalisation and percentiles -------------------------------------------


def test_false_positives_per_host_day() -> None:
    assert false_positives_per_host_day(10, host_count=2, duration_seconds=86_400) == 5.0


def test_false_positives_per_host_day_is_none_without_a_window() -> None:
    assert false_positives_per_host_day(10, host_count=0, duration_seconds=86_400) is None
    assert false_positives_per_host_day(10, host_count=1, duration_seconds=0) is None


def test_percentiles_are_nearest_rank() -> None:
    assert percentiles(list(range(1, 101)), (50, 95, 99)) == {"p50": 50, "p95": 95, "p99": 99}


def test_percentiles_of_nothing_is_empty_not_zero() -> None:
    assert percentiles([]) == {}


# --- score orientation (ADR-0004) --------------------------------------------


def _prediction(verdict: Verdict, confidence: float, **kwargs: object) -> ThreatPredictionV1:
    return ThreatPredictionV1(
        prediction_id="p1",
        sequence_id="seq-1",
        verdict=verdict,
        confidence=confidence,
        novelty_score=float(kwargs.get("novelty", 0.0)),
        uncertainty=0.0,
        abstained=bool(kwargs.get("abstained", False)),
        model_state_version="m.1.0.0",
        compute_path=ComputePath.CHEAP_TRANSITION,
    )


def test_benign_confidence_does_not_rank_as_detection() -> None:
    """The regression ADR-0004 documents: reading confidence raw inverts ranking."""
    confidently_benign = _prediction(Verdict.BENIGN, 0.99)
    confidently_malicious = _prediction(Verdict.MALICIOUS, 0.99)
    assert _detection_score(confidently_benign) < _detection_score(confidently_malicious)
    assert _detection_score(confidently_benign) == pytest.approx(0.01)


def test_high_novelty_abstention_scores_zero() -> None:
    """Novelty is not maliciousness: it must not manufacture unclaimed recall."""
    abstained = _prediction(
        Verdict.UNKNOWN, 0.0, novelty=1.0, abstained=True
    )
    assert _detection_score(abstained) == 0.0


# --- the assembled block -----------------------------------------------------


def test_evaluate_scores_assembles_a_complete_block() -> None:
    metrics = evaluate_scores(
        [1, 0, 1, 0],
        [0.9, 0.1, 0.8, 0.2],
        threshold=0.5,
        fpr_budget=0.5,
        latencies_ns=[100.0, 200.0, 300.0, 400.0],
        abstentions=1,
        host_count=1,
        duration_seconds=86_400,
    )
    assert metrics.sample_count == 4
    assert metrics.positive_count == 2
    assert metrics.pr_auc == pytest.approx(1.0)
    assert metrics.abstention_rate == 0.25
    assert metrics.detection_latency_ns["p50"] == 200.0
    assert metrics.false_positives_per_host_day == 0.0


def test_evaluate_scores_rejects_misaligned_inputs() -> None:
    with pytest.raises(ValueError, match="must align"):
        evaluate_scores(
            [1, 0],
            [0.5],
            threshold=0.5,
            fpr_budget=0.1,
            latencies_ns=[],
            abstentions=0,
            host_count=1,
            duration_seconds=1,
        )


def test_evaluate_scores_rejects_non_binary_labels() -> None:
    with pytest.raises(ValueError, match="labels must be 0 or 1"):
        evaluate_scores(
            [2, 0],
            [0.5, 0.1],
            threshold=0.5,
            fpr_budget=0.1,
            latencies_ns=[],
            abstentions=0,
            host_count=1,
            duration_seconds=1,
        )
