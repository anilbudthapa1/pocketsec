"""Security-quality metrics (spec section 12), stdlib only.

Every metric here is computed from measured predictions. Nothing is estimated,
interpolated from a library default, or reported when the inputs cannot support
it — an unavailable metric is ``None``, never a plausible-looking number.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

__all__ = [
    "ConfusionMatrix",
    "SecurityMetrics",
    "average_precision",
    "evaluate_scores",
    "false_positives_per_host_day",
    "percentiles",
    "recall_at_max_fpr",
]


@dataclass(frozen=True, slots=True)
class ConfusionMatrix:
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int

    @property
    def precision(self) -> float | None:
        predicted_positive = self.true_positives + self.false_positives
        if predicted_positive == 0:
            return None
        return self.true_positives / predicted_positive

    @property
    def recall(self) -> float | None:
        actual_positive = self.true_positives + self.false_negatives
        if actual_positive == 0:
            return None
        return self.true_positives / actual_positive

    @property
    def false_positive_rate(self) -> float | None:
        actual_negative = self.false_positives + self.true_negatives
        if actual_negative == 0:
            return None
        return self.false_positives / actual_negative

    @property
    def f1(self) -> float | None:
        precision, recall = self.precision, self.recall
        if precision is None or recall is None or precision + recall == 0.0:
            return None
        return 2 * precision * recall / (precision + recall)

    def to_dict(self) -> dict[str, Any]:
        return {
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "true_negatives": self.true_negatives,
            "false_negatives": self.false_negatives,
            "precision": self.precision,
            "recall": self.recall,
            "false_positive_rate": self.false_positive_rate,
            "f1": self.f1,
        }


def confusion_at_threshold(
    labels: Sequence[int], scores: Sequence[float], threshold: float
) -> ConfusionMatrix:
    """Count outcomes when every score ``>= threshold`` is called positive."""
    _require_aligned(labels, scores)
    tp = fp = tn = fn = 0
    for label, score in zip(labels, scores, strict=True):
        predicted_positive = score >= threshold
        if label == 1 and predicted_positive:
            tp += 1
        elif label == 1:
            fn += 1
        elif predicted_positive:
            fp += 1
        else:
            tn += 1
    return ConfusionMatrix(tp, fp, tn, fn)


def average_precision(labels: Sequence[int], scores: Sequence[float]) -> float | None:
    """PR-AUC as average precision — the step-wise sum, not trapezoid.

    Trapezoidal interpolation of a PR curve is optimistic, which is exactly the
    wrong bias for a detector that must justify its cost.
    """
    _require_aligned(labels, scores)
    positives = sum(1 for label in labels if label == 1)
    if positives == 0:
        return None
    ranked = sorted(zip(scores, labels, strict=True), key=lambda pair: -pair[0])
    seen_tp = 0
    seen = 0
    previous_recall = 0.0
    total = 0.0
    for index, (score, label) in enumerate(ranked):
        seen += 1
        if label == 1:
            seen_tp += 1
        # Only emit a point at the end of a tied score block, so ties cannot be
        # ordered favourably.
        if index + 1 < len(ranked) and ranked[index + 1][0] == score:
            continue
        recall = seen_tp / positives
        precision = seen_tp / seen
        total += precision * (recall - previous_recall)
        previous_recall = recall
    return total


def recall_at_max_fpr(
    labels: Sequence[int], scores: Sequence[float], max_fpr: float
) -> tuple[float | None, float | None]:
    """Best recall achievable without exceeding ``max_fpr``.

    Returns ``(recall, threshold)``. This, not headline F1, is the number an
    endpoint deployment lives with: false positives are paid per host per day.
    """
    _require_aligned(labels, scores)
    if not 0.0 <= max_fpr <= 1.0:
        raise ValueError(f"max_fpr must be within [0, 1], got {max_fpr!r}")
    if not any(label == 1 for label in labels) or not any(label == 0 for label in labels):
        return None, None

    best_recall: float | None = None
    best_threshold: float | None = None
    # A threshold above every score means "detect nothing": zero recall at zero
    # FPR. Including it is what makes "no achievable recall within this budget"
    # report as 0.0 rather than None. None must mean "not computable"; a
    # detector that cannot fire once without busting the budget scores zero,
    # and that distinction decides whether a mechanism is worth its cost.
    candidates = sorted({*scores, max(scores) + 1.0}, reverse=True)
    for threshold in candidates:
        matrix = confusion_at_threshold(labels, scores, threshold)
        fpr = matrix.false_positive_rate
        recall = matrix.recall
        if fpr is None or recall is None or fpr > max_fpr:
            continue
        if best_recall is None or recall > best_recall:
            best_recall, best_threshold = recall, threshold
    return best_recall, best_threshold


def false_positives_per_host_day(
    false_positives: int, host_count: int, duration_seconds: float
) -> float | None:
    """Normalise false positives to the unit operators actually feel."""
    if host_count <= 0 or duration_seconds <= 0:
        return None
    host_days = host_count * (duration_seconds / 86_400.0)
    return false_positives / host_days


def percentiles(values: Sequence[float], points: Sequence[int] = (50, 95, 99)) -> dict[str, float]:
    """Nearest-rank percentiles. Empty input yields an empty result, not zeros."""
    if not values:
        return {}
    ordered = sorted(values)
    result: dict[str, float] = {}
    for point in points:
        rank = max(1, min(len(ordered), -(-point * len(ordered) // 100)))
        result[f"p{point}"] = ordered[rank - 1]
    return result


@dataclass(frozen=True, slots=True)
class SecurityMetrics:
    """The security half of every PocketSec result record."""

    sample_count: int
    positive_count: int
    threshold: float
    confusion: ConfusionMatrix
    pr_auc: float | None
    recall_at_fpr_budget: float | None
    fpr_budget: float
    threshold_at_fpr_budget: float | None
    false_positives_per_host_day: float | None
    detection_latency_ns: dict[str, float]
    abstention_rate: float
    unseen_technique_recall: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "sample_count": self.sample_count,
            "positive_count": self.positive_count,
            "threshold": self.threshold,
            "confusion": self.confusion.to_dict(),
            "pr_auc": self.pr_auc,
            "fpr_budget": self.fpr_budget,
            "recall_at_fpr_budget": self.recall_at_fpr_budget,
            "threshold_at_fpr_budget": self.threshold_at_fpr_budget,
            "false_positives_per_host_day": self.false_positives_per_host_day,
            "detection_latency_ns": self.detection_latency_ns,
            "abstention_rate": self.abstention_rate,
            "unseen_technique_recall": self.unseen_technique_recall,
        }


def evaluate_scores(
    labels: Sequence[int],
    scores: Sequence[float],
    *,
    threshold: float,
    fpr_budget: float,
    latencies_ns: Sequence[float],
    abstentions: int,
    host_count: int,
    duration_seconds: float,
) -> SecurityMetrics:
    """Compute the full security metric block from measured outputs."""
    _require_aligned(labels, scores)
    matrix = confusion_at_threshold(labels, scores, threshold)
    recall_budget, threshold_budget = recall_at_max_fpr(labels, scores, fpr_budget)
    return SecurityMetrics(
        sample_count=len(labels),
        positive_count=sum(1 for label in labels if label == 1),
        threshold=threshold,
        confusion=matrix,
        pr_auc=average_precision(labels, scores),
        recall_at_fpr_budget=recall_budget,
        fpr_budget=fpr_budget,
        threshold_at_fpr_budget=threshold_budget,
        false_positives_per_host_day=false_positives_per_host_day(
            matrix.false_positives, host_count, duration_seconds
        ),
        detection_latency_ns=percentiles(latencies_ns),
        abstention_rate=(abstentions / len(labels)) if labels else 0.0,
    )


def _require_aligned(labels: Sequence[int], scores: Sequence[float]) -> None:
    if len(labels) != len(scores):
        raise ValueError(f"labels ({len(labels)}) and scores ({len(scores)}) must align")
    for label in labels:
        if label not in (0, 1):
            raise ValueError(f"labels must be 0 or 1, got {label!r}")
