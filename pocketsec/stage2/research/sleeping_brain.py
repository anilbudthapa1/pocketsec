"""S2-E19 / D2.14 — the sleeping-brain benchmark (spec section 33).

> The defining experiment measures how often expensive inference can remain
> asleep. Plot security quality vs full-core wake rate vs CPU/event. The target
> is the safest Pareto point, not an arbitrary 99% sleep target.

This exists because detection PR-AUC stopped discriminating. Four corpora in,
every architecture either ties at 1.0000 or sits at the base rate, and Stage 2
falsification criterion 1 explicitly allows DTL to survive on **wake rate,
attribution or robustness** rather than detection.

When quality ties, cost is the only remaining axis — and it is the axis
PocketSec actually cares about. The whole project thesis is computation
proportional to security novelty rather than to event volume. A model that
matches the best baseline's detection at a fraction of its per-event cost has
earned its place; one that matches detection at higher cost has not, whatever
its architecture diagram looks like.

Measurements here are wall-clock and path-distribution figures taken on this
machine. They are comparative, not absolute: the same harness times every
model, so the ranking is meaningful even though the milliseconds are not
portable.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from pocketsec.stage0.benchmark.security_metrics import average_precision
from pocketsec.stage2.core_ids import PATH_COST_UNITS, ExecutionPath
from pocketsec.stage2.dataset import Stage2Dataset

__all__ = ["SleepingBrainPoint", "sleeping_brain_report"]

#: Repeats for the timing loop, so a single scheduling hiccup cannot decide a
#: ranking. The minimum is reported rather than the mean: it is the figure least
#: polluted by unrelated load.
TIMING_REPEATS = 5


@dataclass(frozen=True, slots=True)
class SleepingBrainPoint:
    """One model's position on the quality/cost frontier."""

    name: str
    pr_auc: float
    transitions: int
    #: Best-of-N wall clock for scoring the whole split.
    predict_seconds: float
    parameters: int
    #: Fraction of events resolved on each execution path, when the model
    #: exposes routing. Empty for models with no notion of paths.
    path_fractions: dict[str, float]
    compute_units_per_event: float | None

    @property
    def microseconds_per_event(self) -> float:
        return self.predict_seconds / max(self.transitions, 1) * 1e6

    @property
    def cheap_path_share(self) -> float | None:
        """Share of events resolved without full predictive inference (P0-P2).

        This is the number the novelty-energy principle lives or dies by.
        """
        if not self.path_fractions:
            return None
        return sum(
            self.path_fractions.get(path.value, 0.0)
            for path in (
                ExecutionPath.P0_COMPILED,
                ExecutionPath.P1_LATTICE,
                ExecutionPath.P2_LOCAL,
            )
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "pr_auc": round(self.pr_auc, 4),
            "microseconds_per_event": round(self.microseconds_per_event, 2),
            "predict_seconds": round(self.predict_seconds, 4),
            "parameters": self.parameters,
            "transitions": self.transitions,
            "path_fractions": self.path_fractions,
            "compute_units_per_event": self.compute_units_per_event,
            "cheap_path_share": (
                round(self.cheap_path_share, 4)
                if self.cheap_path_share is not None
                else None
            ),
        }


def _time_prediction(model: Any, dataset: Stage2Dataset) -> tuple[float, list[float]]:
    """Best-of-N timing, returning the fastest run and its scores."""
    best = float("inf")
    scores: list[float] = []
    for _ in range(TIMING_REPEATS):
        started = time.perf_counter()
        scores = model.predict_scores(dataset)
        best = min(best, time.perf_counter() - started)
    return best, scores


def sleeping_brain_report(
    models: list[Any], train: Stage2Dataset, test: Stage2Dataset
) -> dict[str, Any]:
    """Measure quality against per-event cost for every model.

    Each model is fitted on ``train`` and timed on ``test`` with the same
    harness, so the comparison is like-for-like.
    """
    labels = list(test.labels)
    points: list[SleepingBrainPoint] = []

    for model in models:
        model.fit(train)
        seconds, scores = _time_prediction(model, test)
        routing = model.route(test) if hasattr(model, "route") else {}
        points.append(
            SleepingBrainPoint(
                name=model.name,
                pr_auc=average_precision(labels, scores) or 0.0,
                transitions=test.transition_count,
                predict_seconds=seconds,
                parameters=model.resource_profile()["parameters"],
                path_fractions=routing.get("path_fractions", {}),
                compute_units_per_event=routing.get("compute_units_per_event"),
            )
        )

    return {
        "dataset": test.to_provenance(),
        "points": [point.to_dict() for point in points],
        "pareto": _pareto(points),
        "path_cost_model": {p.value: PATH_COST_UNITS[p] for p in ExecutionPath},
    }


def _pareto(points: list[SleepingBrainPoint]) -> dict[str, Any]:
    """The safest Pareto point, and who is dominated.

    A model is dominated when another matches its quality (within a small
    tolerance) at strictly lower per-event cost. That is the operational
    question: among everything that detects equally well, what is cheapest?
    """
    if not points:
        return {}
    tolerance = 0.01
    best_quality = max(point.pr_auc for point in points)
    tied = [point for point in points if point.pr_auc >= best_quality - tolerance]
    cheapest = min(tied, key=lambda point: point.microseconds_per_event)

    dominated: list[dict[str, Any]] = []
    for point in points:
        beaten_by = [
            other.name
            for other in points
            if other.pr_auc >= point.pr_auc - tolerance
            and other.microseconds_per_event < point.microseconds_per_event * 0.95
        ]
        if beaten_by:
            dominated.append({"name": point.name, "dominated_by": beaten_by})

    return {
        "best_quality": round(best_quality, 4),
        "tied_at_best_quality": [point.name for point in tied],
        "cheapest_at_best_quality": cheapest.name,
        "cheapest_microseconds_per_event": round(cheapest.microseconds_per_event, 2),
        "dominated": dominated,
        "verdict": (
            f"{cheapest.name} detects as well as anything measured "
            f"({best_quality:.4f}) at {cheapest.microseconds_per_event:.1f} us/event, "
            "the cheapest among the models tied at that quality."
        ),
    }
