"""Feature extraction and a stdlib logistic probe for the Information Guillotine.

The first guillotine implementation scored scenarios with a fixed weighted sum
whose weights I chose by hand. That measures *my weights* as much as the
representation: on a corpus with real overlap, removing the novelty and timing
families **raised** PR-AUC, which says the hand-picked weights were wrong, not
that those fields carry no information.

So the probe is now **fitted**, not assumed. For each ablation the model is
refit on a training split using only the surviving field families, and scored on
a held-out eval split. That makes each frontier point the answer to the right
question: *how much separation is still achievable when this information is
gone?*

Stage 0 fair-comparison rule 6 applies — the probe never sees the eval split
during fitting. The probe is deliberately a plain linear model: Stage 1 must
measure what the representation carries, not how clever a model is. Confounding
representation loss with model capacity is exactly what Stage 2 is for.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass

from pocketsec.stage1.pipeline import ScenarioResult

__all__ = ["FEATURE_FAMILIES", "LogisticProbe", "extract_features", "feature_names"]

#: Feature name -> the SSIR field family that carries it. Removing a family
#: removes its features from the model entirely, so the fit is done on exactly
#: the information that survives the cut.
FEATURE_FAMILIES: dict[str, str] = {
    # capability delta: what security truth changed, and by how much
    "delta_total": "state_delta",
    "delta_max": "state_delta",
    "delta_dimensions": "state_delta",
    "phi_total": "invariant_delta",
    "phi_peak_step": "invariant_delta",
    # semantics
    "object_props_max": "object_sem",
    "object_props_total": "object_sem",
    "actor_props_max": "actor_sem",
    "actor_props_total": "actor_sem",
    # novelty tensor
    "novelty_peak": "novelty_host",
    "novelty_mean": "novelty_host",
    "novelty_actor_peak": "novelty_actor",
    # confidence
    "uncertainty_peak": "uncertainty",
    "uncertainty_mean": "uncertainty",
    # temporal
    "time_bucket_min": "time_bucket",
    "time_bucket_mean": "time_bucket",
    # causal structure
    "causal_depth": "causal_sig",
    "causal_concentration": "causal_sig",
    "responsibility_peak": "causal_sig",
    # controls, expected to be uninformative for detection
    "distinct_actors": "actor_id",
    "evidence_count": "evidence_id",
    "transition_count": "relation",
}


def feature_names(retained: frozenset[str]) -> tuple[str, ...]:
    """Feature names whose carrying field family survived the cut."""
    return tuple(
        name for name, family in FEATURE_FAMILIES.items() if family in retained
    )


def extract_features(result: ScenarioResult, names: Sequence[str]) -> list[float]:
    """Extract the named features from one compiled scenario."""
    transitions = result.transitions
    if not transitions:
        return [0.0] * len(names)

    deltas = [t.state_delta.magnitude for t in transitions]
    phis = [max(0.0, t.delta_phi) for t in transitions]
    novelty_peaks = [t.novelty.peak for t in transitions]
    uncertainties = [t.uncertainty for t in transitions]
    buckets = [t.temporal.since_actor_bucket for t in transitions]
    responsibilities = [t.responsibility for t in transitions]
    phi_total = sum(phis)

    values: dict[str, float] = {
        "delta_total": float(sum(deltas)),
        "delta_max": float(max(deltas)),
        "delta_dimensions": float(
            len({d for t in transitions for d in t.state_delta.dimensions})
        ),
        "phi_total": phi_total,
        "phi_peak_step": max(phis),
        "object_props_max": float(
            max(len(t.object.semantics.asserted) for t in transitions)
        ),
        "object_props_total": float(
            len({p for t in transitions for p in t.object.semantics.asserted})
        ),
        "actor_props_max": float(
            max(len(t.actor.semantics.asserted) for t in transitions)
        ),
        "actor_props_total": float(
            len({p for t in transitions for p in t.actor.semantics.asserted})
        ),
        "novelty_peak": max(novelty_peaks),
        "novelty_mean": sum(novelty_peaks) / len(novelty_peaks),
        "novelty_actor_peak": max(t.novelty["actor"] for t in transitions),
        "uncertainty_peak": max(uncertainties),
        "uncertainty_mean": sum(uncertainties) / len(uncertainties),
        "time_bucket_min": float(min(buckets)),
        "time_bucket_mean": sum(buckets) / len(buckets),
        "causal_depth": float(len({t.causal_signature for t in transitions})),
        # Concentration: was capability gained in one jump or accumulated?
        # This is what the causal signature carries that ΔS does not, because
        # the lattices are monotone and the final state is order-independent.
        "causal_concentration": (max(phis) / phi_total) if phi_total > 0 else 0.0,
        "responsibility_peak": max(responsibilities),
        "distinct_actors": float(len({t.actor.identity for t in transitions})),
        "evidence_count": float(sum(len(t.evidence) for t in transitions)),
        "transition_count": float(len(transitions)),
    }
    return [values[name] for name in names]


@dataclass
class LogisticProbe:
    """A plain L2-regularised logistic regression, fitted by gradient descent.

    Stdlib only (ADR-0001). Deterministic: zero initialisation and a fixed
    iteration count, so the same inputs always give the same frontier.
    """

    learning_rate: float = 0.1
    iterations: int = 400
    l2: float = 0.01

    def __post_init__(self) -> None:
        self._weights: list[float] = []
        self._bias = 0.0
        self._mean: list[float] = []
        self._scale: list[float] = []

    def fit(self, rows: list[list[float]], labels: list[int]) -> LogisticProbe:
        """Fit on a labelled split containing **both** classes.

        A single-class fit produces weights driven entirely by L2 and the
        majority class, which then rank the eval split in an arbitrary — often
        inverted — direction. That looks like "the representation is worse than
        random" when it is really "the probe was never taught anything", so it
        is refused loudly rather than silently producing a misleading frontier.
        """
        if not rows:
            return self
        present = set(labels)
        if len(present) < 2:
            raise ValueError(
                f"LogisticProbe.fit needs both classes, got only {sorted(present)}. "
                "An anomaly-detection split (benign-only) cannot train a supervised "
                "probe; use a labelled split disjoint from the scoring split."
            )
        width = len(rows[0])
        self._standardise_from(rows, width)
        scaled = [self._apply_scaling(row) for row in rows]

        self._weights = [0.0] * width
        self._bias = 0.0
        count = len(scaled)
        for _ in range(self.iterations):
            gradient = [0.0] * width
            bias_gradient = 0.0
            for row, label in zip(scaled, labels, strict=True):
                error = self._sigmoid(self._raw(row)) - label
                bias_gradient += error
                for index, value in enumerate(row):
                    gradient[index] += error * value
            for index in range(width):
                penalty = self.l2 * self._weights[index]
                self._weights[index] -= self.learning_rate * (
                    gradient[index] / count + penalty
                )
            self._bias -= self.learning_rate * bias_gradient / count
        return self

    def predict(self, rows: list[list[float]]) -> list[float]:
        if not self._weights:
            return [0.0] * len(rows)
        return [self._sigmoid(self._raw(self._apply_scaling(row))) for row in rows]

    # --- internals ------------------------------------------------------

    def _standardise_from(self, rows: list[list[float]], width: int) -> None:
        """Zero-mean, unit-scale per feature, learned on the training split only.

        Features live on wildly different scales (a bucket index vs. a Φ sum),
        and unscaled gradient descent would let the largest-magnitude feature
        dominate regardless of its information content.
        """
        self._mean = []
        self._scale = []
        for index in range(width):
            column = [row[index] for row in rows]
            mean = sum(column) / len(column)
            variance = sum((value - mean) ** 2 for value in column) / len(column)
            self._mean.append(mean)
            self._scale.append(math.sqrt(variance) or 1.0)

    def _apply_scaling(self, row: list[float]) -> list[float]:
        return [
            (value - mean) / scale
            for value, mean, scale in zip(row, self._mean, self._scale, strict=True)
        ]

    def _raw(self, row: list[float]) -> float:
        return self._bias + sum(
            weight * value for weight, value in zip(self._weights, row, strict=True)
        )

    @staticmethod
    def _sigmoid(value: float) -> float:
        if value >= 0:
            return 1.0 / (1.0 + math.exp(-min(value, 60.0)))
        exp_value = math.exp(max(value, -60.0))
        return exp_value / (1.0 + exp_value)
