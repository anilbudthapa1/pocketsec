"""D9.8 (ONTO-F08, first half) — Causal Geometry: mechanism distance and geodesic deviation.

Architecture §18 defines a *security* distance between two mechanisms: the cheapest sequence
of causal edits (add or remove an enabling event, change the causal order, alter a privilege
transition) that turns one into the other — deliberately unrelated to lexical similarity.
§19 then scores a trajectory by its deviation from the benign manifold,
``D(τ, M_N) = min_m d_c(τ, m)``, and says it must be benchmarked against nearest-neighbour
embeddings and Isolation Forest.

Here a lineage's *mechanism* is its sequence of ``(relation_family, state_delta_mask)`` pairs,
and :func:`mechanism_distance` is a bounded Damerau-style edit distance over it: inserting or
deleting an event, substituting a family, flipping state-delta bits, or transposing two
adjacent events ("change causal ordering"). Both inputs are truncated to
:data:`MAX_MECHANISM_LENGTH`, so one distance costs at most a 65 x 65 table, whatever the
session. The benign manifold is at most :data:`MAX_PROTOTYPES` sequences, chosen by greedy
farthest-point cover so it spans the benign variety instead of repeating its commonest
routine.

What this module refuses to do. It does not build Isolation Forest: that is a second ML
library, and Stage 9 is stdlib-only (ADR-0080); the comparison records it as NOT BUILT and
UNMEASURED rather than omitting it. It does not read identity: ``actor_slot`` only groups
events into lineages. :data:`CAUSAL_GEOMETRY_DEFAULT_ENABLED` ships ``False``.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass

from pocketsec.stage2.dataset import Stage2Dataset, Stage2Sample
from pocketsec.stage2.encoder.ssir_encoder import FEATURE_WIDTH
from pocketsec.stage9.renormalization.laboratory import (
    ScoredDetector,
    compare_detectors,
    phi_oracle_scores,
    unmeasured_comparison,
)
from pocketsec.stage9.spec.mssc import DetectorComparison

__all__ = [
    "CAUSAL_GEOMETRY_DEFAULT_ENABLED",
    "DEFAULT_COSTS",
    "ISOLATION_FOREST_STATUS",
    "KNN_K",
    "MAX_MECHANISM_LENGTH",
    "MAX_PROTOTYPES",
    "Mechanism",
    "TransformationCosts",
    "build_benign_manifold",
    "compare_causal_geometry",
    "geodesic_deviation",
    "mean_pooled",
    "mechanism_distance",
    "mechanism_sequence",
    "pooled_knn_score",
]

#: Off until a measured JUSTIFIED verdict is cited in the findings and its ADR (spec §4.22).
CAUSAL_GEOMETRY_DEFAULT_ENABLED: bool = False
#: A mechanism longer than this is truncated, so every distance is an O(64 x 64) table.
MAX_MECHANISM_LENGTH = 64
#: The benign manifold holds at most this many prototype mechanisms (spec §4.12). Chosen.
MAX_PROTOTYPES = 32
#: Neighbours for the pooled-feature kNN control. Chosen (spec §4.12 default).
KNN_K = 5
#: Recorded, never silently dropped: the third §19 baseline is not built here.
ISOLATION_FOREST_STATUS = (
    "Isolation Forest: NOT BUILT (a second ML library; Stage 9 is stdlib-only, ADR-0080) "
    "-> UNMEASURED"
)

#: One event of a mechanism: ``(relation_family, state_delta_mask)``.
Mechanism = tuple[tuple[int, int], ...]


@dataclass(frozen=True, slots=True)
class TransformationCosts:
    """The price of each causal edit. Chosen, not fitted (spec §4.12)."""

    insert: float = 1.0
    delete: float = 1.0
    substitute_family: float = 1.0
    substitute_mask_bit: float = 0.5
    transpose: float = 0.5

    def __post_init__(self) -> None:
        for name in ("insert", "delete", "substitute_family", "substitute_mask_bit", "transpose"):
            value = getattr(self, name)
            if not isinstance(value, int | float) or not math.isfinite(value) or value < 0:
                raise ValueError(f"TransformationCosts.{name} must be finite and >= 0")


#: The spec's default prices, as one module-level instance (never a call in a default).
DEFAULT_COSTS = TransformationCosts()


def mechanism_sequence(sample: Stage2Sample, actor_slot: int) -> Mechanism:
    """The lineage's ``(relation_family, state_delta_mask)`` events, first 64 kept."""
    events = [
        (step.relation_family, step.state_delta_mask)
        for step in sample.steps
        if step.actor_slot == actor_slot
    ]
    return tuple(events[:MAX_MECHANISM_LENGTH])


def _substitution(a: tuple[int, int], b: tuple[int, int], costs: TransformationCosts) -> float:
    family = costs.substitute_family if a[0] != b[0] else 0.0
    return family + costs.substitute_mask_bit * (a[1] ^ b[1]).bit_count()


def mechanism_distance(
    a: Sequence[tuple[int, int]],
    b: Sequence[tuple[int, int]],
    costs: TransformationCosts = DEFAULT_COSTS,
) -> float:
    """Optimal-string-alignment edit distance over causal edits; bounded by construction.

    Both sides are truncated to :data:`MAX_MECHANISM_LENGTH` first, so the table is at most
    65 x 65 whatever the caller passes. The result is 0 iff the (truncated) sequences are
    equal under zero-cost edits, symmetric when ``insert == delete``, and never exceeds
    ``delete * len(a) + insert * len(b)``.
    """
    left = tuple(a[:MAX_MECHANISM_LENGTH])
    right = tuple(b[:MAX_MECHANISM_LENGTH])
    rows, cols = len(left) + 1, len(right) + 1
    table = [[0.0] * cols for _ in range(rows)]
    for i in range(1, rows):
        table[i][0] = table[i - 1][0] + costs.delete
    for j in range(1, cols):
        table[0][j] = table[0][j - 1] + costs.insert
    for i in range(1, rows):
        for j in range(1, cols):
            best = min(
                table[i - 1][j] + costs.delete,
                table[i][j - 1] + costs.insert,
                table[i - 1][j - 1] + _substitution(left[i - 1], right[j - 1], costs),
            )
            if i > 1 and j > 1 and left[i - 1] == right[j - 2] and left[i - 2] == right[j - 1]:
                best = min(best, table[i - 2][j - 2] + costs.transpose)
            table[i][j] = best
    return table[-1][-1]


def _lineage_mechanisms(sample: Stage2Sample) -> tuple[Mechanism, ...]:
    slots = dict.fromkeys(step.actor_slot for step in sample.steps)
    return tuple(mechanism_sequence(sample, slot) for slot in slots)


def build_benign_manifold(train: Stage2Dataset) -> tuple[Mechanism, ...]:
    """At most :data:`MAX_PROTOTYPES` benign lineage mechanisms, by greedy farthest-point cover.

    Starts from the first distinct benign mechanism and repeatedly adds the one farthest from
    the manifold so far (ties: first seen). Deterministic; no randomness.
    """
    distinct = list(
        dict.fromkeys(
            mechanism
            for sample in train.samples
            if sample.label == 0
            for mechanism in _lineage_mechanisms(sample)
            if mechanism
        )
    )
    if not distinct:
        return ()
    manifold = [distinct[0]]
    nearest = [mechanism_distance(m, distinct[0]) for m in distinct]
    while len(manifold) < min(MAX_PROTOTYPES, len(distinct)):
        far = max(range(len(distinct)), key=lambda index: (nearest[index], -index))
        if nearest[far] <= 0.0:
            break
        manifold.append(distinct[far])
        nearest = [
            min(d, mechanism_distance(m, distinct[far]))
            for d, m in zip(nearest, distinct, strict=True)
        ]
    return tuple(manifold)


def geodesic_deviation(sample: Stage2Sample, manifold: Sequence[Mechanism]) -> float:
    """``max`` over the session's lineages of the distance to the nearest benign prototype.

    With an empty manifold there is nothing to deviate from, so the deviation is 0.0; the
    comparison refuses to run on an empty manifold rather than rank on that.
    """
    if not manifold:
        return 0.0
    return max(
        (min(mechanism_distance(m, p) for p in manifold) for m in _lineage_mechanisms(sample)),
        default=0.0,
    )


def mean_pooled(sample: Stage2Sample) -> tuple[float, ...]:
    """The session's 96-d feature vector averaged over its events (the kNN control's input)."""
    if not sample.steps:
        return tuple(0.0 for _ in range(FEATURE_WIDTH))
    count = len(sample.steps)
    return tuple(sum(column) / count for column in zip(*sample.features, strict=True))


def pooled_knn_score(
    sample: Stage2Sample | Sequence[float],
    train_benign_pooled: Sequence[Sequence[float]],
    k: int = KNN_K,
) -> float:
    """Mean Euclidean distance to the ``k`` nearest train-benign pooled vectors (control)."""
    if k < 1:
        raise ValueError(f"k must be >= 1, got {k}")
    vector = mean_pooled(sample) if isinstance(sample, Stage2Sample) else tuple(sample)
    distances = sorted(math.dist(vector, other) for other in train_benign_pooled)
    nearest = distances[:k]
    return sum(nearest) / len(nearest) if nearest else 0.0


def _train_knn_scores(
    pooled: Sequence[tuple[float, ...]], benign: Sequence[int]
) -> tuple[float, ...]:
    """Train scores with leave-one-out, so a benign session is not its own neighbour."""
    scores = []
    for index, vector in enumerate(pooled):
        others = [pooled[j] for j in benign if j != index]
        scores.append(pooled_knn_score(vector, others))
    return tuple(scores)


def compare_causal_geometry(train: Stage2Dataset, heldout: Stage2Dataset) -> DetectorComparison:
    """Geodesic deviation vs pooled-feature kNN and the Φ-oracle, on held-out AP.

    JUSTIFIED iff ``AP >= max(controls) + 0.02``. Isolation Forest is recorded NOT BUILT.
    An empty benign manifold (no train benign lineage) is UNMEASURED; nothing raises.
    """
    mechanism = f"{__name__}:CAUSAL_GEOMETRY_DEFAULT_ENABLED"
    metric = "heldout_ap(geodesic_deviation)"
    names = ("pooled-knn", "phi-oracle")
    manifold = build_benign_manifold(train)
    if not manifold:
        return unmeasured_comparison(
            mechanism, metric, names, f"no train benign lineage to build a manifold. "
            f"{ISOLATION_FOREST_STATUS}"
        )
    train_pooled = tuple(mean_pooled(sample) for sample in train.samples)
    benign = [index for index, label in enumerate(train.labels) if label == 0]
    benign_pooled = [train_pooled[index] for index in benign]
    candidate = ScoredDetector(
        "geodesic-deviation",
        tuple(geodesic_deviation(sample, manifold) for sample in heldout.samples),
        tuple(geodesic_deviation(sample, manifold) for sample in train.samples),
    )
    controls = (
        ScoredDetector(
            names[0], tuple(pooled_knn_score(s, benign_pooled) for s in heldout.samples),
            _train_knn_scores(train_pooled, benign),
        ),
        ScoredDetector(names[1], phi_oracle_scores(heldout), phi_oracle_scores(train)),
    )
    return compare_detectors(
        mechanism, metric, candidate, controls, heldout_labels=heldout.labels,
        train_labels=train.labels,
        detail=f"manifold of {len(manifold)} prototype(s). {ISOLATION_FOREST_STATUS}.",
    )
