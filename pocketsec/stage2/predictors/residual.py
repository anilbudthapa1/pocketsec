"""D2.5 / DTL-F09 — structured prediction residuals, including negative space.

Spec section 9 says surprise is a *geometry*, not a scalar: two events with equal
aggregate surprise can differ radically, and downstream risk should use the
direction of surprise. Spec section 23 adds the other half — security
information also lives in expected events that **fail to occur**. A service
child heartbeat that stops, while a new external channel opens, is a residual
with two parts, and only one of them is an observed event.

**This module is measured, default-off, and never feeds detection.** The
structured surprise vector was measured at **−0.073 PR-AUC** on the ambiguous
corpus and removed from the Stage 2 core for that reason (`planning/MEMORY.md`,
ADR-0010). Nothing here is backpropagated, added to a score, or used to rank a
verdict. It exists so that the residual can be *reported* and, in some later
wave, re-measured honestly against the Φ-oracle rather than assumed useful.

``components`` is kept per head and is never collapsed into one number. The
``magnitude`` property exists only to order residuals in a report; a caller that
treats it as an anomaly score has reintroduced the −0.073.

Which heads get a residual is decided by what a single observed transition can
actually falsify. ``relation``, ``object``, ``state_delta``, ``time`` and ``phi``
have ground truth inside ``EncodedTransition``. ``causal``, ``epoch`` and
``uncertainty`` do not, and scoring them anyway would repeat a mistake this
project already made and fixed: an unsupervised head fits noise.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Mapping

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.ssir.relations import Relation
from pocketsec.stage1.state.security_state import DIMENSIONS
from pocketsec.stage2.encoder.ssir_encoder import (
    GROUP_OFFSETS,
    EncodedTransition,
    feature_names,
)
from pocketsec.stage2.predictors.heads import (
    HEAD_CLASSES,
    OBJECT_PROPERTY_CLASSES,
    HeadPrediction,
    phi_bucket,
)

__all__ = [
    "MULTI_LABEL_HEADS",
    "OBJECT_PROPERTY_NAMES",
    "SCORABLE_HEADS",
    "Residual",
    "class_names",
    "score_prediction_residual",
]

#: Heads whose target a single observed transition can falsify.
SCORABLE_HEADS: tuple[str, ...] = ("relation", "object", "state_delta", "time", "phi")

#: Of those, the ones whose observation is a *set* of classes rather than one.
#: An escalation that touches privilege and credential together is the case that
#: matters, so these two are scored as independent bits.
MULTI_LABEL_HEADS: frozenset[str] = frozenset({"object", "state_delta"})

#: Clamp for log arguments: a head is allowed to be confidently wrong, but an
#: infinite residual would destroy every aggregate it enters.
_EPSILON: float = 1e-12


def _object_property_names() -> tuple[str, ...]:
    """Read H2's class names out of the frozen encoder layout.

    The encoder exposes a deliberate subset of ``SemanticProperty`` and
    ``object_property_mask`` bit indices are positions in *that* subset, so the
    names must come from the encoder rather than from the enum.
    """
    offset = GROUP_OFFSETS["object_semantics"]
    names = feature_names()[offset : offset + OBJECT_PROPERTY_CLASSES]
    return tuple(name.split(".", 1)[1] for name in names)


OBJECT_PROPERTY_NAMES: tuple[str, ...] = _object_property_names()

assert len(OBJECT_PROPERTY_NAMES) == OBJECT_PROPERTY_CLASSES


def class_names(head_id: str) -> tuple[str, ...]:
    """Human-readable class names, for the ``absent_expected`` labels."""
    if head_id == "relation":
        return tuple(relation.name.lower() for relation in Relation)
    if head_id == "object":
        return OBJECT_PROPERTY_NAMES
    if head_id == "state_delta":
        return tuple(DIMENSIONS)
    if head_id == "time":
        return tuple(f"bucket{index}" for index in range(HEAD_CLASSES["time"]))
    if head_id == "phi":
        return tuple(f"phi{index}" for index in range(HEAD_CLASSES["phi"]))
    if head_id not in HEAD_CLASSES:
        raise ContractError(f"unknown head id {head_id!r}")
    return tuple(f"class{index}" for index in range(HEAD_CLASSES[head_id]))


def _bits(mask: int, width: int) -> frozenset[int]:
    if mask < 0:
        raise ContractError(f"negative bitmask {mask}")
    return frozenset(index for index in range(width) if mask & (1 << index))


def _observed_classes(head_id: str, observed: EncodedTransition) -> frozenset[int]:
    if head_id == "relation":
        return frozenset({observed.relation})
    if head_id == "time":
        return frozenset({observed.time_bucket})
    if head_id == "phi":
        return frozenset({phi_bucket(observed.delta_phi)})
    if head_id == "object":
        return _bits(observed.object_property_mask, OBJECT_PROPERTY_CLASSES)
    if head_id == "state_delta":
        return _bits(observed.state_delta_mask, len(DIMENSIONS))
    raise ContractError(  # pragma: no cover - guarded by SCORABLE_HEADS
        f"head {head_id!r} has no observable target in one transition"
    )


def _single_label_surprise(
    probabilities: tuple[float, ...], observed: frozenset[int]
) -> float:
    """−log p(observed class)."""
    index = next(iter(observed))
    if index >= len(probabilities):
        raise ContractError(
            f"observed class {index} outside the head's {len(probabilities)} classes"
        )
    return -math.log(max(probabilities[index], _EPSILON))


def _multi_label_surprise(
    probabilities: tuple[float, ...], observed: frozenset[int]
) -> float:
    """Mean per-class binary cross-entropy.

    A softmax mass is read as the marginal probability that this class is among
    the observed set. That is an approximation, and it is the one that keeps
    "nothing was raised" a scorable observation instead of an infinite residual:
    under a strict multinomial reading, the empty set has probability zero and
    every benign transition would look infinitely surprising.
    """
    if max(observed, default=-1) >= len(probabilities):
        raise ContractError("observed class outside the head's class count")
    total = 0.0
    for index, probability in enumerate(probabilities):
        clamped = min(max(probability, _EPSILON), 1.0 - _EPSILON)
        total += (
            -math.log(clamped) if index in observed else -math.log(1.0 - clamped)
        )
    return total / len(probabilities)


@dataclass(frozen=True, slots=True)
class Residual:
    """The structured residual for one observed transition.

    ``components`` is the surprise geometry of spec section 9, kept per head.
    Collapsing it is forbidden: a temporally odd but harmless event and an
    improbable privilege→credential transition can carry the same total.
    """

    observed_surprise: float
    #: ``"<head>:<class>"`` labels for expected continuations that did not occur.
    absent_expected: tuple[str, ...]
    #: Summed probability of those continuations, **across heads**. It is a sum of
    #: masses from several distributions, so it is not itself a probability and may
    #: exceed 1.0; reading it as one would be a category error.
    absent_mass: float
    components: dict[str, float]

    def __post_init__(self) -> None:
        if self.observed_surprise < 0.0:
            raise ContractError("observed_surprise cannot be negative")
        if not 0.0 <= self.absent_mass:
            raise ContractError("absent_mass cannot be negative")
        # Copy so a caller cannot mutate the geometry after the fact; same
        # pattern as Stage 1's StateDelta.
        object.__setattr__(self, "components", dict(self.components))

    @property
    def magnitude(self) -> float:
        """L2 norm of the per-head components.

        A reporting/ordering aid only. This number must never be added to,
        compared against, or blended into a detection score: doing so is exactly
        the −0.073 that removed the surprise vector from the Stage 2 core.
        """
        return math.sqrt(sum(value * value for value in self.components.values()))

    def to_dict(self) -> dict[str, Any]:
        return {
            "observed_surprise": round(self.observed_surprise, 6),
            "absent_expected": list(self.absent_expected),
            "absent_mass": round(self.absent_mass, 6),
            "components": {
                head: round(value, 6) for head, value in sorted(self.components.items())
            },
            "magnitude": round(self.magnitude, 6),
            "feeds_detection": False,
        }


def score_prediction_residual(
    predicted: Mapping[str, HeadPrediction],
    observed: EncodedTransition,
    *,
    expectation_floor: float = 0.05,
) -> Residual:
    """DTL-F09 — residual over what happened *and* what was expected and did not.

    ``expectation_floor`` is the bar for calling something "expected": a class the
    head gave more than this mass to, which then did not occur, is recorded with
    its probability. Every such class is named, and their mass is summed into
    ``absent_mass`` — the negative-space half of spec section 23.

    Heads with no observable ground truth in a single transition (``causal``,
    ``epoch``, ``uncertainty``) are skipped rather than scored against a guess.
    """
    if not 0.0 < expectation_floor < 1.0:
        raise ContractError(
            f"expectation_floor must be in (0, 1), got {expectation_floor}"
        )
    components: dict[str, float] = {}
    absent: list[tuple[str, float]] = []
    for head_id in SCORABLE_HEADS:
        prediction = predicted.get(head_id)
        if prediction is None:
            continue
        if len(prediction.probabilities) != HEAD_CLASSES[head_id]:
            raise ContractError(
                f"head {head_id!r} returned {len(prediction.probabilities)} "
                f"probabilities, vocabulary has {HEAD_CLASSES[head_id]}"
            )
        seen = _observed_classes(head_id, observed)
        if head_id in MULTI_LABEL_HEADS:
            components[head_id] = _multi_label_surprise(prediction.probabilities, seen)
        else:
            components[head_id] = _single_label_surprise(prediction.probabilities, seen)
        names = class_names(head_id)
        for index, probability in enumerate(prediction.probabilities):
            if probability > expectation_floor and index not in seen:
                absent.append((f"{head_id}:{names[index]}", probability))
    if not components:
        raise ContractError(
            "no scorable head was supplied; residuals need at least one of "
            f"{SCORABLE_HEADS}"
        )
    absent.sort(key=lambda item: (-item[1], item[0]))
    return Residual(
        observed_surprise=sum(components.values()),
        absent_expected=tuple(label for label, _ in absent),
        absent_mass=sum(mass for _, mass in absent),
        components=components,
    )
