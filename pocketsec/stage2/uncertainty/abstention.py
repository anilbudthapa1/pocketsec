"""DTL-F07 — where Stage 2's uncertainty comes from, and when it abstains.

Spec section 18 is an *epistemic budget*: what a system spends on an event should
depend on two independent quantities — how uncertain it is, and how much
consequence is on the table (Φ). The four quadrants of (U, Φ) are the policy, and
this module is their only implementation.

| | low Φ | high Φ |
|---|---|---|
| **low U** | ``CHEAP_PATH`` | ``KNOWN_HIGH_RISK`` |
| **high U** | ``OBSERVE_LAZILY`` | ``ESCALATE`` — AOP, deeper inference, preserve evidence |

Two invariants this module exists to hold, both inherited from Stage 1 and both
paid for by real bugs:

1. **Novelty, Φ and uncertainty are three separate signals.**
   ``UncertaintyEstimate.value`` never absorbs novelty or Φ. Φ arrives as a
   separate argument and is used only to pick the quadrant; novelty is not read
   at all. Collapsing them makes "novel" mean "malicious", which it does not
   (``planning/MEMORY.md``).
2. **"No properties asserted" is not "maximally uncertain."** A source that was
   evaluated and came back empty is a *negative result*, and a negative result
   lowers uncertainty. A source that was never evaluated contributes nothing
   rather than contributing 1.0 — conflating the two drove constant AOP
   escalation in Stage 1 and suppressed aggregation entirely.

``EVIDENCE_INCOMPLETE`` has exactly one driver, ``transition.observation_
incomplete``. Nothing else may raise it: it means "the sensors did not agree or
fusion did not finish", not "the model is unsure", and an AOP request built on a
conflated flag would be asking for observation that already arrived.

Abstention is a valid output. Stage 0's harness scores a non-committal
prediction 0.0, so abstaining can never manufacture recall — which is what makes
it safe to abstain honestly rather than guess.

Types from ``pocketsec.stage2.predictors`` are consumed **structurally** (see the
protocols below) so this module imports nothing from a sibling package. That
keeps the uncertainty layer usable — and testable — without the predictive heads
being present, which matters because the heads are optional and detached
(ADR-0009).
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.ssir.transition import SSIRTransitionV1
from pocketsec.stage2.uncertainty.calibration import IsotonicCalibrator

__all__ = [
    "ABSTAIN_THRESHOLD",
    "BranchLike",
    "ConeLike",
    "EpistemicQuadrant",
    "HeadLike",
    "MAX_SOFTMAX_CONTROL",
    "PHI_HIGH",
    "SOURCE_WEIGHTS",
    "STAGE1_PRIOR_KEY",
    "UNCERTAINTY_HIGH",
    "UncertaintyEstimate",
    "UncertaintySource",
    "estimate_uncertainty",
    "one_minus_max",
    "quadrant_for",
]


class UncertaintySource(StrEnum):
    """Where an uncertainty contribution came from.

    Kept as separate, named contributions rather than one scalar: an operator who
    sees 0.8 needs to know whether the heads disagreed, the atom was far from
    every prototype, the future branched, or a sensor simply did not report —
    because the four call for different responses.
    """

    ENTROPY = "ENTROPY"
    PROTOTYPE_DISTANCE = "PROTOTYPE_DISTANCE"
    CONE_AMBIGUITY = "CONE_AMBIGUITY"
    EVIDENCE_INCOMPLETE = "EVIDENCE_INCOMPLETE"


class EpistemicQuadrant(StrEnum):
    """Spec section 18's (U, Φ) policy, verbatim."""

    CHEAP_PATH = "CHEAP_PATH"
    OBSERVE_LAZILY = "OBSERVE_LAZILY"
    KNOWN_HIGH_RISK = "KNOWN_HIGH_RISK"
    ESCALATE = "ESCALATE"


#: Stage 1's own uncertainty for the transition, carried as a term so Stage 2 can
#: never quietly contradict it. It is not an :class:`UncertaintySource` because it
#: is not a Stage 2 source; the reserved key keeps it visible in ``sources``.
STAGE1_PRIOR_KEY = "stage1_transition_uncertainty"

#: Weights over whichever terms were actually evaluated, renormalised each call.
#: Not fitted — there is no labelled uncertainty ground truth to fit them on, and
#: inventing one would be the "unsupervised head fits noise" trap (MEMORY.md 6).
#: Calibration is what corrects the scale; these only set the mixture.
SOURCE_WEIGHTS: dict[str, float] = {
    UncertaintySource.ENTROPY.value: 0.25,
    UncertaintySource.CONE_AMBIGUITY.value: 0.20,
    UncertaintySource.PROTOTYPE_DISTANCE.value: 0.15,
    UncertaintySource.EVIDENCE_INCOMPLETE.value: 0.25,
    STAGE1_PRIOR_KEY: 0.15,
}

#: Quadrant boundaries. Φ's scale comes from Stage 1's measured separation
#: (benign mean 0.62, malicious mean 9.46, ``planning/MEMORY.md``), so 4.0 sits
#: between the two populations rather than being a round number chosen for looks.
UNCERTAINTY_HIGH = 0.5
PHI_HIGH = 4.0
#: Abstention needs more than "high": an ESCALATE quadrant already buys deeper
#: inference, and abstaining on everything in it would hand the analyst nothing.
ABSTAIN_THRESHOLD = 0.7

MAX_SOFTMAX_CONTROL: str = "one_minus_max_probability"


class HeadLike(Protocol):
    """Structural view of ``predictors.heads.HeadPrediction``."""

    probabilities: tuple[float, ...]
    entropy: float


class BranchLike(Protocol):
    """Structural view of ``predictors.future_cone.ConeBranch``."""

    probability: float


class ConeLike(Protocol):
    """Structural view of ``predictors.future_cone.FutureCone``."""

    branches: tuple[BranchLike, ...]
    unresolved_mass: float


@dataclass(frozen=True, slots=True)
class UncertaintyEstimate:
    """One event's uncertainty, decomposed, with its calibration provenance.

    ``calibration_id`` is ``None`` whenever the value was not passed through a
    fitted map — which is the common case — because an uncalibrated 0.8 and a
    calibrated 0.8 are different claims and the consumer must be able to tell.
    """

    value: float
    sources: dict[str, float]
    calibration_id: str | None
    quadrant: EpistemicQuadrant
    abstain: bool
    detail: str

    def __post_init__(self) -> None:
        if not 0.0 <= self.value <= 1.0:
            raise ContractError(f"uncertainty value must be in [0, 1], got {self.value!r}")
        if self.abstain and self.quadrant is not EpistemicQuadrant.ESCALATE:
            raise ContractError(
                f"abstention is only valid in ESCALATE, got {self.quadrant.value}"
            )
        object.__setattr__(self, "sources", dict(self.sources))

    @property
    def dominant_source(self) -> str | None:
        """The largest contribution, or ``None`` when nothing contributed."""
        if not self.sources:
            return None
        return max(self.sources, key=lambda key: self.sources[key])

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "sources": dict(self.sources),
            "calibration_id": self.calibration_id,
            "quadrant": self.quadrant.value,
            "abstain": self.abstain,
            "detail": self.detail,
            "dominant_source": self.dominant_source,
        }


def _normalised_entropy(probabilities: Sequence[float]) -> float:
    """Shannon entropy scaled by ln(k) so widths are comparable across heads.

    Unnormalised entropies silently weight a head by its vocabulary size — the
    same bug that starved detection to 16 % of the gradient in the joint-training
    experiment (``planning/MEMORY.md``, trap 7).
    """
    classes = len(probabilities)
    if classes < 2:
        return 0.0
    total = 0.0
    for probability in probabilities:
        if probability > 0.0:
            total -= probability * math.log(probability)
    return min(1.0, max(0.0, total / math.log(classes)))


def one_minus_max(heads: Mapping[str, HeadLike]) -> float:
    """THE SIMPLE CONTROL: mean of (1 - max probability) over the heads.

    This is what every uncertainty mechanism has to beat. It costs one pass over
    a probability vector, has no calibration, no state and no parameters. Raises
    on an empty mapping rather than returning 0.0: "there were no heads" is not
    "the heads were certain".
    """
    if not heads:
        raise ContractError(
            "one_minus_max needs at least one head; an empty mapping is not certainty"
        )
    total = 0.0
    for head_id, head in heads.items():
        probabilities = tuple(head.probabilities)
        if not probabilities:
            raise ContractError(f"head {head_id!r} has no probabilities")
        total += 1.0 - max(probabilities)
    return min(1.0, max(0.0, total / len(heads)))


def quadrant_for(
    value: float,
    phi_total: float,
    *,
    uncertainty_high: float = UNCERTAINTY_HIGH,
    phi_high: float = PHI_HIGH,
) -> EpistemicQuadrant:
    """Spec section 18's table as code. Φ never enters ``value``; only this."""
    high_uncertainty = value >= uncertainty_high
    high_phi = phi_total >= phi_high
    if high_uncertainty and high_phi:
        return EpistemicQuadrant.ESCALATE
    if high_uncertainty:
        return EpistemicQuadrant.OBSERVE_LAZILY
    if high_phi:
        return EpistemicQuadrant.KNOWN_HIGH_RISK
    return EpistemicQuadrant.CHEAP_PATH


def _collect_sources(
    *,
    heads: Mapping[str, HeadLike] | None,
    cone: ConeLike | None,
    prototype_distance: float | None,
    transition: SSIRTransitionV1,
) -> tuple[dict[str, float], list[str]]:
    """Evaluate only the sources that were actually available.

    An unavailable source is *absent from the mapping*, not present at 1.0. That
    is the Stage 1 modelling distinction: never-evaluated is not
    evaluated-and-maximal.
    """
    sources: dict[str, float] = {}
    notes: list[str] = []

    if heads:
        entropies = [_normalised_entropy(tuple(head.probabilities)) for head in heads.values()]
        sources[UncertaintySource.ENTROPY.value] = sum(entropies) / len(entropies)
    else:
        notes.append("heads=not_evaluated")

    if cone is not None:
        branch_probabilities = tuple(float(branch.probability) for branch in cone.branches)
        unresolved = float(cone.unresolved_mass)
        if not 0.0 <= unresolved <= 1.0:
            raise ContractError(f"cone.unresolved_mass must be in [0, 1], got {unresolved!r}")
        ambiguity = 0.5 * unresolved + 0.5 * _normalised_entropy(branch_probabilities)
        sources[UncertaintySource.CONE_AMBIGUITY.value] = min(1.0, max(0.0, ambiguity))
    else:
        notes.append("cone=not_evaluated")

    if prototype_distance is not None:
        distance = float(prototype_distance)
        if distance < 0.0 or not math.isfinite(distance):
            raise ContractError(
                f"prototype_distance must be a finite, non-negative distance, got {distance!r}"
            )
        # Squashed, not clipped: a point twice as far from every prototype should
        # still order above one that is merely outside the radius.
        sources[UncertaintySource.PROTOTYPE_DISTANCE.value] = distance / (1.0 + distance)
    else:
        notes.append("prototype_distance=not_evaluated")

    # Always evaluated: the flag is carried on every transition, so "complete"
    # is a measured negative result and correctly pulls uncertainty *down*.
    sources[UncertaintySource.EVIDENCE_INCOMPLETE.value] = (
        1.0 if transition.observation_incomplete else 0.0
    )
    sources[STAGE1_PRIOR_KEY] = float(transition.uncertainty)
    return sources, notes


def estimate_uncertainty(
    *,
    heads: Mapping[str, HeadLike] | None,
    cone: ConeLike | None,
    prototype_distance: float | None,
    transition: SSIRTransitionV1,
    calibrator: IsotonicCalibrator | None = None,
    phi_total: float,
) -> UncertaintyEstimate:
    """DTL-F07 — combine the evaluated uncertainty sources and place the event.

    ``phi_total`` selects the quadrant and **never** enters ``value``; novelty is
    not an argument at all. If a future caller wants a single risk number it must
    compose the three signals itself, where the composition is visible.

    When a ``calibrator`` is supplied it is applied to the *confidence*
    (1 - value), which is the quantity a reliability diagram is drawn over, and
    the result is turned back into an uncertainty. An unfitted calibrator is not
    silently used: the raw value is kept, ``calibration_id`` stays ``None``, and
    ``detail`` records the refusal.
    """
    if isinstance(phi_total, bool) or not isinstance(phi_total, (int, float)):
        raise ContractError(f"phi_total must be a number, got {phi_total!r}")
    if not math.isfinite(float(phi_total)):
        raise ContractError(f"phi_total must be finite, got {phi_total!r}")

    sources, notes = _collect_sources(
        heads=heads,
        cone=cone,
        prototype_distance=prototype_distance,
        transition=transition,
    )
    weight_total = sum(SOURCE_WEIGHTS[key] for key in sources)
    raw = sum(SOURCE_WEIGHTS[key] * value for key, value in sources.items()) / weight_total
    # Refused, not clamped. `max(0.0, nan)` returns 0.0 in CPython, so a NaN
    # anywhere upstream used to arrive here as value=0.0 — abstain=False,
    # quadrant CHEAP_PATH — reporting a numerically undefined estimate as
    # perfect certainty. That is the exact inversion "UNKNOWN is a valid output"
    # forbids: the safe direction for an undefined uncertainty is maximum
    # uncertainty or an error, never minimum (S2-AUTH-03).
    if not math.isfinite(raw):
        raise ContractError(
            f"estimate_uncertainty computed a non-finite uncertainty ({raw!r}) "
            f"from sources {sources}; clamping it would report an undefined "
            "estimate as perfect certainty"
        )
    raw = min(1.0, max(0.0, raw))

    value = raw
    calibration_id: str | None = None
    if calibrator is not None:
        fitted_id = calibrator.calibration_id()
        if fitted_id is None:
            notes.append("calibration=refused")
        else:
            value = min(1.0, max(0.0, 1.0 - calibrator.apply(1.0 - raw)))
            calibration_id = fitted_id
            notes.append(f"calibrated_from={raw:.4f}")

    quadrant = quadrant_for(value, float(phi_total))
    abstain = quadrant is EpistemicQuadrant.ESCALATE and value >= ABSTAIN_THRESHOLD
    notes.append(f"phi_total={float(phi_total):.4f}")
    if abstain:
        notes.append("abstain=preserve_evidence")
    return UncertaintyEstimate(
        value=value,
        sources=sources,
        calibration_id=calibration_id,
        quadrant=quadrant,
        abstain=abstain,
        detail="; ".join(notes),
    )
