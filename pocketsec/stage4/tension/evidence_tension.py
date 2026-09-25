"""D4.4 — Evidence Tension: how badly a world disagrees with reality (§7).

Accumulating only *supporting* evidence is how a system talks itself into one
story. Architecture §7 measures the opposite quantity::

    Tension(W) = unexpected_observation_cost
               + missing_expected_evidence_cost
               + causal_inconsistency
               + temporal_inconsistency
               + security_state_inconsistency
               + visibility_adjusted_contradiction

and states the consequence that makes it worth building: *a world can die from
accumulated tension even if no single event disproves it*. That is what
``sustained_steps`` is for.

Two disciplines this module refuses to bend:

1. **Never a bare float.** :class:`EvidenceTension` carries all six terms beside
   the total, exactly as ``PhiBreakdown`` (``potential.py:147``) carries its base
   terms and interactions beside Φ. Stage 1 already learned that a scalar with no
   reasoning attached is indistinguishable from an arbitrary weight, and a world
   killed by an unexplainable number is a world killed arbitrarily.
2. **A missing signal costs nothing unless its absence is informative.** The
   ``MISSING_EXPECTED`` term is computed through
   :func:`~pocketsec.stage4.tension.negative_evidence.classify_absence` and
   contributes exactly zero for ``UNKNOWN_ABSENCE`` and ``NOT_EXPECTED``. Under
   dropped telemetry that term therefore goes to zero rather than to "a bit
   less", which is the difference between degrading and guessing.

Every weight in ``TENSION_WEIGHTS`` and every threshold here is a **chosen
parameter, not a measured one** (spec §9.11).
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from pocketsec.stage0.contracts.common import ContractError, require_finite_unit_interval
from pocketsec.stage1.ssir.transition import SSIRTransitionV1
from pocketsec.stage4.tension.negative_evidence import (
    MIN_INFORMATIVE_VISIBILITY,
    NegativeEvidenceVerdict,
    classify_absence,
)
from pocketsec.stage4.visibility.model import (
    VisibilityModel,
    best_visibility,
    signals_of_transition,
)
from pocketsec.stage4.visibility.sensor_shadow import SensorShadow

if TYPE_CHECKING:  # pragma: no cover - typing only
    from pocketsec.stage4.worlds.world import SecurityWorldV1

__all__ = [
    "HARD_CONTRADICTION_TENSION",
    "TENSION_DEATH_THRESHOLD",
    "TENSION_SUSTAIN_FLOOR",
    "TENSION_SUSTAIN_STEPS",
    "TENSION_WEIGHTS",
    "EvidenceTension",
    "TensionTerm",
    "TensionWorld",
    "calculate_evidence_tension",
    "tension_history",
]


class TensionTerm(StrEnum):
    """Architecture §7's six terms, exactly. No seventh, no rename."""

    UNEXPECTED_OBSERVATION = "UNEXPECTED_OBSERVATION"
    MISSING_EXPECTED = "MISSING_EXPECTED"
    CAUSAL_INCONSISTENCY = "CAUSAL_INCONSISTENCY"
    TEMPORAL_INCONSISTENCY = "TEMPORAL_INCONSISTENCY"
    STATE_INCONSISTENCY = "STATE_INCONSISTENCY"
    VISIBILITY_ADJUSTED_CONTRADICTION = "VISIBILITY_ADJUSTED_CONTRADICTION"


#: Weights over the six terms, summing to 1.0 so ``total`` stays in [0, 1] and is
#: comparable across worlds. The contradiction and causal terms carry the most
#: because they are the two that can be *wrong about the mechanism* rather than
#: merely surprised by it; the temporal term carries the least because a
#: mis-sequenced observation is most often a clock artefact.
TENSION_WEIGHTS: Mapping[TensionTerm, float] = MappingProxyType(
    {
        TensionTerm.UNEXPECTED_OBSERVATION: 0.15,
        TensionTerm.MISSING_EXPECTED: 0.15,
        TensionTerm.CAUSAL_INCONSISTENCY: 0.20,
        TensionTerm.TEMPORAL_INCONSISTENCY: 0.10,
        TensionTerm.STATE_INCONSISTENCY: 0.15,
        TensionTerm.VISIBILITY_ADJUSTED_CONTRADICTION: 0.25,
    }
)

if abs(math.fsum(TENSION_WEIGHTS.values()) - 1.0) > 1e-9:  # pragma: no cover - import guard
    raise ContractError("TENSION_WEIGHTS must sum to 1.0")
if set(TENSION_WEIGHTS) != set(TensionTerm):  # pragma: no cover - import guard
    raise ContractError("TENSION_WEIGHTS must carry exactly the six §7 terms")

#: A world that forbade something we then plainly saw is not "under tension", it
#: is refuted. 1.0 is the ceiling and is reserved for that case.
HARD_CONTRADICTION_TENSION: float = 1.0

#: Tension at or above which a world dies outright.
TENSION_DEATH_THRESHOLD: float = 0.75

#: Consecutive steps at or above ``TENSION_SUSTAIN_FLOOR`` that also kill. This is
#: §7's "a world can die from accumulated tension even if no single event
#: disproves it", made mechanical.
TENSION_SUSTAIN_STEPS: int = 3

#: The floor a step must clear to count towards ``sustained_steps``. Strictly
#: below ``TENSION_DEATH_THRESHOLD`` — if it were not, accumulation could never
#: add anything a single step had not already decided, and the mechanism would be
#: decorative. Chosen parameter, and the one most worth ablating.
TENSION_SUSTAIN_FLOOR: float = 0.35


@runtime_checkable
class TensionWorld(Protocol):
    """The slice of ``SecurityWorldV1`` the tension calculation reads.

    Structural, for the same reason as
    :class:`~pocketsec.stage4.tension.negative_evidence.PredictingWorld`:
    ``SecurityWorldV1`` holds an ``EvidenceTension`` field, so importing it here
    at runtime would close a cycle.
    """

    mechanism_id: str
    expected_evidence: frozenset[str]
    forbidden_evidence: frozenset[str]
    uncertainty: float
    spine_signatures: tuple[str, ...]
    born_at_sequence: int


@dataclass(frozen=True, slots=True)
class EvidenceTension:
    """Tension(W) (§7), always with its six terms attached — never a bare float."""

    terms: Mapping[TensionTerm, float]
    total: float
    hard_contradictions: tuple[str, ...]
    sustained_steps: int

    def __post_init__(self) -> None:
        if set(self.terms) != set(TensionTerm):
            missing = sorted(t.value for t in set(TensionTerm) - set(self.terms))
            raise ContractError(
                f"EvidenceTension.terms must carry all six terms; missing {missing}"
            )
        frozen: dict[TensionTerm, float] = {}
        for term, value in self.terms.items():
            frozen[TensionTerm(term)] = require_finite_unit_interval(
                value, f"EvidenceTension.terms[{TensionTerm(term).value}]"
            )
        object.__setattr__(self, "terms", MappingProxyType(frozen))
        require_finite_unit_interval(self.total, "EvidenceTension.total")
        if self.sustained_steps < 0:
            raise ContractError("EvidenceTension.sustained_steps must be non-negative")
        object.__setattr__(self, "hard_contradictions", tuple(self.hard_contradictions))
        if self.hard_contradictions and self.total < HARD_CONTRADICTION_TENSION:
            raise ContractError(
                "a hard contradiction must carry total == HARD_CONTRADICTION_TENSION, "
                f"got {self.total}"
            )

    def is_fatal(self) -> bool:
        """Whether this world should die.

        Three independent routes, and the third is the one §7 exists for: a world
        can accumulate its way to death without any single disproving event.
        """
        return (
            bool(self.hard_contradictions)
            or self.total >= TENSION_DEATH_THRESHOLD
            or self.sustained_steps >= TENSION_SUSTAIN_STEPS
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "terms": {term.value: round(self.terms[term], 4) for term in TensionTerm},
            "total": round(self.total, 4),
            "hard_contradictions": list(self.hard_contradictions),
            "sustained_steps": self.sustained_steps,
            "fatal": self.is_fatal(),
        }


def _missing_expected_term(
    world: TensionWorld | SecurityWorldV1,
    *,
    model: VisibilityModel,
    observed: frozenset[str],
) -> float:
    """Fraction of expected signals whose absence is *informative*.

    ``UNKNOWN_ABSENCE`` and ``NOT_EXPECTED`` contribute exactly zero. That is the
    §8 contract and the reason a dropped sensor cannot kill a world here.
    """
    expected = frozenset(world.expected_evidence)
    if not expected:
        return 0.0
    informative = 0
    for signal in sorted(expected):
        verdict, _ = classify_absence(
            signal=signal, world=world, model=model, observed=observed
        )
        if verdict is NegativeEvidenceVerdict.INFORMATIVE_ABSENCE:
            informative += 1
    return informative / len(expected)


def _contradiction_terms(
    world: TensionWorld | SecurityWorldV1,
    *,
    observed: frozenset[str],
    shadow: SensorShadow,
    model: VisibilityModel,
) -> tuple[float, tuple[str, ...]]:
    """The visibility-adjusted contradiction term and any hard contradictions.

    A forbidden signal we plainly saw, on a path measured to see it, with no
    shadow over it, is a refutation and goes in ``hard_contradictions``. The same
    signal seen where visibility is unmeasured or shadowed is still tension — we
    did see something the world forbade — but discounted by the shadow, because
    the observation itself may be the artefact.
    """
    forbidden = frozenset(world.forbidden_evidence)
    seen = sorted(forbidden & observed)
    if not seen:
        return 0.0, ()
    hard: list[str] = []
    soft = 0
    for signal in seen:
        visibility = best_visibility(model, signal)
        trustworthy = (
            not shadow.covers(signal)
            and visibility is not None
            and visibility >= MIN_INFORMATIVE_VISIBILITY
        )
        if trustworthy:
            hard.append(signal)
        else:
            soft += 1
    if hard:
        return 1.0, tuple(hard)
    discount = 1.0 - shadow.confidence_penalty()
    return min(1.0, (soft / len(forbidden)) * discount), ()


def _structural_terms(
    world: TensionWorld | SecurityWorldV1, transition: SSIRTransitionV1
) -> dict[TensionTerm, float]:
    """Causal, temporal and state inconsistency for one transition."""
    spine = frozenset(world.spine_signatures)
    off_spine = bool(spine) and not (
        transition.parent_signature in spine or transition.causal_signature in spine
    )
    raised = transition.state_delta.dimensions
    asserted = _asserted_dimensions(world)
    unexplained = raised - asserted if raised else frozenset()
    return {
        TensionTerm.CAUSAL_INCONSISTENCY: (
            1.0 if off_spine and transition.is_high_consequence else 0.0
        ),
        TensionTerm.TEMPORAL_INCONSISTENCY: (
            1.0 if transition.sequence < world.born_at_sequence else 0.0
        ),
        TensionTerm.STATE_INCONSISTENCY: (
            len(unexplained) / len(raised) if raised else 0.0
        ),
    }


def _asserted_dimensions(world: TensionWorld | SecurityWorldV1) -> frozenset[str]:
    """Dimensions the world commits to, read defensively.

    ``latent_state`` is owned by ``worlds/world.py``, which this module must not
    import at runtime. A world without one asserts nothing, which makes every
    raised dimension unexplained — the conservative direction.
    """
    latent = getattr(world, "latent_state", None)
    asserted = getattr(latent, "asserted_dimensions", None)
    return frozenset(asserted) if asserted else frozenset()


def calculate_evidence_tension(
    world: TensionWorld | SecurityWorldV1,
    transition: SSIRTransitionV1,
    *,
    shadow: SensorShadow,
    model: VisibilityModel,
    history: EvidenceTension | None,
    observed: frozenset[str] | None = None,
) -> EvidenceTension:
    """CBF-F07 — tension between ``world`` and the evidence so far.

    ``observed`` is the incident's cumulative observed-signal set. It is a
    keyword with a default beyond the spec's signature because absence is a
    property of the incident, not of one transition: scored against a single
    transition's signals, every multi-signal world would look as though most of
    its expectations had gone missing at every step. Defaulting to this
    transition's own signals keeps the spec's call shape working.
    """
    seen = signals_of_transition(transition) if observed is None else frozenset(observed)
    unexpected = seen - frozenset(world.expected_evidence) - frozenset(world.forbidden_evidence)
    contradiction, hard = _contradiction_terms(
        world, observed=seen, shadow=shadow, model=model
    )
    terms: dict[TensionTerm, float] = {
        TensionTerm.UNEXPECTED_OBSERVATION: (len(unexpected) / len(seen) if seen else 0.0),
        TensionTerm.MISSING_EXPECTED: _missing_expected_term(
            world, model=model, observed=seen
        ),
        TensionTerm.VISIBILITY_ADJUSTED_CONTRADICTION: contradiction,
        **_structural_terms(world, transition),
    }
    weighted = math.fsum(TENSION_WEIGHTS[term] * terms[term] for term in TensionTerm)
    total = HARD_CONTRADICTION_TENSION if hard else max(0.0, min(1.0, weighted))
    previous = history.sustained_steps if history is not None else 0
    sustained = previous + 1 if total >= TENSION_SUSTAIN_FLOOR else 0
    return EvidenceTension(
        terms=terms,
        total=total,
        hard_contradictions=hard,
        sustained_steps=sustained,
    )


def tension_history(tensions: Sequence[EvidenceTension]) -> tuple[float, int]:
    """Peak total and peak sustained-step count over a sequence.

    Used by the labs to summarise a paired replay without re-deriving the run.
    """
    if not tensions:
        return 0.0, 0
    return (
        max(tension.total for tension in tensions),
        max(tension.sustained_steps for tension in tensions),
    )
