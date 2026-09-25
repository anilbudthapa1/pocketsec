"""D4.4 (part) — negative evidence without the classic trap (architecture §8).

The trap, stated plainly: *"the world predicted a credential read, we saw no
credential read, therefore the world is wrong."* That inference is only valid if
PocketSec would have seen the credential read. On a host where the relevant
sensor was never collecting, the same reasoning kills the true world and leaves
the innocent-looking one standing — a security failure produced by good
statistics over bad epistemics.

§8's rule, as three conditions that must all hold before an absence counts:

    if P(observe e | e occurred, A_t, V_t) is high
       AND W strongly predicts e
       AND e is absent
    then absence is informative.
    Otherwise: absence remains UNKNOWN.

This module is that rule and nothing else. What it refuses to do:

* It never treats ``VisibilityModel.probability() is None`` as low visibility.
  ``None`` is UNMEASURED, and an unmeasured pair yields ``UNKNOWN_ABSENCE`` with
  that stated as the reason. Substituting a prior here is the single change that
  would re-open the trap.
* It never lets a weakly-predicting world be strengthened by an absence. A world
  that is itself uncertain does not get to claim the absence as a win: see
  :func:`prediction_strength`.

The caller contract, which the tension engine honours: on ``UNKNOWN_ABSENCE`` and
``NOT_EXPECTED`` the ``MISSING_EXPECTED`` tension term contributes **exactly
zero**. Not a small number. Zero.
"""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from pocketsec.stage4.visibility.model import VisibilityModel, best_visibility

if TYPE_CHECKING:  # pragma: no cover - typing only
    from pocketsec.stage4.worlds.world import SecurityWorldV1

__all__ = [
    "MIN_INFORMATIVE_VISIBILITY",
    "MIN_PREDICTION_STRENGTH",
    "NegativeEvidenceVerdict",
    "PredictingWorld",
    "classify_absence",
    "prediction_strength",
]


class NegativeEvidenceVerdict(StrEnum):
    """What an absence is worth."""

    #: Visibility is high, the world predicts the signal strongly, and it is
    #: absent. This is evidence.
    INFORMATIVE_ABSENCE = "INFORMATIVE_ABSENCE"
    #: We cannot show we would have seen it. This is not evidence.
    UNKNOWN_ABSENCE = "UNKNOWN_ABSENCE"
    #: The world does not predict it, so its absence says nothing either way.
    NOT_EXPECTED = "NOT_EXPECTED"


#: Visibility at or above which an absence may count. 0.9 is a **chosen
#: parameter**, declared as one in the findings document: it is not measured and
#: must never be reported as a result.
MIN_INFORMATIVE_VISIBILITY: float = 0.9

#: Prediction strength at or above which a world's expectation is strong enough
#: for its violation to matter. Also a chosen parameter.
MIN_PREDICTION_STRENGTH: float = 0.7


@runtime_checkable
class PredictingWorld(Protocol):
    """The slice of ``SecurityWorldV1`` negative-evidence reasoning needs.

    Structural rather than nominal on purpose: ``worlds/world.py`` imports
    ``EvidenceTension`` from this package's sibling module, so a runtime import of
    ``SecurityWorldV1`` here would close an import cycle. Typing against the
    behaviour also means a lifecycle test can substitute a minimal world without
    building a full ten-tuple.
    """

    expected_evidence: frozenset[str]
    forbidden_evidence: frozenset[str]
    uncertainty: float


def prediction_strength(world: PredictingWorld | SecurityWorldV1, signal: str) -> float:
    """How strongly ``world`` predicts ``signal``, in [0, 1].

    A forbidden signal is predicted at 0.0 — forbidding something is not a weak
    prediction of it. An expected signal is predicted at ``1 - uncertainty``: a
    world that is only 40% sure of its own mechanism does not get to kill itself
    (or a rival) on the strength of an expectation it half holds. Anything the
    world neither expects nor forbids is 0.0.

    This is where ``MIN_PREDICTION_STRENGTH`` bites: with the default 0.7, a world
    whose uncertainty exceeds 0.3 can never make an absence informative.
    """
    if signal in world.forbidden_evidence:
        return 0.0
    if signal not in world.expected_evidence:
        return 0.0
    return max(0.0, min(1.0, 1.0 - float(world.uncertainty)))


def classify_absence(
    *,
    signal: str,
    world: PredictingWorld | SecurityWorldV1,
    model: VisibilityModel,
    observed: frozenset[str],
) -> tuple[NegativeEvidenceVerdict, str]:
    """Classify the absence of ``signal`` for ``world``. Returns (verdict, reason).

    The reason string is part of the deliverable, not decoration: an incident
    record that says "absence ignored" without saying *why* cannot be audited,
    and this is the exact decision a reviewer will want to re-derive.
    """
    if signal in observed:
        return (
            NegativeEvidenceVerdict.NOT_EXPECTED,
            f"{signal} was observed; absence reasoning does not apply",
        )

    strength = prediction_strength(world, signal)
    if strength < MIN_PREDICTION_STRENGTH:
        return (
            NegativeEvidenceVerdict.NOT_EXPECTED,
            f"world predicts {signal} at {strength:.2f} < {MIN_PREDICTION_STRENGTH:.2f}",
        )

    visibility = best_visibility(model, signal)
    if visibility is None:
        return (
            NegativeEvidenceVerdict.UNKNOWN_ABSENCE,
            f"no visibility evidence for {signal} on any live sensor path (UNMEASURED)",
        )
    if visibility < MIN_INFORMATIVE_VISIBILITY:
        return (
            NegativeEvidenceVerdict.UNKNOWN_ABSENCE,
            f"visibility for {signal} is {visibility:.2f} "
            f"< {MIN_INFORMATIVE_VISIBILITY:.2f}; we cannot show we would have seen it",
        )
    return (
        NegativeEvidenceVerdict.INFORMATIVE_ABSENCE,
        f"visibility {visibility:.2f} and prediction {strength:.2f}: "
        f"{signal} should have been observed and was not",
    )
