"""D3.12 (part) — certificate decay: how a cell's confidence changes with events.

Architecture §28. The one thing this module refuses to do is decay with **time**.
§28 is explicit: "age alone does not automatically make knowledge wrong, but
untested change reduces trust." A time term would be the easiest thing to write
and the most dishonest: it would retire a correct, well-audited cell on a
schedule, and it would let an unaudited cell in a drifting region keep its
confidence simply because the clock had not run out.

So :func:`decay_confidence` takes five **event counts** and nothing else. Its
signature is part of the contract, and the test suite asserts the parameter names
so a later contributor cannot slip ``age_seconds`` in beside them.

Crossing :data:`MIN_ASSURANCE_CONFIDENCE` is never a no-op. :func:`decay_response`
returns the action that must follow — raise the audit rate, or melt — because a
cell that has fallen below the floor and keeps answering at the old rate is the
failure mode the floor exists to prevent.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage3.melting.stress import FULL_MELT_THRESHOLD, PARTIAL_MELT_THRESHOLD

if TYPE_CHECKING:  # pragma: no cover - import-time cost, not behaviour
    from pocketsec.stage3.melting.stress import CellStress

__all__ = [
    "ConfidenceAction",
    "DECAY_EVENT_TERMS",
    "DECAY_TERMS",
    "MIN_ASSURANCE_CONFIDENCE",
    "below_minimum",
    "decay_confidence",
    "decay_response",
]

#: The five coefficients of §28's ``Gamma_(t+1)``, as a named mapping so each can
#: be cited and argued about separately. There is no sixth entry for time, and
#: adding one would be a contract change, not a tuning change.
DECAY_TERMS: Mapping[str, float] = MappingProxyType(
    {
        "successful_audit_credit": 0.010,
        "disagreement_penalty": 0.120,
        "epoch_shift_penalty": 0.080,
        "boundary_violation_penalty": 0.150,
        "unobserved_change_penalty": 0.050,
    }
)

#: The keyword parameters :func:`decay_confidence` accepts, in order. Pinned so
#: the "no time term" property is mechanically checkable rather than a comment.
DECAY_EVENT_TERMS: tuple[str, ...] = (
    "successful_audits",
    "disagreements",
    "epoch_shifts",
    "boundary_violations",
    "unobserved_changes",
)

#: Below this, a cell may not simply carry on. §28: the response is a higher
#: audit rate or a melt, and :func:`decay_response` names which.
MIN_ASSURANCE_CONFIDENCE = 0.35


class ConfidenceAction(StrEnum):
    """What must happen when confidence is read.

    ``CONTINUE`` is only reachable above the floor. There is deliberately no
    "log and carry on" member: the whole point of the floor is that crossing it
    changes behaviour.
    """

    CONTINUE = "CONTINUE"
    RAISE_AUDIT_RATE = "RAISE_AUDIT_RATE"
    PARTIAL_MELT = "PARTIAL_MELT"
    FULL_MELT = "FULL_MELT"


def _require_count(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ContractError(f"{field} must be a non-negative int, got {value!r}")
    return value


def _require_unit(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ContractError(f"{field} must be a real number, got {value!r}")
    number = float(value)
    if not math.isfinite(number) or not 0.0 <= number <= 1.0:
        raise ContractError(f"{field} must lie in [0, 1], got {number!r}")
    return number


def decay_confidence(
    confidence: float,
    *,
    successful_audits: int,
    disagreements: int,
    epoch_shifts: int,
    boundary_violations: int,
    unobserved_changes: int,
) -> float:
    """Update ``Gamma_t`` from observed events only, clamped to [0, 1].

    With every count at zero the value is returned **unchanged**. That fixed
    point is the "no time term" property in executable form: calling this
    function a million times on a quiet host cannot move a cell's confidence by
    a single bit, because nothing was observed.
    """
    current = _require_unit(confidence, "decay_confidence(confidence=)")
    audits = _require_count(successful_audits, "decay_confidence(successful_audits=)")
    disagree = _require_count(disagreements, "decay_confidence(disagreements=)")
    shifts = _require_count(epoch_shifts, "decay_confidence(epoch_shifts=)")
    violations = _require_count(boundary_violations, "decay_confidence(boundary_violations=)")
    unobserved = _require_count(unobserved_changes, "decay_confidence(unobserved_changes=)")

    terms = DECAY_TERMS
    change = (
        terms["successful_audit_credit"] * audits
        - terms["disagreement_penalty"] * disagree
        - terms["epoch_shift_penalty"] * shifts
        - terms["boundary_violation_penalty"] * violations
        - terms["unobserved_change_penalty"] * unobserved
    )
    updated = current + change
    return 0.0 if updated < 0.0 else (1.0 if updated > 1.0 else updated)


def below_minimum(confidence: float) -> bool:
    """Has this cell fallen through the assurance floor?"""
    return _require_unit(confidence, "below_minimum(confidence=)") < MIN_ASSURANCE_CONFIDENCE


def decay_response(confidence: float, *, stress: CellStress) -> ConfidenceAction:
    """The action that must follow a confidence reading. Never "carry on".

    Above the floor the cell keeps answering. Below it, the choice is decided by
    measured stress rather than by confidence alone: a cell that lost confidence
    but shows little stress is under-audited, not wrong, so the answer is more
    auditing. A cell that lost confidence *and* is under stress has a region that
    stopped being true, so the answer is a melt — partial first, because the
    stage's claim is that repair is localised.
    """
    total = float(stress.total)
    if not math.isfinite(total) or total < 0.0:
        raise ContractError(f"decay_response requires a finite non-negative stress, got {total!r}")
    if not below_minimum(confidence):
        return ConfidenceAction.CONTINUE
    if total >= FULL_MELT_THRESHOLD:
        return ConfidenceAction.FULL_MELT
    if total >= PARTIAL_MELT_THRESHOLD:
        return ConfidenceAction.PARTIAL_MELT
    return ConfidenceAction.RAISE_AUDIT_RATE


def _assert_no_time_term() -> None:
    """Fail at import if a time coefficient is ever added to ``DECAY_TERMS``."""
    if set(DECAY_TERMS) != {
        "successful_audit_credit",
        "disagreement_penalty",
        "epoch_shift_penalty",
        "boundary_violation_penalty",
        "unobserved_change_penalty",
    }:
        raise ContractError(
            f"DECAY_TERMS changed shape: {sorted(DECAY_TERMS)}. §28 decays on untested "
            "change, never on age; a new term needs an ADR, not a constant"
        )
    for name, value in DECAY_TERMS.items():
        if not math.isfinite(value) or value <= 0.0:
            raise ContractError(f"DECAY_TERMS[{name!r}] must be finite and > 0, got {value!r}")
    if not 0.0 < MIN_ASSURANCE_CONFIDENCE < 1.0:
        raise ContractError("MIN_ASSURANCE_CONFIDENCE must lie strictly inside (0, 1)")


_assert_no_time_term()
