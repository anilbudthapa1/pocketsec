"""The bounded Resolution Horizon of architecture §20 — how long Stage 4 may keep thinking.

This module exists to stop endless reasoning loops without letting the stop itself
become a lie. An incident that runs out of budget has *not* been resolved, and the
one thing this module refuses to do is let exhaustion look like an answer:
``outcome()`` can never return ``RESOLVED`` for a non-committal verdict, and there is
no code path here that produces ``Verdict.BENIGN``. Architecture §29 states the rule
this module enforces: "It cannot silently simplify into benign."

The primary budget is a deterministic **work-unit** counter, not wall-clock time.
Milliseconds on this host swung 7x between load 8-12 and load 23-67 (`PROGRESS.md`,
cited, not measured here), so a millisecond bound would make the horizon a coin flip
and its test unreproducible. Transitions, work units and escalations are all counted,
all hard, and all charged immutably.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from pocketsec.stage0.contracts.common import ContractError, require_non_negative_int

if TYPE_CHECKING:  # pragma: no cover - typing only, and deliberately one-directional
    from pocketsec.stage4.identifiability.resolution import IdentifiabilityVerdict

__all__ = [
    "DEFAULT_HORIZON_ESCALATIONS",
    "DEFAULT_HORIZON_TRANSITIONS",
    "DEFAULT_HORIZON_WORK_UNITS",
    "HorizonOutcome",
    "ResolutionHorizon",
    "VerdictLike",
]

#: Transitions one incident may consume before the horizon closes. 64 is the low end
#: of a deliberately small range: an incident that has not separated its leaders in 64
#: transitions is a case for an analyst, not for more compute.
DEFAULT_HORIZON_TRANSITIONS: int = 64

#: Deterministic reasoning work units. This is the contract; see the module docstring
#: for why it is not milliseconds.
DEFAULT_HORIZON_WORK_UNITS: int = 4096

#: Observation escalations one incident may request. Stage 1's ``AOPBudget`` caps
#: escalation globally; this caps it *per incident* so one ambiguous incident cannot
#: spend the whole host's observation budget.
DEFAULT_HORIZON_ESCALATIONS: int = 4


class HorizonOutcome(StrEnum):
    """§20's four permitted endings. There is deliberately no fifth."""

    RESOLVED = "RESOLVED"
    ESCALATE_TO_ANALYST = "ESCALATE_TO_ANALYST"
    PRESERVE_UNRESOLVED = "PRESERVE_UNRESOLVED"
    REQUEST_HIGHER_OBSERVATION_TIER = "REQUEST_HIGHER_OBSERVATION_TIER"


@runtime_checkable
class VerdictLike(Protocol):
    """The slice of an identifiability verdict the horizon reads.

    Declared as a protocol so this module imports nothing from ``resolution`` at
    runtime: ``resolution`` needs the horizon constants, the horizon needs a verdict,
    and a protocol is how that stays a one-way dependency instead of a cycle.
    """

    @property
    def state(self) -> object: ...

    def abstains(self) -> bool: ...


@dataclass(frozen=True, slots=True)
class ResolutionHorizon:
    """A bounded reasoning budget, charged immutably.

    ``charge()`` returns a new horizon rather than mutating this one. That is not
    style: the oscillation and truncation checks elsewhere in Stage 4 compare a field
    against its own predecessor, and a mutated budget destroys the predecessor.
    """

    max_transitions: int = DEFAULT_HORIZON_TRANSITIONS
    max_work_units: int = DEFAULT_HORIZON_WORK_UNITS
    max_escalations: int = DEFAULT_HORIZON_ESCALATIONS
    consumed_transitions: int = 0
    consumed_work_units: int = 0
    consumed_escalations: int = 0

    def __post_init__(self) -> None:
        for name in (
            "max_transitions",
            "max_work_units",
            "max_escalations",
            "consumed_transitions",
            "consumed_work_units",
            "consumed_escalations",
        ):
            require_non_negative_int(getattr(self, name), f"ResolutionHorizon.{name}")
        if self.max_transitions == 0 or self.max_work_units == 0:
            raise ContractError(
                "ResolutionHorizon.max_transitions and max_work_units must be positive; "
                "a zero budget is exhausted before it starts and hides the real bound"
            )

    # --- budget ---------------------------------------------------------

    def exhausted(self) -> bool:
        """True once any one of the three budgets is spent.

        Any, not all: a horizon that kept reasoning because two of three budgets
        remained would not be a bound.
        """
        return (
            self.consumed_transitions >= self.max_transitions
            or self.consumed_work_units >= self.max_work_units
            or self.consumed_escalations >= self.max_escalations
        )

    def escalations_remaining(self) -> int:
        return max(0, self.max_escalations - self.consumed_escalations)

    def charge(
        self, *, transitions: int = 0, work_units: int = 0, escalations: int = 0
    ) -> ResolutionHorizon:
        """Return a new horizon with the charge applied.

        Charges are clamped at the maximum rather than allowed to overrun, so
        ``consumed_*`` is always a readable fraction of the bound and a caller cannot
        report "spent 9000 of 4096".
        """
        for value, name in (
            (transitions, "transitions"),
            (work_units, "work_units"),
            (escalations, "escalations"),
        ):
            require_non_negative_int(value, f"ResolutionHorizon.charge.{name}")
        return replace(
            self,
            consumed_transitions=min(
                self.max_transitions, self.consumed_transitions + transitions
            ),
            consumed_work_units=min(self.max_work_units, self.consumed_work_units + work_units),
            consumed_escalations=min(
                self.max_escalations, self.consumed_escalations + escalations
            ),
        )

    # --- the ending -----------------------------------------------------

    def outcome(self, verdict: IdentifiabilityVerdict | VerdictLike) -> HorizonOutcome:
        """Route an identifiability verdict to one of §20's four endings.

        The guarantees this method is here to provide, in the order they matter:

        1. ``RESOLVED`` requires a committal verdict. An abstaining verdict can never
           be reported as resolved, whatever the budget says.
        2. Exhaustion never manufactures an answer. An exhausted horizon on a
           non-committal verdict goes to an analyst or is preserved unresolved; it
           does not collapse into benign (§29).
        3. ``UNIDENTIFIABLE`` is preserved, not escalated forever. Asking an analyst
           to look harder at a case that no affordable observation can separate wastes
           the one scarce resource in the loop.
        """
        state_name = _state_name(verdict)
        abstains = bool(verdict.abstains())

        if state_name == "IDENTIFIED" and not abstains:
            return HorizonOutcome.RESOLVED

        if state_name == "UNIDENTIFIABLE":
            # Genuinely non-identifiable: more budget cannot help, and neither can an
            # analyst re-reading the same telemetry. Preserve it as what it is.
            return HorizonOutcome.PRESERVE_UNRESOLVED

        if self.exhausted():
            return HorizonOutcome.ESCALATE_TO_ANALYST

        if state_name in ("INSUFFICIENT_EVIDENCE", "UNKNOWN") and self.escalations_remaining() > 0:
            return HorizonOutcome.REQUEST_HIGHER_OBSERVATION_TIER

        return HorizonOutcome.ESCALATE_TO_ANALYST

    def to_dict(self) -> dict[str, int]:
        return {
            "max_transitions": self.max_transitions,
            "max_work_units": self.max_work_units,
            "max_escalations": self.max_escalations,
            "consumed_transitions": self.consumed_transitions,
            "consumed_work_units": self.consumed_work_units,
            "consumed_escalations": self.consumed_escalations,
        }


def _state_name(verdict: IdentifiabilityVerdict | VerdictLike) -> str:
    """Read the verdict's state as a plain name.

    Duck-typed on purpose: see ``VerdictLike``. A malformed verdict is refused here
    rather than silently routed to ``ESCALATE_TO_ANALYST``, because a silent default
    would make a broken identifiability engine look like a busy one.
    """
    state = getattr(verdict, "state", None)
    name = getattr(state, "value", None) or getattr(state, "name", None)
    if not isinstance(name, str):
        raise ContractError(
            f"ResolutionHorizon.outcome needs a verdict with a named state, got {verdict!r}"
        )
    if not callable(getattr(verdict, "abstains", None)):
        raise ContractError("ResolutionHorizon.outcome needs a verdict with abstains()")
    return name
