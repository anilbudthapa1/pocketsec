"""D3.1 — AICT's measurable definitions: consequence, resolution, density, pressure.

The architecture states Stage 3's central quantities as formulas
(``ID(R)``, ``Resolution(R)``, ``Theta_c``, ``KP(R)``). This module turns them
into types that can only hold measured things, because the formulas are where a
stage like this normally starts lying to itself:

* ``Resolution`` is six terms and a ``measured_by`` producer. A resolution state
  with no ``module:function`` that produced it does not exist.
* ``IntelligenceDensity`` uses ``float | None``. ``None`` means UNMEASURED and
  never 0.0, and one ``None`` anywhere makes the derived density ``None``. There
  is no default that turns an unmeasured term into a number.
* ``KnowledgePressure`` deliberately exposes **no** combined ``.score``.
  Architecture §17: "implementation should maintain separate compute-pressure
  and security-pressure components rather than blindly multiplying arbitrary
  scores." A single scalar would let a high-frequency, unpredictable region
  outrank a rare, security-critical one purely by arithmetic.

What this module refuses to do: it will not invent a threshold that is easier
than the one Stage 2 already had to clear. ``THRESHOLDS`` demands at least two
distinct corroborated epochs at every consequence level, matching
``CandidateStability`` ("frequency is not corroboration", ADR-0007). Stage 3 may
not crystallise on weaker evidence than Stage 2 needed to export.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import IntEnum
from types import MappingProxyType
from typing import Any

from pocketsec.stage0.contracts.common import (
    ContractError,
    require_finite_unit_interval,
    require_non_negative_int,
)
from pocketsec.stage1.state.potential import phi
from pocketsec.stage1.state.security_state import SecurityStateV1, StateDelta

__all__ = [
    "HIGH_CONSEQUENCE_DIMENSIONS",
    "IntelligenceDensity",
    "KnowledgePressure",
    "RESOLUTION_TERMS",
    "ResolutionState",
    "ResolutionThreshold",
    "SecurityConsequence",
    "THRESHOLDS",
    "consequence_of",
    "crystallization_allowed",
    "require_producer",
]


class SecurityConsequence(IntEnum):
    """How much it costs to be wrong here (architecture §7).

    Ordered because the crystallisation threshold ``Theta_c`` is a function of
    it: the required evidence rises with consequence, so the enum must support
    ``<``/``>`` rather than being a bag of names.
    """

    ROUTINE = 0
    ELEVATED = 1
    HIGH = 2
    CRITICAL = 3


#: State dimensions whose raise is, on its own, a high-consequence event: these
#: are exactly the capabilities an attacker needs and a benign process rarely
#: gains. Derived from Stage 1's ``MANDATORY_SIGNALS`` reasoning, not fitted.
HIGH_CONSEQUENCE_DIMENSIONS = frozenset({"privilege", "credential", "persistence", "isolation"})

#: The six Resolution terms in ``Resolution(R) = (P, U, V, C, E, D)`` order.
RESOLUTION_TERMS = (
    "predictive_stability",
    "calibrated_uncertainty",
    "validated_breadth",
    "counterfactual_consistency",
    "evidence_agreement",
    "drift_stability",
)


def require_producer(value: object, field: str) -> str:
    """Require a ``module:function`` string naming who produced a number.

    The project's honesty contract turns on one distinction: a number someone
    produced by running code, versus a number that looks plausible. Mirrors
    ``MeasuredCost.measured_by`` (``stage2/compile_candidates/candidate.py``) so
    the two seams reject the same shape for the same reason.
    """
    if not isinstance(value, str) or not value.strip():
        raise ContractError(
            f"{field} must name the 'module:function' that produced the number; "
            "a figure with no producer is UNMEASURED, not zero"
        )
    producer = value.split(":")
    if len(producer) != 2 or not all(part.strip() for part in producer):
        raise ContractError(f"{field} must look like 'module:function', got {value!r}")
    return value


def consequence_of(delta: StateDelta, state: SecurityStateV1) -> SecurityConsequence:
    """Classify how consequential one transition is, from Stage 1 alone.

    No model is consulted. ``CRITICAL`` is "one of Stage 1's ``INTERACTIONS``
    predicates fires on the resulting state" — the combinations that are worth
    more than the sum of their parts (``potential.INTERACTIONS``). We read them
    through the public ``phi(state).active_interactions`` projection rather than
    the private ``_PREDICATES`` table, so this stays correct if the predicate
    implementations move.
    """
    if not isinstance(delta, StateDelta):
        raise ContractError(f"consequence_of expects a StateDelta, got {type(delta).__name__}")
    if not isinstance(state, SecurityStateV1):
        raise ContractError(f"consequence_of expects a SecurityStateV1, got {type(state).__name__}")
    if phi(state).active_interactions:
        return SecurityConsequence.CRITICAL
    if delta.dimensions & HIGH_CONSEQUENCE_DIMENSIONS:
        return SecurityConsequence.HIGH
    if delta:
        return SecurityConsequence.ELEVATED
    return SecurityConsequence.ROUTINE


@dataclass(frozen=True, slots=True)
class ResolutionThreshold:
    """``Theta_c`` — the evidence bar for one consequence level (architecture §7)."""

    min_predictive_stability: float
    max_calibrated_uncertainty: float
    min_validated_breadth: int
    min_counterfactual_consistency: float
    min_evidence_agreement: float
    min_drift_stability: int

    def __post_init__(self) -> None:
        require_finite_unit_interval(
            self.min_predictive_stability, "ResolutionThreshold.min_predictive_stability"
        )
        require_finite_unit_interval(
            self.max_calibrated_uncertainty, "ResolutionThreshold.max_calibrated_uncertainty"
        )
        require_non_negative_int(
            self.min_validated_breadth, "ResolutionThreshold.min_validated_breadth"
        )
        require_finite_unit_interval(
            self.min_counterfactual_consistency,
            "ResolutionThreshold.min_counterfactual_consistency",
        )
        require_finite_unit_interval(
            self.min_evidence_agreement, "ResolutionThreshold.min_evidence_agreement"
        )
        require_non_negative_int(
            self.min_drift_stability, "ResolutionThreshold.min_drift_stability"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "min_predictive_stability": self.min_predictive_stability,
            "max_calibrated_uncertainty": self.max_calibrated_uncertainty,
            "min_validated_breadth": self.min_validated_breadth,
            "min_counterfactual_consistency": self.min_counterfactual_consistency,
            "min_evidence_agreement": self.min_evidence_agreement,
            "min_drift_stability": self.min_drift_stability,
        }


@dataclass(frozen=True, slots=True)
class ResolutionState:
    """``Resolution(R) = (P, U, V, C, E, D)`` — does PocketSec understand this region?

    A region is not resolved because it was seen often. It must predict
    consistently (P), expose its uncertainty (U, where *lower* is better),
    have been validated across breadth (V), survive perturbation (C), agree with
    its evidence (E) and hold across corroborated epochs (D).
    """

    predictive_stability: float
    calibrated_uncertainty: float
    validated_breadth: int
    counterfactual_consistency: float
    evidence_agreement: float
    drift_stability: int
    measured_by: str

    def __post_init__(self) -> None:
        require_finite_unit_interval(
            self.predictive_stability, "ResolutionState.predictive_stability"
        )
        require_finite_unit_interval(
            self.calibrated_uncertainty, "ResolutionState.calibrated_uncertainty"
        )
        require_non_negative_int(self.validated_breadth, "ResolutionState.validated_breadth")
        require_finite_unit_interval(
            self.counterfactual_consistency, "ResolutionState.counterfactual_consistency"
        )
        require_finite_unit_interval(self.evidence_agreement, "ResolutionState.evidence_agreement")
        require_non_negative_int(self.drift_stability, "ResolutionState.drift_stability")
        require_producer(self.measured_by, "ResolutionState.measured_by")

    def unmet(self, threshold: ResolutionThreshold) -> tuple[str, ...]:
        """Name every term that fails ``threshold``, in ``RESOLUTION_TERMS`` order.

        Returns names rather than a bool so a refusal can say *which* evidence is
        missing. An empty tuple is the only thing that means "resolved".
        """
        if not isinstance(threshold, ResolutionThreshold):
            raise ContractError("ResolutionState.unmet expects a ResolutionThreshold")
        failing: list[str] = []
        if self.predictive_stability < threshold.min_predictive_stability:
            failing.append("predictive_stability")
        if self.calibrated_uncertainty > threshold.max_calibrated_uncertainty:
            failing.append("calibrated_uncertainty")
        if self.validated_breadth < threshold.min_validated_breadth:
            failing.append("validated_breadth")
        if self.counterfactual_consistency < threshold.min_counterfactual_consistency:
            failing.append("counterfactual_consistency")
        if self.evidence_agreement < threshold.min_evidence_agreement:
            failing.append("evidence_agreement")
        if self.drift_stability < threshold.min_drift_stability:
            failing.append("drift_stability")
        return tuple(failing)

    def to_dict(self) -> dict[str, Any]:
        return {
            "predictive_stability": self.predictive_stability,
            "calibrated_uncertainty": self.calibrated_uncertainty,
            "validated_breadth": self.validated_breadth,
            "counterfactual_consistency": self.counterfactual_consistency,
            "evidence_agreement": self.evidence_agreement,
            "drift_stability": self.drift_stability,
            "measured_by": self.measured_by,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ResolutionState:
        try:
            return cls(
                predictive_stability=float(payload["predictive_stability"]),
                calibrated_uncertainty=float(payload["calibrated_uncertainty"]),
                validated_breadth=int(payload["validated_breadth"]),
                counterfactual_consistency=float(payload["counterfactual_consistency"]),
                evidence_agreement=float(payload["evidence_agreement"]),
                drift_stability=int(payload["drift_stability"]),
                measured_by=str(payload["measured_by"]),
            )
        except KeyError as exc:
            raise ContractError(f"ResolutionState missing field {exc.args[0]!r}") from exc


#: ``Theta_c`` over all four consequence levels. Rising with consequence, which
#: is asserted below rather than trusted: a later edit that accidentally makes
#: CRITICAL easier than ROUTINE fails at import, not in production.
#:
#: ``min_drift_stability >= 2`` everywhere is not arbitrary. Stage 2's
#: ``CandidateStability`` refuses to call anything stable on one epoch, and
#: Stage 3 compiling on weaker corroboration than Stage 2 needed to *propose*
#: would reintroduce exactly the poisoning path ADR-0007 closed.
THRESHOLDS: Mapping[SecurityConsequence, ResolutionThreshold] = MappingProxyType(
    {
        SecurityConsequence.ROUTINE: ResolutionThreshold(
            min_predictive_stability=0.80,
            max_calibrated_uncertainty=0.35,
            min_validated_breadth=2,
            min_counterfactual_consistency=0.70,
            min_evidence_agreement=0.80,
            min_drift_stability=2,
        ),
        SecurityConsequence.ELEVATED: ResolutionThreshold(
            min_predictive_stability=0.90,
            max_calibrated_uncertainty=0.25,
            min_validated_breadth=4,
            min_counterfactual_consistency=0.80,
            min_evidence_agreement=0.90,
            min_drift_stability=2,
        ),
        SecurityConsequence.HIGH: ResolutionThreshold(
            min_predictive_stability=0.95,
            max_calibrated_uncertainty=0.15,
            min_validated_breadth=8,
            min_counterfactual_consistency=0.90,
            min_evidence_agreement=0.95,
            min_drift_stability=2,
        ),
        SecurityConsequence.CRITICAL: ResolutionThreshold(
            min_predictive_stability=0.99,
            max_calibrated_uncertainty=0.05,
            min_validated_breadth=16,
            min_counterfactual_consistency=0.97,
            min_evidence_agreement=0.99,
            min_drift_stability=3,
        ),
    }
)


def crystallization_allowed(
    resolution: ResolutionState, consequence: SecurityConsequence
) -> tuple[bool, tuple[str, ...]]:
    """``Crystallize(R) only if Resolution(R) >= Theta_c(SecurityConsequence(R))``.

    Returns the decision *and* the unmet term names, so a caller can record why
    a region stayed on the learned path instead of reporting a bare ``False``.
    """
    if consequence not in THRESHOLDS:
        raise ContractError(f"no crystallisation threshold for {consequence!r}")
    unmet = resolution.unmet(THRESHOLDS[consequence])
    return (not unmet, unmet)


@dataclass(frozen=True, slots=True)
class IntelligenceDensity:
    """``ID(R)`` — security-relevant utility per unit of **measured** cost (§5).

    Every cost term is ``float | None`` / ``int | None`` because the architecture
    is explicit that cost "must be measured, not inferred from parameter count
    alone". ``None`` is UNMEASURED. It is not zero, and it is not "fast".
    """

    utility: float | None
    microseconds_per_event: float | None
    resident_bytes: int | None
    audit_cost_per_event: float | None
    measured_by: str

    def __post_init__(self) -> None:
        if self.utility is not None:
            require_finite_unit_interval(self.utility, "IntelligenceDensity.utility")
        for name in ("microseconds_per_event", "audit_cost_per_event"):
            value = getattr(self, name)
            if value is None:
                continue
            if not isinstance(value, float) or value != value or value < 0.0:
                raise ContractError(
                    f"IntelligenceDensity.{name} must be None (UNMEASURED) or a finite "
                    f"float >= 0, got {value!r}"
                )
        if self.resident_bytes is not None:
            require_non_negative_int(self.resident_bytes, "IntelligenceDensity.resident_bytes")
        require_producer(self.measured_by, "IntelligenceDensity.measured_by")

    @property
    def measured(self) -> bool:
        """``False`` means at least one term is UNMEASURED. It never means free."""
        return None not in (
            self.utility,
            self.microseconds_per_event,
            self.resident_bytes,
            self.audit_cost_per_event,
        )

    @property
    def density(self) -> float | None:
        """Utility per microsecond of measured cost, or ``None``.

        ``None`` in two distinct cases, both of which must not become a number:

        * any term is UNMEASURED — one missing measurement poisons the ratio;
        * the measured cost is **zero**. A ratio with a zero denominator is
          undefined, not infinite. This is the live case, not a corner: the
          Φ-oracle costs ~0 µs/event, and an "infinite density" headline would
          be the exact kind of number this project refuses to print.

        ``resident_bytes`` is required to be measured but deliberately **not**
        folded into the denominator. Bytes and microseconds are not commensurable
        and summing them would be the same error §17 names for pressure.
        """
        if not self.measured:
            return None
        assert self.utility is not None  # narrowed by `measured`
        assert self.microseconds_per_event is not None
        assert self.audit_cost_per_event is not None
        cost = self.microseconds_per_event + self.audit_cost_per_event
        if cost <= 0.0:
            return None
        return self.utility / cost

    def to_dict(self) -> dict[str, Any]:
        return {
            "utility": self.utility,
            "microseconds_per_event": self.microseconds_per_event,
            "resident_bytes": self.resident_bytes,
            "audit_cost_per_event": self.audit_cost_per_event,
            "measured_by": self.measured_by,
            "density": self.density,
        }


@dataclass(frozen=True, slots=True)
class KnowledgePressure:
    """``KP(R)`` — where compilation effort is worth spending (§17).

    **There is no combined ``.score`` and there must never be one.** Architecture
    §17: "implementation should maintain separate compute-pressure and
    security-pressure components rather than blindly multiplying arbitrary
    scores." A single product lets a high-frequency, unpredictable region outrank
    a rare, security-critical one by arithmetic alone, which is the opposite of
    what the two components exist to express.

    ``security_pressure`` is deliberately frequency-free for the same reason: a
    rare but security-critical region keeps its validation priority.
    """

    frequency: int
    measured_teacher_cost_us: float | None
    predictability: float
    security_utility: float

    def __post_init__(self) -> None:
        require_non_negative_int(self.frequency, "KnowledgePressure.frequency")
        if self.measured_teacher_cost_us is not None:
            value = self.measured_teacher_cost_us
            if not isinstance(value, float) or value != value or value < 0.0:
                raise ContractError(
                    f"KnowledgePressure.measured_teacher_cost_us must be None (UNMEASURED) "
                    f"or a finite float >= 0, got {value!r}"
                )
        require_finite_unit_interval(self.predictability, "KnowledgePressure.predictability")
        require_finite_unit_interval(self.security_utility, "KnowledgePressure.security_utility")

    @property
    def compute_pressure(self) -> float | None:
        """Expected compute saved, discounted by how compilable the region is.

        ``None`` when the teacher cost was never measured. Stage 3's teacher is
        a frozen snapshot, so "we did not time it" is a real state and must not
        silently read as "it is free".
        """
        if self.measured_teacher_cost_us is None:
            return None
        return self.frequency * self.measured_teacher_cost_us * self.predictability

    @property
    def security_pressure(self) -> float:
        """Validation priority. Frequency is absent on purpose (§17)."""
        return self.security_utility * self.predictability

    def to_dict(self) -> dict[str, Any]:
        return {
            "frequency": self.frequency,
            "measured_teacher_cost_us": self.measured_teacher_cost_us,
            "predictability": self.predictability,
            "security_utility": self.security_utility,
            "compute_pressure": self.compute_pressure,
            "security_pressure": self.security_pressure,
        }


def _assert_thresholds_rise_with_consequence() -> None:
    """Fail at import if ``Theta_c`` ever stops rising with consequence."""
    levels = sorted(THRESHOLDS)
    assert set(levels) == set(SecurityConsequence), "THRESHOLDS must cover every consequence"
    for lower, higher in zip(levels, levels[1:], strict=False):
        low, high = THRESHOLDS[lower], THRESHOLDS[higher]
        assert high.min_predictive_stability >= low.min_predictive_stability
        assert high.max_calibrated_uncertainty <= low.max_calibrated_uncertainty
        assert high.min_validated_breadth >= low.min_validated_breadth
        assert high.min_counterfactual_consistency >= low.min_counterfactual_consistency
        assert high.min_evidence_agreement >= low.min_evidence_agreement
        assert high.min_drift_stability >= low.min_drift_stability


_assert_thresholds_rise_with_consequence()
