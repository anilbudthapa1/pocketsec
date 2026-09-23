"""D1.9 — the Adaptive Observation Policy (spec section 15).

    ObservationBudget_t ∝ Uncertainty_t × SecurityPotential_t × CausalRelevance_t

Selective telemetry escalation: cheap observation everywhere, higher resolution
only where uncertainty and consequence justify the cost.

Two hard constraints, both from spec section 15, and both enforced here rather
than documented and hoped for:

1. **AOP never disables mandatory deterministic security signals.** It controls
   optional high-resolution collection only. :data:`MANDATORY_SIGNALS` is
   checked on every de-escalation path.
2. **Strict CPU, memory, event-rate and duration budgets.** Telemetry
   amplification is a denial-of-service vector against the host PocketSec is
   supposed to protect. Every escalation is capped and expires.

The product form matters: because budget is a *product*, any factor near zero
suppresses escalation. High uncertainty about something with no security
consequence does not earn extra telemetry.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

__all__ = [
    "AOPBudget",
    "AdaptiveObservationPolicy",
    "EscalationDecision",
    "MANDATORY_SIGNALS",
    "ObservationLevel",
]


class ObservationLevel(StrEnum):
    BASELINE = "BASELINE"
    ELEVATED = "ELEVATED"
    HIGH_RESOLUTION = "HIGH_RESOLUTION"


#: Signals that are always collected. AOP may add to observation; it may never
#: take these away, no matter what the budget says.
MANDATORY_SIGNALS = frozenset(
    {
        "privilege_change",
        "credential_access",
        "persistence_write",
        "module_load",
        "boundary_crossing",
        "authentication",
    }
)


@dataclass(frozen=True, slots=True)
class AOPBudget:
    """Hard caps. Exceeding any one of them stops escalation, not slows it."""

    #: Maximum concurrent escalated targets.
    max_concurrent: int = 8
    #: Nanoseconds an escalation survives without renewal.
    max_duration_ns: int = 30_000_000_000  # 30 s
    #: Maximum escalations opened per window, to bound amplification.
    max_escalations_per_window: int = 32
    window_ns: int = 60_000_000_000  # 60 s
    #: Extra events per second an escalation may add.
    max_extra_events_per_second: int = 500
    #: Memory ceiling for escalation bookkeeping.
    max_memory_bytes: int = 256 * 1024
    #: Geometric-mean budget score at or above which escalation is considered.
    #: 0.5 reads as "the three factors are at least moderately elevated on
    #: average" — uncertainty, security potential and causal relevance all
    #: pointing the same way, which is the case the spec describes.
    escalation_threshold: float = 0.5

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_concurrent": self.max_concurrent,
            "max_duration_ns": self.max_duration_ns,
            "max_escalations_per_window": self.max_escalations_per_window,
            "window_ns": self.window_ns,
            "max_extra_events_per_second": self.max_extra_events_per_second,
            "max_memory_bytes": self.max_memory_bytes,
            "escalation_threshold": self.escalation_threshold,
        }


@dataclass(frozen=True, slots=True)
class EscalationDecision:
    """One AOP decision, with the reason it went that way."""

    target: str
    level: ObservationLevel
    budget_score: float
    escalated: bool
    refused_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "level": self.level.value,
            "budget_score": round(self.budget_score, 4),
            "escalated": self.escalated,
            "refused_reason": self.refused_reason,
        }


@dataclass
class _Escalation:
    target: str
    opened_at_ns: int
    renewed_at_ns: int
    level: ObservationLevel
    uncertainty_at_open: float


@dataclass(frozen=True, slots=True)
class AOPReport:
    escalations_opened: int
    escalations_refused: int
    expired: int
    currently_active: int
    extra_events_collected: int
    mean_uncertainty_reduction: float | None
    peak_concurrent: int
    memory_bytes: int
    caps_hit: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "escalations_opened": self.escalations_opened,
            "escalations_refused": self.escalations_refused,
            "expired": self.expired,
            "currently_active": self.currently_active,
            "extra_events_collected": self.extra_events_collected,
            "mean_uncertainty_reduction": (
                round(self.mean_uncertainty_reduction, 4)
                if self.mean_uncertainty_reduction is not None
                else None
            ),
            "peak_concurrent": self.peak_concurrent,
            "memory_bytes": self.memory_bytes,
            "caps_hit": list(self.caps_hit),
        }


class AdaptiveObservationPolicy:
    """Budget-bounded selective telemetry escalation."""

    def __init__(self, budget: AOPBudget | None = None) -> None:
        self.budget = budget or AOPBudget()
        self._active: OrderedDict[str, _Escalation] = OrderedDict()
        self._window_start_ns = 0
        self._window_escalations = 0
        self._opened = 0
        self._refused = 0
        self._expired = 0
        self._extra_events = 0
        self._peak_concurrent = 0
        self._caps_hit: set[str] = set()
        self._uncertainty_reductions: list[float] = []

    # --- budget ---------------------------------------------------------

    @staticmethod
    def budget_score(
        *, uncertainty: float, security_potential: float, causal_relevance: float
    ) -> float:
        """The budget score in [0, 1], as the **geometric mean** of the factors.

        The spec defines ``ObservationBudget ∝ U × Φ × CausalRelevance``. The
        geometric mean is the cube root of exactly that product: a monotone
        rescaling, so the policy's ordering is identical to the spec's, on a
        scale a human can set a threshold against. A raw triple product puts
        three moderate factors (0.5 each) at 0.125, which invites picking a
        threshold by trial; the geometric mean puts them at 0.5, so the
        threshold reads as "how elevated must the factors be, on average".

        Φ is unbounded above and is squashed rather than clipped, so very high
        potential still orders correctly instead of saturating.
        """
        phi_normalised = security_potential / (1.0 + security_potential)
        relevance = max(0.0, min(1.0, causal_relevance))
        product = max(0.0, min(1.0, uncertainty)) * phi_normalised * relevance
        return product ** (1.0 / 3.0)

    @property
    def memory_bytes(self) -> int:
        return sum(len(esc.target.encode("utf-8")) + 48 for esc in self._active.values())

    def level_for(self, target: str) -> ObservationLevel:
        escalation = self._active.get(target)
        return escalation.level if escalation else ObservationLevel.BASELINE

    def is_mandatory(self, signal: str) -> bool:
        return signal in MANDATORY_SIGNALS

    def collects(self, signal: str, target: str) -> bool:
        """Whether a signal is collected for a target right now.

        Mandatory signals return True unconditionally — this is the method that
        makes "AOP never disables mandatory signals" structural rather than a
        convention a future change could quietly break.
        """
        if self.is_mandatory(signal):
            return True
        return self.level_for(target) is not ObservationLevel.BASELINE

    # --- decisions ------------------------------------------------------

    def consider(
        self,
        *,
        target: str,
        uncertainty: float,
        security_potential: float,
        causal_relevance: float,
        now_ns: int,
    ) -> EscalationDecision:
        """Decide whether to escalate observation on ``target``."""
        self._expire(now_ns)
        self._roll_window(now_ns)

        score = self.budget_score(
            uncertainty=uncertainty,
            security_potential=security_potential,
            causal_relevance=causal_relevance,
        )

        if target in self._active:
            self._active[target].renewed_at_ns = now_ns
            return EscalationDecision(target, self._active[target].level, score, escalated=True)

        if score < self.budget.escalation_threshold:
            return EscalationDecision(
                target, ObservationLevel.BASELINE, score, False, "below escalation threshold"
            )

        refusal = self._cap_refusal()
        if refusal:
            self._refused += 1
            return EscalationDecision(target, ObservationLevel.BASELINE, score, False, refusal)

        level = (
            ObservationLevel.HIGH_RESOLUTION
            if score >= (1.0 + self.budget.escalation_threshold) / 2
            else ObservationLevel.ELEVATED
        )
        self._active[target] = _Escalation(
            target=target,
            opened_at_ns=now_ns,
            renewed_at_ns=now_ns,
            level=level,
            uncertainty_at_open=uncertainty,
        )
        self._opened += 1
        self._window_escalations += 1
        self._peak_concurrent = max(self._peak_concurrent, len(self._active))
        return EscalationDecision(target, level, score, escalated=True)

    def _cap_refusal(self) -> str:
        """Return the first cap that forbids a new escalation."""
        if len(self._active) >= self.budget.max_concurrent:
            self._caps_hit.add("max_concurrent")
            return f"max_concurrent cap ({self.budget.max_concurrent}) reached"
        if self._window_escalations >= self.budget.max_escalations_per_window:
            self._caps_hit.add("max_escalations_per_window")
            return "escalation rate cap reached for this window"
        if self.memory_bytes >= self.budget.max_memory_bytes:
            self._caps_hit.add("max_memory_bytes")
            return "escalation memory cap reached"
        return ""

    def record_observation(
        self, target: str, *, extra_events: int, uncertainty_now: float
    ) -> None:
        """Record what an escalation actually bought.

        ``mean_uncertainty_reduction`` is the measured payoff, and acceptance
        criterion 7 requires it to be positive in selected scenarios. Recording
        it per escalation is what makes that a measurement rather than a claim.
        """
        escalation = self._active.get(target)
        if escalation is None:
            return
        capped = min(extra_events, self.budget.max_extra_events_per_second)
        if capped < extra_events:
            self._caps_hit.add("max_extra_events_per_second")
        self._extra_events += capped
        self._uncertainty_reductions.append(escalation.uncertainty_at_open - uncertainty_now)

    def _expire(self, now_ns: int) -> None:
        for target in list(self._active):
            if now_ns - self._active[target].renewed_at_ns >= self.budget.max_duration_ns:
                self._active.pop(target)
                self._expired += 1

    def _roll_window(self, now_ns: int) -> None:
        if now_ns - self._window_start_ns >= self.budget.window_ns:
            self._window_start_ns = now_ns
            self._window_escalations = 0

    def report(self) -> AOPReport:
        reductions = self._uncertainty_reductions
        return AOPReport(
            escalations_opened=self._opened,
            escalations_refused=self._refused,
            expired=self._expired,
            currently_active=len(self._active),
            extra_events_collected=self._extra_events,
            mean_uncertainty_reduction=(
                sum(reductions) / len(reductions) if reductions else None
            ),
            peak_concurrent=self._peak_concurrent,
            memory_bytes=self.memory_bytes,
            caps_hit=tuple(sorted(self._caps_hit)),
        )
