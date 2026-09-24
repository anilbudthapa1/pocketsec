"""DTL-F12 — value-of-information feedback into Stage 1's observation policy.

Architecture spec section 19: request extra telemetry only when its expected
reduction in decision uncertainty justifies the collection cost.

    VoI = expected uncertainty reduction / collection cost

The hard constraint that shapes every line here: **Stage 2 never builds a second
observation path.** It computes a need, hands it to Stage 1's
:class:`~pocketsec.stage1.observation.policy.AdaptiveObservationPolicy`, and
lives with the answer. Telemetry amplification is a denial-of-service vector
against the host PocketSec is supposed to protect, and there is exactly one
component allowed to be the throttle.

What this module refuses to do:

* **It refuses to retry a refusal.** A refused target is recorded and not asked
  again by the same tracker. Retrying is how a bounded budget becomes an
  unbounded one.
* **It refuses to disable a mandatory signal.** ``MANDATORY_SIGNALS`` is checked
  before and after every request; if collection of one ever stops, that is a
  :class:`ContractError`, not a trade-off.
* **It refuses to report a reduction it did not observe.**
  ``VoIReport.measured_reduction`` stays ``None`` until an observation actually
  came back and uncertainty was re-estimated. UNMEASURED is not zero.

Whether this beats the simple control — Stage 1's existing uncertainty threshold
on its own, :func:`uncertainty_only_requests` — is an open measurement, not an
assumption. The VoI weighting below is a stated policy heuristic; no measured
result yet says it is better.

Stdlib only. D2.9's ``UncertaintyEstimate`` and D2.8's ``FutureCone`` are
consumed through their documented shapes, not imported at module scope.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.observation.policy import (
    MANDATORY_SIGNALS,
    AdaptiveObservationPolicy,
    EscalationDecision,
    ObservationLevel,
)
from pocketsec.stage2.counterfactual.twin import ConeView, expected_delta_phi

if TYPE_CHECKING:  # pragma: no cover - typing only, never imported at runtime
    from pocketsec.stage2.uncertainty.abstention import UncertaintyEstimate

__all__ = [
    "COLLECTION_COST_FLOOR",
    "MAX_INFORMATION_NEEDS",
    "MIN_VALUE_OF_INFORMATION",
    "REDUCIBLE_SOURCES",
    "InformationNeed",
    "InformationNeedTracker",
    "VoIReport",
    "assert_mandatory_signals_intact",
    "estimate_information_need",
    "request_observation_escalation",
    "uncertainty_only_requests",
]

#: Uncertainty sources that *more observation* can actually reduce. Entropy and
#: prototype distance are properties of the model's own limits: collecting more
#: telemetry about an event the model simply cannot place does not help, and
#: pretending otherwise is how an observation budget gets burned on nothing.
REDUCIBLE_SOURCES: frozenset[str] = frozenset(
    {"EVIDENCE_INCOMPLETE", "CONE_AMBIGUITY"}
)

#: VoI at or above which collection is proposed. A policy threshold, not a
#: measured optimum — the point of the control comparison is to find out whether
#: any threshold on this quantity beats thresholding uncertainty alone.
MIN_VALUE_OF_INFORMATION: float = 0.1

#: Cost of one escalation with an empty budget. Cost rises towards 2.0 as AOP's
#: concurrency fills, so the same need is worth less when the budget is scarce.
COLLECTION_COST_FLOOR: float = 1.0

#: Requests one tracker retains. Bounded like every other Stage 2 structure.
MAX_INFORMATION_NEEDS: int = 64


@dataclass(frozen=True, slots=True)
class InformationNeed:
    """What extra observation would be worth, and what it would cost."""

    target: str
    expected_uncertainty_reduction: float
    #: In AOP budget units, not seconds.
    collection_cost: float
    #: reduction / cost — the quantity whose usefulness is being tested.
    value_of_information: float
    worth_collecting: bool
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "expected_uncertainty_reduction": round(
                self.expected_uncertainty_reduction, 4
            ),
            "collection_cost": round(self.collection_cost, 4),
            "value_of_information": round(self.value_of_information, 4),
            "worth_collecting": self.worth_collecting,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class VoIReport:
    """What the active perception loop asked for and what it got."""

    requests: tuple[InformationNeed, ...]
    escalations_requested: int
    escalations_granted: int
    escalations_refused: int
    #: ``None`` until an observation came back and uncertainty was re-estimated.
    measured_reduction: float | None
    #: Requests dropped because the tracker is bounded. Truncation is explicit.
    truncated: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "requests": [need.to_dict() for need in self.requests],
            "escalations_requested": self.escalations_requested,
            "escalations_granted": self.escalations_granted,
            "escalations_refused": self.escalations_refused,
            "measured_reduction": (
                round(self.measured_reduction, 4)
                if self.measured_reduction is not None
                else None
            ),
            "truncated": self.truncated,
        }


def assert_mandatory_signals_intact(
    policy: AdaptiveObservationPolicy, *, target: str
) -> None:
    """Raise unless every mandatory signal is still collected for ``target``.

    Stage 1 makes this structurally true (``collects`` short-circuits on
    ``MANDATORY_SIGNALS``). Checking it anyway is cheap, and it means a future
    change to the policy — or a caller that substitutes its own — cannot let
    Stage 2's feedback loop be the thing that turned a deterministic security
    signal off.
    """
    for signal in sorted(MANDATORY_SIGNALS):
        if not policy.collects(signal, target):
            raise ContractError(
                f"mandatory signal {signal!r} is not collected for {target!r}; "
                "AOP may never disable a mandatory signal"
            )


def _cone_ambiguity(cone: ConeView | None) -> float:
    """How unresolved a predicted future is, in [0, 1].

    Both terms matter: explicit unknown mass, and a resolved-but-undecided
    spread across branches. Taking the max keeps either one from hiding the
    other behind an average.
    """
    if cone is None:
        return 1.0
    probabilities = [float(b.probability) for b in cone.branches if b.probability > 0.0]
    unresolved = min(1.0, max(0.0, float(getattr(cone, "unresolved_mass", 0.0))))
    if len(probabilities) < 2:
        return unresolved
    total = sum(probabilities)
    if total <= 0.0:
        return 1.0
    entropy = -sum(
        (p / total) * math.log2(p / total) for p in probabilities
    )
    return max(unresolved, entropy / math.log2(len(probabilities)))


def _reducible_share(sources: dict[str, float]) -> tuple[float, str]:
    """Fraction of the uncertainty that more telemetry could plausibly remove."""
    total = sum(abs(value) for value in sources.values())
    if total <= 0.0:
        # No source breakdown means we cannot tell what is reducible. The honest
        # response is to claim no expected benefit, not to guess one.
        return 0.0, "no uncertainty sources reported; reducible share unknown"
    reducible = sum(
        abs(value) for name, value in sources.items() if name in REDUCIBLE_SOURCES
    )
    return reducible / total, f"reducible share {reducible / total:.3f}"


def estimate_information_need(
    estimate: UncertaintyEstimate,
    cone: ConeView | None,
    policy: AdaptiveObservationPolicy,
    *,
    target: str,
) -> InformationNeed:
    """Compute VoI for one target without asking for anything yet."""
    share, share_detail = _reducible_share(dict(estimate.sources))
    ambiguity = _cone_ambiguity(cone)
    # The ambiguity weight never drops below 0.5: the reducible share is already
    # the dominant discount, and discounting twice would suppress collection
    # even where the cone is confidently pointing at a bad outcome.
    weight = (1.0 + ambiguity) / 2.0
    reduction = max(0.0, min(1.0, float(estimate.value))) * share * weight
    active = policy.report().currently_active
    cost = COLLECTION_COST_FLOOR + active / max(1, policy.budget.max_concurrent)
    voi = reduction / cost
    return InformationNeed(
        target=target,
        expected_uncertainty_reduction=reduction,
        collection_cost=cost,
        value_of_information=voi,
        worth_collecting=voi >= MIN_VALUE_OF_INFORMATION,
        detail=(
            f"{share_detail}; cone_ambiguity {ambiguity:.3f}; "
            f"active_escalations {active}"
        ),
    )


def request_observation_escalation(
    estimate: UncertaintyEstimate,
    cone: ConeView | None,
    policy: AdaptiveObservationPolicy,
    *,
    target: str,
    now_ns: int,
    security_potential: float | None = None,
    causal_relevance: float = 1.0,
) -> tuple[InformationNeed, EscalationDecision]:
    """DTL-F12. Ask Stage 1's AOP for more telemetry, and accept its answer.

    ``security_potential`` defaults to the cone's probability-weighted ΔΦ — a
    *predicted* consequence, which is the only consequence Stage 2 has at this
    point. ``causal_relevance`` defaults to the permissive 1.0; a caller that
    has Stage 1's lineage cumulative responsibility should pass it, because that
    is the factor the AOP budget was designed around and 1.0 removes it from the
    product.
    """
    assert_mandatory_signals_intact(policy, target=target)
    need = estimate_information_need(estimate, cone, policy, target=target)
    if not need.worth_collecting:
        # Not worth asking. Nothing is escalated and AOP is not even consulted,
        # which is the cheap half of value-of-information actually paying off.
        return need, EscalationDecision(
            target=target,
            level=ObservationLevel.BASELINE,
            budget_score=0.0,
            escalated=False,
            refused_reason="value_of_information below threshold",
        )
    potential = (
        max(0.0, expected_delta_phi(cone))
        if security_potential is None
        else max(0.0, security_potential)
    )
    decision = policy.consider(
        target=target,
        uncertainty=float(estimate.value),
        security_potential=potential,
        causal_relevance=causal_relevance,
        now_ns=now_ns,
    )
    assert_mandatory_signals_intact(policy, target=target)
    return need, decision


def uncertainty_only_requests(
    estimate: UncertaintyEstimate,
    policy: AdaptiveObservationPolicy,
    *,
    target: str,
    now_ns: int,
) -> EscalationDecision:
    """THE SIMPLE CONTROL: Stage 1's existing threshold on uncertainty alone.

    No cone, no reducible-source decomposition, no cost model. Uncertainty is
    compared against ``AOPBudget.escalation_threshold`` (0.5) and, if it clears,
    AOP is asked with neutral consequence factors so that uncertainty is the
    only input that moved. If VoI cannot beat this, VoI should be deleted.
    """
    assert_mandatory_signals_intact(policy, target=target)
    if float(estimate.value) < policy.budget.escalation_threshold:
        return EscalationDecision(
            target=target,
            level=ObservationLevel.BASELINE,
            budget_score=float(estimate.value),
            escalated=False,
            refused_reason="uncertainty below Stage 1 escalation threshold",
        )
    return policy.consider(
        target=target,
        uncertainty=float(estimate.value),
        security_potential=1.0,
        causal_relevance=1.0,
        now_ns=now_ns,
    )


class InformationNeedTracker:
    """Accumulates VoI requests, records refusals, and never retries one."""

    __slots__ = (
        "max_requests",
        "_needs",
        "_requested",
        "_granted",
        "_refused",
        "_refusals",
        "_reductions",
        "_truncated",
    )

    def __init__(self, *, max_requests: int = MAX_INFORMATION_NEEDS) -> None:
        if max_requests < 1:
            raise ContractError("max_requests must be >= 1")
        self.max_requests = max_requests
        self._needs: list[InformationNeed] = []
        self._requested = 0
        self._granted = 0
        self._refused = 0
        self._refusals: dict[str, EscalationDecision] = {}
        self._reductions: list[float] = []
        self._truncated = 0

    def request(
        self,
        estimate: UncertaintyEstimate,
        cone: ConeView | None,
        policy: AdaptiveObservationPolicy,
        *,
        target: str,
        now_ns: int,
        security_potential: float | None = None,
        causal_relevance: float = 1.0,
    ) -> tuple[InformationNeed, EscalationDecision]:
        """Request once. A previously refused target is not asked again."""
        recorded = self._refusals.get(target)
        if recorded is not None:
            need = estimate_information_need(estimate, cone, policy, target=target)
            return (
                InformationNeed(
                    target=need.target,
                    expected_uncertainty_reduction=need.expected_uncertainty_reduction,
                    collection_cost=need.collection_cost,
                    value_of_information=need.value_of_information,
                    worth_collecting=False,
                    detail=f"refusal already recorded: {recorded.refused_reason}",
                ),
                recorded,
            )
        need, decision = request_observation_escalation(
            estimate,
            cone,
            policy,
            target=target,
            now_ns=now_ns,
            security_potential=security_potential,
            causal_relevance=causal_relevance,
        )
        self._record(need, decision)
        return need, decision

    def _record(self, need: InformationNeed, decision: EscalationDecision) -> None:
        if len(self._needs) < self.max_requests:
            self._needs.append(need)
        else:
            self._truncated += 1
        if not need.worth_collecting:
            return
        self._requested += 1
        if decision.escalated:
            self._granted += 1
        else:
            self._refused += 1
            self._refusals[decision.target] = decision

    def record_observation(
        self,
        policy: AdaptiveObservationPolicy,
        *,
        target: str,
        extra_events: int,
        uncertainty_before: float,
        uncertainty_after: float,
    ) -> float:
        """Record what an escalation actually bought, through Stage 1's AOP.

        This is the only place ``measured_reduction`` can become non-``None``:
        it requires an observation to have come back and uncertainty to have
        been re-estimated on it.
        """
        policy.record_observation(
            target, extra_events=extra_events, uncertainty_now=uncertainty_after
        )
        reduction = uncertainty_before - uncertainty_after
        self._reductions.append(reduction)
        return reduction

    def refusals(self) -> tuple[EscalationDecision, ...]:
        return tuple(self._refusals.values())

    def report(self) -> VoIReport:
        return VoIReport(
            requests=tuple(self._needs),
            escalations_requested=self._requested,
            escalations_granted=self._granted,
            escalations_refused=self._refused,
            measured_reduction=(
                sum(self._reductions) / len(self._reductions)
                if self._reductions
                else None
            ),
            truncated=self._truncated,
        )
