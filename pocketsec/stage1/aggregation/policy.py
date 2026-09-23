"""D1.10 — semantic aggregation (spec sections 19-20).

Repetitive benign transitions may be coalesced, but only under a strict
conservation rule::

    Aggregate(e) iff LowNovelty(e) AND LowSecurityPotential(e)
                     AND LowUncertainty(e) AND SameSemanticRelation(e)

All four conjuncts, every time. The Security Conservation Principle (section 20)
is the reason: compression may remove representational redundancy, but it must
not silently remove information needed for a security decision.

The rule that makes this safe rather than merely cheap: **privilege, credential,
persistence and boundary-crossing transitions are never hidden merely because
they repeat.** A thousand identical credential reads is not less interesting
than one — arguably more. :func:`can_aggregate` refuses those unconditionally,
before the four conjuncts are even considered.

Aggregated records retain count, interval, extrema and evidence references
sufficient for later investigation, so aggregation is a fidelity reduction and
never an erasure.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any

from pocketsec.stage0.contracts.common import EvidenceRef
from pocketsec.stage1.ssir.transition import SSIRTransitionV1

__all__ = [
    "AggregatedTransition",
    "AggregationPolicy",
    "AggregationThresholds",
    "can_aggregate",
]


@dataclass(frozen=True, slots=True)
class AggregationThresholds:
    """What counts as "low" for each conjunct."""

    max_novelty: float = 0.25
    max_delta_phi: float = 0.0
    max_uncertainty: float = 0.3
    #: Evidence references kept per aggregate: first N and last N.
    evidence_sample: int = 3
    max_groups: int = 512

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_novelty": self.max_novelty,
            "max_delta_phi": self.max_delta_phi,
            "max_uncertainty": self.max_uncertainty,
            "evidence_sample": self.evidence_sample,
            "max_groups": self.max_groups,
        }


def can_aggregate(
    transition: SSIRTransitionV1, thresholds: AggregationThresholds
) -> tuple[bool, str]:
    """Evaluate the conservation rule. Returns ``(allowed, reason)``.

    The reason is returned even on success so the decision is auditable: an
    aggregation policy nobody can inspect is indistinguishable from data loss.
    """
    # Checked first and unconditionally. A high-consequence transition is never
    # aggregated, regardless of how ordinary its novelty or uncertainty look.
    if transition.is_high_consequence:
        return False, "high-consequence: raised a security capability"
    if transition.delta_phi > thresholds.max_delta_phi:
        return False, f"delta_phi {transition.delta_phi:.3f} above threshold"
    if transition.novelty.peak > thresholds.max_novelty:
        return False, f"novelty peak {transition.novelty.peak:.3f} above threshold"
    if transition.uncertainty > thresholds.max_uncertainty:
        return False, f"uncertainty {transition.uncertainty:.3f} above threshold"
    if transition.observation_incomplete:
        return False, "observation incomplete: cannot certify low information loss"
    return True, "low novelty, low potential, low uncertainty, no state change"


@dataclass
class AggregatedTransition:
    """A coalesced run of semantically identical low-value transitions."""

    key: tuple[Any, ...]
    exemplar: SSIRTransitionV1
    count: int = 1
    first_ns: int = 0
    last_ns: int = 0
    min_novelty: float = 1.0
    max_novelty: float = 0.0
    max_uncertainty: float = 0.0
    evidence_head: list[EvidenceRef] = field(default_factory=list)
    evidence_tail: list[EvidenceRef] = field(default_factory=list)

    @property
    def interval_ns(self) -> int:
        return self.last_ns - self.first_ns

    @property
    def evidence(self) -> tuple[EvidenceRef, ...]:
        """Retained evidence: the head and tail of the run.

        Enough to locate the run's boundaries in the evidence store without
        retaining one reference per occurrence, which would defeat the point.
        """
        return tuple(self.evidence_head + self.evidence_tail)

    def absorb(self, transition: SSIRTransitionV1, thresholds: AggregationThresholds) -> None:
        self.count += 1
        self.last_ns = transition.sequence
        self.min_novelty = min(self.min_novelty, transition.novelty.peak)
        self.max_novelty = max(self.max_novelty, transition.novelty.peak)
        self.max_uncertainty = max(self.max_uncertainty, transition.uncertainty)
        if len(self.evidence_head) < thresholds.evidence_sample:
            self.evidence_head.extend(transition.evidence[:1])
        else:
            self.evidence_tail.extend(transition.evidence[:1])
            if len(self.evidence_tail) > thresholds.evidence_sample:
                self.evidence_tail.pop(0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "relation": self.exemplar.relation.name,
            "count": self.count,
            "first_sequence": self.first_ns,
            "last_sequence": self.last_ns,
            "interval": self.interval_ns,
            "novelty_extrema": [round(self.min_novelty, 4), round(self.max_novelty, 4)],
            "max_uncertainty": round(self.max_uncertainty, 4),
            "retained_evidence": [ref.to_dict() for ref in self.evidence],
        }


@dataclass(frozen=True, slots=True)
class AggregationReport:
    emitted: int
    aggregated_away: int
    groups: int
    high_consequence_preserved: int
    refusal_reasons: dict[str, int]

    @property
    def compression_ratio(self) -> float:
        total = self.emitted + self.aggregated_away
        return self.aggregated_away / total if total else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "emitted": self.emitted,
            "aggregated_away": self.aggregated_away,
            "groups": self.groups,
            "high_consequence_preserved": self.high_consequence_preserved,
            "compression_ratio": round(self.compression_ratio, 4),
            "refusal_reasons": dict(self.refusal_reasons),
        }


class AggregationPolicy:
    """Bounded coalescing of repetitive low-value transitions."""

    def __init__(self, thresholds: AggregationThresholds | None = None) -> None:
        self.thresholds = thresholds or AggregationThresholds()
        self._groups: OrderedDict[tuple[Any, ...], AggregatedTransition] = OrderedDict()
        self._emitted = 0
        self._aggregated_away = 0
        self._high_consequence = 0
        self._refusals: dict[str, int] = {}

    def offer(self, transition: SSIRTransitionV1) -> SSIRTransitionV1 | None:
        """Offer a transition. Returns it to emit, or ``None`` if absorbed."""
        allowed, reason = can_aggregate(transition, self.thresholds)
        if not allowed:
            if transition.is_high_consequence:
                self._high_consequence += 1
            self._refusals[reason.split(":")[0]] = (
                self._refusals.get(reason.split(":")[0], 0) + 1
            )
            self._emitted += 1
            return transition

        key = transition.semantic_key()
        group = self._groups.get(key)
        if group is None:
            self._groups[key] = AggregatedTransition(
                key=key,
                exemplar=transition,
                first_ns=transition.sequence,
                last_ns=transition.sequence,
                min_novelty=transition.novelty.peak,
                max_novelty=transition.novelty.peak,
                max_uncertainty=transition.uncertainty,
                evidence_head=list(transition.evidence[:1]),
            )
            self._evict_if_needed()
            self._emitted += 1
            return transition  # first of a run is always emitted

        group.absorb(transition, self.thresholds)
        self._groups.move_to_end(key)
        self._aggregated_away += 1
        return None

    def _evict_if_needed(self) -> None:
        while len(self._groups) > self.thresholds.max_groups:
            self._groups.popitem(last=False)

    @property
    def groups(self) -> tuple[AggregatedTransition, ...]:
        return tuple(self._groups.values())

    def report(self) -> AggregationReport:
        return AggregationReport(
            emitted=self._emitted,
            aggregated_away=self._aggregated_away,
            groups=len(self._groups),
            high_consequence_preserved=self._high_consequence,
            refusal_reasons=dict(self._refusals),
        )
