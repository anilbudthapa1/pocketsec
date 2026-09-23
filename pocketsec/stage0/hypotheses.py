"""Competing hypotheses H0–H8 (spec section 11), carried forward as hypotheses.

Stage 0 non-goal: "do not claim NERA is novel or superior". So every entry here
starts at :attr:`HypothesisStatus.PROPOSED`, and
:func:`unsupported_status_claims` refuses to let a Stage 0 gate pass while any
hypothesis claims a result. A status may only advance on the back of a
registered experiment.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any

__all__ = ["HYPOTHESES", "Hypothesis", "HypothesisStatus", "unsupported_status_claims"]


class HypothesisStatus(StrEnum):
    PROPOSED = "PROPOSED"
    UNDER_TEST = "UNDER_TEST"
    SUPPORTED = "SUPPORTED"
    REFUTED = "REFUTED"


#: Statuses that assert a measured outcome and therefore require evidence.
RESULT_CLAIMING_STATUSES = frozenset({HypothesisStatus.SUPPORTED, HypothesisStatus.REFUTED})


@dataclass(frozen=True, slots=True)
class Hypothesis:
    id: str
    title: str
    reason_to_test: str
    status: HypothesisStatus = HypothesisStatus.PROPOSED
    #: Experiment ids that bear on this hypothesis. Empty at Stage 0.
    evidence: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "reason_to_test": self.reason_to_test,
            "status": self.status.value,
            "evidence": list(self.evidence),
        }


_HYPOTHESES = (
    Hypothesis("H0", "Conventional compact classifier / GRU", "Establish a hard baseline."),
    Hypothesis("H1", "State-space / recurrent baseline", "Test fixed-state temporal compression."),
    Hypothesis(
        "H2",
        "Learned behavioural automaton",
        "Determine whether security behaviour can compile into minimal transitions.",
    ),
    Hypothesis(
        "H3",
        "Novelty-budgeted conditional compute",
        "Test whether compute can scale with information novelty.",
    ),
    Hypothesis(
        "H4",
        "Neural-to-symbolic JIT compilation",
        "Test whether stable learned behaviour can become cheap executable detectors.",
    ),
    Hypothesis(
        "H5", "Adaptive state growth + minimisation", "Test host-dependent model complexity."
    ),
    Hypothesis(
        "H6",
        "Hierarchical reversible forgetting",
        "Bound memory while retaining recognisable behaviour.",
    ),
    Hypothesis(
        "H7",
        "Relational latent state",
        "Represent process/user/file/network relations rather than raw event sequence.",
    ),
    Hypothesis(
        "H8",
        "Combined NERA architecture",
        "Combine only components independently justified by ablation.",
    ),
)

HYPOTHESES = MappingProxyType({item.id: item for item in _HYPOTHESES})


def unsupported_status_claims() -> list[str]:
    """Return hypotheses claiming a result without a registered experiment."""
    return [
        f"{item.id} claims {item.status.value} with no supporting experiment id"
        for item in HYPOTHESES.values()
        if item.status in RESULT_CLAIMING_STATUSES and not item.evidence
    ]
