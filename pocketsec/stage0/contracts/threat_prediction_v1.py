"""D0.2 — ``ThreatPredictionV1``, the model-slot -> hub output contract.

Spec section 10 fixes the minimum outputs: state identifier, calibrated
confidence, novelty score, evidence relevance, optional next-event surprise,
model state version and an uncertainty/abstention signal.

Two invariants are enforced here rather than left to prose:

* **Abstention is a first-class answer.** ``UNKNOWN``, ``UNIDENTIFIABLE`` and
  ``INSUFFICIENT_EVIDENCE`` are valid verdicts, not error states.
* **A prediction carries no authority.** There is no action, remediation or
  privilege field, and :data:`FORBIDDEN_AUTHORITY_FIELDS` plus a test keep it
  that way. Response authority is Stage 5's, gated by SENTINEL — confidence
  never earns it.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from pocketsec.stage0.contracts.common import (
    ContractError,
    EvidenceRef,
    register_schema,
    require_finite_unit_interval,
    require_identifier,
)

__all__ = [
    "ComputePath",
    "EvidenceRelevance",
    "FORBIDDEN_AUTHORITY_FIELDS",
    "NextEventExpectation",
    "THREAT_PREDICTION_V1_ID",
    "THREAT_PREDICTION_V1_VERSION",
    "ThreatPredictionV1",
    "Verdict",
]

THREAT_PREDICTION_V1_ID = "pocketsec.threat_prediction.v1"
THREAT_PREDICTION_V1_VERSION = register_schema(THREAT_PREDICTION_V1_ID, "1.0.0")

# Field-name fragments that would smuggle response authority into a model
# output. Guarded by tests/test_authority_boundary.py.
FORBIDDEN_AUTHORITY_FIELDS = frozenset(
    {
        "action",
        "remediation",
        "execute",
        "command",
        "shell",
        "kill",
        "quarantine",
        "block",
        "authorize",
        "authorization",
        "privilege",
        "sudo",
    }
)


class Verdict(StrEnum):
    """Model-slot verdicts. The last three are answers, not failures."""

    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    UNKNOWN = "UNKNOWN"
    UNIDENTIFIABLE = "UNIDENTIFIABLE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


#: Verdicts that assert nothing about maliciousness. Novelty is not
#: maliciousness (MEMORY.md), so these must never be scored as positives.
NON_COMMITTAL_VERDICTS = frozenset(
    {Verdict.UNKNOWN, Verdict.UNIDENTIFIABLE, Verdict.INSUFFICIENT_EVIDENCE}
)


class ComputePath(StrEnum):
    """Which tier of the novelty-energy ladder produced this prediction.

    Spec section 4. Recording this per prediction is what makes "percentage of
    events resolved without neural inference" a measured number instead of a
    claim.
    """

    CHEAP_TRANSITION = "CHEAP_TRANSITION"
    STATISTICAL = "STATISTICAL"
    LEARNED_SOLVER = "LEARNED_SOLVER"


@dataclass(frozen=True, slots=True)
class EvidenceRelevance:
    """A weighted pointer back to the raw evidence that drove the verdict."""

    ref: EvidenceRef
    weight: float

    def __post_init__(self) -> None:
        if not isinstance(self.ref, EvidenceRef):
            raise ContractError("EvidenceRelevance.ref must be an EvidenceRef")
        require_finite_unit_interval(self.weight, "EvidenceRelevance.weight")

    def to_dict(self) -> dict[str, Any]:
        return {"ref": self.ref.to_dict(), "weight": self.weight}


@dataclass(frozen=True, slots=True)
class NextEventExpectation:
    """Optional predictive output feeding the novelty budget ``I(e|s)``."""

    surprise_bits: float | None = None
    distribution: Mapping[str, float] | None = None

    def __post_init__(self) -> None:
        if self.surprise_bits is not None:
            value = float(self.surprise_bits)
            if value < 0.0 or value != value:
                raise ContractError(f"surprise_bits must be finite and >= 0, got {value!r}")
        if self.distribution is not None:
            total = 0.0
            for key, probability in self.distribution.items():
                require_identifier(key, "NextEventExpectation.distribution key")
                total += require_finite_unit_interval(
                    probability, f"distribution[{key!r}]"
                )
            if total > 1.0 + 1e-6:
                raise ContractError(f"distribution sums to {total!r}, which exceeds 1.0")

    def to_dict(self) -> dict[str, Any]:
        return {
            "surprise_bits": self.surprise_bits,
            "distribution": dict(self.distribution) if self.distribution is not None else None,
        }


@dataclass(frozen=True, slots=True)
class ThreatPredictionV1:
    """The complete, authority-free output of a model slot."""

    prediction_id: str
    sequence_id: str
    verdict: Verdict
    confidence: float
    novelty_score: float
    uncertainty: float
    model_state_version: str
    compute_path: ComputePath
    compute_budget_units: float = 0.0
    state_identifier: str | None = None
    #: ``None`` means the confidence is **uncalibrated**. Never invent a
    #: calibration id to satisfy a schema; an unmeasured calibration is a
    #: fabricated result.
    calibration_id: str | None = None
    abstained: bool = False
    evidence_relevance: tuple[EvidenceRelevance, ...] = ()
    next_event: NextEventExpectation | None = None
    schema_version: str = THREAT_PREDICTION_V1_VERSION

    def __post_init__(self) -> None:
        require_identifier(self.prediction_id, "ThreatPredictionV1.prediction_id")
        require_identifier(self.sequence_id, "ThreatPredictionV1.sequence_id")
        require_identifier(self.model_state_version, "ThreatPredictionV1.model_state_version")
        require_finite_unit_interval(self.confidence, "ThreatPredictionV1.confidence")
        require_finite_unit_interval(self.novelty_score, "ThreatPredictionV1.novelty_score")
        require_finite_unit_interval(self.uncertainty, "ThreatPredictionV1.uncertainty")
        object.__setattr__(self, "verdict", Verdict(self.verdict))
        object.__setattr__(self, "compute_path", ComputePath(self.compute_path))
        object.__setattr__(self, "evidence_relevance", _freeze(self.evidence_relevance))
        self._validate_budget()
        self._validate_abstention()
        if self.state_identifier is not None:
            require_identifier(self.state_identifier, "ThreatPredictionV1.state_identifier")
        if self.calibration_id is not None:
            require_identifier(self.calibration_id, "ThreatPredictionV1.calibration_id")

    def _validate_budget(self) -> None:
        value = float(self.compute_budget_units)
        if value != value or value < 0.0:
            raise ContractError(f"compute_budget_units must be finite and >= 0, got {value!r}")

    def _validate_abstention(self) -> None:
        if not isinstance(self.abstained, bool):
            raise ContractError("ThreatPredictionV1.abstained must be a bool")
        if self.abstained and self.verdict not in NON_COMMITTAL_VERDICTS:
            raise ContractError(
                f"an abstaining prediction cannot also assert verdict {self.verdict.value}; "
                "use UNKNOWN, UNIDENTIFIABLE or INSUFFICIENT_EVIDENCE"
            )
        if self.verdict is Verdict.INSUFFICIENT_EVIDENCE and not self.abstained:
            raise ContractError("verdict INSUFFICIENT_EVIDENCE requires abstained=True")

    @property
    def is_committal(self) -> bool:
        """True when the model asserts something about maliciousness."""
        return self.verdict not in NON_COMMITTAL_VERDICTS

    @property
    def is_calibrated(self) -> bool:
        return self.calibration_id is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": THREAT_PREDICTION_V1_ID,
            "schema_version": self.schema_version,
            "prediction_id": self.prediction_id,
            "sequence_id": self.sequence_id,
            "verdict": self.verdict.value,
            "state_identifier": self.state_identifier,
            "confidence": self.confidence,
            "calibration_id": self.calibration_id,
            "novelty_score": self.novelty_score,
            "uncertainty": self.uncertainty,
            "abstained": self.abstained,
            "evidence_relevance": [item.to_dict() for item in self.evidence_relevance],
            "next_event": self.next_event.to_dict() if self.next_event is not None else None,
            "compute_path": self.compute_path.value,
            "compute_budget_units": self.compute_budget_units,
            "model_state_version": self.model_state_version,
        }


def _freeze(value: Iterable[EvidenceRelevance]) -> tuple[EvidenceRelevance, ...]:
    items = tuple(value)
    for index, item in enumerate(items):
        if not isinstance(item, EvidenceRelevance):
            raise ContractError(f"evidence_relevance[{index}] must be an EvidenceRelevance")
    return items
