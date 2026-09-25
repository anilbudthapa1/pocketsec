"""D4.17 — ``CBFSlot``: Stage 4 behind Stage 0's frozen model slot.

The slot is the only way Stage 4's cognition reaches the hub, and it is built so
that Stage 4 *not working* is an ordinary outcome rather than an incident:

* The engine is **injected**. The LUCID loop lands in a later package (D4.2), so
  this module defines the engine as a :class:`IncidentEngine` Protocol and
  defaults to :class:`NullIncidentEngine`, which abstains. ``NullModelSlot``
  (``model_slot.py:80``) is the precedent: a slot that always abstains is not a
  placeholder to delete later, it is the proof that the hub degrades to "no
  Stage 4" and still produces well-formed, honestly-abstaining output.
* Every engine call, and the construction of the prediction from what it returned,
  is wrapped in ``guarded``. A crash — or a well-typed outcome carrying an unusable
  value — becomes one
  :class:`~pocketsec.stage4.engine.degradation.DegradationRecord` and an abstention.
  The one thing refused loudly is an engine returning the wrong TYPE, which is a
  wiring error in the engine rather than a runtime failure of the cognition.
* ``calibration_id`` is **always** ``None``. Stage 4 has not measured calibration
  yet (D4.10 does), and inventing an id to satisfy a schema is a fabricated
  result. The field is not a constructor parameter, so no caller can supply one.
* The slot emits ``UNIDENTIFIABLE`` with ``abstained=True`` rather than guessing,
  and ``BENIGN`` can never be reached from a degraded run
  (:func:`~pocketsec.stage4.engine.degradation.downgrade_verdict`).

``compute_path`` is ``STATISTICAL``: the CBF weighs competing worlds against
evidence. ``CHEAP_TRANSITION`` is reserved for the case a later package can
actually demonstrate — a crystallised cell resolving an incident with no world
branching — and claiming it here would misreport where the compute went.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, ClassVar, Protocol, runtime_checkable

from pocketsec.stage0.contracts.common import ContractError, require_identifier
from pocketsec.stage0.contracts.model_slot import (
    ACCEPTED_INPUT_SCHEMA,
    PRODUCED_OUTPUT_SCHEMA,
)
from pocketsec.stage0.contracts.security_event_v1 import SecurityEventSequenceV1
from pocketsec.stage0.contracts.threat_prediction_v1 import (
    NON_COMMITTAL_VERDICTS,
    ComputePath,
    EvidenceRelevance,
    ThreatPredictionV1,
    Verdict,
)
from pocketsec.stage4.engine.degradation import (
    DEGRADED_VERDICT,
    DegradationLedger,
    Subsystem,
    downgrade_verdict,
    guarded,
)
from pocketsec.stage4.worlds.world import authority_named_fields

__all__ = [
    "CBFSlot",
    "CBF_SLOT_NAME",
    "ENGINE_SUBSYSTEM",
    "EngineOutcome",
    "IncidentEngine",
    "NullIncidentEngine",
    "STAGE4_MODEL_STATE_VERSION",
]

CBF_SLOT_NAME = "stage4-cbf-lucid"

#: Version of the *reasoning state*, distinct from the code version. ``0.1.0``
#: because no learned or fitted state exists yet: the slot is wiring plus an
#: abstention until a later package measures something.
STAGE4_MODEL_STATE_VERSION = "stage4-cbf.0.1.0"

#: Which subsystem an unguarded engine crash is attributed to. The engine *is* the
#: LUCID loop, whose job is the world lifecycle, and the engine is expected to
#: guard its own ten subsystems; this is the outer net for the case it does not.
ENGINE_SUBSYSTEM: Subsystem = Subsystem.WORLD_LIFECYCLE


@dataclass(frozen=True, slots=True)
class EngineOutcome:
    """One incident resolution, as the engine hands it to the slot.

    Deliberately not a ``ThreatPredictionV1``: the engine reasons about worlds and
    the slot owns the hub contract, so the engine cannot set ``calibration_id``,
    ``compute_path`` or ``abstained`` even by accident.
    """

    verdict: Verdict
    confidence: float
    novelty_score: float
    uncertainty: float
    #: ``IdentifiabilityState.value`` from D4.8, carried as a string so this
    #: module does not import the resolution package it may outlive.
    identifiability: str
    compute_budget_units: float = 0.0
    state_identifier: str | None = None
    evidence_relevance: tuple[EvidenceRelevance, ...] = ()

    def __post_init__(self) -> None:
        # T5 / ADR-0003: this object becomes a ThreatPredictionV1, so an authority
        # field here would be authority in a model output. Audited with Stage 4's
        # one helper (§2.4) rather than a local copy of the token list.
        offenders = authority_named_fields(type(self))
        if offenders:
            raise ContractError(
                f"EngineOutcome names response authority in {list(offenders)}; "
                "confidence never earns execution authority"
            )
        object.__setattr__(self, "verdict", Verdict(self.verdict))
        object.__setattr__(self, "evidence_relevance", tuple(self.evidence_relevance))
        if not isinstance(self.identifiability, str) or not self.identifiability:
            raise ContractError("EngineOutcome.identifiability must be a non-empty string")
        if self.state_identifier is not None:
            require_identifier(self.state_identifier, "EngineOutcome.state_identifier")
        # confidence / novelty / uncertainty are validated by ThreatPredictionV1's
        # own __post_init__; re-checking here would be a second definition of the
        # unit interval that could drift from the contract's.


@runtime_checkable
class IncidentEngine(Protocol):
    """What the slot requires of the LUCID engine, and nothing more.

    ``resolve`` returns ``None`` when the engine will not commit — a non-answer is
    an answer, and it keeps the "engine present but unresolved" case distinct from
    "engine crashed", which the ledger records separately.
    """

    def resolve(
        self, sequence: SecurityEventSequenceV1, *, ledger: DegradationLedger
    ) -> EngineOutcome | None:
        """Resolve one bounded window. Must not mutate ``sequence``."""
        ...


class NullIncidentEngine:
    """The honest default: no cognition attached, so nothing is resolved."""

    def resolve(
        self, sequence: SecurityEventSequenceV1, *, ledger: DegradationLedger
    ) -> EngineOutcome | None:
        return None


@dataclass(frozen=True, slots=True)
class CBFSlot:
    """``ModelSlot`` over the Causal Belief Field.

    Satisfies ``validate_slot`` (``model_slot.py:57``), which is the only way the
    hub will wire it. Frozen, because the slot holds no per-sequence state: the
    ledger it writes into is passed in, so two hosts cannot share an accidental
    accumulation through a slot instance.
    """

    slot_name: ClassVar[str] = CBF_SLOT_NAME
    input_schema: ClassVar[str] = ACCEPTED_INPUT_SCHEMA
    output_schema: ClassVar[str] = PRODUCED_OUTPUT_SCHEMA

    model_state_version: str = STAGE4_MODEL_STATE_VERSION
    engine: IncidentEngine = field(default_factory=NullIncidentEngine)
    ledger: DegradationLedger = field(default_factory=DegradationLedger)

    def __post_init__(self) -> None:
        require_identifier(self.model_state_version, "CBFSlot.model_state_version")
        if not hasattr(self.engine, "resolve"):
            raise ContractError(
                f"{type(self.engine).__name__} does not satisfy IncidentEngine: no resolve()"
            )

    def predict(self, sequence: SecurityEventSequenceV1) -> ThreatPredictionV1:
        """Score one bounded window, abstaining rather than guessing.

        The ledger is consulted *around* the engine call, so a subsystem that the
        engine guarded internally still downgrades this verdict: whether the hole
        was caught one frame down or here, the reasoning did not complete.
        """
        if not isinstance(sequence, SecurityEventSequenceV1):
            raise ContractError("CBFSlot.predict takes a SecurityEventSequenceV1")
        before = self.ledger.count + self.ledger.dropped
        scope = guarded(
            ENGINE_SUBSYSTEM,
            self.ledger,
            at_sequence=0,
            fallback=None,
            evidence_preserved=True,
        )
        with scope:
            scope.result = self.engine.resolve(sequence, ledger=self.ledger)
        outcome = scope.result
        degraded = (self.ledger.count + self.ledger.dropped) > before
        if outcome is None:
            return self._abstain(sequence, degraded=degraded)
        if not isinstance(outcome, EngineOutcome):
            # A wrong return TYPE is a wiring error in the engine's author's code, not a
            # runtime failure of the cognition, and it is refused loudly at the seam.
            raise ContractError(
                f"{type(self.engine).__name__}.resolve returned "
                f"{type(outcome).__name__}, not an EngineOutcome"
            )
        # A well-typed outcome carrying an unusable VALUE — ``EngineOutcome`` defers
        # validation, so a NaN or out-of-range confidence first fails here — is a
        # runtime failure and degrades like one. It used to escape the slot as a
        # ContractError with no DegradationRecord (S4-SEC-05 / S4-FC-14).
        build = guarded(
            ENGINE_SUBSYSTEM,
            self.ledger,
            at_sequence=0,
            fallback=None,
            evidence_preserved=True,
        )
        with build:
            build.result = self._from_outcome(sequence, outcome, degraded=degraded)
        if build.result is None:
            return self._abstain(sequence, degraded=True)
        return build.result

    def _abstain(
        self, sequence: SecurityEventSequenceV1, *, degraded: bool
    ) -> ThreatPredictionV1:
        """Confidence 0, uncertainty 1 — no world was resolved.

        ``UNIDENTIFIABLE`` rather than ``INSUFFICIENT_EVIDENCE``: the evidence may
        be ample, what is absent is a reason to prefer one world over another, and
        Stage 4 exists precisely so that distinction survives (ADR-0032 reuses
        Stage 1's vocabulary rather than minting a parallel one). When something
        degraded, ``UNKNOWN`` instead — that case is "the reasoning did not
        finish", which is a different fact about the system and not about the
        evidence.
        """
        return ThreatPredictionV1(
            prediction_id=self._prediction_id(sequence),
            sequence_id=sequence.sequence_id,
            verdict=DEGRADED_VERDICT if degraded else Verdict.UNIDENTIFIABLE,
            confidence=0.0,
            novelty_score=0.0,
            uncertainty=1.0,
            abstained=True,
            model_state_version=self.model_state_version,
            compute_path=ComputePath.STATISTICAL,
            compute_budget_units=0.0,
            state_identifier=None,
            calibration_id=None,
            evidence_relevance=(),
        )

    def _from_outcome(
        self,
        sequence: SecurityEventSequenceV1,
        outcome: EngineOutcome,
        *,
        degraded: bool,
    ) -> ThreatPredictionV1:
        verdict = downgrade_verdict(outcome.verdict, degraded=degraded)
        # A downgraded verdict keeps the engine's uncertainty as a floor and
        # widens it: §45's calibration rule is "widen uncertainty and increase
        # abstention", and reporting the engine's own confidence for a verdict the
        # engine did not reach would be the fabrication this stage exists to stop.
        confidence = 0.0 if verdict is not outcome.verdict else outcome.confidence
        uncertainty = 1.0 if verdict is not outcome.verdict else outcome.uncertainty
        return ThreatPredictionV1(
            prediction_id=self._prediction_id(sequence),
            sequence_id=sequence.sequence_id,
            verdict=verdict,
            confidence=confidence,
            novelty_score=outcome.novelty_score,
            uncertainty=uncertainty,
            abstained=verdict in NON_COMMITTAL_VERDICTS,
            model_state_version=self.model_state_version,
            compute_path=ComputePath.STATISTICAL,
            compute_budget_units=outcome.compute_budget_units,
            state_identifier=outcome.state_identifier,
            #: Uncalibrated, honestly, until D4.10 measures it.
            calibration_id=None,
            evidence_relevance=outcome.evidence_relevance,
        )

    def _prediction_id(self, sequence: SecurityEventSequenceV1) -> str:
        return f"{CBF_SLOT_NAME}:{sequence.sequence_id}"

    def report(self) -> dict[str, Any]:
        """What this slot is and what degraded under it, for provenance."""
        return {
            "slot_name": self.slot_name,
            "model_state_version": self.model_state_version,
            "engine": type(self.engine).__name__,
            "input_schema": self.input_schema,
            "output_schema": self.output_schema,
            "compute_path": ComputePath.STATISTICAL.value,
            "calibrated": False,
            "degradations": self.ledger.to_dict(),
        }
