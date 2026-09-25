"""D3.16 — ``CrystalSlot``: the crystallised path behind Stage 0's frozen model slot.

Stage 3's runtime **holds no model**. There is no teacher forward pass here, no
weights blob and no fallback learner. A frame either falls inside a promoted
cell's validity boundary and is answered by a verified bytecode program, or it is
handed back as ``Verdict.UNKNOWN``. Those are the only two outcomes, and the
second one is an answer rather than a failure: novelty is not maliciousness, and
a cell that guesses outside its boundary is worse than no cell at all, because a
guess arrives wearing the cheap path's credibility.

Four things make the slot abstain, each for its own reason:

* **no cell claims the frame** — the region was never crystallised. The reason
  distinguishes a frame that is *near* some cell's boundary from one in wholly
  unexplored territory, because §40 asks for near-boundary matches to raise
  DTL/AOP activation and a single reason for both cases cannot;
* **several cells claim it and contradict** — ``KnowledgeField.compose`` refuses
  to pick an arbitrary winner (§16 rule 5);
* **the cells disagree about epoch** — knowledge from two regimes does not
  compose;
* **the cell's program abstains or fails verification** — ``CellVM`` runs nothing
  it has not verified.

The slot never returns ``Verdict.MALICIOUS``. A Knowledge Cell reproduces a
bounded behavioural invariant; it attributes nothing. ``SUSPICIOUS`` — "worth
looking at" — is the strongest thing a bounded invariant can honestly say, and
the ceiling is enforced here rather than left to a caller's discretion.

``confidence`` is confidence *in the stated verdict*, never a detection score
(ADR-0004): a BENIGN verdict reports ``1 - risk``, so Stage 0's harness, which
maps BENIGN through ``1 - confidence``, ranks this slot's least-risky windows
lowest rather than highest. ``uncertainty`` is the distance from the decision
threshold rather than ``1 - risk``, so a confident BENIGN is not reported as a
maximally uncertain committal answer.

``compute_path`` is always :attr:`ComputePath.CHEAP_TRANSITION` because there is
only one path in this runtime; the integration plan §3.2 binds a *cell hit* to
that value, and an abstention costs strictly less than a hit.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field as dataclass_field, fields
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import ContractError, EvidenceRef
from pocketsec.stage0.contracts.model_slot import (
    ACCEPTED_INPUT_SCHEMA,
    PRODUCED_OUTPUT_SCHEMA,
)
from pocketsec.stage0.contracts.security_event_v1 import SecurityEventSequenceV1
from pocketsec.stage0.contracts.threat_prediction_v1 import (
    FORBIDDEN_AUTHORITY_FIELDS,
    ComputePath,
    EvidenceRelevance,
    ThreatPredictionV1,
    Verdict,
)
from pocketsec.stage3.cells.field import (
    CellActivation,
    CompositionOutcome,
    CompositionVerdict,
    KnowledgeField,
)
from pocketsec.stage3.cells.frame import CellFrame
from pocketsec.stage3.cells.schema import KnowledgeCellV1
from pocketsec.stage3.theory import consequence_of

if TYPE_CHECKING:  # pragma: no cover - typing only
    from pocketsec.stage3.boundary.index import BoundaryIndex
    from pocketsec.stage3.bytecode.vm import CellResult, CellVM
    from pocketsec.stage3.oracles.teacher import TeacherOracle
    from pocketsec.stage3.promotion.audit import AuditSampler

__all__ = [
    "CRYSTAL_SLOT_NAME",
    "CrystalSlot",
    "MAX_FRAMES_PER_SEQUENCE",
    "MAX_NEAR_BOUNDARY_FRAMES",
    "SUSPICIOUS_RISK_FLOOR",
    "slot_report",
]

CRYSTAL_SLOT_NAME = "stage3-crystal"

#: A composed risk at or above this is reported as ``SUSPICIOUS``. It is a
#: threshold, not a measurement — the point at which the slot asks something
#: downstream to look. Named so that changing it is a visible change.
SUSPICIOUS_RISK_FLOOR = 0.25

#: Endpoint state is bounded (``planning/MEMORY.md``). A sequence offering more
#: frames than this is truncated *explicitly*, and the truncation is reported in
#: the prediction's uncertainty rather than silently dropped.
MAX_FRAMES_PER_SEQUENCE = 512

#: How many frames of a window the slot may ask ``BoundaryIndex.near_boundary``
#: about. That query scans every registered cell, so asking it about a whole
#: window would make an abstention's *reason* cost more than an answer.
MAX_NEAR_BOUNDARY_FRAMES = 8

#: Floor on a truncated window's uncertainty. A window we did not fully read is
#: at least half unknown whatever the composed risk says.
_TRUNCATED_UNCERTAINTY = 0.5

_ABSTAIN_NO_FRAMES = "no crystallised frame for this sequence"
_ABSTAIN_NO_CELL = "no cell claims any frame in this sequence"
_ABSTAIN_NEAR_BOUNDARY = "no cell claims any frame, but one is near a boundary"
_ABSTAIN_VM = "every claiming cell's program abstained"


@dataclass(kw_only=True)
class CrystalSlot:
    """Stage 0's ``ModelSlot``, answered from crystallised knowledge or not at all."""

    field: KnowledgeField
    index: BoundaryIndex
    vm: CellVM
    sampler: AuditSampler | None = None
    teacher: TeacherOracle | None = None
    #: Frames are compiled by Stage 1 and keyed by sequence id, exactly as
    #: ``pocketsec/stage1/slot.py`` keys ``ScenarioResult``. The slot does not
    #: compile telemetry itself: doing so would put a second pipeline in the
    #: repository, and the corpus walk is Stage 1's (integration plan §3.1).
    frames: Mapping[str, tuple[CellFrame, ...]] = dataclass_field(default_factory=dict)
    #: How many times each abstention reason fired, for a gate or a findings
    #: table. Bounded by construction: the keys are the three constants above
    #: plus the ``CompositionOutcome`` members, so this cannot grow with traffic.
    #: It counts; it never changes what the slot answers.
    abstention_reasons: dict[str, int] = dataclass_field(default_factory=dict)
    model_state_version: str = "stage3-crystal.1.0.0"
    input_schema: str = ACCEPTED_INPUT_SCHEMA
    output_schema: str = PRODUCED_OUTPUT_SCHEMA
    slot_name: str = CRYSTAL_SLOT_NAME

    def __post_init__(self) -> None:
        self._audit_authority_free()
        if not isinstance(self.field, KnowledgeField):
            raise ContractError("CrystalSlot.field must be a KnowledgeField")
        if not hasattr(self.index, "lookup_all"):
            raise ContractError("CrystalSlot.index must expose the BoundaryIndex lookup contract")
        if not hasattr(self.vm, "run"):
            raise ContractError("CrystalSlot.vm must expose CellVM.run")

    def _audit_authority_free(self) -> None:
        """ADR-0003, enforced the way ``EvidenceBoundPrediction`` enforces it.

        A field named ``action`` or ``quarantine`` on the slot would be a response
        channel wearing a model's clothes. Adding one breaks construction rather
        than quietly shipping.
        """
        offenders = [
            member.name
            for member in fields(self)
            if any(token in member.name.lower() for token in FORBIDDEN_AUTHORITY_FIELDS)
        ]
        if offenders:
            raise ContractError(
                f"CrystalSlot declares response-authority fields {offenders}; a model "
                "slot carries no authority (ADR-0003)"
            )

    # --- the model-slot contract ---------------------------------------------

    def predict(self, sequence: SecurityEventSequenceV1) -> ThreatPredictionV1:
        """Answer one bounded window from crystallised knowledge, or abstain.

        Never mutates ``sequence``, never runs a model, never guesses.
        """
        if not isinstance(sequence, SecurityEventSequenceV1):
            raise ContractError(
                f"CrystalSlot.predict expects a SecurityEventSequenceV1, "
                f"got {type(sequence).__name__}"
            )
        frames = self.frames.get(sequence.sequence_id, ())
        if not frames:
            return self._abstain(sequence, _ABSTAIN_NO_FRAMES, ())
        truncated = len(frames) > MAX_FRAMES_PER_SEQUENCE
        kept = frames[:MAX_FRAMES_PER_SEQUENCE]
        activations, evidence = self._activate(kept)
        if not activations:
            if evidence:
                reason = _ABSTAIN_VM
            elif self._near_any_boundary(kept):
                reason = _ABSTAIN_NEAR_BOUNDARY
            else:
                reason = _ABSTAIN_NO_CELL
            return self._abstain(sequence, reason, evidence)
        verdict = self.field.compose(activations)
        if verdict.outcome is not CompositionOutcome.RESOLVED:
            # Only the outcome is recorded, never ``verdict.reason``: the reason
            # names cell ids, and a counter keyed on it would grow with traffic.
            return self._abstain(sequence, verdict.outcome.value, evidence)
        return self._resolved(sequence, verdict, truncated=truncated)

    # --- internals ------------------------------------------------------------

    def _activate(
        self, frames: Sequence[CellFrame]
    ) -> tuple[list[CellActivation], tuple[EvidenceRef, ...]]:
        """Run every claiming cell over every frame; keep the non-abstaining results.

        ``evidence`` accumulates even from frames whose cell abstained, so the
        caller can tell "no cell claimed anything" (empty) from "a cell claimed it
        and its program declined to answer" (non-empty).
        """
        activations: dict[str, CellActivation] = {}
        seen: list[EvidenceRef] = []
        digests: set[str] = set()
        for frame in frames:
            for cell in self.index.lookup_all(frame):
                result = self.vm.run(cell.operator, frame)
                for ref in frame.evidence:
                    if ref.digest not in digests:
                        digests.add(ref.digest)
                        seen.append(ref)
                if result.abstained:
                    continue
                activation = _activation_of(cell, frame, result)
                incumbent = activations.get(cell.cell_id)
                if incumbent is None or activation.risk > incumbent.risk:
                    activations[cell.cell_id] = activation
        return list(activations.values()), tuple(seen)

    def _near_any_boundary(self, frames: Sequence[CellFrame]) -> bool:
        """Did any of these frames miss a cell by a countable number of clauses?

        §40 requires a near-boundary match to raise DTL/AOP activation rather
        than to look like wholly unexplored territory, and ``near_boundary`` was
        measured but never consulted, so the slot reported both cases under one
        reason. The answer only changes the *reason* recorded for the
        abstention: near-boundary is still an abstention, because a cell that
        answers next to its boundary is the silent extrapolation §10 forbids.

        Bounded on purpose. ``near_boundary`` scans every registered cell, so it
        is asked about at most :data:`MAX_NEAR_BOUNDARY_FRAMES` frames of a
        window rather than all of them; the cost of the reason must not scale
        with the window.
        """
        if not hasattr(self.index, "near_boundary"):
            return False
        for frame in frames[:MAX_NEAR_BOUNDARY_FRAMES]:
            if self.index.near_boundary(frame):
                return True
        return False

    def _abstain(
        self,
        sequence: SecurityEventSequenceV1,
        reason: str,
        evidence: tuple[EvidenceRef, ...],
    ) -> ThreatPredictionV1:
        """``UNKNOWN``, with uncertainty at its ceiling. Never a low-confidence guess."""
        self.abstention_reasons[reason] = self.abstention_reasons.get(reason, 0) + 1
        return ThreatPredictionV1(
            prediction_id=f"crystal-{sequence.sequence_id}",
            sequence_id=sequence.sequence_id,
            verdict=Verdict.UNKNOWN,
            confidence=0.0,
            novelty_score=0.0,
            uncertainty=1.0,
            abstained=True,
            model_state_version=self.model_state_version,
            compute_path=ComputePath.CHEAP_TRANSITION,
            compute_budget_units=0.0,
            state_identifier=None,
            calibration_id=None,
            evidence_relevance=_relevance(evidence),
            next_event=None,
        )

    def _resolved(
        self,
        sequence: SecurityEventSequenceV1,
        verdict: CompositionVerdict,
        *,
        truncated: bool,
    ) -> ThreatPredictionV1:
        """A cell hit. ``CHEAP_TRANSITION``, evidence carried, no authority attached."""
        suspicious = verdict.risk >= SUSPICIOUS_RISK_FLOOR
        committal = Verdict.SUSPICIOUS if suspicious else Verdict.BENIGN
        # ``confidence`` is confidence *in the stated verdict* (ADR-0004), not a
        # detection score. Writing the composed risk here for both verdicts made
        # a risk-0.0 BENIGN the strongest possible detection once Stage 0's
        # harness applied its ``1 - confidence`` mapping, which inverts the
        # ranking across the whole BENIGN band. ``stage1/slot.py`` has always
        # done it this way; this slot did not.
        confidence = verdict.risk if suspicious else 1.0 - verdict.risk
        uncertainty = _decision_uncertainty(verdict.risk)
        if truncated:
            # Truncation is explicit: a window we did not fully read raises
            # uncertainty rather than being reported as a complete observation.
            # ``max`` rather than assignment, so truncating a call that was
            # already near the threshold cannot *lower* its uncertainty.
            uncertainty = max(uncertainty, _TRUNCATED_UNCERTAINTY)
        return ThreatPredictionV1(
            prediction_id=f"crystal-{sequence.sequence_id}",
            sequence_id=sequence.sequence_id,
            verdict=committal,
            confidence=min(1.0, max(0.0, confidence)),
            novelty_score=0.0,
            uncertainty=uncertainty,
            abstained=False,
            model_state_version=self.model_state_version,
            compute_path=ComputePath.CHEAP_TRANSITION,
            compute_budget_units=float(len(verdict.contributing)),
            state_identifier=None,
            # ``None`` because no Stage 3 confidence has been calibrated. Inventing a
            # calibration id to fill the field is a fabricated result.
            calibration_id=None,
            evidence_relevance=_relevance(verdict.evidence),
            next_event=None,
        )


def _decision_uncertainty(risk: float) -> float:
    """How near the call was, in [0, 1] — never ``1 - risk``.

    ``1 - risk`` made a confident BENIGN (risk 0.0) report ``uncertainty=1.0``
    with ``abstained=False``: a maximally uncertain committal answer, which is
    incoherent. What this slot can honestly say about a *committal* verdict is
    how far the composed risk sat from :data:`SUSPICIOUS_RISK_FLOOR`, normalised
    within the band the verdict fell in. A risk sitting exactly on the floor is
    the most uncertain call available (1.0); the ends of either band are the
    least (0.0). It is a distance, not a calibrated probability, which is why
    ``calibration_id`` stays ``None``.
    """
    if risk >= SUSPICIOUS_RISK_FLOOR:
        span = 1.0 - SUSPICIOUS_RISK_FLOOR
        margin = risk - SUSPICIOUS_RISK_FLOOR
    else:
        span = SUSPICIOUS_RISK_FLOOR
        margin = SUSPICIOUS_RISK_FLOOR - risk
    if span <= 0.0:  # pragma: no cover - SUSPICIOUS_RISK_FLOOR is strictly inside (0, 1)
        return 1.0
    return min(1.0, max(0.0, 1.0 - margin / span))


def _activation_of(
    cell: KnowledgeCellV1, frame: CellFrame, result: CellResult
) -> CellActivation:
    """Project one executed cell result into the composition algebra's input.

    The consequence is taken from the **frame**, not from the result. A result
    that downgrades its own consequence must not be able to talk its way into a
    lower composition band; that check belongs to Oracle B, and this keeps the
    two honest by never letting the cell nominate its own severity.
    """
    return CellActivation(
        cell_id=cell.cell_id,
        delta=result.delta,
        risk=float(result.risk),
        evidence_required=result.evidence or frame.evidence,
        escalation=result.escalation,
        consequence=consequence_of(frame.delta, frame.state),
        confidence=cell.confidence,
        epochs=cell.epochs,
    )


def _relevance(evidence: Sequence[EvidenceRef]) -> tuple[EvidenceRelevance, ...]:
    """Weight evidence uniformly, and say so.

    A per-reference responsibility weight would be a claim about attribution that
    nothing in this runtime measured. Uniform weights are the honest encoding of
    "these are the bytes behind the answer, and we did not rank them".
    """
    if not evidence:
        return ()
    share = 1.0 / len(evidence)
    return tuple(EvidenceRelevance(ref=ref, weight=share) for ref in evidence)


def slot_report(slot: CrystalSlot) -> dict[str, Any]:
    """What the slot is carrying, for a gate or a findings table."""
    return {
        "slot_name": slot.slot_name,
        "model_state_version": slot.model_state_version,
        "cells": len(slot.field),
        "field_bytes": slot.field.memory_bytes(),
        "index_bytes": slot.index.memory_bytes(),
        "sequences": len(slot.frames),
        "abstention_reasons": dict(sorted(slot.abstention_reasons.items())),
        "teacher_available": bool(slot.teacher is not None and slot.teacher.available),
    }
