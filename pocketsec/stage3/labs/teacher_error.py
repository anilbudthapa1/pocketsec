"""G3.5 — three constructed ways a teacher can be wrong, and the control that matters.

Oracle A is a *recording of the scorer being compiled*. If the recording is wrong
about a frame, nothing else in the pipeline disagrees with it — so a single-oracle
design certifies the teacher's own mistakes. These three cases construct exactly
that situation and check that Oracle B (Stage 1's invariants, already in code)
catches it.

The **control is the point**. ``TeacherErrorCase.teacher_only_passed`` records
what a teacher-divergence-only rule would have done with the same evidence. If it
would have refused too, then "the dual oracle refused" says nothing about Oracle
B, and falsifier F4 is live. A case is only evidence when the dual oracle refuses
and the teacher-only control accepts.

The VM is scripted, and this is the disclosure. The unit under test is the
oracle's decision rule; a real synthesised program that happened to be benign on a
CRITICAL frame would be testing the synthesiser instead, and could not be
constructed deterministically. Every frame, result, snapshot and verdict here is
the genuine Stage 3 type — only the execution is staged.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pocketsec.stage0.contracts.common import ContractError, EvidenceRef, digest_of_bytes
from pocketsec.stage1.ssir.relations import RelationFamily
from pocketsec.stage1.state.security_state import (
    CredentialExposure,
    Privilege,
    SecurityStateV1,
    StateDelta,
)
from pocketsec.stage2.encoder.ssir_encoder import ENCODER_VERSION
from pocketsec.stage3.bytecode.vm import CellResult
from pocketsec.stage3.cells.frame import CellFrame
from pocketsec.stage3.oracles.dual_oracle import DualOracleEvaluator, DualOracleVerdict
from pocketsec.stage3.oracles.teacher import TeacherOracle, TeacherSnapshotV1, frame_digest
from pocketsec.stage3.theory import SecurityConsequence, consequence_of

__all__ = ["TeacherErrorCase", "teacher_error_cases"]

@dataclass(frozen=True, slots=True)
class TeacherErrorCase:
    """One constructed way a teacher can be wrong, and what each oracle said.

    ``teacher_only_passed`` is the control. A dual oracle that refuses all three
    proves nothing unless a single-oracle rule would have accepted them: that is
    the difference between Oracle B doing work and Oracle B being decorative
    (falsifier F4).
    """

    case_id: str
    description: str
    verdict: DualOracleVerdict
    teacher_only_passed: bool

    @property
    def dual_oracle_refused(self) -> bool:
        return not self.verdict.passed

    @property
    def violation_kinds(self) -> tuple[str, ...]:
        return tuple(sorted({v.kind.value for v in self.verdict.hard_violations}))

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "description": self.description,
            "dual_oracle_refused": self.dual_oracle_refused,
            "teacher_only_passed": self.teacher_only_passed,
            "violation_kinds": list(self.violation_kinds),
            "reason": self.verdict.reason,
        }


class _ScriptedVM:
    """A VM stand-in that returns the wrong answer we constructed.

    Scripted on purpose. The unit under test is the oracle's *decision rule*, and
    a real synthesised program that happened to be benign on a critical frame
    would test the synthesiser instead, and could not be constructed
    deterministically. The frames and results are the genuine Stage 3 types; only
    the execution is staged, and this docstring is the disclosure.
    """

    def __init__(self, result: CellResult) -> None:
        self._result = result

    def run(self, program: Any, frame: CellFrame) -> CellResult:
        return self._result


@dataclass(frozen=True, slots=True)
class _StubCell:
    """The oracles read a cell's identity and its program, and nothing else."""

    cell_id: str
    operator: Any


def _evidence(store: str, locator: str) -> EvidenceRef:
    return EvidenceRef(
        store=store, locator=locator, digest=digest_of_bytes(f"{store}/{locator}".encode())
    )


#: Carries the ``credential_access`` token, so it is MANDATORY_SIGNALS evidence.
_MANDATORY = _evidence("raw.credential_access", "rec-0001")


def _critical_frame() -> CellFrame:
    """A frame whose ``consequence_of`` is HIGH or above, by Stage 1's own rule."""
    state = SecurityStateV1(credential=CredentialExposure.READABLE)
    frame = CellFrame(
        state=state,
        delta=StateDelta({"privilege": (0, int(Privilege.ROOT))}),
        actor_properties=0,
        object_properties=0,
        relation_family=RelationFamily.AUTHORIZATION,
        phi=0.0,
        delta_phi=6.0,
        uncertainty=0.0,
        epoch_id=0,
        window_counts={},
        evidence=(_MANDATORY,),
        encoder_version=ENCODER_VERSION,
    )
    consequence = consequence_of(frame.delta, frame.state)
    if consequence < SecurityConsequence.HIGH:
        raise ContractError(
            f"the constructed frame is {consequence.name}, not HIGH or above; the "
            "teacher-error cases would then test nothing"
        )
    return frame


def _snapshot_agreeing_with(frame: CellFrame, score: float, *, case_id: str) -> TeacherSnapshotV1:
    """A teacher that agrees with the wrong answer — which is what makes it wrong.

    Oracle A is a recording of the scorer being compiled. If the recording is
    wrong about a frame, nothing else in the pipeline disagrees with it. That is
    the case Oracle B exists for.
    """
    return TeacherSnapshotV1.create(
        teacher_id=f"teacher-error-{case_id}",
        source="phi-oracle",
        encoder_version=frame.encoder_version,
        corpus_version="constructed-teacher-error",
        seed=0,
        responses={frame_digest(frame): float(score)},
        measured_by="pocketsec.stage3.labs.baselines:teacher_error_cases",
        experiment_id="PS-S3-20260925-H4-teacher-error-0001",
    )


def _case(
    case_id: str, description: str, frame: CellFrame, result: CellResult
) -> TeacherErrorCase:
    cell = _StubCell(cell_id=f"cell-{case_id}", operator=object())
    snapshot = _snapshot_agreeing_with(frame, result.risk, case_id=case_id)
    evaluator = DualOracleEvaluator(teacher=TeacherOracle(snapshot), vm=_ScriptedVM(result))
    verdict = evaluator.evaluate(cell, [frame])
    # The control: a teacher-only rule ignores hard constraints entirely and asks
    # only whether the recording and the cell agree.
    teacher_only = (
        verdict.teacher_available
        and verdict.teacher_divergence is not None
        and verdict.teacher_divergence <= verdict.envelope
    )
    return TeacherErrorCase(
        case_id=case_id,
        description=description,
        verdict=verdict,
        teacher_only_passed=bool(teacher_only),
    )


def teacher_error_cases() -> tuple[TeacherErrorCase, ...]:
    """G3.5's three cases, each with a teacher that agrees with the error.

    (a) a CRITICAL-consequence frame scored benign;
    (b) a result that suppresses a ``MANDATORY_SIGNALS`` evidence requirement;
    (c) a result that lowers Φ.
    """
    frame = _critical_frame()
    benign = CellResult(
        abstained=False,
        delta=StateDelta({}),
        evidence=(_MANDATORY,),
        risk=0.0,
        escalation=None,
        steps_taken=3,
        reason="RETURN_RISK",
    )
    suppressed = CellResult(
        abstained=False,
        delta=StateDelta({"privilege": (0, int(Privilege.ROOT))}),
        evidence=(),
        risk=0.9,
        escalation=None,
        steps_taken=3,
        reason="RETURN_STATE",
    )
    lowered = CellResult(
        abstained=False,
        delta=StateDelta({"credential": (2, 0)}),
        evidence=(_MANDATORY,),
        risk=0.9,
        escalation=None,
        steps_taken=3,
        reason="RETURN_STATE",
    )
    return (
        _case("a", "teacher scores a CRITICAL-consequence frame benign", frame, benign),
        _case(
            "b",
            "teacher accepts a result that drops mandatory-signal evidence",
            frame,
            suppressed,
        ),
        _case("c", "teacher accepts a result that lowers Φ", frame, lowered),
    )
