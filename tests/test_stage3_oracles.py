"""D3.8/D3.9 — the dual oracle and counterexample memory.

Gate criterion G3.5 is the centre of this file: three constructed teacher-error cases
that the dual oracle must refuse, plus the control that makes them mean anything — an
assertion that a *teacher-only* rule would have passed all three. Without the control,
"the dual oracle refused" is not evidence that the second oracle did any work.

The ``CellVM`` is scripted rather than real. The unit under test is the oracle's
decision rule, not the bytecode synthesiser: a real program that happens to produce a
benign result on a critical frame would test ``synthesis`` and ``bytecode`` as much as
this package, and could not construct the three error cases deterministically. The
frames and results themselves are the genuine ``pocketsec.stage3.bytecode.vm`` types.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import pytest

from pocketsec.stage0.contracts.common import ContractError, EvidenceRef, digest_of_bytes
from pocketsec.stage1.novelty.engine import NOVELTY_CONTEXTS, NoveltyTensor
from pocketsec.stage1.ssir.entities import Entity
from pocketsec.stage1.ssir.relations import Relation, RelationFamily
from pocketsec.stage1.ssir.transition import SSIRTransitionV1, TemporalContext
from pocketsec.stage1.state.potential import phi
from pocketsec.stage1.state.security_state import (
    CredentialExposure,
    Privilege,
    Reachability,
    SecurityStateV1,
    StateDelta,
)
from pocketsec.stage3.bytecode.vm import CellFrame, CellResult
from pocketsec.stage3.cells.schema import ConstraintKind
from pocketsec.stage3.oracles.counterexamples import (
    MAX_HOT_BYTES,
    MAX_HOT_COUNTEREXAMPLES,
    Counterexample,
    CounterexampleStore,
    replay_corpus_size,
)
from pocketsec.stage3.oracles.dual_oracle import (
    DEFAULT_DIVERGENCE_WEIGHTS,
    ENVELOPES,
    DualOracleEvaluator,
    SecurityDivergence,
    envelope_for,
)
from pocketsec.stage3.oracles.security_specs import (
    BENIGN_RISK_CEILING,
    Violation,
    apply_delta,
    check_hard_security_constraints,
    is_benign_result,
    mandatory_evidence,
)
from pocketsec.stage3.oracles.teacher import (
    TEACHER_SOURCES,
    TeacherOracle,
    TeacherSnapshotV1,
    build_phi_oracle_snapshot,
    frame_digest,
    load_snapshot,
    phi_oracle_score,
    write_snapshot,
)
from pocketsec.stage3.theory import SecurityConsequence, consequence_of

EXPERIMENT_ID = "PS-S3-20260925-H9-oracle-fixtures-0001"
ENCODER = "ssir-encoder-test"


# --- fixtures ----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _StubCell:
    """The oracles read a cell's identity and its program, and nothing else."""

    cell_id: str
    operator: Any


class _ScriptedVM:
    """A VM stand-in that returns a predetermined result for each frame."""

    def __init__(self, respond: Any) -> None:
        self._respond = respond
        self.runs = 0

    def run(self, program: Any, frame: CellFrame) -> CellResult:
        self.runs += 1
        return self._respond(frame)


def _evidence(store: str, locator: str) -> EvidenceRef:
    return EvidenceRef(
        store=store, locator=locator, digest=digest_of_bytes(f"{store}/{locator}".encode())
    )


#: Carries the ``credential_access`` token, so it is MANDATORY_SIGNALS evidence.
MANDATORY_REF = _evidence("raw.credential_access", "rec-0001")
#: Carries ``credential_accessory`` — a substring of a mandatory signal, not a token.
NEAR_MISS_REF = _evidence("raw.credential_accessory", "rec-0002")
ROUTINE_REF = _evidence("raw.filesystem", "rec-0003")


def _frame(
    *,
    state: SecurityStateV1,
    delta: StateDelta,
    evidence: tuple[EvidenceRef, ...] = (MANDATORY_REF,),
    uncertainty: float = 0.0,
    delta_phi: float | None = None,
    epoch_id: int = 0,
) -> CellFrame:
    return CellFrame(
        state=state,
        delta=delta,
        actor_properties=0b0101,
        object_properties=0b0010,
        relation_family=RelationFamily.FILESYSTEM,
        phi=phi(state).total,
        delta_phi=phi(state).total if delta_phi is None else delta_phi,
        uncertainty=uncertainty,
        epoch_id=epoch_id,
        window_counts={int(RelationFamily.FILESYSTEM): 3},
        evidence=evidence,
        encoder_version=ENCODER,
    )


def _result(
    *,
    delta: StateDelta,
    evidence: tuple[EvidenceRef, ...],
    risk: float,
    abstained: bool = False,
    reason: str = "RETURN_STATE",
) -> CellResult:
    return CellResult(
        abstained=abstained,
        delta=delta,
        evidence=evidence,
        risk=risk,
        escalation=None,
        steps_taken=3,
        reason=reason,
    )


def _snapshot(responses: dict[str, float], *, source: str = "phi-oracle") -> TeacherSnapshotV1:
    return TeacherSnapshotV1.create(
        teacher_id="pocketsec.teacher.phi-oracle-test",
        source=source,
        encoder_version=ENCODER,
        corpus_version="crystal-test-1",
        seed=11,
        responses=responses,
        measured_by="tests.test_stage3_oracles:_snapshot",
        experiment_id=EXPERIMENT_ID,
    )


def _agreeing_oracle(frame: CellFrame, risk: float) -> TeacherOracle:
    """A teacher that scores this frame exactly as the cell did: divergence 0.0."""
    return TeacherOracle(_snapshot({frame_digest(frame): risk}))


#: A state where ``credential_egress`` fires, so ``consequence_of`` is CRITICAL.
CRITICAL_STATE = SecurityStateV1(
    credential=CredentialExposure.READABLE, reachability=Reachability.EXTERNAL
)
#: Privilege already held, no interaction active: lowering it is a monotonicity failure.
ELEVATED_STATE = SecurityStateV1(privilege=Privilege.ELEVATED)

PRIVILEGE_DELTA = StateDelta(raised={"privilege": (0, 1)})
CREDENTIAL_DELTA = StateDelta(raised={"credential": (1, 2)})


# --- G3.5: the three constructed teacher-error cases -------------------------


def _case_normalises_critical_frame() -> tuple[CellFrame, CellResult]:
    """(a) The teacher scores a CRITICAL-consequence frame benign, and the cell agrees."""
    frame = _frame(state=CRITICAL_STATE, delta=CREDENTIAL_DELTA)
    result = _result(delta=CREDENTIAL_DELTA, evidence=(MANDATORY_REF,), risk=0.05)
    return frame, result


def _case_suppresses_mandatory_evidence() -> tuple[CellFrame, CellResult]:
    """(b) The teacher endorses a result that drops a MANDATORY_SIGNALS evidence ref."""
    frame = _frame(
        state=SecurityStateV1(), delta=PRIVILEGE_DELTA, evidence=(MANDATORY_REF, ROUTINE_REF)
    )
    result = _result(delta=PRIVILEGE_DELTA, evidence=(ROUTINE_REF,), risk=0.9)
    return frame, result


def _case_lowers_phi() -> tuple[CellFrame, CellResult]:
    """(c) The teacher endorses a result whose delta lowers Φ."""
    frame = _frame(state=ELEVATED_STATE, delta=PRIVILEGE_DELTA)
    result = _result(
        delta=StateDelta(raised={"privilege": (1, 0)}), evidence=(MANDATORY_REF,), risk=0.9
    )
    return frame, result


TEACHER_ERROR_CASES = (
    ("normalises_critical_frame", _case_normalises_critical_frame,
     ConstraintKind.NEVER_NORMALISE_HIGH_CONSEQUENCE),
    ("suppresses_mandatory_evidence", _case_suppresses_mandatory_evidence,
     ConstraintKind.NEVER_SUPPRESS_MANDATORY_EVIDENCE),
    ("lowers_phi", _case_lowers_phi, ConstraintKind.NEVER_LOWER_PHI),
)


def _verdict_for(frame: CellFrame, result: CellResult) -> Any:
    """Evaluate with a teacher that agrees perfectly, so only Oracle B can refuse."""
    vm = _ScriptedVM(lambda _frame: result)
    evaluator = DualOracleEvaluator(teacher=_agreeing_oracle(frame, result.risk), vm=vm)
    return evaluator.evaluate(_StubCell(cell_id="cell.under-test", operator=object()), [frame])


@pytest.mark.parametrize(("name", "build", "expected_kind"), TEACHER_ERROR_CASES)
def test_dual_oracle_refuses_each_predefined_teacher_error_case(
    name: str, build: Any, expected_kind: ConstraintKind
) -> None:
    frame, result = build()
    verdict = _verdict_for(frame, result)
    assert verdict.passed is False, name
    kinds = {v.kind for v in verdict.hard_violations}
    assert expected_kind in kinds, f"{name}: expected {expected_kind} in {kinds}"
    assert verdict.reason.startswith("HARD_CONSTRAINT_VIOLATED")


@pytest.mark.parametrize(("name", "build", "expected_kind"), TEACHER_ERROR_CASES)
def test_teacher_only_control_would_have_passed_all_three(
    name: str, build: Any, expected_kind: ConstraintKind
) -> None:
    """The control that makes G3.5 mean something.

    Each case is constructed so Oracle A is *perfectly satisfied*: the teacher is
    available and its divergence from the cell is zero, inside every envelope. A
    teacher-only rule would therefore have crystallized all three errors. Everything
    that refused them came from Oracle B.
    """
    frame, result = build()
    verdict = _verdict_for(frame, result)
    assert verdict.teacher_available is True, name
    assert verdict.teacher_divergence == 0.0, name
    assert verdict.teacher_divergence <= verdict.envelope, name
    teacher_only_would_pass = (
        verdict.teacher_available and verdict.teacher_divergence <= verdict.envelope
    )
    assert teacher_only_would_pass is True, name
    assert verdict.passed is False, name


def test_a_clean_result_with_an_agreeing_teacher_does_pass() -> None:
    """The refusals above must not be an evaluator that refuses everything."""
    frame = _frame(state=SecurityStateV1(), delta=PRIVILEGE_DELTA)
    result = _result(delta=PRIVILEGE_DELTA, evidence=(MANDATORY_REF,), risk=0.9)
    verdict = _verdict_for(frame, result)
    assert verdict.hard_violations == ()
    assert verdict.passed is True
    assert verdict.reason == "PASSED"


# --- the two named failures the design exists to prevent ---------------------


def test_verdict_never_passes_on_oracle_a_alone() -> None:
    """Perfect teacher agreement, one hard violation: still a refusal."""
    frame, result = _case_normalises_critical_frame()
    verdict = _verdict_for(frame, result)
    assert verdict.teacher_divergence == 0.0
    assert verdict.hard_violations != ()
    assert verdict.passed is False


def test_verdict_never_passes_on_oracle_b_alone() -> None:
    """No hard violation at all, but no teacher: still a refusal, and UNMEASURED."""
    frame = _frame(state=SecurityStateV1(), delta=PRIVILEGE_DELTA)
    result = _result(delta=PRIVILEGE_DELTA, evidence=(MANDATORY_REF,), risk=0.9)
    evaluator = DualOracleEvaluator(
        teacher=TeacherOracle(None), vm=_ScriptedVM(lambda _f: result)
    )
    verdict = evaluator.evaluate(_StubCell(cell_id="cell.b-only", operator=object()), [frame])
    assert verdict.hard_violations == ()
    assert verdict.teacher_available is False
    assert verdict.teacher_divergence is None
    assert verdict.passed is False
    assert verdict.reason == "TEACHER_UNAVAILABLE"


def test_a_teacher_with_no_entry_for_the_frame_is_unavailable_not_agreeing() -> None:
    """A snapshot that has never seen this frame is UNKNOWN, which is not agreement."""
    frame = _frame(state=SecurityStateV1(), delta=PRIVILEGE_DELTA)
    other = _frame(state=SecurityStateV1(), delta=CREDENTIAL_DELTA, epoch_id=7)
    result = _result(delta=PRIVILEGE_DELTA, evidence=(MANDATORY_REF,), risk=0.9)
    evaluator = DualOracleEvaluator(
        teacher=TeacherOracle(_snapshot({frame_digest(other): 0.9})),
        vm=_ScriptedVM(lambda _f: result),
    )
    verdict = evaluator.evaluate(_StubCell(cell_id="cell.unknown", operator=object()), [frame])
    assert verdict.teacher_available is False
    assert verdict.passed is False
    assert verdict.reason == "TEACHER_UNAVAILABLE"


def test_divergence_above_the_envelope_refuses_even_with_no_violations() -> None:
    frame = _frame(state=SecurityStateV1(), delta=PRIVILEGE_DELTA)
    result = _result(delta=PRIVILEGE_DELTA, evidence=(MANDATORY_REF,), risk=0.9)
    evaluator = DualOracleEvaluator(
        teacher=_agreeing_oracle(frame, 0.2), vm=_ScriptedVM(lambda _f: result)
    )
    verdict = evaluator.evaluate(_StubCell(cell_id="cell.far", operator=object()), [frame])
    assert verdict.consequence is SecurityConsequence.HIGH
    assert verdict.teacher_divergence == pytest.approx(0.7)
    assert verdict.passed is False
    assert verdict.reason.startswith("DIVERGENCE_ABOVE_ENVELOPE")


def test_evaluate_refuses_an_empty_frame_sequence() -> None:
    evaluator = DualOracleEvaluator(
        teacher=TeacherOracle(None), vm=_ScriptedVM(lambda _f: None)
    )
    with pytest.raises(ContractError, match="zero frames"):
        evaluator.evaluate(_StubCell(cell_id="cell.empty", operator=object()), [])


# --- §19 divergence ----------------------------------------------------------


def test_d_future_hazard_cannot_be_set_to_a_number() -> None:
    """ADR-0116 rejected hazard on measured calibration; the type keeps it rejected."""
    with pytest.raises(ContractError, match="ADR-0116"):
        SecurityDivergence(
            d_state_delta=0.0,
            d_security_potential=0.0,
            d_uncertainty=0.0,
            d_evidence_requirement=0.0,
            d_causal_attribution=0.0,
            d_future_hazard=0.5,  # type: ignore[arg-type]
        )


def test_d_future_hazard_must_carry_zero_weight() -> None:
    """A non-zero hazard weight would make every total None and hide the removal."""
    weights = dict(DEFAULT_DIVERGENCE_WEIGHTS) | {"d_future_hazard": 0.1}
    with pytest.raises(ContractError, match="weight 0.0"):
        SecurityDivergence(
            d_state_delta=0.0,
            d_security_potential=0.0,
            d_uncertainty=0.0,
            d_evidence_requirement=0.0,
            d_causal_attribution=0.0,
            weights=weights,
        )


def test_total_is_a_number_despite_the_permanently_none_hazard_term() -> None:
    divergence = SecurityDivergence(
        d_state_delta=1.0,
        d_security_potential=0.0,
        d_uncertainty=0.0,
        d_evidence_requirement=0.0,
        d_causal_attribution=0.0,
    )
    assert divergence.d_future_hazard is None
    assert divergence.total == pytest.approx(DEFAULT_DIVERGENCE_WEIGHTS["d_state_delta"])


def test_divergence_rejects_a_non_finite_term() -> None:
    with pytest.raises(ContractError, match="finite"):
        SecurityDivergence(
            d_state_delta=float("inf"),
            d_security_potential=0.0,
            d_uncertainty=0.0,
            d_evidence_requirement=0.0,
            d_causal_attribution=0.0,
        )


def test_envelopes_are_closed_and_strictly_tighten_with_consequence() -> None:
    """Would fail if anyone slackened a high-consequence envelope to make a cell pass."""
    assert set(ENVELOPES) == set(SecurityConsequence)
    values = [ENVELOPES[c] for c in sorted(SecurityConsequence)]
    assert all(a > b for a, b in zip(values, values[1:]))
    assert envelope_for(SecurityConsequence.CRITICAL) < envelope_for(SecurityConsequence.ROUTINE)


# --- Oracle B in isolation ---------------------------------------------------


def test_abstention_is_not_a_benign_verdict() -> None:
    """UNKNOWN is a valid output; a cell that declines has normalised nothing.

    Pins S3-09 / S3-AUTH-03. The abstention here carries ``evidence=()``, which
    is the only shape ``CellVM._abstained`` can produce — the previous version of
    this test passed ``evidence=frame.evidence`` and so never reached
    ``_check_mandatory_evidence``, which had no abstention guard and reported
    every real abstention on a mandatory-signal frame as evidence suppression.
    """
    frame = _frame(state=CRITICAL_STATE, delta=CREDENTIAL_DELTA)
    assert mandatory_evidence(frame.evidence), "the frame must carry a mandatory signal"
    abstained = _result(
        delta=StateDelta.empty(),
        evidence=(),
        risk=0.0,
        abstained=True,
        reason="ABSTAIN",
    )
    assert is_benign_result(abstained) is False
    violations = check_hard_security_constraints(
        _StubCell(cell_id="cell.abstain", operator=object()), frame, abstained
    )
    assert violations == ()


def test_the_vm_own_abstention_is_not_charged_with_evidence_suppression() -> None:
    """Pins S3-09 / S3-AUTH-03 through the real ``CellVM``, not a hand-built result.

    ``CellVM.run`` abstains with ``NOT_EXECUTABLE_FORM`` on every non-BYTECODE
    operator, so on a frame carrying a MANDATORY_SIGNALS token the whole
    non-bytecode candidate set was branded NEVER_SUPPRESS_MANDATORY_EVIDENCE and
    CRYSTAL reported a hard security violation where the true cause was a missing
    interpreter.
    """
    from pocketsec.stage3.bytecode.vm import CellVM
    from pocketsec.stage3.cells.operator import OperatorForm, OperatorProgram

    frame = _frame(state=CRITICAL_STATE, delta=CREDENTIAL_DELTA)
    assert mandatory_evidence(frame.evidence)
    table_form = OperatorProgram(
        form=OperatorForm.LOOKUP_TABLE, words=(), table={}, max_steps=4, max_state_bytes=64
    )
    result = CellVM().run(table_form, frame)

    assert result.abstained and result.evidence == ()
    cell = _StubCell(cell_id="cell.table", operator=table_form)
    assert check_hard_security_constraints(cell, frame, result) == ()


def test_a_benign_result_on_a_critical_frame_is_refused_at_the_ceiling() -> None:
    """Pins BENIGN_RISK_CEILING: raising it silently would let this case through."""
    frame = _frame(state=CRITICAL_STATE, delta=CREDENTIAL_DELTA)
    cell = _StubCell(cell_id="cell.ceiling", operator=object())
    at_ceiling = _result(delta=CREDENTIAL_DELTA, evidence=frame.evidence,
                         risk=BENIGN_RISK_CEILING)
    above = _result(delta=CREDENTIAL_DELTA, evidence=frame.evidence,
                    risk=BENIGN_RISK_CEILING + 0.01)
    assert consequence_of(frame.delta, frame.state) is SecurityConsequence.CRITICAL
    assert any(
        v.kind is ConstraintKind.NEVER_NORMALISE_HIGH_CONSEQUENCE
        for v in check_hard_security_constraints(cell, frame, at_ceiling)
    )
    assert check_hard_security_constraints(cell, frame, above) == ()


def test_lowering_a_dimension_breaks_monotonicity_and_phi_together() -> None:
    frame, result = _case_lowers_phi()
    kinds = {
        v.kind
        for v in check_hard_security_constraints(
            _StubCell(cell_id="cell.monotone", operator=object()), frame, result
        )
    }
    assert ConstraintKind.STATE_MONOTONE in kinds
    assert ConstraintKind.NEVER_LOWER_PHI in kinds


def test_consequence_downgrade_is_refused_separately() -> None:
    """A result that drops the privilege dimension entirely downgrades the frame."""
    frame = _frame(state=SecurityStateV1(), delta=PRIVILEGE_DELTA)
    result = _result(delta=StateDelta(raised={"discovery": (0, 1)}),
                     evidence=(MANDATORY_REF,), risk=0.9)
    kinds = {
        v.kind
        for v in check_hard_security_constraints(
            _StubCell(cell_id="cell.downgrade", operator=object()), frame, result
        )
    }
    assert ConstraintKind.NEVER_DOWNGRADE_CONSEQUENCE in kinds


def test_apply_delta_is_literal_so_a_downgrade_is_visible() -> None:
    """``raised_to`` clamps; if the oracle used it, NEVER_LOWER_PHI could never fire."""
    lowered = apply_delta(ELEVATED_STATE, StateDelta(raised={"privilege": (1, 0)}))
    assert lowered is not None
    assert lowered.privilege is Privilege.USER
    assert phi(lowered).total < phi(ELEVATED_STATE).total
    assert ELEVATED_STATE.raised_to("privilege", Privilege.USER) is ELEVATED_STATE


def test_apply_delta_refuses_a_level_outside_the_lattice() -> None:
    assert apply_delta(SecurityStateV1(), StateDelta(raised={"privilege": (0, 99)})) is None
    assert apply_delta(SecurityStateV1(), StateDelta(raised={"nonsense": (0, 1)})) is None


def test_out_of_lattice_delta_is_reported_as_a_monotonicity_violation() -> None:
    frame = _frame(state=SecurityStateV1(), delta=PRIVILEGE_DELTA)
    result = _result(delta=StateDelta(raised={"privilege": (0, 99)}),
                     evidence=(MANDATORY_REF,), risk=0.9)
    violations = check_hard_security_constraints(
        _StubCell(cell_id="cell.lattice", operator=object()), frame, result
    )
    assert [v.kind for v in violations] == [ConstraintKind.STATE_MONOTONE]


def test_mandatory_evidence_matches_whole_tokens_not_substrings() -> None:
    """``credential_accessory`` must not be mistaken for ``credential_access``."""
    assert mandatory_evidence((MANDATORY_REF,)) == (MANDATORY_REF,)
    assert mandatory_evidence((NEAR_MISS_REF, ROUTINE_REF)) == ()


def test_violation_rejects_a_kind_that_is_not_a_constraint_kind() -> None:
    with pytest.raises(ContractError, match="ConstraintKind"):
        Violation(
            constraint_id="c", kind="NEVER_LOWER_PHI", detail="d",  # type: ignore[arg-type]
            frame_digest="sha256:0",
        )


# --- Oracle A: the frozen teacher snapshot -----------------------------------


def test_consult_returns_none_not_zero_for_an_unknown_frame() -> None:
    """None is UNKNOWN. 0.0 would be a confident claim that nothing is happening."""
    known = _frame(state=SecurityStateV1(), delta=PRIVILEGE_DELTA)
    unknown = _frame(state=CRITICAL_STATE, delta=CREDENTIAL_DELTA)
    oracle = TeacherOracle(_snapshot({frame_digest(known): 0.42}))
    assert oracle.consult(known) == 0.42
    assert oracle.consult(unknown) is None
    assert TeacherOracle(None).consult(known) is None
    assert TeacherOracle(None).available is False


def test_snapshot_round_trips_through_canonical_json(tmp_path: Path) -> None:
    frame = _frame(state=SecurityStateV1(), delta=PRIVILEGE_DELTA)
    snapshot = _snapshot({frame_digest(frame): 0.375})
    path = tmp_path / "teacher.json"
    file_digest = write_snapshot(snapshot, path)
    assert file_digest.startswith("sha256:")
    assert write_snapshot(snapshot, path) == file_digest  # canonical: byte-stable
    loaded = load_snapshot(path)
    assert loaded == snapshot
    assert loaded.digest == snapshot.digest


def test_a_snapshot_with_a_mismatched_digest_fails_to_load(tmp_path: Path) -> None:
    frame = _frame(state=SecurityStateV1(), delta=PRIVILEGE_DELTA)
    snapshot = _snapshot({frame_digest(frame): 0.375})
    path = tmp_path / "tampered.json"
    write_snapshot(snapshot, path)
    text = path.read_text(encoding="utf-8").replace("0.375", "0.999")
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ContractError, match="digest mismatch"):
        load_snapshot(path)


def test_a_snapshot_cannot_declare_a_digest_it_does_not_hash_to() -> None:
    frame = _frame(state=SecurityStateV1(), delta=PRIVILEGE_DELTA)
    good = _snapshot({frame_digest(frame): 0.5})
    with pytest.raises(ContractError, match="digest mismatch"):
        replace(good, responses={frame_digest(frame): 0.6})


def test_snapshot_refuses_an_unknown_source_and_a_malformed_producer() -> None:
    assert TEACHER_SOURCES == {"phi-oracle", "tcn"}
    with pytest.raises(ContractError, match="source must be one of"):
        _snapshot({}, source="random-forest")
    with pytest.raises(ContractError, match="module:function"):
        TeacherSnapshotV1.create(
            teacher_id="t",
            source="phi-oracle",
            encoder_version=ENCODER,
            corpus_version="c",
            seed=0,
            responses={},
            measured_by="somewhere",
            experiment_id=EXPERIMENT_ID,
        )


def test_snapshot_refuses_a_response_key_that_is_not_a_frame_digest() -> None:
    with pytest.raises(ContractError, match="frame digests"):
        _snapshot({"not-a-digest": 0.5})


def test_the_tcn_source_is_loadable_and_unproduced() -> None:
    """§2.3: no TCN snapshot exists this wave. Loadable, empty of responses, UNMEASURED.

    The point of the assertion is the ``consult`` result: a TCN teacher with no
    responses reports UNKNOWN for every frame, so nothing downstream can read the
    missing teacher as agreement.
    """
    frame = _frame(state=SecurityStateV1(), delta=PRIVILEGE_DELTA)
    tcn = TeacherOracle(_snapshot({}, source="tcn"))
    assert tcn.available is True
    assert tcn.source == "tcn"
    assert tcn.consult(frame) is None


def test_phi_oracle_snapshot_reproduces_the_encoder_squash() -> None:
    from pocketsec.stage2.compile_candidates.phi_oracle_candidate import PHI_ORACLE_SCORER

    frames = [
        _frame(state=SecurityStateV1(), delta=PRIVILEGE_DELTA, delta_phi=2.0),
        _frame(state=CRITICAL_STATE, delta=CREDENTIAL_DELTA, delta_phi=-6.0),
    ]
    snapshot = build_phi_oracle_snapshot(
        frames,
        scorer=PHI_ORACLE_SCORER,
        teacher_id="pocketsec.teacher.phi-oracle",
        corpus_version="crystal-test-1",
        seed=11,
        experiment_id=EXPERIMENT_ID,
    )
    assert snapshot.source == "phi-oracle"
    assert snapshot.responses[frame_digest(frames[0])] == pytest.approx(2.0 / 10.0)
    # Magnitude, not direction: a fall in Phi scores exactly like a rise.
    assert snapshot.responses[frame_digest(frames[1])] == pytest.approx(6.0 / 14.0)
    assert phi_oracle_score(0.0) == 0.0


def test_phi_oracle_snapshot_refuses_a_scorer_that_reads_another_feature() -> None:
    from pocketsec.stage2.compile_candidates.phi_oracle_candidate import (
        PHI_ORACLE_SCORER,
        PHI_SIGN_FEATURE_INDEX,
    )

    wrong = replace(PHI_ORACLE_SCORER, feature_index=PHI_SIGN_FEATURE_INDEX)
    with pytest.raises(ContractError, match="must read feature"):
        build_phi_oracle_snapshot(
            [_frame(state=SecurityStateV1(), delta=PRIVILEGE_DELTA)],
            scorer=wrong,
            teacher_id="t",
            corpus_version="c",
            seed=1,
            experiment_id=EXPERIMENT_ID,
        )


def test_phi_oracle_snapshot_refuses_empty_and_mixed_encoder_corpora() -> None:
    from pocketsec.stage2.compile_candidates.phi_oracle_candidate import PHI_ORACLE_SCORER

    kwargs: dict[str, Any] = {
        "scorer": PHI_ORACLE_SCORER,
        "teacher_id": "t",
        "corpus_version": "c",
        "seed": 1,
        "experiment_id": EXPERIMENT_ID,
    }
    with pytest.raises(ContractError, match="no teacher"):
        build_phi_oracle_snapshot([], **kwargs)
    mixed = [
        _frame(state=SecurityStateV1(), delta=PRIVILEGE_DELTA),
        replace(_frame(state=CRITICAL_STATE, delta=CREDENTIAL_DELTA), encoder_version="other"),
    ]
    with pytest.raises(ContractError, match="encoder versions"):
        build_phi_oracle_snapshot(mixed, **kwargs)


def test_frame_digest_ignores_nothing_that_changes_the_security_meaning() -> None:
    base = _frame(state=SecurityStateV1(), delta=PRIVILEGE_DELTA)
    assert frame_digest(base) == frame_digest(_frame(state=SecurityStateV1(),
                                                     delta=PRIVILEGE_DELTA))
    assert frame_digest(base) != frame_digest(replace(base, epoch_id=1))
    assert frame_digest(base) != frame_digest(replace(base, uncertainty=0.5))
    assert frame_digest(base) != frame_digest(replace(base, evidence=(ROUTINE_REF,)))


# --- D3.9 counterexample memory ----------------------------------------------


def _transition(sequence: int) -> SSIRTransitionV1:
    return SSIRTransitionV1(
        actor=Entity(identity=f"proc:{sequence}"),
        relation=Relation.READ,
        object=Entity(identity=f"file:{sequence}"),
        state_delta=PRIVILEGE_DELTA,
        uncertainty=0.1,
        novelty=NoveltyTensor(values=dict.fromkeys(NOVELTY_CONTEXTS, 0.5)),
        causal_signature=f"sig-{sequence}",
        parent_signature="sig-root",
        responsibility=1.0,
        temporal=TemporalContext(),
        evidence=(ROUTINE_REF,),
        epoch_id=0,
        sequence=sequence,
    )


def _counterexample(
    index: int, *, incident_linked: bool = False, candidate: str = "cand.alpha"
) -> Counterexample:
    expected = _result(delta=PRIVILEGE_DELTA, evidence=(MANDATORY_REF,), risk=0.9)
    observed = _result(delta=StateDelta.empty(), evidence=(), risk=0.0, abstained=True)
    return Counterexample(
        counterexample_id=f"cx.{index:04d}",
        cell_candidate_id=candidate,
        transitions=(_transition(index),),
        state=SecurityStateV1(),
        epoch_id=0,
        expected=expected,
        observed=observed,
        divergence_type="ABSTAINED_ON_HIGH_CONSEQUENCE",
        evidence=(MANDATORY_REF,),
        incident_linked=incident_linked,
    )


def test_the_store_exposes_no_delete_api() -> None:
    """Enforced by absence, not by review. Would fail the moment anyone added one."""
    store = CounterexampleStore(cold_archive=None)
    forbidden = ("delete", "remove", "discard", "purge", "evict", "clear", "pop", "drop")
    exposed = [
        name
        for name in dir(store)
        if not name.startswith("_") and any(word in name.lower() for word in forbidden)
    ]
    assert exposed == []
    assert not hasattr(store, "__delitem__")


def test_the_store_never_drops_an_incident_linked_counterexample(tmp_path: Path) -> None:
    store = CounterexampleStore(cold_archive=tmp_path / "cold.jsonl", max_hot=2)
    store.record(_counterexample(1, incident_linked=True))
    store.record(_counterexample(2, incident_linked=False))
    store.record(_counterexample(3))
    ids = [cx.counterexample_id for cx in store.hot()]
    assert "cx.0001" in ids, "the incident-linked entry was spilled"
    assert "cx.0002" not in ids, "the oldest non-incident entry should have spilled"
    assert store.archived_count == 1
    assert (tmp_path / "cold.jsonl").read_bytes().count(b"\n") == 1


def test_the_store_raises_rather_than_dropping_when_every_entry_is_incident_linked(
    tmp_path: Path,
) -> None:
    store = CounterexampleStore(cold_archive=tmp_path / "cold.jsonl", max_hot=2)
    store.record(_counterexample(1, incident_linked=True))
    store.record(_counterexample(2, incident_linked=True))
    with pytest.raises(ContractError, match="incident-linked"):
        store.record(_counterexample(3))
    assert len(store) == 2
    assert store.archived_count == 0


def test_a_store_with_no_cold_archive_refuses_rather_than_losing_a_record() -> None:
    store = CounterexampleStore(cold_archive=None, max_hot=1)
    store.record(_counterexample(1))
    with pytest.raises(ContractError, match="no cold archive"):
        store.record(_counterexample(2))
    assert len(store) == 1


def test_re_recording_an_identical_counterexample_is_a_no_op() -> None:
    """The same failure found twice is one fact; producers hash content into the id."""
    store = CounterexampleStore(cold_archive=None)
    store.record(_counterexample(1))
    store.record(_counterexample(1))
    assert len(store) == 1
    assert store.memory_bytes() == _counterexample(1).size_bytes()


def test_the_store_refuses_a_different_record_under_a_held_id() -> None:
    """Overwriting evidence is the one thing the store exists to make impossible."""
    store = CounterexampleStore(cold_archive=None)
    store.record(_counterexample(1))
    imposter = replace(_counterexample(1), divergence_type="SOMETHING_ELSE")
    with pytest.raises(ContractError, match="different"):
        store.record(imposter)
    assert store.hot()[0].divergence_type == "ABSTAINED_ON_HIGH_CONSEQUENCE"


def test_supersede_marks_and_keeps_the_record() -> None:
    store = CounterexampleStore(cold_archive=None)
    store.record(_counterexample(1))
    store.record(_counterexample(2))
    store.supersede("cx.0001", "cx.0002")
    held = {cx.counterexample_id: cx for cx in store.hot()}
    assert set(held) == {"cx.0001", "cx.0002"}
    assert held["cx.0001"].superseded_by == "cx.0002"
    assert replay_corpus_size(store) == 1
    with pytest.raises(ContractError, match="already superseded"):
        store.supersede("cx.0001", "cx.0002")


def test_supersede_refuses_a_successor_that_does_not_exist() -> None:
    store = CounterexampleStore(cold_archive=None)
    store.record(_counterexample(1))
    with pytest.raises(ContractError, match="does not"):
        store.supersede("cx.0001", "cx.9999")
    with pytest.raises(ContractError, match="cannot supersede itself"):
        store.supersede("cx.0001", "cx.0001")


def test_for_candidate_scopes_and_memory_bytes_tracks_the_bound() -> None:
    store = CounterexampleStore(cold_archive=None)
    store.record(_counterexample(1, candidate="cand.alpha"))
    store.record(_counterexample(2, candidate="cand.beta"))
    assert [cx.counterexample_id for cx in store.for_candidate("cand.beta")] == ["cx.0002"]
    assert store.memory_bytes() == sum(cx.size_bytes() for cx in store.hot())
    assert 0 < store.memory_bytes() <= MAX_HOT_BYTES


def test_the_store_refuses_bounds_above_the_declared_maximums() -> None:
    with pytest.raises(ContractError, match="exceeds the §38 bound"):
        CounterexampleStore(cold_archive=None, max_hot=MAX_HOT_COUNTEREXAMPLES + 1)
    with pytest.raises(ContractError, match="exceeds the §38 bound"):
        CounterexampleStore(cold_archive=None, max_bytes=MAX_HOT_BYTES + 1)


def test_the_byte_bound_spills_before_the_count_bound_when_it_binds(tmp_path: Path) -> None:
    """The byte cap must bind on its own, not only as a side effect of the count cap."""
    one = _counterexample(1)
    store = CounterexampleStore(
        cold_archive=tmp_path / "cold.jsonl", max_hot=64, max_bytes=one.size_bytes() + 8
    )
    store.record(one)
    store.record(_counterexample(2))
    assert len(store) == 1
    assert store.archived_count == 1
    assert store.memory_bytes() <= one.size_bytes() + 8


def test_counterexample_refuses_an_empty_transition_sequence() -> None:
    with pytest.raises(ContractError, match="non-empty tuple"):
        replace(_counterexample(1), transitions=())


def test_replay_all_refuses_without_a_frame_builder_and_returns_failures_with_one() -> None:
    store = CounterexampleStore(cold_archive=None)
    store.record(_counterexample(1))
    cell = _StubCell(cell_id="cell.replay", operator=object())
    with pytest.raises(ContractError, match="frame_builder"):
        store.replay_all(cell, vm=_ScriptedVM(lambda _f: None))

    frame = _frame(state=SecurityStateV1(), delta=PRIVILEGE_DELTA)
    repaired = _result(delta=PRIVILEGE_DELTA, evidence=(MANDATORY_REF,), risk=0.9)
    still_broken = _result(delta=StateDelta.empty(), evidence=(), risk=0.0, abstained=True)

    fixed_store = CounterexampleStore(cold_archive=None, frame_builder=lambda _cx: frame)
    fixed_store.record(_counterexample(1))
    assert fixed_store.replay_all(cell, vm=_ScriptedVM(lambda _f: repaired)) == ()
    assert len(fixed_store.replay_all(cell, vm=_ScriptedVM(lambda _f: still_broken))) == 1


def test_replay_all_skips_superseded_records() -> None:
    frame = _frame(state=SecurityStateV1(), delta=PRIVILEGE_DELTA)
    still_broken = _result(delta=StateDelta.empty(), evidence=(), risk=0.0, abstained=True)
    store = CounterexampleStore(cold_archive=None, frame_builder=lambda _cx: frame)
    store.record(_counterexample(1))
    store.record(_counterexample(2))
    store.supersede("cx.0001", "cx.0002")
    failing = store.replay_all(
        _StubCell(cell_id="cell.replay", operator=object()),
        vm=_ScriptedVM(lambda _f: still_broken),
    )
    assert [cx.counterexample_id for cx in failing] == ["cx.0002"]
