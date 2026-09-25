"""D3.14/D3.15/D3.16 — the Stage 3 runtime seam, its resource story and its controls.

This file tests behaviour and failure paths, not construction. The things it is
here to break are:

* an abstention that quietly becomes a guess;
* a resource report that calls UNMEASURED "within target";
* a garbage collector that frees a cell whose cost nobody measured;
* a Stage 4 handoff that leaks a Stage 3 class name;
* a threat case that passes because the attack was never viable;
* a baseline suite that reports a comparison against a broken control.

Several tests are written so they would fail if the invariant were *weakened*
rather than only if it were removed —
``test_a_resource_report_cannot_claim_within_budget_without_measuring`` and
``test_gc_retains_an_unmeasured_cell_even_under_budget_pressure`` in particular.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from pocketsec.stage0.contracts.common import ContractError, EvidenceRef, digest_of_bytes
from pocketsec.stage0.contracts.model_slot import validate_slot
from pocketsec.stage0.contracts.security_event_v1 import (
    SecurityEventSequenceV1,
    SecurityEventV1,
)
from pocketsec.stage0.contracts.threat_prediction_v1 import (
    FORBIDDEN_AUTHORITY_FIELDS,
    ComputePath,
    ThreatPredictionV1,
    Verdict,
)
from pocketsec.stage3.boundary.index import BoundaryIndex
from pocketsec.stage3.bytecode.vm import CellVM
from pocketsec.stage3.cells.field import KnowledgeField
from pocketsec.stage3.cells.schema import KnowledgeCellV1
from pocketsec.stage3.gc.controller import (
    CellUtility,
    GCReason,
    GCReport,
    garbage_collect_knowledge,
)
from pocketsec.stage3.labs.ablation import (
    AblationReport,
    AblationStatus,
    ComponentVerdict,
    run_ablation,
    saturation_guard,
)
from pocketsec.stage3.labs.baselines import (
    AT_CHANCE_PR_AUC_BAND,
    BASELINE_IDS,
    BaselineTable,
    CellPathBaseline,
    phi_oracle_cell,
    run_baselines,
    teacher_error_cases,
)
from pocketsec.stage3.labs.boundary_evasion import (
    THREAT_CASE_IDS,
    ThreatSuiteReport,
    run_threat_suite,
)
from pocketsec.stage3.labs.crystal_corpus import (
    CRYSTAL_CORPUS_VERSION,
    CrystalCorpus,
    build_crystal_corpus,
    median_peak_delta_phi,
    operation_counts,
    session_frames,
    session_identity_owners,
    vocabulary_leak,
)
from pocketsec.stage3.resources import (
    STAGE3_BUDGET,
    STAGE3_NORMAL_INCREMENTAL_RSS_BYTES,
    Stage3ResourceReport,
    loadavg,
    measure_stage3_resources,
    unmeasured_stage3_resources,
)
from pocketsec.stage3.slot import SUSPICIOUS_RISK_FLOOR, CrystalSlot
from pocketsec.stage3.stage4_interface import (
    CRYSTAL_HANDOFF_V1_ID,
    CrystalHandoffV1,
    build_crystal_handoff,
    seam_violations,
    write_crystal_handoff,
)

#: Small enough to keep the suite quick, large enough that the drift corpus still
#: places both of its corroborated changes (25% and 50%).
CORPUS_COUNT = 24
FIT_SEED = 11
EVAL_SEED = 29

MEASURED_BY = "tests.test_stage3_runtime:fixture"


# --- fixtures ----------------------------------------------------------------


def _event(index: int) -> SecurityEventV1:
    return SecurityEventV1(
        event_id=f"ev-{index:03d}",
        host_id="lab-host-01",
        boot_id="boot-0001",
        observed_at_ns=1_000_000_000 + index * 1000,
        monotonic_ns=index * 1000,
        source="test.source",
        kind="process.exec",
        attributes={"i": str(index)},
        evidence=(
            EvidenceRef(
                store="raw.credential_access",
                locator=f"e{index}",
                digest=digest_of_bytes(f"e{index}".encode()),
            ),
        ),
    )


def _sequence(sequence_id: str = "seq-1") -> SecurityEventSequenceV1:
    return SecurityEventSequenceV1(
        sequence_id=sequence_id,
        host_id="lab-host-01",
        events=(_event(0), _event(1)),
    )


@pytest.fixture(scope="module")
def fit_corpus() -> CrystalCorpus:
    return build_crystal_corpus(count=CORPUS_COUNT, seed=FIT_SEED)


@pytest.fixture(scope="module")
def eval_corpus() -> CrystalCorpus:
    return build_crystal_corpus(count=CORPUS_COUNT, seed=EVAL_SEED)


@pytest.fixture(scope="module")
def baseline_table(fit_corpus: CrystalCorpus, eval_corpus: CrystalCorpus) -> BaselineTable:
    return run_baselines(fit=fit_corpus, evaluation=eval_corpus)


@pytest.fixture(scope="module")
def threat_suite() -> ThreatSuiteReport:
    return run_threat_suite()


def _slot_with_cell(
    corpus: CrystalCorpus, *, sequence_id: str = "seq-1"
) -> tuple[CrystalSlot, KnowledgeCellV1]:
    """A slot holding one Φ-oracle cell and one session's frames.

    The session is chosen as the first whose frames the cell actually claims, so
    a hit test measures the hit path rather than the corpus's luck.
    """
    cell = phi_oracle_cell()
    field = KnowledgeField()
    field.insert(cell)
    index = BoundaryIndex()
    index.insert(cell)
    for session in corpus.sessions:
        frames = session_frames(session)
        claimed = [f for f in frames if index.lookup(f) is not None]
        if claimed:
            return CrystalSlot(
                field=field,
                index=index,
                vm=CellVM(),
                frames={sequence_id: tuple(claimed)},
            ), cell
    pytest.fail("no session in the corpus produced a frame inside the cell's boundary")


# --- D3.16: the model slot ----------------------------------------------------


def test_validate_slot_accepts_crystal_slot() -> None:
    slot = CrystalSlot(field=KnowledgeField(), index=BoundaryIndex(), vm=CellVM())
    validate_slot(slot)
    assert slot.slot_name == "stage3-crystal"


def test_a_cell_hit_reports_cheap_transition_and_carries_evidence(
    eval_corpus: CrystalCorpus,
) -> None:
    slot, _cell = _slot_with_cell(eval_corpus)
    prediction = slot.predict(_sequence())
    assert prediction.compute_path is ComputePath.CHEAP_TRANSITION
    assert not prediction.abstained
    assert prediction.verdict in {Verdict.BENIGN, Verdict.SUSPICIOUS}
    # G3.8: a resolved prediction is bound to the evidence behind it.
    assert prediction.evidence_relevance, "a cell hit must carry an EvidenceRef chain"
    assert all(isinstance(item.ref, EvidenceRef) for item in prediction.evidence_relevance)


def test_detection_score_through_stage0s_harness_is_monotone_in_the_cells_risk() -> None:
    """Pins S3-01: the slot wrote the composed *risk* into ``confidence``.

    ADR-0004 fixes ``confidence`` as confidence *in the stated verdict*, so Stage
    0's harness maps a BENIGN verdict through ``1 - confidence``. Writing the risk
    there for both verdicts inverted the detection ranking across the whole BENIGN
    band: a cell's most-benign window scored 1.00, the maximum. Run every verdict
    the slot can produce through the real harness function and require the score to
    rise with risk.
    """
    from pocketsec.stage0.benchmark.harness import _detection_score
    from pocketsec.stage1.state.security_state import StateDelta
    from pocketsec.stage3.cells.field import CompositionOutcome, CompositionVerdict
    from pocketsec.stage3.slot import SUSPICIOUS_RISK_FLOOR

    slot = CrystalSlot(field=KnowledgeField(), index=BoundaryIndex(), vm=CellVM())
    risks = [0.0, 0.05, 0.2, 0.24, SUSPICIOUS_RISK_FLOOR, 0.6, 1.0]
    scores: list[float] = []
    for risk in risks:
        verdict = CompositionVerdict(
            outcome=CompositionOutcome.RESOLVED,
            delta=StateDelta(raised={}),
            risk=risk,
            evidence=(),
            escalation=None,
            contributing=("cell-x",),
            reason="unit",
        )
        prediction = slot._resolved(_sequence(), verdict, truncated=False)
        scores.append(_detection_score(prediction))
        if risk >= SUSPICIOUS_RISK_FLOOR:
            assert prediction.verdict is Verdict.SUSPICIOUS
            assert prediction.confidence == pytest.approx(risk)
        else:
            assert prediction.verdict is Verdict.BENIGN
            assert prediction.confidence == pytest.approx(1.0 - risk)

    assert scores == sorted(scores), f"detection score is not monotone in risk: {scores}"
    assert scores[0] == pytest.approx(0.0), "the least-risky window must score lowest"
    assert scores[-1] == pytest.approx(1.0)


def test_a_confident_benign_is_not_reported_as_maximally_uncertain() -> None:
    """Pins S3-01's second half: ``uncertainty = 1 - risk`` on a committal verdict.

    A risk-0.0 BENIGN reported ``uncertainty=1.0`` with ``abstained=False`` — a
    maximally uncertain committal answer, which no contract rejected. Uncertainty is
    now the distance from the decision threshold, so it peaks *at* the threshold.
    """
    from pocketsec.stage1.state.security_state import StateDelta
    from pocketsec.stage3.cells.field import CompositionOutcome, CompositionVerdict
    from pocketsec.stage3.slot import SUSPICIOUS_RISK_FLOOR

    slot = CrystalSlot(field=KnowledgeField(), index=BoundaryIndex(), vm=CellVM())

    def _predict(risk: float, *, truncated: bool = False) -> ThreatPredictionV1:
        verdict = CompositionVerdict(
            outcome=CompositionOutcome.RESOLVED,
            delta=StateDelta(raised={}),
            risk=risk,
            evidence=(),
            escalation=None,
            contributing=("cell-x",),
            reason="unit",
        )
        return slot._resolved(_sequence(), verdict, truncated=truncated)

    confident_benign = _predict(0.0)
    assert not confident_benign.abstained
    assert confident_benign.uncertainty == pytest.approx(0.0)
    assert _predict(1.0).uncertainty == pytest.approx(0.0)
    assert _predict(SUSPICIOUS_RISK_FLOOR).uncertainty == pytest.approx(1.0)
    # Truncation raises uncertainty; it can never lower it.
    assert _predict(0.0, truncated=True).uncertainty >= 0.5
    assert _predict(SUSPICIOUS_RISK_FLOOR, truncated=True).uncertainty == pytest.approx(1.0)


def test_a_near_boundary_miss_is_reported_apart_from_unexplored_territory(
    eval_corpus: CrystalCorpus,
) -> None:
    """Pins S3-11: ``near_boundary`` was measured and never consulted.

    §40 asks for a near-boundary match to raise DTL/AOP activation, which needs
    "near" to be distinguishable from "nothing was ever crystallised here". Both
    cases are still abstentions — a cell answering next to its boundary is the
    silent extrapolation §10 forbids — but they are now different reasons.
    """
    slot, _cell = _slot_with_cell(eval_corpus)
    one_clause_out = tuple(replace(f, epoch_id=99) for f in slot.frames["seq-1"])
    near = CrystalSlot(
        field=slot.field, index=slot.index, vm=slot.vm, frames={"seq-1": one_clause_out}
    )
    assert near.index.near_boundary(one_clause_out[0]), "the fixture must sit one clause out"
    near_prediction = near.predict(_sequence())
    assert near_prediction.abstained

    empty = CrystalSlot(
        field=KnowledgeField(), index=BoundaryIndex(), vm=CellVM(), frames={"seq-1": one_clause_out}
    )
    empty_prediction = empty.predict(_sequence())
    assert empty_prediction.abstained

    assert set(near.abstention_reasons) != set(empty.abstention_reasons)
    assert any("near a boundary" in reason for reason in near.abstention_reasons)
    assert not any("near a boundary" in reason for reason in empty.abstention_reasons)


def test_no_cell_yields_unknown_and_never_a_guess() -> None:
    slot = CrystalSlot(field=KnowledgeField(), index=BoundaryIndex(), vm=CellVM())
    prediction = slot.predict(_sequence())
    assert prediction.verdict is Verdict.UNKNOWN
    assert prediction.abstained
    assert prediction.confidence == 0.0
    assert prediction.uncertainty == 1.0
    # The whole point: abstention is not a low-confidence commitment.
    assert not prediction.is_committal


def test_an_off_boundary_frame_abstains_rather_than_answering(
    eval_corpus: CrystalCorpus,
) -> None:
    """The boundary is the control, and moving one clause outside must lose the answer."""
    slot, _cell = _slot_with_cell(eval_corpus)
    off_boundary = tuple(replace(f, epoch_id=99) for f in slot.frames["seq-1"])
    evasive = CrystalSlot(
        field=slot.field, index=slot.index, vm=slot.vm, frames={"seq-1": off_boundary}
    )
    prediction = evasive.predict(_sequence())
    assert prediction.verdict is Verdict.UNKNOWN
    assert prediction.abstained


def test_a_claimed_frame_whose_program_abstains_still_yields_unknown(
    eval_corpus: CrystalCorpus,
) -> None:
    """The VM runs nothing it cannot execute, and the slot must not fill the gap.

    A ``LOOKUP_TABLE`` operator is structurally sound and is not instructions, so
    ``CellVM`` abstains. The cell still *claims* the frame, so this exercises the
    "claimed but unanswered" path rather than the "no cell" path.
    """
    from pocketsec.stage3.cells.operator import OperatorForm, OperatorProgram

    slot, cell = _slot_with_cell(eval_corpus)
    table_cell = replace(
        cell,
        cell_id="cell-table",
        operator=OperatorProgram(
            form=OperatorForm.LOOKUP_TABLE,
            words=(),
            table={"1:2:4": 0.81},
            max_steps=4,
            max_state_bytes=64,
        ),
    )
    field = KnowledgeField()
    field.insert(table_cell)
    index = BoundaryIndex()
    index.insert(table_cell)
    unanswering = CrystalSlot(
        field=field, index=index, vm=CellVM(), frames=dict(slot.frames)
    )
    prediction = unanswering.predict(_sequence())
    assert prediction.verdict is Verdict.UNKNOWN
    assert prediction.abstained
    # The evidence the claimed frames carried still reaches the caller, so an
    # abstention is investigable rather than a dead end.
    assert prediction.evidence_relevance


def test_the_slot_never_commits_to_malicious(
    eval_corpus: CrystalCorpus,
) -> None:
    """A bounded invariant attributes nothing; SUSPICIOUS is its ceiling."""
    slot, _cell = _slot_with_cell(eval_corpus)
    prediction = slot.predict(_sequence())
    assert prediction.verdict is not Verdict.MALICIOUS
    assert 0.0 <= SUSPICIOUS_RISK_FLOOR <= 1.0


def test_the_slot_records_why_it_abstained_without_growing_with_traffic() -> None:
    """An abstention must be explainable, and the explanation must stay bounded."""
    from pocketsec.stage3.cells.field import CompositionOutcome
    from pocketsec.stage3.slot import slot_report

    slot = CrystalSlot(field=KnowledgeField(), index=BoundaryIndex(), vm=CellVM())
    for index in range(50):
        slot.predict(_sequence(f"seq-{index}"))
    assert sum(slot.abstention_reasons.values()) == 50
    # One reason, not fifty: the keys are a closed set, never per-sequence text.
    assert len(slot.abstention_reasons) == 1
    allowed = {outcome.value for outcome in CompositionOutcome} | set(slot.abstention_reasons)
    assert set(slot.abstention_reasons) <= allowed
    assert slot_report(slot)["abstention_reasons"] == slot.abstention_reasons


def test_crystal_slot_carries_no_authority_field() -> None:
    from dataclasses import fields as dataclass_fields

    names = {member.name.lower() for member in dataclass_fields(CrystalSlot)}
    offenders = {
        name for name in names if any(token in name for token in FORBIDDEN_AUTHORITY_FIELDS)
    }
    assert offenders == set(), f"CrystalSlot names response-authority fields {offenders}"


def test_a_slot_declaring_an_authority_field_cannot_be_constructed() -> None:
    """The audit is over ``__dataclass_fields__``, so adding one breaks construction."""
    from dataclasses import make_dataclass

    rogue = make_dataclass(
        "RogueSlot",
        [("quarantine_action", str, "kill")],
        bases=(CrystalSlot,),
        kw_only=True,
    )
    with pytest.raises(ContractError, match="response-authority"):
        rogue(field=KnowledgeField(), index=BoundaryIndex(), vm=CellVM())


def test_predict_refuses_anything_that_is_not_a_sequence() -> None:
    slot = CrystalSlot(field=KnowledgeField(), index=BoundaryIndex(), vm=CellVM())
    with pytest.raises(ContractError, match="SecurityEventSequenceV1"):
        slot.predict("seq-1")  # type: ignore[arg-type]


# --- D3.16: the Stage 4 seam --------------------------------------------------


def test_the_handoff_round_trips_exactly(tmp_path: Path) -> None:
    field = KnowledgeField()
    index = BoundaryIndex()
    cell = phi_oracle_cell()
    field.insert(cell)
    index.insert(cell)
    handoff = build_crystal_handoff(field, index, handoff_id="handoff-0001")
    payload = handoff.to_dict()
    assert payload["schema_id"] == CRYSTAL_HANDOFF_V1_ID
    assert CrystalHandoffV1.from_dict(payload) == handoff
    digest = write_crystal_handoff(handoff, tmp_path / "crystal.json")
    assert digest.startswith("sha256:")
    reloaded = json.loads((tmp_path / "crystal.json").read_bytes())
    assert CrystalHandoffV1.from_dict(reloaded) == handoff


def test_the_seam_refuses_an_infinity_before_the_bytes_exist() -> None:
    """Pins S3-AUTH-09: ``_require_json`` rejected NaN but not ±inf.

    The module's opening claim is that "the refusal runs *before* the bytes exist,
    so a leak cannot be written and then noticed". A handoff carrying ``inf``
    constructed cleanly and then raised ValueError — not ContractError — at the
    write, inside ``json.dumps(..., allow_nan=False)``: the guard that exists
    specifically to stop non-canonical floats reaching the seam caught one of the
    three non-canonical values.
    """
    from pocketsec.stage3.stage4_interface import _require_json

    assert _require_json(1.5, field="x") == 1.5
    for bad in (float("inf"), float("-inf"), float("nan")):
        with pytest.raises(ContractError):
            _require_json(bad, field="x")
        with pytest.raises(ContractError):
            _require_json({"a": [1.0, bad]}, field="x")


def test_a_real_assurance_state_crosses_the_seam_as_plain_data() -> None:
    """The handoff must carry ``lifecycle``'s own projections, not a re-derived shape."""
    from pocketsec.stage3.cells.schema import AssuranceLevel
    from pocketsec.stage3.promotion.assurance import AssuranceState

    state = AssuranceState(
        level=AssuranceLevel.A1,
        replay=None,
        pressure=None,
        shadow=None,
        exhaustive_domain=None,
        proven_properties=(),
        prover=None,
        counterexamples_open=0,
    )
    field = KnowledgeField()
    index = BoundaryIndex()
    cell = phi_oracle_cell()
    field.insert(cell)
    index.insert(cell)
    handoff = build_crystal_handoff(
        field, index, handoff_id="handoff-0004", assurance=(state.to_dict(),)
    )
    payload = handoff.to_dict()
    assert payload["assurance"][0]["level"] == "A1"
    assert seam_violations(payload) == ()
    assert CrystalHandoffV1.from_dict(payload) == handoff


def test_the_handoff_refuses_to_emit_a_stage3_class_name() -> None:
    with pytest.raises(ContractError, match="Stage 3 classes"):
        CrystalHandoffV1(
            handoff_id="handoff-0002",
            cells=({"KnowledgeCellV1": {"cell_id": "c1"}},),
            assurance=(),
            boundary_keys=(),
            melt_history=(),
            encoder_version="dtl-encoder.1.0.0",
        )


def test_seam_violations_finds_a_class_name_nested_in_a_list() -> None:
    assert seam_violations({"rows": [{"cell_vm": 1}]}) == ("handoff.rows[0].cell_vm",)
    # Plain data must NOT be caught, or nothing could ever cross the seam.
    assert seam_violations({"cells": [{"cell_id": "c1", "epochs": [0]}]}) == ()


def test_the_handoff_refuses_a_python_object() -> None:
    with pytest.raises(ContractError, match="plain JSON"):
        CrystalHandoffV1(
            handoff_id="handoff-0003",
            cells=({"operator": object()},),
            assurance=(),
            boundary_keys=(),
            melt_history=(),
            encoder_version="dtl-encoder.1.0.0",
        )


# --- D3.14: intelligence GC ---------------------------------------------------


def _utility(**overrides: object) -> CellUtility:
    base: dict[str, object] = {
        "saved_compute_us": 4.0,
        "usage": 100,
        "assurance": 0.9,
        "security_utility": 0.5,
        "memory_bytes": 2048,
        "audit_cost_us": 0.5,
        "maintenance_cost_us": 0.5,
    }
    base.update(overrides)
    return CellUtility(**base)  # type: ignore[arg-type]


def test_cell_utility_is_none_when_any_measured_term_is_none() -> None:
    assert _utility().utility is not None
    for missing in ("saved_compute_us", "audit_cost_us", "maintenance_cost_us"):
        assert _utility(**{missing: None}).utility is None, missing


def test_utility_goes_negative_when_audit_costs_more_than_the_cell_saves() -> None:
    """Falsifier F5 must be representable, or it can never be measured."""
    value = _utility(saved_compute_us=0.2, audit_cost_us=2.0).utility
    assert value is not None and value < 0.0


def test_gc_retains_every_cell_whose_utility_is_none() -> None:
    field = KnowledgeField()
    index = BoundaryIndex()
    for name in ("cell-a", "cell-b"):
        cell = phi_oracle_cell(cell_id=name)
        field.insert(cell)
        index.insert(cell)
    report = garbage_collect_knowledge(
        field,
        index=index,
        store=None,
        budget_bytes=10 * 1024 * 1024,
        utilities={"cell-a": _utility(saved_compute_us=None)},
    )
    assert report.compacted == 0
    assert report.retained == 2
    # cell-a has an UNMEASURED utility, cell-b has none at all: both are unmeasured.
    assert report.unmeasured_skipped == 2
    assert field.get("cell-a") is not None


def test_gc_retains_an_unmeasured_cell_even_under_budget_pressure() -> None:
    """The invariant someone will be tempted to weaken: "just this once, we are over budget".

    A budget of zero bytes is maximum pressure. Nothing measured means nothing
    collected, and the field is left visibly over budget instead.
    """
    field = KnowledgeField()
    cell = phi_oracle_cell(cell_id="cell-unmeasured")
    field.insert(cell)
    report = garbage_collect_knowledge(field, store=None, budget_bytes=0, utilities={})
    assert report.compacted == 0
    assert report.bytes_reclaimed == 0
    assert report.bytes_after > 0, "the field stays over budget rather than losing knowledge"
    assert field.get("cell-unmeasured") is not None


def test_gc_collects_a_measured_negative_utility_cell() -> None:
    """The control for the test above: measured cells *are* collectable."""
    field = KnowledgeField()
    index = BoundaryIndex()
    cell = phi_oracle_cell(cell_id="cell-costly")
    field.insert(cell)
    index.insert(cell)
    report = garbage_collect_knowledge(
        field,
        index=index,
        store=None,
        budget_bytes=10 * 1024 * 1024,
        utilities={"cell-costly": _utility(saved_compute_us=0.1, audit_cost_us=5.0)},
    )
    assert report.compacted == 1
    assert report.compacted_ids == (("cell-costly", GCReason.NEGATIVE_UTILITY),)
    assert field.get("cell-costly") is None
    assert "cell-costly" not in index.cell_ids()


def test_gc_never_collects_incident_linked_evidence(tmp_path: Path) -> None:
    """Incident evidence is protected independently of cell GC (§29, §40)."""
    from pocketsec.stage3.labs.boundary_evasion import make_counterexample
    from pocketsec.stage3.oracles.counterexamples import CounterexampleStore

    store = CounterexampleStore(cold_archive=tmp_path / "cold.jsonl", max_hot=8)
    for index in range(3):
        store.record(make_counterexample(index, incident=True))
    field = KnowledgeField()
    cell = phi_oracle_cell(cell_id="cell-costly")
    field.insert(cell)
    before = len(store.hot())
    report = garbage_collect_knowledge(
        field,
        store=store,
        budget_bytes=0,
        utilities={"cell-costly": _utility(saved_compute_us=0.0, audit_cost_us=9.0)},
    )
    assert report.compacted == 1, "the cell itself is collectable"
    assert report.incident_protected == 3
    assert len(store.hot()) == before, "GC must not reach into the counterexample store"


def test_gc_collects_a_measured_duplicate_but_keeps_the_survivor() -> None:
    """The control for the unmeasured-retention rule: measured duplicates DO go."""
    field = KnowledgeField()
    index = BoundaryIndex()
    for name in ("cell-a", "cell-b"):
        cell = phi_oracle_cell(cell_id=name)
        field.insert(cell)
        index.insert(cell)
    report = garbage_collect_knowledge(
        field,
        index=index,
        store=None,
        budget_bytes=10 * 1024 * 1024,
        utilities={"cell-a": _utility(), "cell-b": _utility()},
    )
    assert report.compacted == 1
    assert report.compacted_ids[0][1] == GCReason.DUPLICATE
    assert len(field) == 1, "exactly one survivor, and the lineage of the other is not lost"
    assert report.bytes_reclaimed > 0


def test_gc_keeps_same_operator_cells_that_cover_disjoint_regions() -> None:
    """Pins S3-06 / S3-03(resource-simplicity): DUPLICATE_OPERATOR ignored the region.

    ``OperatorProgram.digest`` is computed from the program's own canonical bytes,
    so cells compiled from one bounded rule over *disjoint* boundaries collide on
    it by construction — which is what crystallising a zero-parameter Φ-oracle per
    relation family produces. Keying duplicates on ``(operator digest, epochs)``
    deleted all but one of them, under a reason that was false: they were not
    duplicates, they covered disjoint index keys. Same-operator-different-region is
    a fusion question, never a collection one.
    """
    from pocketsec.stage3.gate_criteria import actor_predicate
    from pocketsec.stage1.ssir.relations import RelationFamily

    field = KnowledgeField()
    index = BoundaryIndex()
    families = (RelationFamily.IDENTITY, RelationFamily.AUTHORIZATION, RelationFamily.LOADING)
    cells = []
    for position, family in enumerate(families, start=1):
        cell = phi_oracle_cell(cell_id=f"cell-{position}")
        cell = replace(
            cell, boundary=replace(cell.boundary, predicates=(actor_predicate(family),))
        )
        field.insert(cell)
        index.insert(cell)
        cells.append(cell)
    digests = {cell.operator.digest for cell in cells}
    footprints = [frozenset(cell.boundary.keys()) for cell in cells]
    assert len(digests) == 1, "the fixture must share one operator or it proves nothing"
    assert footprints[0].isdisjoint(footprints[1]) and footprints[1].isdisjoint(footprints[2])

    report = garbage_collect_knowledge(
        field,
        index=index,
        store=None,
        budget_bytes=20 * 1024 * 1024,
        utilities={cell.cell_id: _utility() for cell in cells},
    )

    assert report.compacted == 0, f"GC deleted {report.compacted_ids}"
    assert len(field) == 3
    for cell, footprint in zip(cells, footprints, strict=True):
        assert frozenset(index.keys_for(cell.cell_id)) == footprint


def test_gc_compacts_a_measured_cell_bound_only_to_a_dead_epoch() -> None:
    field = KnowledgeField()
    index = BoundaryIndex()
    stale = phi_oracle_cell(cell_id="cell-old", epochs=frozenset({0}))
    live = phi_oracle_cell(cell_id="cell-new", epochs=frozenset({2}))
    for cell in (stale, live):
        field.insert(cell)
        index.insert(cell)
    report = garbage_collect_knowledge(
        field,
        index=index,
        store=None,
        budget_bytes=10 * 1024 * 1024,
        utilities={"cell-old": _utility(), "cell-new": _utility()},
        live_epochs=frozenset({2}),
    )
    assert ("cell-old", GCReason.OBSOLETE_EPOCH) in report.compacted_ids
    assert field.get("cell-new") is not None


def test_gc_leaves_a_field_over_budget_rather_than_guessing_which_cell_to_lose() -> None:
    """Budget pressure ranks MEASURED cells only, lowest utility first."""
    field = KnowledgeField()
    index = BoundaryIndex()
    for name in ("cell-a", "cell-b"):
        epochs = frozenset({0}) if name == "cell-a" else frozenset({1})
        cell = phi_oracle_cell(cell_id=name, epochs=epochs)
        field.insert(cell)
        index.insert(cell)
    report = garbage_collect_knowledge(
        field,
        index=index,
        store=None,
        budget_bytes=1,
        utilities={
            "cell-a": _utility(saved_compute_us=1.0),
            "cell-b": _utility(saved_compute_us=9.0),
        },
    )
    assert GCReason.OVER_BUDGET in {reason for _cell_id, reason in report.compacted_ids}
    # The lower-utility cell goes first; the higher-utility one is the survivor.
    assert "cell-a" in {cell_id for cell_id, _reason in report.compacted_ids}


def test_gc_report_refuses_to_misaccount_its_own_cells() -> None:
    with pytest.raises(ContractError, match="every cell is compacted or retained"):
        GCReport(
            evaluated=5,
            compacted=1,
            retained=1,
            incident_protected=0,
            bytes_reclaimed=0,
            unmeasured_skipped=0,
        )


# --- D3.14: the resource budget ----------------------------------------------


def test_within_budget_is_none_rather_than_true_when_nothing_was_measured() -> None:
    report = unmeasured_stage3_resources(
        measured_by=MEASURED_BY, reason="no sampler on this host"
    )
    assert report.within_budget is None
    assert report.peak_sampled_rss_bytes is None
    assert report.to_dict()["within_budget"] is None


def test_a_resource_report_cannot_claim_within_budget_without_measuring() -> None:
    """The ``ProfileReport.within_target`` rule, enforced in the constructor.

    This is the test that fails if somebody "simplifies" the verdict to a bool.
    """
    with pytest.raises(ContractError, match="unmeasured is not within target"):
        Stage3ResourceReport(
            peak_sampled_rss_bytes=None,
            incremental_rss_bytes=None,
            per_component_bytes={},
            within_budget=True,
            loadavg=loadavg(),
            measured_by=MEASURED_BY,
            unmeasured=("nothing was sampled",),
        )


def test_a_resource_report_cannot_claim_within_budget_with_no_incremental_rss() -> None:
    """Pins S3-15: ``incremental_rss_bytes`` was left out of the honesty check.

    ``_require_honest_verdict`` tested ``self.unmeasured or
    self.peak_sampled_rss_bytes is None`` and omitted the second observation, so a
    report with ``incremental_rss_bytes=None``, an empty ``unmeasured`` tuple and
    ``within_budget=True`` was accepted — an unmeasured observation recorded as a
    pass, which is the one thing this type exists to refuse. G3.10 reads exactly
    that field against the §38 ceiling.
    """
    with pytest.raises(ContractError, match="unmeasured is not within target"):
        Stage3ResourceReport(
            peak_sampled_rss_bytes=1024,
            incremental_rss_bytes=None,
            per_component_bytes={},
            within_budget=True,
            loadavg=loadavg(),
            measured_by=MEASURED_BY,
            unmeasured=(),
        )
    # ``None`` remains the honest verdict for the same report.
    assert (
        Stage3ResourceReport(
            peak_sampled_rss_bytes=1024,
            incremental_rss_bytes=None,
            per_component_bytes={},
            within_budget=None,
            loadavg=loadavg(),
            measured_by=MEASURED_BY,
            unmeasured=(),
        ).within_budget
        is None
    )


def test_the_certificate_rollback_control_arm_runs_real_code() -> None:
    """Pins S3-17: T5's ``succeeded_without_control`` was a dict assignment.

    The arm read ``shadow = {"cell-target": current}; shadow["cell-target"] =
    stale; ... shadow["cell-target"].version == 1`` — a tautology about Python
    dicts, not a run of any PocketSec code with a control disabled. T5 is not one
    of the two cases the module docstring discloses as reference implementations,
    and its ``control`` field names a real object, ``KnowledgeField.insert``.
    """
    import inspect

    from pocketsec.stage3.labs import boundary_evasion

    source = inspect.getsource(boundary_evasion._case_certificate_rollback)
    assert "shadow_field = KnowledgeField()" in source
    assert 'shadow["cell-target"]' not in source, "the control arm is a dict again"


def test_a_resource_report_refuses_a_component_with_no_budget() -> None:
    with pytest.raises(ContractError, match="no §38 budget"):
        Stage3ResourceReport(
            peak_sampled_rss_bytes=1,
            incremental_rss_bytes=1,
            per_component_bytes={"invented_component": 1},
            within_budget=None,
            loadavg=loadavg(),
            measured_by=MEASURED_BY,
            unmeasured=("x",),
        )


def test_a_resource_report_refuses_a_producer_that_is_not_module_function() -> None:
    with pytest.raises(ContractError, match="module:function"):
        unmeasured_stage3_resources(measured_by="somewhere", reason="x")


def test_measure_stage3_resources_uses_the_stage0_sampler_and_records_loadavg() -> None:
    field = KnowledgeField()
    index = BoundaryIndex()
    cell = phi_oracle_cell()
    field.insert(cell)
    index.insert(cell)

    def work() -> int:
        return sum(1 for _ in field.cells())

    report = measure_stage3_resources(
        work,
        measured_by="tests.test_stage3_runtime:test_measure_stage3_resources",
        boundary_index=index,
        knowledge_cells=field,
    )
    assert len(report.loadavg) == 3
    # counterexample_hot, cell_vm and audit_state were not supplied, so the verdict
    # must be UNMEASURED rather than a pass over a partial measurement.
    assert report.within_budget is None
    assert report.unmeasured
    assert set(report.per_component_bytes) <= set(STAGE3_BUDGET)
    assert report.per_component_bytes["knowledge_cells"] == field.memory_bytes()


def test_the_declared_budget_matches_the_architecture_envelope() -> None:
    assert STAGE3_BUDGET["boundary_index"] == 8 * 1024 * 1024
    assert STAGE3_BUDGET["knowledge_cells"] == 20 * 1024 * 1024
    assert STAGE3_BUDGET["cell_vm"] == 8 * 1024 * 1024
    assert STAGE3_BUDGET["audit_state"] == 5 * 1024 * 1024
    assert STAGE3_BUDGET["counterexample_hot"] == 15 * 1024 * 1024
    assert STAGE3_NORMAL_INCREMENTAL_RSS_BYTES == 25 * 1024 * 1024


def test_a_live_field_and_index_fit_inside_their_declared_budgets() -> None:
    field = KnowledgeField()
    index = BoundaryIndex()
    for i in range(16):
        cell = phi_oracle_cell(cell_id=f"cell-{i:03d}")
        field.insert(cell)
        index.insert(cell)
    assert field.memory_bytes() < STAGE3_BUDGET["knowledge_cells"]
    assert index.memory_bytes() < STAGE3_BUDGET["boundary_index"]


# --- ADR-0028: the corpus -----------------------------------------------------


def test_the_crystal_corpus_reaches_two_distinct_epochs_without_lowering_anything(
    eval_corpus: CrystalCorpus,
) -> None:
    """G2.13's bar, met by a corpus that genuinely drifts rather than by a weaker rule."""
    assert eval_corpus.distinct_epochs >= 2
    assert eval_corpus.corroborated_transitions == 2
    reasons = [d.reason.value for d in eval_corpus.epoch_decisions]
    assert "REJECTED_NO_CORROBORATION" in reasons, (
        "the uncorroborated change must be offered and refused, or the corpus is not "
        "testing the anti-poisoning rule at all"
    )
    assert eval_corpus.version == CRYSTAL_CORPUS_VERSION


def test_crystal_corpus_uses_session_unique_identities(
    eval_corpus: CrystalCorpus,
) -> None:
    """Stage1Pipeline carries lineage state across scenarios; reuse erases the signal."""
    owners = session_identity_owners([s.scenario for s in eval_corpus.sessions])
    shared = {key: sorted(value) for key, value in owners.items() if len(value) > 1}
    assert not shared, f"process identities reused across sessions: {sorted(shared)[:5]}"


def test_crystal_corpus_has_non_zero_median_delta_phi_for_both_classes(
    eval_corpus: CrystalCorpus,
) -> None:
    """Asserted BEFORE anything is fitted, because the signal can be erased."""
    medians = median_peak_delta_phi(eval_corpus)
    assert set(medians) == {0, 1}
    assert medians[0] > 0.0, f"benign median peak ΔΦ is {medians[0]}"
    assert medians[1] > 0.0, f"malicious median peak ΔΦ is {medians[1]}"
    assert medians[1] > medians[0], "single-lineage accumulation must move Φ further"


def test_crystal_corpus_carries_no_vocabulary_signal(
    eval_corpus: CrystalCorpus,
) -> None:
    scenarios = [s.scenario for s in eval_corpus.sessions]
    totals = operation_counts(scenarios)
    sessions = {label: sum(1 for s in scenarios if s.label == label) for label in totals}
    for operation in set(totals[0]) | set(totals[1]):
        benign = totals[0][operation] / sessions[0]
        attack = totals[1][operation] / sessions[1]
        assert abs(benign - attack) < max(0.5, 0.05 * max(benign, attack)), (
            f"{operation!r} differs across classes: {benign:.2f} vs {attack:.2f}"
        )
    pooled, base_rate = vocabulary_leak(eval_corpus)
    assert pooled - base_rate < 0.05, (
        f"an order-free pooled baseline reaches {pooled:.4f} against a "
        f"{base_rate:.4f} base rate; the corpus leaks its label"
    )


def test_building_a_corpus_too_small_to_drift_is_refused() -> None:
    with pytest.raises(ContractError, match="three phases"):
        build_crystal_corpus(count=4, seed=1)


# --- D3.15: the baselines -----------------------------------------------------


def test_every_baseline_beats_the_base_rate_or_is_reported_at_chance(
    baseline_table: BaselineTable,
) -> None:
    """Pins S3-FC-09's guard: three outcomes, not two.

    ``beats_base_rate`` used to be a bare ``pr_auc > base_rate``, so B4 counted as a
    working control on a margin of +0.0086 — inside the same 0.01 band this stage
    uses to declare a split unable to tell models apart, and a margin whose *sign*
    flips with corpus size. It is tri-state now: measurably above, measurably below,
    or AT_CHANCE. Only the second refuses the table, because a control below chance
    is a bug in the control; the third is a result *about* that control and is
    reported, not concealed — and it is not evidence that the control works.
    """
    controls = [row for row in baseline_table.rows if row.baseline_id in BASELINE_IDS]
    assert len(controls) == 5, "all five mandated controls must run"
    below = [row.baseline_id for row in controls if row.beats_base_rate is False]
    at_chance = [row.baseline_id for row in controls if row.beats_base_rate is None]

    if below:
        assert baseline_table.refused, (
            f"{below} are measurably below the base rate and the table still reported "
            "a comparison; a control below chance is a bug"
        )
        assert baseline_table.refusal_reason
    else:
        assert not baseline_table.refused

    # An at-chance control is never silently carried as a working one.
    assert sorted(baseline_table.at_chance) == sorted(at_chance)
    for row in controls:
        if row.pr_auc is None:
            assert row.beats_base_rate is None
            continue
        margin = row.pr_auc - baseline_table.base_rate
        if abs(margin) <= AT_CHANCE_PR_AUC_BAND:
            assert row.beats_base_rate is None, f"{row.baseline_id} margin {margin}"
        else:
            assert row.beats_base_rate is (margin > 0.0)


def test_the_baseline_table_reports_bytes_and_microseconds_for_every_row(
    baseline_table: BaselineTable,
) -> None:
    for row in baseline_table.rows:
        assert row.bytes_resident > 0
        assert row.microseconds_per_event is not None
        assert row.events > 0
    assert len(baseline_table.loadavg) == 3, "a timing with no load context is not comparable"


def test_the_cell_path_is_measured_against_the_phi_oracle_in_the_same_run(
    baseline_table: BaselineTable,
) -> None:
    """G3.9/F1. The comparison must exist; this test does not prescribe its outcome."""
    rows = baseline_table.by_id
    assert "S3" in rows and "B3" in rows
    byte_ratio = baseline_table.ratio("S3", "B3", metric="bytes_resident")
    us_ratio = baseline_table.ratio("S3", "B3", metric="microseconds_per_event")
    assert byte_ratio is not None and us_ratio is not None
    # The cell path is the mechanism, not a control, so it does NOT gate the report.
    assert "S3" not in BASELINE_IDS


def test_refusing_to_fit_and_evaluate_on_the_same_split(fit_corpus: CrystalCorpus) -> None:
    with pytest.raises(ContractError, match="share a seed"):
        run_baselines(fit=fit_corpus, evaluation=fit_corpus)


def test_the_cell_path_abstains_off_its_boundary_rather_than_scoring(
    eval_corpus: CrystalCorpus,
) -> None:
    path = CellPathBaseline()
    for session in eval_corpus.sessions[:4]:
        path.score(session)
    assert path.abstentions > 0, (
        "a cell whose boundary is narrower than the corpus must abstain somewhere; "
        "zero abstentions would mean the boundary is not being consulted"
    )


# --- G3.5: the dual oracle against constructed teacher error ------------------


def test_the_three_teacher_error_cases_fail_dual_oracle_evaluation() -> None:
    cases = teacher_error_cases()
    assert len(cases) == 3
    assert {case.case_id for case in cases} == {"a", "b", "c"}
    for case in cases:
        assert case.dual_oracle_refused, f"case {case.case_id} passed the dual oracle"
        assert case.violation_kinds, f"case {case.case_id} refused without naming a constraint"


def test_a_teacher_only_control_would_have_passed_all_three() -> None:
    """Without this control, "the dual oracle refused" says nothing about Oracle B."""
    cases = teacher_error_cases()
    assert all(case.teacher_only_passed for case in cases), (
        "a teacher-only rule must accept all three, or the cases do not demonstrate "
        "that the second oracle did any work"
    )


def test_each_teacher_error_case_names_the_constraint_that_caught_it() -> None:
    kinds = {case.case_id: set(case.violation_kinds) for case in teacher_error_cases()}
    assert "NEVER_NORMALISE_HIGH_CONSEQUENCE" in kinds["a"]
    assert "NEVER_SUPPRESS_MANDATORY_EVIDENCE" in kinds["b"]
    assert "NEVER_LOWER_PHI" in kinds["c"]


# --- §39: the threat suite ----------------------------------------------------


def test_the_threat_suite_covers_all_nine_cases(
    threat_suite: ThreatSuiteReport,
) -> None:
    assert set(threat_suite.by_id) == set(THREAT_CASE_IDS)


@pytest.mark.parametrize("case_id", THREAT_CASE_IDS)
def test_each_threat_case_is_stopped_with_its_control_and_succeeds_without(
    threat_suite: ThreatSuiteReport, case_id: str
) -> None:
    case = threat_suite.by_id[case_id]
    assert case.succeeded_without_control, (
        f"{case_id}: the attack did not work even with the control disabled, so this "
        "case demonstrates nothing about the control"
    )
    assert case.stopped_with_control, f"{case_id}: {case.control} did not stop {case.attack}"


def test_the_threat_report_is_complete_and_nothing_is_unmitigated(
    threat_suite: ThreatSuiteReport,
) -> None:
    assert threat_suite.unmitigated == ()
    assert threat_suite.complete


def test_a_threat_case_outside_the_nine_is_refused() -> None:
    from pocketsec.stage3.labs.boundary_evasion import ThreatCase

    with pytest.raises(ContractError, match="not one of the nine"):
        ThreatCase(
            case_id="T99_INVENTED",
            attack="x",
            control="y",
            stopped_with_control=True,
            succeeded_without_control=True,
            detail="z",
        )


# --- G3.11: ablation ----------------------------------------------------------


def test_the_saturation_guard_runs_first_and_records_no_ablation_when_degenerate(
    baseline_table: BaselineTable, eval_corpus: CrystalCorpus
) -> None:
    pooled, _base = vocabulary_leak(eval_corpus)
    report = run_ablation(baseline_table, order_free=pooled)
    if report.status is AblationStatus.DEGENERATE:
        assert report.entries == (), "a DEGENERATE split must record no component result"
        assert report.saturation.reason
        assert not report.passes_g3_11
    else:
        assert report.entries, "a MEASURED ablation must judge every OPTIONAL id"


def test_a_degenerate_report_cannot_smuggle_in_entries() -> None:
    from pocketsec.stage3.labs.ablation import AblationEntry, SaturationVerdict

    verdict = SaturationVerdict(
        degenerate=True, best=1.0, median=1.0, spread=0.0, order_free=None, reason="saturated"
    )
    entry = AblationEntry(
        core_id="AICT-F19",
        name="garbage_collect_knowledge",
        deliverable="D3.14",
        experiment_id=None,
        delta_pr_auc=None,
        verdict=ComponentVerdict.FAILED,
        reason="x",
    )
    with pytest.raises(ContractError, match="may record no component result"):
        AblationReport(
            status=AblationStatus.DEGENERATE,
            saturation=verdict,
            entries=(entry,),
            measured_by=MEASURED_BY,
        )


def test_an_optional_function_with_no_experiment_id_is_failed_not_pending(
    baseline_table: BaselineTable,
) -> None:
    """On a discriminating split, a component with no measurement FAILS."""
    discriminating = replace(
        baseline_table,
        rows=tuple(
            replace(row, pr_auc=score)
            for row, score in zip(baseline_table.rows, (0.9, 0.5, 0.4, 0.3, 0.2, 0.1), strict=False)
        ),
    )
    report = run_ablation(discriminating, order_free=0.1)
    assert report.status is AblationStatus.MEASURED
    assert report.failed, "no OPTIONAL id has a registered experiment yet, so all must FAIL"
    assert not report.passes_g3_11
    assert all(entry.verdict is ComponentVerdict.FAILED for entry in report.entries)


def test_not_yet_justified_is_kept_apart_from_rejected(
    baseline_table: BaselineTable,
) -> None:
    discriminating = replace(
        baseline_table,
        rows=tuple(
            replace(row, pr_auc=score)
            for row, score in zip(baseline_table.rows, (0.9, 0.5, 0.4, 0.3, 0.2, 0.1), strict=False)
        ),
    )
    experiment = "PS-S3-20260925-H4-gc-ablation-0001"
    report = run_ablation(
        discriminating,
        experiments={"AICT-F19": experiment, "AICT-F11": experiment},
        deltas={"AICT-F19": 0.0005, "AICT-F11": -0.25},
        order_free=0.1,
    )
    assert "AICT-F19" in report.not_yet_justified
    assert "AICT-F11" in report.rejected
    assert set(report.not_yet_justified) & set(report.rejected) == set()


def test_ablation_refuses_an_experiment_for_a_non_optional_function(
    baseline_table: BaselineTable,
) -> None:
    discriminating = replace(
        baseline_table,
        rows=tuple(
            replace(row, pr_auc=score)
            for row, score in zip(baseline_table.rows, (0.9, 0.5, 0.4, 0.3, 0.2, 0.1), strict=False)
        ),
    )
    with pytest.raises(ContractError, match="non-OPTIONAL core ids"):
        run_ablation(
            discriminating,
            experiments={"AICT-F01": "PS-S3-20260925-H4-x-0001"},
            order_free=0.1,
        )


def test_the_saturation_guard_says_which_degeneracy_it_found() -> None:
    """Pins S3-14: the verdict was fail-closed but the stated reason was false.

    With four of six models at the PR-AUC ceiling and two near chance, the median
    *is* the ceiling and ``best - median`` is 0.0 — while the split separates the
    two groups by 0.72. The guard reported "the split cannot tell models apart",
    and ``docs/stage-3-findings.md`` drew a strong conclusion from it. It cannot
    *rank within the upper group*, which is a different statement.
    """
    ceiling_heavy = saturation_guard([1.0, 1.0, 1.0, 1.0, 0.29, 0.28])
    assert ceiling_heavy.degenerate is True
    assert ceiling_heavy.spread == 0.0
    assert "cannot tell models apart" not in ceiling_heavy.reason
    assert "sit at the ceiling" in ceiling_heavy.reason
    assert "0.7" in ceiling_heavy.reason, "the real separation must be stated"

    genuinely_flat = saturation_guard([0.50, 0.501, 0.499, 0.5005])
    assert genuinely_flat.degenerate is True
    assert "cannot tell models apart" in genuinely_flat.reason


def test_the_saturation_guard_refuses_to_judge_a_single_model() -> None:
    verdict = saturation_guard([0.9])
    assert verdict.degenerate
    assert verdict.median is None
    assert "UNMEASURED" in verdict.reason


def test_the_saturation_guard_drops_unmeasured_scores_rather_than_zeroing_them() -> None:
    """A ``None`` PR-AUC must not become a 0.0 that manufactures spread."""
    verdict = saturation_guard([1.0, None, None])
    assert verdict.degenerate
    assert verdict.best == 1.0


# --- the two document checks G3.12(c) and G3.13 rely on -----------------------


def test_a_verification_claim_inside_a_table_row_is_scanned(tmp_path: Path) -> None:
    """Pins S3-FC-11: table rows were skipped whole, and that is where results live.

    The exclusion existed so a citation would not be required inside every cell of
    a results table. But a results table is exactly where a verification claim
    escapes this repository, and skipping the row meant the claim was never
    scanned at all. The window still supplies the backing, so a table whose
    surrounding prose names its producer passes as before.
    """
    from pocketsec.stage3.gate_criteria import unbounded_verification_language

    unbacked = tmp_path / "unbacked.md"
    unbacked.write_text(
        "## Results\n\n| property | status |\n|---|---|\n| termination | proven |\n",
        encoding="utf-8",
    )
    assert unbounded_verification_language(unbacked), "a table row must be scanned"

    backed = tmp_path / "backed.md"
    backed.write_text(
        "## Results\n\n| property | status |\n|---|---|\n| termination | proven |\n\n"
        "Produced by `pocketsec.stage3.bytecode.verifier:verify`.\n",
        encoding="utf-8",
    )
    assert unbounded_verification_language(backed) == []


def test_a_fenced_block_is_backed_by_its_own_command_but_not_by_nothing(
    tmp_path: Path,
) -> None:
    """The fence rule must not become the table-row exemption by another door.

    A fenced block is pasted command output: requiring a citation *inside* verbatim
    output would mean editing the output. So the backing window widens to the whole
    block plus the lines before it — and a block with no producer anywhere in it is
    still reported.
    """
    from pocketsec.stage3.gate_criteria import unbounded_verification_language

    unbacked = tmp_path / "unbacked.md"
    unbacked.write_text(
        "Some prose with no citation at all.\n\n```\nproperty termination: proven\n```\n",
        encoding="utf-8",
    )
    assert unbounded_verification_language(unbacked), "an unbacked paste must be reported"

    backed = tmp_path / "backed.md"
    backed.write_text(
        "Some prose with no citation at all.\n\n```\n"
        "$ python -m pocketsec.stage3.cli gate\n"
        "... twenty lines of output ...\n"
        "property termination: proven\n```\n",
        encoding="utf-8",
    )
    assert unbounded_verification_language(backed) == []


def test_a_novelty_claim_is_only_exempt_when_the_negation_is_near_it() -> None:
    """Pins S3-FC-11: any "no"/"not"/"never" anywhere on the line exempted the line.

    That is most careful prose in this repository, so an unguarded novelty claim
    could ride along beside an unrelated negation.
    """
    from pocketsec.stage3.gate_criteria import claims_novelty

    far_negation = (
        "This is the first system to compile behavioural invariants, and no other "
        "stage in this repository does anything comparable at all whatsoever here."
    )
    assert claims_novelty(far_negation, "novel") is False, "the fixture must not use 'novel'"
    assert claims_novelty(
        "This mechanism is novel, and nothing in the repository resembles it in any "
        "way that a reader of the architecture document would recognise as similar.",
        "novel",
    ), "a distant negation must not exempt the claim"
    # A negation about the claim itself still exempts it, which is what lets this
    # repository state the prohibition without tripping it.
    assert not claims_novelty("No novelty is claimed here.", "novelty")
    assert not claims_novelty("This is not novel.", "novel")
