"""D3.11–D3.13 behaviour tests — shadow promotion, auditing, decay and melting.

These test **refusals and locality**, not construction.

The first test in the file is the falsification experiment for the whole stage.
Anyone can compile a model into a table; what distinguishes AICT is the claim
that localised drift reopens a subregion without discarding unrelated
crystallised knowledge. If ``repair_locality`` is ever below 1.0 for cells that
were nowhere near the drift, or the melted region keeps answering from a stale
cell, Stage 3 reduces to ordinary distillation plus cache invalidation and
falsifier F2 has fired. That test is written first on purpose.

The rest pin the guards it would be tempting to soften:

* an A5 assurance claim with no prover, or naming a property the verifier only
  *tests*, **raises** — G3.12 in executable form;
* shadow coverage for CRITICAL is strictly stricter than for ROUTINE, and the
  same frames that satisfy ROUTINE must fail CRITICAL;
* ``decay_confidence`` has no time term, asserted on the signature and on the
  fixed point;
* the audit schedule is not reproducible from public data alone;
* ``compute_cell_stress`` refuses to report a rate over zero audits.

**On the two ``CellBoundary`` definitions in this tree.** Stage 3 currently
carries ``cells/boundary.py`` (foundation) *and* ``boundary/index.py``
(knowledge boundary), with different predicate semantics: the first ANDs the
relation-family clause across predicates, the second treats the declared
families as a membership set. ``KnowledgeCellV1`` isinstance-checks the first.
A proper key-disjoint subregion is only expressible in the second — under the
first, any two boundaries sharing a family and an actor mask always share the
empty-delta key, so no narrowing can be disjoint. These tests therefore use the
**real** ``KnowledgeCellV1``/``KnowledgeField`` wherever the first suffices, and
the contract-shaped stand-ins below for the partial-melt locality experiment.
The lifecycle modules isinstance-check neither type, so they run unchanged
against whichever pair the integrator settles on. The duplication is reported as
a blocker, not worked around in production code.
"""

from __future__ import annotations

import inspect
from dataclasses import dataclass, replace
from typing import Any

import pytest

from pocketsec.stage0.contracts.common import ContractError, EvidenceRef
from pocketsec.stage1.ssir.entities import SemanticProperty
from pocketsec.stage1.ssir.relations import RelationFamily
from pocketsec.stage1.state.security_state import SecurityStateV1, StateDelta
from pocketsec.stage3.boundary.index import BoundaryIndex
from pocketsec.stage3.boundary.index import CellBoundary as IndexBoundary
from pocketsec.stage3.bytecode.isa import Instruction, Op, encode
from pocketsec.stage3.bytecode.verifier import (
    ALL_PROVEN_PROPERTIES,
    TESTED_ONLY_PROPERTIES,
    verify,
)
from pocketsec.stage3.bytecode.vm import CellVM
from pocketsec.stage3.boundary.index import CellBoundary
from pocketsec.stage3.cells.field import FieldFull, KnowledgeField
from pocketsec.stage3.cells.frame import CellFrame
from pocketsec.stage3.cells.invariant import (
    ConsequentSpec,
    Invariant,
    PredicateRole,
    SemanticPredicate,
)
from pocketsec.stage3.cells.masks import property_mask
from pocketsec.stage3.cells.operator import OperatorForm, OperatorProgram
from pocketsec.stage3.cells.schema import (
    AssuranceLevel,
    AuditPolicy,
    CellPhase,
    ConstraintKind,
    HardConstraint,
    KnowledgeCellV1,
)
from pocketsec.stage3.melting.full import full_melt, recrystallize, rollback
from pocketsec.stage3.melting.partial import (
    MeltKind,
    MeltReport,
    narrow_boundary,
    partial_melt,
    successor_cell_id,
)
from pocketsec.stage3.melting.stress import (
    FULL_MELT_THRESHOLD,
    PARTIAL_MELT_THRESHOLD,
    CellStress,
    compute_cell_stress,
)
from pocketsec.stage3.oracles.counterexamples import Counterexample, CounterexampleStore
from pocketsec.stage3.oracles.dual_oracle import DualOracleEvaluator
from pocketsec.stage3.oracles.teacher import TeacherOracle, TeacherSnapshotV1, frame_digest
from pocketsec.stage3.promotion.assurance import (
    MIN_PROMOTABLE_ASSURANCE,
    AssuranceState,
    PromotionOutcome,
    promote_cell,
)
from pocketsec.stage3.promotion.audit import (
    MAX_AUDIT_RATE,
    MIN_AUDIT_RATE,
    AuditReport,
    AuditSampler,
    audit_probability,
    sample_audit,
)
from pocketsec.stage3.promotion.decay import (
    DECAY_EVENT_TERMS,
    MIN_ASSURANCE_CONFIDENCE,
    ConfidenceAction,
    below_minimum,
    decay_confidence,
    decay_response,
)
from pocketsec.stage3.promotion.shadow import (
    SHADOW_MIN_COVERAGE,
    SHADOW_MIN_TRANSITIONS,
    ShadowRun,
    shadow_execute,
)
from pocketsec.stage3.theory import ResolutionState, SecurityConsequence

ENCODER = "ssir-encoder.1"

#: H4 ("neural-to-symbolic JIT compilation") is the honest existing binding for
#: this wave; H9 needs ADR-0012 and the prior-art ledger entry first.
EXPERIMENT_ID = "PS-S3-20260925-H4-lifecycle-shadow-melt-0001"


# --- shared construction -----------------------------------------------------


def _evidence(count: int = 3, *, tag: str = "e") -> tuple[EvidenceRef, ...]:
    return tuple(
        EvidenceRef(store="unit", locator=f"{tag}{i}", digest=f"sha256:{i:064x}")
        for i in range(count)
    )


def _predicate(prop: SemanticProperty, family: RelationFamily) -> SemanticPredicate:
    return SemanticPredicate(
        role=PredicateRole.ACTOR,
        required_properties=frozenset({prop}),
        forbidden_properties=frozenset(),
        relation_family=family,
        entity_kind=None,
    )


P_NET = _predicate(SemanticProperty.NETWORK_CLIENT, RelationFamily.NETWORK)
P_EXEC = _predicate(SemanticProperty.NETWORK_CLIENT, RelationFamily.EXECUTION)
P_IDENT = _predicate(SemanticProperty.CREDENTIAL_READER, RelationFamily.IDENTITY)
P_FS = _predicate(SemanticProperty.PERSISTENCE_WRITER, RelationFamily.FILESYSTEM)
P_AUTH = _predicate(SemanticProperty.PRIVILEGE_CHANGER, RelationFamily.AUTHORIZATION)


def _operator() -> OperatorProgram:
    """A verified straight-line program that preserves evidence and answers.

    Deliberately *not* an abstaining stub: the dual oracle's evidence-requirement
    and hard-constraint checks only bite on a cell that actually answers, so a
    stub would let the promotion tests pass without exercising them at all.
    """
    words = encode((Instruction(Op.PRESERVE_EVIDENCE, 0), Instruction(Op.RETURN_STATE, 0)))
    return OperatorProgram(
        form=OperatorForm.BYTECODE, words=words, table={}, max_steps=8, max_state_bytes=320
    )


def _resolution() -> ResolutionState:
    return ResolutionState(
        predictive_stability=0.95,
        calibrated_uncertainty=0.10,
        validated_breadth=8,
        counterfactual_consistency=0.95,
        evidence_agreement=0.95,
        drift_stability=2,
        measured_by="tests.test_stage3_lifecycle:_resolution",
    )


def _invariant(
    name: str,
    predicates: tuple[SemanticPredicate, ...],
    *,
    consequence: SecurityConsequence = SecurityConsequence.ROUTINE,
) -> Invariant:
    return Invariant(
        invariant_id=name,
        antecedent=predicates,
        consequent=ConsequentSpec(
            required_dimensions=frozenset({"privilege"}),
            min_delta_phi=0.0,
            required_evidence_kinds=frozenset({"unit"}),
            consequence=consequence,
        ),
        support=8,
        contradictions=0,
        identities_collapsed=5,
        epochs=frozenset({0, 1}),
        falsifier="a matching antecedent that does not raise the consequent dimension",
        evidence=_evidence(),
    )


def _audit_policy() -> AuditPolicy:
    return AuditPolicy(base_rate=0.05, min_rate=0.001, max_rate=1.0, jitter_salt="cell-salt")


def _constraints() -> tuple[HardConstraint, ...]:
    return (
        HardConstraint(
            constraint_id="q-phi",
            kind=ConstraintKind.NEVER_LOWER_PHI,
            detail="a cell may never lower the security potential of the state it reads",
        ),
    )


def _frame(
    *,
    family: RelationFamily = RelationFamily.NETWORK,
    actor: SemanticProperty = SemanticProperty.NETWORK_CLIENT,
    raised: dict[str, tuple[int, int]] | None = None,
    phi: float = 0.2,
    epoch_id: int = 0,
    evidence_tag: str = "e",
) -> CellFrame:
    return CellFrame(
        state=SecurityStateV1(),
        delta=StateDelta(raised={} if raised is None else raised),
        actor_properties=property_mask({actor}),
        object_properties=0,
        relation_family=family,
        phi=phi,
        delta_phi=0.0,
        uncertainty=0.2,
        epoch_id=epoch_id,
        window_counts={int(family): 1},
        evidence=_evidence(3, tag=evidence_tag),
        encoder_version=ENCODER,
    )


# --- real KnowledgeCellV1 fixtures -------------------------------------------


def _boundary(
    predicates: tuple[SemanticPredicate, ...], dimensions: frozenset[str]
) -> CellBoundary:
    return CellBoundary(
        predicates=predicates,
        state_dimensions=dimensions,
        phi_range=(0.0, 100.0),
        max_uncertainty=0.9,
        epochs=frozenset({0, 1}),
        forbidden_combinations=(),
    )


def _cell(
    cell_id: str,
    predicates: tuple[SemanticPredicate, ...],
    dimensions: frozenset[str],
    *,
    consequence: SecurityConsequence = SecurityConsequence.ROUTINE,
    phase: CellPhase = CellPhase.CRYSTALLIZED,
    assurance: AssuranceLevel = AssuranceLevel.A3,
    confidence: float = 0.8,
) -> KnowledgeCellV1:
    return KnowledgeCellV1(
        cell_id=cell_id,
        invariant=_invariant(f"inv-{cell_id}", predicates, consequence=consequence),
        boundary=_boundary(predicates, dimensions),
        operator=_operator(),
        resolution=_resolution(),
        confidence=confidence,
        assurance=assurance,
        phase=phase,
        evidence_lineage=_evidence(),
        constraints=_constraints(),
        epochs=frozenset({0, 1}),
        audit_policy=_audit_policy(),
        version=1,
        parent_cell_id=None,
        source_candidate_id=None,
    )


def _real_field() -> tuple[KnowledgeField, BoundaryIndex, dict[str, KnowledgeCellV1]]:
    """Four real cells over four disjoint relation families."""
    field = KnowledgeField()
    index = BoundaryIndex()
    cells = {
        "net": _cell("net", (P_NET,), frozenset({"privilege"})),
        "ident": _cell("ident", (P_IDENT,), frozenset({"credential"})),
        "fs": _cell("fs", (P_FS,), frozenset({"persistence"})),
        "auth": _cell("auth", (P_AUTH,), frozenset({"trust"})),
    }
    for cell in cells.values():
        field.insert(cell)
        index.insert(cell)
    return field, index, cells


# --- contract-shaped stand-ins for the locality experiment -------------------


@dataclass(frozen=True, slots=True)
class _LifecycleCell:
    """``KnowledgeCellV1``, restricted to the fields D3.13 actually touches.

    ``cell_id``, ``boundary``, ``phase``, ``version`` and ``parent_cell_id`` are
    the whole of what ``partial_melt``/``full_melt`` read or rewrite, and they
    carry the names and types ``docs/stage-3-spec.md`` §D3.5 assigns them. The
    stand-in exists only because a key-disjoint subregion cannot be expressed in
    the ``cells/boundary.py`` variant ``KnowledgeCellV1`` currently accepts — see
    the module docstring.
    """

    cell_id: str
    boundary: IndexBoundary
    phase: CellPhase = CellPhase.CRYSTALLIZED
    version: int = 1
    parent_cell_id: str | None = None


class _ShimField:
    """``KnowledgeField``'s container half, with its refusals kept intact.

    Duplicate ids and capacity both raise rather than evicting, exactly as the
    real field does; softening either here would make the melt tests pass for
    the wrong reason.
    """

    def __init__(self, *, max_cells: int = 512) -> None:
        self._max_cells = max_cells
        self._cells: dict[str, _LifecycleCell] = {}

    def insert(self, cell: _LifecycleCell) -> None:
        if cell.cell_id in self._cells:
            raise ContractError(f"field already holds {cell.cell_id!r}")
        if len(self._cells) >= self._max_cells:
            raise FieldFull(f"field holds {len(self._cells)} cells, at its bound")
        self._cells[cell.cell_id] = cell

    def remove(self, cell_id: str) -> bool:
        return self._cells.pop(cell_id, None) is not None

    def get(self, cell_id: str) -> _LifecycleCell | None:
        return self._cells.get(cell_id)

    def cells(self) -> tuple[_LifecycleCell, ...]:
        return tuple(self._cells.values())

    def __len__(self) -> int:
        return len(self._cells)


def _index_boundary(
    predicates: tuple[SemanticPredicate, ...], dimensions: frozenset[str]
) -> IndexBoundary:
    return IndexBoundary(
        predicates=predicates,
        state_dimensions=dimensions,
        phi_range=(0.0, 100.0),
        max_uncertainty=0.9,
        epochs=frozenset({0, 1}),
        forbidden_combinations=(),
    )


def _regioned_field() -> tuple[_ShimField, BoundaryIndex, dict[str, _LifecycleCell]]:
    """Four cells across two behavioural regions; ``region-a`` spans two families.

    ``region-a`` is the only one drift will hit. The other three are nowhere
    near it and every one of them must come through the melt untouched.
    """
    field = _ShimField()
    index = BoundaryIndex()
    cells = {
        "region-a": _LifecycleCell(
            "region-a", _index_boundary((P_NET, P_EXEC), frozenset({"privilege"}))
        ),
        "region-a-neighbour": _LifecycleCell(
            "region-a-neighbour", _index_boundary((P_IDENT,), frozenset({"credential"}))
        ),
        "region-b": _LifecycleCell(
            "region-b", _index_boundary((P_FS,), frozenset({"persistence"}))
        ),
        "region-b-neighbour": _LifecycleCell(
            "region-b-neighbour", _index_boundary((P_AUTH,), frozenset({"trust"}))
        ),
    }
    for cell in cells.values():
        field.insert(cell)
        index.insert(cell)
    return field, index, cells


# --- F2: the falsification experiment, written first -------------------------


def test_partial_melt_is_localised_and_reopens_only_the_drifted_region() -> None:
    """THE load-bearing claim (G3.7, falsifier F2).

    Drive drift into one behavioural region of a four-cell field and assert that
    every unrelated cell survives *identical*, and that the keys the melt
    reopened are a subset of the drifted region's keys. A ratio below 1.0 here,
    or a reopened key outside the region, means Stage 3 is ordinary distillation
    plus cache invalidation.
    """
    field, index, cells = _regioned_field()
    target = cells["region-a"]
    unrelated_before = {cid: cell for cid, cell in cells.items() if cid != "region-a"}

    drifted_region = _index_boundary((P_NET,), frozenset({"privilege"}))
    region_keys = frozenset(drifted_region.keys())

    report = partial_melt(target, drifted_region, field=field, index=index)

    assert report.kind is MeltKind.PARTIAL
    assert report.reopened_keys, "a melt that reopened nothing has not been demonstrated"
    assert frozenset(report.reopened_keys) <= region_keys
    assert report.unrelated_cells_before == 3
    assert report.unrelated_cells_retained == 3
    assert report.repair_locality == 1.0

    # Not merely present: identical. A melt that rebuilt a bystander would hold
    # the count at 3 while quietly replacing what it held.
    for cell_id, before in unrelated_before.items():
        assert field.get(cell_id) is before
        assert index.keys_for(cell_id) == tuple(before.boundary.keys())

    surviving = report.surviving_cell
    assert surviving is not None
    assert surviving.parent_cell_id == "region-a"
    assert surviving.version == target.version + 1
    assert surviving.phase is CellPhase.STRESSED
    assert frozenset(surviving.boundary.keys()).isdisjoint(region_keys)
    assert frozenset(surviving.boundary.keys()) <= frozenset(target.boundary.keys())


def test_melted_region_routes_to_abstention_not_to_a_stale_cell() -> None:
    """After the melt the drifted region must reach the learned path.

    This is the quiet failure the locality counts cannot catch: the index still
    answers for the reopened keys, so the melt "worked" by every number while
    nothing changed at runtime.
    """
    field, index, cells = _regioned_field()
    drifted = _frame(family=RelationFamily.NETWORK, raised={"privilege": (0, 1)})
    assert index.lookup(drifted) is cells["region-a"]

    partial_melt(
        cells["region-a"],
        _index_boundary((P_NET,), frozenset({"privilege"})),
        field=field,
        index=index,
    )

    assert index.lookup(drifted) is None
    assert index.lookup_all(drifted) == ()
    # The rest of the index still answers, so the melt did not blank everything.
    intact = _frame(
        family=RelationFamily.FILESYSTEM,
        actor=SemanticProperty.PERSISTENCE_WRITER,
        raised={"persistence": (0, 1)},
    )
    assert index.lookup(intact) is cells["region-b"]
    # The surviving half still answers in the family that did not drift.
    survivor_frame = _frame(family=RelationFamily.EXECUTION, raised={"privilege": (0, 1)})
    assert index.lookup(survivor_frame) is not None
    assert index.lookup(survivor_frame).cell_id == "region-a-v2"


def test_partial_melt_refuses_rather_than_escalating_to_a_full_melt() -> None:
    """A region covering the whole cell is reported, never silently destroyed."""
    field, index, cells = _regioned_field()
    target = cells["region-b"]
    whole = _index_boundary((P_FS,), frozenset({"persistence"}))

    report = partial_melt(target, whole, field=field, index=index)

    assert report.surviving_cell is None
    assert "REGION_COVERS_CELL" in report.reason
    assert field.get("region-b") is target
    assert "region-b" in index.cell_ids()
    assert report.repair_locality == 1.0


def test_partial_melt_of_a_disjoint_region_changes_nothing() -> None:
    field, index, cells = _regioned_field()
    target = cells["region-b"]
    elsewhere = _index_boundary((P_IDENT,), frozenset({"credential"}))

    report = partial_melt(target, elsewhere, field=field, index=index)

    assert report.reopened_keys == ()
    assert report.surviving_cell is target
    assert "REGION_DISJOINT" in report.reason
    assert len(field) == 4


def test_narrow_boundary_never_widens_a_cell() -> None:
    """The narrowing search must not repair a cell by enlarging it.

    Dropping every predicate makes a boundary span all relation families, which
    is the seductive "solution" — it avoids the drifted region by covering
    everything else as well.
    """
    boundary = _index_boundary((P_NET, P_EXEC), frozenset({"privilege"}))
    region = _index_boundary((P_NET,), frozenset({"privilege"}))

    narrowed = narrow_boundary(boundary, region)

    assert narrowed is not None
    assert frozenset(narrowed.keys()) <= frozenset(boundary.keys())
    assert not narrowed.intersects(region)
    assert narrowed.accepts_no_more_than(boundary)
    assert narrow_boundary(boundary, boundary) is None


def _property_lattice() -> tuple[int, ...]:
    """Every actor-property mask over the four properties the fixtures use."""
    bits = [
        property_mask({prop})
        for prop in (
            SemanticProperty.NETWORK_CLIENT,
            SemanticProperty.CREDENTIAL_READER,
            SemanticProperty.PERSISTENCE_WRITER,
            SemanticProperty.PRIVILEGE_CHANGER,
        )
    ]
    masks = {0}
    for bit in bits:
        masks |= {mask | bit for mask in masks}
    return tuple(sorted(masks))


def _frame_lattice() -> tuple[CellFrame, ...]:
    """A bounded lattice of frames spanning families x actor masks x deltas."""
    frames: list[CellFrame] = []
    for family in (
        RelationFamily.NETWORK,
        RelationFamily.EXECUTION,
        RelationFamily.FILESYSTEM,
        RelationFamily.IDENTITY,
    ):
        for mask in _property_lattice():
            for raised in ({}, {"privilege": (0, 1)}, {"credential": (0, 1)}):
                frames.append(
                    replace(
                        _frame(family=family, raised=dict(raised)),
                        actor_properties=mask,
                    )
                )
    return tuple(frames)


def test_narrow_boundary_accepts_no_frame_the_original_refused() -> None:
    """Pins S3-01 (resource-simplicity, CRITICAL): a narrowing melt WIDENED the cell.

    Two ACTOR predicates on one family with *different* required masks. Dropping
    either shrinks the key footprint — the old accept condition — while relaxing
    the mask conjunction, so a frame carrying only one of the two properties went
    from refused to answered committally by the survivor. Asserted over a
    generated frame lattice rather than over key sets, because key containment is
    exactly the check that was wrong.
    """
    interpreter = _predicate(SemanticProperty.NETWORK_CLIENT, RelationFamily.NETWORK)
    credential = _predicate(SemanticProperty.CREDENTIAL_READER, RelationFamily.NETWORK)
    boundary = _index_boundary((interpreter, credential), frozenset({"privilege"}))
    region = _index_boundary((credential,), frozenset({"privilege"}))

    narrowed = narrow_boundary(boundary, region)

    lattice = _frame_lattice()
    assert any(boundary.contains(frame) for frame in lattice), "the fixture proves nothing"
    if narrowed is not None:
        widened = [
            frame
            for frame in lattice
            if narrowed.contains(frame) and not boundary.contains(frame)
        ]
        assert not widened, (
            f"narrow_boundary widened the validated region onto {len(widened)} frame(s) "
            "the pre-melt cell refused"
        )


def test_partial_melt_survivor_never_answers_a_frame_the_cell_refused() -> None:
    """Pins S3-01 (resource-simplicity) end to end, through the index and the VM.

    The reviewer's reproduction: an interpreter-only frame is refused before the
    melt, and after a melt of the credential-reader half the survivor answers it
    on the cheap path. The survivor must never gain a frame.
    """
    interpreter = _predicate(SemanticProperty.NETWORK_CLIENT, RelationFamily.NETWORK)
    credential = _predicate(SemanticProperty.CREDENTIAL_READER, RelationFamily.NETWORK)
    field, index = _ShimField(), BoundaryIndex()
    target = _LifecycleCell(
        "cell-two-preds", _index_boundary((interpreter, credential), frozenset({"privilege"}))
    )
    field.insert(target)
    index.insert(target)
    lattice = _frame_lattice()
    refused_before = [frame for frame in lattice if index.lookup(frame) is None]

    partial_melt(
        target,
        _index_boundary((credential,), frozenset({"privilege"})),
        field=field,
        index=index,
    )

    still_refused = [frame for frame in refused_before if index.lookup(frame) is None]
    assert len(still_refused) == len(refused_before), (
        "a melt handed the cheap path frames nothing ever validated it on"
    )


def test_partial_melt_does_not_report_a_dimension_scoped_drift_as_disjoint() -> None:
    """Pins S3-FC-01: a state-dimension-scoped drift read as REGION_DISJOINT.

    ``keys()`` folds ``state_dimensions`` into one union delta mask while
    ``contains`` matches it by subset, so a region declaring one of the cell's two
    dimensions shares no key with it and still reaches frames the cell answers.
    The old key-intersection test called that disjoint and left the stale cell
    live and indexed — falsifier F2's own failure condition.
    """
    field, index = _ShimField(), BoundaryIndex()
    target = _LifecycleCell(
        "cell-two-dims",
        _index_boundary((P_NET,), frozenset({"privilege", "credential"})),
    )
    field.insert(target)
    index.insert(target)
    region = _index_boundary((P_NET,), frozenset({"credential"}))
    reached = _frame(family=RelationFamily.NETWORK, raised={"credential": (0, 1)})
    assert region.contains(reached) and target.boundary.contains(reached)
    assert frozenset(region.keys()).isdisjoint(frozenset(target.boundary.keys()))

    report = partial_melt(target, region, field=field, index=index)

    assert "REGION_DISJOINT" not in report.reason
    assert report.reopened_keys, "the drift reached this cell and must be reported as such"
    if report.surviving_cell is None:
        # Refusing is the honest outcome: nothing this cell can keep avoids the
        # region. What must not happen is the cell staying live under a
        # "disjoint" label.
        assert "REGION_COVERS_CELL" in report.reason
    else:
        assert index.lookup(reached) is None


def test_partial_melt_refuses_when_the_successor_id_is_already_live() -> None:
    """Pins S3-04: the rollback path deleted a bystander that held the successor id.

    ``cell_id`` and ``version`` are validated independently, so
    ``successor_cell_id`` can name a different live cell. The failed insert then
    removed *that* cell from the field and the index with no MeltReport, no
    reason and no rollback record.
    """
    field, index = _ShimField(), BoundaryIndex()
    target = _LifecycleCell("cell-a", _index_boundary((P_NET, P_EXEC), frozenset({"privilege"})))
    bystander = _LifecycleCell("cell-a-v2", _index_boundary((P_IDENT,), frozenset({"credential"})))
    field.insert(target)
    index.insert(target)
    field.insert(bystander)
    index.insert(bystander)
    bystander_keys = index.keys_for("cell-a-v2")

    report = partial_melt(
        target, _index_boundary((P_NET,), frozenset({"privilege"})), field=field, index=index
    )

    assert report.surviving_cell is None
    assert "SUCCESSOR_ID_TAKEN" in report.reason
    assert field.get("cell-a-v2") is bystander
    assert index.keys_for("cell-a-v2") == bystander_keys
    assert field.get("cell-a") is target
    assert "cell-a" in index.cell_ids()


def test_melt_lifecycle_end_to_end_over_the_regioned_field() -> None:
    """G3.6's melt half: partial melt, full melt, recrystallize, rollback."""
    field, index, cells = _regioned_field()
    store = CounterexampleStore(cold_archive=None)

    partial = partial_melt(
        cells["region-a"],
        _index_boundary((P_NET,), frozenset({"privilege"})),
        field=field,
        index=index,
    )
    assert partial.surviving_cell is not None
    assert len(field) == 4

    full = full_melt(partial.surviving_cell, field=field, index=index)
    assert len(field) == 3
    assert full.repair_locality == 1.0
    assert recrystallize(
        full, config=object(), teacher=TeacherOracle(None), field=field, store=store
    ) is None
    assert rollback(full, field=field, index=index) is partial.surviving_cell
    assert len(field) == 4


# --- full melt, rollback, counterexample preservation ------------------------


class _StubTransition:
    """The minimum a ``Counterexample`` needs; SSIR itself is Stage 1's test."""

    def __init__(self, label: str) -> None:
        self._label = label

    def to_dict(self) -> dict[str, Any]:
        return {"label": self._label}


def _counterexample(
    cell_id: str,
    *,
    cx_id: str,
    result: Any,
    incident_linked: bool = False,
    epoch_id: int = 0,
) -> Counterexample:
    return Counterexample(
        counterexample_id=cx_id,
        cell_candidate_id=cell_id,
        transitions=(_StubTransition(cx_id),),
        state=SecurityStateV1(),
        epoch_id=epoch_id,
        expected=result,
        observed=result,
        divergence_type="STATE_DELTA",
        evidence=_evidence(1),
        incident_linked=incident_linked,
    )


def test_full_melt_preserves_incident_linked_counterexamples_and_rollback_version() -> None:
    """§29/§40: incident-linked evidence survives melting, independently of GC."""
    field, index, cells = _real_field()
    target = cells["fs"]
    store = CounterexampleStore(cold_archive=None)
    result = CellVM().run(target.operator, _frame())
    store.record(
        _counterexample(target.cell_id, cx_id="cx-incident", result=result, incident_linked=True)
    )
    store.record(_counterexample(target.cell_id, cx_id="cx-plain", result=result))

    report = full_melt(target, field=field, index=index)

    assert report.kind is MeltKind.FULL
    assert report.surviving_cell is None
    assert report.rollback_version == target.version
    assert report.melted_cell is target
    assert field.get("fs") is None
    assert "fs" not in index.cell_ids()
    # Untouched: ``full_melt`` holds no reference to the store, which is the
    # guarantee — expressed as an absence rather than as a promise.
    assert {cx.counterexample_id for cx in store.for_candidate(target.cell_id)} == {
        "cx-incident",
        "cx-plain",
    }
    assert not hasattr(store, "delete")
    assert report.repair_locality == 1.0


def test_rollback_reinstates_a_fully_melted_cell() -> None:
    field, index, cells = _real_field()
    target = cells["fs"]
    frame = _frame(
        family=RelationFamily.FILESYSTEM,
        actor=SemanticProperty.PERSISTENCE_WRITER,
        raised={"persistence": (0, 1)},
    )
    report = full_melt(target, field=field, index=index)
    assert index.lookup(frame) is None

    restored = rollback(report, field=field, index=index)

    assert restored is target
    assert index.lookup(frame) is target
    # Rolling back twice is a no-op, not a duplicate insert.
    assert rollback(report, field=field, index=index) is None


def test_rollback_refuses_a_partial_melt_report() -> None:
    """A partial melt already left a survivor; reinstating the parent would put
    two cells over the same territory."""
    field, index, cells = _regioned_field()
    report = partial_melt(
        cells["region-a"],
        _index_boundary((P_NET,), frozenset({"privilege"})),
        field=field,
        index=index,
    )
    assert report.surviving_cell is not None
    assert rollback(report, field=field, index=index) is None


def test_repair_locality_is_none_not_zero_when_nothing_could_have_been_damaged() -> None:
    """``None`` never means zero, and never means 'within target'."""
    field = KnowledgeField()
    index = BoundaryIndex()
    lone = _cell("lone", (P_FS,), frozenset({"persistence"}))
    field.insert(lone)
    index.insert(lone)

    report = full_melt(lone, field=field, index=index)

    assert report.unrelated_cells_before == 0
    assert report.repair_locality is None
    assert report.to_dict()["repair_locality"] is None


def test_melt_report_refuses_to_retain_more_cells_than_existed() -> None:
    """The invariant guard: a locality above 1.0 cannot be constructed."""
    with pytest.raises(ContractError, match="better-than-perfect"):
        MeltReport(
            cell_id="c",
            kind=MeltKind.FULL,
            melted_region=None,
            surviving_cell=None,
            reopened_keys=(),
            unrelated_cells_before=2,
            unrelated_cells_retained=3,
            rollback_version=0,
            reason="fabricated",
        )


def test_successor_cell_id_does_not_grow_without_bound() -> None:
    cell = _LifecycleCell("region-b", _index_boundary((P_FS,), frozenset({"persistence"})))
    first = successor_cell_id(cell)
    second = successor_cell_id(replace(cell, cell_id=first, version=2))
    assert first == "region-b-v2"
    assert second == "region-b-v3"


# --- promotion: the G3.12 guard ----------------------------------------------


class _PressureStub:
    """Stands in for ``BoundaryPressureReport``; promotion reads only presence."""

    def to_dict(self) -> dict[str, Any]:
        return {"strategy": "GUIDED", "probes_run": 0}


def _met_shadow(consequence: SecurityConsequence = SecurityConsequence.ROUTINE) -> ShadowRun:
    frames, keys = SHADOW_MIN_COVERAGE[consequence]
    return ShadowRun(
        frames_seen=frames,
        distinct_boundary_keys=keys,
        distinct_transitions=SHADOW_MIN_TRANSITIONS[consequence],
        agreements=frames,
        divergences=(),
        consequence=consequence,
        coverage_met=True,
        reason=f"COVERAGE_MET[{consequence.name}]",
    )


def _assurance(
    level: AssuranceLevel,
    *,
    shadow: ShadowRun | None = None,
    proven: tuple[str, ...] = (),
    prover: str | None = None,
    counterexamples_open: int = 0,
) -> AssuranceState:
    return AssuranceState(
        level=level,
        replay=shadow,
        pressure=_PressureStub(),
        shadow=shadow,
        exhaustive_domain="the boundary keys of this cell, enumerated",
        proven_properties=proven,
        prover=prover,
        counterexamples_open=counterexamples_open,
    )


def test_promote_cell_raises_on_an_a5_claim_with_no_prover() -> None:
    field, index = KnowledgeField(), BoundaryIndex()
    cell = _cell("a5", (P_FS,), frozenset({"persistence"}), assurance=AssuranceLevel.A5)
    state = _assurance(
        AssuranceLevel.A5, shadow=_met_shadow(), proven=(ALL_PROVEN_PROPERTIES[0],)
    )

    with pytest.raises(ContractError, match="prover=None"):
        promote_cell(cell, state, field=field, index=index)
    assert len(field) == 0


def test_promote_cell_raises_on_an_a5_claim_naming_an_unproven_property() -> None:
    field, index = KnowledgeField(), BoundaryIndex()
    cell = _cell("a5b", (P_FS,), frozenset({"persistence"}), assurance=AssuranceLevel.A5)
    state = _assurance(
        AssuranceLevel.A5,
        shadow=_met_shadow(),
        proven=("memory safety: the VM is written in a safe language",),
        prover="pocketsec.stage3.bytecode.verifier:verify",
    )

    with pytest.raises(ContractError, match="does not prove by construction"):
        promote_cell(cell, state, field=field, index=index)


def test_promote_cell_raises_when_an_empirical_property_is_claimed_as_proven() -> None:
    """The exact wording G3.12 exists to police: tested is not proven."""
    field, index = KnowledgeField(), BoundaryIndex()
    cell = _cell("a4", (P_FS,), frozenset({"persistence"}), assurance=AssuranceLevel.A4)
    state = _assurance(
        AssuranceLevel.A4, shadow=_met_shadow(), proven=(TESTED_ONLY_PROPERTIES[0],)
    )

    with pytest.raises(ContractError, match="TESTED_ONLY_PROPERTIES"):
        promote_cell(cell, state, field=field, index=index)


def test_promote_cell_admits_a_well_evidenced_a3_cell() -> None:
    field, index = KnowledgeField(), BoundaryIndex()
    cell = _cell("good", (P_FS,), frozenset({"persistence"}))

    verdict = promote_cell(
        cell, _assurance(AssuranceLevel.A3, shadow=_met_shadow()), field=field, index=index
    )

    assert verdict.outcome is PromotionOutcome.PROMOTED
    assert verdict.cell is cell
    assert index.keys_for("good")


def test_promote_cell_refuses_an_open_counterexample() -> None:
    field, index = KnowledgeField(), BoundaryIndex()
    cell = _cell("known-wrong", (P_FS,), frozenset({"persistence"}))
    state = _assurance(AssuranceLevel.A3, shadow=_met_shadow(), counterexamples_open=1)

    verdict = promote_cell(cell, state, field=field, index=index)

    assert verdict.outcome is PromotionOutcome.REFUSED_OPEN_COUNTEREXAMPLE
    assert verdict.cell is None
    assert len(field) == 0 and len(index) == 0


def test_promote_cell_refuses_short_shadow_coverage() -> None:
    field, index = KnowledgeField(), BoundaryIndex()
    cell = _cell("thin", (P_FS,), frozenset({"persistence"}))
    thin = replace(
        _met_shadow(),
        frames_seen=4,
        agreements=4,
        coverage_met=False,
        reason="COVERAGE_SHORT[ROUTINE]: frames 4 < 32",
    )

    verdict = promote_cell(
        cell, _assurance(AssuranceLevel.A3, shadow=thin), field=field, index=index
    )

    assert verdict.outcome is PromotionOutcome.REFUSED_COVERAGE
    assert len(field) == 0


def test_promote_cell_refuses_a_melted_cell() -> None:
    field, index = KnowledgeField(), BoundaryIndex()
    cell = _cell("melted", (P_FS,), frozenset({"persistence"}), phase=CellPhase.MELTED)

    verdict = promote_cell(
        cell, _assurance(AssuranceLevel.A3, shadow=_met_shadow()), field=field, index=index
    )

    assert verdict.outcome is PromotionOutcome.REFUSED_HARD_CONSTRAINT
    assert "MELTED" in verdict.reason


def test_promote_cell_refuses_a_shadow_run_with_divergences() -> None:
    field, index = KnowledgeField(), BoundaryIndex()
    cell = _cell("diverged", (P_FS,), frozenset({"persistence"}))
    oracle = DualOracleEvaluator(teacher=TeacherOracle(None), vm=CellVM())
    run = shadow_execute(cell, (_frame(),), oracle=oracle, vm=CellVM())
    assert run.divergences, "an unavailable teacher must register as divergence, not agreement"
    diverged = replace(
        run,
        frames_seen=32,
        distinct_boundary_keys=2,
        distinct_transitions=2,
        agreements=0,
        coverage_met=True,
        reason="COVERAGE_MET[ROUTINE]",
    )

    verdict = promote_cell(
        cell, _assurance(AssuranceLevel.A3, shadow=diverged), field=field, index=index
    )

    assert verdict.outcome is PromotionOutcome.REFUSED_HARD_CONSTRAINT
    assert len(field) == 0


def test_promote_cell_refuses_an_a0_candidate() -> None:
    """Pins S3-AUTH-06: A0 promoted on no evidence at all.

    ``ASSURANCE_EVIDENCE[A0]`` is the empty tuple, so ``missing_evidence()`` was
    empty and the assurance check was vacuous exactly where §25 calls a cell
    "candidate only". A0 is also the only level this repository's cell producers
    emit — ``crystallize`` builds at A0, and ``fuse_cells`` demotes to A0 "so it
    re-enters shadow", a rule with no mechanism behind it unless promotion refuses.
    """
    field, index = KnowledgeField(), BoundaryIndex()
    cell = _cell(
        "candidate", (P_FS,), frozenset({"persistence"}), assurance=AssuranceLevel.A0
    )
    bare = AssuranceState(
        level=AssuranceLevel.A0,
        replay=None,
        pressure=None,
        shadow=None,
        exhaustive_domain=None,
        proven_properties=(),
        prover=None,
        counterexamples_open=0,
    )
    assert bare.missing_evidence() == (), "A0 requires nothing; that is the defect"

    verdict = promote_cell(cell, bare, field=field, index=index)

    assert verdict.outcome is PromotionOutcome.REFUSED_ASSURANCE
    assert MIN_PROMOTABLE_ASSURANCE.value in verdict.reason
    assert field.get("candidate") is None
    assert "candidate" not in index.cell_ids()


def test_a_fused_cell_cannot_be_promoted_before_it_re_enters_shadow() -> None:
    """Pins S3-AUTH-06 on the path that produces A0 cells in this repository.

    ``fuse_cells`` demotes to A0/STRUCTURED precisely so the fused cell re-enters
    shadow. Without a promotion-time refusal that sentence was a comment.
    """
    from pocketsec.stage3.cells.fusion import fuse_cells

    left = _cell("fuse-a", (P_FS,), frozenset({"persistence"}))
    right = _cell("fuse-b", (P_AUTH,), frozenset({"trust"}))
    fused = fuse_cells(left, right)
    assert fused.assurance is AssuranceLevel.A0

    verdict = promote_cell(
        fused,
        AssuranceState(
            level=AssuranceLevel.A0,
            replay=None,
            pressure=None,
            shadow=None,
            exhaustive_domain=None,
            proven_properties=(),
            prover=None,
            counterexamples_open=0,
        ),
        field=KnowledgeField(),
        index=BoundaryIndex(),
    )

    assert verdict.outcome is PromotionOutcome.REFUSED_ASSURANCE


def test_promote_cell_refuses_an_assurance_level_the_cell_does_not_carry() -> None:
    field, index = KnowledgeField(), BoundaryIndex()
    cell = _cell("mismatch", (P_FS,), frozenset({"persistence"}), assurance=AssuranceLevel.A1)

    verdict = promote_cell(
        cell, _assurance(AssuranceLevel.A3, shadow=_met_shadow()), field=field, index=index
    )

    assert verdict.outcome is PromotionOutcome.REFUSED_ASSURANCE


def test_promote_cell_refuses_a_level_whose_evidence_is_missing() -> None:
    field, index = KnowledgeField(), BoundaryIndex()
    cell = _cell("bare", (P_FS,), frozenset({"persistence"}))

    verdict = promote_cell(
        cell, _assurance(AssuranceLevel.A3, shadow=None), field=field, index=index
    )

    assert verdict.outcome is PromotionOutcome.REFUSED_ASSURANCE
    assert "shadow" in verdict.reason


def test_promote_cell_is_all_or_nothing_when_the_index_refuses() -> None:
    """A cell in the field but not the index answers where melting cannot see.

    The cell needs a footprint genuinely larger than ``max_keys``, and breadth
    over ``state_dimensions`` does not supply one: ``CellBoundary.keys`` folds
    the declared dimensions into a single union delta mask, so a two-dimension
    boundary with one predicate claims exactly one key. Two predicates on two
    relation families claim four, which is what makes the index refuse and this
    test exercise the rollback rather than the happy path.
    """
    field = KnowledgeField()
    index = BoundaryIndex(max_keys=1)
    cell = _cell("wide", (P_IDENT, P_FS), frozenset({"credential", "privilege"}))

    verdict = promote_cell(
        cell, _assurance(AssuranceLevel.A3, shadow=_met_shadow()), field=field, index=index
    )

    assert verdict.outcome is PromotionOutcome.REFUSED_FIELD_FULL
    assert len(field) == 0, "the field insertion must be rolled back"
    assert len(index) == 0


def test_promote_cell_refuses_a_field_at_capacity() -> None:
    field = KnowledgeField(max_cells=1)
    index = BoundaryIndex()
    state = _assurance(AssuranceLevel.A3, shadow=_met_shadow())
    first = _cell("first", (P_FS,), frozenset({"persistence"}))
    second = _cell("second", (P_AUTH,), frozenset({"trust"}))
    assert promote_cell(first, state, field=field, index=index).outcome is (
        PromotionOutcome.PROMOTED
    )

    verdict = promote_cell(second, state, field=field, index=index)

    assert verdict.outcome is PromotionOutcome.REFUSED_FIELD_FULL
    assert "second" not in index.cell_ids()


def test_assurance_state_records_an_unfounded_claim_so_promotion_can_reject_it() -> None:
    """The guard lives in ``promote_cell``, not in the record.

    If ``AssuranceState`` refused the claim at construction, an unfounded claim
    could never reach the check that rejects it, and Stage 10 — which extends
    this type — would have no way to represent a state under review.
    """
    state = _assurance(AssuranceLevel.A5, shadow=_met_shadow(), proven=("something untrue",))
    assert state.proven_properties == ("something untrue",)
    assert state.to_dict()["level"] == "A5"
    assert state.missing_evidence() == ("prover",)


def test_assurance_state_refuses_a_prover_nobody_can_open() -> None:
    with pytest.raises(ContractError, match="module:function"):
        _assurance(AssuranceLevel.A5, shadow=_met_shadow(), prover="trust me")


# --- shadow execution ---------------------------------------------------------


def test_shadow_coverage_for_critical_is_strictly_stricter_than_for_routine() -> None:
    routine_frames, routine_keys = SHADOW_MIN_COVERAGE[SecurityConsequence.ROUTINE]
    critical_frames, critical_keys = SHADOW_MIN_COVERAGE[SecurityConsequence.CRITICAL]

    assert critical_frames > routine_frames
    assert critical_keys > routine_keys
    assert (
        SHADOW_MIN_TRANSITIONS[SecurityConsequence.CRITICAL]
        > SHADOW_MIN_TRANSITIONS[SecurityConsequence.ROUTINE]
    )
    ordered = sorted(SecurityConsequence)
    assert set(SHADOW_MIN_COVERAGE) == set(ordered)
    triples = [(*SHADOW_MIN_COVERAGE[level], SHADOW_MIN_TRANSITIONS[level]) for level in ordered]
    for lower, higher in zip(triples, triples[1:], strict=False):
        assert all(h > lo for lo, h in zip(lower, higher, strict=True))


def _routine_covering_frames() -> tuple[CellFrame, ...]:
    """Enough frames, keys and transition shapes to clear the ROUTINE floors."""
    min_frames, _ = SHADOW_MIN_COVERAGE[SecurityConsequence.ROUTINE]
    families = (RelationFamily.FILESYSTEM, RelationFamily.NETWORK, RelationFamily.IDENTITY)
    actors = (
        SemanticProperty.PERSISTENCE_WRITER,
        SemanticProperty.NETWORK_CLIENT,
        SemanticProperty.CREDENTIAL_READER,
    )
    return tuple(
        _frame(
            family=families[i % len(families)],
            actor=actors[i % len(actors)],
            phi=0.1 * (i % 5),
            evidence_tag=f"f{i}-",
        )
        for i in range(min_frames)
    )


def _teacher_for(frames: tuple[CellFrame, ...], *, score: float = 0.0) -> TeacherOracle:
    """A frozen Φ-oracle snapshot covering exactly these frames.

    Oracle A is data, never a live forward pass (ADR-0023). A frame outside the
    snapshot yields ``None``, which the dual oracle reads as UNKNOWN and refuses
    to treat as agreement.
    """
    snapshot = TeacherSnapshotV1.create(
        teacher_id="teacher-lifecycle",
        source="phi-oracle",
        encoder_version=ENCODER,
        corpus_version="lifecycle-tests.1",
        seed=0,
        responses={frame_digest(frame): score for frame in frames},
        measured_by="tests.test_stage3_lifecycle:_teacher_for",
        experiment_id=EXPERIMENT_ID,
    )
    return TeacherOracle(snapshot)


def test_the_same_frames_that_cover_routine_fail_critical() -> None:
    """Coverage is consequence-dependent, not a single event count (§26)."""
    routine_cell = _cell("cov-routine", (P_FS,), frozenset({"persistence"}))
    critical_cell = _cell(
        "cov-critical",
        (P_FS,),
        frozenset({"persistence"}),
        consequence=SecurityConsequence.CRITICAL,
    )
    frames = _routine_covering_frames()
    oracle = DualOracleEvaluator(teacher=_teacher_for(frames), vm=CellVM())
    vm = CellVM()

    routine_run = shadow_execute(routine_cell, frames, oracle=oracle, vm=vm)
    critical_run = shadow_execute(critical_cell, frames, oracle=oracle, vm=vm)

    assert routine_run.coverage_met is True
    assert critical_run.coverage_met is False
    assert "COVERAGE_SHORT[CRITICAL]" in critical_run.reason


def test_shadow_execute_changes_nothing_and_counts_agreement_honestly() -> None:
    field, index, cells = _real_field()
    cell = cells["fs"]
    frames = _routine_covering_frames()
    oracle = DualOracleEvaluator(teacher=_teacher_for(frames), vm=CellVM())
    before_cells = field.cells()
    before_keys = index.key_count()

    run = shadow_execute(cell, frames, oracle=oracle, vm=CellVM())

    assert field.cells() == before_cells
    assert index.key_count() == before_keys
    assert run.frames_seen == len(frames)
    assert run.agreements + len(run.divergences) + run.abstentions == run.frames_seen
    assert run.distinct_boundary_keys >= 2
    assert run.distinct_transitions >= 2


def test_shadow_run_refuses_more_agreements_than_frames() -> None:
    with pytest.raises(ContractError, match="different populations"):
        ShadowRun(
            frames_seen=2,
            distinct_boundary_keys=2,
            distinct_transitions=2,
            agreements=3,
            divergences=(),
            consequence=SecurityConsequence.ROUTINE,
            coverage_met=True,
            reason="fabricated",
        )


# --- adaptive auditing --------------------------------------------------------


def _stress(driver: float = 0.0) -> CellStress:
    return CellStress(
        teacher_disagreement=driver,
        boundary_violations=0,
        epoch_drift=0,
        uncertainty_rise=0.0,
        counterexamples=0,
        calibration_decay=0.0,
    )


class _FixedStress:
    """A stress value with a chosen ``total``, for threshold-boundary tests."""

    def __init__(self, total: float) -> None:
        self.total = total


def test_audit_sampler_decisions_are_not_reproducible_without_the_boot_salt() -> None:
    """§39 audit gaming: the schedule must not be a function of public data.

    Cell id and frame are both observable. If an attacker could reproduce the
    decision from those alone they could wait for an unaudited frame.
    """
    cell = _cell("sampled", (P_FS,), frozenset({"persistence"}))
    frames = _routine_covering_frames()
    attacker = AuditSampler("guessed-salt")
    defender = AuditSampler("actual-boot-salt")

    attacker_calls = [attacker.should_audit(cell, f, probability=0.5) for f in frames]
    defender_calls = [defender.should_audit(cell, f, probability=0.5) for f in frames]

    assert attacker_calls != defender_calls
    # The same salt reproduces exactly, so an audit can be replayed and argued about.
    assert [
        AuditSampler("actual-boot-salt").should_audit(cell, f, probability=0.5) for f in frames
    ] == defender_calls


def test_audit_sampler_is_not_a_counter() -> None:
    """Decisions depend on the frame, not on how many frames came before it."""
    cell = _cell("nocount", (P_FS,), frozenset({"persistence"}))
    frames = _routine_covering_frames()
    sampler = AuditSampler("salt")
    forwards = [sampler.should_audit(cell, f, probability=0.5) for f in frames]
    backwards = [sampler.should_audit(cell, f, probability=0.5) for f in reversed(frames)]
    assert forwards == list(reversed(backwards))


def test_audit_sampler_never_switches_auditing_off() -> None:
    """A probability of zero is clamped to the floor, not honoured.

    A promoted cell that is never re-checked is an unverified cell holding the
    authority of a verified one.
    """
    cell = _cell("floored", (P_FS,), frozenset({"persistence"}))
    sampler = AuditSampler("salt")
    frame = _frame()
    assert sampler.should_audit(cell, frame, probability=0.0) == (
        sampler.draw(cell, frame) < MIN_AUDIT_RATE
    )
    with pytest.raises(ContractError):
        sampler.should_audit(cell, frame, probability=1.5)
    with pytest.raises(ContractError, match="boot_salt"):
        AuditSampler("   ")


def test_audit_probability_rises_with_consequence_stress_and_proximity() -> None:
    routine = _cell("p-routine", (P_FS,), frozenset({"persistence"}))
    critical = _cell(
        "p-critical",
        (P_FS,),
        frozenset({"persistence"}),
        consequence=SecurityConsequence.CRITICAL,
    )
    base: dict[str, Any] = {
        "stress": _stress(),
        "epoch_age": 0,
        "boundary_distance": 4,
        "recent_agreement": 0.0,
    }

    calm = audit_probability(routine, **base)
    assert audit_probability(critical, **base) > calm
    assert audit_probability(routine, **{**base, "stress": _stress(1.0)}) > calm
    assert audit_probability(routine, **{**base, "boundary_distance": 0}) > calm
    assert audit_probability(routine, **{**base, "epoch_age": 6}) > calm
    assert audit_probability(routine, **{**base, "recent_agreement": 1.0}) < calm


def test_audit_probability_stays_inside_the_declared_bounds() -> None:
    cell = _cell("bounded", (P_FS,), frozenset({"persistence"}))
    maxed = audit_probability(
        cell, stress=_stress(1.0), epoch_age=1000, boundary_distance=0, recent_agreement=0.0
    )
    floored = audit_probability(
        cell, stress=_stress(), epoch_age=0, boundary_distance=1000, recent_agreement=1.0
    )
    assert MIN_AUDIT_RATE <= floored <= maxed <= MAX_AUDIT_RATE
    with pytest.raises(ContractError):
        audit_probability(
            cell, stress=_stress(), epoch_age=-1, boundary_distance=0, recent_agreement=0.0
        )


def test_sample_audit_reports_an_unmeasured_teacher_cost_as_none() -> None:
    cell = _cell("cost", (P_FS,), frozenset({"persistence"}))
    frames = _routine_covering_frames()
    oracle = DualOracleEvaluator(teacher=_teacher_for(frames), vm=CellVM())

    report = sample_audit(
        cell, frames, sampler=AuditSampler("salt"), oracle=oracle, probability=1.0
    )

    assert report.audits == len(frames)
    assert report.rate_observed == 1.0
    assert report.teacher_cost_us is None, "UNMEASURED is None, never 0.0"
    assert report.disagreement_rate is not None


def test_sample_audit_at_the_floor_does_not_claim_a_teacher_it_never_consulted() -> None:
    cell = _cell("quiet", (P_FS,), frozenset({"persistence"}))
    frames = _routine_covering_frames()
    oracle = DualOracleEvaluator(teacher=_teacher_for(frames), vm=CellVM())

    report = sample_audit(
        cell, frames, sampler=AuditSampler("salt"), oracle=oracle, probability=MIN_AUDIT_RATE
    )

    assert report.audits == 0
    assert report.teacher_available is False
    assert report.disagreement_rate is None


def test_audit_report_refuses_more_disagreements_than_audits() -> None:
    with pytest.raises(ContractError, match="different populations"):
        AuditReport(
            audits=2,
            disagreements=3,
            rate_observed=1.0,
            teacher_available=True,
            teacher_cost_us=None,
        )


# --- certificate decay --------------------------------------------------------


def test_decay_confidence_has_no_time_term() -> None:
    """§28: age alone does not make knowledge wrong.

    Asserted on the signature so a later ``age_seconds`` cannot be slipped in
    beside the event counts, and on the fixed point so a constant drift cannot
    be hidden in the body.
    """
    parameters = inspect.signature(decay_confidence).parameters
    assert tuple(parameters)[0] == "confidence"
    assert tuple(parameters)[1:] == DECAY_EVENT_TERMS
    forbidden = ("age", "time", "seconds", "elapsed", "clock", "now")
    assert not [
        name for name in parameters if any(token in name.lower() for token in forbidden)
    ]

    value = 0.77
    for _ in range(1000):
        value = decay_confidence(
            value,
            successful_audits=0,
            disagreements=0,
            epoch_shifts=0,
            boundary_violations=0,
            unobserved_changes=0,
        )
    assert value == 0.77


@dataclass(frozen=True, slots=True)
class _StubVerdict:
    """The three fields ``sample_audit`` reads off a ``DualOracleVerdict``."""

    passed: bool
    teacher_available: bool = True
    hard_violations: tuple[Any, ...] = ()
    reason: str = ""


def test_a_silent_teacher_is_not_reported_as_total_disagreement() -> None:
    """Pins S3-10: absence of a teacher read as ``teacher_disagreement = 1.0``.

    ``_decide`` returns not-passed for TEACHER_UNAVAILABLE as well as for real
    divergence, and ``sample_audit`` counted every not-passed verdict as a
    disagreement. A snapshot built on a different split therefore produced a 1.0
    disagreement rate — the maximum, and the heaviest-weighted term in
    ``CellStress`` — for a cell nothing had been measured wrong about. A rate over
    trials in which the oracle never answered is undefined, not 1.0.
    """

    class _SilentTeacherOracle:
        def evaluate(self, cell: Any, frames: tuple[CellFrame, ...]) -> Any:
            return _StubVerdict(
                passed=False, teacher_available=False, reason="TEACHER_UNAVAILABLE"
            )

    cell = _cell("silent", (P_NET,), frozenset({"privilege"}))
    frames = tuple(_frame(epoch_id=0, evidence_tag=f"e{i}") for i in range(16))
    report = sample_audit(
        cell,
        frames,
        sampler=AuditSampler("boot-salt"),
        oracle=_SilentTeacherOracle(),
        probability=1.0,
    )

    assert report.audits == len(frames)
    assert report.teacher_silent == report.audits
    assert report.disagreements == 0
    assert report.measured_audits == 0
    assert report.disagreement_rate is None, "a rate over no opinions is UNMEASURED"
    with pytest.raises(ContractError, match="UNMEASURED rather than 1.0"):
        compute_cell_stress(
            cell, audit=report, pressure=None, store=CounterexampleStore(cold_archive=None)
        )


def test_a_hard_violation_is_still_a_disagreement_without_a_teacher() -> None:
    """The S3-10 fix must not exempt a cell Oracle B caught.

    A hard constraint violation is the cell being wrong whatever the teacher says.
    """

    class _ViolatingOracle:
        def evaluate(self, cell: Any, frames: tuple[CellFrame, ...]) -> Any:
            return _StubVerdict(
                passed=False,
                teacher_available=False,
                hard_violations=(object(),),
                reason="HARD_CONSTRAINT_VIOLATED",
            )

    cell = _cell("caught", (P_NET,), frozenset({"privilege"}))
    frames = tuple(_frame(epoch_id=0, evidence_tag=f"h{i}") for i in range(8))
    report = sample_audit(
        cell,
        frames,
        sampler=AuditSampler("boot-salt"),
        oracle=_ViolatingOracle(),
        probability=1.0,
    )

    assert report.teacher_silent == 0
    assert report.disagreements == report.audits
    assert report.disagreement_rate == 1.0
    stress = compute_cell_stress(
        cell, audit=report, pressure=None, store=CounterexampleStore(cold_archive=None)
    )
    assert stress.teacher_disagreement == 1.0


def test_re_salting_one_cell_changes_its_audit_schedule() -> None:
    """Pins S3-AUTH-04: ``AuditPolicy.jitter_salt`` was never read.

    ``AuditSampler.draw`` keyed on ``(boot_salt, cell_id, frame_digest)`` only, so
    two cells differing solely in their jitter salt produced byte-identical draw
    sequences and the documented mitigation — rotate a compromised cell's salt —
    was provably a no-op, while ``AuditPolicy``'s docstring asserted a per-cell
    salt and the field crossed the Stage 4 seam as though it did something.
    """
    base = _cell("salted", (P_NET,), frozenset({"privilege"}))
    rotated = replace(
        base,
        audit_policy=AuditPolicy(
            base_rate=base.audit_policy.base_rate,
            min_rate=base.audit_policy.min_rate,
            max_rate=base.audit_policy.max_rate,
            jitter_salt="rotated-after-a-suspected-compromise",
        ),
    )
    assert base.cell_id == rotated.cell_id
    assert base.audit_policy.jitter_salt != rotated.audit_policy.jitter_salt
    sampler = AuditSampler("boot-salt")
    frames = tuple(_frame(epoch_id=0, evidence_tag=f"s{i}") for i in range(32))

    before = [sampler.draw(base, frame) for frame in frames]
    after = [sampler.draw(rotated, frame) for frame in frames]

    assert before != after, "rotating a cell's salt must change its schedule"
    # Still reproducible for a given boot salt and policy, or an audit could not
    # be replayed and argued about.
    assert [sampler.draw(base, frame) for frame in frames] == before
    # And still unpredictable without the boot salt.
    assert [AuditSampler("other-boot").draw(base, frame) for frame in frames] != before


def test_decay_confidence_moves_only_on_observed_events_and_stays_bounded() -> None:
    dropped = decay_confidence(
        0.9,
        successful_audits=0,
        disagreements=3,
        epoch_shifts=1,
        boundary_violations=2,
        unobserved_changes=0,
    )
    assert 0.0 <= dropped < 0.9
    assert (
        decay_confidence(
            0.1,
            successful_audits=0,
            disagreements=100,
            epoch_shifts=0,
            boundary_violations=0,
            unobserved_changes=0,
        )
        == 0.0
    )
    assert (
        decay_confidence(
            0.99,
            successful_audits=1000,
            disagreements=0,
            epoch_shifts=0,
            boundary_violations=0,
            unobserved_changes=0,
        )
        == 1.0
    )
    with pytest.raises(ContractError):
        decay_confidence(
            0.5,
            successful_audits=-1,
            disagreements=0,
            epoch_shifts=0,
            boundary_violations=0,
            unobserved_changes=0,
        )


def test_crossing_the_assurance_floor_never_silently_continues() -> None:
    """Below the floor the answer is more auditing or a melt — never 'carry on'."""
    assert below_minimum(MIN_ASSURANCE_CONFIDENCE - 1e-9)
    assert not below_minimum(MIN_ASSURANCE_CONFIDENCE)

    assert decay_response(0.9, stress=_stress()) is ConfidenceAction.CONTINUE

    low = MIN_ASSURANCE_CONFIDENCE / 2
    assert decay_response(low, stress=_stress()) is ConfidenceAction.RAISE_AUDIT_RATE
    assert (
        decay_response(low, stress=_FixedStress(PARTIAL_MELT_THRESHOLD))
        is ConfidenceAction.PARTIAL_MELT
    )
    assert (
        decay_response(low, stress=_FixedStress(FULL_MELT_THRESHOLD))
        is ConfidenceAction.FULL_MELT
    )
    # There is no member that means "log it and keep going".
    assert set(ConfidenceAction) == {
        ConfidenceAction.CONTINUE,
        ConfidenceAction.RAISE_AUDIT_RATE,
        ConfidenceAction.PARTIAL_MELT,
        ConfidenceAction.FULL_MELT,
    }


# --- cell stress --------------------------------------------------------------


def test_compute_cell_stress_refuses_to_invent_a_rate_over_zero_audits() -> None:
    """A disagreement rate over no trials is undefined, not zero."""
    cell = _cell("unaudited", (P_FS,), frozenset({"persistence"}))
    store = CounterexampleStore(cold_archive=None)
    empty = AuditReport(
        audits=0,
        disagreements=0,
        rate_observed=0.0,
        teacher_available=False,
        teacher_cost_us=None,
    )

    with pytest.raises(ContractError, match="rate over zero trials"):
        compute_cell_stress(cell, audit=empty, pressure=None, store=store)


def test_compute_cell_stress_counts_only_unsuperseded_counterexamples() -> None:
    cell = _cell("stressed", (P_FS,), frozenset({"persistence"}))
    store = CounterexampleStore(cold_archive=None)
    result = CellVM().run(cell.operator, _frame())
    store.record(_counterexample(cell.cell_id, cx_id="cx-old", result=result, epoch_id=7))
    store.record(_counterexample(cell.cell_id, cx_id="cx-new", result=result, epoch_id=7))
    audit = AuditReport(
        audits=10,
        disagreements=2,
        rate_observed=0.5,
        teacher_available=True,
        teacher_cost_us=None,
    )

    before = compute_cell_stress(cell, audit=audit, pressure=None, store=store)
    store.supersede("cx-old", "cx-new")
    after = compute_cell_stress(cell, audit=audit, pressure=None, store=store)

    assert before.counterexamples == 2
    assert after.counterexamples == 1
    assert after.total < before.total
    # Epoch 7 is outside the cell's declared {0, 1}: that is drift, and it counts.
    assert after.epoch_drift == 1
    assert before.teacher_disagreement == pytest.approx(0.2)


def test_cell_stress_total_is_bounded_and_monotone() -> None:
    quiet = CellStress(
        teacher_disagreement=0.0,
        boundary_violations=0,
        epoch_drift=0,
        uncertainty_rise=0.0,
        counterexamples=0,
        calibration_decay=0.0,
    )
    loud = CellStress(
        teacher_disagreement=1.0,
        boundary_violations=1000,
        epoch_drift=1000,
        uncertainty_rise=1.0,
        counterexamples=1000,
        calibration_decay=1.0,
    )
    assert quiet.total == 0.0
    assert 0.0 < loud.total <= 1.0
    assert loud.total > quiet.total
    with pytest.raises(ContractError):
        CellStress(
            teacher_disagreement=-0.1,
            boundary_violations=0,
            epoch_drift=0,
            uncertainty_rise=0.0,
            counterexamples=0,
            calibration_decay=0.0,
        )


# --- end to end ---------------------------------------------------------------


def test_promote_audit_stress_decay_end_to_end() -> None:
    """G3.6's promotion half, over real cells and a real field."""
    field, index = KnowledgeField(), BoundaryIndex()
    store = CounterexampleStore(cold_archive=None)
    cell = _cell("e2e", (P_FS,), frozenset({"persistence"}))
    frames = _routine_covering_frames()
    oracle = DualOracleEvaluator(teacher=_teacher_for(frames), vm=CellVM())

    run = shadow_execute(cell, frames, oracle=oracle, vm=CellVM())
    state = AssuranceState(
        level=AssuranceLevel.A3,
        replay=run,
        pressure=_PressureStub(),
        shadow=replace(run, divergences=(), coverage_met=True, agreements=run.frames_seen),
        exhaustive_domain=None,
        proven_properties=(),
        prover=None,
        counterexamples_open=0,
    )
    assert promote_cell(cell, state, field=field, index=index).outcome is (
        PromotionOutcome.PROMOTED
    )

    report = sample_audit(
        cell, frames, sampler=AuditSampler("boot"), oracle=oracle, probability=1.0
    )
    stress = compute_cell_stress(cell, audit=report, pressure=None, store=store)
    probability = audit_probability(
        cell, stress=stress, epoch_age=1, boundary_distance=0, recent_agreement=0.2
    )
    assert MIN_AUDIT_RATE <= probability <= MAX_AUDIT_RATE

    confidence = decay_confidence(
        cell.confidence,
        successful_audits=report.audits - report.disagreements,
        disagreements=report.disagreements,
        epoch_shifts=1,
        boundary_violations=0,
        unobserved_changes=0,
    )
    assert 0.0 <= confidence <= 1.0
    assert decay_response(confidence, stress=stress) in set(ConfidenceAction)
    assert len(field) == 1
    assert field.memory_bytes() < 20 * 1024 * 1024

    melt = full_melt(cell, field=field, index=index)
    assert len(field) == 0
    assert rollback(melt, field=field, index=index) is cell


def test_verifier_proven_set_is_what_promotion_checks_against() -> None:
    """If this drifts, the G3.12 guard is checking against the wrong list."""
    cell = _cell("v", (P_FS,), frozenset({"persistence"}))
    assert verify(cell.operator).ok
    assert set(TESTED_ONLY_PROPERTIES).isdisjoint(ALL_PROVEN_PROPERTIES)
