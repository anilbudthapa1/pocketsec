"""D3.4 behaviour tests — the Knowledge Boundary index and Boundary Pressure.

These test refusals, not construction. The index must *raise* where a cache
would evict, ``lookup`` must return nothing where a nearest-neighbour structure
would return something, ``keys()`` must raise where a bounded builder would
truncate, and the guided search must find a counterexample class equal-budget
random replay misses or the mechanism is removed.

The Stage 3 packages this one calls — ``cells``, ``bytecode``, ``oracles`` — are
being written concurrently, so their types appear here as minimal stand-ins with
exactly the fields ``docs/stage-3-spec.md`` §D3.4/§D3.6/§D3.8 give them. The
production modules touch only those fields, which is what makes the stand-ins
legitimate rather than a way of dodging the real contract.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from pocketsec.stage0.contracts.common import ContractError, EvidenceRef
from pocketsec.stage1.ssir.entities import SemanticProperty
from pocketsec.stage1.ssir.relations import RelationFamily
from pocketsec.stage1.state.security_state import SecurityStateV1, StateDelta
from pocketsec.stage2.compile_candidates.candidate import ValidityBoundary
from pocketsec.stage3.boundary.index import (
    BOUNDARY_PROPERTY_ORDER,
    MAX_INDEX_KEYS,
    MAX_KEYS_PER_CELL,
    BoundaryIndex,
    BoundaryIndexFull,
    CellBoundary,
    boundary_property_mask,
    check_property_order,
)
from pocketsec.stage3.boundary.pressure import (
    AXIS_ORDER,
    MAX_PRESSURE_BUDGET,
    MAX_STEPS_PER_AXIS,
    BoundaryPressureReport,
    Perturbation,
    PressureStrategy,
    apply_boundary_pressure,
    compare_strategies,
    perturbed_frame,
    random_replay_control,
)

# --- stand-ins for the concurrently-built packages ---------------------------


@dataclass(frozen=True, slots=True)
class StubPredicate:
    """``cells/invariant.py`` ``SemanticPredicate``, fields §D3.3 assigns it."""

    role: str
    required_properties: frozenset[SemanticProperty] = frozenset()
    forbidden_properties: frozenset[SemanticProperty] = frozenset()
    relation_family: RelationFamily | None = None
    entity_kind: None = None


@dataclass(frozen=True, slots=True)
class StubFrame:
    """``bytecode/vm.py`` ``CellFrame``, fields §D3.6 assigns it."""

    state: SecurityStateV1
    delta: StateDelta
    actor_properties: int
    object_properties: int
    relation_family: RelationFamily
    phi: float
    delta_phi: float
    uncertainty: float
    epoch_id: int
    window_counts: dict[int, int]
    evidence: tuple[EvidenceRef, ...]
    encoder_version: str = "ssir-encoder.1"


@dataclass(frozen=True, slots=True)
class StubCell:
    """``cells/schema.py`` ``KnowledgeCellV1`` — only the two fields D3.4 reads."""

    cell_id: str
    boundary: CellBoundary


@dataclass(frozen=True, slots=True)
class StubViolation:
    constraint_id: str
    kind: str
    detail: str = ""
    frame_digest: str = ""


@dataclass(frozen=True, slots=True)
class StubDivergence:
    d_state_delta: float = 0.0
    d_security_potential: float = 0.0
    d_future_hazard: None = None
    d_uncertainty: float = 0.0
    d_evidence_requirement: float = 0.0
    d_causal_attribution: float = 0.0

    @property
    def total(self) -> float:
        return (
            self.d_state_delta
            + self.d_security_potential
            + self.d_uncertainty
            + self.d_evidence_requirement
            + self.d_causal_attribution
        )


@dataclass(frozen=True, slots=True)
class StubVerdict:
    passed: bool
    teacher_available: bool = True
    hard_violations: tuple[StubViolation, ...] = ()
    divergence: StubDivergence = field(default_factory=StubDivergence)
    reason: str = ""


def _evidence(count: int) -> tuple[EvidenceRef, ...]:
    return tuple(
        EvidenceRef(store="unit", locator=f"e{i}", digest=f"sha256:{i:064x}")
        for i in range(count)
    )


def _frame(**overrides: Any) -> StubFrame:
    base: dict[str, Any] = {
        "state": SecurityStateV1(),
        "delta": StateDelta(raised={}),
        "actor_properties": boundary_property_mask({SemanticProperty.NETWORK_CLIENT}),
        "object_properties": 0,
        "relation_family": RelationFamily.NETWORK,
        "phi": 0.0,
        "delta_phi": 0.0,
        "uncertainty": 0.1,
        "epoch_id": 0,
        "window_counts": {0: 0},
        "evidence": _evidence(8),
    }
    base.update(overrides)
    return StubFrame(**base)


def _boundary(**overrides: Any) -> CellBoundary:
    base: dict[str, Any] = {
        "predicates": (),
        "state_dimensions": frozenset({"privilege", "credential"}),
        "phi_range": (0.0, 1e9),
        "max_uncertainty": 0.5,
        "epochs": frozenset({0}),
        "forbidden_combinations": (),
    }
    base.update(overrides)
    return CellBoundary(**base)


def _actor_predicates(count: int, *, family: RelationFamily | None = None) -> tuple[StubPredicate, ...]:
    """``count`` ACTOR predicates with distinct required-property masks."""
    return tuple(
        StubPredicate(
            role="ACTOR",
            required_properties=frozenset({BOUNDARY_PROPERTY_ORDER[i]}),
            relation_family=family,
        )
        for i in range(count)
    )


# --- CellBoundary contract ---------------------------------------------------


def test_boundary_refuses_a_non_abstain_unseen_input_behaviour() -> None:
    with pytest.raises(ContractError, match="ABSTAIN"):
        _boundary(unseen_input_behaviour="NEAREST")


def test_boundary_refuses_an_unknown_state_dimension() -> None:
    with pytest.raises(ContractError, match="DIMENSIONS"):
        _boundary(state_dimensions=frozenset({"privilege", "vibes"}))


def test_boundary_refuses_an_inverted_phi_range() -> None:
    with pytest.raises(ContractError, match="ordered"):
        _boundary(phi_range=(2.0, 1.0))


def test_empty_boundary_contains_nothing_and_says_so() -> None:
    """Empty epochs are refused outright; empty dimensions are flagged.

    This test originally asserted that an empty-epoch boundary is merely
    ``is_empty``. It is now refused at construction, which is the stronger of the
    two behaviours and the one spec §4 D3.4 annotates (``epochs: frozenset[int]
    # non-empty``): an empty epoch set is the classic inversion, reading as
    "valid everywhere" and meaning "valid nowhere", and a value that can never be
    correct should not be constructible.

    ``is_empty`` keeps its job for the ``state_dimensions`` half, which a
    narrowing partial melt can legitimately produce and which
    ``KnowledgeCellV1.__post_init__`` refuses to promote.
    """
    with pytest.raises(ContractError, match="valid in no epoch"):
        _boundary(epochs=frozenset())
    assert _boundary(state_dimensions=frozenset()).is_empty
    assert not _boundary().is_empty


def test_distance_counts_each_violated_clause_separately() -> None:
    boundary = _boundary(predicates=_actor_predicates(1, family=RelationFamily.NETWORK))
    inside = _frame(actor_properties=boundary_property_mask({BOUNDARY_PROPERTY_ORDER[0]}))
    assert boundary.contains(inside)
    assert boundary.distance(inside) == 0

    # Three independent clauses broken at once: epoch, uncertainty and family.
    outside = _frame(
        actor_properties=boundary_property_mask({BOUNDARY_PROPERTY_ORDER[0]}),
        epoch_id=9,
        uncertainty=0.99,
        relation_family=RelationFamily.FILESYSTEM,
    )
    assert boundary.distance(outside) == 3
    assert set(boundary.violated_clauses(outside)) == {"epoch", "uncertainty", "relation_family"}


def test_from_validity_boundary_does_not_widen_or_narrow_what_stage2_declared() -> None:
    validity = ValidityBoundary(
        epochs=frozenset({0, 1}),
        encoder_version="ssir-encoder.1",
        state_dimensions=frozenset({"privilege"}),
        max_uncertainty=0.25,
        min_evidence_count=1,
    )
    lifted = CellBoundary.from_validity_boundary(validity)
    assert lifted.epochs == validity.epochs
    assert lifted.state_dimensions == validity.state_dimensions
    assert lifted.max_uncertainty == validity.max_uncertainty
    assert lifted.unseen_input_behaviour == validity.unseen_input_behaviour


# --- key expansion: the MAX_KEYS_PER_CELL cap --------------------------------


def test_boundary_at_the_key_cap_expands_to_exactly_that_many_keys() -> None:
    """The cap is 64, not a smaller number a truncating builder would settle on."""
    boundary = _boundary(predicates=_actor_predicates(8))
    keys = boundary.keys()
    assert len(keys) == MAX_KEYS_PER_CELL == 64
    assert len(set(keys)) == len(keys)


def test_boundary_past_the_key_cap_is_refused_at_insert_and_never_truncated() -> None:
    boundary = _boundary(predicates=_actor_predicates(9))  # 8 families x 9 masks = 72
    cell = StubCell(cell_id="too-broad", boundary=boundary)
    index = BoundaryIndex()

    with pytest.raises(ContractError, match="over the cap"):
        boundary.keys()
    with pytest.raises(ContractError, match="over the cap"):
        index.insert(cell)

    # A refused insert must leave nothing behind; a half-indexed cell would
    # answer in part of its region and miss in the rest.
    assert len(index) == 0
    assert index.key_count() == 0


# --- BoundaryIndex: refusal, not eviction ------------------------------------


def _cell(cell_id: str, masks: int, *, family: RelationFamily, epochs: frozenset[int] | None = None) -> StubCell:
    predicates = tuple(
        StubPredicate(
            role="ACTOR",
            required_properties=frozenset({BOUNDARY_PROPERTY_ORDER[i]}),
            relation_family=family,
        )
        for i in range(masks)
    )
    return StubCell(
        cell_id=cell_id,
        boundary=_boundary(predicates=predicates, epochs=epochs or frozenset({0})),
    )


def test_full_index_raises_and_keeps_every_key_it_already_promised() -> None:
    """The invariant-weakening test: an LRU here would silently drop coverage."""
    index = BoundaryIndex(max_keys=4)
    first = _cell("cell-a", 4, family=RelationFamily.NETWORK)
    index.insert(first)
    assert index.key_count() == 4

    second = _cell("cell-b", 4, family=RelationFamily.FILESYSTEM)
    with pytest.raises(BoundaryIndexFull, match="does not evict"):
        index.insert(second)

    # Nothing was evicted to make room, and the incumbent still answers.
    assert index.cell_ids() == ("cell-a",)
    assert index.key_count() == 4
    assert index.keys_for("cell-a") == first.boundary.keys()
    hit = _frame(
        relation_family=RelationFamily.NETWORK,
        actor_properties=boundary_property_mask(set(BOUNDARY_PROPERTY_ORDER[:4])),
    )
    assert index.lookup(hit) is first


def test_index_refuses_an_insert_that_would_breach_the_byte_ceiling() -> None:
    index = BoundaryIndex(max_bytes=1)
    with pytest.raises(BoundaryIndexFull, match="bytes"):
        index.insert(_cell("cell-a", 1, family=RelationFamily.NETWORK))
    assert len(index) == 0


def test_reinserting_a_cell_id_is_refused_rather_than_silently_replaced() -> None:
    index = BoundaryIndex()
    index.insert(_cell("cell-a", 1, family=RelationFamily.NETWORK))
    with pytest.raises(ContractError, match="already indexed"):
        index.insert(_cell("cell-a", 2, family=RelationFamily.NETWORK))


def test_remove_releases_keys_and_is_idempotent() -> None:
    index = BoundaryIndex()
    index.insert(_cell("cell-a", 3, family=RelationFamily.NETWORK))
    assert index.remove("cell-a") == 3
    assert index.remove("cell-a") == 0
    assert index.key_count() == 0
    assert len(index) == 0


def test_declared_caps_are_the_spec_caps() -> None:
    assert MAX_INDEX_KEYS == 8192
    assert MAX_KEYS_PER_CELL == 64
    assert MAX_PRESSURE_BUDGET == 4096


# --- lookup: no nearest match, no arbitrary winner ---------------------------


def test_lookup_returns_none_off_the_boundary_and_never_a_nearest_match() -> None:
    index = BoundaryIndex()
    cell = _cell("cell-a", 1, family=RelationFamily.NETWORK)
    index.insert(cell)

    off = _frame(
        relation_family=RelationFamily.NETWORK,
        actor_properties=boundary_property_mask({BOUNDARY_PROPERTY_ORDER[0]}),
        epoch_id=7,  # one clause outside
    )
    assert index.lookup(off) is None
    assert index.lookup_all(off) == ()
    # It is near, and near is reported as near — not served as a hit.
    assert index.near_boundary(off) == (cell,)


def test_lookup_abstains_when_two_cells_claim_the_same_frame() -> None:
    index = BoundaryIndex()
    a = _cell("cell-a", 1, family=RelationFamily.NETWORK)
    b = StubCell(
        cell_id="cell-b",
        boundary=_boundary(
            predicates=(
                StubPredicate(role="ACTOR", relation_family=RelationFamily.NETWORK),
            )
        ),
    )
    index.insert(a)
    index.insert(b)
    frame = _frame(
        relation_family=RelationFamily.NETWORK,
        actor_properties=boundary_property_mask({BOUNDARY_PROPERTY_ORDER[0]}),
    )
    assert len(index.lookup_all(frame)) == 2
    assert index.lookup(frame) is None


def test_near_boundary_finds_a_cell_exactly_one_clause_outside_and_excludes_hits() -> None:
    index = BoundaryIndex()
    cell = _cell("cell-a", 1, family=RelationFamily.NETWORK)
    index.insert(cell)
    inside = _frame(
        relation_family=RelationFamily.NETWORK,
        actor_properties=boundary_property_mask({BOUNDARY_PROPERTY_ORDER[0]}),
    )
    one_out = _frame(
        relation_family=RelationFamily.NETWORK,
        actor_properties=boundary_property_mask({BOUNDARY_PROPERTY_ORDER[0]}),
        uncertainty=0.9,
    )
    two_out = _frame(
        relation_family=RelationFamily.FILESYSTEM,
        actor_properties=boundary_property_mask({BOUNDARY_PROPERTY_ORDER[0]}),
        uncertainty=0.9,
    )

    assert index.lookup(inside) is cell
    assert index.near_boundary(inside) == ()  # a hit is not "near"
    assert index.near_boundary(one_out) == (cell,)
    assert index.near_boundary(two_out) == ()
    assert index.near_boundary(two_out, within=2) == (cell,)
    with pytest.raises(ContractError):
        index.near_boundary(one_out, within=0)


def test_near_boundary_sees_a_frame_outside_the_lookup_bucket() -> None:
    """A wrong-family frame is exactly the case a bucketed scan would miss."""
    index = BoundaryIndex()
    cell = _cell("cell-a", 1, family=RelationFamily.NETWORK)
    index.insert(cell)
    wrong_family = _frame(
        relation_family=RelationFamily.PACKAGING,
        actor_properties=boundary_property_mask({BOUNDARY_PROPERTY_ORDER[0]}),
    )
    assert index.lookup(wrong_family) is None
    assert index.near_boundary(wrong_family) == (cell,)


def test_memory_bytes_grows_with_content_and_shrinks_on_remove() -> None:
    index = BoundaryIndex()
    empty = index.memory_bytes()
    index.insert(_cell("cell-a", 4, family=RelationFamily.NETWORK))
    loaded = index.memory_bytes()
    assert loaded > empty
    index.remove("cell-a")
    assert index.memory_bytes() < loaded


def test_property_order_disagreement_is_refused_not_reconciled() -> None:
    check_property_order(BOUNDARY_PROPERTY_ORDER)  # the agreeing case is silent
    with pytest.raises(ContractError, match="reinterpreted"):
        check_property_order(tuple(reversed(BOUNDARY_PROPERTY_ORDER)))


# --- Boundary Pressure -------------------------------------------------------


class _EpochAndBitOracle:
    """Fails inside the boundary on a semantic bit, and outside it on deep epochs.

    Two independent failure modes on purpose, so ``false_inside`` and
    ``false_outside`` cannot both be produced by the same probe.
    """

    def evaluate(self, cell: StubCell, frames: tuple[StubFrame, ...]) -> StubVerdict:
        frame = frames[0]
        if frame.actor_properties & 1:
            return StubVerdict(
                passed=False,
                hard_violations=(StubViolation("q1", "NEVER_LOWER_PHI"),),
            )
        if frame.epoch_id >= 5:
            return StubVerdict(
                passed=False,
                hard_violations=(StubViolation("q2", "STATE_MONOTONE"),),
            )
        return StubVerdict(passed=True)


class _NeedleOracle:
    """Diverges only on a four-axis conjunction, each axis at depth >= 7.

    A smooth gradient leads to it: ``divergence.total`` rises with depth on every
    needle axis, so a search that follows the gradient and *accumulates* across
    axes arrives; a uniform draw has to land all four axes deep in one probe.
    """

    NEEDLE_DEPTH = 7

    def _depths(self, frame: StubFrame) -> tuple[int, int, int, int]:
        timing = max(frame.window_counts.values(), default=0)
        causal = round(frame.delta_phi / 0.25)
        epoch = frame.epoch_id
        evidence = 8 - len(frame.evidence)
        return timing, causal, epoch, evidence

    def evaluate(self, cell: StubCell, frames: tuple[StubFrame, ...]) -> StubVerdict:
        depths = self._depths(frames[0])
        total = float(sum(depths))
        divergence = StubDivergence(d_state_delta=total)
        if all(depth >= self.NEEDLE_DEPTH for depth in depths):
            return StubVerdict(
                passed=False,
                hard_violations=(StubViolation("q3", "NEVER_DOWNGRADE_CONSEQUENCE"),),
                divergence=divergence,
            )
        return StubVerdict(passed=True, divergence=divergence)


def _pressure_cell(epochs: frozenset[int]) -> StubCell:
    return StubCell(cell_id="pressure-cell", boundary=_boundary(epochs=epochs))


def test_perturbation_axes_cover_architecture_section_11_exactly() -> None:
    assert {str(axis) for axis in Perturbation} == {
        "SEMANTIC_DIMENSION",
        "TIMING",
        "CAUSAL_PREDECESSOR",
        "EPOCH",
        "PRIVILEGE",
        "ACTOR_SUBSTITUTION",
        "EVIDENCE_ABLATION",
    }
    assert len(AXIS_ORDER) == 7


def test_perturbation_is_deterministic_and_step_bounded() -> None:
    seed = _frame()
    assert perturbed_frame(seed, Perturbation.EPOCH, 3) == perturbed_frame(
        seed, Perturbation.EPOCH, 3
    )
    assert perturbed_frame(seed, Perturbation.EPOCH, 3).epoch_id == 3
    # Actor substitution keeps the semantic weight and changes the identity.
    rotated = perturbed_frame(seed, Perturbation.ACTOR_SUBSTITUTION, 1)
    assert bin(rotated.actor_properties).count("1") == bin(seed.actor_properties).count("1")
    assert rotated.actor_properties != seed.actor_properties
    # Raising privilege moves Φ with it rather than leaving it stale.
    raised = perturbed_frame(seed, Perturbation.PRIVILEGE, 2)
    assert raised.phi > seed.phi
    for bad in (0, MAX_STEPS_PER_AXIS + 1):
        with pytest.raises(ContractError, match="step"):
            perturbed_frame(seed, Perturbation.EPOCH, bad)


def test_pressure_refuses_an_over_budget_run_and_a_fabricated_start() -> None:
    cell = _pressure_cell(frozenset({0}))
    oracle = _EpochAndBitOracle()
    with pytest.raises(ContractError, match="MAX_PRESSURE_BUDGET"):
        apply_boundary_pressure(
            cell, oracle=oracle, budget=MAX_PRESSURE_BUDGET + 1, seed=1, seeds=(_frame(),)
        )
    with pytest.raises(ContractError, match=">= 1"):
        apply_boundary_pressure(cell, oracle=oracle, budget=0, seed=1, seeds=(_frame(),))
    with pytest.raises(ContractError, match="inside the validated region"):
        apply_boundary_pressure(cell, oracle=oracle, budget=16, seed=1, seeds=())


def test_budget_exhaustion_is_reported_rather_than_concealed() -> None:
    cell = _pressure_cell(frozenset(range(32)))
    oracle = _NeedleOracle()
    seeds = (_frame(),)

    starved = apply_boundary_pressure(cell, oracle=oracle, budget=5, seed=11, seeds=seeds)
    assert starved.probes_run == 5
    assert starved.budget == 5
    assert starved.budget_exhausted is True

    ample = apply_boundary_pressure(cell, oracle=oracle, budget=256, seed=11, seeds=seeds)
    assert ample.probes_run < 256
    assert ample.budget_exhausted is False


def test_false_inside_and_false_outside_are_counted_as_different_errors() -> None:
    """They mean opposite things: a wrong answer served, versus coverage lost."""
    cell = _pressure_cell(frozenset({0}))
    report = apply_boundary_pressure(
        cell,
        oracle=_EpochAndBitOracle(),
        budget=256,
        seed=7,
        seeds=(_frame(actor_properties=0),),
    )
    # Semantic-bit probes stay inside the boundary and diverge: answers the cell
    # would have served with the cheap path's authority.
    assert report.false_inside > 0
    # Epoch probes leave the boundary and agree: coverage the boundary gave up.
    assert report.false_outside > 0
    assert report.false_inside != report.false_outside
    # Divergence one clause outside is tracked on its own, for §40 escalation.
    assert report.near_boundary_errors > 0
    assert report.near_boundary_errors <= len(report.divergences)


def test_guided_and_random_run_at_identical_budget_and_seed_family() -> None:
    cell = _pressure_cell(frozenset(range(32)))
    oracle = _NeedleOracle()
    seeds = (_frame(),)
    guided, control, _ = compare_strategies(
        cell, oracle=oracle, budget=192, seed=4242, seeds=seeds
    )
    assert guided.budget == control.budget == 192
    assert guided.seed == control.seed == 4242
    assert guided.strategy is PressureStrategy.GUIDED
    assert control.strategy is PressureStrategy.RANDOM_REPLAY
    assert guided.probes_run <= 192
    assert control.probes_run == 192  # the control spends every probe it is given


def test_guided_search_finds_a_counterexample_class_random_replay_misses() -> None:
    """G3.4 / falsifier F3, as a controlled test class.

    The needle is a four-axis conjunction at depth >= 7. Guided reaches it by
    following the divergence gradient and carrying each axis's best frame into
    the next axis; equal-budget uniform sampling has to land all four axes deep
    in a single draw.

    This test is written to FAIL, not to be relaxed, if the mechanism stops
    working. Removing the cross-axis accumulation in ``_walk_axes``, or the
    gradient it climbs, empties ``gained`` and this assertion goes red — which
    is the measured verdict ADR-0026 needs, and the architecture gate's own
    wording then applies: *or it is removed*.
    """
    cell = _pressure_cell(frozenset(range(32)))
    oracle = _NeedleOracle()
    seeds = (_frame(),)
    guided, control, gained = compare_strategies(
        cell, oracle=oracle, budget=192, seed=4242, seeds=seeds
    )

    assert gained, (
        "guided Boundary Pressure found no counterexample class that equal-budget "
        "random replay missed; by the architecture acceptance gate the guided "
        "search must then be removed, not weakened"
    )
    assert gained == {"EVIDENCE_ABLATION:NEVER_DOWNGRADE_CONSEQUENCE"}
    assert guided.counterexample_classes >= gained
    assert not (gained & control.counterexample_classes)
    assert guided.divergences, "a gained class with no recorded probe is unreplayable"


def test_random_replay_is_credited_for_every_axis_it_touched() -> None:
    """The comparison must not be won by attribution bookkeeping.

    An oracle that fails on any single-step epoch move is trivially findable by
    random replay; if multi-axis probes were credited to one axis only, random
    would lose classes it genuinely found.
    """

    class _AlwaysFails:
        def evaluate(self, cell: StubCell, frames: tuple[StubFrame, ...]) -> StubVerdict:
            return StubVerdict(passed=False, hard_violations=(StubViolation("q", "K"),))

    cell = _pressure_cell(frozenset(range(32)))
    control = random_replay_control(
        cell, oracle=_AlwaysFails(), budget=64, seed=3, seeds=(_frame(),)
    )
    # Every axis is reachable by a uniform draw, so all seven show up as classes.
    assert control.counterexample_classes == {f"{axis}:K" for axis in AXIS_ORDER}


def test_random_replay_is_not_credited_for_an_axis_it_could_not_move() -> None:
    """Pins S3-02: drawn-but-skipped axes were credited with counterexample classes.

    A seed holding exactly one ``EvidenceRef`` — which is every frame on the real
    corpus — cannot be moved along EVIDENCE_ABLATION at all: ``perturbed_frame``
    returns ``None`` and the loop skips it. Crediting that axis anyway minted
    ``EVIDENCE_ABLATION:*`` classes for frames whose evidence was never touched,
    and those fabricated classes were the entire measured basis for G3.4's
    (now withdrawn) "random replay found a strict superset".
    """

    class _AlwaysFails:
        def evaluate(self, cell: StubCell, frames: tuple[StubFrame, ...]) -> StubVerdict:
            return StubVerdict(passed=False, hard_violations=(StubViolation("q", "K"),))

    cell = _pressure_cell(frozenset(range(32)))
    one_ref = _frame(evidence=_evidence(1))
    assert perturbed_frame(one_ref, Perturbation.EVIDENCE_ABLATION, 1) is None

    control = random_replay_control(
        cell, oracle=_AlwaysFails(), budget=256, seed=11, seeds=(one_ref,)
    )

    assert f"{Perturbation.EVIDENCE_ABLATION}:K" not in control.counterexample_classes
    assert control.probes_on(Perturbation.EVIDENCE_ABLATION) == 0
    # The other six axes are all movable and must still be credited.
    assert control.counterexample_classes == {
        f"{axis}:K" for axis in AXIS_ORDER if axis is not Perturbation.EVIDENCE_ABLATION
    }
    # The unmovable draws still cost budget; that is reported, not concealed.
    assert control.probes_run == 256


def test_a_silent_teacher_is_not_counted_as_a_boundary_quality_error() -> None:
    """Pins S3-03: snapshot key misses were reported as missed detections.

    Oracle A is an exact-digest snapshot of corpus frames and every perturbed
    frame misses it, so a well-bounded cell could report ``false_inside`` equal to
    its whole probe count. ``false_inside`` is documented as a frame the boundary
    claims to contain on which the oracle *diverges*; a teacher with no entry has
    not diverged, and at weight 0.25 that count feeds the melt decision.
    """

    class _NoTeacher:
        def evaluate(self, cell: StubCell, frames: tuple[StubFrame, ...]) -> StubVerdict:
            return StubVerdict(passed=False, teacher_available=False)

    cell = _pressure_cell(frozenset(range(32)))
    report = apply_boundary_pressure(
        cell, oracle=_NoTeacher(), budget=32, seed=2, seeds=(_frame(),)
    )

    assert report.probes_run > 0
    assert report.unmeasured_probes == report.probes_run
    assert report.false_inside == 0
    assert report.false_outside == 0
    assert report.near_boundary_errors == 0
    # The divergences themselves are still recorded — they are UNKNOWN, not absent.
    assert len(report.divergences) == report.probes_run


def test_a_hard_violation_counts_even_with_no_teacher() -> None:
    """The S3-03 fix must not exempt a cell the security spec caught.

    A hard constraint is the cell being wrong whatever the teacher says, so it is
    a measured boundary-quality error even when the snapshot is silent.
    """

    class _ViolatesInside:
        def evaluate(self, cell: StubCell, frames: tuple[StubFrame, ...]) -> StubVerdict:
            return StubVerdict(
                passed=False,
                teacher_available=False,
                hard_violations=(StubViolation("q", "NEVER_LOWER_PHI"),),
            )

    cell = _pressure_cell(frozenset(range(32)))
    report = apply_boundary_pressure(
        cell, oracle=_ViolatesInside(), budget=16, seed=2, seeds=(_frame(actor_properties=0),)
    )

    assert report.unmeasured_probes == 0
    assert report.false_inside > 0


def test_per_axis_probe_counts_are_recorded_for_every_axis_walked() -> None:
    """Pins S3-05/S3-07: a per-axis metric had no per-axis denominator.

    ``_substitution_consistency`` divided ACTOR_SUBSTITUTION divergences by
    ``probes_run`` — the total over all seven axes — because the report carried no
    per-axis count. It now does.
    """

    class _AlwaysFails:
        def evaluate(self, cell: StubCell, frames: tuple[StubFrame, ...]) -> StubVerdict:
            return StubVerdict(passed=False, hard_violations=(StubViolation("q", "K"),))

    cell = _pressure_cell(frozenset(range(32)))
    report = apply_boundary_pressure(
        cell, oracle=_AlwaysFails(), budget=64, seed=5, seeds=(_frame(),)
    )

    assert sum(count for _axis, count in report.probes_by_axis) == report.probes_run
    for axis in AXIS_ORDER:
        assert report.divergences_on(axis) <= report.probes_on(axis)
    assert report.probes_on(Perturbation.ACTOR_SUBSTITUTION) >= 1


def test_counterexample_classes_collapse_repeats_of_the_same_failure() -> None:
    """Classes, not frames: a strategy must not win by generating more probes."""

    class _AlwaysFails:
        def evaluate(self, cell: StubCell, frames: tuple[StubFrame, ...]) -> StubVerdict:
            return StubVerdict(passed=False, hard_violations=(StubViolation("q", "K"),))

    cell = _pressure_cell(frozenset(range(32)))
    report = apply_boundary_pressure(
        cell, oracle=_AlwaysFails(), budget=128, seed=5, seeds=(_frame(), _frame(epoch_id=1))
    )
    assert len(report.divergences) > len(report.counterexample_classes)
    assert len(report.counterexample_classes) <= len(AXIS_ORDER)


def test_an_unavailable_teacher_is_classified_as_unmeasured_not_as_agreement() -> None:
    class _NoTeacher:
        def evaluate(self, cell: StubCell, frames: tuple[StubFrame, ...]) -> StubVerdict:
            return StubVerdict(passed=False, teacher_available=False)

    cell = _pressure_cell(frozenset(range(32)))
    report = apply_boundary_pressure(
        cell, oracle=_NoTeacher(), budget=16, seed=2, seeds=(_frame(),)
    )
    assert all(cls.endswith(":TEACHER_UNAVAILABLE") for cls in report.counterexample_classes)


def test_report_serialises_every_field_the_gate_reads() -> None:
    cell = _pressure_cell(frozenset(range(32)))
    report = apply_boundary_pressure(
        cell, oracle=_NeedleOracle(), budget=128, seed=9, seeds=(_frame(),)
    )
    assert isinstance(report, BoundaryPressureReport)
    payload = report.to_dict()
    assert set(payload) == {
        "strategy",
        "seed",
        "probes_run",
        "budget",
        "budget_exhausted",
        "divergence_count",
        "counterexample_classes",
        "false_inside",
        "false_outside",
        "near_boundary_errors",
        "probes_by_axis",
        "divergences_by_axis",
        "unmeasured_probes",
    }
    assert payload["strategy"] == "GUIDED"
    assert payload["counterexample_classes"] == sorted(report.counterexample_classes)
