"""Behaviour and failure paths for the Stage 3 ``synthesis`` package.

These tests exist to make three claims falsifiable rather than asserted:

1. **Every bound actually bounds.** Each synthesiser is handed a region that
   does not fit and must return ``None``, and is handed a widened cap and must
   raise. A synthesiser that quietly grew would pass a "does it produce a
   program" test and fail these.
2. **UNMEASURED is never cheap.** The selector must refuse an unmeasured
   candidate even when it is the only one, and must refuse a violating
   candidate *before* cost is consulted — proven by making the violating
   candidate the cheapest one on the board.
3. **Refusals leave a trace.** ``crystallize`` must record a counterexample for
   every non-``PROMOTED`` outcome and must never promote.

``test_selector_refuses_violation_before_cost`` and
``test_crystallize_never_touches_the_field`` are the two that would fail if
someone silently weakened the invariant: the first orders the candidates so a
cost-first selector returns the violating one, and the second replaces the
field's mutators with tripwires.
"""

from __future__ import annotations

import pytest

from pocketsec.stage0.contracts.common import ContractError, EvidenceRef, digest_of_bytes
from pocketsec.stage1.labs.corpus import ATTACK_EXFIL, Scenario, build_corpus
from pocketsec.stage1.pipeline import ScenarioResult, Stage1Pipeline
from pocketsec.stage1.ssir.relations import RelationFamily
from pocketsec.stage1.state.security_state import (
    Privilege,
    SecurityStateV1,
    StateDelta,
)
from pocketsec.stage3.boundary.index import CellBoundary
from pocketsec.stage3.bytecode.verifier import verify
from pocketsec.stage3.bytecode.vm import CellResult
from pocketsec.stage3.cells.frame import CellFrame
from pocketsec.stage3.cells.field import MAX_CELLS, KnowledgeField
from pocketsec.stage3.cells.fission import MAX_FISSION_DEPTH, fission_cell
from pocketsec.stage3.cells.fusion import FUSED_PARENT_PREFIX, fuse_cells, fusion_refusal
from pocketsec.stage3.cells.invariant import (
    ConsequentSpec,
    Invariant,
    PredicateRole,
    SemanticPredicate,
)
from pocketsec.stage3.cells.operator import OperatorForm, OperatorProgram
from pocketsec.stage3.cells.schema import (
    AssuranceLevel,
    AuditPolicy,
    CellPhase,
    ConstraintKind,
    HardConstraint,
    KnowledgeCellV1,
)
from pocketsec.stage3.crystal.pipeline import (
    MAX_PRESSURE_BUDGET,
    CrystalConfig,
    CrystalOutcome,
    RegionSample,
    crystallize,
)
from pocketsec.stage3.melting.stress import open_counterexamples
from pocketsec.stage3.oracles.counterexamples import Counterexample, CounterexampleStore
from pocketsec.stage3.oracles.dual_oracle import (
    DualOracleVerdict,
    SecurityDivergence,
)
from pocketsec.stage3.oracles.security_specs import Violation
from pocketsec.stage3.oracles.teacher import TeacherOracle, TeacherSnapshotV1, frame_digest
from pocketsec.stage3.synthesis.operators import (
    MAX_DAG_NODES,
    MAX_FSM_STATES,
    MAX_LINEAR_TERMS,
    MAX_SYNTH_INSTRUCTIONS,
    MAX_TABLE_ENTRIES,
    SYNTHESISERS,
    OperatorSample,
    synthesize_bitset_predicate,
    synthesize_bytecode,
    synthesize_constant,
    synthesize_decision_dag,
    synthesize_fsm_fragment,
    synthesize_linear_expression,
    synthesize_lookup_table,
    synthesize_weighted_transition,
)
from pocketsec.stage3.synthesis.selector import (
    OperatorCandidate,
    measure_candidate,
    pareto_frontier,
    select_operator_form,
)
from pocketsec.stage3.theory import ResolutionState, SecurityConsequence

# --- fixtures ----------------------------------------------------------------


def evidence(tag: str) -> EvidenceRef:
    return EvidenceRef(store="test", locator=f"ev-{tag}", digest=digest_of_bytes(tag.encode()))


def frame(
    *,
    actor: int = 0b0011,
    obj: int = 0b0001,
    family: RelationFamily = RelationFamily.EXECUTION,
    phi: float = 1.0,
    delta_phi: float = 0.0,
    uncertainty: float = 0.1,
    epoch: int = 0,
    raised: dict[str, tuple[int, int]] | None = None,
) -> CellFrame:
    state = SecurityStateV1(privilege=Privilege.USER)
    return CellFrame(
        state=state,
        delta=StateDelta(raised=raised or {}),
        actor_properties=actor,
        object_properties=obj,
        relation_family=family,
        phi=phi,
        delta_phi=delta_phi,
        uncertainty=uncertainty,
        epoch_id=epoch,
        window_counts={0: 1},
        # Two refs, not one: boundary pressure's EVIDENCE_ABLATION axis drops
        # the last ref, and cells.frame.CellFrame refuses a frame with none.
        evidence=(evidence("a"), evidence("b")),
        encoder_version="test.1",
    )


def sample(risk: float, **kwargs: object) -> OperatorSample:
    raised = kwargs.pop("raised", None)
    return OperatorSample(
        frame=frame(raised=raised, **kwargs),  # type: ignore[arg-type]
        risk=risk,
        delta=StateDelta(raised=raised or {}),
    )


def predicate() -> SemanticPredicate:
    return SemanticPredicate(
        role=PredicateRole.ACTOR,
        required_properties=frozenset(),
        forbidden_properties=frozenset(),
        relation_family=RelationFamily.EXECUTION,
        entity_kind=None,
    )


def invariant(name: str = "inv-1", epochs: frozenset[int] = frozenset({0})) -> Invariant:
    return Invariant(
        invariant_id=name,
        antecedent=(predicate(),),
        consequent=ConsequentSpec(
            required_dimensions=frozenset({"privilege"}),
            min_delta_phi=0.0,
            required_evidence_kinds=frozenset({"observation"}),
            consequence=SecurityConsequence.ELEVATED,
        ),
        support=4,
        contradictions=0,
        identities_collapsed=2,
        epochs=epochs,
        falsifier="a privileged spawn that does not raise privilege",
        evidence=(evidence("b"),),
    )


def boundary(
    *,
    dimensions: frozenset[str] = frozenset({"privilege", "credential"}),
    epochs: frozenset[int] = frozenset({0}),
) -> CellBoundary:
    return CellBoundary(
        predicates=(predicate(),),
        state_dimensions=dimensions,
        phi_range=(0.0, 4.0),
        max_uncertainty=0.5,
        epochs=epochs,
        forbidden_combinations=(),
    )


def program(risk: float = 0.5) -> OperatorProgram:
    produced = synthesize_constant([sample(risk), sample(risk)])
    assert produced is not None
    return produced


def cell(
    cell_id: str = "cell-1",
    *,
    dimensions: frozenset[str] = frozenset({"privilege", "credential"}),
    epochs: frozenset[int] = frozenset({0}),
    operator: OperatorProgram | None = None,
    consequence: SecurityConsequence = SecurityConsequence.ELEVATED,
) -> KnowledgeCellV1:
    spec = ConsequentSpec(
        required_dimensions=frozenset({"privilege"}),
        min_delta_phi=0.0,
        required_evidence_kinds=frozenset({"observation"}),
        consequence=consequence,
    )
    return KnowledgeCellV1(
        cell_id=cell_id,
        invariant=Invariant(
            invariant_id=f"inv-{cell_id}",
            antecedent=(predicate(),),
            consequent=spec,
            support=4,
            contradictions=0,
            identities_collapsed=2,
            epochs=epochs,
            falsifier="a privileged spawn that does not raise privilege",
            evidence=(evidence("b"),),
        ),
        boundary=boundary(dimensions=dimensions, epochs=epochs),
        operator=operator or program(),
        resolution=ResolutionState(
            predictive_stability=0.9, calibrated_uncertainty=0.1, validated_breadth=4,
            counterfactual_consistency=0.9, evidence_agreement=1.0, drift_stability=2,
            measured_by="tests:cell",
        ),
        confidence=0.8,
        assurance=AssuranceLevel.A3,
        phase=CellPhase.CRYSTALLIZED,
        evidence_lineage=(evidence("c"),),
        constraints=(
            HardConstraint(
                constraint_id="Q1",
                kind=ConstraintKind.NEVER_LOWER_PHI,
                detail="phi is monotone under a cell result",
            ),
        ),
        epochs=epochs,
        audit_policy=AuditPolicy(
            base_rate=0.05, min_rate=0.001, max_rate=1.0, jitter_salt="salt"
        ),
        version=1,
        parent_cell_id=None,
        source_candidate_id=None,
    )


def verdict(
    *, violations: tuple[Violation, ...] = (), divergence: float | None = 0.0
) -> DualOracleVerdict:
    return DualOracleVerdict(
        passed=not violations and divergence is not None,
        teacher_available=True,
        teacher_divergence=divergence,
        envelope=0.05,
        divergence=SecurityDivergence(
            d_state_delta=0.0,
            d_security_potential=divergence if divergence is not None else 0.0,
            d_uncertainty=0.0,
            d_evidence_requirement=0.0,
            d_causal_attribution=0.0,
        ),
        hard_violations=violations,
        consequence=SecurityConsequence.ELEVATED,
        reason="test",
    )


_SESSION: ScenarioResult = Stage1Pipeline().run_scenario(Scenario("attack", ATTACK_EXFIL, 1))


def _corpus() -> tuple[ScenarioResult, ...]:
    """A real Stage 1 replay, because invariant discovery counts distinct lineages.

    One scenario has one lineage and clears no support threshold, so a corpus of
    one would make every ``crystallize`` test short-circuit at DiscoverInvariant
    and quietly test nothing past it.
    """
    pipeline = Stage1Pipeline()
    return tuple(
        pipeline.run_scenario(scenario, offset=index)
        for index, scenario in enumerate(build_corpus(count=24, seed=7, split="train"))
    )


_CORPUS: tuple[ScenarioResult, ...] = _corpus()


def counterexample(
    *, epoch: int = 0, dims: tuple[str, ...] = ("credential",), cell_id: str = "cell-1"
) -> Counterexample:
    raised = {name: (0, 1) for name in dims}
    result = CellResult(
        abstained=False,
        delta=StateDelta(raised=raised),
        evidence=(evidence("d"),),
        risk=0.9,
        escalation=None,
        steps_taken=1,
        reason="observed",
    )
    return Counterexample(
        counterexample_id=f"cx-{epoch}-{'.'.join(dims)}",
        cell_candidate_id=cell_id,
        transitions=_SESSION.transitions[:2],
        state=SecurityStateV1(),
        epoch_id=epoch,
        expected=CellResult(
            abstained=False,
            delta=StateDelta(raised={}),
            evidence=(evidence("d"),),
            risk=0.1,
            escalation=None,
            steps_taken=1,
            reason="expected",
        ),
        observed=result,
        divergence_type="RISK",
        evidence=(evidence("d"),),
        incident_linked=False,
        superseded_by=None,
    )


# --- D3.7 synthesisers: bounds actually bound --------------------------------


def test_every_operator_form_has_a_synthesiser() -> None:
    assert {form for form, _ in SYNTHESISERS} == set(OperatorForm)


def test_constant_refuses_a_region_that_disagrees() -> None:
    assert synthesize_constant([sample(0.1), sample(0.9)]) is None
    assert synthesize_constant([]) is None


def test_lookup_table_refuses_beyond_max_entries() -> None:
    samples = [sample(float(i) / 100.0, actor=i) for i in range(12)]
    assert synthesize_lookup_table(samples, max_entries=11) is None
    assert synthesize_lookup_table(samples, max_entries=64) is not None


def test_lookup_table_refuses_a_key_that_is_not_a_function() -> None:
    # Same quantised key, two different risks: averaging would be cheap and wrong.
    assert synthesize_lookup_table([sample(0.1), sample(0.9)]) is None


def test_widening_a_hard_cap_is_a_contract_error_not_a_bigger_table() -> None:
    with pytest.raises(ContractError):
        synthesize_lookup_table([sample(0.1)], max_entries=MAX_TABLE_ENTRIES + 1)
    with pytest.raises(ContractError):
        synthesize_decision_dag([sample(0.1)], max_nodes=MAX_DAG_NODES + 1)
    with pytest.raises(ContractError):
        synthesize_fsm_fragment([sample(0.1)], max_states=MAX_FSM_STATES + 1)
    with pytest.raises(ContractError):
        synthesize_weighted_transition([sample(0.1)], max_states=MAX_FSM_STATES + 1)
    with pytest.raises(ContractError):
        synthesize_linear_expression([sample(0.1)], max_terms=MAX_LINEAR_TERMS + 1)
    with pytest.raises(ContractError):
        synthesize_bytecode([sample(0.1)], max_instructions=MAX_SYNTH_INSTRUCTIONS + 1)


def test_bitset_predicate_separates_two_risks_and_refuses_three() -> None:
    hot = [sample(0.9, actor=0b0101) for _ in range(2)]
    cold = [sample(0.1, actor=0b0010) for _ in range(2)]
    found = synthesize_bitset_predicate([*hot, *cold])
    assert found is not None and found.form is OperatorForm.BITSET_PREDICATE
    assert synthesize_bitset_predicate([sample(0.1), sample(0.5), sample(0.9)]) is None


def test_decision_dag_refuses_rather_than_emitting_an_impure_leaf() -> None:
    # Two samples that are identical on every feature but carry different risks
    # cannot be separated at any depth; a majority-vote leaf would be a lie.
    assert synthesize_decision_dag([sample(0.1), sample(0.9)], max_depth=4) is None


def test_decision_dag_fits_a_separable_region_within_its_node_bound() -> None:
    rows = [sample(0.9, phi=3.0), sample(0.9, phi=3.5), sample(0.1, phi=0.5)]
    found = synthesize_decision_dag(rows, max_depth=2, max_nodes=7)
    assert found is not None
    assert found.table["nodes"] <= 7


def test_fsm_fragment_refuses_more_states_than_its_bound() -> None:
    rows = [
        sample(0.5, raised={name: (0, 1)})
        for name in ("privilege", "trust", "credential", "reachability", "persistence")
    ]
    assert synthesize_fsm_fragment(rows, max_states=3) is None


def test_weighted_transition_tolerates_non_determinism_but_not_overflow() -> None:
    rows = [sample(0.5, raised={"privilege": (0, 1)}) for _ in range(4)]
    assert synthesize_weighted_transition(rows, max_states=2) is not None
    wide = [
        sample(0.5, raised={name: (0, 1)})
        for name in ("privilege", "trust", "credential", "reachability")
    ]
    assert synthesize_weighted_transition(wide, max_states=2) is None


def test_linear_expression_refuses_when_it_cannot_reproduce_the_region() -> None:
    rows = [sample(0.1 * i, phi=float(i)) for i in range(10)]
    assert synthesize_linear_expression(rows, max_terms=2) is not None
    noisy = [*rows, sample(99.0, phi=2.0)]
    assert synthesize_linear_expression(noisy, max_terms=2) is None


def test_linear_expression_refuses_an_underdetermined_system() -> None:
    assert synthesize_linear_expression([sample(0.5), sample(0.5)], max_terms=6) is None


def test_synthesize_bytecode_only_ever_returns_verified_programs() -> None:
    rows = [sample(0.0), sample(0.0), sample(0.0)]
    produced = synthesize_bytecode(rows, max_instructions=3, node_budget=20_000)
    assert produced is None or verify(produced).ok


def test_synthesize_bytecode_refuses_when_the_node_budget_is_exhausted() -> None:
    rows = [sample(0.37, phi=1.0), sample(0.91, phi=9.0)]
    assert synthesize_bytecode(rows, max_instructions=6, node_budget=50) is None


# --- D3.7 selector: UNMEASURED is not cheap ----------------------------------


def candidate(
    *,
    micros: float | None,
    size: int = 100,
    violations: tuple[Violation, ...] = (),
    risk: float = 0.5,
) -> OperatorCandidate:
    return OperatorCandidate(
        program=program(risk=risk),
        microseconds_per_event=micros,
        bytes_resident=size,
        equivalence=verdict(violations=violations),
        loadavg_at_measurement=1.0,
    )


def test_unmeasured_candidate_is_never_selected() -> None:
    only = candidate(micros=None)
    assert select_operator_form([only], constraints=()) is None
    measured = candidate(micros=50.0, risk=0.6)
    assert select_operator_form([only, measured], constraints=()) is measured


def test_selector_refuses_violation_before_cost() -> None:
    """The violating candidate is the cheapest. A cost-first selector fails here."""
    violation = Violation(
        constraint_id="Q1",
        kind=ConstraintKind.NEVER_LOWER_PHI,
        detail="lowered phi",
        frame_digest=digest_of_bytes(b"frame"),
    )
    cheap_and_illegal = candidate(micros=0.001, size=1, violations=(violation,), risk=0.2)
    expensive_and_legal = candidate(micros=500.0, size=9000, risk=0.7)
    chosen = select_operator_form(
        [cheap_and_illegal, expensive_and_legal],
        constraints=(
            HardConstraint(
                constraint_id="Q1", kind=ConstraintKind.NEVER_LOWER_PHI, detail="phi monotone"
            ),
        ),
    )
    assert chosen is expensive_and_legal


def test_selector_returns_none_when_every_candidate_violates() -> None:
    violation = Violation(
        constraint_id="Q1",
        kind=ConstraintKind.NEVER_LOWER_PHI,
        detail="lowered phi",
        frame_digest=digest_of_bytes(b"frame"),
    )
    illegal = candidate(micros=0.1, violations=(violation,))
    assert select_operator_form([illegal], constraints=()) is None


def test_measure_candidate_records_load_and_refuses_to_time_nothing() -> None:
    measured = measure_candidate(program(), [], equivalence=verdict(), repetitions=3)
    assert measured.microseconds_per_event is None  # empty frame set is UNMEASURED, not fast
    assert measured.loadavg_at_measurement >= 0.0
    with pytest.raises(ValueError):
        measure_candidate(program(), [frame()], equivalence=verdict(), repetitions=0)


def test_a_form_the_vm_will_not_execute_is_unmeasured_not_cheap() -> None:
    """CellVM executes BYTECODE only; timing a table measures a refusal."""
    table = measure_candidate(program(), [frame(), frame()], equivalence=verdict())
    assert table.program.form is OperatorForm.CONSTANT
    assert table.microseconds_per_event is None
    assert select_operator_form([table], constraints=()) is None


def test_an_executable_program_is_actually_timed() -> None:
    rows = [sample(0.0), sample(0.0), sample(0.0)]
    executable = synthesize_bytecode(rows, max_instructions=3, node_budget=20_000)
    if executable is None:
        pytest.fail("the bounded enumerator found no executable program to time")
    timed = measure_candidate(executable, [frame(), frame()], equivalence=verdict())
    assert timed.microseconds_per_event is not None and timed.microseconds_per_event > 0.0


def test_pareto_frontier_excludes_unmeasured_and_dominated() -> None:
    fast_small = candidate(micros=1.0, size=10, risk=0.11)
    slow_big = candidate(micros=9.0, size=900, risk=0.22)
    slow_small = candidate(micros=9.0, size=5, risk=0.33)
    unmeasured = candidate(micros=None, size=1, risk=0.44)
    front = pareto_frontier([fast_small, slow_big, slow_small, unmeasured])
    assert fast_small in front and slow_small in front
    assert slow_big not in front and unmeasured not in front


# --- D3.10 fission -----------------------------------------------------------


def test_fission_splits_only_the_heterogeneous_region() -> None:
    field = KnowledgeField()
    target = cell(dimensions=frozenset({"privilege", "credential"}))
    outcome = fission_cell(target, [counterexample(dims=("credential",))], depth=0, field=field)
    assert outcome.stable is not None
    stable = outcome.stable.boundary
    assert stable.state_dimensions == frozenset({"privilege"})
    # Everything except the split dimension is untouched. A fission that moved
    # these would be re-synthesis under another name.
    assert stable.predicates == target.boundary.predicates
    assert stable.phi_range == target.boundary.phi_range
    assert stable.max_uncertainty == target.boundary.max_uncertainty
    assert stable.epochs == target.boundary.epochs
    assert outcome.ambiguous is not None
    assert outcome.ambiguous.state_dimensions == frozenset({"credential"})
    assert outcome.stable.parent_cell_id == target.cell_id


def test_fission_refuses_at_max_depth() -> None:
    field = KnowledgeField()
    outcome = fission_cell(cell(), [counterexample()], depth=MAX_FISSION_DEPTH, field=field)
    assert outcome.stable is None
    assert "MAX_FISSION_DEPTH" in outcome.reason


def test_fission_refuses_when_it_would_exceed_max_cells() -> None:
    """The mechanical cap on the §39 knowledge-explosion threat."""
    field = KnowledgeField()
    for index in range(MAX_CELLS):
        field.insert(cell(f"cell-{index:04d}"))
    outcome = fission_cell(cell("cell-x"), [counterexample()], depth=0, field=field)
    assert outcome.stable is None
    assert "MAX_CELLS" in outcome.reason


def test_fission_refuses_when_no_stable_domain_survives() -> None:
    field = KnowledgeField()
    target = cell(dimensions=frozenset({"credential"}))
    outcome = fission_cell(target, [counterexample(dims=("credential",))], depth=0, field=field)
    assert outcome.stable is None
    assert "NO_STABLE_DOMAIN" in outcome.reason


def test_fission_refuses_a_split_that_would_only_copy_the_cell() -> None:
    """No heterogeneous region means no split: a copy is growth without knowledge."""
    field = KnowledgeField()
    target = cell(dimensions=frozenset({"privilege", "credential"}))
    # The counterexample disagrees about a dimension outside the boundary.
    outcome = fission_cell(target, [counterexample(dims=("reachability",))], depth=0, field=field)
    assert outcome.stable is None
    assert "NO_HETEROGENEOUS_REGION" in outcome.reason


def test_fission_marks_out_of_epoch_counterexamples_invalid() -> None:
    field = KnowledgeField()
    target = cell(epochs=frozenset({0}))
    outcome = fission_cell(
        target, [counterexample(epoch=7, dims=("credential",))], depth=0, field=field
    )
    assert outcome.invalid is not None
    assert outcome.invalid.epochs == frozenset({7})


# --- D3.10 fusion ------------------------------------------------------------


def test_fusion_refuses_across_incompatible_epochs() -> None:
    left = cell("cell-a", epochs=frozenset({0}))
    right = cell("cell-b", epochs=frozenset({5}))
    assert fuse_cells(left, right) is None
    assert "INCOMPATIBLE_EPOCHS" in fusion_refusal(left, right)


def test_fusion_refuses_divergent_security_futures() -> None:
    left = cell("cell-a")
    right = cell("cell-b", consequence=SecurityConsequence.CRITICAL)
    assert fuse_cells(left, right) is None
    assert "SECURITY_FUTURE_DIVERGES" in fusion_refusal(left, right)


def test_fusion_refuses_different_operators() -> None:
    left = cell("cell-a")
    right = cell("cell-b", operator=program(risk=0.9))
    assert fuse_cells(left, right) is None
    assert "OPERATOR_MISMATCH" in fusion_refusal(left, right)


def test_fused_cell_reenters_shadow_at_a0_and_names_both_parents() -> None:
    left = cell("cell-a", dimensions=frozenset({"privilege"}))
    right = cell("cell-b", dimensions=frozenset({"credential"}))
    fused = fuse_cells(left, right)
    assert fused is not None
    assert fused.assurance is AssuranceLevel.A0
    assert fused.phase is not CellPhase.CRYSTALLIZED
    assert fused.parent_cell_id is not None
    assert fused.parent_cell_id.startswith(FUSED_PARENT_PREFIX)
    assert "cell-a" in fused.parent_cell_id and "cell-b" in fused.parent_cell_id
    assert fused.boundary.state_dimensions == frozenset({"privilege", "credential"})
    # The union never loosens a parent's ceiling.
    assert fused.boundary.max_uncertainty <= min(
        left.boundary.max_uncertainty, right.boundary.max_uncertainty
    )
    assert fused.confidence <= min(left.confidence, right.confidence)


def test_fusion_never_manufactures_corroboration() -> None:
    left = cell("cell-a", dimensions=frozenset({"privilege"}))
    right = cell("cell-b", dimensions=frozenset({"credential"}))
    fused = fuse_cells(left, right)
    assert fused is not None
    assert fused.invariant.support == min(left.invariant.support, right.invariant.support)


# --- D3.2 the CRYSTAL loop ---------------------------------------------------


class _TripwireField(KnowledgeField):
    """A field that fails loudly if anything tries to promote into it."""

    def insert(self, cell: KnowledgeCellV1) -> None:
        raise AssertionError("crystallize must never promote")

    def remove(self, cell_id: str) -> bool:
        raise AssertionError("crystallize must never mutate the field")


def region(
    *,
    samples: int = 6,
    sessions: tuple[object, ...] = _CORPUS,
    raised: dict[str, tuple[int, int]] | None = None,
) -> RegionSample:
    """A routine region that actually reaches the pressure loop.

    ``actor=0xFFFF`` so the discovered invariant's antecedent survives the
    region; a frame that violates its own boundary would short-circuit the run
    at InferBoundary and leave everything after it untested.
    """
    delta = StateDelta(raised=raised or {})
    rows = tuple(
        OperatorSample(
            frame=frame(phi=float(index) * 0.1, actor=0xFFFF, raised=raised),
            risk=0.0,
            delta=delta,
        )
        for index in range(samples)
    )
    return RegionSample(
        region_key=(int(RelationFamily.EXECUTION), 0xFFFF, delta.bitmask()),
        samples=rows,
        evidence=(evidence("e"),),
        constraints=(
            HardConstraint(
                constraint_id="Q1", kind=ConstraintKind.NEVER_LOWER_PHI, detail="phi monotone"
            ),
        ),
        epochs=frozenset({0}),
        sessions=sessions,
        transitions=_SESSION.transitions[:3],
    )


def teacher_for(target: RegionSample) -> TeacherOracle:
    return TeacherOracle(
        TeacherSnapshotV1.create(
            teacher_id="t1",
            source="phi-oracle",
            encoder_version="test.1",
            corpus_version="test",
            seed=0,
            responses={frame_digest(s.frame): s.risk for s in target.samples},
            measured_by="tests:teacher_for",
            experiment_id="PS-S3-20260925-H4-synthesis-tests-0001",
        )
    )


def teacher_over_the_lattice(target: RegionSample) -> TeacherOracle:
    """A teacher that also answers for the frames Boundary Pressure will reach.

    ``teacher_for`` covers only the region's own frames, so every perturbed probe
    misses the snapshot and comes back TEACHER_UNAVAILABLE. Since S3-03 those are
    ``unmeasured_probes`` rather than ``false_inside`` / ``near_boundary_errors``,
    which is the honest accounting — and it means a refinement can only be driven
    by a teacher that has an opinion off the corpus. This fixture is that teacher:
    every frame on the bounded perturbation lattice gets the Φ-oracle's own score.
    """
    from pocketsec.stage3.boundary.pressure import (
        AXIS_ORDER,
        MAX_STEPS_PER_AXIS,
        perturbed_frame,
    )
    from pocketsec.stage3.oracles.teacher import phi_oracle_score

    responses = {frame_digest(s.frame): s.risk for s in target.samples}
    for sample in target.samples:
        for axis in AXIS_ORDER:
            for step in range(1, MAX_STEPS_PER_AXIS + 1):
                moved = perturbed_frame(sample.frame, axis, step)
                if moved is None:
                    continue
                responses[frame_digest(moved)] = phi_oracle_score(moved.delta_phi)
    return TeacherOracle(
        TeacherSnapshotV1.create(
            teacher_id="t1-lattice",
            source="phi-oracle",
            encoder_version="test.1",
            corpus_version="test",
            seed=0,
            responses=responses,
            measured_by="tests:teacher_over_the_lattice",
            experiment_id="PS-S3-20260925-H4-synthesis-tests-0001",
        )
    )


def test_crystal_config_defaults_to_the_strategy_adr_0026_retained() -> None:
    """Pins S3-08 (resource-simplicity): the loop hard-coded the removed strategy.

    ADR-0026 (Accepted) says "random_replay_control is the retained strategy" and
    "nothing in the promotion path depends on guided search". The pipeline's only
    pressure call passed ``PressureStrategy.GUIDED`` and ``CrystalConfig`` had no
    way to select anything else, so the ADR recorded a removal no code implemented
    — and the dependency was not cosmetic: the guided report feeds
    ``predictive_stability``, which ``crystallization_allowed`` reads.
    """
    from pocketsec.stage3.boundary.pressure import PressureStrategy

    assert CrystalConfig(seed=0).strategy is PressureStrategy.RANDOM_REPLAY
    assert (
        CrystalConfig(seed=0, strategy=PressureStrategy.GUIDED).strategy
        is PressureStrategy.GUIDED
    )
    with pytest.raises(ContractError):
        CrystalConfig(seed=0, strategy="GUIDED")  # type: ignore[arg-type]


def test_substitution_consistency_is_measured_on_its_own_axis_or_not_at_all() -> None:
    """Pins S3-05 / S3-07 (resource-simplicity).

    ``_substitution_consistency`` divided ACTOR_SUBSTITUTION divergences by
    ``probes_run`` — the total over all seven axes — so a region whose outcome
    depends entirely on which actor acted, with its one actor probe diverging, read
    close to 1.0 instead of 0.0 and cleared the ELEVATED bar. Its early return also
    tested ``probes_run``, so an actor axis that never ran returned exactly the 1.0
    its own docstring called dishonest.
    """
    from pocketsec.stage3.boundary.pressure import BoundaryPressureReport, PressureStrategy
    from pocketsec.stage3.crystal.pipeline import _substitution_consistency

    def _report(**overrides: object) -> BoundaryPressureReport:
        base: dict[str, object] = {
            "strategy": PressureStrategy.GUIDED,
            "seed": 1,
            "probes_run": 64,
            "budget": 64,
            "budget_exhausted": True,
            "divergences": (),
            "counterexample_classes": frozenset(),
            "false_inside": 0,
            "false_outside": 0,
            "near_boundary_errors": 0,
        }
        base.update(overrides)
        return BoundaryPressureReport(**base)  # type: ignore[arg-type]

    # Axis never probed: UNMEASURED, never a number.
    unprobed = _report(probes_by_axis=(("TIMING", 64),))
    assert _substitution_consistency(unprobed) is None
    assert _substitution_consistency(None) is None

    # Probed once and diverged: 0.0, not 1 - 1/64.
    all_bad = _report(
        probes_by_axis=(("ACTOR_SUBSTITUTION", 1), ("TIMING", 63)),
        divergences_by_axis=(("ACTOR_SUBSTITUTION", 1),),
    )
    assert _substitution_consistency(all_bad) == 0.0

    # Axis-local fraction, undiluted by the other six axes.
    mixed = _report(
        probes_by_axis=(("ACTOR_SUBSTITUTION", 8), ("TIMING", 56)),
        divergences_by_axis=(("ACTOR_SUBSTITUTION", 2), ("TIMING", 5)),
    )
    assert _substitution_consistency(mixed) == 0.75


def test_a_run_that_never_perturbed_the_actor_refuses_rather_than_scoring_it() -> None:
    """Pins S3-05's consequence: UNMEASURED must fail, exactly as a None divergence does.

    ACTOR_SUBSTITUTION is sixth of seven in ``AXIS_ORDER``, so a budget-limited
    guided walk routinely never reaches it. The §9 identity-versus-property check
    cannot be reported as satisfied by a run that never perturbed the actor, and a
    number written for it lands in the cell's persisted ``ResolutionState``.
    """
    target = region()
    run = crystallize(
        target,
        config=CrystalConfig(seed=11, pressure_budget=8, max_refinements=0),
        teacher=teacher_over_the_lattice(target),
        field=KnowledgeField(),
        store=CounterexampleStore(cold_archive=None),
    )

    assert run.outcome is not CrystalOutcome.PROMOTED
    if run.resolution is not None:
        # If a resolution was built at all, its actor term must have been measured.
        assert run.pressure is not None
        from pocketsec.stage3.boundary.pressure import Perturbation

        assert run.pressure.probes_on(Perturbation.ACTOR_SUBSTITUTION) > 0


def test_the_pipeline_finds_the_counterexamples_it_filed_itself() -> None:
    """Pins S3-07 / S3-02 (resource-simplicity): two disjoint keyspaces.

    ``_record`` files every counterexample under ``region.candidate_id``
    (``region-<digest>`` or the Stage 2 candidate id) while ``_refined`` looked them
    up by the provisional cell's ``cand-<sha256(program.digest)[:20]>``. The two
    never intersect, so ``_refine_or_fission`` always received an empty tuple, §22's
    preferred repair — ``fission_cell`` — was unreachable from ``crystallize``, and
    a heterogeneous region carrying standing counterexamples was reported as having
    "no refinement available".
    """
    from pocketsec.stage3.crystal import pipeline as crystal_pipeline

    target = region()
    store = CounterexampleStore(cold_archive=None)
    # A prior run over the same region, exactly as the gate's shared store or
    # ``recrystallize`` would leave it.
    crystallize(
        target,
        config=CrystalConfig(seed=11, pressure_budget=16),
        teacher=teacher_for(target),
        field=KnowledgeField(),
        store=store,
    )
    filed = store.for_candidate(target.candidate_id)
    assert filed, "the fixture must leave a record or it proves nothing"

    seen: list[int] = []
    original = crystal_pipeline._refine_or_fission

    def _spy(cell, report, *, region, field, depth, counterexamples):  # type: ignore[no-untyped-def]
        seen.append(len(counterexamples))
        return original(
            cell,
            report,
            region=region,
            field=field,
            depth=depth,
            counterexamples=counterexamples,
        )

    crystal_pipeline._refine_or_fission = _spy  # type: ignore[assignment]
    try:
        crystallize(
            target,
            config=CrystalConfig(seed=13, pressure_budget=16),
            teacher=teacher_for(target),
            field=KnowledgeField(),
            store=store,
        )
    finally:
        crystal_pipeline._refine_or_fission = original  # type: ignore[assignment]

    assert seen, "the refinement step never ran"
    assert max(seen) > 0, (
        "_refine_or_fission was handed no counterexamples although the store held "
        f"{len(filed)} for this region"
    )


def test_a_crystal_built_cell_can_find_its_own_counterexamples_later() -> None:
    """Pins the melting half of S3-02 (resource-simplicity).

    ``open_counterexamples`` joins on the cell, and a provisional cell carried
    ``source_candidate_id=None`` whenever the region did not come from Stage 2. So
    ``CellStress.counterexamples`` and ``epoch_drift`` — 30% of the melt-trigger
    score by weight — were structurally 0.0 for every CRYSTAL-built cell, however
    often it failed its own region.
    """
    from pocketsec.stage3.crystal.pipeline import _provisional_cell

    target = region()
    store = CounterexampleStore(cold_archive=None)
    run = crystallize(
        target,
        config=CrystalConfig(seed=11, pressure_budget=16),
        teacher=teacher_for(target),
        field=KnowledgeField(),
        store=store,
    )
    assert run.counterexamples, "a non-promoted outcome must leave a trace"
    assert run.invariant is not None and run.boundary is not None
    program = (
        run.selected.program if run.selected is not None else _synthesised_program(target)
    )
    provisional = _provisional_cell(target, run.invariant, run.boundary, program)

    assert provisional.source_candidate_id == target.candidate_id
    assert open_counterexamples(provisional, store), (
        "a CRYSTAL-built cell must be able to find the counterexamples the pipeline "
        "filed against its own region"
    )


def _synthesised_program(target: RegionSample) -> Any:
    from pocketsec.stage3.synthesis.operators import SYNTHESISERS

    for _form, synthesiser in SYNTHESISERS:
        program = synthesiser(target.samples)
        if program is not None:
            return program
    raise AssertionError("no synthesiser produced a program for this region")


def test_crystal_config_refuses_to_widen_its_own_bounds() -> None:
    with pytest.raises(ContractError):
        CrystalConfig(seed=0, pressure_budget=MAX_PRESSURE_BUDGET + 1)
    with pytest.raises(ContractError):
        CrystalConfig(seed=0, max_refinements=9)
    with pytest.raises(ContractError):
        CrystalConfig(seed=0, epsilon_by_consequence={SecurityConsequence.ROUTINE: 0.1})


def test_region_refuses_to_exist_without_evidence_or_epoch() -> None:
    rows = (OperatorSample(frame=frame(), risk=0.1, delta=StateDelta(raised={})),)
    with pytest.raises(ContractError):
        RegionSample(
            region_key=(0, 0, 0), samples=rows, evidence=(), constraints=(),
            epochs=frozenset({0}), transitions=_SESSION.transitions[:1],
        )
    with pytest.raises(ContractError):
        RegionSample(
            region_key=(0, 0, 0), samples=rows, evidence=(evidence("e"),), constraints=(),
            epochs=frozenset(), transitions=_SESSION.transitions[:1],
        )


def test_crystallize_never_touches_the_field() -> None:
    """The field's mutators are tripwires: promotion here would raise."""
    target = region()
    run = crystallize(
        target,
        config=CrystalConfig(seed=7),
        teacher=teacher_for(target),
        field=_TripwireField(),
        store=CounterexampleStore(cold_archive=None),
    )
    assert run.outcome in set(CrystalOutcome)
    assert run.candidates_tried, "the run never reached SynthesizeOperators"


def test_crystallize_reaches_the_pressure_loop_and_refuses_on_divergence() -> None:
    target = region()
    run = crystallize(
        target,
        config=CrystalConfig(seed=11, pressure_budget=1),
        teacher=teacher_for(target),
        field=KnowledgeField(),
        store=CounterexampleStore(cold_archive=None),
    )
    assert run.outcome is CrystalOutcome.REFUSED_DIVERGENCE
    assert run.selected is not None and run.pressure is not None
    assert run.pressure.probes_run >= 1
    assert run.cell is None
    assert run.counterexamples


def test_crystallize_records_a_counterexample_for_every_refusal() -> None:
    target = region(sessions=())  # no sessions -> discovery finds nothing
    store = CounterexampleStore(cold_archive=None)
    run = crystallize(
        target,
        config=CrystalConfig(seed=1),
        teacher=teacher_for(target),
        field=KnowledgeField(),
        store=store,
    )
    assert run.outcome is CrystalOutcome.RETURNED_TO_LEARNING
    assert run.counterexamples
    assert store.for_candidate(run.counterexamples[0].cell_candidate_id)


def test_returned_to_learning_still_leaves_a_trace() -> None:
    target = region(sessions=())
    store = CounterexampleStore(cold_archive=None)
    crystallize(
        target,
        config=CrystalConfig(seed=2),
        teacher=teacher_for(target),
        field=KnowledgeField(),
        store=store,
    )
    assert store.memory_bytes() > 0


def test_crystallize_refuses_into_a_full_field_without_promoting() -> None:
    field = KnowledgeField()
    for index in range(MAX_CELLS):
        field.insert(cell(f"cell-{index:04d}"))
    target = region()
    store = CounterexampleStore(cold_archive=None)
    run = crystallize(
        target,
        config=CrystalConfig(seed=3),
        teacher=teacher_for(target),
        field=field,
        store=store,
    )
    assert run.outcome is CrystalOutcome.RETURNED_TO_LEARNING
    assert "FIELD_FULL" in run.reason
    assert run.cell is None


def test_budget_exhaustion_returns_budget_exhausted_and_no_cell() -> None:
    """A run that spends its probe budget hands back nothing, not a half-cell.

    Uses ``teacher_over_the_lattice``: reaching budget exhaustion requires at
    least one *refinement*, and a refinement requires a measured near-boundary
    error. With a snapshot covering only the region's own frames every probe comes
    back TEACHER_UNAVAILABLE, which S3-03 correctly stopped counting as a boundary
    error, so the run refuses on the first divergence instead.
    """
    target = region()
    store = CounterexampleStore(cold_archive=None)
    run = crystallize(
        target,
        config=CrystalConfig(seed=13, pressure_budget=64, max_refinements=8),
        teacher=teacher_over_the_lattice(target),
        field=KnowledgeField(),
        store=store,
    )
    assert run.outcome is CrystalOutcome.BUDGET_EXHAUSTED
    assert run.cell is None
    assert run.resolution is None
    assert run.counterexamples


def test_every_non_promoted_outcome_carries_a_counterexample() -> None:
    store = CounterexampleStore(cold_archive=None)
    seen: set[CrystalOutcome] = set()
    for seed, budget in ((11, 1), (13, 64), (14, 256)):
        target = region()
        run = crystallize(
            target,
            config=CrystalConfig(seed=seed, pressure_budget=budget),
            teacher=teacher_over_the_lattice(target),
            field=KnowledgeField(),
            store=store,
        )
        seen.add(run.outcome)
        if run.outcome is not CrystalOutcome.PROMOTED:
            assert run.counterexamples, f"{run.outcome} left no trace"
    # Distinct refusal reasons, not the same short-circuit three times over.
    assert len(seen) >= 2, f"the loop only ever reached {seen}"


def test_a_region_only_unmeasured_forms_can_fit_is_refused_as_unmeasured() -> None:
    """A state-raising region fits only forms the VM will not execute.

    Every candidate is then UNMEASURED, and the run must refuse rather than
    select the cheapest-looking one. This is the end-to-end form of the
    "UNMEASURED is not cheap" rule, and it fails the moment the selector starts
    treating an unmeasured cost as zero.
    """
    target = region(raised={"privilege": (0, 1)})
    run = crystallize(
        target,
        config=CrystalConfig(seed=21),
        teacher=teacher_for(target),
        field=KnowledgeField(),
        store=CounterexampleStore(cold_archive=None),
    )
    assert run.outcome is CrystalOutcome.REFUSED_RESOLUTION
    assert "UNMEASURED" in run.reason
    assert run.selected is None
    assert run.candidates_tried, "synthesis produced nothing, so nothing was refused"
    assert run.counterexamples


def test_a_region_without_a_hard_constraint_is_refused_at_construction() -> None:
    rows = (OperatorSample(frame=frame(), risk=0.1, delta=StateDelta(raised={})),)
    with pytest.raises(ContractError):
        RegionSample(
            region_key=(0, 0, 0), samples=rows, evidence=(evidence("e"),), constraints=(),
            epochs=frozenset({0}), transitions=_SESSION.transitions[:1],
        )
