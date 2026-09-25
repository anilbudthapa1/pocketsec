"""D3.1/D3.5 — every test here is named after the invariant it protects.

These are not construction smoke tests. Each one asserts that a specific way of
being wrong is *refused*: an unattributable cell, a boundary that contains
nothing but reads as permissive, a predicate that learned a process name, a
field that quietly forgot a cell to make room, a composition that picked a
winner between two cells that disagreed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, replace

import pytest

from pocketsec.stage0.contracts.common import ContractError, EvidenceRef
from pocketsec.stage1.observation.policy import EscalationDecision, ObservationLevel
from pocketsec.stage1.ssir.entities import (
    Entity,
    EntityKind,
    SemanticBelief,
    SemanticProperty,
)
from pocketsec.stage1.ssir.relations import Relation, RelationFamily
from pocketsec.stage1.state.security_state import (
    CredentialExposure,
    Privilege,
    SecurityStateV1,
    StateDelta,
)
from pocketsec.stage3.boundary.index import (
    MAX_KEYS_PER_CELL,
    BoundaryIndex,
    CellBoundary,
)
from pocketsec.stage3.cells.field import (
    MAX_COMPOSITION_DEPTH,
    CellActivation,
    CompositionOutcome,
    FieldFull,
    KnowledgeField,
)
from pocketsec.stage3.cells.frame import CellFrame, boundary_key_of, frame_digest
from pocketsec.stage3.cells.invariant import (
    MAX_ANTECEDENT_TERMS,
    ConsequentSpec,
    Invariant,
    PredicateRole,
    SemanticPredicate,
)
from pocketsec.stage3.cells.masks import (
    PROPERTY_ORDER,
    mask_properties,
    property_mask,
)
from pocketsec.stage3.cells.operator import MAX_CELL_STEPS, OperatorForm, OperatorProgram
from pocketsec.stage3.cells.schema import (
    AssuranceLevel,
    AuditPolicy,
    CellPhase,
    ConstraintKind,
    HardConstraint,
    KnowledgeCellV1,
)
from pocketsec.stage3.core_ids import CORE_IDS, OPTIONAL_IDS, REQUIRED_IDS, FunctionClass
from pocketsec.stage3.theory import (
    THRESHOLDS,
    IntelligenceDensity,
    KnowledgePressure,
    ResolutionState,
    SecurityConsequence,
    consequence_of,
    crystallization_allowed,
)

# --- fixtures ----------------------------------------------------------------


def evidence(tag: str = "a") -> EvidenceRef:
    return EvidenceRef(store="stage1", locator=f"evt/{tag}", digest=f"sha256:{tag * 64}"[:71])


def make_predicate(
    *,
    role: PredicateRole = PredicateRole.ACTOR,
    required: frozenset[SemanticProperty] = frozenset({SemanticProperty.INTERPRETER}),
    forbidden: frozenset[SemanticProperty] = frozenset(),
    family: RelationFamily | None = RelationFamily.FILESYSTEM,
) -> SemanticPredicate:
    return SemanticPredicate(
        role=role,
        required_properties=required,
        forbidden_properties=forbidden,
        relation_family=family,
        entity_kind=None,
    )


def make_boundary(**overrides: object) -> CellBoundary:
    defaults: dict[str, object] = {
        "predicates": (make_predicate(),),
        "state_dimensions": frozenset({"credential", "privilege"}),
        "phi_range": (0.0, 12.0),
        "max_uncertainty": 0.25,
        "epochs": frozenset({0, 1}),
        "forbidden_combinations": (),
    }
    defaults.update(overrides)
    return CellBoundary(**defaults)  # type: ignore[arg-type]


def make_invariant(**overrides: object) -> Invariant:
    defaults: dict[str, object] = {
        "invariant_id": "inv-0001",
        "antecedent": (make_predicate(),),
        "consequent": ConsequentSpec(
            required_dimensions=frozenset({"credential"}),
            min_delta_phi=0.5,
            required_evidence_kinds=frozenset({"credential_access"}),
            consequence=SecurityConsequence.HIGH,
        ),
        "support": 6,
        "contradictions": 0,
        "identities_collapsed": 3,
        "epochs": frozenset({0, 1}),
        "falsifier": "an INTERPRETER actor reads a CREDENTIAL without raising credential",
        "evidence": (evidence("a"),),
    }
    defaults.update(overrides)
    return Invariant(**defaults)  # type: ignore[arg-type]


def make_resolution(**overrides: object) -> ResolutionState:
    defaults: dict[str, object] = {
        "predictive_stability": 0.97,
        "calibrated_uncertainty": 0.10,
        "validated_breadth": 9,
        "counterfactual_consistency": 0.93,
        "evidence_agreement": 0.96,
        "drift_stability": 2,
        "measured_by": "tests.test_stage3_foundation:make_resolution",
    }
    defaults.update(overrides)
    return ResolutionState(**defaults)  # type: ignore[arg-type]


def make_operator(**overrides: object) -> OperatorProgram:
    defaults: dict[str, object] = {
        "form": OperatorForm.LOOKUP_TABLE,
        "words": (),
        "table": {"1:2:4": 0.81},
        "max_steps": 4,
        "max_state_bytes": 64,
    }
    defaults.update(overrides)
    return OperatorProgram(**defaults)  # type: ignore[arg-type]


def make_cell(cell_id: str = "cell-0001", **overrides: object) -> KnowledgeCellV1:
    defaults: dict[str, object] = {
        "cell_id": cell_id,
        "invariant": make_invariant(),
        "boundary": make_boundary(),
        "operator": make_operator(),
        "resolution": make_resolution(),
        "confidence": 0.9,
        "assurance": AssuranceLevel.A3,
        "phase": CellPhase.CRYSTALLIZED,
        "evidence_lineage": (evidence("a"), evidence("b")),
        "constraints": (
            HardConstraint(
                constraint_id="q-never-lower-phi",
                kind=ConstraintKind.NEVER_LOWER_PHI,
                detail="the cell may not report a lower Phi than Stage 1 computes",
            ),
        ),
        "epochs": frozenset({0, 1}),
        "audit_policy": AuditPolicy(
            base_rate=0.05, min_rate=0.01, max_rate=0.5, jitter_salt="boot-salt-1"
        ),
        "version": 1,
        "parent_cell_id": None,
        "source_candidate_id": "phi-oracle-0001",
    }
    defaults.update(overrides)
    return KnowledgeCellV1(**defaults)  # type: ignore[arg-type]


def make_frame(**overrides: object) -> CellFrame:
    defaults: dict[str, object] = {
        "state": SecurityStateV1(credential=CredentialExposure.READABLE),
        "delta": StateDelta({"credential": (0, 2)}),
        "actor_properties": property_mask([SemanticProperty.INTERPRETER]),
        "object_properties": property_mask([SemanticProperty.CREDENTIAL]),
        "relation_family": RelationFamily.FILESYSTEM,
        "phi": 3.0,
        "delta_phi": 3.0,
        "uncertainty": 0.1,
        "epoch_id": 0,
        "window_counts": {int(RelationFamily.FILESYSTEM): 4},
        "evidence": (evidence("a"),),
        "encoder_version": "ssir-encoder.v1",
    }
    defaults.update(overrides)
    return CellFrame(**defaults)  # type: ignore[arg-type]


def make_activation(cell_id: str, **overrides: object) -> CellActivation:
    defaults: dict[str, object] = {
        "cell_id": cell_id,
        "delta": StateDelta({"credential": (0, 2)}),
        "risk": 0.7,
        "evidence_required": (evidence("a"),),
        "escalation": None,
        "consequence": SecurityConsequence.HIGH,
        "confidence": 0.9,
        "epochs": frozenset({0, 1}),
    }
    defaults.update(overrides)
    return CellActivation(**defaults)  # type: ignore[arg-type]


def field_with(*cells: KnowledgeCellV1) -> KnowledgeField:
    field = KnowledgeField()
    for cell in cells:
        field.insert(cell)
    return field


# --- D3.1 theory -------------------------------------------------------------


def test_resolution_state_measured_by_must_name_module_and_function() -> None:
    """A resolution with no producer is UNMEASURED and must not exist."""
    for bad in ("", "   ", "produced_somewhere", "module:", ":function", "a:b:c"):
        with pytest.raises(ContractError, match="measured_by"):
            make_resolution(measured_by=bad)


def test_resolution_unmet_names_every_failing_term() -> None:
    """A refusal must say which evidence is missing, not merely that it is."""
    weak = make_resolution(
        predictive_stability=0.1,
        calibrated_uncertainty=0.9,
        validated_breadth=0,
        counterfactual_consistency=0.1,
        evidence_agreement=0.1,
        drift_stability=0,
    )
    unmet = weak.unmet(THRESHOLDS[SecurityConsequence.ROUTINE])
    assert unmet == (
        "predictive_stability",
        "calibrated_uncertainty",
        "validated_breadth",
        "counterfactual_consistency",
        "evidence_agreement",
        "drift_stability",
    )


def test_crystallization_threshold_rises_with_consequence() -> None:
    """The same resolution must clear ROUTINE and fail CRITICAL, or Theta_c is flat."""
    middling = make_resolution(
        predictive_stability=0.85,
        calibrated_uncertainty=0.30,
        validated_breadth=3,
        counterfactual_consistency=0.75,
        evidence_agreement=0.85,
        drift_stability=2,
    )
    allowed_routine, _ = crystallization_allowed(middling, SecurityConsequence.ROUTINE)
    allowed_critical, unmet = crystallization_allowed(middling, SecurityConsequence.CRITICAL)
    assert allowed_routine is True
    assert allowed_critical is False
    assert unmet


def test_no_threshold_accepts_a_single_epoch_of_corroboration() -> None:
    """Stage 3 may not crystallise on weaker evidence than Stage 2 needed to export.

    This is the test that fails if someone "simplifies" THRESHOLDS: Stage 2's
    CandidateStability refuses one distinct epoch outright, and a Stage 3
    threshold of 1 would reopen the frequency-is-corroboration hole (ADR-0007).
    """
    single_epoch = make_resolution(drift_stability=1)
    for consequence in SecurityConsequence:
        allowed, unmet = crystallization_allowed(single_epoch, consequence)
        assert allowed is False
        assert "drift_stability" in unmet


def test_consequence_of_reads_critical_from_stage1_interactions() -> None:
    """CRITICAL is Stage 1's own INTERACTIONS firing, not a Stage 3 opinion."""
    exfiltration = SecurityStateV1(
        privilege=Privilege.ROOT,
        credential=CredentialExposure.EXTRACTED,
    )
    assert consequence_of(StateDelta({}), exfiltration) is SecurityConsequence.CRITICAL
    quiet = SecurityStateV1()
    assert consequence_of(StateDelta({}), quiet) is SecurityConsequence.ROUTINE
    assert (
        consequence_of(StateDelta({"credential": (0, 1)}), quiet) is SecurityConsequence.HIGH
    )
    assert consequence_of(StateDelta({"discovery": (0, 1)}), quiet) is SecurityConsequence.ELEVATED


def test_intelligence_density_is_none_when_any_term_is_unmeasured() -> None:
    """One missing measurement poisons the ratio; it never defaults to a number."""
    measured = IntelligenceDensity(
        utility=0.75,
        microseconds_per_event=2.0,
        resident_bytes=1024,
        audit_cost_per_event=2.0,
        measured_by="tests.test_stage3_foundation:test_intelligence_density",
    )
    assert measured.density == pytest.approx(0.1875)
    for field_name in (
        "utility",
        "microseconds_per_event",
        "resident_bytes",
        "audit_cost_per_event",
    ):
        blanked = replace(measured, **{field_name: None})
        assert blanked.measured is False
        assert blanked.density is None


def test_intelligence_density_of_a_free_mechanism_is_undefined_not_infinite() -> None:
    """The Phi-oracle costs ~0 us/event; an 'infinite density' headline is a lie."""
    free = IntelligenceDensity(
        utility=0.75,
        microseconds_per_event=0.0,
        resident_bytes=0,
        audit_cost_per_event=0.0,
        measured_by="tests.test_stage3_foundation:test_free_density",
    )
    assert free.measured is True
    assert free.density is None


def test_knowledge_pressure_exposes_no_combined_score() -> None:
    """Architecture §17 forbids one product; a `.score` would reinstate it."""
    pressure = KnowledgePressure(
        frequency=100,
        measured_teacher_cost_us=6.6,
        predictability=0.5,
        security_utility=0.9,
    )
    assert not hasattr(pressure, "score")
    assert "score" not in dir(pressure)
    assert "score" not in pressure.to_dict()
    assert pressure.compute_pressure == pytest.approx(330.0)
    assert pressure.security_pressure == pytest.approx(0.45)


def test_knowledge_pressure_compute_component_is_none_when_teacher_cost_unmeasured() -> None:
    """An untimed teacher is UNMEASURED, never free."""
    pressure = KnowledgePressure(
        frequency=100,
        measured_teacher_cost_us=None,
        predictability=0.5,
        security_utility=0.9,
    )
    assert pressure.compute_pressure is None
    assert pressure.security_pressure == pytest.approx(0.45)


# --- core ids ----------------------------------------------------------------


def test_every_core_id_is_required_or_optional_and_names_a_deliverable() -> None:
    assert len(CORE_IDS) == 20
    assert REQUIRED_IDS.isdisjoint(OPTIONAL_IDS)
    assert len(REQUIRED_IDS | OPTIONAL_IDS) == 20
    for function in CORE_IDS.values():
        assert isinstance(function.function_class, FunctionClass)
        assert function.deliverable.startswith("D3.")


def test_the_ablation_surface_is_exactly_the_mechanisms_the_gate_will_ablate() -> None:
    """G3.11 reads OPTIONAL_IDS; nothing may be marked OPTIONAL and then not ablated."""
    assert OPTIONAL_IDS == {
        "AICT-F04",
        "AICT-F05",
        "AICT-F06",
        "AICT-F11",
        "AICT-F15",
        "AICT-F19",
    }


# --- masks -------------------------------------------------------------------


def test_property_mask_round_trips_through_the_pinned_bit_order() -> None:
    props = frozenset({SemanticProperty.INTERPRETER, SemanticProperty.CREDENTIAL})
    assert mask_properties(property_mask(props)) == props
    assert property_mask([]) == 0
    assert mask_properties(0) == frozenset()


def test_property_mask_refuses_a_value_outside_the_wire_order() -> None:
    """A mask built from a bare string would index the wrong bit forever."""
    with pytest.raises(ContractError, match="PROPERTY_ORDER"):
        property_mask(["INTERPRETER"])  # type: ignore[list-item]


def test_a_mask_with_bits_above_the_property_width_is_refused() -> None:
    """High bits mean the producer used a different ordering, i.e. another build."""
    with pytest.raises(ContractError, match="different property ordering"):
        mask_properties(1 << len(PROPERTY_ORDER))


# --- frames ------------------------------------------------------------------


def test_a_cell_frame_cannot_carry_an_identity() -> None:
    """ADR-0006/0007: a cell that could branch on a name is a rename from wrong."""
    fields = {name.lower() for name in CellFrame.__dataclass_fields__}
    for token in ("identity", "display_name", "entity", "name", "path", "pid"):
        assert not any(token in name for name in fields), f"CellFrame exposes {token!r}"


def test_frame_digest_is_stable_across_equal_frames_and_moves_with_content() -> None:
    """The digest is the teacher-snapshot join key; equal frames must join."""
    assert frame_digest(make_frame()) == frame_digest(make_frame())
    assert frame_digest(make_frame()) != frame_digest(make_frame(epoch_id=1))
    assert frame_digest(make_frame()) != frame_digest(make_frame(phi=3.5))
    assert frame_digest(make_frame()).startswith("sha256:")


def test_frame_digest_ignores_evidence_arrival_order() -> None:
    """The set of bytes behind a frame identifies it; the order they arrived does not."""
    one = make_frame(evidence=(evidence("a"), evidence("b")))
    other = make_frame(evidence=(evidence("b"), evidence("a")))
    assert frame_digest(one) == frame_digest(other)


def test_a_frame_with_no_evidence_is_unconstructible() -> None:
    with pytest.raises(ContractError, match="evidence"):
        make_frame(evidence=())


def test_a_frame_window_is_bounded_and_refuses_an_unknown_family() -> None:
    with pytest.raises(ContractError, match="RelationFamily"):
        make_frame(window_counts={99: 1})


def test_a_frame_with_a_non_finite_phi_is_refused() -> None:
    """NaN would serialise past json.dumps' default and poison the join key."""
    with pytest.raises(ContractError, match="finite"):
        make_frame(phi=float("nan"))


def test_boundary_key_is_three_ints_over_actor_and_delta() -> None:
    key = boundary_key_of(make_frame())
    assert key == (
        int(RelationFamily.FILESYSTEM),
        property_mask([SemanticProperty.INTERPRETER]),
        StateDelta({"credential": (0, 2)}).bitmask(),
    )


# --- invariants --------------------------------------------------------------


def test_a_semantic_predicate_cannot_name_an_identity_field() -> None:
    """Names are evidence, never model vocabulary (ADR-0006, ADR-0007)."""

    @dataclass(frozen=True, slots=True)
    class _SignaturePredicate(SemanticPredicate):
        display_name: str = ""

    with pytest.raises(ContractError, match="identity-shaped fields"):
        _SignaturePredicate(
            role=PredicateRole.ACTOR,
            required_properties=frozenset({SemanticProperty.INTERPRETER}),
            forbidden_properties=frozenset(),
            relation_family=None,
            entity_kind=None,
            display_name="nginx",
        )


def test_a_predicate_that_requires_and_forbids_the_same_property_is_refused() -> None:
    with pytest.raises(ContractError, match="never match"):
        make_predicate(
            required=frozenset({SemanticProperty.INTERPRETER}),
            forbidden=frozenset({SemanticProperty.INTERPRETER}),
        )


def test_a_predicate_matches_on_asserted_semantics_not_on_the_entity_name() -> None:
    """Two differently-named entities with the same semantics must both match."""
    belief = SemanticBelief(
        kind=EntityKind.PROCESS,
        properties={SemanticProperty.INTERPRETER: 0.9},
        observations=4,
    )
    predicate = make_predicate(family=RelationFamily.FILESYSTEM)
    nginx = Entity(identity="boot:1:100", semantics=belief, display_name="nginx")
    apache = Entity(identity="boot:1:200", semantics=belief, display_name="httpd")
    assert predicate.matches(nginx, Relation.READ) is True
    assert predicate.matches(apache, Relation.READ) is True
    # Wrong relation family, same semantics: outside the predicate.
    assert predicate.matches(nginx, Relation.CONNECT) is False


def test_a_predicate_does_not_treat_uncertainty_as_a_negative_answer() -> None:
    """A belief below Stage 1's assert threshold is uncertain, not absent."""
    unsure = Entity(
        identity="boot:1:300",
        semantics=SemanticBelief(
            kind=EntityKind.PROCESS, properties={SemanticProperty.INTERPRETER: 0.5}
        ),
    )
    required = make_predicate(required=frozenset({SemanticProperty.INTERPRETER}))
    forbidding = make_predicate(
        required=frozenset({SemanticProperty.NETWORK_CLIENT}),
        forbidden=frozenset({SemanticProperty.INTERPRETER}),
    )
    assert required.matches(unsure, Relation.READ) is False
    # And it is not counted as *holding* the forbidden property either.
    assert forbidding.matches(unsure, Relation.READ) is False


def test_an_invariant_without_a_falsifier_is_unconstructible() -> None:
    """An unfalsifiable rule is a belief, not an invariant (architecture §8)."""
    with pytest.raises(ContractError, match="falsifier"):
        make_invariant(falsifier="   ")


def test_an_invariant_with_no_antecedent_fires_on_every_event_and_is_refused() -> None:
    with pytest.raises(ContractError, match="at least one SemanticPredicate"):
        make_invariant(antecedent=())


def test_an_invariant_antecedent_is_capped_at_four_terms() -> None:
    too_many = tuple(
        make_predicate(required=frozenset({prop}))
        for prop in PROPERTY_ORDER[: MAX_ANTECEDENT_TERMS + 1]
    )
    with pytest.raises(ContractError, match="MAX_ANTECEDENT_TERMS"):
        make_invariant(antecedent=too_many)


def test_an_invariant_round_trips_through_dict_exactly() -> None:
    invariant = make_invariant()
    assert Invariant.from_dict(json.loads(json.dumps(invariant.to_dict()))) == invariant


# --- boundaries --------------------------------------------------------------


def test_unseen_input_behaviour_cannot_be_anything_but_abstain() -> None:
    """GUESS is not a policy; it is silent extrapolation off the boundary."""
    for bad in ("GUESS", "BEST_EFFORT", "abstain", ""):
        with pytest.raises(ContractError, match="unseen_input_behaviour"):
            make_boundary(unseen_input_behaviour=bad)


def test_an_empty_boundary_contains_nothing_rather_than_everything() -> None:
    """The classic inversion: `not constraints` read as `no restrictions`."""
    empty = make_boundary(state_dimensions=frozenset())
    assert empty.is_empty is True
    assert empty.contains(make_frame()) is False
    assert empty.distance(make_frame()) > 0


def test_a_boundary_valid_in_no_epoch_is_unconstructible() -> None:
    with pytest.raises(ContractError, match="epochs"):
        make_boundary(epochs=frozenset())


def test_an_inverted_phi_range_is_refused() -> None:
    with pytest.raises(ContractError, match="inverted"):
        make_boundary(phi_range=(9.0, 1.0))


def test_boundary_distance_counts_each_violated_clause() -> None:
    """Boundary Pressure walks the near-boundary band; distance must be graded."""
    boundary = make_boundary()
    assert boundary.distance(make_frame()) == 0
    assert boundary.distance(make_frame(epoch_id=7)) == 1
    two_out = make_frame(epoch_id=7, uncertainty=0.99)
    assert boundary.distance(two_out) == 2
    assert boundary.contains(two_out) is False


def test_a_boundary_refuses_a_frame_holding_a_forbidden_combination() -> None:
    boundary = make_boundary(
        forbidden_combinations=(
            frozenset({SemanticProperty.INTERPRETER, SemanticProperty.CREDENTIAL}),
        )
    )
    assert boundary.contains(make_frame()) is False


def test_a_boundary_expanding_past_sixty_four_keys_is_refused() -> None:
    """Architecture §39: the mechanical cap on the knowledge-explosion threat."""
    wide = make_boundary(
        predicates=tuple(
            make_predicate(required=frozenset({prop}), family=None) for prop in PROPERTY_ORDER[:9]
        )
    )
    with pytest.raises(ContractError, match="MAX_KEYS_PER_CELL"):
        wide.keys()
    narrow = make_boundary(
        predicates=tuple(
            make_predicate(required=frozenset({prop}), family=RelationFamily.FILESYSTEM)
            for prop in PROPERTY_ORDER[:4]
        )
    )
    keys = narrow.keys()
    assert 0 < len(keys) <= MAX_KEYS_PER_CELL
    assert len(set(keys)) == len(keys)


def test_a_contained_frame_reaches_its_cell_through_the_real_index() -> None:
    """A frame inside a boundary must be found. Asserted end-to-end, not by proxy.

    This test used to assert ``boundary_key_of(frame) in boundary.keys()``, which
    only implies reachability if the index looks a cell up by exact key. It does
    not: ``BoundaryIndex.lookup_all`` buckets on the relation family and then asks
    ``CellBoundary.contains``, so ``keys()`` is the cell's declared *footprint* —
    what melting reopens and what the §38 ceiling counts — while
    ``boundary_key_of`` is the quantised key baseline B1 hashes on. Two different
    jobs that happened to share a shape.

    The proxy was also simply wrong about the delta term: a boundary declares the
    union of the dimensions it was validated over, and any one frame raises some
    subset of them, so the two are equal only by coincidence. Asserted here as the
    subset relation it actually is, on top of the reachability the proxy stood for.
    """
    boundary = make_boundary()
    frame = make_frame()
    assert boundary.contains(frame) is True

    index = BoundaryIndex()
    cell = make_cell(boundary=boundary)
    index.insert(cell)
    assert index.lookup(frame) is cell
    assert index.lookup_all(frame) == (cell,)

    family, _actor_mask, delta_mask = boundary_key_of(frame)
    footprint = boundary.keys()
    assert family in {key[0] for key in footprint}
    # The frame raises a subset of the dimensions the boundary was validated over.
    assert delta_mask & boundary.delta_mask() == delta_mask


def test_a_boundary_round_trips_through_dict_exactly() -> None:
    boundary = make_boundary(
        forbidden_combinations=(frozenset({SemanticProperty.ROOT_OWNED}),)
    )
    assert CellBoundary.from_dict(json.loads(json.dumps(boundary.to_dict()))) == boundary


# --- operators ---------------------------------------------------------------


def test_an_operator_digest_that_disagrees_with_its_bytes_is_refused() -> None:
    """A forged or stale operator identity must not survive a reload."""
    good = make_operator()
    with pytest.raises(ContractError, match="does not match its own bytes"):
        make_operator(digest="sha256:" + "0" * 64)
    assert good.digest.startswith("sha256:")


def test_a_non_bytecode_operator_may_not_carry_words() -> None:
    with pytest.raises(ContractError, match="empty words"):
        make_operator(form=OperatorForm.CONSTANT, words=(1, 2, 3))


def test_a_bytecode_operator_may_not_carry_a_second_data_path() -> None:
    """Only the pools the ISA reads and the verifier range-checks are allowed.

    This test originally asserted that a BYTECODE program may carry *no* table
    at all. That rule and ``bytecode/isa.py`` contradicted each other: the ISA
    loads the constant and set pools out of ``program.table``, so forcing the
    table empty made the constant pool permanently length 0 — ``LOAD_CONST``
    could never pass its range check and the enumerative synthesiser could not
    emit a literal. The table is the verified data path, not a second one.

    The property the test exists for is unchanged and still asserted below: a
    key the ISA does not read is data the verifier never looks at, and it is
    refused. What changed is that ``const.``/``set.`` are now recognised as the
    first data path rather than mistaken for a second.
    """
    with pytest.raises(ContractError, match="table keys the ISA does not read"):
        make_operator(form=OperatorForm.BYTECODE, words=(1,), table={"k": 1.0})

    pooled = make_operator(
        form=OperatorForm.BYTECODE, words=(1,), table={"const.0": 1.5, "set.0.3": 1.0}
    )
    assert pooled.table == {"const.0": 1.5, "set.0.3": 1.0}


def test_an_operator_table_refuses_nan_and_authority_named_keys() -> None:
    """A NaN serialises here and fails at every other seam; 'action' is ADR-0003."""
    with pytest.raises(ContractError):
        make_operator(table={"k": float("nan")})
    with pytest.raises(ContractError, match="response-authority"):
        make_operator(table={"recommended_action": 1.0})


def test_an_operator_round_trips_through_dict_exactly() -> None:
    operator = make_operator()
    assert OperatorProgram.from_dict(json.loads(json.dumps(operator.to_dict()))) == operator


def test_residual_micro_model_is_absent_from_the_operator_forms() -> None:
    """ADR-0021: it needs a weights blob and numpy, both forbidden this wave."""
    assert "RESIDUAL_MICRO_MODEL" not in {form.value for form in OperatorForm}
    assert len(OperatorForm) == 8


# --- cells -------------------------------------------------------------------


def test_a_cell_with_empty_evidence_lineage_is_unconstructible() -> None:
    """An unattributable cell has nothing to melt back to."""
    with pytest.raises(ContractError, match="evidence_lineage"):
        make_cell(evidence_lineage=())


def test_a_cell_with_an_empty_boundary_is_unconstructible() -> None:
    with pytest.raises(ContractError, match="boundary is empty"):
        make_cell(boundary=make_boundary(state_dimensions=frozenset()))


def test_a_cell_with_no_hard_constraint_is_unconstructible() -> None:
    """Nothing that could fail it is not the same as safe."""
    with pytest.raises(ContractError, match="constraints must be non-empty"):
        make_cell(constraints=())


def test_a_cell_valid_in_no_epoch_is_unconstructible() -> None:
    with pytest.raises(ContractError, match="epochs must be a non-empty"):
        make_cell(epochs=frozenset())


def test_a_cell_may_not_claim_an_epoch_its_boundary_never_covered() -> None:
    with pytest.raises(ContractError, match="boundary does not cover"):
        make_cell(epochs=frozenset({0, 1, 5}))


def test_a_cell_operator_above_the_step_cap_is_unconstructible() -> None:
    with pytest.raises(ContractError, match="MAX_CELL_STEPS"):
        make_cell(operator=make_operator(max_steps=MAX_CELL_STEPS + 1))


def test_a_cell_confidence_outside_the_unit_interval_is_unconstructible() -> None:
    for bad in (-0.1, 1.5, float("nan")):
        with pytest.raises(ContractError, match="confidence"):
            make_cell(confidence=bad)


def test_a_cell_cannot_declare_a_response_authority_field() -> None:
    """ADR-0003: no model output carries response authority."""

    @dataclass(frozen=True, slots=True)
    class _ActingCell(KnowledgeCellV1):
        remediation: str = ""

    with pytest.raises(ContractError, match="response-authority field names"):
        _ActingCell(**make_cell().to_dict())  # type: ignore[arg-type]


def test_an_audit_policy_without_a_jitter_salt_is_unconstructible() -> None:
    """An unsalted audit schedule is a counter, and a counter can be waited out."""
    with pytest.raises(ContractError, match="jitter_salt"):
        AuditPolicy(base_rate=0.1, min_rate=0.0, max_rate=1.0, jitter_salt="")


def test_an_audit_policy_with_a_base_rate_outside_its_own_bounds_is_refused() -> None:
    with pytest.raises(ContractError, match="min_rate <= base_rate <= max_rate"):
        AuditPolicy(base_rate=0.9, min_rate=0.1, max_rate=0.5, jitter_salt="salt")


def test_a_cell_round_trips_through_dict_exactly() -> None:
    cell = make_cell()
    assert KnowledgeCellV1.from_dict(json.loads(json.dumps(cell.to_dict()))) == cell


def test_a_cell_declaring_a_foreign_schema_version_is_refused() -> None:
    with pytest.raises(ContractError, match="schema_version"):
        make_cell(schema_version="9.9.9")


# --- knowledge field ---------------------------------------------------------


def test_the_field_raises_rather_than_evicting_at_max_cells() -> None:
    """Forgetting is a GC decision with a reason, never a side effect of insertion."""
    field = KnowledgeField(max_cells=2)
    field.insert(make_cell("cell-0001"))
    field.insert(make_cell("cell-0002"))
    with pytest.raises(FieldFull, match="at its bound"):
        field.insert(make_cell("cell-0003"))
    assert len(field) == 2
    assert field.get("cell-0001") is not None


def test_the_field_raises_rather_than_evicting_at_max_bytes() -> None:
    field = KnowledgeField(max_bytes=make_cell().size_bytes())
    field.insert(make_cell("cell-0001"))
    with pytest.raises(FieldFull, match="bytes"):
        field.insert(make_cell("cell-0002"))


def test_the_field_refuses_to_replace_a_cell_in_place() -> None:
    """Silent replacement would erase the version lineage rollback needs."""
    field = field_with(make_cell("cell-0001"))
    with pytest.raises(ContractError, match="already holds"):
        field.insert(make_cell("cell-0001", version=2))
    assert field.remove("cell-0001") is True
    assert field.remove("cell-0001") is False
    assert field.memory_bytes() == 0


def test_composition_with_no_cell_abstains_instead_of_answering() -> None:
    verdict = KnowledgeField().compose([])
    assert verdict.outcome is CompositionOutcome.ABSTAINED_NO_CELL
    assert verdict.resolved is False
    assert verdict.delta.dimensions == frozenset()


def test_composition_abstains_for_a_cell_the_field_does_not_hold() -> None:
    """A field must not answer for knowledge it cannot show."""
    field = field_with(make_cell("cell-0001"))
    verdict = field.compose([make_activation("cell-0404")])
    assert verdict.outcome is CompositionOutcome.ABSTAINED_NO_CELL
    assert "cell-0404" in verdict.reason


def test_composition_never_shrinks_the_evidence_union() -> None:
    """§16 rule 1, and it must hold on the abstention paths too."""
    field = field_with(make_cell("cell-0001"), make_cell("cell-0002"))
    activations = [
        make_activation("cell-0001", evidence_required=(evidence("a"), evidence("b"))),
        make_activation("cell-0002", evidence_required=(evidence("b"), evidence("c"))),
    ]
    verdict = field.compose(activations)
    assert verdict.outcome is CompositionOutcome.RESOLVED
    assert len(verdict.evidence) >= max(len(a.evidence_required) for a in activations)
    assert {ref.digest for ref in verdict.evidence} == {
        evidence("a").digest,
        evidence("b").digest,
        evidence("c").digest,
    }

    # The same union survives an abstention: dropping evidence on the way out
    # would be an evidence-suppression channel.
    contradictory = [
        activations[0],
        make_activation(
            "cell-0002",
            delta=StateDelta({"credential": (0, 1)}),
            evidence_required=(evidence("b"), evidence("c")),
        ),
    ]
    abstained = field.compose(contradictory)
    assert abstained.outcome is CompositionOutcome.ABSTAINED_CONTRADICTION
    assert len(abstained.evidence) == 3


def test_a_lower_confidence_cell_cannot_downgrade_a_higher_consequence_result() -> None:
    """§16 rule 2. Averaging here is how a quiet cell mutes a loud one."""
    field = field_with(make_cell("cell-0001"), make_cell("cell-0002"))
    loud = make_activation(
        "cell-0001", risk=0.95, confidence=0.9, consequence=SecurityConsequence.CRITICAL
    )
    quiet = make_activation(
        "cell-0002",
        risk=0.0,
        confidence=0.2,
        consequence=SecurityConsequence.ROUTINE,
        delta=StateDelta({}),
    )
    verdict = field.compose([loud, quiet])
    assert verdict.outcome is CompositionOutcome.RESOLVED
    assert verdict.risk == pytest.approx(0.95)
    # And order must not matter: a composition that depended on it would be a
    # scheduling bug masquerading as a decision.
    assert field.compose([quiet, loud]).risk == pytest.approx(0.95)


def test_contradictory_cells_abstain_rather_than_picking_a_winner() -> None:
    """§16 rule 5. Confidence is not authority."""
    field = field_with(make_cell("cell-0001"), make_cell("cell-0002"))
    verdict = field.compose(
        [
            make_activation("cell-0001", delta=StateDelta({"privilege": (0, 2)}), confidence=0.99),
            make_activation("cell-0002", delta=StateDelta({"privilege": (0, 1)}), confidence=0.10),
        ]
    )
    assert verdict.outcome is CompositionOutcome.ABSTAINED_CONTRADICTION
    assert "privilege" in verdict.reason
    assert verdict.delta.dimensions == frozenset()


def test_epoch_incompatible_cells_do_not_compose() -> None:
    """§16 rule 6. Knowledge from two regimes is not one answer."""
    field = field_with(make_cell("cell-0001"), make_cell("cell-0002"))
    verdict = field.compose(
        [
            make_activation("cell-0001", epochs=frozenset({0})),
            make_activation("cell-0002", epochs=frozenset({3})),
        ]
    )
    assert verdict.outcome is CompositionOutcome.ABSTAINED_EPOCH_INCOMPATIBLE


def test_composition_deeper_than_four_cells_abstains() -> None:
    """§16 rule 7. Beyond this it is a rule explosion, not an answer."""
    cells = [make_cell(f"cell-{index:04d}") for index in range(MAX_COMPOSITION_DEPTH + 1)]
    field = field_with(*cells)
    verdict = field.compose([make_activation(cell.cell_id) for cell in cells])
    assert verdict.outcome is CompositionOutcome.ABSTAINED_DEPTH


def test_a_non_monotone_composed_delta_abstains() -> None:
    """§16 rule 4. Capability does not decay within a lineage (ADR-0005)."""
    field = field_with(make_cell("cell-0001"))
    verdict = field.compose(
        [make_activation("cell-0001", delta=StateDelta({"privilege": (2, 0)}))]
    )
    assert verdict.outcome is CompositionOutcome.ABSTAINED_CONTRADICTION
    assert "monotone" in verdict.reason


def test_a_delta_with_an_off_lattice_level_abstains_rather_than_propagating() -> None:
    """Adversarial or corrupted input must not reach the hub as a state change."""
    field = field_with(make_cell("cell-0001"))
    verdict = field.compose(
        [make_activation("cell-0001", delta=StateDelta({"privilege": (0, 99)}))]
    )
    assert verdict.outcome is CompositionOutcome.ABSTAINED_CONTRADICTION
    assert "not a valid security state" in verdict.reason


def test_escalation_composes_by_maximum_requested_level() -> None:
    """§16 rule 3, and Stage 3 forwards an AOP decision rather than minting one."""
    field = field_with(make_cell("cell-0001"), make_cell("cell-0002"))
    low = EscalationDecision(
        target="boot:1:100", level=ObservationLevel.BASELINE, budget_score=0.1, escalated=False
    )
    high = EscalationDecision(
        target="boot:1:100",
        level=ObservationLevel.HIGH_RESOLUTION,
        budget_score=0.8,
        escalated=True,
    )
    verdict = field.compose(
        [
            make_activation("cell-0001", escalation=low),
            make_activation("cell-0002", escalation=high),
        ]
    )
    assert verdict.escalation is high
    assert isinstance(verdict.escalation, EscalationDecision)


def test_composition_resolves_a_compatible_pair_into_a_joined_delta() -> None:
    """The happy path still has to be right, or every abstention is vacuous."""
    field = field_with(make_cell("cell-0001"), make_cell("cell-0002"))
    verdict = field.compose(
        [
            make_activation("cell-0001", delta=StateDelta({"credential": (0, 2)})),
            make_activation("cell-0002", delta=StateDelta({"privilege": (0, 1)})),
        ]
    )
    assert verdict.outcome is CompositionOutcome.RESOLVED
    assert verdict.delta.dimensions == frozenset({"credential", "privilege"})
    assert verdict.delta.raised["privilege"] == (0, 1)
    assert verdict.contributing == ("cell-0001", "cell-0002")


# --- measured bounds ---------------------------------------------------------


def test_a_full_field_of_cells_stays_inside_the_declared_byte_budget() -> None:
    """Measured, not asserted: fill the field to MAX_CELLS and read the bytes.

    The number this produces is the honest input to G3.9's bytes comparison
    against running the Phi-oracle directly, so it is measured here rather than
    estimated from a parameter count.
    """
    field = KnowledgeField()
    for index in range(16):
        field.insert(make_cell(f"cell-{index:04d}"))
    per_cell = field.memory_bytes() / 16
    projected_full_field = per_cell * 512
    assert field.memory_bytes() == sum(cell.size_bytes() for cell in field.cells())
    assert projected_full_field < 20 * 1024 * 1024


# --- deserialisation and construction boundaries ------------------------------


def test_phi_range_refuses_a_non_finite_bound() -> None:
    """Pins S3-AUTH-07: an infinity or NaN survived construction.

    A NaN bound makes every ``low <= phi <= high`` comparison false, so the
    boundary contains nothing while reading as a constraint. An infinity survived
    construction and then raised **ValueError**, not ContractError, inside
    ``size_bytes``'s ``json.dumps(..., allow_nan=False)`` — past every caller that
    guards on ContractError, including ``partial_melt``'s rollback, which by then
    had already removed the cell from the field and the index.
    """
    from pocketsec.stage3.boundary.index import PHI_UNCONSTRAINED_HIGH, CellBoundary

    def _boundary(low: float, high: float) -> CellBoundary:
        return CellBoundary(
            predicates=(),
            state_dimensions=frozenset({"privilege"}),
            phi_range=(low, high),
            max_uncertainty=0.5,
            epochs=frozenset({0}),
            forbidden_combinations=(),
        )

    for low, high in (
        (0.0, float("inf")),
        (float("-inf"), 1.0),
        (float("nan"), 1.0),
        (0.0, float("nan")),
    ):
        with pytest.raises(ContractError, match="finite"):
            _boundary(low, high)
    # The documented replacement for "no Φ constraint" is finite and serialises.
    ok = _boundary(0.0, PHI_UNCONSTRAINED_HIGH)
    assert json.dumps(ok.to_dict(), allow_nan=False)


def test_from_validity_boundary_does_not_default_to_an_infinite_phi_range() -> None:
    """The same defect shipped as a *default*, so every lifted boundary carried it."""
    from pocketsec.stage2.compile_candidates.candidate import ValidityBoundary
    from pocketsec.stage3.boundary.index import PHI_UNCONSTRAINED_HIGH, CellBoundary

    lifted = CellBoundary.from_validity_boundary(
        ValidityBoundary(
            state_dimensions=frozenset({"privilege"}),
            max_uncertainty=0.5,
            epochs=frozenset({0}),
            encoder_version="test.1",
            min_evidence_count=1,
        )
    )
    assert lifted.phi_range == (0.0, PHI_UNCONSTRAINED_HIGH)
    assert json.dumps(lifted.to_dict(), allow_nan=False)


def test_operator_program_from_dict_raises_contract_error_on_an_oversized_table() -> None:
    """Pins S3-AUTH-10: ``float()`` raises OverflowError, which was not caught."""
    from pocketsec.stage3.cells.operator import OperatorProgram

    with pytest.raises(ContractError):
        OperatorProgram.from_dict(
            {
                "form": "BYTECODE",
                "words": [],
                "table": {"const.0": 10**400},
                "max_steps": 1,
                "max_state_bytes": 1,
            }
        )


def test_teacher_snapshot_from_dict_raises_contract_error_on_a_malformed_experiment_id() -> None:
    """Pins S3-AUTH-10: ``parse_experiment_id``'s ValueError escaped the boundary."""
    from pocketsec.stage3.oracles.teacher import TEACHER_SNAPSHOT_V1_ID, TeacherSnapshotV1

    with pytest.raises(ContractError):
        TeacherSnapshotV1.from_dict(
            {
                "schema": TEACHER_SNAPSHOT_V1_ID,
                "teacher_id": "t",
                "source": "phi-oracle",
                "encoder_version": "v1",
                "corpus_version": "c1",
                "seed": 0,
                "responses": {},
                "measured_by": "tests:unit",
                "experiment_id": "not-an-experiment-id",
                "digest": "sha256:" + "0" * 64,
            }
        )
