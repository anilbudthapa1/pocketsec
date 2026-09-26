"""Stage 9 genome package: MSSC objective, genome schema, expressibility, core ids.

Every test is named after the invariant it protects. The expressibility tests compile a
small ambiguous split (count 24, seed 11) once per module to stay fast; the gate runs the
same check on the saturated count-60 split.
"""

from __future__ import annotations

import dataclasses
import math

import pytest

from pocketsec.stage0.contracts.common import SCHEMA_REGISTRY, ContractError
from pocketsec.stage2.core_ids import FunctionClass
from pocketsec.stage2.gate_measures import compile_split
from pocketsec.stage9 import core_ids
from pocketsec.stage9.chemistry.phenotype import SessionAggregation
from pocketsec.stage9.chemistry.typed_ir import (
    MAX_LOOKUP_ENTRIES,
    MAX_REGISTERS,
    MAX_RING,
    InputSource,
    IRError,
    IRNode,
    IRProgram,
    IRType,
    NodeKind,
    ProgramPhase,
    RegisterSpec,
)
from pocketsec.stage9.foundry.primitives import SEED_ALPHABET, MacroBody
from pocketsec.stage9.genome import computational as comp
from pocketsec.stage9.genome import expressibility as expr
from pocketsec.stage9.spec import mssc

F = IRType.FLOAT


def _reg(index: int = 0, value_type: IRType = F, lag: int = 0) -> IRNode:
    return IRNode(kind=NodeKind.REG, type=value_type, index=index, lag=lag)


def _feature(index: int) -> IRNode:
    return IRNode(kind=NodeKind.INPUT, type=F, source=InputSource.FEATURE, index=index)


def _apply(name: str, value_type: IRType, *args: int) -> IRNode:
    return IRNode(kind=NodeKind.APPLY, type=value_type, primitive=name, args=args)


def _const(value: float) -> IRNode:
    return IRNode(kind=NodeKind.CONST, type=F, value=value)


def _update(*nodes: IRNode, outputs: tuple[int, ...] | None = None) -> IRProgram:
    return IRProgram(ProgramPhase.UPDATE, nodes, outputs or (len(nodes) - 1,))


READ_R0 = IRProgram(ProgramPhase.READOUT, (_reg(0),), (0,))


def _build(update: IRProgram, registers: tuple[RegisterSpec, ...] = (RegisterSpec(F),),
           **kwargs: object) -> comp.ComputationalGenomeV1:
    return comp.build_genome(registers=registers, update=update, readout=READ_R0,
                             aggregation=SessionAggregation.MAX, **kwargs)  # type: ignore[arg-type]


@pytest.fixture(scope="module")
def small_split():  # type: ignore[no-untyped-def]
    return compile_split("ambiguous", count=24, seed=11)


@pytest.fixture(scope="module")
def expressibility(small_split):  # type: ignore[no-untyped-def]
    rows = expr.check_expressibility(small_split.dataset, sessions=small_split.sessions)
    return {row.target: row for row in rows}


# --- typed genomes: ill-typed, looping, recursive and unbounded genomes cannot exist ----


def test_ill_typed_genome_is_unconstructible() -> None:
    # MAX is F,F->F; reading the INT state-delta mask into it is a type error.
    mask = IRNode(kind=NodeKind.INPUT, type=IRType.INT, source=InputSource.STATE_DELTA_MASK)
    with pytest.raises(IRError) as caught:
        _build(_update(_reg(0), mask, _apply("MAX", F, 0, 1)))
    assert caught.value.code == "TYPE_MISMATCH"


def test_genome_written_as_a_loop_is_refused_at_construction() -> None:
    # A loop can only be spelled as a forward or self reference in a DAG of index order.
    with pytest.raises(IRError) as forward:
        _build(_update(_reg(0), _apply("MAX", F, 0, 2), _feature(73), outputs=(1,)))
    assert forward.value.code == "FORWARD_REFERENCE"
    with pytest.raises(IRError) as self_ref:
        _build(_update(_reg(0), _apply("MAX", F, 0, 1)))
    assert self_ref.value.code == "SELF_REFERENCE"


def test_recursive_macro_is_refused_before_it_can_reach_a_genome() -> None:
    body = MacroBody(params=(F,), nodes=(IRNode(kind=NodeKind.PARAM, type=F, index=0),
                                         _apply("LOOPY", F, 0)), output=1)
    with pytest.raises(IRError) as caught:
        SEED_ALPHABET.with_macro("LOOPY", body)
    assert caught.value.code in {"MACRO_CYCLE", "UNKNOWN_PRIMITIVE"}
    assert "LOOPY" not in SEED_ALPHABET.names()  # the receiver is unchanged


def test_unbounded_allocation_is_refused_and_the_bound_is_named() -> None:
    update = _update(_reg(0), _feature(73), _apply("MAX", F, 0, 1))
    with pytest.raises(IRError) as ring:
        _build(update, registers=(RegisterSpec(F, ring=MAX_RING + 1),))
    assert ring.value.code == "RING_BOUND"
    with pytest.raises(IRError) as table:
        _build(update, lookup_table=(0.5,) * (MAX_LOOKUP_ENTRIES + 1))
    assert table.value.code == "LOOKUP_BOUND"
    too_many = tuple(RegisterSpec(F) for _ in range(MAX_REGISTERS + 1))
    with pytest.raises(IRError) as registers:
        # Refused as early as the program itself: no update can write 9 registers.
        wide = _update(*(_feature(73) for _ in too_many), outputs=tuple(range(len(too_many))))
        _build(wide, registers=too_many)
    assert registers.value.code in {"REGISTER_BOUND", "OUTPUT_COUNT"}
    with pytest.raises(IRError) as state:
        _build(_update(*(_feature(73) for _ in range(MAX_REGISTERS)),
                       outputs=tuple(range(MAX_REGISTERS))), registers=too_many)
    assert state.value.code in {"REGISTER_BOUND", "OUTPUT_COUNT"}


def test_declared_bounds_that_understate_are_refused() -> None:
    genome = expr.phi_oracle_genome()
    bounds = genome.bounds
    for field, computed in (("declared_max_state_bytes", bounds.session_state_bytes_max),
                            ("declared_max_steps_per_event", bounds.max_steps_per_event)):
        with pytest.raises(IRError) as caught:
            dataclasses.replace(genome, **{field: computed - 1})
        assert caught.value.code == "DECLARED_BOUND_UNDERSTATED"
        # Over-declaring is legal (wasteful, not a lie).
        assert getattr(dataclasses.replace(genome, **{field: computed + 1}), field) == computed + 1


def test_build_genome_declares_exactly_the_static_bounds() -> None:
    genome = expr.phi_oracle_genome()
    assert genome.declared_max_state_bytes == genome.bounds.session_state_bytes_max
    assert genome.declared_max_steps_per_event == genome.bounds.max_steps_per_event == 3


def test_unknown_enum_values_and_raw_strings_are_refused() -> None:
    genome = expr.phi_oracle_genome()
    with pytest.raises(ContractError):
        dataclasses.replace(genome, aggregation="MAX")  # a string, not the enum member
    payload = genome.to_dict()
    payload["learning_law"] = "GRADIENT_DESCENT"
    with pytest.raises(ContractError):
        comp.ComputationalGenomeV1.from_dict(payload)
    # Lesson 3: laws with one executor have exactly one member.
    for enum_type in (comp.LearningLaw, comp.RoutingLaw, comp.DeploymentBackend,
                      comp.EvidenceSemantics):
        assert len(enum_type) == 1


def test_update_and_readout_phases_cannot_be_swapped() -> None:
    genome = expr.phi_oracle_genome()
    with pytest.raises(ContractError):
        dataclasses.replace(genome, update=genome.readout)


# --- digest, round trip and tamper refusal --------------------------------------------


def test_schema_is_registered_at_1_0_0() -> None:
    assert SCHEMA_REGISTRY[comp.COMPUTATIONAL_GENOME_V1_ID] == "1.0.0"


def test_digest_round_trips_and_excludes_lineage() -> None:
    genome = expr.phi_oracle_raw_genome()
    rebuilt = comp.ComputationalGenomeV1.from_dict(genome.to_dict())
    assert rebuilt == genome and rebuilt.digest == genome.digest
    child = dataclasses.replace(genome, parent_digests=(genome.digest,), mutation="REPLACE")
    assert child.digest == genome.digest
    assert comp.ComputationalGenomeV1.from_dict(child.to_dict()).parent_digests == (genome.digest,)
    # FLOAT init 0 and 0.0 are the same computation and must have the same identity.
    as_int = dataclasses.replace(genome, registers=(RegisterSpec(F, init=0),))
    assert as_int.digest == genome.digest


def test_signed_zero_has_one_identity_whatever_was_hashed_first() -> None:
    """Pins S9-R6 / S9-INT-02: 0.0 == -0.0 (and they hash equal) but canonical JSON wrote
    them differently, so the memoised digest of two EQUAL genomes depended on which one the
    process hashed first, and ``from_dict`` then refused a payload carrying its true digest.
    """
    def genome(zero: float) -> comp.ComputationalGenomeV1:
        return _build(_update(_reg(0), _const(zero), _apply("MAX", F, 0, 1)))

    comp._genome_digest.cache_clear()
    negative_first = genome(-0.0).digest
    comp._genome_digest.cache_clear()
    positive_first = genome(0.0).digest
    assert negative_first == positive_first
    assert math.copysign(1.0, _const(-0.0).value) == 1.0  # one spelling of zero
    payload = genome(-0.0).to_dict()
    assert payload["update"]["nodes"][1]["value"] == 0.0
    assert math.copysign(1.0, payload["update"]["nodes"][1]["value"]) == 1.0
    comp._genome_digest.cache_clear()
    assert comp.ComputationalGenomeV1.from_dict(payload).digest == negative_first


def test_tampered_payload_is_refused() -> None:
    payload = expr.phi_oracle_genome().to_dict()
    payload["update"]["nodes"][2]["primitive"] = "MIN"  # content changed, digest kept
    with pytest.raises(ContractError, match="digest mismatch"):
        comp.ComputationalGenomeV1.from_dict(payload)
    forged = expr.phi_oracle_genome().to_dict()
    forged["update"]["nodes"][2]["args"] = [0, 5]  # a forward reference: ill-typed
    with pytest.raises(IRError):
        comp.ComputationalGenomeV1.from_dict(forged)
    bool_index = expr.phi_oracle_genome().to_dict()
    bool_index["update"]["nodes"][1]["index"] = True
    with pytest.raises(ContractError):
        comp.ComputationalGenomeV1.from_dict(bool_index)


def test_payload_keys_are_exact() -> None:
    payload = expr.phi_oracle_genome().to_dict()
    assert set(payload) == comp.GENOME_KEYS
    extra = dict(payload, authority="x")
    with pytest.raises(ContractError, match="unexpected"):
        comp.ComputationalGenomeV1.from_dict(extra)
    missing = dict(payload)
    del missing["digest"]
    with pytest.raises(ContractError, match="missing"):
        comp.ComputationalGenomeV1.from_dict(missing)
    wrong = dict(payload, schema="pocketsec.something_else.v1")
    with pytest.raises(ContractError):
        comp.ComputationalGenomeV1.from_dict(wrong)


def test_parent_lineage_is_bounded() -> None:
    genome = expr.phi_oracle_genome()
    with pytest.raises(ContractError):
        dataclasses.replace(genome, parent_digests=(genome.digest,) * 5)
    with pytest.raises(ContractError):
        dataclasses.replace(genome, parent_digests=("not-a-digest",))


# --- macros are stored expanded -------------------------------------------------------


def _relu_alphabet():  # type: ignore[no-untyped-def]
    body = MacroBody(params=(F,), nodes=(IRNode(kind=NodeKind.PARAM, type=F, index=0),
                                         _const(0.0), _apply("MAX", F, 0, 1)), output=2)
    return SEED_ALPHABET.with_macro("RELU", body)


def test_macros_are_stored_expanded_and_their_uses_recorded() -> None:
    alphabet = _relu_alphabet()
    update = _update(_reg(0), _feature(73), _apply("RELU", F, 1), _apply("MAX", F, 0, 2))
    genome = _build(update, alphabet=alphabet)
    assert genome.macro_uses == ("RELU",)
    stored = {node.primitive for node in genome.update.nodes if node.kind is NodeKind.APPLY}
    assert "RELU" not in stored and stored <= set(SEED_ALPHABET.names())
    # The unexpanded program is not a storable genome: validation is against the seed set.
    with pytest.raises(IRError) as caught:
        dataclasses.replace(genome, update=update)
    assert caught.value.code == "UNKNOWN_PRIMITIVE"
    # Description length credits the macro, and refuses to guess without its alphabet.
    uncredited = dataclasses.replace(genome, macro_uses=())
    assert genome.description_length_bits(alphabet) < uncredited.description_length_bits()
    with pytest.raises(ContractError):
        genome.description_length_bits()


def test_description_length_follows_the_formula() -> None:
    genome = expr.phi_oracle_genome()
    kinds, inputs, prims = len(NodeKind), len(InputSource), len(SEED_ALPHABET.names())
    expected = (
        (math.log2(kinds) + 1.0 + 1.0)  # REG r0: log2(max(2,1)) + log2(max(2,1))
        + (math.log2(kinds) + math.log2(inputs) + math.log2(96))  # INPUT FEATURE[73]
        + (math.log2(kinds) + math.log2(prims) + 2 * math.log2(2))  # APPLY MAX(0,1) at 2
        + (math.log2(kinds) + 1.0 + 1.0)  # readout REG r0
        + 8.0 + math.log2(3)
    )
    assert genome.description_length_bits() == pytest.approx(expected, abs=1e-9)


# --- the architecture's fourteen fields -----------------------------------------------

ARCHITECTURE_FIELDS = (
    "state_space", "observation_map", "primitive_alphabet", "transition_law", "memory_law",
    "forgetting_law", "learning_law", "uncertainty_law", "readout_law", "routing_law",
    "resource_control_law", "compression_law", "evidence_semantics", "deployment_backend",
)


def test_field_binding_table_is_complete_and_resolvable() -> None:
    assert set(comp.ARCHITECTURE_FIELD_BINDING) == set(ARCHITECTURE_FIELDS)
    genome = expr.phi_oracle_genome()
    for field in ARCHITECTURE_FIELDS:
        values = comp.resolve_field(genome, field)
        assert values and all(value is not None for value in values), field
    with pytest.raises(ContractError):
        comp.resolve_field(genome, "consciousness_law")


def test_observation_map_reads_only_encoded_fields() -> None:
    assert expr.phi_oracle_genome().observation_map == frozenset({(InputSource.FEATURE, 73)})
    assert expr.hand_designed_genomes()["H2"].observation_map == frozenset(
        {(InputSource.STATE_DELTA_MASK, 0)}
    )


def test_abstention_path_is_reachable(small_split) -> None:  # type: ignore[no-untyped-def]
    update = _update(_reg(0), _feature(73), _apply("MAX", F, 0, 1))
    shortest = min(len(sample.steps) for sample in small_split.dataset.samples)
    genome = _build(update, min_events_for_score=shortest + 1)
    runs = genome.phenotype().run_dataset(small_split.dataset)
    assert any(run.score is None for run in runs)  # too few events -> no score, not 0.0
    with pytest.raises(ContractError):
        _build(update, min_events_for_score=0)


# --- expressibility: checked before any search ----------------------------------------


def test_phi_oracle_costs_three_wu_and_is_score_exact_against_both_references(
    expressibility,  # type: ignore[no-untyped-def]
) -> None:
    genome = expr.phi_oracle_genome()
    assert genome.bounds.update_wu_per_event == 3
    assert [n.kind for n in genome.update.nodes] == [NodeKind.REG, NodeKind.INPUT, NodeKind.APPLY]
    row = expressibility["phi-oracle-squashed"]
    assert row.exact is True and row.rank_identical is True, row.reason
    assert row.max_abs_error is not None and row.max_abs_error <= expr.EXACT_TOLERANCE
    assert row.sessions == 24 and row.genome_digest == genome.digest and row.reason == ""


def test_phi_oracle_raw_is_exact(expressibility) -> None:  # type: ignore[no-untyped-def]
    row = expressibility["phi-oracle-raw"]
    assert row.exact is True and row.rank_identical is True, row.reason
    assert any(n.primitive == "DIV" for n in expr.phi_oracle_raw_genome().readout.nodes)


def test_missing_window_reference_is_unmeasured_never_exact(small_split) -> None:  # type: ignore[no-untyped-def]
    rows = {r.target: r for r in expr.check_expressibility(small_split.dataset)}
    assert rows["phi-oracle-squashed"].exact is None
    assert "unmeasured" in rows["phi-oracle-squashed"].reason
    assert rows["deterministic-scorer/73/max_over_window"].exact is None
    with pytest.raises(ContractError):
        expr.check_expressibility(small_split.dataset, sessions=small_split.sessions[:-1])


def test_all_288_deterministic_scorers_construct_and_the_max_rows_are_exact(
    expressibility,  # type: ignore[no-untyped-def]
) -> None:
    rows = [r for t, r in expressibility.items() if t.startswith("deterministic-scorer/")]
    assert len(rows) == 288 == len(expr.deterministic_scorer_specs())
    assert all(row.expressible and row.genome_digest for row in rows)
    max_rows = [r for r in rows if r.target.endswith("/max_over_window")]
    assert len(max_rows) == 96 and all(r.exact is True for r in max_rows)
    # mean/last are defined over a different lineage partition; inexact rows say why.
    for row in rows:
        if row.exact is False:
            assert "actor_slot" in row.reason
    phi_as_scorer = expr.deterministic_scorer_genome(expr.deterministic_scorer_specs()[73 * 3 + 1])
    assert phi_as_scorer.digest == expr.phi_oracle_genome().digest


def test_reduced_tcn_is_exact_and_the_comparison_has_power(
    small_split, expressibility  # type: ignore[no-untyped-def]
) -> None:
    assert expressibility["reduced-tcn"].exact is True, expressibility["reduced-tcn"].reason
    weights, features = expr.REDUCED_TCN_DEFAULT_WEIGHTS, expr.REDUCED_TCN_DEFAULT_FEATURES
    genome = expr.reduced_tcn_genome(weights, features)
    assert genome.registers[0].ring == 3 and len(genome.update.nodes) <= 32
    # Dropping the t-2 tap must change the scores: the exactness check can see a wrong lag.
    no_lag2 = list(weights)
    no_lag2[len(features) + 2] = 0.0
    perturbed = expr.reduced_tcn_genome(no_lag2, features).phenotype().run_dataset(
        small_split.dataset)
    reference = [expr.reduced_tcn_reference(s, weights, features) for s in small_split.dataset]
    assert any(abs(run.score - ref) > 1e-9 for run, ref in zip(perturbed, reference, strict=True))


def test_reduced_tcn_refuses_out_of_family_arguments() -> None:
    weights = expr.REDUCED_TCN_DEFAULT_WEIGHTS
    with pytest.raises(ContractError):
        expr.reduced_tcn_genome((0.1,) * 11, (1, 2, 3, 4, 5))
    with pytest.raises(ContractError):
        expr.reduced_tcn_genome(weights[:-1], expr.REDUCED_TCN_DEFAULT_FEATURES)
    with pytest.raises(ContractError):
        expr.reduced_tcn_genome((math.nan, *weights[1:]), expr.REDUCED_TCN_DEFAULT_FEATURES)
    with pytest.raises(ContractError):
        expr.reduced_tcn_genome(weights, (73, 83, 85, 96))


def test_hand_designed_baselines_and_order_free_control_are_exact(
    expressibility,  # type: ignore[no-untyped-def]
) -> None:
    for target in ("H1", "H2", "order-free-control"):
        assert expressibility[target].exact is True, (target, expressibility[target].reason)
    assert expr.order_free_control_genome().aggregation is SessionAggregation.SUM
    h2 = expr.hand_designed_genomes()["H2"]
    assert [n.kind for n in h2.update.nodes] == [NodeKind.REG, NodeKind.INPUT, NodeKind.APPLY]


def test_full_stage2_tcn_is_reported_not_expressible(expressibility) -> None:  # type: ignore[no-untyped-def]
    row = expressibility["stage2-tcn-full"]
    assert row.expressible is False and row.exact is None and row.genome_digest is None
    assert str(expr.STAGE2_TCN_PARAMETERS) in row.reason and "MAX_CONSTANTS" in row.reason
    assert "NOT a measurement" in expr.STAGE2_TCN_BOUND_NOTE


def test_rank_identical_detects_order_and_tie_changes() -> None:
    assert expr.rank_identical([0.1, 0.5, 0.3], [1.0, 9.0, 4.0])
    assert not expr.rank_identical([0.1, 0.5, 0.3], [1.0, 3.0, 4.0])
    assert not expr.rank_identical([0.1, 0.1, 0.3], [1.0, 2.0, 4.0])  # a tie that is not one
    assert not expr.rank_identical([0.1], [0.1, 0.2])


# --- MSSC objective -------------------------------------------------------------------


def _v(ap: float | None, wu: int, state: int = 1000, dl: float = 10.0) -> mssc.ObjectiveVector:
    return mssc.ObjectiveVector(ap, wu, state, dl)


def test_dominance_uses_three_axes_and_not_description_length() -> None:
    assert mssc.dominates(_v(0.8, 3), _v(0.7, 3))
    assert mssc.dominates(_v(0.7, 2), _v(0.7, 3))
    assert mssc.dominates(_v(0.7, 3, 500), _v(0.7, 3, 1000))
    assert not mssc.dominates(_v(0.7, 3), _v(0.7, 3))  # equal: nobody strictly better
    assert not mssc.dominates(_v(0.8, 4), _v(0.7, 3))  # a trade-off
    assert not mssc.dominates(_v(0.7, 3, dl=1.0), _v(0.7, 3, dl=99.0))  # DL does not vote


def test_unmeasured_ap_never_dominates_and_is_never_on_a_front() -> None:
    assert not mssc.dominates(_v(None, 1, 1), _v(0.1, 64, 60000))
    assert not mssc.dominates(_v(0.99, 1, 1), _v(None, 64, 60000))
    front = mssc.pareto_front([("u", _v(None, 1)), ("a", _v(0.6, 3))])
    assert front == ("a",)


def test_pareto_front_is_stable_and_keeps_ties() -> None:
    points = [("tcn", _v(0.6, 40)), ("phi", _v(0.6, 3)), ("h2", _v(0.8, 3)),
              ("h2-copy", _v(0.8, 3)), ("cheap", _v(0.3, 1))]
    assert mssc.pareto_front(points) == ("h2", "h2-copy", "cheap")
    with pytest.raises(ContractError):
        mssc.pareto_front([("a", _v(0.5, 1)), ("a", _v(0.6, 1))])


def test_hypervolume_is_exact_on_hand_built_points() -> None:
    assert mssc.hypervolume_2d([_v(0.8, 4)], ap_ref=0.3, wu_ref=10) == pytest.approx(0.5 * 6)
    # Two overlapping boxes: 6x0.5 and 8x0.2 -> union 3.0 + (8-6)*0.2 = 3.4.
    two = [_v(0.8, 4), _v(0.5, 2)]
    assert mssc.hypervolume_2d(two, ap_ref=0.3, wu_ref=10) == pytest.approx(3.4)
    # A dominated point, an unmeasured point and points beyond the reference add nothing.
    noise = [*two, _v(0.4, 5), _v(None, 0), _v(0.2, 1), _v(0.9, 10)]
    assert mssc.hypervolume_2d(noise, ap_ref=0.3, wu_ref=10) == pytest.approx(3.4)
    assert mssc.hypervolume_2d([], ap_ref=0.3, wu_ref=10) == 0.0


def test_beats_requires_a_margin_a_clean_record_and_non_domination() -> None:
    base = _v(0.60, 3, 1184)
    win = mssc.beats(_v(0.63, 3, 1184), base, candidate_ok=True)
    assert win.beats and win.dimension == "worst_case_ap"
    assert not mssc.beats(_v(0.61, 3, 1184), base, candidate_ok=True).beats  # inside margin
    cheaper = mssc.beats(_v(0.50, 2, 1184), base, candidate_ok=True)
    assert cheaper.beats and cheaper.dimension == "wu_per_event"  # a genuine trade-off
    assert not mssc.beats(_v(0.63, 3, 1184), base, candidate_ok=False).beats
    assert not mssc.beats(_v(0.55, 4, 1184), base, candidate_ok=True).beats  # dominated
    assert not mssc.beats(_v(None, 1, 10), base, candidate_ok=True).beats
    assert not mssc.beats(_v(0.5, 0, 0), _v(0.5, 0, 0), candidate_ok=True).beats


def test_calibration_constraint_is_never_reported_satisfied() -> None:
    perfect = _v(1.0, 3, 1184)
    verdict = mssc.check_constraints(perfect, clean_ap=1.0, base_rate=0.33)
    assert verdict.violations == () and "calibration" in verdict.unmeasured
    assert verdict.satisfied is None  # never True while no calibrator exists
    with_kmin = mssc.MSSCConstraints(k_min=0.9)
    assert "calibration" in mssc.check_constraints(
        perfect, clean_ap=1.0, base_rate=0.33, constraints=with_kmin).unmeasured
    assert mssc.DEFAULT_CONSTRAINTS.k_min is None


def test_constraint_violations_are_named() -> None:
    bad = _v(0.35, 65, 70000)
    verdict = mssc.check_constraints(bad, clean_ap=0.9, base_rate=0.33)
    assert set(verdict.violations) == {"detection_quality", "robustness", "ram_bytes",
                                       "wu_per_event"}
    assert verdict.satisfied is False
    zero_clean = mssc.check_constraints(_v(0.5, 3), clean_ap=0.0, base_rate=0.33)
    assert "robustness" in zero_clean.unmeasured
    unmeasured = mssc.check_constraints(_v(None, 3), clean_ap=None, base_rate=0.33)
    assert {"detection_quality", "robustness"} <= set(unmeasured.unmeasured)


def test_objective_vectors_refuse_out_of_range_values() -> None:
    for args in ((1.5, 3, 1, 1.0), (0.5, -1, 1, 1.0), (0.5, 1, 1, math.inf), (0.5, True, 1, 1.0)):
        with pytest.raises(ContractError):
            mssc.ObjectiveVector(*args)  # type: ignore[arg-type]


def test_an_inert_mechanism_cannot_be_justified() -> None:
    flag = "pocketsec.stage9.ontogenesis.search:EVOLUTIONARY_SEARCH_DEFAULT_ENABLED"
    record = mssc.DetectorComparison(flag, "heldout worst-case AP", 0.7,
                                     (("random", 0.7), ("exhaustive", None)),
                                     mssc.MechanismVerdict.NOT_YET_JUSTIFIED, 0, "tie")
    assert record.inert
    with pytest.raises(ContractError, match="cannot be JUSTIFIED"):
        dataclasses.replace(record, verdict=mssc.MechanismVerdict.JUSTIFIED)
    with pytest.raises(ContractError):
        dataclasses.replace(record, controls=(("random",),))  # type: ignore[arg-type]


def test_mssc_statement_binds_the_architecture_objective() -> None:
    for term in ("worst-case AP", "Calibration", "UNMEASURED", "candidate", "Pareto"):
        assert term in mssc.MSSC_STATEMENT


# --- core ids -------------------------------------------------------------------------


def test_core_id_table_has_twenty_rows_in_order() -> None:
    ids = [f.core_id for f in core_ids.STAGE9_FUNCTIONS]
    assert ids == [f"ONTO-F{n:02d}" for n in range(1, 21)]
    assert core_ids.FunctionClass is FunctionClass
    assert core_ids.stage9_function("ONTO-F02").deliverable == "D9.2"
    with pytest.raises(ContractError):
        core_ids.stage9_function("ONTO-F21")


def test_optional_row_without_a_flag_is_refused() -> None:
    with pytest.raises(ContractError, match="could never be removed"):
        core_ids.Stage9Function("ONTO-F03", "LAPLACE", "D9.3", FunctionClass.OPTIONAL,
                                "pocketsec.stage9.laplace.state_discovery:discover_minimal_state",
                                (), ())


def test_every_flag_is_a_default_enabled_constant_with_a_control() -> None:
    triples = core_ids.optional_flags()
    assert len(triples) == 16
    assert all(flag.endswith("_DEFAULT_ENABLED") and control for _, flag, control in triples)
    optional = {f.core_id for f in core_ids.STAGE9_FUNCTIONS
                if f.function_class is FunctionClass.OPTIONAL}
    assert optional <= {core_id for core_id, _, _ in triples}
    assert ("ONTO-F15", "pocketsec.stage9.runtime.homeostatic:HYSTERESIS_DEFAULT_ENABLED",
            "no hysteresis") in triples


def test_symbol_resolution_is_lazy_and_refuses_foreign_paths() -> None:
    assert core_ids.symbol_problem("pocketsec.stage9.spec.mssc:check_constraints") is None
    assert core_ids.symbol_problem(
        "pocketsec.stage9.genome.computational:ComputationalGenomeV1") is None
    assert core_ids.symbol_problem("os:system").startswith("malformed")  # type: ignore[union-attr]
    assert "no attribute" in (core_ids.symbol_problem("pocketsec.stage9.spec.mssc:nope") or "")
    missing = core_ids.flag_problem("pocketsec.stage9.spec.mssc:NOPE_DEFAULT_ENABLED")
    assert missing is not None and "no attribute" in missing
    assert core_ids.flag_problem("pocketsec.stage9.spec.mssc:DEFAULT_CONSTRAINTS") is not None
    problems = core_ids.resolve_symbols()
    assert isinstance(problems, tuple)
    assert not any("spec.mssc" in p or "genome.computational" in p for p in problems)
