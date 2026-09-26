"""Stage 9 `laws` package: LAPLACE, CHRONOS, the primitive promotion gate, the observatory.

Every test is named after the invariant it protects. Splits are tiny (ambiguous corpus,
12-24 sessions) so the suite runs in seconds; nothing here is a quality figure.
"""

from __future__ import annotations

import math
from dataclasses import replace

import pytest

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage2.dataset import Stage2Dataset, Stage2Sample
from pocketsec.stage2.encoder.ssir_encoder import FEATURE_WIDTH, EncodedTransition
from pocketsec.stage6.resources import WorkMeter
from pocketsec.stage9.chemistry.phenotype import SessionAggregation
from pocketsec.stage9.chemistry.typed_ir import (
    InputSource,
    IRNode,
    IRProgram,
    IRType,
    NodeKind,
    ProgramPhase,
    RegisterSpec,
)
from pocketsec.stage9.chronos import forgetting_law as fl
from pocketsec.stage9.foundry import promotion as pr
from pocketsec.stage9.foundry.primitives import MacroBody
from pocketsec.stage9.genome.computational import ComputationalGenomeV1, build_genome
from pocketsec.stage9.genome.expressibility import hand_designed_genomes, phi_oracle_genome
from pocketsec.stage9.labs.splits import compile_variant
from pocketsec.stage9.laplace import law_discovery as ld
from pocketsec.stage9.laplace import state_discovery as sd
from pocketsec.stage9.observatory import convergence as cv
from pocketsec.stage9.ontogenesis.fitness import EvaluationSuite, FitnessRecord, evaluate
from pocketsec.stage9.ontogenesis.search import (
    SearchConfig,
    SearchRun,
    SearchStrategy,
    WinnerReport,
    run_search,
)
from pocketsec.stage9.spec.mssc import DEFAULT_CONSTRAINTS, MechanismVerdict

F, INT, BOOL = IRType.FLOAT, IRType.INT, IRType.BOOL


# --- builders -------------------------------------------------------------------------------------


def _reg(index: int, type_: IRType = F, lag: int = 0) -> IRNode:
    return IRNode(kind=NodeKind.REG, type=type_, index=index, lag=lag)


def _feature(index: int) -> IRNode:
    return IRNode(kind=NodeKind.INPUT, type=F, source=InputSource.FEATURE, index=index)


def _apply(primitive: str, *args: int, type_: IRType = F) -> IRNode:
    return IRNode(kind=NodeKind.APPLY, type=type_, primitive=primitive, args=args)


def _genome(
    update: list[IRNode],
    outputs: tuple[int, ...],
    readout: list[IRNode],
    registers: int,
    aggregation: SessionAggregation = SessionAggregation.MAX,
) -> ComputationalGenomeV1:
    return build_genome(
        registers=tuple(RegisterSpec(type=F, init=0.0) for _ in range(registers)),
        update=IRProgram(phase=ProgramPhase.UPDATE, nodes=tuple(update), outputs=outputs),
        readout=IRProgram(
            phase=ProgramPhase.READOUT, nodes=tuple(readout), outputs=(len(readout) - 1,)
        ),
        aggregation=aggregation,
    )


def _phi_plus_irrelevant() -> ComputationalGenomeV1:
    """r0 = running max of features[73] (read out); r1 = sum of features[83] (never read)."""
    update = [
        _reg(0),
        _feature(73),
        _apply("MAX", 0, 1),
        _reg(1),
        _feature(83),
        _apply("ADD", 3, 4),
    ]
    return _genome(update, (2, 5), [_reg(0)], registers=2)


def _phi_with_copy() -> ComputationalGenomeV1:
    """r0 and r2 both = running max of features[73], read out as MAX(r0, r2); r1 irrelevant."""
    update = [
        _reg(0),
        _feature(73),
        _apply("MAX", 0, 1),
        _reg(1),
        _feature(83),
        _apply("ADD", 3, 4),
        _reg(2),
        _apply("MAX", 6, 1),
    ]
    readout = [_reg(0), _reg(2), _apply("MAX", 0, 1)]
    return _genome(update, (2, 5, 7), readout, registers=3)


def _abs_abs_genome() -> ComputationalGenomeV1:
    """r0' = MAX(r0, ABS(ABS(features[73]))): contains the subgraph ABS(ABS(?F))."""
    update = [_reg(0), _feature(73), _apply("ABS", 1), _apply("ABS", 2), _apply("MAX", 0, 3)]
    return _genome(update, (4,), [_reg(0)], registers=1)


def _search_run(genome: ComputationalGenomeV1, record: FitnessRecord, seed: int) -> SearchRun:
    """A SearchRun built from its dataclass fields: one evaluated genome, which won."""
    return SearchRun(
        config=SearchConfig(strategy=SearchStrategy.EVOLUTIONARY, seed=seed, budget_wu=1),
        evaluations=1,
        cache_hits=0,
        wu_spent=0,
        budget_exhausted=False,
        records=(record,),
        genomes=(genome,),
        archive_elites=(),
        winner=0,
        operator_stats=(),
        population_evictions=0,
        fossils_recorded=0,
        fossils_avoided=0,
        determinism_digest="sha256:" + "0" * 64,
        rediscovered_phi=False,
        wall_seconds=0.0,
        loadavg_before=(0.0, 0.0, 0.0),
        loadavg_after=(0.0, 0.0, 0.0),
    )


def _step(slot: int, phi: float) -> EncodedTransition:
    features = [0.0] * FEATURE_WIDTH
    features[73] = phi
    return EncodedTransition(
        features=tuple(features),
        relation=0,
        relation_family=0,
        state_delta_mask=0,
        time_bucket=0,
        delta_phi=phi,
        object_property_mask=0,
        epoch_id=0,
        actor_slot=slot,
    )


def _hand_dataset(sessions: list[tuple[int, list[tuple[int, float]]]]) -> Stage2Dataset:
    samples = tuple(
        Stage2Sample(
            sample_id=f"hand-{i:04d}",
            steps=tuple(_step(s, p) for s, p in steps),
            label=label,
            technique=None,
            unseen_technique=False,
            final_phi=0.0,
        )
        for i, (label, steps) in enumerate(sessions)
    )
    return Stage2Dataset(
        name="hand",
        seed=0,
        corpus="hand",
        encoder_version="hand",
        feature_width=FEATURE_WIDTH,
        samples=samples,
    )


# --- fixtures -------------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def train() -> EvaluationSuite:
    return EvaluationSuite("laws-train", compile_variant(count=12, seed=3), ())


@pytest.fixture(scope="module")
def heldout() -> EvaluationSuite:
    return EvaluationSuite("laws-heldout", compile_variant(count=12, seed=11), ())


def _record(genome: ComputationalGenomeV1, suite: EvaluationSuite) -> FitnessRecord:
    return evaluate(genome, suite, meter=WorkMeter())


# --- LAPLACE: state -------------------------------------------------------------------------------


def test_freezing_an_irrelevant_register_flips_zero_decisions(train: EvaluationSuite) -> None:
    ablations = sd.state_sufficiency(_phi_plus_irrelevant(), train)
    assert [a.register for a in ablations] == [0, 1]
    irrelevant = ablations[1]
    assert irrelevant.decisions_flipped == 0
    assert irrelevant.unique_utility == 0.0
    # The isolating control: freezing the register the readout DOES read must flip decisions,
    # otherwise "0 flips" above would be a property of the measurement, not of the register.
    assert ablations[0].decisions_flipped > 0
    assert ablations[0].sessions == len(train.clean.dataset)


def test_freeze_register_keeps_the_register_and_reads_init(train: EvaluationSuite) -> None:
    frozen = sd.freeze_register(phi_oracle_genome(), 0)
    assert len(frozen.registers) == 1
    scores = sd.suite_scores(frozen, train)[0]
    assert set(scores) == {0.0}  # every read of r0 is its init value
    with pytest.raises(ContractError):
        sd.freeze_register(phi_oracle_genome(), 3)


def test_precision_sweep_is_monotone_in_bytes_and_every_point_carries_a_valid_genome(
    train: EvaluationSuite,
) -> None:
    base = phi_oracle_genome()
    points = sd.precision_sweep(base, train.clean.dataset)
    assert [p.bits for p in points] == list(sd.PRECISION_LEVELS)
    sizes = [p.state_bytes for p in points]
    assert sizes == sorted(sizes)
    assert sizes[0] < sizes[-1]  # precision actually changes the accounted bytes
    for point in points:
        assert isinstance(point.genome, ComputationalGenomeV1)
        assert point.genome.registers[0].precision_bits == point.bits
        assert ComputationalGenomeV1.from_dict(point.genome.to_dict()).digest == point.genome.digest
        assert point.genome.parent_digests == (base.digest,)
    full = points[-1]
    assert full.ap == sd._clean_ap(base, train.clean.dataset)  # 64 bits is the identity
    with pytest.raises(ContractError):
        sd.precision_sweep(base, train.clean.dataset, bits=())


def test_precision_sweep_does_not_move_a_genome_without_float_state(train: EvaluationSuite) -> None:
    points = sd.precision_sweep(hand_designed_genomes()["H2"], train.clean.dataset)
    assert len({p.state_bytes for p in points}) == 1
    assert len({p.ap for p in points}) == 1


def test_minimal_state_never_removes_a_register_whose_removal_flips_a_train_decision(
    train: EvaluationSuite,
    heldout: EvaluationSuite,
) -> None:
    genome = _phi_with_copy()
    found = sd.discover_minimal_state(genome, train, heldout)
    assert 1 in found.removed  # the never-read register goes
    assert len(found.registers_kept) == 1  # one of the two identical copies stays
    assert found.redundant_pairs == ((0, 2),)
    assert found.reason.startswith("HELDOUT_VERIFIED")
    assert found.state_bytes == found.minimal_genome.bounds.session_state_bytes_max
    # Independently: the minimal genome reproduces every train decision of the original ...
    threshold = sd.fit_threshold(train.labels, sd.suite_scores(genome, train)[0])
    original = [sd.decisions(s, threshold) for s in sd.suite_scores(genome, train)]
    minimal = [sd.decisions(s, threshold) for s in sd.suite_scores(found.minimal_genome, train)]
    assert original == minimal
    # ... and no kept register could have been removed without a flip (or at all).
    for position in range(len(found.minimal_genome.registers)):
        try:
            smaller = sd.remove_register(found.minimal_genome, position)
        except ContractError:
            continue
        again = [sd.decisions(s, threshold) for s in sd.suite_scores(smaller, train)]
        assert again != original


def test_removing_the_read_register_is_refused_when_it_flips_decisions(
    train: EvaluationSuite, heldout: EvaluationSuite
) -> None:
    found = sd.discover_minimal_state(_phi_plus_irrelevant(), train, heldout)
    assert found.registers_kept == (0,)
    assert found.removed == (1,)


def test_state_dimension_sweep_refuses_misaligned_records(train: EvaluationSuite) -> None:
    phi, h2 = phi_oracle_genome(), hand_designed_genomes()["H2"]
    records = [_record(phi, train), _record(_phi_plus_irrelevant(), train)]
    sweep = sd.state_dimension_sweep(records, [phi, _phi_plus_irrelevant()])
    assert [count for count, _ap in sweep] == [1, 2]
    with pytest.raises(ContractError):
        sd.state_dimension_sweep(records, [h2, _phi_plus_irrelevant()])
    with pytest.raises(ContractError):
        sd.state_dimension_sweep(records[:1], [phi, h2])


def test_a_single_class_split_cannot_fit_a_decision_threshold() -> None:
    with pytest.raises(ContractError):
        sd.fit_threshold([0, 0, 0], [0.1, 0.2, None])


# --- LAPLACE: laws --------------------------------------------------------------------------------


def test_apply_host_objective_returns_constraints_unchanged_and_refuses_relaxation() -> None:
    objective = ld.HostObjective(fn_weight=1.0, fp_weight=2.0, latency_weight=0.5, ram_weight=0.1)
    assert ld.apply_host_objective(objective, DEFAULT_CONSTRAINTS) is DEFAULT_CONSTRAINTS
    tighter = replace(DEFAULT_CONSTRAINTS, ram_bytes_max=1024, r_min=0.9)
    assert ld.apply_host_objective(objective, tighter) is tighter
    for loosened in (
        replace(DEFAULT_CONSTRAINTS, ram_bytes_max=DEFAULT_CONSTRAINTS.ram_bytes_max * 2),
        replace(DEFAULT_CONSTRAINTS, r_min=0.5),
        replace(DEFAULT_CONSTRAINTS, q_min_margin=0.0),
        replace(DEFAULT_CONSTRAINTS, wu_per_event_max=DEFAULT_CONSTRAINTS.wu_per_event_max + 1),
    ):
        with pytest.raises(ContractError, match="relax"):
            ld.apply_host_objective(objective, loosened)
    for bad in (-1.0, math.nan, math.inf):
        with pytest.raises(ContractError):
            ld.apply_host_objective(replace(objective, fn_weight=bad), DEFAULT_CONSTRAINTS)
    with pytest.raises(ContractError):
        ld.apply_host_objective(ld.HostObjective(0.0, 0.0, 0.0, 0.0), DEFAULT_CONSTRAINTS)


def test_adaptation_laws_decide_before_feedback_and_the_control_never_updates() -> None:
    # Prefix (first 25% = 2 sessions) fits the threshold; then a benign session scores high.
    scores = [0.1, 0.2, 0.9, 0.9, 0.9, 0.95, 0.1, 0.1]
    labels = [0, 0, 0, 0, 0, 1, 0, 0]
    control = ld.evaluate_adaptation(ld.AdaptationLaw.NO_LEARNING, scores, labels)
    assert control.updates_applied == 0
    assert control.benign_fp_rate == pytest.approx(3 / 5)
    proto = ld.evaluate_adaptation(ld.AdaptationLaw.PROTOTYPE_INSERT, scores, labels)
    # The first 0.9 is alerted (decided before its label), then suppressed afterwards.
    assert proto.updates_applied == 1
    assert proto.benign_fp_rate == pytest.approx(1 / 5)
    assert proto.recall == 1.0  # 0.95 is outside the prototype radius
    with pytest.raises(ContractError):
        ld.evaluate_adaptation(ld.AdaptationLaw.EWMA_THRESHOLD, scores, labels[:-1])


def test_compare_learning_laws_reports_a_verdict_and_ships_off() -> None:
    assert ld.LEARNING_LAW_SEARCH_DEFAULT_ENABLED is False
    comparison = ld.compare_learning_laws(phi_oracle_genome(), count=24, seed=11)
    assert comparison.mechanism.endswith(":LEARNING_LAW_SEARCH_DEFAULT_ENABLED")
    assert comparison.controls[0][0] == "NO_LEARNING"
    assert comparison.verdict in set(MechanismVerdict)
    if comparison.verdict is MechanismVerdict.JUSTIFIED:
        assert comparison.fired > 0
    assert (
        ld.law_from_comparison(
            replace(comparison, verdict=MechanismVerdict.NOT_YET_JUSTIFIED, fired=0),
            name="x",
            kind=ld.LawKind.ADAPTATION,
            statement="s",
            failure_domain="d",
        )
        is None
    )


# --- CHRONOS --------------------------------------------------------------------------------------


def test_every_memory_family_rebuilds_the_phi_oracle_and_int_bases_are_refused() -> None:
    phi = phi_oracle_genome()
    for family in fl.MemoryFamily:
        rebuilt = fl.memory_family_genome(family, phi)
        assert rebuilt.parent_digests == (phi.digest,)
        assert rebuilt.mutation == f"chronos-{family.value}"
    ring = fl.memory_family_genome(fl.MemoryFamily.EXACT_RING, phi, parameter=8)
    assert ring.registers[0].ring == 8
    assert len(fl.memory_family_genome(fl.MemoryFamily.MULTISCALE, phi).registers) == 2
    with pytest.raises(ContractError):
        fl.memory_family_genome(fl.MemoryFamily.ACCUMULATE, hand_designed_genomes()["H2"])
    with pytest.raises(ContractError):
        fl.memory_family_genome(fl.MemoryFamily.EXACT_RING, phi, parameter=2.5)


def test_counterfactual_deletion_counts_are_exact_on_a_hand_built_session() -> None:
    dataset = _hand_dataset(
        [
            (1, [(0, 0.9)]),  # alert; forgetting its only lineage leaves nothing -> no alert
            (0, [(0, 0.2)]),  # no alert either way
            (1, [(0, 0.9), (1, 0.9)]),  # the other lineage keeps 0.9: unchanged either way
            (0, [(0, 0.8)]),  # a false positive that the deletion removes: changed, benign
        ]
    )
    genome = phi_oracle_genome()
    one = fl.counterfactual_deletion(genome, dataset, seed=5, threshold=0.5)
    assert (one.deletions, one.decisions_changed, one.catastrophic) == (4, 2, 1)
    assert one.negligible is False
    three = fl.counterfactual_deletion(genome, dataset, seed=5, per_session=3, threshold=0.5)
    assert (three.deletions, three.decisions_changed, three.catastrophic) == (12, 6, 1)
    quiet = fl.counterfactual_deletion(
        genome,
        _hand_dataset([(1, [(0, 0.9), (1, 0.9)]), (0, [(0, 0.1), (1, 0.1)])]),
        seed=1,
        threshold=0.5,
    )
    assert quiet.decisions_changed == 0 and quiet.negligible is True
    with pytest.raises(ContractError):
        fl.counterfactual_deletion(genome, dataset, seed=5, per_session=0)


def test_evaluate_families_reports_every_family_with_bytes(
    train: EvaluationSuite, heldout: EvaluationSuite
) -> None:
    laws = fl.evaluate_families(phi_oracle_genome(), train, heldout)
    assert [law.family for law in laws] == [f.value for f in fl.MemoryFamily]
    for law in laws:
        assert law.bytes_per_lineage > 0
        if law.utility_per_byte is not None:
            assert law.heldout_worst_case_ap is not None
            expected = (law.heldout_worst_case_ap - heldout.base_rate) / law.bytes_per_lineage
            assert law.utility_per_byte == pytest.approx(expected)
    unbuildable = fl.evaluate_families(hand_designed_genomes()["H2"], train, heldout)
    assert all(law.bytes_per_lineage == 0 and law.utility_per_byte is None for law in unbuildable)
    assert fl.compare_forgetting(unbuildable).verdict is MechanismVerdict.UNMEASURED


def _law(family: fl.MemoryFamily, ap: float, size: int) -> fl.ForgettingLaw:
    return fl.ForgettingLaw(family.value, (), size, ap, (ap - 1 / 3) / size)


def test_compare_forgetting_needs_20pc_per_byte_at_equal_ap_and_refuses_saturation() -> None:
    assert fl.LEARNED_FORGETTING_DEFAULT_ENABLED is False
    control = _law(fl.MemoryFamily.EXACT_RING, 0.80, 128)
    better = _law(fl.MemoryFamily.EXPONENTIAL_DECAY, 0.795, 72)  # far cheaper, AP within 0.01
    lossy = _law(fl.MemoryFamily.ACCUMULATE, 0.70, 16)  # cheaper but loses 0.10 AP
    assert fl.compare_forgetting([control, better]).verdict is MechanismVerdict.JUSTIFIED
    only_lossy = fl.compare_forgetting([control, lossy])
    assert only_lossy.verdict is not MechanismVerdict.JUSTIFIED and only_lossy.fired == 0
    marginal = _law(fl.MemoryFamily.PROTOTYPE, 0.80, 120)  # < 20% better per byte
    assert fl.compare_forgetting([control, marginal]).verdict is MechanismVerdict.NOT_YET_JUSTIFIED
    saturated = fl.compare_forgetting(
        [
            _law(fl.MemoryFamily.EXACT_RING, 1.0, 128),
            _law(fl.MemoryFamily.EXPONENTIAL_DECAY, 1.0, 72),
        ]
    )
    assert saturated.verdict is MechanismVerdict.NOT_YET_JUSTIFIED
    assert saturated.detail.startswith("SATURATED")


# --- the promotion gate ---------------------------------------------------------------------------


def test_canonical_subgraphs_sort_commutative_arguments_and_abstract_operands() -> None:
    a = _genome([_reg(0), _feature(73), _apply("ABS", 1), _apply("MAX", 0, 2)], (3,), [_reg(0)], 1)
    b = _genome([_reg(0), _feature(73), _apply("ABS", 1), _apply("MAX", 2, 0)], (3,), [_reg(0)], 1)
    assert pr.canonical_subgraphs(a) == pr.canonical_subgraphs(b) == frozenset({"MAX(?F,ABS(?F))"})
    assert pr.canonical_subgraphs(phi_oracle_genome()) == frozenset()  # one APPLY node only
    with pytest.raises(ContractError):
        pr.canonical_subgraphs(a, max_nodes=1)


def test_reproduces_seed_detects_a_seed_primitive_and_a_projection_but_not_a_new_function() -> None:
    def body(params: tuple[IRType, ...], nodes: list[IRNode]) -> MacroBody:
        return MacroBody(params=params, nodes=tuple(nodes), output=len(nodes) - 1)

    param = lambda t, i: IRNode(kind=NodeKind.PARAM, type=t, index=i)  # noqa: E731
    abs_abs = body((F,), [param(F, 0), _apply("ABS", 0), _apply("ABS", 1)])
    not_not = body(
        (INT,), [param(INT, 0), _apply("NOT", 0, type_=INT), _apply("NOT", 1, type_=INT)]
    )
    max_abs = body((F, F), [param(F, 0), param(F, 1), _apply("ABS", 1), _apply("MAX", 0, 2)])
    assert pr.reproduces_seed(abs_abs) is True  # == ABS
    assert pr.reproduces_seed(not_not) is True  # == a projection
    assert pr.reproduces_seed(max_abs) is False


def test_a_subgraph_equal_to_one_seed_primitive_is_refused_as_reproducing_the_dsl(
    train: EvaluationSuite,
    heldout: EvaluationSuite,
) -> None:
    genome = _abs_abs_genome()
    record = _record(genome, train)
    runs = [_search_run(genome, record, 101), _search_run(genome, record, 202)]
    decisions = {d.candidate.canonical: d for d in pr.promotion_gate(runs, heldout)}
    refused = decisions["ABS(ABS(?F))"]
    assert refused.verdict is pr.PromotionVerdict.REFUSED_REPRODUCES_DSL
    assert refused.candidate.runs_containing == 2
    assert refused.candidate.reproduces_seed is True
    assert refused.candidate.unique_contribution is None  # the gate stopped before ablation
    # MAX(?F,ABS(?F)) is a new function, but on features[73] >= 0 the ABS changes nothing,
    # so its best substitute MAX matches it and the ablation refuses it.
    ablated = decisions["MAX(?F,ABS(?F))"]
    assert ablated.verdict is pr.PromotionVerdict.REFUSED_ABLATION
    assert ablated.candidate.unique_contribution is not None
    assert ablated.candidate.unique_contribution < pr.UNIQUE_CONTRIBUTION_MIN
    assert not any(d.verdict is pr.PromotionVerdict.PROMOTED for d in decisions.values())


def test_a_subgraph_seen_in_one_of_three_runs_is_refused_on_convergence(
    train: EvaluationSuite,
    heldout: EvaluationSuite,
) -> None:
    abs_abs, phi, h2 = _abs_abs_genome(), phi_oracle_genome(), hand_designed_genomes()["H2"]
    runs = [
        _search_run(abs_abs, _record(abs_abs, train), 101),
        _search_run(phi, _record(phi, train), 202),
        _search_run(h2, _record(h2, train), 303),
    ]
    decisions = pr.promotion_gate(runs, heldout)
    assert decisions
    for decision in decisions:
        assert decision.verdict is pr.PromotionVerdict.REFUSED_CONVERGENCE
        assert decision.candidate.runs_containing == 1
        assert decision.candidate.runs_reachable == 3
    conv = cv.convergence(runs, "ABS(ABS(?F))")
    assert (conv.runs_containing, conv.runs_reachable) == (1, 3)
    assert conv.value == pytest.approx(1 / 3)


def test_the_foundry_is_inert_without_promotions_and_unmeasured_without_its_arm() -> None:
    assert pr.PRIMITIVE_FOUNDRY_DEFAULT_ENABLED is False
    body = MacroBody(
        params=(F, F),
        nodes=(
            IRNode(kind=NodeKind.PARAM, type=F, index=0),
            IRNode(kind=NodeKind.PARAM, type=F, index=1),
            _apply("ABS", 1),
            _apply("MAX", 0, 2),
        ),
        output=3,
    )
    candidate = pr.PrimitiveCandidate("MAX(?F,ABS(?F))", body, 3, 3, 0.2, True, 10.0, False, True)
    refused = pr.PromotionDecision(candidate, pr.PromotionVerdict.REFUSED_CROSS_EPOCH, ("x",))
    promoted = pr.PromotionDecision(candidate, pr.PromotionVerdict.PROMOTED, ("y",))
    inert = pr.compare_foundry([refused])
    assert inert.verdict is MechanismVerdict.NOT_YET_JUSTIFIED and inert.fired == 0
    assert pr.compare_foundry([promoted]).verdict is MechanismVerdict.UNMEASURED
    assert pr.promoted_macros([refused, promoted]) == ((pr.macro_name(candidate.canonical), body),)


# --- the observatory ------------------------------------------------------------------------------


def _perfect_decision() -> pr.PromotionDecision:
    body = MacroBody(
        params=(F, F),
        nodes=(
            IRNode(kind=NodeKind.PARAM, type=F, index=0),
            IRNode(kind=NodeKind.PARAM, type=F, index=1),
            _apply("ABS", 1),
            _apply("MAX", 0, 2),
        ),
        output=3,
    )
    candidate = pr.PrimitiveCandidate("MAX(?F,ABS(?F))", body, 3, 3, 0.5, True, 25.0, False, True)
    return pr.PromotionDecision(
        candidate, pr.PromotionVerdict.PROMOTED, ("every refusal examined",)
    )


def test_law_gate_never_yields_a_candidate_law_while_cross_host_is_unmeasured(
    train: EvaluationSuite,
) -> None:
    genome = _genome(
        [_reg(0), _feature(73), _apply("ABS", 1), _apply("MAX", 0, 2)], (3,), [_reg(0)], 1
    )
    record = _record(genome, train)
    runs = [_search_run(genome, record, seed) for seed in (101, 202, 303)]
    winners = [WinnerReport(r.label, genome.digest, 0.9, 0.9, 0.9, 0.0, 3, 1088) for r in runs]
    hand = {"phi-oracle": replace(record, worst_case_ap=0.5)}
    (law,) = cv.law_gate([_perfect_decision()], runs, winners=winners, hand=hand)
    # Every other criterion is measured and met; only cross-host is unmeasurable.
    assert law.criteria() == (True, None, True, True, True, True, True)
    assert law.cross_host is None
    assert law.status is cv.LawStatus.UNMEASURABLE
    with pytest.raises(ContractError):
        replace(law, status=cv.LawStatus.CANDIDATE_LAW)
    (refused,) = cv.law_gate(
        [
            replace(
                _perfect_decision(),
                candidate=replace(_perfect_decision().candidate, runs_containing=1),
            )
        ],
        runs,
    )
    assert refused.status is cv.LawStatus.REFUSED
    assert refused.beats_simple_baseline is None  # no hand baselines given


def test_decay_confidence_decays_without_support_and_is_clipped() -> None:
    start = cv.initial_confidence("MAX(?F,ABS(?F))")
    decayed = cv.decay_confidence(start, steps=100, reproductions=0, contradictions=0)
    assert decayed.confidence == pytest.approx(math.exp(-1.0))
    assert decayed.unsupported_steps == 100
    further = cv.decay_confidence(decayed, steps=100, reproductions=0, contradictions=0)
    assert further.confidence == pytest.approx(math.exp(-2.0))
    assert further.unsupported_steps == 200
    supported = cv.decay_confidence(further, steps=100, reproductions=50, contradictions=0)
    assert supported.confidence == 1.0 and supported.unsupported_steps == 0
    crushed = cv.decay_confidence(start, steps=0, reproductions=0, contradictions=50)
    assert crushed.confidence == 0.0
    assert decayed.half_life_steps == round(math.log(2) / cv.DEFAULT_LAMBDA)
    with pytest.raises(ContractError):
        cv.decay_confidence(start, steps=-1, reproductions=0, contradictions=0)
    with pytest.raises(ContractError):
        cv.decay_confidence(start, steps=1, reproductions=0, contradictions=0, lam=0.0)


@pytest.fixture(scope="module")
def tiny_runs(train: EvaluationSuite) -> tuple[SearchRun, ...]:
    return tuple(
        run_search(
            SearchConfig(strategy=SearchStrategy.EVOLUTIONARY, seed=s, budget_wu=60_000), train
        )
        for s in (101, 202)
    )


def test_meta_falsify_and_archaeology_read_only_the_records(
    tiny_runs: tuple[SearchRun, ...],
    train: EvaluationSuite,
) -> None:
    verdicts = cv.meta_falsify(tiny_runs, (), {})
    assert [v.doctrine for v in verdicts] == [d.value for d in cv.Doctrine]
    learned = verdicts[2]
    assert learned.supported is None  # no winners and no hand records: unmeasured, not False
    phi = phi_oracle_genome()
    hand = {"phi-oracle": _record(phi, train)}
    winners = [WinnerReport("w", "sha256:" + "1" * 64, 0.4, 0.4, 0.4, 0.0, 3, 1000)]
    assert cv.meta_falsify(tiny_runs, winners, hand)[2].supported is (
        hand["phi-oracle"].worst_case_ap + 0.02 <= 0.4
    )
    dig = cv.archaeology(tiny_runs)
    assert len(dig.regressing_operators) <= pr.MAX_CANDIDATES
    assert all(count > 0 for _op, count in dig.regressing_operators)
    assert all(count >= 2 for _c, count in dig.re_evolved)
