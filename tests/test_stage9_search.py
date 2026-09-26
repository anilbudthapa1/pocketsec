"""Stage 9 search package: GENESIS variation, GAIA ecology, the ONTOGENESIS controller.

Every test is named after the invariant it protects. The splits are tiny (ambiguous corpus,
12 sessions) and the budgets small, so these tests check *behaviour and bounds*, never
detection quality: a 12-session split is saturated and no AP here is a result.
"""

from __future__ import annotations

import random
from dataclasses import replace

import pytest

from pocketsec.stage0.contracts.common import ContractError
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
from pocketsec.stage9.foundry.primitives import SEED_ALPHABET, MacroBody
from pocketsec.stage9.gaia import qd_ecology as gaia
from pocketsec.stage9.gaia.qd_ecology import (
    CELL_COUNT,
    ArchiveOutcome,
    ComputationalFossil,
    FossilReason,
    FossilStore,
    NicheKey,
    QualityDiversityArchive,
    hypothesis_explosion,
    niche_of,
    parasites,
    synergy,
)
from pocketsec.stage9.genesis.variation import (
    REFUSED_NO_BACKEND,
    REFUSED_NO_MACRO,
    Mutation,
    VariationOperator,
    ablate_node,
    crossover,
    mutate,
    random_genome,
    unique_utility,
)
from pocketsec.stage9.genome.computational import ComputationalGenomeV1, build_genome
from pocketsec.stage9.genome.expressibility import hand_designed_genomes, phi_oracle_genome
from pocketsec.stage9.labs.splits import compile_variant
from pocketsec.stage9.ontogenesis import search as search_module
from pocketsec.stage9.ontogenesis.fitness import (
    EvaluationCache,
    EvaluationSuite,
    FitnessRecord,
    evaluate,
)
from pocketsec.stage9.ontogenesis.search import (
    EXHAUSTIVE_SIZE,
    INITIAL_POPULATION,
    NullVerdict,
    SearchConfig,
    SearchStrategy,
    WinnerReport,
    compare_arm,
    enumerate_exhaustive,
    null_verdict,
    run_search,
    run_shuffled_label_control,
    strategy_verdict,
)
from pocketsec.stage9.spec.mssc import MechanismVerdict

TINY_COUNT = 12
ATTACK = "rename_binaries"
#: Enough for the evolutionary arm to finish its 32 random genomes and run variation.
LOOP_BUDGET = 900_000
SMALL_BUDGET = 150_000


def _suite(name: str, seed: int) -> EvaluationSuite:
    clean = compile_variant(count=TINY_COUNT, seed=seed)
    attacked = compile_variant(count=TINY_COUNT, seed=seed, attack_id=ATTACK)
    return EvaluationSuite(name=name, clean=clean, attacked=(attacked,))


@pytest.fixture(scope="module")
def train() -> EvaluationSuite:
    return _suite("tiny-train", 3)


@pytest.fixture(scope="module")
def heldout() -> EvaluationSuite:
    return _suite("tiny-heldout", 11)


# --------------------------------------------------------------------------- genomes


def _apply(kind: IRType, name: str, *args: int) -> IRNode:
    return IRNode(kind=NodeKind.APPLY, type=kind, primitive=name, args=args)


def _reg(index: int, kind: IRType = IRType.FLOAT, lag: int = 0) -> IRNode:
    return IRNode(kind=NodeKind.REG, type=kind, index=index, lag=lag)


def _feature(index: int) -> IRNode:
    return IRNode(kind=NodeKind.INPUT, type=IRType.FLOAT, source=InputSource.FEATURE, index=index)


def _const(value: float) -> IRNode:
    return IRNode(kind=NodeKind.CONST, type=IRType.FLOAT, value=value)


def _seeded_genome() -> ComputationalGenomeV1:
    """A genome built so every operator has a site: a duplicate node (MERGE), a shared node
    (SPLIT), an all-CONST APPLY (SPECIALIZE), inputs (SPARSIFY), a ring-2 register
    (COMPRESS) and a readout APPLY over registers (FACTORIZE)."""
    dphi = IRNode(kind=NodeKind.INPUT, type=IRType.FLOAT, source=InputSource.DELTA_PHI)
    update = (
        _reg(0), _feature(73), _apply(IRType.FLOAT, "MAX", 0, 1),         # 0-2: Φ-oracle core
        dphi, _apply(IRType.FLOAT, "ABS", 3), _apply(IRType.FLOAT, "ABS", 3),  # 3-5: duplicate
        _apply(IRType.FLOAT, "ADD", 4, 5), _const(2.0), _const(0.5),      # 6-8
        _apply(IRType.FLOAT, "MUL", 7, 8), _apply(IRType.FLOAT, "ADD", 6, 9),  # 9-10: foldable
        _reg(1, lag=1), _apply(IRType.FLOAT, "MAX", 11, 10),              # 11-12
    )
    readout = (_reg(0), _reg(1), _apply(IRType.FLOAT, "ADD", 0, 1))
    return build_genome(
        registers=(RegisterSpec(type=IRType.FLOAT), RegisterSpec(type=IRType.FLOAT, ring=2)),
        update=IRProgram(phase=ProgramPhase.UPDATE, nodes=update, outputs=(2, 12)),
        readout=IRProgram(phase=ProgramPhase.READOUT, nodes=readout, outputs=(2,)),
        aggregation=SessionAggregation.MAX,
    )


def _macro_alphabet():  # type: ignore[no-untyped-def]
    param = [IRNode(kind=NodeKind.PARAM, type=IRType.FLOAT, index=i) for i in range(2)]
    body = MacroBody(
        params=(IRType.FLOAT, IRType.FLOAT),
        nodes=(*param, _apply(IRType.FLOAT, "ADD", 0, 1), _const(0.0),
               _apply(IRType.FLOAT, "MAX", 2, 3)),
        output=4,
    )
    return SEED_ALPHABET.with_macro("RELU_ADD", body)


def _first_valid(genome, operator, *, alphabet=SEED_ALPHABET, tries: int = 200) -> Mutation:  # type: ignore[no-untyped-def]
    last = None
    for seed in range(tries):
        last = mutate(genome, operator, random.Random(seed), alphabet=alphabet)
        if last.child is not None:
            return last
    assert last is not None
    return last


# --------------------------------------------------------------------------- variation


def test_move_is_refused_every_time_because_there_is_one_backend() -> None:
    rng = random.Random(5)
    genomes = [random_genome(rng) for _ in range(40)] + [_seeded_genome(), phi_oracle_genome()]
    results = [mutate(g, VariationOperator.MOVE, rng) for g in genomes]
    assert all(m.child is None and m.refused_reason == REFUSED_NO_BACKEND for m in results)


@pytest.mark.parametrize(
    "operator",
    [op for op in VariationOperator if op not in (VariationOperator.MOVE,
                                                  VariationOperator.MACRO_INSERT)],
)
def test_every_other_operator_produces_a_valid_child_on_a_seeded_genome(
    operator: VariationOperator,
) -> None:
    parent = _seeded_genome()
    mutation = _first_valid(parent, operator)
    assert mutation.child is not None, mutation.refused_reason
    assert mutation.child.digest != parent.digest
    assert parent.digest in mutation.child.parent_digests
    assert mutation.child.mutation == operator.value


def test_macro_insert_runs_only_when_the_alphabet_holds_a_promoted_primitive() -> None:
    parent = _seeded_genome()
    refused = mutate(parent, VariationOperator.MACRO_INSERT, random.Random(0))
    assert refused.child is None and refused.refused_reason == REFUSED_NO_MACRO
    used = _first_valid(parent, VariationOperator.MACRO_INSERT, alphabet=_macro_alphabet())
    assert used.child is not None, used.refused_reason
    assert "RELU_ADD" in used.child.macro_uses
    # Stored expanded: the child validates against the SEED alphabet alone.
    assert all(n.primitive in SEED_ALPHABET.names() for n in used.child.update.nodes if n.primitive)


def test_two_parent_crossover_grafts_a_typed_subtree_and_records_both_parents() -> None:
    a, b = _seeded_genome(), phi_oracle_genome()
    children = [crossover(a, b, random.Random(s)).child for s in range(60)]
    valid = [c for c in children if c is not None]
    assert valid
    assert all({a.digest, b.digest} <= set(c.parent_digests) for c in valid)


def test_an_invalid_child_is_refused_with_the_ir_code_never_repaired() -> None:
    # INT register, ring 2, read ONLY at lag 1: the only COMPRESS move drops the ring to 1,
    # which makes the lag-1 read out of bounds. The IR must refuse it.
    reg = RegisterSpec(type=IRType.INT, ring=2)
    mask = IRNode(kind=NodeKind.INPUT, type=IRType.INT, source=InputSource.STATE_DELTA_MASK)
    parent = build_genome(
        registers=(reg,),
        update=IRProgram(phase=ProgramPhase.UPDATE,
                         nodes=(_reg(0, IRType.INT, lag=1), mask, _apply(IRType.INT, "OR", 0, 1)),
                         outputs=(2,)),
        readout=IRProgram(phase=ProgramPhase.READOUT,
                          nodes=(_reg(0, IRType.INT), _apply(IRType.FLOAT, "POPCOUNT", 0)),
                          outputs=(1,)),
        aggregation=SessionAggregation.MAX,
    )
    mutation = mutate(parent, VariationOperator.COMPRESS, random.Random(0))
    assert mutation.child is None
    assert mutation.refused_reason.startswith("LAG_BOUND")


def test_a_mutation_carries_exactly_one_of_child_or_reason() -> None:
    with pytest.raises(ContractError):
        Mutation(VariationOperator.REMOVE, None, "")
    with pytest.raises(ContractError):
        Mutation(VariationOperator.REMOVE, phi_oracle_genome(), "why")


def test_random_genome_is_deterministic_per_seed_and_refuses_bad_shapes() -> None:
    first = [random_genome(random.Random(9)).digest for _ in range(3)]
    assert len(set(first)) == 1
    with pytest.raises(ContractError):
        random_genome(random.Random(0), max_registers=0)
    with pytest.raises(ContractError):
        random_genome(random.Random(0), max_depth=-1)


def test_unique_utility_is_positive_for_every_node_the_phi_oracle_needs(
    train: EvaluationSuite,
) -> None:
    phi = phi_oracle_genome()
    meter = WorkMeter()
    # flat index 2 is the update's MAX: without it the register never moves.
    assert (unique_utility(phi, 2, train, meter=meter) or 0.0) > 0.0
    assert meter.spent > 0
    assert ablate_node(phi, 1) is not None  # INPUT -> CONST 0 is a valid ablation
    with pytest.raises(ContractError):
        ablate_node(phi, 99)
    elite = QualityDiversityArchive().insert(phi, evaluate(phi, train, meter=WorkMeter()))[1]
    assert elite is not None
    assert parasites(elite, train, meter=WorkMeter()) == ()


# --------------------------------------------------------------------------- GAIA


def _record(genome: ComputationalGenomeV1, ap: float | None, **changes: object) -> FitnessRecord:
    record = gaia._synthetic_record(genome, 0.5)
    return replace(record, worst_case_ap=ap, clean_ap=ap, **changes)


def test_the_niched_archive_has_504_cells_and_niche_keys_refuse_out_of_range_bins() -> None:
    assert CELL_COUNT == 504
    assert QualityDiversityArchive(niches=True).cell_bound == 504
    assert QualityDiversityArchive().cell_bound == 1  # shipped default: single cell
    with pytest.raises(ContractError):
        NicheKey(wu_bin=7, bytes_bin=0, stateful=False, size_bin=0)
    assert niche_of(phi_oracle_genome()).stateful


def test_single_cell_archive_replaces_only_on_improvement_and_never_keeps_unmeasured() -> None:
    archive = QualityDiversityArchive()
    a, b = phi_oracle_genome(), hand_designed_genomes()["H2"]
    assert archive.insert(a, _record(a, None))[0] is ArchiveOutcome.REJECTED_WORSE
    assert archive.insert(a, _record(a, 0.5))[0] is ArchiveOutcome.NEW_CELL
    assert archive.insert(b, _record(b, 0.4))[0] is ArchiveOutcome.REJECTED_WORSE
    assert archive.insert(b, _record(b, 0.6))[0] is ArchiveOutcome.IMPROVED
    assert archive.occupied() == 1 and archive.elites()[0].genome.digest == b.digest
    with pytest.raises(ContractError):
        archive.insert(a, _record(b, 0.9))  # a record for another genome


@pytest.mark.parametrize("niches", [False, True])
def test_archive_never_exceeds_its_cell_bound_under_hypothesis_explosion(niches: bool) -> None:
    holder: list[QualityDiversityArchive] = []

    def factory() -> QualityDiversityArchive:
        holder.append(QualityDiversityArchive(niches=niches))
        return holder[0]

    finding = hypothesis_explosion(factory)
    bound = holder[0].cell_bound
    assert finding.kind == "DEFENCE"
    assert finding.total == 10 * bound
    assert finding.fired == finding.total
    assert holder[0].occupied() <= bound


def test_hypothesis_explosion_catches_an_archive_that_lies_about_its_bound() -> None:
    class Lying(QualityDiversityArchive):
        __slots__ = ()

        @property
        def cell_bound(self) -> int:  # claims one cell while binning into 504
            return 1

    finding = hypothesis_explosion(lambda: Lying(niches=True))
    assert finding.fired < finding.total  # the DEFENCE failed and says so


def test_fossil_store_is_bounded_and_counts_evictions_and_avoidance() -> None:
    store = FossilStore(capacity=2)
    for name in ("sha256:a", "sha256:b", "sha256:c"):
        store.add(ComputationalFossil(name, None, (), (), FossilReason.DOMINATED,
                                      None, None, None, ()))
    assert len(store) == 2 and store.evictions == 1
    assert "sha256:a" not in store and "sha256:c" in store
    assert store.avoid("sha256:c") and not store.avoid("sha256:zz")
    assert store.avoided == 1


def test_an_archive_with_fossils_rejects_a_fossilised_genome() -> None:
    phi = phi_oracle_genome()
    store = FossilStore()
    store.add(ComputationalFossil(phi.digest, None, (), (), FossilReason.ARGUS_FAILURE,
                                  "rename_binaries", None, 0.2, ()))
    archive = QualityDiversityArchive(fossils=store)
    assert archive.insert(phi, _record(phi, 0.9))[0] is ArchiveOutcome.REJECTED_FOSSIL
    assert archive.occupied() == 0 and store.avoided == 1


def test_synergy_follows_the_architecture_formula_and_abstains_without_positives() -> None:
    labels = [1, 0, 1, 0]
    a, b = [0.9, 0.1, 0.2, 0.3], [0.2, 0.3, 0.9, 0.1]
    value = synergy(a, b, labels)
    assert value is not None and value < 1.0
    assert synergy(a, b, [0, 0, 0, 0]) is None
    with pytest.raises(ContractError):
        synergy(a, b[:3], labels)


# --------------------------------------------------------------------------- search


def test_search_config_defaults_read_the_shipped_flags_all_off() -> None:
    config = SearchConfig(strategy=SearchStrategy.EVOLUTIONARY, seed=101)
    assert config.niches is gaia.QD_ARCHIVE_DEFAULT_ENABLED is False
    assert config.fossil_avoidance is gaia.FOSSIL_AVOIDANCE_DEFAULT_ENABLED is False
    assert config.subtractive is search_module.SUBTRACTIVE_BIAS_DEFAULT_ENABLED is False
    assert search_module.EVOLUTIONARY_SEARCH_DEFAULT_ENABLED is False
    with pytest.raises(ContractError):
        SearchConfig(strategy=SearchStrategy.RANDOM, seed=1, budget_wu=-1)


def test_enumerate_exhaustive_has_exactly_126_and_contains_phi_and_h2_by_digest() -> None:
    genomes = enumerate_exhaustive()
    digests = {g.digest for g in genomes}
    assert len(genomes) == EXHAUSTIVE_SIZE == 126 == len(digests)
    assert phi_oracle_genome().digest in digests
    assert hand_designed_genomes()["H2"].digest in digests


def test_same_seed_gives_the_same_determinism_digest(train: EvaluationSuite) -> None:
    config = SearchConfig(strategy=SearchStrategy.EVOLUTIONARY, seed=101, budget_wu=LOOP_BUDGET)
    first, second = run_search(config, train), run_search(config, train)
    assert first.determinism_digest == second.determinism_digest
    assert [r.genome_digest for r in first.records] == [r.genome_digest for r in second.records]
    other = run_search(replace(config, seed=202), train)
    assert other.determinism_digest != first.determinism_digest
    # The variation loop actually ran (lesson 1: prove the mechanism fires).
    assert sum(s.proposed for s in first.operator_stats) > 0


@pytest.mark.parametrize("strategy", list(SearchStrategy))
def test_the_work_budget_is_never_exceeded(
    train: EvaluationSuite, strategy: SearchStrategy
) -> None:
    run = run_search(SearchConfig(strategy=strategy, seed=303, budget_wu=SMALL_BUDGET), train)
    assert run.wu_spent <= run.config.budget_wu
    assert run.budget_exhausted and run.stop_reason == "WORK_BUDGET_EXCEEDED"
    assert all(wu <= SMALL_BUDGET for wu in run.wu_at_record)
    empty = run_search(SearchConfig(strategy=strategy, seed=303, budget_wu=0), train)
    assert empty.evaluations == 0 and empty.wu_spent == 0 and empty.winner is None


def test_a_cache_hit_costs_zero_work_units(train: EvaluationSuite) -> None:
    meter, cache = WorkMeter(), EvaluationCache()
    genome = hand_designed_genomes()["H2"]
    evaluate(genome, train, meter=meter, cache=cache)
    spent = meter.spent
    assert spent > 0
    evaluate(genome, train, meter=meter, cache=cache)
    assert meter.spent == spent and cache.hits == 1


def test_exhaustive_reports_its_true_spend_and_rediscovers_the_phi_oracle(
    train: EvaluationSuite,
) -> None:
    budget = 10**9
    config = SearchConfig(strategy=SearchStrategy.EXHAUSTIVE, seed=0, budget_wu=budget)
    run = run_search(config, train)
    assert run.evaluations == 126 and run.stop_reason == "EXHAUSTED_SPACE"
    assert 0 < run.wu_spent < budget and not run.budget_exhausted
    assert run.rediscovered_phi


@pytest.mark.parametrize("seed", search_module.SEARCH_SEEDS)
def test_no_population_is_seeded_with_the_phi_oracle_or_hand_rules(
    train: EvaluationSuite, seed: int
) -> None:
    forbidden = {phi_oracle_genome().digest} | {g.digest for g in hand_designed_genomes().values()}
    config = SearchConfig(strategy=SearchStrategy.EVOLUTIONARY, seed=seed, budget_wu=LOOP_BUDGET)
    run = run_search(config, train)
    assert run.initial_records == INITIAL_POPULATION
    initial = {g.digest for g in run.genomes[: run.initial_records]}
    assert not initial & forbidden


def test_fossil_avoidance_skips_fossil_digests_and_counts_them(train: EvaluationSuite) -> None:
    base = SearchConfig(strategy=SearchStrategy.EVOLUTIONARY, seed=202, budget_wu=2_000_000)
    off = run_search(base, train)
    on = run_search(replace(base, fossil_avoidance=True), train)
    assert off.fossils_avoided == 0
    assert on.fossils_avoided > 0
    assert on.fossils_recorded > 0


def _trajectory(run: search_module.SearchRun) -> tuple[object, ...]:
    return (tuple(r.genome_digest for r in run.records), run.wu_at_record, run.winner,
            run.wu_spent, run.evaluations)


def test_fossil_avoidance_changes_no_outcome_and_is_rejected_as_inert(
    train: EvaluationSuite, heldout: EvaluationSuite
) -> None:
    """Pins S9-R1 / S9-CX-05: skipping a fossil is not an outcome change.

    A fossil is always a digest the run already recorded, which the main arm also refuses at
    0 WU with no rng draw, so the two arms must replay the same trajectory. ``fired`` used to
    report the skip count (non-zero) for a mechanism that changed nothing.
    """
    mains, arms = [], []
    for seed in (101, 202):
        base = SearchConfig(strategy=SearchStrategy.EVOLUTIONARY, seed=seed, budget_wu=2_000_000)
        mains.append(run_search(base, train))
        arms.append(run_search(replace(base, fossil_avoidance=True), train))
    assert sum(a.fossils_avoided for a in arms) > 0  # the skip path really ran
    for main, arm in zip(mains, arms, strict=True):
        assert _trajectory(main) == _trajectory(arm)
    comparison = compare_arm(mains, arms, heldout, flag="fossil_avoidance")
    assert comparison.fired == 0 and comparison.inert
    assert comparison.verdict is MechanismVerdict.REJECTED
    assert comparison.detail.startswith("INERT")


def test_a_re_proposed_digest_is_never_evaluated_again(
    train: EvaluationSuite, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pins S9-R7 / S9-CX-07: the known-digest check runs BEFORE evaluation.

    Checking after ``evaluate`` meant a duplicate that had fallen out of the bounded cache was
    re-scored at full suite cost and then thrown away, taxing evolution (which re-proposes
    most) in an equal-budget comparison.
    """
    evaluated: list[str] = []
    real = search_module.evaluate

    def counting(genome: ComputationalGenomeV1, suite: EvaluationSuite, **kwargs: object):
        evaluated.append(genome.digest)
        return real(genome, suite, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(search_module, "evaluate", counting)
    config = SearchConfig(strategy=SearchStrategy.EVOLUTIONARY, seed=202, budget_wu=2_000_000)
    run = run_search(config, train)
    assert run.cache_hits > 0  # duplicates were proposed
    assert len(evaluated) == len(set(evaluated))
    assert len(evaluated) - run.evaluations <= 1  # at most the call the budget refused


def test_the_record_bound_stops_a_run_and_says_so(
    train: EvaluationSuite, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(search_module, "MAX_RECORDS", 5)
    config = SearchConfig(strategy=SearchStrategy.RANDOM, seed=1, budget_wu=LOOP_BUDGET)
    run = run_search(config, train)
    assert len(run.records) == 5 and run.stop_reason == "RECORD_BOUND"


def _report(ap: float | None, name: str = "r") -> WinnerReport:
    return WinnerReport(name, "sha256:x", ap, ap, ap, 0.0, 3, 1184)


def _verdict(
    evo: list[float | None], rnd: list[float | None], exh: float | None
) -> MechanismVerdict:
    return strategy_verdict(
        [_report(v) for v in evo], [_report(v) for v in rnd], _report(exh),
        exhaustive_wu=1, equal_budget_wu=2,
    ).verdict


def test_compare_strategies_verdict_rule_on_synthetic_winner_reports() -> None:
    assert _verdict([0.80, 0.81, 0.82], [0.70, 0.70, 0.70], 0.70) is MechanismVerdict.JUSTIFIED
    # Median +0.03 vs both, but one seed is negative vs random: not every seed -> not justified.
    not_yet = MechanismVerdict.NOT_YET_JUSTIFIED
    assert _verdict([0.80, 0.81, 0.69], [0.70, 0.70, 0.70], 0.70) is not_yet
    # Beats random by a mile but loses to exhaustive enumeration by 0.05: rejected.
    assert _verdict([0.75, 0.75, 0.75], [0.50, 0.50, 0.50], 0.80) is MechanismVerdict.REJECTED
    assert _verdict([0.71, 0.71, 0.71], [0.70, 0.70, 0.70], 0.70) is not_yet
    # Spec §4.9 has no UNMEASURED branch: evolution with no MSSC-satisfying winner, against
    # controls that have one, did not beat them - never JUSTIFIED, NOT_YET_JUSTIFIED, named.
    assert _verdict([None, None, None], [0.7, 0.7, 0.7], 0.7) is not_yet
    empty = WinnerReport("evolutionary-s101", "", None, None, None, None, 0, 0)
    result = strategy_verdict([empty], [_report(0.6)], _report(0.6), exhaustive_wu=1,
                              equal_budget_wu=2)
    assert result.verdict is not_yet
    assert "evolutionary-s101" in result.detail
    # Only when NO strategy produced any winner is there nothing to compare: UNMEASURED.
    nothing = WinnerReport("exhaustive-s101", "", None, None, None, None, 0, 0)
    none_at_all = strategy_verdict([empty], [empty], nothing, exhaustive_wu=1, equal_budget_wu=2)
    assert none_at_all.verdict is MechanismVerdict.UNMEASURED
    # A computable median at or below -0.02 still rejects, even with a missing seed.
    assert _verdict([None, 0.60, 0.60], [0.70, 0.70, 0.70], 0.70) is MechanismVerdict.REJECTED
    with pytest.raises(ContractError):
        strategy_verdict([_report(0.5)], [], _report(0.5), exhaustive_wu=1, equal_budget_wu=1)


def test_null_verdict_rule() -> None:
    assert null_verdict(0.30, 0.99) is NullVerdict.NULL_HELD
    assert null_verdict(0.01, 0.50) is NullVerdict.PRIOR_INFORMATIVE
    assert null_verdict(0.01, 0.99) is NullVerdict.LEAK_SUSPECTED


def test_shuffled_label_control_returns_a_verdict_and_a_p_value(
    train: EvaluationSuite, heldout: EvaluationSuite
) -> None:
    control = run_shuffled_label_control(train, heldout, budget_wu=300_000,
                                         strategy=SearchStrategy.RANDOM)
    assert isinstance(control.verdict, NullVerdict)
    assert control.permutation_p_value is not None
    assert 0.0 < control.permutation_p_value <= 1.0
    assert control.prior_percentile is not None and 0.0 <= control.prior_percentile <= 1.0
    assert control.verdict is null_verdict(control.permutation_p_value, control.prior_percentile)


def test_compare_arm_refuses_an_unknown_flag(heldout: EvaluationSuite) -> None:
    with pytest.raises(ContractError):
        compare_arm((), (), heldout, flag="telepathy")
