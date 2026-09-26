"""Stage 8 package `oracle`: D8.5 hypothesis ecology + lineage DAG, D8.6 ORACLE.

Behaviour and failure paths, not construction: EIG is checked against an independent hand
computation, every selection policy against its definition, every bound against an overflow,
and the PRECEDES/CO_OCCURS twin against the lab switch. Episodes are real Stage 1 renders.
"""

from __future__ import annotations

import math
import random
from dataclasses import replace

import pytest

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.labs.corpus import Behaviour, Scenario
from pocketsec.stage1.pipeline import Stage1Pipeline
from pocketsec.stage6.resources import WorkBudgetExceeded
from pocketsec.stage8.ecology.lineage import (
    MAX_WALK,
    HypothesisLineageDAG,
    LineageNode,
    NodeKind,
)
from pocketsec.stage8.ecology.population import (
    GENERATIONS,
    HypothesisPopulation,
    MutationKind,
    ScoreMode,
    mdl_accepts,
    neighbours,
)
from pocketsec.stage8.episode import Episode, EpisodeContext, Split, episode_from_result
from pocketsec.stage8.genome.grammar import Mechanism, parse_mechanism
from pocketsec.stage8.genome.hypothesis import (
    Direction,
    ExperimentClass,
    GeneratorKind,
    GenomeProvenance,
    HypothesisGenome,
    ObservationScope,
    ResidualType,
    genome_for,
)
from pocketsec.stage8.governor.budget import ResearchBudget, ResearchGovernor
from pocketsec.stage8.laboratory.counterfactual import (
    TRANSFORM_SEMANTICS,
    Semantics,
    TransformKind,
)
from pocketsec.stage8.labs.discovery_corpus import LabOracle
from pocketsec.stage8.ledger.theory import LedgerEventKind, TheoryLedger, TheoryStatus
from pocketsec.stage8.oracle.information_gain import (
    LIKELIHOOD_NOISE,
    PRIOR_VERSION,
    Posterior,
    entropy_bits,
    expected_information_gain,
    uniform_prior,
    update,
)
from pocketsec.stage8.oracle.planner import (
    PRUNE_REASON,
    ExperimentDesign,
    OraclePlanner,
    SelectionPolicy,
    StopReason,
    select_design,
)
from pocketsec.stage8.sandbox.boundary import ResearchSandbox, SandboxOutcome

PM1 = "PRECEDES(EXECUTE+TEMP_LOCATION,CONNECT+EXTERNAL_ENDPOINT)"
PM1_TWIN = "CO_OCCURS(EXECUTE+TEMP_LOCATION,CONNECT+EXTERNAL_ENDPOINT)"
DIGEST = "sha256:" + "a" * 64

DROP = (
    Behaviour("write", {"path": "/tmp/.cache/.x"}),
    Behaviour("execve", {"path": "/tmp/.cache/.x"}),
    Behaviour("read", {"path": "/home/u/documents/d.txt"}),
    Behaviour("connect", {"raddr": "203.0.113.9", "rport": "443"}),
    Behaviour("send", {"raddr": "203.0.113.9", "rport": "443"}),
)
BACKUP = (
    Behaviour("execve", {"path": "/usr/bin/rsync"}),
    Behaviour("read", {"path": "/home/u/documents/d.txt"}),
    Behaviour("connect", {"raddr": "203.0.113.9", "rport": "22"}),
    Behaviour("send", {"raddr": "203.0.113.9", "rport": "22"}),
)
BUILD = (
    Behaviour("write", {"path": "/tmp/build/a.out"}),
    Behaviour("execve", {"path": "/tmp/build/a.out"}),
)
REVERSED = DROP[3:] + DROP[:3]  # connect/send first: CO_OCCURS fires, PRECEDES does not


def _episode(behaviours, label, offset, split=Split.TRAIN, epoch=0) -> Episode:
    host = f"t-h{offset % 4:02d}"
    result = Stage1Pipeline(host_id=host).run_scenario(
        Scenario(name=f"s{offset}", behaviours=tuple(behaviours), label=label), offset=offset
    )
    context = EpisodeContext(host_id=host, epoch_id=epoch, family="test", corpus="test",
                             synthetic=True)
    return episode_from_result(result, split=split, context=context, label=label)


def _genome(dsl: str, direction: Direction = Direction.MALICIOUS, **extra) -> HypothesisGenome:
    scope = ObservationScope(residual_cluster_ids=(),
                             residual_types=frozenset({ResidualType.OBSERVATION}), episode_ids=())
    provenance = GenomeProvenance(generator=GeneratorKind.SYMBOLIC_ENUMERATOR,
                                  source_digest=DIGEST, foreign=False, seed=0)
    return genome_for(parse_mechanism(dsl), direction=direction, scope=scope,
                      provenance=provenance, **extra)


@pytest.fixture(scope="module")
def train() -> tuple[Episode, ...]:
    return tuple(
        [_episode(DROP, 1, i) for i in range(0, 8)]
        + [_episode(BACKUP, 0, i) for i in range(10, 16)]
        + [_episode(BUILD, 0, i) for i in range(20, 26)]
    )


@pytest.fixture(scope="module")
def pool() -> tuple[Episode, ...]:
    return tuple(
        [_episode(DROP, 1, i, Split.LAB_POOL) for i in range(40, 48)]
        + [_episode(BACKUP, 0, i, Split.LAB_POOL) for i in range(50, 55)]
    )


def _governor(units: int = 50_000_000) -> ResearchGovernor:
    return ResearchGovernor(ResearchBudget(work_units=units))


# --- D8.6 information gain ---------------------------------------------------------


def _h(values) -> float:
    return -sum(p * math.log2(p) for p in values if p > 0)


def test_eig_matches_a_hand_computed_three_hypothesis_case() -> None:
    # h1, h2 predict 1; h3 predicts 0; one episode, uniform prior. By hand:
    e = LIKELIHOOD_NOISE
    p_y1 = ((1 - e) + (1 - e) + e) / 3
    p_y0 = (e + e + (1 - e)) / 3
    post_y1 = [(1 - e) / (3 * p_y1), (1 - e) / (3 * p_y1), e / (3 * p_y1)]
    post_y0 = [e / (3 * p_y0), e / (3 * p_y0), (1 - e) / (3 * p_y0)]
    by_hand = math.log2(3) - (p_y1 * _h(post_y1) + p_y0 * _h(post_y0))
    prior = uniform_prior(["h1", "h2", "h3"])
    eig = expected_information_gain(prior, {"h1": (1,), "h2": (1,), "h3": (0,)})
    assert eig == pytest.approx(by_hand, abs=1e-12)
    assert 0.0 < eig < math.log2(3)


def test_eig_renormalises_over_the_distinct_predicted_vectors() -> None:
    # Two episodes, two distinct vectors: (1,1) and (0,0). Outcomes (1,0)/(0,1) are outside the
    # enumerated set; the two in it are renormalised (spec D8.6).
    e = LIKELIHOOD_NOISE
    agree, miss = (1 - e) ** 2, e**2
    posterior_a = [agree / (agree + miss), miss / (agree + miss)]
    by_hand = 1.0 - _h(posterior_a)  # symmetric: both outcomes equally likely
    eig = expected_information_gain(uniform_prior(["a", "b"]), {"a": (1, 1), "b": (0, 0)})
    assert eig == pytest.approx(by_hand, abs=1e-12)


def test_eig_is_zero_when_every_hypothesis_predicts_alike() -> None:
    prior = uniform_prior(["a", "b", "c"])
    assert expected_information_gain(prior, {k: (1, 0, 1) for k in "abc"}) == 0.0


def test_eig_does_not_underflow_on_a_full_size_design() -> None:
    eig = expected_information_gain(uniform_prior(["a", "b"]), {"a": (1,) * 64, "b": (0,) * 64})
    assert math.isfinite(eig) and eig == pytest.approx(1.0, abs=1e-9)


def test_update_moves_toward_the_agreeing_hypothesis_and_none_is_no_evidence() -> None:
    prior = uniform_prior(["a", "b"])
    predictions = {"a": (1, 1), "b": (0, 0)}
    after = update(prior, predictions, (1, 1))
    assert after.probability("a") > 0.99 and after.prior_version == PRIOR_VERSION
    assert update(prior, predictions, (None, None)).probabilities == prior.probabilities
    one = update(prior, predictions, (1, None))
    assert one.probability("a") == pytest.approx(1 - LIKELIHOOD_NOISE)


@pytest.mark.parametrize(
    "build",
    [
        lambda: Posterior(hypothesis_ids=("a", "b"), probabilities=(0.5, 0.6)),
        lambda: Posterior(hypothesis_ids=("a", "a"), probabilities=(0.5, 0.5)),
        lambda: Posterior(hypothesis_ids=("a",), probabilities=(-0.0 - 1.0,)),
        lambda: Posterior(hypothesis_ids=(), probabilities=()),
        lambda: Posterior(hypothesis_ids=("a",), probabilities=(1.0,), prior_version=""),
        lambda: uniform_prior([]),
        lambda: expected_information_gain(uniform_prior(["a", "b"]), {"a": (1,)}),
        lambda: expected_information_gain(uniform_prior(["a", "b"]), {"a": (1,), "b": (2,)}),
        lambda: expected_information_gain(uniform_prior(["a", "b"]), {"a": (1,), "b": (1, 0)}),
        lambda: update(uniform_prior(["a"]), {"a": (1,)}, (1, 0)),
        lambda: update(uniform_prior(["a"]), {"a": (1,)}, (3,)),
    ],
)
def test_malformed_posteriors_predictions_and_observations_are_refused(build) -> None:
    with pytest.raises(ContractError):
        build()


def test_entropy_of_uniform_prior_is_log2_n() -> None:
    assert entropy_bits(uniform_prior(["a", "b", "c", "d"])) == pytest.approx(2.0)


# --- D8.6 selection policies -----------------------------------------------------------


def _design(name: str, cost: int) -> ExperimentDesign:
    return ExperimentDesign(design_id=name, experiment_class=ExperimentClass.HISTORICAL_REPLAY,
                            transform=None, episode_ids=(), cost_units=cost, privacy_cost=0.0,
                            safety_risk=0.0)


def test_each_selection_policy_selects_as_specified() -> None:
    candidates = [(_design("xd-a", 1000), 0.9), (_design("xd-b", 10), 0.3),
                  (_design("xd-c", 1), 0.0)]
    rng = random.Random(0)
    assert select_design(candidates, SelectionPolicy.EIG_ONLY, rng) == 0  # most bits
    assert select_design(candidates, SelectionPolicy.EIG_PER_COST, rng) == 1  # 0.3/11 > 0.9/1001
    assert select_design(candidates, SelectionPolicy.CHEAPEST, rng) == 2  # cost 1, EIG ignored
    picks = {select_design(candidates, SelectionPolicy.RANDOM, random.Random(s)) for s in range(40)}
    assert picks == {0, 1, 2}  # uniform: every design reachable
    with pytest.raises(ContractError):
        select_design([], SelectionPolicy.CHEAPEST, rng)


# --- D8.6 the planner ------------------------------------------------------------------


def _planner(lab_on: bool, *, ledger=None, governor=None, policy=SelectionPolicy.EIG_PER_COST,
             sandbox=None, **extra) -> tuple[OraclePlanner, ResearchGovernor, ResearchSandbox]:
    governor = governor or _governor()
    sandbox = sandbox or ResearchSandbox()
    lab = LabOracle(governor=governor) if lab_on else None
    planner = OraclePlanner(sandbox=sandbox, lab=lab, governor=governor, policy=policy,
                            rng=random.Random(7), ledger=ledger, **extra)
    return planner, governor, sandbox


def _born(*genomes: HypothesisGenome) -> TheoryLedger:
    ledger = TheoryLedger()
    for genome in genomes:
        ledger.record_birth(genome)
    return ledger


def _needs_lab(design: ExperimentDesign) -> bool:
    return design.transform is not None and \
        TRANSFORM_SEMANTICS[design.transform.kind] is not Semantics.PRESERVING


def test_lab_none_removes_every_unknown_and_destroying_design(pool) -> None:
    twins = (_genome(PM1), _genome(PM1_TWIN))
    off, _, _ = _planner(False)
    designs_off = off.candidate_designs(twins, pool)
    assert designs_off and not any(_needs_lab(d) for d in designs_off)
    on, _, _ = _planner(True)
    designs_on = on.candidate_designs(twins, pool)
    assert any(_needs_lab(d) for d in designs_on)
    assert any(d.transform.kind is TransformKind.REORDER for d in designs_on if d.transform)


def test_twin_is_observationally_equivalent_with_lab_off(pool) -> None:
    pm1, twin = _genome(PM1), _genome(PM1_TWIN)
    ledger = _born(pm1, twin)
    planner, _, _ = _planner(False, ledger=ledger)
    report = planner.run((pm1, twin), pool)
    assert report.stop is StopReason.OBSERVATIONALLY_EQUIVALENT
    assert report.experiments == () and report.leading is None and not report.lab_oracle_used
    assert report.designs_needing_lab > 0 and report.designs_offered > 0
    assert ledger.status(twin.hypothesis_id) is TheoryStatus.PROPOSED


def test_twin_is_separated_by_reorder_with_lab_on(pool) -> None:
    pm1, twin = _genome(PM1), _genome(PM1_TWIN)
    ledger = _born(pm1, twin)
    planner, _, sandbox = _planner(True, ledger=ledger)
    report = planner.run((pm1, twin), pool)
    assert report.stop is StopReason.IDENTIFIED and report.leading == pm1.hypothesis_id
    assert report.lab_oracle_used and report.active_experimentation >= 1
    assert any(r.design.transform is not None
               and r.design.transform.kind is TransformKind.REORDER for r in report.experiments)
    assert report.pruned == (twin.hypothesis_id,)
    assert ledger.status(pm1.hypothesis_id) is TheoryStatus.PROPOSED  # ORACLE decides no survival
    _assert_prune_on_record(planner, ledger, twin)
    for record in report.experiments:  # every run experiment was authorised, and safe
        assert record.sandbox.outcome is SandboxOutcome.ALLOWED
        assert record.design.experiment_class is not ExperimentClass.ISOLATED_EMULATION
    assert len(sandbox.audit()) >= len(report.experiments)


def _assert_prune_on_record(planner, ledger, pruned) -> None:
    """Integrator resolution of blocker B-oracle-1 (ADR-0078): a prune retires the theory
    FOSSILIZED with the ``oracle_posterior`` reason, so it can never be registered, and it is
    NOT filed as CHALLENGED_OUT (no FalsifierKind names a posterior). Nothing is refused."""
    assert ledger.status(pruned.hypothesis_id) is TheoryStatus.FOSSILIZED
    status = [e for e in ledger.entries() if e.kind is LedgerEventKind.STATUS]
    assert PRUNE_REASON in str(status[-1].payload)
    assert planner.stats()["prune_refused_by_ledger"] == 0


def test_replay_stratum_separates_the_twin_without_the_lab(pool) -> None:
    # A recorded reversed-order session labelled benign is active learning's evidence.
    rev = tuple(_episode(REVERSED, 0, i, Split.LAB_POOL) for i in range(60, 64))
    pm1, twin = _genome(PM1), _genome(PM1_TWIN)
    planner, _, _ = _planner(False, ledger=_born(pm1, twin))
    report = planner.run((pm1, twin), pool + rev)
    assert report.active_learning >= 1 and not report.lab_oracle_used
    assert report.experiments[0].design.experiment_class is ExperimentClass.HISTORICAL_REPLAY
    assert report.stop is StopReason.IDENTIFIED and report.leading == pm1.hypothesis_id


def test_sandbox_refusal_is_recorded_and_only_emulation_left_stops_safety(pool) -> None:
    emulating = replace(_genome(PM1), hypothesis_id="",
                        information_requests=(ExperimentClass.ISOLATED_EMULATION,))
    other = _genome("SINGLE(EXECUTE+TEMP_LOCATION)")
    quiet = tuple(e for e in pool if e.label == 0)  # backups: neither theory matches any
    assert not any(g.decides(e) for g in (emulating, other) for e in quiet)
    planner, _, sandbox = _planner(False)
    report = planner.run((emulating, other), quiet)
    refusals = [d for d in report.refused
                if d.experiment_class is ExperimentClass.ISOLATED_EMULATION]
    assert refusals and all(d.outcome is not SandboxOutcome.ALLOWED for d in refusals)
    assert any(d.experiment_class is ExperimentClass.ISOLATED_EMULATION for d in sandbox.audit())
    assert report.stop is StopReason.SAFETY and report.experiments == ()


def test_challenge_and_heldout_episodes_never_enter_a_posterior(pool) -> None:
    planner, _, _ = _planner(False)
    hostile = _episode(DROP, 1, 80, Split.CHALLENGE)
    heldout = _episode(DROP, 1, 81, Split.HOLDOUT)
    for bad in (hostile, heldout):
        with pytest.raises(ContractError):
            planner.run((_genome(PM1), _genome(PM1_TWIN)), pool + (bad,))


def test_telemetry_failure_stops_before_any_experiment(pool) -> None:
    planner, governor, sandbox = _planner(True)
    report = planner.run((_genome(PM1), _genome(PM1_TWIN)), pool, visibility_share=0.6)
    assert report.stop is StopReason.TELEMETRY_FAILURE and report.experiments == ()
    assert sandbox.audit() == () and not report.lab_oracle_used


def test_single_hypothesis_is_never_declared_identified(pool) -> None:
    planner, _, _ = _planner(True)
    report = planner.run((_genome(PM1),), pool)
    assert report.stop is StopReason.NO_EXPERIMENTS and report.experiments == ()


def test_experiment_count_and_work_budget_bound_the_run(pool) -> None:
    rev = tuple(_episode(REVERSED, 0, i, Split.LAB_POOL) for i in range(90, 92))
    planner, _, _ = _planner(True, policy=SelectionPolicy.CHEAPEST, max_experiments=1)
    report = planner.run((_genome(PM1), _genome(PM1_TWIN), _genome("SINGLE(SEND)")), pool + rev)
    assert len(report.experiments) <= 1
    assert report.stop in (StopReason.BUDGET, StopReason.IDENTIFIED)
    starved, governor, _ = _planner(True, governor=_governor(units=50))
    report = starved.run((_genome(PM1), _genome(PM1_TWIN)), pool)
    assert report.stop is StopReason.BUDGET and governor.meter.spent <= 50


# --- D8.5 lineage DAG ----------------------------------------------------------------


def _node(node_id: str, kind: NodeKind, *parents: str) -> LineageNode:
    return LineageNode(node_id=node_id, kind=kind, parents=parents, detail_digest=DIGEST)


def test_lineage_refuses_orphans_unknown_parents_duplicates_and_bad_roots() -> None:
    dag = HypothesisLineageDAG()
    assert dag.add(_node("res-1", NodeKind.RESIDUAL))
    assert not dag.add(_node("hyp-1", NodeKind.HYPOTHESIS, "res-missing"))
    assert not dag.add(_node("hyp-2", NodeKind.HYPOTHESIS))  # no recorded origin
    assert not dag.add(_node("res-2", NodeKind.RESIDUAL, "res-1"))  # a residual is a root
    assert not dag.add(_node("res-1", NodeKind.RESIDUAL))
    assert not dag.add(_node("hyp-3", NodeKind.HYPOTHESIS, *(["res-1"] * 2)))
    stats = dag.stats()
    assert stats["refused_unknown_parent"] == 1 and stats["refused_shape"] == 3
    assert stats["refused_duplicate"] == 1 and stats["nodes"] == 1
    with pytest.raises(ContractError):
        LineageNode(node_id="x", kind=NodeKind.RESIDUAL, parents=(), detail_digest="md5:00")


def test_lineage_node_and_edge_caps_bind() -> None:
    dag = HypothesisLineageDAG(max_nodes=3, max_edges=2)
    assert dag.add(_node("r", NodeKind.RESIDUAL))
    assert dag.add(_node("h1", NodeKind.HYPOTHESIS, "r"))
    assert not dag.add(_node("h2", NodeKind.HYPOTHESIS, "r", "h1"))  # 3 edges > 2
    assert dag.add(_node("h3", NodeKind.HYPOTHESIS, "h1"))
    assert not dag.add(_node("h4", NodeKind.HYPOTHESIS, "r"))  # 4 nodes > 3
    assert dag.stats()["refused_full"] == 2 and dag.stats()["nodes"] == 3
    assert dag.memory_bytes() > 0


def test_lineage_walk_is_bounded_but_collect_keeps_the_full_closure() -> None:
    dag = HypothesisLineageDAG()
    dag.add(_node("n0", NodeKind.RESIDUAL))
    for i in range(1, MAX_WALK + 50):
        assert dag.add(_node(f"n{i}", NodeKind.HYPOTHESIS, f"n{i - 1}"))
    dag.add(_node("stray", NodeKind.RESIDUAL))
    tip = f"n{MAX_WALK + 49}"
    assert len(dag.ancestors(tip)) == MAX_WALK and dag.stats()["walks_truncated"] == 1
    removed = dag.collect([tip, "never-added"])
    assert removed == 1 and not dag.has("stray") and dag.has("n0")  # root kept past MAX_WALK
    assert dag.stats()["keep_unknown"] == 1 and dag.stats()["collected"] == 1


def test_lineage_path_kinds_trace_a_package_back_to_its_residual() -> None:
    dag = HypothesisLineageDAG()
    chain = [("r", NodeKind.RESIDUAL), ("h", NodeKind.HYPOTHESIS), ("x", NodeKind.EXPERIMENT),
             ("d", NodeKind.DISCOVERY), ("f", NodeKind.FORGE_CANDIDATE),
             ("c", NodeKind.STAGE6_CAPSULE)]
    previous: tuple[str, ...] = ()
    for node_id, kind in chain:
        assert dag.add(_node(node_id, kind, *previous))
        previous = (node_id,)
    assert dag.path_kinds("c") == frozenset(kind for _, kind in chain)
    assert dag.ancestors("c") == ("f", "d", "x", "h", "r")
    with pytest.raises(ContractError):
        dag.ancestors("unknown")


# --- D8.5 the population ---------------------------------------------------------------


def _edit_units(a: Mechanism, b: Mechanism) -> int:
    """How many single edits separate two mechanisms (relation kind, count, relation, bits)."""
    units = int(a.relation is not b.relation) + abs(a.repeat_min - b.repeat_min)
    if len(a.steps) != len(b.steps):
        return 99
    for x, y in zip(a.steps, b.steps):
        units += int(x.relation != y.relation)
        for name in ("require_properties", "forbid_properties", "require_raised"):
            units += bin(getattr(x, name) ^ getattr(y, name)).count("1")
    return units


def _population(ledger=None, **extra) -> tuple[HypothesisPopulation, TheoryLedger]:
    ledger = ledger or TheoryLedger()
    return HypothesisPopulation(ledger=ledger, governor=_governor(), **extra), ledger


@pytest.mark.parametrize("kind", list(MutationKind))
def test_mutation_changes_exactly_one_thing_and_is_born_with_its_parent(kind) -> None:
    for dsl in (PM1, "SINGLE(CONNECT+EXTERNAL_ENDPOINT)", "REPEATED(CONNECT+EXTERNAL_ENDPOINT,4)"):
        population, ledger = _population()
        parent = _genome(dsl)
        assert population.add(parent)
        options = neighbours(parent.proposed_mechanism, kind)
        assert all(_edit_units(parent.proposed_mechanism, m) == 1 for m in options)
        for seed in range(6):
            child = population.mutate(parent.hypothesis_id, kind, rng=random.Random(seed))
            if not options:
                assert child is None
                break
            if child is None:
                continue  # the same child as an earlier seed: refused as already born
            assert _edit_units(parent.proposed_mechanism, child.proposed_mechanism) == 1
            assert child.parent_hypotheses == (parent.hypothesis_id,)
            assert child.provenance.generator is GeneratorKind.MUTATION
            assert child.direction is parent.direction
            assert child.falsification_tests == parent.falsification_tests
            assert ledger.status(child.hypothesis_id) is TheoryStatus.PROPOSED


def test_depth_past_the_limit_is_refused_and_counted() -> None:
    population, _ = _population(max_depth=1)
    root = _genome("SINGLE(CONNECT+EXTERNAL_ENDPOINT)")
    population.add(root)
    child = population.mutate(root.hypothesis_id, MutationKind.TOGGLE_RAISED, rng=random.Random(1))
    assert child is not None and population.add(child) and population.depth(child.hypothesis_id) == 1
    grandchild = population.mutate(child.hypothesis_id, MutationKind.TOGGLE_RAISED,
                                   rng=random.Random(2))
    assert grandchild is None and population.stats()["depth_refused"] == 1


def test_mdl_rule_in_both_directions_and_its_control() -> None:
    # More bits: +4 bits needs f1 gain >= 0.04.
    assert mdl_accepts(parent_bits=10, parent_f1=0.50, child_bits=14, child_f1=0.54)
    assert not mdl_accepts(parent_bits=10, parent_f1=0.50, child_bits=14, child_f1=0.539)
    # Fewer bits: 4 bits saved tolerates an f1 loss up to 0.04.
    assert mdl_accepts(parent_bits=14, parent_f1=0.54, child_bits=10, child_f1=0.50)
    assert not mdl_accepts(parent_bits=14, parent_f1=0.54, child_bits=10, child_f1=0.49)
    # Control: any f1 gain, however many bits it costs; no gain, however many it saves.
    assert mdl_accepts(parent_bits=10, parent_f1=0.5, child_bits=90, child_f1=0.51, mdl=False)
    assert not mdl_accepts(parent_bits=90, parent_f1=0.5, child_bits=10, child_f1=0.5, mdl=False)
    with pytest.raises(ContractError):
        mdl_accepts(parent_bits=1, parent_f1=0, child_bits=1, child_f1=0, gain_per_bit=-1.0)


def test_population_capacity_evicts_the_lowest_total_and_fossilizes_it(train) -> None:
    population, ledger = _population(capacity=2)
    best = _genome(PM1)
    worst = _genome("SINGLE(RECEIVE)")  # matches nothing on TRAIN
    middle = _genome("SINGLE(EXECUTE+TEMP_LOCATION)")  # matches drops and builds
    for genome in (worst, best):
        population.add(genome)
    population.score(best.hypothesis_id, train)
    assert population.add(middle)
    assert set(g.hypothesis_id for g in population.members()) == {best.hypothesis_id,
                                                                   middle.hypothesis_id}
    assert ledger.status(worst.hypothesis_id) is TheoryStatus.FOSSILIZED
    assert not population.add(_genome("SINGLE(LISTEN)"))  # newcomer is the lowest: refused
    stats = population.stats()
    assert stats["size"] == 2 and stats["evicted"] == 2 and stats["fossilized"] == 2
    assert not population.add(best) and population.stats()["duplicates"] == 1


def test_score_terms_are_on_train_and_fit_only_is_the_control(train, pool) -> None:
    full, _ = _population()
    genome = _genome(PM1)
    full.add(genome)
    score = full.score(genome.hypothesis_id, train)
    assert score.predictive_fit == pytest.approx(1.0) and score.causal_coherence == 1.0
    assert score.complexity == pytest.approx(genome.complexity_cost / 64)
    gains = (score.predictive_fit + score.causal_coherence + score.falsification_survival
             + score.cross_epoch + score.independent_evidence)
    costs = (score.complexity + score.contradictions + score.visibility_dependence
             + score.adversarial_fragility)
    assert score.total == pytest.approx(gains - costs)
    fit_only, _ = _population(score_mode=ScoreMode.FIT_ONLY)
    fit_only.add(genome)
    assert fit_only.score(genome.hypothesis_id, train).total == pytest.approx(score.predictive_fit)
    with pytest.raises(ContractError):
        full.score(genome.hypothesis_id, pool)  # LAB_POOL is not TRAIN


def test_merge_orders_by_majority_train_order_and_split_inverts_it(train) -> None:
    population, ledger = _population()
    connect = _genome("SINGLE(CONNECT+EXTERNAL_ENDPOINT)")
    execute = _genome("SINGLE(EXECUTE+TEMP_LOCATION)")
    for genome in (connect, execute):
        population.add(genome)
    merged = population.merge(connect.hypothesis_id, execute.hypothesis_id, train=train)
    assert merged is not None and merged.proposed_mechanism == parse_mechanism(PM1)
    assert merged.provenance.generator is GeneratorKind.MERGE
    assert set(merged.parent_hypotheses) == {connect.hypothesis_id, execute.hypothesis_id}
    assert ledger.status(merged.hypothesis_id) is TheoryStatus.PROPOSED
    benign = _genome("SINGLE(RECEIVE)", Direction.BENIGN)
    population.add(benign)
    assert population.merge(connect.hypothesis_id, benign.hypothesis_id, train=train) is None
    population.add(merged)
    parts = population.split(merged.hypothesis_id)
    assert {p.proposed_mechanism for p in parts} == {
        connect.proposed_mechanism, execute.proposed_mechanism}
    assert population.split(connect.hypothesis_id) == ()


def test_evolve_births_every_child_and_rejects_by_mdl(train) -> None:
    population, ledger = _population()
    for dsl in ("SINGLE(CONNECT+EXTERNAL_ENDPOINT)", "SINGLE(EXECUTE+TEMP_LOCATION)", PM1):
        population.add(_genome(dsl))
    report = population.evolve(train, rng=random.Random(3))
    assert report.generations == GENERATIONS and report.children > 0
    assert report.accepted + report.rejected_mdl == report.children
    assert report.rejected_mdl > 0 and report.merges >= 1 and report.splits >= 1
    births = [e for e in ledger.entries() if e.kind is LedgerEventKind.BIRTH]
    assert len(births) == population.stats()["births"]  # every genome, every child, on record
    fossils = sum(ledger.status(e.hypothesis_id) is TheoryStatus.FOSSILIZED for e in births)
    assert fossils >= report.rejected_mdl
    assert len(population) <= 256 and population.memory_bytes() > 0


def test_mdl_off_accepts_no_child_that_fails_to_raise_f1(train) -> None:
    population, _ = _population(mdl=False)
    population.add(_genome(PM1))  # f1 = 1.0 on TRAIN: no child can strictly improve it
    report = population.evolve(train, rng=random.Random(5))
    assert report.children > 0 and report.accepted == 0


def test_runaway_evolution_hits_the_work_budget_not_the_host(train) -> None:
    population = HypothesisPopulation(ledger=TheoryLedger(), governor=_governor(units=500))
    population.add(_genome(PM1))
    with pytest.raises(WorkBudgetExceeded):
        population.evolve(train, rng=random.Random(0))
