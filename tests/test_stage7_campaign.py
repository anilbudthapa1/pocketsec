"""Stage 7 package ``campaign``: D7.12 worlds, D7.13 hypergraph, D7.14 novelty, D7.15 falsifier.

Every defence is attacked, not only constructed: each benign common cause, a colluding
fabrication, a Sybil suppression, a flood against every cap, a forged H5 label, and an
unobservable-peer negative-evidence flood. The lab arms and the falsifier share an author
(``labs/campaign_sim.py`` docstring), so these tests show the *mechanism fires as designed*;
they are not evidence about real common causes. Where a test isolates a mechanism it also
runs the control that removes it, so a mechanism that stopped firing fails loudly.
"""

from __future__ import annotations

import ast
import dataclasses
import hashlib
import math
from pathlib import Path
from types import SimpleNamespace

import pytest

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage0.contracts.threat_prediction_v1 import FORBIDDEN_AUTHORITY_FIELDS
from pocketsec.stage1.ssir.relations import Relation, RelationFamily
from pocketsec.stage6.capsule.experience_capsule import PrivacyClass
from pocketsec.stage6.resources import WorkBudgetExceeded, WorkMeter
from pocketsec.stage7.campaign.hypergraph import (
    MAX_FRAGMENTS,
    CampaignHypergraph,
    Fragment,
    Hyperedge,
)
from pocketsec.stage7.capsule.knowledge_capsule import (
    ChainStage,
    EpochContext,
    FalsificationSummary,
    KnowledgeType,
    MotifRow,
    ObservabilityClaim,
    ProvenanceCommitment,
    RoleClass,
    SourceContextSketch,
    Stance,
    ValidationSummary,
    VisibilityClass,
    seal_capsule,
)
from pocketsec.stage7.falsifier.consensus import (
    NEG_CLUSTER_CAP,
    NEG_EVIDENCE_FLOOR,
    ConsensusFalsification,
    ConsensusFalsifier,
    CounterHypothesis,
    HypothesisStatus,
    NegativeClaim,
    negative_evidence_weight,
    poisson_upper_tail,
)
from pocketsec.stage7.labs.campaign_sim import (
    BENIGN_ARM_HYPOTHESIS,
    SIM_RELEVANT_HOSTS,
    SIM_STAGE_BASE_RATES,
    CampaignArm,
    build_campaign_cases,
    run_campaign_case,
    run_campaign_sim,
)
from pocketsec.stage7.novelty.collective import (
    MAX_REPORTS_PER_PATTERN,
    CollectiveNovelty,
    CollectiveNoveltyEngine,
    NoveltyStatus,
)
from pocketsec.stage7.reconstruct.partial_world import (
    PartialWorldReconstructor,
    WorldStatus,
    count_threshold_join,
)
from pocketsec.stage7.relevance.epistemic_distance import LocalContext

ROOT = Path(__file__).resolve().parents[1]
OWN_MODULES = (
    "pocketsec/stage7/campaign/hypergraph.py",
    "pocketsec/stage7/reconstruct/partial_world.py",
    "pocketsec/stage7/novelty/collective.py",
    "pocketsec/stage7/falsifier/consensus.py",
    "pocketsec/stage7/labs/campaign_sim.py",
)
CASES = build_campaign_cases(seed=0, per_arm=6)
LOW = VisibilityClass.LOW


def _hex(label: str, width: int) -> str:
    return hashlib.sha256(label.encode()).hexdigest()[:width]


def _cl(name: str) -> str:
    return "cl-" + _hex("cluster:" + name, 16)


def _se(name: str) -> str:
    return "se-" + _hex("epoch:" + name, 16)


def _frag(name: str, cluster: str, stage: ChainStage, lo: int, hi: int, *,
          role: RoleClass = RoleClass.WEB, epoch: str = "old",
          visibility: VisibilityClass = VisibilityClass.FULL, rarity: float = 0.9) -> Fragment:
    return Fragment(capsule_id="kc-" + _hex("capsule:" + name, 24), cluster_id=_cl(cluster),
                    role=role, stage=stage, window=(lo, hi), software_epoch=_se(epoch),
                    visibility=visibility, rarity=rarity)


def _campaign(offset: int = 100) -> tuple[Fragment, ...]:
    """A two-cluster, four-stage chain on an established image, staggered starts."""
    return (
        _frag("a-cred", "a", ChainStage.CREDENTIAL, offset, offset + 1, role=RoleClass.WEB),
        _frag("b-elev", "b", ChainStage.ELEVATION, offset + 1, offset + 2, role=RoleClass.DEV),
        _frag("a-pers", "a", ChainStage.PERSISTENCE, offset + 2, offset + 3, role=RoleClass.WEB),
        _frag("b-egr", "b", ChainStage.EGRESS, offset + 3, offset + 4, role=RoleClass.DEV),
    )


def _local(role: RoleClass = RoleClass.WEB) -> LocalContext:
    return LocalContext(role=role, software_epoch=_se("old"), visibility=VisibilityClass.FULL,
                        family_profile=(1,) * len(RelationFamily), local_keys=frozenset(),
                        observable_relations=frozenset(int(r) for r in Relation))


def _falsifier(**overrides: object) -> ConsensusFalsifier:
    fields: dict[str, object] = dict(stage_base_rates=SIM_STAGE_BASE_RATES,
                                     relevant_hosts=SIM_RELEVANT_HOSTS)
    fields.update(overrides)
    return ConsensusFalsifier(**fields)  # type: ignore[arg-type]


def _reconstructor(fragments: tuple[Fragment, ...], **overrides: object
                   ) -> tuple[CampaignHypergraph, PartialWorldReconstructor]:
    graph = CampaignHypergraph()
    graph.note_epoch(_se("old"), 0)
    for fragment in fragments:
        assert graph.add_fragment(fragment)
    fields: dict[str, object] = dict(hypergraph=graph, falsifier=_falsifier())
    fields.update(overrides)
    return graph, PartialWorldReconstructor(**fields)  # type: ignore[arg-type]


def _neg(name: str, cluster: str, stage: ChainStage, lo: int, hi: int,
         weight: float) -> NegativeClaim:
    return NegativeClaim(capsule_id="kc-" + _hex("neg:" + name, 24), cluster_id=_cl(cluster),
                         stage=stage, window=(lo, hi), weight=weight)


def _outcomes(arm: CampaignArm, **kwargs: object) -> list:
    return [run_campaign_case(case, **kwargs) for case in CASES if case.arm is arm]  # type: ignore[arg-type]


# --- the ten required behaviours --------------------------------------------------------


def test_every_supported_world_has_six_evaluated_tests() -> None:
    supported = [world for case in CASES for world in run_campaign_case(case).worlds
                 if world.status is WorldStatus.SUPPORTED]
    assert supported, "vacuous: no SUPPORTED world in the simulation"
    for world in supported:
        falsification = world.falsification
        assert falsification is not None
        assert tuple(test.hypothesis for test in falsification.tests) == tuple(CounterHypothesis)
        assert all(test.status is not HypothesisStatus.UNEVALUATED for test in falsification.tests)
        assert falsification.explanation is CounterHypothesis.H5_REAL_CAMPAIGN
        assert falsification.negative_weight < NEG_EVIDENCE_FLOOR
        assert world.first_supported_round is not None


def test_each_benign_arm_is_rejected_by_its_hypothesis() -> None:
    fired = {hypothesis: 0 for hypothesis in BENIGN_ARM_HYPOTHESIS.values()}
    for arm, intended in BENIGN_ARM_HYPOTHESIS.items():
        for outcome in _outcomes(arm):
            assert outcome.detected_after_rounds is None, f"{arm} produced a false campaign"
            for world in outcome.worlds:
                assert world.falsification is not None
                survivors = [test.hypothesis for test in world.falsification.tests[:5]
                             if test.status is HypothesisStatus.SURVIVES]
                # "exactly its intended hypothesis applies": the arm construction contract
                assert survivors == [intended], (arm, survivors)
                assert world.falsification.explanation is intended
                fired[intended] += 1
    assert all(count >= 1 for count in fired.values()), fired


def test_true_campaign_survives_on_2_4_10_hosts() -> None:
    arms = (CampaignArm.TRUE_CAMPAIGN_2, CampaignArm.TRUE_CAMPAIGN_4, CampaignArm.TRUE_CAMPAIGN_10)
    for arm in arms:
        outcomes = _outcomes(arm)
        assert outcomes and all(item.detected_after_rounds is not None for item in outcomes), arm
        for outcome in outcomes:
            supported = [world for world in outcome.worlds if world.status is WorldStatus.SUPPORTED]
            assert supported
            assert all(world.clusters >= 2 and len(world.stages) >= 3 for world in supported)


def test_colluding_single_cluster_fabrication_is_h4() -> None:
    merged = next(case for case in CASES
                  if case.arm is CampaignArm.COLLUDING_FABRICATION and case.cluster_merges)
    outcome = run_campaign_case(merged)
    assert outcome.worlds and outcome.detected_after_rounds is None
    for world in outcome.worlds:
        assert world.status is WorldStatus.REJECTED_COLLUSION
        assert world.clusters == 1  # re-resolved after dependence clustering
        h4 = world.falsification.tests[4]  # type: ignore[union-attr]
        assert (h4.status, h4.reason) == (HypothesisStatus.SURVIVES, "single_cluster")
    # The control that isolates H4: the same fragments without the later merge are a campaign.
    unmerged = run_campaign_case(dataclasses.replace(merged, cluster_merges=()))
    assert unmerged.detected_after_rounds is not None
    # The burst variant is H4 too, for a different reason.
    burst = next(case for case in CASES
                 if case.arm is CampaignArm.COLLUDING_FABRICATION and case.burst_capsules)
    reasons = {world.falsification.tests[4].reason  # type: ignore[union-attr]
               for world in run_campaign_case(burst).worlds}
    assert reasons == {"birth_burst"}


def test_negative_evidence_never_deletes_a_world() -> None:
    _, reconstructor = _reconstructor(_campaign())
    before = {world.world_id: world for world in reconstructor.reconstruct(round_index=110)}
    target = next(world for world in before.values() if world.status is WorldStatus.SUPPORTED)
    heavy = tuple(_neg(f"n{index}", f"sup{index}", ChainStage.CREDENTIAL, 95, 111, 1.0)
                  for index in range(20))
    after = {world.world_id: world
             for world in reconstructor.reconstruct(round_index=111, negative=heavy)}
    assert set(before) <= set(after), "a world disappeared under negative evidence"
    vetoed = after[target.world_id]
    assert vetoed.status is WorldStatus.UNRESOLVED
    assert vetoed.first_supported_round == target.first_supported_round  # history kept
    assert vetoed.falsification is not None
    assert vetoed.falsification.negative_weight >= NEG_EVIDENCE_FLOOR
    # the veto is a status, not an erasure: withdraw the claims and the world is SUPPORTED again
    again = {world.world_id: world for world in reconstructor.reconstruct(round_index=112)}
    assert again[target.world_id].status is WorldStatus.SUPPORTED


def test_unobservable_peer_contributes_zero_negative_weight() -> None:
    blind = ObservabilityClaim(expected_observability=0.0, sensor_health=1.0, temporal_coverage=1.0)
    assert negative_evidence_weight(blind, host_relevance=1.0) == 0.0
    seeing = ObservabilityClaim(expected_observability=0.8, sensor_health=0.5,
                                temporal_coverage=0.5)
    assert math.isclose(negative_evidence_weight(seeing, host_relevance=0.5), 0.1)
    # fifty unobservable peers, each from its own cluster, move nothing
    weight = negative_evidence_weight(blind, host_relevance=1.0)
    claims = tuple(_neg(f"blind{index}", f"blind{index}", ChainStage.CREDENTIAL, 95, 110, weight)
                   for index in range(50))
    _, reconstructor = _reconstructor(_campaign())
    worlds = reconstructor.reconstruct(round_index=110, negative=claims)
    assert any(world.status is WorldStatus.SUPPORTED for world in worlds)
    assert all(world.falsification.negative_weight == 0.0 for world in worlds)  # type: ignore[union-attr]
    with pytest.raises(ContractError):
        negative_evidence_weight(seeing, host_relevance=1.5)


def test_falsifier_false_campaign_rate_not_above_count_threshold_join() -> None:
    report = run_campaign_sim(CASES)
    assert report.synthetic is True
    assert report.false_campaign_rate is not None and report.control_false_campaign_rate is not None
    assert report.false_campaign_rate <= report.control_false_campaign_rate
    assert report.true_recall is not None and report.true_recall > 0.0
    # Firing: without the falsifier every benign arm becomes a campaign, so it changed outcomes.
    ablated = run_campaign_sim(CASES, falsify=False)
    assert ablated.false_campaign_rate is not None
    assert ablated.false_campaign_rate > report.false_campaign_rate
    rejected = dict(report.rejections_by_hypothesis)
    assert all(rejected[hypothesis.value] >= 1 for hypothesis in BENIGN_ARM_HYPOTHESIS.values())


def test_hypergraph_and_fragment_bounds_hold_under_flood() -> None:
    graph = CampaignHypergraph(max_fragments=64, max_edges=8, expiry_rounds=500)
    stages = tuple(ChainStage)[:5]
    # spread in time, so the stored fragments form many distinct maximal groups
    accepted = sum(graph.add_fragment(_frag(f"f{index}", f"c{index % 40}", stages[index % 5],
                                            3 * index, 3 * index + 1)) for index in range(500))
    assert accepted == 64 and len(graph.fragments()) == 64
    assert graph.stats()["fragments_refused_full"] == 436
    assert not graph.add_fragment(graph.fragments()[0])  # a duplicate is refused, not double-stored
    graph.build_edges(round_index=200)
    assert len(graph.edges()) == 8
    assert graph.stats()["edges_refused_full"] > 0
    # the default cap is the one the spec names, and it holds against a larger flood
    big = CampaignHypergraph()
    for index in range(MAX_FRAGMENTS + 500):
        big.add_fragment(_frag(f"g{index}", f"k{index % 97}", stages[index % 5], 3, 5))
    assert len(big.fragments()) == MAX_FRAGMENTS and big.refused() == 500
    memory_full = big.memory_bytes()
    big.build_edges(round_index=6)
    assert len(big.edges()) <= 512 and big.memory_bytes() >= memory_full
    # the pairwise control is bounded too: it truncates instead of enumerating ~2M pairs
    pairwise = CampaignHypergraph(enabled=False, max_edges=16)
    for fragment in big.fragments():
        pairwise.add_fragment(fragment)
    pairwise.build_edges(round_index=6)
    assert len(pairwise.edges()) <= 16 and pairwise.stats()["build_truncations"] >= 1
    # the world table is bounded and refuses rather than deleting
    worlds_graph, reconstructor = _reconstructor(_campaign(), max_worlds=1)
    for index, offset in enumerate((200, 300, 400)):
        for fragment in _campaign(offset):
            worlds_graph.add_fragment(dataclasses.replace(
                fragment, capsule_id="kc-" + _hex(f"{fragment.capsule_id}:{index}", 24)))
    reconstructor.reconstruct(round_index=110)
    reconstructor.reconstruct(round_index=410)
    assert len(reconstructor.worlds()) == 1 and reconstructor.refused() >= 1


def test_rare_benign_population_event_explained_by_epoch() -> None:
    local = _local()
    stages = (ChainStage.CREDENTIAL, ChainStage.PERSISTENCE)
    pattern = "mf-" + _hex("pattern", 16)

    def run(epoch: str, *, enabled: bool = True) -> CollectiveNovelty:
        engine = CollectiveNoveltyEngine(local=local, enabled=enabled)
        engine.note_epoch(_se("old"), 0)
        for round_index in range(100, 116):
            engine.observe_population({}, role=RoleClass.WEB, round_index=round_index)  # rare
            for cluster in ("a", "b", "c"):
                engine.observe_report(pattern, stages=stages, cluster_id=_cl(cluster),
                                      software_epoch=_se(epoch), round_index=round_index)
        (result,) = engine.evaluate(round_index=115)
        return result

    fresh = run("new-image")
    assert fresh.status is NoveltyStatus.EXPLAINED_BY_EPOCH
    assert fresh.benign_epoch_explanation == 1.0 and fresh.rarity == 1.0
    # the controls that isolate the epoch explanation: an established image is novel, and a
    # local-only engine flags the fresh-image event too (so the explanation is what fired)
    assert run("old").status is NoveltyStatus.COLLECTIVELY_NOVEL
    assert run("new-image", enabled=False).status is NoveltyStatus.COLLECTIVELY_NOVEL


def test_novelty_never_produces_a_verdict() -> None:
    assert {status.value for status in NoveltyStatus} == {
        "COLLECTIVELY_NOVEL", "EXPLAINED_BY_EPOCH", "LOCAL_ONLY", "INSUFFICIENT"}
    for relative in OWN_MODULES:
        tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                assert "threat_prediction" not in module, relative
                assert "stage5" not in module and ".promotion" not in module, relative
                assert not module.startswith("pocketsec.stage6.capsule"), relative
                names = {alias.name for alias in node.names}
                assert not names & {"Verdict", "ThreatPredictionV1"}, relative
            if isinstance(node, ast.Attribute) and node.attr in {"admit", "hand_over"}:
                raise AssertionError(f"{relative} reaches Stage 6 through .{node.attr}")
            if isinstance(node, ast.ClassDef):  # T5: no authority-named field, no exemption
                for item in node.body:
                    if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                        lowered = item.target.id.lower()
                        assert not any(word in lowered for word in FORBIDDEN_AUTHORITY_FIELDS), (
                            relative, item.target.id)


# --- the falsifier's rules, pinned -----------------------------------------------------


def test_h0_poisson_tail_matches_closed_form() -> None:
    assert math.isclose(poisson_upper_tail(2.0, 3), 1.0 - math.exp(-2.0) * (1 + 2 + 2))
    assert poisson_upper_tail(0.0, 1) == 0.0 and poisson_upper_tail(5.0, 0) == 1.0
    with pytest.raises(ContractError):
        poisson_upper_tail(-1.0, 2)


def test_a_forged_h5_label_is_refused_while_a_rival_survives() -> None:
    graph, reconstructor = _reconstructor(_campaign())
    world = next(item for item in reconstructor.reconstruct(round_index=110)
                 if item.status is WorldStatus.SUPPORTED)
    assert world.falsification is not None
    tests = list(world.falsification.tests)
    tests[3] = dataclasses.replace(tests[3], status=HypothesisStatus.SURVIVES)
    with pytest.raises(ContractError):
        ConsensusFalsification(world.world_id, tuple(tests),
                               CounterHypothesis.H5_REAL_CAMPAIGN, 0.0)
    with pytest.raises(ContractError):  # five tests, or out of order, is refused
        ConsensusFalsification(world.world_id, tuple(tests[:5]), None, 0.0)
    assert graph.edges()


def test_two_benign_survivors_are_unidentifiable_not_guessed() -> None:
    low_common = (
        _frag("x1", "x", ChainStage.ACCESS, 100, 101, visibility=LOW, role=RoleClass.WEB),
        _frag("y1", "y", ChainStage.PERSISTENCE, 101, 102, visibility=LOW, role=RoleClass.DEV),
        _frag("z1", "z", ChainStage.EGRESS, 102, 103, visibility=LOW, role=RoleClass.ADMIN),
    )
    _, reconstructor = _reconstructor(low_common)
    (world,) = reconstructor.reconstruct(round_index=110)
    assert world.falsification is not None
    assert world.falsification.tests[0].status is HypothesisStatus.SURVIVES  # H0
    assert world.falsification.tests[3].status is HypothesisStatus.SURVIVES  # H3
    assert world.falsification.explanation is None
    assert world.status is WorldStatus.UNRESOLVED


def test_missing_base_rate_leaves_h0_unevaluated_and_the_world_unsupported() -> None:
    rates = {stage: rate for stage, rate in SIM_STAGE_BASE_RATES.items()
             if stage is not ChainStage.EGRESS}
    _, reconstructor = _reconstructor(_campaign(), falsifier=_falsifier(stage_base_rates=rates))
    worlds = reconstructor.reconstruct(round_index=110)
    with_egress = [world for world in worlds if ChainStage.EGRESS in world.stages]
    assert with_egress
    for world in with_egress:
        assert world.falsification.tests[0].status is HypothesisStatus.UNEVALUATED  # type: ignore[union-attr]
        assert world.status is not WorldStatus.SUPPORTED


def test_one_sybil_cluster_cannot_veto_by_volume() -> None:
    flood = tuple(_neg(f"s{index}", "sybil", ChainStage.CREDENTIAL, 95, 110, 1.0)
                  for index in range(100))
    _, reconstructor = _reconstructor(_campaign())
    worlds = reconstructor.reconstruct(round_index=110, negative=flood)
    supported = [world for world in worlds if world.status is WorldStatus.SUPPORTED]
    assert supported and all(world.falsification.negative_weight == NEG_CLUSTER_CAP  # type: ignore[union-attr]
                             for world in supported)
    # but the per-cluster cap follows re-resolution: two clusters the graph did NOT merge veto
    pair = (flood[0], _neg("t0", "other", ChainStage.ELEVATION, 95, 110, 1.0))
    _, fresh = _reconstructor(_campaign())
    assert all(world.status is WorldStatus.UNRESOLVED
               for world in fresh.reconstruct(round_index=110, negative=pair))
    # a negative claim about a stage the world lacks, or a disjoint window, counts for nothing
    _, other = _reconstructor(_campaign())
    stray = (_neg("u0", "u", ChainStage.ACCESS, 95, 110, 1.0),
             _neg("u1", "v", ChainStage.ACCESS, 95, 110, 1.0),
             _neg("w0", "w", ChainStage.CREDENTIAL, 10, 20, 1.0),
             _neg("w1", "q", ChainStage.CREDENTIAL, 10, 20, 1.0))
    worlds = other.reconstruct(round_index=110, negative=stray)
    assert any(world.status is WorldStatus.SUPPORTED for world in worlds)


def test_disabled_falsifier_evaluates_nothing_and_the_world_stays_candidate() -> None:
    _, reconstructor = _reconstructor(_campaign(), falsifier=_falsifier(enabled=False))
    worlds = reconstructor.reconstruct(round_index=110)
    assert worlds and all(world.status is WorldStatus.CANDIDATE for world in worlds)
    _, ablated = _reconstructor(_campaign(), falsify=False)
    assert all(world.status is WorldStatus.SUPPORTED and world.falsification is None
               for world in ablated.reconstruct(round_index=110))


# --- the hypergraph's join rules -------------------------------------------------------


def test_hypergraph_joins_by_interval_overlap_not_equal_timestamps() -> None:
    graph = CampaignHypergraph()
    joined = (_frag("p", "p", ChainStage.CREDENTIAL, 10, 12),
              _frag("q", "q", ChainStage.ELEVATION, 13, 14),
              _frag("r", "r", ChainStage.EGRESS, 15, 16))
    for fragment in joined:
        graph.add_fragment(fragment)
    (edge,) = graph.build_edges(round_index=20)
    assert isinstance(edge, Hyperedge) and len(edge.fragment_ids) == 3  # no two starts are equal
    assert edge.stages == (ChainStage.CREDENTIAL, ChainStage.ELEVATION, ChainStage.EGRESS)
    assert edge.window == (10, 16) and 0.0 < edge.weight <= 1.0
    apart = CampaignHypergraph()
    apart.add_fragment(_frag("s", "s", ChainStage.CREDENTIAL, 10, 11))
    apart.add_fragment(_frag("t", "t", ChainStage.ELEVATION, 17, 18))  # gap 6 > join window 4
    assert apart.build_edges(round_index=20) == ()
    one_cluster = CampaignHypergraph()
    for fragment in (_frag("u", "same", ChainStage.CREDENTIAL, 10, 11),
                     _frag("v", "same", ChainStage.ELEVATION, 11, 12),
                     _frag("w", "same", ChainStage.OTHER, 11, 12)):
        one_cluster.add_fragment(fragment)
    assert one_cluster.build_edges(round_index=20) == ()  # one witness is not a campaign


def test_pairwise_control_cannot_express_a_three_stage_world() -> None:
    graph = CampaignHypergraph(enabled=False)
    graph.note_epoch(_se("old"), 0)
    for fragment in _campaign():
        graph.add_fragment(fragment)
    reconstructor = PartialWorldReconstructor(hypergraph=graph, falsifier=_falsifier())
    assert reconstructor.reconstruct(round_index=110) == ()
    assert graph.edges() and all(len(edge.fragment_ids) == 2 for edge in graph.edges())


def test_expire_keeps_incident_preserved_edges() -> None:
    graph = CampaignHypergraph(expiry_rounds=5)
    for fragment in _campaign(10) + _campaign(10)[:0]:
        graph.add_fragment(fragment)
    (edge,) = graph.build_edges(round_index=15)
    assert graph.expire(round_index=40, preserved=frozenset({edge.edge_id})) == 0
    assert graph.edges() == (edge,) and len(graph.fragments()) == 4
    removed = graph.expire(round_index=40)
    assert removed == 5 and graph.edges() == () and graph.fragments() == ()
    assert graph.evictions() == 5


def test_invalid_fragments_and_claims_are_refused() -> None:
    good = _frag("ok", "c", ChainStage.CREDENTIAL, 5, 6)
    for bad in ({"window": (6, 5)}, {"window": (0, 40)}, {"rarity": 1.5}, {"rarity": math.nan},
                {"stage": "CREDENTIAL"}, {"cluster_id": ""}, {"window": [5, 6]}):
        with pytest.raises(ContractError):
            dataclasses.replace(good, **bad)
    with pytest.raises(ContractError):
        _neg("bad", "c", ChainStage.CREDENTIAL, 5, 6, 1.2)
    with pytest.raises(ContractError):
        _falsifier(stage_base_rates={ChainStage.CREDENTIAL: -0.1})
    with pytest.raises(ContractError):
        _falsifier(relevant_hosts=0)
    graph, reconstructor = _reconstructor(_campaign())
    world = next(item for item in reconstructor.reconstruct(round_index=110))
    with pytest.raises(ContractError):  # fragments that are not the world's are refused
        _falsifier().falsify(world, (good,), birth_burst=lambda _ids: False)
    with pytest.raises(ContractError):
        CampaignHypergraph(max_fragments=0)
    assert graph.fragments()


def test_count_threshold_join_is_the_dumb_control() -> None:
    fragments = _campaign()
    everything = tuple(sorted(item.capsule_id for item in fragments))
    assert count_threshold_join(fragments, window=4, k=2) == (everything,)
    assert count_threshold_join(fragments, window=4, k=3) == ()  # only two clusters
    with pytest.raises(ContractError):
        count_threshold_join(fragments, window=4, k=0)


def test_work_meter_bounds_the_join() -> None:
    graph = CampaignHypergraph(meter=WorkMeter(budget=3))
    for fragment in _campaign():
        graph.add_fragment(fragment)
    with pytest.raises(WorkBudgetExceeded):
        graph.build_edges(round_index=110)


# --- collective novelty, beyond the required pair --------------------------------------


def test_novelty_without_a_release_is_insufficient_and_one_cluster_is_local_only() -> None:
    engine = CollectiveNoveltyEngine(local=_local())
    engine.note_epoch(_se("old"), 0)
    pattern = "mf-" + _hex("p2", 16)
    for round_index in range(16):
        for cluster in ("a", "b"):
            engine.observe_report(pattern, stages=(ChainStage.CREDENTIAL,), cluster_id=_cl(cluster),
                                  software_epoch=_se("old"), round_index=round_index + 20)
    (unknown,) = engine.evaluate(round_index=35)
    assert unknown.status is NoveltyStatus.INSUFFICIENT and unknown.rarity == 0.0
    assert engine.rarity_of(pattern, round_index=35) == 0.0
    # a release for ANOTHER role does not make rarity known for a WEB receiver (conditioning)
    engine.observe_population({pattern: 0}, role=RoleClass.ADMIN, round_index=35)
    assert engine.evaluate(round_index=35)[0].status is NoveltyStatus.INSUFFICIENT
    # a common pattern among WEB hosts is not rare
    engine.observe_population({pattern: 40}, role=RoleClass.WEB, round_index=35)
    assert engine.rarity_of(pattern, round_index=35) == 0.0
    single = CollectiveNoveltyEngine(local=_local())
    single.observe_report(pattern, stages=(ChainStage.CREDENTIAL,), cluster_id=_cl("a"),
                          software_epoch=_se("old"), round_index=1)
    assert single.evaluate(round_index=1)[0].status is NoveltyStatus.LOCAL_ONLY


def test_novelty_tables_are_bounded_under_flood() -> None:
    engine = CollectiveNoveltyEngine(local=_local(), max_patterns=32)
    for index in range(1000):
        engine.observe_report("mf-" + _hex(f"flood{index}", 16), stages=(ChainStage.EGRESS,),
                              cluster_id=_cl("x"), software_epoch=_se(f"e{index}"),
                              round_index=index % 50)
    engine.observe_population({"mf-" + _hex(f"pop{index}", 16): 1 for index in range(500)},
                              role=RoleClass.WEB, round_index=50)
    stats = engine.stats()
    assert engine.patterns() == 32 and stats["population_patterns"] == 32 and stats["epochs"] == 32
    assert stats["pattern_evictions"] == 968 and engine.evictions() > 0
    key = "mf-" + _hex("hot", 16)
    for round_index in range(MAX_REPORTS_PER_PATTERN + 10):
        engine.observe_report(key, stages=(), cluster_id=_cl("x"), software_epoch=_se("e"),
                              round_index=round_index)
    assert engine.stats()["report_drops"] == 10
    with pytest.raises(ContractError):
        engine.observe_population({key: True}, role=RoleClass.WEB, round_index=1)  # type: ignore[dict-item]


def test_novelty_observe_takes_novelty_capsules_only() -> None:
    def capsule(knowledge_type: KnowledgeType) -> object:
        return seal_capsule(
            knowledge_type=knowledge_type, stance=Stance.SUPPORT,
            semantic_invariant=(MotifRow(relation=int(Relation.READ), require_properties=1,
                                         forbid_properties=0, require_raised=0),),
            attack_mappings=(),
            epoch_context=EpochContext(software_epoch=_se("old"), visibility=VisibilityClass.FULL),
            source_context_sketch=SourceContextSketch(role=RoleClass.WEB,
                                                      family_profile=(1,) * len(RelationFamily)),
            validation_summary=ValidationSummary(episodes_replayed=1, true_matches=1,
                                                 false_matches=0),
            falsification_summary=FalsificationSummary(mutations_tried=0, mutations_survived=0,
                                                       counter_hypotheses=()),
            provenance_commitment=ProvenanceCommitment(
                contributor="peer-" + _hex("peer", 16), provenance_root="root-" + _hex("root", 16),
                evidence_commitments=("hc-" + _hex("ev", 32),), aggregation_decision=None),
            independence_group="root-" + _hex("root", 16),
            privacy_class=PrivacyClass.PUBLIC_DERIVED,
            created_round=3, expiry_round=10, sequence=0, parent_capsules=(), time_window=None,
            observability=None, revocation_target=None, revocation_ground=None,
            key_id="key-" + _hex("key", 16),
        )

    engine = CollectiveNoveltyEngine(local=_local())
    novelty = capsule(KnowledgeType.NOVELTY)
    for kind in (KnowledgeType.NOVELTY, KnowledgeType.ANTIBODY):
        engine.observe(SimpleNamespace(capsule=capsule(kind), cluster_id=_cl("a"),  # type: ignore[arg-type]
                                       received_round=3))
    (result,) = engine.evaluate(round_index=3)
    assert result.pattern_key == novelty.compact_feature_signature  # type: ignore[attr-defined]
    assert engine.stats()["ignored_non_novelty"] == 1
