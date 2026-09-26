"""Stage 7 package ``graph``: D7.5 epistemic distance, D7.6 gravity, D7.8 dependence/Sybil graph, §22 trust.

Every defence here is attacked, not just constructed: Sybils sharing a root, relays,
birth-burst co-timing, the staggered/jittered adaptive Sybil (a documented gap), a
relaying identity that bridges honest clusters (a documented gap), a peer flood against
the graph's cap, and slow-poisoning trust. Tests that pin a *known weakness* are named
for what they show, so a later fix flips them loudly instead of silently.
"""

from __future__ import annotations

import hashlib
import math

import pytest

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.ssir.relations import Relation, RelationFamily
from pocketsec.stage6.capsule.experience_capsule import PrivacyClass
from pocketsec.stage6.resources import WorkBudgetExceeded, WorkMeter
from pocketsec.stage7.capsule.knowledge_capsule import (
    MAX_EXPIRY_HORIZON_ROUNDS,
    EpochContext,
    FalsificationSummary,
    KnowledgeCapsuleV1,
    KnowledgeType,
    MotifRow,
    ProvenanceCommitment,
    RoleClass,
    SourceContextSketch,
    Stance,
    ValidationSummary,
    VisibilityClass,
    seal_capsule,
)
from pocketsec.stage7.graph.dependence import (
    BURST_MIN,
    UNASSESSED_CLUSTER_ID,
    DependenceGraph,
    EdgeKind,
    cluster_id_for,
)
from pocketsec.stage7.graph.sybil import (
    SYBIL_MIN_CLUSTER,
    SybilReport,
    amplification_factor,
    sybil_report,
)
from pocketsec.stage7.identity.peer import PeerIdentity
from pocketsec.stage7.relevance.epistemic_distance import (
    DISTANCE_WEIGHTS,
    EpistemicDistance,
    LocalContext,
    epistemic_distance,
    relevance,
)
from pocketsec.stage7.relevance.gravity import KnowledgeGravity, knowledge_gravity
from pocketsec.stage7.trust.contextual import (
    CONFIRM_STEP,
    REFUTE_FACTOR,
    TRUST_FLOOR,
    TRUST_PRIOR,
    ContextualTrust,
    task_key,
)

PROFILE_LEN = len(RelationFamily)
EPOCH_A = "se-" + "a" * 16
EPOCH_B = "se-" + "b" * 16


# --- builders ------------------------------------------------------------------------


def _hex(seed: str, length: int) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()[:length]


def _root(name: str) -> str:
    return "root-" + _hex("root:" + name, 16)


def _peer(name: str, *, root: str | None = None, born: int = 0) -> PeerIdentity:
    return PeerIdentity(
        peer_id="peer-" + _hex("peer:" + name, 16),
        key_id="key-" + _hex("key:" + name, 16),
        provenance_root=root if root is not None else _root(name),
        role_claim=RoleClass.WEB,
        first_seen_round=born,
        last_seen_round=born,
    )


def _capsule(
    peer: PeerIdentity,
    *,
    key: int = 1,
    relation: int = int(Relation.READ),
    round_index: int = 0,
    true_matches: int = 5,
    false_matches: int = 0,
    episodes: int = 20,
    profile: tuple[int, ...] = (1,) * PROFILE_LEN,
    role: RoleClass = RoleClass.WEB,
    epoch: str = EPOCH_A,
    visibility: VisibilityClass = VisibilityClass.FULL,
    parents: tuple[str, ...] = (),
    sequence: int = 0,
) -> KnowledgeCapsuleV1:
    """A real, sealed ANTIBODY capsule; ``key`` selects the invariant (and so the antibody key)."""
    return seal_capsule(
        knowledge_type=KnowledgeType.ANTIBODY,
        stance=Stance.SUPPORT,
        semantic_invariant=(MotifRow(relation=relation, require_properties=key,
                                     forbid_properties=0, require_raised=0),),
        attack_mappings=(),
        epoch_context=EpochContext(software_epoch=epoch, visibility=visibility),
        source_context_sketch=SourceContextSketch(role=role, family_profile=profile),
        validation_summary=ValidationSummary(episodes_replayed=episodes, true_matches=true_matches,
                                             false_matches=false_matches),
        falsification_summary=FalsificationSummary(mutations_tried=0, mutations_survived=0,
                                                   counter_hypotheses=()),
        provenance_commitment=ProvenanceCommitment(
            contributor=peer.peer_id, provenance_root=peer.provenance_root,
            evidence_commitments=("hc-" + _hex(f"ev:{peer.peer_id}:{key}:{round_index}", 32),),
            aggregation_decision=None),
        independence_group=peer.provenance_root,
        privacy_class=PrivacyClass.PUBLIC_DERIVED,
        created_round=round_index,
        expiry_round=round_index + 16,
        sequence=sequence,
        parent_capsules=parents,
        time_window=None,
        observability=None,
        revocation_target=None,
        revocation_ground=None,
        key_id=peer.key_id,
    )


def _local(**overrides: object) -> LocalContext:
    fields: dict[str, object] = dict(
        role=RoleClass.WEB, software_epoch=EPOCH_A, visibility=VisibilityClass.FULL,
        family_profile=(1,) * PROFILE_LEN, local_keys=frozenset(),
        observable_relations=frozenset(int(r) for r in Relation),
    )
    fields.update(overrides)
    return LocalContext(**fields)  # type: ignore[arg-type]


def _cluster_count(graph: DependenceGraph) -> int:
    return len(graph.clusters())


# --- D7.8 dependence graph ----------------------------------------------------------


def test_sybils_sharing_a_root_are_one_cluster() -> None:
    """NO_UNBOUNDED_IDENTITY_INFLUENCE: S identities on one declared root are ONE cluster."""
    root = _root("adversary")
    sybils = [_peer(f"sybil{i}", root=root) for i in range(10)]
    for clustering in (True, False):   # SAME_ROOT is in the control too: it is construction
        graph = DependenceGraph(clustering=clustering)
        ids = {graph.observe(_capsule(p, true_matches=i, key=i + 1), p, round_index=i)
               for i, p in enumerate(sybils)}
        final = {graph.cluster_of(p.peer_id) for p in sybils}
        assert len(final) == 1 and _cluster_count(graph) == 1
        assert final == {cluster_id_for(min(p.peer_id for p in sybils))}
        assert all(graph.independence(p.peer_id) == pytest.approx(0.1) for p in sybils)
        assert graph.merges_by_kind()[EdgeKind.SAME_ROOT] == 9
        assert sum(graph.merges_by_kind().values()) == 9
        assert len(ids) >= 1
    # The influence of the whole root is one cluster's worth, however many identities vote.
    assert sum(graph.independence(p.peer_id) for p in sybils) == pytest.approx(1.0)


def test_near_identical_relays_merge() -> None:
    origin = _peer("origin")
    relays = [_peer(f"relay{i}") for i in range(3)]
    graph = DependenceGraph()
    graph.observe(_capsule(origin, key=7), origin, round_index=0)
    for i, relay in enumerate(relays):   # distinct declared roots, byte-identical content
        graph.observe(_capsule(relay, key=7, round_index=i + 1), relay, round_index=i + 1)
    assert _cluster_count(graph) == 1
    assert graph.merges_by_kind()[EdgeKind.NEAR_IDENTICAL] == 3
    # One differing self-reported count is not a copy: not merged.
    other = _peer("independent")
    graph.observe(_capsule(other, key=7, false_matches=1), other, round_index=5)
    assert graph.cluster_of(other.peer_id) != graph.cluster_of(origin.peer_id)
    # The control trusts declared roots and so does not see the relay at all.
    control = DependenceGraph(clustering=False)
    for p in (origin, *relays):
        control.observe(_capsule(p, key=7), p, round_index=0)
    assert _cluster_count(control) == 4
    assert control.merges_by_kind()[EdgeKind.NEAR_IDENTICAL] == 0


def test_common_parent_merges() -> None:
    parent = "kc-" + _hex("parent", 24)
    a, b = _peer("a"), _peer("b")
    graph = DependenceGraph()
    graph.observe(_capsule(a, key=1, parents=(parent,)), a, round_index=0)
    graph.observe(_capsule(b, key=2, true_matches=9, parents=(parent,)), b, round_index=1)
    assert graph.cluster_of(a.peer_id) == graph.cluster_of(b.peer_id)
    assert graph.merges_by_kind()[EdgeKind.COMMON_PARENT] == 1


def _co_timed_fleet(graph: DependenceGraph, peers: list[PeerIdentity], *, births: list[int],
                    shared_rounds: range, jitter: bool = True) -> None:
    """Each peer is born with a private key, then sends the SAME keys in the SAME rounds."""
    for i, (peer, born) in enumerate(zip(peers, births, strict=True)):
        graph.observe(_capsule(peer, key=1000 + i, round_index=born, true_matches=i), peer,
                      round_index=born)
    for r in shared_rounds:
        for i, peer in enumerate(peers):
            graph.observe(_capsule(peer, key=r + 1, round_index=r,
                                   true_matches=(i if jitter else 0)), peer, round_index=r)


def test_birth_burst_with_co_timing_merges_but_either_alone_does_not() -> None:
    # Both halves: BURST_MIN peers born together, identical co-timed contributions -> one cluster.
    both = [_peer(f"both{i}") for i in range(BURST_MIN)]
    graph = DependenceGraph()
    _co_timed_fleet(graph, both, births=[0] * BURST_MIN, shared_rounds=range(1, 13))
    assert _cluster_count(graph) == 1
    assert graph.merges_by_kind()[EdgeKind.BIRTH_CO_TIMING] == BURST_MIN - 1
    assert graph.merges_by_kind()[EdgeKind.NEAR_IDENTICAL] == 0   # jittered: not a relay
    report = sybil_report(graph)
    assert len(report.suspected_clusters) == 1 and BURST_MIN >= SYBIL_MIN_CLUSTER

    # Co-timing alone: one peer short of a burst.
    short = [_peer(f"short{i}") for i in range(BURST_MIN - 1)]
    graph = DependenceGraph()
    _co_timed_fleet(graph, short, births=[0] * len(short), shared_rounds=range(1, 13))
    assert _cluster_count(graph) == len(short)
    assert sum(graph.merges_by_kind().values()) == 0

    # Burst alone: born together, but every peer contributes its own keys.
    burst = [_peer(f"burst{i}") for i in range(BURST_MIN)]
    graph = DependenceGraph()
    for r in range(4):
        for i, peer in enumerate(burst):
            graph.observe(_capsule(peer, key=100 * (i + 1) + r, round_index=r), peer, round_index=r)
    assert _cluster_count(graph) == BURST_MIN
    assert sum(graph.merges_by_kind().values()) == 0


def test_staggered_jittered_sybils_are_not_merged() -> None:
    """The ADAPTIVE gap, pinned as current behaviour (G7.4 is expected to FAIL on it).

    Forged roots, one birth every 3 rounds, jittered summaries, then perfectly co-timed
    poison: no edge fires, every Sybil is an independent cluster, and the adversary's
    identity count buys full independence. The same traffic born in one burst IS merged,
    so the staggering alone is what defeats the graph. Closing this needs an identity
    authority, which stdlib cannot provide (ADR-0064).
    """
    sybils = [_peer(f"adaptive{i}") for i in range(BURST_MIN)]
    staggered = DependenceGraph()
    _co_timed_fleet(staggered, sybils, births=[3 * i for i in range(BURST_MIN)],
                    shared_rounds=range(30, 42))
    assert _cluster_count(staggered) == BURST_MIN
    assert all(staggered.independence(p.peer_id) == 1.0 for p in sybils)
    assert sum(staggered.merges_by_kind().values()) == 0

    burst = DependenceGraph()
    _co_timed_fleet(burst, sybils, births=[0] * BURST_MIN, shared_rounds=range(30, 42))
    assert _cluster_count(burst) == 1


def test_honest_same_image_hosts_are_not_merged() -> None:
    """There is no same-software-image edge: one golden image does not make one vote."""
    hosts = [_peer(f"honest{i}") for i in range(12)]
    graph = DependenceGraph()
    for i, host in enumerate(hosts):   # same image, same role, same true antibody key
        graph.observe(_capsule(host, key=42, epoch=EPOCH_A, true_matches=3 + i, round_index=i),
                      host, round_index=i)
    assert _cluster_count(graph) == len(hosts)
    assert sum(graph.merges_by_kind().values()) == 0
    assert all(graph.independence(h.peer_id) == 1.0 for h in hosts)


def test_co_born_honest_hosts_with_identical_timing_are_falsely_merged() -> None:
    """Known false-Sybil: at fleet boot every honest host is in one birth burst, so honest
    hosts that send the same true keys in the same rounds are merged like Sybils. Distinct
    roots and distinct self-reported counts do not help. G7.5(b) measures the rate."""
    honest = [_peer(f"boot{i}") for i in range(BURST_MIN)]
    graph = DependenceGraph()
    for r in range(4):
        for i, host in enumerate(honest):
            graph.observe(_capsule(host, key=r + 1, round_index=r, true_matches=10 + i + r),
                          host, round_index=r)
    assert _cluster_count(graph) == 1
    assert graph.merges_by_kind()[EdgeKind.BIRTH_CO_TIMING] == BURST_MIN - 1


def test_one_relaying_identity_bridges_honest_clusters() -> None:
    """Known gap: edges are attacker-creatable and union-find is transitive. One identity
    that relays a copy of each honest capsule collapses N honest clusters into one. It only
    lowers mass (suppression, never acceptance); the Sybil report flags the result."""
    honest = [_peer(f"victim{i}") for i in range(8)]
    bridge = _peer("bridge")
    graph = DependenceGraph()
    for i, host in enumerate(honest):
        graph.observe(_capsule(host, key=i + 1, true_matches=i), host, round_index=i)
    assert _cluster_count(graph) == 8
    for i in range(len(honest)):   # byte-identical relays of each victim's content
        graph.observe(_capsule(bridge, key=i + 1, true_matches=i, round_index=10), bridge,
                      round_index=10)
    assert _cluster_count(graph) == 1
    assert graph.independence(honest[0].peer_id) == pytest.approx(1 / 9)
    assert graph.cluster_of(bridge.peer_id) in sybil_report(graph).suspected_clusters


def test_peer_flood_hits_graph_bound() -> None:
    cap = 16
    graph = DependenceGraph(max_peers=cap, max_history=4, max_edges_per_peer=2)
    established = [_peer(f"est{i}") for i in range(cap)]
    for i, peer in enumerate(established):
        graph.observe(_capsule(peer, key=i + 1), peer, round_index=0)
    full_bytes = graph.memory_bytes()
    flood = [_peer(f"flood{i}", root=_root("flooder")) for i in range(500)]
    for i, peer in enumerate(flood):
        assert graph.observe(_capsule(peer, key=i + 1), peer, round_index=1) == UNASSESSED_CLUSTER_ID
    assert len(graph) == cap and graph.evictions() == 500
    assert graph.memory_bytes() == full_bytes          # the flood cost the graph nothing
    assert all(graph.cluster_of(p.peer_id) != UNASSESSED_CLUSTER_ID for p in established)
    # A refused identity is unassessed, and unassessed is NOT independent: a flood past
    # the cap cannot buy one full vote per identity.
    assert {graph.cluster_of(p.peer_id) for p in flood} == {UNASSESSED_CLUSTER_ID}
    assert all(graph.independence(p.peer_id) == 0.0 for p in flood)
    assert sybil_report(graph).refused_peers == 500

    # One peer flooding its own history hits max_history; memory stays flat.
    talker = established[0]
    for r in range(2, 12):
        graph.observe(_capsule(talker, key=r + 50, round_index=r), talker, round_index=r)
    steady = graph.memory_bytes()
    for r in range(12, 400):
        graph.observe(_capsule(talker, key=r + 50, round_index=r), talker, round_index=r)
    # 388 more events held unboundedly would add tens of KiB; dict slack is < 4 KiB.
    assert graph.memory_bytes() <= steady + 4096
    assert graph.truncations()["history_events_dropped"] >= 388

    # Edge audit records are bounded per peer; the merges still happen.
    hub = DependenceGraph(max_edges_per_peer=2)
    shared = _root("hub")
    for i in range(10):
        peer = _peer(f"hub{i}", root=shared)
        hub.observe(_capsule(peer, key=i + 1), peer, round_index=0)
    assert _cluster_count(hub) == 1
    assert len(hub.edges()) <= 2 and hub.truncations()["edges_unrecorded"] == 9 - len(hub.edges())


def test_canonical_representative_is_order_independent() -> None:
    root = _root("shared")
    peers = [_peer(f"order{i}", root=root) for i in range(6)]
    forward, backward = DependenceGraph(), DependenceGraph()
    for p in peers:
        forward.observe(_capsule(p), p, round_index=0)
    for p in reversed(peers):
        backward.observe(_capsule(p), p, round_index=0)
    assert forward.clusters() == backward.clusters()
    assert forward.clusters()[0][0] == cluster_id_for(min(p.peer_id for p in peers))


def test_graph_charges_work_and_refuses_unpaid_work() -> None:
    meter = WorkMeter(budget=1)
    graph = DependenceGraph(meter=meter)
    a, b = _peer("paid"), _peer("unpaid")
    graph.observe(_capsule(a), a, round_index=0)
    assert meter.spent == 1
    with pytest.raises(WorkBudgetExceeded):
        graph.observe(_capsule(b), b, round_index=0)
    assert len(graph) == 1 and graph.cluster_of(b.peer_id) == UNASSESSED_CLUSTER_ID


def test_graph_rejects_invalid_input() -> None:
    peer = _peer("x")
    with pytest.raises(ContractError):
        DependenceGraph(max_peers=0)
    with pytest.raises(ContractError):
        DependenceGraph().observe(_capsule(peer), peer, round_index=-1)
    with pytest.raises(ContractError):
        DependenceGraph(clustering=1)  # type: ignore[arg-type]


# --- D7.8 Sybil report / amplification ----------------------------------------------


def test_amplification_factor_definition() -> None:
    assert amplification_factor(0.5, 0.25) == pytest.approx(2.0)
    assert amplification_factor(0.25, 0.25) == pytest.approx(1.0)
    assert amplification_factor(0.0, 0.5) == 0.0
    assert amplification_factor(0.3, 0.0) is None          # undefined, not inf and not 0
    for bad in ((1.5, 0.5), (-0.1, 0.5), (0.5, math.nan), (True, 0.5)):
        with pytest.raises(ContractError):
            amplification_factor(*bad)  # type: ignore[arg-type]

    # Lab path: 4 honest roots + 1 adversary root with 8 identities on it.
    graph = DependenceGraph()
    honest = [_peer(f"h{i}") for i in range(4)]
    adversary = [_peer(f"s{i}", root=_root("adv")) for i in range(8)]
    for i, p in enumerate(honest + adversary):
        graph.observe(_capsule(p, key=i + 1), p, round_index=0)
    naive = {p.peer_id: 1.0 for p in honest + adversary}           # identity vote
    capped = {p.peer_id: graph.independence(p.peer_id) for p in honest + adversary}
    adv_ids = frozenset(p.peer_id for p in adversary)
    lab = dict(adversary_peers=adv_ids, adversary_true_roots=1, total_true_roots=5)
    naive_report = sybil_report(graph, support_mass_by_peer=naive, **lab)
    capped_report = sybil_report(graph, support_mass_by_peer=capped, **lab)
    assert naive_report.amplification == pytest.approx((8 / 12) / (1 / 5))
    assert capped_report.amplification == pytest.approx(1.0)
    assert sybil_report(graph).amplification is None                 # no lab truth: None
    assert sybil_report(graph, support_mass_by_peer={p: 0.0 for p in naive},
                        **lab).amplification is None                 # no mass accepted
    with pytest.raises(ContractError):
        sybil_report(graph, adversary_peers=adv_ids)                 # partial lab truth
    empty = sybil_report(DependenceGraph())
    assert empty.peers == 0 and empty.largest_cluster_share is None
    with pytest.raises(ContractError):
        SybilReport(peers=0, clusters=0, largest_cluster_share=0.0, suspected_clusters=(),
                    amplification=None, refused_peers=0)


# --- §22 contextual trust -----------------------------------------------------------


def test_trust_is_task_scoped_and_decays() -> None:
    trust = ContextualTrust(half_life_rounds=10)
    cluster, web, desktop = "cl-" + "1" * 16, task_key(("PERSISTENCE",)), task_key(("CREDENTIAL", "EGRESS"))
    assert desktop == "CREDENTIAL-EGRESS"
    for _ in range(3):
        trust.record(cluster, web, confirmed=True, round_index=0)
    assert trust.reliability(cluster, web, round_index=0) == pytest.approx(TRUST_PRIOR + 3 * CONFIRM_STEP)
    assert trust.reliability(cluster, desktop, round_index=0) == TRUST_PRIOR   # other task: nothing earned
    assert trust.reliability("cl-" + "2" * 16, web, round_index=0) == TRUST_PRIOR
    excess = 3 * CONFIRM_STEP
    assert trust.reliability(cluster, web, round_index=10) == pytest.approx(TRUST_PRIOR + excess / 2)
    assert trust.reliability(cluster, web, round_index=1000) == pytest.approx(TRUST_PRIOR, abs=1e-9)
    trust.record(cluster, desktop, confirmed=False, round_index=0)
    assert trust.reliability(cluster, desktop, round_index=10) == pytest.approx(
        TRUST_PRIOR + (TRUST_PRIOR * REFUTE_FACTOR - TRUST_PRIOR) / 2)
    with pytest.raises(ContractError):
        task_key(())


def test_refutation_outweighs_confirmation() -> None:
    """SLOW_POISON defence: any run of cheap confirmations is undone by ONE local refutation."""
    trust = ContextualTrust()
    cluster, task = "cl-" + "3" * 16, "PERSISTENCE"
    for _ in range(50):
        trust.record(cluster, task, confirmed=True, round_index=5)
    assert trust.reliability(cluster, task, round_index=5) == 1.0          # clamped at the ceiling
    trust.record(cluster, task, confirmed=False, round_index=5)
    assert trust.reliability(cluster, task, round_index=5) == pytest.approx(REFUTE_FACTOR)
    assert trust.reliability(cluster, task, round_index=5) < TRUST_PRIOR
    for _ in range(10):
        trust.record(cluster, task, confirmed=False, round_index=5)
    assert trust.reliability(cluster, task, round_index=5) == TRUST_FLOOR   # clamped, never 0
    state = trust.state(cluster, task)
    assert state is not None and (state.confirmations, state.refutations) == (50, 11)


def test_trust_eviction_never_lifts_a_refuted_cluster() -> None:
    trust = ContextualTrust(capacity=2)
    low, high, newcomer = ("cl-" + c * 16 for c in "abc")
    trust.record(low, "EGRESS", confirmed=False, round_index=0)
    trust.record(high, "EGRESS", confirmed=True, round_index=0)
    trust.record(newcomer, "EGRESS", confirmed=True, round_index=1)
    assert trust.evictions() == 1 and len(trust) == 2
    assert trust.state(high, "EGRESS") is None            # the trusted one was forgotten
    assert trust.reliability(low, "EGRESS", round_index=1) < TRUST_PRIOR
    assert trust.memory_bytes() > 0


def test_disabled_trust_is_constant_prior() -> None:
    trust = ContextualTrust(enabled=False)
    cluster = "cl-" + "4" * 16
    for confirmed in (True, False, True):
        trust.record(cluster, "ELEVATION", confirmed=confirmed, round_index=3)
    assert trust.reliability(cluster, "ELEVATION", round_index=3) == TRUST_PRIOR
    assert len(trust) == 0 and trust.state(cluster, "ELEVATION") is None
    with pytest.raises(ContractError):
        trust.reliability("not an id!", "ELEVATION", round_index=0)
    with pytest.raises(ContractError):
        ContextualTrust(prior=0.0)                        # below the floor
    with pytest.raises(ContractError):
        ContextualTrust().record(cluster, "X", confirmed=1, round_index=0)  # type: ignore[arg-type]


# --- D7.5 epistemic distance --------------------------------------------------------


def test_distance_terms_and_control() -> None:
    local = _local()
    same = epistemic_distance(SourceContextSketch(RoleClass.WEB, (1,) * PROFILE_LEN),
                              EpochContext(EPOCH_A, VisibilityClass.FULL), local)
    assert same.total == 0.0 and relevance(same) == 1.0

    far_profile = (3,) * PROFILE_LEN     # every family 2 levels away
    far = epistemic_distance(SourceContextSketch(RoleClass.DESKTOP, far_profile),
                             EpochContext(EPOCH_B, VisibilityClass.LOW), local)
    assert (far.role, far.software_epoch, far.visibility) == (1.0, 1.0, 1.0)
    assert far.behaviour == pytest.approx(2 / 3)
    expected = (DISTANCE_WEIGHTS["role"] + DISTANCE_WEIGHTS["software_epoch"]
                + DISTANCE_WEIGHTS["visibility"] + DISTANCE_WEIGHTS["behaviour"] * 2 / 3)
    assert far.total == pytest.approx(expected)
    assert relevance(far) == pytest.approx(1 / (1 + expected))

    unknown = epistemic_distance(SourceContextSketch(RoleClass.UNKNOWN, (1,) * PROFILE_LEN),
                                 EpochContext(EPOCH_A, VisibilityClass.PARTIAL),
                                 _local(role=RoleClass.UNKNOWN))
    assert unknown.role == 0.5 and unknown.visibility == 0.5   # UNKNOWN is never "same role"

    # The CONTROL is role equality: same terms reported, total is the role term alone.
    control = epistemic_distance(SourceContextSketch(RoleClass.WEB, far_profile),
                                 EpochContext(EPOCH_B, VisibilityClass.LOW), local, enabled=False)
    assert control.total == 0.0 and control.software_epoch == 1.0
    control_far = epistemic_distance(SourceContextSketch(RoleClass.DESKTOP, far_profile),
                                     EpochContext(EPOCH_B, VisibilityClass.LOW), local, enabled=False)
    assert control_far.total == DISTANCE_WEIGHTS["role"]

    with pytest.raises(ContractError):
        _local(family_profile=(1,) * (PROFILE_LEN - 1))
    with pytest.raises(ContractError):
        _local(family_profile=(4,) * PROFILE_LEN)
    with pytest.raises(ContractError):
        _local(software_epoch="se-short")


def test_policy_and_architecture_distance_are_none() -> None:
    distance = epistemic_distance(SourceContextSketch(RoleClass.DEV, (0,) * PROFILE_LEN),
                                  EpochContext(EPOCH_B, VisibilityClass.PARTIAL), _local())
    assert distance.policy is None and distance.architecture is None
    with pytest.raises(ContractError):
        EpistemicDistance(total=0.0, role=0.0, software_epoch=0.0, visibility=0.0, behaviour=0.0,
                          policy=0.0, architecture=None)  # type: ignore[arg-type]


# --- D7.6 knowledge gravity ---------------------------------------------------------


def test_gravity_formula_values() -> None:
    peer = _peer("grav")
    capsule = _capsule(peer, true_matches=8, false_matches=0, round_index=10)
    distance = epistemic_distance(capsule.source_context_sketch, capsule.epoch_context, _local())
    gravity = knowledge_gravity(capsule, distance=distance, independence=0.5, suspicion=1.0,
                                local=_local(), round_index=26)
    assert isinstance(gravity, KnowledgeGravity)
    assert gravity.validation == pytest.approx(9 / 10)
    assert gravity.recency == pytest.approx(1 - 16 / MAX_EXPIRY_HORIZON_ROUNDS)
    assert gravity.value == pytest.approx(0.9 * 0.5 * 1.0 * gravity.recency / 2.0)
    # A forged perfect record raises validation to near 1 — declared forgeable, and bounded by 1.
    forged = _capsule(peer, true_matches=10_000, false_matches=0, episodes=10_000, round_index=10)
    assert knowledge_gravity(forged, distance=distance, independence=1.0, suspicion=0.0,
                             local=_local(), round_index=10).validation < 1.0
    # Unassessed peers (independence 0) and stale capsules have zero gravity.
    assert knowledge_gravity(capsule, distance=distance, independence=0.0, suspicion=0.0,
                             local=_local(), round_index=10).value == 0.0
    assert knowledge_gravity(capsule, distance=distance, independence=1.0, suspicion=0.0,
                             local=_local(), round_index=10 + MAX_EXPIRY_HORIZON_ROUNDS).value == 0.0
    for bad in ({"independence": 1.5}, {"suspicion": -1.0}, {"suspicion": math.inf}):
        kwargs = dict(distance=distance, independence=0.5, suspicion=0.0, local=_local(),
                      round_index=10)
        kwargs.update(bad)
        with pytest.raises(ContractError):
            knowledge_gravity(capsule, **kwargs)  # type: ignore[arg-type]


def test_gravity_zero_when_relation_unobservable() -> None:
    peer = _peer("blind")
    capsule = _capsule(peer, relation=int(Relation.CONNECT), round_index=0)
    distance = epistemic_distance(capsule.source_context_sketch, capsule.epoch_context, _local())
    blind = _local(observable_relations=frozenset(int(r) for r in Relation) - {int(Relation.CONNECT)})
    gravity = knowledge_gravity(capsule, distance=distance, independence=1.0, suspicion=0.0,
                                local=blind, round_index=0)
    assert gravity.compatibility == 0.0 and gravity.value == 0.0
    seeing = knowledge_gravity(capsule, distance=distance, independence=1.0, suspicion=0.0,
                               local=_local(), round_index=0)
    assert seeing.compatibility == 1.0 and seeing.value > 0.0
