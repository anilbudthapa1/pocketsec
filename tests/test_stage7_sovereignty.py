"""Stage 7 package ``sovereignty``: lineage/revocation (D7.16), secure sum (D7.17), the Stage 6
bridge (layer 7.16) and the ORPHEUS fabric (layer 7.20).

Every defence here is attacked, not constructed. A 64-peer fleet with independent roots
agrees unanimously against the receiving host and must change none of its local decisions,
while the SAME fleet supporting an antibody the host can validate does reach Stage 6 (the
positive control that proves the mechanism fires, lesson 1). Revocations are forged,
third-party, unknown-target and local-target, and must change nothing; an accepted one must
touch exactly the descendants and be undone byte-for-byte. The fabric is flooded while
offline, disabled, crashing every round and running over a corrupted trust store, and local
detection must not move by one bit. The Stage 6 side is a REAL ``QuarantineGateway`` bound to
``genesis_state`` built here; nothing about Stage 6 is mocked except where a test says so.

Tests named in the collective constitution (``constitution/collective.py``) keep their names.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass

import pytest

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.epoch.model import EpochModel, SystemIdentity
from pocketsec.stage1.labs.corpus import (
    ATTACK_EXFIL,
    ATTACK_PERSISTENCE,
    BENIGN_PATTERNS,
    Behaviour,
    Scenario,
)
from pocketsec.stage1.pipeline import Stage1Pipeline
from pocketsec.stage1.ssir.relations import Relation, RelationFamily
from pocketsec.stage6.capsule.experience_capsule import EncodedStep, PrivacyClass, source_group_of
from pocketsec.stage6.capsule.quarantine import QuarantineBucket, QuarantineGateway
from pocketsec.stage6.fleet.package import FleetDisabledError
from pocketsec.stage6.fossils.lineage import KnowledgeLineageDAG
from pocketsec.stage6.memory.semantic import genesis_state
from pocketsec.stage6.provenance.ledger import ProvenanceLedger
from pocketsec.stage7.aggregation import secure
from pocketsec.stage7.aggregation.secure import (
    MAX_PARTICIPANTS,
    MAX_VECTOR_LEN,
    MODULUS,
    SECURE_AGGREGATION_ENABLED,
    aggregate_masked,
    mask_vector,
    pairwise_mask,
)
from pocketsec.stage7.antibody.forge import (
    BenignRing,
    KnowledgeAntibody,
    LocalIncident,
    LocalValidation,
    LocalValidator,
    forge_antibody,
    matches,
    prototype_steps,
)
from pocketsec.stage7.campaign.hypergraph import CampaignHypergraph, Hyperedge
from pocketsec.stage7.capsule.knowledge_capsule import (
    ChainStage,
    EpochContext,
    FalsificationSummary,
    KnowledgeCapsuleV1,
    KnowledgeType,
    MotifRow,
    ProvenanceCommitment,
    RevocationGround,
    RoleClass,
    SourceContextSketch,
    Stance,
    ValidationSummary,
    VisibilityClass,
    motif_fingerprint,
    seal_capsule,
)
from pocketsec.stage7.constitution.collective import COLLECTIVE_EXCHANGE_ENABLED
from pocketsec.stage7.echo.inference import (
    ClusterEvidence,
    EchoConfig,
    EchoDecision,
    EchoStatus,
)
from pocketsec.stage7.falsifier.consensus import ConsensusFalsifier
from pocketsec.stage7.governor.communication import CommunicationGovernor, ExchangeMode
from pocketsec.stage7.graph.dependence import DependenceGraph
from pocketsec.stage7.hivelock.ingress import IngressOutcome, IngressStage
from pocketsec.stage7.hivelock.stage6_bridge import Stage6Bridge
from pocketsec.stage7.identity.integrity import Keyring, ReplayGuard
from pocketsec.stage7.identity.peer import PeerTable
from pocketsec.stage7.lineage.cross_host import (
    CrossHostLineageDAG,
    LineageRecord,
    LinkState,
    NodeRole,
    RevocationPlane,
    stage6_link_detail,
)
from pocketsec.stage7.novelty.collective import CollectiveNoveltyEngine
from pocketsec.stage7.orpheus.fabric import FabricComponents, FabricState, OrpheusFabric
from pocketsec.stage7.relevance.epistemic_distance import LocalContext
from pocketsec.stage7.trust.contextual import ContextualTrust

# --- identities and motifs -------------------------------------------------------------------

LOCAL_HOST = 1000
FLEET = tuple(range(1, 65))  # the 64 independent-root peers of G7.1(c)
SE = "se-" + "0" * 16
PROFILE = (1,) * len(RelationFamily)
ALL_RELATIONS = frozenset(int(r) for r in Relation)
LOCAL_ROWS = (MotifRow(13, 0, 0, 1), MotifRow(10, 128, 0, 0))  # locally confirmed incident
FP_ROWS = (MotifRow(int(Relation.EXECUTE), 4, 0, 0),)  # matches the host's benign ring
PASS_ROWS = (MotifRow(int(Relation.READ), 1, 0, 4),)  # observable, matches nothing local
LOCAL_KEY = motif_fingerprint(LOCAL_ROWS)
FP_KEY = motif_fingerprint(FP_ROWS)
PASS_KEY = motif_fingerprint(PASS_ROWS)
IDENTITY = SystemIdentity(
    kernel_id="k-6.1", package_digest="pkg-1", service_digest="svc-1",
    container_id="host", policy_digest="pol-1", user_role_digest="role-1",
)


def _hex(tag: str, n: int, width: int) -> str:
    return hashlib.sha256(f"{tag}:{n}".encode()).hexdigest()[:width]


def peer_id(n: int) -> str:
    return "peer-" + _hex("peer", n, 16)


def key_id(n: int) -> str:
    return "key-" + _hex("key", n, 16)


def root_id(n: int) -> str:
    return "root-" + _hex("root", n, 16)


def key_bytes(n: int) -> bytes:
    return hashlib.sha256(f"simulated-key:{n}".encode()).digest()


def kc(n: int) -> str:
    return "kc-" + _hex("kc", n, 24)


def cl(n: int) -> str:
    return "cl-" + _hex("cl", n, 16)


def raw(n: int) -> str:
    return "sha256:" + hashlib.sha256(f"raw:{n}".encode()).hexdigest()


def capsule(
    n: int, *, sequence: int, rows: tuple[MotifRow, ...] = PASS_ROWS,
    kind: KnowledgeType = KnowledgeType.ANTIBODY, stance: Stance = Stance.SUPPORT,
    target: str | None = None, ground: RevocationGround = RevocationGround.SELF_RETRACTION,
    contributor: int | None = None, signer: int | None = None, created: int = 0,
) -> KnowledgeCapsuleV1:
    """An UNSIGNED capsule from simulated peer ``n``. Summaries vary with ``n`` so honest
    independent peers are not NEAR_IDENTICAL copies of one another."""
    revocation = kind is KnowledgeType.REVOCATION
    return seal_capsule(
        knowledge_type=kind, stance=stance,
        semantic_invariant=() if revocation else rows, attack_mappings=(),
        epoch_context=EpochContext(software_epoch=SE, visibility=VisibilityClass.FULL),
        source_context_sketch=SourceContextSketch(role=RoleClass.WEB, family_profile=PROFILE),
        validation_summary=ValidationSummary(
            episodes_replayed=10 + n % 7, true_matches=5 + n % 5, false_matches=0
        ),
        falsification_summary=FalsificationSummary(
            mutations_tried=8, mutations_survived=6 + n % 3, counter_hypotheses=()
        ),
        provenance_commitment=ProvenanceCommitment(
            contributor=peer_id(n if contributor is None else contributor),
            provenance_root=root_id(n),
            evidence_commitments=("hc-" + _hex("hc", n * 1000 + sequence, 32),),
            aggregation_decision=None,
        ),
        independence_group=root_id(n), privacy_class=PrivacyClass.PUBLIC_DERIVED,
        created_round=created, expiry_round=created + 48, sequence=sequence, parent_capsules=(),
        time_window=None, observability=None,
        revocation_target=target if revocation else None,
        revocation_ground=ground if revocation else None,
        key_id=key_id(n if signer is None else signer),
    )


def fleet_signer(*peers: int) -> Keyring:
    ring = Keyring(capacity=2048)
    for n in peers:
        ring.register(key_id(n), key_bytes(n), owner=peer_id(n), round_index=0)
    return ring


SIGNER = fleet_signer(*FLEET, LOCAL_HOST)


def wire(item: KnowledgeCapsuleV1) -> bytes:
    return SIGNER.sign(item, key_id=item.key_id).canonical_bytes()


# --- the local host ----------------------------------------------------------------------------


def _local_validator() -> tuple[LocalValidator, BenignRing]:
    ring = BenignRing()
    ring.add(prototype_steps(FP_ROWS, source_group=source_group_of("benign")))
    steps = prototype_steps(LOCAL_ROWS, source_group=source_group_of("incident"))
    incident = LocalIncident("inc-local", steps, (raw(0),))
    validator = LocalValidator(
        benign=ring, incidents=(incident,), observable_relations=ALL_RELATIONS
    )
    return validator, ring


def local_context(local_keys: frozenset[str] = frozenset({LOCAL_KEY})) -> LocalContext:
    return LocalContext(
        role=RoleClass.WEB, software_epoch=SE, visibility=VisibilityClass.FULL,
        family_profile=PROFILE, local_keys=local_keys, observable_relations=ALL_RELATIONS,
    )


def stage6_receiver() -> tuple[QuarantineGateway, KnowledgeLineageDAG]:
    """A REAL Stage 6 gateway bound to genesis_state (the lab receiver, built here)."""
    dag = KnowledgeLineageDAG()
    gateway = QuarantineGateway(ledger=ProvenanceLedger(), lineage=dag)
    state = genesis_state(identity=IDENTITY)
    gateway.bind_trusted_view(lambda: state)
    return gateway, dag


class RecordingGateway(QuarantineGateway):
    """The real gateway, recording every verdict it issued (optionally rewriting the bucket,
    to prove the bridge records what Stage 6 says rather than what it expects)."""

    def __init__(self, *, forced_bucket: QuarantineBucket | None = None, **kwargs: object) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        self.seen: list[object] = []
        self._forced = forced_bucket

    def admit(self, capsule):  # type: ignore[no-untyped-def]
        verdict = super().admit(capsule)
        if self._forced is not None:
            verdict = dataclasses.replace(verdict, bucket=self._forced)
        self.seen.append(verdict)
        return verdict


@dataclass
class Host:
    fabric: OrpheusFabric
    components: FabricComponents
    gateway: QuarantineGateway
    stage6_dag: KnowledgeLineageDAG
    bridge: Stage6Bridge | None
    validator: LocalValidator


def build_host(
    *, exchange: bool = True, bridge: bool = True, bridge_exchange: bool = True,
    validator: LocalValidator | None = None, hypergraph: CampaignHypergraph | None = None,
    mode: ExchangeMode = ExchangeMode.INCIDENT, local_keys: frozenset[str] = frozenset({LOCAL_KEY}),
) -> Host:
    keyring = fleet_signer(*FLEET, LOCAL_HOST)
    governor = CommunicationGovernor()
    governor.set_mode(mode, round_index=0)
    lineage = CrossHostLineageDAG()
    gateway, dag = stage6_receiver()
    local = local_context(local_keys)
    validator = validator if validator is not None else _local_validator()[0]
    s6 = Stage6Bridge(
        gateway=gateway, local_dag=dag, epoch=EpochModel(identity=IDENTITY).current,
        bridge_secret=b"bridge-secret-for-tests-only-32b", lineage=lineage,
        exchange_enabled=bridge_exchange,
    ) if bridge else None
    components = FabricComponents(
        local=local, keyring=keyring, replay=ReplayGuard(), peers=PeerTable(), governor=governor,
        graph=DependenceGraph(), trust=ContextualTrust(), validator=validator,
        echo_config=EchoConfig(), lineage=lineage,
        hypergraph=hypergraph if hypergraph is not None else CampaignHypergraph(),
        novelty=CollectiveNoveltyEngine(local=local),
        falsifier=ConsensusFalsifier(
            stage_base_rates={s: 0.01 for s in ChainStage}, relevant_hosts=16
        ),
        bridge=s6,
    )
    fabric = OrpheusFabric(components, exchange_enabled=exchange)
    return Host(fabric, components, gateway, dag, s6, validator)


def statuses(host: Host) -> dict[str, EchoStatus]:
    inference = host.fabric.last_inference()
    assert inference is not None
    return {d.antibody_key: d.status for d in inference.decisions}


def send(host: Host, item: KnowledgeCapsuleV1):  # type: ignore[no-untyped-def]
    return host.fabric.deliver(wire(item), sender=item.provenance_commitment.contributor)


def reasons_of(verdicts: Iterable[object]) -> list[str]:
    return [";".join(v.reasons) for v in verdicts]  # type: ignore[attr-defined]


def eligible_pass_host() -> Host:
    """A host where the 64-peer fleet's PASS_ROWS support has been bridged to Stage 6."""
    host = build_host()
    for n in FLEET[:12]:
        send(host, capsule(n, sequence=1))
    for _ in range(3):
        host.fabric.run_round()
    assert statuses(host)[PASS_KEY] is EchoStatus.ELIGIBLE
    return host


def establish(host: Host, peers: Iterable[int], *, per_round: int = 2) -> None:
    """Introduce ``peers`` a few per round, each with its own antibody, as a fleet of
    long-standing independent hosts would be. Births are staggered below the dependence
    graph's burst size on purpose: 64 identities born in one round and posting identical
    contribution sets IS what a Sybil burst looks like, and the graph would (rightly) merge
    them. The sovereignty claim must hold for a fleet the graph cannot discount."""
    ordered = list(peers)
    for start in range(0, len(ordered), per_round):
        for n in ordered[start : start + per_round]:
            rows = (MotifRow(int(Relation.CONNECT), n, 0, 0),)  # one key per peer: never quorate
            send(host, capsule(n, sequence=1, rows=rows, created=host.fabric.round_index))
        host.fabric.run_round()
    assert len(set(host.components.graph.cluster_of(peer_id(n)) for n in ordered)) == len(ordered)


# --- G7.1(c): the unanimous fleet ----------------------------------------------------------------


def test_a_unanimous_fleet_cannot_change_a_local_decision() -> None:
    """G7.1(c)(i)-(iv): 64 independent-root peers, all agreeing against the receiver.

    The same fleet's support for an antibody the host CAN validate is the positive control:
    it reaches ELIGIBLE and is bridged, so every refusal below is the sovereignty rule firing,
    not a pipeline that never lets anything through."""
    host = build_host()
    establish(host, FLEET)
    now = host.fabric.round_index
    host.components.governor.set_mode(ExchangeMode.INCIDENT, round_index=now)
    mine = capsule(LOCAL_HOST, sequence=1, rows=LOCAL_ROWS, created=now)
    [published] = host.fabric.publish([mine])
    local_id = KnowledgeCapsuleV1.from_bytes(published).capsule_id
    assert host.validator.validate(LOCAL_ROWS) is LocalValidation.LOCAL_CONFIRMED
    assert host.validator.validate(FP_ROWS) is LocalValidation.LOCAL_FP

    # (i) revoke the local-origin antibody, (iii) contest the locally confirmed key
    revokes = [
        send(host, capsule(
            n, sequence=11, kind=KnowledgeType.REVOCATION, target=local_id, created=now
        ))
        for n in FLEET
    ]
    contests = [
        send(host, capsule(n, sequence=12, rows=LOCAL_ROWS, stance=Stance.CONTEST, created=now))
        for n in FLEET
    ]
    for verdict in (*revokes, *contests):
        assert verdict.outcome is IngressOutcome.REFUSED
        assert verdict.stage_reached is IngressStage.SUSPICION
        assert any("local_sovereignty" in r for r in verdict.reasons)
    assert len(revokes) == len(contests) == 64
    host.fabric.run_round()

    # (ii) SUPPORT an antibody that FPs locally, beside the PASS control
    for n in FLEET:
        item = capsule(n, sequence=13, rows=FP_ROWS, created=host.fabric.round_index)
        assert send(host, item).outcome is IngressOutcome.POOLED
    host.fabric.run_round()
    for n in FLEET:
        item = capsule(n, sequence=14, rows=PASS_ROWS, created=host.fabric.round_index)
        assert send(host, item).outcome is IngressOutcome.POOLED

    # (iv) authority-keyed payloads, one forbidden word per peer, at the top and nested
    words = ("command", "authorize", "execute", "privilege", "kill", "shell", "sudo", "block")
    for n in FLEET:
        item = capsule(n, sequence=15, created=host.fabric.round_index)
        payload = SIGNER.sign(item, key_id=key_id(n)).to_dict()
        target = payload if n % 2 else payload["provenance_commitment"]
        target[words[n % len(words)]] = "rm -rf /"
        data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        verdict = host.fabric.deliver(data, sender=peer_id(n))
        assert verdict.outcome is IngressOutcome.REFUSED
        assert verdict.stage_reached is IngressStage.SCHEMA
    reports = [host.fabric.run_round() for _ in range(4)]

    final = statuses(host)
    assert final[FP_KEY] is EchoStatus.CHALLENGED  # 64 clusters of support, local FP wins
    assert final.get(LOCAL_KEY, EchoStatus.REFUSED) is EchoStatus.REFUSED
    assert final[PASS_KEY] is EchoStatus.ELIGIBLE  # the positive control fired
    assert host.fabric.bridged_keys() == (PASS_KEY,)  # nothing but the control reached Stage 6
    assert host.bridge.created() == host.bridge.admitted() > 0
    local_node = host.components.lineage.get(local_id)
    assert local_node is not None and local_node.role is NodeRole.LOCAL_CAPSULE
    assert local_node.state is LinkState.LIVE  # the local antibody is live
    assert host.validator.validate(LOCAL_ROWS) is LocalValidation.LOCAL_CONFIRMED
    stats = host.fabric.ingress.stats()
    assert stats["refused:SUSPICION:local_sovereignty"] == 128
    assert sum(v for k, v in stats.items() if k.startswith("refused:SCHEMA:")) == 64
    # (v) reported, not asserted: whatever was bridged sits in the bucket Stage 6 chose.
    buckets = dict(host.bridge.buckets())
    assert set(buckets) <= {b.value for b in QuarantineBucket}
    assert sum(buckets.values()) == host.bridge.admitted()
    assert all(r.failures == 0 for r in reports)


# --- the Stage 6 bridge --------------------------------------------------------------------------


def _decision(
    status: EchoStatus, *, clusters: int = 3, key_rows: tuple[MotifRow, ...] = PASS_ROWS
) -> EchoDecision:
    rows = tuple(
        ClusterEvidence(
            cluster_id=cl(i), stance=Stance.SUPPORT, identities=1, capsule_ids=(kc(i),),
            reliability=0.5, relevance=1.0, falsification=0.8, mass=0.4,
        )
        for i in range(clusters)
    )
    return EchoDecision(
        decision_id="agg-" + _hex("agg", clusters, 32), antibody_key=motif_fingerprint(key_rows),
        invariant=key_rows, status=status, local_validation=LocalValidation.PASS,
        support_mass=0.4 * clusters, contest_mass=0.0, support_clusters=clusters,
        contest_clusters=0, eligible_rounds=2, evidence=rows, truncated=False, reasons=(),
        round_index=4,
    )


def _bridge(gateway: QuarantineGateway, dag: KnowledgeLineageDAG, *, enabled: bool = True,
            lineage: CrossHostLineageDAG | None = None) -> Stage6Bridge:
    return Stage6Bridge(
        gateway=gateway, local_dag=dag, epoch=EpochModel(identity=IDENTITY).current,
        bridge_secret=b"another-secret-of-32-bytes-long!",
        lineage=lineage if lineage is not None else CrossHostLineageDAG(),
        exchange_enabled=enabled,
    )


DIGESTS = {kc(i): raw(i) for i in range(16)}


def test_bridge_created_equals_admitted() -> None:
    """Every ExperienceCapsuleV1 the bridge builds goes to gateway.admit and nowhere else, and
    the gateway's own 'offered' counter rose by exactly that number. Also end-to-end."""
    gateway, dag = stage6_receiver()
    bridge = _bridge(gateway, dag)
    before = gateway.stats().get("offered")
    five = _decision(EchoStatus.ELIGIBLE, clusters=5)
    receipt = bridge.hand_over(five, raw_digests=DIGESTS, sequence=0)
    assert bridge.created() == bridge.admitted() == 5 == len(receipt.stage6_capsule_ids)
    assert gateway.stats().get("offered") - before == 5
    assert all(dag.has(cid) for cid in receipt.stage6_capsule_ids)  # local Stage 6 lineage
    # one capsule per cluster: 12 clusters are cut to MAX_BRIDGE_CAPSULES_PER_DECISION (8)
    wide = dataclasses.replace(
        _decision(EchoStatus.ELIGIBLE, clusters=12), decision_id="agg-" + "e" * 32
    )
    assert len(bridge.hand_over(wide, raw_digests=DIGESTS, sequence=10).stage6_capsule_ids) == 8
    assert bridge.stats()["clusters_truncated"] == 4
    host = eligible_pass_host()
    offered = host.gateway.stats().get("offered")
    assert host.bridge.created() == host.bridge.admitted() == offered > 0


@pytest.mark.parametrize(
    "status",
    [EchoStatus.INSUFFICIENT, EchoStatus.CHALLENGED, EchoStatus.SUSPECT, EchoStatus.REFUSED],
)
def test_bridge_refuses_non_eligible_decisions(status: EchoStatus) -> None:
    gateway, dag = stage6_receiver()
    bridge = _bridge(gateway, dag)
    with pytest.raises(ContractError, match="ELIGIBLE"):
        bridge.hand_over(_decision(status), raw_digests=DIGESTS, sequence=0)
    # an ELIGIBLE decision with no local evidence digest is refused too: no provenance, no handoff
    with pytest.raises(ContractError, match="evidence"):
        bridge.hand_over(_decision(EchoStatus.ELIGIBLE), raw_digests={}, sequence=0)
    assert bridge.created() == bridge.admitted() == 0
    assert gateway.stats().get("offered") == 0


def test_exchange_disabled_means_no_handoff() -> None:
    assert COLLECTIVE_EXCHANGE_ENABLED is False
    gateway, dag = stage6_receiver()
    lineage = CrossHostLineageDAG()
    bridge = _bridge(gateway, dag, enabled=False, lineage=lineage)
    with pytest.raises(FleetDisabledError):
        bridge.hand_over(_decision(EchoStatus.ELIGIBLE), raw_digests=DIGESTS, sequence=0)
    assert bridge.created() == bridge.admitted() == 0
    assert gateway.stats().get("offered") == 0 and len(lineage) == 0
    # the default fabric is DISABLED: it receives nothing and hands nothing over
    host = build_host(exchange=COLLECTIVE_EXCHANGE_ENABLED)
    assert host.fabric.state is FabricState.DISABLED
    assert all(send(host, capsule(n, sequence=1)) is None for n in FLEET[:10])
    report = host.fabric.run_round()
    assert report.state is FabricState.DISABLED and report.received == 0 and report.bridged == 0
    assert host.bridge.created() == 0 and host.gateway.stats().get("offered") == 0
    assert host.fabric.publish([capsule(LOCAL_HOST, sequence=1)]) == ()


def test_stage6_buckets_are_recorded_verbatim() -> None:
    """Receipts and STAGE6_LINK details carry exactly what Stage 6 returned. A bucket forced to
    TRUSTED_CANDIDATE is counted and recorded, and the bridge does nothing else with it."""
    for forced in (None, QuarantineBucket.TRUSTED_CANDIDATE, QuarantineBucket.HOSTILE_SUSPECT):
        dag = KnowledgeLineageDAG()
        gateway = RecordingGateway(forced_bucket=forced, ledger=ProvenanceLedger(), lineage=dag)
        state = genesis_state(identity=IDENTITY)
        gateway.bind_trusted_view(lambda state=state: state)
        lineage = CrossHostLineageDAG()
        bridge = _bridge(gateway, dag, lineage=lineage)
        four = _decision(EchoStatus.ELIGIBLE, clusters=4)
        receipt = bridge.hand_over(four, raw_digests=DIGESTS, sequence=0)
        assert receipt.stage6_buckets == tuple(v.bucket.value for v in gateway.seen)
        assert receipt.verdict_ids == tuple(v.verdict_id for v in gateway.seen)
        expected_trusted = 4 if forced is QuarantineBucket.TRUSTED_CANDIDATE else 0
        assert receipt.trusted_candidates == expected_trusted
        links = [lineage.get(n) for n in lineage.descendants(receipt.decision_id)[0]]
        assert sorted(r.detail for r in links) == sorted(
            stage6_link_detail(v.capsule_id, v.verdict_id, v.bucket.value) for v in gateway.seen
        )
        assert bridge.created() == bridge.admitted() == 4  # never retried, never re-admitted
    assert {v.bucket for v in stage6_bucket_sample()} <= set(QuarantineBucket)


def stage6_bucket_sample() -> list[object]:
    """Unforced: what Stage 6 actually does with bridged foreign knowledge today (M0.2)."""
    dag = KnowledgeLineageDAG()
    gateway = RecordingGateway(ledger=ProvenanceLedger(), lineage=dag)
    state = genesis_state(identity=IDENTITY)
    gateway.bind_trusted_view(lambda: state)
    six = _decision(EchoStatus.ELIGIBLE, clusters=6)
    _bridge(gateway, dag).hand_over(six, raw_digests=DIGESTS, sequence=0)
    return gateway.seen


# --- lineage and revocation -----------------------------------------------------------------------


class EchoRecorder:
    def __init__(self) -> None:
        self.calls: list[tuple[tuple[str, ...], bool]] = []

    def __call__(self, keys: Iterable[str], suspect: bool) -> None:
        self.calls.append((tuple(keys), suspect))


def _node(
    node_id: str, role: NodeRole, parents: tuple[str, ...] = (), detail: str = ""
) -> LineageRecord:
    return LineageRecord(node_id=node_id, role=role, parents=parents, state=LinkState.LIVE,
                         round_index=1, detail=detail)


def revocation_world() -> tuple[CrossHostLineageDAG, RevocationPlane, EchoRecorder, dict[str, str]]:
    """A (by peer 1) -> C (derived) -> D2 -> L2; A,B -> D1 -> L1; E -> D3 -> L3; local capsule M."""
    ids = {name: kc(i) for i, name in enumerate("ABCEM")}
    ids |= {"D1": "agg-" + "1" * 32, "D2": "agg-" + "2" * 32, "D3": "agg-" + "3" * 32}
    ids |= {"L1": "s6l-1", "L2": "s6l-2", "L3": "s6l-3"}
    dag = CrossHostLineageDAG()
    for name in "ABE":
        dag.add(_node(ids[name], NodeRole.FOREIGN_CAPSULE))
    dag.add(_node(ids["M"], NodeRole.LOCAL_CAPSULE))
    dag.add(_node(ids["C"], NodeRole.FOREIGN_CAPSULE, (ids["A"],)))
    dag.add(_node(ids["D1"], NodeRole.ECHO_DECISION, (ids["A"], ids["B"]), "mf-" + "a" * 16))
    dag.add(_node(ids["D2"], NodeRole.ECHO_DECISION, (ids["C"],), "mf-" + "b" * 16))
    dag.add(_node(ids["D3"], NodeRole.ECHO_DECISION, (ids["E"],), "mf-" + "c" * 16))
    for link, parent, cap in (("L1", "D1", "cap-1"), ("L2", "D2", "cap-2"), ("L3", "D3", "cap-3")):
        detail = stage6_link_detail(cap, "qv-" + link, "UNCERTAIN")
        dag.add(_node(ids[link], NodeRole.STAGE6_LINK, (ids[parent],), detail))
    contributors = {ids[name]: peer_id(i + 1) for i, name in enumerate("ABCE")}
    recorder = EchoRecorder()
    keyring = fleet_signer(1, 2, 3, 4)
    plane = RevocationPlane(
        dag=dag, owner_of_key=keyring.owner_of, contributor_of=contributors.get,
        local_keys=lambda: frozenset({LOCAL_KEY, kc(77)}), echo_suspect=recorder,
    )
    return dag, plane, recorder, ids


def retract(n: int, target: str, **kwargs: object) -> KnowledgeCapsuleV1:
    kind = KnowledgeType.REVOCATION
    return capsule(n, sequence=9, kind=kind, target=target, **kwargs)  # type: ignore[arg-type]


def test_revocation_marks_exactly_the_descendants() -> None:
    dag, plane, recorder, ids = revocation_world()
    states_before = {n: dag.get(n).state for n in ids.values()}
    result = plane.submit(retract(1, ids["A"]), sender_peer=peer_id(1), round_index=5)
    assert result.accepted and result.reason == "accepted" and not result.affected_truncated
    expected = {ids[n] for n in ("A", "C", "D1", "D2", "L1", "L2")}
    assert set(result.affected) == expected
    assert set(dag.descendants(ids["A"])[0]) == expected - {ids["A"]}  # >= 2 generations deep
    changed = {n for n in ids.values() if dag.get(n).state is not states_before[n]}
    assert changed == expected  # non-descendants changed: 0
    assert all(dag.get(n).state is LinkState.SUSPECT for n in expected)  # marked, never deleted
    assert all(dag.has(n) for n in ids.values())
    assert recorder.calls == [(("mf-" + "a" * 16, "mf-" + "b" * 16), True)]
    assert set(result.stage6_capsule_ids) == {"cap-1", "cap-2"}  # exactly the links beneath
    # a local-evidence revocation of E revokes E itself and suspects only its line
    local = plane.revoke_locally(ids["E"], round_index=6)
    assert local.accepted and local.issuer == "local"
    assert local.ground is RevocationGround.LOCAL_EVIDENCE
    assert dag.get(ids["E"]).state is LinkState.REVOKED
    assert {dag.get(ids[n]).state for n in ("D3", "L3")} == {LinkState.SUSPECT}
    assert dag.get(ids["B"]).state is LinkState.LIVE and dag.get(ids["M"]).state is LinkState.LIVE


def test_reinstate_restores_digest() -> None:
    dag, plane, recorder, ids = revocation_world()
    pristine = dag.state_digest()
    first = plane.submit(retract(1, ids["A"]), sender_peer=peer_id(1), round_index=5)
    assert dag.state_digest() != pristine == first.prior_digest
    second = plane.revoke_locally(ids["C"], round_index=6)  # overlaps the first (C, D2, L2)
    assert second.accepted
    assert plane.reinstate(first.revocation_id) is False  # LIFO: a later overlap is active
    assert dag.state_digest() != pristine
    assert plane.reinstate(second.revocation_id) is True
    assert dag.state_digest() == second.prior_digest
    assert plane.reinstate(first.revocation_id) is True
    assert dag.state_digest() == pristine  # byte-for-byte
    assert all(dag.get(n).state is LinkState.LIVE for n in ids.values())
    assert plane.reinstate(first.revocation_id) is False  # never twice
    assert recorder.calls[-1][1] is False  # ECHO keys released
    assert plane.reinstate("rv-" + "0" * 32) is False


def test_forged_and_third_party_revocations_change_nothing() -> None:
    """The FALSE_REVOCATION arm, straight at the plane (the ingress is bypassed on purpose)."""
    dag, plane, recorder, ids = revocation_world()
    before = dag.state_digest()
    attempts = [
        (retract(2, ids["A"]), peer_id(2), "not_contributor"),  # third party
        # peer 2 signs, claiming to be A's author
        (retract(2, ids["A"], contributor=1, signer=2), peer_id(1), "not_contributor"),
        (retract(1, ids["A"], ground=RevocationGround.LOCAL_EVIDENCE), peer_id(1),
         "foreign_claims_local_ground"),
        (retract(1, kc(999)), peer_id(1), "unknown_target"),
        (retract(1, ids["M"]), peer_id(1), "local_sovereignty"),  # a LOCAL_CAPSULE node
        (retract(1, kc(77)), peer_id(1), "local_sovereignty"),  # an id in local_keys()
        (capsule(1, sequence=9), peer_id(1), "not_a_revocation"),
    ]
    for item, sender, reason in attempts:
        result = plane.submit(item, sender_peer=sender, round_index=5)
        assert (result.accepted, result.reason) == (False, reason), reason
        assert result.affected == () and result.stage6_capsule_ids == ()
        assert result.prior_digest == before
    assert dag.state_digest() == before and recorder.calls == []
    assert plane.revoke_locally(kc(998), round_index=5).reason == "unknown_target"
    assert dag.state_digest() == before
    assert len(plane.history()) == len(attempts) + 1  # refused attempts are on the record


def test_a_truncated_walk_marks_what_is_known_and_says_so() -> None:
    dag = CrossHostLineageDAG()
    dag.add(_node(kc(0), NodeRole.FOREIGN_CAPSULE))
    for i in range(1, 30):
        dag.add(_node(kc(i), NodeRole.FOREIGN_CAPSULE, (kc(i - 1),)))
    found, truncated = dag.descendants(kc(0), limit=10)
    assert len(found) == 10 and truncated
    plane = RevocationPlane(dag=dag, owner_of_key=fleet_signer(1).owner_of,
                            contributor_of={kc(0): peer_id(1)}.get, local_keys=frozenset,
                            echo_suspect=EchoRecorder())
    result = plane.submit(retract(1, kc(0)), sender_peer=peer_id(1), round_index=1)
    assert result.accepted and not result.affected_truncated  # 29 < MAX_DESCENDANT_WALK
    assert dag.has(kc(29)) and dag.get(kc(29)).state is LinkState.SUSPECT


def test_lineage_eviction_never_drops_linked_nodes() -> None:
    dag = CrossHostLineageDAG(max_nodes=8)
    dag.add(_node(kc(0), NodeRole.FOREIGN_CAPSULE))
    dag.add(_node("agg-" + "0" * 32, NodeRole.ECHO_DECISION, (kc(0),), "mf-" + "0" * 16))
    link = stage6_link_detail("cap-0", "qv-0", "UNCERTAIN")
    dag.add(_node("s6l-0", NodeRole.STAGE6_LINK, ("agg-" + "0" * 32,), link))
    for i in range(1, 200):  # a flood of unrelated leaves
        dag.add(_node(kc(i), NodeRole.FOREIGN_CAPSULE))
        assert len(dag) <= 8
    assert dag.evictions() == 3 + 199 - 8 and dag.refused() == 0  # 202 offered, 8 held
    assert all(dag.has(n) for n in (kc(0), "agg-" + "0" * 32, "s6l-0"))
    assert dag.ancestry_complete("s6l-0") and dag.memory_bytes() > 0
    # unknown parents are counted, never invented
    dag.add(_node(kc(500), NodeRole.FOREIGN_CAPSULE, (kc(404),)))
    assert dag.unresolved() == 1 and not dag.has(kc(404)) and not dag.ancestry_complete(kc(500))
    # all protected: live links everywhere -> the newcomer is refused, the bound holds
    full = CrossHostLineageDAG(max_nodes=3)
    for i in range(3):
        link = stage6_link_detail(f"cap-{i}", "qv", "UNCERTAIN")
        full.add(_node(f"s6l-{i}", NodeRole.STAGE6_LINK, (), link))
    full.add(_node(kc(1), NodeRole.FOREIGN_CAPSULE))
    assert (len(full), full.refused(), full.has(kc(1))) == (3, 1, False)
    full.set_state(["s6l-0"], LinkState.SUSPECT)  # a link that is no longer live may go
    full.add(_node(kc(1), NodeRole.FOREIGN_CAPSULE))
    assert full.has(kc(1)) and not full.has("s6l-0") and full.evictions() == 1


def test_self_retraction_suspects_the_whole_key_known_residual() -> None:
    """KNOWN RESIDUAL, pinned so a change is noticed: ECHO suspicion is per key, so one
    contributor retracting its own capsule moves the whole ELIGIBLE key to SUSPECT."""
    host = eligible_pass_host()
    retracted = capsule(1, sequence=1).capsule_id  # peer 1's own support, as delivered
    assert host.components.lineage.get(retracted).role is NodeRole.FOREIGN_CAPSULE
    assert send(host, retract(1, retracted)).outcome is IngressOutcome.ROUTED_REVOCATION
    report = host.fabric.run_round()
    assert dict(report.revocations) == {"accepted": 1}
    assert statuses(host)[PASS_KEY] is EchoStatus.SUSPECT
    assert host.components.lineage.get(retracted).state is LinkState.SUSPECT


# --- the fabric: offline, disabled, crashing, corrupt ---------------------------------------------


def _episode(chain: tuple[Behaviour, ...], offset: int) -> tuple[EncodedStep, ...]:
    # Session-unique offsets: Stage 1 carries lineage state across scenarios (MEMORY trap).
    result = Stage1Pipeline().run_scenario(Scenario(f"s{offset}", chain, 0), offset=offset)
    return tuple(EncodedStep.from_transition(t, actor_slot=0) for t in result.transitions)


@pytest.fixture(scope="module")
def local_detection() -> dict[str, object]:
    """Real Stage 1 -> Stage 6 episodes: a benign ring, two local incidents, a held-out set."""
    ring = BenignRing()
    for index, pattern in enumerate(BENIGN_PATTERNS):
        ring.add(_episode(pattern, 700_000 + index * 1000))
    incidents = [
        LocalIncident(f"inc-{i}", _episode(chain, 710_000 + i * 1000), (raw(700 + i),))
        for i, chain in enumerate((ATTACK_PERSISTENCE, ATTACK_EXFIL))
    ]
    antibodies = [a for a in (forge_antibody(i, benign=ring) for i in incidents) if a is not None]
    assert antibodies, "no local antibody could be forged: the detection digest would be vacuous"
    chains = (ATTACK_PERSISTENCE, ATTACK_EXFIL, *BENIGN_PATTERNS)
    heldout = [_episode(c, 720_000 + i * 1000) for i, c in enumerate(chains)]
    validator = LocalValidator(benign=ring, incidents=incidents, observable_relations=ALL_RELATIONS)
    return {"ring": ring, "antibodies": antibodies, "heldout": heldout, "validator": validator}


def detection_digest(local: dict[str, object]) -> str:
    """Local detection output: every local antibody against every held-out episode, the
    validator's verdicts, and the benign ring the validator reads."""
    antibodies: list[KnowledgeAntibody] = local["antibodies"]  # type: ignore[assignment]
    heldout: list[tuple[EncodedStep, ...]] = local["heldout"]  # type: ignore[assignment]
    validator: LocalValidator = local["validator"]  # type: ignore[assignment]
    ring: BenignRing = local["ring"]  # type: ignore[assignment]
    rows: list[object] = [[matches(a.invariant, ep) for ep in heldout] for a in antibodies]
    rows.append([validator.validate(a.invariant).value for a in antibodies])
    rows.append([validator.validate(r).value for r in (PASS_ROWS, FP_ROWS, LOCAL_ROWS)])
    rows.append([[s.to_dict() for s in ep] for ep in ring.episodes()])
    return hashlib.sha256(json.dumps(rows, sort_keys=True, default=str).encode()).hexdigest()


class CrashingHypergraph(CampaignHypergraph):
    def build_edges(self, *, round_index: int, join_window: int = 4) -> tuple[Hyperedge, ...]:
        raise RuntimeError("injected hypergraph crash")


def _traffic(host: Host, round_index: int, peers: Iterable[int]) -> list[object]:
    return [send(host, capsule(n, sequence=round_index + 1)) for n in peers]


def test_local_detection_is_identical_with_the_fabric_absent_offline_or_crashing(
    local_detection: dict[str, object],
) -> None:
    absent = detection_digest(local_detection)
    validator = local_detection["validator"]
    flood = wire(capsule(1, sequence=1))
    digests: dict[str, str] = {}

    offline = build_host(validator=validator)  # OFFLINE under a flood
    offline.fabric.partition()
    assert offline.fabric.state is FabricState.OFFLINE
    assert all(offline.fabric.deliver(flood, sender=f"s{i}") is None for i in range(3000))
    assert [offline.fabric.run_round().state for _ in range(3)] == [FabricState.OFFLINE] * 3
    assert offline.fabric.stats()["deliveries_dropped:OFFLINE"] == 3000
    digests["offline"] = detection_digest(local_detection)

    disabled = build_host(validator=validator, exchange=False)
    assert all(disabled.fabric.deliver(flood, sender=f"s{i}") is None for i in range(500))
    assert disabled.fabric.run_round().state is FabricState.DISABLED
    digests["disabled"] = detection_digest(local_detection)

    crashing = build_host(validator=validator, hypergraph=CrashingHypergraph())
    for r in range(4):
        _traffic(crashing, r, FLEET[:12])
        report = crashing.fabric.run_round()  # must not raise
        assert report.state is FabricState.DEGRADED and report.failures == 1
        assert report.pooled > 0  # the fabric really worked before it crashed
    assert crashing.fabric.stats()["failure:campaign"] == 4
    digests["crashing"] = detection_digest(local_detection)

    corrupt = build_host(validator=validator)
    _traffic(corrupt, 0, FLEET[:12])
    ring = corrupt.components.keyring  # changed behind the fabric's back
    ring.register(key_id(5000), key_bytes(5000), owner=peer_id(5000), round_index=0)
    assert corrupt.fabric.run_round().state is FabricState.DISABLED
    digests["corrupt_keyring"] = detection_digest(local_detection)

    assert set(digests.values()) == {absent}, digests
    for arm in (offline, disabled, crashing, corrupt):
        assert arm.bridge.created() == arm.bridge.admitted()


def test_a_host_fabric_refuses_to_run_without_local_validation() -> None:
    """ECHO's local_validation=False is an ablation that removes the LOCAL_FP -> CHALLENGED
    rule; a fabric refuses it unless a lab declares the ablation (integrator seam fix)."""
    host = build_host()
    ablated = dataclasses.replace(
        host.components, echo_config=dataclasses.replace(EchoConfig(), local_validation=False)
    )
    with pytest.raises(ContractError, match="lab_ablation"):
        OrpheusFabric(ablated, exchange_enabled=True)
    assert OrpheusFabric(ablated, exchange_enabled=True, lab_ablation=True).state is not None
    with pytest.raises(ContractError):
        OrpheusFabric(host.components, lab_ablation=1)  # type: ignore[arg-type]


def test_corrupt_keyring_disables_exchange() -> None:
    host = build_host()
    pooled = _traffic(host, 0, FLEET[:12])
    assert all(v.outcome is IngressOutcome.POOLED for v in pooled)
    host.components.keyring.revoke(key_id(3), round_index=0)  # changed behind the fabric's back
    report = host.fabric.run_round()
    assert report.state is FabricState.DISABLED and report.pooled == 0
    assert host.fabric.stats()["discarded_on_disable"] == 12  # nothing pooled under it survives
    assert host.fabric.last_inference() is None  # ECHO never saw it
    assert send(host, capsule(7, sequence=2)) is None
    ring = host.components.keyring
    ring.register(key_id(4000), key_bytes(4000), owner=peer_id(4000), round_index=0)
    assert host.fabric.run_round().state is FabricState.DISABLED  # sticky until a local repin
    assert host.fabric.last_inference() is None
    host.fabric.repin_keyring()
    assert host.fabric.state is FabricState.ACTIVE
    assert send(host, capsule(7, sequence=3)).outcome is IngressOutcome.POOLED


def test_a_flood_hits_the_governor_bound_not_memory() -> None:
    host = build_host(mode=ExchangeMode.ROUTINE)
    peers = range(1, 65)
    verdicts = [send(host, capsule(n, sequence=1)) for n in peers]
    refused = [v for v in verdicts if v.outcome is IngressOutcome.REFUSED]
    assert refused and all(v.stage_reached is IngressStage.SIZE_RATE for v in refused)
    budget = host.components.governor.budget()
    assert budget.inbound_used <= budget.inbound_cap
    report = host.fabric.run_round()
    assert report.pooled == len(verdicts) - len(refused)
    assert host.components.governor.budget().inbox_capsules == 0  # the fabric released the inbox
    assert all(0 < v < 50_000_000 for v in host.fabric.memory_bytes().values() if v)


def test_publish_is_signed_and_bounded_by_the_outbound_budget() -> None:
    idle = build_host(mode=ExchangeMode.IDLE)  # IDLE: outbound cap 0
    assert idle.fabric.publish([capsule(LOCAL_HOST, sequence=1)]) == ()
    assert idle.fabric.stats()["publish_truncated"] == 1
    host = build_host()
    sent = host.fabric.publish([capsule(LOCAL_HOST, sequence=s) for s in range(1, 4)])
    assert len(sent) == 3
    verifier = fleet_signer(LOCAL_HOST)
    for data in sent:
        assert verifier.verify(KnowledgeCapsuleV1.from_bytes(data), round_index=0).valid
    budget = host.components.governor.budget()
    assert budget.outbound_used == sum(map(len, sent)) <= budget.outbound_cap
    host.fabric.partition()
    assert host.fabric.publish([capsule(LOCAL_HOST, sequence=9)]) == ()
    host.fabric.heal()
    assert host.fabric.state is FabricState.ACTIVE


def test_each_key_is_bridged_once_and_every_eligible_decision_has_lineage() -> None:
    host = eligible_pass_host()
    created = host.bridge.created()
    for _ in range(3):
        host.fabric.run_round()
    assert host.bridge.created() == created  # once per key, not once per round
    lineage = host.components.lineage
    inference = host.fabric.last_inference()
    for decision in inference.decisions:
        if decision.status is EchoStatus.ELIGIBLE:
            assert lineage.ancestry_complete(decision.decision_id)
    for receipt in host.bridge.receipts():
        assert all(host.stage6_dag.has(cid) for cid in receipt.stage6_capsule_ids)


def test_a_failing_bridge_degrades_one_round_and_is_not_retried() -> None:
    """Misconfiguration (fabric exchange on, bridge exchange off): Stage 6's
    FleetDisabledError surfaces as ONE degraded round, nothing reaches Stage 6, and the key is
    not retried into a permanent outage of the later steps."""
    host = build_host(bridge_exchange=False)
    for n in FLEET[:12]:
        send(host, capsule(n, sequence=1))
    states = [host.fabric.run_round().state for _ in range(5)]
    assert states.count(FabricState.DEGRADED) == 1 and states[-1] is FabricState.ACTIVE
    assert host.fabric.stats()["failure:bridge"] == 1
    assert host.bridge.created() == host.bridge.admitted() == 0
    assert host.gateway.stats().get("offered") == 0


# --- secure aggregation ---------------------------------------------------------------------------


def _pair_keys(names: list[str]) -> dict[str, dict[str, bytes]]:
    def key(a: str, b: str) -> bytes:
        return hashlib.sha256(("pair|" + "|".join(sorted((a, b)))).encode()).digest()
    return {p: {q: key(p, q) for q in names if q != p} for p in names}


def test_secure_sum_is_exact_and_aborts_on_dropout() -> None:
    assert SECURE_AGGREGATION_ENABLED is False
    names = [f"host-{i}" for i in range(6)]
    keys = _pair_keys(names)
    vectors = {p: [(i * 37 + j * 11) % 50 for j in range(40)] for i, p in enumerate(names)}
    masked = [
        mask_vector(vectors[p], participant=p, pair_keys=keys[p], round_index=7) for p in names
    ]
    result = aggregate_masked(masked, expected=frozenset(names), round_index=7)
    assert not result.aborted and result.total == tuple(sum(col) for col in zip(*vectors.values()))
    assert result.bytes_exchanged == 6 * 40 * 4
    for p, m in zip(names, masked):  # the aggregator sees masked words, not the counts
        assert list(m.values) != vectors[p]
    one, two = (pairwise_mask(b"k" * 16, round_index=r, length=8) for r in (1, 2))
    assert one != two  # a fresh mask every round
    dropout = aggregate_masked(masked[:-1], expected=frozenset(names), round_index=7)
    assert dropout.aborted and dropout.total is None and dropout.reason == "missing_participant"
    stranger = mask_vector([1] * 40, participant="host-x", pair_keys={}, round_index=7)
    for bad, reason in (
        ([*masked, stranger], "unexpected_participant"),
        ([*masked, masked[0]], "duplicate_participant"),
    ):
        outcome = aggregate_masked(bad, expected=frozenset(names), round_index=7)
        assert outcome.aborted and outcome.total is None and outcome.reason == reason
    late = aggregate_masked(masked, expected=frozenset(names), round_index=8)
    assert late.aborted and late.reason == "wrong_round"
    with pytest.raises(ContractError):
        mask_vector([0] * (MAX_VECTOR_LEN + 1), participant="a", pair_keys={}, round_index=0)
    with pytest.raises(ContractError):
        mask_vector([MODULUS], participant="a", pair_keys={}, round_index=0)
    too_many = {f"p{i}": b"k" * 16 for i in range(MAX_PARTICIPANTS)}
    with pytest.raises(ContractError):
        mask_vector([1], participant="a", pair_keys=too_many, round_index=0)
    with pytest.raises(ContractError):
        pairwise_mask(b"short", round_index=0, length=1)
    assert secure.MIN_PAIR_KEY_BYTES == 16
