"""Stage 7 ingress package: peer table, keyring/replay, the governor, and HIVELOCK ingress.

Every defence here is attacked, not constructed: tampered, unsigned, stolen-key,
revoked, rotated-past-grace, replayed and oversize capsules; identity floods that try
to evict established peers; message floods that must hit a cap instead of memory; and
a fleet contesting or revoking what this host learned locally. The tests named in the
spec's constitution table (``test_a_validly_signed_capsule_is_only_ever_pooled``) are
bound to a law and must keep those names.
"""

from __future__ import annotations

import ast
import dataclasses
import hashlib
from pathlib import Path

import pytest

from pocketsec.stage0.contracts.common import ContractError, digest_of_bytes
from pocketsec.stage1.ssir.relations import Relation, RelationFamily
from pocketsec.stage6.capsule.experience_capsule import PrivacyClass
from pocketsec.stage6.resources import WorkMeter
from pocketsec.stage7.capsule.knowledge_capsule import (
    MAX_EXPIRY_HORIZON_ROUNDS,
    MAX_KNOWLEDGE_CAPSULE_BYTES,
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
    seal_capsule,
)
from pocketsec.stage7.governor import communication
from pocketsec.stage7.governor.communication import (
    INCIDENT_MAX_ROUNDS,
    MAX_BYTES_PER_PEER_PER_ROUND,
    MAX_CAPSULES_PER_PEER_PER_ROUND,
    MAX_INBOX_CAPSULES,
    MODE_ROUND_BYTES,
    STAGE7_INCREMENTAL_CEILING_BYTES,
    CommunicationGovernor,
    ExchangeMode,
    Stage7ResourceReport,
    measure_stage7_resources,
)
from pocketsec.stage7.hivelock import ingress as ingress_module
from pocketsec.stage7.hivelock.ingress import (
    HivelockIngress,
    IngressOutcome,
    IngressStage,
    IngressVerdict,
)
from pocketsec.stage7.identity.integrity import (
    KEY_GRACE_ROUNDS,
    IntegrityVerdict,
    Keyring,
    KeyState,
    ReplayGuard,
)
from pocketsec.stage7.identity.peer import MAX_PEER_EVICTION_LOG, PeerTable

REPO = Path(__file__).resolve().parents[1]
INGRESS_SOURCE = REPO / "pocketsec" / "stage7" / "hivelock" / "ingress.py"


# --- fixtures: a tiny simulated fleet of pseudonymous peers ------------------------


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


def kc_id(n: int) -> str:
    return "kc-" + _hex("kc", n, 24)


DEFAULT_ROWS = (
    MotifRow(
        relation=int(Relation.READ), require_properties=1, forbid_properties=0, require_raised=0
    ),
    MotifRow(
        relation=int(Relation.WRITE), require_properties=2, forbid_properties=0, require_raised=0
    ),
)
OTHER_ROWS = (
    MotifRow(
        relation=int(Relation.EXECUTE), require_properties=4, forbid_properties=0, require_raised=0
    ),
)


def make_capsule(
    n: int,
    *,
    sequence: int,
    created: int = 0,
    expiry: int | None = None,
    knowledge_type: KnowledgeType = KnowledgeType.ANTIBODY,
    stance: Stance = Stance.SUPPORT,
    rows: tuple[MotifRow, ...] = DEFAULT_ROWS,
    parents: tuple[str, ...] = (),
    aggregation_decision: str | None = None,
    revocation_target: str | None = None,
    contributor: str | None = None,
    signer_key: int | None = None,
) -> KnowledgeCapsuleV1:
    """An UNSIGNED capsule from simulated peer ``n`` (key ``n`` and root ``n`` by default)."""
    is_revocation = knowledge_type is KnowledgeType.REVOCATION
    root = root_id(n)
    return seal_capsule(
        knowledge_type=knowledge_type,
        stance=stance,
        semantic_invariant=() if is_revocation else rows,
        attack_mappings=(),
        epoch_context=EpochContext(
            software_epoch="se-" + _hex("se", 0, 16), visibility=VisibilityClass.FULL
        ),
        source_context_sketch=SourceContextSketch(
            role=RoleClass.WEB, family_profile=(1,) * len(RelationFamily)
        ),
        validation_summary=ValidationSummary(episodes_replayed=10, true_matches=9, false_matches=0),
        falsification_summary=FalsificationSummary(
            mutations_tried=8, mutations_survived=0, counter_hypotheses=()
        ),
        provenance_commitment=ProvenanceCommitment(
            contributor=contributor or peer_id(n),
            provenance_root=root,
            evidence_commitments=("hc-" + _hex("hc", n * 1000 + sequence, 32),),
            aggregation_decision=aggregation_decision,
        ),
        independence_group=root,
        privacy_class=PrivacyClass.PUBLIC_DERIVED,
        created_round=created,
        expiry_round=created + 32 if expiry is None else expiry,
        sequence=sequence,
        parent_capsules=parents,
        time_window=None,
        observability=None,
        revocation_target=revocation_target if is_revocation else None,
        revocation_ground=RevocationGround.SELF_RETRACTION if is_revocation else None,
        key_id=key_id(n if signer_key is None else signer_key),
    )


def signer_ring(*peers: int) -> Keyring:
    """The keyring a sending peer signs with (its own key, owned by its own pseudonym)."""
    ring = Keyring()
    for n in peers:
        ring.register(key_id(n), key_bytes(n), owner=peer_id(n), round_index=0)
    return ring


def wire(capsule: KnowledgeCapsuleV1, ring: Keyring) -> bytes:
    return ring.sign(capsule, key_id=capsule.key_id).canonical_bytes()


def make_ingress(
    receiver_ring: Keyring,
    *,
    governor: CommunicationGovernor | None = None,
    peers: PeerTable | None = None,
    replay: ReplayGuard | None = None,
    gravity: float = 1.0,
    local: frozenset[str] = frozenset(),
    lineage=lambda _id: False,
    gravity_enabled: bool = True,
    meter: WorkMeter | None = None,
) -> HivelockIngress:
    return HivelockIngress(
        keyring=receiver_ring,
        replay=ReplayGuard() if replay is None else replay,
        peers=PeerTable() if peers is None else peers,
        governor=(
            CommunicationGovernor(mode=ExchangeMode.INCIDENT) if governor is None else governor
        ),
        cluster_of=lambda capsule, peer, _round: "cl-" + peer.provenance_root[5:],
        relevance_of=lambda _capsule: 1.0,
        gravity_of=lambda _capsule, _cluster, _round: gravity,
        lineage_resolves=lineage,
        local_keys=lambda: local,
        gravity_enabled=gravity_enabled,
        meter=meter,
    )


def last_reason(verdict: IngressVerdict) -> str:
    return verdict.reasons[-1]


# --- the constitution-bound test ------------------------------------------------------


def test_a_validly_signed_capsule_is_only_ever_pooled() -> None:
    """FOREIGN_IS_UNTRUSTED_EVEN_SIGNED: a unanimous fleet's perfect capsule is only a candidate."""
    senders = tuple(range(1, 65))
    ring = signer_ring(*senders)
    ingress = make_ingress(signer_ring(*senders), gravity=1.0)
    verdicts = []
    for n in senders:  # 64 independent roots all signing the same antibody
        data = wire(make_capsule(n, sequence=1), ring)
        verdicts.append((data, ingress.receive(data, sender=f"link-{n}", round_index=1)))
    assert {v.outcome for _, v in verdicts} == {IngressOutcome.POOLED}
    assert {v.stage_reached for _, v in verdicts} == {IngressStage.POOLED}
    # Every stage was run and passed, in the spec's order, before pooling.
    order = [reason.split(":")[0] for reason in verdicts[0][1].reasons]
    assert order == [stage.value for stage in IngressStage]
    pooled = ingress.drain_pool()
    assert len(pooled) == 64
    assert {p.raw_digest for p in pooled} == {digest_of_bytes(d) for d, _ in verdicts}
    # POOLED is the ceiling: no outcome, stage or field of the verdict names trust or promotion.
    vocabulary = {m.value for m in IngressOutcome} | {m.value for m in IngressStage}
    vocabulary |= {f.name for f in dataclasses.fields(IngressVerdict)}
    vocabulary |= {f.name for f in dataclasses.fields(ingress_module.PooledCapsule)}
    assert not {word for word in vocabulary if "trust" in word.lower() or "promot" in word.lower()}
    assert set(IngressOutcome) == {
        IngressOutcome.REFUSED,
        IngressOutcome.METADATA_ONLY,
        IngressOutcome.POOLED,
        IngressOutcome.ROUTED_REVOCATION,
    }


def test_ingress_imports_no_graph_relevance_echo_lineage_or_writer() -> None:
    """The graph, relevance and lineage are injected; ingress cannot reach a Stage 6 writer."""
    tree = ast.parse(INGRESS_SOURCE.read_text(encoding="utf-8"))
    modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            modules.append("." * node.level + (node.module or ""))
        elif isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
    forbidden = (
        ".graph",
        ".relevance",
        ".echo",
        ".lineage",
        ".antibody",
        "stage5",
        "stage6.promotion",
        "stage6.capsule.quarantine",
        "stage6.fleet",
        "stage6.memory",
        "stage7.labs",
        "stage6_bridge",
    )
    offenders = [m for m in modules if any(word in m for word in forbidden)]
    assert modules and offenders == []
    called_admit = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "admit"
        and not (isinstance(node.func.value, ast.Attribute) and node.func.value.attr == "_replay")
    ]
    assert called_admit == []  # the only .admit ingress calls is its own replay guard's


# --- integrity: tamper, unsigned, unknown, revoked, rotated, mismatch -----------------


def test_tampered_unsigned_unknown_revoked_rotated_keys() -> None:
    ring = signer_ring(1, 2, 3)
    receiver = signer_ring(1, 3)  # peer 2's key was never provisioned here
    ingress = make_ingress(receiver)

    signed = ring.sign(make_capsule(1, sequence=1), key_id=key_id(1))
    # Tamper past the schema: a correctly re-sealed capsule carrying the old signature.
    forged = dataclasses.replace(
        make_capsule(1, sequence=2, rows=OTHER_ROWS), signature=signed.signature
    )
    verdict = ingress.receive(forged.canonical_bytes(), sender="a", round_index=1)
    assert (verdict.outcome, last_reason(verdict)) == (
        IngressOutcome.REFUSED,
        "INTEGRITY:bad_signature",
    )
    # Tamper at the byte level: whatever stage catches it, it is never pooled.
    raw = bytearray(signed.canonical_bytes())
    raw[raw.index(b'"sequence":1') + len(b'"sequence":')] = ord("7")
    assert ingress.receive(bytes(raw), sender="a", round_index=1).outcome is IngressOutcome.REFUSED

    unsigned = make_capsule(1, sequence=3).canonical_bytes()
    assert last_reason(ingress.receive(unsigned, sender="a", round_index=1)) == "INTEGRITY:unsigned"
    unknown = wire(make_capsule(2, sequence=1), ring)
    assert (
        last_reason(ingress.receive(unknown, sender="b", round_index=1)) == "INTEGRITY:unknown_key"
    )

    receiver.revoke(key_id(3), round_index=1)
    revoked = wire(make_capsule(3, sequence=1), ring)
    assert (
        last_reason(ingress.receive(revoked, sender="c", round_index=1)) == "INTEGRITY:revoked_key"
    )
    assert receiver.record(key_id(3)).state is KeyState.REVOKED
    assert ingress.pool_size() == 0

    # Rotation: the old key verifies through the grace window, then is expired_key.
    new_key = "key-" + _hex("rotated", 1, 16)
    receiver.rotate(key_id(1), new_key, key_bytes(99), round_index=10)
    in_flight = ring.sign(make_capsule(1, sequence=4, created=10), key_id=key_id(1))
    assert receiver.verify(in_flight, round_index=10 + KEY_GRACE_ROUNDS).valid
    late = receiver.verify(in_flight, round_index=10 + KEY_GRACE_ROUNDS + 1)
    assert (late.valid, late.reason) == (False, "expired_key")
    with pytest.raises(ContractError):  # a rotated key never signs again
        receiver.sign(make_capsule(1, sequence=5, created=10), key_id=key_id(1))
    fresh = receiver.sign(_rekeyed(1, new_key, sequence=5, created=10), key_id=new_key)
    assert receiver.verify(fresh, round_index=30).valid  # the new key has no grace limit
    with pytest.raises(ContractError):  # a key id is never re-registered (no un-revoking)
        receiver.register(key_id(3), key_bytes(3), owner=peer_id(3), round_index=2)
    with pytest.raises(ContractError):  # short keys are refused (Stage 6 MIN_KEY_BYTES)
        receiver.register("key-" + _hex("short", 0, 16), b"short", owner=peer_id(7), round_index=2)


def _rekeyed(n: int, new_key_id: str, *, sequence: int, created: int) -> KnowledgeCapsuleV1:
    fields = {
        f.name: getattr(make_capsule(n, sequence=sequence, created=created), f.name)
        for f in dataclasses.fields(KnowledgeCapsuleV1)
    }
    for derived in (
        "capsule_id",
        "signature",
        "compact_feature_signature",
        "causal_motif",
        "schema_version",
    ):
        fields.pop(derived, None)
    fields["key_id"] = new_key_id
    return seal_capsule(**fields)


def test_contributor_key_mismatch_refused() -> None:
    """A key holder cannot sign under another pseudonym and mint an 'independent' peer."""
    receiver = signer_ring(1)  # key 1 belongs to peer 1 here
    attacker = Keyring()  # the holder of key 1 claims to be peer 2
    attacker.register(key_id(1), key_bytes(1), owner=peer_id(2), round_index=0)
    capsule = make_capsule(2, sequence=1, contributor=peer_id(2), signer_key=1)
    data = wire(capsule, attacker)
    verdict = make_ingress(receiver).receive(data, sender="x", round_index=1)
    assert (verdict.outcome, last_reason(verdict)) == (
        IngressOutcome.REFUSED,
        "INTEGRITY:contributor_key_mismatch",
    )
    assert verdict.peer_id is None  # the claimed contributor was never bound to a key
    assert receiver.verify(attacker.sign(capsule, key_id=key_id(1)), round_index=1) == (
        IntegrityVerdict(valid=False, reason="contributor_key_mismatch")
    )
    with pytest.raises(ContractError):  # and this host never signs such a capsule itself
        receiver.sign(capsule, key_id=key_id(1))


# --- replay and expiry --------------------------------------------------------------


def test_replay_and_duplicate_refused() -> None:
    ring = signer_ring(1)
    ingress = make_ingress(signer_ring(1))
    early = wire(make_capsule(1, sequence=1, created=5, expiry=20), ring)
    assert last_reason(ingress.receive(early, sender="a", round_index=0)) == (
        "REPLAY_EXPIRY:not_yet_valid"
    )
    first = wire(make_capsule(1, sequence=2, created=1), ring)
    assert ingress.receive(first, sender="a", round_index=1).outcome is IngressOutcome.POOLED
    assert last_reason(ingress.receive(first, sender="a", round_index=1)) == (
        "REPLAY_EXPIRY:duplicate_capsule"
    )
    older = wire(make_capsule(1, sequence=2, created=1, rows=OTHER_ROWS), ring)
    assert last_reason(ingress.receive(older, sender="a", round_index=2)) == (
        "REPLAY_EXPIRY:replayed_sequence"
    )
    stale = wire(make_capsule(1, sequence=9, created=1, expiry=3), ring)
    assert last_reason(ingress.receive(stale, sender="a", round_index=3)) == "REPLAY_EXPIRY:expired"
    assert ingress.pool_size() == 1


def test_replay_after_eviction_is_bounded_by_expiry() -> None:
    """The known residual, demonstrated: after both evictions only expiry stops a replay."""
    guard = ReplayGuard(max_keys=1, max_seen=1)
    victim = make_capsule(1, sequence=1, created=0, expiry=MAX_EXPIRY_HORIZON_ROUNDS)
    assert guard.check(victim, round_index=0) is None
    guard.admit(victim)
    assert guard.check(victim, round_index=1) == "duplicate_capsule"
    guard.admit(make_capsule(2, sequence=1))  # a second key evicts both of victim's entries
    assert guard.evictions() == (1, 1)
    assert guard.sizes() == (1, 1)
    # The residual: inside its window the replay is no longer recognised...
    assert guard.check(victim, round_index=MAX_EXPIRY_HORIZON_ROUNDS - 1) is None
    # ...and the window is the bound: at created + MAX_EXPIRY_HORIZON_ROUNDS it is refused.
    assert guard.check(victim, round_index=MAX_EXPIRY_HORIZON_ROUNDS) == "expired"
    with pytest.raises(
        ContractError
    ):  # the schema forbids a longer horizon, so no capsule outlives it
        make_capsule(3, sequence=1, created=0, expiry=MAX_EXPIRY_HORIZON_ROUNDS + 1)
    with pytest.raises(ContractError):  # admit refuses what check would refuse
        guard.admit(make_capsule(2, sequence=1))


# --- size, flood and the peer table ------------------------------------------------------


class _ParserThatMustNotRun:
    @staticmethod
    def from_bytes(_data: bytes) -> KnowledgeCapsuleV1:
        raise AssertionError("an oversize message reached the parser")


def test_oversize_refused_before_parse(monkeypatch: pytest.MonkeyPatch) -> None:
    ingress = make_ingress(
        signer_ring(1), governor=CommunicationGovernor(mode=ExchangeMode.INCIDENT)
    )
    monkeypatch.setattr(ingress_module, "KnowledgeCapsuleV1", _ParserThatMustNotRun)
    for size in (MAX_KNOWLEDGE_CAPSULE_BYTES + 1, 10_000, 100_000, 1_000_000):
        verdict = ingress.receive(b"{" * size, sender=f"s{size}", round_index=1)
        assert verdict.outcome is IngressOutcome.REFUSED
        assert (verdict.stage_reached, last_reason(verdict)) == (
            IngressStage.SIZE_RATE,
            "SIZE_RATE:oversize",
        )
        assert verdict.capsule_id is None
        assert verdict.raw_digest == digest_of_bytes(b"{" * size)
    monkeypatch.undo()
    at_limit = make_ingress(signer_ring(1)).receive(
        b"{" * MAX_KNOWLEDGE_CAPSULE_BYTES, sender="s", round_index=1
    )
    assert at_limit.stage_reached is IngressStage.SCHEMA  # admitted by size, refused by the parser


def test_hostile_bytes_are_refused_never_raised() -> None:
    ingress = make_ingress(
        signer_ring(1),
        governor=CommunicationGovernor(mode=ExchangeMode.RESEARCH, research_enabled=True),
    )
    hostile = [
        b"",
        b"\xff\xfe",
        b"null",
        b"[]",
        b"{}",
        b"[" * 2000 + b"]" * 2000,
        b'{"schema_id": "pocketsec.knowledge_capsule.v1"}',
        b"1e999",
        b"NaN",
    ]
    for index, data in enumerate(hostile):
        verdict = ingress.receive(data, sender=f"h{index}", round_index=1)
        assert (verdict.outcome, verdict.stage_reached) == (
            IngressOutcome.REFUSED,
            IngressStage.SCHEMA,
        ), data[:20]
        assert len(last_reason(verdict)) <= len("SCHEMA:") + 60 + 40
    # Stats keys carry only the error class, so a flood of distinct messages cannot grow them.
    assert all(key.count(":") <= 2 for key in ingress.stats())


def test_flood_hits_inbox_and_peer_caps_not_memory() -> None:
    # One sender: the per-sender message and byte caps bite first.
    governor = CommunicationGovernor(mode=ExchangeMode.INCIDENT)
    reasons = [governor.admit_inbound("one", 100, round_index=1) for _ in range(20)]
    assert reasons.count(None) == MAX_CAPSULES_PER_PEER_PER_ROUND
    assert set(reasons[MAX_CAPSULES_PER_PEER_PER_ROUND:]) == {"peer_count"}
    big = [governor.admit_inbound("two", 4000, round_index=1) for _ in range(3)]
    assert big == [None, None, "peer_bytes"] and MAX_BYTES_PER_PEER_PER_ROUND < 3 * 4000

    # Many senders, ROUTINE: the round's byte cap bites.
    routine = CommunicationGovernor(mode=ExchangeMode.ROUTINE)
    outcomes = [routine.admit_inbound(f"s{i}", 1000, round_index=1) for i in range(40)]
    assert outcomes.count(None) == MODE_ROUND_BYTES[ExchangeMode.ROUTINE] // 1000
    assert outcomes[-1] == "round_bytes"

    # A 5000-sender flood through ingress in RESEARCH mode: the inbox cap bites, memory plateaus.
    flood = CommunicationGovernor(mode=ExchangeMode.RESEARCH, research_enabled=True)
    ingress = make_ingress(signer_ring(1), governor=flood)
    for i in range(1500):
        ingress.receive(b"x" * 100, sender=f"sybil-{i}", round_index=1)
    memory_at_cap = (flood.memory_bytes(), ingress.memory_bytes())
    for i in range(1500, 5000):
        ingress.receive(b"x" * 100, sender=f"sybil-{i}", round_index=1)
    budget = flood.budget()
    assert budget.inbox_capsules == MAX_INBOX_CAPSULES
    assert flood.senders_this_round() == MAX_INBOX_CAPSULES
    assert dict(budget.refused)["inbound:inbox_full"] == 5000 - MAX_INBOX_CAPSULES
    assert (flood.memory_bytes(), ingress.memory_bytes()) == memory_at_cap
    assert ingress.stats()["refused:SIZE_RATE:inbox_full"] == 5000 - MAX_INBOX_CAPSULES
    # Draining frees the inbox; over-release is refused rather than going negative.
    flood.release(MAX_INBOX_CAPSULES, budget.inbox_bytes)
    with pytest.raises(ContractError):
        flood.release(1, 0)
    # A sender label cannot grow memory: long labels are stored hashed.
    labels = CommunicationGovernor(mode=ExchangeMode.ROUTINE)
    labels.admit_inbound("L" * 100_000, 10, round_index=1)
    assert labels.memory_bytes() < 2048


def test_pool_is_bounded_and_refuses_newcomers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ingress_module, "MAX_POOL_CAPSULES", 4)
    ring = signer_ring(*range(1, 7))
    ingress = make_ingress(signer_ring(*range(1, 7)))
    verdicts = [
        ingress.receive(wire(make_capsule(n, sequence=1), ring), sender=f"s{n}", round_index=1)
        for n in range(1, 7)
    ]
    assert [v.outcome for v in verdicts].count(IngressOutcome.POOLED) == 4
    assert [last_reason(v) for v in verdicts[4:]] == ["POOLED:pool_full"] * 2
    assert [p.peer_id for p in ingress.drain_pool()] == [peer_id(n) for n in range(1, 5)]


def test_peer_flood_never_evicts_active_peers() -> None:
    table = PeerTable(capacity=8, idle_rounds=4)
    honest = [peer_id(n) for n in range(8)]
    for n, pid in enumerate(honest):
        assert (
            table.observe(
                pid,
                key_id=key_id(n),
                provenance_root=root_id(n),
                role_claim=RoleClass.WEB,
                round_index=0,
            )
            is not None
        )
    for i in range(1000):  # a Sybil flood of fresh identities while the honest peers are active
        assert (
            table.observe(
                peer_id(10_000 + i),
                key_id=key_id(1),
                provenance_root=root_id(99),
                role_claim=RoleClass.WEB,
                round_index=3,
            )
            is None
        )
    assert (table.refused(), table.evictions(), len(table)) == (1000, 0, 8)
    assert bool(PeerTable()) and bool(Keyring())  # an empty store is never "absent"
    assert all(table.get(pid) is not None for pid in honest)

    # Seven peers stay active; the one idle past the bound is the only one that can go.
    for n in range(1, 8):
        table.observe(
            honest[n],
            key_id=key_id(n),
            provenance_root=root_id(n),
            role_claim=RoleClass.WEB,
            round_index=9,
        )
    assert (
        table.observe(
            peer_id(20_000),
            key_id=key_id(2),
            provenance_root=root_id(98),
            role_claim=RoleClass.WEB,
            round_index=10,
        )
        is not None
    )
    assert table.get(honest[0]) is None and table.eviction_log() == ((honest[0], 10),)
    assert (
        table.observe(
            peer_id(20_001),
            key_id=key_id(2),
            provenance_root=root_id(98),
            role_claim=RoleClass.WEB,
            round_index=10,
        )
        is None
    )

    # A first declaration binds: a later root claim is counted, never adopted.
    changed = table.observe(
        honest[1],
        key_id=key_id(1),
        provenance_root=root_id(55),
        role_claim=RoleClass.ADMIN,
        round_index=11,
    )
    assert changed is not None and changed.provenance_root == root_id(1)
    assert table.claim_conflicts() == 1

    # The eviction log is bounded; the eviction count is not lost.
    churn = PeerTable(capacity=1, idle_rounds=0)
    for i in range(600):
        churn.observe(
            peer_id(i),
            key_id=key_id(i),
            provenance_root=root_id(i),
            role_claim=RoleClass.DEV,
            round_index=2 * i,
        )
    assert churn.evictions() == 599 and len(churn.eviction_log()) == MAX_PEER_EVICTION_LOG

    # Through ingress, a refused newcomer is a recorded refusal at DEPENDENCE.
    ring = signer_ring(1, 2)
    ingress = make_ingress(signer_ring(1, 2), peers=PeerTable(capacity=1, idle_rounds=64))
    assert (
        ingress.receive(wire(make_capsule(1, sequence=1), ring), sender="a", round_index=1).outcome
        is IngressOutcome.POOLED
    )
    refused = ingress.receive(wire(make_capsule(2, sequence=1), ring), sender="b", round_index=1)
    assert last_reason(refused) == "DEPENDENCE:peer_table_full"


# --- partition, sovereignty, revocation, lineage, relevance ----------------------------


def test_partition_refuses_everything() -> None:
    ring = signer_ring(1)
    governor = CommunicationGovernor(mode=ExchangeMode.INCIDENT)
    ingress = make_ingress(signer_ring(1), governor=governor)
    governor.partition()
    for i, data in enumerate((wire(make_capsule(1, sequence=1), ring), b"", b"x")):
        verdict = ingress.receive(data, sender=f"p{i}", round_index=1)
        assert last_reason(verdict) == "SIZE_RATE:partitioned"
    assert governor.admit_outbound(0, round_index=1) == "partitioned"
    assert governor.budget().inbound_cap == 0 and governor.budget().outbound_cap == 0
    governor.heal(round_index=2)
    healed = ingress.receive(
        wire(make_capsule(1, sequence=2, created=2), ring), sender="p", round_index=2
    )
    assert healed.outcome is IngressOutcome.POOLED
    offline = CommunicationGovernor(mode=ExchangeMode.OFFLINE)
    assert offline.admit_inbound("a", 0, round_index=0) == "partitioned"
    assert offline.admit_outbound(0, round_index=0) == "partitioned"


def test_revocation_never_enters_pool(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ingress_module, "MAX_REVOCATION_INBOX", 2)
    ring = signer_ring(1, 2, 3)
    for gravity_enabled in (True, False):
        ingress = make_ingress(signer_ring(1, 2, 3), gravity_enabled=gravity_enabled)
        verdicts = [
            ingress.receive(
                wire(
                    make_capsule(
                        n,
                        sequence=1,
                        knowledge_type=KnowledgeType.REVOCATION,
                        revocation_target=kc_id(n),
                    ),
                    ring,
                ),
                sender=f"s{n}",
                round_index=1,
            )
            for n in (1, 2, 3)
        ]
        assert [v.outcome for v in verdicts[:2]] == [IngressOutcome.ROUTED_REVOCATION] * 2
        assert last_reason(verdicts[2]) == "SUSPICION:revocation_inbox_full"
        assert ingress.pool_size() == 0 and ingress.drain_pool() == ()
        routed = ingress.drain_revocations()
        assert [(c.revocation_target, pid) for c, pid in routed] == [
            (kc_id(1), peer_id(1)),
            (kc_id(2), peer_id(2)),
        ]
        assert ingress.revocation_inbox_size() == 0


def test_local_key_contest_refused() -> None:
    """LOCAL_SOVEREIGNTY at ingress: a whole fleet cannot contest or revoke local knowledge."""
    fleet = tuple(range(1, 65))
    ring = signer_ring(*fleet)
    local_antibody = make_capsule(1, sequence=1).compact_feature_signature
    local_capsule = kc_id(777)
    ingress = make_ingress(
        signer_ring(*fleet),
        local=frozenset({local_antibody, local_capsule}),
        governor=CommunicationGovernor(mode=ExchangeMode.INCIDENT),
    )
    contests = [
        ingress.receive(
            wire(make_capsule(n, sequence=1, stance=Stance.CONTEST), ring),
            sender=f"f{n}",
            round_index=1,
        )
        for n in fleet
    ]
    assert [last_reason(v) for v in contests] == ["SUSPICION:local_sovereignty"] * 64
    revokes = [
        ingress.receive(
            wire(
                make_capsule(
                    n,
                    sequence=2,
                    knowledge_type=KnowledgeType.REVOCATION,
                    revocation_target=local_capsule,
                ),
                ring,
            ),
            sender=f"f{n}",
            round_index=2,
        )
        for n in fleet
    ]
    assert [last_reason(v) for v in revokes] == ["SUSPICION:local_sovereignty"] * 64
    assert ingress.pool_size() == 0 and ingress.revocation_inbox_size() == 0
    # The direction rule, not a blanket refusal: SUPPORT of a local key, and a CONTEST of a
    # foreign key, are both only candidate evidence.
    support = ingress.receive(wire(make_capsule(1, sequence=3), ring), sender="f1", round_index=3)
    foreign = ingress.receive(
        wire(make_capsule(2, sequence=3, stance=Stance.CONTEST, rows=OTHER_ROWS), ring),
        sender="f2",
        round_index=3,
    )
    assert (support.outcome, foreign.outcome) == (IngressOutcome.POOLED, IngressOutcome.POOLED)


def test_unresolvable_parent_refused() -> None:
    ring = signer_ring(1)
    known = {kc_id(1)}
    ingress = make_ingress(signer_ring(1), lineage=lambda cid: cid in known)
    orphan = wire(make_capsule(1, sequence=1, parents=(kc_id(2),)), ring)
    assert last_reason(ingress.receive(orphan, sender="a", round_index=1)) == (
        "PROVENANCE:unresolvable_lineage"
    )
    half = wire(make_capsule(1, sequence=2, parents=(kc_id(1), kc_id(2))), ring)
    assert last_reason(ingress.receive(half, sender="a", round_index=1)) == (
        "PROVENANCE:unresolvable_lineage"
    )
    agg = "agg-" + _hex("agg", 1, 32)
    with pytest.raises(ContractError):  # the schema already refuses a parentless derived capsule
        make_capsule(1, sequence=3, aggregation_decision=agg)
    resolved = wire(
        make_capsule(1, sequence=4, parents=(kc_id(1),), aggregation_decision=agg), ring
    )
    assert ingress.receive(resolved, sender="a", round_index=1).outcome is IngressOutcome.POOLED
    # A resolver answering something truthy but not True does not resolve a parent.
    loose = make_ingress(signer_ring(1), lineage=lambda _cid: 1)
    again = wire(make_capsule(1, sequence=5, parents=(kc_id(1),)), ring)
    assert last_reason(loose.receive(again, sender="a", round_index=1)) == (
        "PROVENANCE:unresolvable_lineage"
    )


def test_below_floor_is_metadata_only_in_a_bounded_ring(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ingress_module, "MAX_METADATA_RECORDS", 3)
    ring = signer_ring(*range(1, 6))
    triaged = make_ingress(
        signer_ring(*range(1, 6)),
        gravity=0.0,
        governor=CommunicationGovernor(mode=ExchangeMode.INCIDENT),
    )
    for n in range(1, 6):
        verdict = triaged.receive(
            wire(make_capsule(n, sequence=1), ring), sender=f"s{n}", round_index=1
        )
        assert (verdict.outcome, verdict.gravity) == (IngressOutcome.METADATA_ONLY, 0.0)
    assert [pid for _, pid, _ in triaged.metadata()] == [peer_id(n) for n in (3, 4, 5)]
    assert triaged.stats()["metadata_overwritten"] == 2 and triaged.pool_size() == 0
    assert triaged.stats()["pooled"] == 0  # base counters exist at zero
    control = make_ingress(signer_ring(1), gravity=0.0, gravity_enabled=False)
    assert (
        control.receive(wire(make_capsule(1, sequence=1), ring), sender="c", round_index=1).outcome
        is IngressOutcome.POOLED
    )
    nan = make_ingress(signer_ring(1), gravity=float("nan"))
    assert (
        last_reason(nan.receive(wire(make_capsule(1, sequence=1), ring), sender="n", round_index=1))
        == "RELEVANCE:non_finite_score"
    )


def test_work_budget_refuses_instead_of_raising() -> None:
    ring = signer_ring(1)
    ingress = make_ingress(signer_ring(1), meter=WorkMeter(budget=3))
    verdict = ingress.receive(wire(make_capsule(1, sequence=1), ring), sender="a", round_index=1)
    assert verdict.outcome is IngressOutcome.REFUSED and last_reason(verdict).endswith(
        ":work_budget"
    )
    metered = WorkMeter()
    make_ingress(signer_ring(1), meter=metered).receive(
        wire(make_capsule(1, sequence=1), ring), sender="a", round_index=1
    )
    assert metered.spent > 10  # every stage paid for its work


# --- the governor's modes and the resource report --------------------------------------


def test_idle_mode_sends_nothing() -> None:
    idle = CommunicationGovernor()  # IDLE is the default
    assert idle.mode is ExchangeMode.IDLE
    assert [idle.admit_outbound(size, round_index=0) for size in (0, 1, 100)] == ["round_bytes"] * 3
    assert idle.budget().outbound_used == 0 and idle.budget().outbound_cap == 0
    assert idle.admit_inbound("peer", 100, round_index=0) is None  # hearing costs nothing chosen

    routine = CommunicationGovernor(mode=ExchangeMode.ROUTINE)
    assert (
        routine.admit_outbound(MODE_ROUND_BYTES[ExchangeMode.ROUTINE], round_index=0) == "oversize"
    )
    for _ in range(4):
        assert routine.admit_outbound(4096, round_index=0) is None
    assert routine.admit_outbound(1, round_index=0) == "round_bytes"
    assert routine.admit_outbound(1, round_index=1) is None  # a new round resets the budget

    with pytest.raises(ContractError):
        routine.set_mode(ExchangeMode.RESEARCH, round_index=1)
    with pytest.raises(ContractError):
        CommunicationGovernor(mode=ExchangeMode.RESEARCH)
    routine.set_mode(ExchangeMode.INCIDENT, round_index=2)
    routine.begin_round(2 + INCIDENT_MAX_ROUNDS - 1)
    assert routine.mode is ExchangeMode.INCIDENT
    routine.begin_round(2 + INCIDENT_MAX_ROUNDS)
    assert routine.mode is ExchangeMode.ROUTINE  # an incident nobody clears reverts by itself
    with pytest.raises(ContractError):
        routine.begin_round(0)  # rounds never run backwards


def test_resource_report_refuses_unmeasured_true(monkeypatch: pytest.MonkeyPatch) -> None:
    base = dict(
        peak_sampled_rss_bytes=10_000_000,
        profile=None,
        store_bytes=(("pool", 10),),
        loadavg=(1.0, 1.0, 1.0),
        wall_seconds=0.1,
        cpu_seconds=0.1,
    )
    with pytest.raises(ContractError):
        Stage7ResourceReport(incremental_rss_bytes=None, within_ceiling=True, **base)
    with pytest.raises(ContractError):
        Stage7ResourceReport(
            incremental_rss_bytes=STAGE7_INCREMENTAL_CEILING_BYTES + 1, within_ceiling=True, **base
        )
    with pytest.raises(ContractError):
        Stage7ResourceReport(incremental_rss_bytes=-1, within_ceiling=True, **base)
    with pytest.raises(ContractError):
        Stage7ResourceReport(
            incremental_rss_bytes=1, within_ceiling=True, **{**base, "peak_sampled_rss_bytes": None}
        )
    with pytest.raises(ContractError):
        Stage7ResourceReport(
            incremental_rss_bytes=0, within_ceiling=True, **{**base, "store_bytes": (("pool", -5),)}
        )

    ring = signer_ring(1)
    ingress = make_ingress(signer_ring(1))

    def run() -> dict[str, int]:
        ingress.receive(wire(make_capsule(1, sequence=1), ring), sender="a", round_index=1)
        return {"ingress": ingress.memory_bytes()}

    report = measure_stage7_resources(run)
    if report.incremental_rss_bytes is None:  # RSS unreadable on this host: UNMEASURED
        assert report.within_ceiling is None
    else:
        assert report.incremental_rss_bytes >= 0
        assert report.within_ceiling is (
            report.incremental_rss_bytes <= STAGE7_INCREMENTAL_CEILING_BYTES
        )
    assert dict(report.store_bytes)["ingress"] > 0 and len(report.loadavg) == 3

    from pocketsec.stage0.benchmark import resource_metrics

    monkeypatch.setattr(resource_metrics, "read_rss_bytes", lambda: None)
    blind = measure_stage7_resources(lambda: {"ingress": 1})
    assert (blind.incremental_rss_bytes, blind.within_ceiling) == (None, None)
    assert blind.within_normal is None
    assert communication.STAGE7_INCREMENTAL_NORMAL_BYTES < STAGE7_INCREMENTAL_CEILING_BYTES
