"""D7.20 — the simulated receiver harness, and the partition, offline, churn and scale labs.

Stage 7 is an accelerator, not a dependency (§28): a host must detect exactly as well with
the collective fabric absent, OFFLINE, DISABLED, crashing or holding a corrupt trust store,
and every store must plateau under a month of simulated churn and a flood of 10 000 peers.
This module builds the harness every lab shares — :func:`simulated_receiver` (a real
``OrpheusFabric`` over one corpus host's own history, with two declared observation taps) and
:func:`simulate` (one arm, traffic generated once or replayed exactly) — and the four D7.20
labs that attack the host's independence from the collective:

* :func:`run_offline_equivalence` recomputes the host's LOCAL outputs (its held-out Stage 1
  evidence digests and its local antibodies' scores, forged against the very benign ring the
  fabric was handed) with the fabric never constructed, OFFLINE under a flood, crashing every
  round, DISABLED, and with its keyring corrupted, and compares digests.
* :func:`run_partition_recovery` partitions a receiver, then heals it and replays captured,
  stale backlog and expired capsules at it.
* :func:`run_churn_endurance` replaces a share of the peer population every round for
  ``CHURN_ROUNDS`` rounds and samples every store against its cap.
* :func:`run_scale` offers 10 … 10 000 simulated peers to one receiver's ingress.

Everything is simulated in-process: real partitions, real stale-peer behaviour, real churn and
real device memory are UNMEASURED. No figure here is a device measurement; work units come from
``stage6.resources.WorkMeter`` and wall time is never recorded as evidence.
"""

from __future__ import annotations

import hashlib
import random
from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, fields, replace

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.epoch.model import EpochModel
from pocketsec.stage1.ssir.relations import Relation
from pocketsec.stage6.capsule.quarantine import QuarantineGateway
from pocketsec.stage6.fossils.lineage import KnowledgeLineageDAG
from pocketsec.stage6.resources import WorkMeter
from pocketsec.stage7.antibody.forge import (
    BenignRing,
    LocalIncident,
    LocalValidator,
    forge_antibody,
    matches,
)
from pocketsec.stage7.campaign.hypergraph import JOIN_WINDOW_ROUNDS, CampaignHypergraph, Hyperedge
from pocketsec.stage7.capsule.compiler import ExportContext, compile_capsule
from pocketsec.stage7.capsule.knowledge_capsule import (
    KnowledgeCapsuleV1,
    KnowledgeType,
    MotifRow,
    VisibilityClass,
    seal_capsule,
)
from pocketsec.stage7.echo.inference import (
    DEFAULT_ECHO_CONFIG,
    MAX_KEYS_TRACKED,
    EchoConfig,
    EchoInference,
)
from pocketsec.stage7.falsifier.consensus import ConsensusFalsifier
from pocketsec.stage7.governor.communication import CommunicationGovernor, ExchangeMode
from pocketsec.stage7.graph.dependence import DependenceGraph
from pocketsec.stage7.hivelock.ingress import (
    MAX_POOL_CAPSULES,
    IngressOutcome,
    IngressVerdict,
    PooledCapsule,
)
from pocketsec.stage7.hivelock.stage6_bridge import Stage6Bridge
from pocketsec.stage7.identity.integrity import (
    MAX_KEYS,
    MAX_REPLAY_KEYS,
    MAX_SEEN_CAPSULES,
    Keyring,
    ReplayGuard,
)
from pocketsec.stage7.identity.peer import MAX_PEERS, PeerTable
from pocketsec.stage7.labs.campaign_sim import SIM_STAGE_BASE_RATES
from pocketsec.stage7.labs.fleet_corpus import FleetCorpus
from pocketsec.stage7.labs.simulated_fleet import (
    FLEET_SCOPE,
    AdversaryArm,
    Delivery,
    FleetGroundTruth,
    FleetSpec,
    SimulatedFleet,
    default_receivers,
    honest_antibodies,
    simulated_stage6_receiver,
)
from pocketsec.stage7.lineage.cross_host import (
    MAX_LINEAGE_NODES,
    CrossHostLineageDAG,
    LinkState,
    NodeRole,
)
from pocketsec.stage7.novelty.collective import (
    MAX_NOVELTY_PATTERNS,
    CollectiveNovelty,
    CollectiveNoveltyEngine,
)
from pocketsec.stage7.orpheus.fabric import FabricComponents, FabricState, OrpheusFabric
from pocketsec.stage7.privacy.distiller import (
    contributor_pseudonym,
    family_profile,
    software_epoch_class,
)
from pocketsec.stage7.privacy.ledger import PrivacyLedger
from pocketsec.stage7.relevance.epistemic_distance import LocalContext
from pocketsec.stage7.trust.contextual import MAX_TRUST_ENTRIES, TRUST_PRIOR, ContextualTrust

__all__ = [
    "CHURN_ROUNDS",
    "MAX_TAPPED",
    "ChurnReport",
    "OfflineEquivalence",
    "PartitionReport",
    "ScaleRow",
    "SimulatedReceiver",
    "SuiteRun",
    "VerdictHook",
    "local_output_digest",
    "replay_with",
    "run_churn_endurance",
    "run_offline_equivalence",
    "run_partition_recovery",
    "run_scale",
    "simulate",
    "simulated_receiver",
    "store_caps",
    "store_counts",
    "unplateaued",
]

CHURN_ROUNDS: int = 720  # chosen, not measured: "month-scale" at one round per simulated hour
MAX_TAPPED: int = 65_536  # per receiver, per tap; overflow counted in tap_truncated
SCALE_BATCH: int = 600  # deliveries per round in run_scale: under the 1 MiB RESEARCH round cap
_ALL_RELATIONS = frozenset(int(r) for r in Relation)


# --- the simulated receiver ------------------------------------------------------------------


@dataclass(slots=True)
class SimulatedReceiver:
    """One receiving host: a real fabric over its own local context, plus lab taps."""

    host_id: str
    fabric: OrpheusFabric
    components: FabricComponents
    gateway: QuarantineGateway | None
    stage6_dag: KnowledgeLineageDAG | None
    keyring_refused: int
    inferences: list[EchoInference] = field(default_factory=list)
    pooled: list[PooledCapsule] = field(default_factory=list)
    verdicts: Counter[str] = field(default_factory=Counter)
    triage: list[tuple[float, bool]] = field(default_factory=list)  # (gravity, was pooled)
    triaged_keys: set[str] = field(default_factory=set)  # antibody keys sent to METADATA_ONLY
    tap_truncated: int = 0


def _local_context(corpus: FleetCorpus, fleet: SimulatedFleet, host_id: str) -> LocalContext:
    host = corpus.host(host_id)
    counts = Counter(s.relation_family for e in corpus.for_host(host_id, history=True)
                     for s in e.steps)
    return LocalContext(
        role=host.role, software_epoch=software_epoch_class(host.identity),
        visibility=VisibilityClass.FULL, family_profile=family_profile(counts),
        local_keys=frozenset(a.antibody.antibody_key for a in fleet.local_antibodies(host_id)),
        observable_relations=_ALL_RELATIONS,  # sensors observe every relation: declared
    )


def _validator(corpus: FleetCorpus, host_id: str) -> LocalValidator:
    history = corpus.for_host(host_id, history=True)
    ring = BenignRing()
    for episode in history:
        if episode.label == 0:
            ring.add(episode.steps)
    incidents = [LocalIncident(f"{host_id}-e{e.index:03d}", e.steps, e.evidence_digests[:8])
                 for e in history if e.label == 1]
    return LocalValidator(benign=ring, incidents=incidents, observable_relations=_ALL_RELATIONS)


def _tap(receiver: SimulatedReceiver) -> None:
    """Observation taps: return exactly what they wrap, keep a bounded copy (declared)."""
    echo, ingress = receiver.fabric.echo, receiver.fabric.ingress
    infer, drain = echo.infer, ingress.drain_pool

    def tapped_infer(*, round_index: int) -> EchoInference:
        result = infer(round_index=round_index)
        if len(receiver.inferences) < MAX_TAPPED:
            receiver.inferences.append(result)
        else:
            receiver.tap_truncated += 1
        return result

    def tapped_drain() -> tuple[PooledCapsule, ...]:
        pooled = drain()
        room = MAX_TAPPED - len(receiver.pooled)
        receiver.pooled.extend(pooled[:room])
        receiver.tap_truncated += max(0, len(pooled) - room)
        return pooled

    echo.infer = tapped_infer  # type: ignore[method-assign]
    ingress.drain_pool = tapped_drain  # type: ignore[method-assign]


def simulated_receiver(corpus: FleetCorpus, fleet: SimulatedFleet, host_id: str, *,
                       config: EchoConfig = DEFAULT_ECHO_CONFIG, with_stage6: bool = False,
                       trust_prior: float = TRUST_PRIOR, exchange_enabled: bool = True,
                       keyring_capacity: int = MAX_KEYS, peer_capacity: int = MAX_PEERS,
                       override: Mapping[str, object] | None = None,
                       meter: WorkMeter | None = None) -> SimulatedReceiver:
    """A receiver built from the corpus host's own history and the fleet's key directory.

    The governor runs in RESEARCH mode with ``research_enabled=True`` (lab only), so the
    per-round byte cap is 1 MiB and the per-peer and inbox caps still bind. Keys past the
    keyring's capacity are refused and counted, never forced in. override replaces named
    fabric components (fault injection); peer_capacity bounds the peer table and graph.
    """
    host = corpus.host(host_id)
    keyring, refused = Keyring(capacity=keyring_capacity), 0
    for key_id, key, owner in fleet.key_directory(host_id):
        try:
            keyring.register(key_id, key, owner=owner, round_index=0)
        except ContractError:
            refused += 1
    lineage = CrossHostLineageDAG()
    gateway = stage6_dag = bridge = None
    if with_stage6:
        gateway, stage6_dag = simulated_stage6_receiver(host.identity)
        bridge = Stage6Bridge(
            gateway=gateway, local_dag=stage6_dag, epoch=EpochModel(identity=host.identity).current,
            bridge_secret=hashlib.sha256(f"simulated-bridge:{host_id}".encode()).digest(),
            lineage=lineage, exchange_enabled=True,
        )
    local = _local_context(corpus, fleet, host_id)
    components = FabricComponents(
        local=local, keyring=keyring, replay=ReplayGuard(), peers=PeerTable(capacity=peer_capacity),
        governor=CommunicationGovernor(mode=ExchangeMode.RESEARCH, research_enabled=True),
        graph=DependenceGraph(max_peers=peer_capacity, clustering=config.dependence_clustering),
        trust=ContextualTrust(prior=trust_prior, enabled=config.contextual_trust),
        validator=_validator(corpus, host_id), echo_config=config, lineage=lineage,
        hypergraph=CampaignHypergraph(), novelty=CollectiveNoveltyEngine(local=local),
        falsifier=ConsensusFalsifier(stage_base_rates=SIM_STAGE_BASE_RATES,
                                     relevant_hosts=len(corpus.hosts)),
        bridge=bridge,
    )
    components = replace(components, **(override or {}))  # type: ignore[arg-type]
    fabric = OrpheusFabric(components, exchange_enabled=exchange_enabled, meter=meter,
                           lab_ablation=not config.local_validation)  # declared: ablation
    receiver = SimulatedReceiver(host_id, fabric, components, gateway, stage6_dag, refused)
    _tap(receiver)
    if exchange_enabled:  # local knowledge becomes LOCAL_CAPSULE lineage (sovereignty)
        receiver.fabric.publish(fleet.local_capsules(host_id))
    return receiver


# --- one simulated run -------------------------------------------------------------------------


@dataclass(slots=True)
class SuiteRun:
    """One (arm, share) run: the traffic generated once, and every receiver that ingested it."""

    spec: FleetSpec
    fleet: SimulatedFleet
    truth: FleetGroundTruth
    receivers: dict[str, SimulatedReceiver]
    traffic: tuple[tuple[Delivery, ...], ...]
    offered: Counter[str]  # "<adversarial|honest>:<outcome>:<stage>" over every delivery


#: Per-delivery observer (lab/gate only): sees each delivery and exactly what came back.
VerdictHook = Callable[[Delivery, IngressVerdict | None], None]


def _deliver(run_receivers: Mapping[str, SimulatedReceiver], deliveries: Iterable[Delivery],
             offered: Counter[str], on_verdict: VerdictHook | None = None) -> None:
    for delivery in deliveries:
        receiver = run_receivers.get(delivery.receiver)
        if receiver is None:
            continue
        who = "adversarial" if delivery.adversarial else "honest"
        verdict = receiver.fabric.deliver(delivery.data, sender=delivery.sender)
        if on_verdict is not None:
            on_verdict(delivery, verdict)
        if verdict is None:
            offered[f"{who}:DROPPED:{receiver.fabric.state.value}"] += 1
            continue
        offered[f"{who}:{verdict.outcome.value}:{verdict.stage_reached.value}"] += 1
        receiver.verdicts[verdict.outcome.value] += 1
        if verdict.gravity is not None and len(receiver.triage) < MAX_TAPPED:
            receiver.triage.append((verdict.gravity, verdict.outcome is IngressOutcome.POOLED))
        if verdict.outcome is IngressOutcome.METADATA_ONLY:  # rare: parse only these
            receiver.triaged_keys.add(
                KnowledgeCapsuleV1.from_bytes(delivery.data).compact_feature_signature)


def simulate(corpus: FleetCorpus, spec: FleetSpec, *, config: EchoConfig = DEFAULT_ECHO_CONFIG,
             with_stage6: bool = False, trust_prior: float = TRUST_PRIOR,
             traffic: Sequence[Sequence[Delivery]] | None = None,
             on_verdict: VerdictHook | None = None) -> SuiteRun:
    """Run one arm for ``spec.rounds`` rounds. ``traffic`` replays a recorded run exactly;
    ``on_verdict`` observes every delivery's verdict (it may not alter anything)."""
    fleet = SimulatedFleet(corpus, spec)
    receivers = {h: simulated_receiver(corpus, fleet, h, config=config, with_stage6=with_stage6,
                                       trust_prior=trust_prior) for h in fleet.receivers}
    recorded: list[tuple[Delivery, ...]] = []
    offered: Counter[str] = Counter()
    visible: dict[str, frozenset[str]] = {}
    for round_index in range(spec.rounds):
        if traffic is not None:
            deliveries = tuple(traffic[round_index]) if round_index < len(traffic) else ()
        else:
            deliveries = fleet.round_traffic(round_index, visible_keys=visible)
        recorded.append(deliveries)
        _deliver(receivers, deliveries, offered, on_verdict)
        for receiver in receivers.values():
            receiver.fabric.run_round()
        visible = {h: frozenset(p.capsule.compact_feature_signature for p in r.pooled
                                if p.received_round == round_index
                                and p.capsule.knowledge_type is KnowledgeType.ANTIBODY)
                   for h, r in receivers.items()}
    return SuiteRun(spec, fleet, fleet.ground_truth(), receivers, tuple(recorded), offered)



def replay_with(run: SuiteRun, *, config: EchoConfig | None = None,
                trust_prior: float = TRUST_PRIOR) -> SuiteRun:
    """The same recorded traffic through fresh receivers with a changed configuration."""
    return simulate(run.fleet.corpus, run.spec, config=config or DEFAULT_ECHO_CONFIG,
                    trust_prior=trust_prior, traffic=run.traffic)



# --- offline equivalence (G7.3) ---------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class OfflineEquivalence:
    digest_absent: str
    digest_offline: str
    digest_crashing: str
    digest_disabled: str
    identical: bool  # all five digests equal (corrupt keyring included)
    digest_corrupt_keyring: str = ""
    corrupt_reached_disabled: bool = False
    crashing_failures: int = 0  # component failures the fabric absorbed: proves the crash fired
    offline_dropped: int = 0  # flood deliveries dropped while OFFLINE: proves the flood fired


def local_output_digest(corpus: FleetCorpus, host_id: str, validator: LocalValidator, *,
                        local: LocalContext | None = None,
                        lineage: CrossHostLineageDAG | None = None) -> str:
    """sha256 over the host's local detection outputs AND the local state the fabric can reach.

    Outputs: the held-out Stage 1 evidence digests and the scores of the LOCAL antibodies,
    re-forged against ``validator.benign``. State (review finding F2 — the outputs alone are
    almost constant by construction, so a fabric that corrupted the validator still matched):
    the validator's full :meth:`LocalValidator.state_digest`, its verdict on every local rule
    and on one single-row probe per relation, the sovereignty key set, and every LOCAL_CAPSULE
    lineage node that is no longer LIVE (none may be: only this host's own act revokes one).
    """
    rules = [a.invariant for e in corpus.for_host(host_id, history=True) if e.label == 1
             and (a := forge_antibody(LocalIncident(f"{host_id}-e{e.index:03d}", e.steps,
                                                    e.evidence_digests[:8]),
                                      benign=validator.benign)) is not None]
    digest = hashlib.sha256()
    for episode in corpus.for_host(host_id, history=False):
        digest.update("|".join(d for s in episode.steps for d in s.evidence).encode())
        digest.update(b"1" if any(matches(r, episode.steps) for r in rules) else b"0")
    probes = [*rules, *((MotifRow(int(r), 0, 0, 0),) for r in Relation)]
    digest.update(validator.state_digest().encode())
    digest.update("|".join(validator.validate(p).value for p in probes).encode())
    if local is not None:
        digest.update("|".join(sorted(local.local_keys)).encode())
    if lineage is not None:
        for node_id in lineage.node_ids():
            record = lineage.get(node_id)
            if record is not None and record.role is NodeRole.LOCAL_CAPSULE \
                    and record.state is not LinkState.LIVE:
                digest.update(f"{node_id}:{record.state.value}".encode())
    return digest.hexdigest()


class _CrashingNovelty(CollectiveNoveltyEngine):
    """Fault injection: the novelty step raises every round."""

    def evaluate(self, *, round_index: int) -> tuple[CollectiveNovelty, ...]:
        raise RuntimeError("injected crash (simulated fault)")


class _CrashingHypergraph(CampaignHypergraph):
    """Fault injection: the campaign step raises every round."""

    def build_edges(self, *, round_index: int,
                    join_window: int = JOIN_WINDOW_ROUNDS) -> tuple[Hyperedge, ...]:
        raise RuntimeError("injected crash (simulated fault)")


def _condition_digest(corpus: FleetCorpus, fleet: SimulatedFleet, host_id: str, condition: str,
                      traffic: Sequence[Sequence[Delivery]],
                      ) -> tuple[str, SimulatedReceiver | None]:
    if condition == "absent":  # the fabric is never constructed
        validator = _validator(corpus, host_id)
        local = _local_context(corpus, fleet, host_id)
        per_round = [local_output_digest(corpus, host_id, validator, local=local)
                     for _ in traffic]
        return hashlib.sha256("".join(per_round).encode()).hexdigest(), None
    override: dict[str, object] = {}
    if condition == "crashing":
        local = _local_context(corpus, fleet, host_id)
        override = {"novelty": _CrashingNovelty(local=local), "hypergraph": _CrashingHypergraph()}
    receiver = simulated_receiver(corpus, fleet, host_id, override=override,
                                  exchange_enabled=condition != "disabled")
    if condition == "offline":
        receiver.fabric.partition()
    if condition == "corrupt":  # a rogue key appears in the trust store behind the fabric's back
        receiver.components.keyring.register("key-" + "f" * 16, b"\x13" * 32,
                                             owner="peer-" + "f" * 16, round_index=0)
    per_round = []
    for deliveries in traffic:
        _deliver({host_id: receiver}, deliveries, Counter())
        receiver.fabric.run_round()
        per_round.append(local_output_digest(corpus, host_id, receiver.components.validator,
                                             local=receiver.components.local,
                                             lineage=receiver.components.lineage))
    return hashlib.sha256("".join(per_round).encode()).hexdigest(), receiver


def run_offline_equivalence(corpus: FleetCorpus, *, receiver: str, rounds: int = 4,
                            flood_identities: int = 8) -> OfflineEquivalence:
    """Local outputs with the fabric absent / OFFLINE+flood / crashing / DISABLED / corrupt."""
    spec = FleetSpec(arm=AdversaryArm.FLOOD, sybils_per_root=flood_identities, rounds=rounds,
                     receivers=(receiver,))
    fleet = SimulatedFleet(corpus, spec)
    traffic = [fleet.round_traffic(r, visible_keys={}) for r in range(rounds)]
    digests, rigs = {}, {}
    for condition in ("absent", "offline", "crashing", "disabled", "corrupt"):
        digests[condition], rigs[condition] = _condition_digest(corpus, fleet, receiver, condition,
                                                                traffic)
    crashing, offline, corrupt = rigs["crashing"], rigs["offline"], rigs["corrupt"]
    return OfflineEquivalence(
        digest_absent=digests["absent"], digest_offline=digests["offline"],
        digest_crashing=digests["crashing"], digest_disabled=digests["disabled"],
        identical=len(set(digests.values())) == 1, digest_corrupt_keyring=digests["corrupt"],
        corrupt_reached_disabled=(corrupt is not None
                                  and corrupt.fabric.state is FabricState.DISABLED),
        crashing_failures=crashing.fabric.stats().get("failures", 0) if crashing else 0,
        offline_dropped=sum(n for k, n in offline.fabric.stats().items()
                            if k.startswith("deliveries_dropped")) if offline else 0,
    )


# --- partition and stale-peer recovery (S7X-56/57) --------------------------------------------


@dataclass(frozen=True, slots=True)
class PartitionReport:
    stale_refused: int  # backlog held through the partition, refused on heal (newer seen first)
    replay_refused: int  # pre-partition captures re-sent after heal
    recovered_rounds: int | None  # rounds from heal to the first pooled capsule; None = never
    expired_refused: int  # knowledge past its expiry round, re-sent by a stale peer
    dropped_while_partitioned: int = 0


def _refused_with(verdict: object, needle: str) -> bool:
    if verdict is None or verdict.outcome is not IngressOutcome.REFUSED:  # type: ignore[attr-defined]
        return False
    return any(needle in reason for reason in verdict.reasons)  # type: ignore[attr-defined]


def _expired_capsules(fleet: SimulatedFleet, receiver: str, *, round_index: int) -> list[bytes]:
    """Other hosts' own capsules re-sealed as already expired and signed with their real keys."""
    keys = {owner: (key_id, key) for key_id, key, owner in fleet.key_directory(receiver)}
    derived = {"capsule_id", "signature", "compact_feature_signature", "causal_motif",
               "schema_version"}
    out = []
    for host in fleet.corpus.hosts:
        if host.host_id == receiver or not fleet.local_capsules(host.host_id):
            continue
        base = fleet.local_capsules(host.host_id)[0]
        payload = {f.name: getattr(base, f.name) for f in fields(base) if f.name not in derived}
        stale = seal_capsule(**{**payload, "created_round": 0, "expiry_round": 1,
                                "sequence": 10**9 + round_index})
        key_id, key = keys[fleet.peer_of_host(host.host_id)]
        ring = Keyring(capacity=1)
        ring.register(key_id, key, owner=fleet.peer_of_host(host.host_id), round_index=0)
        out.append(ring.sign(stale, key_id=key_id).canonical_bytes())
    return out[:8]


def run_partition_recovery(corpus: FleetCorpus, *, partition_rounds: int = 8,
                           seed: int = 0) -> PartitionReport:
    """Partition one receiver, heal it, then send it backlog, replays and expired knowledge."""
    host = default_receivers(corpus)[0]
    start, heal_at = 3, 3 + partition_rounds
    spec = FleetSpec(arm=AdversaryArm.NONE, rounds=heal_at + 4, seed=seed, receivers=(host,))
    fleet = SimulatedFleet(corpus, spec)
    receiver = simulated_receiver(corpus, fleet, host)
    fabric, counts = receiver.fabric, Counter[str]()
    backlog: list[Delivery] = []
    captured: list[Delivery] = []
    recovered: int | None = None
    for r in range(spec.rounds):
        deliveries = fleet.round_traffic(r, visible_keys={})
        if r == start:
            fabric.partition()
        if r == heal_at:
            fabric.heal()
        partitioned = start <= r < heal_at
        for d in deliveries:
            counts["dropped"] += fabric.deliver(d.data, sender=d.sender) is None and partitioned
        (backlog if partitioned else captured if r < start else []).extend(deliveries)
        if r == heal_at:
            for d in backlog:
                counts["stale"] += _refused_with(fabric.deliver(d.data, sender=d.sender), "REPLAY")
            for d in captured:
                counts["replay"] += _refused_with(fabric.deliver(d.data, sender=d.sender), "REPLAY")
            for data in _expired_capsules(fleet, host, round_index=r):
                counts["expired"] += _refused_with(fabric.deliver(data, sender="stale-peer"),
                                                   "expired")
        report = fabric.run_round()
        if r >= heal_at and recovered is None and report.pooled > 0:
            recovered = r - heal_at
    return PartitionReport(stale_refused=counts["stale"], replay_refused=counts["replay"],
                           recovered_rounds=recovered, expired_refused=counts["expired"],
                           dropped_while_partitioned=counts["dropped"])


# --- synthetic peer populations (churn and scale) ------------------------------------------------


@dataclass(slots=True)
class _Peer:
    peer_id: str
    key_id: str
    key: bytes
    context: ExportContext
    ledger: PrivacyLedger = field(default_factory=lambda: PrivacyLedger(max_releases=1_000_000))
    sequence: int = 0
    provisioned: bool = False


def _synthetic_peer(corpus: FleetCorpus, tag: str, index: int, seed: int) -> _Peer:
    """A fresh simulated identity with its own declared root (every one 'independent')."""
    secret = hashlib.sha256(f"synthetic:{seed}:{tag}:{index}".encode()).digest()
    host = corpus.hosts[index % len(corpus.hosts)]
    counts = Counter(s.relation_family for e in corpus.for_host(host.host_id, history=True)
                     for s in e.steps)
    key_id = "key-" + hashlib.sha256(b"k" + secret).hexdigest()[:16]
    context = ExportContext(
        host_secret=secret, identity=host.identity, role=host.role,
        provenance_root="root-" + hashlib.sha256(b"r" + secret).hexdigest()[:16], key_id=key_id,
        visibility_share=1.0, family_counts=dict(counts), fleet_scope=FLEET_SCOPE,
    )
    return _Peer(contributor_pseudonym(secret, FLEET_SCOPE), key_id,
                 hashlib.sha256(b"key" + secret).digest(), context)


def _peer_capsule(peer: _Peer, corpus: FleetCorpus, round_index: int) -> bytes:
    items = honest_antibodies(corpus)
    item = items[int(peer.key_id[4:12], 16) % len(items)]
    peer.sequence += 1
    capsule = compile_capsule(
        knowledge_type=KnowledgeType.ANTIBODY, invariant=item.antibody.invariant,
        evidence_digests=item.incident.evidence_digests, validation=item.antibody.validation,
        falsification=item.antibody.falsification, context=peer.context, ledger=peer.ledger,
        created_round=round_index, sequence=peer.sequence,
    )
    signer = Keyring(capacity=1)
    signer.register(peer.key_id, peer.key, owner=peer.peer_id, round_index=0)
    return signer.sign(capsule, key_id=peer.key_id).canonical_bytes()


def _provision(receiver: SimulatedReceiver, peer: _Peer, round_index: int) -> bool:
    try:
        receiver.components.keyring.register(peer.key_id, peer.key, owner=peer.peer_id,
                                             round_index=round_index)
    except ContractError:
        return False  # a full keyring refuses; it never evicts (identity.integrity)
    peer.provisioned = True
    return True


# --- churn endurance (S7X-70) --------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ChurnReport:
    rounds: int
    peers_seen: int
    store_peaks: tuple[tuple[str, int, int], ...]  # (store, peak count, cap)
    evictions: tuple[tuple[str, int], ...]
    plateau_ok: bool  # per store: peak(last third) <= peak(middle third)
    unplateaued: tuple[tuple[str, int, int], ...] = ()  # (store, middle peak, last peak) that grew


def store_caps(peer_capacity: int = MAX_PEERS) -> dict[str, int]:
    """Every sampled store's named cap (peer-sized stores follow ``peer_capacity``)."""
    return {"peers": peer_capacity, "keyring": peer_capacity, "graph": peer_capacity,
            "replay_keys": MAX_REPLAY_KEYS, "replay_seen": MAX_SEEN_CAPSULES,
            "trust": MAX_TRUST_ENTRIES, "lineage": MAX_LINEAGE_NODES, "pool": MAX_POOL_CAPSULES,
            "echo_keys": MAX_KEYS_TRACKED, "novelty": MAX_NOVELTY_PATTERNS}


def store_counts(receiver: SimulatedReceiver, echo_keys: int) -> dict[str, int]:
    """Every bounded store's current entry count (the keys of :func:`store_caps`)."""
    c = receiver.components
    keys, seen = c.replay.sizes()
    return {"peers": len(c.peers), "keyring": len(c.keyring), "graph": len(c.graph),
            "replay_keys": keys, "replay_seen": seen, "trust": len(c.trust),
            "lineage": len(c.lineage), "pool": receiver.fabric.ingress.pool_size(),
            "echo_keys": echo_keys, "novelty": c.novelty.patterns()}


def run_churn_endurance(corpus: FleetCorpus, *, rounds: int = CHURN_ROUNDS,
                        churn_share: float = 0.1, seed: int = 0, peer_capacity: int = MAX_PEERS,
                        publish_p: float = 0.1) -> ChurnReport:
    """Replace ``churn_share`` of the peer population EVERY round; sample every store."""
    if not 0.0 <= churn_share <= 1.0 or rounds < 3:
        raise ContractError("churn_share must be in [0, 1] and rounds >= 3")
    host = default_receivers(corpus)[0]
    fleet = SimulatedFleet(corpus, FleetSpec(arm=AdversaryArm.NONE, seed=seed, receivers=(host,)))
    receiver = simulated_receiver(corpus, fleet, host, keyring_capacity=peer_capacity,
                                  peer_capacity=peer_capacity)
    rng, counts = random.Random(f"churn:{seed}"), Counter[str]()
    born = len(corpus.hosts)
    active = [_synthetic_peer(corpus, "churn", i, seed) for i in range(born)]
    for peer in active:
        counts["keyring_refused"] += not _provision(receiver, peer, 0)
    receiver.fabric.repin_keyring()  # a deliberate local provisioning act
    samples: list[dict[str, int]] = []
    for r in range(rounds):
        for peer in active:
            if rng.random() < publish_p:
                receiver.fabric.deliver(_peer_capsule(peer, corpus, r), sender=peer.peer_id)
        receiver.fabric.run_round()
        tracked = receiver.inferences[-1].keys_tracked if receiver.inferences else 0
        samples.append(store_counts(receiver, tracked))
        for i, peer in enumerate(active):
            if rng.random() < churn_share:  # the peer leaves: revoke; a fresh identity joins
                if peer.provisioned:
                    receiver.components.keyring.revoke(peer.key_id, round_index=r)
                active[i] = _synthetic_peer(corpus, "churn", born, seed)
                born += 1
                counts["keyring_refused"] += not _provision(receiver, active[i], r)
        receiver.fabric.repin_keyring()
    return _churn_report(receiver, samples, counts, rounds=rounds, peers_seen=born,
                         peer_capacity=peer_capacity)


def unplateaued(samples: Sequence[Mapping[str, int]], stores: Iterable[str], *,
                rounds: int) -> tuple[tuple[str, int, int], ...]:
    """(store, middle-third max, last-third max) for every store still GROWING.

    A store is growing when its last-third max exceeds its middle-third max by MORE than
    its own largest one-round change in the middle third. Review finding R7-4: the earlier
    rule (any last-third max above the middle-third max) was only ever met because a full
    keyring had stopped the receiver admitting anyone; once dead keys are reclaimed the
    stores are live and fluctuate, and a stationary store would fail the old rule by
    chance. A leak still grows by more than one round's fluctuation over a third of the
    run, which the test pins with a synthetic leak.
    """
    third = rounds // 3
    middle, last = samples[third:2 * third], samples[2 * third:]
    out = []
    for store in stores:
        series = [x[store] for x in middle]
        swing = max((abs(b - a) for a, b in zip(series, series[1:])), default=0)
        top_mid, top_last = max(series), max(x[store] for x in last)
        if top_last > top_mid + swing:
            out.append((store, top_mid, top_last))
    return tuple(out)


def _churn_report(receiver: SimulatedReceiver, samples: Sequence[Mapping[str, int]],
                  counts: Counter[str], *, rounds: int, peers_seen: int,
                  peer_capacity: int) -> ChurnReport:
    caps = store_caps(peer_capacity)
    peaks = tuple((s, max(x[s] for x in samples), caps[s]) for s in sorted(caps))
    grew = unplateaued(samples, sorted(caps), rounds=rounds)
    plateau = not grew
    c = receiver.components
    evictions = {"peers_evicted": c.peers.evictions(), "peers_refused": c.peers.refused(),
                 "graph_evicted": c.graph.evictions(), "keyring_refused": counts["keyring_refused"],
                 "replay_evicted": sum(c.replay.evictions()), "trust_evicted": c.trust.evictions(),
                 "lineage_evicted": c.lineage.evictions(),
                 "echo_keys_refused": receiver.fabric.echo.keys_refused()}
    return ChurnReport(rounds=rounds, peers_seen=peers_seen, store_peaks=peaks,
                       evictions=tuple(sorted((k, int(v)) for k, v in evictions.items())),
                       plateau_ok=plateau, unplateaued=grew)


# --- scale (S7X-59/60) ------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ScaleRow:
    peers: int
    refused_peers: int
    table_size: int
    memory_bytes: int
    work_units: int


def run_scale(*, peer_counts: Sequence[int] = (10, 100, 1000, 10000), seed: int = 0,
              corpus: FleetCorpus | None = None,
              peer_capacity: int = MAX_PEERS) -> tuple[ScaleRow, ...]:
    """Offer N simulated peers (one capsule each) to one receiver's ingress, graph and table.

    The lab keyring holds all N keys (capacity N + 64) so the bound under test is the peer
    table's and the graph's, not the keyring's (the keyring's own bound is churn's finding).
    """
    if corpus is None:
        from pocketsec.stage7.labs.fleet_corpus import build_fleet_corpus
        corpus = build_fleet_corpus(hosts=6, episodes_per_host=16, seed=7)
    host = default_receivers(corpus)[0]
    fleet = SimulatedFleet(corpus, FleetSpec(arm=AdversaryArm.NONE, seed=seed, receivers=(host,)))
    rows = []
    for n in peer_counts:
        meter = WorkMeter()
        receiver = simulated_receiver(corpus, fleet, host, keyring_capacity=n + 64,
                                      peer_capacity=peer_capacity, meter=meter)
        peers = [_synthetic_peer(corpus, "scale", i, seed) for i in range(n)]
        for peer in peers:
            _provision(receiver, peer, 0)
        receiver.fabric.repin_keyring()
        for start in range(0, n, SCALE_BATCH):
            for peer in peers[start:start + SCALE_BATCH]:
                receiver.fabric.deliver(_peer_capsule(peer, corpus, receiver.fabric.round_index),
                                        sender=peer.peer_id)
            receiver.fabric.run_round()
        c = receiver.components
        rows.append(ScaleRow(peers=n, refused_peers=c.peers.refused(), table_size=len(c.peers),
                             memory_bytes=sum(receiver.fabric.memory_bytes().values()),
                             work_units=meter.spent))
    return tuple(rows)
