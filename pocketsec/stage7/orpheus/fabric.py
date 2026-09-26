"""Layer 7.20 / ORPH-F21 — the ORPHEUS fabric: composition root, failure isolation, offline mode.

Architecture §28: Stage 7 is an **accelerator, not a dependency**. This module exists to
wire the collective machinery together in exactly one place — the ingress's injected graph,
relevance, gravity and lineage callables, ECHO, the revocation plane, the campaign and
novelty engines and the Stage 6 bridge — and to guarantee that nothing it does can hurt the
host when it misbehaves:

* **Off by default.** ``exchange_enabled`` defaults to ``COLLECTIVE_EXCHANGE_ENABLED``
  (False): the fabric is DISABLED and :meth:`OrpheusFabric.deliver` receives nothing.
* **Never raises from a round.** :meth:`OrpheusFabric.run_round` catches every component
  exception, marks the round DEGRADED, stops exchange for the rest of that round and counts
  it (§43 "fail closed for foreign knowledge, open for local cognition").
* **A corrupt trust store disables exchange.** The keyring's state digest is pinned at
  construction; if :meth:`Keyring.verify_state` ever fails the fabric goes DISABLED and
  drops what it had pooled under the suspect keys (§43 "peer trust store corrupt → disable
  exchange, preserve local cognition"). Only a deliberate local :meth:`repin_keyring`
  re-enables it.
* **Offline is a mode, not a failure.** :meth:`partition` / :meth:`heal` drive the
  governor's simulated link; while OFFLINE nothing is received or published.

**The fabric holds no reference to anything local detection uses.** Local detection
(Stages 1-6) never imports Stage 7 (boundary rule 11), so the fabric being absent, OFFLINE,
DISABLED or crashing is invisible to it by construction; the sovereignty test measures it
anyway. The fabric **never writes local trusted state**: its only exit towards Stage 6 is
:class:`~pocketsec.stage7.hivelock.stage6_bridge.Stage6Bridge`, which hands ``ELIGIBLE``
candidates to Stage 6's quarantine and records the verdict verbatim. Each antibody key is
bridged at most once.

Round order (spec D7.18, exactly): ingress drain → revocations → ECHO offer/infer → bridge
ELIGIBLE (once per key) → fragments → hypergraph → reconstruct/falsify → novelty. The Sybil
suspicion used by gravity is refreshed after novelty, so a round's receptions are judged
by the previous round's graph (deterministic, and O(peers) once per round, not per capsule).

**What ECHO may count is read from local state every round** (review fixes S7-R1, S7-R4,
R7-1): a contribution counts only while its lineage node is LIVE and its signing key still
verifies, and the sovereignty set ECHO and ingress read is the LIVE view, which includes
every antibody key this host has published. Replay-guard entries that can never matter
again are pruned each round (R7-4).

Everything here is simulated in-process: real latency, real partitions and real Sybil
populations are UNMEASURED for real deployments.
"""

from __future__ import annotations

import sys
from collections import Counter, OrderedDict, deque
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage6.resources import WorkMeter
from pocketsec.stage7.antibody.forge import LocalValidator
from pocketsec.stage7.campaign.hypergraph import STAGE_ORDER, CampaignHypergraph, Fragment
from pocketsec.stage7.capsule.knowledge_capsule import (
    ChainStage,
    KnowledgeCapsuleV1,
    KnowledgeType,
    Stance,
)
from pocketsec.stage7.constitution.collective import COLLECTIVE_EXCHANGE_ENABLED
from pocketsec.stage7.echo.inference import (
    EchoConfig,
    EchoDecision,
    EchoEngine,
    EchoInference,
    EchoStatus,
)
from pocketsec.stage7.falsifier.consensus import (
    ConsensusFalsifier,
    NegativeClaim,
    negative_evidence_weight,
)
from pocketsec.stage7.governor.communication import (
    CommunicationBudget,
    CommunicationGovernor,
    ExchangeMode,
)
from pocketsec.stage7.graph.dependence import DependenceGraph, EdgeKind
from pocketsec.stage7.graph.sybil import sybil_report
from pocketsec.stage7.hivelock.ingress import (
    HivelockIngress,
    IngressOutcome,
    IngressStage,
    IngressVerdict,
    PooledCapsule,
)
from pocketsec.stage7.hivelock.stage6_bridge import Stage6Bridge
from pocketsec.stage7.identity.integrity import Keyring, KeyState, ReplayGuard
from pocketsec.stage7.identity.peer import PeerIdentity, PeerTable
from pocketsec.stage7.lineage.cross_host import (
    MAX_PARENTS_PER_NODE,
    CrossHostLineageDAG,
    LineageRecord,
    LinkState,
    NodeRole,
    RevocationPlane,
)
from pocketsec.stage7.novelty.collective import CollectiveNoveltyEngine, NoveltyStatus
from pocketsec.stage7.privacy.distiller import residual_identifier_hits
from pocketsec.stage7.reconstruct.partial_world import PartialWorldReconstructor, WorldStatus
from pocketsec.stage7.relevance.epistemic_distance import (
    EpistemicDistance,
    LocalContext,
    epistemic_distance,
    relevance,
)
from pocketsec.stage7.relevance.gravity import knowledge_gravity
from pocketsec.stage7.trust.contextual import ContextualTrust

__all__ = [
    "MAX_BRIDGED_KEYS",
    "MAX_NEGATIVE_CLAIMS",
    "MAX_PUBLISHED_IDS",
    "MAX_TRACKED_CAPSULES",
    "FabricComponents",
    "FabricState",
    "OrpheusFabric",
    "RoundReport",
]

#: Chosen parameters, not measurements (fabric-owned bookkeeping; §4.23 names none).
MAX_TRACKED_CAPSULES: int = 16384  # capsule id -> (contributor, raw digest); == MAX_LINEAGE_NODES
MAX_BRIDGED_KEYS: int = 1024  # antibody keys already handed to Stage 6; == MAX_KEYS_TRACKED
MAX_PUBLISHED_IDS: int = 4096  # local capsule ids this host published (sovereignty view)
MAX_NEGATIVE_CLAIMS: int = 1024
MAX_CLUSTER_REPRESENTATIVES: int = 4096


class FabricState(StrEnum):
    DISABLED = "DISABLED"
    OFFLINE = "OFFLINE"
    ACTIVE = "ACTIVE"
    DEGRADED = "DEGRADED"


@dataclass(frozen=True, slots=True)
class FabricComponents:
    """Every store the fabric composes, constructed (and so bounded) by the caller."""

    local: LocalContext
    keyring: Keyring
    replay: ReplayGuard
    peers: PeerTable
    governor: CommunicationGovernor
    graph: DependenceGraph
    trust: ContextualTrust
    validator: LocalValidator
    echo_config: EchoConfig
    lineage: CrossHostLineageDAG
    hypergraph: CampaignHypergraph
    novelty: CollectiveNoveltyEngine
    falsifier: ConsensusFalsifier
    bridge: Stage6Bridge | None  # None: no Stage 6 handoff (measurement arms)
    # Knowledge-gravity triage at ingress (ORPH-F06). A switch here so ADR-0069's
    # recommendation ("default off until work units are compared") is a configuration change.
    gravity_enabled: bool = True


@dataclass(frozen=True, slots=True)
class RoundReport:
    round_index: int
    state: FabricState
    received: int
    pooled: int
    refused_by_stage: tuple[tuple[str, int], ...]
    decisions: tuple[tuple[str, int], ...]
    bridged: int
    stage6_buckets: tuple[tuple[str, int], ...]
    revocations: tuple[tuple[str, int], ...]
    worlds: tuple[tuple[str, int], ...]
    novel: int
    failures: int
    budget: CommunicationBudget


def _sorted(counter: Mapping[str, int]) -> tuple[tuple[str, int], ...]:
    return tuple(sorted((k, v) for k, v in counter.items() if v))


def _supporting_capsules(decision: EchoDecision) -> tuple[str, ...]:
    """The capsule ids behind a decision's SUPPORT rows, in evidence order, deduplicated."""
    return tuple(dict.fromkeys(
        cid
        for row in decision.evidence if row.stance is Stance.SUPPORT
        for cid in row.capsule_ids
    ))


def _fragment_stage(stages: Sequence[ChainStage]) -> ChainStage:
    """The most advanced orderable stage a capsule's chain reaches; OTHER if none is."""
    ordered = [stage for stage in stages if stage in STAGE_ORDER]
    return max(ordered, key=STAGE_ORDER.__getitem__) if ordered else ChainStage.OTHER


class _Bounded:
    """An insertion-ordered map that forgets its oldest entry when full, counting it."""

    def __init__(self, capacity: int) -> None:
        self.capacity = capacity
        self.items: OrderedDict[str, tuple[str, ...]] = OrderedDict()
        self.evictions = 0

    def put(self, key: str, value: tuple[str, ...]) -> None:
        if key in self.items:
            self.items.move_to_end(key)
        elif len(self.items) >= self.capacity:
            self.items.popitem(last=False)
            self.evictions += 1
        self.items[key] = value

    def memory_bytes(self) -> int:
        return sys.getsizeof(self.items) + sum(
            sys.getsizeof(k) + sum(sys.getsizeof(v) for v in vals) + 104
            for k, vals in self.items.items()
        )


class _Round:
    """Per-round tallies; discarded when the round ends."""

    def __init__(self) -> None:
        self.received = 0
        self.pooled = 0
        self.refused: Counter[str] = Counter()
        self.decisions: Counter[str] = Counter()
        self.bridged = 0
        self.buckets: Counter[str] = Counter()
        self.revocations: Counter[str] = Counter()
        self.worlds: Counter[str] = Counter()
        self.novel = 0
        self.failures = 0
        self.pending_count = 0
        self.pending_bytes = 0


class OrpheusFabric:
    """ORPH-F21. Composes the collective subsystems; isolates their failures from the host."""

    def __init__(
        self,
        components: FabricComponents,
        *,
        exchange_enabled: bool = COLLECTIVE_EXCHANGE_ENABLED,
        meter: WorkMeter | None = None,
        lab_ablation: bool = False,
    ) -> None:
        if not isinstance(components, FabricComponents):
            raise ContractError("OrpheusFabric takes FabricComponents")
        if not isinstance(exchange_enabled, bool) or not isinstance(lab_ablation, bool):
            raise ContractError("exchange_enabled and lab_ablation must be bools")
        # ECHO's local_validation=False is an ablation switch that removes the LOCAL_FP ->
        # CHALLENGED sovereignty rule (D7.10 step 2). Only a lab that declares it is running
        # an ablation may build a fabric without it; a host fabric refuses (LOCAL_SOVEREIGNTY).
        if not components.echo_config.local_validation and not lab_ablation:
            raise ContractError(
                "local_validation=False removes a sovereignty rule; only a declared "
                "lab_ablation fabric may run without it"
            )
        self._c = components
        self._local = components.local
        self._enabled = exchange_enabled
        self._keyring_digest = components.keyring.state_digest()
        self._disabled_by_keyring = False
        self._round = components.governor.budget().round_index
        self._now = _Round()
        self._degraded = False
        self._n: Counter[str] = Counter()
        self._facts = _Bounded(MAX_TRACKED_CAPSULES)  # capsule id -> (contributor, raw digest)
        self._cluster_peer = _Bounded(MAX_CLUSTER_REPRESENTATIVES)  # cluster id -> (a member peer,)
        self._bridged = _Bounded(MAX_BRIDGED_KEYS)
        self._published = _Bounded(MAX_PUBLISHED_IDS)
        # Antibody keys this host published after start-up: sovereign exactly like the keys in
        # LocalContext (S7-R4). Never evicted — a full set refuses the next publish instead.
        self._published_keys: dict[str, None] = {}
        self._local_view: frozenset[str] = frozenset(components.local.local_keys)
        self._negative: deque[NegativeClaim] = deque(maxlen=MAX_NEGATIVE_CLAIMS)
        self._suspected: frozenset[str] = frozenset()
        self._burst_cache: tuple[int, frozenset[frozenset[str]]] = (-1, frozenset())
        self._sequence = 0
        self._last: EchoInference | None = None
        self._ingress = self._build_ingress(meter)
        self._echo = EchoEngine(
            local=components.local, validator=components.validator, trust=components.trust,
            cluster_of=components.graph.cluster_of, config=components.echo_config, meter=meter,
            local_keys=lambda: self._local_view, contribution_live=self._capsule_live,
            key_active=self._key_usable,
        )
        self._plane = RevocationPlane(
            dag=components.lineage, owner_of_key=components.keyring.owner_of,
            contributor_of=self._contributor_of, local_keys=lambda: self._local_view,
            echo_suspect=self._echo_suspect,
        )
        self._reconstructor = PartialWorldReconstructor(
            hypergraph=components.hypergraph, falsifier=components.falsifier,
            resolve_cluster=self._resolve_cluster, birth_burst=self._birth_burst, meter=meter,
        )

    # --- wiring: the ingress's injected callables ----------------------------------------

    def _build_ingress(self, meter: WorkMeter | None) -> HivelockIngress:
        c = self._c
        return HivelockIngress(
            keyring=c.keyring, replay=c.replay, peers=c.peers, governor=c.governor,
            cluster_of=self._observe_dependence, relevance_of=self._relevance_of,
            gravity_of=self._gravity_of, lineage_resolves=c.lineage.has,
            local_keys=lambda: self._local_view, gravity_enabled=c.gravity_enabled, meter=meter,
        )

    def _observe_dependence(
        self, capsule: KnowledgeCapsuleV1, peer: PeerIdentity, round_index: int
    ) -> str:
        cluster = self._c.graph.observe(capsule, peer, round_index=round_index)
        self._cluster_peer.put(cluster, (peer.peer_id,))
        return cluster

    def _distance(self, capsule: KnowledgeCapsuleV1) -> EpistemicDistance:
        return epistemic_distance(
            capsule.source_context_sketch, capsule.epoch_context, self._local,
            enabled=self._c.echo_config.epistemic_distance,
        )

    def _relevance_of(self, capsule: KnowledgeCapsuleV1) -> float:
        return relevance(self._distance(capsule))

    def _gravity_of(self, capsule: KnowledgeCapsuleV1, cluster_id: str, round_index: int) -> float:
        contributor = capsule.provenance_commitment.contributor
        # Assessed-ness, not 1/cluster size (R7-5): ECHO's cluster cap already counts a
        # cluster once, so dividing gravity by its size counted dependence twice and dropped
        # a merged honest cluster's every capsule before ECHO could give it its one term. An
        # UNASSESSED peer (graph full) still has independence 0 and so gravity 0.
        assessed = 1.0 if self._c.graph.independence(contributor) > 0.0 else 0.0
        return knowledge_gravity(
            capsule, distance=self._distance(capsule),
            independence=assessed,
            suspicion=1.0 if cluster_id in self._suspected else 0.0,
            local=self._local, round_index=round_index,
        ).value

    def _contributor_of(self, capsule_id: str) -> str | None:
        facts = self._facts.items.get(capsule_id)
        return facts[0] if facts else None

    def _capsule_live(self, capsule_id: str) -> bool:
        """ECHO counts a contribution only while its lineage node is LIVE (S7-R1). A node the
        bounded DAG no longer holds cannot be shown unrevoked, so it does not count."""
        record = self._c.lineage.get(capsule_id)
        return record is not None and record.state is LinkState.LIVE

    def _key_usable(self, key_id: str, round_index: int) -> bool:
        """ECHO counts a contribution only while its signing key would still verify (R7-1)."""
        record = self._c.keyring.record(key_id)
        if record is None or record.state is KeyState.REVOKED:
            return False
        return record.state is KeyState.ACTIVE or round_index <= (record.not_after_round or 0)

    def _echo_suspect(self, keys: Iterable[str], suspect: bool) -> None:
        (self._echo.mark_suspect if suspect else self._echo.clear_suspect)(tuple(keys))

    def _resolve_cluster(self, cluster_id: str) -> str:
        member = self._cluster_peer.items.get(cluster_id)
        return self._c.graph.cluster_of(member[0]) if member else cluster_id

    def _birth_burst(self, capsule_ids: Sequence[str]) -> bool:
        """True iff two contributors of these capsules share a BIRTH_CO_TIMING edge."""
        if self._burst_cache[0] != self._round:
            pairs = frozenset(
                frozenset((e.a, e.b)) for e in self._c.graph.edges()
                if e.kind is EdgeKind.BIRTH_CO_TIMING
            )
            self._burst_cache = (self._round, pairs)
        peers = sorted({f[0] for cid in capsule_ids if (f := self._facts.items.get(cid))})
        pairs = self._burst_cache[1]
        return any(
            frozenset((a, b)) in pairs for i, a in enumerate(peers) for b in peers[i + 1 :]
        )

    # --- state -------------------------------------------------------------------

    @property
    def state(self) -> FabricState:
        if not self._enabled or self._disabled_by_keyring:
            return FabricState.DISABLED
        if self._degraded:
            return FabricState.DEGRADED
        governor = self._c.governor
        if governor.partitioned or governor.mode is ExchangeMode.OFFLINE:
            return FabricState.OFFLINE
        return FabricState.ACTIVE

    @property
    def round_index(self) -> int:
        return self._round

    def repin_keyring(self) -> None:
        """A deliberate LOCAL act after an authorised key change: pin the current keyring
        state and lift a keyring-caused DISABLED. Never called by any foreign path."""
        self._keyring_digest = self._c.keyring.state_digest()
        self._disabled_by_keyring = False

    def _keyring_intact(self) -> bool:
        try:
            intact = self._c.keyring.verify_state(self._keyring_digest)
        except Exception:  # a keyring that cannot even answer is corrupt
            intact = False
        if not intact:
            self._disabled_by_keyring = True
            self._n["keyring_disabled"] += 1
        return intact

    # --- inbound -----------------------------------------------------------------

    def deliver(self, data: bytes, *, sender: str) -> IngressVerdict | None:
        """Hand received bytes to HIVELOCK ingress. None (counted) when DISABLED, OFFLINE or
        DEGRADED — nothing is parsed, nothing is pooled."""
        if not isinstance(data, bytes):
            raise ContractError(f"deliver takes the bytes as received, got {type(data).__name__}")
        state = self.state
        if state is not FabricState.ACTIVE:
            self._n[f"deliveries_dropped:{state.value}"] += 1
            return None
        inbox = self._c.governor.budget()
        try:
            verdict = self._ingress.receive(data, sender=sender, round_index=self._round)
        except Exception:
            # Whatever the governor admitted before the crash must still be released, or a
            # crashing ingress would fill the inbox and shut exchange out for good.
            after = self._c.governor.budget()
            self._now.pending_count += max(0, after.inbox_capsules - inbox.inbox_capsules)
            self._now.pending_bytes += max(0, after.inbox_bytes - inbox.inbox_bytes)
            self._fail("ingress")
            return None
        self._now.received += 1
        refused = verdict.outcome is IngressOutcome.REFUSED
        if not (refused and verdict.stage_reached is IngressStage.SIZE_RATE):
            self._now.pending_count += 1  # the governor admitted it into the inbox
            self._now.pending_bytes += len(data)
        if refused:
            self._now.refused[verdict.stage_reached.value] += 1
        return verdict

    def _fail(self, step: str) -> None:
        self._degraded = True
        self._now.failures += 1
        self._n["failures"] += 1
        self._n[f"failure:{step}"] += 1

    # --- the round -----------------------------------------------------------------

    def run_round(self) -> RoundReport:
        """Process everything received this round, in spec order. NEVER raises."""
        drained: tuple[PooledCapsule, ...] = ()
        try:
            self._release_inbox()
            # Sticky: once the trust store failed its check, only a local repin reopens it,
            # even if the store later happens to match again.
            if self._enabled and not self._disabled_by_keyring and self._keyring_intact():
                drained = self._run_steps()
            else:
                self._discard_inbound()
        except Exception:  # defence in depth: the step runner already isolates steps
            self._fail("round")
        report = self._report(len(drained))
        self._advance()
        return report

    def _release_inbox(self) -> None:
        count, size = self._now.pending_count, self._now.pending_bytes
        self._now.pending_count = self._now.pending_bytes = 0
        budget = self._c.governor.budget()
        if count > budget.inbox_capsules or size > budget.inbox_bytes:
            self._n["inbox_release_clamped"] += 1  # an accounting mismatch, surfaced not hidden
        self._c.governor.release(min(count, budget.inbox_capsules), min(size, budget.inbox_bytes))

    def _discard_inbound(self) -> None:
        """DISABLED: whatever was pooled under a now-suspect trust store is dropped, counted."""
        self._n["discarded_on_disable"] += len(self._ingress.drain_pool())
        self._n["discarded_on_disable"] += len(self._ingress.drain_revocations())

    def _prune_replay(self) -> None:
        """Reclaim replay-guard entries that can never matter again (R7-4): expired capsule
        ids, and every entry of a key that no longer verifies."""
        now = self._round
        pruned = self._c.replay.prune(round_index=now,
                                      key_live=lambda k: self._key_usable(k, now))
        self._n["replay_pruned"] += pruned

    def _run_steps(self) -> tuple[PooledCapsule, ...]:
        holder: list[tuple[PooledCapsule, ...]] = [()]
        revocations: list[tuple[KnowledgeCapsuleV1, str]] = []
        decisions: list[tuple[EchoDecision, ...]] = [()]
        steps: tuple[tuple[str, Callable[[], None]], ...] = (
            ("drain", lambda: self._drain(holder, revocations)),
            ("replay", self._prune_replay),
            ("revocations", lambda: self._revoke(revocations)),
            ("echo", lambda: decisions.__setitem__(0, self._infer(holder[0]))),
            ("bridge", lambda: self._bridge(decisions[0])),
            ("fragments", lambda: self._fragments(holder[0])),
            ("campaign", self._campaign),
            ("novelty", lambda: self._novelty(holder[0])),
            ("suspicion", self._refresh_suspicion),
        )
        for name, step in steps:
            if self._degraded:  # a failure earlier this round closes exchange for the rest of it
                self._n["steps_skipped"] += 1
                continue
            try:
                step()
            except Exception:
                self._fail(name)
        return holder[0]

    def _drain(
        self,
        holder: list[tuple[PooledCapsule, ...]],
        revocations: list[tuple[KnowledgeCapsuleV1, str]],
    ) -> None:
        pooled = self._ingress.drain_pool()
        revocations.extend(self._ingress.drain_revocations())
        holder[0] = pooled
        self._now.pooled = len(pooled)
        for item in pooled:
            capsule = item.capsule
            self._facts.put(capsule.capsule_id, (item.peer_id, item.raw_digest))
            parents = tuple(dict.fromkeys((
                *capsule.parent_capsules,
                *((capsule.provenance_commitment.aggregation_decision,)
                  if capsule.provenance_commitment.aggregation_decision else ()),
            )))[:MAX_PARENTS_PER_NODE]
            self._c.lineage.add(LineageRecord(
                node_id=capsule.capsule_id, role=NodeRole.FOREIGN_CAPSULE, parents=parents,
                state=LinkState.LIVE, round_index=item.received_round, detail="",
            ))
            self._c.hypergraph.note_epoch(capsule.epoch_context.software_epoch, item.received_round)

    def _revoke(self, revocations: Sequence[tuple[KnowledgeCapsuleV1, str]]) -> None:
        for capsule, peer_id in revocations:
            outcome = self._plane.submit(capsule, sender_peer=peer_id, round_index=self._round)
            self._now.revocations[outcome.reason] += 1

    def _infer(self, pooled: Sequence[PooledCapsule]) -> tuple[EchoDecision, ...]:
        self._echo.offer([p for p in pooled if p.capsule.knowledge_type is KnowledgeType.ANTIBODY])
        inference = self._echo.infer(round_index=self._round)
        self._last = inference
        for decision in inference.decisions:
            self._now.decisions[decision.status.value] += 1
            if decision.status is EchoStatus.ELIGIBLE:
                self._record_decision(decision)
        return inference.decisions

    def _record_decision(self, decision: EchoDecision) -> None:
        """One ECHO_DECISION node per distinct decision id. The id is stable while the key's
        status and evidence grouping are unchanged (R7-2), so an unchanged ELIGIBLE key is not
        re-recorded every round (that flooded the descendant walk of its capsules and hid the
        STAGE6_LINKs a revocation must name)."""
        if self._c.lineage.has(decision.decision_id):
            self._n["decisions_unchanged"] += 1
            return
        parents = _supporting_capsules(decision)[:MAX_PARENTS_PER_NODE]
        self._c.lineage.add(LineageRecord(
            node_id=decision.decision_id, role=NodeRole.ECHO_DECISION, parents=parents,
            state=LinkState.LIVE, round_index=decision.round_index, detail=decision.antibody_key,
        ))

    def _bridge(self, decisions: Sequence[EchoDecision]) -> None:
        bridge = self._c.bridge
        if bridge is None:
            return
        for decision in decisions:
            key = decision.antibody_key
            if decision.status is not EchoStatus.ELIGIBLE or key in self._bridged.items:
                continue
            digests = {
                cid: facts[1]
                for cid in _supporting_capsules(decision)
                if (facts := self._facts.items.get(cid)) is not None
            }
            if not digests:  # the local evidence was forgotten: a refusal, not a crash
                self._n["bridge_unevidenced"] += 1
                continue
            # Marked before the handoff: a key whose handoff fails is counted once (DEGRADED
            # for this round) and never retried, so one bad decision cannot starve the
            # campaign and novelty steps of every later round.
            self._bridged.put(key, (decision.decision_id,))
            receipt = bridge.hand_over(decision, raw_digests=digests, sequence=self._sequence)
            self._sequence += max(1, len(receipt.stage6_capsule_ids))
            self._now.bridged += len(receipt.stage6_capsule_ids)
            self._now.buckets.update(receipt.stage6_buckets)

    def _fragments(self, pooled: Sequence[PooledCapsule]) -> None:
        for item in pooled:
            capsule = item.capsule
            kind = capsule.knowledge_type
            if kind not in (KnowledgeType.CAMPAIGN_FRAGMENT, KnowledgeType.NEGATIVE_EVIDENCE):
                continue
            window = capsule.time_window or (capsule.created_round, capsule.created_round)
            stage = _fragment_stage(capsule.causal_motif)
            if kind is KnowledgeType.NEGATIVE_EVIDENCE:
                self._negative_claim(item, stage, window)
                continue
            self._c.hypergraph.add_fragment(Fragment(
                capsule_id=capsule.capsule_id, cluster_id=item.cluster_id,
                role=capsule.source_context_sketch.role, stage=stage, window=window,
                software_epoch=capsule.epoch_context.software_epoch,
                visibility=capsule.epoch_context.visibility,
                rarity=self._c.novelty.rarity_of(
                    capsule.compact_feature_signature, round_index=self._round
                ),
            ))

    def _negative_claim(
        self, item: PooledCapsule, stage: ChainStage, window: tuple[int, int]
    ) -> None:
        claim = item.capsule.observability
        if claim is None:
            self._n["negative_without_observability"] += 1
            return
        if len(self._negative) == self._negative.maxlen:
            self._n["negative_claims_evicted"] += 1
        self._negative.append(NegativeClaim(
            capsule_id=item.capsule.capsule_id, cluster_id=item.cluster_id, stage=stage,
            window=window, weight=negative_evidence_weight(claim, host_relevance=item.relevance),
        ))

    def _campaign(self) -> None:
        worlds = self._reconstructor.reconstruct(
            round_index=self._round, negative=tuple(self._negative)
        )
        for world in worlds:
            self._now.worlds[world.status.value] += 1
        preserved = frozenset(w.edge_id for w in worlds if w.status is WorldStatus.SUPPORTED)
        self._c.hypergraph.expire(round_index=self._round, preserved=preserved)

    def _novelty(self, pooled: Sequence[PooledCapsule]) -> None:
        for item in pooled:
            if item.capsule.knowledge_type is KnowledgeType.NOVELTY:
                self._c.novelty.observe(item)
        verdicts = self._c.novelty.evaluate(round_index=self._round)
        self._now.novel = sum(v.status is NoveltyStatus.COLLECTIVELY_NOVEL for v in verdicts)

    def _refresh_suspicion(self) -> None:
        self._suspected = frozenset(sybil_report(self._c.graph).suspected_clusters)

    def _report(self, pooled: int) -> RoundReport:
        now = self._now
        return RoundReport(
            round_index=self._round, state=self.state, received=now.received, pooled=pooled,
            refused_by_stage=_sorted(now.refused), decisions=_sorted(now.decisions),
            bridged=now.bridged, stage6_buckets=_sorted(now.buckets),
            revocations=_sorted(now.revocations), worlds=_sorted(now.worlds), novel=now.novel,
            failures=now.failures, budget=self._c.governor.budget(),
        )

    def _advance(self) -> None:
        self._round += 1
        self._now = _Round()
        self._degraded = False
        self._n["rounds"] += 1
        try:
            self._c.governor.begin_round(self._round)
        except Exception:
            self._fail("governor")

    # --- outbound ----------------------------------------------------------------

    def publish(self, capsules: Sequence[KnowledgeCapsuleV1]) -> tuple[bytes, ...]:
        """Sign and emit this host's capsules within the round's outbound budget.

        Nothing leaves while the fabric is not ACTIVE. A capsule with any residual
        identifier is refused (defence in depth over the compiler's own screen). The first
        budget refusal stops the batch; the rest are counted as truncated, never queued.
        """
        if self.state is not FabricState.ACTIVE:
            self._n[f"publish_dropped:{self.state.value}"] += len(capsules)
            return ()
        sent: list[bytes] = []
        for index, capsule in enumerate(capsules):
            if not isinstance(capsule, KnowledgeCapsuleV1):
                raise ContractError("publish takes KnowledgeCapsuleV1 values")
            if not self._sovereignty_fits(capsule):
                self._n["publish_sovereignty_full"] += 1  # never publish what we cannot defend
                continue
            signed = self._c.keyring.sign(capsule, key_id=capsule.key_id)
            if residual_identifier_hits(signed.to_dict()):
                self._n["publish_privacy_refused"] += 1
                continue
            data = signed.canonical_bytes()
            if self._c.governor.admit_outbound(len(data), round_index=self._round) is not None:
                self._n["publish_truncated"] += len(capsules) - index
                break
            self._record_local(signed)
            sent.append(data)
        return tuple(sent)

    def _sovereignty_fits(self, capsule: KnowledgeCapsuleV1) -> bool:
        if capsule.knowledge_type is not KnowledgeType.ANTIBODY:
            return True
        key = capsule.compact_feature_signature
        return (
            key in self._local.local_keys
            or key in self._published_keys
            or len(self._published_keys) < MAX_PUBLISHED_IDS
        )

    def _record_local(self, capsule: KnowledgeCapsuleV1) -> None:
        """The published capsule id (revocation target) AND its antibody key (the ECHO and
        ingress CONTEST key space) join the sovereignty view (S7-R4)."""
        self._published.put(capsule.capsule_id, ())
        if capsule.knowledge_type is KnowledgeType.ANTIBODY:
            self._published_keys[capsule.compact_feature_signature] = None
        self._local_view = (
            frozenset(self._local.local_keys) | frozenset(self._published.items)
            | frozenset(self._published_keys)
        )
        self._c.lineage.add(LineageRecord(
            node_id=capsule.capsule_id, role=NodeRole.LOCAL_CAPSULE, parents=(),
            state=LinkState.LIVE, round_index=self._round, detail="",
        ))

    def partition(self) -> None:
        self._c.governor.partition()

    def heal(self) -> None:
        self._c.governor.heal(round_index=self._round)

    # --- read-only views ---------------------------------------------------------

    @property
    def ingress(self) -> HivelockIngress:
        return self._ingress

    @property
    def echo(self) -> EchoEngine:
        return self._echo

    @property
    def revocations(self) -> RevocationPlane:
        return self._plane

    @property
    def reconstructor(self) -> PartialWorldReconstructor:
        return self._reconstructor

    def last_inference(self) -> EchoInference | None:
        """ECHO's most recent inference (None before the first ECHO step ran)."""
        return self._last

    def bridged_keys(self) -> tuple[str, ...]:
        return tuple(self._bridged.items)

    def raw_digest_of(self, capsule_id: str) -> str | None:
        facts = self._facts.items.get(capsule_id)
        return facts[1] if facts else None

    def stats(self) -> Mapping[str, int]:
        counts = Counter(self._n)
        counts["facts_evicted"] = self._facts.evictions
        counts["bridged_keys_evicted"] = self._bridged.evictions
        counts["published_ids_evicted"] = self._published.evictions
        return MappingProxyType(dict(counts))

    def memory_bytes(self) -> Mapping[str, int]:
        c = self._c
        stores = {
            "ingress": self._ingress.memory_bytes(), "keyring": c.keyring.memory_bytes(),
            "replay": c.replay.memory_bytes(), "peers": c.peers.memory_bytes(),
            "governor": c.governor.memory_bytes(), "graph": c.graph.memory_bytes(),
            "trust": c.trust.memory_bytes(), "echo": self._echo.memory_bytes(),
            "lineage": c.lineage.memory_bytes(), "revocations": self._plane.memory_bytes(),
            "hypergraph": c.hypergraph.memory_bytes(), "novelty": c.novelty.memory_bytes(),
            "reconstructor": self._reconstructor.memory_bytes(),
            "bridge": c.bridge.memory_bytes() if c.bridge is not None else 0,
            "fabric": self._own_bytes(),
        }
        return MappingProxyType(stores)

    def _own_bytes(self) -> int:
        negative = sum(sys.getsizeof(n) + 160 for n in self._negative)
        return (
            self._facts.memory_bytes() + self._cluster_peer.memory_bytes()
            + self._bridged.memory_bytes() + self._published.memory_bytes()
            + sys.getsizeof(self._published_keys)
            + sum(sys.getsizeof(k) + 32 for k in self._published_keys)
            + negative + sys.getsizeof(self._local_view) + sys.getsizeof(self._n)
        )
