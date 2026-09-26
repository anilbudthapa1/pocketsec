"""§4.20 — the SIMULATED fleet: honest peers, every adversary arm, and the lab Stage 6 receiver.

Stage 7's defences are only evidence if they have been attacked. This module builds the
attackers the lead requires — (a) Sybil identity inflation, (b) Byzantine poison, (c) slow
poisoning across rounds, (d) a colluding minority timing its contributions — plus the flood,
replay, false-revocation, lineage-tamper, authority-injection and unanimous-fleet arms, and
the honest peers they compete with. Everything is **simulated in-process**: there is no
network, no transport, no real Sybil population and no real fleet, and every fleet-level
property (real latency, partitions, identity cost, population sizes) is UNMEASURED for a
real deployment.

**Honest peers are corpus hosts.** Each forges antibodies from its own lab-labelled history
incidents with ``antibody.forge`` (lab ground truth stands in for a local resolution —
declared optimistic), compiles them with ``capsule.compiler``, signs them with a ``Keyring``
and sends SUPPORT. It CONTESTs (at most :data:`MAX_CONTESTS_PER_PEER_PER_ROUND` per round)
any key visible last round whose invariant fires on its own benign ring: the only
counter-evidence ECHO accepts (ADR-0063: a peer may say "that fires on my benign traffic",
never "that is safe"). Publication is staggered and refreshed at random, so honest peers are
*not* co-timed; a lock-step honest fleet would be merged by the birth/co-timing edge and the
false-Sybil rate would measure the simulator instead of the graph.

**What HMAC proves here (ADR-0064).** :func:`simulated_key_provisioning` hands out
pre-provisioned pairwise symmetric keys. A valid signature proves possession of the key
registered for a ``key_id``: key membership, never host identity. The Sybil arms assume the
adversary obtained a key for every identity it mints; that is the threat model.

**The lab Stage 6 receiver** (:func:`simulated_stage6_receiver`) is a real
``QuarantineGateway`` over a fresh ``ProvenanceLedger`` and ``KnowledgeLineageDAG``, bound to
``genesis_state``. It exists only in ``labs/`` (spec §2.3): on the endpoint the controller
binds the gateway, and Stage 7 runtime code never constructs one.

Bounded: the key registry, replay capture, revocation-target memory and per-round delivery
list have named caps; truncation is counted in :meth:`SimulatedFleet.truncations`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import random
from collections import Counter, deque
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from enum import StrEnum
from types import MappingProxyType

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage0.contracts.threat_prediction_v1 import FORBIDDEN_AUTHORITY_FIELDS
from pocketsec.stage1.epoch.model import SystemIdentity
from pocketsec.stage6.capsule.experience_capsule import EncodedStep
from pocketsec.stage6.capsule.quarantine import QuarantineGateway
from pocketsec.stage6.fossils.lineage import KnowledgeLineageDAG
from pocketsec.stage6.memory.semantic import genesis_state
from pocketsec.stage6.provenance.ledger import ProvenanceLedger
from pocketsec.stage7.antibody.forge import (
    BenignRing,
    KnowledgeAntibody,
    LocalIncident,
    forge_antibody,
    matches,
)
from pocketsec.stage7.capsule.compiler import ExportContext, compile_capsule
from pocketsec.stage7.capsule.knowledge_capsule import (
    FalsificationSummary,
    KnowledgeCapsuleV1,
    KnowledgeType,
    MotifRow,
    RevocationGround,
    RoleClass,
    Stance,
    ValidationSummary,
    derive_chain_stages,
    motif_fingerprint,
)
from pocketsec.stage7.identity.integrity import Keyring
from pocketsec.stage7.labs.fleet_corpus import AttackFamily, FleetCorpus, FleetEpisode
from pocketsec.stage7.privacy.distiller import contributor_pseudonym
from pocketsec.stage7.privacy.ledger import PrivacyLedger

__all__ = [
    "FLEET_SCOPE", "HONEST_ROOTS", "MAX_CONTESTS_PER_PEER_PER_ROUND", "MAX_DELIVERIES_PER_ROUND",
    "SIMULATED_FLEET_VERSION", "SLOW_POISON_WARMUP_ROUNDS", "SUITE_ROUNDS", "UNANIMOUS_PEERS",
    "AdversaryArm", "Delivery", "FleetGroundTruth", "FleetSpec", "HonestAntibody",
    "SimulatedFleet", "adversary_root_count", "authority_payloads", "default_receivers",
    "honest_antibodies", "simulated_key_provisioning", "simulated_stage6_receiver",
]

SIMULATED_FLEET_VERSION = "stage7-simulated-fleet-v0.1.0"

# --- parameters: every value chosen, not measured (spec §4.23) ----------------------------
HONEST_ROOTS: int = 16
SUITE_ROUNDS: int = 12
SLOW_POISON_WARMUP_ROUNDS: int = 6
UNANIMOUS_PEERS: int = 64  # G7.1(c): independent-root peers all agreeing against one host
MAX_CONTESTS_PER_PEER_PER_ROUND: int = 2
MAX_DELIVERIES_PER_ROUND: int = 200_000
HONEST_BIRTH_SPREAD: int = 3  # honest peers first publish in rounds 0..2
HONEST_REFRESH_P: float = 0.1  # then re-publish with this probability per round
SEQ_STRIDE: int = 64  # honest sequence = round * SEQ_STRIDE + slot: deterministic per round
MAX_HONEST_CACHE: int = 20_000  # signed honest capsules reused across runs of one seed
FLOOD_COPIES: int = 12  # copies of one capsule per flood identity per round (> per-peer cap)
REPLAY_PER_ROUND: int = 32
MAX_REPLAY_CAPTURE: int = 512
MAX_KNOWN_KEYS: int = 4096
MAX_RECENT_CAPSULE_IDS: int = 256
FLEET_SCOPE: str = "simulated-fleet"


class AdversaryArm(StrEnum):
    NONE = "NONE"
    SYBIL_DECLARED_ROOT = "SYBIL_DECLARED_ROOT"  # (a) S identities, one declared root
    SYBIL_FORGED_ROOTS = "SYBIL_FORGED_ROOTS"  # (a) fresh roots, one burst, identical summaries
    SYBIL_ADAPTIVE = "SYBIL_ADAPTIVE"  # (a) forged roots, staggered, jittered, honest relays
    BYZANTINE_POISON = "BYZANTINE_POISON"  # (b) poison matching receiver-role benign
    BYZANTINE_LATENT_POISON = "BYZANTINE_LATENT_POISON"  # (b) benign absent from the ring
    BYZANTINE_SUPPRESS = "BYZANTINE_SUPPRESS"  # (b) contests + third-party revocations
    SLOW_POISON = "SLOW_POISON"  # (c) relay true keys for the warm-up, then latent poison
    COLLUSION_TIMING = "COLLUSION_TIMING"  # (d) one-round poison burst + fabricated fragments
    FLOOD = "FLOOD"
    REPLAY = "REPLAY"
    FALSE_REVOCATION = "FALSE_REVOCATION"
    LINEAGE_TAMPER = "LINEAGE_TAMPER"
    AUTHORITY_INJECTION = "AUTHORITY_INJECTION"
    UNANIMOUS_FLEET = "UNANIMOUS_FLEET"


_SYBIL_ARMS = frozenset({
    AdversaryArm.SYBIL_DECLARED_ROOT, AdversaryArm.SYBIL_FORGED_ROOTS,
    AdversaryArm.SYBIL_ADAPTIVE,
})
_LATENT_ARMS = _SYBIL_ARMS | {
    AdversaryArm.BYZANTINE_LATENT_POISON, AdversaryArm.SLOW_POISON,
    AdversaryArm.COLLUSION_TIMING, AdversaryArm.FLOOD,
}
_PROTOCOL_ARMS = frozenset({
    AdversaryArm.FLOOD, AdversaryArm.REPLAY, AdversaryArm.FALSE_REVOCATION,
    AdversaryArm.LINEAGE_TAMPER, AdversaryArm.AUTHORITY_INJECTION,
})


@dataclass(frozen=True, slots=True)
class FleetSpec:
    arm: AdversaryArm
    honest_roots: int = HONEST_ROOTS
    adversary_share: float = 0.0  # share of independent (true) roots, in [0, 1)
    sybils_per_root: int = 1
    rounds: int = SUITE_ROUNDS
    seed: int = 0
    receivers: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.arm, AdversaryArm):
            raise ContractError(f"arm must be an AdversaryArm, got {self.arm!r}")
        for name in ("honest_roots", "sybils_per_root", "rounds", "seed"):
            value = getattr(self, name)
            low = 0 if name == "seed" else 1
            if isinstance(value, bool) or not isinstance(value, int) or value < low:
                raise ContractError(f"{name} must be an int >= {low}, got {value!r}")
        share = self.adversary_share
        if isinstance(share, bool) or not isinstance(share, (int, float)) or not 0 <= share < 1:
            raise ContractError(f"adversary_share must be in [0, 1), got {share!r}")


@dataclass(frozen=True, slots=True)
class Delivery:
    sender: str  # the simulated link: the sending identity's peer id
    receiver: str  # a corpus host id
    data: bytes
    adversarial: bool
    poison_key: str | None  # the poison antibody key this delivery supports, if any
    round_index: int


@dataclass(frozen=True, slots=True)
class FleetGroundTruth:
    poison_keys: frozenset[str]
    true_keys_by_family: Mapping[AttackFamily, frozenset[str]]
    adversary_peers: frozenset[str]
    true_root_of: Mapping[str, str]
    honest_roots: int
    adversary_roots: int


@dataclass(frozen=True, slots=True)
class HonestAntibody:
    """One antibody a corpus host forged from one of its own history incidents."""

    host_id: str
    family: AttackFamily
    antibody: KnowledgeAntibody
    incident: LocalIncident


@dataclass(slots=True)
class _Identity:
    """A simulated identity: mutable lab bookkeeping, never exported."""

    peer_id: str
    key_id: str
    secret: bytes
    declared_root: str
    true_root: str
    host_id: str | None
    adversarial: bool
    birth_round: int
    ledger: PrivacyLedger
    contexts: dict[RoleClass, ExportContext] = field(default_factory=dict)
    sequence: int = 0


def _hex(*parts: object, width: int) -> str:
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:width]


def _root(name: str) -> str:
    return "root-" + _hex("root", name, width=16)


def _fake_digest(*parts: object) -> str:
    return "sha256:" + _hex("simulated-evidence", *parts, width=64)


def simulated_key_provisioning(peers: Sequence[str], receivers: Sequence[str], *,
                               seed: int) -> Mapping[tuple[str, str], bytes]:
    """Pre-provisioned PAIRWISE keys, one per (peer, receiver). SIMULATED.

    Stdlib has no key agreement, so keys derive from a lab seed. A key proves that its holder
    is whoever was provisioned for that pair: key possession, not identity (ADR-0064).
    """
    master = hashlib.sha256(f"simulated-key-provisioning:{seed}".encode()).digest()
    return MappingProxyType({
        (peer, receiver): hmac.new(master, f"{peer}|{receiver}".encode(), hashlib.sha256).digest()
        for peer in peers for receiver in receivers
    })


def simulated_stage6_receiver(
    identity: SystemIdentity,
) -> tuple[QuarantineGateway, KnowledgeLineageDAG]:
    """A real Stage 6 gateway bound to ``genesis_state`` — LAB ONLY (spec §2.3).

    It admits whatever Stage 6's own rules admit; nothing here reinterprets a verdict.
    """
    lineage = KnowledgeLineageDAG()
    gateway = QuarantineGateway(ledger=ProvenanceLedger(), lineage=lineage)
    state = genesis_state(identity=identity)
    gateway.bind_trusted_view(lambda: state)
    return gateway, lineage


def adversary_root_count(honest_roots: int, share: float) -> int:
    """Adversary roots making adversary / (adversary + honest) nearest to ``share``."""
    return 0 if share <= 0.0 else max(1, round(share * honest_roots / (1.0 - share)))


def default_receivers(corpus: FleetCorpus) -> tuple[str, ...]:
    """The first late-benign ADMIN host (the latent-poison target) plus one host per role."""
    eligible = set(corpus.receivers())
    chosen = [h.host_id for h in corpus.hosts if h.late_benign and h.host_id in eligible][:1]
    roles = (RoleClass.WEB, RoleClass.DEV, RoleClass.DESKTOP) if chosen else tuple(RoleClass)
    for role in roles:
        host = next((h.host_id for h in corpus.hosts
                     if h.role is role and h.host_id in eligible and h.host_id not in chosen), None)
        if host is not None:
            chosen.append(host)
    return tuple(chosen)


# --- honest forging: cached per corpus (deterministic, and the costliest step) -----------

_FORGE_CACHE: dict[tuple[int, str, int, int], tuple[HonestAntibody, ...]] = {}
_FORGE_CACHE_CAP: int = 4
#: (corpus, seed, honest_roots, host, key, round) -> (unsigned capsule, receiver -> signed bytes).
#: Honest SUPPORT traffic is a pure function of that key, so every run of one seed reuses it.
_HONEST_CACHE: dict[tuple[object, ...], tuple[KnowledgeCapsuleV1, dict[str, bytes]]] = {}


def _corpus_key(corpus: FleetCorpus) -> tuple[int, str, int, int]:
    return (corpus.seed, corpus.version, len(corpus.hosts), len(corpus.episodes))


def _history_ring(corpus: FleetCorpus, host_id: str) -> BenignRing:
    ring = BenignRing()
    for episode in corpus.for_host(host_id, history=True):
        if episode.label == 0:
            ring.add(episode.steps)
    return ring


def honest_antibodies(corpus: FleetCorpus) -> tuple[HonestAntibody, ...]:
    """Every host's forged antibodies: one per distinct key per host (its first incident)."""
    cache_key = _corpus_key(corpus)
    if cache_key in _FORGE_CACHE:
        return _FORGE_CACHE[cache_key]
    built: list[HonestAntibody] = []
    for host in corpus.hosts:
        ring = _history_ring(corpus, host.host_id)
        seen: set[str] = set()
        for episode in corpus.for_host(host.host_id, history=True):
            if episode.label != 1 or episode.family is None:
                continue
            incident = LocalIncident(f"{host.host_id}-e{episode.index:03d}", episode.steps,
                                     episode.evidence_digests[:8])
            antibody = forge_antibody(incident, benign=ring)
            if antibody is None or antibody.antibody_key in seen:
                continue  # INSUFFICIENT is a valid forge output: nothing to share
            seen.add(antibody.antibody_key)
            built.append(HonestAntibody(host.host_id, episode.family, antibody, incident))
    if len(_FORGE_CACHE) >= _FORGE_CACHE_CAP:
        _FORGE_CACHE.pop(next(iter(_FORGE_CACHE)))
    _FORGE_CACHE[cache_key] = tuple(built)
    return _FORGE_CACHE[cache_key]


# --- poison construction: copied rules of BENIGN behaviour ---------------------------------


def _row(step: EncodedStep) -> MotifRow:
    return MotifRow(step.relation, step.object_property_mask, 0, step.state_delta_mask)


def _candidates(steps: Sequence[EncodedStep]) -> list[tuple[MotifRow, ...]]:
    """Single steps and same-actor ordered pairs with full masks (Stage 6 motif grammar)."""
    rows: list[tuple[MotifRow, ...]] = [(_row(s),) for s in steps]
    rows += [(_row(a), _row(b)) for i, a in enumerate(steps) for b in steps[i + 1:]
             if a.actor_slot == b.actor_slot]
    return rows


def _benign(corpus: FleetCorpus, hosts: set[str], *, history: bool) -> list[FleetEpisode]:
    return [e for e in corpus.episodes
            if e.host_id in hosts and e.label == 0 and e.history is history]


def _role_poison(corpus: FleetCorpus, role: RoleClass) -> tuple[MotifRow, ...] | None:
    """The single-step benign rule firing on the most of a role's own history (visible)."""
    episodes = _benign(corpus, {h.host_id for h in corpus.hosts if h.role is role}, history=True)
    scored = [
        (sum(1 for e in episodes if matches(rows, e.steps)), motif_fingerprint(rows), rows)
        for episode in episodes[:8] for rows in _candidates(episode.steps) if len(rows) == 1
    ]
    return max(scored)[2] if scored else None


def _latent_poison(corpus: FleetCorpus) -> tuple[MotifRow, ...] | None:
    """A rule on a benign behaviour the first late-benign host has NOT seen in its history.

    Local validation replays the receiver's history ring, so this poison passes it at that
    host by construction and fires on its held-out benign traffic (the late service
    install). None when the corpus has no late-benign host or no latent rule exists.
    """
    late = [h.host_id for h in corpus.hosts if h.late_benign][:1]
    heldout = _benign(corpus, set(late), history=False)
    if not heldout:
        return None
    rare, ring = heldout[0], _benign(corpus, set(late), history=True)
    latent = [rows for rows in _candidates(rare.steps)
              if not any(matches(rows, e.steps) for e in ring)]
    return min(latent, key=lambda r: (len(r), motif_fingerprint(r))) if latent else None


def _local_fp_rule(corpus: FleetCorpus, host_id: str) -> tuple[MotifRow, ...] | None:
    """A rule that fires on this host's OWN history benign traffic (unanimous arm (ii))."""
    benign = _benign(corpus, {host_id}, history=True)
    return _candidates(benign[0].steps)[0] if benign else None


def _fragment_rows(corpus: FleetCorpus) -> tuple[tuple[MotifRow, ...], ...]:
    """Single-row invariants with distinct escalating chain stages (fabricated fragments)."""
    chosen: dict[str, tuple[MotifRow, ...]] = {}
    for episode in (e for e in corpus.episodes if e.label == 1):
        for step in episode.steps:
            if step.object_property_mask or step.state_delta_mask:
                rows = (_row(step),)
                stage = derive_chain_stages(rows)[0].value
                if stage != "OTHER":
                    chosen.setdefault(stage, rows)
        if len(chosen) >= 4:
            break
    return tuple(chosen[k] for k in sorted(chosen))


def authority_payloads(capsule: KnowledgeCapsuleV1, key_id: str,
                       signer: Keyring) -> tuple[bytes, ...]:
    """Wire bytes of ``capsule`` with ONE authority-named key injected per payload.

    Every ``FORBIDDEN_AUTHORITY_FIELDS`` word at the top level and nested in the provenance
    record. Serialised by hand because no constructor will build them: that refusal, at
    SCHEMA, is what the arm measures.
    """
    base = signer.sign(capsule, key_id=key_id).to_dict()
    payloads = []
    for word in sorted(FORBIDDEN_AUTHORITY_FIELDS):
        nested = {**base["provenance_commitment"], word: "true"}
        for payload in ({**base, word: "true"}, {**base, "provenance_commitment": nested}):
            text = json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
            payloads.append(text.encode())
    return tuple(payloads)


_PERFECT_VALIDATION = ValidationSummary(episodes_replayed=64, true_matches=64, false_matches=0)
_PERFECT_FALSIFICATION = FalsificationSummary(mutations_tried=8, mutations_survived=8,
                                              counter_hypotheses=())
_Handler = Callable[["SimulatedFleet", list[Delivery], int, frozenset[str]], None]


class SimulatedFleet:
    """One round of signed traffic at a time, for one fixed arm. SIMULATED throughout."""

    def __init__(self, corpus: FleetCorpus, spec: FleetSpec) -> None:
        if not isinstance(corpus, FleetCorpus) or not isinstance(spec, FleetSpec):
            raise ContractError("SimulatedFleet needs a FleetCorpus and a FleetSpec")
        self._corpus, self._spec = corpus, spec
        self._receivers = spec.receivers or default_receivers(corpus)
        hosts = {h.host_id for h in corpus.hosts}
        if not self._receivers or any(r not in hosts for r in self._receivers):
            raise ContractError(f"receivers must be corpus hosts, got {self._receivers!r}")
        self._truncated: Counter[str] = Counter()
        self._keys: dict[str, tuple[MotifRow, ...]] = {}
        self._honest_ab = honest_antibodies(corpus)
        for item in self._honest_ab:
            self._remember(item.antibody.antibody_key, item.antibody.invariant)
        self._honest = self._build_honest()
        self._adversaries = self._build_adversaries()
        self._poison = self._build_poison()
        self._signers = self._build_signers()
        self._captured: deque[Delivery] = deque(maxlen=MAX_REPLAY_CAPTURE)
        self._recent_ids: deque[str] = deque(maxlen=MAX_RECENT_CAPSULE_IDS)
        self._rings: dict[str, BenignRing] = {}
        self._local_cache: dict[str, tuple[KnowledgeCapsuleV1, ...]] = {}
        self._fragments = _fragment_rows(corpus)

    # --- identities -----------------------------------------------------------------

    def _identity(self, name: str, *, declared: str, true_root: str, host_id: str | None,
                  birth: int) -> _Identity:
        secret = hashlib.sha256(f"simulated-secret:{self._spec.seed}:{name}".encode()).digest()
        adversarial = host_id is None
        ledger = PrivacyLedger(max_releases=1_000_000) if adversarial else PrivacyLedger()
        return _Identity(
            peer_id=contributor_pseudonym(secret, FLEET_SCOPE),
            key_id="key-" + _hex("key", self._spec.seed, name, width=16), secret=secret,
            declared_root=declared, true_root=true_root, host_id=host_id,
            adversarial=adversarial, birth_round=birth, ledger=ledger,
        )

    def _build_honest(self) -> dict[str, _Identity]:
        rng = random.Random(f"honest-birth:{self._spec.seed}")
        honest = {}
        for index, host in enumerate(self._corpus.hosts):
            root = _root(f"honest-{index % self._spec.honest_roots}")  # honest roots are truthful
            honest[host.host_id] = self._identity(
                f"honest-{host.host_id}", declared=root, true_root=root, host_id=host.host_id,
                birth=rng.randrange(HONEST_BIRTH_SPREAD),
            )
        return honest

    def _layout(self) -> tuple[int, int]:
        arm = self._spec.arm
        if arm is AdversaryArm.NONE:
            return 0, 0
        if arm is AdversaryArm.UNANIMOUS_FLEET:
            return UNANIMOUS_PEERS, 1
        if arm in _SYBIL_ARMS:
            return 1, self._spec.sybils_per_root
        roots = adversary_root_count(self._spec.honest_roots, self._spec.adversary_share)
        if roots == 0 and arm in _PROTOCOL_ARMS:
            roots = 1  # a protocol attack needs an attacker even at share 0
        return roots, self._spec.sybils_per_root

    def _build_adversaries(self) -> dict[str, _Identity]:
        arm, (roots, per_root) = self._spec.arm, self._layout()
        forged = arm in (AdversaryArm.SYBIL_FORGED_ROOTS, AdversaryArm.SYBIL_ADAPTIVE)
        adversaries = {}
        for r in range(roots):
            true_root = _root(f"adversary-{self._spec.seed}-{r}")
            for s in range(per_root):
                declared = _root(f"forged-{self._spec.seed}-{r}-{s}") if forged else true_root
                birth = 0
                if arm is AdversaryArm.SYBIL_ADAPTIVE:  # staggered births defeat the burst edge
                    birth = (s * self._spec.rounds) // per_root
                ident = self._identity(f"adv-{arm.value}-{r}-{s}", declared=declared,
                                       true_root=true_root, host_id=None, birth=birth)
                adversaries[ident.peer_id] = ident
        return adversaries

    def _build_poison(self) -> dict[str, tuple[MotifRow, ...]]:
        """receiver -> the poison invariant this arm pushes at it ({} for poison-free arms)."""
        arm, poison = self._spec.arm, {}
        latent = _latent_poison(self._corpus) if arm in _LATENT_ARMS else None
        for receiver in self._receivers:
            if arm is AdversaryArm.BYZANTINE_POISON:
                rows = _role_poison(self._corpus, self._corpus.host(receiver).role)
            elif arm is AdversaryArm.UNANIMOUS_FLEET:
                rows = _local_fp_rule(self._corpus, receiver)
            else:
                rows = latent
            if rows is not None:
                poison[receiver] = rows
                self._remember(motif_fingerprint(rows), rows)
        return poison

    def _identities(self) -> dict[str, _Identity]:
        return {**{i.peer_id: i for i in self._honest.values()}, **self._adversaries}

    def _build_signers(self) -> dict[str, Keyring]:
        identities = self._identities()
        keys = simulated_key_provisioning(tuple(identities), self._receivers, seed=self._spec.seed)
        self._provisioned = keys
        signers = {}
        for receiver in self._receivers:
            ring = Keyring(capacity=len(identities) + 1)
            for peer_id, ident in identities.items():
                ring.register(ident.key_id, keys[(peer_id, receiver)], owner=peer_id, round_index=0)
            signers[receiver] = ring
        return signers

    # --- the lab surface --------------------------------------------------------------

    @property
    def receivers(self) -> tuple[str, ...]:
        return self._receivers

    @property
    def spec(self) -> FleetSpec:
        return self._spec

    @property
    def corpus(self) -> FleetCorpus:
        return self._corpus

    def key_directory(self, receiver: str) -> tuple[tuple[str, bytes, str], ...]:
        """(key_id, key, owner) of every identity, as provisioned for ``receiver``."""
        return tuple((i.key_id, self._provisioned[(p, receiver)], p)
                     for p, i in sorted(self._identities().items()))

    def peer_of_host(self, host_id: str) -> str:
        return self._honest[host_id].peer_id

    def invariant_of(self, key: str) -> tuple[MotifRow, ...] | None:
        return self._keys.get(key)

    def local_antibodies(self, host_id: str) -> tuple[HonestAntibody, ...]:
        return tuple(a for a in self._honest_ab if a.host_id == host_id)

    def local_capsules(self, host_id: str) -> tuple[KnowledgeCapsuleV1, ...]:
        """UNSIGNED capsules of this host's own antibodies, for its own fabric to publish."""
        if host_id not in self._local_cache:
            # A clone: local knowledge is not a fleet release, so it must not move the
            # identity's sequence or charge its fleet ledger (rounds only move forward).
            ident = replace(self._honest[host_id], ledger=PrivacyLedger(), contexts={})
            self._local_cache[host_id] = tuple(  # slot SEQ_STRIDE - 1 of round 0: never sent
                self._compile_honest(ident, item, round_index=0, sequence=SEQ_STRIDE - 1)
                for item in self.local_antibodies(host_id)
            )
        return self._local_cache[host_id]

    def truncations(self) -> Mapping[str, int]:
        return MappingProxyType(dict(self._truncated))

    def ground_truth(self) -> FleetGroundTruth:
        by_family: dict[AttackFamily, set[str]] = {}
        for item in self._honest_ab:
            by_family.setdefault(item.family, set()).add(item.antibody.antibody_key)
        return FleetGroundTruth(
            poison_keys=frozenset(motif_fingerprint(rows) for rows in self._poison.values()),
            true_keys_by_family=MappingProxyType({f: frozenset(k) for f, k in by_family.items()}),
            adversary_peers=frozenset(self._adversaries),
            true_root_of=MappingProxyType({p: i.true_root for p, i in self._identities().items()}),
            honest_roots=len({i.true_root for i in self._honest.values()}),
            adversary_roots=len({i.true_root for i in self._adversaries.values()}),
        )

    # --- compile / sign / send ------------------------------------------------------------

    def _remember(self, key: str, rows: tuple[MotifRow, ...]) -> None:
        if key not in self._keys:
            if len(self._keys) >= MAX_KNOWN_KEYS:
                self._truncated["known_keys"] += 1
            else:
                self._keys[key] = rows

    def _context(self, ident: _Identity, role: RoleClass) -> ExportContext:
        if role not in ident.contexts:
            # An adversary mimics a host of the role it targets: role and software image are
            # disclosed by design (ADR-0065), so claiming them costs it nothing.
            host = (self._corpus.host(ident.host_id) if ident.host_id is not None
                    else next(h for h in self._corpus.hosts if h.role is role))
            counts = Counter(s.relation_family for e in self._corpus.for_host(host.host_id,
                                                                                history=True)
                             for s in e.steps)
            identity = host.identity if ident.host_id is not None else SystemIdentity(
                kernel_id=host.identity.kernel_id, package_digest=host.identity.package_digest,
                service_digest=f"svc-sim-{ident.key_id[4:]}",
            )
            ident.contexts[role] = ExportContext(
                host_secret=ident.secret, identity=identity, role=role,
                provenance_root=ident.declared_root, key_id=ident.key_id, visibility_share=1.0,
                family_counts=dict(counts), fleet_scope=FLEET_SCOPE,
            )
        return ident.contexts[role]

    def _compile(self, ident: _Identity, role: RoleClass, *, kind: KnowledgeType,
                 rows: tuple[MotifRow, ...], evidence: Sequence[str], round_index: int,
                 validation: ValidationSummary = _PERFECT_VALIDATION,
                 falsification: FalsificationSummary = _PERFECT_FALSIFICATION,
                 sequence: int | None = None, **extra: object) -> KnowledgeCapsuleV1:
        ident.sequence = ident.sequence + 1 if sequence is None else sequence
        return compile_capsule(
            knowledge_type=kind, invariant=rows, evidence_digests=tuple(evidence)[:8],
            validation=validation, falsification=falsification,
            context=self._context(ident, role), ledger=ident.ledger,
            created_round=round_index, sequence=ident.sequence, **extra,  # type: ignore[arg-type]
        )

    def _compile_honest(self, ident: _Identity, item: HonestAntibody, *, round_index: int,
                        sequence: int) -> KnowledgeCapsuleV1:
        return self._compile(
            ident, self._corpus.host(item.host_id).role, kind=KnowledgeType.ANTIBODY,
            rows=item.antibody.invariant, evidence=item.incident.evidence_digests,
            round_index=round_index, validation=item.antibody.validation,
            falsification=item.antibody.falsification, sequence=sequence,
        )

    def _honest_support(self, out: list[Delivery], ident: _Identity, item: HonestAntibody,
                        round_index: int, slot: int) -> None:
        """Send one honest SUPPORT, from the cross-run cache when this exact release exists.

        A cache hit is the same simulated release (same bytes); the ledger is still charged.
        """
        key = (_corpus_key(self._corpus), self._spec.seed, self._spec.honest_roots,
               ident.host_id, item.antibody.antibody_key, round_index)
        sequence = round_index * SEQ_STRIDE + slot + 1
        entry = _HONEST_CACHE.get(key)
        if entry is None:
            if len(_HONEST_CACHE) >= MAX_HONEST_CACHE:
                _HONEST_CACHE.pop(next(iter(_HONEST_CACHE)))
                self._truncated["honest_cache"] += 1
            capsule = self._compile_honest(ident, item, round_index=round_index, sequence=sequence)
            entry = _HONEST_CACHE.setdefault(key, (capsule, {}))
        else:
            ident.ledger.charge(KnowledgeType.ANTIBODY.value, recipient_scope=FLEET_SCOPE,
                                round_index=round_index)
            ident.sequence = sequence
        capsule, signed = entry
        self._recent_ids.append(capsule.capsule_id)
        for receiver in self._receivers:
            if receiver != ident.host_id:
                if receiver not in signed:
                    signed[receiver] = self._signers[receiver].sign(
                        capsule, key_id=ident.key_id).canonical_bytes()
                out.append(Delivery(ident.peer_id, receiver, signed[receiver], False, None,
                                    round_index))

    def _send(self, out: list[Delivery], ident: _Identity, capsule: KnowledgeCapsuleV1, *,
              round_index: int, targets: Sequence[str], poison_key: str | None = None) -> None:
        for receiver in targets:
            if receiver != ident.host_id:
                data = self._signers[receiver].sign(capsule, key_id=ident.key_id).canonical_bytes()
                out.append(Delivery(ident.peer_id, receiver, data, ident.adversarial, poison_key,
                                    round_index))

    def _by_role(self) -> dict[RoleClass, tuple[str, ...]]:
        groups: dict[RoleClass, list[str]] = {}
        for receiver in self._receivers:
            groups.setdefault(self._corpus.host(receiver).role, []).append(receiver)
        return {role: tuple(names) for role, names in groups.items()}

    def _each_adversary(self, round_index: int) -> list[tuple[_Identity, RoleClass,
                                                              tuple[str, ...]]]:
        """(live adversary, targeted role, receivers of that role), in a deterministic order."""
        live = [a for _, a in sorted(self._adversaries.items()) if a.birth_round <= round_index]
        return [(a, role, targets) for a in live for role, targets in self._by_role().items()]

    # --- one round ----------------------------------------------------------------------

    def round_traffic(self, round_index: int, *,
                      visible_keys: Mapping[str, frozenset[str]]) -> tuple[Delivery, ...]:
        """Every delivery of one simulated round: honest traffic first, then the arm's.

        ``visible_keys`` maps a receiver to the antibody keys pooled there last round: the
        gossip honest peers react to with CONTESTs.
        """
        if isinstance(round_index, bool) or not isinstance(round_index, int) or round_index < 0:
            raise ContractError(f"round_index must be a non-negative int, got {round_index!r}")
        visible = frozenset(k for keys in visible_keys.values() for k in keys)
        out: list[Delivery] = []
        if self._spec.arm is not AdversaryArm.UNANIMOUS_FLEET:  # the unanimous fleet IS the fleet
            self._honest_round(out, round_index, visible)
        _ARM_HANDLERS[self._spec.arm](self, out, round_index, visible)
        if len(out) > MAX_DELIVERIES_PER_ROUND:
            self._truncated["deliveries"] += len(out) - MAX_DELIVERIES_PER_ROUND
            out = out[:MAX_DELIVERIES_PER_ROUND]
        self._captured.extend(d for d in out if not d.adversarial)
        return tuple(out)

    def _honest_round(self, out: list[Delivery], round_index: int, visible: frozenset[str]) -> None:
        rng = random.Random(f"honest-refresh:{self._spec.seed}:{round_index}")
        for host in self._corpus.hosts:
            ident, draw = self._honest[host.host_id], rng.random()
            if round_index < ident.birth_round:
                continue
            own = self.local_antibodies(host.host_id)
            ident.sequence = max(ident.sequence, round_index * SEQ_STRIDE)
            if round_index == ident.birth_round or draw < HONEST_REFRESH_P:
                for slot, item in enumerate(own):
                    self._honest_support(out, ident, item, round_index, slot)
            self._honest_contests(out, ident, round_index, visible, own)

    def _honest_contests(self, out: list[Delivery], ident: _Identity, round_index: int,
                         visible: frozenset[str], own: Sequence[HonestAntibody]) -> None:
        host_id = ident.host_id or ""
        if host_id not in self._rings:
            self._rings[host_id] = _history_ring(self._corpus, host_id)
        ring = self._rings[host_id].episodes()
        pending = [k for k in sorted(visible - {i.antibody.antibody_key for i in own})
                   if (rows := self._keys.get(k)) is not None
                   and any(matches(rows, steps) for steps in ring)]
        if len(pending) > MAX_CONTESTS_PER_PEER_PER_ROUND:
            self._truncated["contests"] += len(pending) - MAX_CONTESTS_PER_PEER_PER_ROUND
        evidence = [d for e in self._corpus.for_host(host_id, history=True) if e.label == 0
                    for d in e.evidence_digests][:8]
        for key in pending[:MAX_CONTESTS_PER_PEER_PER_ROUND]:
            capsule = self._compile(
                ident, self._corpus.host(host_id).role, kind=KnowledgeType.ANTIBODY,
                rows=self._keys[key], evidence=evidence, round_index=round_index,
                stance=Stance.CONTEST, validation=ValidationSummary(len(ring), 0, 1),
            )
            self._send(out, ident, capsule, round_index=round_index, targets=self._receivers)

    # --- adversary arms -----------------------------------------------------------------

    @staticmethod
    def _summaries(ident: _Identity,
                   jitter: str | None) -> tuple[ValidationSummary, FalsificationSummary]:
        """Self-reports. Independent adversary ROOTS each forge their own ("root"); adaptive
        Sybils vary per IDENTITY; declared/forged Sybils copy one (None, spec §4.20)."""
        if jitter is None:
            return _PERFECT_VALIDATION, _PERFECT_FALSIFICATION
        j = int(_hex("jitter", ident.true_root if jitter == "root" else ident.peer_id, width=4), 16)
        tried = 6 + j % 11
        return (ValidationSummary(24 + j % 40, 10 + j % 13, 0),
                FalsificationSummary(tried, tried - j % 2, ()))

    def _forge(self, ident: _Identity, role: RoleClass, round_index: int, tag: object, *,
               rows: tuple[MotifRow, ...] = (), kind: KnowledgeType = KnowledgeType.ANTIBODY,
               jitter: str | None = "root", **extra: object) -> KnowledgeCapsuleV1:
        """An adversary capsule: fabricated evidence, self-reports per ``jitter``."""
        validation, falsification = self._summaries(ident, jitter)
        return self._compile(ident, role, kind=kind, rows=rows, round_index=round_index,
                             evidence=[_fake_digest(ident.peer_id, round_index, tag)],
                             validation=validation, falsification=falsification,
                             **extra)  # type: ignore[arg-type]

    def _push_poison(self, out: list[Delivery], round_index: int, *, jitter: str | None = "root",
                     copies: int = 1) -> None:
        """Every live adversary SUPPORTs its targets' poison, compiled per targeted role."""
        for ident, role, targets in self._each_adversary(round_index):
            if (rows := self._poison.get(targets[0])) is not None:
                capsule = self._forge(ident, role, round_index, "poison", rows=rows, jitter=jitter)
                for _ in range(copies):
                    self._send(out, ident, capsule, round_index=round_index, targets=targets,
                               poison_key=motif_fingerprint(rows))

    def _relay_true(self, out: list[Delivery], round_index: int, *, share: float,
                    jitter: str = "root") -> None:
        """Adversaries SUPPORT honest antibodies (earning trust, or blending in). No poison."""
        rng = random.Random(f"relay:{self._spec.seed}:{round_index}")
        for ident, role, targets in self._each_adversary(round_index):
            for item in (i for i in self._honest_ab if rng.random() < share):
                capsule = self._forge(ident, role, round_index, item.antibody.antibody_key,
                                      rows=item.antibody.invariant, jitter=jitter)
                self._send(out, ident, capsule, round_index=round_index, targets=targets)

    def _arm_sybil(self, out: list[Delivery], round_index: int, visible: frozenset[str]) -> None:
        adaptive = self._spec.arm is AdversaryArm.SYBIL_ADAPTIVE
        self._push_poison(out, round_index, jitter="identity" if adaptive else None)
        if adaptive:
            self._relay_true(out, round_index, share=0.2, jitter="identity")

    def _arm_suppress(self, out: list[Delivery], round_index: int,
                      visible: frozenset[str]) -> None:
        """CONTEST true keys, and 'self-retract' honest capsules as a third party."""
        stride, recent = max(1, len(self._honest_ab) // 4), list(self._recent_ids)[-4:]
        for ident, role, targets in self._each_adversary(round_index):
            planned = [self._forge(ident, role, round_index, "contest", stance=Stance.CONTEST,
                                   rows=item.antibody.invariant)
                       for item in self._honest_ab[::stride]]
            planned += [self._forge(ident, role, round_index, t, kind=KnowledgeType.REVOCATION,
                                    revocation_target=t,
                                    revocation_ground=RevocationGround.SELF_RETRACTION)
                        for t in recent]
            for capsule in planned:
                self._send(out, ident, capsule, round_index=round_index, targets=targets)

    def _arm_slow(self, out: list[Delivery], round_index: int, visible: frozenset[str]) -> None:
        if round_index < SLOW_POISON_WARMUP_ROUNDS:
            self._relay_true(out, round_index, share=0.5)
        else:
            self._push_poison(out, round_index)

    def _arm_collusion(self, out: list[Delivery], round_index: int,
                       visible: frozenset[str]) -> None:
        if round_index != self._spec.rounds // 2:
            return  # one round only: race the contests
        self._push_poison(out, round_index)
        for ident, role, targets in self._each_adversary(round_index):
            for rows in self._fragments:
                capsule = self._forge(ident, role, round_index, rows, rows=rows,
                                      kind=KnowledgeType.CAMPAIGN_FRAGMENT,
                                      time_window=(round_index, round_index + 1))
                self._send(out, ident, capsule, round_index=round_index, targets=targets)

    def _arm_flood(self, out: list[Delivery], round_index: int, visible: frozenset[str]) -> None:
        self._push_poison(out, round_index, copies=FLOOD_COPIES)
        oversize, garbage = b"{" + b" " * 8192 + b"}", b"\x00not-json\xff"
        for ident in (a for a in self._adversaries.values() if a.birth_round <= round_index):
            for receiver in self._receivers:
                out.append(Delivery(ident.peer_id, receiver, oversize, True, None, round_index))
                out.append(Delivery(ident.peer_id, receiver, garbage, True, None, round_index))

    def _arm_replay(self, out: list[Delivery], round_index: int, visible: frozenset[str]) -> None:
        captured = [d for d in self._captured if d.round_index < round_index][-REPLAY_PER_ROUND:]
        for n, old in enumerate(captured):
            link = f"replay-link-{n % 4}"
            out.append(Delivery(link, old.receiver, old.data, True, None, round_index))
            if n % 4 == 0:  # a tampered copy: a forged signature on the same body
                payload = {**json.loads(old.data),
                           "signature": _hex("forged-signature", n, round_index, width=64)}
                forged = json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
                out.append(Delivery(link, old.receiver, forged.encode(), True, None, round_index))

    def _arm_false_revocation(self, out: list[Delivery], round_index: int,
                              visible: frozenset[str]) -> None:
        """Third-party, forged-LOCAL_EVIDENCE, unknown-target and local-origin revocations."""
        recent, own = list(self._recent_ids)[-3:], RevocationGround.SELF_RETRACTION
        for ident, role, targets in self._each_adversary(round_index):
            for receiver in targets:
                unknown = "kc-" + _hex("unknown", ident.peer_id, round_index, width=24)
                plans = [(t, own) for t in recent] + [(unknown, own)]
                plans += [(t, RevocationGround.LOCAL_EVIDENCE) for t in recent[:1]]
                plans += [(c.capsule_id, own) for c in self.local_capsules(receiver)[:1]]
                for target, ground in plans:
                    capsule = self._forge(ident, role, round_index, target,
                                          kind=KnowledgeType.REVOCATION,
                                          revocation_target=target, revocation_ground=ground)
                    self._send(out, ident, capsule, round_index=round_index, targets=(receiver,))

    def _arm_tamper_or_inject(self, out: list[Delivery], round_index: int,
                              visible: frozenset[str]) -> None:
        """LINEAGE_TAMPER: ghost parents and decision; AUTHORITY_INJECTION: authority keys."""
        rows = self._honest_ab[0].antibody.invariant if self._honest_ab else ()
        tamper = self._spec.arm is AdversaryArm.LINEAGE_TAMPER
        for ident, role, targets in self._each_adversary(round_index) if rows else ():
            ghost = {"parents": ("kc-" + _hex("ghost", ident.peer_id, round_index, width=24),),
                     "aggregation_decision": "agg-" + _hex("ghost", round_index, width=32)}
            capsule = self._forge(ident, role, round_index, "x", rows=rows,
                                  **(ghost if tamper else {}))  # type: ignore[arg-type]
            if tamper:
                self._send(out, ident, capsule, round_index=round_index, targets=targets)
                continue
            for receiver in targets:
                for data in authority_payloads(capsule, ident.key_id, self._signers[receiver]):
                    out.append(Delivery(ident.peer_id, receiver, data, True, None, round_index))

    def _arm_unanimous(self, out: list[Delivery], round_index: int,
                       visible: frozenset[str]) -> None:
        """Every peer, against each receiver: (i) revoke its local-origin capsule, (ii) SUPPORT
        a rule that FPs on its own benign ring, (iii) CONTEST its local antibody, (iv) send an
        authority-keyed payload. The whole fleet agrees; none of it is local evidence."""
        for ident, role, targets in self._each_adversary(round_index):
            for receiver in targets:
                plans: list[tuple[KnowledgeCapsuleV1, str | None]] = [
                    (self._forge(ident, role, round_index, receiver, jitter=None,
                                 kind=KnowledgeType.REVOCATION, revocation_target=c.capsule_id,
                                 revocation_ground=RevocationGround.SELF_RETRACTION), None)
                    for c in self.local_capsules(receiver)[:1]]
                if (rows := self._poison.get(receiver)) is not None:
                    plans.append((self._forge(ident, role, round_index, receiver, rows=rows,
                                              jitter=None), motif_fingerprint(rows)))
                plans += [(self._forge(ident, role, round_index, receiver, jitter=None,
                                       rows=item.antibody.invariant, stance=Stance.CONTEST), None)
                          for item in self.local_antibodies(receiver)[:1]]
                for capsule, poison in plans:
                    self._send(out, ident, capsule, round_index=round_index,
                               targets=(receiver,), poison_key=poison)
                if plans:
                    data = authority_payloads(plans[0][0], ident.key_id, self._signers[receiver])[0]
                    out.append(Delivery(ident.peer_id, receiver, data, True, None, round_index))


def _silent(fleet: SimulatedFleet, out: list[Delivery], round_index: int,
            visible: frozenset[str]) -> None:
    return None


def _poison_every_round(fleet: SimulatedFleet, out: list[Delivery], round_index: int,
                        visible: frozenset[str]) -> None:
    fleet._push_poison(out, round_index)


_ARM_HANDLERS: Mapping[AdversaryArm, _Handler] = MappingProxyType({
    AdversaryArm.NONE: _silent,
    AdversaryArm.SYBIL_DECLARED_ROOT: SimulatedFleet._arm_sybil,
    AdversaryArm.SYBIL_FORGED_ROOTS: SimulatedFleet._arm_sybil,
    AdversaryArm.SYBIL_ADAPTIVE: SimulatedFleet._arm_sybil,
    AdversaryArm.BYZANTINE_POISON: _poison_every_round,
    AdversaryArm.BYZANTINE_LATENT_POISON: _poison_every_round,
    AdversaryArm.BYZANTINE_SUPPRESS: SimulatedFleet._arm_suppress,
    AdversaryArm.SLOW_POISON: SimulatedFleet._arm_slow,
    AdversaryArm.COLLUSION_TIMING: SimulatedFleet._arm_collusion,
    AdversaryArm.FLOOD: SimulatedFleet._arm_flood,
    AdversaryArm.REPLAY: SimulatedFleet._arm_replay,
    AdversaryArm.FALSE_REVOCATION: SimulatedFleet._arm_false_revocation,
    AdversaryArm.LINEAGE_TAMPER: SimulatedFleet._arm_tamper_or_inject,
    AdversaryArm.AUTHORITY_INJECTION: SimulatedFleet._arm_tamper_or_inject,
    AdversaryArm.UNANIMOUS_FLEET: SimulatedFleet._arm_unanimous,
})
