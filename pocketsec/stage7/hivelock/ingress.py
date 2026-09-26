"""D7.7 — HIVELOCK ingress: the one entrance for foreign bytes, and it never grants trust.

Stage 7's deliverable is the boundary that keeps foreign knowledge untrusted. Every byte
a peer sends enters through :meth:`HivelockIngress.receive` and runs architecture §21's
pipeline in exactly this order, the **first refusal ending the call**:

1. ``SIZE_RATE`` — :meth:`CommunicationGovernor.admit_inbound` on the raw length:
   partition, oversize (refused **before parsing**), per-sender and round caps, inbox.
2. ``SCHEMA`` — :meth:`KnowledgeCapsuleV1.from_bytes`, strict at every depth. A parse or
   contract error is a refusal carrying the error class and at most 60 characters.
3. ``INTEGRITY`` — :meth:`Keyring.verify`: signed, known key, not revoked or expired,
   HMAC matches, and the key's owner **is** the capsule's contributor. This proves key
   possession, not host identity.
4. ``REPLAY_EXPIRY`` — :meth:`ReplayGuard.check`; on a pass the capsule is admitted to the
   guard, so a later refusal still consumes it (a refused capsule cannot be resent to
   probe the later stages).
5. ``PROVENANCE`` — the commitment is complete, and a derived capsule (one naming an
   aggregation decision or parents) must have **every** parent resolve through the
   injected ``lineage_resolves``. A derived capsule with no parents cannot have its
   ancestry checked and is refused the same way (``unresolvable_lineage``).
6. ``PRIVACY`` — ``residual_identifier_hits`` over the decoded payload must be empty.
   Defence in depth: the schema already constrains every string.
7. ``DEPENDENCE`` — :meth:`PeerTable.observe`; a newcomer refused by a full table is
   ``peer_table_full``. Then the injected ``cluster_of`` names the dependence cluster.
8. ``SUSPICION`` — the sovereignty and direction rules. An ANTIBODY ``CONTEST``, or a
   REVOCATION, touching a key or capsule in ``local_keys()`` is ``local_sovereignty``:
   **no number of peers can contest or revoke what this host learned locally.** Any other
   REVOCATION goes to the bounded revocation inbox — never to the pool.
9. ``RELEVANCE`` — the injected ``gravity_of``; below the floor (when gravity is enabled)
   the capsule is kept only as metadata in a bounded ring.
10. ``POOLED`` — the bounded pool of candidate evidence for ECHO. A full pool refuses the
    newcomer; nothing is ever evicted to make room.

**What ingress refuses to do.** It never marks anything trusted: its best outcome is
``POOLED``, which means "candidate evidence ECHO may weigh", and the only path onward to
local trusted state is Stage 6's quarantine via the bridge, which this module does not
name. It imports **no** graph, relevance, echo or lineage module: those are injected
callables, so the package order stays acyclic and the wiring lives in one place
(``orpheus/fabric.py``). It never raises on foreign input — every malformed, hostile or
over-budget object is a recorded refusal — and every store it keeps is bounded, with its
refusals and ring overwrites counted.

``raw_digest`` is the ``sha256:`` of the bytes exactly as received: the **local** evidence
digest of this foreign object, the one the bridge later cites.
"""

from __future__ import annotations

import dataclasses
import hashlib
import math
import sys
from collections import Counter, deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum, StrEnum
from types import MappingProxyType

from pocketsec.stage0.contracts.common import (
    ContractError,
    digest_of_bytes,
    require_non_negative_int,
)
from pocketsec.stage6.resources import WorkBudgetExceeded, WorkMeter
from pocketsec.stage7.capsule.knowledge_capsule import (
    KnowledgeCapsuleV1,
    KnowledgeType,
    Stance,
)
from pocketsec.stage7.governor.communication import CommunicationGovernor
from pocketsec.stage7.identity.integrity import Keyring, ReplayGuard
from pocketsec.stage7.identity.peer import PeerIdentity, PeerTable
from pocketsec.stage7.privacy.distiller import residual_identifier_hits

__all__ = [
    "MAX_METADATA_RECORDS",
    "MAX_POOL_CAPSULES",
    "MAX_REVOCATION_INBOX",
    "SCHEMA_ERRORS",
    "VALIDATION_FLOOR",
    "HivelockIngress",
    "IngressOutcome",
    "IngressStage",
    "IngressVerdict",
    "PooledCapsule",
]

#: §4.23. Chosen parameters, not measurements.
MAX_POOL_CAPSULES: int = 2048
MAX_METADATA_RECORDS: int = 1024
MAX_REVOCATION_INBOX: int = 256
VALIDATION_FLOOR: float = 0.05

#: What a hostile payload can make the strict parser raise. Each is a refusal at SCHEMA,
#: never an exception out of ``receive``: ContractError and UnicodeError are ValueErrors;
#: TypeError/KeyError cover wrong-typed JSON; RecursionError covers deep nesting.
SCHEMA_ERRORS: tuple[type[BaseException], ...] = (ValueError, TypeError, KeyError, RecursionError)
_SCHEMA_MESSAGE_CHARS: int = 60
_BASE_STATS: tuple[str, ...] = (
    "offered",
    "refused",
    "pooled",
    "metadata_only",
    "routed_revocation",
)


class IngressStage(StrEnum):
    SIZE_RATE = "SIZE_RATE"
    SCHEMA = "SCHEMA"
    INTEGRITY = "INTEGRITY"
    REPLAY_EXPIRY = "REPLAY_EXPIRY"
    PROVENANCE = "PROVENANCE"
    PRIVACY = "PRIVACY"
    DEPENDENCE = "DEPENDENCE"
    SUSPICION = "SUSPICION"
    RELEVANCE = "RELEVANCE"
    POOLED = "POOLED"


class IngressOutcome(StrEnum):
    REFUSED = "REFUSED"
    METADATA_ONLY = "METADATA_ONLY"
    POOLED = "POOLED"
    ROUTED_REVOCATION = "ROUTED_REVOCATION"


#: Where each non-refused outcome must have stopped; a verdict that disagrees is refused.
_OUTCOME_STAGE: Mapping[IngressOutcome, IngressStage] = MappingProxyType(
    {
        IngressOutcome.METADATA_ONLY: IngressStage.RELEVANCE,
        IngressOutcome.POOLED: IngressStage.POOLED,
        IngressOutcome.ROUTED_REVOCATION: IngressStage.SUSPICION,
    }
)


def _verdict_id(
    raw_digest: str, outcome: IngressOutcome, reasons: tuple[str, ...], received_round: int
) -> str:
    text = "\x1f".join((raw_digest, outcome.value, "\x1e".join(reasons), str(received_round)))
    return "iv-" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:32]


@dataclass(frozen=True, slots=True)
class IngressVerdict:
    """What ingress did with one received object. It never promotes and never trusts."""

    verdict_id: str
    raw_digest: str
    capsule_id: str | None
    outcome: IngressOutcome
    stage_reached: IngressStage
    reasons: tuple[str, ...]
    peer_id: str | None
    cluster_id: str | None
    gravity: float | None
    received_round: int

    def __post_init__(self) -> None:
        require_non_negative_int(self.received_round, "IngressVerdict.received_round")
        if not isinstance(self.outcome, IngressOutcome):
            raise ContractError(
                f"IngressVerdict.outcome must be an IngressOutcome: {self.outcome!r}"
            )
        if not isinstance(self.stage_reached, IngressStage):
            raise ContractError("IngressVerdict.stage_reached must be an IngressStage")
        expected_stage = _OUTCOME_STAGE.get(self.outcome)
        if expected_stage is not None and self.stage_reached is not expected_stage:
            raise ContractError(f"{self.outcome} cannot stop at {self.stage_reached}")
        if self.capsule_id is None and self.stage_reached not in (
            IngressStage.SIZE_RATE,
            IngressStage.SCHEMA,
        ):
            raise ContractError("only a refusal before SCHEMA passes may lack a capsule_id")
        expected = _verdict_id(self.raw_digest, self.outcome, self.reasons, self.received_round)
        if self.verdict_id != expected:
            raise ContractError("IngressVerdict.verdict_id does not match its content")


@dataclass(frozen=True, slots=True)
class PooledCapsule:
    """A capsule that passed every ingress stage: candidate evidence, never trusted state."""

    capsule: KnowledgeCapsuleV1
    raw_digest: str
    peer_id: str
    cluster_id: str
    relevance: float
    gravity: float
    received_round: int


class _Refusal(Exception):
    """Internal: a stage refused. Carries the stage and the recorded reason."""

    def __init__(self, stage: IngressStage, reason: str, stat_reason: str | None = None) -> None:
        super().__init__(reason)
        self.stage = stage
        self.reason = reason
        self.stat_reason = reason if stat_reason is None else stat_reason


@dataclass(slots=True)
class _Trace:
    """The mutable record of one ``receive`` call, frozen into an IngressVerdict at the end."""

    raw_digest: str
    round_index: int
    reasons: list[str] = dataclasses.field(default_factory=list)
    capsule_id: str | None = None
    peer_id: str | None = None
    cluster_id: str | None = None
    gravity: float | None = None


def _deep_size(value: object, _depth: int = 0) -> int:
    """An upper-bound byte estimate of a capsule-shaped object graph.

    Shared objects (enum members, interned strings) are counted every time they appear.
    """
    size = sys.getsizeof(value)
    if _depth > 8 or isinstance(value, (str, bytes, int, float, bool, Enum)) or value is None:
        return size
    if isinstance(value, (tuple, list, frozenset, set)):
        return size + sum(_deep_size(item, _depth + 1) for item in value)
    if isinstance(value, Mapping):
        return size + sum(
            _deep_size(k, _depth + 1) + _deep_size(v, _depth + 1) for k, v in value.items()
        )
    if dataclasses.is_dataclass(value):
        return size + sum(
            _deep_size(getattr(value, f.name), _depth + 1) for f in dataclasses.fields(value)
        )
    return size


def _cluster(trace: _Trace) -> str:
    """The cluster DEPENDENCE named; every later stage runs only after it was set."""
    if trace.cluster_id is None:
        raise ContractError("a stage after DEPENDENCE ran without a cluster id")
    return trace.cluster_id


def _finite(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


class HivelockIngress:
    """The §21 pipeline. Its best outcome is POOLED; nothing it returns is trusted.

    ``cluster_of``, ``relevance_of``, ``gravity_of``, ``lineage_resolves`` and
    ``local_keys`` are injected so that ingress imports no graph, relevance, echo or
    lineage module. The defaults refuse lineage (nothing resolves) and protect nothing.
    """

    def __init__(
        self,
        *,
        keyring: Keyring,
        replay: ReplayGuard,
        peers: PeerTable,
        governor: CommunicationGovernor,
        cluster_of: Callable[[KnowledgeCapsuleV1, PeerIdentity, int], str],
        relevance_of: Callable[[KnowledgeCapsuleV1], float],
        gravity_of: Callable[[KnowledgeCapsuleV1, str, int], float],
        lineage_resolves: Callable[[str], bool] = lambda _id: False,
        local_keys: Callable[[], frozenset[str]] = frozenset,
        gravity_floor: float = VALIDATION_FLOOR,
        gravity_enabled: bool = True,
        meter: WorkMeter | None = None,
    ) -> None:
        floor = _finite(gravity_floor)
        if floor is None or floor < 0.0:
            raise ContractError(
                f"gravity_floor must be a finite number >= 0, got {gravity_floor!r}"
            )
        if not isinstance(gravity_enabled, bool):
            raise ContractError("gravity_enabled must be a bool")
        self._keyring = keyring
        self._replay = replay
        self._peers = peers
        self._governor = governor
        self._cluster_of = cluster_of
        self._relevance_of = relevance_of
        self._gravity_of = gravity_of
        self._lineage_resolves = lineage_resolves
        self._local_keys = local_keys
        self._gravity_floor = floor
        self._gravity_enabled = gravity_enabled
        self._meter = meter
        self._pool: list[PooledCapsule] = []
        self._pool_bytes = 0
        self._revocations: list[tuple[KnowledgeCapsuleV1, str]] = []
        self._revocation_bytes = 0
        self._metadata: deque[tuple[str, str, float]] = deque(maxlen=MAX_METADATA_RECORDS)
        # The base counters always exist, so a consumer reading one at zero gets 0, not KeyError.
        self._stats: Counter[str] = Counter(dict.fromkeys(_BASE_STATS, 0))

    # -- the pipeline --------------------------------------------------------------

    def receive(self, data: bytes, *, sender: str, round_index: int) -> IngressVerdict:
        """Run the ten stages over ``data``; the first refusal ends the call.

        Never raises on foreign input: every malformed or hostile object is a recorded
        refusal. It does raise on a caller error (non-bytes ``data``, a negative round).
        """
        if not isinstance(data, bytes):
            raise ContractError(f"receive takes the bytes as received, got {type(data).__name__}")
        require_non_negative_int(round_index, "round_index")
        trace = _Trace(raw_digest=digest_of_bytes(data), round_index=round_index)
        self._stats["offered"] += 1
        try:
            return self._pipeline(data, sender, trace)
        except _Refusal as refusal:
            trace.reasons.append(f"{refusal.stage.value}:{refusal.reason}")
            self._stats["refused"] += 1
            self._stats[f"refused:{refusal.stage.value}:{refusal.stat_reason}"] += 1
            return self._verdict(trace, IngressOutcome.REFUSED, refusal.stage)

    def _pipeline(self, data: bytes, sender: str, trace: _Trace) -> IngressVerdict:
        self._stage(IngressStage.SIZE_RATE, trace, units=1)
        reason = self._governor.admit_inbound(sender, len(data), round_index=trace.round_index)
        self._pass_unless(IngressStage.SIZE_RATE, reason, trace)
        capsule = self._parse(data, trace)
        self._check_integrity(capsule, trace)
        self._check_replay(capsule, trace)
        self._check_provenance(capsule, trace)
        self._check_privacy(capsule, trace)
        peer = self._observe_peer(capsule, trace)
        if self._suspicion(capsule, peer, trace):
            return self._verdict(trace, IngressOutcome.ROUTED_REVOCATION, IngressStage.SUSPICION)
        gravity, relevance = self._relevance(capsule, trace)
        if self._gravity_enabled and gravity < self._gravity_floor:
            self._keep_metadata(capsule, peer, gravity)
            trace.reasons.append(f"{IngressStage.RELEVANCE.value}:below_floor")
            self._stats["metadata_only"] += 1
            return self._verdict(trace, IngressOutcome.METADATA_ONLY, IngressStage.RELEVANCE)
        trace.reasons.append(f"{IngressStage.RELEVANCE.value}:ok")
        self._pool_capsule(
            capsule, peer, trace, relevance=relevance, gravity=gravity, size=len(data)
        )
        return self._verdict(trace, IngressOutcome.POOLED, IngressStage.POOLED)

    def _stage(self, stage: IngressStage, trace: _Trace, *, units: int) -> None:
        """Enter ``stage``: pay for it, or refuse the object if the work budget is spent."""
        if self._meter is None:
            return
        try:
            self._meter.charge(units)
        except WorkBudgetExceeded:
            raise _Refusal(stage, "work_budget") from None

    def _pass_unless(self, stage: IngressStage, reason: str | None, trace: _Trace) -> None:
        if reason is not None:
            raise _Refusal(stage, reason)
        trace.reasons.append(f"{stage.value}:ok")

    def _parse(self, data: bytes, trace: _Trace) -> KnowledgeCapsuleV1:
        # Parsing cost grows with the payload, so it is charged by the 256-byte block.
        self._stage(IngressStage.SCHEMA, trace, units=1 + len(data) // 256)
        try:
            capsule = KnowledgeCapsuleV1.from_bytes(data)
        except SCHEMA_ERRORS as error:
            name = type(error).__name__
            message = str(error)[:_SCHEMA_MESSAGE_CHARS]
            # The stats key carries only the class: messages would make it unbounded.
            raise _Refusal(IngressStage.SCHEMA, f"{name}:{message}", stat_reason=name) from None
        trace.capsule_id = capsule.capsule_id
        trace.reasons.append(f"{IngressStage.SCHEMA.value}:ok")
        return capsule

    def _check_integrity(self, capsule: KnowledgeCapsuleV1, trace: _Trace) -> None:
        self._stage(IngressStage.INTEGRITY, trace, units=2)
        verdict = self._keyring.verify(capsule, round_index=trace.round_index)
        self._pass_unless(IngressStage.INTEGRITY, None if verdict.valid else verdict.reason, trace)
        # Only now is the contributor bound to a key; before this it was an unchecked claim.
        trace.peer_id = capsule.provenance_commitment.contributor

    def _check_replay(self, capsule: KnowledgeCapsuleV1, trace: _Trace) -> None:
        self._stage(IngressStage.REPLAY_EXPIRY, trace, units=1)
        reason = self._replay.check(capsule, round_index=trace.round_index)
        self._pass_unless(IngressStage.REPLAY_EXPIRY, reason, trace)
        self._replay.admit(capsule)

    def _check_provenance(self, capsule: KnowledgeCapsuleV1, trace: _Trace) -> None:
        self._stage(IngressStage.PROVENANCE, trace, units=1 + len(capsule.parent_capsules))
        commitment = capsule.provenance_commitment
        if not (
            commitment.contributor
            and commitment.provenance_root
            and commitment.evidence_commitments
        ):
            raise _Refusal(IngressStage.PROVENANCE, "missing_provenance")
        derived = commitment.aggregation_decision is not None or bool(capsule.parent_capsules)
        if derived and (
            not capsule.parent_capsules
            or not all(self._lineage_resolves(parent) is True for parent in capsule.parent_capsules)
        ):
            raise _Refusal(IngressStage.PROVENANCE, "unresolvable_lineage")
        trace.reasons.append(f"{IngressStage.PROVENANCE.value}:ok")

    def _check_privacy(self, capsule: KnowledgeCapsuleV1, trace: _Trace) -> None:
        self._stage(IngressStage.PRIVACY, trace, units=2)
        hits = residual_identifier_hits(capsule.to_dict())
        self._pass_unless(IngressStage.PRIVACY, "residual_identifier" if hits else None, trace)

    def _observe_peer(self, capsule: KnowledgeCapsuleV1, trace: _Trace) -> PeerIdentity:
        self._stage(IngressStage.DEPENDENCE, trace, units=2)
        commitment = capsule.provenance_commitment
        peer = self._peers.observe(
            commitment.contributor,
            key_id=capsule.key_id,
            provenance_root=commitment.provenance_root,
            role_claim=capsule.source_context_sketch.role,
            round_index=trace.round_index,
        )
        if peer is None:
            raise _Refusal(IngressStage.DEPENDENCE, "peer_table_full")
        cluster_id = self._cluster_of(capsule, peer, trace.round_index)
        if not isinstance(cluster_id, str) or not cluster_id:
            raise ContractError(f"cluster_of must return a non-empty str, got {cluster_id!r}")
        trace.cluster_id = cluster_id
        trace.reasons.append(f"{IngressStage.DEPENDENCE.value}:ok")
        return peer

    def _suspicion(self, capsule: KnowledgeCapsuleV1, peer: PeerIdentity, trace: _Trace) -> bool:
        """Apply the sovereignty and direction rules; ``True`` means routed as a revocation."""
        self._stage(IngressStage.SUSPICION, trace, units=1)
        local = frozenset(self._local_keys())  # any iterable wiring compares the same way
        touched = {capsule.compact_feature_signature, capsule.revocation_target or ""} - {""}
        is_revocation = capsule.knowledge_type is KnowledgeType.REVOCATION
        is_contest = (
            capsule.knowledge_type is KnowledgeType.ANTIBODY and capsule.stance is Stance.CONTEST
        )
        if (is_revocation or is_contest) and touched & local:
            raise _Refusal(IngressStage.SUSPICION, "local_sovereignty")
        if not is_revocation:
            trace.reasons.append(f"{IngressStage.SUSPICION.value}:ok")
            return False
        if len(self._revocations) >= MAX_REVOCATION_INBOX:
            raise _Refusal(IngressStage.SUSPICION, "revocation_inbox_full")
        self._revocations.append((capsule, peer.peer_id))
        self._revocation_bytes += _deep_size(capsule)
        trace.reasons.append(f"{IngressStage.SUSPICION.value}:routed_revocation")
        self._stats["routed_revocation"] += 1
        return True

    def _relevance(self, capsule: KnowledgeCapsuleV1, trace: _Trace) -> tuple[float, float]:
        self._stage(IngressStage.RELEVANCE, trace, units=2)
        gravity = _finite(self._gravity_of(capsule, _cluster(trace), trace.round_index))
        relevance = _finite(self._relevance_of(capsule))
        # A non-finite score would compare False against the floor and slip into the pool.
        if gravity is None or relevance is None:
            raise _Refusal(IngressStage.RELEVANCE, "non_finite_score")
        trace.gravity = gravity
        return gravity, relevance

    def _keep_metadata(
        self, capsule: KnowledgeCapsuleV1, peer: PeerIdentity, gravity: float
    ) -> None:
        if len(self._metadata) == self._metadata.maxlen:
            self._stats["metadata_overwritten"] += 1
        self._metadata.append((capsule.capsule_id, peer.peer_id, gravity))

    def _pool_capsule(
        self,
        capsule: KnowledgeCapsuleV1,
        peer: PeerIdentity,
        trace: _Trace,
        *,
        relevance: float,
        gravity: float,
        size: int,
    ) -> None:
        self._stage(IngressStage.POOLED, trace, units=1)
        if len(self._pool) >= MAX_POOL_CAPSULES:
            raise _Refusal(IngressStage.POOLED, "pool_full")
        entry = PooledCapsule(
            capsule=capsule,
            raw_digest=trace.raw_digest,
            peer_id=peer.peer_id,
            cluster_id=_cluster(trace),
            relevance=relevance,
            gravity=gravity,
            received_round=trace.round_index,
        )
        self._pool.append(entry)
        self._pool_bytes += _deep_size(entry) + size
        trace.reasons.append(f"{IngressStage.POOLED.value}:ok")
        self._stats["pooled"] += 1

    def _verdict(
        self, trace: _Trace, outcome: IngressOutcome, stage: IngressStage
    ) -> IngressVerdict:
        reasons = tuple(trace.reasons)
        return IngressVerdict(
            verdict_id=_verdict_id(trace.raw_digest, outcome, reasons, trace.round_index),
            raw_digest=trace.raw_digest,
            capsule_id=trace.capsule_id,
            outcome=outcome,
            stage_reached=stage,
            reasons=reasons,
            peer_id=trace.peer_id,
            cluster_id=trace.cluster_id,
            gravity=trace.gravity,
            received_round=trace.round_index,
        )

    # -- the bounded stores --------------------------------------------------------

    def drain_pool(self) -> tuple[PooledCapsule, ...]:
        """Hand the pooled candidates to ECHO and empty the pool."""
        drained = tuple(self._pool)
        self._pool.clear()
        self._pool_bytes = 0
        return drained

    def drain_revocations(self) -> tuple[tuple[KnowledgeCapsuleV1, str], ...]:
        """Hand ``(revocation capsule, peer_id)`` pairs to the RevocationPlane; empty the inbox."""
        drained = tuple(self._revocations)
        self._revocations.clear()
        self._revocation_bytes = 0
        return drained

    def metadata(self) -> tuple[tuple[str, str, float], ...]:
        """``(capsule_id, peer_id, gravity)`` of the most recent below-floor capsules."""
        return tuple(self._metadata)

    def pool_size(self) -> int:
        return len(self._pool)

    def revocation_inbox_size(self) -> int:
        return len(self._revocations)

    def stats(self) -> Mapping[str, int]:
        """offered, refused, refused:<stage>:<reason>, pooled, metadata_only, routed_revocation."""
        return MappingProxyType(dict(self._stats))

    def memory_bytes(self) -> int:
        """An upper-bound estimate of the pool, revocation inbox, metadata ring and counters."""
        ring = sum(
            sys.getsizeof(cid) + sys.getsizeof(pid) + 24 + 64 for cid, pid, _ in self._metadata
        )
        stats = sum(sys.getsizeof(key) + 32 for key in self._stats)
        return (
            self._pool_bytes
            + self._revocation_bytes
            + ring
            + stats
            + sys.getsizeof(self._pool)
            + sys.getsizeof(self._revocations)
            + sys.getsizeof(self._metadata)
        )
