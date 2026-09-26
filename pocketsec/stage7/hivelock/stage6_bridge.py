"""Layer 7.16 / ORPH-F17 — the ONE module that hands anything to Stage 6.

Stage 7's thesis is the boundary that keeps foreign knowledge untrusted, and this is the
boundary's only door. The lead's rule is "do not build a second promotion gate", so the
bridge **builds no gate at all**: it turns an ECHO decision that is ``ELIGIBLE`` (a
*candidate*, never trusted) into Stage 6's own foreign-import form and passes each resulting
``ExperienceCapsuleV1`` to ``QuarantineGateway.admit`` — Stage 6's single admission function
— and to nothing else. Whatever Stage 6 then decides is recorded **verbatim** and never
inspected, overridden, retried or reinterpreted. ``TRUSTED_CANDIDATE`` is counted, never
acted on.

Why Stage 6's ``fleet.package`` path and not a hand-built capsule: that path already
rewrites the three foreign claims that would let one package defeat a local check (every
step's source group becomes the fleet group's, every epoch becomes the local epoch, the
label origin becomes ``WEAK``). Building a second import path would duplicate exactly the
code most worth having once. The bridge therefore signs **one package per supporting
dependence cluster** with a key derived for that cluster (``HMAC(bridge_secret, cluster)``),
so Stage 6's independence group ``fleet:s7c-<cluster>`` *is* Stage 7's cluster: N Sybil
identities ECHO merged into one cluster reach Stage 6 as ONE vote.

What the HMAC here proves: nothing about any peer. The bridge signs and verifies with its
own derived keyring on this host; it is **local integrity only** (the package was not
altered between being built and being converted). HMAC proves key possession, not host
identity (ADR-0064), and no Stage 7 signature ever authenticates a host.

The steps are ``antibody.forge.prototype_steps`` of the invariant: relation, relation-family
and semantic-property bits only — no novelty, timing or uncertainty features, no raw event
field. The evidence refs are the ``sha256:`` digests of the foreign bytes **this host
received** (``IngressVerdict.raw_digest``): real local evidence that the foreign object
existed, not a claim copied from the wire.

Exchange off means no handoff: with ``exchange_enabled=False`` Stage 6's
``package_to_capsules`` raises ``FleetDisabledError`` and the bridge lets it propagate —
nothing is built, nothing is admitted, and the counters prove it (``created == admitted``).

Bounded: at most ``MAX_BRIDGE_CAPSULES_PER_DECISION`` capsules per decision, and a receipt
ring of ``capacity`` entries with evictions counted. The Stage 6 lineage DAG is only ever
asked ``.has()``.
"""

from __future__ import annotations

import hashlib
import hmac
import sys
from collections import Counter, deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from pocketsec.stage0.contracts.common import ContractError, require_non_negative_int
from pocketsec.stage1.epoch.model import Epoch
from pocketsec.stage6.capsule.experience_capsule import (
    ExperienceCapsuleV1,
    PrivacyClass,
    source_group_of,
)
from pocketsec.stage6.capsule.quarantine import (
    QuarantineBucket,
    QuarantineGateway,
    QuarantineVerdict,
)
from pocketsec.stage6.fleet.package import (
    KNOWLEDGE_PACKAGE_V1_VERSION,
    MIN_KEY_BYTES,
    KnowledgePackageV1,
    package_to_capsules,
    sign_package,
    verify_package,
)
from pocketsec.stage6.fossils.lineage import KnowledgeLineageDAG
from pocketsec.stage7.antibody.forge import prototype_steps
from pocketsec.stage7.capsule.knowledge_capsule import Stance
from pocketsec.stage7.echo.inference import ClusterEvidence, EchoDecision, EchoStatus
from pocketsec.stage7.lineage.cross_host import (
    MAX_PARENTS_PER_NODE,
    CrossHostLineageDAG,
    LineageRecord,
    LinkState,
    NodeRole,
    stage6_link_detail,
)

__all__ = [
    "MAX_BRIDGE_CAPSULES_PER_DECISION",
    "MAX_BRIDGE_EVIDENCE_REFS",
    "MAX_BRIDGE_LINKS",
    "BridgeReceipt",
    "Stage6Bridge",
    "bridge_key_id",
]

#: §4.23. Chosen parameters, not measurements.
MAX_BRIDGE_CAPSULES_PER_DECISION: int = 8
MAX_BRIDGE_LINKS: int = 4096
#: Spec §7.16 step 2: "raw_digest of each of c's capsules, <= 32" (also Stage 6's per-capsule cap).
MAX_BRIDGE_EVIDENCE_REFS: int = 32

_CLUSTER_PREFIX = "cl-"
_HEX = frozenset("0123456789abcdef")


def bridge_key_id(cluster_id: str) -> str:
    """The Stage 6 key id (and so the independence group ``fleet:<key id>``) of a cluster."""
    body = cluster_id[len(_CLUSTER_PREFIX):] if isinstance(cluster_id, str) else ""
    if not cluster_id.startswith(_CLUSTER_PREFIX) or len(body) != 16 or set(body) - _HEX:
        raise ContractError(f"a dependence cluster id is 'cl-' + 16 hex, got {cluster_id!r}")
    return "s7c-" + body


@dataclass(frozen=True, slots=True)
class BridgeReceipt:
    """What was handed to Stage 6 for one decision, and what Stage 6 said — verbatim."""

    decision_id: str
    antibody_key: str
    stage6_capsule_ids: tuple[str, ...]
    verdict_ids: tuple[str, ...]
    stage6_buckets: tuple[str, ...]  # QuarantineBucket values as returned; never reinterpreted
    trusted_candidates: int  # how many Stage 6 put in TRUSTED_CANDIDATE (reported, never acted on)


class Stage6Bridge:
    """ORPH-F17. The only caller of ``QuarantineGateway.admit`` in Stage 7."""

    def __init__(
        self,
        *,
        gateway: QuarantineGateway,
        local_dag: KnowledgeLineageDAG,
        epoch: Epoch,
        bridge_secret: bytes,
        lineage: CrossHostLineageDAG,
        exchange_enabled: bool,
        capacity: int = MAX_BRIDGE_LINKS,
    ) -> None:
        # The gateway arrives already bound to the host's trusted view (the controller binds
        # it); Stage 7 never constructs a controller and never binds anything.
        if not isinstance(gateway, QuarantineGateway):
            raise ContractError("the bridge hands capsules to a Stage 6 QuarantineGateway only")
        if not isinstance(local_dag, KnowledgeLineageDAG):
            raise ContractError("local_dag must be Stage 6's KnowledgeLineageDAG")
        if not isinstance(epoch, Epoch):
            raise ContractError("epoch must be the LOCAL Stage 1 Epoch")
        if not isinstance(bridge_secret, bytes) or len(bridge_secret) < MIN_KEY_BYTES:
            raise ContractError(f"bridge_secret must be bytes of at least {MIN_KEY_BYTES}")
        if not isinstance(lineage, CrossHostLineageDAG):
            raise ContractError("lineage must be the CrossHostLineageDAG")
        if not isinstance(exchange_enabled, bool):
            raise ContractError("exchange_enabled must be a bool")
        if isinstance(capacity, bool) or not isinstance(capacity, int) or capacity < 1:
            raise ContractError("capacity must be a positive int")
        self._gateway = gateway
        self._local_dag = local_dag
        self._epoch = epoch
        self._secret = bridge_secret
        self._lineage = lineage
        self._exchange_enabled = exchange_enabled
        self._receipts: deque[BridgeReceipt] = deque(maxlen=capacity)
        self._n: Counter[str] = Counter()
        self._buckets: Counter[str] = Counter()

    # --- the handoff ----------------------------------------------------------------

    def hand_over(
        self, decision: EchoDecision, *, raw_digests: Mapping[str, str], sequence: int
    ) -> BridgeReceipt:
        """Spec §7.16's five steps. Refuses (``ContractError``) anything not ELIGIBLE and any
        decision none of whose supporting capsules carries a local evidence digest."""
        if not isinstance(decision, EchoDecision):
            raise ContractError("hand_over takes an EchoDecision")
        if decision.status is not EchoStatus.ELIGIBLE:
            self._n["refused_not_eligible"] += 1
            raise ContractError(
                f"only an ELIGIBLE decision is handed to Stage 6, not {decision.status}"
            )
        require_non_negative_int(sequence, "sequence")
        rows = self._supporting(decision, raw_digests)
        if not rows:
            self._n["refused_unevidenced"] += 1
            raise ContractError("no supporting cluster carries a local evidence digest: refused")
        capsules = self._build(decision, rows, sequence)  # FleetDisabledError propagates here
        self._n["created"] += len(capsules)
        self._ensure_decision_node(decision)
        verdicts = [self._admit(capsule) for capsule in capsules]
        return self._receipt(decision, verdicts)

    def _supporting(
        self, decision: EchoDecision, raw_digests: Mapping[str, str]
    ) -> list[tuple[ClusterEvidence, tuple[str, ...]]]:
        """Step 2's selection: SUPPORT rows in evidence order (highest mass first), each with
        the local digests of its capsules; a row with none is skipped and counted."""
        chosen: list[tuple[ClusterEvidence, tuple[str, ...]]] = []
        for row in decision.evidence:
            if row.stance is not Stance.SUPPORT:
                continue
            if len(chosen) >= MAX_BRIDGE_CAPSULES_PER_DECISION:
                self._n["clusters_truncated"] += 1
                continue
            refs = tuple(dict.fromkeys(
                raw_digests[cid] for cid in row.capsule_ids if cid in raw_digests
            ))[:MAX_BRIDGE_EVIDENCE_REFS]
            if not refs:
                self._n["clusters_unevidenced"] += 1
                continue
            chosen.append((row, refs))
        return chosen

    def _cluster_key(self, cluster_id: str) -> bytes:
        return hmac.new(self._secret, cluster_id.encode("utf-8"), hashlib.sha256).digest()

    def _build(
        self, decision: EchoDecision, rows: Sequence[tuple[ClusterEvidence, tuple[str, ...]]],
        sequence: int,
    ) -> tuple[ExperienceCapsuleV1, ...]:
        """Steps 2-4 for every row BEFORE any admit, so a failure admits nothing."""
        built: list[ExperienceCapsuleV1] = []
        for offset, (row, refs) in enumerate(rows):
            package, key = self._package(decision, row.cluster_id, refs, sequence + offset)
            verification = verify_package(package, keyring={package.key_id: key})
            if not verification.valid:
                raise ContractError(
                    f"bridge package failed local verification: {verification.reasons}"
                )
            built.extend(package_to_capsules(
                package, verification=verification, epoch=self._epoch,
                sequence=sequence + offset, enabled=self._exchange_enabled,
            ))
        return tuple(built)

    def _package(
        self, decision: EchoDecision, cluster_id: str, refs: tuple[str, ...], sequence: int
    ) -> tuple[KnowledgePackageV1, bytes]:
        key_id = bridge_key_id(cluster_id)
        group = source_group_of("stage7:" + cluster_id)
        steps = prototype_steps(decision.invariant, source_group=group)
        item: dict[str, Any] = {
            "privacy_class": PrivacyClass.PUBLIC_DERIVED.value,
            "steps": [step.to_dict() for step in steps],
            "evidence_refs": list(refs),
            "verdict": "MALICIOUS",
        }
        package = KnowledgePackageV1(
            package_id="s7-" + decision.decision_id[4:28] + "-" + cluster_id[3:11],
            source_host="stage7-" + cluster_id,
            key_id=key_id,
            created_sequence=sequence,
            items=(item,),
            lineage_digests=refs,
            signature="",
            schema_version=KNOWLEDGE_PACKAGE_V1_VERSION,
        )
        key = self._cluster_key(cluster_id)
        return sign_package(package, key=key), key

    def _ensure_decision_node(self, decision: EchoDecision) -> None:
        if self._lineage.has(decision.decision_id):
            return
        parents = tuple(dict.fromkeys(
            cid
            for row in decision.evidence if row.stance is Stance.SUPPORT
            for cid in row.capsule_ids
        ))[:MAX_PARENTS_PER_NODE]
        self._lineage.add(LineageRecord(
            node_id=decision.decision_id, role=NodeRole.ECHO_DECISION, parents=parents,
            state=LinkState.LIVE, round_index=decision.round_index, detail=decision.antibody_key,
        ))

    def _admit(self, capsule: ExperienceCapsuleV1) -> tuple[QuarantineVerdict, str]:
        """Step 5 for one capsule: Stage 6 decides; the bridge records, it does not judge."""
        self._n["admitted"] += 1  # counted as passed to admit even if admit then raises
        verdict = self._gateway.admit(capsule)
        self._buckets[verdict.bucket.value] += 1
        if self._local_dag.has(verdict.capsule_id):
            self._n["stage6_lineage_present"] += 1
        else:
            self._n["stage6_lineage_missing"] += 1
        link_id = "s6l-" + hashlib.sha256(
            f"{verdict.capsule_id}|{verdict.verdict_id}".encode("utf-8")
        ).hexdigest()[:32]
        return verdict, link_id

    def _receipt(
        self, decision: EchoDecision, admitted: Sequence[tuple[QuarantineVerdict, str]]
    ) -> BridgeReceipt:
        for verdict, link_id in admitted:
            self._lineage.add(LineageRecord(
                node_id=link_id, role=NodeRole.STAGE6_LINK, parents=(decision.decision_id,),
                state=LinkState.LIVE, round_index=decision.round_index,
                detail=stage6_link_detail(
                    verdict.capsule_id, verdict.verdict_id, verdict.bucket.value
                ),
            ))
        verdicts = [verdict for verdict, _ in admitted]
        receipt = BridgeReceipt(
            decision_id=decision.decision_id,
            antibody_key=decision.antibody_key,
            stage6_capsule_ids=tuple(v.capsule_id for v in verdicts),
            verdict_ids=tuple(v.verdict_id for v in verdicts),
            stage6_buckets=tuple(v.bucket.value for v in verdicts),
            trusted_candidates=sum(
                v.bucket is QuarantineBucket.TRUSTED_CANDIDATE for v in verdicts
            ),
        )
        if len(self._receipts) == self._receipts.maxlen:
            self._n["receipts_evicted"] += 1
        self._receipts.append(receipt)
        self._n["decisions_bridged"] += 1
        return receipt

    # --- introspection ---------------------------------------------------------------

    def created(self) -> int:
        """ExperienceCapsuleV1 values this bridge built."""
        return self._n["created"]

    def admitted(self) -> int:
        """Values it passed to ``gateway.admit`` — G7.1 asserts ``created == admitted``."""
        return self._n["admitted"]

    def receipts(self) -> tuple[BridgeReceipt, ...]:
        return tuple(self._receipts)

    def buckets(self) -> Mapping[str, int]:
        """Stage 6 bucket -> count over every capsule this bridge ever handed over."""
        return MappingProxyType(dict(self._buckets))

    def stats(self) -> Mapping[str, int]:
        return MappingProxyType(dict(self._n))

    def memory_bytes(self) -> int:
        per = sum(
            sys.getsizeof(r) + sys.getsizeof(r.decision_id) + sys.getsizeof(r.antibody_key)
            + sum(
                sys.getsizeof(s) + 8
                for s in (*r.stage6_capsule_ids, *r.verdict_ids, *r.stage6_buckets)
            )
            for r in self._receipts
        )
        counters = sys.getsizeof(self._n) + sys.getsizeof(self._buckets)
        return per + sys.getsizeof(self._receipts) + counters
