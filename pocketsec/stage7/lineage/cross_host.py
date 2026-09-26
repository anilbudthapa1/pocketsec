"""D7.16 / ORPH-F15, ORPH-F16 — cross-host lineage and revocation that is targeted and reversible.

Architecture §24: "every import must be rejectable, expirable and revocable", and
"revocation is itself untrusted input until verified". This module exists so that a
retraction touches **exactly** what descends from its target — nothing more, nothing less —
and so that a mistaken retraction can be undone byte-for-byte.

:class:`CrossHostLineageDAG` records four kinds of node: foreign capsules as received,
local capsules this host published, ECHO decisions (whose parents are the capsules that
supported them) and ``STAGE6_LINK`` nodes (one per ``ExperienceCapsuleV1`` the bridge handed
to Stage 6, whose ``detail`` names the Stage 6 capsule, verdict and bucket). It **never
invents a parent**: an unknown parent id is kept on the record and counted as unresolved, so
:meth:`CrossHostLineageDAG.ancestry_complete` can answer "no" instead of pretending.

It is bounded (``MAX_LINEAGE_NODES``). When full it evicts the **oldest leaf** that is not a
live ``STAGE6_LINK``: a leaf has no descendant a revocation could need, and a live link (and
therefore every ancestor of one, none of which is a leaf) is the only record of what this
host handed to Stage 6, which a later retraction must be able to name. Every eviction leaves
a counted tombstone; when nothing is evictable the newcomer is refused and counted — the
bound is never exceeded and nothing is silently overwritten.

:class:`RevocationPlane` applies the authority rules of spec D7.16, **exactly**:

* a foreign ``SELF_RETRACTION`` is accepted iff the target is a foreign capsule whose
  contributor is the owner of the revocation's signing key (and the sender);
* a foreign capsule claiming ``LOCAL_EVIDENCE`` is refused ``foreign_claims_local_ground`` —
  only this host's own evidence is local evidence (:meth:`RevocationPlane.revoke_locally`);
* a foreign revocation of a ``LOCAL_CAPSULE`` node or of anything in ``local_keys()`` is
  refused ``local_sovereignty``: no number of peers can revoke what this host learned;
* an unknown target is refused ``unknown_target`` and changes nothing;
* a third party retracting someone else's capsule is refused ``not_contributor`` (it may
  still CONTEST, which only reduces ECHO mass — ADR-0063).

An accepted revocation **marks, never deletes**: the target and its descendants become
SUSPECT (REVOKED for the target under local evidence), the affected ECHO keys are marked
suspect through the injected ``echo_suspect``, and the Stage 6 capsule ids beneath are
computed from the ``STAGE6_LINK`` details. Ambiguity (a descendant walk cut at its limit)
marks what is known and says so (``affected_truncated``). **Stage 7 cannot act on Stage 6**:
Stage 6 exposes no revocation input (blocker B7-2, ADR-0067), so ``stage6_capsule_ids`` is
the targeted set, reported, and Stage 6-side rollback is UNMEASURED.

**Order independence (review finding S7-R1).** Marking ECHO keys suspect only reaches keys
that already have an ECHO_DECISION node, i.e. that were ELIGIBLE at least once. A capsule
retracted BEFORE that must still stop counting, so ECHO does not rely on this mark alone:
the fabric hands ECHO a liveness predicate over this DAG, and ECHO excludes every
contribution whose node is not LIVE, every round, whatever the order. Reinstating restores
the node's state and so the contribution.

**Known residual (tested, not defended here).** ECHO's suspicion is keyed on the antibody
key, not on the contribution. A contributor who supported an ELIGIBLE key and then
self-retracts its own capsule therefore moves the whole key to SUSPECT, including the other
clusters' support: a self-retraction is a suppression lever against keys the retractor
touched. The spec's rules are applied as written; the residual is reported.

Stdlib only. Nothing here imports Stage 5, Stage 6's writers or any ``labs`` module.
"""

from __future__ import annotations

import hashlib
import json
import sys
from collections import OrderedDict, deque
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum

from pocketsec.stage0.contracts.common import (
    ContractError,
    require_identifier,
    require_non_negative_int,
)
from pocketsec.stage7.capsule.knowledge_capsule import (
    KnowledgeCapsuleV1,
    KnowledgeType,
    RevocationGround,
)

__all__ = [
    "LOCAL_ISSUER",
    "MAX_DESCENDANT_WALK",
    "MAX_LINEAGE_NODES",
    "MAX_PARENTS_PER_NODE",
    "MAX_REVOCATIONS",
    "REVOCATION_REASONS",
    "CrossHostLineageDAG",
    "LineageRecord",
    "LinkState",
    "NodeRole",
    "Revocation",
    "RevocationPlane",
    "stage6_link_detail",
]

#: §4.23. Chosen parameters, not measurements.
MAX_LINEAGE_NODES: int = 16384
MAX_DESCENDANT_WALK: int = 1024
MAX_REVOCATIONS: int = 256
#: Not in §4.23: an ECHO decision names at most MAX_CLUSTERS_PER_DECISION (16) rows of at
#: most 8 capsule ids each, so 128 parents is the widest honest record. Chosen.
MAX_PARENTS_PER_NODE: int = 128
#: The issuer recorded on a revocation grounded in this host's own evidence.
LOCAL_ISSUER = "local"

#: Every reason a :class:`Revocation` can carry.
REVOCATION_REASONS: frozenset[str] = frozenset(
    {
        "accepted",
        "accepted_truncated",
        "not_a_revocation",
        "foreign_claims_local_ground",
        "local_sovereignty",
        "unknown_target",
        "not_contributor",
        "already_revoked",
    }
)

# Rough per-entry overheads of the dict / set slots holding a record (CPython 3.14).
_SLOT_BYTES = 104


class NodeRole(StrEnum):
    FOREIGN_CAPSULE = "FOREIGN_CAPSULE"
    LOCAL_CAPSULE = "LOCAL_CAPSULE"
    ECHO_DECISION = "ECHO_DECISION"
    STAGE6_LINK = "STAGE6_LINK"


class LinkState(StrEnum):
    LIVE = "LIVE"
    SUSPECT = "SUSPECT"
    REVOKED = "REVOKED"


# A state only ever moves towards more severe; reinstatement restores the recorded prior.
_SEVERITY = {LinkState.LIVE: 0, LinkState.SUSPECT: 1, LinkState.REVOKED: 2}


def stage6_link_detail(stage6_capsule_id: str, verdict_id: str, bucket: str) -> str:
    """The ``detail`` of a ``STAGE6_LINK`` node: ``"<capsule_id>|<verdict_id>|<bucket>"``."""
    for part in (stage6_capsule_id, verdict_id, bucket):
        if not isinstance(part, str) or not part or "|" in part:
            raise ContractError(
                f"a STAGE6_LINK detail part must be a non-empty string without '|': {part!r}"
            )
    return f"{stage6_capsule_id}|{verdict_id}|{bucket}"


@dataclass(frozen=True, slots=True)
class LineageRecord:
    """One node. ``parents`` may name ids this host never saw; they are kept, not invented."""

    node_id: str
    role: NodeRole
    parents: tuple[str, ...]
    state: LinkState
    round_index: int
    # STAGE6_LINK: "<stage6 capsule_id>|<verdict_id>|<bucket>"; ECHO_DECISION: key; else ""
    detail: str

    def __post_init__(self) -> None:
        require_identifier(self.node_id, "LineageRecord.node_id")
        object.__setattr__(self, "role", NodeRole(self.role))
        object.__setattr__(self, "state", LinkState(self.state))
        require_non_negative_int(self.round_index, "LineageRecord.round_index")
        parents = tuple(self.parents)
        if len(parents) > MAX_PARENTS_PER_NODE:
            raise ContractError(f"a lineage node names at most {MAX_PARENTS_PER_NODE} parents")
        if len(set(parents)) != len(parents) or self.node_id in parents:
            raise ContractError("lineage parents must be distinct and must not include the node")
        for parent in parents:
            require_identifier(parent, "LineageRecord.parents[]")
        object.__setattr__(self, "parents", parents)
        if not isinstance(self.detail, str):
            raise ContractError("LineageRecord.detail must be a string")
        if self.role is NodeRole.STAGE6_LINK and self.detail.count("|") != 2:
            raise ContractError("a STAGE6_LINK detail is '<capsule_id>|<verdict_id>|<bucket>'")
        if self.role in (NodeRole.FOREIGN_CAPSULE, NodeRole.LOCAL_CAPSULE) and self.detail:
            raise ContractError("capsule nodes carry no detail")

    def stage6_capsule_id(self) -> str | None:
        """The Stage 6 capsule this link names, or None for any other role."""
        if self.role is not NodeRole.STAGE6_LINK:
            return None
        return self.detail.split("|", 1)[0]


def _record_bytes(record: LineageRecord) -> int:
    return (
        sys.getsizeof(record)
        + sys.getsizeof(record.node_id)
        + sys.getsizeof(record.parents)
        + sum(sys.getsizeof(p) + 8 for p in record.parents)
        + sys.getsizeof(record.detail)
        + _SLOT_BYTES
    )


class CrossHostLineageDAG:
    """ORPH-F15. Append-only lineage of foreign and local knowledge, bounded, never guessing."""

    def __init__(self, *, max_nodes: int = MAX_LINEAGE_NODES) -> None:
        if isinstance(max_nodes, bool) or not isinstance(max_nodes, int) or max_nodes < 1:
            raise ContractError("max_nodes must be a positive int")
        self._max = max_nodes
        self._nodes: OrderedDict[str, LineageRecord] = OrderedDict()  # insertion order = age
        # parent id -> ids of PRESENT children. Indexed even for an unknown parent, so a
        # parent that arrives after its child still finds it; emptied sets are dropped.
        self._children: dict[str, set[str]] = {}
        self._bytes = 0
        self._unresolved = 0
        self._tombstones = 0
        self._refused = 0
        self._duplicates = 0
        self._digest: str | None = None

    # --- writes ----------------------------------------------------------------

    def add(self, record: LineageRecord) -> None:
        """Append ``record``. Unknown parents are counted, never invented; a full DAG evicts
        its oldest evictable leaf, or refuses the newcomer (counted) if none is evictable."""
        if not isinstance(record, LineageRecord):
            raise ContractError("CrossHostLineageDAG.add takes a LineageRecord")
        if record.node_id in self._nodes:
            self._duplicates += 1  # append-only: an id is never overwritten
            return
        if len(self._nodes) >= self._max and not self._evict_one():
            self._refused += 1
            return
        self._unresolved += sum(1 for p in record.parents if p not in self._nodes)
        self._nodes[record.node_id] = record
        for parent in record.parents:
            self._children.setdefault(parent, set()).add(record.node_id)
        self._bytes += _record_bytes(record)
        self._digest = None

    def set_state(self, node_ids: Iterable[str], state: LinkState) -> None:
        """Set ``state`` on every PRESENT id; unknown ids are ignored (nothing is invented)."""
        new = LinkState(state)
        for node_id in node_ids:
            record = self._nodes.get(node_id)
            if record is None or record.state is new:
                continue
            self._nodes[node_id] = LineageRecord(
                node_id=record.node_id, role=record.role, parents=record.parents, state=new,
                round_index=record.round_index, detail=record.detail,
            )
            self._digest = None

    def _evictable(self, record: LineageRecord) -> bool:
        if self._children.get(record.node_id):
            return False  # not a leaf
        return not (record.role is NodeRole.STAGE6_LINK and record.state is LinkState.LIVE)

    def _evict_one(self) -> bool:
        victim = next((r for r in self._nodes.values() if self._evictable(r)), None)
        if victim is None:
            return False
        del self._nodes[victim.node_id]
        for parent in victim.parents:
            siblings = self._children.get(parent)
            if siblings is not None:
                siblings.discard(victim.node_id)
                if not siblings:
                    del self._children[parent]
        self._bytes -= _record_bytes(victim)
        self._tombstones += 1
        self._digest = None
        return True

    # --- reads -----------------------------------------------------------------

    def has(self, node_id: str) -> bool:
        return node_id in self._nodes

    def get(self, node_id: str) -> LineageRecord | None:
        return self._nodes.get(node_id)

    def node_ids(self) -> tuple[str, ...]:
        """Every present node id, sorted (read-only; the gate's "non-descendants changed: 0"
        must look at every node, not a subset it guessed)."""
        return tuple(sorted(self._nodes))

    def __len__(self) -> int:
        return len(self._nodes)

    def descendants(
        self, node_id: str, *, limit: int = MAX_DESCENDANT_WALK
    ) -> tuple[tuple[str, ...], bool]:
        """Present descendants of ``node_id`` in breadth-first order (the node itself
        excluded), and whether the walk stopped at ``limit`` before exhausting them."""
        require_non_negative_int(limit, "limit")
        if node_id not in self._nodes:
            return (), False
        seen: dict[str, None] = {}
        frontier: deque[str] = deque([node_id])
        while frontier:
            current = frontier.popleft()
            for child in sorted(self._children.get(current, ())):
                if child in seen or child == node_id:
                    continue
                if len(seen) >= limit:
                    return tuple(seen), True
                seen[child] = None
                frontier.append(child)
        return tuple(seen), False

    def ancestry_complete(self, node_id: str) -> bool:
        """Every ancestor present (none unknown, none evicted). A walk longer than
        ``MAX_DESCENDANT_WALK`` cannot be proven complete and answers False."""
        if node_id not in self._nodes:
            return False
        seen: set[str] = {node_id}
        frontier: deque[str] = deque([node_id])
        while frontier:
            for parent in self._nodes[frontier.popleft()].parents:
                if parent in seen:
                    continue
                if parent not in self._nodes or len(seen) > MAX_DESCENDANT_WALK:
                    return False
                seen.add(parent)
                frontier.append(parent)
        return True

    def state_digest(self) -> str:
        """``sha256:`` over every present record, sorted by id. Cached until a write."""
        if self._digest is None:
            rows = [
                [r.node_id, r.role.value, list(r.parents), r.state.value, r.round_index, r.detail]
                for _, r in sorted(self._nodes.items())
            ]
            text = json.dumps(rows, separators=(",", ":"), allow_nan=False)
            self._digest = "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()
        return self._digest

    def evictions(self) -> int:
        """Tombstones: nodes evicted to stay within ``max_nodes``."""
        return self._tombstones

    def refused(self) -> int:
        """Newcomers refused because every present node was protected."""
        return self._refused

    def unresolved(self) -> int:
        """Parent references that named a node not present when the child was added."""
        return self._unresolved

    def duplicates(self) -> int:
        return self._duplicates

    def capacity(self) -> int:
        return self._max

    def memory_bytes(self) -> int:
        index = sum(sys.getsizeof(s) + len(s) * 8 + _SLOT_BYTES for s in self._children.values())
        return (
            self._bytes
            + index
            + sys.getsizeof(self._nodes)
            + sys.getsizeof(self._children)
        )


@dataclass(frozen=True, slots=True)
class Revocation:
    """One revocation attempt and its outcome. Refused attempts are recorded too (audit)."""

    revocation_id: str
    target: str
    ground: RevocationGround
    issuer: str  # peer id, or "local"
    accepted: bool
    reason: str
    affected: tuple[str, ...]  # target + descendants marked (empty when refused)
    affected_truncated: bool
    stage6_capsule_ids: tuple[str, ...]  # the targeted Stage 6 set, from STAGE6_LINK details
    prior_digest: str  # DAG state digest before; reinstate restores it

    def __post_init__(self) -> None:
        object.__setattr__(self, "ground", RevocationGround(self.ground))
        if self.reason not in REVOCATION_REASONS:
            raise ContractError(f"unknown revocation reason {self.reason!r}")
        if self.accepted != self.reason.startswith("accepted"):
            raise ContractError("accepted must agree with the reason")
        if not self.accepted and (self.affected or self.stage6_capsule_ids):
            raise ContractError("a refused revocation affects nothing")


@dataclass(frozen=True, slots=True)
class _Applied:
    """What an accepted revocation changed, kept privately so reinstate can undo it."""

    prior_states: tuple[tuple[str, LinkState], ...]
    echo_keys: tuple[str, ...]


class RevocationPlane:
    """ORPH-F16. Judges revocations by the D7.16 authority rules and applies accepted ones."""

    def __init__(
        self,
        *,
        dag: CrossHostLineageDAG,
        owner_of_key: Callable[[str], str | None],
        contributor_of: Callable[[str], str | None],
        local_keys: Callable[[], frozenset[str]],
        echo_suspect: Callable[[Iterable[str], bool], None],
        capacity: int = MAX_REVOCATIONS,
    ) -> None:
        if not isinstance(dag, CrossHostLineageDAG):
            raise ContractError("RevocationPlane needs the CrossHostLineageDAG")
        if isinstance(capacity, bool) or not isinstance(capacity, int) or capacity < 1:
            raise ContractError("capacity must be a positive int")
        self._dag = dag
        self._owner_of_key = owner_of_key
        self._contributor_of = contributor_of
        self._local_keys = local_keys
        self._echo_suspect = echo_suspect
        self._history: deque[Revocation] = deque(maxlen=capacity)
        self._applied: dict[str, _Applied] = {}
        self._reinstated: set[str] = set()
        self._evicted = 0
        self._counter = 0

    # --- foreign -----------------------------------------------------------------

    def submit(
        self, capsule: KnowledgeCapsuleV1, *, sender_peer: str, round_index: int
    ) -> Revocation:
        """A foreign revocation: accepted only as the contributor's own self-retraction."""
        require_non_negative_int(round_index, "round_index")
        reason = self._foreign_refusal(capsule, sender_peer)
        target = getattr(capsule, "revocation_target", None) or ""
        ground = getattr(capsule, "revocation_ground", None) or RevocationGround.SELF_RETRACTION
        source = getattr(capsule, "capsule_id", "")
        if reason is not None:
            return self._refuse(target, ground, sender_peer, reason, round_index, source)
        return self._apply(target, ground, sender_peer, round_index, source)

    def _foreign_refusal(self, capsule: object, sender_peer: str) -> str | None:
        if (
            not isinstance(capsule, KnowledgeCapsuleV1)
            or capsule.knowledge_type is not KnowledgeType.REVOCATION
            or not capsule.revocation_target
            or capsule.revocation_ground is None
        ):
            return "not_a_revocation"
        if capsule.revocation_ground is RevocationGround.LOCAL_EVIDENCE:
            return "foreign_claims_local_ground"
        target = capsule.revocation_target
        record = self._dag.get(target)
        if target in frozenset(self._local_keys()) or (
            record is not None and record.role is NodeRole.LOCAL_CAPSULE
        ):
            return "local_sovereignty"
        if record is None:
            return "unknown_target"
        owner = self._owner_of_key(capsule.key_id)
        foreign = record.role is NodeRole.FOREIGN_CAPSULE
        contributor = self._contributor_of(target) if foreign else None
        claimed = capsule.provenance_commitment.contributor
        if owner is None or contributor is None:
            return "not_contributor"
        if not owner == contributor == sender_peer == claimed:
            return "not_contributor"
        if record.state is not LinkState.LIVE:
            return "already_revoked"
        return None

    # --- local -------------------------------------------------------------------

    def revoke_locally(self, target: str, *, round_index: int) -> Revocation:
        """This host's own evidence (ground LOCAL_EVIDENCE): may revoke any known node."""
        require_non_negative_int(round_index, "round_index")
        record = self._dag.get(target) if isinstance(target, str) else None
        ground = RevocationGround.LOCAL_EVIDENCE
        if record is None:
            return self._refuse(
                str(target), ground, LOCAL_ISSUER, "unknown_target", round_index, ""
            )
        if record.state is LinkState.REVOKED:
            return self._refuse(target, ground, LOCAL_ISSUER, "already_revoked", round_index, "")
        return self._apply(target, ground, LOCAL_ISSUER, round_index, "")

    # --- application and reversal ------------------------------------------------

    def _next_id(self, *parts: object) -> str:
        self._counter += 1
        text = json.dumps([self._counter, *[str(p) for p in parts]], separators=(",", ":"))
        return "rv-" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:32]

    def _refuse(
        self, target: str, ground: RevocationGround, issuer: str, reason: str,
        round_index: int, source: str,
    ) -> Revocation:
        revocation = Revocation(
            revocation_id=self._next_id(issuer, target, ground, reason, round_index, source),
            target=target, ground=ground, issuer=issuer, accepted=False, reason=reason,
            affected=(), affected_truncated=False, stage6_capsule_ids=(),
            prior_digest=self._dag.state_digest(),
        )
        self._remember(revocation, None)
        return revocation

    def _apply(
        self, target: str, ground: RevocationGround, issuer: str, round_index: int, source: str
    ) -> Revocation:
        prior_digest = self._dag.state_digest()
        descendants, truncated = self._dag.descendants(target)
        affected = (target, *descendants)
        records = [self._dag.get(node_id) for node_id in affected]
        present = [r for r in records if r is not None]
        prior = tuple((r.node_id, r.state) for r in present)
        local = ground is RevocationGround.LOCAL_EVIDENCE
        target_state = LinkState.REVOKED if local else LinkState.SUSPECT
        for record in present:
            wanted = target_state if record.node_id == target else LinkState.SUSPECT
            if _SEVERITY[wanted] > _SEVERITY[record.state]:
                self._dag.set_state((record.node_id,), wanted)
        keys = tuple(dict.fromkeys(
            r.detail for r in present if r.role is NodeRole.ECHO_DECISION and r.detail
        ))
        stage6 = tuple(dict.fromkeys(
            cid for r in present if (cid := r.stage6_capsule_id()) is not None
        ))
        if keys:
            self._echo_suspect(keys, True)
        revocation = Revocation(
            revocation_id=self._next_id(issuer, target, ground, round_index, source),
            target=target, ground=ground, issuer=issuer, accepted=True,
            reason="accepted_truncated" if truncated else "accepted",
            affected=affected, affected_truncated=truncated,
            stage6_capsule_ids=stage6, prior_digest=prior_digest,
        )
        self._remember(revocation, _Applied(prior_states=prior, echo_keys=keys))
        return revocation

    def _remember(self, revocation: Revocation, applied: _Applied | None) -> None:
        if len(self._history) == self._history.maxlen:
            oldest = self._history[0]
            self._applied.pop(oldest.revocation_id, None)
            self._reinstated.discard(oldest.revocation_id)
            self._evicted += 1
        self._history.append(revocation)
        if applied is not None:
            self._applied[revocation.revocation_id] = applied

    def reinstate(self, revocation_id: str) -> bool:
        """Undo an accepted revocation. True iff the DAG digest returns to ``prior_digest``
        exactly. Refused (False, nothing changed) for an unknown, refused, evicted or already
        reinstated revocation, or while a LATER active revocation overlaps it (LIFO: undoing
        the earlier one would silently undo part of the later one)."""
        found = [r for r in self._history if r.revocation_id == revocation_id]
        applied = self._applied.get(revocation_id)
        if not found or applied is None or revocation_id in self._reinstated:
            return False
        revocation = found[0]
        if self._overlapped_later(revocation):
            return False
        for node_id, state in applied.prior_states:
            self._dag.set_state((node_id,), state)
        still = self._keys_held_by_others(revocation_id)
        released = tuple(k for k in applied.echo_keys if k not in still)
        if released:
            self._echo_suspect(released, False)
        self._reinstated.add(revocation_id)
        return self._dag.state_digest() == revocation.prior_digest

    def _active(self) -> list[Revocation]:
        return [
            r for r in self._history
            if r.revocation_id in self._applied and r.revocation_id not in self._reinstated
        ]

    def _overlapped_later(self, revocation: Revocation) -> bool:
        active = self._active()
        index = next(i for i, r in enumerate(active) if r.revocation_id == revocation.revocation_id)
        mine = set(revocation.affected)
        return any(mine & set(later.affected) for later in active[index + 1 :])

    def _keys_held_by_others(self, revocation_id: str) -> set[str]:
        return {
            key
            for r in self._active()
            if r.revocation_id != revocation_id
            for key in self._applied[r.revocation_id].echo_keys
        }

    # --- introspection -----------------------------------------------------------

    def history(self) -> tuple[Revocation, ...]:
        return tuple(self._history)

    def counts(self) -> Mapping[str, int]:
        """Reason -> count over the retained history."""
        tally: dict[str, int] = {}
        for revocation in self._history:
            tally[revocation.reason] = tally.get(revocation.reason, 0) + 1
        return tally

    def evictions(self) -> int:
        return self._evicted

    def memory_bytes(self) -> int:
        per = 0
        for revocation in self._history:
            per += sys.getsizeof(revocation) + _SLOT_BYTES
            per += sum(sys.getsizeof(a) + 8 for a in revocation.affected)
            per += sum(sys.getsizeof(s) + 8 for s in revocation.stage6_capsule_ids)
            per += sys.getsizeof(revocation.prior_digest) + sys.getsizeof(revocation.target)
        applied = sum(
            sys.getsizeof(a) + len(a.prior_states) * 72 + len(a.echo_keys) * 64
            for a in self._applied.values()
        )
        return per + applied + sys.getsizeof(self._history) + sys.getsizeof(self._applied)
