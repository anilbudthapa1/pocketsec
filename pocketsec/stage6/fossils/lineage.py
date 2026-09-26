"""D6.10 / HEL-F13 — the Knowledge Lineage DAG: why every trusted item is trusted.

Architecture §16: *a learned fact without lineage is not trusted knowledge.* This module
is the record that makes that sentence checkable. Every capsule the gateway admits,
every verdict it issues, every candidate the chamber builds, every conservation, shadow
and canary report, every promotion, rollback, fossil and rejection is a node; every
edge carries all six fields the architecture names (reason, evidence, tests, parent
versions, transformation, gate result) and a digest over them and over both endpoint
node digests, so a single altered field anywhere is found by :meth:`verify` (S6X-42).

What it refuses, and why each refusal exists:

* **An unknown parent** (:class:`LineageError`). A node may only descend from nodes this
  DAG already holds; only ``GENESIS`` has none. A lineage that can cite a parent it
  never recorded is a lineage that can be written after the fact.
* **A cycle or a duplicate id.** Nodes are append-only and never rewritten; a second
  node under an existing id would silently re-parent everything below it.
* **A caller-minted ``TOMBSTONE``.** Tombstones are the one place
  :meth:`lineage_complete` accepts a capsule id without a live ``CAPSULE`` node, so a
  tombstone a caller could mint would be a lineage-forgery primitive. Only
  :meth:`collect` creates one.
* **Growth past its caps.** ``max_nodes`` / ``max_edges`` refuse the newcomer with
  :class:`LineageCapacityError` rather than evicting history nobody chose to fold.
  Room is made only by :meth:`collect`, which folds nodes **no live item and no pinned
  fossil reaches** into a single bounded tombstone. Live lineage therefore stays
  complete (collection never folds anything a live item's completeness depends on) and
  the DAG stays bounded (live items are capped, and each cites at most
  ``MAX_ITEM_CAPSULE_REFS`` capsules).

The DAG holds digests and short strings only — never evidence content, never a
feature vector. It changes no detection outcome and has no path to Stage 5.
"""

from __future__ import annotations

import hashlib
import json
from collections import deque
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import StrEnum

from pocketsec.stage0.contracts.common import digest_of_bytes, require_identifier
from pocketsec.stage6.memory.semantic import (
    GENESIS_CANDIDATE_ID,
    ItemKind,
    KnowledgeItem,
    LineageError,
)

__all__ = [
    "GATE_PASS",
    "GENESIS_CANDIDATE_ID",
    "MAX_LINEAGE_EDGES",
    "MAX_LINEAGE_NODES",
    "MAX_TOMBSTONE_IDS",
    "KnowledgeLineageDAG",
    "LineageCapacityError",
    "LineageEdge",
    "LineageError",
    "LineageNode",
    "LineageStats",
    "NodeKind",
    "edge_digest",
]

#: §4.21. Chosen parameters, not measurements.
MAX_LINEAGE_NODES: int = 8192
#: Gateway verdict edges that REFUSE a capsule; a capsule with only these is not admitted.
_REFUSING_VERDICTS = frozenset({"FAIL:DISCARD", "FAIL:HOSTILE_SUSPECT"})
MAX_LINEAGE_EDGES: int = 16384
MAX_TOMBSTONE_IDS: int = 1024

GATE_PASS: str = "PASS"
_GATE_FAIL_PREFIX = "FAIL:"

#: How far :meth:`KnowledgeLineageDAG.lineage_complete` searches below a candidate for its
#: PROMOTION. The controller records PROMOTION as a direct child of CANDIDATE, so 8 is
#: generous; the bound exists so a hostile DAG shape cannot make a load-time check unbounded.
_PROMOTION_SEARCH_DEPTH = 8

# Accounting constants for memory_bytes(), matching stage2's estimate style.
_SLOT_BYTES = 8
_NODE_OVERHEAD = 5 * _SLOT_BYTES
_EDGE_OVERHEAD = 9 * _SLOT_BYTES


class LineageCapacityError(LineageError):
    """The DAG is at its cap. The caller must :meth:`KnowledgeLineageDAG.collect` first."""


class NodeKind(StrEnum):
    """Every kind of event that can stand in a trusted item's ancestry."""

    GENESIS = "GENESIS"
    CAPSULE = "CAPSULE"
    VERDICT = "VERDICT"
    CANDIDATE = "CANDIDATE"
    CONSERVATION = "CONSERVATION"
    SHADOW = "SHADOW"
    CANARY = "CANARY"
    PROMOTION = "PROMOTION"
    ROLLBACK = "ROLLBACK"
    FOSSIL = "FOSSIL"
    REJECTION = "REJECTION"
    TOMBSTONE = "TOMBSTONE"


@dataclass(frozen=True, slots=True)
class LineageNode:
    """One event. ``digest`` is the content digest of the thing the node stands for."""

    node_id: str
    kind: NodeKind
    digest: str
    created_sequence: int
    detail: str

    def __post_init__(self) -> None:
        require_identifier(self.node_id, "LineageNode.node_id")
        object.__setattr__(self, "kind", NodeKind(self.kind))
        if not isinstance(self.digest, str) or not self.digest:
            raise LineageError("LineageNode.digest must be a non-empty string")
        if not isinstance(self.created_sequence, int) or self.created_sequence < 0:
            raise LineageError("LineageNode.created_sequence must be a non-negative int")
        if not isinstance(self.detail, str):
            raise LineageError("LineageNode.detail must be a string")


def edge_digest(
    *,
    parent_digest: str,
    child_digest: str,
    reason: str,
    evidence: Sequence[str],
    tests: Sequence[str],
    parent_versions: Sequence[str],
    transformation: str,
    gate_result: str,
) -> str:
    """sha256 over both endpoint node digests and the six architecture §16 fields.

    Canonical JSON with sorted keys, so field order in the caller never changes the digest
    and a change to any one field always does.
    """
    payload = {
        "child": child_digest,
        "evidence": list(evidence),
        "gate_result": gate_result,
        "parent": parent_digest,
        "parent_versions": list(parent_versions),
        "reason": reason,
        "tests": list(tests),
        "transformation": transformation,
    }
    return digest_of_bytes(json.dumps(payload, sort_keys=True, allow_nan=False).encode("utf-8"))


@dataclass(frozen=True, slots=True)
class LineageEdge:
    """Architecture §16: every edge stores all six fields, plus a digest binding them."""

    parent: str
    child: str
    reason: str
    evidence: tuple[str, ...]
    tests: tuple[str, ...]
    parent_versions: tuple[str, ...]
    transformation: str
    gate_result: str
    edge_digest: str

    @property
    def edge_id(self) -> str:
        return f"{self.parent}->{self.child}"


@dataclass(frozen=True, slots=True)
class LineageStats:
    nodes: int
    edges: int
    tombstone_ids: int
    folded_total: int
    tombstone_ids_dropped: int
    collections: int
    refused: int
    memory_bytes: int


def _string_tuple(values: Iterable[str], *, field: str) -> tuple[str, ...]:
    result = tuple(values)
    for value in result:
        if not isinstance(value, str) or not value:
            raise LineageError(f"{field} must hold non-empty strings, got {value!r}")
    return result


def _check_gate_result(gate_result: str) -> None:
    if gate_result == GATE_PASS:
        return
    if isinstance(gate_result, str) and gate_result.startswith(_GATE_FAIL_PREFIX):
        if len(gate_result) > len(_GATE_FAIL_PREFIX):
            return
    raise LineageError(
        f"gate_result must be {GATE_PASS!r} or 'FAIL:<check ids>', got {gate_result!r}"
    )


class KnowledgeLineageDAG:
    """The bounded, append-only, tamper-evident record of how knowledge became trusted."""

    def __init__(
        self, *, max_nodes: int = MAX_LINEAGE_NODES, max_edges: int = MAX_LINEAGE_EDGES
    ) -> None:
        if max_nodes < 2 or max_edges < 1:
            raise ValueError("a lineage DAG needs room for at least a genesis and one edge")
        self._max_nodes = max_nodes
        self._max_edges = max_edges
        self._nodes: dict[str, LineageNode] = {}
        self._parents: dict[str, tuple[str, ...]] = {}
        self._children: dict[str, list[str]] = {}
        self._edges: dict[tuple[str, str], LineageEdge] = {}
        # At most one tombstone node exists at a time; its folded id set lives here.
        self._tombstone_id: str | None = None
        self._tombstone_ids: frozenset[str] = frozenset()
        # The subset of folded ids that were CAPSULE nodes: kept first when the cap bites,
        # because they are the ids lineage_complete() consults.
        self._tombstone_capsules: frozenset[str] = frozenset()
        self._folded_total = 0
        self._ids_dropped = 0
        self._collections = 0
        self._refused = 0
        self._genesis_threshold: float | None = None

    # --- write side -------------------------------------------------------------

    def update_lineage_dag(
        self,
        *,
        node: LineageNode,
        parents: Sequence[str],
        reason: str,
        evidence: Sequence[str] = (),
        tests: Sequence[str] = (),
        parent_versions: Sequence[str] = (),
        transformation: str = "",
        gate_result: str = GATE_PASS,
    ) -> LineageNode:
        """HEL-F13. Append ``node`` under ``parents``, one fully-populated edge per parent."""
        parent_ids = tuple(parents)
        try:
            self._validate_new_node(node, parent_ids, reason=reason, gate_result=gate_result)
        except LineageError:
            self._refused += 1
            raise
        evidence_t = _string_tuple(evidence, field="evidence")
        tests_t = _string_tuple(tests, field="tests")
        versions_t = _string_tuple(parent_versions, field="parent_versions")
        new_edges = tuple(
            self._make_edge(
                parent_id,
                node,
                reason=reason,
                evidence=evidence_t,
                tests=tests_t,
                parent_versions=versions_t,
                transformation=transformation,
                gate_result=gate_result,
            )
            for parent_id in parent_ids
        )
        self._nodes[node.node_id] = node
        self._parents[node.node_id] = parent_ids
        self._children[node.node_id] = []
        for edge in new_edges:
            self._edges[(edge.parent, edge.child)] = edge
            self._children[edge.parent].append(edge.child)
        return node

    def _validate_new_node(
        self, node: LineageNode, parents: tuple[str, ...], *, reason: str, gate_result: str
    ) -> None:
        if not isinstance(node, LineageNode):
            raise LineageError(f"expected a LineageNode, got {type(node).__name__}")
        if node.kind is NodeKind.TOMBSTONE:
            raise LineageError(
                "TOMBSTONE nodes are minted only by collect(); a caller may not forge one"
            )
        if node.node_id in self._nodes or node.node_id in self._tombstone_ids:
            raise LineageError(f"duplicate node id {node.node_id!r}: lineage is append-only")
        if node.node_id in parents:
            raise LineageError(f"cycle: {node.node_id!r} names itself as a parent")
        if len(set(parents)) != len(parents):
            raise LineageError(f"{node.node_id!r} names a parent twice")
        if node.kind is NodeKind.GENESIS and parents:
            raise LineageError("a GENESIS node has no parents")
        if node.kind is not NodeKind.GENESIS and not parents:
            raise LineageError(
                f"{node.kind} node {node.node_id!r} needs a parent; only GENESIS has none"
            )
        for parent in parents:
            if parent not in self._nodes:
                raise LineageError(f"unknown parent {parent!r} for {node.node_id!r}")
        if not isinstance(reason, str) or not reason:
            raise LineageError("every lineage edge needs a non-empty reason")
        _check_gate_result(gate_result)
        if len(self._nodes) + 1 > self._max_nodes:
            raise LineageCapacityError(
                f"lineage DAG holds {len(self._nodes)} nodes (cap {self._max_nodes})"
            )
        if len(self._edges) + len(parents) > self._max_edges:
            raise LineageCapacityError(
                f"lineage DAG holds {len(self._edges)} edges (cap {self._max_edges})"
            )

    def _make_edge(
        self,
        parent_id: str,
        child: LineageNode,
        *,
        reason: str,
        evidence: tuple[str, ...],
        tests: tuple[str, ...],
        parent_versions: tuple[str, ...],
        transformation: str,
        gate_result: str,
    ) -> LineageEdge:
        digest = edge_digest(
            parent_digest=self._nodes[parent_id].digest,
            child_digest=child.digest,
            reason=reason,
            evidence=evidence,
            tests=tests,
            parent_versions=parent_versions,
            transformation=transformation,
            gate_result=gate_result,
        )
        return LineageEdge(
            parent=parent_id,
            child=child.node_id,
            reason=reason,
            evidence=evidence,
            tests=tests,
            parent_versions=parent_versions,
            transformation=transformation,
            gate_result=gate_result,
            edge_digest=digest,
        )

    # --- read side --------------------------------------------------------------

    def has(self, node_id: str) -> bool:
        return node_id in self._nodes

    def node(self, node_id: str) -> LineageNode | None:
        return self._nodes.get(node_id)

    def parents(self, node_id: str) -> tuple[str, ...]:
        return self._parents.get(node_id, ())

    def children(self, node_id: str) -> tuple[str, ...]:
        return tuple(self._children.get(node_id, ()))

    def edge(self, parent: str, child: str) -> LineageEdge | None:
        return self._edges.get((parent, child))

    def edges(self) -> tuple[LineageEdge, ...]:
        return tuple(self._edges.values())

    def nodes(self) -> tuple[LineageNode, ...]:
        return tuple(self._nodes.values())

    def tombstone_ids(self) -> frozenset[str]:
        """Ids folded by :meth:`collect`; bounded by ``MAX_TOMBSTONE_IDS``."""
        return self._tombstone_ids

    def ancestors(self, node_id: str, *, max_depth: int = 64) -> tuple[str, ...]:
        """Breadth-first ancestors of ``node_id`` (itself excluded), ``max_depth`` levels up."""
        seen: set[str] = {node_id}
        ordered: list[str] = []
        frontier = deque((parent, 1) for parent in self._parents.get(node_id, ()))
        while frontier:
            current, depth = frontier.popleft()
            if current in seen or depth > max_depth:
                continue
            seen.add(current)
            ordered.append(current)
            frontier.extend((parent, depth + 1) for parent in self._parents.get(current, ()))
        return tuple(ordered)

    def _has_descendant_of_kind(self, node_id: str, kind: NodeKind, *, max_depth: int) -> bool:
        seen: set[str] = {node_id}
        frontier = deque((child, 1) for child in self._children.get(node_id, ()))
        while frontier:
            current, depth = frontier.popleft()
            if current in seen or depth > max_depth:
                continue
            seen.add(current)
            if self._nodes[current].kind is kind:
                return True
            frontier.extend((child, depth + 1) for child in self._children.get(current, ()))
        return False

    def capsule_admitted(self, capsule_id: str) -> bool:
        """A CAPSULE node with a VERDICT child that did not refuse it, or a folded capsule
        that was admitted when it was folded.

        A DISCARD (secret-bearing, duplicate, lineage-full) or HOSTILE_SUSPECT verdict is a
        refusal: an item citing such a capsule does not descend from *admitted* evidence
        (review S6-AUTH-06). And a folded id counts only if it was an admitted CAPSULE —
        not any folded id, such as a CANDIDATE or REJECTION node (review F5).
        """
        node = self._nodes.get(capsule_id)
        if node is None:
            return capsule_id in self._tombstone_capsules
        if node.kind is not NodeKind.CAPSULE:
            return False
        return any(
            self._nodes[child].kind is NodeKind.VERDICT
            and self._edges[(capsule_id, child)].gate_result not in _REFUSING_VERDICTS
            for child in self._children[capsule_id]
        )

    def lineage_complete(self, item: KnowledgeItem) -> bool:
        """Whether ``item`` descends, provably, from admitted evidence through a promotion.

        True iff its CANDIDATE node exists and has a PROMOTION descendant, and every
        capsule it cites is a CAPSULE node with a VERDICT child (the gateway issued a
        verdict on it) or was folded into the tombstone. The genesis THRESHOLD passes: it
        predates learning — at the genesis weight only, once one is bound
        (:meth:`bind_genesis_threshold`). Any *other* item claiming genesis fails — genesis
        is not a way to skip provenance. Satisfies ``memory.semantic``'s ``LineageChecker``.
        """
        lineage = item.lineage
        candidate_id = lineage.candidate_id
        if candidate_id == GENESIS_CANDIDATE_ID:
            return item.kind is ItemKind.THRESHOLD and (
                self._genesis_threshold is None or item.weight == self._genesis_threshold)
        candidate = self._nodes.get(candidate_id)
        if candidate is None or candidate.kind is not NodeKind.CANDIDATE:
            return False
        if not self._has_descendant_of_kind(
            candidate_id, NodeKind.PROMOTION, max_depth=_PROMOTION_SEARCH_DEPTH
        ):
            return False
        capsule_ids = tuple(lineage.capsule_ids)
        if not capsule_ids:
            return False
        return all(self.capsule_admitted(capsule_id) for capsule_id in capsule_ids)

    def verify(self) -> tuple[str, ...]:
        """Recompute every edge digest. ``()`` means intact; otherwise the offending edge ids.

        Catches a tampered edge field, a tampered node digest (the edge binds both ends),
        and an edge whose endpoint has vanished.
        """
        offenders: list[str] = []
        for (parent_id, child_id), edge in self._edges.items():
            parent = self._nodes.get(parent_id)
            child = self._nodes.get(child_id)
            if parent is None or child is None:
                offenders.append(f"{parent_id}->{child_id}")
                continue
            if edge.parent != parent_id or edge.child != child_id:
                offenders.append(f"{parent_id}->{child_id}")
                continue
            expected = edge_digest(
                parent_digest=parent.digest,
                child_digest=child.digest,
                reason=edge.reason,
                evidence=edge.evidence,
                tests=edge.tests,
                parent_versions=edge.parent_versions,
                transformation=edge.transformation,
                gate_result=edge.gate_result,
            )
            if expected != edge.edge_digest:
                offenders.append(edge.edge_id)
        return tuple(offenders)

    # --- collection ---------------------------------------------------------------

    def _roots_for(self, items: Sequence[KnowledgeItem], pinned: Sequence[str]) -> set[str]:
        """Every node a live item's completeness, or a pinned fossil, depends on."""
        roots: set[str] = {n.node_id for n in self._nodes.values() if n.kind is NodeKind.GENESIS}
        pinned_set = set(pinned)
        for node in self._nodes.values():
            pinned_fossil = node.kind is NodeKind.FOSSIL and node.digest in pinned_set
            if node.node_id in pinned_set or pinned_fossil:
                roots.add(node.node_id)
        for item in items:
            candidate_id = item.lineage.candidate_id
            if candidate_id in self._nodes:
                roots.add(candidate_id)
                roots.update(self._descendants(candidate_id, max_depth=_PROMOTION_SEARCH_DEPTH))
            for capsule_id in item.lineage.capsule_ids:
                if capsule_id in self._nodes:
                    roots.add(capsule_id)
                    roots.update(self._children[capsule_id])
        return roots

    def _descendants(self, node_id: str, *, max_depth: int) -> tuple[str, ...]:
        seen: set[str] = {node_id}
        frontier = deque((child, 1) for child in self._children.get(node_id, ()))
        found: list[str] = []
        while frontier:
            current, depth = frontier.popleft()
            if current in seen or depth > max_depth:
                continue
            seen.add(current)
            found.append(current)
            frontier.extend((child, depth + 1) for child in self._children.get(current, ()))
        return tuple(found)

    def _closure(self, roots: set[str]) -> set[str]:
        keep: set[str] = set()
        stack = list(roots)
        while stack:
            current = stack.pop()
            if current in keep:
                continue
            keep.add(current)
            stack.extend(self._parents.get(current, ()))
        return keep

    def collect(self, *, live_items: Sequence[KnowledgeItem], pinned_fossils: Sequence[str]) -> int:
        """Fold every node no live item and no pinned fossil reaches into ONE tombstone.

        Kept: all GENESIS nodes, every pinned FOSSIL node, and for each live item its
        CANDIDATE node, that node's descendants (the PROMOTION and its siblings), its
        CAPSULE nodes and their VERDICT children — plus every ancestor of all of those.
        Everything else is folded. Items held inside a pinned fossil are only protected
        through that FOSSIL node's ancestry; a caller that may roll back to such a fossil
        should pass its items in ``live_items`` too, or loading it later fails closed.

        The tombstone's id set is capped at ``MAX_TOMBSTONE_IDS``; capsule ids are kept
        first (they are what :meth:`lineage_complete` consults), newest first, and every
        id that does not fit is counted in ``tombstone_ids_dropped``, failing closed: an
        item citing a dropped id is incomplete. Returns the number of nodes folded.
        """
        keep = self._closure(self._roots_for(live_items, pinned_fossils))
        folded = [node for node_id, node in self._nodes.items() if node_id not in keep]
        if not folded:
            return 0
        folded_real = [n for n in folded if n.kind is not NodeKind.TOMBSTONE]
        if not folded_real:
            return 0
        self._fold(folded)
        self._folded_total += len(folded_real)
        self._collections += 1
        return len(folded_real)

    def _fold(self, folded: Sequence[LineageNode]) -> None:
        folded_ids = {node.node_id for node in folded}
        # Decided before anything is deleted: a capsule's verdicts may fold with it.
        admitted = {n.node_id for n in folded
                    if n.kind is NodeKind.CAPSULE and self.capsule_admitted(n.node_id)}
        for key in [k for k in self._edges if k[0] in folded_ids or k[1] in folded_ids]:
            del self._edges[key]
        for node_id in folded_ids:
            del self._nodes[node_id]
            del self._parents[node_id]
            del self._children[node_id]
        for children in self._children.values():
            children[:] = [child for child in children if child not in folded_ids]
        real = [n for n in folded if n.kind is not NodeKind.TOMBSTONE]
        prior_ids = self._tombstone_ids
        newest_first = sorted(real, key=lambda n: (-n.created_sequence, n.node_id))
        new_capsules = [n.node_id for n in newest_first if n.node_id in admitted]
        new_others = [n.node_id for n in newest_first if n.node_id not in admitted]
        capsules = set(new_capsules) | self._tombstone_capsules
        # Priority when the cap bites: capsule ids (what lineage_complete consults) before
        # anything else, and within each class the newest first — a recent capsule is the
        # likelier to be cited by a fossil that rollback may still load.
        ordered = (
            new_capsules
            + sorted(self._tombstone_capsules)
            + new_others
            + sorted(prior_ids - self._tombstone_capsules)
        )
        kept_ids = ordered[:MAX_TOMBSTONE_IDS]
        self._ids_dropped += len(ordered) - len(kept_ids)
        removed_digests = sorted(n.digest for n in real)
        digest = digest_of_bytes("\n".join(removed_digests + sorted(prior_ids)).encode("utf-8"))
        tombstone_id = "tomb-" + hashlib.sha256(digest.encode("utf-8")).hexdigest()[:24]
        sequence = max((n.created_sequence for n in real), default=0)
        tombstone = LineageNode(
            node_id=tombstone_id,
            kind=NodeKind.TOMBSTONE,
            digest=digest,
            created_sequence=sequence,
            detail=f"folded={len(real)} ids_kept={len(kept_ids)}",
        )
        self._nodes[tombstone_id] = tombstone
        self._parents[tombstone_id] = ()
        self._children[tombstone_id] = []
        self._tombstone_id = tombstone_id
        self._tombstone_ids = frozenset(kept_ids)
        self._tombstone_capsules = frozenset(capsules) & self._tombstone_ids

    # --- accounting -----------------------------------------------------------------

    def memory_bytes(self) -> int:
        """Structural estimate: node and edge slots plus every string they hold."""
        nodes = sum(
            _NODE_OVERHEAD + len(n.node_id) + len(n.digest) + len(n.detail)
            for n in self._nodes.values()
        )
        edges = sum(
            _EDGE_OVERHEAD
            + len(e.reason)
            + len(e.transformation)
            + len(e.gate_result)
            + len(e.edge_digest)
            + sum(len(v) for v in e.evidence + e.tests + e.parent_versions)
            for e in self._edges.values()
        )
        tombstone = sum(len(i) + _SLOT_BYTES for i in self._tombstone_ids)
        return nodes + edges + tombstone

    def bind_genesis_threshold(self, weight: float) -> None:
        """Record, once, the genesis THRESHOLD weight this DAG's trusted history began with.

        After binding, a THRESHOLD claiming genesis provenance passes
        :meth:`lineage_complete` only at exactly that weight: a changed threshold that
        still claims genesis is an item without lineage (review F3 / S6-AUTH-08).
        """
        if self._genesis_threshold is not None and self._genesis_threshold != weight:
            raise LineageError("the genesis threshold is bound once")
        self._genesis_threshold = weight

    def has_room(self, *, nodes: int, edges: int) -> bool:
        """Whether ``nodes`` more nodes and ``edges`` more edges fit under the caps.

        Lets a writer refuse (and count) *before* it starts a multi-node record, instead of
        discovering the cap half way through and raising (review S6-R2).
        """
        return (len(self._nodes) + nodes <= self._max_nodes
                and len(self._edges) + edges <= self._max_edges)

    def stats(self) -> LineageStats:
        return LineageStats(
            nodes=len(self._nodes),
            edges=len(self._edges),
            tombstone_ids=len(self._tombstone_ids),
            folded_total=self._folded_total,
            tombstone_ids_dropped=self._ids_dropped,
            collections=self._collections,
            refused=self._refused,
            memory_bytes=self.memory_bytes(),
        )
