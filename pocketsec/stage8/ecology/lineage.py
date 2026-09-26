"""D8.5 / PROM-F06 — the hypothesis lineage DAG: every discovery traces back to an observation.

Architecture §33: ``residual → H1 → H1a/H1b → experiment → H1b2 → discovery → FORGE candidates →
Stage 6 candidate``. This module holds that chain as one node per step, so a gate can walk a
package's ``evidence_lineage`` from the Stage 6 capsule back to the RESIDUAL that started it and
prove nothing was born from nowhere (G8.8).

What it refuses, each refusal counted (never raised, so a bulk writer can report them):

- a node whose parent is unknown — lineage is built root-first, and a child of a node that does
  not exist would be a claim without its history;
- a RESIDUAL node *with* parents (a residual is an observation, the root of every chain), and any
  other node *without* one (a hypothesis, experiment or discovery with no recorded origin is
  exactly what §33 forbids);
- a duplicate id, a self-parent, or more than :data:`MAX_LINEAGE_PARENTS` parents;
- anything past :data:`MAX_LINEAGE_NODES` nodes or :data:`MAX_LINEAGE_EDGES` edges.

What it never does: evict silently. When full it refuses; space is reclaimed only by an explicit
:meth:`HypothesisLineageDAG.collect` naming what to keep, which retains the *complete* ancestor
closure of every kept node (walked without the :data:`MAX_WALK` bound, which applies only to the
read-side walks). Collecting therefore never strands a kept node's history — the Stage 6 trap of
a raw collect that loses the rollback target (MEMORY.md) cannot happen here, because nothing a
kept node descends from is ever removed.

The DAG stores ids and ``sha256:`` digests only: no episode, no genome, no text. It holds no
authority and names nothing in Stage 5 or Stage 6's writers.
"""

from __future__ import annotations

import sys
from collections import deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType

from pocketsec.stage0.contracts.common import ContractError

__all__ = [
    "MAX_LINEAGE_EDGES",
    "MAX_LINEAGE_NODES",
    "MAX_LINEAGE_PARENTS",
    "MAX_NODE_ID_CHARS",
    "MAX_WALK",
    "HypothesisLineageDAG",
    "LineageNode",
    "NodeKind",
]

#: §4.21. Chosen parameters, not measurements.
MAX_LINEAGE_NODES: int = 8192
MAX_LINEAGE_EDGES: int = 16384
MAX_LINEAGE_PARENTS: int = 4
MAX_WALK: int = 256
#: Ids in this stage are short content-derived tokens ("hyp-" + 24 hex, "dp-" + 24 hex, ...).
MAX_NODE_ID_CHARS: int = 128

_DIGEST_PREFIX = "sha256:"
_HEX = frozenset("0123456789abcdef")
_REFUSAL_KEYS: tuple[str, ...] = (
    "refused_full",
    "refused_unknown_parent",
    "refused_duplicate",
    "refused_shape",
)


class NodeKind(StrEnum):
    """One step of the §33 chain, in chain order."""

    RESIDUAL = "residual"
    HYPOTHESIS = "hypothesis"
    EXPERIMENT = "experiment"
    DISCOVERY = "discovery"
    FORGE_CANDIDATE = "forge_candidate"
    STAGE6_CAPSULE = "stage6_capsule"


def _is_digest(value: object) -> bool:
    if not isinstance(value, str) or not value.startswith(_DIGEST_PREFIX):
        return False
    body = value[len(_DIGEST_PREFIX):]
    return len(body) == 64 and not set(body) - _HEX


def _require_node_id(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_NODE_ID_CHARS:
        raise ContractError(f"{name} must be a non-empty id of <= {MAX_NODE_ID_CHARS} chars")
    if not value.isascii() or not value.isprintable() or " " in value:
        raise ContractError(f"{name} must be printable ASCII without spaces, got {value!r}")
    return value


@dataclass(frozen=True, slots=True)
class LineageNode:
    """One lineage step: an id, its kind, the ids it came from, and a digest of its detail.

    ``detail_digest`` is the ``sha256:`` of whatever the node stands for (a residual cluster, a
    genome's canonical bytes, a package). The DAG keeps the digest, never the thing.
    """

    node_id: str
    kind: NodeKind
    parents: tuple[str, ...]
    detail_digest: str

    def __post_init__(self) -> None:
        _require_node_id(self.node_id, "LineageNode.node_id")
        if not isinstance(self.kind, NodeKind):
            raise ContractError(f"LineageNode.kind must be a NodeKind, got {self.kind!r}")
        if not isinstance(self.parents, tuple):
            raise ContractError("LineageNode.parents must be a tuple")
        for index, parent in enumerate(self.parents):
            _require_node_id(parent, f"LineageNode.parents[{index}]")
        if not _is_digest(self.detail_digest):
            raise ContractError(f"detail_digest must be sha256:<64 hex>, got {self.detail_digest!r}")


class HypothesisLineageDAG:
    """PROM-F06 (lineage half). A bounded, append-only DAG of §33 chain steps.

    ``add`` answers ``False`` and counts the reason instead of raising, so a writer that feeds
    many nodes can report every refusal. Nothing is ever removed except by :meth:`collect`.
    """

    __slots__ = ("_nodes", "_edges", "_max_nodes", "_max_edges", "_counters")

    def __init__(
        self, *, max_nodes: int = MAX_LINEAGE_NODES, max_edges: int = MAX_LINEAGE_EDGES
    ) -> None:
        for name, value in (("max_nodes", max_nodes), ("max_edges", max_edges)):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ContractError(f"HypothesisLineageDAG.{name} must be an int >= 1, got {value!r}")
        self._nodes: dict[str, LineageNode] = {}
        self._edges = 0
        self._max_nodes = max_nodes
        self._max_edges = max_edges
        self._counters: dict[str, int] = {
            "added": 0,
            "collected": 0,
            "collections": 0,
            "keep_unknown": 0,
            "walks_truncated": 0,
            **{key: 0 for key in _REFUSAL_KEYS},
        }

    # --- writes ------------------------------------------------------------------

    def add(self, node: LineageNode) -> bool:
        """Append ``node``; ``False`` (counted) when full, malformed for its kind, or orphaned."""
        if not isinstance(node, LineageNode):
            raise ContractError(f"HypothesisLineageDAG.add takes a LineageNode, got {type(node)}")
        reason = self._refusal(node)
        if reason is not None:
            self._counters[reason] += 1
            return False
        self._nodes[node.node_id] = node
        self._edges += len(node.parents)
        self._counters["added"] += 1
        return True

    def _refusal(self, node: LineageNode) -> str | None:
        parents = node.parents
        shape_ok = (
            len(parents) <= MAX_LINEAGE_PARENTS
            and len(set(parents)) == len(parents)
            and node.node_id not in parents
            # A residual is an observation: the root. Everything else must say where it came from.
            and (not parents) == (node.kind is NodeKind.RESIDUAL)
        )
        if not shape_ok:
            return "refused_shape"
        if node.node_id in self._nodes:
            return "refused_duplicate"
        if any(parent not in self._nodes for parent in parents):
            return "refused_unknown_parent"
        if len(self._nodes) >= self._max_nodes or self._edges + len(parents) > self._max_edges:
            return "refused_full"
        return None

    def collect(self, keep: Iterable[str]) -> int:
        """Remove every node that is neither in ``keep`` nor an ancestor of one; return the count.

        Explicit and counted. The closure is walked completely (not bounded by :data:`MAX_WALK`,
        which bounds only reads), so a kept node never loses any part of its history. Ids in
        ``keep`` that are not in the DAG are ignored and counted as ``keep_unknown``.
        """
        roots: list[str] = []
        for node_id in keep:
            if isinstance(node_id, str) and node_id in self._nodes:
                roots.append(node_id)
            else:
                self._counters["keep_unknown"] += 1
        retained = self._closure(roots)
        removed = [node_id for node_id in self._nodes if node_id not in retained]
        for node_id in removed:
            self._edges -= len(self._nodes.pop(node_id).parents)
        self._counters["collected"] += len(removed)
        self._counters["collections"] += 1
        return len(removed)

    def _closure(self, roots: Iterable[str]) -> set[str]:
        # Bounded by the DAG's own size: every node is visited at most once.
        seen: set[str] = set()
        stack = list(roots)
        while stack:
            node_id = stack.pop()
            if node_id in seen:
                continue
            seen.add(node_id)
            stack.extend(parent for parent in self._nodes[node_id].parents if parent not in seen)
        return seen

    # --- reads -------------------------------------------------------------------

    def has(self, node_id: str) -> bool:
        return node_id in self._nodes

    def node(self, node_id: str) -> LineageNode | None:
        return self._nodes.get(node_id)

    def ancestors(self, node_id: str) -> tuple[str, ...]:
        """Breadth-first ancestors of ``node_id`` (nearest first), at most :data:`MAX_WALK`.

        A walk that stops at the bound is counted in ``walks_truncated``; the answer is then a
        prefix of the true ancestor set, never a guess at the rest.
        """
        if node_id not in self._nodes:
            raise ContractError(f"unknown lineage node {node_id!r}")
        found: list[str] = []
        seen = {node_id}
        queue = deque(self._nodes[node_id].parents)
        while queue:
            parent = queue.popleft()
            if parent in seen:
                continue
            if len(found) >= MAX_WALK:
                self._counters["walks_truncated"] += 1
                break
            seen.add(parent)
            found.append(parent)
            queue.extend(self._nodes[parent].parents)
        return tuple(found)

    def path_kinds(self, node_id: str) -> frozenset[NodeKind]:
        """The kinds of ``node_id`` and its (bounded) ancestors: what G8.8 checks a chain holds."""
        kinds = {self._nodes[ancestor].kind for ancestor in self.ancestors(node_id)}
        kinds.add(self._nodes[node_id].kind)
        return frozenset(kinds)

    def stats(self) -> Mapping[str, int]:
        return MappingProxyType(
            {
                **self._counters,
                "nodes": len(self._nodes),
                "edges": self._edges,
                "max_nodes": self._max_nodes,
                "max_edges": self._max_edges,
                "refused": sum(self._counters[key] for key in _REFUSAL_KEYS),
            }
        )

    def memory_bytes(self) -> int:
        """An in-process estimate: the index plus each node's strings and parent tuple."""
        total = sys.getsizeof(self._nodes)
        for node in self._nodes.values():
            total += sys.getsizeof(node) + sys.getsizeof(node.node_id)
            total += sys.getsizeof(node.detail_digest) + sys.getsizeof(node.parents)
        return total
