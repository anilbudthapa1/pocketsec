"""D4.12a — the sparse causal world graph, and the ``Truncation`` record every bound owes.

Full provenance graphs become enormous (architecture §28), and Stage 4 has to run
beside Stages 1–3 on a 2 GB host. So this graph keeps only evidence with
explanatory, contradictory or discriminating utility, and it is hard bounded at
``MAX_GRAPH_NODES`` / ``MAX_GRAPH_EDGES``.

What this module refuses to do, and why it matters more than what it does:

*   It refuses to drop anything silently. Every node and every edge this graph
    declines, evicts or prunes comes back to the caller as exactly one
    ``Truncation`` naming what was lost and the consequence that went with it. A
    silent drop is a defect: an attacker who can make the system branch without
    limit has a denial of service, and the only way to tell "we bounded it" from
    "we lost the answer" is a record of every loss.
*   It refuses to evict a node carrying a Stage 1 ``MANDATORY_SIGNALS`` signal.
    Stage 1's AOP may never stop collecting those (``observation/policy.py:47``),
    so the graph may never forget them either. If capacity is reached and every
    resident node is mandatory, the *incoming* node is refused — with a
    ``Truncation`` — rather than a mandatory one being thrown away.

``Truncation`` lives here rather than in a shared ``types`` module because every
other Stage 4 package imports it and this is the module that owns the bounds it
records.
"""

from __future__ import annotations

import math
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from pocketsec.stage0.contracts.common import (
    ContractError,
    require_finite_unit_interval,
    require_non_negative_int,
)

__all__ = [
    "MAX_FIELD_TRUNCATIONS",
    "MAX_GRAPH_EDGES",
    "MAX_GRAPH_NODES",
    "RETENTION_THRESHOLD",
    "TRUNCATION_KINDS",
    "SparseWorldGraph",
    "Truncation",
    "WorldGraphNode",
    "append_truncations",
    "total_consequence_lost",
]

#: §28 / the Stage 4 constant table. Hard bounds, not advisory targets.
MAX_GRAPH_NODES: int = 512
MAX_GRAPH_EDGES: int = 1024

#: Distinct loss records one incident's truncation log keeps before it coalesces.
#: The log is per-incident endpoint state and was the one piece of it that grew
#: with every transition: re-adding an unchanged spine re-reported the same refused
#: edges on every step, so a 1397-transition incident held 13895 records (the review's
#: measurement on the pre-fix code, cited not re-run) of which
#: a few hundred were distinct (S4-SEC-01 / S4-RES-01, reproduced by the review).
#: Past the cap each kind gets ONE overflow record that counts what it stands for,
#: so the bound is explicit and a world loss can never hide inside an edge count.
MAX_FIELD_TRUNCATIONS: int = 256

#: Identifier prefix of an overflow record, one per ``Truncation.what`` kind.
_OVERFLOW_PREFIX: str = "truncation_overflow:"

#: θ in §28's retention rule. A node whose every utility is at or below this
#: threshold explains nothing, contradicts nothing and discriminates nothing.
RETENTION_THRESHOLD: float = 0.05

#: The closed vocabulary of things Stage 4 is allowed to admit losing. Closed on
#: purpose: "every loss produced exactly one Truncation" is only checkable if a
#: typo cannot invent a new kind. A package that bounds something not listed here
#: adds its kind HERE, in one place, rather than passing a free string.
TRUNCATION_KINDS = frozenset(
    {
        "world",
        "graph_node",
        "graph_edge",
        "branch",
        "claim",
        "counterfactual",
        "evidence_digest",
        "question",
        "sensor_escalation",
        "shadow_region",
        "tombstone",
    }
)

#: Per-node accounting overhead: three floats, an int, a bool and the dict slot
#: that holds the node, measured once from the live interpreter rather than
#: guessed. See ``SparseWorldGraph.memory_bytes``.
_NODE_SCALAR_BYTES: int = 3 * sys.getsizeof(0.0) + sys.getsizeof(0) + sys.getsizeof(False)
_DICT_SLOT_BYTES: int = 64


def _require_finite_non_negative(value: object, field: str) -> float:
    """Consequence is Φ-weighted and may exceed 1.0, so the unit-interval helper
    cannot be reused here. Non-finite is still refused: a NaN consequence would
    make every comparison in a pruning decision silently false."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ContractError(f"{field} must be a number, got {value!r}")
    numeric = float(value)
    if not math.isfinite(numeric):
        raise ContractError(f"{field} must be finite, got {value!r}")
    if numeric < 0.0:
        raise ContractError(f"{field} must be non-negative, got {numeric!r}")
    return numeric


@dataclass(frozen=True, slots=True)
class Truncation:
    """An explicit, recorded loss. Never a silent drop.

    ``consequence_lost`` is the Φ-scale consequence of whatever went away, so an
    auditor can tell a bound that shed noise from a bound that shed the answer.
    Zero is a legitimate value (an edge whose endpoint had already gone); it is
    not a placeholder for "we did not look".
    """

    what: str
    identifier: str
    reason: str
    consequence_lost: float

    def __post_init__(self) -> None:
        if self.what not in TRUNCATION_KINDS:
            raise ContractError(
                f"Truncation.what must be one of {sorted(TRUNCATION_KINDS)}, got {self.what!r}"
            )
        if not isinstance(self.identifier, str) or not self.identifier:
            raise ContractError("Truncation.identifier must be a non-empty string")
        if not isinstance(self.reason, str) or not self.reason:
            raise ContractError("Truncation.reason must be a non-empty string")
        object.__setattr__(
            self,
            "consequence_lost",
            _require_finite_non_negative(self.consequence_lost, "Truncation.consequence_lost"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "what": self.what,
            "identifier": self.identifier,
            "reason": self.reason,
            "consequence_lost": round(self.consequence_lost, 6),
        }


@dataclass(frozen=True, slots=True)
class WorldGraphNode:
    """One retained piece of causal evidence, keyed on ``CausalNode.signature``.

    Keyed on the signature and not on any identity: Stage 1 builds signatures
    from semantics (``causal/memory.py:47``), so renaming a binary does not move
    a node. That is what makes the rename-invariance stress test meaningful.
    """

    signature: str
    causal_credit: float
    contradiction_value: float
    discrimination_value: float
    mandatory: bool
    state_delta_mask: int

    def __post_init__(self) -> None:
        if not isinstance(self.signature, str) or not self.signature:
            raise ContractError("WorldGraphNode.signature must be a non-empty string")
        for name in ("causal_credit", "contradiction_value", "discrimination_value"):
            require_finite_unit_interval(getattr(self, name), f"WorldGraphNode.{name}")
        if not isinstance(self.mandatory, bool):
            raise ContractError("WorldGraphNode.mandatory must be a bool")
        require_non_negative_int(self.state_delta_mask, "WorldGraphNode.state_delta_mask")

    def retained(self) -> bool:
        """§28's four-clause rule.

        The fourth clause is unconditional: a node bearing a mandatory signal is
        retained no matter how little utility it currently shows, because the
        utility of a mandatory signal is often only visible later.
        """
        if self.mandatory:
            return True
        return (
            self.causal_credit > RETENTION_THRESHOLD
            or self.contradiction_value > RETENTION_THRESHOLD
            or self.discrimination_value > RETENTION_THRESHOLD
        )

    def utility(self) -> float:
        """The eviction key. Mandatory nodes are never eviction candidates, so
        this deliberately does not special-case them."""
        return max(self.causal_credit, self.contradiction_value, self.discrimination_value)

    def to_dict(self) -> dict[str, Any]:
        return {
            "signature": self.signature,
            "causal_credit": round(self.causal_credit, 6),
            "contradiction_value": round(self.contradiction_value, 6),
            "discrimination_value": round(self.discrimination_value, 6),
            "mandatory": self.mandatory,
            "state_delta_mask": self.state_delta_mask,
        }


class SparseWorldGraph:
    """A bounded causal graph over retained evidence.

    Mutable by design — it is per-incident scratch state, not a contract object —
    but every mutation reports its losses, so the immutable field that holds it
    can accumulate an auditable truncation record.
    """

    def __init__(
        self, *, max_nodes: int = MAX_GRAPH_NODES, max_edges: int = MAX_GRAPH_EDGES
    ) -> None:
        if max_nodes < 1 or max_nodes > MAX_GRAPH_NODES:
            raise ContractError(f"max_nodes must be in [1, {MAX_GRAPH_NODES}], got {max_nodes}")
        if max_edges < 1 or max_edges > MAX_GRAPH_EDGES:
            raise ContractError(f"max_edges must be in [1, {MAX_GRAPH_EDGES}], got {max_edges}")
        self.max_nodes = max_nodes
        self.max_edges = max_edges
        self._nodes: dict[str, WorldGraphNode] = {}
        # Insertion-ordered so eviction can break a utility tie by age without a
        # timestamp the node does not carry.
        self._edges: dict[tuple[str, str], None] = {}

    # --- inspection ------------------------------------------------------

    def nodes(self) -> tuple[WorldGraphNode, ...]:
        """Signature-sorted, so two runs over the same evidence compare equal."""
        return tuple(self._nodes[key] for key in sorted(self._nodes))

    def edges(self) -> tuple[tuple[str, str], ...]:
        return tuple(sorted(self._edges))

    def node(self, signature: str) -> WorldGraphNode | None:
        return self._nodes.get(signature)

    def __len__(self) -> int:
        return len(self._nodes)

    def memory_bytes(self) -> int:
        """Measured footprint of what is actually stored, not a nominal figure.

        Signature strings are measured with ``sys.getsizeof`` because they are
        what dominates; the scalar overhead per node and per edge slot was
        measured once at import time from this interpreter.
        """
        total = sys.getsizeof(self._nodes) + sys.getsizeof(self._edges)
        for node in self._nodes.values():
            total += sys.getsizeof(node.signature) + _NODE_SCALAR_BYTES + _DICT_SLOT_BYTES
        for parent, child in self._edges:
            total += sys.getsizeof(parent) + sys.getsizeof(child) + _DICT_SLOT_BYTES
        return total

    # --- mutation, each returning what it cost ---------------------------

    def add(self, node: WorldGraphNode) -> tuple[Truncation, ...]:
        """Insert or update a node. Returns every loss the insert caused."""
        if not node.retained():
            return (
                Truncation(
                    what="graph_node",
                    identifier=node.signature,
                    reason="below_retention_threshold",
                    consequence_lost=node.utility(),
                ),
            )
        if node.signature in self._nodes:
            self._nodes[node.signature] = node
            return ()
        if len(self._nodes) < self.max_nodes:
            self._nodes[node.signature] = node
            return ()
        return self._insert_at_capacity(node)

    def _insert_at_capacity(self, node: WorldGraphNode) -> tuple[Truncation, ...]:
        """Make room by evicting the weakest evictable resident, or refuse."""
        victim = self._weakest_evictable()
        if victim is None:
            return (
                Truncation(
                    what="graph_node",
                    identifier=node.signature,
                    reason="node_capacity_all_resident_nodes_mandatory",
                    consequence_lost=node.utility(),
                ),
            )
        if not node.mandatory and node.utility() <= victim.utility():
            return (
                Truncation(
                    what="graph_node",
                    identifier=node.signature,
                    reason="node_capacity_incoming_weaker_than_resident",
                    consequence_lost=node.utility(),
                ),
            )
        losses = [
            Truncation(
                what="graph_node",
                identifier=victim.signature,
                reason="node_capacity_evicted_lowest_utility",
                consequence_lost=victim.utility(),
            ),
            *self._drop_node(victim.signature),
        ]
        self._nodes[node.signature] = node
        return tuple(losses)

    def _weakest_evictable(self) -> WorldGraphNode | None:
        candidates = [n for n in self._nodes.values() if not n.mandatory]
        if not candidates:
            return None
        return min(candidates, key=lambda n: (n.utility(), n.signature))

    def _drop_node(self, signature: str) -> tuple[Truncation, ...]:
        """Remove a node and every edge it anchored, one Truncation per edge."""
        self._nodes.pop(signature, None)
        orphaned = [e for e in self._edges if signature in e]
        for edge in orphaned:
            del self._edges[edge]
        return tuple(
            Truncation(
                what="graph_edge",
                identifier=f"{parent}->{child}",
                reason="endpoint_pruned",
                consequence_lost=0.0,
            )
            for parent, child in orphaned
        )

    def link(self, parent: str, child: str) -> tuple[Truncation, ...]:
        """Add a causal edge. A missing endpoint or a self-loop is a refusal,
        recorded — not an exception, because the caller is mid-incident."""
        if parent == child:
            return (
                Truncation(
                    what="graph_edge",
                    identifier=f"{parent}->{child}",
                    reason="self_loop_refused",
                    consequence_lost=0.0,
                ),
            )
        missing = [s for s in (parent, child) if s not in self._nodes]
        if missing:
            return (
                Truncation(
                    what="graph_edge",
                    identifier=f"{parent}->{child}",
                    reason=f"endpoint_absent:{','.join(missing)}",
                    consequence_lost=0.0,
                ),
            )
        if (parent, child) in self._edges:
            return ()
        if len(self._edges) < self.max_edges:
            self._edges[(parent, child)] = None
            return ()
        return self._link_at_capacity(parent, child)

    def _link_at_capacity(self, parent: str, child: str) -> tuple[Truncation, ...]:
        """Edges are evicted by the weaker of their endpoints' utilities, oldest
        first on a tie — the same rule as nodes, so an audit reads the same."""
        evictable = [e for e in self._edges if not self._edge_is_mandatory(e)]
        if not evictable:
            return (
                Truncation(
                    what="graph_edge",
                    identifier=f"{parent}->{child}",
                    reason="edge_capacity_all_edges_mandatory",
                    consequence_lost=0.0,
                ),
            )
        victim = min(evictable, key=self._edge_utility)
        del self._edges[victim]
        self._edges[(parent, child)] = None
        return (
            Truncation(
                what="graph_edge",
                identifier=f"{victim[0]}->{victim[1]}",
                reason="edge_capacity_evicted_lowest_utility",
                consequence_lost=self._edge_utility(victim)[0],
            ),
        )

    def _edge_is_mandatory(self, edge: tuple[str, str]) -> bool:
        return all(
            (self._nodes[s].mandatory if s in self._nodes else False) for s in edge
        )

    def _edge_utility(self, edge: tuple[str, str]) -> tuple[float, str, str]:
        utilities = [self._nodes[s].utility() for s in edge if s in self._nodes]
        return (min(utilities) if utilities else 0.0, edge[0], edge[1])

    def prune(self) -> tuple[Truncation, ...]:
        """Drop every node §28 no longer retains, plus the edges that go with it."""
        losses: list[Truncation] = []
        for node in sorted(self._nodes.values(), key=lambda n: n.signature):
            if node.retained():
                continue
            losses.append(
                Truncation(
                    what="graph_node",
                    identifier=node.signature,
                    reason="pruned_below_retention_threshold",
                    consequence_lost=node.utility(),
                )
            )
            losses.extend(self._drop_node(node.signature))
        return tuple(losses)

    def report(self) -> dict[str, Any]:
        return {
            "nodes": len(self._nodes),
            "edges": len(self._edges),
            "max_nodes": self.max_nodes,
            "max_edges": self.max_edges,
            "mandatory_nodes": sum(1 for n in self._nodes.values() if n.mandatory),
            "memory_bytes": self.memory_bytes(),
        }


def total_consequence_lost(truncations: Iterable[Truncation]) -> float:
    """Sum of what a bound cost, for the incident record.

    Exported because every package that bounds something needs the same one-line
    summary, and eight private copies would drift.
    """
    return math.fsum(t.consequence_lost for t in truncations)


def _overflow_count(record: Truncation) -> int:
    """How many losses an overflow record already stands for, read off its reason."""
    _, _, tail = record.reason.partition("reports_folded=")
    return int(tail) if tail.isdigit() else 1


def append_truncations(
    existing: Iterable[Truncation],
    extra: Iterable[Truncation],
    *,
    cap: int = MAX_FIELD_TRUNCATIONS,
) -> tuple[Truncation, ...]:
    """Append losses to an incident's log, deduplicated and bounded.

    Two rules, both about keeping the log a record of *losses* rather than of
    *steps*:

    *   A record equal on ``(what, identifier, reason)`` to one already held is
        the same loss reported again (an unchanged spine re-offering a refused
        edge), so it is not appended twice.
    *   Past ``cap`` distinct records, each further loss REPORT folds into one
        overflow record **per kind**, whose reason carries the number of reports
        folded and whose ``consequence_lost`` is the largest consequence among them.
        Reports, not distinct losses: remembering which losses were folded would be
        the unbounded state this cap exists to avoid, so a loss re-reported after
        the cap counts again and the reason says ``reports_folded`` to match. Per
        kind, so a dropped world is never counted inside a graph-edge overflow; the
        maximum rather than the sum, so the field keeps the Φ-scale meaning.

    The result is bounded by ``cap + len(TRUNCATION_KINDS)`` whatever the input.
    """
    require_non_negative_int(cap, "append_truncations cap")
    records = list(existing)
    seen = {(item.what, item.identifier, item.reason) for item in records}
    distinct = sum(1 for item in records if not item.identifier.startswith(_OVERFLOW_PREFIX))
    for item in extra:
        key = (item.what, item.identifier, item.reason)
        if key in seen:
            continue
        if distinct < cap:
            records.append(item)
            seen.add(key)
            distinct += 1
            continue
        identifier = f"{_OVERFLOW_PREFIX}{item.what}"
        index = next(
            (i for i, row in enumerate(records) if row.identifier == identifier), None
        )
        count = 1 if index is None else _overflow_count(records[index]) + 1
        worst = item.consequence_lost
        if index is not None:
            worst = max(worst, records[index].consequence_lost)
        overflow = Truncation(
            what=item.what,
            identifier=identifier,
            reason=f"truncation_log_full:cap={cap}:reports_folded={count}",
            consequence_lost=worst,
        )
        if index is None:
            records.append(overflow)
        else:
            records[index] = overflow
    return tuple(records)
