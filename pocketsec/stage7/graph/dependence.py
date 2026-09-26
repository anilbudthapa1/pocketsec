"""D7.8 — the dependence graph: how many *independent* sources stand behind a contribution.

Architecture §9: "ten thousand copies of one poisoned source should remain approximately
one source of evidence, not ten thousand independent confirmations." Identities are free
to mint, so counting them measures nothing. This module groups contributing peers into
**dependence clusters** with a union-find over four typed edges, and ECHO then caps
evidence mass per cluster instead of per identity. The cluster, not the identity, is the
unit of evidence everywhere downstream.

The edges, in the order they are tried (the first that merges is the one counted):

* ``SAME_ROOT`` — two peers declare the same provenance root. Always merges. A declared
  root is a *claim* (ADR-0064): it can join identities, never prove them independent.
* ``NEAR_IDENTICAL`` — the same ``compact_feature_signature`` with byte-identical
  validation summary, falsification summary and source context sketch: a copy or relay.
* ``COMMON_PARENT`` — both contributed a capsule derived from the same parent capsule.
* ``BIRTH_CO_TIMING`` — first seen within one window of ``BIRTH_WINDOW_ROUNDS`` rounds in
  which at least ``BURST_MIN`` peers were born, AND the Jaccard of their
  ``(antibody_key, round)`` contribution sets is ``>= CO_TIMING_JACCARD`` with at least
  ``CO_TIMING_MIN_EVENTS`` shared events. Either half alone never merges.

**There is no "same software image" edge.** Merging every host of one image would erase
the honest independence of a fleet that runs one golden image, which is most fleets.

What this graph cannot do, stated because a test pins each one:

* A forged-root Sybil that staggers its births and jitters its summaries matches no edge
  and is not merged. That is the adaptive gap G7.4 expects to FAIL; only an identity
  authority (asymmetric signatures or attestation, not stdlib) closes it.
* Every edge can be created unilaterally by an attacker (declare a victim's root, relay a
  victim's capsule, cite its parent, mimic its timing), and union-find is transitive. One
  relaying identity can therefore *bridge* honest clusters into one and collapse honest
  independence. This only ever lowers mass (a suppression attack, never an acceptance),
  and :mod:`pocketsec.stage7.graph.sybil` flags such clusters; it is not prevented.
* At fleet boot every honest peer is born in one burst, so ``BIRTH_CO_TIMING`` reduces to
  contribution-set similarity for the whole honest population: honest hosts that send the
  same keys in the same rounds are merged as if they were Sybils.

Bounds. At most ``max_peers`` tracked peers; the graph **never evicts** (evicting would
let a Sybil launder its dependence history by idling). A newcomer past the cap is
refused and counted, and is reported as the one shared ``UNASSESSED_CLUSTER_ID`` with
independence 0.0: a peer the graph cannot track cannot be vouched for, and giving each
refused newcomer its own singleton cluster would hand a flood one full vote per identity.
Per peer: ``max_history`` contribution events (oldest dropped, counted),
``max_edges_per_peer`` recorded edges (the merge still happens; only the audit record is
dropped, counted), ``MAX_ROOTS_PER_PEER`` declared roots. Every index is keyed on events
held in some peer's bounded history, so it is bounded by construction.
"""

from __future__ import annotations

import hashlib
import sys
from collections import deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING

from pocketsec.stage0.contracts.common import (
    ContractError,
    require_identifier,
    require_non_negative_int,
)
from pocketsec.stage6.resources import WorkMeter

if TYPE_CHECKING:
    from pocketsec.stage7.capsule.knowledge_capsule import KnowledgeCapsuleV1
    from pocketsec.stage7.identity.peer import PeerIdentity

__all__ = [
    "BIRTH_WINDOW_ROUNDS",
    "BURST_MIN",
    "CO_TIMING_JACCARD",
    "CO_TIMING_MIN_EVENTS",
    "MAX_CONTRIBUTION_HISTORY_PER_PEER",
    "MAX_EDGES_PER_PEER",
    "MAX_GRAPH_PEERS",
    "MAX_ROOTS_PER_PEER",
    "UNASSESSED_CLUSTER_ID",
    "ClusterSummary",
    "DependenceEdge",
    "DependenceGraph",
    "EdgeKind",
    "cluster_id_for",
]

#: §4.23. Chosen parameters, not measurements.
MAX_GRAPH_PEERS: int = 1024
MAX_EDGES_PER_PEER: int = 32
MAX_CONTRIBUTION_HISTORY_PER_PEER: int = 64
BIRTH_WINDOW_ROUNDS: int = 2
BURST_MIN: int = 8
CO_TIMING_JACCARD: float = 0.8
CO_TIMING_MIN_EVENTS: int = 3
#: Not in §4.23; chosen. Caps the declared roots one identity can index, so a single peer
#: cannot grow the root index without bound by declaring a fresh root per capsule.
MAX_ROOTS_PER_PEER: int = 4


def cluster_id_for(representative: str) -> str:
    """``"cl-" + sha256(representative)[:16]``: a cluster is named by its canonical member."""
    return "cl-" + hashlib.sha256(representative.encode("utf-8")).hexdigest()[:16]


#: ``sys.getsizeof`` of one slotted ``_Event`` (64 on CPython 3.14) plus its deque slot.
_EVENT_OBJECT_BYTES: int = 72

#: The one cluster every untracked (refused or never-observed) peer shares. Its preimage
#: is not a peer id shape, so no real cluster can collide with it.
UNASSESSED_CLUSTER_ID: str = cluster_id_for("stage7:graph:unassessed")


class EdgeKind(StrEnum):
    SAME_ROOT = "SAME_ROOT"
    NEAR_IDENTICAL = "NEAR_IDENTICAL"
    COMMON_PARENT = "COMMON_PARENT"
    BIRTH_CO_TIMING = "BIRTH_CO_TIMING"


@dataclass(frozen=True, slots=True)
class DependenceEdge:
    """One merge that changed the partition: ``a < b`` lexicographically."""

    a: str
    b: str
    kind: EdgeKind
    first_round: int


@dataclass(frozen=True, slots=True)
class ClusterSummary:
    """What :mod:`graph.sybil` needs about one cluster, without reaching into the graph."""

    cluster_id: str
    members: tuple[str, ...]
    declared_roots: tuple[str, ...]
    behaviour_merged: bool   # at least one merge in its history was by a non-SAME_ROOT edge


@dataclass(frozen=True, slots=True)
class _Event:
    key: str                    # antibody key, or "rev:<target>" for a revocation
    round_index: int
    fingerprint: str | None     # NEAR_IDENTICAL identity; None when there is no invariant
    parents: tuple[str, ...]


@dataclass(slots=True)
class _PeerRecord:
    birth_round: int
    roots: list[str] = field(default_factory=list)
    history: deque[_Event] = field(default_factory=deque)
    edge_count: int = 0


def _event_of(capsule: KnowledgeCapsuleV1, round_index: int) -> _Event:
    # Interned: every received capsule carries its own copy of these strings, and a
    # graph at its caps holds 65k events that would otherwise each pay for one.
    parents = tuple(sys.intern(parent) for parent in capsule.parent_capsules)
    signature = capsule.compact_feature_signature
    if not signature:
        return _Event(sys.intern(f"rev:{capsule.revocation_target}"), round_index, None, parents)
    valid = capsule.validation_summary
    falsified = capsule.falsification_summary
    sketch = capsule.source_context_sketch
    material = repr((
        signature,
        (valid.episodes_replayed, valid.true_matches, valid.false_matches),
        (falsified.mutations_tried, falsified.mutations_survived,
         tuple(str(h) for h in falsified.counter_hypotheses)),
        (str(sketch.role), tuple(sketch.family_profile)),
    ))
    fingerprint = hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]
    return _Event(sys.intern(signature), round_index, sys.intern(fingerprint), parents)


#: An index entry is the single holding peer id (count 1, no container: the common case
#: costs one reference) or a dict of holder -> count once a second holding appears.
_Holders = str | dict[str, int]


def _holders(index: Mapping[object, _Holders], key: object) -> tuple[str, ...]:
    held = index.get(key)
    if held is None:
        return ()
    return (held,) if isinstance(held, str) else tuple(held)


def _index_add(index: dict[object, _Holders], key: object, peer_id: str) -> None:
    held = index.get(key)
    if held is None:
        index[key] = peer_id
    elif isinstance(held, str):
        index[key] = {held: 2} if held == peer_id else {held: 1, peer_id: 1}
    else:
        held[peer_id] = held.get(peer_id, 0) + 1


def _index_remove(index: dict[object, _Holders], key: object, peer_id: str) -> None:
    held = index.get(key)
    if held is None:
        return
    if isinstance(held, str):
        if held == peer_id:
            del index[key]
        return
    count = held.get(peer_id)
    if count is None:
        return
    if count > 1:
        held[peer_id] = count - 1
        return
    del held[peer_id]
    if not held:
        del index[key]
    elif len(held) == 1:
        ((only, left),) = held.items()
        if left == 1:
            index[key] = only


class DependenceGraph:
    """Union-find over contributing peers; the canonical member is the smallest peer id.

    ``clustering=False`` is the CONTROL (ORPH-F08 ``dependence_clustering``): only
    ``SAME_ROOT`` merges, i.e. declared roots are trusted as independence. Contribution
    history is still recorded so the two arms carry the same state.
    """

    def __init__(
        self,
        *,
        max_peers: int = MAX_GRAPH_PEERS,
        max_edges_per_peer: int = MAX_EDGES_PER_PEER,
        max_history: int = MAX_CONTRIBUTION_HISTORY_PER_PEER,
        clustering: bool = True,
        meter: WorkMeter | None = None,
    ) -> None:
        for name, value in (("max_peers", max_peers), ("max_edges_per_peer", max_edges_per_peer),
                            ("max_history", max_history)):
            if require_non_negative_int(value, name) < 1:
                raise ContractError(f"{name} must be >= 1, got {value}")
        if not isinstance(clustering, bool):
            raise ContractError(f"clustering must be a bool, got {clustering!r}")
        self._max_peers = max_peers
        self._max_edges = max_edges_per_peer
        self._max_history = max_history
        self._clustering = clustering
        self._meter = meter
        self._peers: dict[str, _PeerRecord] = {}
        self._parent: dict[str, str] = {}
        self._size: dict[str, int] = {}
        self._behaviour: set[str] = set()
        self._root_rep: dict[str, str] = {}
        self._by_fingerprint: dict[object, _Holders] = {}
        self._by_parent: dict[object, _Holders] = {}
        self._by_event: dict[object, _Holders] = {}
        self._births: dict[int, int] = {}
        self._edges: list[DependenceEdge] = []
        self._merges: dict[EdgeKind, int] = {kind: 0 for kind in EdgeKind}
        self._refused = 0
        self._history_dropped = 0
        self._edges_unrecorded = 0
        self._roots_unrecorded = 0

    @property
    def clustering(self) -> bool:
        return self._clustering

    def __len__(self) -> int:
        return len(self._peers)

    # --- the one mutating entry point ------------------------------------------------

    def observe(self, capsule: KnowledgeCapsuleV1, peer: PeerIdentity, *, round_index: int) -> str:
        """Record one contribution, derive its edges, merge, and return the peer's cluster id."""
        require_non_negative_int(round_index, "round_index")
        peer_id = require_identifier(peer.peer_id, "peer.peer_id")
        roots = (require_identifier(peer.provenance_root, "peer.provenance_root"),
                 require_identifier(capsule.provenance_commitment.provenance_root,
                                    "capsule provenance_root"))
        record = self._peers.get(peer_id)
        if record is None and len(self._peers) >= self._max_peers:
            self._charge(1)
            self._refused += 1
            return UNASSESSED_CLUSTER_ID
        event = _event_of(capsule, round_index)
        candidates = self._co_timing_candidates(peer_id, record, event)
        self._charge(1 + len(candidates))
        if record is None:
            record = self._admit(peer_id, round_index)
        for root in dict.fromkeys(roots):
            self._link_root(peer_id, record, root, round_index)
        if self._clustering:
            self._link_holders(peer_id, _holders(self._by_fingerprint, event.fingerprint),
                               EdgeKind.NEAR_IDENTICAL, round_index)
            for parent in event.parents:
                self._link_holders(peer_id, _holders(self._by_parent, parent),
                                   EdgeKind.COMMON_PARENT, round_index)
        self._append(peer_id, record, event)
        if self._clustering:
            for other in candidates:
                if self._find(other) != self._find(peer_id) and self._co_timed(peer_id, other):
                    self._union(peer_id, other, EdgeKind.BIRTH_CO_TIMING, round_index)
        return self.cluster_of(peer_id)

    # --- reads -------------------------------------------------------------------------

    def cluster_of(self, peer_id: str) -> str:
        """The peer's cluster id; an untracked peer is in :data:`UNASSESSED_CLUSTER_ID`."""
        if peer_id not in self._peers:
            return UNASSESSED_CLUSTER_ID
        return cluster_id_for(self._find(peer_id))

    def independence(self, peer_id: str) -> float:
        """``1 / cluster size``; 0.0 for an untracked peer (unassessed is not independent)."""
        if peer_id not in self._peers:
            return 0.0
        return 1.0 / self._size[self._find(peer_id)]

    def cluster_summaries(self) -> tuple[ClusterSummary, ...]:
        groups: dict[str, list[str]] = {}
        for peer_id in self._peers:
            groups.setdefault(self._find(peer_id), []).append(peer_id)
        out = []
        for rep, members in groups.items():
            roots = sorted({root for m in members for root in self._peers[m].roots})
            out.append(ClusterSummary(cluster_id_for(rep), tuple(sorted(members)), tuple(roots),
                                      rep in self._behaviour))
        return tuple(sorted(out, key=lambda summary: summary.cluster_id))

    def clusters(self) -> tuple[tuple[str, tuple[str, ...]], ...]:
        return tuple((s.cluster_id, s.members) for s in self.cluster_summaries())

    def edges(self) -> tuple[DependenceEdge, ...]:
        return tuple(self._edges)

    def merges_by_kind(self) -> Mapping[EdgeKind, int]:
        """Firing counts: merges that changed the partition, by the edge that caused them."""
        return MappingProxyType(dict(self._merges))

    def evictions(self) -> int:
        """Newcomers refused past ``max_peers`` (counted per refused call). Nothing is evicted."""
        return self._refused

    def truncations(self) -> Mapping[str, int]:
        """Every other explicit truncation, counted: what was dropped rather than stored."""
        return MappingProxyType({
            "history_events_dropped": self._history_dropped,
            "edges_unrecorded": self._edges_unrecorded,
            "roots_unrecorded": self._roots_unrecorded,
        })

    def memory_bytes(self) -> int:
        """A ``sys.getsizeof`` estimate of every container and the objects only it holds."""
        total = sum(sys.getsizeof(c) for c in (
            self._peers, self._parent, self._size, self._behaviour, self._root_rep,
            self._by_fingerprint, self._by_parent, self._by_event, self._births,
            self._edges))
        strings: dict[int, int] = {}   # interned strings are shared: count each once
        for peer_id, record in self._peers.items():
            total += sys.getsizeof(peer_id) + 96 + sys.getsizeof(record.history)
            total += sum(sys.getsizeof(root) for root in record.roots)
            for event in record.history:
                total += _EVENT_OBJECT_BYTES + (sys.getsizeof(event.parents) if event.parents else 0)
                for text in (event.key, event.fingerprint, *event.parents):
                    if text is not None:
                        strings[id(text)] = sys.getsizeof(text)
        total += sum(strings.values())
        for index in (self._by_fingerprint, self._by_parent, self._by_event):
            total += sum(sys.getsizeof(held) for held in index.values() if isinstance(held, dict))
            total += sum(sys.getsizeof(key) for key in index if isinstance(key, tuple))
        return total + 96 * len(self._edges)

    # --- internals ---------------------------------------------------------------------

    def _charge(self, units: int) -> None:
        if self._meter is not None:
            self._meter.charge(units)

    def _admit(self, peer_id: str, round_index: int) -> _PeerRecord:
        record = _PeerRecord(birth_round=round_index, history=deque())
        self._peers[peer_id] = record
        self._parent[peer_id] = peer_id
        self._size[peer_id] = 1
        self._births[round_index] = self._births.get(round_index, 0) + 1
        return record

    def _find(self, peer_id: str) -> str:
        parent = self._parent
        while parent[peer_id] != peer_id:
            parent[peer_id] = parent[parent[peer_id]]   # path halving
            peer_id = parent[peer_id]
        return peer_id

    def _union(self, a: str, b: str, kind: EdgeKind, round_index: int) -> bool:
        root_a, root_b = self._find(a), self._find(b)
        if root_a == root_b:
            return False
        # Each root is the smallest member of its set, so the smaller root is the
        # smallest member of the union: the canonical representative stays canonical.
        keep, gone = (root_a, root_b) if root_a < root_b else (root_b, root_a)
        self._parent[gone] = keep
        self._size[keep] += self._size.pop(gone)
        if kind is not EdgeKind.SAME_ROOT or gone in self._behaviour:
            self._behaviour.add(keep)
        self._behaviour.discard(gone)
        self._merges[kind] += 1
        self._record_edge(a, b, kind, round_index)
        return True

    def _record_edge(self, a: str, b: str, kind: EdgeKind, round_index: int) -> None:
        low, high = (a, b) if a < b else (b, a)
        if self._peers[low].edge_count >= self._max_edges or \
                self._peers[high].edge_count >= self._max_edges:
            self._edges_unrecorded += 1
            return
        self._peers[low].edge_count += 1
        self._peers[high].edge_count += 1
        self._edges.append(DependenceEdge(low, high, kind, round_index))

    def _link_root(self, peer_id: str, record: _PeerRecord, root: str, round_index: int) -> None:
        if root not in record.roots:
            if len(record.roots) >= MAX_ROOTS_PER_PEER:
                self._roots_unrecorded += 1
                rep = self._root_rep.get(root)   # still honoured if someone else indexed it
                if rep is not None:
                    self._union(peer_id, rep, EdgeKind.SAME_ROOT, round_index)
                return
            record.roots.append(root)
        rep = self._root_rep.setdefault(root, peer_id)
        if rep != peer_id:
            self._union(peer_id, rep, EdgeKind.SAME_ROOT, round_index)

    def _link_holders(self, peer_id: str, holders: tuple[str, ...],
                      kind: EdgeKind, round_index: int) -> None:
        # Every holder of one index key was merged with the others when it arrived, so
        # one union with any other holder merges with all of them.
        for other in holders:
            if other != peer_id:
                self._union(peer_id, other, kind, round_index)
                return

    def _append(self, peer_id: str, record: _PeerRecord, event: _Event) -> None:
        if len(record.history) >= self._max_history:
            self._unindex(peer_id, record.history.popleft())
            self._history_dropped += 1
        record.history.append(event)
        _index_add(self._by_event, (event.key, event.round_index), peer_id)
        if event.fingerprint is not None:
            _index_add(self._by_fingerprint, event.fingerprint, peer_id)
        for parent in event.parents:
            _index_add(self._by_parent, parent, peer_id)

    def _unindex(self, peer_id: str, event: _Event) -> None:
        _index_remove(self._by_event, (event.key, event.round_index), peer_id)
        if event.fingerprint is not None:
            _index_remove(self._by_fingerprint, event.fingerprint, peer_id)
        for parent in event.parents:
            _index_remove(self._by_parent, parent, peer_id)

    def _co_timing_candidates(self, peer_id: str, record: _PeerRecord | None,
                              event: _Event) -> tuple[str, ...]:
        """Peers sharing at least one ``(key, round)`` event: nobody else can reach Jaccard."""
        if not self._clustering:
            return ()
        held = 1 + (len(record.history) if record is not None else 0)
        if held < CO_TIMING_MIN_EVENTS:
            return ()
        events: Iterable[_Event] = (record.history if record is not None else ())
        # A peer already in this peer's cluster cannot change the partition, so it is not
        # a candidate: once a burst has merged, each further contribution costs O(1)
        # comparisons instead of one per burst member.
        own = self._find(peer_id) if record is not None else None
        birth = record.birth_round if record is not None else event.round_index
        seen: dict[str, None] = {}
        for item in (*events, event):
            for other in _holders(self._by_event, (item.key, item.round_index)):
                if other == peer_id or other in seen or self._find(other) == own:
                    continue
                # Not co-born means _co_timed can never hold: not worth paying to compare.
                if abs(self._peers[other].birth_round - birth) < BIRTH_WINDOW_ROUNDS:
                    seen[other] = None
        return tuple(seen)

    def _co_timed(self, a: str, b: str) -> bool:
        birth_a, birth_b = self._peers[a].birth_round, self._peers[b].birth_round
        if abs(birth_a - birth_b) >= BIRTH_WINDOW_ROUNDS:
            return False
        if self._burst_size(birth_a, birth_b) < BURST_MIN:
            return False
        set_a = {(e.key, e.round_index) for e in self._peers[a].history}
        set_b = {(e.key, e.round_index) for e in self._peers[b].history}
        shared = len(set_a & set_b)
        if shared < CO_TIMING_MIN_EVENTS:
            return False
        return shared / len(set_a | set_b) >= CO_TIMING_JACCARD

    def _burst_size(self, birth_a: int, birth_b: int) -> int:
        """Most births in any ``BIRTH_WINDOW_ROUNDS``-round window that contains both births."""
        low, high = min(birth_a, birth_b), max(birth_a, birth_b)
        best = 0
        for start in range(max(0, high - BIRTH_WINDOW_ROUNDS + 1), low + 1):
            count = sum(self._births.get(r, 0) for r in range(start, start + BIRTH_WINDOW_ROUNDS))
            best = max(best, count)
        return best

