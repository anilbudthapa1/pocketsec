"""D7.13 / ORPH-F13 — the campaign hypergraph: bounded joins of weak cross-host fragments.

Architecture §16 argues for a *hyper*graph because one campaign hypothesis depends jointly on
several heterogeneous observations: a credential read on one host, an elevation on a second
and an egress on a third mean something together that no pair of them means. This module
holds those observations (:class:`Fragment`, one per ``CAMPAIGN_FRAGMENT`` capsule, each
naming the dependence cluster it came from) and joins them into :class:`Hyperedge` values.
It is the input of the partial-world reconstructor (D7.12); on its own it decides nothing.

How a hyperedge is formed (``build_edges``), and why each rule is there:

* **Interval overlap, never timestamp equality** (§20). Each distinct fragment start ``s``
  anchors the window ``[s - join_window, s]``; the members of an anchor are every live
  fragment whose round interval intersects it. Because intervals have the Helly property,
  the anchors enumerate exactly the maximal groups of fragments that are *pairwise* within
  ``join_window`` rounds of each other (``max(lo) - min(hi) <= join_window`` for every
  pair). Hosts have no shared clock and fragments carry coarse round intervals by design
  (privacy distillation, §6), so equality of anything finer is neither available nor
  meaningful. A consequence worth stating: any two members satisfy
  ``lo_a <= hi_b + join_window``, so no fragment of an earlier chain stage can begin more
  than ``join_window`` rounds after a later-stage fragment ended. That is the coarse
  causal-order constraint §20 asks for, and it holds by construction.
* **Orderable, distinct stages.** Only the five ordered stages
  ``ACCESS < CREDENTIAL < ELEVATION < PERSISTENCE < EGRESS`` take part; ``OTHER`` says nothing
  about a chain and is never joined. An edge keeps at most one fragment per
  ``(cluster, stage)`` (the rarest, then the earliest, then the smallest id), so one cluster
  repeating itself cannot inflate an edge, and the edge's ``stages`` are its distinct stages
  in chain order. An edge needs at least two stages.
* **At least two clusters.** A "campaign" seen by one dependence cluster is one witness.
* **Maximal edges only.** Within one build an edge that is a subset of another is dropped,
  so a flood of anchors over the same fragments yields one edge, not one per anchor.
* ``weight = independence * temporal coherence * mean rarity``: ``independence`` is distinct
  clusters over fragments, ``temporal coherence`` is ``1 / (1 + gap)`` where ``gap`` is how far
  the latest start lies after the earliest end, and ``rarity`` is D7.14's population rarity
  (``0`` when unknown, which makes the weight ``0``: an unknown-rarity edge is not evidence of
  anything unusual). The weight ranks and reports; it gates nothing.

**Control (``enabled=False``).** A pairwise co-occurrence graph: an edge of exactly two
fragments from two clusters whose intervals are within ``join_window`` of each other, with no
stage requirement. It exists so the hypergraph can be ablated (ORPH-F13). A pairwise edge
cannot carry three stages, so a reconstructor that needs three stages finds no world in it;
that is the architecture's §16 argument made measurable, not a defect of the control.

**Bounds, all explicit.** At most ``max_fragments`` fragments: a newcomer to a full graph is
refused (``add_fragment`` returns ``False``) and counted, never admitted by evicting an older
one, so a flood cannot wash out fragments of a slow real campaign. At most ``max_edges``
stored edges: a new edge past the cap is refused and counted, and the build stops generating
candidates (a counted truncation) rather than doing unbounded work it cannot store.
``expire`` removes fragments and edges whose interval ended more than ``expiry_rounds`` ago,
**except** edges named in ``preserved`` (an open incident holds them) and those edges'
fragments; every removal is counted. The software-epoch first-seen table (used by the
falsifier's H1) is bounded at ``max_fragments`` entries with counted LRU eviction.

What this module refuses to do: it never reads raw telemetry (a fragment is already a
distilled, pseudonymous record), never emits a verdict or a ``ThreatPredictionV1``, and never
hands anything to Stage 6. Campaign structure is advisory (spec D7.12).
"""

from __future__ import annotations

import bisect
import hashlib
import sys
from collections import OrderedDict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass

from pocketsec.stage0.contracts.common import (
    ContractError,
    require_finite_unit_interval,
    require_identifier,
    require_non_negative_int,
)
from pocketsec.stage6.resources import WorkMeter
from pocketsec.stage7.capsule.knowledge_capsule import (
    MAX_WINDOW_ROUNDS,
    ChainStage,
    RoleClass,
    VisibilityClass,
)

__all__ = [
    "CAMPAIGN_EXPIRY_ROUNDS",
    "JOIN_WINDOW_ROUNDS",
    "MAX_FRAGMENTS",
    "MAX_HYPEREDGES",
    "STAGE_ORDER",
    "CampaignHypergraph",
    "Fragment",
    "Hyperedge",
    "anchored_members",
    "window_gap",
]

#: §4.23. Chosen parameters, not measurements.
MAX_FRAGMENTS: int = 2048
MAX_HYPEREDGES: int = 512
JOIN_WINDOW_ROUNDS: int = 4
CAMPAIGN_EXPIRY_ROUNDS: int = 32

#: The chain order a hyperedge's stages are sorted by. ``OTHER`` is absent on purpose.
STAGE_ORDER: Mapping[ChainStage, int] = {
    ChainStage.ACCESS: 0,
    ChainStage.CREDENTIAL: 1,
    ChainStage.ELEVATION: 2,
    ChainStage.PERSISTENCE: 3,
    ChainStage.EGRESS: 4,
}

_EDGE_ID_HEX = 24
_SLOT_OVERHEAD_BYTES = 96


def _require_window(value: object, field: str) -> tuple[int, int]:
    if not isinstance(value, tuple) or len(value) != 2:
        raise ContractError(f"{field} must be a (lo, hi) tuple, got {value!r}")
    lo = require_non_negative_int(value[0], f"{field}[0]")
    hi = require_non_negative_int(value[1], f"{field}[1]")
    if lo > hi:
        raise ContractError(f"{field} must have lo <= hi, got {value!r}")
    return lo, hi


def window_gap(windows: Iterable[tuple[int, int]]) -> int:
    """How far the latest start lies after the earliest end; ``0`` when all intervals overlap."""
    items = tuple(windows)
    if not items:
        raise ContractError("window_gap needs at least one window")
    return max(0, max(lo for lo, _ in items) - min(hi for _, hi in items))


@dataclass(frozen=True, slots=True)
class Fragment:
    """One distilled campaign observation from one dependence cluster. Pseudonymous; no raw data."""

    capsule_id: str
    cluster_id: str
    role: RoleClass
    stage: ChainStage
    window: tuple[int, int]
    software_epoch: str
    visibility: VisibilityClass
    rarity: float

    def __post_init__(self) -> None:
        require_identifier(self.capsule_id, "Fragment.capsule_id")
        require_identifier(self.cluster_id, "Fragment.cluster_id")
        require_identifier(self.software_epoch, "Fragment.software_epoch")
        if not isinstance(self.role, RoleClass):
            raise ContractError(f"Fragment.role must be a RoleClass, got {self.role!r}")
        if not isinstance(self.stage, ChainStage):
            raise ContractError(f"Fragment.stage must be a ChainStage, got {self.stage!r}")
        if not isinstance(self.visibility, VisibilityClass):
            raise ContractError(
                f"Fragment.visibility must be a VisibilityClass, got {self.visibility!r}"
            )
        lo, hi = _require_window(self.window, "Fragment.window")
        if hi - lo > MAX_WINDOW_ROUNDS:
            raise ContractError(f"Fragment.window spans {hi - lo} > {MAX_WINDOW_ROUNDS} rounds")
        require_finite_unit_interval(self.rarity, "Fragment.rarity")


@dataclass(frozen=True, slots=True)
class Hyperedge:
    """A joint, temporally compatible multi-cluster observation: candidate structure, no claim."""

    edge_id: str
    fragment_ids: tuple[str, ...]
    stages: tuple[ChainStage, ...]
    clusters: int
    window: tuple[int, int]
    weight: float

    def __post_init__(self) -> None:
        require_identifier(self.edge_id, "Hyperedge.edge_id")
        if len(self.fragment_ids) < 2 or len(set(self.fragment_ids)) != len(self.fragment_ids):
            raise ContractError("Hyperedge.fragment_ids must hold >= 2 distinct ids")
        if tuple(sorted(self.fragment_ids)) != self.fragment_ids:
            raise ContractError("Hyperedge.fragment_ids must be sorted")
        if len(set(self.stages)) != len(self.stages):
            raise ContractError("Hyperedge.stages must be distinct")
        if self.clusters < 1 or self.clusters > len(self.fragment_ids):
            raise ContractError(f"Hyperedge.clusters out of range: {self.clusters}")
        _require_window(self.window, "Hyperedge.window")
        require_finite_unit_interval(self.weight, "Hyperedge.weight")


def _edge_id(fragment_ids: Sequence[str]) -> str:
    digest = hashlib.sha256("|".join(fragment_ids).encode("utf-8")).hexdigest()
    return "he-" + digest[:_EDGE_ID_HEX]


def _select_one_per_cluster_stage(members: Sequence[Fragment]) -> tuple[Fragment, ...]:
    """Keep the rarest (then earliest, then smallest id) fragment per ``(cluster, stage)``."""
    best: dict[tuple[str, ChainStage], Fragment] = {}
    for fragment in members:
        key = (fragment.cluster_id, fragment.stage)
        held = best.get(key)
        rank = (-fragment.rarity, fragment.window[0], fragment.capsule_id)
        if held is None or rank < (-held.rarity, held.window[0], held.capsule_id):
            best[key] = fragment
    return tuple(sorted(best.values(), key=lambda item: item.capsule_id))


def _make_edge(members: Sequence[Fragment]) -> Hyperedge:
    ordered = tuple(sorted(members, key=lambda item: item.capsule_id))
    ids = tuple(item.capsule_id for item in ordered)
    clusters = len({item.cluster_id for item in ordered})
    windows = tuple(item.window for item in ordered)
    independence = clusters / len(ordered)
    coherence = 1.0 / (1.0 + window_gap(windows))
    mean_rarity = sum(item.rarity for item in ordered) / len(ordered)
    stages = tuple(
        sorted({item.stage for item in ordered}, key=lambda stage: STAGE_ORDER.get(stage, 99))
    )
    return Hyperedge(
        edge_id=_edge_id(ids),
        fragment_ids=ids,
        stages=stages,
        clusters=clusters,
        window=(min(lo for lo, _ in windows), max(hi for _, hi in windows)),
        weight=min(1.0, independence * coherence * mean_rarity),
    )


def anchored_members(ordered: Sequence[Fragment], starts: Sequence[int], anchor: int,
              join_window: int) -> list[Fragment]:
    """Fragments (sorted by start) whose interval meets ``[anchor - join_window, anchor]``.

    A window spans at most ``MAX_WINDOW_ROUNDS`` rounds, so every member's start lies in a
    bounded slice found by bisection; the work per anchor does not grow with the store.
    """
    left = bisect.bisect_left(starts, anchor - join_window - MAX_WINDOW_ROUNDS)
    right = bisect.bisect_right(starts, anchor)
    return [item for item in ordered[left:right] if item.window[1] >= anchor - join_window]


def _maximal(candidates: Iterable[frozenset[str]]) -> tuple[frozenset[str], ...]:
    """Drop every candidate that is a subset of a larger (or equal, earlier) one."""
    ordered = sorted(set(candidates), key=lambda item: (-len(item), sorted(item)))
    kept: list[frozenset[str]] = []
    for candidate in ordered:
        if not any(candidate <= held for held in kept):
            kept.append(candidate)
    return tuple(kept)


class CampaignHypergraph:
    """Bounded store of fragments and the hyperedges joining them (see the module docstring)."""

    def __init__(
        self,
        *,
        max_fragments: int = MAX_FRAGMENTS,
        max_edges: int = MAX_HYPEREDGES,
        expiry_rounds: int = CAMPAIGN_EXPIRY_ROUNDS,
        enabled: bool = True,
        meter: WorkMeter | None = None,
    ) -> None:
        for name, value in (("max_fragments", max_fragments), ("max_edges", max_edges)):
            if require_non_negative_int(value, name) < 1:
                raise ContractError(f"{name} must be >= 1, got {value}")
        self._max_fragments = max_fragments
        self._max_edges = max_edges
        self._expiry = require_non_negative_int(expiry_rounds, "expiry_rounds")
        self._enabled = bool(enabled)
        self._meter = meter
        self._fragments: dict[str, Fragment] = {}
        self._edges: dict[str, Hyperedge] = {}
        self._epoch_first: OrderedDict[str, int] = OrderedDict()
        self._counts: dict[str, int] = {
            "fragments_refused_full": 0,
            "fragments_refused_duplicate": 0,
            "edges_refused_full": 0,
            "build_truncations": 0,
            "fragments_expired": 0,
            "edges_expired": 0,
            "epoch_evictions": 0,
        }

    @property
    def enabled(self) -> bool:
        return self._enabled

    # --- fragments and epochs ------------------------------------------------------

    def add_fragment(self, fragment: Fragment) -> bool:
        """Admit ``fragment``; ``False`` means refused (full or duplicate id), and it is counted."""
        if not isinstance(fragment, Fragment):
            raise ContractError(f"add_fragment takes a Fragment, got {type(fragment).__name__}")
        if fragment.capsule_id in self._fragments:
            self._counts["fragments_refused_duplicate"] += 1
            return False
        if len(self._fragments) >= self._max_fragments:
            self._counts["fragments_refused_full"] += 1
            return False
        self._fragments[fragment.capsule_id] = fragment
        self.note_epoch(fragment.software_epoch, fragment.window[0])
        return True

    def note_epoch(self, software_epoch: str, round_index: int) -> None:
        """Record that ``software_epoch`` was seen at ``round_index`` (keeps the earliest round).

        Fragments note their own epochs; a caller with longer history (the fabric, a lab
        replaying population releases) notes established epochs so a fresh-image test (H1)
        is not fooled by a short memory.
        """
        require_identifier(software_epoch, "software_epoch")
        require_non_negative_int(round_index, "round_index")
        held = self._epoch_first.get(software_epoch)
        if held is None:
            if len(self._epoch_first) >= self._max_fragments:
                self._epoch_first.popitem(last=False)
                self._counts["epoch_evictions"] += 1
            self._epoch_first[software_epoch] = round_index
        else:
            self._epoch_first[software_epoch] = min(held, round_index)
            self._epoch_first.move_to_end(software_epoch)

    def epoch_first_seen(self, software_epoch: str) -> int | None:
        """The earliest round ``software_epoch`` was noted, or ``None`` if never (or evicted)."""
        return self._epoch_first.get(software_epoch)

    def fragment(self, capsule_id: str) -> Fragment | None:
        return self._fragments.get(capsule_id)

    def fragments(self) -> tuple[Fragment, ...]:
        return tuple(self._fragments.values())

    def edges(self) -> tuple[Hyperedge, ...]:
        return tuple(self._edges.values())

    # --- edges ---------------------------------------------------------------------

    def _charge(self, units: int) -> None:
        if self._meter is not None and units:
            self._meter.charge(units)

    def _live(self, round_index: int) -> list[Fragment]:
        floor = round_index - self._expiry
        live = [
            fragment
            for fragment in self._fragments.values()
            if fragment.window[0] <= round_index and fragment.window[1] >= floor
        ]
        live.sort(key=lambda item: (item.window[0], item.window[1], item.capsule_id))
        return live

    def _hyper_candidates(self, live: Sequence[Fragment], join_window: int) -> list[frozenset[str]]:
        ordered = [item for item in live if item.stage in STAGE_ORDER]
        starts = [item.window[0] for item in ordered]
        candidates: list[frozenset[str]] = []
        for anchor in sorted(set(starts)):
            members = anchored_members(ordered, starts, anchor, join_window)
            self._charge(len(members))
            chosen = _select_one_per_cluster_stage(members)
            stages = {item.stage for item in chosen}
            if len(stages) < 2 or len({item.cluster_id for item in chosen}) < 2:
                continue
            candidates.append(frozenset(item.capsule_id for item in chosen))
        return candidates

    def _pairwise_candidates(
        self, live: Sequence[Fragment], join_window: int
    ) -> list[frozenset[str]]:
        ordered = [item for item in live if item.stage in STAGE_ORDER]
        starts = [item.window[0] for item in ordered]
        candidates: list[frozenset[str]] = []
        # A build can never store more than max_edges edges, so generating more pairs than
        # that is work with no destination; stop and count the truncation instead.
        budget = self._max_edges
        for index, first in enumerate(ordered):
            right = bisect.bisect_right(starts, first.window[1] + join_window)
            for second in ordered[index + 1 : right]:
                self._charge(1)
                if second.cluster_id == first.cluster_id:
                    continue
                if window_gap((first.window, second.window)) > join_window:
                    continue
                candidates.append(frozenset((first.capsule_id, second.capsule_id)))
                if len(candidates) > budget:
                    self._counts["build_truncations"] += 1
                    return candidates
        return candidates

    def build_edges(
        self, *, round_index: int, join_window: int = JOIN_WINDOW_ROUNDS
    ) -> tuple[Hyperedge, ...]:
        """Join the live fragments; returns every edge this build derived that is stored.

        New edges past ``max_edges`` are refused and counted; already-stored edges stay.
        """
        require_non_negative_int(round_index, "round_index")
        require_non_negative_int(join_window, "join_window")
        live = self._live(round_index)
        if self._enabled:
            candidates = _maximal(self._hyper_candidates(live, join_window))
        else:
            pairs = set(self._pairwise_candidates(live, join_window))
            candidates = tuple(sorted(pairs, key=sorted))
        built: list[Hyperedge] = []
        for candidate in candidates:
            members = [self._fragments[capsule_id] for capsule_id in sorted(candidate)]
            edge = _make_edge(members)
            if edge.edge_id not in self._edges:
                if len(self._edges) >= self._max_edges:
                    self._counts["edges_refused_full"] += 1
                    continue
                self._edges[edge.edge_id] = edge
            built.append(edge)
        return tuple(built)

    # --- expiry and accounting -----------------------------------------------------

    def expire(self, *, round_index: int, preserved: frozenset[str] = frozenset()) -> int:
        """Remove stale edges and fragments; edges in ``preserved`` (and their fragments) stay."""
        require_non_negative_int(round_index, "round_index")
        floor = round_index - self._expiry
        stale_edges = [
            edge_id
            for edge_id, edge in self._edges.items()
            if edge.window[1] < floor and edge_id not in preserved
        ]
        for edge_id in stale_edges:
            del self._edges[edge_id]
        held = {
            capsule_id
            for edge_id in preserved
            if edge_id in self._edges
            for capsule_id in self._edges[edge_id].fragment_ids
        }
        stale_fragments = [
            capsule_id
            for capsule_id, fragment in self._fragments.items()
            if fragment.window[1] < floor and capsule_id not in held
        ]
        for capsule_id in stale_fragments:
            del self._fragments[capsule_id]
        self._counts["edges_expired"] += len(stale_edges)
        self._counts["fragments_expired"] += len(stale_fragments)
        return len(stale_edges) + len(stale_fragments)

    def evictions(self) -> int:
        """Everything removed by expiry or by the bounded epoch table."""
        counts = self._counts
        return counts["fragments_expired"] + counts["edges_expired"] + counts["epoch_evictions"]

    def refused(self) -> int:
        """Newcomers turned away at a cap (fragments, duplicates, edges)."""
        counts = self._counts
        return (
            counts["fragments_refused_full"]
            + counts["fragments_refused_duplicate"]
            + counts["edges_refused_full"]
        )

    def stats(self) -> Mapping[str, int]:
        return {
            **self._counts,
            "fragments": len(self._fragments),
            "edges": len(self._edges),
            "epochs": len(self._epoch_first),
        }

    def memory_bytes(self) -> int:
        """An upper-bound estimate of what the graph holds, in bytes."""
        fragments = sum(
            sys.getsizeof(item)
            + sys.getsizeof(item.capsule_id)
            + sys.getsizeof(item.cluster_id)
            + sys.getsizeof(item.software_epoch)
            + _SLOT_OVERHEAD_BYTES
            for item in self._fragments.values()
        )
        edges = sum(
            sys.getsizeof(edge) + sys.getsizeof(edge.fragment_ids) + sys.getsizeof(edge.edge_id)
            + 8 * len(edge.fragment_ids) + _SLOT_OVERHEAD_BYTES
            for edge in self._edges.values()
        )
        epochs = sum(sys.getsizeof(key) + 32 for key in self._epoch_first)
        containers = sum(
            sys.getsizeof(item) for item in (self._fragments, self._edges, self._epoch_first)
        )
        return fragments + edges + epochs + containers
