"""D7.12 / ORPH-F11 — the partial-world reconstructor: candidate campaigns from weak fragments.

Architecture §15 calls this "the most ambitious Stage 7 capability": individually weak,
privacy-distilled fragments from several hosts, joined in time and chain order, become a
candidate *distributed world* W*, which is then falsified against coincidence and benign
common causes. This module does the last two steps. The join is the campaign hypergraph
(D7.13); the falsification is the consensus falsifier (D7.15).

A hyperedge becomes a :class:`PartialWorld` when it spans at least ``min_stages`` chain stages
and at least ``min_clusters`` dependence clusters. Its status follows from the falsifier:

* ``SUPPORTED`` iff the surviving explanation is H5 and the capped negative evidence stays
  below ``NEG_EVIDENCE_FLOOR``;
* ``UNRESOLVED`` when negative evidence reaches the floor, or when the falsifier answers
  UNIDENTIFIABLE (``None``);
* ``REJECTED_COMMON_CAUSE`` when a benign hypothesis (H0-H3) explains it;
* ``REJECTED_COLLUSION`` when H4 does;
* ``CANDIDATE`` when the falsifier evaluated nothing (it is disabled).

**Worlds are never deleted.** Negative evidence and falsification move a world between
statuses; the record stays, with its falsification, so a later reader sees what was
believed and why it was not (§43, and the project rule that counterexamples are kept). The
world table is still bounded (``max_worlds``): a newcomer to a full table is **refused and
counted**, never admitted by deleting an older world. The price is stated: a flood of junk
worlds that fills the table would refuse a later real one; ``refused()`` makes that visible,
and hyperedge expiry means a table fills only as fast as the hypergraph's own caps allow.

**Ablation (``falsify=False``).** Every candidate hyperedge becomes SUPPORTED, with no
falsification: the "no falsifier" row of ORPH-F14. The other control, the one the spec pits
the whole reconstructor against, is :func:`count_threshold_join`: any ``k`` fragments from
``k`` clusters inside one window, no chain order, no falsifier.

Partial worlds are **advisory**. They are never bridged to Stage 6, carry no authority and
emit no ``ThreatPredictionV1``: a campaign hypothesis is not a verdict, and novelty is not
maliciousness.
"""

from __future__ import annotations

import hashlib
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum

from pocketsec.stage0.contracts.common import (
    ContractError,
    require_identifier,
    require_non_negative_int,
)
from pocketsec.stage6.resources import WorkMeter
from pocketsec.stage7.campaign.hypergraph import (
    MAX_HYPEREDGES,
    CampaignHypergraph,
    Fragment,
    Hyperedge,
    anchored_members,
)
from pocketsec.stage7.capsule.knowledge_capsule import ChainStage
from pocketsec.stage7.falsifier.consensus import (
    BENIGN_HYPOTHESES,
    MIN_WORLD_CLUSTERS,
    NEG_EVIDENCE_FLOOR,
    ConsensusFalsification,
    ConsensusFalsifier,
    CounterHypothesis,
    HypothesisStatus,
    NegativeClaim,
)

__all__ = [
    "MAX_WORLDS",
    "MIN_WORLD_CLUSTERS",
    "MIN_WORLD_STAGES",
    "PartialWorld",
    "PartialWorldReconstructor",
    "WorldStatus",
    "count_threshold_join",
    "status_of",
]

#: §4.23. Chosen parameters, not measurements. ``MIN_WORLD_CLUSTERS`` is re-exported from
#: the falsifier (H4 uses the same number).
MIN_WORLD_STAGES: int = 3
#: Not in §4.23: the world table needs a named cap like every other store. One world per
#: stored hyperedge is the natural ceiling. Chosen, not measured.
MAX_WORLDS: int = MAX_HYPEREDGES

_WORLD_ID_HEX = 24


class WorldStatus(StrEnum):
    CANDIDATE = "CANDIDATE"
    SUPPORTED = "SUPPORTED"
    UNRESOLVED = "UNRESOLVED"
    REJECTED_COMMON_CAUSE = "REJECTED_COMMON_CAUSE"
    REJECTED_COLLUSION = "REJECTED_COLLUSION"


@dataclass(frozen=True, slots=True)
class PartialWorld:
    """One candidate distributed campaign and what the falsifier made of it. Advisory only."""

    world_id: str
    edge_id: str
    fragment_ids: tuple[str, ...]
    clusters: int
    stages: tuple[ChainStage, ...]
    window: tuple[int, int]
    support: float
    status: WorldStatus
    falsification: ConsensusFalsification | None
    first_supported_round: int | None

    def __post_init__(self) -> None:
        require_identifier(self.world_id, "PartialWorld.world_id")
        require_identifier(self.edge_id, "PartialWorld.edge_id")
        if not isinstance(self.status, WorldStatus):
            raise ContractError(f"PartialWorld.status invalid: {self.status!r}")
        if not self.fragment_ids:
            raise ContractError("PartialWorld.fragment_ids must not be empty")
        if self.falsification is not None and self.falsification.world_id != self.world_id:
            raise ContractError("PartialWorld.falsification belongs to another world")
        if self.status is WorldStatus.SUPPORTED and self.first_supported_round is None:
            raise ContractError("a SUPPORTED world must record first_supported_round")


def status_of(falsification: ConsensusFalsification) -> WorldStatus:
    """The one mapping from a falsification to a world status (module docstring)."""
    if all(test.status is HypothesisStatus.UNEVALUATED for test in falsification.tests):
        return WorldStatus.CANDIDATE
    explanation = falsification.explanation
    if explanation is CounterHypothesis.H5_REAL_CAMPAIGN:
        if falsification.negative_weight >= NEG_EVIDENCE_FLOOR:
            return WorldStatus.UNRESOLVED
        return WorldStatus.SUPPORTED
    if explanation is CounterHypothesis.H4_COLLUDING_PEERS:
        return WorldStatus.REJECTED_COLLUSION
    if explanation in BENIGN_HYPOTHESES:
        return WorldStatus.REJECTED_COMMON_CAUSE
    return WorldStatus.UNRESOLVED


def _world_id(edge_id: str) -> str:
    return "pw-" + hashlib.sha256(edge_id.encode("utf-8")).hexdigest()[:_WORLD_ID_HEX]


def _no_burst(_capsule_ids: Sequence[str]) -> bool:
    return False


def _unsuperseded(edges: Sequence[Hyperedge]) -> list[Hyperedge]:
    """Edges whose fragment set is not a strict subset of another edge's, in input order."""
    containing: dict[str, list[frozenset[str]]] = {}
    sets = [frozenset(edge.fragment_ids) for edge in edges]
    for members in sets:
        for capsule_id in members:
            containing.setdefault(capsule_id, []).append(members)
    kept: list[Hyperedge] = []
    for edge, members in zip(edges, sets, strict=True):
        rivals = containing[edge.fragment_ids[0]]
        if not any(members < other for other in rivals):
            kept.append(edge)
    return kept


class PartialWorldReconstructor:
    """Turns qualifying hyperedges into falsified, never-deleted partial worlds."""

    def __init__(
        self,
        *,
        hypergraph: CampaignHypergraph,
        falsifier: ConsensusFalsifier,
        min_clusters: int = MIN_WORLD_CLUSTERS,
        min_stages: int = MIN_WORLD_STAGES,
        falsify: bool = True,
        resolve_cluster: Callable[[str], str] | None = None,
        birth_burst: Callable[[Sequence[str]], bool] = _no_burst,
        max_worlds: int = MAX_WORLDS,
        meter: WorkMeter | None = None,
    ) -> None:
        if not isinstance(hypergraph, CampaignHypergraph):
            raise ContractError("hypergraph must be a CampaignHypergraph")
        if not isinstance(falsifier, ConsensusFalsifier):
            raise ContractError("falsifier must be a ConsensusFalsifier")
        for name, value in (("min_clusters", min_clusters), ("min_stages", min_stages),
                            ("max_worlds", max_worlds)):
            if require_non_negative_int(value, name) < 1:
                raise ContractError(f"{name} must be >= 1, got {value}")
        self._graph = hypergraph
        self._falsifier = falsifier
        self._min_clusters = min_clusters
        self._min_stages = min_stages
        self._falsify = bool(falsify)
        self._resolve: Callable[[str], str] = resolve_cluster or str
        self._birth_burst = birth_burst
        self._max_worlds = max_worlds
        self._meter = meter
        self._worlds: dict[str, PartialWorld] = {}
        self._refused = 0
        self._stale_skips = 0

    def _qualifies(self, edge: Hyperedge) -> bool:
        return len(edge.stages) >= self._min_stages and edge.clusters >= self._min_clusters

    def _evaluate(self, edge: Hyperedge, fragments: Sequence[Fragment], *, round_index: int,
                  negative: Sequence[NegativeClaim]) -> PartialWorld:
        world_id = _world_id(edge.edge_id)
        previous = self._worlds.get(world_id)
        first = previous.first_supported_round if previous is not None else None
        candidate = PartialWorld(
            world_id=world_id,
            edge_id=edge.edge_id,
            fragment_ids=edge.fragment_ids,
            clusters=len({self._resolve(item.cluster_id) for item in fragments}),
            stages=edge.stages,
            window=edge.window,
            support=edge.weight,
            status=WorldStatus.CANDIDATE,
            falsification=None,
            first_supported_round=first,
        )
        if not self._falsify:
            status, falsification = WorldStatus.SUPPORTED, None
        else:
            falsification = self._falsifier.falsify(
                candidate, fragments, negative=negative, birth_burst=self._birth_burst,
                resolve_cluster=self._resolve, epoch_first_seen=self._graph.epoch_first_seen,
            )
            status = status_of(falsification)
        if status is WorldStatus.SUPPORTED and first is None:
            first = round_index
        return PartialWorld(
            world_id=world_id, edge_id=edge.edge_id, fragment_ids=edge.fragment_ids,
            clusters=candidate.clusters, stages=edge.stages, window=edge.window,
            support=edge.weight, status=status, falsification=falsification,
            first_supported_round=first,
        )

    def reconstruct(
        self, *, round_index: int, negative: Sequence[NegativeClaim] = ()
    ) -> tuple[PartialWorld, ...]:
        """Build edges, (re-)evaluate every qualifying one, and return **all** worlds held.

        A world whose fragments have expired from the hypergraph keeps its last status; it
        is not re-evaluated on partial evidence and it is not dropped. Likewise a world whose
        fragments are a strict subset of another qualifying edge is *superseded*: the larger
        world is judged on all the evidence, and the smaller one keeps the status it had
        when it was the most anyone knew (re-judging it would test a fresh-image or
        synchronised-start hypothesis against a window that no longer contains the
        evidence that explains it).
        """
        require_non_negative_int(round_index, "round_index")
        claims = tuple(negative)
        self._graph.build_edges(round_index=round_index)
        qualifying = [edge for edge in self._graph.edges() if self._qualifies(edge)]
        for edge in _unsuperseded(qualifying):
            fragments = [self._graph.fragment(capsule_id) for capsule_id in edge.fragment_ids]
            present = [item for item in fragments if item is not None]
            if len(present) != len(fragments):
                self._stale_skips += 1
                continue
            world_id = _world_id(edge.edge_id)
            if world_id not in self._worlds and len(self._worlds) >= self._max_worlds:
                self._refused += 1
                continue
            if self._meter is not None:
                self._meter.charge(len(present) + len(claims))
            self._worlds[world_id] = self._evaluate(
                edge, present, round_index=round_index, negative=claims
            )
        return tuple(self._worlds.values())

    def worlds(self) -> tuple[PartialWorld, ...]:
        return tuple(self._worlds.values())

    def refused(self) -> int:
        """Worlds turned away because the table was full (nothing is ever deleted)."""
        return self._refused

    def firing(self) -> Mapping[str, int]:
        """Worlds whose status differs from the no-falsifier answer (SUPPORTED), by status."""
        counts: dict[str, int] = {}
        for world in self._worlds.values():
            if world.status is not WorldStatus.SUPPORTED:
                counts[world.status.value] = counts.get(world.status.value, 0) + 1
        return counts

    def memory_bytes(self) -> int:
        """An upper-bound estimate of what the world table holds, in bytes."""
        per_world = 0
        for world in self._worlds.values():
            per_world += sys.getsizeof(world) + sys.getsizeof(world.fragment_ids)
            per_world += 8 * len(world.fragment_ids) + 2 * sys.getsizeof(world.world_id)
            if world.falsification is not None:
                per_world += sys.getsizeof(world.falsification) + 6 * 160
        return per_world + sys.getsizeof(self._worlds)


def count_threshold_join(
    fragments: Sequence[Fragment], *, window: int, k: int
) -> tuple[tuple[str, ...], ...]:
    """The CONTROL: every maximal group of ``>= k`` fragments from ``>= k`` clusters in one window.

    Anchored exactly like the hypergraph (a group is the fragments intersecting
    ``[s - window, s]`` for a fragment start ``s``: every maximal pairwise-within-``window``
    group) but with no chain order, no stage
    requirement, no per-cluster de-duplication and no falsifier. Returns sorted capsule-id
    tuples, maximal groups only, in a deterministic order.
    """
    require_non_negative_int(window, "window")
    if require_non_negative_int(k, "k") < 1:
        raise ContractError("k must be >= 1")
    ordered = sorted(fragments, key=lambda item: (item.window[0], item.window[1], item.capsule_id))
    starts = [item.window[0] for item in ordered]
    groups: set[frozenset[str]] = set()
    for anchor in sorted(set(starts)):
        members = anchored_members(ordered, starts, anchor, window)
        if len(members) >= k and len({item.cluster_id for item in members}) >= k:
            groups.add(frozenset(item.capsule_id for item in members))
    kept: list[frozenset[str]] = []
    for group in sorted(groups, key=lambda item: (-len(item), sorted(item))):
        if not any(group <= held for held in kept):
            kept.append(group)
    return tuple(tuple(sorted(group)) for group in kept)

