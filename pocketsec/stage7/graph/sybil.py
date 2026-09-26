"""D7.8 — the Sybil report: what the dependence graph concluded, and what it bought.

Two different things live here and must not be confused:

* :func:`sybil_report` summarises the graph as an endpoint would see it: peers, clusters,
  the largest cluster's share, the clusters that *look* like Sybil groups (large, spanning
  several declared roots, and merged by behaviour rather than by a shared declared root),
  and how many newcomers the graph refused past its cap.
* :func:`amplification_factor` is architecture §46's "Sybil influence amplification
  factor", and it needs **lab ground truth** — which peers are adversarial and how many
  true independent roots the adversary really has. An endpoint never knows either, so the
  factor is ``None`` unless the caller is a lab that supplies them.

A suspected cluster is a *signal for a human or a later stage*, not a verdict and not an
exclusion: its mass is already capped as one cluster by ECHO. It also fires on the honest
side of the graph's known weakness — a relaying identity that bridges honest clusters
produces exactly this shape (see :mod:`pocketsec.stage7.graph.dependence`).
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass

from pocketsec.stage0.contracts.common import (
    ContractError,
    require_finite_unit_interval,
    require_non_negative_int,
)
from pocketsec.stage7.graph.dependence import DependenceGraph

__all__ = [
    "SYBIL_MIN_CLUSTER",
    "SybilReport",
    "adversary_mass_share",
    "amplification_factor",
    "sybil_report",
]

#: §4.23. Chosen, not measured: the smallest cluster reported as a suspected Sybil group.
SYBIL_MIN_CLUSTER: int = 4


@dataclass(frozen=True, slots=True)
class SybilReport:
    peers: int
    clusters: int
    largest_cluster_share: float | None   # None with zero peers: a share of nothing is undefined
    suspected_clusters: tuple[str, ...]
    amplification: float | None           # None without lab ground truth, or when undefined
    refused_peers: int

    def __post_init__(self) -> None:
        require_non_negative_int(self.peers, "peers")
        require_non_negative_int(self.clusters, "clusters")
        require_non_negative_int(self.refused_peers, "refused_peers")
        if self.clusters > self.peers:
            raise ContractError(f"{self.clusters} clusters cannot come from {self.peers} peers")
        if (self.peers == 0) != (self.largest_cluster_share is None):
            raise ContractError("largest_cluster_share is None exactly when there are no peers")
        if self.largest_cluster_share is not None:
            require_finite_unit_interval(self.largest_cluster_share, "largest_cluster_share")
        if self.amplification is not None and (
                not math.isfinite(self.amplification) or self.amplification < 0.0):
            raise ContractError(f"amplification must be finite and >= 0, got {self.amplification!r}")


def amplification_factor(adversary_mass_share: float, adversary_root_share: float) -> float | None:
    """(adversary share of accepted support mass) / (adversary share of TRUE independent roots).

    1.0 means the adversary's identity count bought nothing beyond its real roots; a naive
    identity majority gives roughly the number of identities per root. ``None`` when the
    adversary holds no true root: the ratio is then undefined, not infinite and not zero.
    """
    mass = require_finite_unit_interval(adversary_mass_share, "adversary_mass_share")
    roots = require_finite_unit_interval(adversary_root_share, "adversary_root_share")
    if roots == 0.0:
        return None
    return mass / roots


def adversary_mass_share(support_mass_by_peer: Mapping[str, float],
                         adversary_peers: frozenset[str]) -> float | None:
    """The adversary's share of all support mass; ``None`` when no mass was accepted at all."""
    total = 0.0
    adversarial = 0.0
    for peer_id, mass in support_mass_by_peer.items():
        if isinstance(mass, bool) or not isinstance(mass, (int, float)) or \
                not math.isfinite(mass) or mass < 0.0:
            raise ContractError(f"support mass for {peer_id!r} must be finite and >= 0, got {mass!r}")
        total += mass
        if peer_id in adversary_peers:
            adversarial += mass
    if total == 0.0:
        return None
    return adversarial / total


def sybil_report(
    graph: DependenceGraph,
    *,
    support_mass_by_peer: Mapping[str, float] | None = None,
    adversary_peers: frozenset[str] | None = None,
    adversary_true_roots: int | None = None,
    total_true_roots: int | None = None,
) -> SybilReport:
    """Summarise ``graph``; the amplification is computed only when all lab truth is given."""
    summaries = graph.cluster_summaries()
    peers = sum(len(s.members) for s in summaries)
    largest = max((len(s.members) for s in summaries), default=0)
    suspected = tuple(
        s.cluster_id for s in summaries
        if len(s.members) >= SYBIL_MIN_CLUSTER and len(s.declared_roots) >= 2 and s.behaviour_merged
    )
    return SybilReport(
        peers=peers,
        clusters=len(summaries),
        largest_cluster_share=(largest / peers) if peers else None,
        suspected_clusters=suspected,
        amplification=_lab_amplification(support_mass_by_peer, adversary_peers,
                                         adversary_true_roots, total_true_roots),
        refused_peers=graph.evictions(),
    )


def _lab_amplification(
    support_mass_by_peer: Mapping[str, float] | None,
    adversary_peers: frozenset[str] | None,
    adversary_true_roots: int | None,
    total_true_roots: int | None,
) -> float | None:
    given = (support_mass_by_peer, adversary_peers, adversary_true_roots, total_true_roots)
    if support_mass_by_peer is None or adversary_peers is None or \
            adversary_true_roots is None or total_true_roots is None:
        if all(value is None for value in given):
            return None
        raise ContractError("amplification needs all four lab inputs, or none of them")
    adversary_roots = require_non_negative_int(adversary_true_roots, "adversary_true_roots")
    total_roots = require_non_negative_int(total_true_roots, "total_true_roots")
    if total_roots == 0 or adversary_roots > total_roots:
        raise ContractError(
            f"need 0 <= adversary_true_roots <= total_true_roots > 0, "
            f"got {adversary_roots} of {total_roots}")
    mass_share = adversary_mass_share(support_mass_by_peer, adversary_peers)
    if mass_share is None:
        return None
    return amplification_factor(mass_share, adversary_roots / total_roots)
