"""D2.6 — the Dynamic Transition Lattice: bounded edges between Behaviour Atoms.

The lattice answers one question: given that the host just did atom *s*, what
usually follows? It is the structure Stage 3 crystallises, so it has three
properties that matter more than accuracy:

* **It is epoch-conditioned.** ``probability(s, t, epoch_id=…)`` filters the
  counts to one epoch, because a transition that is stable in one regime may be
  invalid in another (spec §24). A lattice that pooled every epoch would launder
  pre-change behaviour into post-change confidence, which is precisely the
  drift/poisoning failure Stage 1's epoch rules exist to prevent.
* **It reserves mass for what it has never seen.** Laplace smoothing over a
  *floored* hypothesis space, so an atom with no outgoing evidence reports
  ignorance instead of certainty. Without the floor, an unobserved source would
  score any continuation at probability 1.0 and log-loss would reward having no
  data at all — the same "notional accounting" failure ADR-0010 found in the
  router.
* **It is bounded and counts its truncation.** At ``MAX_TRANSITIONS`` the
  least-observed, then oldest, edge is dropped and :meth:`evictions` reports it.
  A silently dropped edge is a silently wrong probability.

Bounded epoch history has a consequence stated here because it is easy to miss:
each edge records at most ``MAX_EPOCHS_PER_ATOM`` epochs, so an epoch's totals
fall out of the lattice once that epoch is the least-seen on an edge. Epoch
filtering is therefore a claim about *recorded* evidence, never about all history.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage2.lattice.atom import (
    MAX_EPOCHS_PER_ATOM,
    CompileStatus,
    bound_epoch_counts,
)

__all__ = [
    "EPOCHS_PER_EDGE",
    "MAX_TRANSITIONS",
    "VOCABULARY_FLOOR",
    "LatticeTransition",
    "TransitionLattice",
]

#: Re-exported so a caller does not have to import two modules to learn the epoch
#: bound that constrains both atoms and edges.
EPOCHS_PER_EDGE: int = MAX_EPOCHS_PER_ATOM

MAX_TRANSITIONS: int = 4096
#: Smallest hypothesis space the smoothing will assume for one source. Without a
#: floor, "I have seen nothing" and "I am certain" produce the same number.
VOCABULARY_FLOOR: int = 8

_SLOT_BYTES: int = 8
_INT_BYTES: int = 8
_FLOAT_BYTES: int = 8


@dataclass(frozen=True, slots=True)
class LatticeTransition:
    """One directed edge: how often *source* was followed by *target*."""

    source: int
    target: int
    count: int
    #: epoch id -> observations in that epoch. Bounded at
    #: :data:`~pocketsec.stage2.lattice.atom.MAX_EPOCHS_PER_ATOM`.
    epoch_counts: dict[int, int]
    delta_phi_sum: float
    uncertainty_mean: float
    compile_status: CompileStatus

    def __post_init__(self) -> None:
        if self.count < 1:
            raise ContractError(
                f"edge {self.source}->{self.target}: count must be >= 1, "
                f"got {self.count}"
            )
        object.__setattr__(
            self, "epoch_counts", bound_epoch_counts(dict(self.epoch_counts))
        )

    @property
    def probability_hint(self) -> float:
        """This edge's self-confidence, with no knowledge of its siblings.

        A *hint* only: the real probability needs the source's total, which lives
        on the lattice. Exposed because a compile candidate carrying a single edge
        needs some monotone measure of how well-evidenced that edge is, and
        ``count`` alone is not comparable across candidates.
        """
        return self.count / (self.count + 1.0)

    @property
    def mean_delta_phi(self) -> float:
        return self.delta_phi_sum / self.count

    def epochs(self) -> frozenset[int]:
        return frozenset(self.epoch_counts)

    def memory_bytes(self) -> int:
        slots = len(LatticeTransition.__slots__) * _SLOT_BYTES
        epochs = len(self.epoch_counts) * (_INT_BYTES + _INT_BYTES)
        return slots + epochs + 2 * _FLOAT_BYTES

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "count": self.count,
            "epochs": sorted(self.epoch_counts),
            "epoch_counts": {str(k): v for k, v in sorted(self.epoch_counts.items())},
            "delta_phi_sum": round(self.delta_phi_sum, 6),
            "mean_delta_phi": round(self.mean_delta_phi, 6),
            "uncertainty_mean": round(self.uncertainty_mean, 6),
            "probability_hint": round(self.probability_hint, 6),
            "compile_status": str(self.compile_status),
        }


class TransitionLattice:
    """Bounded, epoch-conditioned bigram lattice over Behaviour Atom ids."""

    __slots__ = (
        "_alpha",
        "_edges",
        "_epoch_targets",
        "_epoch_total",
        "_evictions",
        "_max_transitions",
        "_order",
        "_sequence",
        "_source_targets",
        "_source_total",
        "_vocabulary_floor",
    )

    def __init__(
        self,
        *,
        max_transitions: int = MAX_TRANSITIONS,
        alpha: float = 1.0,
        vocabulary_floor: int = VOCABULARY_FLOOR,
    ) -> None:
        if max_transitions <= 0:
            raise ContractError(
                f"max_transitions must be positive, got {max_transitions}"
            )
        if alpha <= 0.0:
            raise ContractError(f"Laplace alpha must be positive, got {alpha}")
        if vocabulary_floor < 1:
            raise ContractError(
                f"vocabulary_floor must be >= 1, got {vocabulary_floor}"
            )
        self._edges: dict[tuple[int, int], LatticeTransition] = {}
        #: Insertion index per edge, so "oldest" is a fact rather than a dict
        #: iteration-order accident.
        self._order: dict[tuple[int, int], int] = {}
        self._source_total: dict[int, int] = {}
        self._source_targets: dict[int, set[int]] = {}
        self._epoch_total: dict[tuple[int, int], int] = {}
        self._epoch_targets: dict[tuple[int, int], set[int]] = {}
        self._max_transitions = max_transitions
        self._alpha = alpha
        self._vocabulary_floor = vocabulary_floor
        self._evictions = 0
        self._sequence = 0

    # --- read side -----------------------------------------------------------

    @property
    def alpha(self) -> float:
        return self._alpha

    @property
    def max_transitions(self) -> int:
        return self._max_transitions

    @property
    def vocabulary_floor(self) -> int:
        """Smallest hypothesis space assumed per source; see the module docstring."""
        return self._vocabulary_floor

    def bucket_count(self, source: int, *, epoch_id: int | None = None) -> int:
        """How many outcome buckets the smoothing assumes for ``source``.

        Exposed because entropy is only interpretable against the space it was
        measured over, and D2.7's heterogeneity threshold needs a *normalised*
        entropy rather than a raw bit count.
        """
        _denominator, _total, reserved = self._denominator(source, epoch_id=epoch_id)
        return len(self.known_targets(source, epoch_id=epoch_id)) + reserved

    def __len__(self) -> int:
        return len(self._edges)

    def edges(self) -> tuple[LatticeTransition, ...]:
        """Edges in (source, target) order, so callers iterate reproducibly."""
        return tuple(self._edges[key] for key in sorted(self._edges))

    def edge(self, source: int, target: int) -> LatticeTransition | None:
        return self._edges.get((source, target))

    def evictions(self) -> int:
        return self._evictions

    def sources(self) -> tuple[int, ...]:
        return tuple(sorted(self._source_targets))

    def known_targets(self, source: int, *, epoch_id: int | None = None) -> tuple[int, ...]:
        """Targets with recorded evidence for ``source``, in id order."""
        if epoch_id is None:
            return tuple(sorted(self._source_targets.get(source, ())))
        return tuple(sorted(self._epoch_targets.get((source, epoch_id), ())))

    def memory_bytes(self) -> int:
        """Edges plus the indices that make epoch filtering O(1) to look up."""
        edge_bytes = sum(edge.memory_bytes() for edge in self._edges.values())
        index = len(self._edges) * 3 * (_INT_BYTES + _SLOT_BYTES)
        totals = (len(self._source_total) + len(self._epoch_total)) * (
            _INT_BYTES + _INT_BYTES
        )
        target_sets = sum(
            len(values) * _INT_BYTES
            for values in list(self._source_targets.values())
            + list(self._epoch_targets.values())
        )
        return edge_bytes + index + totals + target_sets

    # --- probability ---------------------------------------------------------

    def _denominator(self, source: int, *, epoch_id: int | None) -> tuple[float, int, int]:
        """``(denominator, observed_total, reserved_buckets)`` for one source."""
        if epoch_id is None:
            total = self._source_total.get(source, 0)
            known = len(self._source_targets.get(source, ()))
        else:
            total = self._epoch_total.get((source, epoch_id), 0)
            known = len(self._epoch_targets.get((source, epoch_id), ()))
        # One bucket is always reserved for "something I have never seen here",
        # and the hypothesis space never shrinks below the floor.
        buckets = max(known + 1, self._vocabulary_floor)
        return total + self._alpha * buckets, total, buckets - known

    def probability(
        self, source: int, target: int, *, epoch_id: int | None = None
    ) -> float:
        """Laplace-smoothed P(target | source), epoch-filtered when asked.

        An unrecorded target gets the per-bucket unseen mass rather than zero: a
        zero would make :meth:`log_loss` infinite and would claim the lattice has
        enumerated the world.
        """
        denominator, _total, _reserved = self._denominator(source, epoch_id=epoch_id)
        edge = self._edges.get((source, target))
        if edge is None:
            return self._alpha / denominator
        count = edge.count if epoch_id is None else edge.epoch_counts.get(epoch_id, 0)
        if count == 0:
            return self._alpha / denominator
        return (count + self._alpha) / denominator

    def unseen_mass(self, source: int, *, epoch_id: int | None = None) -> float:
        """Total probability reserved for continuations never recorded here.

        Computed from the reserved buckets, not as ``1 - Σ p(t)``. That makes
        "the known successors plus the unseen mass sum to one" an arithmetic
        property a test can falsify, rather than a definition that cannot fail.
        """
        denominator, _total, reserved = self._denominator(source, epoch_id=epoch_id)
        return self._alpha * reserved / denominator

    def successors(
        self, source: int, *, epoch_id: int | None = None, limit: int = 8
    ) -> tuple[tuple[int, float], ...]:
        """Most likely recorded continuations, highest probability first.

        Ties break on the lower target id so the ordering is total; a cone or an
        export built from an unstable ordering is not reproducible.
        """
        if limit <= 0:
            raise ContractError(f"successors limit must be positive, got {limit}")
        targets = self.known_targets(source, epoch_id=epoch_id)
        scored = [
            (target, self.probability(source, target, epoch_id=epoch_id))
            for target in targets
        ]
        scored.sort(key=lambda item: (-item[1], item[0]))
        return tuple(scored[:limit])

    def log_loss(
        self, pairs: Sequence[tuple[int, int]], *, epoch_id: int | None = None
    ) -> float:
        """Mean negative log probability over ``pairs`` — the D2.6 metric.

        Always finite: the smoothing floor guarantees a positive probability for
        every pair, including one whose source the lattice has never seen. Returns
        0.0 for an empty sequence, because there is nothing to be wrong about.
        """
        if not pairs:
            return 0.0
        total = 0.0
        for source, target in pairs:
            total -= math.log(self.probability(source, target, epoch_id=epoch_id))
        return total / len(pairs)

    def perplexity(
        self, pairs: Sequence[tuple[int, int]], *, epoch_id: int | None = None
    ) -> float:
        return math.exp(self.log_loss(pairs, epoch_id=epoch_id))

    # --- write side ----------------------------------------------------------

    def observe(
        self,
        source: int,
        target: int,
        *,
        epoch_id: int,
        delta_phi: float,
        uncertainty: float,
    ) -> None:
        """Record one observed transition, evicting if the table is full."""
        key = (source, target)
        existing = self._edges.get(key)
        if existing is None:
            if len(self._edges) >= self._max_transitions:
                self._evict()
            edge = LatticeTransition(
                source=source,
                target=target,
                count=1,
                epoch_counts={epoch_id: 1},
                delta_phi_sum=delta_phi,
                uncertainty_mean=uncertainty,
                compile_status=CompileStatus.NEURAL,
            )
            self._edges[key] = edge
            self._order[key] = self._sequence
            self._sequence += 1
            self._index_add(edge, {epoch_id: 1})
            return

        counts = dict(existing.epoch_counts)
        counts[epoch_id] = counts.get(epoch_id, 0) + 1
        bounded = bound_epoch_counts(counts)
        # A dropped epoch must leave the epoch indices too, or the lattice keeps
        # reporting evidence it no longer holds.
        for dropped in set(existing.epoch_counts) - set(bounded):
            self._index_remove_epoch(source, target, dropped, existing.epoch_counts[dropped])
        count = existing.count + 1
        edge = LatticeTransition(
            source=source,
            target=target,
            count=count,
            epoch_counts=bounded,
            delta_phi_sum=existing.delta_phi_sum + delta_phi,
            uncertainty_mean=(
                existing.uncertainty_mean * existing.count + uncertainty
            )
            / count,
            compile_status=existing.compile_status,
        )
        self._edges[key] = edge
        self._source_total[source] = self._source_total.get(source, 0) + 1
        if epoch_id in bounded:
            epoch_key = (source, epoch_id)
            self._epoch_total[epoch_key] = self._epoch_total.get(epoch_key, 0) + 1
            self._epoch_targets.setdefault(epoch_key, set()).add(target)

    def set_status(self, source: int, target: int, status: CompileStatus) -> bool:
        """Mark an edge's crystallisation status. Returns False if unknown."""
        key = (source, target)
        edge = self._edges.get(key)
        if edge is None:
            return False
        self._edges[key] = LatticeTransition(
            source=edge.source,
            target=edge.target,
            count=edge.count,
            epoch_counts=dict(edge.epoch_counts),
            delta_phi_sum=edge.delta_phi_sum,
            uncertainty_mean=edge.uncertainty_mean,
            compile_status=status,
        )
        return True

    def remove_edge(self, source: int, target: int) -> LatticeTransition | None:
        """Drop one edge and its index entries. Used by fission re-routing."""
        key = (source, target)
        edge = self._edges.pop(key, None)
        if edge is None:
            return None
        self._order.pop(key, None)
        self._index_remove(edge)
        return edge

    def reinsert(self, edge: LatticeTransition) -> None:
        """Insert a rebuilt edge wholesale — fission moves edges, not events.

        Evicts first if the table is full, so re-routing cannot exceed the bound.
        """
        key = (edge.source, edge.target)
        if key in self._edges:
            raise ContractError(f"edge {key} already present; remove it first")
        if len(self._edges) >= self._max_transitions:
            self._evict()
        self._edges[key] = edge
        self._order[key] = self._sequence
        self._sequence += 1
        self._index_add(edge, edge.epoch_counts)

    # --- index maintenance ---------------------------------------------------

    def _index_add(self, edge: LatticeTransition, epoch_counts: dict[int, int]) -> None:
        self._source_total[edge.source] = (
            self._source_total.get(edge.source, 0) + edge.count
        )
        self._source_targets.setdefault(edge.source, set()).add(edge.target)
        for epoch_id, count in epoch_counts.items():
            epoch_key = (edge.source, epoch_id)
            self._epoch_total[epoch_key] = self._epoch_total.get(epoch_key, 0) + count
            self._epoch_targets.setdefault(epoch_key, set()).add(edge.target)

    def _index_remove(self, edge: LatticeTransition) -> None:
        remaining = self._source_total.get(edge.source, 0) - edge.count
        if remaining > 0:
            self._source_total[edge.source] = remaining
        else:
            self._source_total.pop(edge.source, None)
        targets = self._source_targets.get(edge.source)
        if targets is not None:
            targets.discard(edge.target)
            if not targets:
                del self._source_targets[edge.source]
        for epoch_id, count in edge.epoch_counts.items():
            self._index_remove_epoch(edge.source, edge.target, epoch_id, count)

    def _index_remove_epoch(
        self, source: int, target: int, epoch_id: int, count: int
    ) -> None:
        epoch_key = (source, epoch_id)
        remaining = self._epoch_total.get(epoch_key, 0) - count
        if remaining > 0:
            self._epoch_total[epoch_key] = remaining
        else:
            self._epoch_total.pop(epoch_key, None)
        targets = self._epoch_targets.get(epoch_key)
        if targets is not None:
            targets.discard(target)
            if not targets:
                del self._epoch_targets[epoch_key]

    def _evict(self) -> tuple[int, int]:
        """Lowest count, then oldest insertion. Every eviction is counted."""
        victim_key = min(
            self._edges,
            key=lambda key: (self._edges[key].count, self._order.get(key, 0), key),
        )
        edge = self._edges.pop(victim_key)
        self._order.pop(victim_key, None)
        self._index_remove(edge)
        self._evictions += 1
        return victim_key
