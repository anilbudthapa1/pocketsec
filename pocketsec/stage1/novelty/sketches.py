"""D1.6 (part) — bounded approximate structures (spec section 24).

Every structure here has a **hard, declared memory cap**. That is the whole
point: on a 2 GB host an unbounded frequency table is an availability bug
waiting for a flood, and "flood low-value events to test bounded sketches,
queues and aggregation" is an explicit adversarial test (spec section 22).

Each structure reports its own ``memory_bytes`` so the resource harness can
measure the novelty engine's footprint rather than assume it.
"""

from __future__ import annotations

import hashlib
import math
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any

__all__ = ["BoundedLRUCounter", "CountMinSketch", "EWMA", "StableBloomFilter"]


def _hashes(key: str, count: int, modulus: int) -> list[int]:
    """Derive ``count`` independent-enough indices from one digest.

    One SHA-256 sliced into 4-byte words, rather than ``count`` separate hash
    calls: the sketch sits on the hot path for every transition, and hashing
    dominates its cost.
    """
    digest = hashlib.sha256(key.encode("utf-8")).digest()
    needed = count * 4
    while len(digest) < needed:
        digest += hashlib.sha256(digest).digest()
    return [
        int.from_bytes(digest[i * 4 : i * 4 + 4], "big") % modulus for i in range(count)
    ]


class CountMinSketch:
    """Sublinear frequency estimation with a fixed footprint.

    Over-estimates, never under-estimates. That error direction is the safe one
    here: an inflated count makes something look *more* familiar, so the failure
    mode is a missed novelty signal rather than a fabricated alert. The
    :meth:`estimate` contract says so explicitly, because a caller that assumes
    exactness would be wrong in a security-relevant way.
    """

    def __init__(self, *, width: int = 512, depth: int = 4) -> None:
        if width < 1 or depth < 1:
            raise ValueError("width and depth must be >= 1")
        self.width = width
        self.depth = depth
        self._rows = [[0] * width for _ in range(depth)]
        self._total = 0

    @property
    def total(self) -> int:
        return self._total

    @property
    def memory_bytes(self) -> int:
        """Upper bound on the counter array, ignoring interpreter overhead."""
        return self.width * self.depth * 8

    def add(self, key: str, count: int = 1) -> None:
        self._total += count
        for row, index in zip(self._rows, _hashes(key, self.depth, self.width), strict=True):
            row[index] += count

    def estimate(self, key: str) -> int:
        """Estimated count. May over-estimate; never under-estimates."""
        return min(
            row[index]
            for row, index in zip(self._rows, _hashes(key, self.depth, self.width), strict=True)
        )

    def relative_frequency(self, key: str) -> float:
        if self._total == 0:
            return 0.0
        return self.estimate(key) / self._total

    def error_bound(self) -> float:
        """Additive error bound: counts are over-estimated by <= e/width * total."""
        return math.e / self.width * self._total

    def to_dict(self) -> dict[str, Any]:
        return {
            "width": self.width,
            "depth": self.depth,
            "total": self._total,
            "memory_bytes": self.memory_bytes,
            "error_bound": round(self.error_bound(), 3),
        }


class StableBloomFilter:
    """Membership over an unbounded stream in constant space.

    A classic Bloom filter fills up and then answers "seen" for everything,
    which would silently zero out novelty — the worst possible failure for this
    system. The stable variant decrements random cells on each insert, evicting
    stale entries so the fill rate converges instead of saturating. It trades a
    controlled false-negative rate for never going blind.
    """

    def __init__(
        self,
        *,
        cells: int = 4096,
        hashes: int = 4,
        max_value: int = 3,
        decay: int | None = None,
    ):
        if cells < 1 or hashes < 1:
            raise ValueError("cells and hashes must be >= 1")
        self.cells = cells
        self.hashes = hashes
        self.max_value = max_value
        # Each insert adds at most hashes * max_value "units" to the filter, so
        # the decay must remove a comparable amount or the fill rate climbs to
        # 1.0 and the filter answers "seen" for everything -- silently zeroing
        # out novelty, which is the failure this class exists to prevent.
        self.decay = decay if decay is not None else hashes * max_value
        self._cells = bytearray(cells)
        self._inserts = 0
        self._cursor = 0

    @property
    def memory_bytes(self) -> int:
        return self.cells

    def _decay_cells(self) -> None:
        """Decrement a deterministic stride of cells to bound the fill rate.

        A fixed rotating cursor rather than randomness keeps the structure
        reproducible, which the Stage 0 reproducibility policy requires.
        """
        for _ in range(self.decay):
            if self._cells[self._cursor] > 0:
                self._cells[self._cursor] -= 1
            self._cursor = (self._cursor + 1) % self.cells

    def add(self, key: str) -> None:
        self._decay_cells()
        self._inserts += 1
        for index in _hashes(key, self.hashes, self.cells):
            self._cells[index] = self.max_value

    def seen(self, key: str) -> bool:
        return all(self._cells[i] > 0 for i in _hashes(key, self.hashes, self.cells))

    def add_and_check(self, key: str) -> bool:
        """Return whether the key was already present, then record it."""
        was_seen = self.seen(key)
        self.add(key)
        return was_seen

    @property
    def fill_rate(self) -> float:
        return sum(1 for cell in self._cells if cell > 0) / self.cells

    @property
    def false_positive_rate(self) -> float:
        """Estimated FP rate at the current fill: ``fill_rate ** hashes``.

        The spec requires Bloom false positives to be *measured*, not assumed.
        A false positive here makes something look familiar, so it costs a
        missed novelty signal rather than a fabricated alert -- the safe
        direction, but only while this number stays small.
        """
        return self.fill_rate**self.hashes

    def to_dict(self) -> dict[str, Any]:
        return {
            "cells": self.cells,
            "hashes": self.hashes,
            "decay": self.decay,
            "inserts": self._inserts,
            "fill_rate": round(self.fill_rate, 4),
            "false_positive_rate": round(self.false_positive_rate, 5),
            "memory_bytes": self.memory_bytes,
        }


class BoundedLRUCounter:
    """Exact counts for the hot set, with a hard entry cap.

    The spec's strategy is exact structures for hot relationships and
    approximate ones for the long tail. This is the exact half: precise while a
    key stays hot, and honest about eviction via :attr:`evictions` so the
    approximation boundary is measurable rather than invisible.
    """

    def __init__(self, *, capacity: int = 1024) -> None:
        if capacity < 1:
            raise ValueError("capacity must be >= 1")
        self.capacity = capacity
        self._counts: OrderedDict[str, int] = OrderedDict()
        self._evictions = 0

    @property
    def evictions(self) -> int:
        return self._evictions

    @property
    def memory_bytes(self) -> int:
        """Rough upper bound: key bytes plus an 8-byte count per live entry."""
        return sum(len(key.encode("utf-8")) + 8 for key in self._counts)

    def __len__(self) -> int:
        return len(self._counts)

    def __contains__(self, key: str) -> bool:
        return key in self._counts

    def add(self, key: str, count: int = 1) -> None:
        if key in self._counts:
            self._counts[key] += count
            self._counts.move_to_end(key)
            return
        self._counts[key] = count
        while len(self._counts) > self.capacity:
            self._counts.popitem(last=False)
            self._evictions += 1

    def get(self, key: str) -> int:
        """Exact count for a live key; 0 once evicted."""
        if key not in self._counts:
            return 0
        self._counts.move_to_end(key)
        return self._counts[key]

    def to_dict(self) -> dict[str, Any]:
        return {
            "capacity": self.capacity,
            "live_entries": len(self._counts),
            "evictions": self._evictions,
            "memory_bytes": self.memory_bytes,
        }


@dataclass
class EWMA:
    """Exponentially weighted moving average — temporal statistics, no series.

    Explicitly not a time series: retaining one would be unbounded. Holds two
    floats regardless of how long the host runs.
    """

    alpha: float = 0.1
    value: float = 0.0
    initialised: bool = False

    def update(self, sample: float) -> float:
        if not self.initialised:
            self.value = sample
            self.initialised = True
        else:
            self.value = self.alpha * sample + (1.0 - self.alpha) * self.value
        return self.value

    @property
    def memory_bytes(self) -> int:
        return 24
