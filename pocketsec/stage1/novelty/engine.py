"""D1.6 — the Conditional Novelty Engine (spec section 12).

Novelty is a **tensor, not a scalar**:

    N_t = [N_host, N_user, N_actor, N_parent_child, N_object, N_relation, N_time, N_causal]

One rarity number cannot distinguish "this binary has never run on this host"
from "this binary has never made a network connection" — and those call for
different responses. Each context gets its own bounded estimator.

The invariant this module exists to protect: **novelty is not maliciousness**
(spec section 11, and acceptance criterion 4). A new compiler output is highly
novel and entirely benign. Nothing here produces or consumes a verdict; novelty
is reported alongside Φ and uncertainty as an independent signal, and the three
are never collapsed into one score.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pocketsec.stage1.novelty.sketches import (
    BoundedLRUCounter,
    CountMinSketch,
    StableBloomFilter,
)

__all__ = ["NOVELTY_CONTEXTS", "NoveltyEngine", "NoveltyTensor"]

#: The contexts novelty is conditioned on. Order is frozen: the SSIR binary
#: layout indexes into it.
NOVELTY_CONTEXTS = (
    "host",
    "user",
    "actor",
    "parent_child",
    "object",
    "relation",
    "time",
    "causal",
)


@dataclass(frozen=True, slots=True)
class NoveltyTensor:
    """Per-context novelty, each in [0, 1]. 1.0 means never seen."""

    values: dict[str, float]

    def __post_init__(self) -> None:
        missing = set(NOVELTY_CONTEXTS) - set(self.values)
        if missing:
            raise ValueError(f"novelty tensor missing contexts: {sorted(missing)}")
        for context, value in self.values.items():
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"novelty[{context}] must be in [0, 1], got {value!r}")
        object.__setattr__(self, "values", dict(self.values))

    def __getitem__(self, context: str) -> float:
        return self.values[context]

    @property
    def peak(self) -> float:
        """The most novel context.

        Max, not mean: a transition that is unremarkable everywhere except that
        this actor has never touched the network before is exactly the case a
        mean would dilute into nothing.
        """
        return max(self.values.values())

    @property
    def mean(self) -> float:
        return sum(self.values.values()) / len(self.values)

    def quantised(self, context: str) -> int:
        """Quantise to the uint8 the SSIR layout carries."""
        return min(255, int(round(self.values[context] * 255)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "values": {k: round(v, 4) for k, v in self.values.items()},
            "peak": round(self.peak, 4),
            "mean": round(self.mean, 4),
        }


@dataclass(frozen=True, slots=True)
class NoveltyBudget:
    """Hard per-context memory caps.

    Sized for the Edge profile: the whole engine is a low-single-digit MB, so
    novelty tracking cannot be what breaks the 100 MB agent target.
    """

    lru_capacity: int = 512
    sketch_width: int = 512
    sketch_depth: int = 4
    bloom_cells: int = 4096


class NoveltyEngine:
    """Bounded conditional novelty estimation.

    Three-tier per context: an exact LRU for the hot set, a Count-Min Sketch for
    the long tail, and a stable Bloom filter for "ever seen". Consulting them in
    that order means a hot key gets an exact answer and a cold key degrades
    gracefully, never silently.
    """

    def __init__(self, budget: NoveltyBudget | None = None) -> None:
        self.budget = budget or NoveltyBudget()
        self._exact: dict[str, BoundedLRUCounter] = {}
        self._sketch: dict[str, CountMinSketch] = {}
        self._seen: dict[str, StableBloomFilter] = {}
        for context in NOVELTY_CONTEXTS:
            self._exact[context] = BoundedLRUCounter(capacity=self.budget.lru_capacity)
            self._sketch[context] = CountMinSketch(
                width=self.budget.sketch_width, depth=self.budget.sketch_depth
            )
            self._seen[context] = StableBloomFilter(cells=self.budget.bloom_cells)
        self._observations = 0

    @property
    def observations(self) -> int:
        return self._observations

    @property
    def memory_bytes(self) -> int:
        """Measured footprint across every context."""
        return sum(
            self._exact[c].memory_bytes
            + self._sketch[c].memory_bytes
            + self._seen[c].memory_bytes
            for c in NOVELTY_CONTEXTS
        )

    def score(self, keys: dict[str, str]) -> NoveltyTensor:
        """Score without learning. Pure query, safe to call speculatively."""
        return NoveltyTensor(
            values={context: self._novelty_of(context, keys.get(context, "")) for context in NOVELTY_CONTEXTS}
        )

    def observe(self, keys: dict[str, str]) -> NoveltyTensor:
        """Score, then fold the observation in.

        Score-before-learn is deliberate: learning first would make every
        transition look familiar to itself and drive novelty to zero.
        """
        tensor = self.score(keys)
        for context in NOVELTY_CONTEXTS:
            key = keys.get(context, "")
            if not key:
                continue
            self._exact[context].add(key)
            self._sketch[context].add(key)
            self._seen[context].add(key)
        self._observations += 1
        return tensor

    def _novelty_of(self, context: str, key: str) -> float:
        """Novelty in [0, 1] for one context."""
        if not key:
            # No key for this context is missing information, not familiarity.
            # Returning 0.0 would quietly assert "seen before".
            return 1.0

        exact = self._exact[context].get(key)
        if exact > 0:
            # Hot and exact: novelty decays as the count grows, never to zero —
            # a rare-but-seen relationship stays mildly novel.
            return 1.0 / (1.0 + exact)

        if not self._seen[context].seen(key):
            return 1.0  # never observed in this context

        # Known to the long tail: fall back to the sketch's frequency estimate.
        estimate = self._sketch[context].estimate(key)
        return 1.0 / (1.0 + estimate) if estimate > 0 else 1.0

    def stats(self) -> dict[str, Any]:
        return {
            "observations": self._observations,
            "memory_bytes": self.memory_bytes,
            "contexts": {
                context: {
                    "exact": self._exact[context].to_dict(),
                    "sketch": self._sketch[context].to_dict(),
                    "seen": self._seen[context].to_dict(),
                }
                for context in NOVELTY_CONTEXTS
            },
        }
