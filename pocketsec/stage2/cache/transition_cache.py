"""D2.13 — DTL-F16: a bounded, version-pinned, ledger-proven transition cache.

This is the P0 path: an outcome already computed for this (atom, epoch, ΔS)
combination is returned instead of recomputed. Two properties make it worth
having rather than dangerous.

**It cannot serve a stale answer.** Entries are versioned by model *and* encoder
(architecture spec §37). A lookup whose stored ``model_version`` or
``encoder_version`` differs from the cache's is a **miss** counted as a
``version_rejection``, and the stale entry is dropped. Silently answering from
weights that no longer exist is worse than recomputing: the caller cannot tell,
and the wrong answer carries the cheap path's credibility.

**It cannot fabricate a saving.** ADR-0010 recorded the router reporting 100 %
cheap-path resolution while every branch was computed anyway. So a hit here does
not *claim* a saving: it records ``CACHE_LOOKUP performed=True`` and
``CORE_INFERENCE performed=False`` on a :class:`WorkLedger`, and
``CacheStats.proven_skipped_units`` counts only skips a ledger accepted. Pass no
ledger and the cache reports **zero** proven savings, however many hits it
served. That asymmetry is deliberate: an unprovable saving is not a saving.
The contradiction — a skip recorded for an event that ran the inference anyway —
is caught by ``WorkLedger.assert_no_phantom_savings()``, which is a per-run
assertion and not called per event (measured: 3.9 ms per call at 2000 retained
accounts, so calling it on the P0 path would make the cheap path quadratic).

The key is a ``hashlib`` digest, never builtin ``hash()``: ``hash()`` is salted
per process, so a cache keyed on it would be unreproducible across runs and
every stored artefact would be unreadable tomorrow.

The LRU control is Stage 1's :class:`BoundedLRUCounter` rather than a second
implementation of the same idea — the recency structure is already written,
already bounded and already counts its own evictions.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from pocketsec.stage0.contracts.common import ContractError, require_identifier
from pocketsec.stage1.novelty.sketches import BoundedLRUCounter
from pocketsec.stage1.state.security_state import StateDelta
from pocketsec.stage2.core_ids import PATH_COST_UNITS, ExecutionPath
from pocketsec.stage2.router.accounting import WorkKind, WorkLedger

__all__ = [
    "CORE_INFERENCE_UNITS",
    "CACHE_LOOKUP_UNITS",
    "CacheStats",
    "CachedTransition",
    "MAX_CACHE_ENTRIES",
    "TransitionCache",
    "transition_cache_key",
]

MAX_CACHE_ENTRIES = 1024

#: Cost of the lookup itself — the P0 path, by definition the cheapest thing
#: Stage 2 can do that is not nothing.
CACHE_LOOKUP_UNITS = PATH_COST_UNITS[ExecutionPath.P0_COMPILED]

#: What a hit avoids: one predictive-core inference (P3). These are
#: ``PATH_COST_UNITS`` policy units and ``PATH_COST_UNITS`` is **UNCALIBRATED** —
#: its docstring claims calibration from measured CPU time and no calibration
#: code exists in this repository. ``proven_skipped_units`` is therefore a
#: policy-unit figure, and the only honest cost number remains wall-clock
#: µs/event from ``research/sleeping_brain.py``.
CORE_INFERENCE_UNITS = PATH_COST_UNITS[ExecutionPath.P3_PREDICTIVE]

#: Per-entry byte estimate: the eleven fields at 8 bytes each plus a dict header
#: for ``StateDelta.raised``. Key bytes are added per entry, so the figure grows
#: with real keys rather than with an assumption about them.
_ENTRY_OVERHEAD_BYTES = 11 * 8 + 64


def transition_cache_key(*, atom_id: int, epoch_id: int, state_delta_mask: int) -> str:
    """Deterministic digest of the cache coordinates.

    ``hashlib``, not ``hash()``: builtin hashing is randomised per interpreter
    (PYTHONHASHSEED), so a key derived from it would differ between the run that
    stored an entry and the run that reads it back, and no persisted cache or
    exported candidate could ever be matched again.
    """
    # Validated with three inline comparisons rather than a loop over
    # (name, value) pairs: measured this session, the tidy loop cost 19.7 µs per
    # key on this host against 2.6 µs for the inline form, and this is the P0
    # path — the one that has to be cheaper than the inference it replaces.
    if type(atom_id) is not int or type(epoch_id) is not int or type(state_delta_mask) is not int:
        raise ContractError(
            f"transition_cache_key coordinates must be ints, got "
            f"({type(atom_id).__name__}, {type(epoch_id).__name__}, "
            f"{type(state_delta_mask).__name__})"
        )
    if atom_id < 0 or epoch_id < 0 or state_delta_mask < 0:
        raise ContractError(
            f"transition_cache_key coordinates must be >= 0, got "
            f"({atom_id}, {epoch_id}, {state_delta_mask})"
        )
    material = f"{atom_id}|{epoch_id}|{state_delta_mask}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()[:32]


@dataclass(frozen=True, slots=True)
class CachedTransition:
    """One precomputed outcome, pinned to the versions that produced it."""

    key: str
    atom_id: int
    epoch_id: int
    model_version: str
    encoder_version: str
    predicted_delta: StateDelta
    predicted_phi: float
    uncertainty: float
    hits: int
    utility: float
    last_sequence: int

    def __post_init__(self) -> None:
        if not isinstance(self.key, str) or not self.key:
            raise ContractError("CachedTransition.key must be a non-empty digest string")
        require_identifier(self.model_version, "CachedTransition.model_version")
        require_identifier(self.encoder_version, "CachedTransition.encoder_version")
        if not isinstance(self.predicted_delta, StateDelta):
            raise ContractError("CachedTransition.predicted_delta must be a StateDelta")
        if not 0.0 <= float(self.uncertainty) <= 1.0:
            raise ContractError(
                f"CachedTransition.uncertainty must be within [0, 1], got {self.uncertainty!r}"
            )
        for name in ("atom_id", "epoch_id", "hits", "last_sequence"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ContractError(f"CachedTransition.{name} must be an int >= 0, got {value!r}")

    @property
    def memory_bytes(self) -> int:
        return (
            _ENTRY_OVERHEAD_BYTES
            + len(self.key.encode("utf-8"))
            + len(self.model_version.encode("utf-8"))
            + len(self.encoder_version.encode("utf-8"))
            + 24 * len(self.predicted_delta.raised)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "atom_id": self.atom_id,
            "epoch_id": self.epoch_id,
            "model_version": self.model_version,
            "encoder_version": self.encoder_version,
            "predicted_delta": self.predicted_delta.to_dict(),
            "predicted_phi": round(self.predicted_phi, 6),
            "uncertainty": round(self.uncertainty, 6),
            "hits": self.hits,
            "utility": round(self.utility, 6),
            "last_sequence": self.last_sequence,
        }


#: Field order of :class:`CachedTransition`, used by :func:`_copy_with`.
_CACHED_FIELDS: tuple[str, ...] = CachedTransition.__slots__


def _copy_with(entry: CachedTransition, **overrides: Any) -> CachedTransition:
    """Return a NEW entry with fields replaced, skipping re-validation.

    Still immutable — the original is untouched and a new object is returned —
    but the fields were validated when the entry was first constructed, and
    re-running two ``require_identifier`` regexes on every cache hit is pure
    waste on the cheapest path in the system. Measured this session: 14.5 µs per
    rebuild through the validating constructor against 5.3 µs here.

    Only ``hits``, ``utility`` and ``last_sequence`` are ever overridden, and each
    is bounds-checked by the caller, so no unvalidated value can enter this way.
    """
    fresh = CachedTransition.__new__(CachedTransition)
    for name in _CACHED_FIELDS:
        object.__setattr__(
            fresh, name, overrides[name] if name in overrides else getattr(entry, name)
        )
    return fresh


@dataclass(frozen=True, slots=True)
class CacheStats:
    """What the cache did, including what it refused to claim."""

    entries: int
    hits: int
    misses: int
    evictions: int
    version_rejections: int
    proven_skipped_units: float
    memory_bytes: int

    def hit_rate(self) -> float | None:
        """``None`` on zero lookups — not ``0.0``.

        A cache that was never asked anything has no hit rate. Reporting 0.0
        would let an unexercised cache look like a failing one, or worse let a
        report average it in with real measurements.
        """
        lookups = self.hits + self.misses
        if lookups == 0:
            return None
        return self.hits / lookups

    def to_dict(self) -> dict[str, Any]:
        return {
            "entries": self.entries,
            "hits": self.hits,
            "misses": self.misses,
            "evictions": self.evictions,
            "version_rejections": self.version_rejections,
            "proven_skipped_units": round(self.proven_skipped_units, 4),
            "memory_bytes": self.memory_bytes,
            "hit_rate": self.hit_rate(),
            # ADR-0114's honesty flag, repeated here because the same caveat
            # applies: PATH_COST_UNITS has no calibration code.
            "path_cost_units_calibrated": False,
        }


class TransitionCache:
    """A bounded P0 cache whose savings are ledger-proven or not claimed."""

    def __init__(
        self,
        *,
        capacity: int = MAX_CACHE_ENTRIES,
        model_version: str,
        encoder_version: str,
    ) -> None:
        if capacity < 1:
            raise ContractError(f"capacity must be >= 1, got {capacity}")
        require_identifier(model_version, "TransitionCache.model_version")
        require_identifier(encoder_version, "TransitionCache.encoder_version")
        self.capacity = capacity
        self.model_version = model_version
        self.encoder_version = encoder_version
        self._entries: dict[str, CachedTransition] = {}
        self._recency = BoundedLRUCounter(capacity=capacity)
        # The durable access order. `BoundedLRUCounter` holds the live ordering
        # but exposes no way to read it back, and it is thrown away and rebuilt
        # on every removal. Rebuilding it from `CachedTransition.last_sequence`
        # — the transition sequence at *store* time — discarded every read that
        # had happened since, so the hottest entry became the next eviction
        # victim after any drop/invalidate/forget (S2-03). This counter is
        # bumped on store AND on hit, so the rebuilt order is the real one.
        self._access: dict[str, int] = {}
        self._clock = 0
        self._hits = 0
        self._misses = 0
        self._evictions = 0
        self._version_rejections = 0
        self._proven_skipped = 0.0

    def __len__(self) -> int:
        return len(self._entries)

    def entries(self) -> tuple[CachedTransition, ...]:
        """Live entries, ordered by key so iteration is reproducible."""
        return tuple(self._entries[key] for key in sorted(self._entries))

    def get(self, key: str) -> CachedTransition | None:
        """Read without touching recency or the hit/miss counters (for reports)."""
        return self._entries.get(key)

    def lookup_transition_cache(
        self,
        *,
        atom_id: int,
        epoch_id: int,
        state_delta_mask: int,
        ledger: WorkLedger | None = None,
    ) -> CachedTransition | None:
        """DTL-F16. Return a live, version-matching entry, or ``None``.

        The lookup itself is always recorded as work *performed* — it really ran.
        The skipped ``CORE_INFERENCE`` record is written only on a hit, because
        only a hit genuinely avoids the inference; on a miss the caller is about
        to run it, and recording a skip there is precisely the ADR-0010 defect.
        """
        key = transition_cache_key(
            atom_id=atom_id, epoch_id=epoch_id, state_delta_mask=state_delta_mask
        )
        if ledger is not None:
            ledger.record(
                WorkKind.CACHE_LOOKUP, performed=True, units=CACHE_LOOKUP_UNITS, detail=key
            )
        entry = self._entries.get(key)
        if entry is None:
            self._misses += 1
            return None
        if (
            entry.model_version != self.model_version
            or entry.encoder_version != self.encoder_version
        ):
            # Never a silent hit on stale weights: drop it and make the caller
            # recompute under the versions that actually exist.
            self.drop(key)
            self._version_rejections += 1
            self._misses += 1
            return None
        self._hits += 1
        self._recency.get(key)  # marks the key most-recently-used
        self._touch(key)  # ... and records it durably, so a rebuild keeps it
        refreshed = _copy_with(entry, hits=entry.hits + 1)
        self._entries[key] = refreshed
        if ledger is not None:
            # The ledger owns the phantom check. It is deliberately NOT called
            # here: measured this session, `assert_no_phantom_savings()` costs
            # 3.9 ms per call at 2000 retained accounts because it walks every
            # account, so calling it per event would make the P0 path quadratic.
            # It is a per-run assertion (the gate's, G2.3/G2.10), and until it
            # passes, `proven_skipped_units` is a claim about accepted records
            # rather than a verified saving.
            ledger.record(
                WorkKind.CORE_INFERENCE, performed=False, units=0.0, detail=f"cache hit {key}"
            )
            self._proven_skipped += CORE_INFERENCE_UNITS
        return refreshed

    def store(self, entry: CachedTransition) -> None:
        """Insert or replace an entry, evicting the least-recently-used if full."""
        if not isinstance(entry, CachedTransition):
            raise ContractError(f"store expects a CachedTransition, got {type(entry).__name__}")
        if (
            entry.model_version != self.model_version
            or entry.encoder_version != self.encoder_version
        ):
            raise ContractError(
                f"refusing to store an entry built under model={entry.model_version!r} "
                f"encoder={entry.encoder_version!r} into a cache pinned to "
                f"model={self.model_version!r} encoder={self.encoder_version!r}"
            )
        self._entries[entry.key] = entry
        self._recency.add(entry.key)
        self._touch(entry.key)
        self._reap_evicted()

    def _touch(self, key: str) -> None:
        """Record ``key`` as the most recently accessed entry."""
        self._clock += 1
        self._access[key] = self._clock

    def recency_order(self) -> tuple[str, ...]:
        """Live keys, least-recently-accessed first.

        This is the cache's *access* order, not its insertion order, and it is
        what an LRU policy has to be written against. ``CachedTransition``
        carries a ``last_sequence``, but that is the transition sequence the
        entry was stored under and is never rewritten by a read, so sorting on
        it yields FIFO for any workload that re-reads rather than re-stores.
        """
        return tuple(
            sorted(self._entries, key=lambda key: (self._access.get(key, 0), key))
        )

    def _reap_evicted(self) -> None:
        """Drop entries the recency counter evicted, so both structures agree.

        ``BoundedLRUCounter`` enforces the bound and does not report which key it
        dropped, so the victim is identified by absence. That is O(entries) only
        on an actual eviction, and it keeps the LRU policy in one place instead of
        forking a second implementation of it.
        """
        if len(self._entries) <= self.capacity:
            return
        dropped = [key for key in self._entries if key not in self._recency]
        for key in dropped:
            del self._entries[key]
            self._access.pop(key, None)
            self._evictions += 1

    def _remove(self, key: str) -> bool:
        if key not in self._entries:
            return False
        del self._entries[key]
        self._access.pop(key, None)
        self._evictions += 1
        return True

    def drop(self, key: str) -> bool:
        """Remove one entry and count it as an eviction.

        Every removal counts, whatever the reason — capacity, epoch invalidation
        or utility-based forgetting. Hiding one class of removal would make the
        cache look more stable than it is.
        """
        if not self._remove(key):
            return False
        self._rebuild_recency()
        return True

    def drop_many(self, keys: Iterable[str]) -> int:
        """Remove a batch, rebuilding the recency index once rather than per key."""
        removed = sum(1 for key in list(keys) if self._remove(key))
        if removed:
            self._rebuild_recency()
        return removed

    def _rebuild_recency(self) -> None:
        """Rebuild the recency index after a removal.

        ``BoundedLRUCounter`` has no delete, by design: it is a bounded counter,
        not a map. Rebuilding in ascending *access* order therefore preserves the
        recency the live entries actually have, deterministically. Removals are
        rare (invalidation and batch forgetting), lookups are not, so the cost
        lands in the right place.

        This used to rebuild in ``last_sequence`` order, which is store order:
        every ``drop``/``drop_many``/``invalidate_epoch``/
        ``forget_low_utility_memory`` silently replaced real recency with
        insertion order, so the hottest entry became the next eviction victim
        (S2-03). ``recency_order()`` is now the single source of that ordering.
        """
        rebuilt = BoundedLRUCounter(capacity=self.capacity)
        for key in self.recency_order():
            rebuilt.add(key)
        self._recency = rebuilt

    def invalidate_epoch(self, epoch_id: int) -> int:
        """Remove exactly the entries recorded under ``epoch_id``; return the count.

        Epoch rotation is the one legitimate way cached security meaning expires:
        the host changed, so what was true is no longer known to be true. An entry
        from another epoch is untouched.
        """
        victims = [key for key, entry in self._entries.items() if entry.epoch_id == epoch_id]
        return self.drop_many(victims)

    def stats(self) -> CacheStats:
        return CacheStats(
            entries=len(self._entries),
            hits=self._hits,
            misses=self._misses,
            evictions=self._evictions,
            version_rejections=self._version_rejections,
            proven_skipped_units=self._proven_skipped,
            memory_bytes=self.memory_bytes(),
        )

    def memory_bytes(self) -> int:
        """Computed from live entries plus the recency index, never guessed."""
        live = sum(entry.memory_bytes for entry in self._entries.values())
        return live + self._recency.memory_bytes

    def replace_utilities(self, utilities: Sequence[tuple[str, float]]) -> int:
        """Set the ``utility`` field on named entries; return how many were updated.

        Utility is computed outside the cache (it needs causal credit and an
        uncertainty reduction the cache cannot see), so it is written back here
        rather than derived here.
        """
        updated = 0
        for key, utility in utilities:
            entry = self._entries.get(key)
            if entry is None:
                continue
            if not isinstance(utility, float) or utility != utility:
                raise ContractError(f"utility for {key!r} must be a finite float, got {utility!r}")
            self._entries[key] = _copy_with(entry, utility=utility)
            updated += 1
        return updated
