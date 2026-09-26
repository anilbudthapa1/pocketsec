"""D6.9 / HEL-F12 — the Knowledge Fossil store: the states rollback can return to.

Architecture §15: a fossil is an immutable, content-addressed snapshot of a validated
trusted state. It is what makes every promotion reversible *to a byte-identical prior
state identified by digest* (§1): the controller fossilises the current state before
it installs a new one, and rollback loads that fossil back.

**Rule A — one key space.** A fossil's ``artifact_hash`` *is*
``TrustedKnowledgeState.digest()``: the sha256 of the **uncompressed** canonical bytes.
Compression is a storage detail, never part of an identity. :meth:`FossilStore.create_fossil`
asserts the two are the same string, and a test pins it.

What it refuses:

* **A corrupted fossil is never returned.** :meth:`FossilStore.load` decompresses,
  re-hashes and raises :class:`FossilIntegrityError` on any mismatch — a flipped byte on
  disk, a truncated file, a missing file. :meth:`FossilStore.latest_known_good` skips such
  fossils (and counts them) rather than handing rollback a state it cannot vouch for.
* **An item without lineage is refused at load time.** Loading goes through
  ``TrustedKnowledgeState.from_canonical_bytes``, which refuses a non-genesis item with no
  capsule or evidence citations, and — when a lineage DAG is passed — any item whose
  lineage is incomplete.
* **Unbounded retention.** At most ``max_fossils`` fossils and ``max_bytes`` compressed
  bytes. Eviction takes the **oldest unpinned** fossil first and appends a
  :class:`FossilTombstone` (bounded by ``MAX_TOMBSTONES``; tombstones that fall off are
  counted, never silently lost). Pinned fossils — the current trusted state and the
  probation rollback target — are never evicted; at most ``MAX_PINNED_FOSSILS`` may be
  pinned, and a store that cannot make room without evicting a pinned fossil refuses the
  newcomer with :class:`FossilCapacityError`.

**Rollback depth is bounded by design (ADR-0052).** The 2 GB target forbids keeping every
state ever trusted, so a state older than the retained fossils cannot be restored. The
tombstone says so — hash, parents, eviction sequence — rather than pretending otherwise.

Stdlib only: payloads are ``zlib``-compressed in memory and, when ``directory`` is given,
also written as ``<hex>.fossil`` files, which are then the copy :meth:`load` verifies.
"""

from __future__ import annotations

import json
import zlib
from collections import deque
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path

from pocketsec.stage0.contracts.common import ContractError, digest_of_bytes
from pocketsec.stage2.encoder.ssir_encoder import ENCODER_VERSION, FEATURE_LAYOUT
from pocketsec.stage6.capsule.experience_capsule import EXPERIENCE_CAPSULE_V1_VERSION
from pocketsec.stage6.fossils.lineage import KnowledgeLineageDAG
from pocketsec.stage6.memory.semantic import ItemKind, TrustedKnowledgeState

__all__ = [
    "MAX_FOSSILS",
    "MAX_FOSSIL_BYTES",
    "MAX_PINNED_FOSSILS",
    "MAX_TOMBSTONES",
    "FossilCapacityError",
    "FossilIntegrityError",
    "FossilReason",
    "FossilStore",
    "FossilStoreStats",
    "FossilTombstone",
    "KnowledgeFossil",
    "UnknownFossilError",
    "encoder_layout_digest",
]

#: §4.21. Chosen parameters, not measurements.
MAX_FOSSILS: int = 32
MAX_PINNED_FOSSILS: int = 4
MAX_FOSSIL_BYTES: int = 16_777_216
MAX_TOMBSTONES: int = 256

_ZLIB_LEVEL = 9
_FILE_SUFFIX = ".fossil"
_SLOT_BYTES = 8
_FOSSIL_OVERHEAD = 12 * _SLOT_BYTES
_TOMBSTONE_OVERHEAD = 4 * _SLOT_BYTES


class FossilIntegrityError(ContractError):
    """A fossil's bytes do not hash to its artifact hash. It is never returned."""


class FossilCapacityError(ContractError):
    """The store cannot hold this fossil without evicting a pinned one, or pinning past the cap."""


class UnknownFossilError(ContractError):
    """No retained fossil has this hash — never created, or evicted (see the tombstones)."""


class FossilReason(StrEnum):
    GENESIS = "GENESIS"
    PRE_PROMOTION = "PRE_PROMOTION"
    PROMOTION = "PROMOTION"
    CONTEXT_DORMANCY = "CONTEXT_DORMANCY"
    CONSOLIDATION = "CONSOLIDATION"
    RETIREMENT = "RETIREMENT"


@dataclass(frozen=True, slots=True)
class KnowledgeFossil:
    """Architecture §15, every field bound."""

    artifact_hash: str
    parent_hashes: tuple[str, ...]
    versions: tuple[tuple[str, str], ...]
    benchmark_fingerprint: str
    epoch_range: tuple[int, int]
    capabilities_preserved: tuple[str, ...]
    creation_reason: FossilReason
    created_sequence: int
    pinned: bool
    compressed_bytes: int


@dataclass(frozen=True, slots=True)
class FossilTombstone:
    """What remains of an evicted fossil: enough to say the state existed and cannot return."""

    artifact_hash: str
    reason: str
    evicted_sequence: int
    parent_hashes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class FossilStoreStats:
    fossils: int
    pinned: int
    compressed_bytes: int
    evictions: int
    tombstones: int
    tombstones_dropped: int
    integrity_failures: int
    memory_bytes: int


def encoder_layout_digest() -> str:
    """Digest of the Stage 2 feature layout a fossil's steps and anchors were encoded under."""
    payload = json.dumps({"version": ENCODER_VERSION, "layout": [list(g) for g in FEATURE_LAYOUT]})
    return digest_of_bytes(payload.encode("utf-8"))


def _hex(artifact_hash: str) -> str:
    """The filename-safe part of a ``sha256:<hex>`` hash; anything else is refused."""
    prefix, _, digest = artifact_hash.partition(":")
    if prefix != "sha256" or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise UnknownFossilError(f"not a sha256 artifact hash: {artifact_hash!r}")
    return digest


class FossilStore:
    """Bounded, integrity-checked, content-addressed storage of trusted states."""

    def __init__(
        self,
        *,
        max_fossils: int = MAX_FOSSILS,
        max_bytes: int = MAX_FOSSIL_BYTES,
        directory: Path | None = None,
    ) -> None:
        if max_fossils < 1 or max_bytes < 1:
            raise ValueError("a fossil store needs room for at least one fossil")
        self._max_fossils = max_fossils
        self._max_bytes = max_bytes
        self._directory = directory
        if directory is not None:
            directory.mkdir(parents=True, exist_ok=True)
        # Insertion order is creation order; eviction walks it oldest first.
        self._fossils: dict[str, KnowledgeFossil] = {}
        self._payloads: dict[str, bytes] = {}
        self._tombstones: deque[FossilTombstone] = deque(maxlen=MAX_TOMBSTONES)
        self._evictions = 0
        self._tombstones_dropped = 0
        self._integrity_failures = 0

    # --- write side ------------------------------------------------------------

    def create_fossil(
        self,
        state: TrustedKnowledgeState,
        *,
        reason: FossilReason,
        fingerprint: str,
        epoch_range: tuple[int, int],
        sequence: int,
        pin: bool = False,
    ) -> KnowledgeFossil:
        """HEL-F12. Snapshot ``state``; idempotent on an already-held hash (it may gain a pin)."""
        canonical = state.canonical_bytes()
        artifact_hash = digest_of_bytes(canonical)
        if artifact_hash != state.digest():  # Rule A, asserted where it could break
            raise FossilIntegrityError("state.digest() is not the sha256 of its canonical bytes")
        existing = self._fossils.get(artifact_hash)
        if existing is not None:
            if pin and not existing.pinned:
                self.pin(artifact_hash)
            return self._fossils[artifact_hash]
        low, high = epoch_range
        if low > high:
            raise ContractError(f"epoch_range must be ordered, got {epoch_range!r}")
        if pin and self._pinned_count() >= MAX_PINNED_FOSSILS:
            raise FossilCapacityError(f"already {MAX_PINNED_FOSSILS} pinned fossils")
        compressed = zlib.compress(canonical, _ZLIB_LEVEL)
        self._make_room(len(compressed), sequence=sequence)
        fossil = KnowledgeFossil(
            artifact_hash=artifact_hash,
            parent_hashes=() if state.parent_digest is None else (state.parent_digest,),
            versions=(
                ("state", str(state.version)),
                ("capsule_schema", EXPERIENCE_CAPSULE_V1_VERSION),
                ("encoder", encoder_layout_digest()),
            ),
            benchmark_fingerprint=fingerprint,
            epoch_range=(int(low), int(high)),
            capabilities_preserved=tuple(
                item.item_id for item in state.items if item.kind is ItemKind.DETECTOR
            ),
            creation_reason=FossilReason(reason),
            created_sequence=sequence,
            pinned=pin,
            compressed_bytes=len(compressed),
        )
        if self._directory is not None:
            self._path(artifact_hash).write_bytes(compressed)
        self._fossils[artifact_hash] = fossil
        self._payloads[artifact_hash] = compressed
        return fossil

    def _make_room(self, incoming_bytes: int, *, sequence: int) -> None:
        if incoming_bytes > self._max_bytes:
            raise FossilCapacityError(
                f"fossil of {incoming_bytes} compressed bytes exceeds the store cap "
                f"{self._max_bytes}"
            )
        while (
            len(self._fossils) + 1 > self._max_fossils
            or self._compressed_total() + incoming_bytes > self._max_bytes
        ):
            victim = next((f for f in self._fossils.values() if not f.pinned), None)
            if victim is None:
                raise FossilCapacityError(
                    "every retained fossil is pinned; refusing rather than evicting a "
                    "rollback target"
                )
            self._evict(victim, sequence=sequence)

    def _evict(self, fossil: KnowledgeFossil, *, sequence: int) -> None:
        del self._fossils[fossil.artifact_hash]
        del self._payloads[fossil.artifact_hash]
        if self._directory is not None:
            self._path(fossil.artifact_hash).unlink(missing_ok=True)
        if len(self._tombstones) == self._tombstones.maxlen:
            self._tombstones_dropped += 1
        self._tombstones.append(
            FossilTombstone(
                artifact_hash=fossil.artifact_hash,
                reason=(
                    f"evicted: oldest unpinned ({fossil.creation_reason}); "
                    "rollback depth is bounded"
                ),
                evicted_sequence=sequence,
                parent_hashes=fossil.parent_hashes,
            )
        )
        self._evictions += 1

    def pin(self, artifact_hash: str) -> None:
        fossil = self._require(artifact_hash)
        if fossil.pinned:
            return
        if self._pinned_count() >= MAX_PINNED_FOSSILS:
            raise FossilCapacityError(
                f"already {MAX_PINNED_FOSSILS} pinned fossils; unpin one first"
            )
        self._fossils[artifact_hash] = replace(fossil, pinned=True)

    def unpin(self, artifact_hash: str) -> None:
        fossil = self._require(artifact_hash)
        if fossil.pinned:
            self._fossils[artifact_hash] = replace(fossil, pinned=False)

    # --- read side ---------------------------------------------------------------

    def payload(self, artifact_hash: str) -> bytes:
        """The verified, uncompressed canonical bytes; raises rather than return a corrupt copy."""
        self._require(artifact_hash)
        compressed = self._stored_bytes(artifact_hash)
        try:
            canonical = zlib.decompress(compressed)
        except zlib.error as exc:
            self._integrity_failures += 1
            raise FossilIntegrityError(
                f"fossil {artifact_hash} does not decompress: {exc}"
            ) from exc
        if digest_of_bytes(canonical) != artifact_hash:
            self._integrity_failures += 1
            raise FossilIntegrityError(f"fossil {artifact_hash} re-hashes to a different digest")
        return canonical

    def load(
        self, artifact_hash: str, *, lineage: KnowledgeLineageDAG | None = None
    ) -> TrustedKnowledgeState:
        """Decompress, re-hash, rebuild. A corrupted fossil raises and is never returned."""
        canonical = self.payload(artifact_hash)
        state = TrustedKnowledgeState.from_canonical_bytes(canonical, lineage=lineage)
        if state.digest() != artifact_hash:
            self._integrity_failures += 1
            raise FossilIntegrityError(
                f"fossil {artifact_hash} rebuilt into a state with digest {state.digest()}"
            )
        return state

    def latest_known_good(
        self, *, excluding: frozenset[str] = frozenset()
    ) -> KnowledgeFossil | None:
        """The newest retained fossil not in ``excluding`` whose bytes verify, or ``None``."""
        ordered = sorted(
            enumerate(self._fossils.values()),
            key=lambda pair: (pair[1].created_sequence, pair[0]),
            reverse=True,
        )
        for _, fossil in ordered:
            if fossil.artifact_hash in excluding:
                continue
            try:
                self.payload(fossil.artifact_hash)
            except FossilIntegrityError:
                continue
            return fossil
        return None

    def get(self, artifact_hash: str) -> KnowledgeFossil | None:
        return self._fossils.get(artifact_hash)

    def tombstone_for(self, artifact_hash: str) -> FossilTombstone | None:
        return next((t for t in self._tombstones if t.artifact_hash == artifact_hash), None)

    def fossils(self) -> tuple[KnowledgeFossil, ...]:
        return tuple(self._fossils.values())

    def tombstones(self) -> tuple[FossilTombstone, ...]:
        return tuple(self._tombstones)

    def evictions(self) -> int:
        return self._evictions

    def memory_bytes(self) -> int:
        """Compressed payloads plus a structural estimate of every record and tombstone."""
        records = sum(
            _FOSSIL_OVERHEAD
            + len(f.artifact_hash)
            + len(f.benchmark_fingerprint)
            + sum(len(h) for h in f.parent_hashes)
            + sum(len(k) + len(v) for k, v in f.versions)
            + sum(len(c) for c in f.capabilities_preserved)
            for f in self._fossils.values()
        )
        tombstones = sum(
            _TOMBSTONE_OVERHEAD
            + len(t.artifact_hash)
            + len(t.reason)
            + sum(len(h) for h in t.parent_hashes)
            for t in self._tombstones
        )
        return self._compressed_total() + records + tombstones

    def stats(self) -> FossilStoreStats:
        return FossilStoreStats(
            fossils=len(self._fossils),
            pinned=self._pinned_count(),
            compressed_bytes=self._compressed_total(),
            evictions=self._evictions,
            tombstones=len(self._tombstones),
            tombstones_dropped=self._tombstones_dropped,
            integrity_failures=self._integrity_failures,
            memory_bytes=self.memory_bytes(),
        )

    # --- internals -----------------------------------------------------------------

    def _require(self, artifact_hash: str) -> KnowledgeFossil:
        fossil = self._fossils.get(artifact_hash)
        if fossil is not None:
            return fossil
        tombstone = self.tombstone_for(artifact_hash)
        if tombstone is not None:
            raise UnknownFossilError(
                f"fossil {artifact_hash} was evicted at sequence {tombstone.evicted_sequence}; "
                "rollback depth is bounded (ADR-0052)"
            )
        raise UnknownFossilError(f"no fossil {artifact_hash}")

    def _stored_bytes(self, artifact_hash: str) -> bytes:
        if self._directory is None:
            return self._payloads[artifact_hash]
        path = self._path(artifact_hash)
        try:
            return path.read_bytes()
        except OSError as exc:
            self._integrity_failures += 1
            raise FossilIntegrityError(
                f"fossil file for {artifact_hash} is unreadable: {exc}"
            ) from exc

    def _path(self, artifact_hash: str) -> Path:
        assert self._directory is not None
        return self._directory / f"{_hex(artifact_hash)}{_FILE_SUFFIX}"

    def _pinned_count(self) -> int:
        return sum(1 for f in self._fossils.values() if f.pinned)

    def _compressed_total(self) -> int:
        return sum(len(p) for p in self._payloads.values())
