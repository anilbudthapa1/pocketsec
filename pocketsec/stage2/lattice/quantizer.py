"""D2.6 / DTL-F04 — ``quantize_behaviour_atom``, and the control it must beat.

Two quantizers live here on purpose.

:class:`BehaviourQuantizer` is the learned one: an online, bounded, deterministic
k-prototype clusterer over the 96-slot encoder output. No numpy, no training
loop, no epochs over a corpus — it sees each transition once, on the endpoint.

:class:`HashBucketQuantizer` is **the simple control** (spec §5). Its atom id is a
deterministic bucket of ``(relation_family, state_delta_mask,
object_property_mask)``: zero training, zero drift, and a fraction of the bytes,
because it stores no prototype. Acceptance criterion 4 lets Stage 2 *reject* the
discrete layer, and it can only be rejected honestly if the dumb version is
actually implemented and actually measured. It is not a stub.

Two design commitments worth stating because they are easy to lose:

* **Atom ids are content-addressed, not counter-assigned.** An id is a stable
  digest of the point that created the atom, folded into a fixed id space. A
  counter would make every id a function of everything that happened earlier, so
  prepending unrelated traffic would renumber the whole lattice — and a lattice
  whose node names move cannot be exported to Stage 3, compared across runs, or
  checked for stability (G2.4). The digest uses ``zlib.crc32``, never builtin
  ``hash()``, so it does not depend on ``PYTHONHASHSEED``.
* **Bounds are enforced by eviction, and every eviction is counted.** At
  ``max_atoms`` a new behaviour displaces the least-visited, then the
  stalest, then the lowest-id atom. Truncation is explicit (MEMORY.md
  invariant); a silently dropped atom is a silently wrong probability.

Neither quantizer decides anything. They assign a label. Whether that label is
worth its bytes is a measurement, recorded in ADR-0115.
"""

from __future__ import annotations

import zlib
from dataclasses import dataclass, field, replace
from typing import Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.state.security_state import SecurityStateV1
from pocketsec.stage2.encoder.ssir_encoder import (
    FEATURE_WIDTH,
    GROUP_OFFSETS,
    EncodedTransition,
)
from pocketsec.stage2.lattice.atom import (
    BehaviourAtom,
    CompileStatus,
    bound_epoch_counts,
    welford_update,
)

__all__ = [
    "BEHAVIOUR_QUANTIZER_ENABLED",
    "DEFAULT_QUANTIZER",
    "ID_SPACE",
    "MAX_ATOMS",
    "SPLIT_RADIUS",
    "BehaviourQuantizer",
    "HashBucket",
    "HashBucketQuantizer",
    "QuantizeResult",
    "QuantizerStats",
    "stable_bucket_id",
]

MAX_ATOMS: int = 256
#: A point further than this (squared L2) from every prototype opens a new atom.
SPLIT_RADIUS: float = 0.35
#: Id space for content-addressed atom ids. Wide enough that collisions among
#: ≤256 live atoms are rare; collisions are still handled by probing, because
#: "rare" is not "impossible" and a shared id merges two behaviours invisibly.
ID_SPACE: int = 1 << 24

_SLOT_BYTES: int = 8
_FLOAT_BYTES: int = 8
_INT_BYTES: int = 8

#: Where the encoder puts scalar uncertainty. Read from the layout, never a
#: literal: a magic index into a frozen layout points at the wrong feature the
#: moment the layout grows (the encoder makes the same point).
_UNCERTAINTY_INDEX: int = GROUP_OFFSETS["uncertainty"]


#: **ADR-0115: the learned quantizer is rejected, and this is what "default off"
#: means inside this package.** Measured on the fixed split (corpus=ambiguous,
#: count=240, seed=11, 17,898 transitions, 192/48 scenario split): transition
#: log-loss 1.889260 for :class:`HashBucketQuantizer` at 14 atoms / 3,136 bytes,
#: against 2.148290 for :class:`BehaviourQuantizer` held to the same byte budget
#: and 3.613527 when given 79.7× the memory (256 atoms / 249,856 bytes). The
#: learned layer loses on both axes, so a caller that has not read the ADR gets
#: the control.
#: ``DEFAULT_QUANTIZER`` is derived from this flag at the bottom of the module.
BEHAVIOUR_QUANTIZER_ENABLED: bool = False


def stable_bucket_id(*parts: int) -> int:
    """A deterministic id from integer parts, independent of ``PYTHONHASHSEED``.

    ``zlib.crc32`` over a canonical decimal encoding. Builtin ``hash()`` is
    randomised per process, so an id built from it would differ between two runs
    of the same corpus — which is exactly the reproducibility property G2.4
    measures.
    """
    payload = ",".join(str(int(part)) for part in parts).encode("ascii")
    return zlib.crc32(payload) % ID_SPACE


def _prototype_id(features: tuple[float, ...]) -> int:
    """Content address of a creating point, stable to 6 decimal places."""
    payload = ";".join(f"{value:.6f}" for value in features).encode("ascii")
    return zlib.crc32(payload) % ID_SPACE


def _uncertainty_of(encoded: EncodedTransition) -> float:
    return encoded.features[_UNCERTAINTY_INDEX]


@dataclass(frozen=True, slots=True)
class QuantizeResult:
    """What one quantization did. ``created``/``evicted_atom_id`` are the audit."""

    atom_id: int
    #: Squared L2 to the winning prototype. 0.0 for a bucket quantizer, which
    #: has no metric — see :class:`HashBucketQuantizer`.
    distance: float
    created: bool
    evicted_atom_id: int | None
    #: Did this transition's uncertainty fall inside the atom's envelope *before*
    #: this observation widened it? A run of ``False`` here is the D2.7 fission
    #: signal: the atom is being asked to stand for observations it does not
    #: cover.
    inside_envelope: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "atom_id": self.atom_id,
            "distance": round(self.distance, 6),
            "created": self.created,
            "evicted_atom_id": self.evicted_atom_id,
            "inside_envelope": self.inside_envelope,
        }


@dataclass(frozen=True, slots=True)
class QuantizerStats:
    """Quality and cost together, per the Stage 0 measurement rule."""

    atoms: int
    creations: int
    evictions: int
    mean_visits: float
    memory_bytes: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "atoms": self.atoms,
            "creations": self.creations,
            "evictions": self.evictions,
            "mean_visits": round(self.mean_visits, 4),
            "memory_bytes": self.memory_bytes,
        }


def _eviction_key(atom: BehaviourAtom) -> tuple[int, int, int]:
    """Least-visited, then stalest, then lowest id.

    The third term exists only to make the choice total: two atoms with equal
    visits and equal recency must not be resolved by dict ordering, or the
    partition stops being reproducible.
    """
    return (atom.visit_count, atom.last_sequence, atom.atom_id)


class BehaviourQuantizer:
    """Online, bounded, deterministic k-prototype quantizer (DTL-F04).

    Refuses to grow past ``max_atoms``; refuses to forget silently. It does not
    retain the points it saw, so it cannot re-cluster and cannot validate a split
    against original samples — that limit is stated again in
    ``restructure.split_heterogeneous_atom``, where it matters.
    """

    __slots__ = (
        "_atoms",
        "_creations",
        "_evictions",
        "_learning_rate",
        "_max_atoms",
        "_radius",
    )

    def __init__(
        self,
        *,
        max_atoms: int = MAX_ATOMS,
        radius: float = SPLIT_RADIUS,
        learning_rate: float = 0.05,
    ) -> None:
        if max_atoms <= 0:
            raise ContractError(f"max_atoms must be positive, got {max_atoms}")
        if radius <= 0.0:
            raise ContractError(f"radius must be positive, got {radius}")
        if not 0.0 < learning_rate <= 1.0:
            raise ContractError(
                f"learning_rate must be in (0, 1], got {learning_rate}"
            )
        self._atoms: dict[int, BehaviourAtom] = {}
        self._max_atoms = max_atoms
        self._radius = radius
        self._learning_rate = learning_rate
        self._creations = 0
        self._evictions = 0

    # --- read side -----------------------------------------------------------

    @property
    def max_atoms(self) -> int:
        return self._max_atoms

    @property
    def radius(self) -> float:
        return self._radius

    def atoms(self) -> tuple[BehaviourAtom, ...]:
        """Atoms in id order, so callers iterate reproducibly."""
        return tuple(self._atoms[key] for key in sorted(self._atoms))

    def get(self, atom_id: int) -> BehaviourAtom | None:
        return self._atoms.get(atom_id)

    def stats(self) -> QuantizerStats:
        visits = [atom.visit_count for atom in self._atoms.values()]
        return QuantizerStats(
            atoms=len(self._atoms),
            creations=self._creations,
            evictions=self._evictions,
            mean_visits=(sum(visits) / len(visits)) if visits else 0.0,
            memory_bytes=self.memory_bytes(),
        )

    def memory_bytes(self) -> int:
        """Sum of the live atoms plus the index that holds them."""
        index = len(self._atoms) * (_INT_BYTES + _SLOT_BYTES)
        return index + sum(atom.memory_bytes() for atom in self._atoms.values())

    # --- write side ----------------------------------------------------------

    def quantize_behaviour_atom(
        self,
        encoded: EncodedTransition,
        *,
        state: SecurityStateV1,
        epoch_id: int,
        sequence: int,
    ) -> QuantizeResult:
        """DTL-F04. Assign one transition to an atom, creating one if needed."""
        features = encoded.features
        if len(features) != FEATURE_WIDTH:
            raise ContractError(
                f"quantizer needs {FEATURE_WIDTH} features, got {len(features)}"
            )
        winner, distance = self._nearest(features)
        if winner is None or distance > self._radius:
            if winner is None or len(self._atoms) < self._max_atoms:
                return self._create(
                    encoded, state=state, epoch_id=epoch_id, sequence=sequence
                )
            # At capacity a far point still has to go somewhere. Displacing the
            # least useful atom is the honest choice: assigning it to a distant
            # prototype would quietly poison that prototype's meaning.
            evicted = self._evict()
            created = self._create(
                encoded, state=state, epoch_id=epoch_id, sequence=sequence
            )
            return replace(created, evicted_atom_id=evicted)
        return self._absorb(
            winner,
            encoded,
            distance=distance,
            state=state,
            epoch_id=epoch_id,
            sequence=sequence,
        )

    def fission_atom(self, atom_id: int, *, sequence: int) -> int | None:
        """DTL-F14 support: install a sibling prototype displaced from ``atom_id``.

        Returns the new atom id, or ``None`` when the parent is unknown, when the
        atom count is already at ``max_atoms`` (a split must not evict a third
        atom to pay for itself), or when the displaced prototype collides with an
        existing atom.

        **The sibling's statistics are an estimate.** The quantizer keeps no
        samples, so the parent's visits and ΔΦ mass are halved between the two
        atoms rather than re-derived. A split therefore cannot be validated
        against the original points — only against the successor distribution it
        separates, which is what ``restructure`` measures.
        """
        parent = self._atoms.get(atom_id)
        if parent is None or len(self._atoms) >= self._max_atoms:
            return None
        sibling_prototype = self._displaced(parent.prototype)
        sibling_id = _prototype_id(sibling_prototype)
        if sibling_id in self._atoms or sibling_id == atom_id:
            return None
        kept = (parent.visit_count + 1) // 2
        moved = parent.visit_count - kept
        if moved < 1:
            return None
        share = moved / parent.visit_count
        self._atoms[sibling_id] = BehaviourAtom(
            atom_id=sibling_id,
            prototype=sibling_prototype,
            visit_count=moved,
            epoch_counts=bound_epoch_counts(
                {
                    epoch: max(1, int(count * share))
                    for epoch, count in parent.epoch_counts.items()
                }
            ),
            state_summary=parent.state_summary,
            delta_phi_mean=parent.delta_phi_mean,
            delta_phi_m2=parent.delta_phi_m2 * share,
            uncertainty_envelope=parent.uncertainty_envelope,
            compile_status=CompileStatus.NEURAL,
            first_sequence=parent.first_sequence,
            last_sequence=sequence,
        )
        self._atoms[atom_id] = replace(
            parent,
            visit_count=kept,
            delta_phi_m2=parent.delta_phi_m2 * (1.0 - share),
            compile_status=CompileStatus.NEURAL,
            last_sequence=max(parent.last_sequence, sequence),
        )
        self._creations += 1
        return sibling_id

    # --- internals -----------------------------------------------------------

    def _nearest(
        self, features: tuple[float, ...]
    ) -> tuple[BehaviourAtom | None, float]:
        """Nearest prototype; ties broken by the lowest atom id."""
        best: BehaviourAtom | None = None
        best_distance = float("inf")
        # Ascending id order, so a strict ``<`` resolves a tie in favour of the
        # lowest atom id without a second comparison.
        for atom_id in sorted(self._atoms):
            atom = self._atoms[atom_id]
            distance = atom.distance_within(features, best_distance)
            if distance < best_distance:
                best, best_distance = atom, distance
        return best, best_distance

    def _create(
        self,
        encoded: EncodedTransition,
        *,
        state: SecurityStateV1,
        epoch_id: int,
        sequence: int,
    ) -> QuantizeResult:
        uncertainty = _uncertainty_of(encoded)
        atom_id = self._free_id(_prototype_id(encoded.features))
        self._atoms[atom_id] = BehaviourAtom(
            atom_id=atom_id,
            prototype=encoded.features,
            visit_count=1,
            epoch_counts={epoch_id: 1},
            state_summary=state,
            delta_phi_mean=encoded.delta_phi,
            delta_phi_m2=0.0,
            uncertainty_envelope=(uncertainty, uncertainty),
            compile_status=CompileStatus.NEURAL,
            first_sequence=sequence,
            last_sequence=sequence,
        )
        self._creations += 1
        # A brand-new atom defines its own envelope, so the point is inside it by
        # construction. Reporting False here would make every creation look like
        # a fission candidate.
        return QuantizeResult(
            atom_id=atom_id,
            distance=0.0,
            created=True,
            evicted_atom_id=None,
            inside_envelope=True,
        )

    def _free_id(self, candidate: int) -> int:
        """Linear probing, so a crc32 collision cannot merge two behaviours."""
        atom_id = candidate
        probes = 0
        while atom_id in self._atoms:
            probes += 1
            if probes > self._max_atoms:  # pragma: no cover - needs 256 collisions
                raise ContractError("atom id space exhausted by collisions")
            atom_id = (atom_id + 1) % ID_SPACE
        return atom_id

    def _absorb(
        self,
        atom: BehaviourAtom,
        encoded: EncodedTransition,
        *,
        distance: float,
        state: SecurityStateV1,
        epoch_id: int,
        sequence: int,
    ) -> QuantizeResult:
        low, high = atom.uncertainty_envelope
        uncertainty = _uncertainty_of(encoded)
        inside = low <= uncertainty <= high
        rate = self._learning_rate
        prototype = tuple(
            centre + rate * (value - centre)
            for centre, value in zip(atom.prototype, encoded.features, strict=True)
        )
        visits = atom.visit_count + 1
        mean, m2 = welford_update(
            visits, atom.delta_phi_mean, atom.delta_phi_m2, encoded.delta_phi
        )
        epoch_counts = dict(atom.epoch_counts)
        epoch_counts[epoch_id] = epoch_counts.get(epoch_id, 0) + 1
        self._atoms[atom.atom_id] = BehaviourAtom(
            atom_id=atom.atom_id,
            prototype=prototype,
            visit_count=visits,
            epoch_counts=epoch_counts,
            # Join, not overwrite: the atom summarises every state it stood for.
            state_summary=SecurityStateV1.join(atom.state_summary, state),
            delta_phi_mean=mean,
            delta_phi_m2=m2,
            uncertainty_envelope=(min(low, uncertainty), max(high, uncertainty)),
            compile_status=atom.compile_status,
            first_sequence=atom.first_sequence,
            last_sequence=max(atom.last_sequence, sequence),
        )
        return QuantizeResult(
            atom_id=atom.atom_id,
            distance=distance,
            created=False,
            evicted_atom_id=None,
            inside_envelope=inside,
        )

    def _evict(self) -> int:
        victim = min(self._atoms.values(), key=_eviction_key)
        del self._atoms[victim.atom_id]
        self._evictions += 1
        return victim.atom_id

    def _displaced(self, prototype: tuple[float, ...]) -> tuple[float, ...]:
        """Push a prototype half a radius along its own deviation direction.

        Deterministic and derived from the parent alone: there is no stored data
        to split on, so the only defensible displacement is one the parent
        implies. Unit-normalised, so the offset is exactly half the split radius
        in the squared metric.
        """
        mean = sum(prototype) / len(prototype)
        deviation = [value - mean for value in prototype]
        norm = sum(component * component for component in deviation) ** 0.5
        if norm == 0.0:
            # A flat prototype has no direction; nudge the first coordinate so
            # the sibling is still a distinct point.
            offset = [0.0] * len(prototype)
            offset[0] = (self._radius * 0.5) ** 0.5
        else:
            scale = (self._radius * 0.5) ** 0.5 / norm
            offset = [component * scale for component in deviation]
        return tuple(
            value + shift for value, shift in zip(prototype, offset, strict=True)
        )


@dataclass(frozen=True, slots=True)
class HashBucket:
    """One bucket of the control quantizer. No prototype — that is the point."""

    atom_id: int
    #: ``(relation_family, state_delta_mask, object_property_mask)``.
    key: tuple[int, int, int]
    visit_count: int
    epoch_counts: dict[int, int]
    state_summary: SecurityStateV1
    delta_phi_mean: float
    delta_phi_m2: float
    uncertainty_envelope: tuple[float, float]
    first_sequence: int
    last_sequence: int

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "epoch_counts", bound_epoch_counts(dict(self.epoch_counts))
        )

    def variance(self) -> float:
        if self.visit_count < 2:
            return 0.0
        return self.delta_phi_m2 / (self.visit_count - 1)

    def memory_bytes(self) -> int:
        slots = len(HashBucket.__slots__) * _SLOT_BYTES
        key = len(self.key) * _INT_BYTES
        epochs = len(self.epoch_counts) * (_INT_BYTES + _INT_BYTES)
        state = 9 * _SLOT_BYTES
        envelope = len(self.uncertainty_envelope) * _FLOAT_BYTES
        return slots + key + epochs + state + envelope

    def to_dict(self) -> dict[str, Any]:
        return {
            "atom_id": self.atom_id,
            "key": list(self.key),
            "visit_count": self.visit_count,
            "epochs": sorted(self.epoch_counts),
            "state_summary": self.state_summary.to_dict(),
            "delta_phi_mean": round(self.delta_phi_mean, 6),
            "memory_bytes": self.memory_bytes(),
        }


@dataclass(frozen=True, slots=True)
class HashBucketQuantizer:
    """THE SIMPLE CONTROL (spec §5). Zero training, zero drift, no prototype.

    ``atom_id = stable_bucket_id(relation_family, state_delta_mask,
    object_property_mask)``. Two transitions with the same triple always get the
    same id, in any process, in any order, forever — which is a stability
    property the learned quantizer has to *earn*.

    It is deliberately cheaper per atom: a bucket stores three ints and a state
    summary instead of 96 floats. At a matched byte budget the learned quantizer
    therefore gets far fewer atoms, and that is the comparison spec §5 asks for
    ("transition log-loss at equal ``memory_bytes``").
    """

    max_atoms: int = MAX_ATOMS
    _buckets: dict[int, HashBucket] = field(default_factory=dict, repr=False)
    _counters: dict[str, int] = field(
        default_factory=lambda: {"creations": 0, "evictions": 0, "collisions": 0},
        repr=False,
    )

    def __post_init__(self) -> None:
        if self.max_atoms <= 0:
            raise ContractError(f"max_atoms must be positive, got {self.max_atoms}")

    def buckets(self) -> tuple[HashBucket, ...]:
        return tuple(self._buckets[key] for key in sorted(self._buckets))

    def get(self, atom_id: int) -> HashBucket | None:
        return self._buckets.get(atom_id)

    def stats(self) -> QuantizerStats:
        visits = [bucket.visit_count for bucket in self._buckets.values()]
        return QuantizerStats(
            atoms=len(self._buckets),
            creations=self._counters["creations"],
            evictions=self._counters["evictions"],
            mean_visits=(sum(visits) / len(visits)) if visits else 0.0,
            memory_bytes=self.memory_bytes(),
        )

    def memory_bytes(self) -> int:
        index = len(self._buckets) * (_INT_BYTES + _SLOT_BYTES)
        return index + sum(bucket.memory_bytes() for bucket in self._buckets.values())

    def quantize_behaviour_atom(
        self,
        encoded: EncodedTransition,
        *,
        state: SecurityStateV1,
        epoch_id: int,
        sequence: int,
    ) -> QuantizeResult:
        """Same signature as the learned quantizer, so a harness can swap them."""
        key = (
            encoded.relation_family,
            encoded.state_delta_mask,
            encoded.object_property_mask,
        )
        atom_id = self._bucket_id(key)
        uncertainty = _uncertainty_of(encoded)
        existing = self._buckets.get(atom_id)
        evicted: int | None = None
        if existing is None:
            if len(self._buckets) >= self.max_atoms:
                evicted = self._evict()
            self._buckets[atom_id] = HashBucket(
                atom_id=atom_id,
                key=key,
                visit_count=1,
                epoch_counts={epoch_id: 1},
                state_summary=state,
                delta_phi_mean=encoded.delta_phi,
                delta_phi_m2=0.0,
                uncertainty_envelope=(uncertainty, uncertainty),
                first_sequence=sequence,
                last_sequence=sequence,
            )
            self._counters["creations"] += 1
            return QuantizeResult(
                atom_id=atom_id,
                distance=0.0,
                created=True,
                evicted_atom_id=evicted,
                inside_envelope=True,
            )
        low, high = existing.uncertainty_envelope
        inside = low <= uncertainty <= high
        visits = existing.visit_count + 1
        mean, m2 = welford_update(
            visits, existing.delta_phi_mean, existing.delta_phi_m2, encoded.delta_phi
        )
        epoch_counts = dict(existing.epoch_counts)
        epoch_counts[epoch_id] = epoch_counts.get(epoch_id, 0) + 1
        self._buckets[atom_id] = replace(
            existing,
            visit_count=visits,
            epoch_counts=epoch_counts,
            state_summary=SecurityStateV1.join(existing.state_summary, state),
            delta_phi_mean=mean,
            delta_phi_m2=m2,
            uncertainty_envelope=(min(low, uncertainty), max(high, uncertainty)),
            last_sequence=max(existing.last_sequence, sequence),
        )
        return QuantizeResult(
            atom_id=atom_id,
            # A bucket quantizer has no metric: membership is exact, so the
            # distance is 0.0 rather than a fabricated similarity.
            distance=0.0,
            created=False,
            evicted_atom_id=None,
            inside_envelope=inside,
        )

    def _bucket_id(self, key: tuple[int, int, int]) -> int:
        """The bucket for ``key``, linear-probing past a digest collision.

        ``stable_bucket_id`` maps into ``ID_SPACE`` = 2**24, so two distinct
        ``(relation_family, state_delta_mask, object_property_mask)`` triples can
        collide. This used to use the raw id as the dict key, so the second
        triple's visits, epoch counts, ΔΦ statistics and joined state were folded
        into a bucket whose ``key`` field still named only the first — two
        different behaviours reported as one, silently (S2-11).
        ``BehaviourQuantizer._free_id`` already probes for exactly this reason,
        with exactly this comment; the control quantizer now does too, and it is
        the *default* quantizer (ADR-0115), so it was the one that mattered.
        """
        atom_id = stable_bucket_id(*key)
        probes = 0
        while True:
            bucket = self._buckets.get(atom_id)
            if bucket is None or bucket.key == key:
                return atom_id
            probes += 1
            self._counters["collisions"] += 1
            if probes > self.max_atoms:  # pragma: no cover - needs max_atoms collisions
                raise ContractError(
                    "bucket id space exhausted by collisions; a hash bucket may not "
                    "merge two behaviours to make room"
                )
            atom_id = (atom_id + 1) % ID_SPACE

    def _evict(self) -> int:
        victim = min(
            self._buckets.values(),
            key=lambda b: (b.visit_count, b.last_sequence, b.atom_id),
        )
        del self._buckets[victim.atom_id]
        self._counters["evictions"] += 1
        return victim.atom_id


# Assigned here rather than beside the flag because both classes must exist first.
# A module-level default is the strongest "off" this package can deliver: it does
# not own Stage 2's gate or CLI, so it states the verdict where every consumer of
# the package has to walk past it.
DEFAULT_QUANTIZER = (
    BehaviourQuantizer if BEHAVIOUR_QUANTIZER_ENABLED else HashBucketQuantizer
)
