"""D2.6 — the Behaviour Atom: one recurring behaviour, as a bounded record.

A Behaviour Atom is the discrete layer Stage 2 proposes between a continuous
encoded transition and an executable Knowledge Cell: "this host does *this kind
of thing*, and here is what usually follows". Stage 3 crystallises atoms and
lattice edges, so an atom has to carry everything a validity boundary needs —
which epochs it was seen in, what security state it summarises, how uncertain
its observations were — and nothing that grows without bound.

What this module deliberately refuses to do:

* **It never stores samples.** ΔΦ variance is kept by Welford's recurrence, so a
  hot atom costs the same as a cold one. An atom that accumulated its own
  history would silently defeat the 2 GB target (MEMORY.md invariant).
* **It never records unbounded epoch history.** ``epoch_counts`` is capped at
  ``MAX_EPOCHS_PER_ATOM``; the least-visited epoch is dropped. Epoch validity is
  a *bounded* claim, and an atom that claims validity in every epoch it ever saw
  is an atom that can never be invalidated.
* **It never reports a constant memory figure.** ``memory_bytes`` is derived from
  the actual container lengths, because a constant is how a bound stops being
  measured.

This is a data record. It holds no learning rule; the quantizer (DTL-F04) owns
that, and it updates atoms by building new ones rather than mutating them, per
the repository immutability rule.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.state.security_state import DIMENSIONS, SecurityStateV1
from pocketsec.stage2.encoder.ssir_encoder import FEATURE_WIDTH

__all__ = [
    "MAX_EPOCHS_PER_ATOM",
    "BehaviourAtom",
    "CompileStatus",
    "bound_epoch_counts",
    "welford_update",
]

#: An atom may claim validity in at most this many epochs. Chosen small on
#: purpose: epoch validity is the anti-poisoning boundary (ADR-0005 lineage
#: state, Stage 1 epoch rules), and a claim that spans every epoch ever observed
#: is indistinguishable from no claim at all.
MAX_EPOCHS_PER_ATOM: int = 8

#: Byte accounting constants. These are *per-element* costs used to derive a
#: content-proportional figure, not a per-object total. On CPython 3.14 a float
#: payload and a small-int payload are both 8 bytes of useful content, and a
#: slotted instance spends one machine pointer per slot; the point of the
#: accounting is that it moves when content moves, so a bound can be tested.
_SLOT_BYTES: int = 8
_FLOAT_BYTES: int = 8
_INT_BYTES: int = 8


class CompileStatus(StrEnum):
    """How far along the Stage 3 crystallisation path this atom or edge is.

    ``NEURAL`` is the default and the only status Stage 2 may assign on its own
    evidence. ``CANDIDATE`` means an exporter proposed it; ``EXECUTABLE`` means
    Stage 3 accepted it. Stage 2 never promotes itself to ``EXECUTABLE``: model
    output carries no authority (ADR-0003).
    """

    NEURAL = "NEURAL"
    CANDIDATE = "CANDIDATE"
    EXECUTABLE = "EXECUTABLE"


def bound_epoch_counts(counts: dict[int, int]) -> dict[int, int]:
    """Cap epoch history at :data:`MAX_EPOCHS_PER_ATOM`, dropping the least-seen.

    Ties break on the *lower* epoch id, so the newer regime survives: an atom
    that keeps re-proving itself in the current epoch should not be evicted in
    favour of a single ancient sighting.
    """
    if len(counts) <= MAX_EPOCHS_PER_ATOM:
        return dict(counts)
    ranked = sorted(counts.items(), key=lambda item: (item[1], -item[0]))
    for epoch_id, _count in ranked[: len(counts) - MAX_EPOCHS_PER_ATOM]:
        del counts[epoch_id]
    return dict(counts)


def welford_update(
    count: int, mean: float, m2: float, sample: float
) -> tuple[float, float]:
    """One step of Welford's online variance, returning ``(mean, m2)``.

    ``count`` is the visit count *including* ``sample``. Kept here rather than in
    the quantizer because both the quantizer and fission need it, and because a
    second hand-rolled copy is how variance accounting drifts.
    """
    if count <= 0:
        raise ContractError(f"welford_update needs count >= 1, got {count}")
    delta = sample - mean
    new_mean = mean + delta / count
    return new_mean, m2 + delta * (sample - new_mean)


@dataclass(frozen=True, slots=True)
class BehaviourAtom:
    """One recurring behaviour: a prototype, its evidence, and its boundary."""

    atom_id: int
    #: Cluster centre in encoder space. Exactly ``FEATURE_WIDTH`` wide, because a
    #: prototype of a different width silently compares against the wrong
    #: feature groups instead of failing.
    prototype: tuple[float, ...]
    visit_count: int
    #: epoch id -> times seen in that epoch. Bounded; see
    #: :data:`MAX_EPOCHS_PER_ATOM`.
    epoch_counts: dict[int, int]
    #: Lattice join of the security states observed at this atom — capability
    #: meaning, not identity. Join is monotone and order-independent, so this
    #: summary does not depend on the order transitions arrived in.
    state_summary: SecurityStateV1
    delta_phi_mean: float
    #: Welford's M2. Variance without stored samples; see the module docstring.
    delta_phi_m2: float
    #: (min, max) observed uncertainty. An *envelope*, not a mean: the widest
    #: thing this atom has ever been asked to stand for.
    uncertainty_envelope: tuple[float, float]
    compile_status: CompileStatus
    first_sequence: int
    last_sequence: int

    def __post_init__(self) -> None:
        if len(self.prototype) != FEATURE_WIDTH:
            raise ContractError(
                f"atom {self.atom_id}: prototype width {len(self.prototype)} "
                f"!= encoder FEATURE_WIDTH {FEATURE_WIDTH}"
            )
        if self.visit_count < 0:
            raise ContractError(
                f"atom {self.atom_id}: visit_count must be >= 0, got {self.visit_count}"
            )
        if self.delta_phi_m2 < 0.0:
            raise ContractError(
                f"atom {self.atom_id}: Welford M2 cannot be negative, "
                f"got {self.delta_phi_m2}"
            )
        low, high = self.uncertainty_envelope
        if low > high:
            raise ContractError(
                f"atom {self.atom_id}: inverted uncertainty envelope ({low}, {high})"
            )
        if self.last_sequence < self.first_sequence:
            raise ContractError(
                f"atom {self.atom_id}: last_sequence {self.last_sequence} precedes "
                f"first_sequence {self.first_sequence}"
            )
        # Frozen dataclasses share mutable defaults with their caller, so the
        # dict is copied and bounded here — otherwise the caller could grow an
        # atom's epoch history past the cap after construction.
        object.__setattr__(
            self, "epoch_counts", bound_epoch_counts(dict(self.epoch_counts))
        )

    def distance(self, features: Sequence[float]) -> float:
        """Squared L2 to ``features``. Squared, so no ``sqrt`` per event.

        Comparisons and the split radius are both defined on the squared metric,
        so nothing downstream needs the root. Refuses a width mismatch rather
        than comparing a prefix.
        """
        if len(features) != FEATURE_WIDTH:
            raise ContractError(
                f"distance needs {FEATURE_WIDTH} features, got {len(features)}"
            )
        total = 0.0
        for centre, value in zip(self.prototype, features, strict=True):
            diff = centre - value
            total += diff * diff
        return total

    def distance_within(self, features: Sequence[float], ceiling: float) -> float:
        """Squared L2, abandoned as soon as the partial sum passes ``ceiling``.

        Returns the true distance when it is ``<= ceiling``, and *some* value
        greater than ``ceiling`` otherwise. That is enough for nearest-prototype
        search — a candidate already worse than the incumbent cannot win — and it
        is what makes quantizing a 17k-transition corpus against 256 prototypes
        finish in seconds rather than minutes. The check runs every eighth
        coordinate so the comparison does not cost more than the arithmetic it
        saves.
        """
        total = 0.0
        prototype = self.prototype
        for index in range(0, FEATURE_WIDTH, 8):
            stop = index + 8
            for centre, value in zip(
                prototype[index:stop], features[index:stop], strict=False
            ):
                diff = centre - value
                total += diff * diff
            if total > ceiling:
                return total
        return total

    def epoch_valid(self, epoch_id: int) -> bool:
        """Has this atom been corroborated in ``epoch_id``?

        Absence is a real answer, not a failure: an atom learned before a system
        change must not be reused after it without fresh evidence. Stage 1's rule
        that epochs need corroborating system-change evidence is what makes this
        a boundary rather than a formality.
        """
        return epoch_id in self.epoch_counts

    def variance(self) -> float:
        """Sample variance of ΔΦ at this atom, or 0.0 below two observations."""
        if self.visit_count < 2:
            return 0.0
        return self.delta_phi_m2 / (self.visit_count - 1)

    def envelope_width(self) -> float:
        """Width of the uncertainty envelope — the fission heterogeneity signal."""
        low, high = self.uncertainty_envelope
        return high - low

    def memory_bytes(self) -> int:
        """Derived from actual container lengths, never a constant.

        A constant would make the bound untestable: the whole reason this exists
        is so a test can assert that an atom grows only where it is allowed to.
        """
        slots = len(BehaviourAtom.__slots__) * _SLOT_BYTES
        prototype = len(self.prototype) * _FLOAT_BYTES
        epochs = len(self.epoch_counts) * (_INT_BYTES + _INT_BYTES)
        state = len(DIMENSIONS) * _SLOT_BYTES
        envelope = len(self.uncertainty_envelope) * _FLOAT_BYTES
        return slots + prototype + epochs + state + envelope

    def with_status(self, status: CompileStatus) -> BehaviourAtom:
        """Return a copy at ``status``. Atoms are immutable; nothing mutates."""
        return replace(self, compile_status=status)

    def to_dict(self) -> dict[str, Any]:
        """Plain data. No BehaviourAtom class crosses the Stage 3 seam (§6.5)."""
        low, high = self.uncertainty_envelope
        return {
            "atom_id": self.atom_id,
            "visit_count": self.visit_count,
            "epochs": sorted(self.epoch_counts),
            "epoch_counts": {str(k): v for k, v in sorted(self.epoch_counts.items())},
            "state_summary": self.state_summary.to_dict(),
            "delta_phi_mean": round(self.delta_phi_mean, 6),
            "delta_phi_variance": round(self.variance(), 6),
            "uncertainty_envelope": [round(low, 6), round(high, 6)],
            "compile_status": str(self.compile_status),
            "first_sequence": self.first_sequence,
            "last_sequence": self.last_sequence,
            "memory_bytes": self.memory_bytes(),
            # The prototype is the atom's identity in encoder space; rounded so a
            # serialised atom is byte-stable across runs.
            "prototype": [round(value, 6) for value in self.prototype],
        }
