"""D3.4 (part) — the Knowledge Boundary B(K) and the bounded index over it.

Architecture §10: *a rule without a boundary is unsafe because it silently
extrapolates*. Everything in this module exists to stop that one failure, so it
is built out of refusals rather than defaults:

**The index never evicts.** :meth:`BoundaryIndex.insert` raises when it is full.
A silently dropped key does not shrink the index's promises — it leaves a cell
registered while one of the regions it claims is no longer reachable through the
index, so a frame inside the cell's own boundary misses and a *different* cell,
or no cell, answers instead. Refusing the insert keeps the field's coverage
equal to what the field says it covers.

**Lookup never returns a nearest match.** Off the boundary the answer is
``None``, which the caller turns into abstention and the learned path. A
nearest-match index is a plausible-looking guess, and §40's rule is the
opposite: *on corruption or ambiguity, abstain and return to DTL/deterministic
paths*. Ambiguity is included — two cells containing the same frame is a
composition question (:meth:`lookup_all` plus ``KnowledgeField.compose``), never
an arbitrary winner picked by dictionary order.

**A key footprint is not a frame set.** :meth:`CellBoundary.keys` is a product
over (relation families x declared required masks) with ``state_dimensions``
folded into one union delta mask, while :meth:`CellBoundary.contains` is a
conjunction over the predicates and admits any frame whose delta dimensions are
a *subset*. So a key subset does not imply a frame subset, and key-disjointness
does not imply frame-disjointness. Anything reasoning about regions — melting
above all — must ask :meth:`CellBoundary.accepts_no_more_than` and
:meth:`CellBoundary.intersects` rather than comparing key sets; using the
footprint for either question is how a narrowing melt widened a cell into
territory nothing validated, and how a dimension-scoped drift left a stale cell
answering the region it had just been told drifted.

**Near-boundary is a first-class query, not a fuzzy hit.**
:meth:`BoundaryIndex.near_boundary` reports cells the frame *misses* by a
countable number of clauses. §40 requires near-boundary matches to raise DTL/AOP
activation; that only works if "near" is measured and separated from "inside".

Bounds come from architecture §38 ("Boundary index < 2-8 MB") and §39
("knowledge explosion"): ``MAX_INDEX_KEYS`` caps the index, ``MAX_INDEX_BYTES``
caps its containers, and ``MAX_KEYS_PER_CELL`` caps how much region a single
cell may claim.
"""

from __future__ import annotations

import sys
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.ssir.entities import SemanticProperty
from pocketsec.stage1.ssir.relations import RelationFamily
from pocketsec.stage1.state.security_state import DIMENSIONS
from pocketsec.stage2.compile_candidates.candidate import (
    UNSEEN_INPUT_ABSTAIN,
    ValidityBoundary,
)

if TYPE_CHECKING:  # pragma: no cover - imports exist only for annotations
    from pocketsec.stage3.bytecode.vm import CellFrame
    from pocketsec.stage3.cells.invariant import SemanticPredicate
    from pocketsec.stage3.cells.schema import KnowledgeCellV1

__all__ = [
    "BOUNDARY_PROPERTY_ORDER",
    "BoundaryIndex",
    "BoundaryIndexFull",
    "BoundaryKey",
    "CellBoundary",
    "MAX_FORBIDDEN_COMBINATIONS",
    "MAX_INDEX_BYTES",
    "MAX_INDEX_KEYS",
    "MAX_KEYS_PER_CELL",
    "PHI_UNCONSTRAINED_HIGH",
    "UNSEEN_INPUT_ABSTAIN",
    "boundary_property_mask",
    "check_property_order",
]

#: ``(RelationFamily.value, actor property mask, StateDelta.bitmask)``.
BoundaryKey = tuple[int, int, int]

MAX_INDEX_KEYS = 8192
MAX_INDEX_BYTES = 8 * 1024 * 1024

#: Architecture §39 "knowledge explosion": the mechanical cap on how much of the
#: host one cell may claim. Sixty-four is exactly ``8 relation families x 8
#: actor predicates``, so a cell that needs more is describing a region too
#: coarse to have been validated rather than one that was.
MAX_KEYS_PER_CELL = 64

#: Bound on the exclusion list, for the same reason ``MAX_KEYS_PER_CELL``
#: exists: :meth:`CellBoundary.violated_clauses` walks every forbidden
#: combination on the cheap path, so an unbounded list would be an unbounded
#: loop there. Carried over when ``cells/boundary.py``'s duplicate definition of
#: this class was collapsed into this one, so the merge dropped no constraint.
MAX_FORBIDDEN_COMBINATIONS = 16

#: The Φ of the top of Stage 1's state lattice, measured rather than assumed:
#:
#:     >>> from pocketsec.stage1.state.security_state import SecurityStateV1, DIMENSIONS
#:     >>> from pocketsec.stage1.state.potential import phi
#:     >>> phi(SecurityStateV1(**{n: max(l) for n, l in DIMENSIONS.items()})).total
#:     31.0
#:
#: Used as the "no Φ constraint" ceiling. It replaces ``float("inf")``, which
#: :meth:`CellBoundary._checked_phi_range` now refuses: a boundary carrying an
#: infinity serialises through ``json.dumps(..., allow_nan=False)`` and so raised
#: **ValueError** rather than ``ContractError`` — past every caller that guards
#: on ``ContractError``, including ``partial_melt``'s rollback, which by then had
#: already removed the cell from the field and the index.
PHI_UNCONSTRAINED_HIGH = 31.0

#: Property-bit order for :data:`BoundaryKey`'s middle term: ``SemanticProperty``
#: sorted by name, which is the same rule ``invariants/anti_unification.py`` pins
#: for its ``PROPERTY_ORDER``. Sorted by name rather than by declaration order
#: because a stored key must survive someone reordering the enum, and a
#: declaration-order key would not.
BOUNDARY_PROPERTY_ORDER: tuple[SemanticProperty, ...] = tuple(sorted(SemanticProperty, key=str))

_PROPERTY_BIT: dict[SemanticProperty, int] = {
    prop: 1 << index for index, prop in enumerate(BOUNDARY_PROPERTY_ORDER)
}

_ROLE_ACTOR = "ACTOR"
_ROLE_OBJECT = "OBJECT"

_ALL_FAMILIES: tuple[int, ...] = tuple(int(family) for family in RelationFamily)

#: Structural byte estimate for one index entry: a three-int tuple plus its dict
#: slot plus the set that holds the cell ids for that key. Used only as the
#: denominator of the §38 ceiling; :meth:`BoundaryIndex.memory_bytes` measures
#: the real containers with ``sys.getsizeof`` rather than trusting this.
_KEY_OVERHEAD_BYTES = 3 * 28 + 56 + 216


class BoundaryIndexFull(ContractError):
    """The index is at its declared cap and refuses to evict to make room.

    Raised rather than handled: the caller must melt, garbage-collect or widen
    the declared cap deliberately. Dropping a key here would make the index
    disagree with the field about what is covered.
    """


def boundary_property_mask(properties: Iterable[SemanticProperty]) -> int:
    """Pack semantic properties into the :data:`BoundaryKey` actor/object mask."""
    mask = 0
    for prop in properties:
        bit = _PROPERTY_BIT.get(prop)
        if bit is None:
            raise ContractError(f"unknown semantic property {prop!r}")
        mask |= bit
    return mask


def check_property_order(order: Sequence[SemanticProperty]) -> None:
    """Refuse a property order that disagrees with :data:`BOUNDARY_PROPERTY_ORDER`.

    ``invariants/anti_unification.py`` pins its own ``PROPERTY_ORDER`` as a wire
    commitment. Two pinned orders that disagree would silently reinterpret every
    stored ``BoundaryKey``, so the disagreement is made loud at import time
    instead of being discovered as a wrong answer.
    """
    if tuple(order) != BOUNDARY_PROPERTY_ORDER:
        raise ContractError(
            "property bit order disagrees with BOUNDARY_PROPERTY_ORDER; every "
            "stored BoundaryKey would be reinterpreted"
        )


try:  # pragma: no cover - depends on the concurrently built invariants package
    from pocketsec.stage3.invariants.anti_unification import PROPERTY_ORDER as _DISCOVERY_ORDER
except ImportError:
    pass
else:
    check_property_order(_DISCOVERY_ORDER)


@dataclass(frozen=True, slots=True)
class CellBoundary:
    """B(K) — the states, events and epochs a cell's behaviour was validated on.

    An *empty* boundary is not a permissive boundary. It contains nothing, and
    :attr:`is_empty` exists so promotion can refuse it, exactly as
    ``ValidityBoundary`` already does for a compile candidate.
    """

    predicates: tuple[SemanticPredicate, ...]
    state_dimensions: frozenset[str]
    phi_range: tuple[float, float]
    max_uncertainty: float
    epochs: frozenset[int]
    forbidden_combinations: tuple[frozenset[SemanticProperty], ...]
    unseen_input_behaviour: str = UNSEEN_INPUT_ABSTAIN

    def __post_init__(self) -> None:
        if not isinstance(self.predicates, tuple):
            raise ContractError("CellBoundary.predicates must be a tuple")
        unknown = set(self.state_dimensions) - set(DIMENSIONS)
        if not isinstance(self.state_dimensions, frozenset) or unknown:
            raise ContractError(
                f"CellBoundary.state_dimensions must be a subset of DIMENSIONS, "
                f"unknown: {sorted(unknown)}"
            )
        low, high = self._checked_phi_range()
        if low > high:
            raise ContractError(
                f"CellBoundary.phi_range must be ordered, not inverted: got ({low}, {high}). "
                "An inverted band contains nothing while reading as 'no Φ constraint'"
            )
        if not isinstance(self.max_uncertainty, float) or not 0.0 <= self.max_uncertainty <= 1.0:
            raise ContractError(
                f"CellBoundary.max_uncertainty must be a float in [0, 1], "
                f"got {self.max_uncertainty!r}"
            )
        if not isinstance(self.epochs, frozenset) or any(
            not isinstance(e, int) or isinstance(e, bool) or e < 0 for e in self.epochs
        ):
            raise ContractError("CellBoundary.epochs must be a frozenset of epoch ids >= 0")
        if not self.epochs:
            # Refused at construction rather than left to `is_empty`, because an
            # empty epoch set is the classic inversion: it reads as "valid
            # everywhere" and means "valid nowhere". `is_empty` still covers the
            # empty-`state_dimensions` case, which a narrowing melt can produce.
            raise ContractError(
                "CellBoundary.epochs must be non-empty: a boundary valid in no epoch "
                "contains nothing, and reads as though it constrained nothing"
            )
        if len(self.forbidden_combinations) > MAX_FORBIDDEN_COMBINATIONS:
            raise ContractError(
                f"CellBoundary declares {len(self.forbidden_combinations)} forbidden "
                f"combinations, over the cap of {MAX_FORBIDDEN_COMBINATIONS}"
            )
        for combination in self.forbidden_combinations:
            if not isinstance(combination, frozenset) or not combination:
                raise ContractError(
                    "CellBoundary.forbidden_combinations entries must be non-empty frozensets"
                )
            boundary_property_mask(combination)
        if self.unseen_input_behaviour != UNSEEN_INPUT_ABSTAIN:
            raise ContractError(
                f"CellBoundary.unseen_input_behaviour must be {UNSEEN_INPUT_ABSTAIN!r}, "
                f"never {self.unseen_input_behaviour!r}: guessing off the boundary is what "
                "a validity boundary exists to prevent"
            )

    def _checked_phi_range(self) -> tuple[float, float]:
        if not isinstance(self.phi_range, tuple) or len(self.phi_range) != 2:
            raise ContractError("CellBoundary.phi_range must be a (low, high) tuple")
        low, high = self.phi_range
        if not isinstance(low, float) or not isinstance(high, float):
            raise ContractError(f"CellBoundary.phi_range must hold floats, got {self.phi_range!r}")
        # Finite, and refused here rather than at serialisation time. A NaN bound
        # makes every ``low <= phi <= high`` comparison false, so the boundary
        # contains nothing while reading as a constraint — the same inversion the
        # empty-``epochs`` check above refuses. An infinite bound survives
        # construction and then raises ValueError, not ContractError, inside
        # ``size_bytes``'s ``json.dumps(..., allow_nan=False)``, which escapes
        # every caller that guards on ContractError.
        for name, value in (("low", low), ("high", high)):
            if value != value or value in (float("inf"), float("-inf")):
                raise ContractError(
                    f"CellBoundary.phi_range {name} bound must be finite, got {value!r}; "
                    f"use PHI_UNCONSTRAINED_HIGH ({PHI_UNCONSTRAINED_HIGH}) for 'no Φ "
                    "constraint'. NaN contains nothing while reading as a constraint, and "
                    "an infinity cannot be serialised as canonical JSON"
                )
        return low, high

    @property
    def is_empty(self) -> bool:
        """No epochs or no dimensions means the region can never contain anything."""
        return not self.epochs or not self.state_dimensions

    def violated_clauses(self, frame: CellFrame) -> tuple[str, ...]:
        """Name every clause this frame fails, in a stable order.

        Named rather than counted so a counterexample class can say *which*
        clause broke; :meth:`distance` is just the length of this tuple.
        """
        failed: list[str] = []
        if frame.epoch_id not in self.epochs:
            failed.append("epoch")
        if frame.uncertainty > self.max_uncertainty:
            failed.append("uncertainty")
        low, high = self.phi_range
        if not low <= frame.phi <= high:
            failed.append("phi")
        if not frame.delta.dimensions <= self.state_dimensions:
            failed.append("state_dimensions")
        families = self.relation_families()
        if int(frame.relation_family) not in families:
            failed.append("relation_family")
        failed.extend(self._predicate_failures(frame))
        actor_object = frame.actor_properties | frame.object_properties
        for position, combination in enumerate(self.forbidden_combinations):
            mask = boundary_property_mask(combination)
            if mask and actor_object & mask == mask:
                failed.append(f"forbidden_combination[{position}]")
        return tuple(failed)

    def _predicate_failures(self, frame: CellFrame) -> list[str]:
        failures: list[str] = []
        for position, predicate in enumerate(self.predicates):
            role = str(predicate.role)
            observed = (
                frame.actor_properties if role == _ROLE_ACTOR else frame.object_properties
            )
            required = boundary_property_mask(predicate.required_properties)
            forbidden = boundary_property_mask(predicate.forbidden_properties)
            if observed & required != required or observed & forbidden:
                failures.append(f"predicate[{position}]:{role}")
        return failures

    def contains(self, frame: CellFrame) -> bool:
        return not self.violated_clauses(frame)

    def distance(self, frame: CellFrame) -> int:
        """0 inside; otherwise the number of violated clauses."""
        return len(self.violated_clauses(frame))

    def relation_families(self) -> tuple[int, ...]:
        """Families this boundary constrains; all of them when it constrains none."""
        declared = {
            int(predicate.relation_family)
            for predicate in self.predicates
            if predicate.relation_family is not None
        }
        return tuple(sorted(declared)) if declared else _ALL_FAMILIES

    def actor_masks(self) -> tuple[int, ...]:
        """Required-property masks for the ACTOR predicates; ``(0,)`` when none."""
        masks = {
            boundary_property_mask(predicate.required_properties)
            for predicate in self.predicates
            if str(predicate.role) == _ROLE_ACTOR
        }
        return tuple(sorted(masks)) if masks else (0,)

    def role_masks(self, role: str) -> tuple[int, int]:
        """``(required union, forbidden union)`` for one predicate role.

        :meth:`_predicate_failures` evaluates a *conjunction* over the predicates
        of a role, and that conjunction is exactly ``observed & required ==
        required and observed & forbidden == 0`` against the unions below. Two
        integers therefore characterise the whole predicate clause for a role,
        which is what lets melting decide whether a candidate sub-boundary is
        really a *sub*-boundary instead of guessing from the key footprint.
        """
        required = 0
        forbidden = 0
        for predicate in self.predicates:
            if str(predicate.role) != role:
                continue
            required |= boundary_property_mask(predicate.required_properties)
            forbidden |= boundary_property_mask(predicate.forbidden_properties)
        return required, forbidden

    def accepts_no_more_than(self, other: CellBoundary) -> bool:
        """True when every frame this boundary contains, ``other`` contains too.

        Clause by clause against :meth:`violated_clauses`, because the key
        footprint answers a different question. :meth:`keys` is a *product* over
        (families x declared required masks) while :meth:`contains` is a
        conjunction, so a key subset does not imply a frame subset: dropping one
        ACTOR predicate shrinks the key set and *enlarges* the accepted frame
        set, which is how a narrowing melt came to widen the validated region.

        Conservative where it cannot decide: ``forbidden_combinations`` are
        required to be a superset, which is sufficient rather than exact. A
        boundary this refuses is not necessarily a widening; a boundary it
        accepts provably is not one.
        """
        if not self.epochs <= other.epochs:
            return False
        if self.max_uncertainty > other.max_uncertainty:
            return False
        low, high = self.phi_range
        other_low, other_high = other.phi_range
        if low < other_low or high > other_high:
            return False
        if not self.state_dimensions <= other.state_dimensions:
            return False
        if not set(self.relation_families()) <= set(other.relation_families()):
            return False
        for role in (_ROLE_ACTOR, _ROLE_OBJECT):
            mine, mine_forbidden = self.role_masks(role)
            theirs, theirs_forbidden = other.role_masks(role)
            if mine & theirs != theirs or mine_forbidden & theirs_forbidden != theirs_forbidden:
                return False
        return set(other.forbidden_combinations) <= set(self.forbidden_combinations)

    def intersects(self, other: CellBoundary) -> bool:
        """True when some frame could satisfy both boundaries.

        Asked instead of ``set(self.keys()) & set(other.keys())`` because key
        equality is not the same question: :meth:`keys` folds
        ``state_dimensions`` into one union delta mask, while
        :meth:`violated_clauses` admits any frame whose delta dimensions are a
        *subset* of the declared set — a frame raising nothing is inside every
        boundary's dimension clause. Two boundaries with no key in common can
        therefore both answer the same frame, and reading key-disjointness as
        region-disjointness is what let a dimension-scoped drift leave a stale
        cell live and indexed.

        Errs toward "yes". ``forbidden_combinations`` and the interaction between
        ACTOR and OBJECT masks are not modelled, so an intersection this reports
        may be empty in fact. For melting that is the fail-safe direction: it
        reopens a region that may not have drifted rather than leaving a drifted
        region answered by a stale cell.
        """
        if not (self.epochs & other.epochs):
            return False
        low, high = self.phi_range
        other_low, other_high = other.phi_range
        if max(low, other_low) > min(high, other_high):
            return False
        if not set(self.relation_families()) & set(other.relation_families()):
            return False
        for role in (_ROLE_ACTOR, _ROLE_OBJECT):
            mine, mine_forbidden = self.role_masks(role)
            theirs, theirs_forbidden = other.role_masks(role)
            # A frame must carry the union of both required masks and none of
            # either forbidden mask; those are jointly satisfiable exactly when
            # they do not overlap.
            if (mine | theirs) & (mine_forbidden | theirs_forbidden):
                return False
        return True

    def delta_mask(self) -> int:
        """Bitmask of ``state_dimensions``, in ``StateDelta.bitmask`` bit order."""
        mask = 0
        for index, name in enumerate(DIMENSIONS):
            if name in self.state_dimensions:
                mask |= 1 << index
        return mask

    def keys(self) -> tuple[BoundaryKey, ...]:
        """The coverage footprint of this boundary, capped at :data:`MAX_KEYS_PER_CELL`.

        This is a *footprint*, not a hash of every frame that can match: the
        actor term is the declared requirement, and a frame carries a superset
        mask. Lookup therefore buckets on the footprint and confirms with
        :meth:`contains` — the index narrows, the boundary decides.

        Raises rather than truncating. A truncated footprint would leave the
        cell claiming region it is not indexed for, which is the silent-drop
        failure this module is built to refuse.
        """
        families = self.relation_families()
        masks = self.actor_masks()
        count = len(families) * len(masks)
        if count > MAX_KEYS_PER_CELL:
            raise ContractError(
                f"boundary expands to {count} keys, over the cap MAX_KEYS_PER_CELL="
                f"{MAX_KEYS_PER_CELL}; a region this coarse was not validated, it was assumed"
            )
        delta = self.delta_mask()
        return tuple((family, mask, delta) for family in families for mask in masks)

    @classmethod
    def from_validity_boundary(
        cls,
        boundary: ValidityBoundary,
        *,
        predicates: tuple[SemanticPredicate, ...] = (),
        phi_range: tuple[float, float] = (0.0, PHI_UNCONSTRAINED_HIGH),
        forbidden_combinations: tuple[frozenset[SemanticProperty], ...] = (),
    ) -> CellBoundary:
        """Lift a Stage 2 ``ValidityBoundary`` without widening it.

        Every field the compile candidate already constrained is carried over
        verbatim. The terms Stage 2 has no vocabulary for — semantic predicates,
        a Φ band, forbidden combinations — default to *unconstrained*, and the
        caller narrows them. Defaulting them to something tighter would claim a
        validation the candidate never carried.
        """
        return cls(
            predicates=predicates,
            state_dimensions=boundary.state_dimensions,
            phi_range=phi_range,
            max_uncertainty=boundary.max_uncertainty,
            epochs=boundary.epochs,
            forbidden_combinations=forbidden_combinations,
            unseen_input_behaviour=boundary.unseen_input_behaviour,
        )

    def to_dict(self) -> dict[str, Any]:
        """Lossless projection — every field :meth:`from_dict` needs to rebuild it.

        The predicates are written out in full rather than summarised as a
        count. A boundary is the cell's validity claim, and a claim that cannot
        be reloaded exactly is a claim that quietly widens on the next restart:
        ``KnowledgeCellV1.from_dict`` reaches straight through this method, so a
        lossy projection here would be a lossy cell.
        """
        return {
            "predicates": [predicate.to_dict() for predicate in self.predicates],
            "state_dimensions": sorted(self.state_dimensions),
            "phi_range": list(self.phi_range),
            "max_uncertainty": self.max_uncertainty,
            "epochs": sorted(self.epochs),
            "forbidden_combinations": [
                sorted(str(prop) for prop in combination)
                for combination in self.forbidden_combinations
            ],
            "unseen_input_behaviour": self.unseen_input_behaviour,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> CellBoundary:
        """Rebuild a boundary from :meth:`to_dict`, refusing anything partial.

        A missing key raises rather than defaulting. Every default available
        here would be a *widening* — an absent ``epochs`` becoming "all epochs",
        an absent ``forbidden_combinations`` becoming "nothing forbidden" — so a
        truncated record must fail to load rather than load as a permissive
        boundary.
        """
        from pocketsec.stage3.cells.invariant import SemanticPredicate as _Predicate

        try:
            low, high = payload["phi_range"]
            return cls(
                predicates=tuple(
                    _Predicate.from_dict(item) for item in payload["predicates"]
                ),
                state_dimensions=frozenset(str(name) for name in payload["state_dimensions"]),
                phi_range=(float(low), float(high)),
                max_uncertainty=float(payload["max_uncertainty"]),
                epochs=frozenset(int(epoch) for epoch in payload["epochs"]),
                forbidden_combinations=tuple(
                    frozenset(SemanticProperty(str(prop)) for prop in combination)
                    for combination in payload["forbidden_combinations"]
                ),
                unseen_input_behaviour=str(payload["unseen_input_behaviour"]),
            )
        except KeyError as exc:
            raise ContractError(f"CellBoundary missing field {exc.args[0]!r}") from exc
        except (TypeError, ValueError) as exc:
            raise ContractError(f"CellBoundary could not be rebuilt: {exc}") from exc


class BoundaryIndex:
    """Bounded map from :data:`BoundaryKey` to the cells that claim it.

    Two containers, because they answer two different questions: ``_by_key``
    holds the declared footprint (what the index promised, what melting reopens,
    what the §38 ceiling counts) and ``_by_family`` is the lookup bucket. Both
    are derived from the same :meth:`CellBoundary.keys` call, so they cannot
    disagree about a cell.
    """

    def __init__(self, *, max_keys: int = MAX_INDEX_KEYS, max_bytes: int = MAX_INDEX_BYTES) -> None:
        if max_keys < 1 or max_bytes < 1:
            raise ContractError("BoundaryIndex caps must be >= 1")
        self._max_keys = max_keys
        self._max_bytes = max_bytes
        self._cells: dict[str, KnowledgeCellV1] = {}
        self._by_key: dict[BoundaryKey, set[str]] = {}
        self._by_family: dict[int, set[str]] = {}
        self._cell_keys: dict[str, tuple[BoundaryKey, ...]] = {}

    def __len__(self) -> int:
        return len(self._cells)

    def key_count(self) -> int:
        return len(self._by_key)

    def cell_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._cells))

    def keys_for(self, cell_id: str) -> tuple[BoundaryKey, ...]:
        """The footprint this index registered for a cell — what melting reopens."""
        return self._cell_keys.get(cell_id, ())

    def insert(self, cell: KnowledgeCellV1) -> None:
        """Register a cell's whole footprint, or none of it.

        Raises :class:`BoundaryIndexFull` at the cap instead of evicting, and
        propagates :class:`~pocketsec.stage0.contracts.common.ContractError` from
        :meth:`CellBoundary.keys` when the boundary claims more than
        :data:`MAX_KEYS_PER_CELL`. Both refusals are the point: a cell that is
        only partly indexed answers in some of its region and misses in the
        rest, and nothing downstream can tell which.
        """
        cell_id = cell.cell_id
        if cell_id in self._cells:
            raise ContractError(
                f"cell {cell_id!r} is already indexed; remove it before re-inserting so the "
                "replacement is a decision rather than an accident"
            )
        # Raises before any mutation when the boundary is too broad, so a
        # refused insert leaves the index byte-for-byte as it was.
        keys = cell.boundary.keys()
        if not keys:
            raise ContractError(f"cell {cell_id!r} has an empty boundary footprint")
        new_keys = [key for key in keys if key not in self._by_key]
        if len(self._by_key) + len(new_keys) > self._max_keys:
            raise BoundaryIndexFull(
                f"boundary index holds {len(self._by_key)} keys and cannot admit "
                f"{len(new_keys)} more under the cap of {self._max_keys}; it does not evict"
            )
        projected = self.memory_bytes() + len(new_keys) * _KEY_OVERHEAD_BYTES
        if projected > self._max_bytes:
            raise BoundaryIndexFull(
                f"boundary index would reach ~{projected} bytes, over the cap of "
                f"{self._max_bytes} (architecture §38)"
            )

        self._cells[cell_id] = cell
        self._cell_keys[cell_id] = keys
        for key in keys:
            self._by_key.setdefault(key, set()).add(cell_id)
            self._by_family.setdefault(key[0], set()).add(cell_id)

    def remove(self, cell_id: str) -> int:
        """Drop a cell and return how many index keys it released."""
        keys = self._cell_keys.pop(cell_id, ())
        if not keys:
            return 0
        self._cells.pop(cell_id, None)
        released = 0
        for key in keys:
            holders = self._by_key.get(key)
            if holders is None:
                continue
            holders.discard(cell_id)
            if not holders:
                del self._by_key[key]
                released += 1
            family_holders = self._by_family.get(key[0])
            if family_holders is not None:
                family_holders.discard(cell_id)
                if not family_holders:
                    del self._by_family[key[0]]
        return released

    def lookup(self, frame: CellFrame) -> KnowledgeCellV1 | None:
        """The one cell whose boundary contains this frame, or ``None``.

        ``None`` for no match *and* for more than one. There is no nearest
        match and no tie-break: an ambiguous frame is a composition question for
        ``KnowledgeField.compose`` over :meth:`lookup_all`, and an arbitrary
        winner here would give a guess the cheap path's authority.
        """
        matches = self.lookup_all(frame)
        return matches[0] if len(matches) == 1 else None

    def lookup_all(self, frame: CellFrame) -> tuple[KnowledgeCellV1, ...]:
        """Every cell containing this frame, ordered by cell id for determinism."""
        family = int(frame.relation_family)
        candidates = self._by_family.get(family, set())
        return tuple(
            self._cells[cell_id]
            for cell_id in sorted(candidates)
            if self._cells[cell_id].boundary.contains(frame)
        )

    def near_boundary(self, frame: CellFrame, *, within: int = 1) -> tuple[KnowledgeCellV1, ...]:
        """Cells this frame misses by 1..``within`` clauses.

        Strictly outside: a frame at distance 0 is a hit and belongs to
        :meth:`lookup`. §40 requires near-boundary matches to raise DTL/AOP
        activation, which is only meaningful if "near" and "inside" stay
        distinct — a near-boundary cell must not answer, it must escalate.

        Scans every registered cell rather than the frame's family bucket,
        because a frame one *family* clause outside is exactly the case this
        query exists to catch. The scan is bounded by the index cap.
        """
        if within < 1:
            raise ContractError("near_boundary(within=) must be >= 1")
        near: list[KnowledgeCellV1] = []
        for cell_id in sorted(self._cells):
            cell = self._cells[cell_id]
            if 1 <= cell.boundary.distance(frame) <= within:
                near.append(cell)
        return tuple(near)

    def memory_bytes(self) -> int:
        """Bytes held by the index's own containers, measured not assumed.

        ``sys.getsizeof`` over the real dicts, their key tuples and their id
        strings. The cells themselves are not counted — ``KnowledgeField`` owns
        those bytes, and counting them twice would make the §38 per-component
        budget meaningless.
        """
        total = sys.getsizeof(self._by_key) + sys.getsizeof(self._by_family)
        total += sys.getsizeof(self._cells) + sys.getsizeof(self._cell_keys)
        for key, holders in self._by_key.items():
            total += sys.getsizeof(key) + sum(sys.getsizeof(part) for part in key)
            total += sys.getsizeof(holders)
        for holders in self._by_family.values():
            total += sys.getsizeof(holders)
        for cell_id, keys in self._cell_keys.items():
            total += sys.getsizeof(cell_id) + sys.getsizeof(keys)
        return total
