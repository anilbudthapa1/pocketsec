"""D3.13 (part) — partial melting: reopening one subregion of a cell.

This is the load-bearing claim of the whole stage. Compiling a model into a
table is ordinary distillation; what distinguishes AICT is the assertion that
**localised drift reopens a subregion without discarding unrelated crystallised
knowledge**.

:attr:`MeltReport.repair_locality` is a **bystander-count sanity check, not the
number that falsifies F2**, and the difference matters because it was documented
the other way round for a while:

* ``unrelated_cells_before`` counts every *other* cell in the field before the
  melt, and ``unrelated_cells_retained`` counts how many of those exact cells are
  still there afterwards.
* But ``partial_melt`` touches exactly two ids — ``cell.cell_id`` and
  ``successor_cell_id(cell)`` — and :meth:`KnowledgeField.insert` refuses rather
  than evicting, so no statement in the success path *can* remove a bystander.
  The ratio is therefore 1.0 by construction on every report that exists, and a
  ``partial_melt`` with no narrowing logic at all would report the same 1.0.
* ``repair_locality`` is ``None`` when there were no other cells, because 1.0 out
  of nothing is not a locality demonstration. **None never means zero**, and it
  never means "fine" either.

The two properties that *can* fail, and that F2 is actually about, are checked by
``tests/test_stage3_lifecycle.py`` and by gate criterion G3.7: the survivor's
region must be strictly inside the original's and disjoint from the drifted one,
and a frame in the reopened region must route to abstention rather than to a
stale cell.

The narrowing search is exact rather than heuristic, and its two safety
conditions are evaluated on **frame sets**, not on key footprints:
:meth:`CellBoundary.accepts_no_more_than` for "this is really a sub-boundary"
and :meth:`CellBoundary.intersects` for "this avoids the drifted region". Both
were once key-footprint comparisons and both were unsound in the same direction,
because ``keys()`` is a product over declared requirements while ``contains`` is
a conjunction matched by superset. That is what let a narrowing drop an ACTOR
predicate, shrink the key set, and silently widen the cell into territory it was
never validated for.

``partial_melt`` refuses rather than escalating. If no proper sub-boundary
avoids the region, it reports ``REGION_COVERS_CELL`` and leaves the field
untouched; turning that into a full melt behind the caller's back would destroy
knowledge on a code path nobody asked for.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from enum import StrEnum
from itertools import combinations
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage3.cells.schema import CellPhase

if TYPE_CHECKING:  # pragma: no cover - import-time cost, not behaviour
    from pocketsec.stage3.boundary.index import BoundaryIndex, BoundaryKey, CellBoundary
    from pocketsec.stage3.cells.field import KnowledgeField
    from pocketsec.stage3.cells.schema import KnowledgeCellV1

__all__ = [
    "MAX_NARROWING_CANDIDATES",
    "MeltKind",
    "MeltReport",
    "count_retained",
    "narrow_boundary",
    "partial_melt",
    "reopened_keys",
    "successor_cell_id",
    "unrelated_cell_ids",
]

#: Ceiling on the narrowing lattice. ``MAX_KEYS_PER_CELL`` already bounds a
#: boundary at 64 keys, so a cell cannot declare many predicates and many
#: dimensions at once; this cap catches the pathological combination rather than
#: letting melting become the slowest thing in the stage.
MAX_NARROWING_CANDIDATES = 4096

#: ``name-v<digits>`` suffix, so repeated melts do not grow the identifier past
#: the 128-character limit ``require_identifier`` enforces.
_VERSION_SUFFIX = re.compile(r"-v\d+$")


class MeltKind(StrEnum):
    """Partial reopens a subregion; full returns the whole cell to learning."""

    PARTIAL = "PARTIAL"
    FULL = "FULL"


@dataclass(frozen=True, slots=True)
class MeltReport:
    """What a melt reopened, what survived it, and what it cost the neighbours.

    ``melted_cell`` is not in the architecture's field list; it is carried so a
    melt is **reversible from the report alone**. Rollback information is never
    deleted in this repository, and a report that named a rollback version
    without holding the thing to roll back to would be a promise, not a
    mechanism.
    """

    cell_id: str
    kind: MeltKind
    melted_region: CellBoundary | None
    surviving_cell: KnowledgeCellV1 | None
    reopened_keys: tuple[BoundaryKey, ...]
    unrelated_cells_before: int
    unrelated_cells_retained: int
    rollback_version: int
    reason: str
    melted_cell: KnowledgeCellV1 | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, MeltKind):
            raise ContractError("MeltReport.kind must be a MeltKind")
        for name in ("unrelated_cells_before", "unrelated_cells_retained", "rollback_version"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ContractError(f"MeltReport.{name} must be a non-negative int, got {value!r}")
        if self.unrelated_cells_retained > self.unrelated_cells_before:
            raise ContractError(
                f"MeltReport retained {self.unrelated_cells_retained} of "
                f"{self.unrelated_cells_before} unrelated cells; a melt cannot create cells, "
                "and a ratio above 1.0 would read as better-than-perfect locality"
            )
        if not isinstance(self.reopened_keys, tuple):
            raise ContractError("MeltReport.reopened_keys must be a tuple")
        if not isinstance(self.reason, str) or not self.reason.strip():
            raise ContractError("MeltReport.reason must say why the melt happened")

    @property
    def repair_locality(self) -> float | None:
        """Unrelated cells retained / unrelated cells before, or ``None``.

        ``None`` when there were no unrelated cells: a locality claim needs
        something that could have been damaged. It never means zero and it never
        means "within target".

        Read the module docstring before quoting this as evidence. Nothing in
        ``partial_melt``'s success path can remove a bystander, so on every
        report that exists this is 1.0 or ``None``. It is a sanity check that the
        melt stayed inside its two ids, not a measurement of whether the repair
        was localised *within* the melted cell.
        """
        if self.unrelated_cells_before == 0:
            return None
        return self.unrelated_cells_retained / self.unrelated_cells_before

    def to_dict(self) -> dict[str, Any]:
        return {
            "cell_id": self.cell_id,
            "kind": self.kind.value,
            "melted_region": None if self.melted_region is None else self.melted_region.to_dict(),
            "surviving_cell_id": (
                None if self.surviving_cell is None else self.surviving_cell.cell_id
            ),
            "reopened_keys": [list(key) for key in self.reopened_keys],
            "unrelated_cells_before": self.unrelated_cells_before,
            "unrelated_cells_retained": self.unrelated_cells_retained,
            "repair_locality": self.repair_locality,
            "rollback_version": self.rollback_version,
            "reason": self.reason,
        }


def successor_cell_id(cell: KnowledgeCellV1) -> str:
    """``<base>-v<version+1>``, with any previous version suffix replaced.

    A melted cell's survivor gets a new identity so the old one can still be
    rolled back to. Appending without replacing would grow the id on every melt
    until ``require_identifier`` refused it mid-incident.
    """
    base = _VERSION_SUFFIX.sub("", cell.cell_id)
    return f"{base}-v{cell.version + 1}"


def _subsets(items: tuple[Any, ...]) -> tuple[tuple[Any, ...], ...]:
    """Every subset, largest first, so the widest surviving region wins ties."""
    return tuple(
        subset
        for size in range(len(items), -1, -1)
        for subset in combinations(items, size)
    )


def narrow_boundary(
    boundary: CellBoundary, region: CellBoundary
) -> CellBoundary | None:
    """The widest sub-boundary of ``boundary`` that avoids ``region``.

    Searches the bounded lattice of (predicate subset) x (state-dimension
    subset). A candidate is accepted only when it is non-empty, it accepts **no
    frame the original did not** (:meth:`CellBoundary.accepts_no_more_than`), and
    it does **not intersect** the region (:meth:`CellBoundary.intersects`).

    Both conditions used to be evaluated on the key footprint, and both were
    unsound in the same way. ``keys()`` is a product over (families x declared
    required masks) while ``contains`` is a conjunction, so dropping an ACTOR
    predicate shrinks the key set while *enlarging* the set of frames accepted: a
    frame the pre-melt cell refused was answered committally by the post-melt
    survivor, with ``repair_locality`` still reporting 1.0. Symmetrically, key
    equality is too strict for the disjointness half, because ``keys()`` folds
    ``state_dimensions`` into one union delta mask while ``contains`` admits any
    frame whose delta dimensions are a subset.

    A predicate may still be dropped — the gate's spanning cell is narrowed
    exactly that way — but only when the predicates that remain impose at least
    as strong a mask conjunction, which is what
    :meth:`CellBoundary.accepts_no_more_than` checks per role.

    Returns ``None`` when no sub-boundary avoids the region — which means the
    drift covers the cell, and the caller must decide to melt it fully rather
    than have that decided for it here.
    """
    predicate_subsets = _subsets(tuple(boundary.predicates))
    dimension_subsets = _subsets(tuple(sorted(boundary.state_dimensions)))
    if len(predicate_subsets) * len(dimension_subsets) > MAX_NARROWING_CANDIDATES:
        raise ContractError(
            f"narrowing lattice for this boundary has "
            f"{len(predicate_subsets) * len(dimension_subsets)} candidates, above "
            f"MAX_NARROWING_CANDIDATES={MAX_NARROWING_CANDIDATES}; melting must stay "
            "bounded or a drifting host cannot repair itself"
        )
    best: tuple[tuple[int, int, int], CellBoundary] | None = None
    for predicates in predicate_subsets:
        for dimensions in dimension_subsets:
            if not dimensions:
                continue
            candidate = replace(
                boundary, predicates=predicates, state_dimensions=frozenset(dimensions)
            )
            if candidate.is_empty:
                continue
            try:
                keys = frozenset(candidate.keys())
            except ContractError:
                # An over-wide expansion is not a narrowing; skip it rather than
                # letting a cell grow a region while it is being repaired.
                continue
            if not keys:
                continue
            if not candidate.accepts_no_more_than(boundary):
                continue
            if candidate.intersects(region):
                continue
            score = (len(keys), len(predicates), len(dimensions))
            if best is None or score > best[0]:
                best = (score, candidate)
    return None if best is None else best[1]


def reopened_keys(
    cell_keys: frozenset[BoundaryKey], region: CellBoundary
) -> tuple[BoundaryKey, ...]:
    """Which of the cell's index keys the drifted region can reach.

    Filtered on the relation family only, and deliberately so. The other two
    terms of a :data:`BoundaryKey` cannot separate a region from a cell: the
    actor term is a *declared requirement* that a frame carries as a superset, so
    any two masks in the same family are jointly satisfiable, and the delta term
    is a union that ``contains`` matches by subset, so a frame raising nothing
    sits inside both. Filtering on those would be the key-equality mistake again,
    one axis down.
    """
    families = set(region.relation_families())
    return tuple(sorted(key for key in cell_keys if key[0] in families))


def unrelated_cell_ids(field: KnowledgeField, cell_id: str) -> tuple[str, ...]:
    return tuple(other.cell_id for other in field.cells() if other.cell_id != cell_id)


def count_retained(field: KnowledgeField, before: tuple[str, ...]) -> int:
    return sum(1 for cell_id in before if field.get(cell_id) is not None)


def _report(
    cell: KnowledgeCellV1,
    *,
    region: CellBoundary | None,
    surviving: KnowledgeCellV1 | None,
    reopened: tuple[BoundaryKey, ...],
    before: tuple[str, ...],
    retained: int,
    reason: str,
) -> MeltReport:
    return MeltReport(
        cell_id=cell.cell_id,
        kind=MeltKind.PARTIAL,
        melted_region=region,
        surviving_cell=surviving,
        reopened_keys=reopened,
        unrelated_cells_before=len(before),
        unrelated_cells_retained=retained,
        rollback_version=cell.version,
        reason=reason,
        melted_cell=cell,
    )


def partial_melt(
    cell: KnowledgeCellV1,
    region: CellBoundary,
    *,
    field: KnowledgeField,
    index: BoundaryIndex,
) -> MeltReport:
    """Reopen ``region``'s keys and leave the rest of ``cell`` crystallised.

    Touches exactly two ids: ``cell.cell_id`` and ``successor_cell_id(cell)``.
    Refuses up front when the second already names a live cell, rather than
    discovering the collision inside the insert and rolling back over a bystander.

    The survivor is marked ``STRESSED`` rather than ``CRYSTALLIZED``: it was
    demonstrably next door to something that stopped being true, so it keeps
    answering but at a raised audit rate. Calling it unaffected would be the
    comfortable reading of the same evidence.
    """
    before = unrelated_cell_ids(field, cell.cell_id)
    indexed = index.keys_for(cell.cell_id)
    cell_keys = frozenset(indexed) if indexed else frozenset(cell.boundary.keys())
    # Frame-level, not key-level. ``keys()`` folds ``state_dimensions`` into one
    # union delta mask while ``contains`` admits any frame whose delta dimensions
    # are a subset, so a region scoped to one dimension is key-disjoint from a
    # cell that spans two and still reaches every frame the cell answers. Reading
    # key-disjointness as region-disjointness reported such a drift as
    # REGION_DISJOINT and left the stale cell live and indexed — falsifier F2's
    # own failure condition.
    reopened = reopened_keys(cell_keys, region)
    if not region.intersects(cell.boundary):
        return _report(
            cell,
            region=region,
            surviving=cell,
            reopened=(),
            before=before,
            retained=count_retained(field, before),
            reason=(
                "REGION_DISJOINT: no frame can satisfy both the drifted region and this "
                "cell's boundary"
            ),
        )
    narrowed = narrow_boundary(cell.boundary, region)
    if narrowed is None:
        return _report(
            cell,
            region=region,
            surviving=None,
            reopened=reopened,
            before=before,
            retained=count_retained(field, before),
            reason=(
                "REGION_COVERS_CELL: no sub-boundary of this cell avoids the drifted "
                "region, so there is nothing to keep; call full_melt explicitly"
            ),
        )
    successor = successor_cell_id(cell)
    if successor != cell.cell_id and (
        field.get(successor) is not None or successor in index.cell_ids()
    ):
        # Refused up front rather than discovered inside the insert. ``cell_id``
        # and ``version`` are validated independently, so ``successor_cell_id``
        # can name a live, unrelated cell — and re-melting a stale reference names
        # the survivor of the previous melt. Either way the rollback below used to
        # remove that id, destroying a bystander with no MeltReport, no reason and
        # no rollback record.
        return _report(
            cell,
            region=region,
            surviving=None,
            reopened=reopened,
            before=before,
            retained=count_retained(field, before),
            reason=(
                f"SUCCESSOR_ID_TAKEN: {successor!r} already names a live cell, so this melt "
                "would have to overwrite it; melt or rename that cell first"
            ),
        )
    index.remove(cell.cell_id)
    field.remove(cell.cell_id)
    surviving = replace(
        cell,
        cell_id=successor,
        boundary=narrowed,
        phase=CellPhase.STRESSED,
        version=cell.version + 1,
        parent_cell_id=cell.cell_id,
    )
    inserted_into_field = False
    inserted_into_index = False
    try:
        field.insert(surviving)
        inserted_into_field = True
        index.insert(surviving)
        inserted_into_index = True
    except ContractError:
        # Put the original back rather than leaving the region unanswered by
        # anything: a failed repair must not also be a silent deletion. Only what
        # *this call* inserted is withdrawn — removing by id unconditionally
        # deleted whatever else happened to hold that id.
        if inserted_into_index:
            index.remove(surviving.cell_id)
        if inserted_into_field:
            field.remove(surviving.cell_id)
        _reinstate(cell, field=field, index=index)
        raise
    return _report(
        cell,
        region=region,
        surviving=surviving,
        reopened=reopened,
        before=before,
        retained=count_retained(field, before),
        reason=(
            f"PARTIAL_MELT: reopened {len(reopened)} of {len(cell_keys)} keys; "
            f"{surviving.cell_id!r} keeps the rest"
        ),
    )


def _reinstate(
    cell: KnowledgeCellV1, *, field: KnowledgeField, index: BoundaryIndex
) -> None:
    """Restore a cell to both containers, tolerating a partial removal."""
    if field.get(cell.cell_id) is None:
        field.insert(cell)
    if cell.cell_id not in index.cell_ids():
        index.insert(cell)
