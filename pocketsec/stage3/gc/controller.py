"""D3.14 — Intelligence GC: forgetting crystallised knowledge that stopped paying.

Architecture §29 asks for a utility function over Knowledge Cells and a collector
that compacts obsolete epochs, duplicate cells and unused transitions. This
module is that collector, and it is built around one refusal.

**A cell whose utility is UNMEASURED is retained.** :attr:`CellUtility.utility`
is ``None`` whenever any measured term is ``None``, and a ``None`` utility is
never compared against a threshold, never ranked and never collected — it is
counted in :attr:`GCReport.unmeasured_skipped` and left alone. Collecting on an
unmeasured basis would be exactly the failure this project rejected its own
Stage 2 core to avoid: a number that looks like evidence and is not one. Losing
knowledge on that basis is worse than keeping knowledge that costs bytes,
because the bytes are bounded by §38 and the loss is not recoverable.

**Incident-linked evidence is preserved independently of cell GC.** The
counterexample store has no delete API by construction
(``oracles/counterexamples.py``), and this collector does not reach into it. It
counts the incident-linked entries it protected so the number appears in the
report rather than being asserted in a docstring.

§29 also names "unused transitions" as a collection target. **This collector does
not implement that**, and the omission is deliberate rather than pending: the
only transition store Stage 3 has is the counterexample store, whose entries are
regression material with no delete API, and the transition cache belongs to
Stage 2 and already has its own bounded eviction (``lru_control``). There is no
third structure for this clause to act on, so it is recorded as absent rather
than faked with a no-op.

What GC *is* allowed to do is drop a cell from the field and the boundary index.
That is reversible in the only sense that matters here: the cell's evidence
lineage, its counterexamples and its ``parent_cell_id`` survive it, so the
region returns to the learned path rather than to nothing.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage3.cells.field import KnowledgeField
from pocketsec.stage3.cells.schema import KnowledgeCellV1

if TYPE_CHECKING:  # pragma: no cover - typing only
    from pocketsec.stage3.boundary.index import BoundaryIndex
    from pocketsec.stage3.oracles.counterexamples import CounterexampleStore

__all__ = [
    "CellUtility",
    "GCReason",
    "GCReport",
    "garbage_collect_knowledge",
]


class GCReason:
    """Why one cell was compacted. Strings, because they are report text, not control flow."""

    DUPLICATE = "DUPLICATE_OPERATOR"
    OBSOLETE_EPOCH = "OBSOLETE_EPOCH"
    NEGATIVE_UTILITY = "NEGATIVE_UTILITY"
    OVER_BUDGET = "OVER_BUDGET"


@dataclass(frozen=True, slots=True)
class CellUtility:
    """§29 Utility(K), with every term that could be unmeasured typed as such.

    The shape is a net saving per resident byte, weighted by how much the cell is
    trusted and how much security it carries:

        net_us  = usage * (saved_compute_us - audit_cost_us - maintenance_cost_us)
        utility = net_us * assurance * (1 + security_utility) / memory_bytes

    It can go **negative**, and that is the point. Falsifier F5 says the audit
    traffic needed to hold a cell's confidence may cost more than the cell saves;
    if it does, the arithmetic says so instead of a reviewer having to notice.
    """

    saved_compute_us: float | None
    usage: int
    assurance: float
    security_utility: float
    memory_bytes: int
    audit_cost_us: float | None
    maintenance_cost_us: float | None

    def __post_init__(self) -> None:
        _require_optional_float(self.saved_compute_us, "CellUtility.saved_compute_us")
        _require_optional_float(self.audit_cost_us, "CellUtility.audit_cost_us")
        _require_optional_float(self.maintenance_cost_us, "CellUtility.maintenance_cost_us")
        if not isinstance(self.usage, int) or isinstance(self.usage, bool) or self.usage < 0:
            raise ContractError(f"CellUtility.usage must be a count, got {self.usage!r}")
        for name in ("assurance", "security_utility"):
            value = getattr(self, name)
            if not isinstance(value, (int, float)) or not 0.0 <= float(value) <= 1.0:
                raise ContractError(f"CellUtility.{name} must be within [0, 1], got {value!r}")
        if (
            not isinstance(self.memory_bytes, int)
            or isinstance(self.memory_bytes, bool)
            or self.memory_bytes <= 0
        ):
            raise ContractError(
                "CellUtility.memory_bytes must be a positive byte count: a cell that "
                "resides in zero bytes is not a cell that was measured"
            )

    @property
    def measured(self) -> bool:
        return self.utility is not None

    @property
    def utility(self) -> float | None:
        """``None`` if **any** measured term is ``None``. Never a default, never zero."""
        if (
            self.saved_compute_us is None
            or self.audit_cost_us is None
            or self.maintenance_cost_us is None
        ):
            return None
        per_use = self.saved_compute_us - self.audit_cost_us - self.maintenance_cost_us
        net_us = self.usage * per_use
        return net_us * self.assurance * (1.0 + self.security_utility) / self.memory_bytes

    def to_dict(self) -> dict[str, Any]:
        return {
            "saved_compute_us": self.saved_compute_us,
            "usage": self.usage,
            "assurance": self.assurance,
            "security_utility": self.security_utility,
            "memory_bytes": self.memory_bytes,
            "audit_cost_us": self.audit_cost_us,
            "maintenance_cost_us": self.maintenance_cost_us,
            "utility": self.utility,
        }


@dataclass(frozen=True, slots=True)
class GCReport:
    """One collection pass, counted. No claims, only what happened."""

    evaluated: int
    compacted: int
    retained: int
    incident_protected: int
    bytes_reclaimed: int
    unmeasured_skipped: int
    compacted_ids: tuple[tuple[str, str], ...] = ()
    bytes_before: int = 0
    bytes_after: int = 0

    def __post_init__(self) -> None:
        if self.evaluated != self.compacted + self.retained:
            raise ContractError(
                f"GCReport accounts for {self.compacted + self.retained} of "
                f"{self.evaluated} evaluated cells; every cell is compacted or retained"
            )
        if self.unmeasured_skipped > self.retained:
            raise ContractError(
                "GCReport claims more unmeasured-skipped cells than retained cells; "
                "an unmeasured cell is always retained, so it cannot exceed the retained count"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "evaluated": self.evaluated,
            "compacted": self.compacted,
            "retained": self.retained,
            "incident_protected": self.incident_protected,
            "bytes_reclaimed": self.bytes_reclaimed,
            "unmeasured_skipped": self.unmeasured_skipped,
            "compacted_ids": [list(pair) for pair in self.compacted_ids],
            "bytes_before": self.bytes_before,
            "bytes_after": self.bytes_after,
        }


def _require_optional_float(value: object, name: str) -> None:
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ContractError(f"{name} must be a float or None (UNMEASURED), got {value!r}")
    numeric = float(value)
    if numeric != numeric:
        raise ContractError(f"{name} must be finite; NaN is not an unmeasured marker, None is")


def _incident_protected(store: CounterexampleStore | None) -> int:
    """Count, never touch. The store has no delete API and GC does not want one."""
    if store is None:
        return 0
    return sum(1 for cx in store.hot() if cx.incident_linked)


def _duplicate_ids(cells: Sequence[KnowledgeCellV1]) -> dict[str, str]:
    """Cells that carry an operator another cell already carries over the same region.

    The survivor is the lowest ``version`` at the highest confidence, so a
    rollback identity (``parent_cell_id``) is never the one collected. Only cells
    with a measured utility are ever offered here.

    **The region is part of the key.** ``OperatorProgram.digest`` is computed from
    the program's own canonical bytes and is therefore region-independent: two
    cells compiled from the same bounded rule over *disjoint* boundaries collide
    on it by construction, which is exactly what crystallising a zero-parameter
    Φ-oracle per relation family produces. Keying on the operator and the epochs
    alone deleted all but one of them under the label ``DUPLICATE_OPERATOR`` — a
    false reason for a real, unrecoverable loss of coverage, on the one code path
    whose justification is that forgetting must be a decision with a true
    recorded reason.

    Same operator over a *different* region is a fusion question
    (``cells/fusion.py`` unions the boundaries and re-enters shadow at A0), never
    a collection one.
    """
    seen: dict[tuple[str, frozenset[int], frozenset[Any]], KnowledgeCellV1] = {}
    duplicates: dict[str, str] = {}
    ordered = sorted(cells, key=lambda c: (-c.confidence, c.version, c.cell_id))
    for cell in ordered:
        try:
            footprint = frozenset(cell.boundary.keys())
        except ContractError:
            # A boundary that cannot state its own footprint cannot be shown to
            # duplicate anything. Retained, like an unmeasured utility.
            continue
        key = (cell.operator.digest, cell.epochs, footprint)
        incumbent = seen.get(key)
        if incumbent is None:
            seen[key] = cell
            continue
        duplicates[cell.cell_id] = GCReason.DUPLICATE
    return duplicates


def _obsolete_ids(
    cells: Sequence[KnowledgeCellV1], live_epochs: frozenset[int] | None
) -> dict[str, str]:
    """Cells bound only to epochs that no longer exist.

    ``live_epochs=None`` means the caller did not measure which epochs are live,
    so nothing is obsolete. Guessing here would collect on an unmeasured basis.
    """
    if not live_epochs:
        return {}
    return {
        cell.cell_id: GCReason.OBSOLETE_EPOCH
        for cell in cells
        if not (cell.epochs & live_epochs)
    }


def _drop(field: KnowledgeField, index: BoundaryIndex | None, cell_id: str) -> None:
    field.remove(cell_id)
    if index is not None:
        index.remove(cell_id)


def garbage_collect_knowledge(
    field: KnowledgeField,
    *,
    index: BoundaryIndex | None = None,
    store: CounterexampleStore | None = None,
    budget_bytes: int,
    utilities: Mapping[str, CellUtility] | None = None,
    live_epochs: frozenset[int] | None = None,
) -> GCReport:
    """Compact obsolete epochs, duplicate cells and negative-utility cells (§29).

    §29's "unused transitions" clause is **not implemented** — see the module
    docstring for why there is nothing for it to act on.

    ``utilities`` is keyed by ``cell_id``. A cell that is **absent** from it, or
    whose :attr:`CellUtility.utility` is ``None``, is retained and counted in
    ``unmeasured_skipped``: the collector will not act on a cost it did not
    measure. That is the parameter's whole reason for existing as a mapping
    rather than as a computation inside this function — utility is measured
    elsewhere, by whoever ran the audit, and cannot be synthesised here.

    ``budget_bytes`` is a ceiling, not a target: collection stops as soon as the
    field fits, and a field that already fits loses nothing to budget pressure.
    """
    if not isinstance(field, KnowledgeField):
        raise ContractError(f"garbage_collect_knowledge needs a KnowledgeField, got {field!r}")
    if not isinstance(budget_bytes, int) or isinstance(budget_bytes, bool) or budget_bytes < 0:
        raise ContractError(f"budget_bytes must be a non-negative int, got {budget_bytes!r}")
    measured = dict(utilities or {})
    cells = field.cells()
    bytes_before = field.memory_bytes()

    # Every cell whose utility is UNMEASURED is removed from consideration BEFORE
    # any rule runs — including the duplicate and obsolete-epoch rules. Those two
    # rules are structural rather than cost-based, but a cell nobody measured is a
    # cell nobody can show was safe to lose, and "it looked like a duplicate" is
    # exactly the reasoning that turns an unmeasured basis into a deletion.
    unmeasured = {
        cell.cell_id
        for cell in cells
        if measured.get(cell.cell_id) is None or measured[cell.cell_id].utility is None
    }
    collectable = [cell for cell in cells if cell.cell_id not in unmeasured]

    doomed: dict[str, str] = {}
    doomed.update(_obsolete_ids(collectable, live_epochs))
    doomed.update(_duplicate_ids(collectable))
    for cell in collectable:
        value = measured[cell.cell_id].utility
        if value is not None and value < 0.0 and cell.cell_id not in doomed:
            doomed[cell.cell_id] = GCReason.NEGATIVE_UTILITY

    reclaimed = 0
    compacted: list[tuple[str, str]] = []
    for cell in cells:
        reason = doomed.get(cell.cell_id)
        if reason is None:
            continue
        reclaimed += cell.size_bytes()
        _drop(field, index, cell.cell_id)
        compacted.append((cell.cell_id, reason))

    reclaimed, compacted = _collect_to_budget(
        field,
        index=index,
        budget_bytes=budget_bytes,
        measured=measured,
        reclaimed=reclaimed,
        compacted=compacted,
    )

    survivors = field.cells()
    unmeasured_skipped = sum(1 for cell in survivors if cell.cell_id in unmeasured)
    return GCReport(
        evaluated=len(cells),
        compacted=len(compacted),
        retained=len(survivors),
        incident_protected=_incident_protected(store),
        bytes_reclaimed=reclaimed,
        unmeasured_skipped=unmeasured_skipped,
        compacted_ids=tuple(compacted),
        bytes_before=bytes_before,
        bytes_after=field.memory_bytes(),
    )


def _collect_to_budget(
    field: KnowledgeField,
    *,
    index: BoundaryIndex | None,
    budget_bytes: int,
    measured: Mapping[str, CellUtility],
    reclaimed: int,
    compacted: list[tuple[str, str]],
) -> tuple[int, list[tuple[str, str]]]:
    """Drop the lowest *measured* utility first until the field fits.

    Cells with no measured utility are not candidates at any pressure. A field
    that cannot fit without collecting one of them stays over budget, and the
    caller sees that in ``bytes_after`` — an over-budget field is a visible
    problem, and a silently deleted cell is not.
    """
    if field.memory_bytes() <= budget_bytes:
        return reclaimed, compacted
    ranked = sorted(
        (
            (measured[cell.cell_id].utility, cell)
            for cell in field.cells()
            if cell.cell_id in measured and measured[cell.cell_id].utility is not None
        ),
        key=lambda pair: (pair[0], pair[1].cell_id),  # type: ignore[arg-type,return-value]
    )
    for _utility, cell in ranked:
        if field.memory_bytes() <= budget_bytes:
            break
        reclaimed += cell.size_bytes()
        _drop(field, index, cell.cell_id)
        compacted.append((cell.cell_id, GCReason.OVER_BUDGET))
    return reclaimed, compacted
