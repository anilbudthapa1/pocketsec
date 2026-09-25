"""D3.10 (part) — cell fission (§22): split only the heterogeneous region.

When counterexamples show that one cell contains incompatible security futures,
the tempting repair is to add another branch to the cell's operator. §22 refuses
that: *"Fission is preferred to adding unlimited branches to a single cell. The
objective is locally simple intelligence."* A cell that keeps accreting branches
stops being auditable, and auditability is the only property Stage 3 claims.

So fission carves the cell into three domains and touches nothing else:

* **STABLE** — the part the counterexamples never reached. It keeps its
  predicates, its Φ range, its uncertainty ceiling and its epochs *unchanged*,
  and stays crystallized. If the stable domain's boundary moved, fission would
  be re-synthesis wearing a different name.
* **AMBIGUOUS** — the dimensions and epochs the counterexamples actually
  touched. Returned to the learned path as a boundary, not as a cell: nothing
  here has been validated yet.
* **INVALID** — counterexamples arriving from an epoch the cell never claimed.
  The cell should not have answered there at all, so that region is rejected
  outright rather than relearned.

Two refusals are the mechanical cap on §39's "knowledge explosion" threat, and
both are named tests rather than review comments:

* ``depth >= MAX_FISSION_DEPTH`` — a cell may not be split indefinitely.
* the split would push the field past ``MAX_CELLS`` — fission that cannot fit
  is refused, so an adversary who can force splits cannot force growth.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass, replace
from enum import StrEnum

from pocketsec.stage3.boundary.index import CellBoundary
from pocketsec.stage3.cells.field import MAX_CELLS, KnowledgeField
from pocketsec.stage3.cells.schema import CellPhase, KnowledgeCellV1
from pocketsec.stage3.oracles.counterexamples import Counterexample

__all__ = [
    "MAX_FISSION_DEPTH",
    "FissionDomain",
    "FissionResult",
    "fission_cell",
]

#: A cell split three times is already four cells narrower than the region it
#: was meant to summarise. Beyond that, splitting is admitting the invariant was
#: wrong, and the honest move is a full melt rather than another split.
MAX_FISSION_DEPTH = 3


class FissionDomain(StrEnum):
    STABLE = "STABLE"
    AMBIGUOUS = "AMBIGUOUS"
    INVALID = "INVALID"


@dataclass(frozen=True, slots=True)
class FissionResult:
    """What a split produced, including the case where it produced nothing.

    ``stable is None`` with a non-empty ``reason`` is a refusal, not an error;
    the caller keeps the original cell or melts it.
    """

    stable: KnowledgeCellV1 | None
    ambiguous: CellBoundary | None
    invalid: CellBoundary | None
    depth: int
    reason: str

    @property
    def split(self) -> bool:
        return self.stable is not None

    def domains(self) -> tuple[FissionDomain, ...]:
        present: list[FissionDomain] = []
        if self.stable is not None:
            present.append(FissionDomain.STABLE)
        if self.ambiguous is not None:
            present.append(FissionDomain.AMBIGUOUS)
        if self.invalid is not None:
            present.append(FissionDomain.INVALID)
        return tuple(present)


def _touched_dimensions(
    cell: KnowledgeCellV1, counterexamples: Sequence[Counterexample]
) -> frozenset[str]:
    """Boundary dimensions the counterexamples actually disagreed about."""
    touched: set[str] = set()
    for counterexample in counterexamples:
        moved = (
            counterexample.expected.delta.dimensions
            | counterexample.observed.delta.dimensions
        )
        touched |= moved & cell.boundary.state_dimensions
    return frozenset(touched)


def _invalid_epochs(
    cell: KnowledgeCellV1, counterexamples: Sequence[Counterexample]
) -> frozenset[int]:
    """Epochs a counterexample arrived from that the cell never claimed."""
    return frozenset(
        c.epoch_id for c in counterexamples if c.epoch_id not in cell.boundary.epochs
    )


def _touched_epochs(
    cell: KnowledgeCellV1, counterexamples: Sequence[Counterexample]
) -> frozenset[int]:
    return frozenset(
        c.epoch_id for c in counterexamples if c.epoch_id in cell.boundary.epochs
    )


def _child_id(
    cell: KnowledgeCellV1, domain: FissionDomain, depth: int, dims: frozenset[str]
) -> str:
    """Deterministic child identity, so a replayed fission is the same fission."""
    payload = f"{cell.cell_id}|{domain.value}|{depth}|{'.'.join(sorted(dims))}"
    return f"{cell.cell_id[:32]}-{domain.value[:3].lower()}-" + hashlib.sha256(
        payload.encode("utf-8")
    ).hexdigest()[:12]


def _refusal(depth: int, reason: str) -> FissionResult:
    return FissionResult(stable=None, ambiguous=None, invalid=None, depth=depth, reason=reason)


def fission_cell(
    cell: KnowledgeCellV1,
    counterexamples: Sequence[Counterexample],
    *,
    depth: int,
    field: KnowledgeField,
) -> FissionResult:
    """Split ``cell`` along the dimensions its counterexamples disagreed about.

    ``field`` is required — not optional with a permissive default — because the
    ``MAX_CELLS`` refusal is the cap on the knowledge-explosion threat, and a
    default that skipped the check would remove the cap for every caller that
    forgot the argument.
    """
    if depth < 0:
        raise ValueError("depth must be >= 0")
    if depth >= MAX_FISSION_DEPTH:
        return _refusal(depth, f"MAX_FISSION_DEPTH: depth {depth} >= {MAX_FISSION_DEPTH}")
    if not counterexamples:
        return _refusal(depth, "NO_COUNTEREXAMPLES: nothing identifies a heterogeneous region")

    # Fission replaces one cell with one narrower cell plus an un-crystallized
    # boundary, so it adds at most one occupant — but it is still refused when
    # the field cannot hold that one, which is what stops forced-fission growth.
    if len(field.cells()) + 1 > MAX_CELLS:
        return _refusal(depth, f"MAX_CELLS: field holds {len(field.cells())} of {MAX_CELLS}")

    invalid_epochs = _invalid_epochs(cell, counterexamples)
    touched = _touched_dimensions(cell, counterexamples)
    stable_dimensions = cell.boundary.state_dimensions - touched
    if not stable_dimensions:
        return _refusal(depth, "NO_STABLE_DOMAIN: counterexamples cover every boundary dimension")
    if not touched and not invalid_epochs:
        # Nothing heterogeneous was identified, so a "split" here would emit a
        # copy of the cell under a new id — field growth with no new knowledge,
        # which is the §39 explosion by another route.
        return _refusal(
            depth, "NO_HETEROGENEOUS_REGION: the counterexamples touch no boundary clause"
        )

    return _build_result(
        cell,
        depth=depth,
        touched=touched,
        stable_dimensions=stable_dimensions,
        touched_epochs=_touched_epochs(cell, counterexamples),
        invalid_epochs=invalid_epochs,
    )


def _build_result(
    cell: KnowledgeCellV1,
    *,
    depth: int,
    touched: frozenset[str],
    stable_dimensions: frozenset[str],
    touched_epochs: frozenset[int],
    invalid_epochs: frozenset[int],
) -> FissionResult:
    """Assemble the three domains. Only ``state_dimensions`` ever moves."""
    stable_boundary = replace(cell.boundary, state_dimensions=stable_dimensions)
    stable = replace(
        cell,
        cell_id=_child_id(cell, FissionDomain.STABLE, depth, stable_dimensions),
        boundary=stable_boundary,
        parent_cell_id=cell.cell_id,
        version=cell.version + 1,
        phase=CellPhase.CRYSTALLIZED,
    )
    ambiguous = (
        replace(
            cell.boundary,
            state_dimensions=touched,
            epochs=touched_epochs or cell.boundary.epochs,
        )
        if touched
        else None
    )
    invalid = (
        replace(cell.boundary, state_dimensions=touched or cell.boundary.state_dimensions,
                epochs=invalid_epochs)
        if invalid_epochs
        else None
    )
    reason = (
        f"split on {len(touched)} heterogeneous dimension(s); "
        f"{len(stable_dimensions)} retained unchanged"
    )
    return FissionResult(
        stable=stable, ambiguous=ambiguous, invalid=invalid, depth=depth, reason=reason
    )
