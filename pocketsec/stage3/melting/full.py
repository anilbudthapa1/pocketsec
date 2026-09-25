"""D3.13 (part) — full melting, rollback and recrystallization.

A full melt returns a whole cell to the learned path. It is the destructive end
of the lifecycle, so this module is written around what it must **not** destroy:

* **Counterexamples.** :func:`full_melt` takes no
  :class:`~pocketsec.stage3.oracles.counterexamples.CounterexampleStore`. That
  is the guarantee, expressed as an absence rather than as a promise: a function
  that holds no reference to the store cannot drop an incident-linked
  counterexample, however it is later edited. The store has no delete API for
  the same reason.
* **Rollback information.** The report carries the melted cell and its version,
  so :func:`rollback` can reinstate it. "Never delete prior research artefacts,
  counterexamples, provenance or rollback information" is a repository rule; a
  melt that forgot the cell would break it at the worst possible moment.
* **Lineage.** The melted cell keeps its ``parent_cell_id`` untouched, so a
  chain of melts and recrystallisations stays walkable.

:func:`recrystallize` returns ``None`` rather than guessing. Reopening a region
needs *fresh* observations; recompiling from the same samples that drifted would
rebuild the cell that just failed and call it a repair.

``MeltKind`` and ``MeltReport`` are defined in :mod:`..melting.partial` and
re-exported here, because the build contract names ``melting/full.py`` as the
import path Stages 6 and 11 use. One definition, two doors — a second dataclass
with the same name is how two seams start disagreeing about a field.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage3.melting.partial import (
    MeltKind,
    MeltReport,
    count_retained,
    unrelated_cell_ids,
)

if TYPE_CHECKING:  # pragma: no cover - import-time cost, not behaviour
    from pocketsec.stage3.boundary.index import BoundaryIndex
    from pocketsec.stage3.cells.field import KnowledgeField
    from pocketsec.stage3.cells.schema import KnowledgeCellV1
    from pocketsec.stage3.crystal.pipeline import CrystalConfig, CrystalRun, RegionSample
    from pocketsec.stage3.oracles.counterexamples import CounterexampleStore
    from pocketsec.stage3.oracles.teacher import TeacherOracle

__all__ = ["MeltKind", "MeltReport", "full_melt", "recrystallize", "rollback"]


def full_melt(
    cell: KnowledgeCellV1, *, field: KnowledgeField, index: BoundaryIndex
) -> MeltReport:
    """Return the whole cell to the learned path, reversibly.

    Removes the cell from the field and the index and from nothing else. Every
    other cell keeps its keys, which is what ``repair_locality`` reports; a full
    melt is local too, it is just local to a whole cell rather than to a region.
    """
    before = unrelated_cell_ids(field, cell.cell_id)
    indexed = index.keys_for(cell.cell_id)
    reopened = tuple(sorted(indexed if indexed else cell.boundary.keys()))
    index.remove(cell.cell_id)
    field.remove(cell.cell_id)
    return MeltReport(
        cell_id=cell.cell_id,
        kind=MeltKind.FULL,
        melted_region=cell.boundary,
        surviving_cell=None,
        reopened_keys=reopened,
        unrelated_cells_before=len(before),
        unrelated_cells_retained=count_retained(field, before),
        rollback_version=cell.version,
        reason=(
            f"FULL_MELT: {cell.cell_id!r} returned to the learned path; "
            f"{len(reopened)} key(s) reopened, lineage parent "
            f"{cell.parent_cell_id!r} preserved"
        ),
        melted_cell=cell,
    )


def rollback(
    report: MeltReport, *, field: KnowledgeField, index: BoundaryIndex
) -> KnowledgeCellV1 | None:
    """Reinstate the cell a melt removed, from the report alone.

    Returns ``None`` when the report carries no melted cell, or when the cell is
    already present — reinserting over a live cell would be a silent overwrite,
    and the field refuses those on purpose.

    This is what makes melting *reversible* rather than merely destructive, and
    it is the mechanism behind the certificate-rollback threat control in §40:
    rollback is an explicit call with a report in hand, not something an
    attacker can trigger by making a cell look old.
    """
    cell = report.melted_cell
    if cell is None or report.surviving_cell is not None:
        return None
    if field.get(cell.cell_id) is not None or cell.cell_id in index.cell_ids():
        return None
    field.insert(cell)
    try:
        index.insert(cell)
    except ContractError:
        field.remove(cell.cell_id)
        raise
    return cell


def recrystallize(
    report: MeltReport,
    *,
    config: CrystalConfig,
    teacher: TeacherOracle,
    field: KnowledgeField,
    store: CounterexampleStore,
    region: RegionSample | None = None,
) -> CrystalRun | None:
    """Reopen a melted region through CRYSTAL, or return ``None``.

    ``None`` — never a fabricated run — when either:

    * the melt reopened no keys, so there is nothing to recompile; or
    * no fresh :class:`RegionSample` has been observed since the melt. The
      samples that produced the melted cell are exactly the ones that drifted;
      recompiling from them would reconstruct the failure and label it a repair.

    The pipeline import is deferred to call time so that this module stays
    importable — and melting stays usable — even while the synthesis package is
    mid-change. Melting is the recovery path; it must not be the thing that
    cannot load.
    """
    if not report.reopened_keys:
        return None
    if region is None:
        return None
    from pocketsec.stage3.crystal.pipeline import crystallize

    return crystallize(region, config=config, teacher=teacher, field=field, store=store)
