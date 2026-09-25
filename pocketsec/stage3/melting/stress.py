"""D3.13 (part) — ``CellStress``: the measured pressure on one crystallised cell.

Architecture §24. Stress is what decides whether a cell keeps answering, gets
audited harder, loses a subregion or melts entirely. It exists so that decision
is made on *observations* rather than on a feeling that a cell has "got old".

Two refusals carry the honesty contract here:

* ``compute_cell_stress`` **raises** when no audit was actually run. A
  disagreement *rate* over zero audits is not zero, it is undefined, and a
  fabricated 0.0 would read as "the cell agreed with the oracle" — which is the
  strongest possible claim, made from no evidence at all.
* Counts (boundary violations, counterexamples, epoch drift) legitimately start
  at zero when the corresponding instrument was not run, because a count of
  observed events is honest at zero. The docstrings say which is which so a
  later reader cannot mistake "not looked for" for "looked for and absent".

``total`` is a weighted sum with saturating count terms, so it stays inside
[0, 1] and the two thresholds below are comparable across cells of different
sizes. It is deliberately **not** a probability.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage3.theory import THRESHOLDS

if TYPE_CHECKING:  # pragma: no cover - import-time cost, not behaviour
    from pocketsec.stage3.boundary.pressure import BoundaryPressureReport
    from pocketsec.stage3.cells.schema import KnowledgeCellV1
    from pocketsec.stage3.oracles.counterexamples import CounterexampleStore
    from pocketsec.stage3.promotion.audit import AuditReport

__all__ = [
    "CellStress",
    "FULL_MELT_THRESHOLD",
    "PARTIAL_MELT_THRESHOLD",
    "STRESS_SATURATION",
    "STRESS_TERMS",
    "STRESS_WEIGHTS",
    "compute_cell_stress",
]

#: The six terms architecture §24 names, in the order ``total`` applies them.
#: Pinned as a tuple because the weight mapping is checked against it at import:
#: a term added to one and not the other would silently drop out of the sum.
STRESS_TERMS: tuple[str, ...] = (
    "teacher_disagreement",
    "boundary_violations",
    "epoch_drift",
    "uncertainty_rise",
    "counterexamples",
    "calibration_decay",
)

#: Weights sum to exactly 1.0 so ``total`` is bounded by [0, 1] and the two
#: thresholds mean the same thing for every cell. Teacher disagreement and
#: boundary violations carry the most weight because they are the two terms that
#: say the cell is *wrong*, rather than merely unproven.
STRESS_WEIGHTS: Mapping[str, float] = MappingProxyType(
    {
        "teacher_disagreement": 0.30,
        "boundary_violations": 0.25,
        "epoch_drift": 0.15,
        "uncertainty_rise": 0.10,
        "counterexamples": 0.15,
        "calibration_decay": 0.05,
    }
)

#: Half-saturation constant for the three count terms: ``n / (n + 4)``. Four
#: independent counterexamples is the point at which a region is a problem
#: rather than an unlucky sample, matching ``MIN_LINEAGE_SUPPORT`` in invariant
#: discovery — the same number that made the knowledge admissible retires it.
STRESS_SATURATION = 4.0

#: Above this, one subregion of the cell is reopened (``partial_melt``).
PARTIAL_MELT_THRESHOLD = 0.35

#: Above this, the whole cell goes back to the learned path (``full_melt``).
FULL_MELT_THRESHOLD = 0.70


def _saturate(count: int) -> float:
    """Map an unbounded count into [0, 1) without a cliff edge."""
    return count / (count + STRESS_SATURATION)


def _clamp01(value: float) -> float:
    return 0.0 if value < 0.0 else (1.0 if value > 1.0 else value)


def _require_ratio(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ContractError(f"{field} must be a real number, got {value!r}")
    number = float(value)
    if not math.isfinite(number) or number < 0.0:
        raise ContractError(f"{field} must be finite and >= 0, got {number!r}")
    return number


def _require_count(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ContractError(f"{field} must be a non-negative int, got {value!r}")
    return value


@dataclass(frozen=True, slots=True)
class CellStress:
    """How hard reality is pushing back on one crystallised cell (§24)."""

    teacher_disagreement: float
    boundary_violations: int
    epoch_drift: int
    uncertainty_rise: float
    counterexamples: int
    calibration_decay: float

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "teacher_disagreement",
            _require_ratio(self.teacher_disagreement, "CellStress.teacher_disagreement"),
        )
        object.__setattr__(
            self,
            "uncertainty_rise",
            _require_ratio(self.uncertainty_rise, "CellStress.uncertainty_rise"),
        )
        object.__setattr__(
            self,
            "calibration_decay",
            _require_ratio(self.calibration_decay, "CellStress.calibration_decay"),
        )
        _require_count(self.boundary_violations, "CellStress.boundary_violations")
        _require_count(self.epoch_drift, "CellStress.epoch_drift")
        _require_count(self.counterexamples, "CellStress.counterexamples")

    @property
    def total(self) -> float:
        """Weighted stress in [0, 1]. Not a probability, and never presented as one."""
        weights = STRESS_WEIGHTS
        return (
            weights["teacher_disagreement"] * _clamp01(self.teacher_disagreement)
            + weights["boundary_violations"] * _saturate(self.boundary_violations)
            + weights["epoch_drift"] * _saturate(self.epoch_drift)
            + weights["uncertainty_rise"] * _clamp01(self.uncertainty_rise)
            + weights["counterexamples"] * _saturate(self.counterexamples)
            + weights["calibration_decay"] * _clamp01(self.calibration_decay)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "teacher_disagreement": self.teacher_disagreement,
            "boundary_violations": self.boundary_violations,
            "epoch_drift": self.epoch_drift,
            "uncertainty_rise": self.uncertainty_rise,
            "counterexamples": self.counterexamples,
            "calibration_decay": self.calibration_decay,
            "total": self.total,
        }


def open_counterexamples(
    cell: KnowledgeCellV1, store: CounterexampleStore
) -> tuple[Any, ...]:
    """Counterexamples still standing against this cell.

    A superseded entry is kept forever (the store has no delete API) but it no
    longer counts against the cell, or a fixed defect would hold a cell down for
    the rest of the deployment.

    Looks under the cell's ``source_candidate_id`` as well as its ``cell_id``,
    because those are two different keyspaces and the pipeline writes to the
    first: ``crystal.pipeline._record`` files every refusal under the region's
    ``candidate_id``, while a provisional cell's id is
    ``cand-<sha256(program.digest)[:20]>``. Joining on ``cell_id`` alone always
    returned nothing, so ``counterexamples`` and ``epoch_drift`` — 30% of the
    melt-trigger score by weight — were structurally 0.0 for every CRYSTAL-built
    cell, however often it failed its own region.
    """
    keys = [cell.cell_id]
    if cell.source_candidate_id and cell.source_candidate_id not in keys:
        keys.append(cell.source_candidate_id)
    seen: dict[str, Any] = {}
    for key in keys:
        for cx in store.for_candidate(key):
            if cx.superseded_by is None:
                seen[cx.counterexample_id] = cx
    return tuple(seen[cid] for cid in sorted(seen))


def compute_cell_stress(
    cell: KnowledgeCellV1,
    *,
    audit: AuditReport,
    pressure: BoundaryPressureReport | None,
    store: CounterexampleStore,
) -> CellStress:
    """Assemble §24's six stress terms from things that were actually measured.

    Refuses when ``audit.audits`` is zero: the first term is a *rate*, and a rate
    over no trials cannot be reported as 0.0 without claiming the cell agreed
    with the oracle. Callers with no audit traffic have no stress figure, which
    is the correct answer, not an inconvenience.

    Refuses for the same reason when every audited frame came back with the
    teacher silent. A rate over trials in which the oracle never answered is as
    undefined as a rate over zero trials — and it used to read 1.0, the maximum,
    which is worse than treating absence as agreement.
    """
    if audit.audits <= 0:
        raise ContractError(
            "compute_cell_stress requires at least one audit: teacher_disagreement is a "
            "rate, and a rate over zero trials is undefined, not zero. Run an audit pass "
            "or accept that this cell has no measured stress."
        )
    disagreement_rate = audit.disagreement_rate
    if disagreement_rate is None:
        raise ContractError(
            f"compute_cell_stress was given {audit.audits} audit(s) of which "
            f"{audit.teacher_silent} had no oracle opinion at all, so "
            "teacher_disagreement is UNMEASURED rather than 1.0. Pin a teacher "
            "snapshot covering these frames, or accept that this cell has no measured "
            "stress."
        )
    still_open = open_counterexamples(cell, store)
    drifted_epochs = {cx.epoch_id for cx in still_open} - set(cell.epochs)
    if pressure is None:
        # Not measured and not invented: these are counts of observed events, so
        # zero means "the instrument was not run", stated here rather than hidden.
        violations = 0
        uncertainty_rise = 0.0
    else:
        violations = pressure.false_inside + pressure.near_boundary_errors
        uncertainty_rise = (
            len(pressure.divergences) / pressure.probes_run if pressure.probes_run else 0.0
        )
    threshold = THRESHOLDS[cell.invariant.consequent.consequence]
    overshoot = (
        cell.resolution.calibrated_uncertainty - threshold.max_calibrated_uncertainty
    )
    return CellStress(
        teacher_disagreement=disagreement_rate,
        boundary_violations=violations,
        epoch_drift=len(drifted_epochs),
        uncertainty_rise=uncertainty_rise,
        counterexamples=len(still_open),
        calibration_decay=max(0.0, overshoot),
    )


def _assert_weights_cover_every_term() -> None:
    """A term with no weight would drop silently out of ``total``."""
    if set(STRESS_WEIGHTS) != set(STRESS_TERMS):
        raise ContractError(
            f"STRESS_WEIGHTS keys {sorted(STRESS_WEIGHTS)} do not match STRESS_TERMS "
            f"{sorted(STRESS_TERMS)}; an unweighted term is an unread measurement"
        )
    total = sum(STRESS_WEIGHTS.values())
    if abs(total - 1.0) > 1e-9:
        raise ContractError(
            f"STRESS_WEIGHTS sum to {total}, not 1.0; ``total`` would leave [0, 1] and the "
            "melt thresholds would mean different things for different cells"
        )
    if not 0.0 < PARTIAL_MELT_THRESHOLD < FULL_MELT_THRESHOLD <= 1.0:
        raise ContractError(
            "melt thresholds must satisfy 0 < PARTIAL < FULL <= 1; otherwise a cell could "
            "reach full melt without ever having been partially melted"
        )


_assert_weights_cover_every_term()
