"""D3.15/G3.11 — every OPTIONAL function must name a measured experiment, or it FAILS.

``core_ids.py`` splits Stage 3's twenty functions into REQUIRED and OPTIONAL.
OPTIONAL is not a softer word for required: it is the ablation surface, and a
function on it that cannot point at a registered experiment id with a measured
delta has **failed** the criterion. It has not "not been got to yet". PENDING is
not a verdict this module can return, because a component whose value was never
measured is indistinguishable from a component that has none.

**The saturation guard runs first**, before any component is judged. Stage 1's
``ParetoReport.degenerate`` and ADR-0120 both reached the same conclusion: on a
saturated split no ablation means anything, because the background moves more
than any component could. If the best and median models are within
:data:`SATURATION_PR_AUC_BAND` PR-AUC of each other, or a pooled order-free
control lands within :data:`ORDER_FREE_BAND` of the best, the report is
``DEGENERATE`` and **no ablation result is recorded at all** — not a zero, not a
PENDING, nothing. Recording a component delta measured on a saturated split would
be manufacturing evidence.

Three verdicts are kept strictly apart, because collapsing them is how a project
talks itself into keeping machinery:

* ``JUSTIFIED`` — a measured positive delta above the noise band.
* ``NOT_YET_JUSTIFIED`` — measured, and no detectable benefit. **Not disproven.**
* ``REJECTED`` — measured, and measurably worse. This one is a decision.
* ``FAILED`` — no experiment id, or an experiment id with no measured delta.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage0.experiments.ids import parse_experiment_id
from pocketsec.stage3.core_ids import CORE_IDS, OPTIONAL_IDS
from pocketsec.stage3.labs.baselines import AT_CHANCE_PR_AUC_BAND, BaselineTable

__all__ = [
    "AblationEntry",
    "AblationReport",
    "AblationStatus",
    "ComponentVerdict",
    "MIN_MEANINGFUL_DELTA",
    "ORDER_FREE_BAND",
    "SATURATION_PR_AUC_BAND",
    "SaturationVerdict",
    "run_ablation",
    "saturation_guard",
]

#: Best minus median PR-AUC below this means the split cannot tell models apart.
#: Integration plan §8 risk 2.
SATURATION_PR_AUC_BAND = AT_CHANCE_PR_AUC_BAND

#: A pooled order-free control within this of the best means the split's signal is
#: reachable without any structure at all.
ORDER_FREE_BAND = 0.02

#: A component delta inside this band is measured noise, not a benefit. It is
#: deliberately the same size as the saturation band: a delta smaller than the
#: spread the split itself produces is not a delta.
MIN_MEANINGFUL_DELTA = 0.01


class AblationStatus(StrEnum):
    DEGENERATE = "DEGENERATE"
    MEASURED = "MEASURED"


class ComponentVerdict(StrEnum):
    JUSTIFIED = "JUSTIFIED"
    NOT_YET_JUSTIFIED = "NOT_YET_JUSTIFIED"
    REJECTED = "REJECTED"
    FAILED = "FAILED"


@dataclass(frozen=True, slots=True)
class SaturationVerdict:
    """Whether the split can distinguish anything, and the numbers that decided it."""

    degenerate: bool
    best: float | None
    median: float | None
    spread: float | None
    order_free: float | None
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "degenerate": self.degenerate,
            "best": self.best,
            "median": self.median,
            "spread": self.spread,
            "order_free": self.order_free,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class AblationEntry:
    """One OPTIONAL function's standing."""

    core_id: str
    name: str
    deliverable: str
    experiment_id: str | None
    delta_pr_auc: float | None
    verdict: ComponentVerdict
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "core_id": self.core_id,
            "name": self.name,
            "deliverable": self.deliverable,
            "experiment_id": self.experiment_id,
            "delta_pr_auc": self.delta_pr_auc,
            "verdict": self.verdict.value,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class AblationReport:
    """G3.11's answer, and its refusal to answer on a saturated split."""

    status: AblationStatus
    saturation: SaturationVerdict
    entries: tuple[AblationEntry, ...]
    measured_by: str

    def __post_init__(self) -> None:
        if self.status is AblationStatus.DEGENERATE and self.entries:
            raise ContractError(
                "a DEGENERATE ablation may record no component result; a delta measured "
                "on a split that cannot distinguish models is not evidence"
            )

    @property
    def failed(self) -> tuple[str, ...]:
        return tuple(e.core_id for e in self.entries if e.verdict is ComponentVerdict.FAILED)

    @property
    def not_yet_justified(self) -> tuple[str, ...]:
        """Kept separate from ``rejected`` on purpose. Untested is not disproven."""
        return tuple(
            e.core_id for e in self.entries if e.verdict is ComponentVerdict.NOT_YET_JUSTIFIED
        )

    @property
    def rejected(self) -> tuple[str, ...]:
        return tuple(e.core_id for e in self.entries if e.verdict is ComponentVerdict.REJECTED)

    @property
    def passes_g3_11(self) -> bool:
        """G3.11 passes only on a discriminating split with no FAILED component."""
        return self.status is AblationStatus.MEASURED and not self.failed

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "passes_g3_11": self.passes_g3_11,
            "saturation": self.saturation.to_dict(),
            "failed": list(self.failed),
            "not_yet_justified": list(self.not_yet_justified),
            "rejected": list(self.rejected),
            "entries": [entry.to_dict() for entry in self.entries],
            "measured_by": self.measured_by,
        }


def _median(values: Sequence[float]) -> float:
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / 2.0


def saturation_guard(
    scores: Sequence[float | None], *, order_free: float | None = None
) -> SaturationVerdict:
    """Run before anything is ablated. Refuses to let a saturated split answer.

    ``scores`` are the models' PR-AUCs from one run. A ``None`` is dropped rather
    than treated as zero — an unmeasured model tells you nothing about spread.
    """
    measured = [float(value) for value in scores if value is not None]
    if len(measured) < 2:
        return SaturationVerdict(
            degenerate=True,
            best=max(measured) if measured else None,
            median=None,
            spread=None,
            order_free=order_free,
            reason=(
                f"{len(measured)} measured model score(s); a spread needs at least two, "
                "so the split's discriminating power is UNMEASURED"
            ),
        )
    best = max(measured)
    median = _median(measured)
    spread = best - median
    if spread <= SATURATION_PR_AUC_BAND:
        # Two different degeneracies produce the same small ``spread``, and saying
        # "the split cannot tell models apart" for both was false for one of them.
        # With four of six models at the ceiling the median *is* the ceiling, so
        # the spread is 0.0 while the full range separates the two groups by 0.72:
        # the split discriminates, but a median-based spread cannot see it. The
        # verdict stays DEGENERATE either way — a ceiling that half the models
        # reach cannot show that any component helps — but the reason has to say
        # which case it is.
        worst = min(measured)
        if best - worst > SATURATION_PR_AUC_BAND:
            reason = (
                f"best {best:.4f} and median {median:.4f} differ by {spread:.4f} "
                f"<= {SATURATION_PR_AUC_BAND}, while best and worst differ by "
                f"{best - worst:.4f}: more than half the models sit at the ceiling, so "
                "the split separates two groups but cannot rank within the upper one"
            )
        else:
            reason = (
                f"best {best:.4f} and median {median:.4f} differ by {spread:.4f} "
                f"<= {SATURATION_PR_AUC_BAND}, and best and worst by "
                f"{best - worst:.4f}; the split cannot tell models apart"
            )
        return SaturationVerdict(
            degenerate=True,
            best=best,
            median=median,
            spread=spread,
            order_free=order_free,
            reason=reason,
        )
    if order_free is not None and best - float(order_free) <= ORDER_FREE_BAND:
        return SaturationVerdict(
            degenerate=True,
            best=best,
            median=median,
            spread=spread,
            order_free=order_free,
            reason=(
                f"a pooled order-free control reaches {order_free:.4f} against a best of "
                f"{best:.4f}; the split's signal needs no structure at all"
            ),
        )
    return SaturationVerdict(
        degenerate=False,
        best=best,
        median=median,
        spread=spread,
        order_free=order_free,
        reason=f"spread {spread:.4f} above {SATURATION_PR_AUC_BAND}",
    )


def _entry(
    core_id: str, experiment_id: str | None, delta: float | None
) -> AblationEntry:
    function = CORE_IDS[core_id]
    if experiment_id is None:
        return AblationEntry(
            core_id=core_id,
            name=function.name,
            deliverable=function.deliverable,
            experiment_id=None,
            delta_pr_auc=None,
            verdict=ComponentVerdict.FAILED,
            reason="no registered experiment id; an OPTIONAL function with none has FAILED",
        )
    parse_experiment_id(experiment_id)  # refuses a malformed id rather than recording it
    if delta is None:
        return AblationEntry(
            core_id=core_id,
            name=function.name,
            deliverable=function.deliverable,
            experiment_id=experiment_id,
            delta_pr_auc=None,
            verdict=ComponentVerdict.FAILED,
            reason="experiment id registered but the delta is UNMEASURED; that is a FAIL",
        )
    value = float(delta)
    if value > MIN_MEANINGFUL_DELTA:
        verdict, reason = ComponentVerdict.JUSTIFIED, f"measured +{value:.4f} PR-AUC"
    elif value < -MIN_MEANINGFUL_DELTA:
        verdict, reason = ComponentVerdict.REJECTED, f"measured {value:.4f} PR-AUC: worse"
    else:
        verdict, reason = (
            ComponentVerdict.NOT_YET_JUSTIFIED,
            f"measured {value:+.4f} PR-AUC, inside the {MIN_MEANINGFUL_DELTA} noise band; "
            "no detectable benefit, which is NOT the same as disproven",
        )
    return AblationEntry(
        core_id=core_id,
        name=function.name,
        deliverable=function.deliverable,
        experiment_id=experiment_id,
        delta_pr_auc=value,
        verdict=verdict,
        reason=reason,
    )


def run_ablation(
    table: BaselineTable,
    *,
    experiments: Mapping[str, str] | None = None,
    deltas: Mapping[str, float | None] | None = None,
    order_free: float | None = None,
    measured_by: str = "pocketsec.stage3.labs.ablation:run_ablation",
) -> AblationReport:
    """Guard first, then judge every ``FunctionClass.OPTIONAL`` id in ``core_ids``.

    ``experiments`` maps a core id to the registered experiment that ablated it;
    ``deltas`` maps the same core id to that experiment's measured PR-AUC delta.
    They are separate parameters because an id without a delta is a *different*
    failure from no id at all, and the report says which.

    The OPTIONAL set is read from ``core_ids.OPTIONAL_IDS``, never from the
    caller: a caller that could choose which components to ablate could choose
    not to ablate the one that would fail.
    """
    verdict = saturation_guard(
        [row.pr_auc for row in table.rows], order_free=order_free
    )
    if verdict.degenerate:
        return AblationReport(
            status=AblationStatus.DEGENERATE,
            saturation=verdict,
            entries=(),
            measured_by=measured_by,
        )
    registered = dict(experiments or {})
    measured = dict(deltas or {})
    unknown = set(registered) - set(OPTIONAL_IDS)
    if unknown:
        raise ContractError(
            f"experiments name non-OPTIONAL core ids {sorted(unknown)}; the ablation "
            "surface is OPTIONAL_IDS and nothing else"
        )
    entries = tuple(
        _entry(core_id, registered.get(core_id), measured.get(core_id))
        for core_id in sorted(OPTIONAL_IDS)
    )
    return AblationReport(
        status=AblationStatus.MEASURED,
        saturation=verdict,
        entries=entries,
        measured_by=measured_by,
    )
