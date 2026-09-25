"""D3.14 — the Stage 3 resource budget, and the rule that unmeasured is not within target.

Architecture §38 gives Stage 3 a per-component memory envelope on a 2 GB host.
This module turns that envelope into enforced constants and one report type.

The load-bearing rule is :attr:`Stage3ResourceReport.within_budget`. It is
``bool | None`` and ``None`` means **UNMEASURED**, never "within target" — the
same rule Stage 0 already enforces on
:attr:`pocketsec.stage0.benchmark.profiles.ProfileReport.within_target`. A
report constructed with a ``None`` observation and ``within_budget=True`` raises,
so the honest answer cannot be edited away by a later contributor who wants a
green gate: the constructor refuses to represent the lie.

Every resident figure here comes from
:class:`pocketsec.stage0.benchmark.resource_metrics.ResourceSampler` or from a
component's own ``memory_bytes()``/``size_bytes()``. A resource figure from
anywhere else — ``sys.getsizeof``, a parameter count, an estimate — is
UNMEASURED and this module will not record it.

``loadavg`` rides on every report because this host is shared: a Stage 2 gate
run measured a 7x wall-clock inflation at load 23-67 versus load 8-12
(``planning/PROGRESS.md``). A resident-bytes figure is far less load-sensitive
than a timing, but recording the load is what lets a later reader decide that
for themselves rather than trust us.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Protocol

from pocketsec.stage0.benchmark.resource_metrics import ResourceMetrics, ResourceSampler
from pocketsec.stage0.contracts.common import ContractError

__all__ = [
    "STAGE3_BUDGET",
    "STAGE3_COMPONENTS",
    "STAGE3_NORMAL_INCREMENTAL_RSS_BYTES",
    "STAGE3_PEAK_INCREMENTAL_RSS_BYTES",
    "Stage3ResourceReport",
    "component_bytes",
    "loadavg",
    "measure_stage3_resources",
    "unmeasured_stage3_resources",
]

_MB = 1024 * 1024

#: Architecture §38, component by component. Closed: a component that is not
#: named here has no budget, and ``component_bytes`` refuses to record it rather
#: than silently letting an unbudgeted structure grow.
STAGE3_BUDGET: Mapping[str, int] = MappingProxyType(
    {
        "boundary_index": 8 * _MB,
        "knowledge_cells": 20 * _MB,
        "cell_vm": 8 * _MB,
        "audit_state": 5 * _MB,
        "counterexample_hot": 15 * _MB,
    }
)

STAGE3_COMPONENTS: tuple[str, ...] = tuple(STAGE3_BUDGET)

#: Incremental RSS Stage 3 may add to the agent in steady state (§38).
STAGE3_NORMAL_INCREMENTAL_RSS_BYTES = 25 * _MB
#: Incremental RSS Stage 3 may reach while crystallising (§38). Peak, not normal:
#: synthesis holds candidate programs and their measurement frames at once.
STAGE3_PEAK_INCREMENTAL_RSS_BYTES = 60 * _MB


class _Sized(Protocol):
    """Anything that can report its own resident bytes.

    Structural on purpose: the field, the index and the counterexample store are
    written by three different packages and none of them should have to import
    this module to be measurable by it.
    """

    def memory_bytes(self) -> int: ...


def loadavg() -> tuple[float, float, float]:
    """This host's 1/5/15-minute load, or ``(-1.0, -1.0, -1.0)`` where unavailable.

    The sentinel is negative rather than zero because zero is a plausible load
    and this value is not one: a reader must be able to tell "quiet host" from
    "no load figure", and a plausible-looking stand-in is the exact failure mode
    the UNMEASURED rule exists to prevent.
    """
    try:
        one, five, fifteen = os.getloadavg()
    except (OSError, AttributeError):  # pragma: no cover - Linux always has it
        return (-1.0, -1.0, -1.0)
    return (float(one), float(five), float(fifteen))


@dataclass(frozen=True, slots=True)
class Stage3ResourceReport:
    """What one measured Stage 3 run actually resided in, against §38's budget."""

    peak_sampled_rss_bytes: int | None
    incremental_rss_bytes: int | None
    per_component_bytes: Mapping[str, int]
    within_budget: bool | None
    loadavg: tuple[float, float, float]
    measured_by: str
    unmeasured: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "per_component_bytes", _checked_components(self.per_component_bytes)
        )
        object.__setattr__(self, "unmeasured", tuple(self.unmeasured))
        if not isinstance(self.measured_by, str) or ":" not in self.measured_by:
            raise ContractError(
                f"Stage3ResourceReport.measured_by must look like 'module:function', "
                f"got {self.measured_by!r}; a figure with no producer is not a measurement"
            )
        self._require_honest_verdict()

    def _require_honest_verdict(self) -> None:
        """The whole point of the type: UNMEASURED may not be recorded as a pass.

        This is the invariant a future contributor will be tempted to weaken, so
        it is enforced in the constructor rather than at the call site. If any
        observation is missing, ``within_budget`` must be ``None``.
        """
        if self.within_budget is not None and not isinstance(self.within_budget, bool):
            raise ContractError("Stage3ResourceReport.within_budget must be a bool or None")
        # ``incremental_rss_bytes`` is in this list because it was not, and a
        # report carrying ``incremental_rss_bytes=None`` with an empty
        # ``unmeasured`` and ``within_budget=True`` was accepted — an unmeasured
        # observation recorded as a pass, which is the one thing this type exists
        # to refuse.
        absent = [
            name
            for name, value in (
                ("peak_sampled_rss_bytes", self.peak_sampled_rss_bytes),
                ("incremental_rss_bytes", self.incremental_rss_bytes),
            )
            if value is None
        ]
        missing = list(self.unmeasured) + absent
        if missing and self.within_budget is not None:
            raise ContractError(
                "Stage3ResourceReport claims within_budget="
                f"{self.within_budget!r} while {missing} were "
                "not measured; unmeasured is not within target"
            )

    @property
    def over_budget(self) -> tuple[str, ...]:
        """Components whose measured bytes exceed §38's budget for them."""
        return tuple(
            name
            for name, measured in sorted(self.per_component_bytes.items())
            if measured > STAGE3_BUDGET[name]
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "peak_sampled_rss_bytes": self.peak_sampled_rss_bytes,
            "incremental_rss_bytes": self.incremental_rss_bytes,
            "normal_incremental_budget_bytes": STAGE3_NORMAL_INCREMENTAL_RSS_BYTES,
            "peak_incremental_budget_bytes": STAGE3_PEAK_INCREMENTAL_RSS_BYTES,
            "per_component_bytes": dict(sorted(self.per_component_bytes.items())),
            "budget": dict(sorted(STAGE3_BUDGET.items())),
            "over_budget": list(self.over_budget),
            "within_budget": self.within_budget,
            "loadavg": list(self.loadavg),
            "measured_by": self.measured_by,
            "unmeasured": list(self.unmeasured),
        }


def _checked_components(value: object) -> Mapping[str, int]:
    """Refuse a component name §38 does not budget, and a byte count that is not one."""
    if not isinstance(value, Mapping):
        raise ContractError("Stage3ResourceReport.per_component_bytes must be a mapping")
    snapshot: dict[str, int] = {}
    for name, measured in value.items():
        if name not in STAGE3_BUDGET:
            raise ContractError(
                f"{name!r} has no §38 budget; known components: {sorted(STAGE3_BUDGET)}"
            )
        if not isinstance(measured, int) or isinstance(measured, bool) or measured < 0:
            raise ContractError(f"per_component_bytes[{name!r}] must be a byte count")
        snapshot[name] = measured
    return MappingProxyType(snapshot)


def unmeasured_stage3_resources(*, measured_by: str, reason: str) -> Stage3ResourceReport:
    """The honest report for a run that measured nothing.

    Exists so a caller that could not sample has something correct to return
    instead of inventing zeroes. ``within_budget`` is ``None``.
    """
    if not reason.strip():
        raise ContractError("an unmeasured report must say why it is unmeasured")
    return Stage3ResourceReport(
        peak_sampled_rss_bytes=None,
        incremental_rss_bytes=None,
        per_component_bytes={},
        within_budget=None,
        loadavg=loadavg(),
        measured_by=measured_by,
        unmeasured=(reason,),
    )


def component_bytes(
    *,
    boundary_index: _Sized | None = None,
    knowledge_cells: _Sized | None = None,
    counterexample_hot: _Sized | None = None,
    cell_vm_bytes: int | None = None,
    audit_state_bytes: int | None = None,
) -> tuple[dict[str, int], tuple[str, ...]]:
    """Ask each component for its own resident bytes; report the rest as unmeasured.

    Nothing is estimated here. A component that is not supplied is named in the
    returned ``unmeasured`` tuple, which is what makes ``within_budget`` ``None``
    downstream rather than a pass over a partial measurement.
    """
    measured: dict[str, int] = {}
    missing: list[str] = []
    sized = {
        "boundary_index": boundary_index,
        "knowledge_cells": knowledge_cells,
        "counterexample_hot": counterexample_hot,
    }
    for name, component in sized.items():
        if component is None:
            missing.append(f"{name} not supplied")
            continue
        measured[name] = int(component.memory_bytes())
    for name, value in (("cell_vm", cell_vm_bytes), ("audit_state", audit_state_bytes)):
        if value is None:
            missing.append(f"{name} not supplied")
        else:
            measured[name] = int(value)
    return measured, tuple(missing)


def measure_stage3_resources(
    work: Callable[[], int],
    *,
    measured_by: str,
    boundary_index: _Sized | None = None,
    knowledge_cells: _Sized | None = None,
    counterexample_hot: _Sized | None = None,
    cell_vm_bytes: int | None = None,
    audit_state_bytes: int | None = None,
    interval_seconds: float = 0.01,
) -> Stage3ResourceReport:
    """Run ``work`` under Stage 0's sampler and report Stage 3's footprint.

    ``work`` returns the number of events it processed. The sampler is Stage 0's
    and only Stage 0's: a resident figure produced any other way is not a
    measurement this project accepts, so there is no parameter by which one could
    be supplied.

    ``within_budget`` is ``True`` only when *every* term was observed and every
    term is under its §38 budget. One missing term makes it ``None``.
    """
    sampler = ResourceSampler(interval_seconds=interval_seconds)
    with sampler:
        events = int(work())
    metrics: ResourceMetrics = sampler.result(events_processed=events, startup_seconds=None)

    measured, missing = component_bytes(
        boundary_index=boundary_index,
        knowledge_cells=knowledge_cells,
        counterexample_hot=counterexample_hot,
        cell_vm_bytes=cell_vm_bytes,
        audit_state_bytes=audit_state_bytes,
    )
    unmeasured = list(missing)
    unmeasured.extend(f"stage0 sampler: {name}" for name in metrics.unavailable)
    peak = metrics.peak_sampled_rss_bytes
    incremental = metrics.delta_rss_bytes
    if peak is None:
        unmeasured.append("peak_sampled_rss_bytes")
    if incremental is None:
        unmeasured.append("incremental_rss_bytes")

    # ``within_budget`` is True only when EVERY term was observed. The ``None``
    # checks are repeated rather than asserted away because an assert can be
    # stripped with -O, and this verdict is the one thing in the module that must
    # not be able to become True by accident.
    within: bool | None
    if unmeasured or peak is None or incremental is None:
        within = None
    else:
        within = not any(
            measured[name] > STAGE3_BUDGET[name] for name in measured
        ) and incremental <= STAGE3_NORMAL_INCREMENTAL_RSS_BYTES
    return Stage3ResourceReport(
        peak_sampled_rss_bytes=peak,
        incremental_rss_bytes=incremental,
        per_component_bytes=measured,
        within_budget=within,
        loadavg=loadavg(),
        measured_by=measured_by,
        unmeasured=tuple(unmeasured),
    )
