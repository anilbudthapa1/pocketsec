"""D4.16 — the Stage 4 resource budget, and the rule that unmeasured is not within target.

Architecture §44 gives Stage 4 an envelope on a 2 GB host: normal incremental RSS
under 25–45 MB, peak without the optional language model under 90 MB. The strongest
target in that section is not "below 2 GB" — it is keeping Stage 4 small enough that
**Stages 1–3 stay comfortable on the same machine**. This module turns that envelope
into enforced constants and one report type.

The load-bearing rule is :attr:`Stage4ResourceReport.within_target`. It is
``bool | None`` and ``None`` means **UNMEASURED**, never "within target" — the same
rule Stage 0 enforces on ``ProfileReport.within_target`` and Stage 3 on
``Stage3ResourceReport.within_budget``. A report constructed with a missing
observation and ``within_target=True`` raises, so the honest answer cannot be edited
away by a later contributor who wants a green gate: the constructor refuses to
represent the lie.

Every resident figure comes from
:class:`~pocketsec.stage0.benchmark.resource_metrics.ResourceSampler` or from a
component's own ``memory_bytes()``. A figure from anywhere else — ``sys.getsizeof``,
a parameter count, an estimate — is UNMEASURED and this module will not record it.
There is no parameter by which one could be supplied.

``loadavg`` rides on every report because this host is shared: a Stage 2 gate run
measured a 7x wall-clock inflation at load 23-67 versus load 8-12
(``planning/PROGRESS.md``). Resident bytes are far less load-sensitive than timing,
but recording the load is what lets a later reader decide that instead of trusting us.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Protocol

from pocketsec.stage0.benchmark.profiles import PROFILES, ProfileReport, check_profile
from pocketsec.stage0.benchmark.resource_metrics import ResourceMetrics, ResourceSampler
from pocketsec.stage0.contracts.common import ContractError

__all__ = [
    "STAGE4_BUDGET",
    "STAGE4_COMPONENTS",
    "STAGE4_NORMAL_INCREMENTAL_RSS_BYTES",
    "STAGE4_PEAK_CEILING_BYTES",
    "STAGE4_PROFILE",
    "Stage4ResourceReport",
    "component_bytes",
    "loadavg",
    "measure_stage4_profile",
    "measure_stage4_resources",
    "unmeasured_stage4_resources",
]

_MB = 1024 * 1024

#: Architecture §44, component by component. Closed: a component not named here has
#: no budget, and :func:`component_bytes` refuses to record it rather than letting an
#: unbudgeted structure grow unobserved. The five are the five §44 names, mapped onto
#: the objects that actually report their own bytes.
STAGE4_BUDGET: Mapping[str, int] = MappingProxyType(
    {
        "belief_field": 8 * _MB,  # §44 "KB-scale/world" x MAX_WORLDS, with headroom
        "world_graph": 8 * _MB,  # §44 "hard bounded per incident"
        "claim_graph": 4 * _MB,
        "tombstones": 2 * _MB,
        "calibration": 2 * _MB,  # §32's ring buffer, MAX_CALIBRATION_HISTORY per epoch
        "degradation": 1 * _MB,
    }
)

STAGE4_COMPONENTS: tuple[str, ...] = tuple(STAGE4_BUDGET)

#: §44 "LUCID normal incremental RSS: target < 25-45 MB". The **high** end of the
#: architecture's own range, because the low end would fail a target the document
#: itself declares acceptable and a gate that fails on a satisfied requirement
#: teaches nothing.
STAGE4_NORMAL_INCREMENTAL_RSS_BYTES: int = 45 * _MB

#: §44 "Peak without optional LM: initial ceiling < 90 MB". Peak, not normal: the
#: counterfactual workspace is allocated on demand and freed, so it exists at peak
#: and not in steady state.
STAGE4_PEAK_CEILING_BYTES: int = 90 * _MB

#: Stage 0's profile Stage 4 is judged against. ``edge`` is "the primary PocketSec
#: target" (``profiles.py:36``) at a 100 MB agent RSS target, which is the figure §44's
#: 90 MB ceiling has to fit *inside* alongside Stages 1-3 — the §44 sentence that
#: matters is not "below 2 GB", it is that the stages stay comfortable together.
STAGE4_PROFILE: str = "edge"


class _Sized(Protocol):
    """Anything that reports its own resident bytes.

    Structural on purpose: the field, the world graph, the tombstone ledger, the
    calibration ring and the degradation ledger are written by five different work
    packages, and none of them should have to import this module to be measurable by
    it.
    """

    def memory_bytes(self) -> int: ...


def loadavg() -> tuple[float, float, float]:
    """This host's 1/5/15-minute load, or ``(-1.0, -1.0, -1.0)`` where unavailable.

    Negative rather than zero because zero is a plausible load and this value is not
    one: a reader must be able to tell "quiet host" from "no load figure", and a
    plausible-looking stand-in is the exact failure the UNMEASURED rule prevents.
    """
    try:
        one, five, fifteen = os.getloadavg()
    except (OSError, AttributeError):  # pragma: no cover - Linux always has it
        return (-1.0, -1.0, -1.0)
    return (float(one), float(five), float(fifteen))


@dataclass(frozen=True, slots=True)
class Stage4ResourceReport:
    """What one measured Stage 4 run actually resided in, against §44's envelope."""

    peak_sampled_rss_bytes: int | None
    incremental_rss_bytes: int | None
    per_component_bytes: Mapping[str, int]
    within_target: bool | None
    loadavg: tuple[float, float, float]
    measured_by: str
    unmeasured: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "per_component_bytes", _checked_components(self.per_component_bytes)
        )
        object.__setattr__(self, "unmeasured", tuple(self.unmeasured))
        object.__setattr__(self, "loadavg", tuple(float(x) for x in self.loadavg))
        if not isinstance(self.measured_by, str) or ":" not in self.measured_by:
            raise ContractError(
                "Stage4ResourceReport.measured_by must look like 'module:function', got "
                f"{self.measured_by!r}; a figure with no producer is not a measurement"
            )
        self._require_honest_verdict()

    def _require_honest_verdict(self) -> None:
        """The point of the type: UNMEASURED may not be recorded as a pass.

        Enforced in the constructor rather than at the call site, because this is the
        invariant a future contributor under deadline will be tempted to weaken. If
        any observation is missing, ``within_target`` must be ``None``.
        """
        if self.within_target is not None and not isinstance(self.within_target, bool):
            raise ContractError("Stage4ResourceReport.within_target must be a bool or None")
        absent = [
            name
            for name, value in (
                ("peak_sampled_rss_bytes", self.peak_sampled_rss_bytes),
                ("incremental_rss_bytes", self.incremental_rss_bytes),
            )
            if value is None
        ]
        missing = [*self.unmeasured, *absent]
        if missing and self.within_target is not None:
            raise ContractError(
                f"Stage4ResourceReport claims within_target={self.within_target!r} while "
                f"{missing} were not measured; unmeasured is not within target"
            )

    @property
    def over_budget(self) -> tuple[str, ...]:
        """Components whose measured bytes exceed §44's budget for them."""
        return tuple(
            name
            for name, measured in sorted(self.per_component_bytes.items())
            if measured > STAGE4_BUDGET[name]
        )

    @property
    def over_peak_ceiling(self) -> bool | None:
        """``None`` when peak RSS was not observed — never ``False`` (falsifier F10)."""
        if self.peak_sampled_rss_bytes is None:
            return None
        return self.peak_sampled_rss_bytes > STAGE4_PEAK_CEILING_BYTES

    def to_dict(self) -> dict[str, Any]:
        return {
            "peak_sampled_rss_bytes": self.peak_sampled_rss_bytes,
            "incremental_rss_bytes": self.incremental_rss_bytes,
            "normal_incremental_budget_bytes": STAGE4_NORMAL_INCREMENTAL_RSS_BYTES,
            "peak_ceiling_bytes": STAGE4_PEAK_CEILING_BYTES,
            "per_component_bytes": dict(sorted(self.per_component_bytes.items())),
            "budget": dict(sorted(STAGE4_BUDGET.items())),
            "over_budget": list(self.over_budget),
            "over_peak_ceiling": self.over_peak_ceiling,
            "within_target": self.within_target,
            "loadavg": list(self.loadavg),
            "measured_by": self.measured_by,
            "unmeasured": list(self.unmeasured),
        }


def _checked_components(value: object) -> Mapping[str, int]:
    """Refuse a component §44 does not budget, and a byte count that is not one."""
    if not isinstance(value, Mapping):
        raise ContractError("Stage4ResourceReport.per_component_bytes must be a mapping")
    snapshot: dict[str, int] = {}
    for name, measured in value.items():
        if name not in STAGE4_BUDGET:
            raise ContractError(
                f"{name!r} has no §44 budget; known components: {sorted(STAGE4_BUDGET)}"
            )
        if not isinstance(measured, int) or isinstance(measured, bool) or measured < 0:
            raise ContractError(f"per_component_bytes[{name!r}] must be a byte count")
        snapshot[name] = measured
    return MappingProxyType(snapshot)


def unmeasured_stage4_resources(*, measured_by: str, reason: str) -> Stage4ResourceReport:
    """The honest report for a run that measured nothing.

    Exists so a caller that could not sample has something correct to return instead
    of inventing zeroes. ``within_target`` is ``None``.
    """
    if not reason.strip():
        raise ContractError("an unmeasured report must say why it is unmeasured")
    return Stage4ResourceReport(
        peak_sampled_rss_bytes=None,
        incremental_rss_bytes=None,
        per_component_bytes={},
        within_target=None,
        loadavg=loadavg(),
        measured_by=measured_by,
        unmeasured=(reason,),
    )


def component_bytes(
    *,
    belief_field: _Sized | None = None,
    world_graph: _Sized | None = None,
    claim_graph: _Sized | None = None,
    tombstones: _Sized | None = None,
    calibration: _Sized | None = None,
    degradation: _Sized | None = None,
    belief_field_bytes: int | None = None,
    claim_graph_bytes: int | None = None,
) -> tuple[dict[str, int], tuple[str, ...]]:
    """Ask each component for its own resident bytes; name the rest as unmeasured.

    ``belief_field`` and ``claim_graph`` also accept a plain byte count, because
    ``CausalBeliefField.state_bytes()`` and the claim graph's serialised size are the
    honest figures for those two and neither type carries ``memory_bytes()``. Nothing
    is estimated: a component that is not supplied appears in the returned
    ``unmeasured`` tuple, which is what makes ``within_target`` ``None`` downstream
    rather than a pass over a partial measurement.
    """
    measured: dict[str, int] = {}
    missing: list[str] = []
    sized: Mapping[str, _Sized | None] = {
        "belief_field": belief_field,
        "world_graph": world_graph,
        "claim_graph": claim_graph,
        "tombstones": tombstones,
        "calibration": calibration,
        "degradation": degradation,
    }
    direct: Mapping[str, int | None] = {
        "belief_field": belief_field_bytes,
        "claim_graph": claim_graph_bytes,
    }
    for name in STAGE4_COMPONENTS:
        component = sized.get(name)
        if component is not None:
            measured[name] = int(component.memory_bytes())
            continue
        value = direct.get(name)
        if value is not None:
            measured[name] = int(value)
            continue
        missing.append(f"{name} not supplied")
    return measured, tuple(missing)


def measure_stage4_resources(
    work: Callable[[], int],
    *,
    measured_by: str,
    belief_field: _Sized | None = None,
    world_graph: _Sized | None = None,
    claim_graph: _Sized | None = None,
    tombstones: _Sized | None = None,
    calibration: _Sized | None = None,
    degradation: _Sized | None = None,
    belief_field_bytes: int | None = None,
    claim_graph_bytes: int | None = None,
    interval_seconds: float = 0.01,
) -> Stage4ResourceReport:
    """Run ``work`` under Stage 0's sampler and report Stage 4's footprint.

    ``work`` returns the number of events it processed. The sampler is Stage 0's and
    only Stage 0's: a resident figure produced any other way is not a measurement
    this project accepts, so no parameter exists by which one could be supplied.

    ``within_target`` is ``True`` only when *every* term was observed, every component
    is under its §44 budget, incremental RSS is under
    :data:`STAGE4_NORMAL_INCREMENTAL_RSS_BYTES` and peak RSS is under
    :data:`STAGE4_PEAK_CEILING_BYTES`. One missing term makes it ``None``.
    """
    sampler = ResourceSampler(interval_seconds=interval_seconds)
    with sampler:
        events = int(work())
    metrics: ResourceMetrics = sampler.result(events_processed=events, startup_seconds=None)

    measured, missing = component_bytes(
        belief_field=belief_field,
        world_graph=world_graph,
        claim_graph=claim_graph,
        tombstones=tombstones,
        calibration=calibration,
        degradation=degradation,
        belief_field_bytes=belief_field_bytes,
        claim_graph_bytes=claim_graph_bytes,
    )
    unmeasured = list(missing)
    unmeasured.extend(f"stage0 sampler: {name}" for name in metrics.unavailable)
    peak = metrics.peak_sampled_rss_bytes
    incremental = metrics.delta_rss_bytes
    if peak is None:
        unmeasured.append("peak_sampled_rss_bytes")
    if incremental is None:
        unmeasured.append("incremental_rss_bytes")

    # The ``None`` checks are repeated rather than asserted away, because an assert
    # can be stripped with -O and this verdict is the one thing in the module that
    # must not be able to become True by accident.
    within: bool | None
    if unmeasured or peak is None or incremental is None:
        within = None
    else:
        within = (
            not any(measured[name] > STAGE4_BUDGET[name] for name in measured)
            and incremental <= STAGE4_NORMAL_INCREMENTAL_RSS_BYTES
            and peak <= STAGE4_PEAK_CEILING_BYTES
        )
    return Stage4ResourceReport(
        peak_sampled_rss_bytes=peak,
        incremental_rss_bytes=incremental,
        per_component_bytes=measured,
        within_target=within,
        loadavg=loadavg(),
        measured_by=measured_by,
        unmeasured=tuple(unmeasured),
    )


def measure_stage4_profile(
    work: Callable[[], int],
    *,
    profile_name: str = STAGE4_PROFILE,
    interval_seconds: float = 0.01,
) -> ProfileReport:
    """Run ``work`` under Stage 0's sampler and return **Stage 0's own** profile report.

    Kept beside :func:`measure_stage4_resources` rather than folded into it because the
    two answer different questions: §44's per-component envelope is Stage 4's, while
    :func:`~pocketsec.stage0.benchmark.profiles.check_profile` answers whether the
    *agent* fits its deployment profile — which is the figure that decides whether
    Stages 1-3 still fit on the same 2 GB host.

    ``ProfileReport.within_target`` is ``bool | None`` and Stage 0 already refuses to
    return ``True`` when nothing was observed. This function adds no interpretation on
    top of that: it does not default the profile, does not smooth a missing sample, and
    does not convert ``None`` to a pass.
    """
    if profile_name not in PROFILES:
        raise ContractError(
            f"unknown resource profile {profile_name!r}; known: {sorted(PROFILES)}"
        )
    sampler = ResourceSampler(interval_seconds=interval_seconds)
    with sampler:
        events = int(work())
    metrics = sampler.result(events_processed=events, startup_seconds=None)
    # ``model_bytes=None`` is the honest value: Stage 4 ships no model. The ``edge``
    # profile carries a model-size target, so passing 0 would claim a measurement of a
    # thing that does not exist and Stage 0 would record it as met.
    return check_profile(metrics, profile_name, model_bytes=None)
