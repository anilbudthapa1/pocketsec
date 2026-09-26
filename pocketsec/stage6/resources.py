"""§39/§40 — Stage 6's resource envelope, its work meter, and "unmeasured is not within".

Long-horizon learning is the one Stage 6 activity that grows with time, so its budget has
to be a number the code can check, not a sentence. This module holds four things:

**The work meter** (:class:`WorkMeter`). Cost is counted in deterministic work units, not
microseconds (ADR-0033 precedent): this host is shared, and a Stage 2 gate measured the
same two code paths 7x slower at load 23-67 than at load 8-12. Every learning, scoring and
consolidation path charges a meter; a meter with a budget refuses the charge that would
exceed it by raising :class:`WorkBudgetExceeded`, and the refused units are *not* added
to ``spent`` — the work they would have paid for was not done.

**The consolidation conditions** (:class:`ResourceSnapshot`). Architecture §40: run
consolidation only if memory pressure, CPU load and incident urgency are low, disk is
available and the thermal policy allows. :meth:`ResourceSnapshot.capture` reads each
condition from the host. A condition it cannot read is recorded in ``unmeasured`` and
given its **fail-closed** value (full pressure, full load, no disk, thermal not OK), so
an unreadable host defers consolidation instead of pretending to be idle. Deferral never
blocks detection (§40); it only postpones learning.

**The budgets** (:data:`STORE_BUDGETS` and the constants). Architecture §39's five store
rows, normal and peak, the 55 MiB normal incremental RSS preference, the 100 MiB initial
ceiling and the 500 MiB disk target. Every value is the upper end of the architecture's
range and a chosen parameter, not a measurement.

**The measurement** (:func:`measure_stage6_resources`). The only RSS source is Stage 0's
:class:`ResourceSampler`. ``within_ceiling`` is ``None`` whenever RSS could not be read:
**UNMEASURED is never True**, and :class:`Stage6ResourceReport` refuses to be constructed
with a verdict its own figures do not support. The incremental figure is the peak rise
over the measured block, which in a shared process (a test run, the gate) is an upper
bound that includes whatever else the interpreter allocated meanwhile.

``loadavg`` rides on every report because this host is shared; Stage 6 keeps its own copy
because it may import Stage 5 only through ``stage6_interface``.

Nothing here holds state except :class:`WorkMeter`, which holds one counter.
"""

from __future__ import annotations

import math
import os
import resource
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType

from pocketsec.stage0.benchmark.profiles import ProfileReport, check_profile
from pocketsec.stage0.benchmark.resource_metrics import ResourceMetrics, ResourceSampler
from pocketsec.stage0.contracts.common import ContractError

__all__ = [
    "CONSOLIDATION_MAX_CPU_LOAD",
    "CONSOLIDATION_MAX_MEMORY_PRESSURE",
    "CONSOLIDATION_MAX_URGENCY",
    "CONSOLIDATION_MIN_DISK_FREE_BYTES",
    "CONSOLIDATION_WORKSPACE_BUDGET_BYTES",
    "CONSOLIDATION_WORKSPACE_PEAK_BYTES",
    "EPISODIC_BUDGET_BYTES",
    "EPISODIC_PEAK_BYTES",
    "LINEAGE_FOSSIL_META_BUDGET_BYTES",
    "LINEAGE_FOSSIL_META_PEAK_BYTES",
    "LOADAVG_PATH",
    "LOADAVG_UNAVAILABLE",
    "MEMINFO_PATH",
    "QUARANTINE_META_BUDGET_BYTES",
    "QUARANTINE_META_PEAK_BYTES",
    "SEMANTIC_PROCEDURAL_BUDGET_BYTES",
    "SEMANTIC_PROCEDURAL_PEAK_BYTES",
    "STAGE6_DISK_BUDGET_BYTES",
    "STAGE6_INCREMENTAL_CEILING_BYTES",
    "STAGE6_NORMAL_INCREMENTAL_RSS_BYTES",
    "STAGE6_PROFILE",
    "STORE_BUDGETS",
    "THERMAL_ROOT",
    "ResourceSnapshot",
    "Stage6ResourceReport",
    "StoreBudget",
    "WorkBudgetExceeded",
    "WorkMeter",
    "loadavg",
    "measure_stage6_resources",
]

_MIB = 1024 * 1024

#: Architecture §39 "Stage 6 incremental RSS excluding shadow model: prefer 25-55 MB".
STAGE6_NORMAL_INCREMENTAL_RSS_BYTES: int = 57671680  # 55 MiB
#: Architecture §39 "< 100 MB initial ceiling".
STAGE6_INCREMENTAL_CEILING_BYTES: int = 104857600  # 100 MiB
#: Architecture §39 "a starting research target is 100-500 MB" of compressed history.
STAGE6_DISK_BUDGET_BYTES: int = 500 * _MIB

#: The five §39 store rows: the upper end of each normal range, and the peak.
QUARANTINE_META_BUDGET_BYTES: int = 15 * _MIB
QUARANTINE_META_PEAK_BYTES: int = 25 * _MIB
EPISODIC_BUDGET_BYTES: int = 15 * _MIB
EPISODIC_PEAK_BYTES: int = 25 * _MIB
SEMANTIC_PROCEDURAL_BUDGET_BYTES: int = 20 * _MIB
SEMANTIC_PROCEDURAL_PEAK_BYTES: int = 30 * _MIB
LINEAGE_FOSSIL_META_BUDGET_BYTES: int = 10 * _MIB
LINEAGE_FOSSIL_META_PEAK_BYTES: int = 15 * _MIB
CONSOLIDATION_WORKSPACE_BUDGET_BYTES: int = 15 * _MIB
CONSOLIDATION_WORKSPACE_PEAK_BYTES: int = 35 * _MIB

#: Architecture §40 thresholds. Chosen, not measured.
CONSOLIDATION_MAX_MEMORY_PRESSURE: float = 0.8
CONSOLIDATION_MAX_CPU_LOAD: float = 0.8
CONSOLIDATION_MAX_URGENCY: float = 0.5
CONSOLIDATION_MIN_DISK_FREE_BYTES: int = 64 * _MIB

#: Stage 0's profile Stage 6 is judged against; ``edge`` is the primary 2 GB target.
STAGE6_PROFILE: str = "edge"

LOADAVG_PATH: Path = Path("/proc/loadavg")
MEMINFO_PATH: Path = Path("/proc/meminfo")
THERMAL_ROOT: Path = Path("/sys/class/thermal")

#: Negative, not zero: a quiet host and "no figure at all" must be distinguishable.
LOADAVG_UNAVAILABLE: tuple[float, float, float] = (-1.0, -1.0, -1.0)

#: Degrees below a zone's hot/critical trip point at which the thermal policy stops
#: allowing optional work, in the kernel's millidegrees Celsius. Chosen, not measured.
_THERMAL_MARGIN_MILLIDEGREES: int = 5000

_SNAPSHOT_CONDITIONS: frozenset[str] = frozenset(
    {"memory_pressure", "cpu_load", "disk_free_bytes", "thermal_ok"}
)


class WorkBudgetExceeded(RuntimeError):
    """A charge would take a :class:`WorkMeter` past its budget; the work was not paid for."""


class WorkMeter:
    """A deterministic cost counter, the primary cost measure of Stage 6.

    ``budget=None`` means unbounded — for measurement passes that must report what the
    work cost rather than cap it. A bounded meter raises *before* admitting the charge
    that crosses the budget, so a caller that charges before working never does the
    unpaid work, and ``spent`` never reports more than the budget.
    """

    __slots__ = ("_budget", "_spent")

    def __init__(self, *, budget: int | None = None) -> None:
        if budget is not None and (isinstance(budget, bool) or not isinstance(budget, int)):
            raise ContractError(f"WorkMeter budget must be an int or None, got {budget!r}")
        if budget is not None and budget < 0:
            raise ContractError(f"WorkMeter budget must be >= 0, got {budget}")
        self._budget = budget
        self._spent = 0

    def charge(self, units: int = 1) -> None:
        """Pay for ``units`` of work, or raise :class:`WorkBudgetExceeded` and pay nothing."""
        if isinstance(units, bool) or not isinstance(units, int) or units < 0:
            raise ContractError(f"WorkMeter.charge takes a non-negative int, got {units!r}")
        if self._budget is not None and self._spent + units > self._budget:
            raise WorkBudgetExceeded(
                f"charging {units} work units would reach {self._spent + units}, "
                f"past the budget of {self._budget}"
            )
        self._spent += units

    @property
    def spent(self) -> int:
        return self._spent

    @property
    def budget(self) -> int | None:
        return self._budget

    @property
    def remaining(self) -> int | None:
        """Units left, or ``None`` for an unbounded meter."""
        return None if self._budget is None else self._budget - self._spent


def loadavg() -> tuple[float, float, float]:
    """This host's 1/5/15-minute load from ``/proc/loadavg``, or :data:`LOADAVG_UNAVAILABLE`."""
    try:
        fields = LOADAVG_PATH.read_text(encoding="utf-8").split()
        one, five, fifteen = (float(fields[index]) for index in range(3))
    except (OSError, IndexError, ValueError):
        return LOADAVG_UNAVAILABLE
    return (one, five, fifteen)


def _meminfo_pressure() -> float | None:
    """``1 - MemAvailable / MemTotal``, or ``None`` when either line is unreadable."""
    values: dict[str, int] = {}
    try:
        for line in MEMINFO_PATH.read_text(encoding="ascii").splitlines():
            key, _, rest = line.partition(":")
            if key in ("MemTotal", "MemAvailable"):
                values[key] = int(rest.split()[0])
    except (OSError, ValueError, IndexError):
        return None
    total, available = values.get("MemTotal"), values.get("MemAvailable")
    if not total or available is None:
        return None
    return min(1.0, max(0.0, 1.0 - available / total))


def _normalised_load() -> float | None:
    one = loadavg()[0]
    cpus = os.cpu_count()
    if one < 0 or not cpus:
        return None
    return one / cpus


def _disk_free(path: Path) -> int | None:
    try:
        stats = os.statvfs(path)
    except OSError:
        return None
    return int(stats.f_bavail * stats.f_frsize)


def _read_millidegrees(path: Path) -> int | None:
    try:
        return int(path.read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        return None


def _zone_thermal_ok(zone: Path) -> bool | None:
    """Whether one zone sits below its lowest hot/critical trip minus the margin.

    Zones without a positive hot or critical trip point (sensor placeholders report
    -274000) say nothing and return ``None``.
    """
    temperature = _read_millidegrees(zone / "temp")
    trips: list[int] = []
    for kind_path in sorted(zone.glob("trip_point_*_type")):
        try:
            kind = kind_path.read_text(encoding="ascii").strip()
        except OSError:
            continue
        if kind not in ("hot", "critical"):
            continue
        trip = _read_millidegrees(kind_path.with_name(kind_path.name[: -len("type")] + "temp"))
        if trip is not None and trip > 0:
            trips.append(trip)
    if temperature is None or not trips:
        return None
    return temperature < min(trips) - _THERMAL_MARGIN_MILLIDEGREES


def _thermal_ok(root: Path) -> bool | None:
    """All informative zones OK; ``None`` when no zone is informative (UNMEASURED)."""
    verdicts = [
        verdict
        for zone in sorted(root.glob("thermal_zone*"))
        if (verdict := _zone_thermal_ok(zone)) is not None
    ]
    return all(verdicts) if verdicts else None


@dataclass(frozen=True, slots=True)
class ResourceSnapshot:
    """Architecture §40's consolidation conditions, each a field.

    ``unmeasured`` names the conditions that could not be read; each of them holds its
    fail-closed value, so a consumer that reads only the five fields still refuses to
    consolidate on a host it cannot see.
    """

    memory_pressure: float
    cpu_load: float
    incident_urgency: float
    disk_free_bytes: int
    thermal_ok: bool
    unmeasured: tuple[str, ...] = field(default=())

    def __post_init__(self) -> None:
        for label, value, upper in (
            ("memory_pressure", self.memory_pressure, 1.0),
            ("incident_urgency", self.incident_urgency, 1.0),
            ("cpu_load", self.cpu_load, math.inf),
        ):
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ContractError(f"ResourceSnapshot.{label} must be a number")
            if not math.isfinite(value) or not 0.0 <= value <= upper:
                raise ContractError(f"ResourceSnapshot.{label}={value} out of range")
        if isinstance(self.disk_free_bytes, bool) or not isinstance(self.disk_free_bytes, int):
            raise ContractError("ResourceSnapshot.disk_free_bytes must be an int")
        if self.disk_free_bytes < 0:
            raise ContractError("ResourceSnapshot.disk_free_bytes must be >= 0")
        if not isinstance(self.thermal_ok, bool):
            raise ContractError("ResourceSnapshot.thermal_ok must be a bool")
        object.__setattr__(self, "unmeasured", tuple(sorted(set(self.unmeasured))))
        unknown = set(self.unmeasured) - _SNAPSHOT_CONDITIONS
        if unknown:
            raise ContractError(f"ResourceSnapshot.unmeasured names unknown conditions {unknown}")
        if "thermal_ok" in self.unmeasured and self.thermal_ok:
            raise ContractError("an unmeasured thermal condition cannot be recorded as OK")

    @classmethod
    def capture(
        cls, *, incident_urgency: float = 0.0, disk_path: Path | None = None
    ) -> ResourceSnapshot:
        """Read the host now. Unreadable conditions take their fail-closed values."""
        unmeasured: list[str] = []
        pressure = _meminfo_pressure()
        if pressure is None:
            unmeasured.append("memory_pressure")
        load = _normalised_load()
        if load is None:
            unmeasured.append("cpu_load")
        disk = _disk_free(disk_path if disk_path is not None else Path.cwd())
        if disk is None:
            unmeasured.append("disk_free_bytes")
        thermal = _thermal_ok(THERMAL_ROOT)
        if thermal is None:
            unmeasured.append("thermal_ok")
        return cls(
            memory_pressure=1.0 if pressure is None else pressure,
            cpu_load=1.0 if load is None else load,
            incident_urgency=incident_urgency,
            disk_free_bytes=0 if disk is None else disk,
            thermal_ok=bool(thermal),
            unmeasured=tuple(unmeasured),
        )


@dataclass(frozen=True, slots=True)
class StoreBudget:
    """One §39 row: a store's normal target and its peak."""

    name: str
    normal_bytes: int
    peak_bytes: int

    def __post_init__(self) -> None:
        if not 0 < self.normal_bytes <= self.peak_bytes:
            raise ContractError(f"StoreBudget {self.name}: need 0 < normal <= peak")


STORE_BUDGETS: tuple[StoreBudget, ...] = (
    StoreBudget("quarantine_metadata", QUARANTINE_META_BUDGET_BYTES, QUARANTINE_META_PEAK_BYTES),
    StoreBudget("episodic_hot_index", EPISODIC_BUDGET_BYTES, EPISODIC_PEAK_BYTES),
    StoreBudget(
        "semantic_procedural_memory",
        SEMANTIC_PROCEDURAL_BUDGET_BYTES,
        SEMANTIC_PROCEDURAL_PEAK_BYTES,
    ),
    StoreBudget(
        "lineage_fossil_metadata", LINEAGE_FOSSIL_META_BUDGET_BYTES, LINEAGE_FOSSIL_META_PEAK_BYTES
    ),
    StoreBudget(
        "consolidation_workspace",
        CONSOLIDATION_WORKSPACE_BUDGET_BYTES,
        CONSOLIDATION_WORKSPACE_PEAK_BYTES,
    ),
)

_BUDGET_BY_NAME: Mapping[str, StoreBudget] = MappingProxyType(
    {budget.name: budget for budget in STORE_BUDGETS}
)


def _checked_store_bytes(store_bytes: Mapping[str, int]) -> Mapping[str, int]:
    checked: dict[str, int] = {}
    for name, value in store_bytes.items():
        if not isinstance(name, str) or not name:
            raise ContractError(f"store names must be non-empty strings, got {name!r}")
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ContractError(f"store {name!r} reported {value!r}; memory_bytes is an int >= 0")
        checked[name] = value
    return MappingProxyType(dict(sorted(checked.items())))


@dataclass(frozen=True, slots=True)
class Stage6ResourceReport:
    """What one measured Stage 6 block resided in, against §39's envelope."""

    metrics: ResourceMetrics
    profile: ProfileReport
    incremental_rss_bytes: int | None
    within_ceiling: bool | None
    store_bytes: Mapping[str, int]
    loadavg: tuple[float, float, float]

    def __post_init__(self) -> None:
        object.__setattr__(self, "store_bytes", _checked_store_bytes(self.store_bytes))
        object.__setattr__(self, "loadavg", tuple(float(value) for value in self.loadavg))
        self._require_honest_verdict()

    def _require_honest_verdict(self) -> None:
        """The point of the type: the verdict must be the one the figure supports.

        Enforced in the constructor, because this is the invariant a contributor under
        deadline pressure will be tempted to weaken: no incremental figure means
        ``within_ceiling is None``, and a figure means exactly its comparison.
        """
        if self.incremental_rss_bytes is None:
            if self.within_ceiling is not None:
                raise ContractError("within_ceiling must be None when RSS is UNMEASURED")
            return
        expected = self.incremental_rss_bytes <= STAGE6_INCREMENTAL_CEILING_BYTES
        if self.within_ceiling is not expected:
            raise ContractError(
                f"within_ceiling={self.within_ceiling} contradicts incremental RSS "
                f"{self.incremental_rss_bytes} B against the {STAGE6_INCREMENTAL_CEILING_BYTES} B "
                "ceiling"
            )

    def over_budget(self, *, peak: bool = False) -> tuple[str, ...]:
        """Budgeted stores whose reported bytes exceed their normal (or peak) target."""
        return tuple(
            name
            for name, used in self.store_bytes.items()
            if name in _BUDGET_BY_NAME
            and used
            > (_BUDGET_BY_NAME[name].peak_bytes if peak else _BUDGET_BY_NAME[name].normal_bytes)
        )

    def unbudgeted(self) -> tuple[str, ...]:
        """Reported stores that no §39 row covers — reported, never silently passed."""
        return tuple(name for name in self.store_bytes if name not in _BUDGET_BY_NAME)


def _lifetime_peak_bytes() -> int | None:
    """The process's resident high-water mark from ``getrusage`` (Linux reports KiB)."""
    try:
        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    except (OSError, ValueError):
        return None
    return int(peak) if sys.platform == "darwin" else int(peak) * 1024


def _incremental_rss(metrics: ResourceMetrics, lifetime_peak_before: int | None) -> int | None:
    """Peak rise over the block, floored at zero; ``None`` when the start RSS is unknown.

    Three observations of the block's peak, and the largest wins: the sampler's peak
    (it samples every 10 ms, so it can miss a short block entirely), the end RSS (it
    understates a block that allocates and frees), and the lifetime high-water mark
    *if the block raised it* — the process then provably reached that size inside the
    block. The figure is still a lower bound on the true block peak when the block
    stayed under an earlier high-water mark and between samples; it is never inflated.
    """
    start = metrics.idle_rss_bytes
    if start is None:
        return None
    raised_peak = (
        metrics.peak_rss_bytes
        if metrics.peak_rss_bytes is not None
        and lifetime_peak_before is not None
        and metrics.peak_rss_bytes > lifetime_peak_before
        else None
    )
    candidates = [
        value
        for value in (
            metrics.peak_sampled_rss_bytes,
            None if metrics.delta_rss_bytes is None else start + metrics.delta_rss_bytes,
            raised_peak,
        )
        if value is not None
    ]
    if not candidates:
        return None
    return max(0, max(candidates) - start)


def measure_stage6_resources(
    work: Callable[[], Mapping[str, int]],
    *,
    events: int,
    model_bytes: Callable[[], int] | None = None,
) -> Stage6ResourceReport:
    """Run ``work()`` under Stage 0's sampler and report it against §39.

    ``work`` performs the Stage 6 loop being measured and returns each store's
    ``memory_bytes()``. ``events`` is how many offered capsules it processed, for the
    per-event CPU figure. ``within_ceiling`` is ``None`` when RSS is unavailable.

    ``model_bytes`` (read after ``work``) is the size of the learned artifact the endpoint
    scores with — for Stage 6 the trusted state's canonical bytes. Omitted, the profile's
    model row stays UNMEASURED and ``within_target`` is ``None``, never ``True``.
    """
    if isinstance(events, bool) or not isinstance(events, int) or events < 0:
        raise ContractError(f"events must be a non-negative int, got {events!r}")
    lifetime_peak_before = _lifetime_peak_bytes()
    sampler = ResourceSampler()
    with sampler:
        store_bytes = work()
    metrics = sampler.result(events_processed=events, startup_seconds=None)
    incremental = _incremental_rss(metrics, lifetime_peak_before)
    return Stage6ResourceReport(
        metrics=metrics,
        profile=check_profile(
            metrics, STAGE6_PROFILE, model_bytes=None if model_bytes is None else model_bytes()
        ),
        incremental_rss_bytes=incremental,
        within_ceiling=(
            None if incremental is None else incremental <= STAGE6_INCREMENTAL_CEILING_BYTES
        ),
        store_bytes=store_bytes,
        loadavg=loadavg(),
    )
