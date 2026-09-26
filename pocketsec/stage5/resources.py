"""D5.18 — Stage 5's §43 resource envelope, and the rule that unmeasured is not within target.

Architecture §43 gives Stage 5 seven budget rows on a 2 GB host. The strongest target
in that section is not "below 2 GB" — it is keeping Stage 5 small enough that
**Stages 1–4 stay comfortable on the same machine**. This module turns that envelope
into named constants and one report type.

The load-bearing rule is :attr:`Stage5ResourceReport.within_target`. It is
``bool | None``, and ``None`` means **UNMEASURED**, never "within target" — the same
rule Stage 0 enforces on ``ProfileReport.within_target`` and Stage 4 on its own report.
A report constructed with a missing observation and ``within_target=True`` raises, so
the honest answer cannot be edited away later by a contributor who wants a green gate:
the constructor refuses to represent the lie.

**Every byte figure comes from Stage 0's** :class:`ResourceSampler`, or from a
component's own ``state_bytes()`` / ``bytes_used()``. A figure from anywhere else —
``sys.getsizeof`` over a graph, a parameter count, an estimate — is UNMEASURED and this
module will not record it. There is no parameter through which one could be supplied.

**One figure is process-wide and is not a Stage 5 figure**, and this is the trap that
caught this module's own first test. ``ResourceSampler.peak_sampled_rss_bytes`` is the
peak resident size of the whole interpreter, so inside a shared process — a full test
run, or the gate — it includes everything Stages 0-4 happen to be holding, and the
previous engineer on this package recorded it failing the 110 MB ceiling inside the full
suite while Stage 5's work was unchanged. ``peak_rss_bytes`` and
:attr:`over_peak_ceiling` are therefore reported as *upper bounds on a shared process*,
and the only figure attributable to Stage 5 is ``incremental_rss_bytes``, the delta
across the measured block.

**The incremental figure depends on what ran before it in the same process.** Measured
in one process, a full-loop pass over ``build_response_corpus(count=40, seed=7)`` read
249856 B incremental *after* a field-only pass had warmed the allocator; measured in a
fresh process the same pass read 819200 B (peak 29057024 B, load 5.84 / 4.20 / 2.62).
Only the fresh-process figure is a Stage 5 figure, so a gate that wants one should run
the measurement first or in its own process.

Consequently ``within_target`` may be ``True`` only in a process that holds Stage 5 alone,
and it is ``None`` anyway because two of §43's seven rows have no self-reported
footprint.

``loadavg`` rides on every report because this host is shared. A Stage 2 gate run
measured the *same* two code paths at 122.48/647.23 us/event at load 8–12 and
855.31/3040.63 at load 23–67 — a 7x inflation (``planning/MEMORY.md``). Resident bytes
are far less load-sensitive than timing, but recording the load is what lets a later
reader decide that for themselves instead of trusting us. It is read from
``/proc/loadavg`` and falls back to ``(-1.0, -1.0, -1.0)`` — negative rather than zero,
because zero is a plausible load and "no figure" must not look like one.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any

from pocketsec.stage0.benchmark.profiles import PROFILES, ProfileReport, check_profile
from pocketsec.stage0.benchmark.resource_metrics import ResourceMetrics, ResourceSampler
from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage5.cells.response_cells import ResponseCellField
from pocketsec.stage5.constitution.invariants import FROZEN_CONSTITUTION
from pocketsec.stage5.executor.journal import RollbackJournal
from pocketsec.stage5.governor import ResourceGovernor
from pocketsec.stage5.labs.baselines import (
    REFERENCE_ARM_ID,
    BaselineRig,
    ExecutorFactory,
    reference_arm,
    run_arm,
)
from pocketsec.stage5.labs.response_corpus import ResponseCase
from pocketsec.stage5.memory.effectiveness import EffectivenessMemory
from pocketsec.stage5.safe.action_field import ActionField, generate_action_field
from pocketsec.stage5.twin.response_twin import ResponseTwin

__all__ = [
    "incremental_rss",
    "AGGREGATE_COMPONENTS",
    "LOADAVG_PATH",
    "LOADAVG_UNAVAILABLE",
    "STAGE5_BUDGET_BYTES",
    "STAGE5_COMPONENTS",
    "STAGE5_NORMAL_INCREMENTAL_RSS_BYTES",
    "STAGE5_PEAK_CEILING_BYTES",
    "STAGE5_PROFILE",
    "Stage5ResourceReport",
    "component_bytes",
    "loadavg",
    "measure_stage5_profile",
    "measure_stage5_resources",
    "unmeasured_stage5_resources",
]

_MB = 1024 * 1024

#: §43's seven rows, in the document's order. The last two are **aggregate** rows
#: rather than components; they keep their own constants below and are carried here so a
#: reader can check the table against the architecture without a second list.
STAGE5_COMPONENTS: tuple[str, ...] = (
    "aegis_planning_state",
    "twin_dependency_state",
    "simulation_workspace",
    "sentinel_and_executor",
    "rollback_evidence_hot_state",
    "normal_incremental_rss",
    "peak_without_optional_lm",
)

#: The two §43 rows that are **aggregates of the whole process**, not components of
#: Stage 5. They are excluded from :attr:`Stage5ResourceReport.over_budget`, which is a
#: per-component verdict, and are judged instead by ``over_peak_ceiling`` and by the
#: incremental comparison — the only one of the two that is attributable to Stage 5. Left
#: in :data:`STAGE5_COMPONENTS` because §43 lists seven rows and dropping two would make
#: the table disagree with the document.
AGGREGATE_COMPONENTS: tuple[str, ...] = ("normal_incremental_rss", "peak_without_optional_lm")

#: The upper end of each §43 range. The upper end rather than the lower, because the
#: architecture declares the range acceptable and a gate that fails on a satisfied
#: requirement teaches nothing.
STAGE5_BUDGET_BYTES: Mapping[str, int] = MappingProxyType(
    {
        "aegis_planning_state": 15 * _MB,
        "twin_dependency_state": 20 * _MB,
        "simulation_workspace": 30 * _MB,
        "sentinel_and_executor": 10 * _MB,
        "rollback_evidence_hot_state": 15 * _MB,
        "normal_incremental_rss": 50 * _MB,
        "peak_without_optional_lm": 110 * _MB,
    }
)

#: §43 "normal Stage 5 incremental RSS: prefer < 35-50 MB". 50 MB exactly.
STAGE5_NORMAL_INCREMENTAL_RSS_BYTES: int = 52428800

#: §43 "peak Stage 5 without optional LM: initial ceiling < 110 MB". 110 MB exactly.
STAGE5_PEAK_CEILING_BYTES: int = 115343360

#: Stage 0's profile Stage 5 is judged against. ``edge`` is the primary PocketSec
#: target at a 100 MB agent RSS figure, which is what §43's 110 MB peak has to fit
#: inside *alongside* Stages 1-4.
STAGE5_PROFILE: str = "edge"

LOADAVG_PATH: Path = Path("/proc/loadavg")

#: Negative, not zero: a reader must be able to tell a quiet host from no figure at all.
LOADAVG_UNAVAILABLE: tuple[float, float, float] = (-1.0, -1.0, -1.0)


def loadavg() -> tuple[float, float, float]:
    """This host's 1/5/15-minute load from ``/proc/loadavg``, or the unavailable triple."""
    try:
        fields = LOADAVG_PATH.read_text(encoding="utf-8").split()
    except OSError:  # pragma: no cover - Linux always has it
        return LOADAVG_UNAVAILABLE
    try:
        one, five, fifteen = (float(fields[index]) for index in range(3))
    except (IndexError, ValueError):  # pragma: no cover - a malformed proc file
        return LOADAVG_UNAVAILABLE
    return (one, five, fifteen)


@dataclass(frozen=True, slots=True)
class Stage5ResourceReport:
    """What one measured Stage 5 run actually resided in, against §43's envelope."""

    #: The **whole process's** peak sampled RSS, not Stage 5's. See the module docstring:
    #: inside a shared process this is an upper bound that includes every other stage's
    #: resident state.
    peak_rss_bytes: int | None
    #: The delta across the measured block. This one *is* attributable to Stage 5.
    incremental_rss_bytes: int | None
    component_bytes: Mapping[str, int | None]
    within_target: bool | None
    profile: ProfileReport | None
    loadavg: tuple[float, float, float]
    detail: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "component_bytes", _checked_components(self.component_bytes))
        object.__setattr__(self, "loadavg", tuple(float(value) for value in self.loadavg))
        if self.within_target is not None and not isinstance(self.within_target, bool):
            raise ContractError("Stage5ResourceReport.within_target must be a bool or None")
        if not self.detail.strip():
            raise ContractError("Stage5ResourceReport.detail must say how it was produced")
        self._require_honest_verdict()

    def _require_honest_verdict(self) -> None:
        """The point of the type: UNMEASURED may not be recorded as a pass.

        Enforced in the constructor rather than at the call site, because this is the
        invariant a future contributor under deadline pressure will be tempted to
        weaken. If any observation is missing, ``within_target`` must be ``None``.
        """
        absent = [
            name
            for name, value in (
                ("peak_rss_bytes", self.peak_rss_bytes),
                ("incremental_rss_bytes", self.incremental_rss_bytes),
            )
            if value is None
        ]
        absent.extend(name for name, value in self.component_bytes.items() if value is None)
        if absent and self.within_target is not None:
            raise ContractError(
                f"Stage5ResourceReport claims within_target={self.within_target!r} while "
                f"{sorted(absent)} were not measured; unmeasured is not within target"
            )

    @property
    def over_budget(self) -> tuple[str, ...]:
        """Stage 5 **components** whose measured bytes exceed §43's budget for them.

        The two aggregate rows are excluded, and the exclusion is load-bearing rather than
        tidy: ``peak_without_optional_lm`` holds the whole interpreter's peak, so inside a
        shared process it reports Stage 5 as over budget on evidence about Stages 0-4 — the
        previous engineer on this package recorded it doing so inside the full suite. Those
        two rows are judged by
        :attr:`over_peak_ceiling` and by ``incremental_rss_bytes``, and only the second of
        those is a Stage 5 figure.
        """
        return tuple(
            name
            for name, measured in sorted(self.component_bytes.items())
            if name not in AGGREGATE_COMPONENTS
            and measured is not None
            and measured > STAGE5_BUDGET_BYTES[name]
        )

    @property
    def over_peak_ceiling(self) -> bool | None:
        """Whether the **process** peak exceeded §43's Stage 5 ceiling.

        ``None`` when peak RSS was not observed — never ``False`` (falsifier F10). A
        ``True`` here inside a shared process is not evidence that Stage 5 is over budget,
        because the figure is process-wide; it is evidence that the measurement needs its
        own process. Falsifier F10 must be judged on ``incremental_rss_bytes``.
        """
        if self.peak_rss_bytes is None:
            return None
        return self.peak_rss_bytes > STAGE5_PEAK_CEILING_BYTES

    def to_dict(self) -> dict[str, Any]:
        return {
            "peak_rss_bytes": self.peak_rss_bytes,
            "incremental_rss_bytes": self.incremental_rss_bytes,
            "normal_incremental_budget_bytes": STAGE5_NORMAL_INCREMENTAL_RSS_BYTES,
            "peak_ceiling_bytes": STAGE5_PEAK_CEILING_BYTES,
            "component_bytes": dict(sorted(self.component_bytes.items())),
            "budget_bytes": dict(sorted(STAGE5_BUDGET_BYTES.items())),
            "over_budget": list(self.over_budget),
            "over_peak_ceiling": self.over_peak_ceiling,
            "within_target": self.within_target,
            "profile": None if self.profile is None else self.profile.to_dict(),
            "loadavg": list(self.loadavg),
            "detail": self.detail,
        }


def _checked_components(value: object) -> Mapping[str, int | None]:
    """Refuse a component §43 does not budget, and a byte count that is not one."""
    if not isinstance(value, Mapping):
        raise ContractError("Stage5ResourceReport.component_bytes must be a mapping")
    snapshot: dict[str, int | None] = {}
    for name, measured in value.items():
        if name not in STAGE5_BUDGET_BYTES:
            raise ContractError(
                f"{name!r} has no §43 budget; known rows: {sorted(STAGE5_BUDGET_BYTES)}"
            )
        if measured is None:
            snapshot[name] = None
            continue
        if not isinstance(measured, int) or isinstance(measured, bool) or measured < 0:
            raise ContractError(f"component_bytes[{name!r}] must be a byte count or None")
        snapshot[name] = measured
    return MappingProxyType(snapshot)


def component_bytes(
    *,
    fields: Sequence[ActionField] = (),
    planning: ResponseCellField | None = None,
    memory: EffectivenessMemory | None = None,
    twin: ResponseTwin | None = None,
    journal: RollbackJournal | None = None,
    workspace_bytes: int | None = None,
    sentinel_bytes: int | None = None,
    incremental_rss_bytes: int | None = None,
    peak_rss_bytes: int | None = None,
) -> Mapping[str, int | None]:
    """Ask each component for its own bytes; leave the rest ``None``.

    Nothing is estimated, and **nothing that was never filled is measured**. Every row
    is the canonical serialised size of state the measured block actually produced:

    * ``aegis_planning_state`` — the largest action field's candidates, plus the cells
      and the effectiveness memory §43's row also covers. ``None`` with no field.
    * ``twin_dependency_state`` — the twin's own canonical projections (see
      :func:`_twin_bytes`).
    * ``rollback_evidence_hot_state`` — the journal's ``bytes_used()``, and ``None`` when
      the journal holds no entry. An earlier revision reported the 0 bytes of a journal
      the measured block never wrote to: a true figure about an unused structure, read by
      every consumer as the footprint of a used one.

    ``simulation_workspace`` and ``sentinel_and_executor`` take plain byte counts because
    neither the simulated host nor the kernel reports its own footprint, and inventing a
    ``state_bytes()`` for them would be an estimate wearing a measurement's name. They
    stay ``None`` here, which is what keeps ``within_target`` ``None`` downstream.
    """
    planning_bytes = None
    if fields:
        planning_bytes = max(_field_bytes(field) for field in fields)
        if planning is not None:
            planning_bytes += int(planning.state_bytes())
        if memory is not None:
            planning_bytes += _canonical_length(list(memory.rows()))
    journal_bytes = None
    if journal is not None and journal.entries():
        journal_bytes = int(journal.bytes_used())
    return _checked_components(
        {
            "aegis_planning_state": planning_bytes,
            "twin_dependency_state": None if twin is None else _twin_bytes(twin),
            "simulation_workspace": workspace_bytes,
            "sentinel_and_executor": sentinel_bytes,
            "rollback_evidence_hot_state": journal_bytes,
            "normal_incremental_rss": incremental_rss_bytes,
            "peak_without_optional_lm": peak_rss_bytes,
        }
    )


def _canonical_length(payload: object) -> int:
    """Bytes of the sorted-key JSON form: the form Stage 5 state is exported and digested in."""
    return len(json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode())


def _field_bytes(field: ActionField) -> int:
    return _canonical_length([candidate.to_dict() for candidate in field.candidates])


def _twin_bytes(twin: ResponseTwin) -> int | None:
    """The twin's projected state in the bytes its canonical form occupies, or ``None``.

    ``TwinState`` carries ``canonical_bytes()`` and the twin bounds itself at
    ``MAX_TWIN_BYTES``, so this is the figure the twin's own bound is expressed in — not
    a ``getsizeof`` walk over Python objects, which would measure the interpreter.

    The projection store is the twin's own private business, so it is read defensively:
    if it is not there under the name this function expects, the answer is ``None`` and
    the row is UNMEASURED. Returning ``0`` instead would put a plausible number where
    there is no measurement, which is the one thing this module exists to prevent.
    """
    cache = getattr(twin, "_cache", None)
    if not isinstance(cache, Mapping) or not cache:
        return None
    total = 0
    for entry in cache.values():
        # The store holds ``(TwinState, bool)``. An earlier revision read the tuple as
        # the state, found no ``canonical_bytes`` on it, and so reported this row
        # UNMEASURED on every run — honest by accident, and silent about why.
        state = entry[0] if isinstance(entry, tuple) and entry else entry
        canonical = getattr(state, "canonical_bytes", None)
        if canonical is None:
            return None
        total += len(canonical())
    return total


def _largest_twin(twins: Sequence[ResponseTwin]) -> ResponseTwin | None:
    """The twin whose projected state is largest, or ``None`` if any is unmeasurable.

    §43's twin row bounds the dependency state *one incident* needs, and the twins here
    are one per case, so the row is judged on the worst case rather than on whichever
    twin happened to be built first — an earlier revision measured ``twins[0]``, which
    reports the smallest footprint on any corpus whose first case is the simplest. If a
    single twin cannot be measured the answer is ``None``: a maximum over the twins that
    happened to be readable is a figure about a subset.
    """
    sized: list[tuple[int, ResponseTwin]] = []
    for twin in twins:
        size = _twin_bytes(twin)
        if size is None:
            return None
        sized.append((size, twin))
    if not sized:
        return None
    return max(sized, key=lambda pair: pair[0])[1]


def unmeasured_stage5_resources(reason: str) -> Stage5ResourceReport:
    """The honest report for a run that measured nothing. ``within_target`` is ``None``.

    Exists so a caller that could not sample has something correct to return instead of
    inventing zeroes.
    """
    if not reason.strip():
        raise ContractError("an unmeasured report must say why it is unmeasured")
    return Stage5ResourceReport(
        peak_rss_bytes=None,
        incremental_rss_bytes=None,
        component_bytes=dict.fromkeys(STAGE5_COMPONENTS),
        within_target=None,
        profile=None,
        loadavg=loadavg(),
        detail=f"UNMEASURED: {reason}",
    )


def _field_pass(cases: Sequence[ResponseCase]) -> tuple[int, dict[str, Any]]:
    """Generate the action field for every case, returning the work done and the state.

    The field, the twin projections, the cells and the effectiveness memory for a whole
    corpus, held live at the same time so the peak is a peak of something real rather
    than of one case.
    """
    governor = ResourceGovernor()
    memory = EffectivenessMemory()
    cells = ResponseCellField()
    twins: list[ResponseTwin] = []
    fields: list[ActionField] = []
    for case in cases:
        snapshot = case.host.snapshot()
        twin = ResponseTwin(snapshot=snapshot, governor=ResourceGovernor())
        twins.append(twin)
        fields.append(
            generate_action_field(
                case.resolution,
                snapshot,
                constitution=FROZEN_CONSTITUTION,
                invariants=case.invariants,
                governor=governor,
                memory=memory,
                cells=cells,
                twin=twin,
            )
        )
    held = {"cells": cells, "twins": twins, "memory": memory, "fields": fields}
    return sum(len(field.candidates) for field in fields), held


def _loop_pass(
    cases: Sequence[ResponseCase], build_executor: ExecutorFactory
) -> BaselineRig | None:
    """Run the full planner loop through the real executor; return the heaviest rig.

    "Heaviest" is the rig whose journal holds the most bytes, because §43's rollback row
    bounds the hot state one incident can pin. Every rig is released after it is read,
    so the RSS the sampler sees is the loop's working set rather than a corpus of rigs
    nobody would keep alive in production.
    """
    heaviest: list[BaselineRig] = []

    def observe(rig: BaselineRig) -> None:
        if not heaviest or rig.journal.bytes_used() > heaviest[0].journal.bytes_used():
            heaviest[:] = [rig]

    run_arm(
        reference_arm, cases, baseline_id=REFERENCE_ARM_ID, build_executor=build_executor,
        observe=observe,
    )
    return heaviest[0] if heaviest else None


def incremental_rss(metrics: ResourceMetrics) -> int | None:
    """Working-set growth over the measured block, never negative; ``None`` if unread.

    ``delta_rss_bytes`` is end minus start, which goes negative whenever the block
    frees more than it keeps, and a negative byte count crashed the section 43 contract
    on whichever run the allocator happened to return pages. It also understates a
    block that allocates and frees. The sampled peak over the starting RSS is the growth
    the block actually caused; the end delta is kept when it is larger. A block that
    never rose above its starting RSS grew by 0 bytes, which is a reading, not a guess.
    """
    start = metrics.idle_rss_bytes
    if start is None:
        return None
    growth = []
    if metrics.peak_sampled_rss_bytes is not None:
        growth.append(metrics.peak_sampled_rss_bytes - start)
    if metrics.delta_rss_bytes is not None:
        growth.append(metrics.delta_rss_bytes)
    if not growth:
        return None
    return max(0, *growth)


def measure_stage5_resources(
    cases: Sequence[ResponseCase], *, build_executor: ExecutorFactory | None = None
) -> Stage5ResourceReport:
    """Run Stage 5 over ``cases`` under Stage 0's sampler and report §43's rows.

    With ``build_executor`` the measured block is the **whole loop** — field, planner,
    SENTINEL, transactional executor, lease sweep — through ``labs.baselines.run_arm``;
    without it, only the field pass runs and the rollback row is ``None`` because no
    journal was written. The factory is a parameter for trust rule T4's reason: this
    module may not name ``TransactionalExecutor``.

    ``within_target`` is ``True`` only when every term was observed, every §43 component
    is under its budget and both RSS figures are under their ceilings. One missing term
    makes it ``None``, and two of the seven rows are always missing —
    ``simulation_workspace`` and ``sentinel_and_executor`` have no self-reported
    footprint — so the honest answer is ``None`` with the measured bytes beside it.
    """
    if not cases:
        return unmeasured_stage5_resources("no cases were supplied to measure")
    sampler = ResourceSampler()
    with sampler:
        candidates, held = _field_pass(cases)
        rig = None if build_executor is None else _loop_pass(cases, build_executor)
    metrics: ResourceMetrics = sampler.result(events_processed=candidates, startup_seconds=None)
    measured = component_bytes(
        fields=held["fields"],
        planning=held["cells"] if rig is None else rig.cells,
        memory=held["memory"] if rig is None else rig.memory,
        twin=_largest_twin(held["twins"]),
        journal=None if rig is None else rig.journal,
        incremental_rss_bytes=incremental_rss(metrics),
        peak_rss_bytes=metrics.peak_sampled_rss_bytes,
    )
    absent = [name for name, value in measured.items() if value is None]
    within = None if absent else _within_budget(measured)
    loop = "field pass only" if build_executor is None else "full loop through the executor"
    return Stage5ResourceReport(
        peak_rss_bytes=metrics.peak_sampled_rss_bytes,
        incremental_rss_bytes=incremental_rss(metrics),
        component_bytes=measured,
        within_target=within,
        profile=check_profile(metrics, STAGE5_PROFILE, model_bytes=None),
        loadavg=loadavg(),
        detail=(
            f"resources.measure_stage5_resources, {loop}, over {len(cases)} cases, "
            f"{candidates} candidates; unmeasured rows {sorted(absent)}; "
            f"stage0 sampler unavailable {list(metrics.unavailable)}"
        ),
    )


def _within_budget(measured: Mapping[str, int | None]) -> bool:
    """The verdict for a report with **no** missing row. Callers pass ``None`` otherwise.

    Computed rather than asserted: an assert can be stripped with ``-O``, and this is the
    one value in the module that must never become ``True`` by accident.
    """
    if any(value is None for value in measured.values()):
        raise ContractError("within_budget needs every row measured; a gap is UNMEASURED")
    return all(
        value is not None and value <= STAGE5_BUDGET_BYTES[name]
        for name, value in measured.items()
    )


def measure_stage5_profile(
    cases: Sequence[ResponseCase], *, build_executor: ExecutorFactory | None = None
) -> ProfileReport:
    """Stage 0's **own** profile report for one Stage 5 pass.

    Kept beside :func:`measure_stage5_resources` rather than folded into it because the
    two answer different questions: §43's per-component envelope is Stage 5's, while
    ``check_profile`` answers whether the *agent* fits its deployment profile — the
    figure that decides whether Stages 1-4 still fit on the same 2 GB host.
    ``model_bytes=None`` is the honest value: Stage 5 ships no model, and passing 0 would
    claim a measurement of something that does not exist.
    """
    if STAGE5_PROFILE not in PROFILES:
        raise ContractError(f"unknown resource profile {STAGE5_PROFILE!r}")
    sampler = ResourceSampler()
    with sampler:
        candidates, _held = _field_pass(cases)
        if build_executor is not None:
            _loop_pass(cases, build_executor)
    metrics = sampler.result(events_processed=candidates, startup_seconds=None)
    return check_profile(metrics, STAGE5_PROFILE, model_bytes=None)


assert set(STAGE5_COMPONENTS) == set(STAGE5_BUDGET_BYTES), "every §43 row needs a budget"
assert STAGE5_BUDGET_BYTES["normal_incremental_rss"] == STAGE5_NORMAL_INCREMENTAL_RSS_BYTES
assert STAGE5_BUDGET_BYTES["peak_without_optional_lm"] == STAGE5_PEAK_CEILING_BYTES
