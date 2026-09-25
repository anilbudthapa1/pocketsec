"""D4.18 (dropped-telemetry variants) — paired full / degraded replays.

Gate criterion G4.4 and falsifier F4 both need the *same* incident observed two
ways: once with every sensor path available, once with one path removed. This
module builds that pair, in one call, from one construction, so the comparison is
within-run. On this host a cross-run comparison would be indistinguishable from
load: a Stage 2 gate measured a 7x wall-clock inflation at load 23-67 against the
same two passes at load 8-12 (cited from PROGRESS.md, not measured here).

**A measured finding that shapes this module.** Replaying
``build_corpus(count=40, seed=5, split="eval")`` and
``build_ambiguous_corpus(count=20, seed=7)`` through eBPF, auditd and procfs and
counting relation-family signals gives observations == occurrences on every path,
for every signal, with zero unresolved events. The Stage 1 replay simulator has
**no measured per-path visibility asymmetry**: every path observes everything.
That is a real result about the simulator and it means a *measured* sensor drop
cannot be constructed from it.

:data:`SENSOR_SIGNAL_DOMAINS` is therefore a **declared parameter, not a
measurement** — see :data:`SENSOR_SIGNAL_DOMAINS_STATUS`. It states which signal
families each Linux telemetry source is the one that carries, so that dropping a
path removes exactly the evidence only that path delivers. It is grounded in what
each subsystem can see on a real host, it is coarse, and it is declared in the
findings document as a parameter. Reporting the resulting byte or confidence
figures as a measurement of Linux sensor loss would be exactly the fabrication
spec §6.1 forbids.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from types import MappingProxyType
from typing import TYPE_CHECKING, Protocol, TypeVar, runtime_checkable

from pocketsec.stage1.labs.corpus import Behaviour, Scenario
from pocketsec.stage1.pipeline import ScenarioResult, Stage1Pipeline
from pocketsec.stage1.telemetry.raw_event_v1 import SensorPath
from pocketsec.stage4.visibility.model import (
    RELATION_SIGNALS,
    VisibilityModel,
    occurrence_counts,
    signal_for_operation,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from pocketsec.stage4.labs.incident_corpus import IncidentCase

__all__ = [
    "SENSOR_SIGNAL_DOMAINS",
    "SENSOR_SIGNAL_DOMAINS_STATUS",
    "MaskableCase",
    "degrade_model",
    "domain_restricted",
    "drop_sensor_path",
    "drop_signal",
    "exclusive_signals",
    "mask_scenario",
    "masked_occurrences",
    "paired_replay",
    "paired_replay_batch",
]

#: Signals auditd does not record without extra configuration: per-write socket
#: egress and ingress, and memory mapping. Named as the *difference* from the full
#: vocabulary rather than as a list of what auditd does see, so that a relation
#: added to Stage 1 lands inside auditd's domain by default instead of silently
#: falling outside every domain.
_AUDITD_BLIND: frozenset[str] = frozenset({"send", "receive", "map"})

#: Declared, not measured. Which relation families each telemetry source carries.
#: eBPF is the whole vocabulary because it observes at syscall granularity — and
#: because *deriving* it means a new Stage 1 relation cannot end up outside every
#: domain, where :func:`domain_restricted` would erase its measured visibility.
#: That defect existed in the first draft of this table: 14 of Stage 1's 24
#: relation families were in no domain at all, and the eval corpus exercises only
#: 10 of them, so no test on that corpus would have shown it.
SENSOR_SIGNAL_DOMAINS: Mapping[SensorPath, frozenset[str]] = MappingProxyType(
    {
        SensorPath.EBPF: RELATION_SIGNALS,
        SensorPath.AUDITD: RELATION_SIGNALS - _AUDITD_BLIND,
        SensorPath.PROCFS: frozenset({"change", "execute", "impersonate", "map", "spawn"}),
        SensorPath.JOURNALD: frozenset(
            {"authenticate", "control", "grant", "impersonate", "install", "revoke"}
        ),
        SensorPath.LSM: frozenset(
            {
                "control",
                "create",
                "delete",
                "execute",
                "load",
                "map",
                "mount",
                "read",
                "remove",
                "rename",
                "write",
            }
        ),
    }
)

#: Read this before quoting any number derived from a sensor drop.
SENSOR_SIGNAL_DOMAINS_STATUS: str = (
    "DECLARED_PARAMETER_NOT_MEASURED: the Stage 1 replay simulator was measured to "
    "have no per-path visibility asymmetry (observations == occurrences on eBPF, "
    "auditd and procfs for every relation family), so path exclusivity cannot be "
    "fitted from this repository's corpora and is declared here instead."
)


@runtime_checkable
class MaskableCase(Protocol):
    """The slice of ``IncidentCase`` these helpers read and rewrite.

    Structural because ``labs/incident_corpus.py`` belongs to another work
    package being written in parallel; these functions only need a scenario and a
    visibility mask, and ``dataclasses.replace`` does the rest. A test can supply
    a minimal frozen case without waiting for the full corpus.
    """

    scenario: Scenario
    visibility_mask: frozenset[str]


#: Bound so a masked case comes back as the same type it went in as: the caller
#: keeps its own ``IncidentCase``, not a widened object it has to re-narrow.
_CaseT = TypeVar("_CaseT", bound=MaskableCase)


def exclusive_signals(sensor: SensorPath) -> frozenset[str]:
    """Signals only ``sensor`` carries, per :data:`SENSOR_SIGNAL_DOMAINS`.

    Dropping a path blinds you to what *only* it could see. Anything another live
    path also delivers is not lost, and marking it lost would overstate the
    shadow — which sounds safe but is not: an overstated shadow suppresses
    confidence everywhere and makes the measure useless for deciding anything.
    Returning an empty set is a legitimate answer and means exactly what it says.
    """
    sensor = SensorPath(sensor)
    mine = SENSOR_SIGNAL_DOMAINS.get(sensor, frozenset())
    others: set[str] = set()
    for path, signals in SENSOR_SIGNAL_DOMAINS.items():
        if path is not sensor:
            others |= signals
    return frozenset(mine - others)


def domain_restricted(model: VisibilityModel) -> VisibilityModel:
    """Drop the rows :data:`SENSOR_SIGNAL_DOMAINS` says a path cannot carry.

    Without this step a sensor drop cannot blind anything, and the reason is a
    measured property of the simulator rather than an oversight. ``emit`` sends
    every behaviour down whichever path is asked for, so a fitted model states
    that auditd observes ``send`` at 1.0 — true of the replay, false of Linux.
    A drop of eBPF then leaves auditd "covering" the egress the drop removed, the
    shadow stays empty, and G4.4 would pass while measuring nothing.

    Restricting to the declared domains makes the model the one a real host would
    hold. It is applied through a **declared parameter**
    (:data:`SENSOR_SIGNAL_DOMAINS_STATUS`) and every figure computed from a
    restricted model inherits that status. The restriction only ever *removes*
    rows: it cannot invent visibility, only decline to claim it.
    """
    kept = {
        key: row
        for key, row in model.rows.items()
        if row.signal in SENSOR_SIGNAL_DOMAINS.get(row.sensor, frozenset())
    }
    return VisibilityModel(rows=kept, level=model.level, dropped_paths=model.dropped_paths)


def degrade_model(model: VisibilityModel, sensor: SensorPath) -> VisibilityModel:
    """The visibility model a host holds after losing ``sensor``.

    Restriction first, then the drop: applying the drop to an unrestricted model
    produces the empty shadow described in :func:`domain_restricted`.
    """
    return domain_restricted(model).with_dropped(SensorPath(sensor))


def drop_sensor_path(case: _CaseT, sensor: SensorPath) -> _CaseT:
    """The same incident with ``sensor``'s exclusive signals made unobservable."""
    lost = exclusive_signals(sensor)
    return replace(case, visibility_mask=frozenset(case.visibility_mask) | lost)


def drop_signal(case: _CaseT, signal: str) -> _CaseT:
    """The same incident with one named signal made unobservable."""
    return replace(case, visibility_mask=frozenset(case.visibility_mask) | {signal})


def _survives(behaviour: Behaviour, mask: frozenset[str]) -> bool:
    signal = signal_for_operation(behaviour.operation)
    return signal is None or signal not in mask


def mask_scenario(scenario: Scenario, mask: frozenset[str]) -> Scenario:
    """Drop the behaviours a masked sensor path would never have delivered.

    The drop happens at emission, not after compilation: an event that no sensor
    delivered never reaches the assembler, so Stage 1's uncertainty, novelty and
    lineage state all see the degraded stream. Filtering compiled transitions
    instead would leave the pipeline's internal state built from evidence the
    incident never had, and every downstream figure would be measured against a
    host that does not exist.

    ``label``, ``technique`` and ``unseen_technique`` are carried through
    unchanged: masking telemetry does not change what actually happened.
    """
    if not mask:
        return scenario
    kept = tuple(b for b in scenario.behaviours if _survives(b, mask))
    return Scenario(
        name=f"{scenario.name}-masked",
        behaviours=kept,
        label=scenario.label,
        technique=scenario.technique,
        unseen_technique=scenario.unseen_technique,
    )


def masked_occurrences(scenario: Scenario, mask: frozenset[str]) -> dict[str, int]:
    """Relation-family occurrences the mask removed, per signal.

    The explicit record of what a drop cost. A drop that removed nothing returns
    an empty mapping, which is the honest answer for a path whose signals another
    live path also carries.
    """
    full = occurrence_counts(scenario.behaviours)
    degraded = occurrence_counts(mask_scenario(scenario, mask).behaviours)
    return {
        signal: full[signal] - degraded.get(signal, 0)
        for signal in sorted(full)
        if full[signal] - degraded.get(signal, 0) > 0
    }


def paired_replay(
    case: MaskableCase | IncidentCase,
    pipeline_factory: Callable[[], Stage1Pipeline],
    *,
    sensor: SensorPath = SensorPath.EBPF,
    offset: int = 0,
) -> tuple[ScenarioResult, ScenarioResult]:
    """Replay one incident at full and at degraded telemetry. Returns (full, dropped).

    A **fresh pipeline for each leg**, from ``pipeline_factory``:
    ``Stage1Pipeline`` carries lineage state, and sharing one would let the full
    replay's accumulated capability leak into the degraded replay, manufacturing
    exactly the confidence the degraded run is supposed to lack. The same
    ``offset`` is used for both so the synthetic pid and the host timeline match
    and the two legs remain comparable.
    """
    mask = frozenset(case.visibility_mask)
    full = pipeline_factory().run_scenario(case.scenario, sensor=sensor, offset=offset)
    degraded = pipeline_factory().run_scenario(
        mask_scenario(case.scenario, mask), sensor=sensor, offset=offset
    )
    return full, degraded


def paired_replay_batch(
    cases: Sequence[MaskableCase | IncidentCase],
    pipeline_factory: Callable[[], Stage1Pipeline],
    *,
    sensor: SensorPath = SensorPath.EBPF,
) -> tuple[tuple[ScenarioResult, ScenarioResult], ...]:
    """:func:`paired_replay` over a corpus, with a distinct offset per case."""
    return tuple(
        paired_replay(case, pipeline_factory, sensor=sensor, offset=index)
        for index, case in enumerate(cases)
    )
