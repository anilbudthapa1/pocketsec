"""G4.9's two arms the short flood cannot reach: one long incident, and a full field.

This module is FOR showing that Stage 4's bounds are bounds on WORK and STATE, not on
a counter, and that hitting one is recorded rather than silent.

The original G4.9 flood is 40 short incidents of ~28 transitions. Every bound held on
it and none of that said anything about one incident an attacker keeps open: the
review drove a single incident for 1000 updates and watched per-update time grow
2.8 ms -> 18.5 ms, the transition list and the truncation log grow without limit, and
``memory_bytes()`` stay flat at ~4 KB while ``spend_report`` read 4096/4096 "within
bound" (S4-REV-01, S4-SEC-01, S4-RES-01, S4-RES-03). :func:`long_incident_bounds`
is that attack as a measurement. Its pass conditions are deterministic — state and
memory plateau, the truncation log stays inside its cap, and once the horizon closes
an update costs one integrate unit — and the CPU-per-update ratio between the first
and last windows is REPORTED beside ``/proc/loadavg``, never asserted, because this
host's timings are contended (spec §2.8).

The flood also never reached the world bound (3 of 8), so G4.9 could not show a
world being refused at capacity, and the refusal was in fact discarded silently
(S4-FC-05 / S4-RES-02). :func:`capacity_bounds` re-runs a slice of the flood at a
deliberately small ``max_worlds`` so the bound IS hit, and counts the world-kind
``Truncation`` records the engine now writes when it refuses a birth there.
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from dataclasses import dataclass, replace
from typing import Any

from pocketsec.stage0.gate import GateCheck
from pocketsec.stage1.observation.policy import AdaptiveObservationPolicy
from pocketsec.stage4 import gate_criteria as criteria
from pocketsec.stage4.claims.graph import MAX_CLAIMS_PER_GRAPH
from pocketsec.stage4.engine.lucid import LucidConfig, LucidEngine
from pocketsec.stage4.engine.lucid_support import WORK_UNITS
from pocketsec.stage4.gate_probes import BoundSample, flood_bounds
from pocketsec.stage4.graph.entropy_budget import MAX_INCIDENT_BYTES
from pocketsec.stage4.graph.sparse_world_graph import (
    MAX_FIELD_TRUNCATIONS,
    MAX_GRAPH_EDGES,
    MAX_GRAPH_NODES,
    TRUNCATION_KINDS,
)
from pocketsec.stage4.labs.baseline_metrics import Replay, replay_corpus
from pocketsec.stage4.labs.incident_corpus import build_world_flood
from pocketsec.stage4.resources import loadavg
from pocketsec.stage4.visibility.model import VisibilityModel

__all__ = [
    "CAPACITY_MAX_WORLDS",
    "CPU_WINDOW",
    "PLATEAU_TOLERANCE",
    "LongIncidentSample",
    "bounds_check",
    "capacity_bounds",
    "long_incident_bounds",
]

#: Updates averaged at each end of the long incident for the reported CPU ratio.
CPU_WINDOW: int = 100

#: How much state may still grow between the half-way sample and the end before the
#: plateau is refused. 10% plus 1 KiB absorbs the last few evidence digests the lineage
#: may still take (it is itself capped at ``MAX_FIELD_EVIDENCE_REFS``); linear growth
#: over ~500 further updates — what the review measured at ~1.4 KB per update — cannot
#: hide inside it.
PLATEAU_TOLERANCE: float = 0.10
_PLATEAU_SLACK_BYTES: int = 1024

#: The world bound the capacity arm runs at: small enough that the flood hits it.
CAPACITY_MAX_WORLDS: int = 2


@dataclass(frozen=True, slots=True)
class LongIncidentSample:
    """One incident held open for every same-epoch transition of the flood."""

    updates: int
    horizon_closed_at: int | None
    state_bytes_half: int
    state_bytes_end: int
    worst_state_bytes: int
    memory_bytes_half: int
    memory_bytes_end: int
    truncations_end: int
    max_units_after_close: int
    units_total: int
    cpu_first_ms: float | None
    cpu_last_ms: float | None
    loadavg: tuple[float, float, float]

    @property
    def truncation_cap(self) -> int:
        return MAX_FIELD_TRUNCATIONS + len(TRUNCATION_KINDS)

    @property
    def plateaued(self) -> bool:
        """State and memory stopped growing between the half-way point and the end."""
        return _within(self.state_bytes_end, self.state_bytes_half) and _within(
            self.memory_bytes_end, self.memory_bytes_half
        )

    @property
    def passed(self) -> bool:
        return (
            self.horizon_closed_at is not None
            and self.plateaued
            and self.truncations_end <= self.truncation_cap
            and self.max_units_after_close <= WORK_UNITS["integrate"]
        )

    @property
    def cpu_ratio(self) -> float | None:
        """Last-window over first-window mean CPU per update. Reported, never asserted."""
        if not self.cpu_first_ms or self.cpu_last_ms is None:
            return None
        return self.cpu_last_ms / self.cpu_first_ms

    def to_dict(self) -> dict[str, Any]:
        return {
            "updates": self.updates,
            "horizon_closed_at": self.horizon_closed_at,
            "state_bytes_half": self.state_bytes_half,
            "state_bytes_end": self.state_bytes_end,
            "worst_state_bytes": self.worst_state_bytes,
            "memory_bytes_half": self.memory_bytes_half,
            "memory_bytes_end": self.memory_bytes_end,
            "truncations_end": self.truncations_end,
            "max_units_after_close": self.max_units_after_close,
            "units_total": self.units_total,
            "cpu_ratio": self.cpu_ratio,
            "loadavg": list(self.loadavg),
        }


def _within(end: int, half: int) -> bool:
    return end <= half * (1.0 + PLATEAU_TOLERANCE) + _PLATEAU_SLACK_BYTES


def _stream(replays: Sequence[Replay]) -> list[tuple[Any, Any]]:
    """Every transition sharing the first replay's epoch, each with its own spine."""
    if not replays or not replays[0].result.transitions:
        return []
    epoch = replays[0].result.transitions[0].epoch_id
    stream: list[tuple[Any, Any]] = []
    for replay in replays:
        spine = replay.pipeline.causal.spine()
        stream.extend(
            (transition, spine)
            for transition in replay.result.transitions
            if transition.epoch_id == epoch
        )
    return stream


def long_incident_bounds(
    replays: Sequence[Replay], model: VisibilityModel, *, config: LucidConfig | None = None
) -> LongIncidentSample:
    """Hold ONE incident open across the whole flood and sample its cost and state."""
    stream = _stream(replays)
    engine = LucidEngine(
        config=config if config is not None else LucidConfig(),
        visibility=model,
        observation=AdaptiveObservationPolicy(),
    )
    epoch = stream[0][0].epoch_id if stream else 0
    field = engine.open_incident("g49-long-incident", epoch)
    half = len(stream) // 2
    closed_at: int | None = None
    sample = {"state_half": 0, "memory_half": 0, "worst": 0, "units": 0, "after_close": 0}
    cpu: list[float] = []
    for index, (transition, spine) in enumerate(stream):
        started = time.process_time()
        outcome = engine.update(field, transition, spine)
        cpu.append((time.process_time() - started) * 1000.0)
        field = outcome.field
        sample["units"] += outcome.work_units
        sample["worst"] = max(sample["worst"], field.state_bytes())
        if closed_at is None and any(
            item.reason.startswith("resolution_horizon_exhausted") for item in outcome.truncations
        ):
            closed_at = index
        elif closed_at is not None:
            sample["after_close"] = max(sample["after_close"], outcome.work_units)
        if index == half:
            sample["state_half"] = field.state_bytes()
            sample["memory_half"] = engine.memory_bytes()
    result = LongIncidentSample(
        updates=len(stream),
        horizon_closed_at=closed_at,
        state_bytes_half=sample["state_half"],
        state_bytes_end=field.state_bytes(),
        worst_state_bytes=sample["worst"],
        memory_bytes_half=sample["memory_half"],
        memory_bytes_end=engine.memory_bytes(),
        truncations_end=len(field.truncations),
        max_units_after_close=sample["after_close"],
        units_total=sample["units"],
        cpu_first_ms=_mean(cpu[:CPU_WINDOW]),
        cpu_last_ms=_mean(cpu[-CPU_WINDOW:]),
        loadavg=loadavg(),
    )
    engine.close_incident(field)
    return result


def _mean(values: Sequence[float]) -> float | None:
    return sum(values) / len(values) if values else None


def capacity_bounds(
    replays: Sequence[Replay], model: VisibilityModel, *, config: LucidConfig | None = None
) -> BoundSample:
    """The flood again at ``CAPACITY_MAX_WORLDS``, so the world bound is actually hit."""
    base = config if config is not None else LucidConfig()
    sample, _runs = flood_bounds(
        replays, model, config=replace(base, max_worlds=CAPACITY_MAX_WORLDS)
    )
    return sample


def bounds_check(ctx: Any) -> GateCheck:
    """G4.9 — every bound sampled at every step, on three arms.

    The short flood alone could not fail on the defects that mattered: its incidents
    are ~28 transitions long and it never reached the world bound (S4-REV-01,
    S4-FC-05). ``gate_bounds`` adds one incident held open across the whole flood and
    a capacity arm at a small ``max_worlds``.
    """
    flood = build_world_flood(count=criteria.FLOOD_COUNT, seed=criteria.FLOOD_SEED)
    replays = replay_corpus(flood)
    config = LucidConfig()
    sample, runs = flood_bounds(replays, ctx.visibility.model, config=config)
    long = long_incident_bounds(replays, ctx.visibility.model, config=config)
    capacity = capacity_bounds(replays, ctx.visibility.model, config=config)

    within = (
        sample.worst_worlds <= config.max_worlds
        and sample.worst_graph_nodes <= MAX_GRAPH_NODES
        and sample.worst_graph_edges <= MAX_GRAPH_EDGES
        and sample.worst_claims <= MAX_CLAIMS_PER_GRAPH
        and sample.worst_reasoning_units <= config.budget.max_reasoning_units
        and sample.worst_state_bytes <= MAX_INCIDENT_BYTES
    )
    # Losses AT the world bound must be world-kind records. The old clause
    # ``truncations > 0`` was met by graph-edge noise whether or not a world was lost.
    explicit_at_bound = (
        "worlds" in capacity.bounds_reached
        and capacity.world_truncations > 0
        and capacity.worst_worlds <= CAPACITY_MAX_WORLDS
    )
    truth_survived = sum(
        1
        for run in runs
        if run.replay.truth_signals
        and any(
            run.replay.truth_signals
            <= (world.expected_evidence | world.visibility_requirements)
            for world in run.field.worlds
        )
    )
    countable = sum(1 for run in runs if run.replay.truth_signals)
    passed = (
        within
        and long.passed
        and long.worst_state_bytes <= MAX_INCIDENT_BYTES
        and explicit_at_bound
        and (countable == 0 or truth_survived == countable)
    )
    cpu_ratio = long.cpu_ratio
    return GateCheck(
        "G4.9",
        "World count, graph size and reasoning work remain hard bounded",
        passed,
        f"SHORT FLOOD build_world_flood(count={criteria.FLOOD_COUNT}, seed={criteria.FLOOD_SEED}), "
        f"every bound sampled at each of {sample.steps} update steps: worlds "
        f"{sample.worst_worlds}/{config.max_worlds}; graph nodes "
        f"{sample.worst_graph_nodes}/{MAX_GRAPH_NODES}; edges "
        f"{sample.worst_graph_edges}/{MAX_GRAPH_EDGES}; claims "
        f"{sample.worst_claims}/{MAX_CLAIMS_PER_GRAPH} (read off the resolved graph); "
        f"reasoning units demanded per incident {sample.worst_reasoning_units}/"
        f"{config.budget.max_reasoning_units}; state bytes "
        f"{sample.worst_state_bytes}/{MAX_INCIDENT_BYTES}. All within bound: {within}. "
        f"{sample.truncations} Truncation records, {sample.world_truncations} of them world-kind. "
        f"LONG INCIDENT — one incident held open for all {long.updates} same-epoch flood "
        f"transitions: the §20 horizon closed reasoning at update {long.horizon_closed_at}, after "
        f"which an update costs at most {long.max_units_after_close} unit(s); state bytes "
        f"{long.state_bytes_half} at the half-way point and {long.state_bytes_end} at the end, "
        f"engine.memory_bytes {long.memory_bytes_half} -> {long.memory_bytes_end} "
        f"(plateaued: {long.plateaued}); truncation log {long.truncations_end}/"
        f"{long.truncation_cap}; {long.units_total} units over the whole incident. Mean CPU per "
        f"update, last {CPU_WINDOW} over first {CPU_WINDOW}: "
        f"{cpu_ratio if cpu_ratio is None else round(cpu_ratio, 3)} at loadavg {long.loadavg} "
        f"— REPORTED, not asserted (contended host, spec §2.8); before S4-REV-01 the same shape "
        f"of run went 2.83 -> 18.50 ms per update in the review's measurement of the pre-fix "
        f"code (cited, not re-run: that code is no longer in the tree). Long-incident arm "
        f"passed: {long.passed}. "
        f"CAPACITY — the flood at max_worlds={CAPACITY_MAX_WORLDS}: bounds reached "
        f"{list(capacity.bounds_reached)}, worlds {capacity.worst_worlds}/"
        f"{CAPACITY_MAX_WORLDS}, {capacity.world_truncations} world-kind Truncation "
        f"records for births refused at capacity (these were discarded silently before "
        f"S4-FC-05): {explicit_at_bound}. The ground-truth world survived the short flood on "
        f"{truth_survived}/{countable} countable cases. Wall clock is observed, not asserted; "
        f"loadavg {ctx.loadavg}.",
    )
