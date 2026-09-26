"""D9.18 (ONTO-F18) — the hardware-in-loop harness: what a phenotype actually costs on this host.

Architecture §52 says FLOPs and parameter counts are secondary proxies: a candidate must be
deployed to a reference 2 GB Linux target, replayed, and measured for RSS/PSS, cycles, cache
misses, wakeups, latency, event loss and disk writes. This module measures what can honestly
be measured *here* and names everything else UNMEASURED.

What it measures. :func:`measure_phenotype` replays a compiled split through
``Phenotype.run_dataset`` inside Stage 0's :class:`ResourceSampler` (the only RSS source any
stage uses), takes the best of :data:`HIL_REPETITIONS` ``perf_counter``/``process_time``
runs, and times the direct-loop Φ-oracle (``max(step.features[73])``) **in the same run**, so
``ratio_to_phi_oracle`` is a within-run ratio. Incremental RSS is sampled peak minus start,
floored at 0. The load average is recorded before and after, because this host is shared and
a Stage 2 gate run measured the same code 7x slower at high load.

What it refuses to do.

* **This host is not a reference target.** ``is_reference_target`` compares ``MemTotal`` with
  2 GiB x :data:`REFERENCE_TOLERANCE`; on this 16 GB host it is ``False``, and G9.4 fails
  rather than quoting a 16 GB figure as a 2 GB one. An unreadable ``/proc/meminfo`` gives
  ``None``, never a guess.
* ``cache_misses``, ``wakeups`` and ``disk_writes`` are typed ``None`` and refused otherwise:
  no perf-counter access exists in a stdlib process. ``event_loss`` is 0 with basis
  ``REPLAY_NO_LOSS_POSSIBLE``: a replay of an in-memory split cannot drop events, which says
  nothing about a live sensor.
* Every microsecond figure is host-contended and not a device measurement; work units (exact)
  stay the primary cost.
* :func:`tcn_pareto_point` places the Stage 2 TCN only from registered, authenticated count-60
  frontier evidence. Its work units and bytes are ANALYTIC (arithmetic from architecture
  constants) and labelled so; refused evidence gives ``None`` plus the loader's reason.

Stage 0's ``run_benchmark`` is not used: no SSIR -> ``SecurityEventSequenceV1`` path exists
for Stage 9 phenotypes; the sampler is used directly, as Stages 5-7 did.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from pocketsec.stage0.benchmark.resource_metrics import ResourceSampler
from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage2.dataset import Stage2Dataset
from pocketsec.stage2.gate_evidence import load_frontier
from pocketsec.stage6.resources import loadavg
from pocketsec.stage9.chemistry.typed_ir import VALUE_BYTES
from pocketsec.stage9.genome.computational import ComputationalGenomeV1
from pocketsec.stage9.genome.expressibility import STAGE2_TCN_PARAMETERS
from pocketsec.stage9.labs.splits import SATURATED_COUNT
from pocketsec.stage9.spec.mssc import ObjectiveVector

__all__ = [
    "EVENT_LOSS_BASIS",
    "HIL_REPETITIONS",
    "MEMINFO_PATH",
    "PHI_ORACLE_FEATURE_INDEX",
    "REFERENCE_TARGET_RAM_BYTES",
    "REFERENCE_TOLERANCE",
    "TCN_ANALYTIC_BYTES",
    "TCN_ANALYTIC_DESCRIPTION_BITS",
    "TCN_ANALYTIC_WU",
    "TIMING_NOTE",
    "UNMEASURED_FIELDS",
    "HardwareMeasurement",
    "ProxyCorrelation",
    "host_is_reference_target",
    "host_mem_total_bytes",
    "measure_phenotype",
    "phi_oracle_direct_scores",
    "proxy_vs_real",
    "spearman",
    "tcn_pareto_point",
]

#: The architecture's reference target (§52, §61): a 2 GB Linux host.
REFERENCE_TARGET_RAM_BYTES: Final = 2 * 1024**3
#: ``MemTotal`` reads a little under the installed RAM; 10% headroom still excludes 4 GB hosts.
REFERENCE_TOLERANCE: Final = 1.10
#: Best-of-N repetitions for every timing (chosen).
HIL_REPETITIONS: Final = 5
MEMINFO_PATH: Final = Path("/proc/meminfo")
#: ``features[73]`` = |ΔΦ|/(|ΔΦ|+8), the Φ-oracle's slot (``PHI_SQUASHED_FEATURE_INDEX``).
PHI_ORACLE_FEATURE_INDEX: Final = 73
EVENT_LOSS_BASIS: Final = "REPLAY_NO_LOSS_POSSIBLE"
TIMING_NOTE: Final = "host-contended, not a device measurement"
UNMEASURED_FIELDS: Final = ("cache_misses", "wakeups", "disk_writes")

#: ANALYTIC, not measured: the TCN's per-event multiply-accumulates from its architecture
#: constants (kernel 3, width 96, hidden 24), 3*96*24 + 3*24 (spec §4.20).
TCN_ANALYTIC_WU: Final = 3 * 96 * 24 + 3 * 24
#: ANALYTIC lower bound: the TCN's weights at Stage 9's 8-byte value accounting, activations
#: excluded. The frontier evidence carries no model bytes, and ``ObjectiveVector`` cannot hold
#: ``None`` bytes, so a labelled lower bound stands in: a lower bound can only flatter the TCN.
TCN_ANALYTIC_BYTES: Final = STAGE2_TCN_PARAMETERS * VALUE_BYTES
#: ANALYTIC lower bound: 32 bits per weight, the genome description-length price of a CONST.
TCN_ANALYTIC_DESCRIPTION_BITS: Final = float(STAGE2_TCN_PARAMETERS * 32)

_MEASURED_BY = "pocketsec.stage9.harness.hardware_in_loop:measure_phenotype"


@dataclass(frozen=True, slots=True)
class HardwareMeasurement:
    """One phenotype replayed on this host. ``None`` always means UNMEASURED, never zero."""

    genome_digest: str
    host_mem_total_bytes: int | None
    is_reference_target: bool | None
    events: int
    wu_per_event: int
    peak_sampled_rss_bytes: int | None
    incremental_rss_bytes: int | None
    cpu_seconds_per_event: float | None
    wall_us_per_event: float | None
    phi_oracle_wall_us_per_event: float | None
    ratio_to_phi_oracle: float | None
    cache_misses: None = None
    wakeups: None = None
    disk_writes: None = None
    event_loss: int = 0
    loadavg_before: tuple[float, float, float] = (-1.0, -1.0, -1.0)
    loadavg_after: tuple[float, float, float] = (-1.0, -1.0, -1.0)
    measured_by: str = _MEASURED_BY

    def __post_init__(self) -> None:
        for name in UNMEASURED_FIELDS:
            if getattr(self, name) is not None:
                raise ContractError(f"{name} cannot be measured here and must stay None")
        if self.event_loss != 0:
            raise ContractError(f"event_loss is 0 by construction ({EVENT_LOSS_BASIS})")
        if self.incremental_rss_bytes is not None and self.incremental_rss_bytes < 0:
            raise ContractError("incremental RSS is floored at 0")
        if self.events < 0 or self.wu_per_event < 0:
            raise ContractError("events and wu_per_event are non-negative counts")
        expected = _host_verdict(self.host_mem_total_bytes)
        if self.is_reference_target != expected:
            raise ContractError(
                f"is_reference_target={self.is_reference_target} contradicts MemTotal "
                f"{self.host_mem_total_bytes} (expected {expected})"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "genome_digest": self.genome_digest,
            "host_mem_total_bytes": self.host_mem_total_bytes,
            "is_reference_target": self.is_reference_target,
            "events": self.events,
            "wu_per_event": self.wu_per_event,
            "peak_sampled_rss_bytes": self.peak_sampled_rss_bytes,
            "incremental_rss_bytes": self.incremental_rss_bytes,
            "cpu_seconds_per_event": self.cpu_seconds_per_event,
            "wall_us_per_event": self.wall_us_per_event,
            "phi_oracle_wall_us_per_event": self.phi_oracle_wall_us_per_event,
            "ratio_to_phi_oracle": self.ratio_to_phi_oracle,
            "cache_misses": None,
            "wakeups": None,
            "disk_writes": None,
            "unmeasured": list(UNMEASURED_FIELDS),
            "event_loss": self.event_loss,
            "event_loss_basis": EVENT_LOSS_BASIS,
            "timing_note": TIMING_NOTE,
            "loadavg_before": list(self.loadavg_before),
            "loadavg_after": list(self.loadavg_after),
            "measured_by": self.measured_by,
        }


def host_mem_total_bytes(path: Path | None = None) -> int | None:
    """``MemTotal`` in bytes from ``/proc/meminfo``, or ``None`` if it cannot be read."""
    source = MEMINFO_PATH if path is None else path
    try:
        for line in source.read_text(encoding="ascii").splitlines():
            key, _, rest = line.partition(":")
            if key == "MemTotal":
                value = int(rest.split()[0]) * 1024
                return value if value > 0 else None
    except (OSError, ValueError, IndexError, UnicodeDecodeError):
        return None
    return None


def _host_verdict(mem_total: int | None) -> bool | None:
    if mem_total is None:
        return None
    return mem_total <= REFERENCE_TARGET_RAM_BYTES * REFERENCE_TOLERANCE


def host_is_reference_target(path: Path | None = None) -> bool | None:
    """Whether this host is a 2 GB reference target; ``None`` when ``MemTotal`` is unreadable."""
    return _host_verdict(host_mem_total_bytes(path))


def phi_oracle_direct_scores(dataset: Stage2Dataset) -> tuple[float, ...]:
    """The Φ-oracle as a hand-written loop — the in-run timing reference, not a genome."""
    return tuple(
        max((step.features[PHI_ORACLE_FEATURE_INDEX] for step in sample.steps), default=0.0)
        for sample in dataset.samples
    )


def _best_of(work: Callable[[], object]) -> tuple[float, float]:
    """(best wall seconds, best CPU seconds) over :data:`HIL_REPETITIONS` calls of ``work``."""
    walls: list[float] = []
    cpus: list[float] = []
    for _ in range(HIL_REPETITIONS):
        wall0, cpu0 = time.perf_counter(), time.process_time()
        work()
        cpus.append(time.process_time() - cpu0)
        walls.append(time.perf_counter() - wall0)
    return min(walls), min(cpus)


def _per_event(total: float, events: int, scale: float = 1.0) -> float | None:
    return None if events <= 0 else total * scale / events


def measure_phenotype(genome: ComputationalGenomeV1, dataset: Stage2Dataset) -> HardwareMeasurement:
    """Replay ``dataset`` through ``genome``'s phenotype and the Φ-oracle loop in one run."""
    if not isinstance(genome, ComputationalGenomeV1):
        raise ContractError("measure_phenotype takes a constructed genome")
    phenotype = genome.phenotype()
    events = dataset.transition_count
    before = loadavg()
    sampler = ResourceSampler()
    with sampler:
        wall, cpu = _best_of(lambda: phenotype.run_dataset(dataset))
    metrics = sampler.result(events_processed=events, startup_seconds=None)
    phi_wall, _ = _best_of(lambda: phi_oracle_direct_scores(dataset))
    after = loadavg()
    peak, start = metrics.peak_sampled_rss_bytes, metrics.idle_rss_bytes
    wall_us = _per_event(wall, events, 1e6)
    phi_us = _per_event(phi_wall, events, 1e6)
    mem_total = host_mem_total_bytes()
    return HardwareMeasurement(
        genome_digest=genome.digest,
        host_mem_total_bytes=mem_total,
        is_reference_target=_host_verdict(mem_total),
        events=events,
        wu_per_event=genome.bounds.update_wu_per_event,
        peak_sampled_rss_bytes=peak,
        incremental_rss_bytes=None if peak is None or start is None else max(0, peak - start),
        cpu_seconds_per_event=_per_event(cpu, events),
        wall_us_per_event=wall_us,
        phi_oracle_wall_us_per_event=phi_us,
        ratio_to_phi_oracle=None if not wall_us or not phi_us else wall_us / phi_us,
        loadavg_before=before,
        loadavg_after=after,
    )


# --- S9X-111: is the work-unit proxy ordered like real time? ----------------------------------


@dataclass(frozen=True, slots=True)
class ProxyCorrelation:
    """Spearman rank correlation of static WU/event against measured wall time per event."""

    spearman_wu_vs_wall: float | None
    n: int


def _ranks(values: Sequence[float]) -> list[float]:
    """Average ranks (1-based), ties sharing the mean of their positions."""
    order = sorted(range(len(values)), key=lambda i: values[i])
    ranks = [0.0] * len(values)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and values[order[j + 1]] == values[order[i]]:
            j += 1
        for k in range(i, j + 1):
            ranks[order[k]] = (i + j) / 2.0 + 1.0
        i = j + 1
    return ranks


def spearman(xs: Sequence[float], ys: Sequence[float]) -> float | None:
    """Spearman's rho with average-rank ties; ``None`` below 3 points or with a constant side."""
    if len(xs) != len(ys):
        raise ContractError("spearman needs aligned sequences")
    if len(xs) < 3:
        return None
    rx, ry = _ranks(xs), _ranks(ys)
    mx, my = sum(rx) / len(rx), sum(ry) / len(ry)
    cov = sum((a - mx) * (b - my) for a, b in zip(rx, ry, strict=True))
    vx = sum((a - mx) ** 2 for a in rx)
    vy = sum((b - my) ** 2 for b in ry)
    if vx == 0.0 or vy == 0.0:
        return None
    return float(cov / (vx * vy) ** 0.5)


def proxy_vs_real(measurements: Sequence[HardwareMeasurement]) -> ProxyCorrelation:
    """S9X-111 on this (non-reference) host; unmeasured timings are left out, not zeroed."""
    pairs = [
        (float(m.wu_per_event), m.wall_us_per_event)
        for m in measurements
        if m.wall_us_per_event is not None
    ]
    rho = spearman([p[0] for p in pairs], [p[1] for p in pairs])
    return ProxyCorrelation(spearman_wu_vs_wall=rho, n=len(pairs))


# --- the TCN on the saturated Pareto plot --------------------------------------------------------


def tcn_pareto_point() -> tuple[ObjectiveVector | None, str]:
    """The Stage 2 TCN's point on the count-60 plot, or ``None`` and the reason there is none.

    ``worst_case_ap`` holds the frontier's CLEAN AP: no attacked TCN evaluation exists, so it
    is an upper bound on the TCN's worst case. Work units and bytes are ANALYTIC.
    """
    evidence, refusal = load_frontier()
    if evidence is None:
        return None, f"TCN point refused: {refusal}"
    if evidence.count != SATURATED_COUNT:
        return None, f"TCN point refused: frontier is count {evidence.count}, not {SATURATED_COUNT}"
    tcn = evidence.scores.get("tcn")
    if tcn is None:
        return None, "TCN point refused: the frontier evidence carries no 'tcn' score"
    vector = ObjectiveVector(
        worst_case_ap=float(tcn),
        wu_per_event=TCN_ANALYTIC_WU,
        state_bytes=TCN_ANALYTIC_BYTES,
        description_length_bits=TCN_ANALYTIC_DESCRIPTION_BITS,
    )
    return vector, (
        f"AP {tcn:.4f}: registered Stage 2 frontier evidence {evidence.experiment_id} "
        f"({evidence.corpus} count {evidence.count} seed {evidence.seed}, degenerate="
        f"{evidence.degenerate}, {evidence.reason}); CLEAN AP, an upper bound on worst case. "
        f"WU {TCN_ANALYTIC_WU} ANALYTIC (3*96*24 + 3*24 MACs/event from architecture "
        f"constants, not measured). Bytes {TCN_ANALYTIC_BYTES} ANALYTIC lower bound "
        f"({STAGE2_TCN_PARAMETERS} weights x {VALUE_BYTES} B, activations excluded; the "
        f"frontier carries no model bytes). Description length ANALYTIC lower bound."
    )
