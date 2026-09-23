"""Runtime resource measurement (spec section 12), stdlib only.

Resource cost is a co-equal acceptance dimension, so it is measured, not
estimated. On a platform where a figure is genuinely unavailable (no
``/proc``, no ``smaps_rollup``) the field is ``None`` and
:attr:`ResourceMetrics.unavailable` names it. A missing measurement is reported
as missing.
"""

from __future__ import annotations

import os
import platform
import resource
import threading
import time
from dataclasses import dataclass, field
from types import TracebackType
from typing import Any

__all__ = ["ResourceMetrics", "ResourceSampler", "read_pss_bytes", "read_rss_bytes"]

_PROC_STATUS = "/proc/self/status"
_SMAPS_ROLLUP = "/proc/self/smaps_rollup"


def _read_kb_field(path: str, key: str) -> int | None:
    try:
        with open(path, encoding="ascii") as handle:
            for line in handle:
                if line.startswith(key):
                    return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        return None
    return None


def read_rss_bytes() -> int | None:
    """Resident set size of this process, or ``None`` off Linux."""
    return _read_kb_field(_PROC_STATUS, "VmRSS:")


def read_pss_bytes() -> int | None:
    """Proportional set size — the honest number when pages are shared."""
    return _read_kb_field(_SMAPS_ROLLUP, "Pss:")


def _peak_rss_bytes() -> int | None:
    try:
        usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    except (OSError, ValueError):  # pragma: no cover - defensive
        return None
    # Linux reports kilobytes; macOS reports bytes.
    return usage if platform.system() == "Darwin" else usage * 1024


@dataclass(frozen=True, slots=True)
class ResourceMetrics:
    """Measured runtime cost for one benchmark run."""

    idle_rss_bytes: int | None
    peak_rss_bytes: int | None
    peak_sampled_rss_bytes: int | None
    pss_bytes: int | None
    delta_rss_bytes: int | None
    cpu_seconds: float
    wall_seconds: float
    events_processed: int
    startup_seconds: float | None
    sample_count: int
    unavailable: tuple[str, ...] = ()

    @property
    def cpu_seconds_per_event(self) -> float | None:
        if self.events_processed <= 0:
            return None
        return self.cpu_seconds / self.events_processed

    @property
    def events_per_second(self) -> float | None:
        if self.wall_seconds <= 0:
            return None
        return self.events_processed / self.wall_seconds

    def to_dict(self) -> dict[str, Any]:
        return {
            "idle_rss_bytes": self.idle_rss_bytes,
            "peak_rss_bytes": self.peak_rss_bytes,
            "peak_sampled_rss_bytes": self.peak_sampled_rss_bytes,
            "pss_bytes": self.pss_bytes,
            "delta_rss_bytes": self.delta_rss_bytes,
            "cpu_seconds": self.cpu_seconds,
            "wall_seconds": self.wall_seconds,
            "events_processed": self.events_processed,
            "cpu_seconds_per_event": self.cpu_seconds_per_event,
            "events_per_second": self.events_per_second,
            "startup_seconds": self.startup_seconds,
            "sample_count": self.sample_count,
            "unavailable": list(self.unavailable),
        }


class ResourceSampler:
    """Context manager that samples RSS on a background thread while work runs.

    Peak RSS from ``getrusage`` is a high-water mark for the whole process
    lifetime, which over-reports when the harness itself allocated earlier. The
    sampled peak is scoped to the measured region, so both are recorded and the
    difference stays visible.
    """

    def __init__(self, *, interval_seconds: float = 0.01) -> None:
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be > 0")
        self._interval = interval_seconds
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._samples: list[int] = []
        self._start_rss: int | None = None
        self._start_wall = 0.0
        self._start_cpu = 0.0
        self._elapsed_wall = 0.0
        self._elapsed_cpu = 0.0

    def __enter__(self) -> ResourceSampler:
        self._start_rss = read_rss_bytes()
        self._stop.clear()
        self._samples = []
        if self._start_rss is not None:
            self._thread = threading.Thread(target=self._run, name="rss-sampler", daemon=True)
            self._thread.start()
        self._start_wall = time.perf_counter()
        self._start_cpu = time.process_time()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self._elapsed_cpu = time.process_time() - self._start_cpu
        self._elapsed_wall = time.perf_counter() - self._start_wall
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    def _run(self) -> None:
        while not self._stop.is_set():
            value = read_rss_bytes()
            if value is not None:
                self._samples.append(value)
            self._stop.wait(self._interval)

    def result(self, *, events_processed: int, startup_seconds: float | None) -> ResourceMetrics:
        end_rss = read_rss_bytes()
        pss = read_pss_bytes()
        peak = _peak_rss_bytes()
        unavailable: list[str] = []
        if end_rss is None:
            unavailable.append("rss")
        if pss is None:
            unavailable.append("pss")
        if peak is None:
            unavailable.append("peak_rss")
        delta = (
            end_rss - self._start_rss
            if end_rss is not None and self._start_rss is not None
            else None
        )
        return ResourceMetrics(
            idle_rss_bytes=self._start_rss,
            peak_rss_bytes=peak,
            peak_sampled_rss_bytes=max(self._samples) if self._samples else None,
            pss_bytes=pss,
            delta_rss_bytes=delta,
            cpu_seconds=self._elapsed_cpu,
            wall_seconds=self._elapsed_wall,
            events_processed=events_processed,
            startup_seconds=startup_seconds,
            sample_count=len(self._samples),
            unavailable=tuple(unavailable),
        )


@dataclass(frozen=True, slots=True)
class HostFacts:
    """Hardware context a result is only comparable within (spec section 13)."""

    cpu_count: int | None = field(default_factory=os.cpu_count)
    total_ram_bytes: int | None = None
    kernel: str = ""
    machine: str = ""

    @classmethod
    def capture(cls) -> HostFacts:
        return cls(
            cpu_count=os.cpu_count(),
            total_ram_bytes=_read_kb_field("/proc/meminfo", "MemTotal:"),
            kernel=platform.release(),
            machine=platform.machine(),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "cpu_count": self.cpu_count,
            "total_ram_bytes": self.total_ram_bytes,
            "kernel": self.kernel,
            "machine": self.machine,
        }
