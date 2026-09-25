"""Epoch-conditioned calibration monitoring (architecture §32).

Confidence is not stationary across host changes, so calibration here is keyed on
Stage 1's ``Epoch`` (``stage1/epoch/model.py:105``) rather than measured once and
trusted forever. §32 also makes calibration error itself a security signal: when it
rises, uncertainty must widen and abstention must rise. Those are the two monotonicity
properties this module exists to provide, and they are asserted as inequalities in
``tests/test_stage4_resolution.py`` rather than described here and hoped for.

The refusal that matters most: **``ece`` is ``None`` below
``CALIBRATION_BINS * 5`` samples, never 0.0.** Stage 2's G2.5 recorded a held-out ECE
of exactly 0.0 and a Brier of exactly 0.0 on a perfectly separable split (cited from
`MEMORY.md`, not measured here). Those numbers looked like excellent calibration and
were a saturation artifact. Returning ``None`` and failing the check is the correction,
and ``None`` never means zero (ADR-0004). While ``ece`` is ``None``, ``calibration_id``
stays ``None``, which is what keeps ``ThreatPredictionV1.calibration_id`` honest.

State is bounded twice over: ``MAX_CALIBRATION_HISTORY`` samples per epoch in a ring
buffer, and ``MAX_TRACKED_EPOCHS`` epochs, with evictions counted rather than silent.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Any

from pocketsec.stage0.contracts.common import (
    ContractError,
    require_finite_unit_interval,
    require_non_negative_int,
)
from pocketsec.stage1.epoch.model import Epoch

__all__ = [
    "CALIBRATION_ALERT_ECE",
    "CALIBRATION_BINS",
    "MAX_CALIBRATION_HISTORY",
    "MAX_TRACKED_EPOCHS",
    "MAX_UNCERTAINTY_WIDENING",
    "MIN_CALIBRATION_SAMPLES",
    "UNMEASURED_ABSTENTION_PRESSURE",
    "CalibrationReport",
    "EpochCalibration",
    "epoch_key",
]

#: Equal-width reliability bins over [0, 1].
CALIBRATION_BINS: int = 10

#: Samples retained per epoch, ring-buffered. The oldest sample is dropped, which is
#: the right direction for drift: recent behaviour is what a rotated host is doing now.
MAX_CALIBRATION_HISTORY: int = 512

#: Epochs tracked concurrently. Bounded because epoch ids are attacker-influenceable:
#: a host that can be made to rotate epochs repeatedly must not be able to grow this
#: table without limit.
MAX_TRACKED_EPOCHS: int = 8

#: ECE at or above which calibration is treated as a security signal in its own right.
#: A chosen parameter (spec §9.11).
CALIBRATION_ALERT_ECE: float = 0.15

#: Below this many samples in an epoch, ECE and Brier are ``None``. See the module
#: docstring for the Stage 2 result that made this non-negotiable.
MIN_CALIBRATION_SAMPLES: int = CALIBRATION_BINS * 5

#: Most a rising calibration error may widen a reported uncertainty. Widening is
#: capped so that a bad epoch degrades confidence rather than destroying the signal.
MAX_UNCERTAINTY_WIDENING: float = 0.25

#: Abstention pressure for an epoch whose ECE could not be measured.
#:
#: 1.0, not 0.0. An uncalibrated confidence is not a *good* confidence, and treating
#: "we could not measure it" as "it is fine" is exactly the substitution ADR-0004
#: forbids. This is deliberately the most conservative value available, and it is the
#: standing reason for a wave to go and collect enough samples.
UNMEASURED_ABSTENTION_PRESSURE: float = 1.0

#: MEASURED on this host (Python 3.14.7) by appending 512 ``(float, bool)`` tuples to a
#: ``deque`` and reading ``sys.getsizeof`` before and after, plus ``sys.getsizeof`` of one
#: tuple and of one float. Result: 8.25 bytes of deque slot + 64 bytes tuple + 24 bytes
#: float = 96.25 bytes per sample, rounded up so the figure is an upper bound.
_SAMPLE_BYTES: int = 97

#: MEASURED with the same interpreter: an empty ``deque`` is 760 bytes and a dict slot for
#: eight int keys is 44 bytes each.
_EPOCH_BYTES: int = 804


def epoch_key(epoch: Epoch) -> int:
    """The calibration key for one Stage 1 epoch.

    Exists so that the binding to ``stage1.epoch.model.Epoch`` is visible in this
    module's imports rather than implied by an ``int`` parameter name. **Stage 4 defines
    no epoch type of its own**: epochs are Stage 1's concept, epoch rotation is Stage 1's
    decision, and a parallel Stage 4 epoch would drift from it the first time a host
    changed.
    """
    if not isinstance(epoch, Epoch):
        raise ContractError(f"epoch_key needs a stage1 Epoch, got {type(epoch).__name__}")
    return require_non_negative_int(epoch.epoch_id, "Epoch.epoch_id")


@dataclass(frozen=True, slots=True)
class CalibrationReport:
    """One epoch's reliability picture, with ``None`` where nothing was measured."""

    epoch_id: int
    #: ``(mean_confidence, observed_rate, count)`` per **non-empty** bin. An empty bin
    #: is omitted rather than reported at rate 0.0, because a bin with no samples has
    #: no observed rate and printing one invents a measurement.
    bins: tuple[tuple[float, float, int], ...]
    ece: float | None
    brier: float | None
    samples: int
    #: ``None`` means uncalibrated, and it stays ``None`` while ``ece`` is ``None``.
    calibration_id: str | None = None

    def __post_init__(self) -> None:
        require_non_negative_int(self.epoch_id, "CalibrationReport.epoch_id")
        require_non_negative_int(self.samples, "CalibrationReport.samples")
        if self.ece is not None:
            require_finite_unit_interval(self.ece, "CalibrationReport.ece")
        if self.brier is not None:
            require_finite_unit_interval(self.brier, "CalibrationReport.brier")
        if self.ece is None and self.calibration_id is not None:
            raise ContractError(
                "calibration_id must stay None while ece is None; an id would let a "
                "downstream ThreatPredictionV1 claim to be calibrated when it is not"
            )
        if self.ece is not None and self.samples < MIN_CALIBRATION_SAMPLES:
            raise ContractError(
                f"ece was reported from {self.samples} samples, below "
                f"MIN_CALIBRATION_SAMPLES {MIN_CALIBRATION_SAMPLES}; an under-sampled "
                "ECE is the saturation artifact this contract exists to refuse"
            )

    @property
    def is_measured(self) -> bool:
        return self.ece is not None

    @property
    def alerting(self) -> bool:
        """True only when a *measured* ECE is at or above the alert level.

        An unmeasured epoch is not alerting and is not fine either; that distinction
        lives in ``abstention_pressure``.
        """
        return self.ece is not None and self.ece >= CALIBRATION_ALERT_ECE

    def to_dict(self) -> dict[str, Any]:
        return {
            "epoch_id": self.epoch_id,
            "bins": [[round(c, 6), round(r, 6), n] for c, r, n in self.bins],
            "ece": None if self.ece is None else round(self.ece, 6),
            "brier": None if self.brier is None else round(self.brier, 6),
            "samples": self.samples,
            "calibration_id": self.calibration_id,
        }


class EpochCalibration:
    """Bounded, epoch-keyed calibration history.

    Mutable by design — it is an accumulator of observations, not a contract object —
    but everything it hands out (``CalibrationReport``) is frozen, so a caller cannot
    edit a report and then re-present it as measured.
    """

    __slots__ = ("_history", "_evicted_epochs", "_dropped_samples")

    def __init__(self) -> None:
        self._history: dict[int, deque[tuple[float, bool]]] = {}
        self._evicted_epochs: int = 0
        self._dropped_samples: int = 0

    # --- observation ----------------------------------------------------

    def observe(self, *, epoch_id: int, confidence: float, correct: bool) -> None:
        """Record one prediction's confidence and whether it turned out right."""
        require_non_negative_int(epoch_id, "EpochCalibration.observe.epoch_id")
        require_finite_unit_interval(confidence, "EpochCalibration.observe.confidence")
        if not isinstance(correct, bool):
            raise ContractError("EpochCalibration.observe.correct must be a bool")
        bucket = self._history.get(epoch_id)
        if bucket is None:
            self._evict_if_needed(protect=epoch_id)
            bucket = deque(maxlen=MAX_CALIBRATION_HISTORY)
            self._history[epoch_id] = bucket
        if len(bucket) == MAX_CALIBRATION_HISTORY:
            # deque(maxlen=...) drops silently; counting it is what makes the
            # truncation explicit rather than invisible.
            self._dropped_samples += 1
        bucket.append((float(confidence), correct))

    def _evict_if_needed(self, *, protect: int) -> None:
        while len(self._history) >= MAX_TRACKED_EPOCHS:
            oldest = min(k for k in self._history if k != protect)
            self._history.pop(oldest)
            self._evicted_epochs += 1

    # --- reporting ------------------------------------------------------

    def samples(self, epoch_id: int) -> int:
        return len(self._history.get(epoch_id, ()))

    def report(self, epoch_id: int) -> CalibrationReport:
        """Reliability bins, ECE and Brier for one epoch, or ``None`` if under-sampled."""
        require_non_negative_int(epoch_id, "EpochCalibration.report.epoch_id")
        rows = tuple(self._history.get(epoch_id, ()))
        bins = _reliability_bins(rows)
        if len(rows) < MIN_CALIBRATION_SAMPLES:
            return CalibrationReport(
                epoch_id=epoch_id,
                bins=bins,
                ece=None,
                brier=None,
                samples=len(rows),
                calibration_id=None,
            )
        total = len(rows)
        ece = sum((count / total) * abs(mean_conf - rate) for mean_conf, rate, count in bins)
        brier = sum((conf - (1.0 if correct else 0.0)) ** 2 for conf, correct in rows) / total
        return CalibrationReport(
            epoch_id=epoch_id,
            bins=bins,
            ece=min(1.0, max(0.0, ece)),
            brier=min(1.0, max(0.0, brier)),
            samples=total,
            calibration_id=f"stage4-cal-e{epoch_id}-n{total}",
        )

    # --- §32's two required responses -----------------------------------

    def abstention_pressure(self, epoch_id: int) -> float:
        """Pressure to abstain in [0, 1], non-decreasing in measured calibration error.

        An epoch whose ECE could not be measured returns
        ``UNMEASURED_ABSTENTION_PRESSURE``; see that constant for why the conservative
        value is the honest one.
        """
        report = self.report(epoch_id)
        if report.ece is None:
            return UNMEASURED_ABSTENTION_PRESSURE
        return min(1.0, report.ece / CALIBRATION_ALERT_ECE)

    def widen_uncertainty(self, epoch_id: int, uncertainty: float) -> float:
        """Widen a reported uncertainty in proportion to calibration error (§32).

        Monotone in the abstention pressure and never narrowing: the returned value is
        always ``>= uncertainty``. A calibration monitor that could *reduce* reported
        uncertainty would be a way to launder a miscalibrated model into a confident one.
        """
        require_finite_unit_interval(uncertainty, "EpochCalibration.widen_uncertainty.uncertainty")
        widened = uncertainty + self.abstention_pressure(epoch_id) * MAX_UNCERTAINTY_WIDENING
        return min(1.0, max(float(uncertainty), widened))

    # --- bounds ---------------------------------------------------------

    def memory_bytes(self) -> int:
        """Accounted footprint of the retained history.

        The two per-item constants were measured with ``sys.getsizeof`` on this
        interpreter (the command is in the constant's comment). This is an accounting
        figure for the bounded-state check, not a process RSS measurement — RSS comes
        from ``ResourceSampler`` and from nowhere else.
        """
        return sum(len(rows) * _SAMPLE_BYTES for rows in self._history.values()) + (
            len(self._history) * _EPOCH_BYTES
        )

    def report_bounds(self) -> dict[str, int]:
        return {
            "tracked_epochs": len(self._history),
            "max_tracked_epochs": MAX_TRACKED_EPOCHS,
            "evicted_epochs": self._evicted_epochs,
            "dropped_samples": self._dropped_samples,
            "memory_bytes": self.memory_bytes(),
        }


def _reliability_bins(
    rows: tuple[tuple[float, bool], ...],
) -> tuple[tuple[float, float, int], ...]:
    """Equal-width reliability bins, non-empty ones only, ordered by confidence."""
    buckets: list[list[tuple[float, bool]]] = [[] for _ in range(CALIBRATION_BINS)]
    for confidence, correct in rows:
        index = min(CALIBRATION_BINS - 1, int(confidence * CALIBRATION_BINS))
        buckets[index].append((confidence, correct))
    out: list[tuple[float, float, int]] = []
    for bucket in buckets:
        if not bucket:
            continue
        count = len(bucket)
        mean_conf = sum(c for c, _ in bucket) / count
        rate = sum(1 for _, ok in bucket if ok) / count
        out.append((mean_conf, rate, count))
    return tuple(out)
