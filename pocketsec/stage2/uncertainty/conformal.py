"""D2.9 (part) — split-conformal intervals over a bounded residual reservoir.

A calibrated point estimate still says nothing about how wrong it might be. Split
conformal prediction gives a finite-sample interval with a distribution-free
coverage guarantee, and it needs no model internals — only a bag of past
nonconformity scores. That makes it the one interval construction that fits on
the endpoint: no gradients, no second model, no third-party library.

The reservoir is **bounded** because the 2 GB host target is a hard constraint
(``planning/MEMORY.md``). Unbounded calibration sets are the usual way a
conformal implementation quietly becomes the largest object in a process.

What this module refuses to do:

* It refuses to produce an interval with no calibration data. A zero-width
  interval around a point claims certainty, which is the opposite of what the
  caller asked for, so ``interval`` raises instead.
* It refuses to report coverage it did not measure: ``empirical_coverage`` is
  ``None`` unless a labelled set was actually scored against the fitted
  quantile.
* It refuses to hide the cost of the bound. Once the reservoir is full, further
  residuals enter by **reservoir sampling** (Vitter's Algorithm R), so what is
  retained stays a uniform sample of the whole stream and the rank-α order
  statistic of the reservoir estimates the rank-α order statistic of the stream.
  The subsampling is still counted in ``evictions()`` and flagged by
  ``saturated()``, because an estimate from 1024 of 4323 residuals is an
  estimate.

  The previous policy kept both tails and deleted the sample nearest the median.
  Its docstring called that "biased upward ... conservative rather than
  anti-conservative", which understated it by an order of magnitude: hollowing
  out the middle makes the rank-0.9 order statistic of the retained set roughly
  the 99th percentile of the stream, so a nominal 90 % interval became a ~99.5 %
  one on any stream longer than ``MAX_CALIBRATION``. Measured on the Stage 2
  gate's own split (4323 residuals, cap 1024): radius 2.250000 and coverage
  0.9793 under the old policy against radius 0.750000 and coverage 0.9167 with
  the cap lifted — so G2.5's only failing clause was a property of this module's
  eviction rule, reported as a property of the predictor's calibration (S2-04).

Reservoir sampling needs randomness, so the sampler is seeded at construction
and the stream order fixes the result: the same residuals in the same order
always produce the same reservoir, which is what the reproducibility policy
requires.
"""

from __future__ import annotations

import bisect
import math
import random
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from pocketsec.stage0.contracts.common import ContractError

__all__ = [
    "ConformalInterval",
    "MAX_CALIBRATION",
    "NOMINAL_COVERAGE",
    "RESERVOIR_SEED",
    "SplitConformal",
]

#: Bounded by the 2 GB target: 1024 floats is 8 KB of residuals per predictor.
MAX_CALIBRATION = 1024
NOMINAL_COVERAGE = 0.9

#: Fixed seed for the reservoir sampler. Reproducibility policy: the same
#: residual stream must always yield the same reservoir, so the randomness that
#: makes the subsample unbiased may not also make the result unrepeatable.
RESERVOIR_SEED = 11


@dataclass(frozen=True, slots=True)
class ConformalInterval:
    """An interval plus the provenance needed to judge it.

    ``calibration_size`` travels with the interval because a split-conformal
    guarantee is a function of the calibration count: at n = 4 the tightest
    honest level is 0.8, and an interval that does not carry n invites its reader
    to assume the nominal level was achievable.
    """

    lower: float
    upper: float
    nominal_coverage: float
    empirical_coverage: float | None
    calibration_size: int

    @property
    def width(self) -> float:
        return self.upper - self.lower

    def contains(self, value: float) -> bool:
        return self.lower <= value <= self.upper

    def to_dict(self) -> dict[str, Any]:
        return {
            "lower": self.lower,
            "upper": self.upper,
            "nominal_coverage": self.nominal_coverage,
            "empirical_coverage": self.empirical_coverage,
            "calibration_size": self.calibration_size,
            "width": self.width,
        }


class SplitConformal:
    """Absolute-residual split conformal with a bounded, sorted reservoir."""

    __slots__ = ("_nominal", "_capacity", "_residuals", "_evictions", "_seen", "_rng")

    def __init__(
        self,
        *,
        nominal_coverage: float = NOMINAL_COVERAGE,
        max_calibration: int = MAX_CALIBRATION,
        seed: int = RESERVOIR_SEED,
    ) -> None:
        if not 0.0 < nominal_coverage < 1.0:
            raise ContractError(
                f"nominal_coverage must be in (0, 1), got {nominal_coverage!r}"
            )
        if not isinstance(max_calibration, int) or isinstance(max_calibration, bool):
            raise ContractError(f"max_calibration must be an int, got {max_calibration!r}")
        if max_calibration < 1:
            raise ContractError(f"max_calibration must be >= 1, got {max_calibration}")
        self._nominal = float(nominal_coverage)
        self._capacity = max_calibration
        self._residuals: list[float] = []
        self._evictions = 0
        self._seen = 0
        self._rng = random.Random(seed)

    # --- fitting -------------------------------------------------------------

    def fit(self, residuals: Sequence[float]) -> None:
        """Add absolute nonconformity scores to the reservoir.

        Additive rather than replacing, so a long-running endpoint accumulates
        calibration data without ever holding more than ``max_calibration`` of
        it. Signed residuals are accepted and stored as ``abs(r)``: the interval
        is two-sided, so the sign carries no information the quantile can use.
        """
        for index, residual in enumerate(residuals):
            if isinstance(residual, bool) or not isinstance(residual, (int, float)):
                raise ContractError(f"residuals[{index}] must be a number, got {residual!r}")
            numeric = float(residual)
            if not math.isfinite(numeric):
                raise ContractError(f"residuals[{index}] must be finite, got {residual!r}")
            self._insert(abs(numeric))

    def _insert(self, residual: float) -> None:
        """Reservoir sampling (Algorithm R) into a list kept sorted for quantiles.

        Below capacity every residual is kept. At capacity the *k*-th residual
        (1-based, k > capacity) replaces a uniformly chosen incumbent with
        probability ``capacity / k`` and is otherwise dropped, which is exactly
        the rule that leaves the retained set a uniform sample of the stream.
        A uniform sample is what makes the rank-α order statistic of the
        reservoir an estimate of the stream's — the property the old
        median-closest eviction destroyed (S2-04).
        """
        self._seen += 1
        if len(self._residuals) < self._capacity:
            bisect.insort(self._residuals, residual)
            return
        self._evictions += 1
        index = self._rng.randrange(self._seen)
        if index >= self._capacity:
            return  # the new residual is the one dropped
        del self._residuals[index]
        bisect.insort(self._residuals, residual)

    # --- use -----------------------------------------------------------------

    def quantile(self) -> float | None:
        """The conformal quantile, or ``None`` when nothing has been fitted.

        Uses the finite-sample index ceil((n + 1) * coverage), clamped to n. When
        the clamp bites — n too small for the requested level — the widest
        observed residual is returned and the honest coverage is below nominal;
        ``calibration_size`` on the interval is what lets a reader see that.
        """
        count = len(self._residuals)
        if count == 0:
            return None
        rank = math.ceil((count + 1) * self._nominal)
        index = min(max(rank, 1), count) - 1
        return self._residuals[index]

    def interval(
        self, point: float, *, empirical_coverage: float | None = None
    ) -> ConformalInterval:
        """Two-sided interval around ``point``.

        ``empirical_coverage`` stays ``None`` unless the caller measured it with
        :meth:`coverage`: coverage is a property of a labelled set, never of a
        single interval, and filling it in from the nominal level would be a
        fabricated measurement.
        """
        radius = self.quantile()
        if radius is None:
            raise ContractError(
                "SplitConformal has no calibration residuals; an interval built from "
                "nothing would claim zero width, i.e. certainty"
            )
        if isinstance(point, bool) or not isinstance(point, (int, float)):
            raise ContractError(f"point must be a number, got {point!r}")
        centre = float(point)
        if not math.isfinite(centre):
            raise ContractError(f"point must be finite, got {point!r}")
        if empirical_coverage is not None and not 0.0 <= float(empirical_coverage) <= 1.0:
            raise ContractError(
                f"empirical_coverage must be in [0, 1], got {empirical_coverage!r}"
            )
        return ConformalInterval(
            lower=centre - radius,
            upper=centre + radius,
            nominal_coverage=self._nominal,
            empirical_coverage=(
                None if empirical_coverage is None else float(empirical_coverage)
            ),
            calibration_size=len(self._residuals),
        )

    def coverage(self, labels: Sequence[int], scores: Sequence[float]) -> float | None:
        """Fraction of labelled points the fitted interval actually covers.

        ``None`` — never 0.0 — when there is nothing to measure: an unfitted
        reservoir or an empty evaluation set. 0.0 is reserved for "measured, and
        it covered nothing", which is a very different result.
        """
        if len(labels) != len(scores):
            raise ContractError(
                f"labels and scores must align, got {len(labels)} and {len(scores)}"
            )
        radius = self.quantile()
        if radius is None or not labels:
            return None
        covered = 0
        for label, score in zip(labels, scores, strict=True):
            if isinstance(score, bool) or not isinstance(score, (int, float)):
                raise ContractError(f"scores must be numbers, got {score!r}")
            if abs(float(label) - float(score)) <= radius:
                covered += 1
        return covered / len(labels)

    # --- accounting ----------------------------------------------------------

    def residual_count(self) -> int:
        return len(self._residuals)

    def observed(self) -> int:
        """Residuals ever offered, including the evicted ones."""
        return self._seen

    def evictions(self) -> int:
        """Residuals the reservoir sampler declined to retain."""
        return self._evictions

    def saturated(self) -> bool:
        """True once the reservoir is subsampling the stream rather than holding it.

        The quantile is then an *estimate* from ``residual_count()`` of
        ``observed()`` residuals rather than the whole stream's order statistic.
        Reservoir sampling makes that estimate unbiased, not exact, so a caller
        quoting a coverage number measured here should quote this flag with it.
        """
        return self._evictions > 0

    def truncated(self) -> bool:
        """Alias of :meth:`saturated`, matching the Stage 0 bounded-window vocabulary."""
        return self.saturated()

    def memory_bytes(self) -> int:
        """Computed from the bound, not estimated."""
        return len(self._residuals) * 8 + 5 * 8

    def to_dict(self) -> dict[str, Any]:
        return {
            "nominal_coverage": self._nominal,
            "capacity": self._capacity,
            "residuals": len(self._residuals),
            "observed": self._seen,
            "evictions": self._evictions,
            "saturated": self.saturated(),
            "quantile": self.quantile(),
            "memory_bytes": self.memory_bytes(),
        }
