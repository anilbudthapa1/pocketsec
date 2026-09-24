"""D2.9 (part) — calibration metrics, and an isotonic map that refuses to lie.

Stage 1 ships ``calibration_id=None`` in both of its slots, honestly: nothing in
Stage 0 or Stage 1 ever fitted a map from a raw score to an empirical event
rate, so no slot could name one. This module is where Stage 2 earns the right to
emit an id — **for its own outputs only**.

Why this is not a duplicate harness: Stage 0's ``benchmark.security_metrics``
measures *ranking* (PR-AUC, recall at an FP budget) and has no ECE, no Brier
score, no reliability bins and no conformal machinery. Calibration asks a
different question — "when this scorer says 0.7, does the event happen 70 % of
the time?" — and ranking quality answers none of it. An isotonic map is monotone
and therefore *cannot* change a ranking, yet a perfectly ranking scorer can be
arbitrarily miscalibrated. Both numbers are needed and neither substitutes.

What this module refuses to do, each refusal paid for by a real wrong answer:

* It refuses a **single-class fit**. Stage 1's Information Guillotine gave a
  confident wrong answer exactly this way (``planning/MEMORY.md``, trap 2): a
  benign-only fit split produced an inverted ranking and a PR-AUC below the base
  rate. A map fitted on one class is indistinguishable from a constant, so the
  fit is refused, ``calibration_id`` stays ``None`` and ``refusal_reason`` says
  why.
* It refuses to report **0.0 for a metric it could not compute**. "No positive
  samples" is ``None``; "measured, and the answer is zero" is ``0.0``. Reporting
  either as the other is the same class of error (ADR-0004), so the two are kept
  apart and both are tested.
* It refuses to hand out an id, or to pass a score through, for an unfitted map.
  A silent pass-through that carries a plausible id is precisely the failure this
  module exists to prevent.
"""

from __future__ import annotations

import bisect
import hashlib
import json
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from pocketsec.stage0.contracts.common import ContractError

__all__ = [
    "CALIBRATION_ID_PREFIX",
    "CALIBRATOR_JSON_VERSION",
    "CalibrationReport",
    "DEFAULT_BINS",
    "IsotonicCalibrator",
    "MIN_FIT_SAMPLES",
    "ReliabilityBin",
    "brier_score",
    "expected_calibration_error",
    "max_calibration_error",
    "reliability_bins",
]

#: Prefix of every Stage 2 calibration id. The suffix identifies the *fitted
#: knots*, so the id changes when the map changes and only then (ADR-0117).
CALIBRATION_ID_PREFIX = "stage2-isotonic"
CALIBRATOR_JSON_VERSION = "stage2-isotonic.1.0.0"
DEFAULT_BINS = 10
#: Below this, a monotone fit is noise. Not a tuned number: it is the smallest
#: count at which a 10-bin reliability diagram can hold more than one sample
#: per occupied bin, and it is reported in ``refusal_reason`` when it bites.
MIN_FIT_SAMPLES = 8
#: Knots are rounded to this many decimals before hashing, so two maps that
#: differ below float noise share an id instead of churning it.
_ID_PRECISION = 6


@dataclass(frozen=True, slots=True)
class ReliabilityBin:
    """One occupied bin of a reliability diagram.

    Empty bins are not emitted: a bin with no samples has no empirical accuracy,
    and inventing 0.0 for it would drag ECE toward whatever the binning happened
    to leave unoccupied.
    """

    lower: float
    upper: float
    count: int
    mean_confidence: float
    empirical_accuracy: float

    @property
    def gap(self) -> float:
        """|claimed - observed| for this bin."""
        return abs(self.mean_confidence - self.empirical_accuracy)

    def to_dict(self) -> dict[str, Any]:
        return {
            "lower": self.lower,
            "upper": self.upper,
            "count": self.count,
            "mean_confidence": self.mean_confidence,
            "empirical_accuracy": self.empirical_accuracy,
            "gap": self.gap,
        }


@dataclass(frozen=True, slots=True)
class CalibrationReport:
    """The outcome of a fit, including the outcome "it was refused".

    Every metric is ``float | None`` and ``calibration_id`` is ``str | None``
    because "could not be computed" is a first-class answer here. A report with
    ``calibration_id is None`` and an empty ``refusal_reason`` is a contract
    violation: a refusal that does not say why is not a refusal, it is a silence.

    ``in_sample`` exists because of a trap measured in this session. Isotonic
    regression's in-sample ECE is **exactly 0.0 by construction**: every point in
    a pooled block receives that block's own empirical rate, so every occupied
    reliability bin is a union of complete blocks and every gap cancels. A report
    from :meth:`IsotonicCalibrator.fit` therefore proves nothing about
    calibration, and a gate reading its ECE would be passing on an algebraic
    identity. Held-out numbers come from :meth:`IsotonicCalibrator.evaluate` and
    carry ``in_sample=False``.
    """

    calibration_id: str | None
    bins: tuple[ReliabilityBin, ...]
    expected_calibration_error: float | None
    max_calibration_error: float | None
    brier_score: float | None
    sample_count: int
    refusal_reason: str = ""
    in_sample: bool = True

    def __post_init__(self) -> None:
        if self.calibration_id is None and not self.refusal_reason:
            raise ContractError(
                "a refused calibration must carry a refusal_reason; "
                "an unexplained None is indistinguishable from a bug"
            )
        if self.calibration_id is not None and self.refusal_reason:
            raise ContractError(
                "a fitted calibration must not carry a refusal_reason "
                f"(got {self.refusal_reason!r})"
            )

    @property
    def fitted(self) -> bool:
        return self.calibration_id is not None

    def to_dict(self) -> dict[str, Any]:
        """Full precision, deliberately.

        The report is the persisted provenance of a calibration map, and rounding
        a persisted map changes its identity. Display rounding belongs to the
        caller that is displaying it.
        """
        return {
            "calibration_id": self.calibration_id,
            "bins": [b.to_dict() for b in self.bins],
            "expected_calibration_error": self.expected_calibration_error,
            "max_calibration_error": self.max_calibration_error,
            "brier_score": self.brier_score,
            "sample_count": self.sample_count,
            "refusal_reason": self.refusal_reason,
            "in_sample": self.in_sample,
        }


def _validated(
    labels: Sequence[int], confidences: Sequence[float]
) -> tuple[tuple[int, ...], tuple[float, ...]]:
    """Reject malformed input loudly rather than scoring it.

    A calibration metric silently computed over misaligned arrays is worse than
    no metric: it looks like evidence.
    """
    if len(labels) != len(confidences):
        raise ContractError(
            f"labels and confidences must align, got {len(labels)} and {len(confidences)}"
        )
    checked_labels: list[int] = []
    for index, label in enumerate(labels):
        if not isinstance(label, int) or int(label) not in (0, 1):
            raise ContractError(f"labels[{index}] must be 0 or 1, got {label!r}")
        checked_labels.append(int(label))
    checked_confidences: list[float] = []
    for index, value in enumerate(confidences):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ContractError(f"confidences[{index}] must be a number, got {value!r}")
        numeric = float(value)
        if not math.isfinite(numeric):
            raise ContractError(f"confidences[{index}] must be finite, got {value!r}")
        if not 0.0 <= numeric <= 1.0:
            raise ContractError(f"confidences[{index}] must be in [0, 1], got {numeric!r}")
        checked_confidences.append(numeric)
    return tuple(checked_labels), tuple(checked_confidences)


def _single_class(labels: Sequence[int]) -> bool:
    return len(set(labels)) < 2


def reliability_bins(
    labels: Sequence[int], confidences: Sequence[float], *, bins: int = DEFAULT_BINS
) -> tuple[ReliabilityBin, ...]:
    """Equal-width reliability bins over [0, 1], empty bins omitted."""
    if not isinstance(bins, int) or isinstance(bins, bool) or bins < 1:
        raise ContractError(f"bins must be a positive int, got {bins!r}")
    checked_labels, checked_confidences = _validated(labels, confidences)
    buckets: list[list[tuple[int, float]]] = [[] for _ in range(bins)]
    for label, confidence in zip(checked_labels, checked_confidences, strict=True):
        index = min(int(confidence * bins), bins - 1)
        buckets[index].append((label, confidence))
    out: list[ReliabilityBin] = []
    for index, bucket in enumerate(buckets):
        if not bucket:
            continue
        count = len(bucket)
        out.append(
            ReliabilityBin(
                lower=index / bins,
                upper=(index + 1) / bins,
                count=count,
                mean_confidence=sum(c for _, c in bucket) / count,
                empirical_accuracy=sum(label for label, _ in bucket) / count,
            )
        )
    return tuple(out)


def _refuse_inconsistent_report(raw: Mapping[str, Any]) -> None:
    """Refuse a deserialised report whose own numbers do not hold together.

    Not a recomputation — the samples are gone by the time a report is
    serialised, so nothing here can re-derive the ECE. What it can do is refuse
    the shapes that are impossible for a genuine report, so a hand-written one
    has to be at least self-consistent rather than merely well-formed
    (S2-AUTH-10):

    * the reliability bins must account for ``sample_count`` exactly, and each
      bin's count must be non-negative;
    * ECE and MCE must be finite and within [0, 1], and MCE >= ECE, because MCE
      is a maximum over the same per-bin gaps ECE averages;
    * the Brier score must be finite and within [0, 1] for probabilities;
    * ``in_sample`` must be a bool — the field that decides whether any of this
      is evidence at all.
    """
    for name in ("expected_calibration_error", "max_calibration_error", "brier_score"):
        value = raw.get(name)
        if value is None:
            continue
        numeric = float(value)
        if not math.isfinite(numeric) or not 0.0 <= numeric <= 1.0:
            raise ContractError(
                f"calibrator report {name} must be within [0, 1], got {value!r}"
            )
    ece, mce = raw.get("expected_calibration_error"), raw.get("max_calibration_error")
    if ece is not None and mce is not None and float(mce) + 1e-12 < float(ece):
        raise ContractError(
            f"calibrator report max_calibration_error {mce} is below its "
            f"expected_calibration_error {ece}; MCE is a maximum over the same "
            "per-bin gaps ECE averages, so this report describes no fit"
        )
    if not isinstance(raw.get("in_sample"), bool):
        raise ContractError(
            f"calibrator report in_sample must be a bool, got "
            f"{raw.get('in_sample')!r}; it is the field that decides whether these "
            "numbers are evidence about calibration at all"
        )
    bins = raw.get("bins") or ()
    counts = [int(entry["count"]) for entry in bins]
    if any(count < 0 for count in counts):
        raise ContractError(f"calibrator report has a negative bin count: {counts}")
    total = sum(counts)
    if total != int(raw.get("sample_count", -1)):
        raise ContractError(
            f"calibrator report bins account for {total} samples but sample_count "
            f"is {raw.get('sample_count')!r}; the bins and the count describe "
            "different fits"
        )


def expected_calibration_error(
    labels: Sequence[int], confidences: Sequence[float], *, bins: int = DEFAULT_BINS
) -> float | None:
    """Count-weighted mean |claimed - observed| over occupied bins.

    ``None`` when the input is empty or single-class — not 0.0. A single-class
    sample cannot separate a calibrated scorer from a constant one, and a 0.0
    here would read as "perfectly calibrated" (the Stage 1 guillotine trap).
    """
    checked_labels, checked_confidences = _validated(labels, confidences)
    if not checked_labels or _single_class(checked_labels):
        return None
    diagram = reliability_bins(checked_labels, checked_confidences, bins=bins)
    total = len(checked_labels)
    return sum(b.count / total * b.gap for b in diagram)


def max_calibration_error(
    labels: Sequence[int], confidences: Sequence[float], *, bins: int = DEFAULT_BINS
) -> float | None:
    """Worst occupied-bin gap. ``None`` under the same refusals as ECE."""
    checked_labels, checked_confidences = _validated(labels, confidences)
    if not checked_labels or _single_class(checked_labels):
        return None
    diagram = reliability_bins(checked_labels, checked_confidences, bins=bins)
    return max((b.gap for b in diagram), default=0.0)


def brier_score(labels: Sequence[int], confidences: Sequence[float]) -> float | None:
    """Mean squared error of a probabilistic claim.

    ``None`` on empty or single-class input, for the same reason as ECE: the
    Brier score of a one-class sample is minimised by a constant, so it grades
    the label distribution rather than the scorer. 0.0 is returned only when it
    was actually measured as zero.
    """
    checked_labels, checked_confidences = _validated(labels, confidences)
    if not checked_labels or _single_class(checked_labels):
        return None
    return sum(
        (confidence - label) ** 2
        for label, confidence in zip(checked_labels, checked_confidences, strict=True)
    ) / len(checked_labels)


def _pool_adjacent_violators(
    labels: Sequence[int], scores: Sequence[float]
) -> tuple[tuple[float, float], ...]:
    """Isotonic regression by PAV, returning ``(x, y)`` knots.

    Tied scores are grouped *before* pooling. Without that, two samples sharing a
    score can land in separate blocks whose means already increase, so PAV sees
    nothing to fix and the resulting map is two-valued at one x — non-monotone as
    a function, which is the whole property this is here to guarantee.
    """
    grouped: dict[float, list[int]] = {}
    for label, score in zip(labels, scores, strict=True):
        grouped.setdefault(score, []).append(label)
    # blocks: [x_lo, x_hi, sum_y, count]
    blocks: list[list[float]] = []
    for score in sorted(grouped):
        members = grouped[score]
        blocks.append([score, score, float(sum(members)), float(len(members))])
        while len(blocks) >= 2 and (
            blocks[-2][2] / blocks[-2][3] > blocks[-1][2] / blocks[-1][3] + 1e-12
        ):
            right = blocks.pop()
            left = blocks.pop()
            blocks.append(
                [left[0], right[1], left[2] + right[2], left[3] + right[3]]
            )
    # Two knots per pooled block, at its x boundaries, both carrying the block's
    # value. That makes the map *constant inside a block* and interpolated only
    # in the gaps between blocks. Interpolating across a block instead (one knot
    # at its centroid) is what produced a measured in-sample ECE of 0.114 on a
    # 5-distinct-value score: samples inside a block were mapped to values their
    # own block rate contradicts.
    knots: list[tuple[float, float]] = []
    for x_lo, x_hi, sum_y, count in blocks:
        value = sum_y / count
        knots.append((x_lo, value))
        if x_hi > x_lo:
            knots.append((x_hi, value))
    return tuple(knots)


class IsotonicCalibrator:
    """Pool-adjacent-violators, pure stdlib, shipped as plain data.

    The map is generic on purpose: it fits a monotone function from a raw score
    to the empirical rate of whatever binary event the labels encode. Stage 2
    uses it in two modes and the caller decides which:

    * confidence -> P(prediction was correct), which is what abstention needs;
    * score -> P(positive), which is what a hazard estimate needs.

    It is deliberately *not* a frozen dataclass: a fitted calibrator has state,
    and pretending otherwise would mean rebuilding the map on every apply.
    """

    __slots__ = ("_knots", "_xs", "_id", "_report")

    def __init__(self) -> None:
        self._knots: tuple[tuple[float, float], ...] = ()
        self._xs: tuple[float, ...] = ()
        self._id: str | None = None
        self._report: CalibrationReport | None = None

    def _install(self, knots: tuple[tuple[float, float], ...]) -> None:
        """Adopt a knot set, precomputing the lookup axis and the id.

        The id is computed **once** here rather than on every call. Measured in
        this session: hashing the knots inside ``calibration_id()`` on every
        event cost 636 µs/event against 15 µs with it cached — 40× the whole rest
        of the estimate, for a string that never changes between fits.
        """
        self._knots = knots
        self._xs = tuple(x for x, _ in knots)
        if not knots:
            self._id = None
            return
        payload = json.dumps(
            [[round(x, _ID_PRECISION), round(y, _ID_PRECISION)] for x, y in knots],
            separators=(",", ":"),
        )
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        self._id = f"{CALIBRATION_ID_PREFIX}-{digest[:12]}"

    # --- fitting -------------------------------------------------------------

    def fit(self, labels: Sequence[int], scores: Sequence[float]) -> CalibrationReport:
        """Fit the map, or refuse and say why.

        On refusal the calibrator is left *unfitted* rather than partly fitted: a
        half-built map that answers ``apply`` is the thing this refuses to be.

        The returned report is ``in_sample=True`` and its ECE is 0.0 by
        construction (see :class:`CalibrationReport`). **It is not evidence.**
        Use :meth:`evaluate` on data the map never saw for any reported ECE,
        including G2.5's.
        """
        checked_labels, checked_scores = _validated(labels, scores)
        refusal = self._refusal_reason(checked_labels)
        if refusal:
            self._install(())
            self._report = CalibrationReport(
                calibration_id=None,
                bins=(),
                expected_calibration_error=None,
                max_calibration_error=None,
                brier_score=None,
                sample_count=len(checked_labels),
                refusal_reason=refusal,
            )
            return self._report

        self._install(_pool_adjacent_violators(checked_labels, checked_scores))
        calibrated = tuple(self.apply(score) for score in checked_scores)
        self._report = CalibrationReport(
            calibration_id=self.calibration_id(),
            bins=reliability_bins(checked_labels, calibrated),
            expected_calibration_error=expected_calibration_error(checked_labels, calibrated),
            max_calibration_error=max_calibration_error(checked_labels, calibrated),
            brier_score=brier_score(checked_labels, calibrated),
            sample_count=len(checked_labels),
        )
        return self._report

    def evaluate(self, labels: Sequence[int], scores: Sequence[float]) -> CalibrationReport:
        """Score the fitted map on data it never saw. This is the honest report.

        Refuses, rather than returning zeros, when the map is unfitted or the
        evaluation split is single-class — the same two refusals as :meth:`fit`,
        for the same reason: a metric computed on one class grades the label
        distribution, not the map.
        """
        checked_labels, checked_scores = _validated(labels, scores)
        reason = ""
        if not self._knots:
            reason = (
                "unfitted calibrator cannot be evaluated; refusal: "
                f"{self._report.refusal_reason if self._report else 'fit() never called'}"
            )
        elif not checked_labels:
            reason = "no samples: an empty evaluation split measures nothing"
        elif _single_class(checked_labels):
            reason = (
                f"single-class evaluation refused: every label is {checked_labels[0]}"
            )
        if reason:
            return CalibrationReport(
                calibration_id=None,
                bins=(),
                expected_calibration_error=None,
                max_calibration_error=None,
                brier_score=None,
                sample_count=len(checked_labels),
                refusal_reason=reason,
                in_sample=False,
            )
        calibrated = tuple(self.apply(score) for score in checked_scores)
        return CalibrationReport(
            calibration_id=self.calibration_id(),
            bins=reliability_bins(checked_labels, calibrated),
            expected_calibration_error=expected_calibration_error(checked_labels, calibrated),
            max_calibration_error=max_calibration_error(checked_labels, calibrated),
            brier_score=brier_score(checked_labels, calibrated),
            sample_count=len(checked_labels),
            in_sample=False,
        )

    @staticmethod
    def _refusal_reason(labels: Sequence[int]) -> str:
        if not labels:
            return "no samples: a calibration map cannot be fitted on an empty split"
        if len(labels) < MIN_FIT_SAMPLES:
            return (
                f"insufficient samples: {len(labels)} < MIN_FIT_SAMPLES={MIN_FIT_SAMPLES}; "
                "a monotone fit on this few points is noise"
            )
        if _single_class(labels):
            only = labels[0]
            return (
                f"single-class fit refused: every label is {only}. A map fitted on one "
                "class is indistinguishable from a constant (Stage 1 guillotine trap 2)"
            )
        return ""

    # --- use -----------------------------------------------------------------

    def apply(self, score: float) -> float:
        """Map a raw score onto the fitted empirical rate.

        Raises when unfitted. Returning ``score`` unchanged would be a
        pass-through wearing a calibrated coat, and downstream code has no way to
        tell the difference — so it does not get the chance.
        """
        if not self._knots:
            raise ContractError(
                "calibrator is not fitted; "
                f"refusal: {self._report.refusal_reason if self._report else 'fit() never called'}"
            )
        if isinstance(score, bool) or not isinstance(score, (int, float)):
            raise ContractError(f"score must be a number, got {score!r}")
        numeric = float(score)
        if not math.isfinite(numeric):
            raise ContractError(f"score must be finite, got {score!r}")
        if numeric <= self._xs[0]:
            return self._knots[0][1]
        if numeric >= self._xs[-1]:
            return self._knots[-1][1]
        # Binary search, not a scan: apply() runs once per event on the endpoint
        # and the knot count grows with the calibration split.
        index = bisect.bisect_right(self._xs, numeric)
        left_x, left_y = self._knots[index - 1]
        right_x, right_y = self._knots[index]
        span = right_x - left_x
        if span <= 0.0:
            return right_y
        return left_y + (numeric - left_x) / span * (right_y - left_y)

    def calibration_id(self) -> str | None:
        """``stage2-isotonic-<sha256(knots)[:12]>``, or ``None`` when unfitted.

        Computed at install time (see :meth:`_install`) so that reading it on the
        hot path costs an attribute load rather than a hash.
        """
        return self._id

    def report(self) -> CalibrationReport | None:
        return self._report

    def knots(self) -> tuple[tuple[float, float], ...]:
        return self._knots

    def memory_bytes(self) -> int:
        """Two floats per knot, plus the id string. Computed, not guessed."""
        return len(self._knots) * 2 * 8 + len(self.calibration_id() or "")

    # --- plain-data transport ------------------------------------------------

    def to_json(self) -> str:
        """The map as JSON so it ships as data, not as a live Python object."""
        return json.dumps(
            {
                "version": CALIBRATOR_JSON_VERSION,
                "calibration_id": self.calibration_id(),
                "knots": [[x, y] for x, y in self._knots],
                "report": self._report.to_dict() if self._report is not None else None,
            },
            separators=(",", ":"),
        )

    @classmethod
    def from_json(cls, payload: str) -> IsotonicCalibrator:
        """Rebuild from ``to_json``, verifying the id rather than trusting it."""
        try:
            data = json.loads(payload)
        except json.JSONDecodeError as exc:  # pragma: no cover - message passthrough
            raise ContractError(f"calibrator payload is not JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ContractError("calibrator payload must be a JSON object")
        if data.get("version") != CALIBRATOR_JSON_VERSION:
            raise ContractError(
                f"unknown calibrator payload version {data.get('version')!r}; "
                f"expected {CALIBRATOR_JSON_VERSION}"
            )
        knots = tuple((float(x), float(y)) for x, y in data.get("knots") or ())
        for (left_x, left_y), (right_x, right_y) in zip(knots, knots[1:], strict=False):
            if right_x < left_x or right_y < left_y - 1e-12:
                raise ContractError(
                    "calibrator knots must be non-decreasing in both axes; "
                    f"got ({left_x}, {left_y}) then ({right_x}, {right_y})"
                )
        restored = cls()
        restored._install(knots)
        raw_report = data.get("report")
        if raw_report is not None:
            # The report is rebuilt from the same untrusted payload as the knots,
            # so it has to be tied to them the same way. Verifying the top-level
            # `calibration_id` against the knots while copying
            # `expected_calibration_error`, `brier_score`, `sample_count` and —
            # critically — `in_sample` verbatim left the one field that says
            # whether these numbers mean anything entirely attacker-chosen: an
            # in-sample report relabelled `in_sample: false` reads as held-out
            # evidence (S2-AUTH-10).
            if raw_report["calibration_id"] != data.get("calibration_id"):
                raise ContractError(
                    f"calibrator report claims calibration_id "
                    f"{raw_report['calibration_id']!r} but the payload declares "
                    f"{data.get('calibration_id')!r}; a report that does not belong "
                    "to these knots is not evidence about them"
                )
            _refuse_inconsistent_report(raw_report)
            restored._report = CalibrationReport(
                calibration_id=raw_report["calibration_id"],
                bins=tuple(
                    ReliabilityBin(
                        lower=b["lower"],
                        upper=b["upper"],
                        count=b["count"],
                        mean_confidence=b["mean_confidence"],
                        empirical_accuracy=b["empirical_accuracy"],
                    )
                    for b in raw_report["bins"]
                ),
                expected_calibration_error=raw_report["expected_calibration_error"],
                max_calibration_error=raw_report["max_calibration_error"],
                brier_score=raw_report["brier_score"],
                sample_count=raw_report["sample_count"],
                refusal_reason=raw_report["refusal_reason"],
                in_sample=raw_report["in_sample"],
            )
        declared = data.get("calibration_id")
        if declared != restored.calibration_id():
            raise ContractError(
                f"calibration_id {declared!r} does not match the knots it claims to "
                f"identify ({restored.calibration_id()!r})"
            )
        return restored
