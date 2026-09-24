"""Stage 2 D2.9 — calibration, conformal intervals and abstention (DTL-F07).

These tests exist to stop three specific wrong answers, each of which has a
precedent in this repository:

1. A calibration metric reported as 0.0 when it could not be computed, or as
   ``None`` when zero was the honest answer (ADR-0004's reasoning, applied to a
   metric family Stage 0 does not provide).
2. A ``calibration_id`` emitted for a map that was never fitted — the Stage 1
   guillotine's single-class trap, which produced an *inverted* ranking before it
   was pinned by a test.
3. Uncertainty quietly absorbing novelty or Φ, which would make "novel" mean
   "malicious". ``test_uncertainty_value_is_invariant_to_novelty`` and
   ``test_uncertainty_value_ignores_phi`` fail if anyone weakens that.

The last test is a measurement, not an assertion about design: it reports ECE,
Brier and risk–coverage AUC for a calibrated Stage 2 estimate against the
``one_minus_max`` control on a fixed ``(corpus='ambiguous', count=240, seed=11)``
split, because a component with no control implemented is not measured.
"""

from __future__ import annotations

import json
import math
import random
from collections.abc import Sequence
from dataclasses import dataclass

import pytest

from pocketsec.stage0.benchmark.security_metrics import average_precision
from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.novelty.engine import NOVELTY_CONTEXTS, NoveltyTensor
from pocketsec.stage1.ssir.entities import Entity
from pocketsec.stage1.ssir.relations import Relation
from pocketsec.stage1.ssir.transition import SSIRTransitionV1, TemporalContext
from pocketsec.stage1.state.security_state import StateDelta
from pocketsec.stage2.dataset import build_dataset
from pocketsec.stage2.encoder.ssir_encoder import NEED_SIGNAL_INDICES
from pocketsec.stage2.uncertainty.abstention import (
    ABSTAIN_THRESHOLD,
    MAX_SOFTMAX_CONTROL,
    PHI_HIGH,
    STAGE1_PRIOR_KEY,
    EpistemicQuadrant,
    UncertaintyEstimate,
    UncertaintySource,
    estimate_uncertainty,
    one_minus_max,
)
from pocketsec.stage2.uncertainty.calibration import (
    CALIBRATION_ID_PREFIX,
    CalibrationReport,
    IsotonicCalibrator,
    brier_score,
    expected_calibration_error,
    max_calibration_error,
    reliability_bins,
)
from pocketsec.stage2.uncertainty.conformal import ConformalInterval, SplitConformal

# --- fixtures ----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Head:
    """Structural stand-in for ``predictors.heads.HeadPrediction``.

    The uncertainty layer consumes heads structurally so it stays importable and
    testable without the predictors package, which is optional and detached
    (ADR-0009). This stub is that contract, written out.
    """

    probabilities: tuple[float, ...]
    entropy: float = 0.0
    argmax: int = 0


@dataclass(frozen=True, slots=True)
class _Branch:
    probability: float


@dataclass(frozen=True, slots=True)
class _Cone:
    branches: tuple[_Branch, ...]
    unresolved_mass: float


def _uniform_head(classes: int = 4) -> _Head:
    probability = 1.0 / classes
    return _Head(
        probabilities=tuple([probability] * classes),
        entropy=math.log(classes),
    )


def _confident_head(classes: int = 4) -> _Head:
    rest = 0.001 / (classes - 1)
    return _Head(probabilities=(0.999,) + tuple([rest] * (classes - 1)), entropy=0.01)


def _transition(
    *,
    uncertainty: float = 0.1,
    novelty: float = 0.1,
    incomplete: bool = False,
    delta_phi: float = 0.0,
    sequence: int = 0,
) -> SSIRTransitionV1:
    return SSIRTransitionV1(
        actor=Entity(identity="proc:boot-1:101:900"),
        relation=Relation.READ,
        object=Entity(identity="file:/etc/shadow"),
        state_delta=StateDelta(raised={}),
        uncertainty=uncertainty,
        novelty=NoveltyTensor(values={context: novelty for context in NOVELTY_CONTEXTS}),
        causal_signature=f"sig-{sequence}",
        parent_signature="sig-root",
        responsibility=0.2,
        temporal=TemporalContext(),
        evidence=(),
        epoch_id=1,
        sequence=sequence,
        delta_phi=delta_phi,
        observation_incomplete=incomplete,
    )


def _estimate(
    *,
    heads: dict[str, _Head] | None = None,
    cone: _Cone | None = None,
    prototype_distance: float | None = None,
    uncertainty: float = 0.1,
    novelty: float = 0.1,
    incomplete: bool = False,
    calibrator: IsotonicCalibrator | None = None,
    phi_total: float = 0.0,
) -> UncertaintyEstimate:
    """DTL-F07 under test, with the transition fields the case actually varies."""
    return estimate_uncertainty(
        heads=heads,
        cone=cone,
        prototype_distance=prototype_distance,
        transition=_transition(
            uncertainty=uncertainty, novelty=novelty, incomplete=incomplete
        ),
        calibrator=calibrator,
        phi_total=phi_total,
    )


def _calibrated_sample(count: int, seed: int) -> tuple[list[int], list[float]]:
    """Scores that *are* the event probability: a perfectly calibrated scorer."""
    rng = random.Random(seed)
    scores = [rng.random() for _ in range(count)]
    labels = [1 if rng.random() < score else 0 for score in scores]
    return labels, scores


def _risk_coverage_auc(
    uncertainty: Sequence[float], predictions: Sequence[int], labels: Sequence[int]
) -> float:
    """Mean error rate over every coverage level, ordering by ascending uncertainty.

    Lower is better. This is the metric the spec names for abstention (§5): an
    uncertainty signal is useful exactly insofar as dropping its most uncertain
    events removes errors faster than chance would.
    """
    order = sorted(range(len(labels)), key=lambda index: (uncertainty[index], index))
    errors = 0
    total = 0.0
    for covered, index in enumerate(order, start=1):
        errors += 0 if predictions[index] == labels[index] else 1
        total += errors / covered
    return total / len(order)


# --- calibration metrics -----------------------------------------------------


def test_ece_is_zero_for_a_perfectly_calibrated_set() -> None:
    """Zero is a measured answer here, and it must be reachable."""
    labels = [1, 0, 1, 0, 1, 0, 1, 0]
    confidences = [0.5] * 8
    assert expected_calibration_error(labels, confidences) == 0.0
    assert expected_calibration_error([1, 0], [1.0, 0.0]) == 0.0


def test_ece_is_positive_for_a_deliberately_overconfident_set() -> None:
    labels = [1, 1, 0, 0, 1, 0, 1, 0]
    confidences = [0.99] * 8  # claims 99 %, delivers 50 %
    ece = expected_calibration_error(labels, confidences)
    assert ece is not None
    assert ece == pytest.approx(0.49, abs=0.01)
    mce = max_calibration_error(labels, confidences)
    assert mce is not None and mce >= ece


def test_brier_distinguishes_measured_zero_from_unmeasurable() -> None:
    """0.0 and None are different claims and the code must never swap them."""
    assert brier_score([1, 0], [1.0, 0.0]) == 0.0  # measured, and it is zero
    assert brier_score([], []) is None  # nothing to measure
    assert brier_score([0, 0, 0], [0.0, 0.1, 0.2]) is None  # one class only
    assert expected_calibration_error([], []) is None
    assert expected_calibration_error([1, 1, 1], [0.9, 0.9, 0.9]) is None
    assert max_calibration_error([0, 0], [0.0, 0.0]) is None


def test_metric_inputs_are_validated_not_coerced() -> None:
    with pytest.raises(ContractError):
        expected_calibration_error([1, 0], [0.5])
    with pytest.raises(ContractError):
        expected_calibration_error([2, 0], [0.5, 0.5])
    with pytest.raises(ContractError):
        expected_calibration_error([1, 0], [1.5, 0.5])
    with pytest.raises(ContractError):
        expected_calibration_error([1, 0], [float("nan"), 0.5])
    with pytest.raises(ContractError):
        reliability_bins([1, 0], [0.9, 0.1], bins=0)


def test_reliability_bins_omit_empty_bins() -> None:
    bins = reliability_bins([1, 0, 1, 0], [0.95, 0.05, 0.92, 0.02], bins=10)
    assert len(bins) == 2
    assert all(b.count > 0 for b in bins)
    assert sum(b.count for b in bins) == 4


def test_calibration_report_refuses_an_unexplained_none() -> None:
    """A refusal that does not say why is a silence, not a refusal."""
    with pytest.raises(ContractError):
        CalibrationReport(
            calibration_id=None,
            bins=(),
            expected_calibration_error=None,
            max_calibration_error=None,
            brier_score=None,
            sample_count=0,
        )
    with pytest.raises(ContractError):
        CalibrationReport(
            calibration_id="stage2-isotonic-deadbeef1234",
            bins=(),
            expected_calibration_error=0.0,
            max_calibration_error=0.0,
            brier_score=0.0,
            sample_count=10,
            refusal_reason="cannot be both fitted and refused",
        )


# --- the isotonic calibrator -------------------------------------------------


def test_isotonic_fit_is_monotone_non_decreasing() -> None:
    labels, scores = _calibrated_sample(400, seed=11)
    calibrator = IsotonicCalibrator()
    assert calibrator.fit(labels, scores).fitted
    grid = [calibrator.apply(index / 200) for index in range(201)]
    assert all(later >= earlier - 1e-12 for earlier, later in zip(grid, grid[1:]))
    assert all(0.0 <= value <= 1.0 for value in grid)


def test_apply_is_near_idempotent_on_an_already_calibrated_score() -> None:
    """A calibrated scorer should come back roughly unchanged.

    Tolerance, not equality: the map is fitted on 2000 Bernoulli draws, so the
    residual is sampling noise. The measured maximum deviation is reported so a
    regression shows up as a number rather than as a silent loosening.
    """
    labels, scores = _calibrated_sample(2000, seed=11)
    calibrator = IsotonicCalibrator()
    calibrator.fit(labels, scores)
    deviations = [abs(calibrator.apply(x / 100) - x / 100) for x in range(5, 96)]
    worst = max(deviations)
    mean = sum(deviations) / len(deviations)
    print(f"[measured] isotonic idempotence: max_dev={worst:.4f} mean_dev={mean:.4f}")
    assert worst < 0.15
    assert mean < 0.05


def test_single_class_fit_is_refused_and_the_calibrator_stays_unfitted() -> None:
    """Stage 1 guillotine trap 2: a one-class fit inverted a ranking."""
    calibrator = IsotonicCalibrator()
    report = calibrator.fit([1] * 40, [0.4 + index / 100 for index in range(40)])
    assert report.calibration_id is None
    assert not report.fitted
    assert "single-class" in report.refusal_reason
    assert report.expected_calibration_error is None
    assert report.brier_score is None
    assert calibrator.calibration_id() is None
    # The refusal must not degrade into a pass-through that looks calibrated.
    with pytest.raises(ContractError):
        calibrator.apply(0.5)
    with pytest.raises(ContractError):
        calibrator.apply(0.5)


def test_too_few_samples_and_empty_fits_are_refused() -> None:
    for labels, scores in (([], []), ([0, 1, 0], [0.1, 0.9, 0.2])):
        report = IsotonicCalibrator().fit(labels, scores)
        assert report.calibration_id is None
        assert report.refusal_reason


def test_calibration_id_tracks_the_knots_and_nothing_else() -> None:
    labels, scores = _calibrated_sample(400, seed=11)
    first = IsotonicCalibrator()
    first.fit(labels, scores)
    again = IsotonicCalibrator()
    again.fit(labels, scores)
    assert first.calibration_id() == again.calibration_id()
    assert first.calibration_id() is not None
    assert first.calibration_id().startswith(f"{CALIBRATION_ID_PREFIX}-")

    other_labels, other_scores = _calibrated_sample(400, seed=3)
    changed = IsotonicCalibrator()
    changed.fit(other_labels, other_scores)
    assert changed.knots() != first.knots()
    assert changed.calibration_id() != first.calibration_id()


def test_json_round_trip_is_exact_and_verifies_the_id() -> None:
    labels, scores = _calibrated_sample(400, seed=11)
    calibrator = IsotonicCalibrator()
    calibrator.fit(labels, scores)
    payload = calibrator.to_json()
    restored = IsotonicCalibrator.from_json(payload)
    assert restored.to_json() == payload
    assert restored.knots() == calibrator.knots()
    assert restored.calibration_id() == calibrator.calibration_id()
    assert restored.report() is not None
    assert restored.report().to_dict() == calibrator.report().to_dict()
    for probe in (0.0, 0.13, 0.5, 0.87, 1.0):
        assert restored.apply(probe) == calibrator.apply(probe)


def test_from_json_rejects_a_tampered_id_and_non_monotone_knots() -> None:
    """The id must identify the knots, so a mismatch is a hard failure."""
    labels, scores = _calibrated_sample(400, seed=11)
    calibrator = IsotonicCalibrator()
    calibrator.fit(labels, scores)
    data = json.loads(calibrator.to_json())

    tampered = dict(data, calibration_id="stage2-isotonic-000000000000")
    with pytest.raises(ContractError):
        IsotonicCalibrator.from_json(json.dumps(tampered))

    broken = dict(data, knots=[[0.1, 0.9], [0.2, 0.1]])
    with pytest.raises(ContractError):
        IsotonicCalibrator.from_json(json.dumps(broken))

    with pytest.raises(ContractError):
        IsotonicCalibrator.from_json(json.dumps(dict(data, version="nope")))


def test_in_sample_ece_is_structurally_zero_so_evaluate_is_the_honest_report() -> None:
    """The invariant someone could silently weaken, pinned.

    Isotonic regression's in-sample ECE is exactly 0.0 by construction: each
    point receives its own pooled block's empirical rate, so every occupied bin
    is a union of complete blocks. A gate that read ``fit(...).expected_
    calibration_error`` would therefore pass on an algebraic identity. This test
    asserts the identity holds *and* that the held-out report is marked as the
    one that is evidence.
    """
    labels, scores = _calibrated_sample(600, seed=11)
    calibrator = IsotonicCalibrator()
    in_sample = calibrator.fit(labels[:300], scores[:300])
    assert in_sample.in_sample is True
    assert in_sample.expected_calibration_error == 0.0

    held_out = calibrator.evaluate(labels[300:], scores[300:])
    assert held_out.in_sample is False
    assert held_out.expected_calibration_error is not None
    assert held_out.expected_calibration_error > 0.0
    assert held_out.calibration_id == calibrator.calibration_id()


def test_evaluate_refuses_an_unfitted_map_and_a_single_class_split() -> None:
    unfitted = IsotonicCalibrator()
    refusal = unfitted.evaluate([0, 1], [0.1, 0.9])
    assert refusal.calibration_id is None and refusal.refusal_reason
    assert refusal.in_sample is False

    labels, scores = _calibrated_sample(200, seed=11)
    fitted = IsotonicCalibrator()
    fitted.fit(labels, scores)
    one_class = fitted.evaluate([1, 1, 1], [0.2, 0.5, 0.8])
    assert one_class.calibration_id is None
    assert "single-class" in one_class.refusal_reason


# --- split conformal ---------------------------------------------------------


def test_empirical_coverage_is_within_five_points_of_nominal() -> None:
    rng = random.Random(7)
    conformal = SplitConformal(nominal_coverage=0.9, max_calibration=1024)
    conformal.fit([rng.gauss(0.0, 1.0) for _ in range(512)])
    assert not conformal.saturated()
    radius = conformal.quantile()
    assert radius is not None
    fresh = [rng.gauss(0.0, 1.0) for _ in range(2000)]
    covered = sum(1 for residual in fresh if abs(residual) <= radius) / len(fresh)
    print(
        f"[measured] conformal nominal=0.90 empirical={covered:.4f} "
        f"quantile={radius:.4f} n={conformal.residual_count()}"
    )
    assert abs(covered - 0.9) <= 0.05


def test_coverage_over_labels_and_scores_matches_nominal() -> None:
    rng = random.Random(11)
    labels = [index % 2 for index in range(600)]
    scores = [min(1.0, max(0.0, label + rng.gauss(0.0, 0.25))) for label in labels]
    conformal = SplitConformal(nominal_coverage=0.9)
    conformal.fit([label - score for label, score in zip(labels[:300], scores[:300])])
    coverage = conformal.coverage(labels[300:], scores[300:])
    assert coverage is not None
    print(f"[measured] conformal coverage(labels, scores)={coverage:.4f}")
    assert abs(coverage - 0.9) <= 0.05


def test_a_deserialised_calibration_report_must_hold_together() -> None:
    """Pins S2-AUTH-10.

    ``from_json`` verified the ``calibration_id`` against the knots it claims to
    identify — correctly, and it said so — and then rebuilt the attached
    ``CalibrationReport`` verbatim from the same untrusted payload.
    ``expected_calibration_error``, ``max_calibration_error``, ``brier_score``,
    ``sample_count`` and, critically, ``in_sample`` were copied with no check at
    all, so an in-sample report relabelled ``in_sample: false`` read as held-out
    evidence — the exact distinction ``CalibrationReport``'s own docstring
    exists to protect.
    """
    labels, scores = _calibrated_sample(200, seed=3)
    calibrator = IsotonicCalibrator()
    calibrator.fit(labels, scores)
    calibrator.evaluate(*_calibrated_sample(200, seed=5))
    payload = json.loads(calibrator.to_json())
    assert payload["report"] is not None
    assert IsotonicCalibrator.from_json(json.dumps(payload)) is not None

    for field, value in (
        ("in_sample", "false"),
        ("expected_calibration_error", 1.5),
        ("brier_score", -0.1),
        ("sample_count", 99999),
        ("calibration_id", "stage2-isotonic-deadbeefdead"),
    ):
        broken = json.loads(calibrator.to_json())
        broken["report"][field] = value
        with pytest.raises(ContractError):
            IsotonicCalibrator.from_json(json.dumps(broken))

    # MCE is a maximum over the gaps ECE averages, so it can never be below it.
    broken = json.loads(calibrator.to_json())
    broken["report"]["expected_calibration_error"] = 0.4
    broken["report"]["max_calibration_error"] = 0.1
    with pytest.raises(ContractError, match="max_calibration_error"):
        IsotonicCalibrator.from_json(json.dumps(broken))


def test_an_undefined_uncertainty_is_refused_not_reported_as_certainty() -> None:
    """Pins S2-AUTH-03's mirror case.

    ``raw = min(1.0, max(0.0, raw))`` swallowed a NaN into **0.0**, because
    ``max(0.0, nan)`` returns 0.0 in CPython. The estimate then came back with
    ``value=0.0``, ``abstain=False`` and quadrant ``CHEAP_PATH`` — a numerically
    undefined estimate reported as perfect certainty, on the cheapest path, which
    is the exact inversion the "UNKNOWN is a valid output" invariant forbids.

    ``SSIRTransitionV1`` refuses a NaN ``uncertainty`` at its own boundary, so
    the clamp is reached here through a transition-shaped object carrying the
    two fields this function reads — which is what any future caller that
    composes its own prior, or any Stage 1 change that relaxes that field, would
    present. The guard belongs at the clamp because that is where the inversion
    happened.
    """

    @dataclass(frozen=True, slots=True)
    class _Transition:
        uncertainty: float
        observation_incomplete: bool = False

    assert max(0.0, math.nan) == 0.0, "the CPython behaviour this pins"
    with pytest.raises(ContractError, match="non-finite"):
        estimate_uncertainty(
            heads=None,
            cone=None,
            prototype_distance=None,
            transition=_Transition(uncertainty=math.nan),  # type: ignore[arg-type]
            phi_total=0.0,
        )
    # The same call with a finite prior still works, so the guard is a guard and
    # not a blanket refusal.
    fine = estimate_uncertainty(
        heads=None,
        cone=None,
        prototype_distance=None,
        transition=_Transition(uncertainty=0.4),  # type: ignore[arg-type]
        phi_total=0.0,
    )
    assert 0.0 <= fine.value <= 1.0


def test_a_saturated_reservoir_still_estimates_the_nominal_level() -> None:
    """Pins S2-04. The bound must cost precision, never the level itself.

    The old policy kept both tails and deleted the sample nearest the median.
    Its docstring called the result "conservative"; what it actually did was
    turn the rank-0.9 order statistic of the retained set into roughly the 99th
    percentile of the stream, so a nominal 90 % interval became a ~99.5 % one on
    any stream longer than the cap — and the Stage 2 gate then reported that as
    a calibration failure of the ΔΦ predictor.

    MEASURED by running this test (Python 3.14.7, Linux 7.1.5+kali-amd64), 4000
    ``gauss(0, 1)`` residuals at cap 256, evaluated on 2000 fresh draws:

    | reservoir              | quantile | empirical coverage |
    |------------------------|----------|--------------------|
    | bounded (256 of 4000)  | 1.5661   | 0.8800             |
    | unbounded (all 4000)   | 1.6571   | 0.8945             |

    The bounded estimate now tracks the unbounded one instead of standing far
    above it, so the assertion is two-sided: an eviction rule that inflates the
    quantile fails here exactly as one that deflates it does.
    """
    rng = random.Random(3)
    stream = [rng.gauss(0.0, 1.0) for _ in range(4000)]
    conformal = SplitConformal(nominal_coverage=0.9, max_calibration=256)
    conformal.fit(stream)
    assert conformal.residual_count() == 256
    assert conformal.evictions() == 4000 - 256
    assert conformal.observed() == 4000
    assert conformal.saturated() and conformal.truncated()
    assert conformal.memory_bytes() == 256 * 8 + 5 * 8

    unbounded = SplitConformal(nominal_coverage=0.9, max_calibration=4001)
    unbounded.fit(stream)
    assert not unbounded.saturated()

    radius = conformal.quantile()
    reference = unbounded.quantile()
    assert radius is not None and reference is not None
    fresh = [rng.gauss(0.0, 1.0) for _ in range(2000)]
    covered = sum(1 for residual in fresh if abs(residual) <= radius) / len(fresh)
    print(
        f"[measured] saturated reservoir: n=256 evictions={conformal.evictions()} "
        f"quantile={radius:.4f} (unbounded {reference:.4f}) "
        f"empirical_coverage={covered:.4f} (nominal 0.90)"
    )
    assert abs(covered - 0.9) <= 0.05, covered
    # The subsample is an estimate, so it may sit either side of the whole
    # stream's order statistic — but not 3x above it, which is what the old
    # eviction rule produced.
    assert 0.5 * reference <= radius <= 1.5 * reference, (radius, reference)


def test_a_reservoir_is_reproducible_across_instances() -> None:
    """Reservoir sampling introduces randomness; it may not introduce variance.

    Same residuals in the same order must always yield the same reservoir, or a
    conformal radius could not be reproduced from a recorded run.
    """
    rng = random.Random(5)
    stream = [rng.gauss(0.0, 1.0) for _ in range(3000)]
    first = SplitConformal(max_calibration=128)
    second = SplitConformal(max_calibration=128)
    first.fit(stream)
    second.fit(stream)
    assert first.quantile() == second.quantile()
    assert first.to_dict() == second.to_dict()


def test_conformal_refuses_to_invent_an_interval_or_a_coverage() -> None:
    empty = SplitConformal()
    assert empty.quantile() is None
    with pytest.raises(ContractError):
        empty.interval(0.5)
    assert empty.coverage([0, 1], [0.1, 0.9]) is None

    fitted = SplitConformal(nominal_coverage=0.9)
    fitted.fit([0.1, 0.2, 0.3, 0.4, 0.5])
    assert fitted.coverage([], []) is None  # nothing measured, not "zero covered"
    interval = fitted.interval(0.5)
    assert isinstance(interval, ConformalInterval)
    assert interval.empirical_coverage is None  # never fabricated from nominal
    assert interval.calibration_size == 5
    assert interval.contains(0.5) and interval.width > 0.0
    with pytest.raises(ContractError):
        fitted.interval(float("inf"))
    with pytest.raises(ContractError):
        fitted.interval(0.5, empirical_coverage=1.5)
    with pytest.raises(ContractError):
        fitted.fit([float("nan")])
    with pytest.raises(ContractError):
        SplitConformal(nominal_coverage=1.0)
    with pytest.raises(ContractError):
        SplitConformal(max_calibration=0)
    with pytest.raises(ContractError):
        fitted.coverage([0, 1], [0.5])


# --- abstention and the epistemic quadrants ----------------------------------


def test_all_four_quadrants_are_reachable() -> None:
    cheap = _estimate(
        heads={"relation": _confident_head()},
        prototype_distance=0.01,
        uncertainty=0.05,
        phi_total=0.5,
    )
    lazy = _estimate(
        heads={"relation": _uniform_head()},
        uncertainty=0.9,
        incomplete=True,
        phi_total=0.5,
    )
    known_risk = _estimate(
        heads={"relation": _confident_head()},
        prototype_distance=0.01,
        uncertainty=0.05,
        phi_total=PHI_HIGH + 5.0,
    )
    escalate = _estimate(
        heads={"relation": _uniform_head()},
        uncertainty=0.9,
        incomplete=True,
        phi_total=PHI_HIGH + 5.0,
    )
    assert cheap.quadrant is EpistemicQuadrant.CHEAP_PATH
    assert lazy.quadrant is EpistemicQuadrant.OBSERVE_LAZILY
    assert known_risk.quadrant is EpistemicQuadrant.KNOWN_HIGH_RISK
    assert escalate.quadrant is EpistemicQuadrant.ESCALATE
    assert {e.quadrant for e in (cheap, lazy, known_risk, escalate)} == set(EpistemicQuadrant)


def test_abstain_only_in_escalate_and_only_above_the_threshold() -> None:
    escalate = _estimate(
        heads={"relation": _uniform_head()},
        uncertainty=0.9,
        incomplete=True,
        phi_total=PHI_HIGH + 5.0,
    )
    assert escalate.value >= ABSTAIN_THRESHOLD
    assert escalate.abstain is True
    assert "preserve_evidence" in escalate.detail

    # High Φ, uncertain enough for ESCALATE but below the abstention threshold.
    borderline = _estimate(
        heads={"relation": _uniform_head()},
        uncertainty=0.6,
        phi_total=PHI_HIGH + 5.0,
    )
    assert borderline.quadrant is EpistemicQuadrant.ESCALATE
    assert ABSTAIN_THRESHOLD > borderline.value >= 0.5
    assert borderline.abstain is False

    # Very high uncertainty but low Φ must not abstain: nothing is at stake.
    lazy = _estimate(
        heads={"relation": _uniform_head()},
        uncertainty=1.0,
        incomplete=True,
        phi_total=0.0,
    )
    assert lazy.value >= ABSTAIN_THRESHOLD and lazy.abstain is False

    # And the type itself refuses an abstention outside ESCALATE.
    with pytest.raises(ContractError):
        UncertaintyEstimate(
            value=0.9,
            sources={},
            calibration_id=None,
            quadrant=EpistemicQuadrant.OBSERVE_LAZILY,
            abstain=True,
            detail="",
        )
    with pytest.raises(ContractError):
        UncertaintyEstimate(
            value=1.5,
            sources={},
            calibration_id=None,
            quadrant=EpistemicQuadrant.CHEAP_PATH,
            abstain=False,
            detail="",
        )


def test_uncertainty_value_is_invariant_to_novelty() -> None:
    """Novelty, Φ and uncertainty are three signals. This is the wall between them."""
    values = []
    for novelty in (0.0, 0.25, 0.5, 0.75, 1.0):
        estimate = _estimate(
            heads={"relation": _uniform_head()},
            cone=_Cone(branches=(_Branch(0.5), _Branch(0.3)), unresolved_mass=0.2),
            prototype_distance=0.4,
            uncertainty=0.3,
        novelty=novelty,
            phi_total=1.0,
        )
        values.append(estimate.value)
    assert len(set(values)) == 1, f"novelty leaked into uncertainty: {values}"


def test_uncertainty_value_ignores_phi() -> None:
    """Φ selects the quadrant. It must never enter the value."""
    values = []
    quadrants = set()
    for phi in (0.0, 1.0, 4.0, 20.0):
        estimate = _estimate(
            heads={"relation": _uniform_head()},
            prototype_distance=0.4,
            uncertainty=0.3,
            phi_total=phi,
        )
        values.append(estimate.value)
        quadrants.add(estimate.quadrant)
    assert len(set(values)) == 1, f"phi leaked into uncertainty: {values}"
    assert len(quadrants) > 1  # but it does move the quadrant


def test_observation_incomplete_is_the_only_driver_of_evidence_incomplete() -> None:
    incomplete = _estimate(
        heads={"relation": _uniform_head()},
        cone=_Cone(branches=(_Branch(0.4), _Branch(0.2)), unresolved_mass=0.4),
        prototype_distance=5.0,
        uncertainty=1.0,
        incomplete=True,
        phi_total=0.0,
    )
    assert incomplete.sources[UncertaintySource.EVIDENCE_INCOMPLETE.value] == 1.0

    # Everything else maxed out, observation complete: the source must read 0.0.
    complete = _estimate(
        heads={"relation": _uniform_head()},
        cone=_Cone(branches=(_Branch(0.4), _Branch(0.2)), unresolved_mass=0.4),
        prototype_distance=5.0,
        uncertainty=1.0,
        incomplete=False,
        phi_total=0.0,
    )
    assert complete.sources[UncertaintySource.EVIDENCE_INCOMPLETE.value] == 0.0
    assert complete.value < incomplete.value


def test_an_unevaluated_source_is_absent_not_maximal() -> None:
    """An unevaluated source is absent, not maximal (Stage 1's real bug).

    A source that never ran must be missing from ``sources``; a source that ran
    and found nothing must be present at a low value and must *lower* the result.
    """
    nothing_evaluated = _estimate(uncertainty=0.2, phi_total=0.0)
    assert UncertaintySource.ENTROPY.value not in nothing_evaluated.sources
    assert UncertaintySource.CONE_AMBIGUITY.value not in nothing_evaluated.sources
    assert UncertaintySource.PROTOTYPE_DISTANCE.value not in nothing_evaluated.sources
    assert nothing_evaluated.sources[STAGE1_PRIOR_KEY] == pytest.approx(0.2)
    assert "heads=not_evaluated" in nothing_evaluated.detail
    assert nothing_evaluated.value < 0.5  # not treated as maximal uncertainty

    evaluated_and_certain = _estimate(
        heads={"relation": _confident_head()},
        prototype_distance=0.0,
        uncertainty=0.2,
        phi_total=0.0,
    )
    assert evaluated_and_certain.value < nothing_evaluated.value
    assert evaluated_and_certain.sources[UncertaintySource.PROTOTYPE_DISTANCE.value] == 0.0


def test_cone_ambiguity_rises_with_unresolved_mass() -> None:
    def ambiguity(unresolved: float, branches: tuple[_Branch, ...]) -> float:
        estimate = _estimate(
            cone=_Cone(branches=branches, unresolved_mass=unresolved),
            uncertainty=0.0,
            phi_total=0.0,
        )
        return estimate.sources[UncertaintySource.CONE_AMBIGUITY.value]

    decided = ambiguity(0.0, (_Branch(1.0),))
    split = ambiguity(0.0, (_Branch(0.5), _Branch(0.5)))
    unknown = ambiguity(0.9, (_Branch(0.05), _Branch(0.05)))
    assert decided == 0.0  # one branch, no unresolved mass: the future is settled
    assert decided < split < unknown
    with pytest.raises(ContractError):
        _estimate(cone=_Cone(branches=(_Branch(1.0),), unresolved_mass=1.5), phi_total=0.0)


def test_estimate_rejects_malformed_inputs() -> None:
    with pytest.raises(ContractError):
        _estimate(prototype_distance=-1.0, phi_total=0.0)
    with pytest.raises(ContractError):
        _estimate(phi_total=float("nan"))


def test_an_unfitted_calibrator_never_yields_a_calibration_id() -> None:
    """A refused fit must not produce a plausible-looking id downstream."""
    refused = IsotonicCalibrator()
    refused.fit([0] * 40, [index / 100 for index in range(40)])
    estimate = _estimate(
        heads={"relation": _uniform_head()},
        uncertainty=0.5,
        calibrator=refused,
        phi_total=0.0,
    )
    assert estimate.calibration_id is None
    assert "calibration=refused" in estimate.detail

    labels, scores = _calibrated_sample(400, seed=11)
    fitted = IsotonicCalibrator()
    fitted.fit(labels, scores)
    calibrated = _estimate(
        heads={"relation": _uniform_head()},
        uncertainty=0.5,
        calibrator=fitted,
        phi_total=0.0,
    )
    assert calibrated.calibration_id == fitted.calibration_id()
    assert "calibrated_from=" in calibrated.detail
    assert 0.0 <= calibrated.value <= 1.0


def test_one_minus_max_control_is_implemented_and_refuses_emptiness() -> None:
    assert MAX_SOFTMAX_CONTROL == "one_minus_max_probability"
    assert one_minus_max({"relation": _confident_head()}) == pytest.approx(0.001)
    assert one_minus_max({"relation": _uniform_head(4)}) == pytest.approx(0.75)
    with pytest.raises(ContractError):
        one_minus_max({})
    with pytest.raises(ContractError):
        one_minus_max({"relation": _Head(probabilities=())})


def test_estimate_to_dict_is_plain_json_data() -> None:
    estimate = _estimate(
        heads={"relation": _uniform_head()},
        prototype_distance=0.5,
        uncertainty=0.4,
        phi_total=2.0,
    )
    payload = estimate.to_dict()
    assert json.loads(json.dumps(payload)) == payload
    assert payload["quadrant"] in set(EpistemicQuadrant)
    assert payload["dominant_source"] in payload["sources"]


# --- the measurement ---------------------------------------------------------


def test_measured_calibration_against_the_one_minus_max_control() -> None:
    """The G2.5 numbers, measured on a fixed (corpus, count, seed) split.

    Fixed because a zero-parameter scorer's PR-AUC on this generator moves 0.4025
    with corpus size alone; a result quoted without all three is void.

    The scorer under test is the deterministic Φ window score — max over the
    lineage window of feature 73, the squashed |ΔΦ| slot — because that is the
    free baseline everything in Stage 2 must beat, and calibrating it is the
    smallest honest test of the machinery. Synthetic data: this is a mechanism
    measurement, not a detection result.
    """
    dataset = build_dataset(name="uncertainty-eval", count=240, seed=11, corpus="ambiguous")
    assert len(dataset) == 240
    phi_slot = NEED_SIGNAL_INDICES["delta_phi"]
    scores = [max(step.features[phi_slot] for step in s.steps) for s in dataset.samples]
    labels = list(dataset.labels)

    pr_auc = average_precision(labels, scores)
    # Deterministic, class-balanced split: even indices calibrate, odd evaluate.
    fit_labels, fit_scores = labels[0::2], scores[0::2]
    eval_labels, eval_scores = labels[1::2], scores[1::2]
    assert 0 < sum(fit_labels) < len(fit_labels)
    assert 0 < sum(eval_labels) < len(eval_labels)

    calibrator = IsotonicCalibrator()
    fit_report = calibrator.fit(fit_labels, fit_scores)
    assert fit_report.calibration_id is not None
    held_out = calibrator.evaluate(eval_labels, eval_scores)
    calibrated = [calibrator.apply(score) for score in eval_scores]

    raw_ece = expected_calibration_error(eval_labels, eval_scores)
    raw_brier = brier_score(eval_labels, eval_scores)
    assert raw_ece is not None and raw_brier is not None
    assert held_out.expected_calibration_error is not None
    assert held_out.brier_score is not None

    control_uncertainty = [
        one_minus_max({"detection": _Head(probabilities=(1.0 - score, score))})
        for score in eval_scores
    ]
    control_predictions = [1 if score >= 0.5 else 0 for score in eval_scores]
    calibrated_uncertainty = [1.0 - abs(2.0 * p - 1.0) for p in calibrated]
    calibrated_predictions = [1 if p >= 0.5 else 0 for p in calibrated]

    control_rc = _risk_coverage_auc(control_uncertainty, control_predictions, eval_labels)
    calibrated_rc = _risk_coverage_auc(
        calibrated_uncertainty, calibrated_predictions, eval_labels
    )

    conformal = SplitConformal(nominal_coverage=0.9)
    conformal.fit(
        [label - calibrator.apply(score) for label, score in zip(fit_labels, fit_scores)]
    )
    conformal_coverage = conformal.coverage(eval_labels, calibrated)

    print(
        "\n[measured] corpus=ambiguous count=240 seed=11 synthetic_data=True\n"
        f"  samples={len(dataset)} base_rate={dataset.base_rate:.4f} "
        f"phi-window PR-AUC={pr_auc:.4f}\n"
        f"  calibration split n={len(fit_labels)}  eval split n={len(eval_labels)}\n"
        f"  calibration_id={fit_report.calibration_id}\n"
        f"  ECE   raw={raw_ece:.4f} -> calibrated={held_out.expected_calibration_error:.4f}\n"
        f"  Brier raw={raw_brier:.4f} -> calibrated={held_out.brier_score:.4f}\n"
        f"  MCE   calibrated={held_out.max_calibration_error:.4f}\n"
        f"  risk-coverage AUC: one_minus_max control={control_rc:.4f} "
        f"calibrated={calibrated_rc:.4f}\n"
        f"  conformal coverage (nominal 0.90)={conformal_coverage} "
        f"radius={conformal.quantile():.4f} -> the interval spans the whole unit "
        "interval, so it is honest but vacuous for a binary label\n"
    )

    # G2.5's threshold, asserted rather than restated. If this ever fails the
    # honest report is "G2.5 FAILS", not a looser threshold.
    assert held_out.expected_calibration_error <= 0.10
    assert held_out.calibration_id == fit_report.calibration_id
    # Calibration is supposed to improve the probabilistic claim, not the ranking:
    # an isotonic map is monotone, so it cannot reorder anything.
    assert held_out.expected_calibration_error < raw_ece
    assert held_out.brier_score < raw_brier
    assert conformal_coverage is not None
