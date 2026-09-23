"""D0.3 — the benchmark harness.

One entry point runs any :class:`ModelSlot` over a checksum-bound dataset and
returns a single record carrying security quality, resource cost, novelty
economics and full reproducibility provenance. Every later stage reports through
this harness, which is what makes Stage 0's measurement rules binding on
Stage 1+ without Stage 1 having to renegotiate them.
"""

from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass
from typing import Any

from pocketsec.stage0.benchmark.dataset import SequenceDataset
from pocketsec.stage0.benchmark.profiles import ProfileReport, check_profile
from pocketsec.stage0.benchmark.resource_metrics import (
    HostFacts,
    ResourceMetrics,
    ResourceSampler,
)
from pocketsec.stage0.benchmark.security_metrics import (
    SecurityMetrics,
    evaluate_scores,
    recall_at_max_fpr,
)
from pocketsec.stage0.contracts.model_slot import ModelSlot, validate_slot
from pocketsec.stage0.contracts.threat_prediction_v1 import (
    ComputePath,
    ThreatPredictionV1,
    Verdict,
)
from pocketsec.stage0.experiments.ids import parse_experiment_id
from pocketsec.stage0.repro.environment import EnvironmentFingerprint
from pocketsec.stage0.repro.seeds import SeedSet

__all__ = ["BenchmarkCase", "BenchmarkResult", "NoveltyEconomics", "run_benchmark"]


@dataclass(frozen=True, slots=True)
class BenchmarkCase:
    """A fixed, versioned evaluation configuration."""

    case_id: str
    #: Score at or above which a prediction counts as a positive detection.
    threshold: float = 0.5
    #: The false-positive budget recall is reported at (spec section 12).
    fpr_budget: float = 0.01
    #: Deployment context used to normalise false positives per host-day.
    host_count: int = 1
    duration_seconds: float = 86_400.0
    resource_profile: str = "edge"

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "threshold": self.threshold,
            "fpr_budget": self.fpr_budget,
            "host_count": self.host_count,
            "duration_seconds": self.duration_seconds,
            "resource_profile": self.resource_profile,
        }


@dataclass(frozen=True, slots=True)
class NoveltyEconomics:
    """Spec section 12 — does compute actually scale with novelty?"""

    events_total: int
    predictions_total: int
    path_counts: dict[str, int]
    resolved_without_inference: float
    learned_solver_wake_rate: float
    mean_compute_budget_units: float
    mean_surprise_bits: float | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "events_total": self.events_total,
            "predictions_total": self.predictions_total,
            "path_counts": dict(self.path_counts),
            "resolved_without_inference": self.resolved_without_inference,
            "learned_solver_wake_rate": self.learned_solver_wake_rate,
            "mean_compute_budget_units": self.mean_compute_budget_units,
            "mean_surprise_bits": self.mean_surprise_bits,
        }


@dataclass(frozen=True, slots=True)
class BenchmarkResult:
    """The complete, self-describing result record."""

    experiment_id: str
    case: BenchmarkCase
    slot_name: str
    model_state_version: str
    dataset: dict[str, Any]
    security: SecurityMetrics
    resources: ResourceMetrics
    novelty: NoveltyEconomics
    profile_report: ProfileReport
    environment: EnvironmentFingerprint
    seeds: dict[str, int]
    host: HostFacts
    calibrated: bool
    synthetic_data: bool
    started_at_ns: int
    finished_at_ns: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "experiment_id": self.experiment_id,
            "case": self.case.to_dict(),
            "slot_name": self.slot_name,
            "model_state_version": self.model_state_version,
            "dataset": self.dataset,
            "security": self.security.to_dict(),
            "resources": self.resources.to_dict(),
            "novelty": self.novelty.to_dict(),
            "profile_report": self.profile_report.to_dict(),
            "environment": self.environment.to_dict(),
            "seeds": dict(self.seeds),
            "host": self.host.to_dict(),
            "calibrated": self.calibrated,
            "synthetic_data": self.synthetic_data,
            "started_at_ns": self.started_at_ns,
            "finished_at_ns": self.finished_at_ns,
        }


def run_benchmark(
    slot: ModelSlot,
    dataset: SequenceDataset,
    case: BenchmarkCase,
    *,
    experiment_id: str,
    seeds: SeedSet,
    synthetic_data: bool,
    model_bytes: int | None = None,
) -> BenchmarkResult:
    """Run ``slot`` over ``dataset`` and return one fully-provenanced record.

    ``synthetic_data`` is required, not inferred: spec section 13 forbids
    presenting synthetic performance as real-world detection quality, so the
    caller must state which it is and the label travels with the result.
    """
    validate_slot(slot)
    parse_experiment_id(experiment_id)
    seeds.apply()

    started_at_ns = time.time_ns()
    startup_started = time.perf_counter()
    environment = EnvironmentFingerprint.capture(seeds=seeds)
    startup_seconds = time.perf_counter() - startup_started

    predictions: list[ThreatPredictionV1] = []
    latencies_ns: list[float] = []

    with ResourceSampler() as sampler:
        for item in dataset:
            call_started = time.perf_counter_ns()
            prediction = slot.predict(item.sequence)
            latencies_ns.append(float(time.perf_counter_ns() - call_started))
            _require_matching_sequence(prediction, item.sequence.sequence_id)
            predictions.append(prediction)

    resources = sampler.result(
        events_processed=dataset.event_count, startup_seconds=startup_seconds
    )

    labels = [item.label for item in dataset]
    scores = [_detection_score(prediction) for prediction in predictions]
    security = evaluate_scores(
        labels,
        scores,
        threshold=case.threshold,
        fpr_budget=case.fpr_budget,
        latencies_ns=latencies_ns,
        abstentions=sum(1 for prediction in predictions if prediction.abstained),
        host_count=case.host_count,
        duration_seconds=case.duration_seconds,
    )
    security = _with_unseen_recall(security, dataset, scores, case)

    return BenchmarkResult(
        experiment_id=experiment_id,
        case=case,
        slot_name=slot.slot_name,
        model_state_version=slot.model_state_version,
        dataset=dataset.to_provenance(),
        security=security,
        resources=resources,
        novelty=_novelty_economics(predictions, dataset.event_count),
        profile_report=check_profile(resources, case.resource_profile, model_bytes=model_bytes),
        environment=environment,
        seeds=seeds.as_dict(),
        host=HostFacts.capture(),
        calibrated=all(prediction.is_calibrated for prediction in predictions),
        synthetic_data=synthetic_data,
        started_at_ns=started_at_ns,
        finished_at_ns=time.time_ns(),
    )


def _detection_score(prediction: ThreatPredictionV1) -> float:
    """Map a prediction to a single comparable detection score in [0, 1].

    ``confidence`` is confidence *in the stated verdict*, not a detection score,
    so the mapping must be verdict-aware: a confidently-BENIGN window is a very
    weak detection, not a very strong one. Reading confidence directly would
    invert the ranking and silently corrupt PR-AUC and every FP figure.

    An abstention scores 0.0. Novelty is not maliciousness (MEMORY.md), so a
    high novelty score on a non-committal verdict must not leak into the
    detection score and manufacture recall the model never claimed.
    """
    if not prediction.is_committal:
        return 0.0
    if prediction.verdict is Verdict.BENIGN:
        return 1.0 - prediction.confidence
    return prediction.confidence


def _require_matching_sequence(prediction: ThreatPredictionV1, sequence_id: str) -> None:
    if prediction.sequence_id != sequence_id:
        raise ValueError(
            f"slot returned prediction for {prediction.sequence_id!r} "
            f"while scoring {sequence_id!r}; results would be misaligned"
        )


def _novelty_economics(
    predictions: list[ThreatPredictionV1], events_total: int
) -> NoveltyEconomics:
    counts = Counter(prediction.compute_path.value for prediction in predictions)
    total = len(predictions)
    if total == 0:
        return NoveltyEconomics(events_total, 0, {}, 0.0, 0.0, 0.0, None)

    solver = counts.get(ComputePath.LEARNED_SOLVER.value, 0)
    surprises = [
        prediction.next_event.surprise_bits
        for prediction in predictions
        if prediction.next_event is not None and prediction.next_event.surprise_bits is not None
    ]
    return NoveltyEconomics(
        events_total=events_total,
        predictions_total=total,
        path_counts=dict(counts),
        resolved_without_inference=(total - solver) / total,
        learned_solver_wake_rate=solver / total,
        mean_compute_budget_units=sum(p.compute_budget_units for p in predictions) / total,
        mean_surprise_bits=(sum(surprises) / len(surprises)) if surprises else None,
    )


def _with_unseen_recall(
    security: SecurityMetrics,
    dataset: SequenceDataset,
    scores: list[float],
    case: BenchmarkCase,
) -> SecurityMetrics:
    """Attach unseen-technique recall when the split marks any such items."""
    pairs = [
        (item.label, score)
        for item, score in zip(dataset, scores, strict=True)
        if item.unseen_technique
    ]
    if not pairs:
        return security
    recall, _ = recall_at_max_fpr(
        [label for label, _ in pairs], [score for _, score in pairs], case.fpr_budget
    )
    if recall is None:
        # The unseen subset is usually all-positive, so it has no false-positive
        # rate of its own. Re-deriving an operating point from positives alone
        # would measure a different thing and report it under the same name.
        # Instead apply the operating point the FP budget already selected on the
        # full distribution -- that is the threshold a deployment would run at.
        operating_point = security.threshold_at_fpr_budget
        if operating_point is None:
            operating_point = case.threshold
        positives = [score for label, score in pairs if label == 1]
        recall = (
            sum(1 for score in positives if score >= operating_point) / len(positives)
            if positives
            else None
        )
    return SecurityMetrics(
        sample_count=security.sample_count,
        positive_count=security.positive_count,
        threshold=security.threshold,
        confusion=security.confusion,
        pr_auc=security.pr_auc,
        recall_at_fpr_budget=security.recall_at_fpr_budget,
        fpr_budget=security.fpr_budget,
        threshold_at_fpr_budget=security.threshold_at_fpr_budget,
        false_positives_per_host_day=security.false_positives_per_host_day,
        detection_latency_ns=security.detection_latency_ns,
        abstention_rate=security.abstention_rate,
        unseen_technique_recall=recall,
    )
