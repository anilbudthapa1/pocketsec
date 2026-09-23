"""D2.14 — the Stage 2 experimental program (ADR-0008: research only).

Implements the measurements the Stage 2 gate and the falsification criteria
depend on:

* **S2-E01..E07 baseline comparison** — DTL against eight baselines on identical
  splits. DTL has no right to exist unless it wins or complements.
* **S2-E08 latent sweep** — the minimum-sufficient state frontier. The chosen
  size is the knee of the measured curve, not the largest that fits.
* **S2-E19 sleeping-brain benchmark** — quality against wake rate and compute.
* **S2-E30 ablation** — every DTL mechanism removed in turn.

Everything reports measured numbers on a held-out split. Where a result is
negative it is reported as negative: the falsification criteria are the point of
the exercise, not an obstacle to it.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import numpy as np

from pocketsec.stage0.benchmark.security_metrics import (
    average_precision,
    confusion_at_threshold,
    recall_at_max_fpr,
)
from pocketsec.stage2.dataset import Stage2Dataset, build_dataset
from pocketsec.stage2.research.baselines import build_baselines
from pocketsec.stage2.research.dtl import DTLConfig, DTLModel

__all__ = [
    "ModelResult",
    "ablation_study",
    "baseline_comparison",
    "build_splits",
    "latent_sweep",
    "sleeping_brain",
]

TRAIN_SEED = 3
TEST_SEED = 11
DEFAULT_SIZE = 240
FPR_BUDGET = 0.05


def build_splits(size: int = DEFAULT_SIZE) -> tuple[Stage2Dataset, Stage2Dataset]:
    """Two disjoint labelled splits, each from its own Stage 1 pipeline."""
    return (
        build_dataset(name="s2-train", count=size, seed=TRAIN_SEED),
        build_dataset(name="s2-test", count=size, seed=TEST_SEED),
    )


@dataclass(frozen=True, slots=True)
class ModelResult:
    name: str
    pr_auc: float | None
    recall_at_budget: float | None
    precision: float | None
    recall: float | None
    false_positives: int
    parameters: int
    model_bytes: int
    fit_seconds: float
    predict_seconds: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "pr_auc": round(self.pr_auc, 4) if self.pr_auc is not None else None,
            "recall_at_budget": (
                round(self.recall_at_budget, 4)
                if self.recall_at_budget is not None
                else None
            ),
            "precision": round(self.precision, 4) if self.precision is not None else None,
            "recall": round(self.recall, 4) if self.recall is not None else None,
            "false_positives": self.false_positives,
            "parameters": self.parameters,
            "model_bytes": self.model_bytes,
            "fit_seconds": round(self.fit_seconds, 3),
            "predict_seconds": round(self.predict_seconds, 4),
        }


def _evaluate(model: Any, train: Stage2Dataset, test: Stage2Dataset) -> ModelResult:
    started = time.perf_counter()
    model.fit(train)
    fit_seconds = time.perf_counter() - started

    started = time.perf_counter()
    scores = model.predict_scores(test)
    predict_seconds = time.perf_counter() - started

    labels = list(test.labels)
    matrix = confusion_at_threshold(labels, scores, 0.5)
    recall_budget, _ = recall_at_max_fpr(labels, scores, FPR_BUDGET)
    profile = model.resource_profile()
    return ModelResult(
        name=model.name,
        pr_auc=average_precision(labels, scores),
        recall_at_budget=recall_budget,
        precision=matrix.precision,
        recall=matrix.recall,
        false_positives=matrix.false_positives,
        parameters=profile["parameters"],
        model_bytes=profile["model_bytes_fp32"],
        fit_seconds=fit_seconds,
        predict_seconds=predict_seconds,
    )


# --- S2-E01..E07 -------------------------------------------------------------


def baseline_comparison(
    *, size: int = DEFAULT_SIZE, hidden: int = 24, epochs: int = 40
) -> dict[str, Any]:
    """DTL against every baseline, identical splits and training budget."""
    train, test = build_splits(size)
    results = [_evaluate(m, train, test) for m in build_baselines(hidden=hidden, epochs=epochs)]
    dtl = _evaluate(
        DTLModel(DTLConfig(latent=hidden * 2, epochs=epochs)), train, test
    )
    results.append(dtl)

    ranked = sorted(
        results, key=lambda r: (r.pr_auc or 0.0), reverse=True
    )
    best_baseline = next(r for r in ranked if r.name != "dtl")
    verdict = _falsification_verdict(dtl, best_baseline)
    return {
        "train": train.to_provenance(),
        "test": test.to_provenance(),
        "results": [r.to_dict() for r in ranked],
        "best_baseline": best_baseline.name,
        "dtl_vs_best_baseline": {
            "dtl_pr_auc": round(dtl.pr_auc or 0.0, 4),
            "baseline_pr_auc": round(best_baseline.pr_auc or 0.0, 4),
            "delta": round((dtl.pr_auc or 0.0) - (best_baseline.pr_auc or 0.0), 4),
            "dtl_parameters": dtl.parameters,
            "baseline_parameters": best_baseline.parameters,
        },
        "falsification_verdict": verdict,
    }


def _falsification_verdict(dtl: ModelResult, baseline: ModelResult) -> dict[str, Any]:
    """Apply Stage 2 falsification criterion 1, honestly.

    "A simple baseline achieves statistically comparable security performance
    with materially lower cost" → DTL must be simplified or rejected.
    """
    dtl_score = dtl.pr_auc or 0.0
    base_score = baseline.pr_auc or 0.0
    cheaper = baseline.parameters < dtl.parameters
    comparable = abs(dtl_score - base_score) < 0.02
    baseline_wins = base_score > dtl_score + 0.005

    if baseline_wins and cheaper:
        status = "DTL_FAILS_CRITERION_1"
        detail = (
            f"{baseline.name} scores {base_score:.4f} vs DTL {dtl_score:.4f} with "
            f"{baseline.parameters} parameters vs {dtl.parameters}. A simpler, "
            "cheaper baseline is better: DTL must be simplified or rejected on "
            "detection alone, and can only survive on a complementary capability."
        )
    elif comparable and cheaper:
        status = "DTL_COMPARABLE_BUT_COSTLIER"
        detail = (
            f"{baseline.name} matches DTL within 0.02 PR-AUC at lower cost. DTL "
            "must justify itself by wake rate, attribution or robustness."
        )
    else:
        status = "DTL_ADVANTAGE_MEASURED"
        detail = (
            f"DTL {dtl_score:.4f} vs best baseline {base_score:.4f} "
            f"({baseline.name})."
        )
    return {"status": status, "detail": detail}


# --- S2-E08 ------------------------------------------------------------------


def latent_sweep(
    *, dimensions: tuple[int, ...] = (8, 16, 24, 32, 48, 64, 96, 128), size: int = DEFAULT_SIZE,
    epochs: int = 40,
) -> dict[str, Any]:
    """The minimum-sufficient latent-state frontier (spec section 10)."""
    train, test = build_splits(size)
    points: list[dict[str, Any]] = []
    for latent in dimensions:
        result = _evaluate(DTLModel(DTLConfig(latent=latent, epochs=epochs)), train, test)
        points.append({**result.to_dict(), "latent": latent})

    best = max(points, key=lambda p: p["pr_auc"] or 0.0)
    tolerance = 0.01
    acceptable = [
        p for p in points if (p["pr_auc"] or 0.0) >= (best["pr_auc"] or 0.0) - tolerance
    ]
    knee = min(acceptable, key=lambda p: p["latent"]) if acceptable else None
    return {
        "points": points,
        "best": best,
        "knee": knee,
        "note": (
            "The chosen size is the knee of the measured frontier, not the "
            "largest model that fits."
        ),
    }


# --- S2-E19 ------------------------------------------------------------------


def sleeping_brain(
    *, wake_penalties: tuple[float, ...] = (0.0, 0.05, 0.25, 1.0, 4.0, 16.0),
    size: int = DEFAULT_SIZE, latent: int = 48, epochs: int = 40,
) -> dict[str, Any]:
    """Quality against wake rate and compute (spec section 33).

    Sweeps the wake penalty. The target is the safest Pareto point, not an
    arbitrary sleep target.
    """
    train, test = build_splits(size)
    labels = list(test.labels)
    points: list[dict[str, Any]] = []

    for penalty in wake_penalties:
        model = DTLModel(DTLConfig(latent=latent, epochs=epochs, w_wake=penalty))
        model.fit(train)
        scores = model.predict_scores(test)
        routing = model.route(test)
        recall_budget, _ = recall_at_max_fpr(labels, scores, FPR_BUDGET)
        points.append(
            {
                "w_wake": penalty,
                "pr_auc": round(average_precision(labels, scores) or 0.0, 4),
                "recall_at_budget": round(recall_budget or 0.0, 4),
                "blocks_awake": round(routing["mean_blocks_awake"], 4),
                "block_wake_rate": {
                    k: round(v, 3) for k, v in routing["block_wake_rate"].items()
                },
                "compute_units_per_event": round(routing["compute_units_per_event"], 2),
                "path_fractions": routing["path_fractions"],
            }
        )

    baseline_quality = points[0]["pr_auc"]
    # The safest Pareto point: cheapest routing that stays within 1 PR-AUC point
    # of the unpenalised model.
    viable = [p for p in points if p["pr_auc"] >= baseline_quality - 0.01]
    pareto = min(viable, key=lambda p: p["blocks_awake"]) if viable else None
    return {
        "points": points,
        "unpenalised_pr_auc": baseline_quality,
        "pareto_point": pareto,
        "routing_is_selective": bool(pareto and pareto["blocks_awake"] < 5.9),
    }


# --- S2-E30 ------------------------------------------------------------------

ABLATIONS: tuple[tuple[str, dict[str, Any]], ...] = (
    ("full", {}),
    ("no_relation_head", {"w_relation": 0.0, "w_family": 0.0}),
    ("no_state_delta_head", {"w_delta": 0.0}),
    ("no_time_head", {"w_time": 0.0}),
    ("no_phi_head", {"w_phi": 0.0}),
    ("no_prediction_at_all", {
        "w_relation": 0.0, "w_family": 0.0, "w_delta": 0.0,
        "w_time": 0.0, "w_phi": 0.0,
    }),
    ("no_wake_penalty", {"w_wake": 0.0}),
)


def ablation_study(
    *, size: int = DEFAULT_SIZE, latent: int = 48, epochs: int = 40
) -> dict[str, Any]:
    """Remove each DTL mechanism in turn (spec section 26 and criterion 12).

    ``no_prediction_at_all`` is the decisive one: it trains the detection head
    with no predictive supervision. If DTL scores the same without predicting
    anything, the entire "detection emerges from prediction" thesis is
    unsupported on this data.
    """
    train, test = build_splits(size)
    labels = list(test.labels)
    results: list[dict[str, Any]] = []

    for name, overrides in ABLATIONS:
        model = DTLModel(DTLConfig(latent=latent, epochs=epochs, **overrides))
        model.fit(train)
        scores = model.predict_scores(test)
        results.append(
            {
                "ablation": name,
                "pr_auc": round(average_precision(labels, scores) or 0.0, 4),
                "removed": sorted(overrides),
            }
        )

    full = next(r for r in results if r["ablation"] == "full")
    for result in results:
        result["delta_vs_full"] = round(result["pr_auc"] - full["pr_auc"], 4)

    justified = [
        r["ablation"] for r in results if r["ablation"] != "full" and r["delta_vs_full"] < -0.005
    ]
    return {
        "results": results,
        "full_pr_auc": full["pr_auc"],
        "mechanisms_with_measured_benefit": justified,
        "note": (
            "A mechanism whose removal does not reduce PR-AUC has no "
            "ablation-supported reason to exist (acceptance criterion 12)."
        ),
    }
