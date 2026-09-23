"""Multi-seed stability for the Information Guillotine (D1.11 -> D1.13).

A single frontier is one draw. The D1.13 freeze permanently removes fields from
a contract every later stage depends on, so "this family looked free once" is
not sufficient evidence — a family that is redundant on one corpus draw and
load-bearing on the next must not be dropped.

This module runs the frontier over several independent seed pairs and reports,
per family, how often it was measured redundant. Only families redundant on
**every** draw become freeze candidates.

Stage 0 fair-comparison rule 5 (report multiple seeds for stochastic models)
applies. The probe is deterministic given its inputs, so the variance measured
here is corpus variance, which is exactly the variance that matters.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pocketsec.stage1.guillotine.ablation import ABLATIONS, run_guillotine
from pocketsec.stage1.labs.hard_corpus import build_hard_corpus
from pocketsec.stage1.pipeline import Stage1Pipeline

__all__ = ["FREEZE_UNANIMITY_REQUIRED", "StabilityReport", "measure_stability"]

#: A family must be measured redundant on every draw to be a freeze candidate.
#: Anything less and the freeze rests on which seed happened to be picked.
FREEZE_UNANIMITY_REQUIRED = True

DEFAULT_CORPUS_SIZE = 240


@dataclass(frozen=True, slots=True)
class StabilityReport:
    draws: int
    corpus_size: int
    #: Family -> fraction of draws on which it was measured redundant.
    redundancy_rate: dict[str, float]
    #: Family -> (min, mean, max) leave-one-out cost across draws.
    loo_spread: dict[str, tuple[float, float, float]]
    baseline_pr_auc: tuple[float, float, float]
    knee_bytes: tuple[float, float, float]
    full_bytes: float

    @property
    def freeze_candidates(self) -> frozenset[str]:
        """Families safe to drop: redundant on every draw."""
        threshold = 1.0 if FREEZE_UNANIMITY_REQUIRED else 0.8
        return frozenset(
            name for name, rate in self.redundancy_rate.items() if rate >= threshold
        )

    @property
    def unstable(self) -> frozenset[str]:
        """Families redundant on some draws but not others.

        These are the dangerous ones: a single-draw frontier would have
        recommended dropping them.
        """
        return frozenset(
            name for name, rate in self.redundancy_rate.items() if 0.0 < rate < 1.0
        )

    @property
    def freeze_ready(self) -> bool:
        return bool(self.freeze_candidates) and self.draws >= 3

    def to_dict(self) -> dict[str, Any]:
        return {
            "draws": self.draws,
            "corpus_size": self.corpus_size,
            "redundancy_rate": {k: round(v, 3) for k, v in self.redundancy_rate.items()},
            "loo_spread": {
                k: [round(v, 4) for v in spread] for k, spread in self.loo_spread.items()
            },
            "baseline_pr_auc": [round(v, 4) for v in self.baseline_pr_auc],
            "knee_bytes": [round(v, 1) for v in self.knee_bytes],
            "full_bytes": self.full_bytes,
            "freeze_candidates": sorted(self.freeze_candidates),
            "unstable": sorted(self.unstable),
            "freeze_ready": self.freeze_ready,
        }


def _compile(count: int, seed: int) -> list[Any]:
    pipeline = Stage1Pipeline()
    return [
        pipeline.run_scenario(scenario, offset=index)
        for index, scenario in enumerate(
            build_hard_corpus(count=count, seed=seed, split="eval")
        )
    ]


def measure_stability(
    *, draws: int = 4, corpus_size: int = DEFAULT_CORPUS_SIZE, base_seed: int = 1000
) -> StabilityReport:
    """Run the frontier over ``draws`` independent seed pairs.

    Each draw uses two disjoint labelled splits — a fit split and a scoring
    split — with different seeds, so no draw scores data its probe was fitted on.
    """
    redundancy_counts: dict[str, int] = {family.name: 0 for family in ABLATIONS}
    loo_samples: dict[str, list[float]] = {family.name: [] for family in ABLATIONS}
    baselines: list[float] = []
    knees: list[float] = []
    full_bytes = 0.0

    for draw in range(draws):
        fit_seed = base_seed + draw * 2
        score_seed = base_seed + draw * 2 + 1
        fit = _compile(corpus_size, fit_seed)
        score = _compile(corpus_size, score_seed)
        report = run_guillotine(score, train=fit)

        full_bytes = report.baseline.bytes_per_transition
        baselines.append(report.baseline.pr_auc or 0.0)
        knees.append(
            report.knee.bytes_per_transition if report.knee else full_bytes
        )
        for name in redundancy_counts:
            if name in report.redundant_families:
                redundancy_counts[name] += 1
            loo_samples[name].append(report.leave_one_out.get(name, 0.0))

    return StabilityReport(
        draws=draws,
        corpus_size=corpus_size,
        redundancy_rate={name: count / draws for name, count in redundancy_counts.items()},
        loo_spread={
            name: (min(values), sum(values) / len(values), max(values))
            for name, values in loo_samples.items()
        },
        baseline_pr_auc=(min(baselines), sum(baselines) / len(baselines), max(baselines)),
        knee_bytes=(min(knees), sum(knees) / len(knees), max(knees)),
        full_bytes=full_bytes,
    )
