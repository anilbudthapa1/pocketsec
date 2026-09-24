"""D2.14 / D2.2 — the corpus degeneracy guard (ADR-0120, research only).

This module exists to stop Stage 2 justifying eleven components on a
corpus-size artefact.

The measurement that forced it into existence was taken with
``PYTHONHASHSEED=0`` on Python 3.14.7: :class:`PhiOracleBaseline`, which has
**zero parameters**, scores PR-AUC 1.0000 on ``corpus='ambiguous'`` at
``count=60 seed=11``, 0.8495 at ``count=120`` and 0.5975 at ``count=240`` — a
0.4025 swing produced by nothing but the number of scenarios drawn from the same
generator. A component delta of +0.04 measured against that background says
nothing about the component.

So before any ablation is recorded, :func:`saturation_check` fits the whole
baseline suite at one shared budget on the split that ablation would use, and
:func:`refuse_if_degenerate` raises when the split cannot discriminate. Four
conditions mark a corpus degenerate:

1. ``best - median < DEGENERATE_SPREAD`` — every architecture agrees, so there
   is no headroom in which a mechanism could show an effect.
2. an **order-free** pooled baseline (:class:`MLPBaseline`, which sees a bag of
   pooled features and cannot see sequence order at all) lands within
   ``ORDER_FREE_TOLERANCE`` of the best score — then the task is not a sequence
   task and no sequential mechanism can be credited for solving it.
3. the **zero-parameter** Φ-oracle lands within ``ORDER_FREE_TOLERANCE`` of the
   best score — then Stage 1's representation already solved the task and the
   learning is not where the value is.
4. any baseline scores **at or below the base rate**. A model below chance is a
   bug (``planning/MEMORY.md``, benchmarking trap 2), and a split that produces
   one cannot be used to rank mechanisms.

What this module refuses to do: it never converts a degenerate corpus into a
weaker threshold, and it never returns a plausible-looking number for a fit that
did not happen. Every field is ``None`` when it could not be measured.

Precedent: ``ParetoReport.degenerate`` in ``stage1/guillotine/ablation.py``,
which reached the same conclusion about the Stage 1 field frontier.
"""

from __future__ import annotations

from dataclasses import dataclass
from statistics import median as _median
from typing import Any

from pocketsec.stage0.benchmark.security_metrics import average_precision
from pocketsec.stage2.dataset import Stage2Dataset
from pocketsec.stage2.research.baselines import build_baselines

__all__ = [
    "DEGENERATE_SPREAD",
    "ORDER_FREE_TOLERANCE",
    "REASON_BELOW_BASE_RATE",
    "REASON_INFORMATIVE",
    "REASON_NO_SCORES",
    "REASON_ORDER_FREE",
    "REASON_PHI_ORACLE",
    "REASON_SPREAD",
    "CorpusDegenerate",
    "SaturationVerdict",
    "refuse_if_degenerate",
    "saturation_check",
]

#: Best minus median PR-AUC below this and the architectures are indistinguishable.
DEGENERATE_SPREAD: float = 0.01

#: How close an order-free or zero-parameter baseline may come to the best score
#: before the corpus stops being evidence about sequential machinery.
ORDER_FREE_TOLERANCE: float = 0.02

#: The order-free control: pooled features, no notion of sequence order.
ORDER_FREE_BASELINE = "mlp-pooled"

#: The zero-parameter control: Stage 1's representation with no model at all.
PHI_ORACLE_BASELINE = "phi-oracle"

REASON_INFORMATIVE = "INFORMATIVE"
REASON_SPREAD = "DEGENERATE_SPREAD"
REASON_ORDER_FREE = "ORDER_FREE_BASELINE_TIES_BEST"
REASON_PHI_ORACLE = "ZERO_PARAMETER_BASELINE_TIES_BEST"
REASON_BELOW_BASE_RATE = "BASELINE_BELOW_BASE_RATE"
REASON_NO_SCORES = "NO_BASELINE_PRODUCED_A_SCORE"

#: One shared training budget for every baseline. Acceptance criterion 1 needs
#: identical inputs *and* identical budgets, and a baseline that lost because it
#: was starved would make the comparison worthless.
SHARED_HIDDEN: int = 24
SHARED_EPOCHS: int = 40


class CorpusDegenerate(RuntimeError):
    """Raised instead of recording an ablation on a corpus that cannot rank."""


@dataclass(frozen=True, slots=True)
class SaturationVerdict:
    """What the whole baseline suite says about a split, before any ablation.

    Every float is a measured PR-AUC or ``None``. There is no field that can
    hold an estimate.

    ``count`` is the **sample count of the evaluated split**, not the ``count``
    argument a corpus builder was given: ``build_hard_corpus(count=6)`` yields 26
    scenarios, and the number that makes a result reproducible is the one actually
    scored. The builder's argument travels in
    ``Stage2Report.provenance["count"]`` beside it.
    """

    corpus: str
    count: int
    seed: int
    best: float | None
    median: float | None
    spread: float | None
    order_free_baseline: float | None
    phi_oracle: float | None
    degenerate: bool
    reason: str
    base_rate: float | None = None
    below_base_rate: tuple[str, ...] = ()
    scores: tuple[tuple[str, float], ...] = ()
    best_model: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "corpus": self.corpus,
            "count": self.count,
            "seed": self.seed,
            "best": _round(self.best),
            "best_model": self.best_model,
            "median": _round(self.median),
            "spread": _round(self.spread),
            "order_free_baseline": _round(self.order_free_baseline),
            "phi_oracle": _round(self.phi_oracle),
            "base_rate": _round(self.base_rate),
            "below_base_rate": list(self.below_base_rate),
            "degenerate": self.degenerate,
            "reason": self.reason,
            "scores": {name: round(value, 4) for name, value in self.scores},
            "measured_by": "pocketsec.stage2.research.saturation:saturation_check",
        }


def _round(value: float | None) -> float | None:
    return None if value is None else round(value, 4)


def _fit_suite(
    train: Stage2Dataset, test: Stage2Dataset
) -> tuple[tuple[str, float], ...]:
    """Fit every baseline on ``train`` once and score ``test`` once.

    A fresh suite is built here on purpose. ``fit`` continues training rather
    than restarting, so handing an already-fitted model to a second evaluation
    silently doubles its budget and invents an advantage.
    """
    labels = list(test.labels)
    scored: list[tuple[str, float]] = []
    for model in build_baselines(hidden=SHARED_HIDDEN, epochs=SHARED_EPOCHS):
        model.fit(train)
        value = average_precision(labels, model.predict_scores(test))
        if value is not None:
            scored.append((model.name, float(value)))
    return tuple(scored)


def _classify(
    scores: tuple[tuple[str, float], ...],
    *,
    base_rate: float,
) -> tuple[bool, str, tuple[str, ...]]:
    """Decide degeneracy from measured scores alone."""
    if not scores:
        return True, REASON_NO_SCORES, ()

    table = dict(scores)
    best = max(table.values())
    below = tuple(
        name for name, value in sorted(scores) if value <= base_rate
    )
    if below:
        return True, REASON_BELOW_BASE_RATE, below

    spread = best - _median(sorted(table.values()))
    if spread < DEGENERATE_SPREAD:
        return True, REASON_SPREAD, below

    order_free = table.get(ORDER_FREE_BASELINE)
    if order_free is not None and best - order_free <= ORDER_FREE_TOLERANCE:
        return True, REASON_ORDER_FREE, below

    oracle = table.get(PHI_ORACLE_BASELINE)
    if oracle is not None and best - oracle <= ORDER_FREE_TOLERANCE:
        return True, REASON_PHI_ORACLE, below

    return False, REASON_INFORMATIVE, below


def saturation_check(train: Stage2Dataset, test: Stage2Dataset) -> SaturationVerdict:
    """Fit the full baseline suite on one split and judge whether it can rank.

    ``train`` and ``test`` must be disjoint splits of the same corpus; the
    verdict records ``test``'s ``(corpus, count, seed)`` because a result quoted
    without all three is void (spec §0.1).
    """
    scores = _fit_suite(train, test)
    base_rate = test.base_rate
    degenerate, reason, below = _classify(scores, base_rate=base_rate)

    table = dict(scores)
    values = sorted(table.values())
    best = max(values) if values else None
    middle = _median(values) if values else None
    best_model = (
        max(scores, key=lambda pair: pair[1])[0] if scores else None
    )
    return SaturationVerdict(
        corpus=test.corpus,
        count=len(test),
        seed=test.seed,
        best=best,
        median=middle,
        spread=None if best is None or middle is None else best - middle,
        order_free_baseline=table.get(ORDER_FREE_BASELINE),
        phi_oracle=table.get(PHI_ORACLE_BASELINE),
        degenerate=degenerate,
        reason=reason,
        base_rate=base_rate,
        below_base_rate=below,
        scores=tuple(sorted(scores)),
        best_model=best_model,
    )


def refuse_if_degenerate(verdict: SaturationVerdict) -> None:
    """Raise :class:`CorpusDegenerate` rather than record a void ablation.

    This is the only enforcement point. It refuses instead of warning because a
    warning next to a number gets quoted without the warning.
    """
    if not verdict.degenerate:
        return
    raise CorpusDegenerate(
        f"corpus={verdict.corpus!r} count={verdict.count} seed={verdict.seed} "
        f"is degenerate ({verdict.reason}): best={_round(verdict.best)} "
        f"median={_round(verdict.median)} spread={_round(verdict.spread)} "
        f"order_free={_round(verdict.order_free_baseline)} "
        f"phi_oracle={_round(verdict.phi_oracle)} "
        f"base_rate={_round(verdict.base_rate)}. "
        "No component delta measured on this split is evidence about the "
        "component, so nothing is recorded."
    )
