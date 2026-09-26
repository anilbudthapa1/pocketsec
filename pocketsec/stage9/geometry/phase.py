"""D9.8 (ONTO-F08, second half) — the Phase Observatory: order parameters and precursors.

Architecture §20-§21 asks whether a low-dimensional *order parameter* ``Ψ_t`` over a short
window of host state separates a normal regime from a pre-transition regime from a
compromised one, and whether a change in ``Ψ`` *precedes* the security-relevant step (a
precursor). It lists the candidates: variance change, autocorrelation change, transition-rate
change, entropy change, novelty accumulation. They are hypotheses, not physics, and §20 is
explicit: "no phase-transition language is accepted unless change-point baselines and
ordinary temporal models are beaten". So :func:`compare_phase` pits the best parameter
against a one-sided CUSUM on ``|ΔΦ|`` and the Φ-oracle.

Each :class:`OrderParameter` is computed over a trailing window of :data:`PSI_WINDOW`
events of the session stream. A session's score is its peak ``Ψ``. Two further figures are
measured because a detector's AP hides them: the **benign false-transition rate** (S9X-042),
the share of held-out benign sessions whose ``Ψ`` ever crosses the train-fitted threshold,
and the **precursor lead**: in malicious sessions, how many events the first ``Ψ`` exceedance
comes before the first step with ``|ΔΦ| >= 2.0`` (positive = early warning, negative = late).

What this module refuses to do. It selects the parameter on train AP, fits every threshold
on train benign sessions, and reports the lead as ``None`` when no malicious session has both
an exceedance and a large step — never a plausible-looking default.
:data:`PHASE_OBSERVATORY_DEFAULT_ENABLED` ships ``False``.
"""

from __future__ import annotations

import math
import statistics
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from itertools import pairwise

from pocketsec.stage2.dataset import Stage2Dataset, Stage2Sample
from pocketsec.stage2.encoder.ssir_encoder import NEED_SIGNAL_INDICES, EncodedTransition
from pocketsec.stage9.renormalization.laboratory import (
    ScoredDetector,
    compare_detectors,
    fpr_threshold,
    phi_oracle_scores,
    ranked_ap,
    unmeasured_comparison,
)
from pocketsec.stage9.spec.mssc import DetectorComparison

__all__ = [
    "BIG_STEP_ABS_DPHI",
    "CUSUM_DRIFT",
    "PHASE_OBSERVATORY_DEFAULT_ENABLED",
    "PSI_WINDOW",
    "OrderParameter",
    "PhaseObservation",
    "compare_phase",
    "cusum_score",
    "observe",
    "order_parameter_series",
]

#: Off until a measured JUSTIFIED verdict is cited in the findings and its ADR (spec §4.22).
PHASE_OBSERVATORY_DEFAULT_ENABLED: bool = False
#: Trailing window over which each ``Ψ_t`` is computed (spec §4.12). Chosen.
PSI_WINDOW = 8
#: The "security-relevant step" a precursor must precede (spec §4.12). Chosen.
BIG_STEP_ABS_DPHI = 2.0
#: CUSUM allowance per event on ``|ΔΦ|`` (spec §4.12 default). Chosen.
CUSUM_DRIFT = 0.5

_NOVELTY_PEAK = NEED_SIGNAL_INDICES["novelty_peak"]


class OrderParameter(StrEnum):
    """The five §21 precursor hypotheses, each a function of the last :data:`PSI_WINDOW` events."""

    DPHI_VARIANCE = "DPHI_VARIANCE"
    DPHI_AUTOCORR = "DPHI_AUTOCORR"
    TRANSITION_RATE = "TRANSITION_RATE"
    FAMILY_ENTROPY = "FAMILY_ENTROPY"
    NOVELTY_ACCUMULATION = "NOVELTY_ACCUMULATION"


def _autocorr(values: Sequence[float]) -> float:
    """Lag-1 autocorrelation; 0.0 when fewer than 3 points or no variance (undefined)."""
    if len(values) < 3:
        return 0.0
    mean = sum(values) / len(values)
    denominator = sum((v - mean) ** 2 for v in values)
    if denominator <= 0.0:
        return 0.0
    numerator = sum((a - mean) * (b - mean) for a, b in pairwise(values))
    return numerator / denominator


def _entropy(values: Sequence[int]) -> float:
    counts = Counter(values)
    total = len(values)
    return -sum((c / total) * math.log2(c / total) for c in counts.values()) if total else 0.0


def _psi(window: Sequence[EncodedTransition], parameter: OrderParameter) -> float:
    if parameter is OrderParameter.DPHI_VARIANCE:
        values = [s.delta_phi for s in window]
        return float(statistics.pvariance(values)) if len(values) > 1 else 0.0
    if parameter is OrderParameter.DPHI_AUTOCORR:
        return _autocorr([s.delta_phi for s in window])
    if parameter is OrderParameter.TRANSITION_RATE:
        return sum(1 for s in window if s.state_delta_mask) / len(window)
    if parameter is OrderParameter.FAMILY_ENTROPY:
        return _entropy([s.relation_family for s in window])
    return float(sum(s.features[_NOVELTY_PEAK] for s in window))  # NOVELTY_ACCUMULATION


def order_parameter_series(sample: Stage2Sample, parameter: OrderParameter) -> tuple[float, ...]:
    """``Ψ_t`` for every event ``t``, over the trailing window ``[t-7, t]`` of the stream."""
    parameter = OrderParameter(parameter)
    steps = sample.steps
    return tuple(
        _psi(steps[max(0, t - PSI_WINDOW + 1) : t + 1], parameter) for t in range(len(steps))
    )


def cusum_score(sample: Stage2Sample, drift: float = CUSUM_DRIFT) -> float:
    """One-sided CUSUM on ``|ΔΦ|``: ``S_t = max(0, S_{t-1} + |ΔΦ_t| - drift)``, peak ``S``."""
    level = peak = 0.0
    for step in sample.steps:
        level = max(0.0, level + abs(step.delta_phi) - drift)
        peak = max(peak, level)
    return peak


@dataclass(frozen=True, slots=True)
class PhaseObservation:
    """One order parameter on held-out data: AP, false transitions, precursor lead.

    ``train_ap`` selects the parameter; ``ap`` is held-out. ``precursor_sessions`` is how
    many malicious held-out sessions had both an exceedance and a large step (the lead's n).
    """

    parameter: str
    ap: float | None
    benign_false_transition_rate: float | None
    precursor_lead_events: float | None
    train_ap: float | None = None
    threshold: float | None = None
    precursor_sessions: int = 0


def _first(values: Sequence[float], predicate_threshold: float) -> int | None:
    return next((t for t, v in enumerate(values) if v > predicate_threshold), None)


def _lead(sample: Stage2Sample, series: Sequence[float], threshold: float) -> int | None:
    exceed = _first(series, threshold)
    big = next(
        (t for t, s in enumerate(sample.steps) if abs(s.delta_phi) >= BIG_STEP_ABS_DPHI), None
    )
    return None if exceed is None or big is None else big - exceed


def observe(
    parameter: OrderParameter, train: Stage2Dataset, heldout: Stage2Dataset
) -> tuple[PhaseObservation, tuple[float, ...], tuple[float, ...]]:
    """One parameter's observation plus its train and held-out session scores (peak ``Ψ``)."""
    train_series = [order_parameter_series(s, parameter) for s in train.samples]
    heldout_series = [order_parameter_series(s, parameter) for s in heldout.samples]
    train_scores = tuple(max(series, default=0.0) for series in train_series)
    heldout_scores = tuple(max(series, default=0.0) for series in heldout_series)
    benign_train = [s for s, lab in zip(train_scores, train.labels, strict=True) if lab == 0]
    threshold = fpr_threshold(benign_train)
    benign = [s for s, lab in zip(heldout_scores, heldout.labels, strict=True) if lab == 0]
    false_rate = None
    leads: list[int] = []
    if threshold is not None:
        false_rate = sum(1 for s in benign if s > threshold) / len(benign) if benign else None
        for sample, series in zip(heldout.samples, heldout_series, strict=True):
            lead = _lead(sample, series, threshold) if sample.label == 1 else None
            if lead is not None:
                leads.append(lead)
    observation = PhaseObservation(
        parameter=parameter.value, ap=ranked_ap(heldout.labels, heldout_scores),
        benign_false_transition_rate=false_rate,
        precursor_lead_events=float(statistics.median(leads)) if leads else None,
        train_ap=ranked_ap(train.labels, train_scores), threshold=threshold,
        precursor_sessions=len(leads),
    )
    return observation, train_scores, heldout_scores


def compare_phase(
    train: Stage2Dataset, heldout: Stage2Dataset
) -> tuple[tuple[PhaseObservation, ...], DetectorComparison]:
    """All five parameters observed; the train-selected one vs CUSUM and the Φ-oracle.

    JUSTIFIED iff its held-out AP ``>= max(CUSUM, Φ-oracle) + 0.02``. Degenerate splits
    (no train AP for any parameter) give UNMEASURED; nothing raises.
    """
    mechanism = f"{__name__}:PHASE_OBSERVATORY_DEFAULT_ENABLED"
    metric = "heldout_ap(peak order parameter)"
    names = ("cusum-abs-dphi", "phi-oracle")
    measured = [observe(parameter, train, heldout) for parameter in OrderParameter]
    observations = tuple(record[0] for record in measured)
    usable = [record for record in measured if record[0].train_ap is not None]
    if not usable:
        return observations, unmeasured_comparison(
            mechanism, metric, names, "no order parameter has a train AP (one class, or empty)"
        )
    best, train_scores, heldout_scores = max(usable, key=lambda r: r[0].train_ap or 0.0)
    candidate = ScoredDetector(f"psi/{best.parameter}", heldout_scores, train_scores)
    controls = (
        ScoredDetector(
            names[0], tuple(cusum_score(s) for s in heldout.samples),
            tuple(cusum_score(s) for s in train.samples),
        ),
        ScoredDetector(names[1], phi_oracle_scores(heldout), phi_oracle_scores(train)),
    )
    comparison = compare_detectors(
        mechanism, metric, candidate, controls, heldout_labels=heldout.labels,
        train_labels=train.labels,
        detail=f"selected {best.parameter} on train AP {best.train_ap:.4f}; benign false "
        f"transition rate {best.benign_false_transition_rate}; precursor lead "
        f"{best.precursor_lead_events} events over {best.precursor_sessions} session(s).",
    )
    return observations, comparison
