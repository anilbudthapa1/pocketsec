"""D1.11 — the Information Guillotine (spec section 21).

Start from a deliberately rich representation and systematically remove
information families, measuring security retention and byte cost at every cut.
The objective is to find the **knee** of the security-information/byte-cost
frontier — and, critically, to produce a *measured Pareto frontier rather than
an arbitrary field list* (acceptance criterion 9).

Removal order follows the spec:

    exact identity -> path semantics -> process semantics -> capability delta
    -> uncertainty -> novelty dimensions -> timing -> causal memory
    -> bit widths -> representation level

The detector used for scoring is deliberately simple and deterministic. This
measures what the *representation* carries, not how clever a model is; a learned
detector would confound representation loss with model capacity, which is
exactly what Stage 1 must not do before Stage 2 has chosen a model.

Stage 1 non-goal: do not optimise for byte count at the expense of unmeasured
security loss. Every cut here is measured.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pocketsec.stage0.benchmark.security_metrics import (
    average_precision,
    confusion_at_threshold,
    recall_at_max_fpr,
)
from pocketsec.stage1.guillotine.features import (
    LogisticProbe,
    extract_features,
    feature_names,
)
from pocketsec.stage1.pipeline import ScenarioResult
from pocketsec.stage1.ssir.codec import LAYOUTS, SSIRCodec
from pocketsec.stage1.ssir.transition import RepresentationLevel

__all__ = ["ABLATIONS", "AblationResult", "InformationFamily", "ParetoReport", "run_guillotine"]


@dataclass(frozen=True, slots=True)
class InformationFamily:
    """One information family and the SSIR fields it contributes."""

    name: str
    fields: frozenset[str]
    rationale: str


#: Families in the spec's removal order. ``cumulative`` ablation removes this
#: family and every earlier one, which is what traces the frontier.
ABLATIONS: tuple[InformationFamily, ...] = (
    InformationFamily(
        "exact_identity",
        frozenset({"actor_id", "object_id"}),
        "opaque identity handles; tests whether behaviour alone suffices",
    ),
    InformationFamily(
        "evidence_link",
        frozenset({"evidence_id"}),
        "pointer into the evidence store; investigation cost, not detection",
    ),
    InformationFamily(
        "object_semantics",
        frozenset({"object_sem"}),
        "what the object IS (credential, persistence, external endpoint)",
    ),
    InformationFamily(
        "actor_semantics",
        frozenset({"actor_sem"}),
        "what the actor has DEMONSTRATED it can do",
    ),
    InformationFamily(
        "capability_delta",
        frozenset({"state_delta", "invariant_delta"}),
        "ΔS and ΔΦ: the security-state change itself",
    ),
    InformationFamily(
        "uncertainty",
        frozenset({"uncertainty"}),
        "explicit confidence in the semantic interpretation",
    ),
    InformationFamily(
        "novelty",
        frozenset({"novelty_host", "novelty_actor", "novelty_relation", "novelty_object"}),
        "the conditional novelty tensor",
    ),
    InformationFamily(
        "timing",
        frozenset({"time_bucket"}),
        "bucketed temporal context",
    ),
    InformationFamily(
        "causal_memory",
        frozenset({"causal_sig", "epoch_id_low"}),
        "causal signature and epoch scoping",
    ),
)


@dataclass(frozen=True, slots=True)
class AblationResult:
    """One point on the frontier."""

    label: str
    removed: tuple[str, ...]
    retained_fields: tuple[str, ...]
    bytes_per_transition: float
    pr_auc: float | None
    recall_at_fpr_budget: float | None
    precision: float | None
    recall: float | None
    false_positives: int
    transitions_scored: int

    @property
    def security_retention(self) -> float | None:
        return self.pr_auc

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "removed": list(self.removed),
            "retained_field_count": len(self.retained_fields),
            "bytes_per_transition": round(self.bytes_per_transition, 2),
            "pr_auc": round(self.pr_auc, 4) if self.pr_auc is not None else None,
            "recall_at_fpr_budget": (
                round(self.recall_at_fpr_budget, 4)
                if self.recall_at_fpr_budget is not None
                else None
            ),
            "precision": round(self.precision, 4) if self.precision is not None else None,
            "recall": round(self.recall, 4) if self.recall is not None else None,
            "false_positives": self.false_positives,
            "transitions_scored": self.transitions_scored,
        }


@dataclass(frozen=True, slots=True)
class ParetoReport:
    """The measured frontier and its knee."""

    #: Leave-one-out cost per family: how much PR-AUC drops when ONLY that
    #: family is removed. Cumulative ablation answers "what is the cheapest
    #: viable representation"; leave-one-out answers "what does this family
    #: uniquely contribute". They disagree whenever two families are redundant,
    #: and a freeze decision needs both: a family that looks free cumulatively
    #: may be the sole carrier once its partner is gone.
    leave_one_out: dict[str, float]
    points: tuple[AblationResult, ...]
    knee: AblationResult | None
    baseline: AblationResult
    #: True when the probe was fitted on a separate training split. A frontier
    #: fitted and scored on the same data is optimistic and must not drive a
    #: freeze decision (Stage 0 fair-comparison rule 6).
    held_out: bool = False

    @property
    def is_measured_frontier(self) -> bool:
        """True when at least two distinct byte costs were actually measured."""
        return len({p.bytes_per_transition for p in self.points}) >= 2

    @property
    def informative_cuts(self) -> int:
        """Cuts where removing a family measurably cost security retention."""
        count = 0
        previous = self.baseline.pr_auc
        for point in self.points[1:]:
            if previous is not None and point.pr_auc is not None and point.pr_auc < previous:
                count += 1
            previous = point.pr_auc
        return count

    @property
    def degenerate(self) -> bool:
        """True when the corpus cannot discriminate between field families.

        A frontier where almost every cut is free is a statement about the
        *data*, not the representation: the scenarios are separable by so many
        redundant signals that dropping one changes nothing. Such a frontier is
        measured but not yet informative, and the knee it reports must not be
        used to justify freezing fields.
        """
        return self.informative_cuts <= 1

    @property
    def redundant_families(self) -> frozenset[str]:
        """Families that cost nothing alone AND nothing in sequence.

        These are the only honest removal candidates. A family that is free
        cumulatively but costly leave-one-out is being masked by a partner and
        must not be dropped.
        """
        cumulative_free: set[str] = set()
        previous = self.baseline.pr_auc
        for point in self.points[1:]:
            family = point.removed[-1]
            if (
                previous is not None
                and point.pr_auc is not None
                and point.pr_auc >= previous - 1e-9
            ):
                cumulative_free.add(family)
            previous = point.pr_auc
        loo_free = {name for name, cost in self.leave_one_out.items() if cost <= 1e-9}
        return frozenset(cumulative_free & loo_free)

    @property
    def caveat(self) -> str:
        if not self.held_out:
            return (
                "OPTIMISTIC: the probe was fitted and scored on the same split. "
                "Fair-comparison rule 6 forbids using this to justify a freeze."
            )
        if self.degenerate:
            return (
                "DEGENERATE: only "
                f"{self.informative_cuts} of {len(self.points) - 1} cuts measurably cost "
                "security retention. The corpus is too easily separable to discriminate "
                "between field families, so this knee must NOT be used to justify "
                "dropping fields at the D1.13 freeze. A harder corpus is required."
            )
        return "frontier discriminates between field families"

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline": self.baseline.to_dict(),
            "knee": self.knee.to_dict() if self.knee else None,
            "points": [p.to_dict() for p in self.points],
            "leave_one_out": {k: round(v, 4) for k, v in self.leave_one_out.items()},
            "redundant_families": sorted(self.redundant_families),
            "is_measured_frontier": self.is_measured_frontier,
            "held_out": self.held_out,
            "informative_cuts": self.informative_cuts,
            "degenerate": self.degenerate,
            "caveat": self.caveat,
        }


def _fit_and_score(
    retained: frozenset[str],
    train: list[ScenarioResult],
    evaluation: list[ScenarioResult],
) -> list[float]:
    """Fit the probe on ``train`` with the surviving fields, score ``evaluation``.

    Refitting per ablation is the point: each frontier point answers "how much
    separation is still achievable without this information", rather than "how
    much did my fixed weights happen to depend on it".
    """
    names = feature_names(retained)
    if not names:
        return [0.0] * len(evaluation)
    probe = LogisticProbe().fit(
        [extract_features(r, names) for r in train],
        [r.scenario.label for r in train],
    )
    return probe.predict([extract_features(r, names) for r in evaluation])


def _evaluate(
    label: str,
    removed: tuple[str, ...],
    retained: frozenset[str],
    train: list[ScenarioResult],
    evaluation: list[ScenarioResult],
    *,
    fpr_budget: float,
    threshold: float,
) -> AblationResult:
    labels = [result.scenario.label for result in evaluation]
    scores = _fit_and_score(retained, train, evaluation)

    codec = SSIRCodec(retained=retained)
    per_record = codec.record_bytes(RepresentationLevel.L2)
    transitions = sum(len(result.transitions) for result in evaluation)

    matrix = confusion_at_threshold(labels, scores, threshold)
    recall_budget, _ = recall_at_max_fpr(labels, scores, fpr_budget)
    return AblationResult(
        label=label,
        removed=removed,
        retained_fields=tuple(sorted(retained)),
        bytes_per_transition=float(per_record),
        pr_auc=average_precision(labels, scores),
        recall_at_fpr_budget=recall_budget,
        precision=matrix.precision,
        recall=matrix.recall,
        false_positives=matrix.false_positives,
        transitions_scored=transitions,
    )


def run_guillotine(
    results: list[ScenarioResult],
    *,
    train: list[ScenarioResult] | None = None,
    fpr_budget: float = 0.05,
    threshold: float = 0.5,
    knee_tolerance: float = 0.02,
) -> ParetoReport:
    """Ablate cumulatively and return the measured frontier.

    ``train`` is the split the probe is fitted on. When omitted, ``results`` is
    used for both, and the frontier is optimistic — reported honestly by
    ``ParetoReport.held_out``. Stage 0 fair-comparison rule 6 forbids tuning
    against the final test set, so a real freeze decision needs a held-out fit.

    The knee is the cheapest point whose PR-AUC is within ``knee_tolerance`` of
    the full representation. Selecting it by measurement is the whole point: an
    arbitrary field list would not survive acceptance criterion 9.
    """
    all_fields = frozenset(LAYOUTS)
    fit_split = train if train is not None else results
    baseline = _evaluate(
        "full",
        (),
        all_fields,
        fit_split,
        results,
        fpr_budget=fpr_budget,
        threshold=threshold,
    )

    points = [baseline]
    removed_so_far: set[str] = set()
    removed_names: list[str] = []
    for family in ABLATIONS:
        removed_so_far |= family.fields
        removed_names.append(family.name)
        points.append(
            _evaluate(
                f"-{family.name}",
                tuple(removed_names),
                all_fields - removed_so_far,
                fit_split,
                results,
                fpr_budget=fpr_budget,
                threshold=threshold,
            )
        )

    leave_one_out: dict[str, float] = {}
    baseline_auc = baseline.pr_auc or 0.0
    for family in ABLATIONS:
        point = _evaluate(
            f"only -{family.name}",
            (family.name,),
            all_fields - family.fields,
            fit_split,
            results,
            fpr_budget=fpr_budget,
            threshold=threshold,
        )
        leave_one_out[family.name] = max(0.0, baseline_auc - (point.pr_auc or 0.0))

    knee = _find_knee(points, baseline, knee_tolerance)
    return ParetoReport(
        leave_one_out=leave_one_out,
        points=tuple(points),
        knee=knee,
        baseline=baseline,
        held_out=train is not None,
    )


def _find_knee(
    points: list[AblationResult], baseline: AblationResult, tolerance: float
) -> AblationResult | None:
    """Cheapest point that retains baseline security within ``tolerance``."""
    if baseline.pr_auc is None:
        return None
    acceptable = [
        point
        for point in points
        if point.pr_auc is not None and point.pr_auc >= baseline.pr_auc - tolerance
    ]
    if not acceptable:
        return None
    return min(acceptable, key=lambda p: p.bytes_per_transition)
