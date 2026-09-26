"""D8.2 / PROM-F03 — the Discovery Priority Field: which residual clusters deserve research.

Architecture §6: "This prevents the research engine from wasting compute on every
novelty." A research loop with a bounded budget must choose which unexplained things to
study, and this module is that choice, written as the architecture's formula with every
term bound to a count the observatory actually made (spec §4 D8.2):

=====================  ================================================================
term                   binding (each in [0, 1])
=====================  ================================================================
impact                 mean over members of the share of escalating steps
recurrence             min(1, members / RECURRENCE_SATURATION)
persistence            min(1, (hosts + epochs - 1) / members)
information_gap        share of members that are residuals of the current theory
independent_support    min(1, source_groups / members)
known_explanation      ``visibility_share`` — missing telemetry already explains it
experiment_cost        min(1, Σ member steps / 2048)
safety_risk            0.0 — replay and lab only; nothing here touches a host
resource_cost          min(1, members / 64)
=====================  ================================================================

``priority = impact·recurrence·persistence·gap·support / (known + cost + risk + resource + ε)``.

Two honest caveats, stated where the formula lives:

* ``information_gap`` is **identically 1.0** with the current observatory: every cluster
  member *is* a residual of the current theory by construction. The term is kept because
  the architecture names it, and a test pins that it cannot vary, so nobody quotes it as
  evidence (Stage 2 lesson 10: a term that cannot change says nothing).
* ``safety_risk`` is the constant 0.0 for the same reason: there is no active experiment
  class that touches a host (ADR-0075).

``PriorityMode.SIZE_ONLY`` is the control (falsifier F2): rank by member count alone. If the
full field does not predict research value better than cluster size, it is NOT-YET-JUSTIFIED
and the findings say so. This module ranks; it never discards a cluster and decides nothing
about truth.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, fields
from enum import StrEnum

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage8.residual.observatory import (
    MAX_CLUSTER_MEMBERS,
    Residual,
    ResidualCluster,
    ResidualField,
)

__all__ = [
    "EXPERIMENT_COST_STEPS",
    "PRIORITY_EPSILON",
    "RECURRENCE_SATURATION",
    "PriorityMode",
    "PriorityScore",
    "PriorityTerms",
    "prioritise",
    "priority_terms",
]

#: Spec §4.21. Chosen parameters, not measurements.
RECURRENCE_SATURATION: int = 8
PRIORITY_EPSILON: float = 1e-6
#: The experiment-cost denominator of spec §4 D8.2 (Σ member steps / 2048).
EXPERIMENT_COST_STEPS: int = 2048


class PriorityMode(StrEnum):
    FULL = "FULL"
    SIZE_ONLY = "SIZE_ONLY"  # the control: rank by member count


@dataclass(frozen=True, slots=True)
class PriorityTerms:
    impact: float
    recurrence: float
    persistence: float
    information_gap: float
    independent_support: float
    known_explanation: float
    experiment_cost: float
    safety_risk: float
    resource_cost: float

    def __post_init__(self) -> None:
        for spec in fields(self):
            value = getattr(self, spec.name)
            if not isinstance(value, float) or not 0.0 <= value <= 1.0:
                raise ContractError(
                    f"PriorityTerms.{spec.name} must be a float in [0, 1], got {value!r}")


@dataclass(frozen=True, slots=True)
class PriorityScore:
    cluster_id: str
    terms: PriorityTerms
    priority: float
    rank: int  # 1 = study first


def _clip(value: float) -> float:
    return float(min(1.0, max(0.0, value)))


def _members(cluster: ResidualCluster, residuals: Mapping[str, Residual]) -> list[Residual]:
    missing = [rid for rid in cluster.residual_ids if rid not in residuals]
    if missing:
        raise ContractError(
            f"cluster {cluster.cluster_id} names residuals not in the field: {missing[:2]}")
    return [residuals[rid] for rid in cluster.residual_ids]


def _terms(cluster: ResidualCluster, residuals: Mapping[str, Residual]) -> PriorityTerms:
    members = _members(cluster, residuals)
    count = len(members)
    impact = sum(member.escalating_steps / member.steps for member in members) / count
    return PriorityTerms(
        impact=_clip(impact),
        recurrence=_clip(count / RECURRENCE_SATURATION),
        persistence=_clip((cluster.hosts + cluster.epochs - 1) / count),
        # Every member of a cluster is a residual of the current theory, so this share is
        # 1.0 by construction (module docstring). Written as the constant it is, not as a
        # computation that could never come out differently.
        information_gap=1.0,
        independent_support=_clip(cluster.source_groups / count),
        known_explanation=_clip(cluster.visibility_share),
        experiment_cost=_clip(sum(member.steps for member in members) / EXPERIMENT_COST_STEPS),
        safety_risk=0.0,
        resource_cost=_clip(count / MAX_CLUSTER_MEMBERS),
    )


def priority_terms(cluster: ResidualCluster, field: ResidualField) -> PriorityTerms:
    """The nine named terms of one cluster, each in [0, 1]."""
    return _terms(cluster, field.by_id())


def _priority(terms: PriorityTerms) -> float:
    numerator = (terms.impact * terms.recurrence * terms.persistence
                 * terms.information_gap * terms.independent_support)
    denominator = (terms.known_explanation + terms.experiment_cost + terms.safety_risk
                   + terms.resource_cost + PRIORITY_EPSILON)
    return numerator / denominator


def prioritise(field: ResidualField, *, top_n: int,
               mode: PriorityMode = PriorityMode.FULL) -> tuple[PriorityScore, ...]:
    """The ``top_n`` clusters, best first. Ties break by cluster id (deterministic).

    ``SIZE_ONLY`` computes the same terms (so a report can show them) but ranks by member
    count: the control the full field must beat.
    """
    if isinstance(top_n, bool) or not isinstance(top_n, int) or top_n < 0:
        raise ContractError(f"top_n must be an int >= 0, got {top_n!r}")
    if not isinstance(mode, PriorityMode):
        raise ContractError(f"mode must be a PriorityMode, got {mode!r}")
    residuals = field.by_id()
    scored: list[tuple[float, str, PriorityTerms]] = []
    for cluster in field.clusters:
        terms = _terms(cluster, residuals)
        value = (float(len(cluster.residual_ids)) if mode is PriorityMode.SIZE_ONLY
                 else _priority(terms))
        scored.append((value, cluster.cluster_id, terms))
    scored.sort(key=lambda row: (-row[0], row[1]))
    return tuple(
        PriorityScore(cluster_id=cid, terms=terms, priority=value, rank=index + 1)
        for index, (value, cid, terms) in enumerate(scored[:top_n])
    )
