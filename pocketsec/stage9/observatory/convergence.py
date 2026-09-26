"""D9.16 — the Convergence/Law Observatory: what recurs, what may be called a law, and why not.

The architecture ends its search story with four questions this module answers from the
search runs alone:

* **Convergence (§46).** ``Convergence(P) = successful runs containing P / runs where P was
  reachable``. High convergence is evidence of usefulness, never proof of universality.
* **The law gate (§47).** Eight criteria — independent rediscovery, cross-host and
  cross-epoch reproduction, unique ablation contribution, ARGUS robustness, resource
  advantage, a beaten simple baseline and an explicit failure domain — each recorded as
  ``True``/``False``/``None`` (unmeasured). A construct is a ``CANDIDATE_LAW`` only when every
  one is ``True``. Stage 9 runs on ONE synthetic host, so :func:`law_gate` always records
  ``cross_host = None``: the status is ``UNMEASURABLE`` (or ``REFUSED`` when a measured
  criterion failed), and no construct can become a law by an unmeasured criterion being
  skipped.
* **Law half-life (§48).** :func:`decay_confidence` implements
  ``confidence_t = confidence_0 * exp(-lambda * unsupported_time) + reproduction -
  contradiction``, clipped to [0, 1].
* **Meta-falsification (§49, S9X-100..102)** and **archaeology (§59).** The search's own
  design doctrines are tested against its records, and the runs are mined for operators that
  keep failing and subgraphs that keep re-evolving.

What this module refuses to do: it never promotes a law (it has no path to any authority
and no writer), it never reports an unmeasured criterion as met, and it never reads a
doctrine's verdict from anything but the records it is handed.
"""

from __future__ import annotations

import bisect
import math
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage9.foundry.promotion import (
    MAX_CANDIDATES,
    PROMOTION_MIN_RUNS,
    UNIQUE_CONTRIBUTION_MIN,
    PromotionDecision,
    canonical_subgraphs,
    construct_reachable,
    run_winner,
)
from pocketsec.stage9.genesis.variation import VariationOperator
from pocketsec.stage9.laplace.law_discovery import DEFAULT_HALF_LIFE_EVENTS
from pocketsec.stage9.ontogenesis.fitness import FitnessRecord

if TYPE_CHECKING:  # pragma: no cover - typing only
    from pocketsec.stage9.ontogenesis.search import SearchRun, WinnerReport

__all__ = [
    "CONTRADICTION_PENALTY",
    "DEFAULT_LAMBDA",
    "DOCTRINE_MARGIN",
    "DOCTRINE_SUPPORT_SHARE",
    "REPRODUCTION_GAIN",
    "SINGLE_HOST_FAILURE_DOMAIN",
    "Archaeology",
    "Convergence",
    "Doctrine",
    "DoctrineVerdict",
    "LawCandidate",
    "LawConfidence",
    "LawStatus",
    "archaeology",
    "convergence",
    "decay_confidence",
    "initial_confidence",
    "law_gate",
    "meta_falsify",
]

#: §48 lambda per step, and what one reproduction adds / one contradiction removes. Chosen.
DEFAULT_LAMBDA = 0.01
REPRODUCTION_GAIN = 0.1
CONTRADICTION_PENALTY = 0.2
#: A doctrine stated with "always" is supported only if it holds on this share of the
#: comparable cases it makes a claim about. Chosen.
DOCTRINE_SUPPORT_SHARE = 0.95
#: AP margin for doctrines that compare quality (the Stage 9 verdict margin).
DOCTRINE_MARGIN = 0.02

SINGLE_HOST_FAILURE_DOMAIN = (
    "one synthetic host (Stage 1 ambiguous corpus, project-authored generator); "
    "cross-host behaviour unmeasured"
)


@dataclass(frozen=True, slots=True)
class Convergence:
    construct: str
    runs_containing: int  # successful runs whose winner contains the construct
    runs_reachable: int  # runs whose search could have produced it
    value: float | None  # containing / reachable; None when unreachable everywhere


def convergence(runs: Sequence[SearchRun], construct: str) -> Convergence:
    """Architecture §46 over ``runs`` (a run without a winner is not successful)."""
    containing = 0
    for run in runs:
        winner = run_winner(run)
        if winner is not None and construct in canonical_subgraphs(winner):
            containing += 1
    reachable = sum(1 for run in runs if construct_reachable(run, construct))
    return Convergence(
        construct, containing, reachable, None if reachable == 0 else containing / reachable
    )


# --- the law gate (§47) ---------------------------------------------------------------------------


class LawStatus(StrEnum):
    CANDIDATE_LAW = "CANDIDATE_LAW"
    REFUSED = "REFUSED"
    UNMEASURABLE = "UNMEASURABLE"


@dataclass(frozen=True, slots=True)
class LawCandidate:
    """Architecture §47's eight criteria; ``None`` = not measured."""

    construct: str
    independent_rediscovery: bool | None
    cross_host: bool | None
    cross_epoch: bool | None
    unique_ablation: bool | None
    argus_robust: bool | None
    resource_advantage: bool | None  # description bits saved as a macro (search resource)
    beats_simple_baseline: bool | None
    failure_domain: str
    status: LawStatus

    def __post_init__(self) -> None:
        criteria = self.criteria()
        if self.status is LawStatus.CANDIDATE_LAW and not all(c is True for c in criteria):
            raise ContractError(
                f"{self.construct}: CANDIDATE_LAW needs all criteria True, got {criteria}"
            )
        if not self.failure_domain.strip():
            raise ContractError("a law candidate must state an explicit failure domain")

    def criteria(self) -> tuple[bool | None, ...]:
        return (
            self.independent_rediscovery,
            self.cross_host,
            self.cross_epoch,
            self.unique_ablation,
            self.argus_robust,
            self.resource_advantage,
            self.beats_simple_baseline,
        )


def _status(criteria: Sequence[bool | None]) -> LawStatus:
    if any(c is False for c in criteria):
        return LawStatus.REFUSED
    if any(c is None for c in criteria):
        return LawStatus.UNMEASURABLE
    return LawStatus.CANDIDATE_LAW


def _beats_simple(
    decision: PromotionDecision,
    runs: Sequence[SearchRun],
    winners: Sequence[WinnerReport],
    hand: Mapping[str, FitnessRecord] | None,
) -> bool | None:
    """Does a winner containing the construct beat the best hand baseline held-out by the
    Stage 9 margin? ``None`` when either side is unmeasured."""
    if hand is None:
        return None
    hand_aps = [r.worst_case_ap for r in hand.values() if r.worst_case_ap is not None]
    containing = {
        winner.digest
        for run in runs
        if (winner := run_winner(run)) is not None
        and decision.candidate.canonical in canonical_subgraphs(winner)
    }
    mine = [
        w.heldout_worst_case_ap
        for w in winners
        if w.genome_digest in containing and w.heldout_worst_case_ap is not None
    ]
    if not hand_aps or not mine:
        return None
    return max(mine) >= max(hand_aps) + DOCTRINE_MARGIN


def law_gate(
    candidates: Sequence[PromotionDecision],
    runs: Sequence[SearchRun],
    *,
    winners: Sequence[WinnerReport] = (),
    hand: Mapping[str, FitnessRecord] | None = None,
) -> tuple[LawCandidate, ...]:
    """Grade each promotion decision against §47. ``cross_host`` is ALWAYS ``None``.

    ``winners`` (held-out reports) and ``hand`` (held-out hand-baseline records) feed the
    simple-baseline criterion; without them it is ``None``. ``resource_advantage`` is the
    macro's description-length saving: runtime cost cannot differ, because macros are
    expanded before a genome runs.
    """
    graded = []
    for decision in candidates:
        c = decision.candidate
        criteria = {
            "independent_rediscovery": c.runs_containing >= PROMOTION_MIN_RUNS,
            "cross_host": None,  # one synthetic host: structurally unmeasurable
            "cross_epoch": c.cross_epoch,
            "unique_ablation": None
            if c.unique_contribution is None
            else c.unique_contribution >= UNIQUE_CONTRIBUTION_MIN,
            "argus_robust": c.argus_survived,
            "resource_advantage": c.description_bits_saved > 0.0,
            "beats_simple_baseline": _beats_simple(decision, runs, winners, hand),
        }
        graded.append(
            LawCandidate(
                construct=c.canonical,
                failure_domain=SINGLE_HOST_FAILURE_DOMAIN,
                status=_status(tuple(criteria.values())),
                **criteria,
            )
        )
    return tuple(graded)


# --- law half-life (§48) --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LawConfidence:
    construct: str
    confidence: float
    unsupported_steps: int
    half_life_steps: int


def _count(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ContractError(f"{name} must be a non-negative int, got {value!r}")
    return value


def decay_confidence(
    c: LawConfidence,
    *,
    steps: int,
    reproductions: int,
    contradictions: int,
    lam: float = DEFAULT_LAMBDA,
) -> LawConfidence:
    """Advance ``c`` by ``steps`` (architecture §48), clipped to [0, 1].

    Without a reproduction in the interval the confidence decays by ``exp(-lam * steps)``
    and the unsupported clock runs on; a reproduction stops the decay for the interval and
    resets the clock. Each reproduction adds :data:`REPRODUCTION_GAIN`, each contradiction
    removes :data:`CONTRADICTION_PENALTY`.
    """
    _count(steps, "steps")
    _count(reproductions, "reproductions")
    _count(contradictions, "contradictions")
    if (
        isinstance(lam, bool)
        or not isinstance(lam, (int, float))
        or not (math.isfinite(lam) and lam > 0)
    ):
        raise ContractError(f"lam must be a positive finite number, got {lam!r}")
    if reproductions:
        base, unsupported = c.confidence, 0
    else:
        base, unsupported = c.confidence * math.exp(-lam * steps), c.unsupported_steps + steps
    value = base + REPRODUCTION_GAIN * reproductions - CONTRADICTION_PENALTY * contradictions
    return LawConfidence(
        construct=c.construct,
        confidence=min(1.0, max(0.0, value)),
        unsupported_steps=unsupported,
        half_life_steps=round(math.log(2) / lam),
    )


def initial_confidence(construct: str) -> LawConfidence:
    """A freshly discovered construct: confidence 1.0, the default half-life."""
    return LawConfidence(construct, 1.0, 0, DEFAULT_HALF_LIFE_EVENTS)


# --- meta-falsification (§49) ---------------------------------------------------------------------


class Doctrine(StrEnum):
    SPARSITY_IS_CHEAPER = "SPARSITY_IS_CHEAPER"
    SPECIALIZATION_REDUCES_COST = "SPECIALIZATION_REDUCES_COST"
    LEARNED_STATE_BEATS_ENGINEERED = "LEARNED_STATE_BEATS_ENGINEERED"
    MORE_TELEMETRY_HELPS = "MORE_TELEMETRY_HELPS"


@dataclass(frozen=True, slots=True)
class DoctrineVerdict:
    doctrine: str
    supported: bool | None  # None = no comparable case in the records
    evidence: str


def _evaluated(runs: Sequence[SearchRun]) -> list[tuple[int, int, float | None]]:
    """(distinct inputs read, WU/event, worst-case AP) for every evaluated genome."""
    return [
        (len(genome.observation_map), record.wu_per_event, record.worst_case_ap)
        for run in runs
        for genome, record in zip(run.genomes, run.records, strict=True)
    ]


def _sparsity(runs: Sequence[SearchRun]) -> DoctrineVerdict:
    """S9X-100: over pairs where one genome reads strictly fewer inputs, is it cheaper?"""
    groups: dict[int, list[int]] = {}
    for inputs, wu, _ap in _evaluated(runs):
        groups.setdefault(inputs, []).append(wu)
    for values in groups.values():
        values.sort()
    keys = sorted(groups)
    pairs = held = 0
    for i, sparse in enumerate(keys):
        for dense in keys[i + 1 :]:
            dense_wu = groups[dense]
            for wu in groups[sparse]:
                pairs += len(dense_wu)
                held += len(dense_wu) - bisect.bisect_right(dense_wu, wu)  # dense strictly costlier
    if pairs == 0:
        return DoctrineVerdict(
            Doctrine.SPARSITY_IS_CHEAPER.value, None, "no pair differs in inputs read"
        )
    share = held / pairs
    return DoctrineVerdict(
        Doctrine.SPARSITY_IS_CHEAPER.value,
        share >= DOCTRINE_SUPPORT_SHARE,
        f"sparser genome strictly cheaper in {held}/{pairs} pairs ({share:.4f})",
    )


def _specialization(runs: Sequence[SearchRun]) -> DoctrineVerdict:
    """S9X-102: does a SPECIALIZE child cost strictly less WU/event than its parent?"""
    cheaper = total = 0
    for run in runs:
        by_digest = {r.genome_digest: r for r in run.records}
        for genome, record in zip(run.genomes, run.records, strict=True):
            if genome.mutation != VariationOperator.SPECIALIZE.value or not genome.parent_digests:
                continue
            parent = by_digest.get(genome.parent_digests[0])
            if parent is None:
                continue
            total += 1
            cheaper += record.wu_per_event < parent.wu_per_event
    if total == 0:
        return DoctrineVerdict(
            Doctrine.SPECIALIZATION_REDUCES_COST.value,
            None,
            "no evaluated SPECIALIZE child with a recorded parent",
        )
    return DoctrineVerdict(
        Doctrine.SPECIALIZATION_REDUCES_COST.value,
        cheaper / total >= DOCTRINE_SUPPORT_SHARE,
        f"SPECIALIZE child strictly cheaper than its parent in {cheaper}/{total}",
    )


def _learned_state(
    winners: Sequence[WinnerReport], hand: Mapping[str, FitnessRecord]
) -> DoctrineVerdict:
    """Do searched winners beat the engineered baselines on held-out worst-case AP?"""
    mine = sorted(w.heldout_worst_case_ap for w in winners if w.heldout_worst_case_ap is not None)
    engineered = [r.worst_case_ap for r in hand.values() if r.worst_case_ap is not None]
    if not mine or not engineered:
        return DoctrineVerdict(
            Doctrine.LEARNED_STATE_BEATS_ENGINEERED.value, None, "winner or hand AP unmeasured"
        )
    median = (
        mine[len(mine) // 2]
        if len(mine) % 2
        else (mine[len(mine) // 2 - 1] + mine[len(mine) // 2]) / 2
    )
    best = max(engineered)
    return DoctrineVerdict(
        Doctrine.LEARNED_STATE_BEATS_ENGINEERED.value,
        median >= best + DOCTRINE_MARGIN,
        f"median searched winner {median:.4f} vs best engineered {best:.4f} "
        f"({', '.join(sorted(hand))}), margin {DOCTRINE_MARGIN}",
    )


def _telemetry(runs: Sequence[SearchRun]) -> DoctrineVerdict:
    """Does reading >= 2 distinct inputs beat reading <= 1 on the best worst-case train AP?"""
    few = [ap for inputs, _wu, ap in _evaluated(runs) if inputs <= 1 and ap is not None]
    many = [ap for inputs, _wu, ap in _evaluated(runs) if inputs >= 2 and ap is not None]
    if not few or not many:
        return DoctrineVerdict(
            Doctrine.MORE_TELEMETRY_HELPS.value, None, "one input-count group is empty"
        )
    return DoctrineVerdict(
        Doctrine.MORE_TELEMETRY_HELPS.value,
        max(many) >= max(few) + DOCTRINE_MARGIN,
        f"best worst-case train AP: >=2 inputs {max(many):.4f} vs <=1 input {max(few):.4f}",
    )


def meta_falsify(
    runs: Sequence[SearchRun],
    winners: Sequence[WinnerReport],
    hand: Mapping[str, FitnessRecord],
) -> tuple[DoctrineVerdict, ...]:
    """Test each :class:`Doctrine` against the records (S9X-100..102).

    ``hand`` holds the hand baselines' HELD-OUT records (Φ-oracle, H1, H2), comparable with
    ``winners``' held-out figures. A doctrine the records cannot speak to is ``None``.
    """
    return (
        _sparsity(runs),
        _specialization(runs),
        _learned_state(winners, hand),
        _telemetry(runs),
    )


# --- archaeology (§59) ----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Archaeology:
    #: (operator, valid children that did not improve the archive), summed over runs.
    regressing_operators: tuple[tuple[str, int], ...]
    #: (canonical subgraph, run winners containing it) for subgraphs in >= 2 winners.
    re_evolved: tuple[tuple[str, int], ...]


def archaeology(runs: Sequence[SearchRun]) -> Archaeology:
    """Which operators keep failing, and which subgraphs keep re-evolving (§59).

    "Regressing" is read from :class:`OperatorStats` as ``valid - improved_archive``: a valid
    child that the archive did not keep. The list is bounded to :data:`MAX_CANDIDATES`.
    """
    failing: Counter[str] = Counter()
    for run in runs:
        for stats in run.operator_stats:
            failing[str(stats.operator)] += max(0, stats.valid - stats.improved_archive)
    regressing = tuple(
        sorted(((k, v) for k, v in failing.items() if v > 0), key=lambda kv: (-kv[1], kv[0]))
    )
    seen: Counter[str] = Counter()
    for run in runs:
        winner = run_winner(run)
        if winner is not None:
            seen.update(canonical_subgraphs(winner))
    re_evolved = sorted(((k, v) for k, v in seen.items() if v >= 2), key=lambda kv: (-kv[1], kv[0]))
    return Archaeology(regressing[:MAX_CANDIDATES], tuple(re_evolved[:MAX_CANDIDATES]))
