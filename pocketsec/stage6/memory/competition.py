"""HEL-F10 — ``compete_knowledge``: a new explanation must beat the old one to replace it.

Architecture §13: new knowledge challenges validated old knowledge **under the
same replay set**, and replaces it only if it dominates; otherwise the two may
coexist by context, or the newcomer is rejected. The failure this prevents is
catastrophic replacement — a detector that looks better on this week's traffic
silently displacing one that still guards last month's attack.

The rule, exactly as the spec binds it:

* **REPLACE** iff ``new`` Pareto-dominates ``old`` on (recall ↑, fp_burden ↓,
  calibration ↓, resource_bytes ↓, robustness ↑) with at least one strict
  improvement **and** ``new`` applies everywhere ``old`` applied.
* **COEXIST** iff the two apply to disjoint contexts and each is within
  ``EPS_SECURITY`` of the better of the two on its own contexts' replay.
* otherwise **REJECT_NEW**.
* A **protected** old item is never replaced by an item that misses any replay
  positive or semantics-preserving variant the old item caught — dominance on
  the averages is not enough when the thing at stake is a protected anchor.

What it refuses to do: compete anything but ``DETECTOR`` items. A detector is the
only kind whose "recall" and "robustness" are defined by the scorer; a catalog of
competition rules for baselines or procedures would be richer than any consumer
(lesson 3), so asking for one is a ``ContractError``.

Simple controls (spec §7): ``newest_wins`` (always REPLACE) and ``oldest_wins``
(never replace). Firing count: conflicts resolved to COEXIST or REJECT_NEW that
newest-wins would have replaced — i.e. every non-REPLACE outcome.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage0.contracts.threat_prediction_v1 import Verdict
from pocketsec.stage6.capsule.experience_capsule import EncodedStep
from pocketsec.stage6.memory.episodic import EpisodeSkeleton
from pocketsec.stage6.memory.semantic import ALL_CONTEXTS, ItemKind, KnowledgeItem, match_motif
from pocketsec.stage6.rehearsal.counterfactual import ReplayVariant
from pocketsec.stage6.resources import WorkMeter

__all__ = [
    "CompetitionOutcome",
    "CompetitionResult",
    "CompetitionScores",
    "applies_to",
    "compete_knowledge",
    "covers",
    "item_bytes",
    "newest_wins",
    "oldest_wins",
    "overlaps",
    "score_detector",
]


class CompetitionOutcome(StrEnum):
    REPLACE = "REPLACE"
    COEXIST = "COEXIST"
    REJECT_NEW = "REJECT_NEW"


@dataclass(frozen=True, slots=True)
class CompetitionScores:
    """Architecture §13, every axis bound to a replay measurement."""

    coverage: float  # share of replay positives matched (motif only, threshold ignored)
    recall: float  # share of replay positives alerted at the trusted threshold
    fp_burden: float  # share of replay negatives alerted
    calibration: float  # Brier over labelled replay (lower is better)
    applicability: frozenset[str]  # context ids
    resource_bytes: int
    robustness: float  # recall over semantics-preserving counterfactual variants


@dataclass(frozen=True, slots=True)
class CompetitionResult:
    outcome: CompetitionOutcome
    new_item_id: str
    old_item_id: str
    new: CompetitionScores
    old: CompetitionScores
    reason: str


def applies_to(item: KnowledgeItem, context_id: str) -> bool:
    """The scorer's applicability rule: ``ALL_CONTEXTS`` or the context itself."""
    return ALL_CONTEXTS in item.context_ids or context_id in item.context_ids


def covers(wider: frozenset[str], narrower: frozenset[str]) -> bool:
    """``wider ⊇ narrower`` where ``ALL_CONTEXTS`` covers every context."""
    return ALL_CONTEXTS in wider or narrower <= wider


def _disjoint(left: frozenset[str], right: frozenset[str]) -> bool:
    return ALL_CONTEXTS not in left and ALL_CONTEXTS not in right and not (left & right)


def item_bytes(item: KnowledgeItem) -> int:
    """A structural size estimate, identical in method for every item compared.

    Eight bytes per motif integer and anchor float plus the key and context
    strings. It is used only to compare two items against each other, never
    reported as a memory figure (``TrustedKnowledgeState.byte_size`` is that).
    """
    motif_ints = 4 * len(item.motif)
    return (
        8 * (motif_ints + len(item.anchor))
        + len(item.pattern_key.encode("utf-8"))
        + sum(len(context.encode("utf-8")) for context in item.context_ids)
    )


def _alerts(
    item: KnowledgeItem,
    steps: Sequence[EncodedStep],
    context_id: str,
    threshold: float,
    meter: WorkMeter,
    *,
    anywhere: bool = False,
) -> tuple[bool, float]:
    """(matched, score) of one detector on one step sequence, charging the meter.

    ``anywhere`` ignores applicability; it is used only to ask how well a rival
    *would* explain episodes outside its contexts, never to score an alert.
    """
    if not anywhere and not applies_to(item, context_id):
        return False, 0.0
    meter.charge(max(1, len(steps)))
    matched = match_motif(item.motif, steps)
    return matched, (item.weight if matched else 0.0)


def _labelled(
    replay: Sequence[EpisodeSkeleton],
) -> tuple[list[EpisodeSkeleton], list[EpisodeSkeleton]]:
    positives = [episode for episode in replay if episode.verdict is Verdict.MALICIOUS]
    negatives = [episode for episode in replay if episode.verdict is Verdict.BENIGN]
    return positives, negatives


def _require_detector(item: KnowledgeItem, role: str) -> None:
    if item.kind is not ItemKind.DETECTOR:
        raise ContractError(
            f"competition is defined for DETECTOR items only; {role} is {item.kind.value}"
        )


def score_detector(
    item: KnowledgeItem,
    *,
    replay: Sequence[EpisodeSkeleton],
    variants: Sequence[ReplayVariant],
    threshold: float,
    meter: WorkMeter,
) -> CompetitionScores:
    """Every §13 axis for one detector on the shared replay set."""
    _require_detector(item, "item")
    positives, negatives = _labelled(replay)
    matched = alerted = false_alerts = 0
    squared_error = 0.0
    for episode in positives:
        hit, score = _alerts(item, episode.steps, episode.context_id, threshold, meter)
        matched += hit
        alerted += score >= threshold and hit
        squared_error += (1.0 - score) ** 2
    for episode in negatives:
        hit, score = _alerts(item, episode.steps, episode.context_id, threshold, meter)
        false_alerts += score >= threshold and hit
        squared_error += score**2
    labelled = len(positives) + len(negatives)
    robust_total = robust_hits = 0
    contexts = {episode.episode_id: episode.context_id for episode in replay}
    for variant in variants:
        if not variant.semantics_preserved or variant.expected_verdict is not Verdict.MALICIOUS:
            continue
        robust_total += 1
        hit, score = _alerts(
            item, variant.steps, contexts.get(variant.source_episode_id, ""), threshold, meter
        )
        robust_hits += hit and score >= threshold
    recall = alerted / len(positives) if positives else 0.0
    return CompetitionScores(
        coverage=matched / len(positives) if positives else 0.0,
        recall=recall,
        fp_burden=false_alerts / len(negatives) if negatives else 0.0,
        calibration=squared_error / labelled if labelled else 0.0,
        applicability=frozenset(item.context_ids),
        resource_bytes=item_bytes(item),
        # No semantics-preserving variant means robustness was not tested, so it
        # falls back to plain replay recall rather than an invented 1.0.
        robustness=robust_hits / robust_total if robust_total else recall,
    )


def _dominates(new: CompetitionScores, old: CompetitionScores) -> bool:
    no_worse = (
        new.recall >= old.recall
        and new.fp_burden <= old.fp_burden
        and new.calibration <= old.calibration
        and new.resource_bytes <= old.resource_bytes
        and new.robustness >= old.robustness
    )
    strictly_better = (
        new.recall > old.recall
        or new.fp_burden < old.fp_burden
        or new.calibration < old.calibration
        or new.resource_bytes < old.resource_bytes
        or new.robustness > old.robustness
    )
    return no_worse and strictly_better


def _protected_loss(
    new: KnowledgeItem,
    old: KnowledgeItem,
    *,
    replay: Sequence[EpisodeSkeleton],
    variants: Sequence[ReplayVariant],
    threshold: float,
    meter: WorkMeter,
) -> bool:
    """True if ``old`` catches any positive episode or variant that ``new`` misses."""
    contexts = {episode.episode_id: episode.context_id for episode in replay}
    cases: list[tuple[Sequence[EncodedStep], str]] = [
        (episode.steps, episode.context_id)
        for episode in replay
        if episode.verdict is Verdict.MALICIOUS
    ]
    cases.extend(
        (variant.steps, contexts.get(variant.source_episode_id, ""))
        for variant in variants
        if variant.semantics_preserved and variant.expected_verdict is Verdict.MALICIOUS
    )
    for steps, context_id in cases:
        old_hit, old_score = _alerts(old, steps, context_id, threshold, meter)
        if not (old_hit and old_score >= threshold):
            continue
        new_hit, new_score = _alerts(new, steps, context_id, threshold, meter)
        if not (new_hit and new_score >= threshold):
            return True
    return False


def _context_recall(
    item: KnowledgeItem,
    positives: Sequence[EpisodeSkeleton],
    threshold: float,
    meter: WorkMeter,
    *,
    anywhere: bool = False,
) -> float:
    hits = 0
    for episode in positives:
        hit, score = _alerts(
            item, episode.steps, episode.context_id, threshold, meter, anywhere=anywhere
        )
        hits += hit and score >= threshold
    return hits / len(positives) if positives else 0.0


def _coexists(
    new: KnowledgeItem,
    old: KnowledgeItem,
    *,
    replay: Sequence[EpisodeSkeleton],
    threshold: float,
    meter: WorkMeter,
    eps: float,
) -> bool:
    """Disjoint applicability, and each is within ``eps`` of the better on its own contexts."""
    if not _disjoint(new.context_ids, old.context_ids):
        return False
    positives, _ = _labelled(replay)
    for owner in (new, old):
        own = [episode for episode in positives if applies_to(owner, episode.context_id)]
        mine = _context_recall(owner, own, threshold, meter)
        # The rival is scored on the owner's episodes as if it applied there:
        # "best" means the better explanation of these episodes, not the one that
        # happens to be switched on for them.
        rival = new if owner is old else old
        best = max(mine, _context_recall(rival, own, threshold, meter, anywhere=True))
        if mine < best - eps:
            return False
    return True


def compete_knowledge(
    new: KnowledgeItem,
    old: KnowledgeItem,
    *,
    replay: Sequence[EpisodeSkeleton],
    variants: Sequence[ReplayVariant],
    threshold: float,
    meter: WorkMeter,
) -> CompetitionResult:
    """HEL-F10. See the module docstring for the exact rule."""
    # Imported here, not at module scope: conservation/gate.py owns EPS_SECURITY
    # (§4.21) and itself depends on the chamber, which depends on this module.
    from pocketsec.stage6.conservation.gate import EPS_SECURITY

    _require_detector(new, "new")
    _require_detector(old, "old")
    new_scores = score_detector(
        new, replay=replay, variants=variants, threshold=threshold, meter=meter
    )
    old_scores = score_detector(
        old, replay=replay, variants=variants, threshold=threshold, meter=meter
    )

    def result(outcome: CompetitionOutcome, reason: str) -> CompetitionResult:
        return CompetitionResult(outcome, new.item_id, old.item_id, new_scores, old_scores, reason)

    dominant = _dominates(new_scores, old_scores)
    if dominant and covers(new_scores.applicability, old_scores.applicability):
        if old.protected and _protected_loss(
            new, old, replay=replay, variants=variants, threshold=threshold, meter=meter
        ):
            return result(
                CompetitionOutcome.REJECT_NEW, "protected_old_item_catches_what_new_misses"
            )
        return result(CompetitionOutcome.REPLACE, "pareto_dominates")
    if _coexists(new, old, replay=replay, threshold=threshold, meter=meter, eps=EPS_SECURITY):
        return result(CompetitionOutcome.COEXIST, "disjoint_contexts_both_valid")
    return result(CompetitionOutcome.REJECT_NEW, "not_dominating")


def _control(
    new: KnowledgeItem,
    old: KnowledgeItem,
    outcome: CompetitionOutcome,
    reason: str,
    replay: Sequence[EpisodeSkeleton],
    variants: Sequence[ReplayVariant],
    threshold: float,
    meter: WorkMeter,
) -> CompetitionResult:
    """A control's fixed decision, with the same scores so its rows compare."""
    return CompetitionResult(
        outcome,
        new.item_id,
        old.item_id,
        score_detector(new, replay=replay, variants=variants, threshold=threshold, meter=meter),
        score_detector(old, replay=replay, variants=variants, threshold=threshold, meter=meter),
        reason,
    )


def newest_wins(
    new: KnowledgeItem,
    old: KnowledgeItem,
    *,
    replay: Sequence[EpisodeSkeleton],
    variants: Sequence[ReplayVariant],
    threshold: float,
    meter: WorkMeter,
) -> CompetitionResult:
    """SIMPLE CONTROL: always REPLACE."""
    return _control(
        new,
        old,
        CompetitionOutcome.REPLACE,
        "control_newest_wins",
        replay,
        variants,
        threshold,
        meter,
    )


def oldest_wins(
    new: KnowledgeItem,
    old: KnowledgeItem,
    *,
    replay: Sequence[EpisodeSkeleton],
    variants: Sequence[ReplayVariant],
    threshold: float,
    meter: WorkMeter,
) -> CompetitionResult:
    """SIMPLE CONTROL: never replace."""
    return _control(
        new,
        old,
        CompetitionOutcome.REJECT_NEW,
        "control_oldest_wins",
        replay,
        variants,
        threshold,
        meter,
    )


def overlaps(
    a: KnowledgeItem,
    b: KnowledgeItem,
    *,
    replay: Sequence[EpisodeSkeleton] = (),
    meter: WorkMeter | None = None,
) -> bool:
    """Same kind and (same pattern_key, or their motif match-sets intersect on replay)."""
    if a.kind is not b.kind:
        return False
    if a.pattern_key == b.pattern_key or (a.motif and a.motif == b.motif):
        return True
    if a.kind is not ItemKind.DETECTOR or not replay:
        return False
    counter = meter if meter is not None else WorkMeter()
    for episode in replay:
        counter.charge(max(1, 2 * len(episode.steps)))
        if match_motif(a.motif, episode.steps) and match_motif(b.motif, episode.steps):
            return True
    return False
