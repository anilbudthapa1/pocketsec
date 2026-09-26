"""D8.7 / PROM-F11 — the Metamorphic Laboratory: does a detector honour its own semantics?

A detector that claims to see a *mechanism* must not change its mind when the world changes
in ways the mechanism cannot see (an actor renamed, a clock shifted, a harmless decoy), and
must lose its support when the step it claims to need is taken away. Those are metamorphic
relations: tests that need no new ground truth, only the source decision and the transformed
one. They are how the laboratory catches a detector that is right for the wrong reason (the
TRAIN-only shortcut fires on the trap step, so deleting it collapses the support; a detector
keyed on slot numbers flips under ACTOR_RENAME).

``decide`` is any detector: a genome's ``decides``, a compiled FORGE representation, a
baseline. It is treated as opaque, so the result says only what the detector did, never why.

What it refuses to do. A relation over zero applicable episodes has ``holds=None``, never
True: a test that ran on nothing passed nothing. A SUPPORT_FALLS relation over episodes on
which the detector never fired is also ``None`` (there was no support to fall). It never
labels anything and never writes anywhere; its only side effect is the governor's work
accounting. Every transform and every decision is charged to the run's ``ResearchGovernor``
before it runs, so a runaway sweep ends in ``WorkBudgetExceeded``, not on the host.

``NECESSARY_STEP_DELETION`` without a target (the default relation, which cannot know the
detector's mechanism) uses the detector itself: for each episode the detector fires on, the
steps are deleted one at a time, in order, and the support falls for that episode iff some
single deletion flips the decision. That costs up to ``MAX_EPISODE_STEPS`` decisions per
episode, all charged. A caller that knows the necessary predicate passes it as ``target``.
"""

from __future__ import annotations

import random
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum

from pocketsec.stage0.contracts.common import ContractError, require_identifier
from pocketsec.stage8.episode import Episode, Split
from pocketsec.stage8.governor.budget import ResearchGovernor
from pocketsec.stage8.genome.grammar import StepPredicate
from pocketsec.stage8.laboratory.counterfactual import (
    TransformKind,
    TransformSpec,
    apply_transform,
    decoy_is_neutral,
)

__all__ = [
    "DEFAULT_RELATIONS",
    "INVARIANCE_TOLERANCE",
    "MAX_METAMORPHIC_EPISODES",
    "MAX_METAMORPHIC_RELATIONS",
    "METAMORPHIC_COMPONENT",
    "SUPPORT_FALLS_SHARE",
    "Expectation",
    "MetamorphicRelation",
    "MetamorphicResult",
    "run_metamorphic",
]

#: Chosen parameters (§4.21), not measurements.
INVARIANCE_TOLERANCE: float = 0.02
SUPPORT_FALLS_SHARE: float = 0.5
MAX_METAMORPHIC_EPISODES: int = 4096
MAX_METAMORPHIC_RELATIONS: int = 32
#: The governor component every charge of this module is attributed to.
METAMORPHIC_COMPONENT = "laboratory.metamorphic"


class Expectation(StrEnum):
    INVARIANT = "INVARIANT"          # decisions unchanged, within tolerance
    SUPPORT_FALLS = "SUPPORT_FALLS"  # at least ``tolerance`` of the matches disappear


@dataclass(frozen=True, slots=True)
class MetamorphicRelation:
    relation_id: str
    transform: TransformSpec
    expectation: Expectation
    tolerance: float

    def __post_init__(self) -> None:
        require_identifier(self.relation_id, "MetamorphicRelation.relation_id")
        if not isinstance(self.transform, TransformSpec):
            raise ContractError("MetamorphicRelation.transform must be a TransformSpec")
        try:
            object.__setattr__(self, "expectation", Expectation(self.expectation))
        except ValueError as exc:
            raise ContractError(f"unknown Expectation {self.expectation!r}") from exc
        value = self.tolerance
        if (isinstance(value, bool) or not isinstance(value, (int, float))
                or not 0.0 <= value <= 1.0):
            raise ContractError(f"MetamorphicRelation.tolerance must be in [0, 1], got {value!r}")
        object.__setattr__(self, "tolerance", float(value))


@dataclass(frozen=True, slots=True)
class MetamorphicResult:
    relation_id: str
    episodes: int
    applicable: int
    agreement: float | None      # INVARIANT: share of unchanged decisions; else None
    support_before: int          # applicable episodes the detector fired on, untransformed
    support_after: int           # applicable episodes it fired on, transformed
    holds: bool | None           # None when applicable == 0 (never True on nothing)

    def __post_init__(self) -> None:
        if self.applicable == 0 and self.holds is not None:
            raise ContractError("a relation over zero applicable episodes cannot hold or fail")
        if not 0 <= self.applicable <= self.episodes:
            raise ContractError("applicable must be in [0, episodes]")


DEFAULT_RELATIONS: tuple[MetamorphicRelation, ...] = (
    MetamorphicRelation("mr-actor-rename", TransformSpec(TransformKind.ACTOR_RENAME, 1),
                        Expectation.INVARIANT, INVARIANCE_TOLERANCE),
    MetamorphicRelation("mr-timing-shift", TransformSpec(TransformKind.TIMING_SHIFT, 3),
                        Expectation.INVARIANT, INVARIANCE_TOLERANCE),
    MetamorphicRelation("mr-parent-substitution",
                        TransformSpec(TransformKind.PARENT_SUBSTITUTION, 1),
                        Expectation.INVARIANT, INVARIANCE_TOLERANCE),
    MetamorphicRelation("mr-epoch-change", TransformSpec(TransformKind.EPOCH_CHANGE, 1),
                        Expectation.INVARIANT, INVARIANCE_TOLERANCE),
    MetamorphicRelation("mr-decoy-insertion", TransformSpec(TransformKind.DECOY_INSERTION, 4),
                        Expectation.INVARIANT, INVARIANCE_TOLERANCE),
    MetamorphicRelation("mr-necessary-step-deletion",
                        TransformSpec(TransformKind.NECESSARY_STEP_DELETION, 0),
                        Expectation.SUPPORT_FALLS, SUPPORT_FALLS_SHARE),
)

_Decide = Callable[[Episode], bool]


@dataclass(slots=True)
class _Tally:
    applicable: int = 0
    agree: int = 0
    before: int = 0
    after: int = 0


def _decided(decide: _Decide, episode: Episode, governor: ResearchGovernor) -> bool:
    governor.charge(METAMORPHIC_COMPONENT, len(episode.steps))  # one feature read per step
    return bool(decide(episode))


def _without(episode: Episode, index: int) -> Episode:
    steps = episode.steps[:index] + episode.steps[index + 1:]
    return Episode(episode_id="", steps=steps, label=None, split=Split.CHALLENGE,
                   context=episode.context, truncated=episode.truncated)


def _leave_one_out(decide: _Decide, episode: Episode, governor: ResearchGovernor,
                   tally: _Tally) -> None:
    """Untargeted deletion: does any single-step deletion remove this episode's match?"""
    if len(episode.steps) < 2 or not _decided(decide, episode, governor):
        return  # nothing fires, or nothing could remain: not applicable
    tally.applicable += 1
    tally.before += 1
    for index in range(len(episode.steps)):
        governor.charge(METAMORPHIC_COMPONENT, len(episode.steps))  # building the variant
        if not _decided(decide, _without(episode, index), governor):
            return  # the support fell on this episode
    tally.after += 1


def _transformed(decide: _Decide, episode: Episode, relation: MetamorphicRelation,
                 pool: Sequence[Episode], rng: random.Random, governor: ResearchGovernor,
                 tally: _Tally, decoy_avoid: Sequence[StepPredicate]) -> None:
    governor.charge(METAMORPHIC_COMPONENT, len(episode.steps))  # the transform reads every step
    derived = apply_transform(episode, relation.transform, rng=rng, donors=pool)
    if derived is None:
        return
    if (relation.transform.kind is TransformKind.DECOY_INSERTION
            and not decoy_is_neutral(episode, derived, decoy_avoid)):
        return  # F1: a decoy the hypothesis names is not a harmless decoy for it
    source = _decided(decide, episode, governor)
    variant = _decided(decide, derived, governor)
    tally.applicable += 1
    tally.agree += source == variant
    tally.before += source
    tally.after += variant


def _result(relation: MetamorphicRelation, episodes: int, tally: _Tally) -> MetamorphicResult:
    agreement: float | None = None
    holds: bool | None = None
    if tally.applicable and relation.expectation is Expectation.INVARIANT:
        agreement = tally.agree / tally.applicable
        holds = agreement >= 1.0 - relation.tolerance
    elif tally.applicable and tally.before:
        holds = (tally.before - tally.after) / tally.before >= relation.tolerance
    return MetamorphicResult(relation.relation_id, episodes, tally.applicable, agreement,
                             tally.before, tally.after, holds)


def run_metamorphic(decide: _Decide, episodes: Sequence[Episode],
                    relations: Sequence[MetamorphicRelation], *, rng: random.Random,
                    governor: ResearchGovernor,
                    decoy_avoid: Sequence[StepPredicate] = ()) -> tuple[MetamorphicResult, ...]:
    """One ``MetamorphicResult`` per relation, in order, every unit charged to ``governor``.

    ``decoy_avoid`` is the tested hypothesis's predicates when the detector is one: a
    DECOY_INSERTION world whose decoy matches one of them is not applicable (F1). An opaque
    detector passes nothing, and the relation then reads every decoy as harmless.
    """
    if not callable(decide):
        raise ContractError("run_metamorphic needs a callable detector")
    if not isinstance(governor, ResearchGovernor):
        raise ContractError("run_metamorphic needs the run's ResearchGovernor")
    if not isinstance(rng, random.Random):
        raise ContractError("run_metamorphic needs an explicit random.Random (reproducibility)")
    pool = tuple(episodes)
    if len(pool) > MAX_METAMORPHIC_EPISODES or len(relations) > MAX_METAMORPHIC_RELATIONS:
        raise ContractError(f"run_metamorphic is bounded to {MAX_METAMORPHIC_EPISODES} episodes "
                            f"and {MAX_METAMORPHIC_RELATIONS} relations")
    if any(not isinstance(e, Episode) for e in pool):
        raise ContractError("run_metamorphic takes Episode values only")
    results: list[MetamorphicResult] = []
    for relation in relations:
        if not isinstance(relation, MetamorphicRelation):
            raise ContractError("run_metamorphic takes MetamorphicRelation values only")
        tally = _Tally()
        untargeted = (relation.transform.kind is TransformKind.NECESSARY_STEP_DELETION
                      and relation.transform.target is None)
        for episode in pool:
            if untargeted:
                _leave_one_out(decide, episode, governor, tally)
            else:
                _transformed(decide, episode, relation, pool, rng, governor, tally,
                             tuple(decoy_avoid))
        results.append(_result(relation, len(pool), tally))
    return tuple(results)
