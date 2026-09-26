"""D8.9 / PROM-F13 — the Adversarial Challenger: does the defence still hold when the world shifts?

A detector measured only on the sessions it was built from has been measured against an
adversary who does not adapt. This module builds **robustness corpora**: synthetic
``Split.CHALLENGE`` episodes derived from LAB_POOL episodes by laboratory transforms, each
kind modelling one way telemetry could move under an adapting adversary or a failing sensor,
and then measures how much of a detector's recall and specificity survives.

Recipes (spec §4 D8.9), all over encoded synthetic steps:

====================== ==============================================================
FEATURE_OBFUSCATION    clear one *non-necessary* property bit on the steps matching a
                       necessary predicate (on escalating steps when none is given)
TIMING_SHIFT           the laboratory ``TIMING_SHIFT`` transform
LOTL_SUBSTITUTION      an ``EXECUTE+TEMP_LOCATION`` step becomes ``SYSTEM_BINARY|ROOT_OWNED``
EVENT_FLOOD            ``DECOY_INSERTION`` up to the episode step cap
RARE_BENIGN_MIMICRY    one necessary-predicate step inserted into a benign episode under
                       a fresh actor
PARTIAL_TELEMETRY_LOSS ``SENSOR_DROPOUT`` at 500 permille, sensor-wide
POISONED_LABELS        a share of the pool's labels flipped (content untouched)
SHORTCUT_TRIGGER       the corpus's trap step inserted at the front of benign episodes
====================== ==============================================================

Labels are the defence's question, not the variant's: a challenged positive stays label 1
and a challenged negative label 0, whatever the transform's own semantics. The one
exception is ``POISONED_LABELS``, whose whole content *is* a label change: its entry measures
how far a detector's recall would appear to move if the labels it is judged against were
poisoned. The training-time half of that challenge (a detector *fitted* on poisoned labels)
is run by ``labs/discovery_run.py`` through :func:`poisoned_labels`.

``recall_retained`` is recall on the challenged episodes divided by recall on their
sources. The source link is not an ``Episode`` field, so :func:`build_challenge_corpus`
returns a :class:`ChallengeCorpus`: an ordinary ``Mapping[ChallengeKind, tuple[Episode, ...]]``
that also carries each challenged episode's source, index for index. A plain mapping
without sources gets ``recall_retained=None`` — UNMEASURED, never a guessed 1.0.

What it refuses to do. **Defensive only (DL-01).** The output is synthetic ``Episode``
values and nothing else: no procedure, command line, payload, file or network artefact is
produced, and no member of :class:`ChallengeKind` names offensive tooling (the constitution
screens the vocabulary against ``OFFENSIVE_TOKENS``). It reads LAB_POOL only (never a
held-out split), charges the run's governor for every episode it derives, and caps each
kind at ``CHALLENGE_PER_KIND`` episodes.
"""

from __future__ import annotations

import random
from collections import Counter
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage6.capsule.experience_capsule import EncodedStep, source_group_of
from pocketsec.stage6.memory.semantic import is_escalating
from pocketsec.stage8.episode import MAX_EPISODE_STEPS, Episode, Split, fit_counts
from pocketsec.stage8.genome.grammar import Mechanism, StepPredicate, parse_mechanism
from pocketsec.stage8.governor.budget import ResearchGovernor
from pocketsec.stage8.laboratory.counterfactual import (
    TransformKind,
    TransformSpec,
    apply_transform,
    restep,
)

__all__ = [
    "CHALLENGER_COMPONENT",
    "CHALLENGE_PER_KIND",
    "DEFAULT_POISON_SHARE",
    "DROPOUT_PERMILLE",
    "LABEL_KEEPING_KINDS",
    "TIMING_SHIFT_BUCKETS",
    "AdversarialChallenge",
    "ChallengeCorpus",
    "ChallengeKind",
    "build_challenge_corpus",
    "challenge",
    "challenge_stats",
    "poisoned_labels",
]

#: Spec §4.21. Chosen, not measured.
CHALLENGE_PER_KIND: int = 32
#: PARTIAL_TELEMETRY_LOSS drops each step with this probability (spec: 500 permille).
DROPOUT_PERMILLE: int = 500
#: TIMING_SHIFT moves every step this many time buckets. Chosen, not measured.
TIMING_SHIFT_BUCKETS: int = 4
#: The share of labels POISONED_LABELS flips in the robustness corpus. Chosen, not measured.
DEFAULT_POISON_SHARE: float = 0.2
CHALLENGER_COMPONENT: str = "challenger"


class ChallengeKind(StrEnum):
    """Ways an adapting adversary or a failing sensor moves telemetry. Detection vocabulary only."""

    FEATURE_OBFUSCATION = "FEATURE_OBFUSCATION"
    TIMING_SHIFT = "TIMING_SHIFT"
    LOTL_SUBSTITUTION = "LOTL_SUBSTITUTION"
    EVENT_FLOOD = "EVENT_FLOOD"
    RARE_BENIGN_MIMICRY = "RARE_BENIGN_MIMICRY"
    PARTIAL_TELEMETRY_LOSS = "PARTIAL_TELEMETRY_LOSS"
    POISONED_LABELS = "POISONED_LABELS"
    SHORTCUT_TRIGGER = "SHORTCUT_TRIGGER"


#: Kinds applied to both classes, each keeping its source label (recall and FPR both measured).
LABEL_KEEPING_KINDS: frozenset[ChallengeKind] = frozenset({
    ChallengeKind.FEATURE_OBFUSCATION,
    ChallengeKind.TIMING_SHIFT,
    ChallengeKind.LOTL_SUBSTITUTION,
    ChallengeKind.EVENT_FLOOD,
    ChallengeKind.PARTIAL_TELEMETRY_LOSS,
})
#: Kinds applied to benign episodes only: they measure false positives, never recall.
_BENIGN_ONLY: frozenset[ChallengeKind] = frozenset(
    {ChallengeKind.RARE_BENIGN_MIMICRY, ChallengeKind.SHORTCUT_TRIGGER}
)

# Masks read from the grammar's own vocabulary, so a renamed property fails loudly here.
_TEMP_EXECUTE: StepPredicate = parse_mechanism("SINGLE(EXECUTE+TEMP_LOCATION)").steps[0]
_TEMP_BIT: int = _TEMP_EXECUTE.require_properties
_SYSTEM_BITS: int = parse_mechanism(
    "SINGLE(EXECUTE+SYSTEM_BINARY+ROOT_OWNED)").steps[0].require_properties


@dataclass(frozen=True, slots=True)
class AdversarialChallenge:
    """One detector against one challenge kind. Plain data; decides nothing."""

    detector_id: str
    kind: ChallengeKind
    episodes: int
    positives: int
    recall_retained: float | None  # recall on challenged / recall on their sources
    false_positive_rate: float | None  # on challenged negatives

    def __post_init__(self) -> None:
        if not isinstance(self.detector_id, str) or not self.detector_id:
            raise ContractError("AdversarialChallenge.detector_id must be a non-empty string")
        if not isinstance(self.kind, ChallengeKind):
            raise ContractError(f"kind must be a ChallengeKind, got {self.kind!r}")
        for name in ("episodes", "positives"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ContractError(f"AdversarialChallenge.{name} must be an int >= 0")
        if self.positives > self.episodes:
            raise ContractError("positives cannot exceed episodes")
        for name in ("recall_retained", "false_positive_rate"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, float) or value < 0.0):
                raise ContractError(f"AdversarialChallenge.{name} must be a float >= 0 or None")
        if self.false_positive_rate is not None and self.false_positive_rate > 1.0:
            raise ContractError("false_positive_rate is a share in [0, 1]")


class ChallengeCorpus(Mapping[ChallengeKind, tuple[Episode, ...]]):
    """Challenged episodes per kind, plus each one's source, index for index. Immutable."""

    __slots__ = ("_challenged", "_not_applicable", "_sources")

    def __init__(
        self,
        challenged: Mapping[ChallengeKind, tuple[Episode, ...]],
        sources: Mapping[ChallengeKind, tuple[Episode, ...]],
        not_applicable: Mapping[ChallengeKind, int],
    ) -> None:
        if set(challenged) != set(sources):
            raise ContractError("every challenge kind needs its sources")
        for kind, episodes in challenged.items():
            if len(episodes) != len(sources[kind]):
                raise ContractError(f"{kind}: challenged and source episodes must align")
            if len(episodes) > CHALLENGE_PER_KIND:
                raise ContractError(f"{kind}: at most {CHALLENGE_PER_KIND} challenged episodes")
        self._challenged = MappingProxyType(dict(challenged))
        self._sources = MappingProxyType(dict(sources))
        self._not_applicable = MappingProxyType(dict(not_applicable))

    def __getitem__(self, kind: ChallengeKind) -> tuple[Episode, ...]:
        return self._challenged[kind]

    def __iter__(self) -> Iterator[ChallengeKind]:
        return iter(self._challenged)

    def __len__(self) -> int:
        return len(self._challenged)

    def sources(self, kind: ChallengeKind) -> tuple[Episode, ...]:
        """The source episode of each challenged episode of ``kind``, in the same order."""
        return self._sources[kind]

    def not_applicable(self) -> Mapping[ChallengeKind, int]:
        """Per kind, pool episodes the recipe was tried on and could not be applied to."""
        return self._not_applicable


# --- recipes ---------------------------------------------------------------------------

_Recipe = Callable[[Episode, "_Context"], Episode | None]


@dataclass(frozen=True, slots=True)
class _Context:
    rng: random.Random
    pool: tuple[Episode, ...]
    necessary: tuple[StepPredicate, ...]
    trap: StepPredicate | None


def _derived(source: Episode, steps: Sequence[EncodedStep], *, truncated: bool = False) -> Episode:
    return Episode(episode_id="", steps=tuple(steps), label=source.label, split=Split.CHALLENGE,
                   context=source.context, truncated=source.truncated or truncated)


def _obfuscate(episode: Episode, ctx: _Context) -> Episode | None:
    required = 0
    for predicate in ctx.necessary:
        required |= predicate.require_properties
    def targeted(step: EncodedStep) -> bool:
        if ctx.necessary:
            return any(p.matches(step) for p in ctx.necessary)
        return is_escalating(step)
    candidates = sorted({
        1 << bit for step in episode.steps if targeted(step)
        for bit in range(step.object_property_mask.bit_length())
        if step.object_property_mask >> bit & 1 and not required >> bit & 1
    })
    if not candidates:
        return None  # nothing but necessary bits to clear: the recipe does not apply
    bit = candidates[ctx.rng.randrange(len(candidates))]
    return _derived(episode, [
        restep(s, object_property_mask=s.object_property_mask & ~bit)
        if targeted(s) and s.object_property_mask & bit else s
        for s in episode.steps
    ])


def _lotl(episode: Episode, ctx: _Context) -> Episode | None:
    if not any(_TEMP_EXECUTE.matches(s) for s in episode.steps):
        return None
    return _derived(episode, [
        restep(s, object_property_mask=(s.object_property_mask & ~_TEMP_BIT) | _SYSTEM_BITS)
        if _TEMP_EXECUTE.matches(s) else s
        for s in episode.steps
    ])


def _transform(kind: TransformKind, parameter: int) -> _Recipe:
    spec = TransformSpec(kind, parameter)
    def recipe(episode: Episode, ctx: _Context) -> Episode | None:
        made = apply_transform(episode, spec, rng=ctx.rng, donors=ctx.pool)
        # The transform's own semantics may leave the label unset (SENSOR_DROPOUT is
        # UNKNOWN to the lab); the challenge keeps the source label on purpose.
        return None if made is None else made.with_split(Split.CHALLENGE, label=episode.label)
    return recipe


def _flood(episode: Episode, ctx: _Context) -> Episode | None:
    room = MAX_EPISODE_STEPS - len(episode.steps)
    return None if room < 1 else _transform(TransformKind.DECOY_INSERTION, room)(episode, ctx)


def _donor(ctx: _Context, predicate: StepPredicate) -> EncodedStep | None:
    return next((s for ep in ctx.pool for s in ep.steps if predicate.matches(s)), None)


def _insert(episode: Episode, step: EncodedStep, position: int, tag: str) -> Episode | None:
    if len(episode.steps) >= MAX_EPISODE_STEPS:
        return None  # no room: inserting would silently drop a real step
    fresh = max(s.actor_slot for s in episode.steps) + 1
    inserted = restep(step, actor_slot=fresh, epoch_id=episode.steps[0].epoch_id,
                      source_group=source_group_of(f"{tag}:{episode.episode_id}"))
    steps = list(episode.steps)
    steps.insert(position, inserted)
    return _derived(episode, steps)


def _mimicry(episode: Episode, ctx: _Context) -> Episode | None:
    if not ctx.necessary:
        return None
    donor = _donor(ctx, ctx.necessary[ctx.rng.randrange(len(ctx.necessary))])
    if donor is None:
        return None
    return _insert(episode, donor, ctx.rng.randint(0, len(episode.steps)), "mimicry")


def _shortcut(episode: Episode, ctx: _Context) -> Episode | None:
    if ctx.trap is None or any(ctx.trap.matches(s) for s in episode.steps):
        return None  # already carries the trigger: inserting it changes nothing
    donor = _donor(ctx, ctx.trap)
    return None if donor is None else _insert(episode, donor, 0, "shortcut")


_RECIPES: Mapping[ChallengeKind, _Recipe] = MappingProxyType({
    ChallengeKind.FEATURE_OBFUSCATION: _obfuscate,
    ChallengeKind.TIMING_SHIFT: _transform(TransformKind.TIMING_SHIFT, TIMING_SHIFT_BUCKETS),
    ChallengeKind.LOTL_SUBSTITUTION: _lotl,
    ChallengeKind.EVENT_FLOOD: _flood,
    ChallengeKind.RARE_BENIGN_MIMICRY: _mimicry,
    ChallengeKind.PARTIAL_TELEMETRY_LOSS: _transform(TransformKind.SENSOR_DROPOUT,
                                                     DROPOUT_PERMILLE),
    ChallengeKind.SHORTCUT_TRIGGER: _shortcut,
})
assert set(_RECIPES) | {ChallengeKind.POISONED_LABELS} == set(ChallengeKind)


# --- public API ------------------------------------------------------------------------


def _require_pool(episodes: Sequence[Episode]) -> tuple[Episode, ...]:
    pool = tuple(episodes)
    for episode in pool:
        if not isinstance(episode, Episode):
            raise ContractError(f"challenge corpora are built from Episodes, got {type(episode)}")
        if episode.split is not Split.LAB_POOL:
            raise ContractError(
                f"challenge corpora are built from LAB_POOL only; {episode.episode_id} is "
                f"{episode.split}"
            )
        if not episode.context.synthetic:
            # S8-DEF-07: adversarial generation perturbs SYNTHETIC telemetry only (standing
            # order); a variant of real telemetry would be recorded as real.
            raise ContractError(
                f"challenge corpora are built from synthetic telemetry only; "
                f"{episode.episode_id} is not synthetic")
    return tuple(ep for ep in pool if ep.label is not None)


def _build_kind(
    kind: ChallengeKind, labelled: tuple[Episode, ...], ctx: _Context,
    governor: ResearchGovernor, cap: int,
) -> tuple[tuple[Episode, ...], tuple[Episode, ...], int]:
    if kind is ChallengeKind.POISONED_LABELS:
        chosen = [labelled[i] for i in sorted(ctx.rng.sample(range(len(labelled)),
                                                             min(cap, len(labelled))))]
        governor.charge(CHALLENGER_COMPONENT, len(chosen))
        flipped = poisoned_labels(chosen, share=DEFAULT_POISON_SHARE, rng=ctx.rng)
        made = tuple(ep.with_split(Split.CHALLENGE, label=ep.label) for ep in flipped)
        return made, tuple(chosen), 0
    order = list(range(len(labelled)))
    ctx.rng.shuffle(order)
    made: list[Episode] = []
    sources: list[Episode] = []
    skipped = 0
    for index in order:
        if len(made) >= cap:
            break
        source = labelled[index]
        if kind in _BENIGN_ONLY and source.label != 0:
            continue
        governor.charge(CHALLENGER_COMPONENT, len(source.steps))  # paid before the work
        result = _RECIPES[kind](source, ctx)
        if result is None:
            skipped += 1
            continue
        made.append(result)
        sources.append(source)
    return tuple(made), tuple(sources), skipped


def build_challenge_corpus(
    episodes: Sequence[Episode],
    *,
    kinds: Sequence[ChallengeKind],
    rng: random.Random,
    governor: ResearchGovernor,
    cap: int = CHALLENGE_PER_KIND,
    necessary: Sequence[StepPredicate] = (),
    trap: Mechanism | None = None,
) -> ChallengeCorpus:
    """Derive at most ``cap`` challenged episodes per kind from LAB_POOL ``episodes``.

    ``necessary`` (a genome's ``necessary_conditions``) steers FEATURE_OBFUSCATION away from
    the bits the theory needs and supplies RARE_BENIGN_MIMICRY's inserted step; ``trap``
    (the corpus's ``trap_mechanism``, a SINGLE) supplies SHORTCUT_TRIGGER's step. Without
    them those recipes apply to nothing, which the corpus records as ``not_applicable``.
    """
    if not isinstance(rng, random.Random):
        raise ContractError("build_challenge_corpus needs an explicit random.Random")
    if not isinstance(governor, ResearchGovernor):
        raise ContractError("build_challenge_corpus needs the run's ResearchGovernor")
    if isinstance(cap, bool) or not isinstance(cap, int) or not 1 <= cap <= CHALLENGE_PER_KIND:
        raise ContractError(f"cap must be an int in 1..{CHALLENGE_PER_KIND}, got {cap!r}")
    requested = tuple(kinds)
    if any(not isinstance(kind, ChallengeKind) for kind in requested):
        raise ContractError("kinds must be ChallengeKind members")
    necessary = tuple(necessary)
    if any(not isinstance(p, StepPredicate) for p in necessary):
        raise ContractError("necessary must be StepPredicate values")
    if trap is not None and (not isinstance(trap, Mechanism) or len(trap.steps) != 1):
        raise ContractError("trap must be the corpus's single-step trap Mechanism")
    labelled = _require_pool(episodes)
    ctx = _Context(rng=rng, pool=labelled, necessary=necessary,
                   trap=None if trap is None else trap.steps[0])
    challenged: dict[ChallengeKind, tuple[Episode, ...]] = {}
    sources: dict[ChallengeKind, tuple[Episode, ...]] = {}
    skipped: dict[ChallengeKind, int] = {}
    for kind in ChallengeKind:  # enum order, so rng use is independent of the caller's order
        if kind in requested:
            challenged[kind], sources[kind], skipped[kind] = _build_kind(
                kind, labelled, ctx, governor, cap)
    return ChallengeCorpus(challenged, sources, skipped)


def _checked(decide: Callable[[Episode], bool]) -> Callable[[Episode], bool]:
    def strict(episode: Episode) -> bool:
        answer = decide(episode)
        if not isinstance(answer, bool):
            raise ContractError(f"a detector decides True or False, got {answer!r}")
        return answer
    return strict


def challenge(
    detector_id: str,
    decide: Callable[[Episode], bool],
    corpus: Mapping[ChallengeKind, tuple[Episode, ...]],
) -> tuple[AdversarialChallenge, ...]:
    """Measure ``decide`` on every kind of ``corpus``, in enum order."""
    if not isinstance(detector_id, str) or not detector_id:
        raise ContractError("detector_id must be a non-empty string")
    if not callable(decide):
        raise ContractError("decide must be callable")
    strict = _checked(decide)
    results: list[AdversarialChallenge] = []
    for kind in ChallengeKind:
        if kind not in corpus:
            continue
        episodes = tuple(corpus[kind])
        counts = fit_counts(strict, episodes)
        retained: float | None = None
        if isinstance(corpus, ChallengeCorpus) and counts.recall is not None:
            before = fit_counts(strict, corpus.sources(kind)).recall
            if before:  # None or 0.0: nothing was retained *from*, so the ratio is undefined
                retained = counts.recall / before
        results.append(AdversarialChallenge(
            detector_id=detector_id, kind=kind, episodes=len(episodes),
            positives=counts.positives, recall_retained=retained,
            false_positive_rate=counts.false_positive_rate,
        ))
    return tuple(results)


def poisoned_labels(
    train: Sequence[Episode], *, share: float, rng: random.Random
) -> tuple[Episode, ...]:
    """``train`` with ``round(share * labelled)`` labels flipped; order and content unchanged.

    Unlabelled episodes are never touched and never counted. The split is kept: this is a
    training-time challenge, and a poisoned TRAIN episode is still a TRAIN episode.
    """
    if isinstance(share, bool) or not isinstance(share, int | float) or not 0.0 <= share <= 1.0:
        raise ContractError(f"share must be in [0, 1], got {share!r}")
    if not isinstance(rng, random.Random):
        raise ContractError("poisoned_labels needs an explicit random.Random")
    episodes = tuple(train)
    if any(not isinstance(ep, Episode) for ep in episodes):
        raise ContractError("poisoned_labels takes Episodes")
    labelled = [i for i, ep in enumerate(episodes) if ep.label is not None]
    flip = set(rng.sample(labelled, round(float(share) * len(labelled))))
    return tuple(
        ep.with_split(ep.split, label=1 - ep.label) if i in flip and ep.label is not None else ep
        for i, ep in enumerate(episodes)
    )


def challenge_stats(corpus: ChallengeCorpus) -> Mapping[str, int]:
    """Firing counts of a corpus build: episodes made and recipes that did not apply, per kind."""
    counts: Counter[str] = Counter()
    for kind in corpus:
        counts[f"made:{kind.value}"] = len(corpus[kind])
        counts[f"not_applicable:{kind.value}"] = corpus.not_applicable().get(kind, 0)
    return MappingProxyType(dict(counts))
