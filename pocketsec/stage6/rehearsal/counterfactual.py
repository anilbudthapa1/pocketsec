"""D6.8 / HEL-F11 — counterfactual rehearsal: perturbed replays of stored episode skeletons.

Architecture §14: full raw replay buffers are too expensive, so Stage 6 keeps compact
episode skeletons and *reconstructs* perturbations of them. The purpose is to test
whether a candidate preserves **semantic** security capability rather than memorising
identities, timing or incidental context. The conservation gate's G4 replays the
``semantics_preserved`` variants of the rehearsal positives and refuses a candidate whose
recall on them drops more than ``EPS_COUNTERFACTUAL`` below the trusted state's.

Five kinds, each deterministic from ``seed`` (``random.Random`` seeded with a string,
which does not depend on ``PYTHONHASHSEED``):

* ``RENAME_ACTORS`` permutes ``actor_slot`` values.
* ``ALTER_TIMING`` redraws ``time_bucket`` and the encoder's ``temporal`` feature group.
* ``DROP_TELEMETRY`` removes one step and clears its visibility bit. When the removed step
  is needed by **every** motif that matched the source, the variant is
  ``semantics_preserved=False`` and its ``expected_verdict`` is ``UNKNOWN``: missing
  telemetry is not evidence of innocence, and an episode that lost its only meaningful
  step has no verdict to preserve.
* ``SUBSTITUTE_PROCESS_CLASS`` swaps the ``actor_semantics`` feature group between two
  actors of the episode — never ``object_semantics`` or ``state_delta_raised``, which are
  what the step *means*.
* ``INJECT_DECOYS`` interleaves benign decoy steps under fresh ``actor_slot`` values.

**Stated in advance, derived from the score in spec §4.0 rather than hoped for (lesson 2).**
``score_session`` reads a step's ``relation``, ``object_property_mask``,
``state_delta_mask``, its ``actor_slot`` *only as a grouping key*, and its meaning vector
(``object_semantics`` + ``state_delta_raised`` + ``state_delta_scalars``). It never reads
actor identity values, time, or the ``actor_semantics`` group. Therefore:

* ``RENAME_ACTORS``, ``ALTER_TIMING`` and ``SUBSTITUTE_PROCESS_CLASS`` **cannot change any
  score by construction** (:data:`SCORE_INVARIANT_KINDS`). They are kept as regression
  tests that identity, timing or actor class have not leaked into the representation, and
  are reported ``INERT``, never as a mechanism result. The spec lists SUBSTITUTE among the
  kinds that can fire; reading the score shows it cannot, and this module says so instead
  of reporting a firing count that is structurally zero.
* ``INJECT_DECOYS`` can only *raise* a score: the detector term is a max over motif
  matches, which added steps under fresh actors cannot un-match, and the unexplained term
  is a max over actors, which a new actor can only increase. It can therefore move the
  false-positive side (competition's FP burden), never G4's recall.
* Only ``DROP_TELEMETRY`` can lower a positive's score, so it is the only kind that can
  make G4 refuse a candidate G2 accepted. Its step choice prefers a step whose removal
  still leaves some matching motif intact, because that is the variant that separates a
  robust candidate from a brittle one; if no such step exists the variant is emitted as
  not semantics-preserving.

What it refuses: more than ``MAX_VARIANTS_PER_EPISODE`` variants, and non-BENIGN decoys
(a malicious "decoy" would change the episode's meaning, not its context).
"""

from __future__ import annotations

import hashlib
import random
from collections.abc import Sequence
from dataclasses import dataclass, replace
from enum import StrEnum

from pocketsec.stage0.contracts.threat_prediction_v1 import Verdict
from pocketsec.stage2.encoder.ssir_encoder import FEATURE_LAYOUT, GROUP_OFFSETS
from pocketsec.stage6.capsule.experience_capsule import FEATURE_DECIMALS, EncodedStep
from pocketsec.stage6.memory.episodic import EpisodeSkeleton
from pocketsec.stage6.memory.semantic import MotifStep, is_escalating, match_motif

__all__ = [
    "CAN_LOWER_RECALL_KINDS",
    "MAX_DECOY_STEPS_PER_VARIANT",
    "MAX_TIME_BUCKET",
    "MAX_VARIANTS_PER_EPISODE",
    "SCORE_INVARIANT_KINDS",
    "ReplayVariant",
    "VariantKind",
    "generate_counterfactual_replay",
]

#: §4.21. A chosen parameter: one variant per kind.
MAX_VARIANTS_PER_EPISODE: int = 5
#: Bounds the size of an INJECT_DECOYS variant, so a decoy set cannot inflate replay cost.
MAX_DECOY_STEPS_PER_VARIANT: int = 8
#: The Stage 2 encoder's time-bucket ceiling (``ssir_encoder._MAX_TIME_BUCKET``, private
#: there); a test pins that the two agree, so a changed encoder cannot desynchronise them.
MAX_TIME_BUCKET: int = 15

_TEMPORAL = GROUP_OFFSETS["temporal"]
_ACTOR = GROUP_OFFSETS["actor_semantics"]
_ACTOR_WIDTH = dict(FEATURE_LAYOUT)["actor_semantics"]
#: The encoder's burst indicator: 1.0 when the actor bucket is <= 1.
_BURST_BUCKET = 1


class VariantKind(StrEnum):
    RENAME_ACTORS = "RENAME_ACTORS"
    ALTER_TIMING = "ALTER_TIMING"
    DROP_TELEMETRY = "DROP_TELEMETRY"
    SUBSTITUTE_PROCESS_CLASS = "SUBSTITUTE_PROCESS_CLASS"
    INJECT_DECOYS = "INJECT_DECOYS"


#: Kinds that cannot change any ``score_session`` result by construction (module docstring).
SCORE_INVARIANT_KINDS: frozenset[VariantKind] = frozenset(
    {VariantKind.RENAME_ACTORS, VariantKind.ALTER_TIMING, VariantKind.SUBSTITUTE_PROCESS_CLASS}
)
#: The only kind that can lower a positive's score, hence the only one G4 can fire on.
CAN_LOWER_RECALL_KINDS: frozenset[VariantKind] = frozenset({VariantKind.DROP_TELEMETRY})


@dataclass(frozen=True, slots=True)
class ReplayVariant:
    """One perturbed replay of a stored skeleton.

    ``visibility_mask`` is the source skeleton's mask with the dropped step's bit cleared
    (DROP_TELEMETRY) and otherwise the source mask unchanged; its bit positions refer to
    the **source** skeleton's step indices, so it records which observation went missing.
    """

    variant_id: str
    kind: VariantKind
    source_episode_id: str
    steps: tuple[EncodedStep, ...]
    expected_verdict: Verdict
    semantics_preserved: bool
    visibility_mask: int | None = None


def _rng(seed: int, episode_id: str, kind: VariantKind) -> random.Random:
    return random.Random(f"{seed}|{episode_id}|{kind.value}")


def _variant_id(seed: int, episode_id: str, kind: VariantKind) -> str:
    digest = hashlib.sha256(f"{seed}|{episode_id}|{kind.value}".encode()).hexdigest()
    return f"var-{digest[:16]}"


def _slots(steps: Sequence[EncodedStep]) -> tuple[int, ...]:
    """Distinct actor slots in order of first appearance."""
    return tuple(dict.fromkeys(step.actor_slot for step in steps))


def _rename(steps: Sequence[EncodedStep], rng: random.Random) -> tuple[EncodedStep, ...]:
    slots = list(_slots(steps))
    permuted = slots[:]
    rng.shuffle(permuted)
    if len(slots) > 1 and permuted == slots:
        permuted = permuted[1:] + permuted[:1]  # a rename that renames nothing tests nothing
    mapping = dict(zip(slots, permuted, strict=True))
    return tuple(replace(step, actor_slot=mapping[step.actor_slot]) for step in steps)


def _retime(step: EncodedStep, rng: random.Random) -> EncodedStep:
    actor_bucket = rng.randint(0, MAX_TIME_BUCKET)
    host_bucket = rng.randint(0, MAX_TIME_BUCKET)
    features = list(step.features)
    features[_TEMPORAL] = round(actor_bucket / MAX_TIME_BUCKET, FEATURE_DECIMALS)
    features[_TEMPORAL + 1] = round(host_bucket / MAX_TIME_BUCKET, FEATURE_DECIMALS)
    features[_TEMPORAL + 2] = 1.0 if actor_bucket <= _BURST_BUCKET else 0.0
    return replace(step, features=tuple(features), time_bucket=actor_bucket)


def _actor_semantics(step: EncodedStep) -> tuple[float, ...]:
    return tuple(step.features[_ACTOR : _ACTOR + _ACTOR_WIDTH])


def _with_actor_semantics(step: EncodedStep, values: tuple[float, ...]) -> EncodedStep:
    features = list(step.features)
    features[_ACTOR : _ACTOR + _ACTOR_WIDTH] = values
    return replace(step, features=tuple(features))


def _substitute(steps: Sequence[EncodedStep], rng: random.Random) -> tuple[EncodedStep, ...] | None:
    """Swap the actor-class feature group of two actors; ``None`` if the episode has one actor."""
    slots = _slots(steps)
    if len(slots) < 2:
        return None
    left, right = rng.sample(slots, 2)
    first = {
        slot: _actor_semantics(next(s for s in steps if s.actor_slot == slot))
        for slot in (left, right)
    }
    swapped = {left: first[right], right: first[left]}
    return tuple(
        _with_actor_semantics(step, swapped[step.actor_slot])
        if step.actor_slot in swapped
        else step
        for step in steps
    )


def _drop_preserves(
    skeleton: EpisodeSkeleton, index: int, matching: Sequence[Sequence[MotifStep]]
) -> bool:
    if skeleton.verdict is not Verdict.MALICIOUS:
        # Losing telemetry cannot turn a benign (or unresolved) episode into an attack.
        return True
    remaining = skeleton.steps[:index] + skeleton.steps[index + 1 :]
    if matching:
        # Preserved iff at least one motif that matched the source still matches.
        return any(match_motif(motif, remaining) for motif in matching)
    # No motif knowledge applies: fail closed on any step that carries security meaning.
    return not is_escalating(skeleton.steps[index])


def _drop(
    skeleton: EpisodeSkeleton, rng: random.Random, motifs: Sequence[Sequence[MotifStep]]
) -> tuple[int, bool] | None:
    """Choose the step to drop: a semantics-preserving one if any exists."""
    if not skeleton.steps:
        return None
    matching = [motif for motif in motifs if match_motif(motif, skeleton.steps)]
    indices = list(range(len(skeleton.steps)))
    preserving = [i for i in indices if _drop_preserves(skeleton, i, matching)]
    if preserving:
        return rng.choice(preserving), True
    return rng.choice(indices), False


def _inject(
    steps: Sequence[EncodedStep], decoys: Sequence[EpisodeSkeleton], rng: random.Random
) -> tuple[EncodedStep, ...] | None:
    pool = [decoy for decoy in decoys if decoy.steps]
    if not pool:
        return None
    decoy = pool[rng.randrange(len(pool))]
    base = max(_slots(steps), default=-1) + 1
    fresh = {slot: base + rank for rank, slot in enumerate(_slots(decoy.steps))}
    injected = [
        replace(s, actor_slot=fresh[s.actor_slot])
        for s in decoy.steps[:MAX_DECOY_STEPS_PER_VARIANT]
    ]
    # Interleave at seeded positions, keeping each sequence's own order intact.
    merged: list[EncodedStep] = []
    source, extra = list(steps), injected
    while source or extra:
        share = len(extra) / (len(extra) + len(source))
        take_extra = bool(extra) and (not source or rng.random() < share)
        merged.append(extra.pop(0) if take_extra else source.pop(0))
    return tuple(merged)


def _build(
    kind: VariantKind,
    skeleton: EpisodeSkeleton,
    *,
    seed: int,
    decoys: Sequence[EpisodeSkeleton],
    motifs: Sequence[Sequence[MotifStep]],
) -> ReplayVariant | None:
    rng = _rng(seed, skeleton.episode_id, kind)
    mask = skeleton.visibility_mask
    preserved = True
    if kind is VariantKind.RENAME_ACTORS:
        steps: tuple[EncodedStep, ...] | None = _rename(skeleton.steps, rng)
    elif kind is VariantKind.ALTER_TIMING:
        steps = tuple(_retime(step, rng) for step in skeleton.steps)
    elif kind is VariantKind.SUBSTITUTE_PROCESS_CLASS:
        steps = _substitute(skeleton.steps, rng)
    elif kind is VariantKind.INJECT_DECOYS:
        steps = _inject(skeleton.steps, decoys, rng)
    else:
        choice = _drop(skeleton, rng, motifs)
        if choice is None:
            return None
        index, preserved = choice
        steps = skeleton.steps[:index] + skeleton.steps[index + 1 :]
        mask = mask & ~(1 << index)
    if steps is None:
        return None
    return ReplayVariant(
        variant_id=_variant_id(seed, skeleton.episode_id, kind),
        kind=kind,
        source_episode_id=skeleton.episode_id,
        steps=steps,
        expected_verdict=skeleton.verdict if preserved else Verdict.UNKNOWN,
        semantics_preserved=preserved,
        visibility_mask=mask,
    )


def generate_counterfactual_replay(
    skeleton: EpisodeSkeleton,
    *,
    kinds: Sequence[VariantKind] = tuple(VariantKind),
    seed: int,
    decoys: Sequence[EpisodeSkeleton] = (),
    max_variants: int = MAX_VARIANTS_PER_EPISODE,
    motifs: Sequence[Sequence[MotifStep]] = (),
) -> tuple[ReplayVariant, ...]:
    """HEL-F11. At most one variant per requested kind, at most ``max_variants`` in total.

    ``motifs`` are the detector motifs that define "matching" for DROP_TELEMETRY (normally
    the trusted state's detectors). A kind that cannot apply to this skeleton — SUBSTITUTE
    with one actor, INJECT_DECOYS with no decoys, DROP on an empty skeleton — yields no
    variant rather than a fake one.
    """
    if not 0 <= max_variants <= MAX_VARIANTS_PER_EPISODE:
        raise ValueError(
            f"max_variants must be within [0, {MAX_VARIANTS_PER_EPISODE}], got {max_variants}"
        )
    for decoy in decoys:
        if decoy.verdict is not Verdict.BENIGN:
            raise ValueError(
                f"decoy {decoy.episode_id!r} is {decoy.verdict}; decoys must be BENIGN"
            )
    variants: list[ReplayVariant] = []
    for kind in dict.fromkeys(VariantKind(k) for k in kinds):
        if len(variants) >= max_variants:
            break
        variant = _build(kind, skeleton, seed=seed, decoys=decoys, motifs=motifs)
        if variant is not None:
            variants.append(variant)
    return tuple(variants)
