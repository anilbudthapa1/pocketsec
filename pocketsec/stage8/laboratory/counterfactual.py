"""D8.7 / PROM-F10 — the Counterfactual Laboratory: typed transforms of encoded episodes.

A hypothesis that survives only the data it was born on has not been tested. This module
manufactures the *other* worlds a mechanism claims to be indifferent to (an actor renamed, a
clock shifted, a decoy actor doing harmless work) and the worlds it claims to depend on (its
necessary step deleted), so a falsifier can ask the question directly instead of hoping the
held-out split happens to contain the answer.

What it is for, bound to the contract:

* Every transform is a closed ``TransformKind`` with a fixed ``Semantics`` row
  (``TRANSFORM_SEMANTICS``). PRESERVING results keep the source label; DESTROYING and UNKNOWN
  results are **unlabelled** (``label=None``): the laboratory never invents ground truth for
  a world it cannot vouch for.
* Every result is ``Split.CHALLENGE``. A transform that does not apply (no target step, nothing
  to substitute, nothing left) returns ``None`` rather than a silent copy, so "applicable" is a
  count a metamorphic test can be judged on.
* ``restep`` is the only way a step changes. It rewrites the one-hot and mask feature groups
  through Stage 2's ``GROUP_OFFSETS`` so a pooled-feature detector sees exactly the change a
  mask detector sees; ``EncodedStep`` re-validates every result.

What it refuses to do. It operates on **synthetic encoded telemetry only**: no transform
produces a command line, a file, a packet or anything that runs outside this process. The
vocabulary names perturbations of observations (DL-01). It never touches Stage 1 raw
evidence: a derived episode carries the source's evidence digests, so lineage survives, but
the raw ``ScenarioResult`` is never rewritten.

Bounded: an episode never exceeds ``MAX_EPISODE_STEPS`` (decoys that do not fit are counted
and flag ``truncated``); a counterfactual set never exceeds its cap, and the pairs the cap
refused are counted in ``CounterfactualBatch.truncated``, never dropped silently.
"""

from __future__ import annotations

import hashlib
import random
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.ssir.relations import Relation, RelationFamily, family_of
from pocketsec.stage2.encoder.ssir_encoder import FEATURE_LAYOUT, GROUP_OFFSETS, feature_names
from pocketsec.stage6.capsule.experience_capsule import EncodedStep, source_group_of
from pocketsec.stage6.memory.semantic import is_escalating
from pocketsec.stage8.episode import MAX_EPISODE_STEPS, Episode, Split
from pocketsec.stage8.genome.grammar import StepPredicate

__all__ = [
    "MAX_COUNTERFACTUAL_SET",
    "MAX_TIME_BUCKET",
    "TRANSFORM_SEMANTICS",
    "TRANSFORM_VERSION",
    "CounterfactualBatch",
    "Semantics",
    "TransformKind",
    "TransformSpec",
    "apply_transform",
    "build_counterfactuals",
    "counterfactual_set",
    "decoy_is_neutral",
    "decoy_steps",
    "restep",
]

TRANSFORM_VERSION = "stage8-lab-transforms.1.0.0"
#: Hard ceiling on one counterfactual set, whatever cap a caller asks for. A chosen
#: parameter: a runaway caller must hit a bound, not the host.
MAX_COUNTERFACTUAL_SET: int = 4096
#: The encoder's time-bucket scale (``ssir_encoder._MAX_TIME_BUCKET``); buckets are clamped here.
MAX_TIME_BUCKET: int = 15
_PERMILLE = 1000
#: ``EncodedStep`` requires features rounded to 6 dp (Stage 6's ``FEATURE_DECIMALS``, which
#: ADR-0071 does not let Stage 8 import). A mismatch is refused by ``EncodedStep`` itself.
_DECIMALS = 6


class TransformKind(StrEnum):
    ACTOR_RENAME = "ACTOR_RENAME"
    TIMING_SHIFT = "TIMING_SHIFT"
    SENSOR_DROPOUT = "SENSOR_DROPOUT"
    PARENT_SUBSTITUTION = "PARENT_SUBSTITUTION"
    DESTINATION_CLASS_SWAP = "DESTINATION_CLASS_SWAP"
    EPOCH_CHANGE = "EPOCH_CHANGE"
    DECOY_INSERTION = "DECOY_INSERTION"
    NECESSARY_STEP_DELETION = "NECESSARY_STEP_DELETION"
    REORDER = "REORDER"
    ACTOR_SPLIT = "ACTOR_SPLIT"


class Semantics(StrEnum):
    PRESERVING = "PRESERVING"
    DESTROYING = "DESTROYING"
    UNKNOWN = "UNKNOWN"


#: What each transform does to the lab ground truth. PRESERVING: the grammar has no
#: vocabulary for slot names, time, parents or epochs, and a decoy is non-escalating work by
#: another actor. DECOY_INSERTION is PRESERVING only *relative to a hypothesis none of whose
#: predicates a decoy step matches* (F1): the grammar says a mechanism fires "in some actor",
#: so a decoy that performs a step the hypothesis names is an instance of the hypothesis, not
#: harmless noise, and "the lab says non-escalating work is harmless" would silently refute every
#: hypothesis over a non-escalating step while never testing one over an escalating step. Every
#: consumer that judges a hypothesis on decoyed worlds filters them with :func:`decoy_is_neutral`.
#: DESTROYING is relative to the target predicate. UNKNOWN: whether lost
#: telemetry, a different destination, a different order or a different actor changes the
#: truth is exactly what a hypothesis is being asked, so the lab refuses to answer it.
TRANSFORM_SEMANTICS: Mapping[TransformKind, Semantics] = MappingProxyType({
    TransformKind.ACTOR_RENAME: Semantics.PRESERVING,
    TransformKind.TIMING_SHIFT: Semantics.PRESERVING,
    TransformKind.PARENT_SUBSTITUTION: Semantics.PRESERVING,
    TransformKind.EPOCH_CHANGE: Semantics.PRESERVING,
    TransformKind.DECOY_INSERTION: Semantics.PRESERVING,
    TransformKind.NECESSARY_STEP_DELETION: Semantics.DESTROYING,
    TransformKind.SENSOR_DROPOUT: Semantics.UNKNOWN,
    TransformKind.DESTINATION_CLASS_SWAP: Semantics.UNKNOWN,
    TransformKind.REORDER: Semantics.UNKNOWN,
    TransformKind.ACTOR_SPLIT: Semantics.UNKNOWN,
})

#: Inclusive parameter range per kind. SENSOR_DROPOUT: permille; ACTOR_RENAME: slot offset;
#: TIMING_SHIFT: bucket delta; EPOCH_CHANGE: epoch delta; DECOY_INSERTION: decoy count;
#: PARENT_SUBSTITUTION: salt; REORDER: 0 = move the target step to the front of its actor,
#: 1 = to the back. The rest take no parameter.
_PARAMETER_RANGE: Mapping[TransformKind, tuple[int, int]] = MappingProxyType({
    TransformKind.ACTOR_RENAME: (1, MAX_EPISODE_STEPS),
    TransformKind.TIMING_SHIFT: (-MAX_TIME_BUCKET, MAX_TIME_BUCKET),
    TransformKind.SENSOR_DROPOUT: (0, _PERMILLE),
    TransformKind.PARENT_SUBSTITUTION: (0, 2**31 - 1),
    TransformKind.DESTINATION_CLASS_SWAP: (0, 0),
    TransformKind.EPOCH_CHANGE: (1, 2**16),
    TransformKind.DECOY_INSERTION: (1, MAX_EPISODE_STEPS),
    TransformKind.NECESSARY_STEP_DELETION: (0, 0),
    TransformKind.REORDER: (0, 1),
    TransformKind.ACTOR_SPLIT: (0, 0),
})


@dataclass(frozen=True, slots=True)
class TransformSpec:
    """One transform request. ``target`` names the step a targeted transform acts on.

    ``target`` is meaningful for NECESSARY_STEP_DELETION, REORDER, ACTOR_SPLIT (which do not
    apply without one), DESTINATION_CLASS_SWAP (default: every EXTERNAL_ENDPOINT step) and
    SENSOR_DROPOUT (the relation family of ``target.relation``; default: every family, a
    sensor-wide loss). The other kinds ignore it.
    """

    kind: TransformKind
    parameter: int
    target: StepPredicate | None = None

    def __post_init__(self) -> None:
        try:
            kind = TransformKind(self.kind)
        except ValueError as exc:
            raise ContractError(f"unknown TransformKind {self.kind!r}") from exc
        value = self.parameter
        if isinstance(value, bool) or not isinstance(value, int):
            raise ContractError(f"TransformSpec.parameter must be an int, got {value!r}")
        low, high = _PARAMETER_RANGE[kind]
        if not low <= value <= high:
            raise ContractError(f"{kind} parameter must be in [{low}, {high}], got {value}")
        if self.target is not None and not isinstance(self.target, StepPredicate):
            raise ContractError(f"TransformSpec.target must be a StepPredicate or None, got "
                                f"{type(self.target).__name__}")
        object.__setattr__(self, "kind", kind)


# --- restep: the one way a step changes ---------------------------------------------

_WIDTH: Mapping[str, int] = MappingProxyType(dict(FEATURE_LAYOUT))
_RESTEP_KEYS = frozenset({
    "relation", "object_property_mask", "state_delta_mask", "time_bucket", "host_bucket",
    "actor_slot", "epoch_id", "observation_incomplete", "parent_signature", "source_group",
})


def _property_bit(name: str) -> int:
    """The object-property bit of ``name``, read from the encoder's own feature names."""
    offset = GROUP_OFFSETS["object_semantics"]
    names = feature_names()[offset:offset + _WIDTH["object_semantics"]]
    return 1 << names.index(f"object.{name}")


_EXTERNAL_BIT = _property_bit("EXTERNAL_ENDPOINT")


def _set_group(features: list[float], group: str, bits: int) -> None:
    """Write ``bits`` into a 0/1 feature group, bit *i* at offset + *i*."""
    width = _WIDTH[group]
    if isinstance(bits, bool) or not isinstance(bits, int) or not 0 <= bits < 2**width:
        raise ContractError(f"{group} needs an int mask in [0, 2**{width}), got {bits!r}")
    offset = GROUP_OFFSETS[group]
    for index in range(width):
        features[offset + index] = 1.0 if bits >> index & 1 else 0.0


def _bucket(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_TIME_BUCKET:
        raise ContractError(f"{name} must be an int in [0, {MAX_TIME_BUCKET}], got {value!r}")
    return value


def _restep_relation(features: list[float], value: object, fields: dict[str, Any]) -> None:
    try:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(value)
        relation = Relation(value)
    except ValueError as exc:
        raise ContractError(f"restep relation must be a Relation value, got {value!r}") from exc
    family = family_of(relation)
    _set_group(features, "relation_onehot", 1 << int(relation))
    _set_group(features, "relation_family_onehot", 1 << int(family))
    fields["relation"] = int(relation)
    fields["relation_family"] = int(family)


def _restep_raised(features: list[float], mask: object, fields: dict[str, Any]) -> None:
    _set_group(features, "state_delta_raised", mask)  # type: ignore[arg-type]
    scalars = GROUP_OFFSETS["state_delta_scalars"]
    count = bin(int(mask)).count("1")  # type: ignore[call-overload]
    features[scalars + 1] = min(1.0, count / _WIDTH["state_delta_raised"])
    if count == 0:
        # A magnitude is a lattice distance and cannot be re-derived from a mask; it is
        # cleared with the mask (nothing raised moved nothing) and otherwise kept.
        features[scalars] = 0.0
    fields["state_delta_mask"] = int(mask)  # type: ignore[call-overload]


def _restep_temporal(features: list[float], changes: Mapping[str, Any],
                     fields: dict[str, Any]) -> None:
    temporal = GROUP_OFFSETS["temporal"]
    if "time_bucket" in changes:
        bucket = _bucket(changes["time_bucket"], "time_bucket")
        features[temporal] = bucket / MAX_TIME_BUCKET
        features[temporal + 2] = 1.0 if bucket <= 1 else 0.0  # the encoder's burst rule
        fields["time_bucket"] = bucket
    if "host_bucket" in changes:
        features[temporal + 1] = _bucket(changes["host_bucket"], "host_bucket") / MAX_TIME_BUCKET


def restep(step: EncodedStep, **changes: Any) -> EncodedStep:
    """Return ``step`` with ``changes`` applied and every dependent feature re-derived.

    Keys: ``relation`` (relation + family one-hots, ``relation_family``),
    ``object_property_mask`` (``object_semantics``), ``state_delta_mask``
    (``state_delta_raised`` and the dimension-count scalar), ``time_bucket`` /
    ``host_bucket`` (``temporal``, including the burst indicator), ``observation_incomplete``
    (``uncertainty[1]``), ``parent_signature`` (``causal[1]``, has-parent), and the
    feature-free ``actor_slot``, ``epoch_id``, ``source_group``. ``features`` and
    ``relation_family`` are derived and may not be set; an unknown key is refused.
    """
    if not isinstance(step, EncodedStep):
        raise ContractError(f"restep needs an EncodedStep, got {type(step).__name__}")
    unknown = sorted(set(changes) - _RESTEP_KEYS)
    if unknown:
        raise ContractError(f"restep cannot change {unknown}; allowed {sorted(_RESTEP_KEYS)}")
    features = list(step.features)
    fields: dict[str, Any] = {}
    if "relation" in changes:
        _restep_relation(features, changes["relation"], fields)
    if "object_property_mask" in changes:
        _set_group(features, "object_semantics", changes["object_property_mask"])
        fields["object_property_mask"] = changes["object_property_mask"]
    if "state_delta_mask" in changes:
        _restep_raised(features, changes["state_delta_mask"], fields)
    _restep_temporal(features, changes, fields)
    if "observation_incomplete" in changes:
        flag = changes["observation_incomplete"]
        if not isinstance(flag, bool):
            raise ContractError(f"observation_incomplete must be a bool, got {flag!r}")
        features[GROUP_OFFSETS["uncertainty"] + 1] = 1.0 if flag else 0.0
    if "parent_signature" in changes:
        parent = changes["parent_signature"]
        features[GROUP_OFFSETS["causal"] + 1] = 0.0 if str(parent).strip("0") == "" else 1.0
        fields["parent_signature"] = parent
    for name in ("actor_slot", "epoch_id", "source_group"):
        if name in changes:
            fields[name] = changes[name]
    rounded = tuple(round(value, _DECIMALS) for value in features)
    return replace(step, features=rounded, **fields)


# --- transform handlers ---------------------------------------------------------------

_Outcome = tuple[list[EncodedStep], bool] | None
_Handler = Callable[[Episode, TransformSpec, random.Random, Sequence[Episode]], _Outcome]


def _host_bucket(step: EncodedStep) -> int:
    return round(step.features[GROUP_OFFSETS["temporal"] + 1] * MAX_TIME_BUCKET)


def _clamp(value: int) -> int:
    return max(0, min(MAX_TIME_BUCKET, value))


def _actor_rename(episode: Episode, spec: TransformSpec, rng: random.Random,
                  donors: Sequence[Episode]) -> _Outcome:
    return [restep(s, actor_slot=s.actor_slot + spec.parameter) for s in episode.steps], False


def _timing_shift(episode: Episode, spec: TransformSpec, rng: random.Random,
                  donors: Sequence[Episode]) -> _Outcome:
    delta = spec.parameter
    return [restep(s, time_bucket=_clamp(s.time_bucket + delta),
                   host_bucket=_clamp(_host_bucket(s) + delta)) for s in episode.steps], False


def _epoch_change(episode: Episode, spec: TransformSpec, rng: random.Random,
                  donors: Sequence[Episode]) -> _Outcome:
    return [restep(s, epoch_id=s.epoch_id + spec.parameter) for s in episode.steps], False


def _parent_substitution(episode: Episode, spec: TransformSpec, rng: random.Random,
                         donors: Sequence[Episode]) -> _Outcome:
    if not any(s.parent_signature.strip("0") for s in episode.steps):
        return None  # nothing has a parent to substitute
    steps = []
    for step in episode.steps:
        if step.parent_signature.strip("0"):
            material = f"{step.parent_signature}|{spec.parameter}".encode()
            substitute = "psub-" + hashlib.sha256(material).hexdigest()[:16]
            step = restep(step, parent_signature=substitute)
        steps.append(step)
    return steps, False


def _sensor_dropout(episode: Episode, spec: TransformSpec, rng: random.Random,
                    donors: Sequence[Episode]) -> _Outcome:
    families = (frozenset({family_of(Relation(spec.target.relation))}) if spec.target is not None
                else frozenset(RelationFamily))
    if not any(RelationFamily(s.relation_family) in families for s in episode.steps):
        return None
    kept: list[EncodedStep] = []
    blind: set[int] = set()
    for step in episode.steps:
        lost = rng.randrange(_PERMILLE) < spec.parameter
        if RelationFamily(step.relation_family) in families and lost:
            blind.add(step.actor_slot)
            continue
        kept.append(step)
    marked = [restep(s, observation_incomplete=True) if s.actor_slot in blind else s for s in kept]
    return (marked, False) if marked else None


def _destination_swap(episode: Episode, spec: TransformSpec, rng: random.Random,
                      donors: Sequence[Episode]) -> _Outcome:
    def chosen(step: EncodedStep) -> bool:
        if spec.target is not None:
            return spec.target.matches(step)
        return bool(step.object_property_mask & _EXTERNAL_BIT)

    if not any(chosen(s) for s in episode.steps):
        return None
    return [restep(s, object_property_mask=s.object_property_mask ^ _EXTERNAL_BIT) if chosen(s)
            else s for s in episode.steps], False


def _decoy_pool(episode: Episode, donors: Sequence[Episode]) -> list[EncodedStep]:
    pool = [s for d in donors if d.episode_id != episode.episode_id for s in d.steps
            if not is_escalating(s)]
    return pool or [s for s in episode.steps if not is_escalating(s)]


def _decoy_insertion(episode: Episode, spec: TransformSpec, rng: random.Random,
                     donors: Sequence[Episode]) -> _Outcome:
    pool = _decoy_pool(episode, donors)
    if not pool:
        return None  # no non-escalating step anywhere: a decoy would not be harmless
    room = MAX_EPISODE_STEPS - len(episode.steps)
    count = max(0, min(spec.parameter, room))
    steps = list(episode.steps)
    fresh = max(s.actor_slot for s in steps) + 1
    epoch = steps[0].epoch_id
    for index in range(count):
        donor = pool[rng.randrange(len(pool))]
        decoy = restep(donor, actor_slot=fresh + index, epoch_id=epoch,
                       source_group=source_group_of(f"decoy:{episode.episode_id}:{index}"))
        steps.insert(rng.randint(0, len(steps)), decoy)
    return steps, count < spec.parameter


def decoy_steps(source: Episode, derived: Episode) -> tuple[EncodedStep, ...]:
    """The steps DECOY_INSERTION added to ``source``: those on actor slots ``source`` never used.

    Decoys are placed on fresh slots above the source's highest (``_decoy_insertion``), so the
    added steps are exactly the derived steps above that slot.
    """
    top = max(s.actor_slot for s in source.steps)
    return tuple(s for s in derived.steps if s.actor_slot > top)


def decoy_is_neutral(source: Episode, derived: Episode,
                     predicates: Sequence[StepPredicate]) -> bool:
    """Whether a decoyed world is label-preserving *for a hypothesis over* ``predicates`` (F1).

    False when any added decoy step matches any of the hypothesis's predicates: that world is
    not a harmless-decoy world for this hypothesis, so it cannot test the hypothesis's
    invariance. Callers skip it (not applicable), never count it as a flip.
    """
    return not any(predicate.matches(step) for step in decoy_steps(source, derived)
                   for predicate in predicates)


def _necessary_deletion(episode: Episode, spec: TransformSpec, rng: random.Random,
                        donors: Sequence[Episode]) -> _Outcome:
    target = spec.target
    if target is None or not any(target.matches(s) for s in episode.steps):
        return None
    kept = [s for s in episode.steps if not target.matches(s)]
    return (kept, False) if kept else None


def _first_target(episode: Episode, target: StepPredicate | None) -> int | None:
    if target is None:
        return None
    return next((i for i, s in enumerate(episode.steps) if target.matches(s)), None)


def _reorder(episode: Episode, spec: TransformSpec, rng: random.Random,
             donors: Sequence[Episode]) -> _Outcome:
    index = _first_target(episode, spec.target)
    if index is None:
        return None
    slot = episode.steps[index].actor_slot
    own = [i for i, s in enumerate(episode.steps) if s.actor_slot == slot]
    destination = own[0] if spec.parameter == 0 else own[-1]
    if destination == index:
        return None  # already first (or last) of its actor: the order cannot change
    steps = list(episode.steps)
    moved = steps.pop(index)
    steps.insert(destination, moved)
    return steps, False


def _actor_split(episode: Episode, spec: TransformSpec, rng: random.Random,
                 donors: Sequence[Episode]) -> _Outcome:
    index = _first_target(episode, spec.target)
    if index is None:
        return None
    slot = episode.steps[index].actor_slot
    if index == min(i for i, s in enumerate(episode.steps) if s.actor_slot == slot):
        return None  # the target opens its actor: there is nothing to split it from
    fresh = max(s.actor_slot for s in episode.steps) + 1
    steps = [
        restep(s, actor_slot=fresh, source_group=source_group_of(f"split:{s.source_group}:{fresh}"))
        if i >= index and s.actor_slot == slot else s
        for i, s in enumerate(episode.steps)
    ]
    return steps, False


_HANDLERS: Mapping[TransformKind, _Handler] = MappingProxyType({
    TransformKind.ACTOR_RENAME: _actor_rename,
    TransformKind.TIMING_SHIFT: _timing_shift,
    TransformKind.SENSOR_DROPOUT: _sensor_dropout,
    TransformKind.PARENT_SUBSTITUTION: _parent_substitution,
    TransformKind.DESTINATION_CLASS_SWAP: _destination_swap,
    TransformKind.EPOCH_CHANGE: _epoch_change,
    TransformKind.DECOY_INSERTION: _decoy_insertion,
    TransformKind.NECESSARY_STEP_DELETION: _necessary_deletion,
    TransformKind.REORDER: _reorder,
    TransformKind.ACTOR_SPLIT: _actor_split,
})
assert set(_HANDLERS) == set(TransformKind) == set(TRANSFORM_SEMANTICS), "every kind needs both"


def apply_transform(episode: Episode, spec: TransformSpec, *, rng: random.Random,
                    donors: Sequence[Episode] = ()) -> Episode | None:
    """One derived ``Split.CHALLENGE`` episode, or ``None`` when ``spec`` does not apply.

    ``donors`` supplies DECOY_INSERTION's non-escalating steps ("copied from other
    episodes"); with none, the episode's own non-escalating steps are copied under fresh
    actor slots. The label is the source label for PRESERVING kinds and ``None`` otherwise.
    """
    if not isinstance(episode, Episode):
        raise ContractError(f"apply_transform needs an Episode, got {type(episode).__name__}")
    if not isinstance(spec, TransformSpec):
        raise ContractError(f"apply_transform needs a TransformSpec, got {type(spec).__name__}")
    if not isinstance(rng, random.Random):
        raise ContractError("apply_transform needs an explicit random.Random (reproducibility)")
    if not episode.context.synthetic:
        # S8-DEF-07: the laboratory perturbs SYNTHETIC telemetry only; a derived episode copies
        # its source's context, so a variant of real telemetry would be stamped real.
        raise ContractError("the laboratory transforms synthetic telemetry only")
    outcome = _HANDLERS[spec.kind](episode, spec, rng, donors)
    if outcome is None:
        return None
    steps, truncated = outcome
    preserving = TRANSFORM_SEMANTICS[spec.kind] is Semantics.PRESERVING
    return Episode(
        episode_id="", steps=tuple(steps), label=episode.label if preserving else None,
        split=Split.CHALLENGE, context=episode.context, truncated=episode.truncated or truncated,
    )


@dataclass(frozen=True, slots=True)
class CounterfactualBatch:
    """A bounded counterfactual set and the accounting that makes its bound visible."""

    episodes: tuple[Episode, ...]
    attempted: int         # (episode, spec) pairs a transform was run on
    not_applicable: int    # of those, pairs that returned None
    truncated: int         # pairs never attempted because the cap was reached
    cap: int


def build_counterfactuals(episodes: Sequence[Episode], specs: Sequence[TransformSpec], *,
                          rng: random.Random, cap: int) -> CounterfactualBatch:
    """Apply every spec to every episode, in order, until ``cap`` results exist."""
    if isinstance(cap, bool) or not isinstance(cap, int) or not 0 <= cap <= MAX_COUNTERFACTUAL_SET:
        raise ContractError(f"cap must be an int in [0, {MAX_COUNTERFACTUAL_SET}], got {cap!r}")
    pool = tuple(episodes)
    made: list[Episode] = []
    attempted = not_applicable = 0
    total = len(pool) * len(specs)
    for episode in pool:
        for spec in specs:
            if len(made) >= cap:
                return CounterfactualBatch(tuple(made), attempted, not_applicable,
                                           total - attempted, cap)
            attempted += 1
            result = apply_transform(episode, spec, rng=rng, donors=pool)
            if result is None:
                not_applicable += 1
            else:
                made.append(result)
    return CounterfactualBatch(tuple(made), attempted, not_applicable, 0, cap)


def counterfactual_set(episodes: Sequence[Episode], specs: Sequence[TransformSpec], *,
                       rng: random.Random, cap: int) -> tuple[Episode, ...]:
    """The episodes of :func:`build_counterfactuals`; use that function for the counts."""
    return build_counterfactuals(episodes, specs, rng=rng, cap=cap).episodes
