"""D6.4 — bounded episodic memory: which episodes are worth keeping, and what was dropped.

Raw event streams are already bounded by Stages 1-2. What Stage 6 keeps is a small,
*selected* set of episodes, each reduced to an :class:`EpisodeSkeleton` — every
escalating step plus the first step of each distinct ``(actor_slot, pattern_key)`` —
because a replay set that grows with the event rate puts the 2 GB bound at the
attacker's mercy.

Admission is value-aware (architecture §9)::

    value = security_information x novelty x future_replay_value x label_quality
            x provenance_trust / (storage_cost + redundancy + poison_risk + EPS)

and when the store is full the **minimum-value LEARNING episode is evicted only if
the newcomer is worth more**; otherwise the newcomer is refused. Evicting on arrival
order instead would let a flood of cheap episodes wash out the rare, well-labelled
one that a detector's only exemplar depends on. The simple control this must beat is
reservoir / FIFO replacement (``value_aware_rehearsal`` → reservoir, spec §4.22).

What it refuses to do:

* **It writes no trusted state.** Episodic memory is quarantine-side and untrusted.
  Its content reaches trusted state only when a candidate adds an exemplar to the
  rehearsal set, which goes through the one promotion controller like every other
  change.
* **It never drops silently.** Every eviction appends an :class:`EvictionRecord` to a
  bounded log; when the log itself is full the oldest *record* is forgotten and
  counted. Counters never reset.
* **Hostile episodes are kept as evidence, never learned from.** The HOSTILE tier is
  a separate bounded store; nothing in it is ever returned as a LEARNING episode.
  Like Stage 2's retained evidence it drops its *oldest* entry when full, recorded,
  because an investigation needs the most recent evidence — and the evidence itself
  stays in Stage 1's immutable store, referenced here by digest.
* **It truncates explicitly.** A skeleton cut to ``MAX_SKELETON_STEPS`` or
  ``MAX_SKELETON_BYTES`` says ``truncated=True``.
"""

from __future__ import annotations

import json
from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage0.contracts.threat_prediction_v1 import Verdict
from pocketsec.stage2.adaptation.quarantine import pattern_key
from pocketsec.stage2.encoder.ssir_encoder import FEATURE_WIDTH, GROUP_OFFSETS
from pocketsec.stage6.capsule.experience_capsule import (
    EncodedStep,
    ExperienceCapsuleV1,
    LabelOrigin,
)
from pocketsec.stage6.constitution.learning import touches_protected
from pocketsec.stage6.memory.semantic import (
    CapacityError,
    ItemStatus,
    TrustedKnowledgeState,
    canonical_float,
    is_escalating,
    match_motif,
)
from pocketsec.stage6.provenance.trust import LABEL_ORIGIN_WEIGHT

if TYPE_CHECKING:
    # Annotation only: episode_value reads one number from the record.
    from pocketsec.stage6.provenance.ledger import TrustRecord

__all__ = [
    "EPISODE_VALUE_EPS",
    "MAX_EPISODES",
    "MAX_EPISODIC_BYTES",
    "MAX_EVICTION_LOG",
    "MAX_HOSTILE_EPISODES",
    "MAX_SKELETON_BYTES",
    "MAX_SKELETON_STEPS",
    "AdmissionRecord",
    "EpisodeSkeleton",
    "EpisodeTier",
    "EpisodeValue",
    "EpisodicMemory",
    "EpisodicStats",
    "EvictionRecord",
    "episode_value",
    "motif_signature",
    "skeleton_from_capsule",
]

MAX_EPISODES: int = 512
MAX_HOSTILE_EPISODES: int = 64
MAX_EPISODIC_BYTES: int = 4_194_304
MAX_SKELETON_STEPS: int = 32
MAX_SKELETON_BYTES: int = 8192
MAX_EVICTION_LOG: int = 128
#: Keeps the value finite for a free, unique, clean episode; not a tuning knob.
EPISODE_VALUE_EPS: float = 1e-9

#: ``uncertainty`` group = (uncertainty, observation_incomplete); the second is the
#: per-step visibility bit. The encoder names this group positionally
#: ("uncertainty[1]"), so the offset is the only derivation available.
_OBSERVATION_INCOMPLETE = GROUP_OFFSETS["uncertainty"] + 1

#: Upper bound on an eviction record's fixed-width fields (tier, value, reason,
#: sequence) in canonical form; the variable-width ids are counted exactly.
_EVICTION_RECORD_FIXED_BYTES = 64

_STEP_FIELDS: tuple[str, ...] = (
    "relation", "relation_family", "state_delta_mask", "time_bucket", "delta_phi",
    "object_property_mask", "epoch_id", "actor_slot", "uncertainty", "source_group",
    "causal_signature", "parent_signature", "evidence",
)
_FLOAT_FIELDS = frozenset({"delta_phi", "uncertainty"})


def _step_payload(step: EncodedStep) -> list[Any]:
    """Positional and sparse: a skeleton is stored in trusted state, so bytes matter.

    Features are stored as ``[index, value]`` pairs for non-zero values only; the
    encoder's vector is mostly one-hot zeros.
    """
    sparse = [[i, canonical_float(v)] for i, v in enumerate(step.features) if v != 0.0]
    values: list[Any] = [sparse]
    for name in _STEP_FIELDS:
        value = getattr(step, name)
        if name in _FLOAT_FIELDS:
            value = canonical_float(value)
        elif name == "evidence":
            value = list(value)
        values.append(value)
    return values


def _step_from_payload(raw: object) -> EncodedStep:
    if not isinstance(raw, list) or len(raw) != len(_STEP_FIELDS) + 1:
        raise ContractError("a skeleton step payload has the wrong shape")
    features = [0.0] * FEATURE_WIDTH
    for pair in raw[0]:
        index, value = pair
        if not isinstance(index, int) or not 0 <= index < FEATURE_WIDTH:
            raise ContractError(f"skeleton feature index {index!r} is out of range")
        features[index] = float(value)
    fields = dict(zip(_STEP_FIELDS, raw[1:], strict=True))
    fields["evidence"] = tuple(fields["evidence"])
    for name in _FLOAT_FIELDS:
        fields[name] = float(fields[name])
    return EncodedStep(features=tuple(features), **fields)


def _anchors_of(steps: Sequence[EncodedStep]) -> tuple[str, ...]:
    touched: set[str] = set()
    for step in steps:
        touched.update(touches_protected(step.object_property_mask, step.state_delta_mask))
    return tuple(sorted(touched))


def _triple(step: EncodedStep) -> tuple[int, int, int]:
    return (step.relation, step.object_property_mask, step.state_delta_mask)


def motif_signature(steps: Sequence[EncodedStep]) -> frozenset[tuple[int, int, int]]:
    """What an episode *does*, actor- and time-free: its distinct (relation, props, raised)."""
    return frozenset(_triple(s) for s in steps)


@dataclass(frozen=True, slots=True)
class EpisodeSkeleton:
    """Architecture §14's compact sufficient episode representation."""

    episode_id: str
    steps: tuple[EncodedStep, ...]
    verdict: Verdict
    label_origin: LabelOrigin
    epoch_id: int
    context_id: str
    visibility_mask: int
    anchors_touched: tuple[str, ...]
    truncated: bool

    def __post_init__(self) -> None:
        if not isinstance(self.episode_id, str) or not self.episode_id:
            raise ContractError("EpisodeSkeleton.episode_id is the source capsule_id")
        object.__setattr__(self, "steps", tuple(self.steps))
        object.__setattr__(self, "verdict", Verdict(self.verdict))
        object.__setattr__(self, "label_origin", LabelOrigin(self.label_origin))
        object.__setattr__(self, "anchors_touched", tuple(sorted(self.anchors_touched)))
        if len(self.steps) > MAX_SKELETON_STEPS:
            raise CapacityError(f"a skeleton holds at most {MAX_SKELETON_STEPS} steps")
        mask, width = self.visibility_mask, len(self.steps)
        if not isinstance(mask, int) or isinstance(mask, bool) or not 0 <= mask < 1 << width:
            raise ContractError("visibility_mask has one bit per step")
        if not isinstance(self.context_id, str) or not self.context_id.startswith("ctx-"):
            raise ContractError("EpisodeSkeleton.context_id comes from context_id_for()")
        derived = _anchors_of(self.steps)
        if self.anchors_touched != derived:
            # Derived, not asserted: a skeleton that under-reports the protected anchors
            # its own steps touch would look like cheap, unprotected material.
            raise ContractError(f"anchors_touched must be {derived!r}, the anchors its steps touch")
        if self.byte_size() > MAX_SKELETON_BYTES:
            raise CapacityError(f"a skeleton is at most {MAX_SKELETON_BYTES} bytes; truncate it")

    def to_payload(self) -> dict[str, Any]:
        return {
            "episode_id": self.episode_id,
            "steps": [_step_payload(step) for step in self.steps],
            "verdict": self.verdict.value,
            "label_origin": self.label_origin.value,
            "epoch_id": self.epoch_id,
            "context_id": self.context_id,
            "visibility_mask": self.visibility_mask,
            "anchors_touched": list(self.anchors_touched),
            "truncated": self.truncated,
        }

    @classmethod
    def from_payload(cls, raw: Mapping[str, Any]) -> EpisodeSkeleton:
        keys = {"episode_id", "steps", "verdict", "label_origin", "epoch_id", "context_id",
                "visibility_mask", "anchors_touched", "truncated"}
        if not isinstance(raw, Mapping) or set(raw) != keys:
            raise ContractError("a skeleton payload has the wrong keys")
        if not isinstance(raw["truncated"], bool) or not isinstance(raw["steps"], list):
            raise ContractError("a skeleton payload has mistyped fields")
        return cls(
            episode_id=raw["episode_id"],
            steps=tuple(_step_from_payload(step) for step in raw["steps"]),
            verdict=Verdict(raw["verdict"]),
            label_origin=LabelOrigin(raw["label_origin"]),
            epoch_id=raw["epoch_id"],
            context_id=raw["context_id"],
            visibility_mask=raw["visibility_mask"],
            anchors_touched=tuple(raw["anchors_touched"]),
            truncated=raw["truncated"],
        )

    def byte_size(self) -> int:
        """Bytes of this skeleton's canonical form — what it costs inside trusted state."""
        text = json.dumps(self.to_payload(), sort_keys=True, separators=(",", ":"), allow_nan=False)
        return len(text.encode("utf-8"))


def _select_steps(steps: Sequence[EncodedStep]) -> list[int]:
    """Indices to keep, in priority order: escalating steps, then first-of-(actor, key)."""
    escalating = [i for i, step in enumerate(steps) if is_escalating(step)]
    seen: set[tuple[int, str]] = set()
    firsts: list[int] = []
    for i, step in enumerate(steps):
        slot_key = (step.actor_slot, pattern_key(step.to_encoded()))
        if slot_key not in seen:
            seen.add(slot_key)
            if i not in escalating:
                firsts.append(i)
    return escalating + firsts


def _build_skeleton(
    capsule: ExperienceCapsuleV1, chosen: list[int], *, verdict: Verdict,
    label_origin: LabelOrigin, truncated: bool,
) -> EpisodeSkeleton:
    ordered = sorted(chosen)  # original order: motif matching needs i < j preserved
    steps = tuple(capsule.steps[i] for i in ordered)
    visibility = sum(
        1 << n for n, step in enumerate(steps) if step.features[_OBSERVATION_INCOMPLETE] < 0.5
    )
    return EpisodeSkeleton(
        episode_id=capsule.capsule_id,
        steps=steps,
        verdict=verdict,
        label_origin=label_origin,
        epoch_id=capsule.epoch_id,
        context_id=capsule.context_id,
        visibility_mask=visibility,
        anchors_touched=_anchors_of(steps),
        truncated=truncated,
    )


def skeleton_from_capsule(
    capsule: ExperienceCapsuleV1, *, verdict: Verdict, label_origin: LabelOrigin
) -> EpisodeSkeleton:
    """Reduce a capsule to its skeleton, cutting explicitly to the step and byte caps.

    Priority when cutting: escalating steps first (they are what detectors are made
    of), then the first step of each (actor, pattern key). ``truncated`` is set when
    anything selected was cut or the capsule itself was already truncated.
    """
    priority = _select_steps(capsule.steps)
    chosen = priority[:MAX_SKELETON_STEPS]
    truncated = bool(capsule.truncated) or len(priority) > len(chosen)
    while True:
        try:
            return _build_skeleton(
                capsule, chosen, verdict=verdict, label_origin=label_origin, truncated=truncated
            )
        except CapacityError:
            if not chosen:
                raise
            chosen = chosen[:-1]  # drop the lowest-priority step and say so
            truncated = True


class EpisodeTier(StrEnum):
    LEARNING = "LEARNING"
    HOSTILE = "HOSTILE"  # kept as evidence, never learned from


@dataclass(frozen=True, slots=True)
class EpisodeValue:
    """Architecture §9, every factor bound to a field."""

    security_information: float
    novelty: float
    future_replay_value: float
    label_quality: float
    provenance_trust: float
    storage_cost: float
    redundancy: float
    poison_risk: float
    value: float

    def __post_init__(self) -> None:
        for name in self.__dataclass_fields__:
            numeric = getattr(self, name)
            if isinstance(numeric, bool) or not isinstance(numeric, (int, float)):
                raise ContractError(f"EpisodeValue.{name} must be a number")
            if not 0.0 <= float(numeric) < float("inf"):
                raise ContractError(f"EpisodeValue.{name} must be finite and non-negative")


_NUMERATOR = (
    "security_information", "novelty", "future_replay_value", "label_quality", "provenance_trust"
)
_DENOMINATOR = ("storage_cost", "redundancy", "poison_risk")


def _unit(value: float) -> float:
    return min(1.0, max(0.0, float(value)))


def _replay_value(
    skeleton: EpisodeSkeleton, resident: Sequence[EpisodeSkeleton], trusted: TrustedKnowledgeState
) -> float:
    """1 if the episode covers a DETECTOR with fewer than two exemplars, else 0.5."""
    pool = {sk.episode_id: sk for sk in (*trusted.rehearsal, *resident)}
    pool.pop(skeleton.episode_id, None)
    for detector in trusted.detectors():
        if detector.status is not ItemStatus.ACTIVE:
            continue
        if not match_motif(detector.motif, skeleton.steps):
            continue
        exemplars = sum(1 for sk in pool.values() if match_motif(detector.motif, sk.steps))
        if exemplars < 2:
            return 1.0
    return 0.5


def episode_value(
    skeleton: EpisodeSkeleton,
    *,
    trust: TrustRecord,
    suspicion_summary: float,
    resident: Sequence[EpisodeSkeleton],
    trusted: TrustedKnowledgeState,
) -> EpisodeValue:
    steps = skeleton.steps
    if skeleton.anchors_touched:
        security = 1.0
    else:
        security = sum(1 for s in steps if s.state_delta_mask) / len(steps) if steps else 0.0
    signature = motif_signature(steps)
    same = sum(1 for sk in resident if motif_signature(sk.steps) == signature)
    novelty = 1.0 - same / (1 + len(resident))
    covered: set[tuple[int, int, int]] = set()
    for sk in resident:
        covered |= motif_signature(sk.steps)
    repeated = sum(1 for triple in (_triple(s) for s in steps) if triple in covered)
    redundancy = repeated / len(steps) if steps else 0.0
    factors = {
        "security_information": _unit(security),
        "novelty": _unit(novelty),
        "future_replay_value": _replay_value(skeleton, resident, trusted),
        "label_quality": _unit(LABEL_ORIGIN_WEIGHT[skeleton.label_origin]),
        "provenance_trust": _unit(trust.provenance_score),
        "storage_cost": skeleton.byte_size() / MAX_SKELETON_BYTES,
        "redundancy": _unit(redundancy),
        "poison_risk": _unit(suspicion_summary),
    }
    product = 1.0
    for name in _NUMERATOR:
        product *= factors[name]
    denominator = EPISODE_VALUE_EPS + sum(factors[name] for name in _DENOMINATOR)
    return EpisodeValue(**factors, value=product / denominator)


@dataclass(frozen=True, slots=True)
class EvictionRecord:
    episode_id: str
    tier: EpisodeTier
    value: float
    verdict_id: str
    replaced_by: str
    reason: str
    sequence: int


@dataclass(frozen=True, slots=True)
class AdmissionRecord:
    episode_id: str
    tier: EpisodeTier
    admitted: bool
    reason: str
    value: float
    evicted: tuple[str, ...]
    sequence: int


@dataclass(frozen=True, slots=True)
class EpisodicStats:
    learning_episodes: int
    hostile_episodes: int
    learning_bytes: int
    hostile_bytes: int
    admitted: int
    refused: int
    evictions: int
    hostile_evictions: int
    eviction_log_dropped: int
    memory_bytes: int


@dataclass(frozen=True, slots=True)
class _Resident:
    skeleton: EpisodeSkeleton
    value: float
    verdict_id: str
    size: int
    sequence: int


class EpisodicMemory:
    """Bounded, value-aware, untrusted episode store. Writes no trusted state."""

    def __init__(
        self,
        *,
        capacity: int = MAX_EPISODES,
        byte_budget: int = MAX_EPISODIC_BYTES,
        hostile_capacity: int = MAX_HOSTILE_EPISODES,
    ) -> None:
        for name, value, cap in (
            ("capacity", capacity, MAX_EPISODES),
            ("byte_budget", byte_budget, MAX_EPISODIC_BYTES),
            ("hostile_capacity", hostile_capacity, MAX_HOSTILE_EPISODES),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= cap:
                raise ContractError(f"{name} must be an int in [1, {cap}]; bounds cannot be raised")
        self._capacity = capacity
        self._byte_budget = byte_budget
        self._hostile_capacity = hostile_capacity
        self._learning: dict[str, _Resident] = {}
        self._hostile: dict[str, _Resident] = {}
        self._log: deque[EvictionRecord] = deque(maxlen=MAX_EVICTION_LOG)
        self._sequence = 0
        self._admitted = 0
        self._refused = 0
        self._evictions = 0
        self._hostile_evictions = 0
        self._log_dropped = 0

    def admit_episode(
        self,
        skeleton: EpisodeSkeleton,
        *,
        value: EpisodeValue,
        verdict_id: str,
        tier: EpisodeTier = EpisodeTier.LEARNING,
    ) -> AdmissionRecord:
        """HEL-F06. Full ⇒ evict the min-value LEARNING episode iff the newcomer is worth more."""
        if not isinstance(skeleton, EpisodeSkeleton) or not isinstance(value, EpisodeValue):
            raise ContractError("admit_episode takes an EpisodeSkeleton and its EpisodeValue")
        if not isinstance(verdict_id, str) or not verdict_id:
            raise ContractError("an episode is admitted under a gateway verdict_id")
        tier = EpisodeTier(tier)
        self._sequence += 1
        size = skeleton.byte_size()
        resident = _Resident(skeleton, value.value, verdict_id, size, self._sequence)
        if skeleton.episode_id in self._learning or skeleton.episode_id in self._hostile:
            return self._refuse(resident, tier, "duplicate_episode")
        if tier is EpisodeTier.HOSTILE:
            return self._admit_hostile(resident)
        return self._admit_learning(resident)

    def _refuse(self, resident: _Resident, tier: EpisodeTier, reason: str) -> AdmissionRecord:
        self._refused += 1
        return AdmissionRecord(
            resident.skeleton.episode_id, tier, False, reason, resident.value, (), resident.sequence
        )

    def _accept(
        self, resident: _Resident, tier: EpisodeTier, evicted: list[str]
    ) -> AdmissionRecord:
        store = self._hostile if tier is EpisodeTier.HOSTILE else self._learning
        store[resident.skeleton.episode_id] = resident
        self._admitted += 1
        reason = "admitted_by_eviction" if evicted else "admitted"
        return AdmissionRecord(
            resident.skeleton.episode_id, tier, True, reason, resident.value, tuple(evicted),
            resident.sequence,
        )

    def _record_eviction(self, victim: _Resident, tier: EpisodeTier, by: str, reason: str) -> None:
        if len(self._log) == self._log.maxlen:
            self._log_dropped += 1
        self._log.append(
            EvictionRecord(
                victim.skeleton.episode_id, tier, victim.value, victim.verdict_id, by, reason,
                self._sequence,
            )
        )

    def _admit_learning(self, newcomer: _Resident) -> AdmissionRecord:
        if newcomer.size > self._byte_budget:
            return self._refuse(newcomer, EpisodeTier.LEARNING, "larger_than_byte_budget")
        # Plan the evictions first and commit only if every victim is worth less than
        # the newcomer: a refused admission must leave the store untouched.
        by_value = sorted(self._learning.values(), key=lambda r: (r.value, r.sequence))
        count, used = len(self._learning), self.learning_bytes()
        victims: list[_Resident] = []
        while count + 1 > self._capacity or used + newcomer.size > self._byte_budget:
            victim = by_value[len(victims)]
            if not newcomer.value > victim.value:
                return self._refuse(newcomer, EpisodeTier.LEARNING, "lower_value_than_resident")
            victims.append(victim)
            count, used = count - 1, used - victim.size
        newcomer_id = newcomer.skeleton.episode_id
        for victim in victims:
            del self._learning[victim.skeleton.episode_id]
            self._evictions += 1
            self._record_eviction(victim, EpisodeTier.LEARNING, newcomer_id, "min_value")
        return self._accept(
            newcomer, EpisodeTier.LEARNING, [v.skeleton.episode_id for v in victims]
        )

    def _admit_hostile(self, newcomer: _Resident) -> AdmissionRecord:
        evicted: list[str] = []
        while len(self._hostile) >= self._hostile_capacity:
            oldest = min(self._hostile.values(), key=lambda r: r.sequence)
            del self._hostile[oldest.skeleton.episode_id]
            self._hostile_evictions += 1
            by = newcomer.skeleton.episode_id
            self._record_eviction(oldest, EpisodeTier.HOSTILE, by, "oldest_evidence")
            evicted.append(oldest.skeleton.episode_id)
        return self._accept(newcomer, EpisodeTier.HOSTILE, evicted)

    def episodes(self, *, tier: EpisodeTier = EpisodeTier.LEARNING) -> tuple[EpisodeSkeleton, ...]:
        store = self._hostile if EpisodeTier(tier) is EpisodeTier.HOSTILE else self._learning
        return tuple(r.skeleton for r in sorted(store.values(), key=lambda r: r.sequence))

    def value_of(self, episode_id: str) -> float | None:
        entry = self._learning.get(episode_id) or self._hostile.get(episode_id)
        return None if entry is None else entry.value

    def verdict_of(self, episode_id: str) -> str | None:
        """The gateway verdict id a resident episode came in under; None if not resident."""
        entry = self._learning.get(episode_id) or self._hostile.get(episode_id)
        return None if entry is None else entry.verdict_id

    def eviction_log(self) -> tuple[EvictionRecord, ...]:
        return tuple(self._log)

    def evictions(self) -> int:
        return self._evictions + self._hostile_evictions

    def learning_bytes(self) -> int:
        return sum(r.size for r in self._learning.values())

    def hostile_bytes(self) -> int:
        return sum(r.size for r in self._hostile.values())

    def memory_bytes(self) -> int:
        """Serialized bytes held: skeletons plus the eviction log.

        Canonical-form accounting, the same measure the byte budget enforces. Python
        object overhead is not counted here; the RSS measurement in ``resources.py``
        is where interpreter cost is observed.
        """
        log = sum(
            len(r.episode_id) + len(r.verdict_id) + len(r.replaced_by) for r in self._log
        ) + len(self._log) * _EVICTION_RECORD_FIXED_BYTES
        return self.learning_bytes() + self.hostile_bytes() + log

    def stats(self) -> EpisodicStats:
        return EpisodicStats(
            learning_episodes=len(self._learning),
            hostile_episodes=len(self._hostile),
            learning_bytes=self.learning_bytes(),
            hostile_bytes=self.hostile_bytes(),
            admitted=self._admitted,
            refused=self._refused,
            evictions=self._evictions,
            hostile_evictions=self._hostile_evictions,
            eviction_log_dropped=self._log_dropped,
            memory_bytes=self.memory_bytes(),
        )
