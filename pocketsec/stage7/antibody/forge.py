"""ORPH-F10 / D7.11 — the Knowledge Antibody Forge, and the receiver's local validator.

An *antibody* is the only knowledge Stage 7 shares: a Stage 6 DETECTOR motif (1-2
``MotifRow`` bitmask tests, spec §4.0) meaning "this behaviour pattern is malicious". This
module exists for two jobs that sit on opposite sides of the wire:

* **Sender side — forging.** ``forge_antibody`` turns one LOCAL incident into the smallest
  motif that still separates it from this host's own benign history and from a doppelganger
  that performs the same steps split across two actors (architecture §13). It is a search
  over a closed candidate set, never a learned model: candidates are single escalating steps
  and same-actor ordered pairs of them, nothing else is expressible in Stage 6's grammar
  (spec §3.2 — counts, timing and chains longer than 2 steps are inexpressible, stated in
  advance). ``copied_rule`` is the control the forge must beat (§7, ORPH-F10).
* **Receiver side — validating.** ``LocalValidator.validate`` replays a FOREIGN motif against
  this host's own resolved episodes. It is the sovereignty gate ECHO applies before any
  collective mass is counted: a motif that fires on local benign history is ``LOCAL_FP``,
  and nothing a peer says can overrule that (spec D7.10 step 2).

What this module refuses to do:

* It never reimplements the match. ``matches`` delegates to Stage 6's ``match_motif``, so the
  antibody grammar is Stage 6's DETECTOR grammar exactly (lesson 3). A second matcher would
  be a second, silently diverging definition of what an antibody means.
* It never grades. A match is boolean because its only consumer (a Stage 6 DETECTOR) is
  boolean (ADR-0062); §14's graded product is not built.
* It never writes trusted state and never touches Stage 5. It returns values.
* It never claims more than it did. ``ValidationSummary``/``FalsificationSummary`` on a
  forged antibody count exactly the replays and mutations run here; a receiver treats them
  as self-reported (spec D7.2) because it cannot check them.

Known limit, stated rather than hidden: the attack-preserving mutations only drop
non-escalating steps, re-slot actors and interleave benign steps on fresh actors, so every
candidate drawn from the incident's escalating steps survives them by construction. The
discriminating tests are the benign ring and the doppelgangers; the preserving test is a
guard against a future candidate generator, and its firing count on a corpus is reported by
the labs, not assumed.

Every bound is a named constant (spec §4.23, chosen, not measured).
"""

from __future__ import annotations

import hashlib
import random
import sys
from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass, replace
from enum import StrEnum

from pocketsec.stage0.contracts.common import ContractError, require_identifier
from pocketsec.stage1.ssir.relations import Relation, family_of
from pocketsec.stage2.encoder.ssir_encoder import FEATURE_LAYOUT, FEATURE_WIDTH, GROUP_OFFSETS
from pocketsec.stage6.capsule.experience_capsule import EncodedStep
from pocketsec.stage6.memory.semantic import MAX_MOTIF_LENGTH, match_motif
from pocketsec.stage6.resources import WorkMeter
from pocketsec.stage7.capsule.knowledge_capsule import (
    ChainStage,
    FalsificationSummary,
    MotifRow,
    ValidationSummary,
    derive_chain_stages,
    motif_fingerprint,
)

__all__ = [
    "LOCAL_FP_CEILING",
    "MAX_BENIGN_EPISODES",
    "MAX_BIT_DROPS",
    "MAX_FORGE_CANDIDATES",
    "MAX_LOCAL_INCIDENTS",
    "MUTATIONS_PER_INCIDENT",
    "BenignRing",
    "KnowledgeAntibody",
    "LocalIncident",
    "LocalValidation",
    "LocalValidator",
    "copied_rule",
    "forge_antibody",
    "matches",
    "mutate_incident",
    "prototype_steps",
]

#: A foreign motif matching MORE than this many local benign episodes is a local false
#: positive. 0: one benign match is already a contradiction by local evidence.
LOCAL_FP_CEILING: int = 0
#: Capacity of the benign ring (FIFO; evictions counted).
MAX_BENIGN_EPISODES: int = 512
#: Candidate motifs considered per incident (singles first, then same-actor pairs).
MAX_FORGE_CANDIDATES: int = 64
#: Attack-preserving mutations, and separately doppelganger mutations, per incident.
MUTATIONS_PER_INCIDENT: int = 8
#: Successful ``require_properties`` bit drops per candidate during minimisation.
MAX_BIT_DROPS: int = 16
#: Local incidents a validator holds. Not in spec §4.23: added so the validator's store is
#: bounded like every other store; equal to the benign ring's capacity. Chosen, not measured.
MAX_LOCAL_INCIDENTS: int = MAX_BENIGN_EPISODES

_WIDTHS: dict[str, int] = dict(FEATURE_LAYOUT)
_OBJECT_OFFSET: int = GROUP_OFFSETS["object_semantics"]
_OBJECT_WIDTH: int = _WIDTHS["object_semantics"]
_RAISED_OFFSET: int = GROUP_OFFSETS["state_delta_raised"]
_RAISED_WIDTH: int = _WIDTHS["state_delta_raised"]
_RELATION_OFFSET: int = GROUP_OFFSETS["relation_onehot"]
_FAMILY_OFFSET: int = GROUP_OFFSETS["relation_family_onehot"]
#: Rough per-step footprint for ``memory_bytes``: the feature tuple plus the scalar fields.
_STEP_OVERHEAD_BYTES: int = 256
_DIGEST_PREFIX = "sha256:"
_HEX = frozenset("0123456789abcdef")


class LocalValidation(StrEnum):
    """What this host's own evidence says about a motif. Only local evidence confirms."""

    PASS = "PASS"
    LOCAL_FP = "LOCAL_FP"
    LOCAL_CONFIRMED = "LOCAL_CONFIRMED"
    NOT_OBSERVABLE = "NOT_OBSERVABLE"


def _charge(meter: WorkMeter | None, units: int) -> None:
    if meter is not None:
        meter.charge(max(1, units))


def _require_steps(steps: object, field: str) -> tuple[EncodedStep, ...]:
    if not isinstance(steps, (list, tuple)) or not steps:
        raise ContractError(f"{field} must be a non-empty sequence of EncodedStep")
    if any(not isinstance(step, EncodedStep) for step in steps):
        raise ContractError(f"{field} must hold EncodedStep values only")
    return tuple(steps)


def _require_rows(invariant: object) -> tuple[MotifRow, ...]:
    if not isinstance(invariant, (list, tuple)):
        raise ContractError(
            f"an invariant is a sequence of MotifRow, got {type(invariant).__name__}"
        )
    rows = tuple(invariant)
    if not 1 <= len(rows) <= MAX_MOTIF_LENGTH:
        raise ContractError(f"an invariant has 1..{MAX_MOTIF_LENGTH} rows, got {len(rows)}")
    if any(not isinstance(row, MotifRow) for row in rows):
        raise ContractError("an invariant must hold MotifRow values only")
    return rows


def _is_digest(value: object) -> bool:
    if not isinstance(value, str) or not value.startswith(_DIGEST_PREFIX):
        return False
    body = value[len(_DIGEST_PREFIX) :]
    return len(body) == 64 and set(body) <= _HEX


def matches(invariant: Sequence[MotifRow], steps: Sequence[EncodedStep]) -> bool:
    """Stage 6's ``match_motif`` over the rows, never a copy of it.

    Length 1: any step matches. Length 2: step i then step j (i < j) of ONE actor.
    """
    rows = _require_rows(invariant)
    return match_motif(tuple(row.to_motif_step() for row in rows), tuple(steps))


def _matches_charged(
    rows: tuple[MotifRow, ...], steps: Sequence[EncodedStep], meter: WorkMeter | None
) -> bool:
    # One work unit per motif x step comparison, the Stage 6 cost convention.
    _charge(meter, len(steps))
    return match_motif(tuple(row.to_motif_step() for row in rows), steps)


# --- the local evidence stores ----------------------------------------------------


@dataclass(frozen=True, slots=True)
class LocalIncident:
    """A LOCAL resolution labelled MALICIOUS. In the labs this is ground truth (optimistic,
    declared): a poisoned local label is UNMEASURED (spec §9.2)."""

    incident_id: str
    steps: tuple[EncodedStep, ...]
    evidence_digests: tuple[str, ...]

    def __post_init__(self) -> None:
        require_identifier(self.incident_id, "LocalIncident.incident_id")
        object.__setattr__(self, "steps", _require_steps(self.steps, "LocalIncident.steps"))
        digests = self.evidence_digests
        if not isinstance(digests, (list, tuple)):
            raise ContractError("LocalIncident.evidence_digests must be a sequence")
        digests = tuple(digests)
        if len(set(digests)) != len(digests) or not all(_is_digest(d) for d in digests):
            raise ContractError("LocalIncident.evidence_digests must be distinct sha256:<64 hex>")
        object.__setattr__(self, "evidence_digests", digests)


class BenignRing:
    """Locally-resolved benign episodes: a bounded FIFO whose evictions are counted.

    The ring is the receiver's private holdout (architecture §38's challenge set, the only
    one built). Old history falls off the front rather than refusing the new: a benign ring
    that stopped learning at capacity would validate against an ever-staler host.
    """

    __slots__ = ("_capacity", "_episodes", "_evictions")

    def __init__(self, *, capacity: int = MAX_BENIGN_EPISODES) -> None:
        if isinstance(capacity, bool) or not isinstance(capacity, int) or capacity < 1:
            raise ContractError(f"BenignRing capacity must be a positive int, got {capacity!r}")
        self._capacity = capacity
        self._episodes: deque[tuple[EncodedStep, ...]] = deque()
        self._evictions = 0

    @property
    def capacity(self) -> int:
        return self._capacity

    def add(self, steps: Sequence[EncodedStep]) -> None:
        episode = _require_steps(steps if isinstance(steps, tuple) else tuple(steps), "episode")
        if len(self._episodes) >= self._capacity:
            self._episodes.popleft()
            self._evictions += 1
        self._episodes.append(episode)

    def episodes(self) -> tuple[tuple[EncodedStep, ...], ...]:
        return tuple(self._episodes)

    def evictions(self) -> int:
        return self._evictions

    def memory_bytes(self) -> int:
        """An estimate: every step's feature tuple, its floats and a fixed scalar overhead."""
        total = sys.getsizeof(self._episodes)
        for episode in self._episodes:
            total += sys.getsizeof(episode)
            for step in episode:
                total += sys.getsizeof(step.features) + 24 * len(step.features)
                total += _STEP_OVERHEAD_BYTES
        return total


class LocalValidator:
    """Replays a motif against THIS host's evidence. The receiver's only trusted input.

    Order is the spec's (D7.11): ``NOT_OBSERVABLE`` first (a motif over relations this host
    cannot see is unjudgeable, not clean), then ``LOCAL_FP``, then ``LOCAL_CONFIRMED``,
    else ``PASS``. A motif that is both a local FP and matches a local incident is LOCAL_FP:
    firing on benign history is the contradiction that matters for sovereignty.
    """

    __slots__ = ("_benign", "_ceiling", "_incidents", "_meter", "_observable")

    def __init__(
        self,
        *,
        benign: BenignRing,
        incidents: Sequence[LocalIncident],
        observable_relations: frozenset[int],
        fp_ceiling: int = LOCAL_FP_CEILING,
        meter: WorkMeter | None = None,
    ) -> None:
        if not isinstance(benign, BenignRing):
            raise ContractError("LocalValidator needs a BenignRing")
        held = tuple(incidents)
        if any(not isinstance(item, LocalIncident) for item in held):
            raise ContractError("LocalValidator incidents must be LocalIncident values")
        if len(held) > MAX_LOCAL_INCIDENTS:
            raise ContractError(f"LocalValidator holds at most {MAX_LOCAL_INCIDENTS} incidents")
        if isinstance(fp_ceiling, bool) or not isinstance(fp_ceiling, int) or fp_ceiling < 0:
            raise ContractError(f"fp_ceiling must be a non-negative int, got {fp_ceiling!r}")
        observable = frozenset(observable_relations)
        if any(isinstance(r, bool) or not isinstance(r, int) for r in observable):
            raise ContractError("observable_relations must hold int relation ids")
        self._benign = benign
        self._incidents = held
        self._observable = observable
        self._ceiling = fp_ceiling
        self._meter = meter

    @property
    def benign(self) -> BenignRing:
        return self._benign

    def state_digest(self) -> str:
        """sha256 over EVERYTHING this validator judges with: FP ceiling, observable relations,
        each incident (id, evidence digests, length) and each benign episode's evidence digests.

        It exists so the offline-equivalence check (G7.3) can see a fabric that damaged local
        detection state; digesting only re-derived outputs could not (review finding F2).
        """
        material = [
            self._ceiling,
            sorted(self._observable),
            [[i.incident_id, list(i.evidence_digests), len(i.steps)] for i in self._incidents],
            [[d for step in episode for d in step.evidence] for episode in self._benign.episodes()],
        ]
        return hashlib.sha256(repr(material).encode("utf-8")).hexdigest()

    def validate(self, invariant: Sequence[MotifRow]) -> LocalValidation:
        rows = _require_rows(invariant)
        if any(row.relation not in self._observable for row in rows):
            return LocalValidation.NOT_OBSERVABLE
        hits = 0
        for episode in self._benign.episodes():
            if _matches_charged(rows, episode, self._meter):
                hits += 1
                if hits > self._ceiling:
                    return LocalValidation.LOCAL_FP
        for incident in self._incidents:
            if _matches_charged(rows, incident.steps, self._meter):
                return LocalValidation.LOCAL_CONFIRMED
        return LocalValidation.PASS


# --- the antibody -------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class KnowledgeAntibody:
    """A portable invariant. ``antibody_key`` is ``motif_fingerprint(invariant)``."""

    antibody_key: str
    invariant: tuple[MotifRow, ...]
    chain: tuple[ChainStage, ...]
    validation: ValidationSummary
    falsification: FalsificationSummary
    minimised: bool

    def __post_init__(self) -> None:
        rows = _require_rows(self.invariant)
        object.__setattr__(self, "invariant", rows)
        if self.antibody_key != motif_fingerprint(rows):
            raise ContractError(
                "KnowledgeAntibody.antibody_key must be motif_fingerprint(invariant)"
            )
        if tuple(self.chain) != derive_chain_stages(rows):
            raise ContractError("KnowledgeAntibody.chain must be derive_chain_stages(invariant)")


def _antibody(
    rows: tuple[MotifRow, ...],
    validation: ValidationSummary,
    falsification: FalsificationSummary,
    *,
    minimised: bool,
) -> KnowledgeAntibody:
    return KnowledgeAntibody(
        antibody_key=motif_fingerprint(rows),
        invariant=rows,
        chain=derive_chain_stages(rows),
        validation=validation,
        falsification=falsification,
        minimised=minimised,
    )


def _escalating(step: EncodedStep) -> bool:
    # Spec D7.11: "escalating" = the step asserts an object property or raises a dimension.
    return bool(step.object_property_mask or step.state_delta_mask)


def _row_of(step: EncodedStep) -> MotifRow:
    return MotifRow(
        relation=step.relation,
        require_properties=step.object_property_mask,
        forbid_properties=0,
        require_raised=step.state_delta_mask,
    )


def _candidates(incident: LocalIncident) -> tuple[tuple[MotifRow, ...], ...]:
    """Singles over escalating steps, then same-actor ordered pairs; capped, deduplicated."""
    escalating = [step for step in incident.steps if _escalating(step)]
    found: dict[tuple[MotifRow, ...], None] = {}
    for step in escalating:
        if len(found) >= MAX_FORGE_CANDIDATES:
            return tuple(found)
        found.setdefault((_row_of(step),), None)
    for index, first in enumerate(escalating):
        for second in escalating[index + 1 :]:
            if len(found) >= MAX_FORGE_CANDIDATES:
                return tuple(found)
            if first.actor_slot == second.actor_slot:
                found.setdefault((_row_of(first), _row_of(second)), None)
    return tuple(found)


# --- mutations ------------------------------------------------------------------------


def _rng_for(incident: LocalIncident, seed: int) -> random.Random:
    material = f"{seed}|{incident.incident_id}".encode()
    return random.Random(int.from_bytes(hashlib.sha256(material).digest()[:8], "big"))


def _reslot(steps: Sequence[EncodedStep], mapping: dict[int, int]) -> tuple[EncodedStep, ...]:
    return tuple(
        step
        if mapping.get(step.actor_slot, step.actor_slot) == step.actor_slot
        else replace(step, actor_slot=mapping[step.actor_slot])
        for step in steps
    )


def _drop_non_escalating(
    steps: tuple[EncodedStep, ...], rng: random.Random
) -> tuple[EncodedStep, ...]:
    return tuple(step for step in steps if _escalating(step) or rng.random() < 0.5)


def _permute_actors(steps: tuple[EncodedStep, ...], rng: random.Random) -> tuple[EncodedStep, ...]:
    slots = sorted({step.actor_slot for step in steps})
    targets = rng.sample(range(4 * len(slots) + 8), len(slots))
    return _reslot(steps, dict(zip(slots, targets, strict=True)))


def _interleave(
    steps: tuple[EncodedStep, ...], filler: tuple[EncodedStep, ...], rng: random.Random
) -> tuple[EncodedStep, ...]:
    """Merge benign filler on FRESH actor slots into the incident, keeping both orders."""
    if not filler:
        return steps
    base = max(step.actor_slot for step in steps) + 1
    fresh = _reslot(filler, {s.actor_slot: base + s.actor_slot for s in filler})
    merged: list[EncodedStep] = []
    left, right = list(steps), list(fresh)
    while left or right:
        take_left = bool(left) and (
            not right or rng.random() < len(left) / (len(left) + len(right))
        )
        merged.append(left.pop(0) if take_left else right.pop(0))
    return tuple(merged)


def _filler(
    incident: LocalIncident, benign: BenignRing | None, rng: random.Random
) -> tuple[EncodedStep, ...]:
    episodes = benign.episodes() if benign is not None else ()
    if episodes:
        return episodes[rng.randrange(len(episodes))]
    # No ring: the incident's own non-escalating steps are the only benign-like material.
    return tuple(step for step in incident.steps if not _escalating(step))


def _preserving(
    incident: LocalIncident, benign: BenignRing | None, rng: random.Random, kind: int
) -> tuple[EncodedStep, ...]:
    steps = incident.steps
    if kind == 0:
        return _drop_non_escalating(steps, rng)
    if kind == 1:
        return _permute_actors(steps, rng)
    return _interleave(steps, _filler(incident, benign, rng), rng)


def _splittable(steps: tuple[EncodedStep, ...]) -> dict[int, list[int]]:
    """Per actor slot, the indices of its escalating steps, for actors with >= 2 of them."""
    by_actor: dict[int, list[int]] = {}
    for index, step in enumerate(steps):
        if _escalating(step):
            by_actor.setdefault(step.actor_slot, []).append(index)
    return {slot: indices for slot, indices in by_actor.items() if len(indices) >= 2}


def _doppelganger(steps: tuple[EncodedStep, ...], rng: random.Random) -> tuple[EncodedStep, ...]:
    """Same steps, but each multi-step actor's escalating chain is cut across two actors."""
    splittable = _splittable(steps)
    next_free = max(step.actor_slot for step in steps) + 1
    moved: dict[int, int] = {}
    for slot in sorted(splittable):
        indices = splittable[slot]
        cut = rng.randint(1, len(indices) - 1)
        for index in indices[cut:]:
            moved[index] = next_free
        next_free += 1
    return tuple(
        replace(step, actor_slot=moved[index]) if index in moved else step
        for index, step in enumerate(steps)
    )


def mutate_incident(
    incident: LocalIncident, *, seed: int, benign: BenignRing | None = None
) -> tuple[tuple[tuple[EncodedStep, ...], ...], tuple[tuple[EncodedStep, ...], ...]]:
    """(attack_preserving, doppelgangers), ``MUTATIONS_PER_INCIDENT`` of each; deterministic.

    Preserving mutations cycle through: drop non-escalating steps, re-slot every actor
    through a random injective map, interleave a benign-ring episode on fresh actor slots.
    ``benign`` is an addition to the spec signature (keyword, optional): the spec asks the
    interleave to use benign-ring steps, which this function could not otherwise reach.
    Without a ring the incident's own non-escalating steps are the filler.

    Doppelgangers split every actor with >= 2 escalating steps at a random cut, moving the
    later part to a fresh actor slot: the attribution-only difference the ambiguous corpus
    is built on. An incident with no such actor has NO doppelganger (an unsplit copy of the
    incident is not a benign look-alike, and would convict every candidate), so the tuple
    is empty and the report says so by its length.
    """
    if not isinstance(incident, LocalIncident):
        raise ContractError("mutate_incident needs a LocalIncident")
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ContractError(f"seed must be an int, got {seed!r}")
    rng = _rng_for(incident, seed)
    preserving = tuple(
        _preserving(incident, benign, rng, index % 3) for index in range(MUTATIONS_PER_INCIDENT)
    )
    if not _splittable(incident.steps):
        return preserving, ()
    doppelgangers = tuple(_doppelganger(incident.steps, rng) for _ in range(MUTATIONS_PER_INCIDENT))
    return preserving, doppelgangers


# --- forging --------------------------------------------------------------------------


class _Discriminator:
    """The forge's four tests over one incident, cheapest and most-refuting first."""

    __slots__ = ("doppelgangers", "incident", "meter", "preserving", "ring")

    def __init__(
        self,
        incident: tuple[EncodedStep, ...],
        preserving: tuple[tuple[EncodedStep, ...], ...],
        doppelgangers: tuple[tuple[EncodedStep, ...], ...],
        ring: tuple[tuple[EncodedStep, ...], ...],
        meter: WorkMeter | None,
    ) -> None:
        self.incident = incident
        self.preserving = preserving
        self.doppelgangers = doppelgangers
        self.ring = ring
        self.meter = meter

    def holds(self, rows: tuple[MotifRow, ...]) -> bool:
        if not _matches_charged(rows, self.incident, self.meter):
            return False
        if any(_matches_charged(rows, d, self.meter) for d in self.doppelgangers):
            return False
        if not all(_matches_charged(rows, p, self.meter) for p in self.preserving):
            return False
        return not any(_matches_charged(rows, e, self.meter) for e in self.ring)


def _bits(rows: Sequence[MotifRow]) -> int:
    return sum(row.require_properties.bit_count() + row.require_raised.bit_count() for row in rows)


def _order(rows: Sequence[MotifRow]) -> tuple[int, int, tuple[tuple[int, int, int, int], ...]]:
    lexical = tuple(
        (r.relation, r.require_properties, r.forbid_properties, r.require_raised) for r in rows
    )
    return (len(rows), _bits(rows), lexical)


def _minimise(rows: tuple[MotifRow, ...], test: _Discriminator) -> tuple[MotifRow, ...]:
    """Greedy: drop one ``require_properties`` bit at a time while every test still holds."""
    current = list(rows)
    drops = 0
    for position in range(len(current)):
        mask = current[position].require_properties
        for bit in range(mask.bit_length()):
            if drops >= MAX_BIT_DROPS:
                return tuple(current)
            if not current[position].require_properties >> bit & 1:
                continue
            row = current[position]
            trial_row = replace(row, require_properties=row.require_properties & ~(1 << bit))
            trial = (*current[:position], trial_row, *current[position + 1 :])
            if test.holds(trial):
                current[position] = trial_row
                drops += 1
    return tuple(current)


def forge_antibody(
    incident: LocalIncident,
    *,
    benign: BenignRing,
    minimise: bool = True,
    seed: int = 0,
    meter: WorkMeter | None = None,
) -> KnowledgeAntibody | None:
    """§13: the smallest stable discriminative core of ``incident``, or ``None``.

    Keep candidates that match the incident and every attack-preserving mutation and no
    benign-ring episode and no doppelganger; minimise if asked; choose the shortest, then
    the fewest bits, then the lexicographically smallest. ``None`` means no stable
    discriminative core exists here: INSUFFICIENT is a valid output, never a failure.
    """
    if not isinstance(incident, LocalIncident):
        raise ContractError("forge_antibody needs a LocalIncident")
    if not isinstance(benign, BenignRing):
        raise ContractError("forge_antibody needs a BenignRing")
    preserving, doppelgangers = mutate_incident(incident, seed=seed, benign=benign)
    ring = benign.episodes()
    test = _Discriminator(incident.steps, preserving, doppelgangers, ring, meter)
    survivors = [rows for rows in _candidates(incident) if test.holds(rows)]
    if not survivors:
        return None
    shortest = min(len(rows) for rows in survivors)
    finalists = [rows for rows in survivors if len(rows) == shortest]
    if minimise:
        finalists = [_minimise(rows, test) for rows in finalists]
    chosen = min(finalists, key=_order)
    tried = len(preserving) + len(doppelgangers)
    return _antibody(
        chosen,
        ValidationSummary(episodes_replayed=1 + len(ring), true_matches=1, false_matches=0),
        FalsificationSummary(
            mutations_tried=tried, mutations_survived=tried, counter_hypotheses=()
        ),
        minimised=minimise,
    )


def copied_rule(incident: LocalIncident) -> KnowledgeAntibody | None:
    """The CONTROL (§13 "a rule copied from the original host", ORPH-F10).

    The first and last escalating steps of the incident's most-escalating actor (ties: the
    lowest slot), full masks, no minimisation and no mutation tests. ``None`` when the
    incident has no escalating step at all.
    """
    if not isinstance(incident, LocalIncident):
        raise ContractError("copied_rule needs a LocalIncident")
    by_actor: dict[int, list[EncodedStep]] = {}
    for step in incident.steps:
        if _escalating(step):
            by_actor.setdefault(step.actor_slot, []).append(step)
    if not by_actor:
        return None
    slot = min(by_actor, key=lambda s: (-len(by_actor[s]), s))
    chain = by_actor[slot]
    rows = (_row_of(chain[0]),) if len(chain) == 1 else (_row_of(chain[0]), _row_of(chain[-1]))
    return _antibody(
        rows,
        ValidationSummary(episodes_replayed=1, true_matches=1, false_matches=0),
        FalsificationSummary(mutations_tried=0, mutations_survived=0, counter_hypotheses=()),
        minimised=False,
    )


# --- prototype steps (the bridge's EncodedStep form of an antibody) ------------------


def _prototype(row: MotifRow, source_group: str) -> EncodedStep:
    try:
        relation = Relation(row.relation)
    except ValueError as exc:
        raise ContractError(f"MotifRow.relation {row.relation} is not a Stage 1 Relation") from exc
    if row.require_properties >> _OBJECT_WIDTH:
        raise ContractError(
            f"require_properties has bits past the {_OBJECT_WIDTH} encoded properties"
        )
    if row.require_raised >> _RAISED_WIDTH:
        raise ContractError(f"require_raised has bits past the {_RAISED_WIDTH} state dimensions")
    family = family_of(relation)
    features = [0.0] * FEATURE_WIDTH
    features[_RELATION_OFFSET + int(relation)] = 1.0
    features[_FAMILY_OFFSET + int(family)] = 1.0
    for bit in range(_OBJECT_WIDTH):
        if row.require_properties >> bit & 1:
            features[_OBJECT_OFFSET + bit] = 1.0
    for bit in range(_RAISED_WIDTH):
        if row.require_raised >> bit & 1:
            features[_RAISED_OFFSET + bit] = 1.0
    return EncodedStep(
        features=tuple(features),
        relation=int(relation),
        relation_family=int(family),
        state_delta_mask=row.require_raised,
        time_bucket=0,
        delta_phi=0.0,
        object_property_mask=row.require_properties,
        epoch_id=0,
        actor_slot=0,
        uncertainty=0.0,
        source_group=source_group,
        causal_signature="",
        parent_signature="",
        evidence=(),
    )


def prototype_steps(invariant: Sequence[MotifRow], *, source_group: str) -> tuple[EncodedStep, ...]:
    """One ``EncodedStep`` per row, all on actor slot 0, carrying ONLY what the row asserts.

    Relation and family one-hots, object-semantics bits from ``require_properties`` and
    raised bits from ``require_raised``; every other feature 0.0 (no novelty, no timing,
    no uncertainty: those are host-baseline dependent and are never invented). Features
    are exactly 0.0/1.0, so they already satisfy ``EncodedStep``'s rounding contract.
    INVARIANT (tested): ``matches(invariant, prototype_steps(invariant, ...))``.
    """
    rows = _require_rows(invariant)
    steps = tuple(_prototype(row, source_group) for row in rows)
    if not matches(rows, steps):  # pragma: no cover - guarded by a test
        raise ContractError("prototype steps do not satisfy their own invariant")
    return steps
