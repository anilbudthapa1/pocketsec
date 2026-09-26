"""D6.5 / HEL-F07 — epistemic half-life: how long a trusted item deserves to be believed.

Knowledge does not decay merely because it is old (architecture §10). An item that
keeps being validated and keeps recurring should outlive one that was contradicted or
whose context has moved on::

    H = h0 * (1 + validation_strength + recurrence)
            / (1 + contradiction + epoch_distance + drift_sensitivity)
    trust(age) = 2 ** (-age / H)          # trust(0) = 1

``age`` is counted in sequences since the item last matched — time is the event
stream, not the wall clock (spec §2.3). Each input is squashed to ``x / (x + 1)`` so
no single count can dominate and the ratio stays within ``[h0/4, 3*h0]``.

**The simple control is least-recently-matched (LRU) order** (:func:`lru_ranking`):
evict or retire whatever matched longest ago. Half-life earns its place only by
choosing a *different* victim than LRU and being right to; its firing count is the
number of eviction decisions whose victim differs from the LRU victim, and a count of
zero means it is ``INERT`` (Rule C). The architecture calls the formula "a research
starting point"; ``HALF_LIFE_H0`` and ``RETIRE_TRUST_FLOOR`` are chosen parameters,
not calibrated values.

What it refuses to do: it ranks and never removes. Retiring an item changes trusted
state, and only the promotion controller does that. It also refuses a ``now`` earlier
than an item's last match — negative age would mint trust above 1.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage6.memory.semantic import ItemKind, KnowledgeItem

__all__ = [
    "HALF_LIFE_H0",
    "RETIRE_TRUST_FLOOR",
    "EpistemicHalfLife",
    "HalfLifeInputs",
    "below_retire_floor",
    "half_life",
    "half_life_inputs",
    "lru_ranking",
    "trust_ranking",
    "update_epistemic_half_life",
]

HALF_LIFE_H0: float = 2048.0
RETIRE_TRUST_FLOOR: float = 0.05

#: Context-bound kinds decay faster when the environment moves: a BASELINE describes
#: one host's normal, and a PROCEDURE is keyed to the context it was verified in. A
#: DETECTOR describes attacker behaviour, which a host upgrade does not change.
_DRIFT_SENSITIVE: frozenset[ItemKind] = frozenset({ItemKind.BASELINE, ItemKind.PROCEDURE})


def _squash(count: int, field: str) -> float:
    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        raise ContractError(f"{field} must be a non-negative int, got {count!r}")
    return count / (count + 1)


@dataclass(frozen=True, slots=True)
class HalfLifeInputs:
    validation_strength: float  # validations / (validations + 1)
    recurrence: float  # recurrence / (recurrence + 1)
    contradiction: float  # contradictions / (contradictions + 1)
    epoch_distance: float  # corroborated epochs since last match, / (that + 1)
    drift_sensitivity: float  # 1 for context-bound kinds, 0 otherwise

    def __post_init__(self) -> None:
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ContractError(f"HalfLifeInputs.{name} must be a number")
            if not 0.0 <= float(value) <= 1.0:
                raise ContractError(f"HalfLifeInputs.{name} must be within [0, 1], got {value!r}")


def half_life(inputs: HalfLifeInputs, *, h0: float = HALF_LIFE_H0) -> float:
    """H = h0 * (1 + V + R) / (1 + C + E + D), in sequences."""
    numeric = isinstance(h0, (int, float)) and not isinstance(h0, bool)
    if not numeric or not 0.0 < float(h0) < float("inf"):
        raise ContractError(f"h0 must be a positive finite number, got {h0!r}")
    numerator = 1.0 + inputs.validation_strength + inputs.recurrence
    denominator = 1.0 + inputs.contradiction + inputs.epoch_distance + inputs.drift_sensitivity
    return float(h0) * numerator / denominator


def half_life_inputs(item: KnowledgeItem, *, epochs_since_match: int) -> HalfLifeInputs:
    checks = item.validation
    return HalfLifeInputs(
        validation_strength=_squash(checks.validations, "validations"),
        recurrence=_squash(checks.recurrence, "recurrence"),
        contradiction=_squash(checks.contradictions, "contradictions"),
        epoch_distance=_squash(epochs_since_match, "epochs_since_match"),
        drift_sensitivity=1.0 if item.kind in _DRIFT_SENSITIVE else 0.0,
    )


@dataclass(frozen=True, slots=True)
class EpistemicHalfLife:
    item_id: str
    half_life: float
    age: int
    trust: float
    inputs: HalfLifeInputs


def update_epistemic_half_life(
    item: KnowledgeItem, *, now_sequence: int, epochs_since_match: int
) -> EpistemicHalfLife:
    """HEL-F07. Pure: computes an item's current trust; changes nothing."""
    if not isinstance(item, KnowledgeItem):
        raise ContractError("update_epistemic_half_life takes a KnowledgeItem")
    if not isinstance(now_sequence, int) or isinstance(now_sequence, bool):
        raise ContractError("now_sequence is an int sequence counter")
    age = now_sequence - item.validation.last_matched_sequence
    if age < 0:
        raise ContractError(
            f"now_sequence {now_sequence} precedes item {item.item_id}'s last match; "
            "negative age would mint trust above 1"
        )
    inputs = half_life_inputs(item, epochs_since_match=epochs_since_match)
    horizon = half_life(inputs)
    return EpistemicHalfLife(
        item_id=item.item_id,
        half_life=horizon,
        age=age,
        trust=2.0 ** (-age / horizon),
        inputs=inputs,
    )


def trust_ranking(
    items: Sequence[KnowledgeItem], *, now_sequence: int, epochs_since_match: Mapping[str, int]
) -> tuple[EpistemicHalfLife, ...]:
    """Least-trusted first (the eviction/retire order); ties broken by item id.

    An item absent from ``epochs_since_match`` is taken to have seen no epoch change.
    """
    rows = [
        update_epistemic_half_life(
            item,
            now_sequence=now_sequence,
            epochs_since_match=epochs_since_match.get(item.item_id, 0),
        )
        for item in items
    ]
    return tuple(sorted(rows, key=lambda row: (row.trust, row.item_id)))


def lru_ranking(items: Sequence[KnowledgeItem]) -> tuple[str, ...]:
    """The simple control: item ids, least-recently-matched first; ties by item id."""
    ordered = sorted(items, key=lambda item: (item.validation.last_matched_sequence, item.item_id))
    return tuple(item.item_id for item in ordered)


def below_retire_floor(ranking: Sequence[EpistemicHalfLife]) -> tuple[str, ...]:
    """Item ids whose trust fell below ``RETIRE_TRUST_FLOOR`` — candidates, not decisions."""
    return tuple(row.item_id for row in ranking if row.trust < RETIRE_TRUST_FLOOR)
