"""HEL-F09 — ``generate_plasticity_mask``: the permission a candidate is built under.

Architecture §12's mask, bound: a frozen core, an adaptable set, a bounded
number of item mutations, a bounded threshold move, and an expiry. The chamber
drops every proposed change the mask does not permit and counts it; nothing a
mask forbids reaches a candidate.

HEL-F09 is REQUIRED because the frozen core and the budgets are **safety
bounds**, not tuning:

* **Every protected item is always frozen.** An item that touches a protected
  anchor (credential material, privilege boundary, egress …) can never be
  mutated, replaced or removed through a mask, whatever the plasticity field
  says. ``protected`` is applied *before* the field is read, and a mask whose
  frozen core and adaptable set intersect cannot be constructed.
* **Budgets are capped by module constants.** A mask asking for more than
  ``MAX_ITEM_MUTATIONS`` or ``MAX_THRESHOLD_DELTA`` is refused at construction.
* **An expired mask permits nothing.** Masks are sequence-dated (time is the
  event stream, not the wall clock); a stale permission cannot be replayed into
  a later candidate.

``uniform_mask`` is the simple control for HEL-F08: the same protected freeze and
the **same** budgets, with no field. The only thing that differs between the two
is whether low-plasticity components are frozen, which is exactly the mechanism
the ablation isolates.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage6.plasticity.field import PLASTICITY_FLOOR, PlasticityField

__all__ = [
    "MASK_EXPIRY_SEQUENCES",
    "MAX_ITEM_MUTATIONS",
    "MAX_THRESHOLD_DELTA",
    "PlasticityMask",
    "field_only_freezes",
    "generate_plasticity_mask",
    "uniform_mask",
]

#: Item additions, replacements and removals one candidate may carry. Chosen:
#: small enough that a regression is attributable to a handful of changes.
MAX_ITEM_MUTATIONS: int = 4
#: Largest move of the alert threshold one candidate may make.
MAX_THRESHOLD_DELTA: float = 0.10
#: A mask is valid for this many offered capsules after it was created.
MASK_EXPIRY_SEQUENCES: int = 512


@dataclass(frozen=True, slots=True)
class PlasticityMask:
    """Architecture §12. Construction refuses any mask looser than the bounds."""

    frozen_core: frozenset[str]  # every protected item + every component with P < PLASTICITY_FLOOR
    adaptable: frozenset[str]
    max_item_mutations: int  # <= MAX_ITEM_MUTATIONS
    max_threshold_delta: float  # <= MAX_THRESHOLD_DELTA
    expires_at_sequence: int  # created + MASK_EXPIRY_SEQUENCES

    def __post_init__(self) -> None:
        if self.frozen_core & self.adaptable:
            overlap = sorted(self.frozen_core & self.adaptable)
            raise ContractError(f"a component cannot be both frozen and adaptable: {overlap}")
        if not isinstance(self.max_item_mutations, int) or isinstance(
            self.max_item_mutations, bool
        ):
            raise ContractError("max_item_mutations must be an int")
        if not 0 <= self.max_item_mutations <= MAX_ITEM_MUTATIONS:
            raise ContractError(
                f"max_item_mutations {self.max_item_mutations} outside [0, {MAX_ITEM_MUTATIONS}]"
            )
        delta = float(self.max_threshold_delta)
        if delta != delta or not 0.0 <= delta <= MAX_THRESHOLD_DELTA:
            raise ContractError(
                f"max_threshold_delta {delta!r} outside [0, {MAX_THRESHOLD_DELTA}]"
            )
        if not isinstance(self.expires_at_sequence, int) or self.expires_at_sequence < 0:
            raise ContractError("expires_at_sequence must be a non-negative int")

    def expired(self, now_sequence: int) -> bool:
        return now_sequence >= self.expires_at_sequence

    def permits(self, component_id: str, *, now_sequence: int) -> bool:
        """True only for an adaptable, unfrozen component of an unexpired mask."""
        if self.expired(now_sequence):
            return False
        return component_id in self.adaptable and component_id not in self.frozen_core

    def threshold_budget(self, *, now_sequence: int) -> float:
        """The threshold move this mask allows now: ``0.0`` once expired or frozen."""
        if not self.permits("threshold", now_sequence=now_sequence):
            return 0.0
        return self.max_threshold_delta


def _budgets(max_item_mutations: int, max_threshold_delta: float) -> tuple[int, float]:
    # Validated again by PlasticityMask; checked here so the error names the call.
    if max_item_mutations > MAX_ITEM_MUTATIONS or max_threshold_delta > MAX_THRESHOLD_DELTA:
        raise ContractError("a mask budget may not exceed the module caps")
    return max_item_mutations, max_threshold_delta


def generate_plasticity_mask(
    field: PlasticityField,
    *,
    protected: frozenset[str],
    now_sequence: int,
    max_item_mutations: int = MAX_ITEM_MUTATIONS,
    max_threshold_delta: float = MAX_THRESHOLD_DELTA,
) -> PlasticityMask:
    """HEL-F09. Protected components and every ``P < PLASTICITY_FLOOR`` are frozen.

    ``protected`` is unioned into the frozen core whether or not the field scored
    the component, so a caller that forgets to score a protected item still
    cannot make it adaptable.
    """
    mutations, delta = _budgets(max_item_mutations, max_threshold_delta)
    low = frozenset(cid for cid, value in field.entries if value < PLASTICITY_FLOOR)
    frozen = frozenset(protected) | low
    adaptable = frozenset(field.component_ids()) - frozen
    return PlasticityMask(
        frozen_core=frozen,
        adaptable=adaptable,
        max_item_mutations=mutations,
        max_threshold_delta=delta,
        expires_at_sequence=now_sequence + MASK_EXPIRY_SEQUENCES,
    )


def uniform_mask(
    component_ids: Iterable[str],
    *,
    protected: frozenset[str],
    now_sequence: int,
    max_item_mutations: int = MAX_ITEM_MUTATIONS,
    max_threshold_delta: float = MAX_THRESHOLD_DELTA,
) -> PlasticityMask:
    """The SIMPLE CONTROL: the same protected freeze and budgets, no field."""
    mutations, delta = _budgets(max_item_mutations, max_threshold_delta)
    frozen = frozenset(protected)
    return PlasticityMask(
        frozen_core=frozen,
        adaptable=frozenset(component_ids) - frozen,
        max_item_mutations=mutations,
        max_threshold_delta=delta,
        expires_at_sequence=now_sequence + MASK_EXPIRY_SEQUENCES,
    )


def field_only_freezes(
    field_mask: PlasticityMask,
    control: PlasticityMask,
    component_ids: Iterable[str],
    *,
    now_sequence: int,
) -> int:
    """HEL-F08's firing count: proposed changes the field froze that uniform allowed."""
    return sum(
        1
        for cid in component_ids
        if control.permits(cid, now_sequence=now_sequence)
        and not field_mask.permits(cid, now_sequence=now_sequence)
    )
