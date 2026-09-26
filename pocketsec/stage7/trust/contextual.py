"""Architecture §22 — contextual trust: Trust(cluster, task, epoch) is not a global reputation.

A peer cluster that has been right about web-server persistence motifs has earned nothing
about desktop credential motifs, and what it earned last month is worth less today. So
reliability is keyed on ``(cluster_id, task)`` — ``task`` is the capsule's causal motif,
``"-".join`` of its chain stages — and every entry decays toward ``prior`` with a
half-life counted in rounds. The unit is the dependence **cluster**, never an identity:
trust bought by one identity is shared by (and diluted across) every identity merged
with it.

**Trust never removes local validation.** ECHO gates on the receiver's own local
validation first and independently of reliability; reliability can only scale how much
mass an already locally-validated contribution carries. A perfectly trusted cluster whose
antibody fires on local benign behaviour is still CHALLENGED.

Why the update is asymmetric (``+CONFIRM_STEP`` on a confirmation, ``x REFUTE_FACTOR`` on
a refutation): the slow-poisoning adversary (arm SLOW_POISON) earns trust with cheap
correct relays and then spends it once. One refutation must cost more than many
confirmations earn — from any level, a single refutation lands below the prior. Only
LOCAL evidence records an outcome; a peer's contest is not a refutation.

Whether reputation helps at all is an open question this module does not settle: if it
measurably raises poison acceptance on SLOW_POISON, it is HARMFUL and ADR-0069 says so.
``enabled=False`` is the CONTROL: every reliability is the prior.

Bounded: at most ``capacity`` entries. When full, the entry evicted is the one whose
decayed reliability is **highest** (oldest first on ties), because forgetting may only move
a cluster's trust down toward the prior, never lift a refuted cluster back up to it.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence
from dataclasses import dataclass, replace

from pocketsec.stage0.contracts.common import (
    ContractError,
    require_finite_unit_interval,
    require_identifier,
    require_non_negative_int,
)

__all__ = [
    "CONFIRM_STEP",
    "MAX_TRUST_ENTRIES",
    "REFUTE_FACTOR",
    "TRUST_CEILING",
    "TRUST_FLOOR",
    "TRUST_HALF_LIFE_ROUNDS",
    "TRUST_PRIOR",
    "ContextualTrust",
    "TrustState",
    "task_key",
]

#: §4.23. Chosen parameters, not measurements.
MAX_TRUST_ENTRIES: int = 4096
TRUST_PRIOR: float = 0.5
TRUST_FLOOR: float = 0.05
TRUST_CEILING: float = 1.0
CONFIRM_STEP: float = 0.1
REFUTE_FACTOR: float = 0.25
TRUST_HALF_LIFE_ROUNDS: int = 64


def task_key(causal_motif: Sequence[str]) -> str:
    """The trust task of a capsule: ``"-".join`` of its chain-stage values (never empty)."""
    stages = [str(stage) for stage in causal_motif]
    if not stages or not all(stages):
        raise ContractError(f"a trust task needs at least one chain stage, got {causal_motif!r}")
    return "-".join(stages)


@dataclass(frozen=True, slots=True)
class TrustState:
    reliability: float    # as of last_round, before any decay since
    confirmations: int
    refutations: int
    last_round: int

    def __post_init__(self) -> None:
        require_finite_unit_interval(self.reliability, "reliability")
        require_non_negative_int(self.confirmations, "confirmations")
        require_non_negative_int(self.refutations, "refutations")
        require_non_negative_int(self.last_round, "last_round")


def _clamp(value: float) -> float:
    return min(TRUST_CEILING, max(TRUST_FLOOR, value))


class ContextualTrust:
    """Bounded, decaying, task-scoped reliability per dependence cluster."""

    def __init__(
        self,
        *,
        capacity: int = MAX_TRUST_ENTRIES,
        prior: float = TRUST_PRIOR,
        half_life_rounds: int = TRUST_HALF_LIFE_ROUNDS,
        enabled: bool = True,
    ) -> None:
        if require_non_negative_int(capacity, "capacity") < 1:
            raise ContractError(f"capacity must be >= 1, got {capacity}")
        if require_non_negative_int(half_life_rounds, "half_life_rounds") < 1:
            raise ContractError(f"half_life_rounds must be >= 1, got {half_life_rounds}")
        prior = require_finite_unit_interval(prior, "prior")
        if not TRUST_FLOOR <= prior <= TRUST_CEILING:
            raise ContractError(f"prior must lie in [{TRUST_FLOOR}, {TRUST_CEILING}], got {prior}")
        if not isinstance(enabled, bool):
            raise ContractError(f"enabled must be a bool, got {enabled!r}")
        self._capacity = capacity
        self._prior = prior
        self._half_life = half_life_rounds
        self._enabled = enabled
        self._table: dict[tuple[str, str], TrustState] = {}
        self._evictions = 0

    @property
    def prior(self) -> float:
        return self._prior

    @property
    def enabled(self) -> bool:
        return self._enabled

    def __len__(self) -> int:
        return len(self._table)

    def reliability(self, cluster_id: str, task: str, *, round_index: int) -> float:
        """Decayed reliability in ``[TRUST_FLOOR, TRUST_CEILING]``; the prior if unknown or disabled."""
        key = self._key(cluster_id, task)
        require_non_negative_int(round_index, "round_index")
        if not self._enabled:
            return self._prior
        state = self._table.get(key)
        if state is None:
            return self._prior
        return self._decayed(state, round_index)

    def state(self, cluster_id: str, task: str) -> TrustState | None:
        """The stored (undecayed) state, for audit; ``None`` if never recorded."""
        return self._table.get(self._key(cluster_id, task))

    def record(self, cluster_id: str, task: str, *, confirmed: bool, round_index: int) -> None:
        """Apply one LOCAL outcome: ``+CONFIRM_STEP`` if confirmed, ``x REFUTE_FACTOR`` if refuted."""
        key = self._key(cluster_id, task)
        require_non_negative_int(round_index, "round_index")
        if not isinstance(confirmed, bool):
            raise ContractError(f"confirmed must be a bool, got {confirmed!r}")
        if not self._enabled:
            return
        state = self._table.get(key)
        if state is None:
            self._make_room(round_index)
            state = TrustState(self._prior, 0, 0, round_index)
        current = self._decayed(state, round_index)
        if confirmed:
            updated = replace(state, reliability=_clamp(current + CONFIRM_STEP),
                              confirmations=state.confirmations + 1,
                              last_round=max(state.last_round, round_index))
        else:
            updated = replace(state, reliability=_clamp(current * REFUTE_FACTOR),
                              refutations=state.refutations + 1,
                              last_round=max(state.last_round, round_index))
        self._table[key] = updated

    def evictions(self) -> int:
        return self._evictions

    def memory_bytes(self) -> int:
        per_entry = sum(sys.getsizeof(cluster) + sys.getsizeof(task) + 48 + 80
                        for cluster, task in self._table)
        return sys.getsizeof(self._table) + per_entry

    # --- internals ---------------------------------------------------------------------

    @staticmethod
    def _key(cluster_id: str, task: str) -> tuple[str, str]:
        return (require_identifier(cluster_id, "cluster_id"), require_identifier(task, "task"))

    def _decayed(self, state: TrustState, round_index: int) -> float:
        # A query for a round before the last update does not un-decay: elapsed floors at 0.
        elapsed = max(0, round_index - state.last_round)
        factor = 0.5 ** (elapsed / self._half_life)
        return _clamp(self._prior + (state.reliability - self._prior) * factor)

    def _make_room(self, round_index: int) -> None:
        if len(self._table) < self._capacity:
            return
        victim = max(self._table, key=lambda k: (self._decayed(self._table[k], round_index),
                                                 -self._table[k].last_round))
        del self._table[victim]
        self._evictions += 1
