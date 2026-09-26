"""D7.14 / ORPH-F12 — collective novelty: distributed rarity, conditioned on similar hosts.

Architecture §17: search for *distributed* rarity, not local rarity alone, and condition
population rarity "on epistemically similar hosts to avoid calling ordinary role-specific
behaviour globally anomalous". A pattern that is new to this host may be routine on every
ADMIN box in the fleet; a pattern several independent clusters report while the relevant
population almost never shows it is a different thing. This engine computes that
difference and nothing more.

The §17 binding (spec D7.14), for one pattern at round ``r`` over the window
``[r - window_rounds + 1, r]``:

* ``rarity = 1 - min(1, count_in_relevant_roles / RARITY_SCALE)``, from the per-role
  population counts released through :meth:`CollectiveNoveltyEngine.observe_population`
  (exact, DP-noised or secure-summed; a noised negative count is floored at 0). The
  relevant roles are the receiver's own role, or every role when the receiver's role is
  UNKNOWN. **No release for a relevant role in the window means rarity is unknown**, and an
  unknown rarity is reported as ``0.0`` with status INSUFFICIENT: silence about the
  population is not evidence that a pattern is rare.
* ``coherence = min(1, distinct clusters in window / 2)``.
* ``causal_surprise = (escalating stages in causal_motif) / 3``, clipped at 1; escalating
  means CREDENTIAL, ELEVATION, PERSISTENCE or EGRESS. The antibody grammar carries at most
  two rows (Stage 6's ``MAX_MOTIF_LENGTH``), so this term never exceeds 2/3: stated, not hidden.
* ``persistence = distinct rounds reported / window_rounds``.
* ``independent_support`` = distinct clusters reporting in the window.
* ``benign_epoch_explanation`` = share of reports in the window whose ``software_epoch`` first
  appeared inside the window (a fresh image: H1's signal). An epoch the engine has lost
  track of counts as fresh, the direction that suppresses novelty rather than inventing it.
* ``score = rarity * coherence * causal_surprise * persistence / (1 + EPOCH_EXPLANATION_K *
  explanation)``.

Status: LOCAL_ONLY when fewer than two clusters report it; INSUFFICIENT when rarity is
unknown or the evidence is weak; COLLECTIVELY_NOVEL iff ``score >= NOVELTY_FLOOR`` and
support ``>= 2``; EXPLAINED_BY_EPOCH when the pattern would be novel but for a fresh image.

**Control (``enabled=False``): local novelty only.** A pattern is flagged (status
COLLECTIVELY_NOVEL, score 1.0) iff this host first sighted it inside the window, whatever
the population says. The status name is shared so the two answers can be compared
pattern by pattern; under the control it means "new to me", nothing collective.

**Novelty is not maliciousness.** This module emits no verdict, imports no verdict type and
produces no ``ThreatPredictionV1``; its outputs feed fragment rarity (D7.13) and reporting
only. Nothing here is bridged to Stage 6.

**Bounds.** The pattern table holds at most ``max_patterns`` patterns, evicting the least
recently touched one (counted); each pattern keeps at most :data:`MAX_REPORTS_PER_PATTERN`
reports (oldest dropped, counted). The population table and the epoch first-seen table are
bounded by ``max_patterns`` the same way, and population rounds are pruned to the window.
Unlike the peer table, eviction rather than refusal is chosen here because the engine is
advisory and holds no identity: a flood can make it forget, never make it trust.
"""

from __future__ import annotations

import sys
from collections import OrderedDict, deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from pocketsec.stage0.contracts.common import (
    ContractError,
    require_finite_unit_interval,
    require_identifier,
    require_non_negative_int,
)
from pocketsec.stage6.resources import WorkMeter
from pocketsec.stage7.capsule.knowledge_capsule import ChainStage, KnowledgeType, RoleClass

if TYPE_CHECKING:  # annotation only: this engine duck-reads .capsule/.cluster_id/.received_round
    from pocketsec.stage7.hivelock.ingress import PooledCapsule
    from pocketsec.stage7.relevance.epistemic_distance import LocalContext

__all__ = [
    "EPOCH_EXPLANATION_K",
    "ESCALATING_STAGES",
    "MAX_NOVELTY_PATTERNS",
    "MAX_REPORTS_PER_PATTERN",
    "MIN_INDEPENDENT_SUPPORT",
    "NOVELTY_FLOOR",
    "NOVELTY_WINDOW_ROUNDS",
    "RARITY_SCALE",
    "CollectiveNovelty",
    "CollectiveNoveltyEngine",
    "NoveltyStatus",
]

#: §4.23. Chosen parameters, not measurements.
MAX_NOVELTY_PATTERNS: int = 1024
NOVELTY_WINDOW_ROUNDS: int = 16
RARITY_SCALE: int = 8
NOVELTY_FLOOR: float = 0.3
EPOCH_EXPLANATION_K: float = 4.0
#: "support >= 2" in the spec, named so it is one number.
MIN_INDEPENDENT_SUPPORT: int = 2
#: Not in §4.23: a per-pattern report cap so one round's flood cannot grow a pattern
#: without bound. Chosen, not measured.
MAX_REPORTS_PER_PATTERN: int = 64

ESCALATING_STAGES: frozenset[ChainStage] = frozenset(
    {ChainStage.CREDENTIAL, ChainStage.ELEVATION, ChainStage.PERSISTENCE, ChainStage.EGRESS}
)
_ENTRY_OVERHEAD_BYTES = 120


class NoveltyStatus(StrEnum):
    COLLECTIVELY_NOVEL = "COLLECTIVELY_NOVEL"
    EXPLAINED_BY_EPOCH = "EXPLAINED_BY_EPOCH"
    LOCAL_ONLY = "LOCAL_ONLY"
    INSUFFICIENT = "INSUFFICIENT"


@dataclass(frozen=True, slots=True)
class CollectiveNovelty:
    """How unusual one pattern is across the relevant population. A report, never a verdict."""

    pattern_key: str
    rarity: float
    coherence: float
    causal_surprise: float
    persistence: float
    independent_support: int
    benign_epoch_explanation: float
    score: float
    status: NoveltyStatus

    def __post_init__(self) -> None:
        require_identifier(self.pattern_key, "CollectiveNovelty.pattern_key")
        for name in ("rarity", "coherence", "causal_surprise", "persistence",
                     "benign_epoch_explanation", "score"):
            require_finite_unit_interval(getattr(self, name), f"CollectiveNovelty.{name}")
        require_non_negative_int(self.independent_support, "CollectiveNovelty.independent_support")
        if not isinstance(self.status, NoveltyStatus):
            raise ContractError(f"CollectiveNovelty.status invalid: {self.status!r}")


class _Pattern:
    """Mutable per-pattern state; lives only inside the engine."""

    __slots__ = ("first_local_round", "reports", "stages")

    def __init__(self, stages: tuple[ChainStage, ...], first_round: int) -> None:
        self.stages = stages
        self.first_local_round = first_round
        self.reports: deque[tuple[int, str, str]] = deque(maxlen=MAX_REPORTS_PER_PATTERN)


class CollectiveNoveltyEngine:
    """Bounded collective-novelty bookkeeping for one receiving host (module docstring)."""

    def __init__(
        self,
        *,
        local: LocalContext,
        window_rounds: int = NOVELTY_WINDOW_ROUNDS,
        max_patterns: int = MAX_NOVELTY_PATTERNS,
        enabled: bool = True,
        meter: WorkMeter | None = None,
    ) -> None:
        if not isinstance(getattr(local, "role", None), RoleClass):
            raise ContractError("local must carry a RoleClass .role (a LocalContext)")
        for name, value in (("window_rounds", window_rounds), ("max_patterns", max_patterns)):
            if require_non_negative_int(value, name) < 1:
                raise ContractError(f"{name} must be >= 1, got {value}")
        self._role: RoleClass = local.role
        self._window = window_rounds
        self._max = max_patterns
        self._enabled = bool(enabled)
        self._meter = meter
        self._patterns: OrderedDict[str, _Pattern] = OrderedDict()
        self._population: OrderedDict[str, dict[RoleClass, dict[int, int]]] = OrderedDict()
        self._released: dict[RoleClass, set[int]] = {}
        self._epochs: OrderedDict[str, int] = OrderedDict()
        self._counts: dict[str, int] = {
            "ignored_non_novelty": 0,
            "pattern_evictions": 0,
            "report_drops": 0,
            "population_evictions": 0,
            "epoch_evictions": 0,
        }

    # --- intake --------------------------------------------------------------------

    def observe(self, pooled: PooledCapsule) -> None:
        """Record a pooled NOVELTY capsule; any other knowledge type is ignored and counted."""
        capsule = pooled.capsule
        if capsule.knowledge_type is not KnowledgeType.NOVELTY:
            self._counts["ignored_non_novelty"] += 1
            return
        self.observe_report(
            capsule.compact_feature_signature,
            stages=tuple(capsule.causal_motif),
            cluster_id=pooled.cluster_id,
            software_epoch=capsule.epoch_context.software_epoch,
            round_index=pooled.received_round,
        )

    def observe_report(self, pattern_key: str, *, stages: Iterable[ChainStage], cluster_id: str,
                       software_epoch: str, round_index: int) -> None:
        """The primitive behind :meth:`observe`: one cluster reported one pattern this round."""
        require_identifier(pattern_key, "pattern_key")
        require_identifier(cluster_id, "cluster_id")
        require_non_negative_int(round_index, "round_index")
        chain = tuple(stages)
        if not all(isinstance(stage, ChainStage) for stage in chain):
            raise ContractError("stages must be ChainStage values")
        self.note_epoch(software_epoch, round_index)
        state = self._patterns.get(pattern_key)
        if state is None:
            if len(self._patterns) >= self._max:
                self._patterns.popitem(last=False)
                self._counts["pattern_evictions"] += 1
            state = _Pattern(chain, round_index)
            self._patterns[pattern_key] = state
        else:
            self._patterns.move_to_end(pattern_key)
            state.first_local_round = min(state.first_local_round, round_index)
        if len(state.reports) == MAX_REPORTS_PER_PATTERN:
            self._counts["report_drops"] += 1
        state.reports.append((round_index, cluster_id, software_epoch))
        if self._meter is not None:
            self._meter.charge(1)

    def note_epoch(self, software_epoch: str, round_index: int) -> None:
        """Record a sighting of ``software_epoch`` (the earliest round is kept)."""
        require_identifier(software_epoch, "software_epoch")
        require_non_negative_int(round_index, "round_index")
        held = self._epochs.get(software_epoch)
        if held is None:
            if len(self._epochs) >= self._max:
                self._epochs.popitem(last=False)
                self._counts["epoch_evictions"] += 1
            self._epochs[software_epoch] = round_index
        else:
            self._epochs[software_epoch] = min(held, round_index)
            self._epochs.move_to_end(software_epoch)

    def observe_population(self, counts: Mapping[str, int], *, role: RoleClass,
                           round_index: int) -> None:
        """A released per-role count of hosts showing each pattern this round (§17 conditioning).

        An empty mapping is still a release: it says "zero hosts of this role showed any
        pattern", which makes rarity known (and high) rather than unknown.
        """
        if not isinstance(role, RoleClass):
            raise ContractError(f"role must be a RoleClass, got {role!r}")
        require_non_negative_int(round_index, "round_index")
        floor = round_index - self._window + 1
        released = self._released.setdefault(role, set())
        released.add(round_index)
        self._released[role] = {item for item in released if item >= floor}
        for pattern_key, count in counts.items():
            require_identifier(pattern_key, "population pattern key")
            if isinstance(count, bool) or not isinstance(count, int):
                raise ContractError(
                    f"population count for {pattern_key} must be an int, got {count!r}"
                )
            per_role = self._population.get(pattern_key)
            if per_role is None:
                if len(self._population) >= self._max:
                    self._population.popitem(last=False)
                    self._counts["population_evictions"] += 1
                per_role = {}
                self._population[pattern_key] = per_role
            else:
                self._population.move_to_end(pattern_key)
            rounds = per_role.setdefault(role, {})
            rounds[round_index] = count
            per_role[role] = {item: value for item, value in rounds.items() if item >= floor}

    # --- evaluation ----------------------------------------------------------------

    def _relevant_roles(self) -> tuple[RoleClass, ...]:
        if self._role is RoleClass.UNKNOWN:
            return tuple(RoleClass)
        return (self._role,)

    def _rarity(self, pattern_key: str, round_index: int) -> float | None:
        floor = round_index - self._window + 1
        roles = self._relevant_roles()
        released = (item for role in roles for item in self._released.get(role, ()))
        if not any(floor <= item <= round_index for item in released):
            return None
        per_role = self._population.get(pattern_key, {})
        count = sum(
            max(0, value)
            for role in roles
            for item, value in per_role.get(role, {}).items()
            if floor <= item <= round_index
        )
        return 1.0 - min(1.0, count / RARITY_SCALE)

    def rarity_of(self, pattern_key: str, *, round_index: int) -> float:
        """Population rarity for a fragment (D7.13): ``0.0`` when unknown, by the spec's rule."""
        rarity = self._rarity(pattern_key, round_index)
        return 0.0 if rarity is None else rarity

    def _fresh(self, software_epoch: str, floor: int) -> bool:
        first = self._epochs.get(software_epoch)
        return first is None or first >= floor

    def _assess(
        self, pattern_key: str, state: _Pattern, round_index: int
    ) -> CollectiveNovelty | None:
        floor = round_index - self._window + 1
        reports = [item for item in state.reports if floor <= item[0] <= round_index]
        if not reports:
            return None
        support = len({cluster for _, cluster, _ in reports})
        coherence = min(1.0, support / 2)
        surprise = min(1.0, len(set(state.stages) & ESCALATING_STAGES) / 3)
        persistence = min(1.0, len({item[0] for item in reports}) / self._window)
        explanation = sum(1 for _, _, epoch in reports if self._fresh(epoch, floor)) / len(reports)
        rarity = self._rarity(pattern_key, round_index)
        known = 0.0 if rarity is None else rarity
        raw = known * coherence * surprise * persistence
        score = raw / (1.0 + EPOCH_EXPLANATION_K * explanation)
        if not self._enabled:
            new = state.first_local_round >= floor
            score = 1.0 if new else 0.0
            status = NoveltyStatus.COLLECTIVELY_NOVEL if new else NoveltyStatus.INSUFFICIENT
        elif support < MIN_INDEPENDENT_SUPPORT:
            status = NoveltyStatus.LOCAL_ONLY
        elif rarity is None:
            status = NoveltyStatus.INSUFFICIENT
        elif score >= NOVELTY_FLOOR:
            status = NoveltyStatus.COLLECTIVELY_NOVEL
        elif raw >= NOVELTY_FLOOR and explanation > 0.0:
            status = NoveltyStatus.EXPLAINED_BY_EPOCH
        else:
            status = NoveltyStatus.INSUFFICIENT
        return CollectiveNovelty(
            pattern_key=pattern_key, rarity=known, coherence=coherence, causal_surprise=surprise,
            persistence=persistence, independent_support=support,
            benign_epoch_explanation=explanation, score=score, status=status,
        )

    def evaluate(self, *, round_index: int) -> tuple[CollectiveNovelty, ...]:
        """One assessment per pattern reported inside the window, sorted by pattern key."""
        require_non_negative_int(round_index, "round_index")
        results: list[CollectiveNovelty] = []
        for pattern_key in sorted(self._patterns):
            if self._meter is not None:
                self._meter.charge(1)
            assessed = self._assess(pattern_key, self._patterns[pattern_key], round_index)
            if assessed is not None:
                results.append(assessed)
        return tuple(results)

    # --- accounting ----------------------------------------------------------------

    def patterns(self) -> int:
        return len(self._patterns)

    def evictions(self) -> int:
        counts = self._counts
        return (counts["pattern_evictions"] + counts["report_drops"]
                + counts["population_evictions"] + counts["epoch_evictions"])

    def stats(self) -> Mapping[str, int]:
        return {**self._counts, "patterns": len(self._patterns),
                "population_patterns": len(self._population), "epochs": len(self._epochs)}

    def memory_bytes(self) -> int:
        """An upper-bound estimate of what the engine holds, in bytes."""
        patterns = sum(
            sys.getsizeof(key) + sys.getsizeof(state.reports) + _ENTRY_OVERHEAD_BYTES
            + len(state.reports) * (sys.getsizeof((0, "", "")) + 96)
            for key, state in self._patterns.items()
        )
        population = sum(
            sys.getsizeof(key) + sys.getsizeof(per_role)
            + sum(sys.getsizeof(rounds) + 64 * len(rounds) for rounds in per_role.values())
            for key, per_role in self._population.items()
        )
        epochs = sum(sys.getsizeof(key) + 32 for key in self._epochs)
        released = sum(sys.getsizeof(items) + 32 * len(items) for items in self._released.values())
        tables = (self._patterns, self._population, self._epochs)
        containers = sum(sys.getsizeof(item) for item in tables)
        return patterns + population + epochs + released + containers
