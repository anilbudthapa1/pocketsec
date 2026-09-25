"""D4.12b — the incident entropy budget, and safe pruning when it runs out.

§29 gives every incident a bounded reasoning budget. This module makes that bound
**deterministic**, which is the one design decision here worth arguing about.

The architecture's ``Budget_I`` lists ``max_reasoning_ms``. On this host a
millisecond bound would be a coin flip: ``/proc/loadavg`` swung 1.88 -> 3.04 in
twenty idle minutes, and a Stage 2 gate run at load 23-67 measured 855.31/3040.63
µs per event for the same two passes that read 122.48/647.23 at load 8-12 — a 7x
inflation from contention alone (cited from ``planning/PROGRESS.md``, not measured
here). A gate criterion that flips with the neighbours' test run is not a
criterion. So:

*   ``max_reasoning_units`` is **the contract**. It counts deterministic work
    units, so the same incident charges the same total on an idle host and a
    loaded one, and G4.9 either holds or does not.
*   ``max_reasoning_ms`` is **advisory and observed-only**. It is recorded beside
    the load average and never decides anything. ``exhausted()`` does not read it.

What ``safe_prune`` refuses to do is §45's first rule, and it is the reason this
module exists rather than a bare counter:

*   it prunes **low-consequence dominated** worlds first, never merely cheap ones;
*   it never removes the last non-benign world;
*   it never converts an unresolved field into a benign resolution.

When safe pruning cannot reach the bound, the field stays over budget and the
caller must abstain or escalate. "It cannot silently simplify into benign" is the
architecture's own wording, and a controller that quietly deleted the last
worrying world to fit a byte target would be the most dangerous line of code in
Stage 4.
"""

from __future__ import annotations

import dataclasses
import math
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field as dataclass_field
from typing import Any

from pocketsec.stage0.contracts.common import ContractError, require_non_negative_int
from pocketsec.stage4.graph.sparse_world_graph import (
    MAX_GRAPH_EDGES,
    Truncation,
    append_truncations,
)
from pocketsec.stage4.worlds.lifecycle import dominance_test

__all__ = [
    "BUDGET_KINDS",
    "COUNTERFACTUAL_KIND",
    "DEFAULT_MAX_COUNTERFACTUALS",
    "DEFAULT_MAX_REASONING_UNITS",
    "DEFAULT_MAX_SENSOR_ESCALATIONS",
    "DEFAULT_MAX_WORLDS",
    "MAX_INCIDENT_BYTES",
    "SENSOR_ESCALATION_KIND",
    "BudgetController",
    "EntropyBudget",
]

#: Mirrors of constants owned by other modules. They are re-declared instead of
#: imported because ``worlds/field.py`` holds an ``EntropyBudget`` field, so
#: importing ``MAX_WORLDS`` from there would close an import cycle. The mirror is
#: not left to trust: ``tests/test_stage4_lifecycle.py`` asserts each value equals
#: the owning module's once that module exists.
DEFAULT_MAX_WORLDS: int = 8  # worlds/field.MAX_WORLDS
DEFAULT_MAX_COUNTERFACTUALS: int = 32  # counterfactual/intervention
DEFAULT_MAX_SENSOR_ESCALATIONS: int = 4  # identifiability/horizon
DEFAULT_MAX_REASONING_UNITS: int = 4096  # identifiability/horizon

#: §29 ``max_memory_bytes``. The 2 GB host target is a hard constraint and Stages
#: 1-3 must stay comfortable on the same machine (§44).
MAX_INCIDENT_BYTES: int = 8 * 1024 * 1024

#: Charge kinds that count against a dedicated bound as well as the work total.
COUNTERFACTUAL_KIND = "counterfactual"
SENSOR_ESCALATION_KIND = "sensor_escalation"

#: Closed vocabulary of chargeable work. Closed for the same reason
#: ``TRUNCATION_KINDS`` is: a typo that invents a kind makes a spend report
#: unreadable and the bound unauditable. A package that charges for something new
#: adds it here.
BUDGET_KINDS = frozenset(
    {
        "claim_compile",
        "dominance_pruning",
        "evidence_integration",
        "fission",
        "fusion",
        "graph_update",
        "identifiability",
        "sequential_evidence",
        "sensor_plan",
        "tension",
        "verbalizer",
        "visibility_update",
        "world_birth",
        "world_death",
        COUNTERFACTUAL_KIND,
        SENSOR_ESCALATION_KIND,
    }
)

#: A world is treated as benign when it asserts no security dimension and carries
#: no consequence. Deliberately strict: anything that moved the security lattice
#: at all counts as non-benign, so the "never remove the last non-benign world"
#: rule errs towards keeping worlds.
_BENIGN_CONSEQUENCE_EPSILON: float = 1e-9


@dataclass(frozen=True, slots=True)
class EntropyBudget:
    """``Budget_I`` (§29).

    ``max_reasoning_units`` is the contract; ``max_reasoning_ms`` is observed-only
    and defaults to ``None``, which means "not observed" rather than "unlimited".
    """

    max_worlds: int = DEFAULT_MAX_WORLDS
    max_edges: int = MAX_GRAPH_EDGES
    max_counterfactuals: int = DEFAULT_MAX_COUNTERFACTUALS
    max_sensor_escalations: int = DEFAULT_MAX_SENSOR_ESCALATIONS
    max_reasoning_units: int = DEFAULT_MAX_REASONING_UNITS
    max_memory_bytes: int = MAX_INCIDENT_BYTES
    max_reasoning_ms: float | None = None

    def __post_init__(self) -> None:
        for name in (
            "max_worlds",
            "max_edges",
            "max_counterfactuals",
            "max_sensor_escalations",
            "max_reasoning_units",
            "max_memory_bytes",
        ):
            value = require_non_negative_int(getattr(self, name), f"EntropyBudget.{name}")
            if value < 1:
                raise ContractError(f"EntropyBudget.{name} must be >= 1, got {value}")
        if self.max_edges > MAX_GRAPH_EDGES:
            raise ContractError(f"max_edges may not exceed MAX_GRAPH_EDGES={MAX_GRAPH_EDGES}")
        if self.max_memory_bytes > MAX_INCIDENT_BYTES:
            raise ContractError(
                f"max_memory_bytes may not exceed MAX_INCIDENT_BYTES={MAX_INCIDENT_BYTES}"
            )
        if self.max_reasoning_ms is not None:
            ms = self.max_reasoning_ms
            if isinstance(ms, bool) or not isinstance(ms, (int, float)):
                raise ContractError("EntropyBudget.max_reasoning_ms must be a number or None")
            if not math.isfinite(float(ms)) or float(ms) <= 0.0:
                raise ContractError(f"max_reasoning_ms must be finite and > 0, got {ms!r}")
            object.__setattr__(self, "max_reasoning_ms", float(ms))

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_worlds": self.max_worlds,
            "max_edges": self.max_edges,
            "max_counterfactuals": self.max_counterfactuals,
            "max_sensor_escalations": self.max_sensor_escalations,
            "max_reasoning_units": self.max_reasoning_units,
            "max_memory_bytes": self.max_memory_bytes,
            "max_reasoning_ms": self.max_reasoning_ms,
        }


@dataclass(slots=True)
class _Spend:
    """Mutable spend accounting. Separated from the frozen budget so a budget is
    never mistaken for a running total."""

    units: int = 0
    refused_units: int = 0
    counterfactuals: int = 0
    sensor_escalations: int = 0
    per_kind: dict[str, int] = dataclass_field(default_factory=dict)
    observed_ns: int = 0


class BudgetController:
    """Charges deterministic work against an ``EntropyBudget`` and prunes safely.

    ``charge`` **saturates** at the cap rather than raising: the counter can never
    exceed ``max_reasoning_units``, and the part that did not fit is recorded as
    ``refused_units`` instead of being forgotten. Raising mid-incident would push a
    bound violation into the degradation path, where it would look like a crash
    rather than a budget.

    **A saturating counter is accounting, not enforcement.** ``charge`` runs after
    the work it books, so on its own it bounds nothing: the review of this wave
    drove one incident for 1000 updates and every step kept running while the
    counter read 4096/4096 (S4-REV-01 / S4-FC-04). The work bound is the engine's
    job — ``LucidEngine.update`` consults :meth:`units_exhausted` *before* the
    optional and O(K^2) passes and refuses them with a recorded ``Truncation``,
    and the §20 horizon stops reasoning on the incident altogether.
    """

    def __init__(
        self,
        budget: EntropyBudget | None = None,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self.budget = budget if budget is not None else EntropyBudget()
        self._clock = clock if clock is not None else time.perf_counter_ns
        self._spend = _Spend()

    # --- charging --------------------------------------------------------

    def charge(self, kind: str, units: int) -> None:
        """Charge ``units`` of work of ``kind``. Never raises on exhaustion."""
        if kind not in BUDGET_KINDS:
            raise ContractError(f"unknown budget kind {kind!r}; add it to BUDGET_KINDS")
        require_non_negative_int(units, "charge(units)")
        headroom = max(0, self.budget.max_reasoning_units - self._spend.units)
        granted = min(units, headroom)
        self._spend.units += granted
        self._spend.refused_units += units - granted
        self._spend.per_kind[kind] = self._spend.per_kind.get(kind, 0) + granted
        if kind == COUNTERFACTUAL_KIND:
            self._spend.counterfactuals += 1
        elif kind == SENSOR_ESCALATION_KIND:
            self._spend.sensor_escalations += 1

    def observe(self, elapsed_ns: int) -> None:
        """Record wall-clock time. Observed only — nothing reads it to decide."""
        require_non_negative_int(elapsed_ns, "observe(elapsed_ns)")
        self._spend.observed_ns += elapsed_ns

    def timed(self, kind: str, units: int) -> _ChargeScope:
        """Context manager charging ``units`` and observing the elapsed time."""
        return _ChargeScope(self, kind, units)

    def exhausted(self) -> bool:
        """True when a deterministic bound is spent. Wall clock is not consulted."""
        return (
            self._spend.units >= self.budget.max_reasoning_units
            or self._spend.counterfactuals >= self.budget.max_counterfactuals
            or self._spend.sensor_escalations >= self.budget.max_sensor_escalations
        )

    def units_exhausted(self) -> bool:
        """True once the deterministic reasoning-unit cap is spent.

        Narrower than :meth:`exhausted`, which also trips on the counterfactual and
        escalation counts. The engine refuses optional work on *this* signal: the
        counterfactual cap already refuses its own family, and conflating the two
        switched fission off after eleven transitions for a reason unrelated to
        reasoning cost.
        """
        return self._spend.units >= self.budget.max_reasoning_units

    def advisory_ms_exceeded(self) -> bool | None:
        """``None`` when no advisory bound was set — never ``False``.

        "Unmeasured is not measured": a wall-clock target that was not configured
        is not a target that was met.
        """
        if self.budget.max_reasoning_ms is None:
            return None
        return (self._spend.observed_ns / 1_000_000.0) > self.budget.max_reasoning_ms

    def spend_report(self) -> Mapping[str, int]:
        report: dict[str, int] = {
            "reasoning_units": self._spend.units,
            "refused_units": self._spend.refused_units,
            "counterfactuals": self._spend.counterfactuals,
            "sensor_escalations": self._spend.sensor_escalations,
            "observed_ms": int(self._spend.observed_ns // 1_000_000),
        }
        for kind in sorted(self._spend.per_kind):
            report[f"kind.{kind}"] = self._spend.per_kind[kind]
        return report

    # --- safe pruning ----------------------------------------------------

    def safe_prune(self, field: Any) -> tuple[Any, tuple[Truncation, ...]]:
        """§45's first rule. Returns the pruned field and every loss it cost.

        Candidates must be **dominated** (all five §30 clauses, veto included) and
        low-consequence, and they are removed in ascending consequence order. The
        two absolute refusals are checked on every step, not once at the end: the
        last non-benign world is never removed, and a field that held a non-benign
        world never comes back holding only benign ones.
        """
        worlds = list(field.worlds)
        if len(worlds) <= 1 or not self._over_budget(field, len(worlds)):
            return field, ()
        had_non_benign = any(_is_non_benign(w) for w in worlds)
        losses: list[Truncation] = []
        for loser in sorted(worlds, key=lambda w: float(w.latent_state.consequence)):
            if len(worlds) <= 1:
                break
            remaining = [w for w in worlds if w.world_id != loser.world_id]
            if not self._may_remove(loser, remaining, had_non_benign=had_non_benign):
                continue
            worlds = remaining
            losses.append(
                Truncation(
                    what="world",
                    identifier=loser.world_id,
                    reason="budget_truncation_low_consequence_dominated",
                    consequence_lost=float(loser.latent_state.consequence),
                )
            )
            if not self._over_budget(field, len(worlds)):
                break
        if not losses:
            return field, ()
        return _append_truncations(field.with_worlds(tuple(worlds)), tuple(losses)), tuple(losses)

    def _over_budget(self, field: Any, world_count: int) -> bool:
        return (
            world_count > self.budget.max_worlds
            or field.state_bytes() > self.budget.max_memory_bytes
            or self.exhausted()
        )

    def _may_remove(self, loser: Any, remaining: Sequence[Any], *, had_non_benign: bool) -> bool:
        """Every refusal §45 imposes, in one place so none can be skipped."""
        if not remaining:
            return False
        if _is_non_benign(loser) and not any(_is_non_benign(w) for w in remaining):
            return False  # the last non-benign world is never pruned
        if had_non_benign and not any(_is_non_benign(w) for w in remaining):
            return False  # an unresolved field never resolves benign by pruning
        winner = None
        for candidate in remaining:
            if dominance_test(candidate, loser).dominates():
                winner = candidate
                break
        return winner is not None


class _ChargeScope:
    """Charges on enter, observes elapsed time on exit — including on the way out
    of an exception, so a failed pass still shows the work it consumed."""

    __slots__ = ("_controller", "_kind", "_units", "_started")

    def __init__(self, controller: BudgetController, kind: str, units: int) -> None:
        self._controller = controller
        self._kind = kind
        self._units = units
        self._started = 0

    def __enter__(self) -> BudgetController:
        self._started = self._controller._clock()
        self._controller.charge(self._kind, self._units)
        return self._controller

    def __exit__(self, *exc: object) -> None:
        self._controller.observe(max(0, self._controller._clock() - self._started))


def _is_non_benign(world: Any) -> bool:
    return bool(world.latent_state.asserted_dimensions) or (
        float(world.latent_state.consequence) > _BENIGN_CONSEQUENCE_EPSILON
    )


def _append_truncations(field: Any, extra: tuple[Truncation, ...]) -> Any:
    if not dataclasses.is_dataclass(field):
        raise ContractError("a causal belief field must be a frozen dataclass")
    return dataclasses.replace(
        field, truncations=append_truncations(field.truncations, extra)
    )
