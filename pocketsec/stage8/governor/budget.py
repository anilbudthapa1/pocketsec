"""Layer 8.21 / D8.18 / PROM-F22 — the research budget and the one meter that enforces it.

Stage 8's search may be far heavier than anything the 2 GB endpoint runs, but it must never
be *unbounded*: a runaway generator, a flood of external proposals or a mutation loop has to
hit a number, not the host. This module holds that number. :class:`ResearchBudget` names the
run's work-unit budget and every structural cap the other packages consult;
:class:`ResearchGovernor` wraps **one** bounded Stage 6 :class:`WorkMeter` per run, so
there is a single kill switch rather than one meter per component that could each be
generous on its own.

**The kill switch is the budget.** :meth:`ResearchGovernor.charge` delegates to
``WorkMeter.charge``, which raises :class:`WorkBudgetExceeded` *before* admitting the charge
that crosses the budget and pays nothing for it. The exception propagates; the run ends with
everything recorded so far. Nothing here catches it for the caller.

**Cost is work units, never wall time** (ADR-0033 precedent: a Stage 2 gate measured the same
paths 7x slower at load 23-67 than at load 8-12). One unit is one predicate test of one step,
one state update or one feature read. Code that hands :attr:`ResearchGovernor.meter` straight
to a foundation function (``genome.decides(episode, meter=...)``) pays the meter without
naming a component; :meth:`ResearchGovernor.report` shows those units as ``unattributed``
rather than hiding them, and :meth:`ResearchGovernor.account` lets the caller name them
afterwards. Attribution never exceeds what the meter was actually paid.

**Structural caps are counted, not silent.** :meth:`ResearchGovernor.admit` answers whether a
store at size ``current`` may grow under the cap named by a :class:`ResearchBudget` field, and
counts every refusal by that name, so a report can show *which* bound a flood reached.

What it refuses to do: it holds no research state, reads no episode, grants nothing and never
raises a budget. Every constant is a chosen parameter, not a measurement (spec §4.21).
"""

from __future__ import annotations

import sys
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, fields
from types import MappingProxyType

from pocketsec.stage0.contracts.common import ContractError, require_identifier
from pocketsec.stage6.resources import WorkBudgetExceeded, WorkMeter

__all__ = [
    "DEFAULT_RESEARCH_WORK_UNITS",
    "MAX_GOVERNOR_COMPONENTS",
    "OVERFLOW_COMPONENT",
    "UNATTRIBUTED_COMPONENT",
    "WORK_UNITS_BOUND",
    "GovernorReport",
    "ResearchBudget",
    "ResearchGovernor",
    "WorkBudgetExceeded",
]

#: Spec §4.21. Chosen, not measured.
DEFAULT_RESEARCH_WORK_UNITS: int = 50_000_000
#: Component names are caller-chosen strings; past this many the ledger of names would itself
#: grow without bound, so further names are pooled under :data:`OVERFLOW_COMPONENT` (counted).
MAX_GOVERNOR_COMPONENTS: int = 64
OVERFLOW_COMPONENT: str = "other"
#: Units paid through :attr:`ResearchGovernor.meter` directly and never named by a component.
UNATTRIBUTED_COMPONENT: str = "unattributed"
#: The refusal-counter name used when the work-unit budget itself refuses a charge.
WORK_UNITS_BOUND: str = "work_units"


@dataclass(frozen=True, slots=True)
class ResearchBudget:
    """The run's work-unit budget and the structural caps every Stage 8 store consults.

    Field names are the bound names :meth:`ResearchGovernor.admit` accepts. All values are
    chosen parameters (spec §4.21), not calibrated ones.
    """

    work_units: int = DEFAULT_RESEARCH_WORK_UNITS
    max_active_residual_clusters: int = 16
    max_hypotheses_per_residual: int = 32
    max_population: int = 256
    max_branch_depth: int = 4
    max_experiments_per_hypothesis: int = 8
    max_experiment_queue: int = 128
    max_counterfactual_worlds: int = 64
    max_external_proposals: int = 256
    max_registrations_per_batch: int = 64

    def __post_init__(self) -> None:
        for spec in fields(self):
            value = getattr(self, spec.name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise ContractError(f"ResearchBudget.{spec.name} must be an int, got {value!r}")
            # Zero work units is a legal "do nothing" budget; a zero structural cap would
            # make every store refuse its first item, which no caller means.
            floor = 0 if spec.name == "work_units" else 1
            if value < floor:
                raise ContractError(f"ResearchBudget.{spec.name} must be >= {floor}, got {value}")

    @classmethod
    def bound_names(cls) -> tuple[str, ...]:
        """Every structural cap :meth:`ResearchGovernor.admit` accepts, in field order."""
        return tuple(spec.name for spec in fields(cls) if spec.name != "work_units")


@dataclass(frozen=True, slots=True)
class GovernorReport:
    """What one run spent and which bounds refused it. Plain data; decides nothing."""

    budget: ResearchBudget
    spent: int
    exhausted: bool
    spent_by_component: tuple[tuple[str, int], ...]
    refusals_by_bound: tuple[tuple[str, int], ...]

    def __post_init__(self) -> None:
        if isinstance(self.spent, bool) or not isinstance(self.spent, int) or self.spent < 0:
            raise ContractError(f"GovernorReport.spent must be an int >= 0, got {self.spent!r}")
        if self.spent > self.budget.work_units:
            raise ContractError("GovernorReport.spent cannot exceed the budget it was paid under")
        if sum(units for _, units in self.spent_by_component) != self.spent:
            raise ContractError("GovernorReport.spent_by_component must sum to spent")


class ResearchGovernor:
    """One bounded :class:`WorkMeter` per run, with per-component and per-bound accounting.

    The governor is the only object in Stage 8 that owns the run's budget. Components either
    call :meth:`charge` with their name, or pass :attr:`meter` to a foundation function and
    later :meth:`account` for what it cost. Either way the meter is the one that refuses.
    """

    __slots__ = ("_attributed", "_budget", "_by_component", "_meter", "_n", "_refusals")

    def __init__(self, budget: ResearchBudget) -> None:
        if not isinstance(budget, ResearchBudget):
            raise ContractError(f"ResearchGovernor needs a ResearchBudget, got {budget!r}")
        self._budget = budget
        self._meter = WorkMeter(budget=budget.work_units)
        self._by_component: Counter[str] = Counter()
        self._refusals: Counter[str] = Counter()
        self._attributed = 0
        self._n: Counter[str] = Counter()

    @property
    def budget(self) -> ResearchBudget:
        return self._budget

    @property
    def meter(self) -> WorkMeter:
        """The run's single bounded meter. Every Stage 8 cost path pays this one."""
        return self._meter

    def charge(self, component: str, units: int) -> None:
        """Pay ``units`` for ``component``, or raise :class:`WorkBudgetExceeded` and pay nothing."""
        name = self._component_name(component)
        try:
            self._meter.charge(units)
        except WorkBudgetExceeded:
            self._refusals[WORK_UNITS_BOUND] += 1
            self._n["charges_refused"] += 1
            raise
        self._by_component[name] += units
        self._attributed += units
        self._n["charges"] += 1

    def account(self, component: str, units: int) -> None:
        """Name ``units`` already paid through :attr:`meter` directly as ``component``'s.

        Refused when it would attribute more than the meter was actually paid: accounting
        moves cost between names, it never invents or erases any.
        """
        name = self._component_name(component)
        if isinstance(units, bool) or not isinstance(units, int) or units < 0:
            raise ContractError(f"account takes a non-negative int, got {units!r}")
        if self._attributed + units > self._meter.spent:
            raise ContractError(
                f"cannot attribute {units} units to {name!r}: only "
                f"{self._meter.spent - self._attributed} unattributed units were paid"
            )
        self._by_component[name] += units
        self._attributed += units

    def admit(self, bound: str, current: int) -> bool:
        """Whether a store holding ``current`` items may add one under cap ``bound``.

        A refusal is counted under ``bound``. An unknown bound name is a programming error,
        not a refusal, and raises: a typo must not read as "always admitted".
        """
        if bound not in ResearchBudget.bound_names():
            raise ContractError(f"unknown research bound {bound!r}")
        if isinstance(current, bool) or not isinstance(current, int) or current < 0:
            raise ContractError(f"admit takes current as an int >= 0, got {current!r}")
        if current < getattr(self._budget, bound):
            self._n["admitted"] += 1
            return True
        self._refusals[bound] += 1
        return False

    def exhausted(self) -> bool:
        """True once a charge was refused or the budget is spent to the last unit."""
        return self._refusals[WORK_UNITS_BOUND] > 0 or self._meter.remaining == 0

    def report(self) -> GovernorReport:
        by_component = dict(self._by_component)
        unattributed = self._meter.spent - self._attributed
        if unattributed:
            by_component[UNATTRIBUTED_COMPONENT] = unattributed
        return GovernorReport(
            budget=self._budget,
            spent=self._meter.spent,
            exhausted=self.exhausted(),
            spent_by_component=tuple(sorted(by_component.items())),
            refusals_by_bound=tuple(sorted(self._refusals.items())),
        )

    def stats(self) -> Mapping[str, int]:
        counters = dict(self._n)
        counters["spent"] = self._meter.spent
        counters["components"] = len(self._by_component)
        counters["refusals"] = sum(self._refusals.values())
        return MappingProxyType(counters)

    def memory_bytes(self) -> int:
        names = sum(sys.getsizeof(name) + 8 for name in (*self._by_component, *self._refusals))
        return (
            sys.getsizeof(self._by_component) + sys.getsizeof(self._refusals)
            + sys.getsizeof(self._n) + names
        )

    def _component_name(self, component: str) -> str:
        require_identifier(component, "component")
        if component in (UNATTRIBUTED_COMPONENT,):
            raise ContractError(f"{component!r} is reserved for units no component named")
        if component in self._by_component or len(self._by_component) < MAX_GOVERNOR_COMPONENTS:
            return component
        self._n["components_pooled"] += 1
        return OVERFLOW_COMPONENT
