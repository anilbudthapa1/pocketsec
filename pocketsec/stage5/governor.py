"""D5.23 — the Resource Governor: hard caps on planning, and a safe way to hit them.

Architecture §34 gives Stage 5 a list of hard caps and one rule about what happens
when one is reached: *"On budget exhaustion, Stage 5 prunes planning or escalates;
it does not relax safety constraints."* This module is that rule in code. Nothing
here widens a cap, and there is no constructor argument, flag or environment
variable that does either.

**Work units, never milliseconds.** §34's own list says "simulation
milliseconds", and this module deliberately does not implement that. A Stage 2
gate measured the same two code paths at 122/647 µs per event at load average
8–12 and at 855/3041 µs at load 23–67 — a 7× inflation from nothing but host
contention (``planning/MEMORY.md``). A millisecond budget on this host is a random
number generator; a work-unit budget is reproducible, and reproducibility is what
a bound is for.

**Pruning is safety-monotone.** :meth:`ResourceGovernor.prune` drops the most
irreversible, highest-shadow candidates first, never drops the observe-only
candidate, and never drops a protected no-action option. Dropping the *safest*
option under pressure is how a resource bound turns into an attack: an adversary
that can make planning expensive should not thereby be able to make it decisive.
Every drop emits a :class:`PruneRecord`, because truncation must be explicit.

The candidate type is read through a :class:`Protocol`. ``safe/action_field.py``
imports this module, so importing ``CandidateAction`` back would be a cycle; and a
governor that could only be tested once the action field existed would be tested
late.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from dataclasses import fields as dataclass_fields
from enum import StrEnum
from types import MappingProxyType
from typing import Protocol

from pocketsec.stage0.contracts.common import ContractError, require_non_negative_int
from pocketsec.stage5.constitution.invariants import (
    AuthorityClass,
    authority_rank,
    reversibility_rank,
)

__all__ = [
    "KIND_CAPS",
    "OBSERVE_ONLY_AUTHORITY",
    "PROTECTED_CANDIDATE_IDS",
    "STAGE5_BUDGET",
    "BudgetExhausted",
    "CandidateView",
    "PruneRecord",
    "ResourceBudget",
    "ResourceGovernor",
    "WorkKind",
]


class WorkKind(StrEnum):
    """What a unit of Stage 5 planning work was spent on.

    Recorded per kind so that an exhausted budget can say *where* it went. A
    single total would make "the cone ate the budget" and "the twin ate the
    budget" the same report, and those need different answers.
    """

    CANDIDATE_GENERATION = "CANDIDATE_GENERATION"
    WORLD_EVALUATION = "WORLD_EVALUATION"
    TWIN_STEP = "TWIN_STEP"
    CONE_NODE = "CONE_NODE"
    DEPENDENCY_WALK = "DEPENDENCY_WALK"
    SENTINEL_CHECK = "SENTINEL_CHECK"
    HOST_CALL = "HOST_CALL"


@dataclass(frozen=True, slots=True)
class ResourceBudget:
    """§34's hard caps, as integers.

    Every field is a **chosen parameter**, not a measured one. None of these
    numbers is evidence about anything; they are the ceilings this wave decided
    planning must fit inside on a 2 GB host, and the findings document lists them
    under PARAMETERS for exactly that reason.
    """

    max_candidate_actions: int = 16
    max_worlds_per_action: int = 8
    max_cone_depth: int = 3
    max_cone_branches_per_node: int = 4
    max_dependency_nodes: int = 64
    max_twin_nodes: int = 64
    max_work_units: int = 4096
    max_concurrent_leases: int = 4
    max_rollback_journal_bytes: int = 262144
    max_autonomous_actions_per_window: int = 8
    window_seconds: int = 3600

    def __post_init__(self) -> None:
        for field in dataclass_fields(self):
            value = getattr(self, field.name)
            require_non_negative_int(value, f"ResourceBudget.{field.name}")
            if value == 0:
                raise ContractError(f"ResourceBudget.{field.name} of 0 disables planning entirely")


#: The one budget. A subsystem takes this instance; the type exists to be
#: serialised and to be *narrowed* in an ablation, never widened at runtime.
STAGE5_BUDGET: ResourceBudget = ResourceBudget()

#: The work kinds whose *cumulative* count a §34 cap bounds directly. The other
#: four kinds are bounded by ``max_work_units`` alone, and saying so here is
#: better than inventing a derived cap and presenting it as an architecture bound:
#: ``max_worlds_per_action`` is per action, not cumulative, so a cumulative cap of
#: 8 world evaluations would silently truncate a 16-candidate field.
KIND_CAPS: Mapping[WorkKind, str] = MappingProxyType(
    {
        WorkKind.CANDIDATE_GENERATION: "max_candidate_actions",
        WorkKind.TWIN_STEP: "max_twin_nodes",
        WorkKind.DEPENDENCY_WALK: "max_dependency_nodes",
    }
)

#: The authority class of an observe-only candidate. Pruning never drops one:
#: §2's eighth law says NO ACTION must always be available, and the observe-only
#: candidate is what "no action" looks like in an action field.
OBSERVE_ONLY_AUTHORITY: AuthorityClass = AuthorityClass.A0

#: Candidate ids that are structurally protected from pruning whatever they score.
PROTECTED_CANDIDATE_IDS: frozenset[str] = frozenset({"NO_ACTION"})


class BudgetExhausted(ContractError):
    """Raised on overspend. Callers prune or escalate; nothing relaxes a constraint."""


@dataclass(frozen=True, slots=True)
class PruneRecord:
    """One dropped thing, named. An implicit truncation is a silent lie about scope."""

    what: str
    identifier: str
    reason: str

    def to_dict(self) -> dict[str, str]:
        return {"what": self.what, "identifier": self.identifier, "reason": self.reason}


class ShadowView(Protocol):
    """The one member pruning needs from an ``ActionShadow``: its normalised score."""

    @property
    def score(self) -> float: ...


class CandidateView(Protocol):
    """The slice of ``safe.action_field.CandidateAction`` pruning reads.

    Four read-only members, none of which can change the host. ``reversibility``
    is ranked through ``constitution.invariants.reversibility_rank``, which ranks
    an unrecognised value as IRREVERSIBLE — so a candidate the governor cannot
    understand is dropped first rather than kept first.
    """

    @property
    def candidate_id(self) -> str: ...

    @property
    def authority(self) -> AuthorityClass: ...

    @property
    def reversibility(self) -> str: ...

    @property
    def shadow(self) -> ShadowView: ...


class ResourceGovernor:
    """Tracks spend against one budget and prunes deterministically when it must."""

    def __init__(self, budget: ResourceBudget = STAGE5_BUDGET) -> None:
        self._budget = budget
        self._spent: dict[WorkKind, int] = {kind: 0 for kind in WorkKind}
        self._escalation: str | None = None

    @property
    def budget(self) -> ResourceBudget:
        return self._budget

    def spend(self, kind: WorkKind, units: int = 1) -> None:
        """Charge work to the budget, raising :class:`BudgetExhausted` past a cap.

        The spend is **not** recorded when it would exceed a cap: a governor whose
        counters ran past their own ceiling would report a spend that never
        happened, and the escalation record would be unreadable.
        """
        require_non_negative_int(units, "units")
        if units == 0:
            return
        if not isinstance(kind, WorkKind):
            raise ContractError(f"unknown work kind {kind!r}")
        reason = self._exceeds(kind, units)
        if reason is not None:
            self._escalation = reason
            raise BudgetExhausted(reason)
        self._spent[kind] += units

    def _exceeds(self, kind: WorkKind, units: int) -> str | None:
        total = sum(self._spent.values()) + units
        if total > self._budget.max_work_units:
            return (
                f"{total} work units exceeds the {self._budget.max_work_units} unit budget "
                f"(spending {units} on {kind.value})"
            )
        cap_field = KIND_CAPS.get(kind)
        if cap_field is None:
            return None
        cap = int(getattr(self._budget, cap_field))
        if self._spent[kind] + units > cap:
            return f"{kind.value} would exceed its {cap_field} cap of {cap}"
        return None

    def would_exceed(self, kind: WorkKind, units: int) -> bool:
        """Ask before spending. Asking never records anything."""
        return self._exceeds(kind, units) is not None

    def remaining(self) -> int:
        """Work units left in the total budget."""
        return self._budget.max_work_units - sum(self._spent.values())

    def prune(
        self, candidates: Sequence[CandidateView]
    ) -> tuple[tuple[CandidateView, ...], tuple[PruneRecord, ...]]:
        """Cut a candidate list to the budget, deterministically and safely.

        Ordering is total — (irreversibility, shadow, authority, candidate_id) —
        so the same input always yields the same output regardless of the order it
        arrived in. Protected candidates are kept first and are never counted
        against the safety ordering; if the protected set alone exceeds the cap,
        every protected candidate is still kept and an escalation is recorded,
        because the alternative is dropping the only safe option to satisfy a
        number.
        """
        self._refuse_duplicate_ids(candidates)
        cap = self._budget.max_candidate_actions
        protected = [c for c in candidates if self._is_protected(c)]
        optional = sorted((c for c in candidates if not self._is_protected(c)), key=self._risk_key)
        if len(protected) > cap:
            self._escalation = (
                f"{len(protected)} protected candidates exceed the {cap} candidate cap; "
                "none was dropped"
            )
            return tuple(protected), ()
        keep = protected + optional[: cap - len(protected)]
        dropped = optional[cap - len(protected) :]
        records = tuple(
            PruneRecord(
                what="candidate",
                identifier=candidate.candidate_id,
                reason=(
                    f"over the {cap} candidate cap; dropped by "
                    f"(irreversibility={reversibility_rank(candidate.reversibility)}, "
                    f"shadow={candidate.shadow.score:.4f})"
                ),
            )
            for candidate in dropped
        )
        if records:
            self._escalation = f"pruned {len(records)} candidates to the {cap} candidate cap"
        return tuple(keep), records

    def _refuse_duplicate_ids(self, candidates: Sequence[CandidateView]) -> None:
        ids = [candidate.candidate_id for candidate in candidates]
        if len(set(ids)) != len(ids):
            raise ContractError("candidate ids must be unique for pruning to be deterministic")

    def _is_protected(self, candidate: CandidateView) -> bool:
        """Observe-only and no-action candidates are never dropped."""
        return (
            candidate.candidate_id in PROTECTED_CANDIDATE_IDS
            or candidate.authority is OBSERVE_ONLY_AUTHORITY
        )

    def _risk_key(self, candidate: CandidateView) -> tuple[int, float, int, str]:
        """Keep-first ordering: safest first, so the tail of the sort is what is dropped.

        Ascending in (irreversibility, shadow, authority), then by id so the order
        is total and the same field always prunes the same way.
        """
        return (
            reversibility_rank(candidate.reversibility),
            float(candidate.shadow.score),
            authority_rank(candidate.authority),
            candidate.candidate_id,
        )

    def rate_limited(self, *, recent_action_times: Sequence[int], now: int) -> bool:
        """Whether the autonomous action rate for the trailing window is used up.

        Counts only actions inside the window and refuses a time from the future:
        a clock that runs backwards must not be able to clear the rate limit.
        """
        require_non_negative_int(now, "now")
        if any(at > now for at in recent_action_times):
            raise ContractError("an action recorded in the future cannot clear a rate limit")
        window_start = now - self._budget.window_seconds
        inside = [at for at in recent_action_times if window_start <= at <= now]
        limited = len(inside) >= self._budget.max_autonomous_actions_per_window
        if limited:
            self._escalation = (
                f"{len(inside)} autonomous actions in {self._budget.window_seconds}s reaches the "
                f"{self._budget.max_autonomous_actions_per_window} action limit"
            )
        return limited

    def spend_report(self) -> Mapping[str, int]:
        """Per-kind spend plus the total. Read-only, so a report cannot rewrite a cap."""
        report = {kind.value: units for kind, units in self._spent.items()}
        report["TOTAL"] = sum(self._spent.values())
        report["REMAINING"] = self.remaining()
        return MappingProxyType(report)

    def escalation(self) -> str | None:
        """Why the caller must escalate, or ``None``.

        ``None`` means nothing was exhausted — not "it is fine to proceed". The
        planner's answer to a non-``None`` value is ``PlanDecision.ESCALATE``.
        """
        return self._escalation


assert set(KIND_CAPS) <= set(WorkKind), "a capped kind must be a work kind"
assert all(
    hasattr(STAGE5_BUDGET, field) for field in KIND_CAPS.values()
), "every per-kind cap must name a real ResourceBudget field"
assert STAGE5_BUDGET.max_candidate_actions == 16, "spec §4.9: MAX_CANDIDATES is 16"
assert STAGE5_BUDGET.max_work_units == 4096, "spec §4.9: the work-unit budget is 4096"
