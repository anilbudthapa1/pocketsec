"""D5.22 — the eight runtime-observable adversarial-response monitors of architecture §33.

§33 names eleven ways an attacker attacks the *responder* rather than the host. Three are
answered by construction elsewhere and cross-referenced rather than duplicated: action
injection through logs or prose (the closed ``ArgvAtom`` union plus catalog identity), PID
reuse and TOCTOU (identity revalidation inside COMMIT), and token replay (the single-use
nonce). The other eight can only be seen by watching the system respond.

Two properties matter more than any threshold. **A monitor raises shadow, never authority**:
the strongest thing one can say is ``HALT_AUTONOMY``, which removes the system's own
permission to act by itself — no severity lets an action through, and ``FALSE_CERTAINTY``
makes the system *less* willing to act on a resolution presenting impossible confidence.
**The history is bounded**: every buffer is a ``deque`` with ``maxlen``
:data:`MAX_MONITOR_HISTORY`, and counting happens over that window rather than a wall clock
because a receipt carries no single timestamp and this host's load swung sevenfold between
two runs of one gate (``planning/MEMORY.md``) — a window in rows reproduces, one in seconds
here does not.

The plan and receipt arguments are **structural views**, not the planner's and executor's
classes: nothing under ``sentinel/`` may import ``aegis/`` (boundary rule 7), the kernel's
independence argument is worth more if the monitors do not know those types either, and it
makes them testable without either package existing.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage4.stage5_interface import CBFResolutionV1
from pocketsec.stage5.constitution.schema import MissionInvariantSet
from pocketsec.stage5.governor import ResourceBudget
from pocketsec.stage5.operators.algebra import DefensiveOperator, OperatorClass, TargetKind

__all__ = [
    "ACTION_OSCILLATION_FLIPS",
    "CERTAINTY_CEILING",
    "EXECUTOR_FAULT_BURST_COUNT",
    "IDENTIFIABILITY_MARGIN",
    "MAX_MONITOR_HISTORY",
    "ROLLBACK_SABOTAGE_HALT",
    "CandidateView",
    "MonitorFinding",
    "MonitorId",
    "PlanView",
    "ReceiptView",
    "ResponseDefenseMonitors",
    "Severity",
]

#: Rows retained per buffer. Bounded endpoint state is a hard constraint (MEMORY.md).
MAX_MONITOR_HISTORY: int = 64

#: Support gap below which two hypotheses are not separated. Read from Stage 4's
#: ``identifiability/resolution.py:65``; restated rather than imported because Stage 5
#: consumes Stage 4 through one module only (ADR-0045). A chosen parameter.
IDENTIFIABILITY_MARGIN: float = 0.15

#: Uncertainty at or below which a resolution is presenting certainty. A parameter.
CERTAINTY_CEILING: float = 0.01

#: Operator-identity flips on one target within the window that count as oscillation.
ACTION_OSCILLATION_FLIPS: int = 3

#: Faulted receipts within the window that count as a burst.
EXECUTOR_FAULT_BURST_COUNT: int = 3

#: Failed rollbacks within the window at which autonomy halts.
ROLLBACK_SABOTAGE_HALT: int = 2

#: Outcomes meaning the executor itself is not behaving. Refusals are absent on purpose: a
#: refusal is the system working, and counting them would make a kernel doing its job look
#: like an outage.
_FAULT_OUTCOMES: frozenset[str] = frozenset({"ROLLBACK_FAILED", "COMMITTED_UNVERIFIED"})

#: Outcomes that changed the host.
_COMMITTED_OUTCOMES: frozenset[str] = frozenset(
    {"COMMITTED_VERIFIED", "COMMITTED_UNVERIFIED", "ROLLED_BACK", "ROLLBACK_FAILED"}
)

#: The class at or above which an action is disruptive enough to count toward a
#: self-inflicted denial of service.
_DISRUPTIVE_CLASS: int = int(OperatorClass.O3_SUSPEND)

#: Plan decisions that are about to touch the host.
_ACTING_DECISIONS: frozenset[str] = frozenset({"ACT", "ROLLBACK"})


class MonitorId(StrEnum):
    """The eight runtime-observable families of §33."""

    SELF_DOS_INDUCTION = "SELF_DOS_INDUCTION"
    CRITICAL_PROCESS_BAITING = "CRITICAL_PROCESS_BAITING"
    ACTION_OSCILLATION = "ACTION_OSCILLATION"
    CANDIDATE_EXPLOSION = "CANDIDATE_EXPLOSION"
    ROLLBACK_SABOTAGE = "ROLLBACK_SABOTAGE"
    DEPENDENCY_POISONING = "DEPENDENCY_POISONING"
    FALSE_CERTAINTY = "FALSE_CERTAINTY"
    EXECUTOR_FAULT_BURST = "EXECUTOR_FAULT_BURST"


class Severity(StrEnum):
    """Three levels, none of which permits anything."""

    INFO = "INFO"
    ESCALATE = "ESCALATE"
    HALT_AUTONOMY = "HALT_AUTONOMY"


@dataclass(frozen=True, slots=True)
class MonitorFinding:
    """One reading, with the number seen and the number compared against, so a finding can
    always be decomposed back into what produced it: a bare severity is a score nobody can
    audit."""

    monitor: MonitorId
    fired: bool
    severity: Severity
    detail: str
    observed_value: float | int
    threshold: float | int

    def __post_init__(self) -> None:
        object.__setattr__(self, "monitor", MonitorId(self.monitor))
        object.__setattr__(self, "severity", Severity(self.severity))
        if not isinstance(self.fired, bool):
            raise ContractError("MonitorFinding.fired must be a bool")
        if not self.fired and self.severity is not Severity.INFO:
            raise ContractError(
                f"MonitorFinding({self.monitor}) did not fire but carries {self.severity}; a "
                "severity nothing triggered is how a finding gets quoted out of context"
            )


class CandidateView(Protocol):
    """What a monitor needs of a candidate action: its id and its typed operator."""

    candidate_id: str
    operator: DefensiveOperator


class PlanView(Protocol):
    """What a monitor needs of a plan. Structural, so no planner type is imported."""

    plan_id: str
    decision: Any
    chosen: CandidateView | None
    frontier: Sequence[CandidateView]
    rejected: Sequence[Any]
    truncations: Sequence[Any]


class ReceiptView(Protocol):
    """What a monitor needs of a receipt. Structural, for the same reason."""

    receipt_id: str
    operator_id: str
    operator_class: Any
    target_digest: str
    outcome: Any
    rollback_attempted: bool
    rollback_succeeded: bool | None


class ResponseDefenseMonitors:
    """Bounded ring buffers only. Holds no host handle and decides no action."""

    __slots__ = ("_budget", "_findings", "_invariants", "_plans", "_receipts")

    def __init__(self, *, invariants: MissionInvariantSet, budget: ResourceBudget) -> None:
        if not isinstance(invariants, MissionInvariantSet):
            raise ContractError("ResponseDefenseMonitors.invariants must be a MissionInvariantSet")
        if not isinstance(budget, ResourceBudget):
            raise ContractError("ResponseDefenseMonitors.budget must be a ResourceBudget")
        self._invariants = invariants
        self._budget = budget
        self._plans: deque[tuple[str, int]] = deque(maxlen=MAX_MONITOR_HISTORY)
        self._receipts: deque[ReceiptView] = deque(maxlen=MAX_MONITOR_HISTORY)
        self._findings: deque[MonitorFinding] = deque(maxlen=MAX_MONITOR_HISTORY)

    def observe_plan(
        self, plan: PlanView, resolution: CBFResolutionV1
    ) -> tuple[MonitorFinding, ...]:
        """Evaluate the four monitors that read a plan and its upstream resolution."""
        frontier = tuple(plan.frontier)
        chosen = plan.chosen
        candidates = frontier if chosen is None or chosen in frontier else frontier + (chosen,)
        self._plans.append((str(plan.plan_id), len(candidates)))
        return self._retain(
            (
                self._critical_process_baiting(candidates),
                self._candidate_explosion(plan, candidates),
                self._dependency_poisoning(plan, resolution),
                self._false_certainty(resolution),
            )
        )

    def _critical_process_baiting(self, candidates: Sequence[CandidateView]) -> MonitorFinding:
        critical = self._invariants.critical_units()
        baited = sum(
            1
            for candidate in candidates
            if candidate.operator.target.scope.kind is TargetKind.SERVICE
            and candidate.operator.target.scope.subject in critical
        )
        return _finding(
            MonitorId.CRITICAL_PROCESS_BAITING, baited, 0, baited > 0, Severity.ESCALATE,
            f"{baited} candidate(s) name a critical unit",
        )

    def _candidate_explosion(
        self, plan: PlanView, candidates: Sequence[CandidateView]
    ) -> MonitorFinding:
        total = len(candidates) + len(tuple(plan.rejected))
        limit = self._budget.max_candidate_actions
        return _finding(
            MonitorId.CANDIDATE_EXPLOSION, total, limit, total > limit, Severity.ESCALATE,
            f"{total} candidates considered against a cap of {limit}",
        )

    def _dependency_poisoning(self, plan: PlanView, resolution: CBFResolutionV1) -> MonitorFinding:
        """Acting while the upstream reports a degraded dependency view: an attacker who can
        cause a degradation row can choose what the responder believes about dependencies, so
        acting anyway raises shadow."""
        degraded = len(resolution.degradations)
        fired = str(plan.decision) in _ACTING_DECISIONS and degraded > 0
        return _finding(
            MonitorId.DEPENDENCY_POISONING, degraded, 0, fired, Severity.ESCALATE,
            f"decision={plan.decision} with {degraded} upstream degradation(s)",
        )

    def _false_certainty(self, resolution: CBFResolutionV1) -> MonitorFinding:
        """Certainty a resolution cannot have, from two independent readings."""
        lost = len(resolution.truncations) + len(resolution.degradations)
        certain = resolution.uncertainty <= CERTAINTY_CEILING
        supports = sorted(
            (
                float(row["support"])
                for row in resolution.hypotheses
                if isinstance(row.get("support"), (int, float))
            ),
            reverse=True,
        )
        gap = supports[0] - supports[1] if len(supports) >= 2 else 1.0
        fired = certain and (lost > 0 or gap < IDENTIFIABILITY_MARGIN)
        return _finding(
            MonitorId.FALSE_CERTAINTY, round(resolution.uncertainty, 6), CERTAINTY_CEILING,
            fired, Severity.ESCALATE,
            f"uncertainty={resolution.uncertainty} with {lost} truncation/degradation row(s) "
            f"and a leading support gap of {round(gap, 6)}",
        )

    def observe_receipt(self, receipt: ReceiptView) -> tuple[MonitorFinding, ...]:
        """Evaluate the four monitors that read execution history."""
        self._receipts.append(receipt)
        return self._retain(
            (
                self._self_dos_induction(),
                self._action_oscillation(),
                self._rollback_sabotage(),
                self._executor_fault_burst(),
            )
        )

    def _self_dos_induction(self) -> MonitorFinding:
        disruptive = sum(
            1
            for receipt in self._receipts
            if _committed(receipt) and _class_of(receipt) >= _DISRUPTIVE_CLASS
        )
        limit = self._budget.max_autonomous_actions_per_window
        return _finding(
            MonitorId.SELF_DOS_INDUCTION, disruptive, limit, disruptive >= limit,
            Severity.HALT_AUTONOMY,
            f"{disruptive} disruptive commits in the last {len(self._receipts)} receipts",
        )

    def _action_oscillation(self) -> MonitorFinding:
        by_target: dict[str, list[str]] = {}
        for receipt in self._receipts:
            if _committed(receipt):
                by_target.setdefault(str(receipt.target_digest), []).append(
                    str(receipt.operator_id)
                )
        flips = max(
            (
                sum(1 for a, b in zip(seq, seq[1:], strict=False) if a != b)
                for seq in by_target.values()
            ),
            default=0,
        )
        return _finding(
            MonitorId.ACTION_OSCILLATION, flips, ACTION_OSCILLATION_FLIPS,
            flips >= ACTION_OSCILLATION_FLIPS, Severity.ESCALATE,
            f"{flips} operator flip(s) on one target",
        )

    def _rollback_sabotage(self) -> MonitorFinding:
        failed = sum(
            1
            for receipt in self._receipts
            if bool(receipt.rollback_attempted) and receipt.rollback_succeeded is not True
        )
        severity = (
            Severity.HALT_AUTONOMY if failed >= ROLLBACK_SABOTAGE_HALT else Severity.ESCALATE
        )
        return _finding(
            MonitorId.ROLLBACK_SABOTAGE, failed, 1, failed >= 1, severity,
            f"{failed} attempted rollback(s) did not succeed",
        )

    def _executor_fault_burst(self) -> MonitorFinding:
        faults = sum(1 for receipt in self._receipts if str(receipt.outcome) in _FAULT_OUTCOMES)
        return _finding(
            MonitorId.EXECUTOR_FAULT_BURST, faults, EXECUTOR_FAULT_BURST_COUNT,
            faults >= EXECUTOR_FAULT_BURST_COUNT, Severity.HALT_AUTONOMY,
            f"{faults} faulted receipt(s) in the window",
        )

    def _retain(self, findings: Sequence[MonitorFinding]) -> tuple[MonitorFinding, ...]:
        for finding in findings:
            if finding.fired:
                self._findings.append(finding)
        return tuple(findings)

    def halted(self) -> bool:
        """True once any monitor has fired at ``HALT_AUTONOMY``. Latching is deliberate: a halt
        that clears when the next plan looks calmer is what an attacker paces actions against."""
        return any(finding.severity is Severity.HALT_AUTONOMY for finding in self._findings)

    def findings(self) -> tuple[MonitorFinding, ...]:
        return tuple(self._findings)

    def history_sizes(self) -> dict[str, int]:
        """Buffer occupancy, for the bounded-state assertions of G5.12."""
        return {
            "plans": len(self._plans), "receipts": len(self._receipts),
            "findings": len(self._findings), "max": MAX_MONITOR_HISTORY,
        }


def _finding(
    monitor: MonitorId,
    observed: float | int,
    threshold: float | int,
    fired: bool,
    severity: Severity,
    detail: str,
) -> MonitorFinding:
    return MonitorFinding(
        monitor=monitor,
        fired=fired,
        severity=severity if fired else Severity.INFO,
        detail=detail,
        observed_value=observed,
        threshold=threshold,
    )


def _class_of(receipt: ReceiptView) -> int:
    try:
        return int(receipt.operator_class)
    except (TypeError, ValueError):
        # An unreadable class is treated as the most disruptive: a receipt the monitors
        # cannot classify must not be the cheapest one to ignore.
        return int(OperatorClass.O7_DESTRUCTIVE)


def _committed(receipt: ReceiptView) -> bool:
    return str(receipt.outcome) in _COMMITTED_OUTCOMES
