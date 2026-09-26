"""D5.14 — recovery is part of response: getting back inside the safe manifold.

Architecture §22: "Containment without recovery is incomplete", and recovery
"proceeds incrementally rather than restoring everything at once" — verify
dependencies, restore **one** bounded capability, observe, then continue, roll
back or escalate. §23 replaces the binary healthy/compromised flag with a
manifold: ``M_safe`` is the set of states where the critical invariants hold, the
known malicious trajectory is blocked, a recovery path exists and observation
remains sufficient. All four conjuncts are evaluated here; dropping the third is
how a system declares itself healthy while holding a change it can no longer undo.

What this module refuses to do:

- **It refuses to restore wholesale.** :func:`execute_recovery` runs step *i*,
  re-reads the host, and only then decides whether step *i+1* is eligible. The
  plan is a bound on what *may* happen, not a script that will.
- **It refuses to always find a path.**
  :data:`ManifoldStatus.OUTSIDE_UNRECOVERABLE` is reachable — a containment whose
  rollback operator is no longer in the catalog, a target that is gone, or a
  service that lost ``restartable`` — and it leads to
  :data:`RecoveryAction.ESCALATE`. A recovery planner that always succeeds has
  not been tested.
- **It refuses to claim a real host.** ``RecoveryReport.simulated`` is read from
  the executor's host adapter, never defaulted. §6.1 and ADR-0046: "safe recovery
  is demonstrated after containment" is a claim about a Linux host, and the
  mechanism demonstrated here runs against the simulated host model. G5.11 asserts
  ``report.simulated is False`` and therefore **fails** while only the simulator
  exists. That is the honest outcome, not a bug to be worked around.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import (
    ContractError,
    digest_of_bytes,
    require_identifier,
)
from pocketsec.stage1.state.security_state import Isolation
from pocketsec.stage5.constitution.invariants import (
    AUTHORITY_ORDER,
    MAX_AUTONOMOUS_AUTHORITY,
)
from pocketsec.stage5.constitution.schema import (
    InvariantKind,
    InvariantViolation,
    MissionInvariant,
    MissionInvariantSet,
)
from pocketsec.stage5.executor.identity import identity_digest
from pocketsec.stage5.executor.lease import DEFAULT_LEASE_TTL_SECONDS, Lease
from pocketsec.stage5.executor.verify import PostconditionKind
from pocketsec.stage5.governor import ResourceGovernor, WorkKind
from pocketsec.stage5.host.simulated import (
    HostAdapter,
    HostKind,
    HostSnapshot,
    ProcessRow,
)
from pocketsec.stage5.operators.algebra import (
    DefensiveOperator,
    OperatorSpec,
    ProcessTarget,
    Reversibility,
    TargetKind,
    TargetScope,
)
from pocketsec.stage5.operators.catalog import CATALOG

if TYPE_CHECKING:  # pragma: no cover - annotations only
    from pocketsec.stage4.stage5_interface import CBFResolutionV1
    from pocketsec.stage5.authority.capability import AuthorityGrant
    from pocketsec.stage5.authority.tokens import TokenStore
    from pocketsec.stage5.executor.transactional import (
        TransactionalExecutor,
        TransactionReceipt,
    )

__all__ = [
    "COMMITTED_OUTCOME_NAMES",
    "DEFAULT_OBSERVE_SECONDS",
    "MAX_RECOVERY_STEPS",
    "RECOVERY_EXPECTS_BY_TARGET_KIND",
    "ManifoldStatus",
    "ManifoldVerdict",
    "RecoveryAction",
    "RecoveryReport",
    "RecoveryStep",
    "SafeStateManifold",
    "SafeStatePlan",
    "SafeStatePlanner",
    "capability_signature",
    "changed_capabilities",
    "execute_recovery",
    "in_manifold",
    "recovery_action_for",
]

#: A recovery plan is bounded like every other piece of endpoint state. Eight
#: steps is two more than ``MAX_CONCURRENT_LEASES`` allows to be outstanding, so
#: a plan can always cover the leases plus a dependency restart.
MAX_RECOVERY_STEPS: int = 8
#: How long a step says to watch before the next one is considered. Metadata for
#: the operator of the sweep; the eligibility decision itself is taken from the
#: probe, not from a timer.
DEFAULT_OBSERVE_SECONDS: int = 5

#: ``Outcome`` member names that mean the action reached and changed the host.
#: Mirrored rather than imported so this module does not pull the privileged
#: executor in at import time (``executor/verify.py`` explains the cycle).
COMMITTED_OUTCOME_NAMES: frozenset[str] = frozenset(
    {"COMMITTED_VERIFIED", "COMMITTED_UNVERIFIED"}
)

#: What a recovery step expects when its catalog entry declares no
#: postconditions of its own. A recovery step with nothing to check is a step
#: whose failure would be invisible, so there is no empty case.
RECOVERY_EXPECTS_BY_TARGET_KIND: Mapping[TargetKind, tuple[PostconditionKind, ...]] = {
    TargetKind.PROCESS: (
        PostconditionKind.PROCESS_RESUMED,
        PostconditionKind.SERVICE_HEALTH_ACCEPTABLE,
    ),
    TargetKind.SERVICE: (
        PostconditionKind.SERVICE_RELEASED,
        PostconditionKind.SERVICE_HEALTH_ACCEPTABLE,
    ),
    TargetKind.SOCKET: (PostconditionKind.SOCKET_RELEASED,),
    TargetKind.SESSION: (PostconditionKind.OBSERVATION_RETAINED,),
    TargetKind.HOST: (PostconditionKind.SERVICE_HEALTH_ACCEPTABLE,),
}

assert set(RECOVERY_EXPECTS_BY_TARGET_KIND) == set(TargetKind), (
    "RECOVERY_EXPECTS_BY_TARGET_KIND must be total over TargetKind"
)


@dataclass(frozen=True, slots=True)
class SafeStateManifold:
    """§23's ``M_safe``, as a predicate over a snapshot rather than a flag."""

    invariants: MissionInvariantSet
    required_observation: frozenset[str]
    blocked_trajectory_signals: frozenset[str]

    def __post_init__(self) -> None:
        if not isinstance(self.invariants, MissionInvariantSet):
            raise ContractError(
                "SafeStateManifold.invariants must be a MissionInvariantSet, got "
                f"{self.invariants!r}"
            )
        object.__setattr__(
            self, "required_observation", frozenset(self.required_observation)
        )
        object.__setattr__(
            self,
            "blocked_trajectory_signals",
            frozenset(self.blocked_trajectory_signals),
        )


class ManifoldStatus(StrEnum):
    INSIDE = "INSIDE"
    OUTSIDE_RECOVERABLE = "OUTSIDE_RECOVERABLE"
    OUTSIDE_UNRECOVERABLE = "OUTSIDE_UNRECOVERABLE"


@dataclass(frozen=True, slots=True)
class ManifoldVerdict:
    status: ManifoldStatus
    violated: tuple[InvariantViolation, ...]
    missing_observation: tuple[str, ...]
    recovery_path_exists: bool
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "violated": [violation.invariant_id for violation in self.violated],
            "missing_observation": list(self.missing_observation),
            "recovery_path_exists": self.recovery_path_exists,
            "detail": self.detail,
        }


class RecoveryAction(StrEnum):
    CONTINUE = "CONTINUE"
    ROLLBACK_STEP = "ROLLBACK_STEP"
    ESCALATE = "ESCALATE"
    HALT = "HALT"


def _observable(snapshot: HostSnapshot) -> frozenset[str]:
    signals: set[str] = set()
    for row in snapshot.processes:
        signals.update(row.volatile_signals)
    return frozenset(signals)


def _invariant_violation(
    invariant: MissionInvariant,
    snapshot: HostSnapshot,
    leases: Sequence[Lease],
    observable: frozenset[str],
) -> InvariantViolation | None:
    """Total dispatch over :class:`InvariantKind` — no ``case _``.

    The two kinds this host model cannot see (kernel modification, host-local
    scope) return ``None`` **and** are reported as unobservable by the caller: an
    invariant nobody can check is not an invariant that holds.
    """
    match invariant.kind:
        case InvariantKind.CRITICAL_SERVICE:
            row = snapshot.service(invariant.subject)
            failed = row is None or not row.running or not row.healthy or row.constrained
            detail = "unit missing" if row is None else "unit not serving"
        case InvariantKind.ADMIN_RECOVERY_ACCESS:
            row = snapshot.service(invariant.subject)
            failed = invariant.subject not in snapshot.sessions and (
                row is None or not row.running
            )
            detail = "no session and no running unit for recovery access"
        case InvariantKind.EVIDENCE_RETENTION:
            failed = invariant.subject not in observable
            detail = "required signal is no longer observable"
        case InvariantKind.BOUNDARY_NOT_CROSSED:
            failed = snapshot.security_state.level("isolation") >= int(
                Isolation.BOUNDARY_CROSSED
            )
            detail = "lineage state reports a crossed boundary"
        case InvariantKind.MAX_AUTONOMOUS_DOWNTIME | InvariantKind.MAX_CONTAINMENT_DURATION:
            bound = invariant.bound_seconds or 0
            overdue = [
                lease.lease_id
                for lease in leases
                if snapshot.at - lease.granted_at > bound
            ]
            failed = bool(overdue)
            detail = f"leases past {bound}s: {','.join(sorted(overdue))}"
        case InvariantKind.FORBIDDEN_KERNEL_MODIFICATION | InvariantKind.HOST_LOCAL_SCOPE:
            return None
    if not failed:
        return None
    return InvariantViolation(
        invariant_id=invariant.invariant_id,
        kind=invariant.kind,
        subject=invariant.subject,
        detail=detail,
    )


_UNOBSERVABLE_KINDS: frozenset[InvariantKind] = frozenset(
    {InvariantKind.FORBIDDEN_KERNEL_MODIFICATION, InvariantKind.HOST_LOCAL_SCOPE}
)


def _recovery_path(
    snapshot: HostSnapshot, leases: Sequence[Lease]
) -> tuple[bool, tuple[str, ...]]:
    """Whether every outstanding change can still be undone, and why not.

    Three ways the path disappears, all of them real: the rollback operator is
    gone from the catalog, the thing it would act on is gone from the host, or a
    constrained service has lost its restart semantics. Each one turns a
    "reversible intervention" into a permanent change.
    """
    reasons: list[str] = []
    digests = {identity_digest(row.identity) for row in snapshot.processes}
    for lease in leases:
        rollback_id = lease.rollback_operator_id
        if rollback_id is None:
            reasons.append(f"{lease.lease_id}: no rollback operator")
            continue
        entry = CATALOG.get(rollback_id)
        if entry is None:
            reasons.append(f"{lease.lease_id}: rollback {rollback_id} not in the catalog")
            continue
        if lease.target_digest not in digests:
            reasons.append(
                f"{lease.lease_id}: target identity absent, {rollback_id} has no target"
            )
    for service in snapshot.services:
        if service.constrained and not service.restartable:
            reasons.append(f"unit {service.unit}: constrained and not restartable")
    return (not reasons, tuple(reasons))


def in_manifold(
    snapshot: HostSnapshot, manifold: SafeStateManifold, *, leases: Sequence[Lease]
) -> ManifoldVerdict:
    """Evaluate §23's four conjuncts against one snapshot."""
    observable = _observable(snapshot)
    violated = tuple(
        violation
        for violation in (
            _invariant_violation(invariant, snapshot, leases, observable)
            for invariant in manifold.invariants.invariants
        )
        if violation is not None
    )
    missing = tuple(sorted(manifold.required_observation - observable))
    active_trajectory = tuple(sorted(manifold.blocked_trajectory_signals & observable))
    path, reasons = _recovery_path(snapshot, leases)
    unobservable = tuple(
        sorted(
            invariant.invariant_id
            for invariant in manifold.invariants.invariants
            if invariant.kind in _UNOBSERVABLE_KINDS
        )
    )
    inside = not violated and not missing and not active_trajectory and path
    if inside:
        status = ManifoldStatus.INSIDE
    elif path:
        status = ManifoldStatus.OUTSIDE_RECOVERABLE
    else:
        status = ManifoldStatus.OUTSIDE_UNRECOVERABLE
    detail = (
        f"violated={len(violated)} missing_observation={len(missing)} "
        f"trajectory_signals_active={len(active_trajectory)} "
        f"unobservable_invariants={len(unobservable)}"
    )
    if reasons:
        detail += " no_path=" + ";".join(reasons)
    return ManifoldVerdict(
        status=status,
        violated=violated,
        missing_observation=missing,
        recovery_path_exists=path,
        detail=detail,
    )


def recovery_action_for(verdict: ManifoldVerdict) -> RecoveryAction:
    """Total dispatch over :class:`ManifoldStatus`.

    ``OUTSIDE_UNRECOVERABLE`` escalates: there is nothing left for this stage to
    try, and looping would be an autonomous system retrying a change it cannot
    undo.
    """
    match verdict.status:
        case ManifoldStatus.INSIDE:
            return RecoveryAction.CONTINUE
        case ManifoldStatus.OUTSIDE_RECOVERABLE:
            return RecoveryAction.ROLLBACK_STEP
        case ManifoldStatus.OUTSIDE_UNRECOVERABLE:
            return RecoveryAction.ESCALATE


@dataclass(frozen=True, slots=True)
class RecoveryStep:
    step_index: int
    operator: DefensiveOperator
    expects: tuple[PostconditionKind, ...]
    on_failure: RecoveryAction
    observe_seconds: int

    def __post_init__(self) -> None:
        if self.step_index < 0:
            raise ContractError("RecoveryStep.step_index is dense from 0")
        if not self.expects:
            raise ContractError(
                "RecoveryStep.expects may not be empty; a step whose failure "
                "cannot be detected is not a recovery step"
            )
        if self.observe_seconds < 0:
            raise ContractError("RecoveryStep.observe_seconds must be >= 0")


@dataclass(frozen=True, slots=True)
class SafeStatePlan:
    plan_id: str
    incident_id: str
    steps: tuple[RecoveryStep, ...]
    manifold: SafeStateManifold

    def __post_init__(self) -> None:
        require_identifier(self.plan_id, "SafeStatePlan.plan_id")
        require_identifier(self.incident_id, "SafeStatePlan.incident_id")
        if len(self.steps) > MAX_RECOVERY_STEPS:
            raise ContractError(
                f"SafeStatePlan holds {len(self.steps)} steps, over "
                f"MAX_RECOVERY_STEPS={MAX_RECOVERY_STEPS}"
            )
        for position, step in enumerate(self.steps):
            if step.step_index != position:
                raise ContractError(
                    "SafeStatePlan.steps must be dense from 0; step at position "
                    f"{position} says {step.step_index}"
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "incident_id": self.incident_id,
            "steps": [
                {
                    "step_index": step.step_index,
                    "operator_id": step.operator.spec.operator_id,
                    "expects": [kind.value for kind in step.expects],
                    "on_failure": step.on_failure.value,
                    "observe_seconds": step.observe_seconds,
                }
                for step in self.steps
            ],
        }


@dataclass(frozen=True, slots=True)
class RecoveryReport:
    plan_id: str
    steps_attempted: int
    steps_succeeded: int
    final_status: ManifoldStatus
    receipts: tuple[TransactionReceipt, ...]
    halted_at: int | None
    detail: str
    simulated: bool

    def __post_init__(self) -> None:
        if self.steps_succeeded > self.steps_attempted:
            raise ContractError(
                "RecoveryReport cannot succeed at more steps than it attempted"
            )
        if not isinstance(self.simulated, bool):
            raise ContractError(
                "RecoveryReport.simulated must be read from the host adapter, "
                "never defaulted (ADR-0046)"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "steps_attempted": self.steps_attempted,
            "steps_succeeded": self.steps_succeeded,
            "final_status": self.final_status.value,
            "halted_at": self.halted_at,
            "receipts": len(self.receipts),
            "simulated": self.simulated,
            "detail": self.detail,
        }


def capability_signature(snapshot: HostSnapshot) -> frozenset[str]:
    """The set of capabilities the host currently affords.

    "Restore one bounded capability" (§22) needs a definition of *one*. This is
    it: a running process, an unrestricted socket, an unconstrained running
    service and a live session are each one capability, and recovery is
    incremental exactly when consecutive probes differ by at most one element.
    """
    units: set[str] = set()
    for row in snapshot.processes:
        if row.state.name == "RUNNING":
            units.add(f"process:{row.identity.pid}")
        for socket_id in row.socket_ids:
            if socket_id not in snapshot.restricted_sockets:
                units.add(f"socket:{socket_id}")
    for service in snapshot.services:
        if service.running and not service.constrained:
            units.add(f"service:{service.unit}")
    for session in snapshot.sessions:
        units.add(f"session:{session}")
    return frozenset(units)


def changed_capabilities(before: HostSnapshot, after: HostSnapshot) -> frozenset[str]:
    return capability_signature(before) ^ capability_signature(after)


class SafeStatePlanner:
    """Builds the bounded, ordered list of restorations that *may* be attempted."""

    def __init__(
        self,
        *,
        manifold: SafeStateManifold,
        catalog: Mapping[str, OperatorSpec],
        governor: ResourceGovernor,
    ) -> None:
        self._manifold = manifold
        self._catalog = catalog
        self._governor = governor
        self._unresolved: list[str] = []

    def unresolved(self) -> tuple[str, ...]:
        """Leases no step could be built for. Explicit, like every truncation."""
        return tuple(self._unresolved)

    def plan(
        self,
        *,
        contained: Sequence[Lease],
        snapshot: HostSnapshot,
        incident_id: str,
    ) -> SafeStatePlan:
        self._unresolved = []
        steps: list[RecoveryStep] = []
        for lease in self._ordered(contained):
            if len(steps) >= MAX_RECOVERY_STEPS:
                self._unresolved.append(
                    f"{lease.lease_id}: plan already at MAX_RECOVERY_STEPS"
                )
                continue
            self._governor.spend(WorkKind.DEPENDENCY_WALK)
            operator = self._restore_operator(lease, snapshot, incident_id)
            if operator is None:
                continue
            entry = operator.spec
            steps.append(
                RecoveryStep(
                    step_index=len(steps),
                    operator=operator,
                    expects=tuple(entry.postconditions)
                    or RECOVERY_EXPECTS_BY_TARGET_KIND[entry.target_kind],
                    on_failure=_on_failure(entry),
                    observe_seconds=DEFAULT_OBSERVE_SECONDS,
                )
            )
        material = "|".join(lease.lease_id for lease in contained) + incident_id
        return SafeStatePlan(
            plan_id=f"rp.{digest_of_bytes(material.encode()).removeprefix('sha256:')[:16]}",
            incident_id=incident_id,
            steps=tuple(steps),
            manifold=self._manifold,
        )

    def _ordered(self, contained: Sequence[Lease]) -> tuple[Lease, ...]:
        """Least-authority restoration first, then oldest containment.

        Restoring the cheapest capability first means that if a step goes wrong
        the system has given back the least it could, and the ordering is
        deterministic so two runs of one corpus produce one plan.
        """

        def key(lease: Lease) -> tuple[int, int, str]:
            entry = (
                self._catalog.get(lease.rollback_operator_id)
                if lease.rollback_operator_id
                else None
            )
            authority = AUTHORITY_ORDER[entry.authority] if entry is not None else 99
            return (authority, lease.granted_at, lease.lease_id)

        return tuple(sorted(contained, key=key))

    def _restore_operator(
        self, lease: Lease, snapshot: HostSnapshot, incident_id: str
    ) -> DefensiveOperator | None:
        rollback_id = lease.rollback_operator_id
        entry = self._catalog.get(rollback_id) if rollback_id else None
        if entry is None:
            self._unresolved.append(
                f"{lease.lease_id}: rollback operator {rollback_id!r} is not in the catalog"
            )
            return None
        row = next(
            (
                candidate
                for candidate in snapshot.processes
                if identity_digest(candidate.identity) == lease.target_digest
            ),
            None,
        )
        if row is None:
            self._unresolved.append(
                f"{lease.lease_id}: no live process matches the leased target identity"
            )
            return None
        subject = _subject_for(entry.target_kind, row, snapshot)
        if subject is None:
            self._unresolved.append(
                f"{lease.lease_id}: no {entry.target_kind.value} subject on pid "
                f"{row.identity.pid}"
            )
            return None
        return DefensiveOperator(
            spec=entry,
            target=ProcessTarget(
                identity=row.identity,
                scope=TargetScope(kind=entry.target_kind, subject=subject),
            ),
            incident_id=incident_id,
            ttl_seconds=min(DEFAULT_LEASE_TTL_SECONDS, entry.max_duration_seconds),
            evidence_refs=(),
        )


def _subject_for(
    kind: TargetKind, row: ProcessRow, snapshot: HostSnapshot
) -> str | None:
    """Total dispatch over :class:`TargetKind`, resolved from observed host state."""
    match kind:
        case TargetKind.PROCESS:
            return str(row.identity.pid)
        case TargetKind.SERVICE:
            return row.unit
        case TargetKind.SESSION:
            return row.session_id
        case TargetKind.SOCKET:
            restricted = [
                socket_id
                for socket_id in row.socket_ids
                if socket_id in snapshot.restricted_sockets
            ]
            if restricted:
                return restricted[0]
            return row.socket_ids[0] if row.socket_ids else None
        case TargetKind.HOST:
            return "host"


def _on_failure(entry: OperatorSpec) -> RecoveryAction:
    if AUTHORITY_ORDER[entry.authority] > AUTHORITY_ORDER[MAX_AUTONOMOUS_AUTHORITY]:
        return RecoveryAction.ESCALATE
    if entry.reversibility is Reversibility.IRREVERSIBLE:
        return RecoveryAction.HALT
    return RecoveryAction.ROLLBACK_STEP


_HOST_ATTRIBUTE_CANDIDATES: tuple[str, ...] = ("host", "_host", "adapter", "_adapter")


def _is_host(candidate: object) -> bool:
    return all(
        hasattr(candidate, name) for name in ("host_kind", "snapshot", "apply")
    )


def _host_of(executor: TransactionalExecutor) -> HostAdapter:
    """Resolve the executor's host adapter structurally.

    D5.11's contract gives ``TransactionalExecutor`` no public host accessor, and
    ``RecoveryReport.simulated`` may not be defaulted: a report that says
    ``simulated=False`` because nobody asked is exactly the lie ADR-0046 exists to
    prevent. So this looks, and raises when it cannot tell.
    """
    for name in _HOST_ATTRIBUTE_CANDIDATES:
        candidate = getattr(executor, name, None)
        if candidate is not None and _is_host(candidate):
            return candidate  # type: ignore[return-value]
    for name in dir(executor):
        if name.startswith("__"):
            continue
        candidate = getattr(executor, name, None)
        if candidate is not None and _is_host(candidate):
            return candidate  # type: ignore[return-value]
    raise ContractError(
        "execute_recovery cannot find the executor's host adapter, so it cannot "
        "state whether the recovery ran against a simulated host; refusing rather "
        "than defaulting RecoveryReport.simulated"
    )


def _step_ok(receipt: TransactionReceipt, step: RecoveryStep) -> bool:
    if receipt.outcome.name not in COMMITTED_OUTCOME_NAMES:
        return False
    satisfied = {
        result.kind: result.satisfied for result in receipt.postconditions
    }
    return all(satisfied.get(kind) is True for kind in step.expects)


def _grant_for(
    grant: AuthorityGrant | Mapping[str, AuthorityGrant], operator_id: str
) -> AuthorityGrant | None:
    """Pick the grant that covers this step's operator, or ``None``.

    **Declared deviation from §D5.14's signature, with the reason.**
    ``TokenStore.mint`` refuses a grant whose ``subject_operator_id`` is not this
    operator ("a grant is scoped to one operator", §D5.6), and a recovery plan
    restores several *different* capabilities — resume a process, release a
    socket, release a service. A single ``AuthorityGrant`` therefore cannot mint
    a heterogeneous plan at all. So this accepts either one grant or a mapping,
    and a step with no grant **escalates** instead of raising: an autonomous
    system that cannot find the authority to restore a capability has found a
    human's decision, not an error.
    """
    if isinstance(grant, Mapping):
        return grant.get(operator_id)
    return grant if grant.subject_operator_id == operator_id else None


class _RecoveryRun:
    """The mutable accumulator behind :func:`execute_recovery`.

    It exists so the per-step decision is one small readable function: attempt,
    re-read the host, record, and answer "may the next step run?". A loop that
    decided eligibility from the plan instead of from the probe would be a
    wholesale restore with extra steps.
    """

    def __init__(self, *, host: HostAdapter, manifold: SafeStateManifold) -> None:
        self._host = host
        self._manifold = manifold
        self._verdict = in_manifold(host.snapshot(), manifold, leases=())
        self._attempted = 0
        self._succeeded = 0
        self._receipts: list[TransactionReceipt] = []
        self._halted_at: int | None = None
        self._notes: list[str] = [f"start={self._verdict.status.value}"]

    def step(
        self,
        step: RecoveryStep,
        *,
        plan: SafeStatePlan,
        executor: TransactionalExecutor,
        tokens: TokenStore,
        grant: AuthorityGrant | Mapping[str, AuthorityGrant],
        resolution: CBFResolutionV1,
    ) -> bool:
        """Run one step; return whether the plan may continue."""
        action = recovery_action_for(self._verdict)
        if action in (RecoveryAction.ESCALATE, RecoveryAction.HALT):
            return self._halt(step.step_index, f"halt_before={step.step_index}", action)
        operator_id = step.operator.spec.operator_id
        step_grant = _grant_for(grant, operator_id)
        if step_grant is None:
            return self._halt(
                step.step_index,
                f"halt_at={step.step_index} no grant for {operator_id}",
                RecoveryAction.ESCALATE,
            )
        token = tokens.mint(
            grant=step_grant,
            operator=step.operator,
            action_id=f"{plan.plan_id}.{step.step_index}",
            ttl_seconds=step.operator.ttl_seconds,
        )
        receipt = executor.execute(step.operator, token, resolution=resolution)
        self._receipts.append(receipt)
        self._attempted += 1
        ok = _step_ok(receipt, step)
        self._succeeded += int(ok)
        self._verdict = in_manifold(self._host.snapshot(), self._manifold, leases=())
        self._notes.append(
            f"{step.step_index}:{operator_id}"
            f"={'ok' if ok else receipt.outcome.value}->{self._verdict.status.value}"
        )
        if not ok and step.on_failure in (
            RecoveryAction.ESCALATE,
            RecoveryAction.HALT,
        ):
            return self._halt(
                step.step_index, f"halt_at={step.step_index}", step.on_failure
            )
        return True

    def report(self, plan: SafeStatePlan, *, simulated: bool) -> RecoveryReport:
        return RecoveryReport(
            plan_id=plan.plan_id,
            steps_attempted=self._attempted,
            steps_succeeded=self._succeeded,
            final_status=self._verdict.status,
            receipts=tuple(self._receipts),
            halted_at=self._halted_at,
            detail=" ".join(self._notes),
            simulated=simulated,
        )

    def _halt(self, index: int, note: str, action: RecoveryAction) -> bool:
        self._halted_at = index
        self._notes.append(f"{note} on {action.value}")
        return False


def execute_recovery(
    plan: SafeStatePlan,
    *,
    executor: TransactionalExecutor,
    tokens: TokenStore,
    grant: AuthorityGrant | Mapping[str, AuthorityGrant],
    resolution: CBFResolutionV1,
) -> RecoveryReport:
    """Run the plan one step at a time, re-reading the host between steps.

    Eligibility for step *i+1* is decided from the probe taken **after** step
    *i*: a plan built against a five-minute-old snapshot is a hypothesis, and
    restoring a capability on the strength of it is the same class of mistake as
    acting on a stale pid. ``simulated`` is read from the executor's host adapter
    and never defaulted (ADR-0046).
    """
    host = _host_of(executor)
    run = _RecoveryRun(host=host, manifold=plan.manifold)
    for step in plan.steps:
        if not run.step(
            step,
            plan=plan,
            executor=executor,
            tokens=tokens,
            grant=grant,
            resolution=resolution,
        ):
            break
    return run.report(plan, simulated=host.host_kind is not HostKind.REAL)
