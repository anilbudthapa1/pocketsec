"""D5.1 — protected mission invariants, machine-enforced rather than documented.

Architecture §24 lists eight things a defensive response may not do to the host it
is defending: interrupt a critical service, cut administrative recovery access,
destroy evidence policy requires, cross a namespace boundary, exceed an
autonomous downtime or containment bound, modify the kernel, or act off-host.
:class:`InvariantKind` holds exactly eight members, one per bullet.

The mechanism that makes G5.8 ("evidence and mission invariants are machine
enforced") more than a slogan is :meth:`MissionInvariantSet.violations`: a
``match`` over :class:`InvariantKind` with **no** ``case _``. Adding a member to
the enum without writing its arm is a ``mypy --strict`` error rather than a
silently unchecked invariant — the failure mode where a new protected asset class
is declared in a policy file and enforced nowhere.

This module imports no operator algebra and no host model. It reads its arguments
through :class:`Protocol` views naming only the members it touches, the way
``stage4/worlds/world.py`` reads ``TensionLike``. That keeps ``constitution/`` a
leaf package (``operators/algebra.py`` imports the constitution for
:class:`AuthorityClass`) and keeps the invariant checker testable before the host
model exists.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol

from pocketsec.stage0.contracts.common import (
    ContractError,
    require_identifier,
    require_non_negative_int,
)
from pocketsec.stage5.constitution.invariants import canonical_bytes

__all__ = [
    "BOUNDED_KINDS",
    "DEFAULT_MISSION_INVARIANTS",
    "FORBIDDEN_ARGV_PREFIXES",
    "HOST_GLOBAL_KINDS",
    "MAX_INVARIANT_SET_BYTES",
    "MAX_MISSION_INVARIANTS",
    "MAX_SUBJECT_LENGTH",
    "MIN_DOWNTIME_CLASS_ORDINAL",
    "MIN_INTERRUPTING_CLASS_ORDINAL",
    "InvariantKind",
    "InvariantViolation",
    "MissionInvariant",
    "MissionInvariantSet",
]

#: Bounded endpoint state: a mission invariant set is policy, and policy that can
#: grow without limit is an unbounded allocation on a 2 GB host.
MAX_MISSION_INVARIANTS: int = 64
MAX_SUBJECT_LENGTH: int = 128
MAX_INVARIANT_SET_BYTES: int = 16384

#: From this operator-class ordinal upward an action can interrupt or restrict its
#: target (O2 reversible restrict). O0/O1 observe and preserve, so they cannot.
#: The same threshold the constitution uses for "this action changes host state",
#: spelled once: ``MIN_ROLLBACK_PLAN_RANK`` ranks reversibility, this ranks class.
MIN_INTERRUPTING_CLASS_ORDINAL: int = 2
#: From this ordinal upward an action stops the target doing its job (O3 suspend),
#: which is what "autonomous downtime" measures.
MIN_DOWNTIME_CLASS_ORDINAL: int = 3

#: Literal argv atoms that would name a kernel or boot modification. The current
#: catalog contains none, and this is how it stays that way: the check runs over
#: every operator the planner proposes, so a catalog entry added later without
#: reading §24 is refused at plan time rather than reviewed at merge time.
FORBIDDEN_ARGV_PREFIXES: tuple[str, ...] = ("kernel.", "boot.", "module.", "sysctl.")


class InvariantKind(StrEnum):
    """Architecture §24, one member per bullet. Eight members, closed."""

    CRITICAL_SERVICE = "CRITICAL_SERVICE"
    """subject = unit name; never autonomously interrupted"""
    ADMIN_RECOVERY_ACCESS = "ADMIN_RECOVERY_ACCESS"
    """subject = unit or session; must stay reachable"""
    EVIDENCE_RETENTION = "EVIDENCE_RETENTION"
    """subject = volatile signal name; bound = seconds it must survive"""
    BOUNDARY_NOT_CROSSED = "BOUNDARY_NOT_CROSSED"
    """subject = namespace or cgroup id the response may not reach into"""
    MAX_AUTONOMOUS_DOWNTIME = "MAX_AUTONOMOUS_DOWNTIME"
    """bound = seconds of downtime a lease may hold"""
    MAX_CONTAINMENT_DURATION = "MAX_CONTAINMENT_DURATION"
    """bound = seconds any containment lease may hold"""
    FORBIDDEN_KERNEL_MODIFICATION = "FORBIDDEN_KERNEL_MODIFICATION"
    HOST_LOCAL_SCOPE = "HOST_LOCAL_SCOPE"
    """the defensive scope is this host; a non-host-local action is off-boundary"""


#: The four kinds that are host-global and therefore carry no subject.
HOST_GLOBAL_KINDS: frozenset[InvariantKind] = frozenset(
    {
        InvariantKind.MAX_AUTONOMOUS_DOWNTIME,
        InvariantKind.MAX_CONTAINMENT_DURATION,
        InvariantKind.FORBIDDEN_KERNEL_MODIFICATION,
        InvariantKind.HOST_LOCAL_SCOPE,
    }
)

#: The three kinds whose bound is a number of seconds.
BOUNDED_KINDS: frozenset[InvariantKind] = frozenset(
    {
        InvariantKind.EVIDENCE_RETENTION,
        InvariantKind.MAX_AUTONOMOUS_DOWNTIME,
        InvariantKind.MAX_CONTAINMENT_DURATION,
    }
)


class ScopeView(Protocol):
    """The slice of ``operators.algebra.TargetScope`` an invariant check reads."""

    @property
    def kind(self) -> Any: ...

    @property
    def subject(self) -> str: ...

    @property
    def host_local(self) -> bool: ...


class IdentityView(Protocol):
    """The slice of ``operators.algebra.ProcessIdentity`` an invariant check reads."""

    @property
    def pid(self) -> int: ...

    @property
    def cgroup_id(self) -> str | None: ...

    @property
    def namespace_id(self) -> str | None: ...


class TargetView(Protocol):
    @property
    def identity(self) -> IdentityView: ...

    @property
    def scope(self) -> ScopeView: ...


class SpecView(Protocol):
    """The slice of ``operators.algebra.OperatorSpec`` an invariant check reads."""

    @property
    def operator_id(self) -> str: ...

    @property
    def operator_class(self) -> int: ...

    @property
    def evidence_effect(self) -> Any: ...

    @property
    def argv_template(self) -> Sequence[Any]: ...


class OperatorView(Protocol):
    """The slice of ``operators.algebra.DefensiveOperator`` an invariant check reads.

    A Protocol rather than an import: ``violations()`` must not be able to *act*,
    and a structural view of four read-only members is the narrowest statement of
    that. The executor's entry point is where the nominal ``DefensiveOperator``
    type is mandatory (spec §5.1 rule 4), and that is a different guarantee.
    """

    @property
    def spec(self) -> SpecView: ...

    @property
    def target(self) -> TargetView: ...


class ProcessRowView(Protocol):
    """The slice of ``host.simulated.ProcessRow`` an invariant check reads."""

    @property
    def unit(self) -> str | None: ...

    @property
    def session_id(self) -> str | None: ...

    @property
    def volatile_signals(self) -> tuple[str, ...]: ...


class HostSnapshotView(Protocol):
    """Read-only host state. There is no method here that changes anything."""

    def process(self, pid: int) -> ProcessRowView | None: ...


@dataclass(frozen=True, slots=True)
class MissionInvariant:
    """One protected thing, with the bound that makes it checkable."""

    invariant_id: str
    kind: InvariantKind
    subject: str
    bound_seconds: int | None
    detail: str

    def __post_init__(self) -> None:
        require_identifier(self.invariant_id, "MissionInvariant.invariant_id")
        if self.kind in HOST_GLOBAL_KINDS and self.subject:
            raise ContractError(
                f"{self.invariant_id}: {self.kind.value} is host-global and takes no subject"
            )
        if self.kind not in HOST_GLOBAL_KINDS and not self.subject:
            raise ContractError(f"{self.invariant_id}: {self.kind.value} must name its subject")
        if len(self.subject) > MAX_SUBJECT_LENGTH:
            raise ContractError(
                f"{self.invariant_id}: subject exceeds {MAX_SUBJECT_LENGTH} characters"
            )
        if self.kind in BOUNDED_KINDS:
            if self.bound_seconds is None:
                raise ContractError(
                    f"{self.invariant_id}: {self.kind.value} is meaningless without a bound"
                )
            require_non_negative_int(self.bound_seconds, f"{self.invariant_id}.bound_seconds")
        elif self.bound_seconds is not None:
            raise ContractError(
                f"{self.invariant_id}: {self.kind.value} takes no bound, got {self.bound_seconds}"
            )
        if not self.detail:
            raise ContractError(f"{self.invariant_id}: an invariant must say why it exists")

    def to_dict(self) -> dict[str, Any]:
        return {
            "invariant_id": self.invariant_id,
            "kind": self.kind.value,
            "subject": self.subject,
            "bound_seconds": self.bound_seconds,
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> MissionInvariant:
        bound = payload.get("bound_seconds")
        return cls(
            invariant_id=str(payload["invariant_id"]),
            kind=InvariantKind(payload["kind"]),
            subject=str(payload.get("subject", "")),
            bound_seconds=None if bound is None else int(bound),
            detail=str(payload["detail"]),
        )


@dataclass(frozen=True, slots=True)
class InvariantViolation:
    """What was violated, on what subject, and why — never a bare boolean."""

    invariant_id: str
    kind: InvariantKind
    subject: str
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "invariant_id": self.invariant_id,
            "kind": self.kind.value,
            "subject": self.subject,
            "detail": self.detail,
        }


def _ordinal(spec: SpecView) -> int:
    """The operator class as an int, refusing anything that is not an ``IntEnum`` member."""
    value = spec.operator_class
    if isinstance(value, bool) or not isinstance(value, int):
        raise ContractError(
            f"{spec.operator_id}: operator_class must be an OperatorClass (an IntEnum), "
            f"got {value!r}"
        )
    return int(value)


def _target_unit(operator: OperatorView, snapshot: HostSnapshotView) -> str | None:
    """The unit the action lands on, whether named directly or reached through a pid."""
    scope = operator.target.scope
    if str(scope.kind) == "SERVICE":
        return scope.subject
    row = snapshot.process(operator.target.identity.pid)
    return None if row is None else row.unit


def _target_session(operator: OperatorView, snapshot: HostSnapshotView) -> str | None:
    scope = operator.target.scope
    if str(scope.kind) == "SESSION":
        return scope.subject
    row = snapshot.process(operator.target.identity.pid)
    return None if row is None else row.session_id


def _lost_signals(operator: OperatorView, snapshot: HostSnapshotView) -> tuple[str, ...]:
    """Volatile signals this action would degrade or destroy.

    ``PRESERVES`` and ``NEUTRAL`` lose nothing; the other two lose whatever the
    target process is currently the only source of. This is the input to the
    evidence half of G5.8, and it is deliberately computed from the *host's*
    view of what is observable now, not from the operator's own description.

    **Deliberately conservative, and it cannot be cleared from a snapshot.**
    ``violations()`` sees no pre-action bundle, so a ``DEGRADES_VOLATILE``
    operator on a process holding required evidence always reports the loss. The
    bundle-aware check is D5.10's evidence preservation gate; the resolution is to
    preserve first and then act, which is what §2's seventh law asks for. A caller
    that reads this as a standalone veto will refuse such an action outright —
    which is the fail-closed direction, and the ordering fix belongs to the
    planner rather than to a looser check here.
    """
    effect = str(operator.spec.evidence_effect)
    if effect not in {"DEGRADES_VOLATILE", "DESTROYS"}:
        return ()
    row = snapshot.process(operator.target.identity.pid)
    return () if row is None else tuple(row.volatile_signals)


@dataclass(frozen=True, slots=True)
class MissionInvariantSet:
    """The host's protected set, bounded and checkable.

    Bounded three ways, because "bounded endpoint state" is a Stage 0 invariant
    and a policy object is state: at most :data:`MAX_MISSION_INVARIANTS` entries,
    subjects at most :data:`MAX_SUBJECT_LENGTH` characters, and the whole
    serialised set at most :data:`MAX_INVARIANT_SET_BYTES` canonical bytes.
    """

    invariants: tuple[MissionInvariant, ...]

    def __post_init__(self) -> None:
        if not self.invariants:
            # A floor (finding S5-SEC-06): an empty set — what a missing or empty config
            # used to produce — switched off every mission check in SENTINEL and the
            # evidence gate while both still reported PASS. "No mission" is not a mission.
            raise ContractError("a mission invariant set must hold at least one invariant")
        if len(self.invariants) > MAX_MISSION_INVARIANTS:
            raise ContractError(
                f"a mission invariant set holds at most {MAX_MISSION_INVARIANTS} entries, "
                f"got {len(self.invariants)}"
            )
        ids = [invariant.invariant_id for invariant in self.invariants]
        if len(set(ids)) != len(ids):
            raise ContractError("mission invariant ids must be unique")
        size = len(canonical_bytes(self.to_dict()))
        if size > MAX_INVARIANT_SET_BYTES:
            raise ContractError(
                f"mission invariant set is {size} canonical bytes, over the "
                f"{MAX_INVARIANT_SET_BYTES} byte bound"
            )

    def violations(
        self,
        *,
        operator: OperatorView,
        lease_ttl_seconds: int,
        snapshot: HostSnapshotView,
        preserved: frozenset[str] = frozenset(),
    ) -> tuple[InvariantViolation, ...]:
        """Every §24 invariant this action would break.

        A **total** ``match`` over :class:`InvariantKind` with no ``case _``: a
        ninth kind added to the enum without an arm here fails ``mypy --strict``
        instead of becoming an invariant that is declared but never enforced.

        ``preserved`` is the set of volatile signals already captured in a
        pre-action bundle. It defaults to empty, which is the fail-closed reading
        every planning-side caller gets: without a bundle, a ``DEGRADES_VOLATILE``
        action on a process holding required evidence is a violation. SENTINEL
        passes the signals of the bundle it is itself handed, so the
        EVIDENCE_RETENTION arm means exactly what its message says — *lost before it
        was preserved*. Integrator fix, measured: without it, MI-04 denied every
        ``SUSPEND_PROCESS`` on a process carrying ``process_memory_map`` while the
        evidence gate refused every one that did not carry it, so no
        ``DEGRADES_VOLATILE`` operator was reachable at all under the default set.
        """
        require_non_negative_int(lease_ttl_seconds, "lease_ttl_seconds")
        if not isinstance(preserved, frozenset):
            raise ContractError(f"preserved must be a frozenset of signal names, got {preserved!r}")
        found: list[InvariantViolation] = []
        for invariant in self.invariants:
            match invariant.kind:
                case InvariantKind.CRITICAL_SERVICE:
                    hit = self._critical_service(invariant, operator, snapshot)
                case InvariantKind.ADMIN_RECOVERY_ACCESS:
                    hit = self._admin_access(invariant, operator, snapshot)
                case InvariantKind.EVIDENCE_RETENTION:
                    hit = self._evidence_retention(invariant, operator, snapshot, preserved)
                case InvariantKind.BOUNDARY_NOT_CROSSED:
                    hit = self._boundary(invariant, operator)
                case InvariantKind.MAX_AUTONOMOUS_DOWNTIME:
                    hit = self._downtime(invariant, operator, lease_ttl_seconds)
                case InvariantKind.MAX_CONTAINMENT_DURATION:
                    hit = self._containment(invariant, operator, lease_ttl_seconds)
                case InvariantKind.FORBIDDEN_KERNEL_MODIFICATION:
                    hit = self._kernel(invariant, operator)
                case InvariantKind.HOST_LOCAL_SCOPE:
                    hit = self._host_local(invariant, operator)
            if hit is not None:
                found.append(hit)
        return tuple(found)

    def _critical_service(
        self, invariant: MissionInvariant, operator: OperatorView, snapshot: HostSnapshotView
    ) -> InvariantViolation | None:
        if _ordinal(operator.spec) < MIN_INTERRUPTING_CLASS_ORDINAL:
            return None
        if _target_unit(operator, snapshot) != invariant.subject:
            return None
        return InvariantViolation(
            invariant.invariant_id,
            invariant.kind,
            invariant.subject,
            f"{operator.spec.operator_id} would interrupt a critical unit",
        )

    def _admin_access(
        self, invariant: MissionInvariant, operator: OperatorView, snapshot: HostSnapshotView
    ) -> InvariantViolation | None:
        """Recovery access is checked against unit *and* session.

        §24 says "minimum administrative recovery access", and on a Linux host
        that is reachable as a unit (``sshd.service``) or as a live session. A
        check that only knew about units would be silent on exactly the case
        where an operator revokes the session the administrator is holding.
        """
        if _ordinal(operator.spec) < MIN_INTERRUPTING_CLASS_ORDINAL:
            return None
        reached = {
            _target_unit(operator, snapshot),
            _target_session(operator, snapshot),
        }
        if invariant.subject not in reached:
            return None
        return InvariantViolation(
            invariant.invariant_id,
            invariant.kind,
            invariant.subject,
            f"{operator.spec.operator_id} would remove administrative recovery access",
        )

    def _evidence_retention(
        self,
        invariant: MissionInvariant,
        operator: OperatorView,
        snapshot: HostSnapshotView,
        preserved: frozenset[str],
    ) -> InvariantViolation | None:
        if invariant.subject not in _lost_signals(operator, snapshot):
            return None
        if invariant.subject in preserved:
            return None
        return InvariantViolation(
            invariant.invariant_id,
            invariant.kind,
            invariant.subject,
            f"{operator.spec.operator_id} would lose {invariant.subject} before it was preserved",
        )

    def _boundary(
        self, invariant: MissionInvariant, operator: OperatorView
    ) -> InvariantViolation | None:
        if _ordinal(operator.spec) < MIN_INTERRUPTING_CLASS_ORDINAL:
            return None
        identity = operator.target.identity
        if invariant.subject not in {identity.namespace_id, identity.cgroup_id}:
            return None
        return InvariantViolation(
            invariant.invariant_id,
            invariant.kind,
            invariant.subject,
            f"{operator.spec.operator_id} would act inside a boundary it may not cross",
        )

    def _downtime(
        self, invariant: MissionInvariant, operator: OperatorView, lease_ttl_seconds: int
    ) -> InvariantViolation | None:
        bound = invariant.bound_seconds
        if bound is None:  # pragma: no cover - __post_init__ refuses this construction
            return None
        if _ordinal(operator.spec) < MIN_DOWNTIME_CLASS_ORDINAL or lease_ttl_seconds <= bound:
            return None
        return InvariantViolation(
            invariant.invariant_id,
            invariant.kind,
            invariant.subject,
            f"a {lease_ttl_seconds}s lease exceeds the {bound}s autonomous downtime bound",
        )

    def _containment(
        self, invariant: MissionInvariant, operator: OperatorView, lease_ttl_seconds: int
    ) -> InvariantViolation | None:
        bound = invariant.bound_seconds
        if bound is None:  # pragma: no cover - __post_init__ refuses this construction
            return None
        if _ordinal(operator.spec) < MIN_INTERRUPTING_CLASS_ORDINAL or lease_ttl_seconds <= bound:
            return None
        return InvariantViolation(
            invariant.invariant_id,
            invariant.kind,
            invariant.subject,
            f"a {lease_ttl_seconds}s lease exceeds the {bound}s containment bound",
        )

    def _kernel(
        self, invariant: MissionInvariant, operator: OperatorView
    ) -> InvariantViolation | None:
        """Read off the operator's own argv template, not off its name.

        Every literal atom in a catalog entry is a frozen, metacharacter-free
        token, so the prefixes in :data:`FORBIDDEN_ARGV_PREFIXES` are a decidable
        test over the operator's *mechanism* rather than over its label.
        """
        for atom in operator.spec.argv_template:
            literal = getattr(atom, "value", None)
            if isinstance(literal, str) and literal.startswith(FORBIDDEN_ARGV_PREFIXES):
                return InvariantViolation(
                    invariant.invariant_id,
                    invariant.kind,
                    invariant.subject,
                    f"{operator.spec.operator_id} names {literal!r}, a kernel or boot change",
                )
        return None

    def _host_local(
        self, invariant: MissionInvariant, operator: OperatorView
    ) -> InvariantViolation | None:
        if operator.target.scope.host_local:
            return None
        return InvariantViolation(
            invariant.invariant_id,
            invariant.kind,
            invariant.subject,
            f"{operator.spec.operator_id} targets state outside this host",
        )

    def critical_units(self) -> frozenset[str]:
        """Unit names that may not be autonomously interrupted.

        ``CRITICAL_SERVICE`` subjects only. ``ADMIN_RECOVERY_ACCESS`` subjects may
        be a unit *or* a session id, and folding them in here would hand a
        consumer a set it would join against ``ServiceRow.unit`` — two key spaces
        that would silently half-match (spec §4.9 rule A).
        """
        return frozenset(
            invariant.subject
            for invariant in self.invariants
            if invariant.kind is InvariantKind.CRITICAL_SERVICE
        )

    def required_evidence(self) -> frozenset[str]:
        """Volatile signal names policy requires to survive an intervention."""
        return frozenset(
            invariant.subject
            for invariant in self.invariants
            if invariant.kind is InvariantKind.EVIDENCE_RETENTION
        )

    def to_dict(self) -> dict[str, Any]:
        return {"invariants": [invariant.to_dict() for invariant in self.invariants]}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> MissionInvariantSet:
        if "invariants" not in payload:
            # A missing key is a missing config, not an empty mission (S5-SEC-06).
            raise ContractError("MissionInvariantSet payload has no 'invariants' key")
        rows = payload["invariants"]
        if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes)):
            raise ContractError("MissionInvariantSet payload must hold a sequence of invariants")
        return cls(tuple(MissionInvariant.from_dict(row) for row in rows))


#: The default protected set the labs corpus and the gate run against. Nine
#: invariants covering all eight kinds; ``CRITICAL_SERVICE`` appears twice because
#: a host with exactly one critical unit is not a host anybody has.
DEFAULT_MISSION_INVARIANTS: MissionInvariantSet = MissionInvariantSet(
    (
        MissionInvariant(
            "MI-01",
            InvariantKind.CRITICAL_SERVICE,
            "sshd.service",
            None,
            "remote administration; interrupting it can strand the operator",
        ),
        MissionInvariant(
            "MI-02",
            InvariantKind.CRITICAL_SERVICE,
            "systemd-journald.service",
            None,
            "the host's own evidence pipeline; containment must not silence it",
        ),
        MissionInvariant(
            "MI-03",
            InvariantKind.ADMIN_RECOVERY_ACCESS,
            "admin-recovery",
            None,
            "the session reserved for recovery after a containment action",
        ),
        MissionInvariant(
            "MI-04",
            InvariantKind.EVIDENCE_RETENTION,
            "process_memory_map",
            900,
            "the incident's only record of what the process had mapped",
        ),
        MissionInvariant(
            "MI-05",
            InvariantKind.BOUNDARY_NOT_CROSSED,
            "netns:quarantine",
            None,
            "a namespace PocketSec observes but does not act inside",
        ),
        MissionInvariant(
            "MI-06",
            InvariantKind.MAX_AUTONOMOUS_DOWNTIME,
            "",
            300,
            "five minutes is the longest an unattended action may stop useful work",
        ),
        MissionInvariant(
            "MI-07",
            InvariantKind.MAX_CONTAINMENT_DURATION,
            "",
            900,
            "containment expires; forgotten containment is an outage nobody opened",
        ),
        MissionInvariant(
            "MI-08",
            InvariantKind.FORBIDDEN_KERNEL_MODIFICATION,
            "",
            None,
            "the defensive boundary stops at userspace",
        ),
        MissionInvariant(
            "MI-09",
            InvariantKind.HOST_LOCAL_SCOPE,
            "",
            None,
            "PocketSec defends one host and reaches no further",
        ),
    )
)


assert len(InvariantKind) == 8, "architecture §24 lists exactly eight protected invariant kinds"
assert len(DEFAULT_MISSION_INVARIANTS.invariants) == 9, "the default set is nine invariants"
assert {invariant.kind for invariant in DEFAULT_MISSION_INVARIANTS.invariants} == set(
    InvariantKind
), "the default set must exercise every kind, or a kind ships unmeasured"
assert len(HOST_GLOBAL_KINDS) == 4, "four §24 bullets are host-global"
assert len(BOUNDED_KINDS) == 3, "three §24 bullets carry a seconds bound"
