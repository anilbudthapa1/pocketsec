"""The SIMULATED host model — labelled as such here, in its types and in every figure.

This module exists so that §6.1 of ``docs/stage-5-spec.md`` can be honest. Stage 5's
executor, verifier, lease sweeper and recovery planner all need something to act on, and
this repository has no real Linux host, no real telemetry and — deliberately — no
``RealHost`` implementation. So the substrate is a dictionary of :class:`ProcessRow` and
:class:`ServiceRow` objects with a seeded :class:`FaultProfile`.

**A number produced by this simulator is a property of this simulator.** Whether
``SUSPEND_PROCESS`` succeeds, whether a rollback works, whether a dependency restarts and
whether evidence is lost are all decided by numbers this wave wrote into
:class:`FaultProfile`. Measuring rollback reliability against them measures the choice.
Rollback reliability, containment effectiveness, collateral rate, time-to-effect and
recovery success **against a real host are UNMEASURED** (ADR-0046), and every in-simulator
figure is named ``simulated_*`` so the caveat travels with the number.

Three constructions keep that from decaying into self-congratulation:

1. :attr:`SimulatedHost.host_kind` is a property returning a constant. There is no flag, no
   constructor argument and no subclass that makes a simulated host claim to be real.
2. There is **no** ``RealHost`` class, not even a stub. A stub is the thing someone fills
   in under deadline pressure; implementing one — with the privilege-drop, seccomp and
   capability analysis it needs — is follow-on work with its own ADR.
3. :data:`HOST_HANDLERS` has one handler for **every** catalog entry, asserted at import
   time in both directions. Stage 3 shipped seven of eight operator forms with no
   interpreter and measured nothing (ADR-0027); a catalog richer than its executor is a
   catalog that lies about what the system can do.

:class:`HostSnapshot` is read-only and is the only thing the planner, the twin and the cone
ever see, so no planning code can mutate the host even by accident (§35's privilege split).
"""

from __future__ import annotations

import json
import random
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Protocol

from pocketsec.stage0.contracts.common import ContractError, require_identifier
from pocketsec.stage1.state.security_state import SecurityStateV1
from pocketsec.stage5.operators.algebra import (
    DefensiveOperator,
    OperatorClass,
    ProcessIdentity,
    TargetKind,
)
from pocketsec.stage5.operators.catalog import CATALOG, RESTORATION_OPERATOR_IDS

if TYPE_CHECKING:  # pragma: no cover - annotations only
    # `Clock` lives in executor/identity.py, which belongs to a downstream work package.
    # A runtime import would invert the build order; the host only ever calls `now()`.
    from pocketsec.stage5.executor.identity import Clock

__all__ = [
    "HOST_HANDLERS",
    "MAX_SIMULATED_PROCESSES",
    "MAX_SIMULATED_SERVICES",
    "MAX_SIMULATED_SESSIONS",
    "MAX_VOLATILE_SIGNALS_PER_PROCESS",
    "SIMULATED_HOST_VERSION",
    "FaultProfile",
    "HostAdapter",
    "HostEffect",
    "HostFailure",
    "HostKind",
    "HostSnapshot",
    "ProcessRow",
    "ProcessState",
    "ServiceRow",
    "SimulatedHost",
]

SIMULATED_HOST_VERSION: str = "stage5-simulated-host-v0.1.0"

#: Bounded endpoint state, as everywhere else. A fixture that exceeds a bound is refused
#: rather than truncated, because a silently truncated host model would make a corpus
#: measure something other than what it declared.
MAX_SIMULATED_PROCESSES: int = 64
MAX_SIMULATED_SERVICES: int = 32
MAX_SIMULATED_SESSIONS: int = 16
MAX_VOLATILE_SIGNALS_PER_PROCESS: int = 16


class HostKind(StrEnum):
    """``REAL`` has no implementation in this repository, deliberately.

    The member exists so that a receipt can *state* which kind of host it came from and so
    that a gate check can require ``REAL`` for a criterion that a simulator cannot settle
    (G5.7, G5.11 fail by construction while only ``SIMULATED`` exists).
    """

    SIMULATED = "SIMULATED"
    REAL = "REAL"


class ProcessState(StrEnum):
    RUNNING = "RUNNING"
    SUSPENDED = "SUSPENDED"
    EXITED = "EXITED"


class HostFailure(StrEnum):
    """Why a typed operator did not take effect.

    ``ENFORCEMENT_SILENTLY_FAILED`` is the one that matters most: the call returns success
    and nothing changed, which is precisely the case "command success is not security
    success" (§20) exists to catch.
    """

    TARGET_GONE = "TARGET_GONE"
    PERMISSION = "PERMISSION"
    ENFORCEMENT_SILENTLY_FAILED = "ENFORCEMENT_SILENTLY_FAILED"
    DEPENDENCY_RESTART = "DEPENDENCY_RESTART"
    ROLLBACK_UNAVAILABLE = "ROLLBACK_UNAVAILABLE"
    TARGET_BINDING_CHANGED = "TARGET_BINDING_CHANGED"
    """At the instant of the act, the process at the pid is not the operator's identity, or
    the scoped subject no longer belongs to it. The host refused; nothing changed. This is
    the simulated analogue of acting through a pidfd rather than a pid (F1 / S5-SEC-05)."""


@dataclass(frozen=True, slots=True)
class HostEffect:
    """What one typed operator did. ``applied`` is about the call; nothing more."""

    applied: bool
    changed: tuple[str, ...]
    failure: HostFailure | None
    evidence_lost: tuple[str, ...]
    collateral_units: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "applied": self.applied,
            "changed": list(self.changed),
            "failure": None if self.failure is None else str(self.failure),
            "evidence_lost": list(self.evidence_lost),
            "collateral_units": list(self.collateral_units),
        }


@dataclass(frozen=True, slots=True)
class FaultProfile:
    """Deterministic, seeded fault injection.

    **Every probability here is a PARAMETER of the simulator, not a measurement of
    anything.** A rollback success rate obtained by setting ``rollback_failure_rate`` and
    counting outcomes measures the parameter. What it *can* honestly show is that the
    protocol handles the failure: that a failed rollback escalates and is never reported as
    success.
    """

    seed: int
    enforcement_failure_rate: float = 0.0
    rollback_failure_rate: float = 0.0
    pid_reuse_rate: float = 0.0
    dependency_restart_rate: float = 0.0
    attacker_adapts: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.seed, int) or isinstance(self.seed, bool):
            raise ContractError(f"FaultProfile.seed must be an int, got {self.seed!r}")
        for name in (
            "enforcement_failure_rate",
            "rollback_failure_rate",
            "pid_reuse_rate",
            "dependency_restart_rate",
        ):
            rate = getattr(self, name)
            if isinstance(rate, bool) or not isinstance(rate, (int, float)):
                raise ContractError(f"FaultProfile.{name} must be a number, got {rate!r}")
            if not 0.0 <= float(rate) <= 1.0:
                raise ContractError(f"FaultProfile.{name} must be within [0, 1], got {rate!r}")
        if not isinstance(self.attacker_adapts, bool):
            raise ContractError("FaultProfile.attacker_adapts must be a bool")

    def to_dict(self) -> dict[str, Any]:
        return {
            "seed": self.seed,
            "enforcement_failure_rate": self.enforcement_failure_rate,
            "rollback_failure_rate": self.rollback_failure_rate,
            "pid_reuse_rate": self.pid_reuse_rate,
            "dependency_restart_rate": self.dependency_restart_rate,
            "attacker_adapts": self.attacker_adapts,
            "note": "every rate is a chosen simulator parameter, not a measurement",
        }


@dataclass(frozen=True, slots=True)
class ProcessRow:
    """One process. ``volatile_signals`` is what is observable now and lost if it dies."""

    identity: ProcessIdentity
    state: ProcessState
    unit: str | None
    session_id: str | None
    socket_ids: tuple[str, ...]
    children: tuple[int, ...]
    volatile_signals: tuple[str, ...]
    #: Signals a preservation operator has actually CAPTURED for this identity. Filled by
    #: :meth:`SimulatedHost.snapshot`; a fixture row carries none. "Preserved" means this,
    #: not "the signal is listed on the row" (findings F4 / S5-SEC-01).
    preserved_signals: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.identity, ProcessIdentity):
            raise ContractError("ProcessRow.identity must be a ProcessIdentity")
        if not isinstance(self.state, ProcessState):
            raise ContractError("ProcessRow.state must be a ProcessState")
        for name, value in (("unit", self.unit), ("session_id", self.session_id)):
            if value is not None:
                require_identifier(value, f"ProcessRow.{name}")
        for socket_id in self.socket_ids:
            require_identifier(socket_id, "ProcessRow.socket_ids[]")
        if len(self.volatile_signals) > MAX_VOLATILE_SIGNALS_PER_PROCESS:
            raise ContractError(
                f"ProcessRow {self.identity.pid} holds {len(self.volatile_signals)} "
                f"volatile signals, bound is {MAX_VOLATILE_SIGNALS_PER_PROCESS}"
            )
        for signal in (*self.volatile_signals, *self.preserved_signals):
            require_identifier(signal, "ProcessRow.volatile_signals[]")

    def binds(self, kind: TargetKind, subject: str) -> bool:
        """Whether ``subject`` of ``kind`` belongs to this process, right now.

        The one predicate SENTINEL's precondition and :meth:`SimulatedHost.apply` both
        read, so "the subject belongs to the target" is one rule and not two that drift.
        """
        match kind:
            case TargetKind.PROCESS | TargetKind.HOST:
                return True
            case TargetKind.SOCKET:
                return subject in self.socket_ids
            case TargetKind.SESSION:
                return subject == self.session_id
            case TargetKind.SERVICE:
                return subject == self.unit

    def to_dict(self) -> dict[str, Any]:
        return {
            "pid": self.identity.pid,
            "identity_digest": self.identity.digest(),
            "state": str(self.state),
            "unit": self.unit,
            "session_id": self.session_id,
            "socket_ids": list(self.socket_ids),
            "children": list(self.children),
            "volatile_signals": list(self.volatile_signals),
            "preserved_signals": list(self.preserved_signals),
        }


@dataclass(frozen=True, slots=True)
class ServiceRow:
    unit: str
    running: bool
    constrained: bool
    restartable: bool
    depends_on: tuple[str, ...]
    healthy: bool

    def __post_init__(self) -> None:
        require_identifier(self.unit, "ServiceRow.unit")
        for dependency in self.depends_on:
            require_identifier(dependency, "ServiceRow.depends_on[]")

    def to_dict(self) -> dict[str, Any]:
        return {
            "unit": self.unit,
            "running": self.running,
            "constrained": self.constrained,
            "restartable": self.restartable,
            "depends_on": list(self.depends_on),
            "healthy": self.healthy,
        }


@dataclass(frozen=True, slots=True)
class HostSnapshot:
    """Read-only. The planner, the twin and the cone see ONLY this.

    They never receive the :class:`HostAdapter`, so no planning code can mutate the host
    even by accident — the privilege split of §35 expressed as a type rather than as a
    convention.
    """

    host_kind: HostKind
    at: int
    processes: tuple[ProcessRow, ...]
    services: tuple[ServiceRow, ...]
    sessions: tuple[str, ...]
    restricted_sockets: frozenset[str]
    security_state: SecurityStateV1
    host_version: str = SIMULATED_HOST_VERSION

    def process(self, pid: int) -> ProcessRow | None:
        for row in self.processes:
            if row.identity.pid == pid:
                return row
        return None

    def identity(self, pid: int) -> ProcessIdentity | None:
        row = self.process(pid)
        return None if row is None else row.identity

    def service(self, unit: str) -> ServiceRow | None:
        for row in self.services:
            if row.unit == unit:
                return row
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "host_kind": str(self.host_kind),
            "simulated": self.host_kind is HostKind.SIMULATED,
            "host_version": self.host_version,
            "at": self.at,
            "processes": [row.to_dict() for row in self.processes],
            "services": [row.to_dict() for row in self.services],
            "sessions": list(self.sessions),
            "restricted_sockets": sorted(self.restricted_sockets),
            "security_state": self.security_state.to_dict(),
        }

    def canonical_bytes(self) -> bytes:
        """Deterministic bytes, so two snapshots can be compared by digest."""
        return json.dumps(
            self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")


class HostAdapter(Protocol):
    """The privileged surface. Exactly four members, all taking typed arguments.

    There is no ``run``, no ``exec`` and no method that accepts a string: the only way to
    ask a host to do something is to hand it a :class:`DefensiveOperator`.
    """

    @property
    def host_kind(self) -> HostKind: ...

    def snapshot(self) -> HostSnapshot: ...

    def observe_identity(self, pid: int) -> ProcessIdentity | None: ...

    def apply(self, operator: DefensiveOperator, argv: tuple[str, ...]) -> HostEffect: ...


#: The catalog entries that are themselves somebody's rollback. ``rollback_failure_rate``
#: is consulted for exactly these, which is what makes "the rollback failed" a distinct
#: injectable fault from "the intervention failed".
_ROLLBACK_OPERATOR_IDS: frozenset[str] = RESTORATION_OPERATOR_IDS


class SimulatedHost:
    """A simulated Linux host. ``host_kind`` is ``SIMULATED`` and nothing changes that."""

    def __init__(
        self,
        *,
        processes: Sequence[ProcessRow],
        services: Sequence[ServiceRow],
        sessions: Sequence[str],
        security_state: SecurityStateV1,
        faults: FaultProfile,
        clock: Clock,
    ) -> None:
        if len(processes) > MAX_SIMULATED_PROCESSES:
            raise ContractError(
                f"{len(processes)} processes exceeds MAX_SIMULATED_PROCESSES="
                f"{MAX_SIMULATED_PROCESSES}"
            )
        if len(services) > MAX_SIMULATED_SERVICES:
            raise ContractError(
                f"{len(services)} services exceeds MAX_SIMULATED_SERVICES="
                f"{MAX_SIMULATED_SERVICES}"
            )
        if len(sessions) > MAX_SIMULATED_SESSIONS:
            raise ContractError(
                f"{len(sessions)} sessions exceeds MAX_SIMULATED_SESSIONS="
                f"{MAX_SIMULATED_SESSIONS}"
            )
        if not isinstance(security_state, SecurityStateV1):
            raise ContractError("SimulatedHost.security_state must be a SecurityStateV1")
        if not isinstance(faults, FaultProfile):
            raise ContractError("SimulatedHost.faults must be a FaultProfile")
        self._processes: dict[int, ProcessRow] = {}
        for row in processes:
            if row.identity.pid in self._processes:
                raise ContractError(f"duplicate pid {row.identity.pid} in the host fixture")
            self._processes[row.identity.pid] = row
        self._services: dict[str, ServiceRow] = {}
        for service in services:
            if service.unit in self._services:
                raise ContractError(f"duplicate unit {service.unit!r} in the host fixture")
            self._services[service.unit] = service
        self._sessions: list[str] = [require_identifier(s, "session") for s in sessions]
        self._security_state = security_state
        self._faults = faults
        self._clock = clock
        self._restricted_sockets: set[str] = set()
        self._traced: set[int] = set()
        #: Captured evidence, keyed by identity DIGEST, not pid: a pid is not an identity,
        #: and evidence captured from one process must not be credited to its pid's reuser.
        self._preserved: dict[str, set[str]] = {}
        self._apply_calls = 0
        self._advance_steps = 0
        self._next_pid = (max(self._processes) if self._processes else 1000) + 1

    # --- the HostAdapter surface ------------------------------------------------

    @property
    def host_kind(self) -> HostKind:
        """Always ``SIMULATED``. No argument, no flag, no subclass hook."""
        return HostKind.SIMULATED

    @property
    def apply_calls(self) -> int:
        """How many times :meth:`apply` was entered.

        The TOCTOU tests read this to assert the host was *not* touched when identity
        revalidation refused: "the action refused" and "the action happened to fail" are
        different claims and only a call count can tell them apart.
        """
        return self._apply_calls

    def snapshot(self) -> HostSnapshot:
        return HostSnapshot(
            host_kind=self.host_kind,
            at=self._clock.now(),
            processes=tuple(self._with_preserved(self._processes[pid])
                            for pid in sorted(self._processes)),
            services=tuple(self._services[unit] for unit in sorted(self._services)),
            sessions=tuple(sorted(self._sessions)),
            restricted_sockets=frozenset(self._restricted_sockets),
            security_state=self._security_state,
            host_version=SIMULATED_HOST_VERSION,
        )

    def observe_identity(self, pid: int) -> ProcessIdentity | None:
        """The identity currently at ``pid``, or ``None``.

        ``None`` for an exited process is the whole point: the executor reads it as
        ``EXITED`` rather than as a match, so a reaped target cannot be acted on.
        """
        row = self._processes.get(pid)
        if row is None or row.state is ProcessState.EXITED:
            return None
        return row.identity

    def apply(self, operator: DefensiveOperator, argv: tuple[str, ...]) -> HostEffect:
        """Apply one typed operator. The only privileged entry point.

        Refuses, before any state changes, an ``argv`` that is not the vector the operator
        itself assembles. A caller that assembled a vector some other way has by
        definition left the one code path that validates tokens, so the mismatch is a
        contract failure rather than an argument the host quietly prefers.
        """
        self._apply_calls += 1
        if type(operator) is not DefensiveOperator:
            raise ContractError(
                f"SimulatedHost.apply accepts only DefensiveOperator, got {type(operator)!r}"
            )
        expected = operator.argv()
        if tuple(argv) != expected:
            raise ContractError(
                f"argv {tuple(argv)!r} is not the vector {operator.spec.operator_id} "
                f"assembles ({expected!r}); there is one argument-vector provenance"
            )
        handler = HOST_HANDLERS.get(operator.spec.operator_id)
        if handler is None:
            raise ContractError(
                f"no host handler for {operator.spec.operator_id!r}; a catalog entry "
                "without a handler measures nothing (ADR-0027)"
            )
        if not self._bound_at_act(operator):
            # Checked inside the act, not before it: the executor's revalidation and this
            # call are two host calls, and a real kernel can recycle the pid between them.
            return _binding_changed()
        if operator.spec.operator_class >= OperatorClass.O2_REVERSIBLE_RESTRICT and self._hit(
            self._faults.enforcement_failure_rate, f"enforce:{operator.spec.operator_id}"
        ):
            # The call "succeeds" and the host is unchanged. Post-action verification is
            # the only thing that can notice, which is exactly what G5.10 injects.
            return HostEffect(
                applied=True,
                changed=(),
                failure=HostFailure.ENFORCEMENT_SILENTLY_FAILED,
                evidence_lost=(),
                collateral_units=(),
            )
        if operator.spec.operator_id in _ROLLBACK_OPERATOR_IDS and self._hit(
            self._faults.rollback_failure_rate, f"rollback:{operator.spec.operator_id}"
        ):
            return HostEffect(
                applied=False,
                changed=(),
                failure=HostFailure.ROLLBACK_UNAVAILABLE,
                evidence_lost=(),
                collateral_units=(),
            )
        return handler(self, operator)

    # --- environment stepping ---------------------------------------------------

    def advance(self, seconds: int) -> None:
        """Step the host forward. **Does not advance the clock.**

        The clock is injected and owned by the caller, so lease-expiry tests can advance
        the host without advancing time and vice versa. A host that moved the clock would
        make "the lease expired because something else called in" indistinguishable from
        "the lease expired because it was due".
        """
        if not isinstance(seconds, int) or isinstance(seconds, bool) or seconds < 0:
            raise ContractError(f"advance(seconds) must be a non-negative int, got {seconds!r}")
        self._advance_steps += 1
        self._reuse_pids()
        self._restart_dependencies()
        if self._faults.attacker_adapts:
            self._adapt()

    def reap(self, pid: int, *, reuse_pid_for: ProcessIdentity | None = None) -> None:
        """Exit the process at ``pid``, optionally handing the pid to a new identity.

        This is the TOCTOU race made explicit: between plan and commit the pid can be
        reused, and the executor must refuse rather than act on whatever holds the number
        now. ``reuse_pid_for`` must carry the same pid, because a fixture that reuses a pid
        with a different pid in the identity would silently test nothing.
        """
        row = self._processes.get(pid)
        if row is None:
            raise ContractError(f"cannot reap unknown pid {pid}")
        self._processes[pid] = replace(row, state=ProcessState.EXITED, volatile_signals=())
        if reuse_pid_for is None:
            return
        if reuse_pid_for.pid != pid:
            raise ContractError(
                f"reuse_pid_for.pid is {reuse_pid_for.pid}, expected {pid}; a pid-reuse "
                "fixture whose identity names a different pid tests nothing"
            )
        if reuse_pid_for.digest() == row.identity.digest():
            raise ContractError(
                "reuse_pid_for is the same identity, so nothing was substituted; "
                "a pid is not an identity and the fixture must prove it"
            )
        self._processes[pid] = ProcessRow(
            identity=reuse_pid_for,
            state=ProcessState.RUNNING,
            unit=row.unit,
            session_id=row.session_id,
            socket_ids=(),
            children=(),
            volatile_signals=(),
        )

    # --- internals the handlers use --------------------------------------------

    def _hit(self, rate: float, kind: str) -> bool:
        """A seeded draw. Deterministic in (seed, call index, kind), so a run replays."""
        if rate <= 0.0:
            return False
        key = f"{self._faults.seed}:{self._apply_calls}:{self._advance_steps}:{kind}"
        return random.Random(key).random() < rate

    def _bound_at_act(self, operator: DefensiveOperator) -> bool:
        """The act's own identity check: exact identity at the pid, subject still owned.

        An exited or absent target is left to the handler, which reports TARGET_GONE.
        """
        row = self._processes.get(operator.target.identity.pid)
        if row is None or row.state is ProcessState.EXITED:
            return True
        scope = operator.target.scope
        return row.identity == operator.target.identity and row.binds(scope.kind, scope.subject)

    def _with_preserved(self, row: ProcessRow) -> ProcessRow:
        captured = self._preserved.get(row.identity.digest(), set())
        return replace(row, preserved_signals=tuple(sorted(captured)))

    def _row(self, operator: DefensiveOperator) -> ProcessRow | None:
        row = self._processes.get(operator.target.identity.pid)
        if row is None or row.state is ProcessState.EXITED:
            return None
        return row

    def _unpreserved(self, row: ProcessRow) -> tuple[str, ...]:
        preserved = self._preserved.get(row.identity.digest(), set())
        return tuple(sorted(set(row.volatile_signals) - preserved))

    def _collateral_for(self, row: ProcessRow) -> tuple[str, ...]:
        if row.unit is None:
            return ()
        service = self._services.get(row.unit)
        if service is None or not service.running:
            return ()
        return (row.unit,)

    def _reuse_pids(self) -> None:
        for pid in sorted(self._processes):
            row = self._processes[pid]
            if row.state is not ProcessState.RUNNING:
                continue
            if not self._hit(self._faults.pid_reuse_rate, f"reuse:{pid}"):
                continue
            substitute = ProcessIdentity(
                pid=pid,
                start_time_ticks=row.identity.start_time_ticks + 1,
                uid=row.identity.uid + 1,
                executable_digest=None,
                cgroup_id=row.identity.cgroup_id,
                namespace_id=row.identity.namespace_id,
            )
            self.reap(pid, reuse_pid_for=substitute)

    def _restart_dependencies(self) -> None:
        for unit in sorted(self._services):
            service = self._services[unit]
            if not service.constrained:
                continue
            if not self._hit(self._faults.dependency_restart_rate, f"dep:{unit}"):
                continue
            for dependency in service.depends_on:
                dependent = self._services.get(dependency)
                if dependent is not None:
                    self._services[dependency] = replace(dependent, running=True, healthy=False)

    def _adapt(self) -> None:
        """Bounded adversary adaptation (§25): replace a contained process, once per step.

        Only observed/learned adaptations are represented — process replacement and a new
        socket — because unrestricted game-theoretic search is explicitly out of scope.
        """
        if len(self._processes) >= MAX_SIMULATED_PROCESSES:
            return
        for pid in sorted(self._processes):
            row = self._processes[pid]
            if row.state is ProcessState.RUNNING:
                continue
            replacement_pid = self._next_pid
            self._next_pid += 1
            self._processes[replacement_pid] = ProcessRow(
                identity=ProcessIdentity(
                    pid=replacement_pid,
                    start_time_ticks=row.identity.start_time_ticks + 100,
                    uid=row.identity.uid,
                    executable_digest=None,
                    cgroup_id=row.identity.cgroup_id,
                    namespace_id=row.identity.namespace_id,
                ),
                state=ProcessState.RUNNING,
                unit=row.unit,
                session_id=row.session_id,
                socket_ids=(f"sock-{replacement_pid}",),
                children=(),
                volatile_signals=row.volatile_signals,
            )
            return


# --- handlers, one per catalog entry -----------------------------------------------


def _target_gone() -> HostEffect:
    return HostEffect(
        applied=False,
        changed=(),
        failure=HostFailure.TARGET_GONE,
        evidence_lost=(),
        collateral_units=(),
    )


def _binding_changed() -> HostEffect:
    return HostEffect(
        applied=False,
        changed=(),
        failure=HostFailure.TARGET_BINDING_CHANGED,
        evidence_lost=(),
        collateral_units=(),
    )


def _observed(changed: tuple[str, ...]) -> HostEffect:
    return HostEffect(
        applied=True, changed=changed, failure=None, evidence_lost=(), collateral_units=()
    )


def _observe_process_metadata(host: SimulatedHost, operator: DefensiveOperator) -> HostEffect:
    row = host._row(operator)
    if row is None:
        return _target_gone()
    return _observed((f"observed:{row.identity.pid}",))


def _hash_executable(host: SimulatedHost, operator: DefensiveOperator) -> HostEffect:
    row = host._row(operator)
    if row is None:
        return _target_gone()
    if row.identity.executable_digest is None:
        # An absent digest is an honest observation, not a failure of the call. The
        # executor reads it as UNOBSERVABLE, never as a match.
        return _observed(())
    return _observed((f"hashed:{row.identity.executable_digest}",))


def _trace_process_bounded(host: SimulatedHost, operator: DefensiveOperator) -> HostEffect:
    row = host._row(operator)
    if row is None:
        return _target_gone()
    host._traced.add(row.identity.pid)
    return _observed((f"traced:{row.identity.pid}",))


def _stop_trace(host: SimulatedHost, operator: DefensiveOperator) -> HostEffect:
    pid = operator.target.identity.pid
    if pid not in host._traced:
        return _observed(())
    host._traced.discard(pid)
    return _observed((f"trace_stopped:{pid}",))


def _snapshot_process_state(host: SimulatedHost, operator: DefensiveOperator) -> HostEffect:
    row = host._row(operator)
    if row is None:
        return _target_gone()
    host._preserved.setdefault(row.identity.digest(), set()).add("process_state")
    return _observed((f"snapshot:{row.identity.pid}",))


def _preserve_volatile_evidence(host: SimulatedHost, operator: DefensiveOperator) -> HostEffect:
    row = host._row(operator)
    if row is None:
        return _target_gone()
    host._preserved.setdefault(row.identity.digest(), set()).update(row.volatile_signals)
    return _observed(tuple(f"preserved:{signal}" for signal in sorted(row.volatile_signals)))


def _restrict_local_socket(host: SimulatedHost, operator: DefensiveOperator) -> HostEffect:
    socket_id = operator.target.scope.subject
    if not any(socket_id in row.socket_ids for row in host._processes.values()):
        return _target_gone()
    host._restricted_sockets.add(socket_id)
    return HostEffect(
        applied=True,
        changed=(f"socket_restricted:{socket_id}",),
        failure=None,
        evidence_lost=(),
        collateral_units=(),
    )


def _release_local_socket(host: SimulatedHost, operator: DefensiveOperator) -> HostEffect:
    socket_id = operator.target.scope.subject
    if socket_id not in host._restricted_sockets:
        return _observed(())
    host._restricted_sockets.discard(socket_id)
    return _observed((f"socket_released:{socket_id}",))


def _suspend_process(host: SimulatedHost, operator: DefensiveOperator) -> HostEffect:
    row = host._row(operator)
    if row is None:
        return _target_gone()
    lost = host._unpreserved(row)
    host._processes[row.identity.pid] = replace(row, state=ProcessState.SUSPENDED)
    return HostEffect(
        applied=True,
        changed=(f"suspended:{row.identity.pid}",),
        failure=None,
        # DEGRADES_VOLATILE: a stopped process stops producing. Whatever was not
        # preserved first is gone, which is why the evidence gate runs BEFORE the action.
        evidence_lost=lost,
        collateral_units=host._collateral_for(row),
    )


def _resume_process(host: SimulatedHost, operator: DefensiveOperator) -> HostEffect:
    row = host._processes.get(operator.target.identity.pid)
    if row is None or row.state is ProcessState.EXITED:
        return _target_gone()
    if row.state is ProcessState.RUNNING:
        return _observed(())
    host._processes[row.identity.pid] = replace(row, state=ProcessState.RUNNING)
    return _observed((f"resumed:{row.identity.pid}",))


def _revoke_local_session(host: SimulatedHost, operator: DefensiveOperator) -> HostEffect:
    session_id = operator.target.scope.subject
    if session_id not in host._sessions:
        return _target_gone()
    host._sessions.remove(session_id)
    affected = tuple(
        sorted(
            row.unit
            for row in host._processes.values()
            if row.session_id == session_id and row.unit is not None
        )
    )
    return HostEffect(
        applied=True,
        changed=(f"session_revoked:{session_id}",),
        failure=None,
        evidence_lost=(),
        collateral_units=affected,
    )


def _constrain_service(host: SimulatedHost, operator: DefensiveOperator) -> HostEffect:
    unit = operator.target.scope.subject
    service = host._services.get(unit)
    if service is None or not service.running:
        return _target_gone()
    if not service.restartable:
        # SERVICE_HAS_RESTART_SEMANTICS is a precondition; a host that cannot restart the
        # unit cannot release it either, so refusing here is the fail-closed reading.
        return HostEffect(
            applied=False,
            changed=(),
            failure=HostFailure.ROLLBACK_UNAVAILABLE,
            evidence_lost=(),
            collateral_units=(),
        )
    host._services[unit] = replace(service, constrained=True, healthy=False)
    if host._hit(host._faults.dependency_restart_rate, f"constrain:{unit}"):
        for dependency in service.depends_on:
            dependent = host._services.get(dependency)
            if dependent is not None:
                host._services[dependency] = replace(dependent, running=True, healthy=False)
        return HostEffect(
            applied=True,
            changed=(f"service_constrained:{unit}",),
            failure=HostFailure.DEPENDENCY_RESTART,
            evidence_lost=(),
            collateral_units=tuple(sorted(service.depends_on)),
        )
    return HostEffect(
        applied=True,
        changed=(f"service_constrained:{unit}",),
        failure=None,
        evidence_lost=(),
        collateral_units=(),
    )


def _release_service(host: SimulatedHost, operator: DefensiveOperator) -> HostEffect:
    unit = operator.target.scope.subject
    service = host._services.get(unit)
    if service is None:
        return _target_gone()
    if not service.constrained:
        return _observed(())
    host._services[unit] = replace(service, constrained=False, healthy=True)
    return _observed((f"service_released:{unit}",))


def _terminate_process(host: SimulatedHost, operator: DefensiveOperator) -> HostEffect:
    row = host._row(operator)
    if row is None:
        return _target_gone()
    lost = host._unpreserved(row)
    collateral = host._collateral_for(row)
    host._processes[row.identity.pid] = replace(
        row, state=ProcessState.EXITED, volatile_signals=()
    )
    return HostEffect(
        applied=True,
        changed=(f"terminated:{row.identity.pid}",),
        failure=None,
        evidence_lost=lost,
        collateral_units=collateral,
    )


#: One handler per catalog entry. The import-time check below is the mechanical form of
#: Stage 3's lesson: a vocabulary richer than its interpreter measures nothing.
HOST_HANDLERS: Mapping[str, Callable[[SimulatedHost, DefensiveOperator], HostEffect]] = (
    MappingProxyType(
        {
            "OBSERVE_PROCESS_METADATA": _observe_process_metadata,
            "HASH_EXECUTABLE": _hash_executable,
            "TRACE_PROCESS_BOUNDED": _trace_process_bounded,
            "STOP_TRACE": _stop_trace,
            "SNAPSHOT_PROCESS_STATE": _snapshot_process_state,
            "PRESERVE_VOLATILE_EVIDENCE": _preserve_volatile_evidence,
            "RESTRICT_LOCAL_SOCKET": _restrict_local_socket,
            "RELEASE_LOCAL_SOCKET": _release_local_socket,
            "SUSPEND_PROCESS": _suspend_process,
            "RESUME_PROCESS": _resume_process,
            "REVOKE_LOCAL_SESSION": _revoke_local_session,
            "CONSTRAIN_SERVICE": _constrain_service,
            "RELEASE_SERVICE": _release_service,
            "TERMINATE_PROCESS": _terminate_process,
        }
    )
)

_MISSING_HANDLERS = tuple(sorted(set(CATALOG) - set(HOST_HANDLERS)))
_EXTRA_HANDLERS = tuple(sorted(set(HOST_HANDLERS) - set(CATALOG)))
if _MISSING_HANDLERS or _EXTRA_HANDLERS:  # pragma: no cover - an ImportError is the point
    raise ContractError(
        f"host handler set disagrees with the catalog: missing={_MISSING_HANDLERS}, "
        f"extra={_EXTRA_HANDLERS}"
    )
