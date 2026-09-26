"""D5.11's race, actually built and actually run — the TOCTOU and PID-reuse suites.

Architecture §17 says target identity is revalidated immediately before
intervention. That sentence is the single property in this stage most likely to
be implemented as a comment, so this module builds the race rather than
describing it: the target's identity is changed *after* PREPARE has finished and
*before* COMMIT reaches ``host.apply``, and the suites assert that the executor
refuses instead of acting on the wrong process.

**The lab cannot build privilege; it is handed it.** Spec §5.1 rule 4 permits the
name ``TransactionalExecutor`` only under ``executor/`` and ``recovery/``, so every
entry point here takes a ``build_executor`` factory supplied by its caller — the
gate or the test file — and depends only on the :class:`ExecutorLike` protocol. The
rule reads as a typing inconvenience and is not: a fixture that could assemble its
own executor could quietly wire a permissive kernel into one, and then a race that
"passed" would prove nothing.

**How the race is injected, stated precisely because it is the whole point.**
:class:`RacingHost` is a :class:`~pocketsec.stage5.host.simulated.HostAdapter`
that wraps a :class:`~pocketsec.stage5.host.simulated.SimulatedHost` and calls
``reap(pid, reuse_pid_for=...)`` on it in the middle of one transaction. The
substitution is triggered by ``observe_identity`` call count rather than by a
timer: PREPARE observes the identity once, for SENTINEL's
``target_identity`` check, and COMMIT observes it again immediately before
applying. Firing on the *second* call is therefore exactly "between ``_prepare``
and ``_commit``". Firing on the first would make SENTINEL deny, which is a
different — and weaker — test: it would prove the kernel works, not that the
executor closed the window after the kernel spoke.

:data:`PREPARE_IDENTITY_OBSERVATIONS` is the number that couples this lab to the
executor's PREPARE, and
``tests/test_stage5_executor.py::test_prepare_observes_the_identity_exactly_once``
counts the real calls in a clean run so the two cannot drift apart silently.

**Four variants, because there are four ways to stop being the same process.**
EXITED, PID_REUSED, EXECUTABLE_CHANGED and UID_CHANGED. Each must produce
``Outcome.REFUSED_IDENTITY``, an **unchanged** ``host.apply`` call count, and a
substituted process that is untouched in the post-snapshot.

**What this module is not.** Every number it produces is a property of
:class:`~pocketsec.stage5.host.simulated.SimulatedHost`, which this wave wrote.
"Four of four races refused" is a real, falsifiable statement about the
executor's control flow; it is **not** a measurement of a Linux kernel's pid
recycling behaviour, and the fixture key minted here is a lab key for a simulated
host, not a credential.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any, Protocol

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage0.contracts.threat_prediction_v1 import Verdict
from pocketsec.stage1.state.security_state import SecurityStateV1
from pocketsec.stage4.stage5_interface import CBFResolutionV1
from pocketsec.stage5.authority.capability import (
    AuthorityGrant,
    GrantSource,
    required_authority,
)
from pocketsec.stage5.authority.tokens import CapabilityToken, TokenStore
from pocketsec.stage5.constitution.invariants import FROZEN_CONSTITUTION
from pocketsec.stage5.constitution.schema import (
    DEFAULT_MISSION_INVARIANTS,
    MissionInvariantSet,
)
from pocketsec.stage5.executor.identity import (
    IdentityRevalidation,
    ManualClock,
    identity_digest,
)
from pocketsec.stage5.executor.transactional import Outcome, TransactionReceipt
from pocketsec.stage5.host.simulated import (
    FaultProfile,
    HostEffect,
    HostKind,
    HostSnapshot,
    ProcessRow,
    ProcessState,
    ServiceRow,
    SimulatedHost,
)
from pocketsec.stage5.operators.algebra import (
    DefensiveOperator,
    ProcessIdentity,
    ProcessTarget,
    TargetScope,
)
from pocketsec.stage5.operators.catalog import spec

__all__ = [
    "PREPARE_IDENTITY_OBSERVATIONS",
    "RACE_OPERATOR_ID",
    "RACE_VARIANTS",
    "REQUIRED_VOLATILE_SIGNALS",
    "ExecutorFactory",
    "ExecutorLike",
    "RaceSetup",
    "RacingHost",
    "TOCTOURace",
    "build_race_setup",
    "pid_reuse_suite",
    "run_race",
    "toctou_suite",
]

#: ``TransactionalExecutor._prepare`` observes the target identity once, for
#: SENTINEL's ``target_identity`` check. The race therefore fires on the next
#: observation, which is the one inside ``_commit``. Pinned by a test.
PREPARE_IDENTITY_OBSERVATIONS: int = 1

#: O2, fully reversible, ``NEUTRAL`` on evidence, rollback
#: ``RELEASE_LOCAL_SOCKET``. At class O2 the action is leased, so the race
#: exercises the lease path as well as the identity path.
#:
#: **Why not SUSPEND_PROCESS**, which reads as the sharper harm. Under
#: ``DEFAULT_MISSION_INVARIANTS`` plus ``DEFAULT_RETENTION`` no
#: ``DEGRADES_VOLATILE`` operator is reachable at all: MI-04 (EVIDENCE_RETENTION
#: of ``process_memory_map``) denies the action whenever the target carries that
#: signal, and the evidence gate returns INSUFFICIENT_EVIDENCE when it does not,
#: because ``required_evidence()`` asks for the same signal. SENTINEL therefore
#: answers ``MISSION_INVARIANT`` before COMMIT is reached, and a race that ends in
#: a SENTINEL denial proves the kernel works rather than proving the executor
#: closed the check-to-use window. Measured, not assumed: a SUSPEND_PROCESS run
#: through this rig returns ``REFUSED_SENTINEL`` with reason ``MISSION_INVARIANT``.
#: Lowering the invariant set to make the sharper fixture work would be weakening a
#: safety policy to make a test pass, so the fixture moved instead and the
#: contradiction is reported.
RACE_OPERATOR_ID: str = "RESTRICT_LOCAL_SOCKET"

#: The four ways a target stops being the process the plan was about.
RACE_VARIANTS: tuple[str, ...] = (
    "EXITED",
    "PID_REUSED",
    "EXECUTABLE_CHANGED",
    "UID_CHANGED",
)

_TARGET_PID: int = 4101
_SUBSTITUTE_PID: int = 4101  # the kernel recycles the number; that is the attack
_TARGET_START_TICKS: int = 900_100
_SUBSTITUTE_START_TICKS: int = 900_777
_TARGET_UID: int = 1000
_SUBSTITUTE_UID: int = 0
_BYSTANDER_PID: int = 4102

#: What the target must expose for the evidence gate to return PRESERVED:
#: ``DEFAULT_MISSION_INVARIANTS.required_evidence()`` asks for
#: ``process_memory_map``, and it is deliberately NOT in
#: ``DEFAULT_RETENTION.uniquely_necessary``, so a DEGRADES_VOLATILE operator is
#: permitted and the race — not the evidence gate — decides the outcome.
REQUIRED_VOLATILE_SIGNALS: tuple[str, ...] = ("process_memory_map",)

#: The scope subject for :data:`RACE_OPERATOR_ID`. It must name a socket the
#: target process actually holds, or the host reports TARGET_GONE for an unrelated
#: reason.
_RACE_SUBJECT: str = "sock.lab.1"

_TARGET_DIGEST = "sha256:" + "a1" * 32
_SUBSTITUTE_DIGEST = "sha256:" + "b2" * 32


@dataclass(frozen=True, slots=True)
class TOCTOURace:
    """One race, run end to end, with everything needed to judge it.

    ``apply_calls`` is counted by :class:`RacingHost` rather than read out of the
    simulated host, so the count is independent of anything the host model might
    do with its own bookkeeping.
    """

    variant: str
    expected_revalidation: IdentityRevalidation
    observed_revalidation: IdentityRevalidation
    outcome: Outcome
    apply_calls: int
    refused: bool
    substitute_untouched: bool
    target_digest: str
    host_kind: HostKind
    simulated: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "variant": self.variant,
            "expected_revalidation": str(self.expected_revalidation),
            "observed_revalidation": str(self.observed_revalidation),
            "outcome": str(self.outcome),
            "apply_calls": self.apply_calls,
            "refused": self.refused,
            "substitute_untouched": self.substitute_untouched,
            "target_digest": self.target_digest,
            "host_kind": str(self.host_kind),
            "simulated": self.simulated,
        }


class RacingHost:
    """A host adapter that substitutes the target between PREPARE and COMMIT.

    It is a wrapper rather than a subclass so that ``SimulatedHost.host_kind``
    still reports the truth: this adapter forwards it and cannot claim to be real.
    """

    __slots__ = ("_apply_calls", "_fired", "_inner", "_observations", "_pid", "_substitute")

    def __init__(
        self,
        *,
        inner: SimulatedHost,
        pid: int,
        substitute: ProcessIdentity | None,
        fire_after: int = PREPARE_IDENTITY_OBSERVATIONS,
    ) -> None:
        self._inner = inner
        self._pid = pid
        self._substitute = substitute
        self._observations = 0
        self._apply_calls = 0
        self._fired = fire_after

    @property
    def host_kind(self) -> HostKind:
        return self._inner.host_kind

    def snapshot(self) -> HostSnapshot:
        return self._inner.snapshot()

    def observe_identity(self, pid: int) -> ProcessIdentity | None:
        """Race here: the substitution happens before the answer COMMIT will use."""
        self._observations += 1
        if self._observations == self._fired + 1:
            self._inner.reap(self._pid, reuse_pid_for=self._substitute)
        return self._inner.observe_identity(pid)

    def apply(self, operator: DefensiveOperator, argv: tuple[str, ...]) -> HostEffect:
        self._apply_calls += 1
        return self._inner.apply(operator, argv)

    def apply_calls(self) -> int:
        return self._apply_calls

    def observations(self) -> int:
        return self._observations


def _target_identity() -> ProcessIdentity:
    """The identity the plan is about. Its ``executable_digest`` is non-``None`` so
    the EXECUTABLE_CHANGED and UID_CHANGED variants are distinguishable — with a
    ``None`` digest both would collapse into UNOBSERVABLE (spec §9.2 item 8)."""
    return ProcessIdentity(
        pid=_TARGET_PID,
        start_time_ticks=_TARGET_START_TICKS,
        uid=_TARGET_UID,
        executable_digest=_TARGET_DIGEST,
        cgroup_id="cgroup.user.slice",
        namespace_id="ns.host",
    )


def _substitute_for(variant: str) -> tuple[ProcessIdentity | None, IdentityRevalidation]:
    """Map a variant to the identity that replaces the target, and to the answer
    ``revalidate`` must give. A ``None`` substitute means the pid is simply gone."""
    target = _target_identity()
    if variant == "EXITED":
        return None, IdentityRevalidation.EXITED
    if variant == "PID_REUSED":
        return (
            replace(target, start_time_ticks=_SUBSTITUTE_START_TICKS, pid=_SUBSTITUTE_PID),
            IdentityRevalidation.PID_REUSED,
        )
    if variant == "EXECUTABLE_CHANGED":
        return (
            replace(target, executable_digest=_SUBSTITUTE_DIGEST),
            IdentityRevalidation.EXECUTABLE_CHANGED,
        )
    if variant == "UID_CHANGED":
        return replace(target, uid=_SUBSTITUTE_UID), IdentityRevalidation.UID_CHANGED
    raise ContractError(f"unknown race variant {variant!r}; expected one of {RACE_VARIANTS}")


def _bystander_identity() -> ProcessIdentity:
    return ProcessIdentity(
        pid=_BYSTANDER_PID,
        start_time_ticks=901_200,
        uid=_TARGET_UID,
        executable_digest="sha256:" + "c3" * 32,
        cgroup_id="cgroup.user.slice",
        namespace_id="ns.host",
    )


def race_resolution(*, incident_id: str) -> CBFResolutionV1:
    """A minimal, valid Stage 4 handoff.

    Every value here is a **fixture**. The ``support`` figures are numbers this
    module wrote, not measurements of anything, and the resolution exists only so
    the executor has the input its contract requires.
    """
    return CBFResolutionV1(
        resolution_id=f"res.{incident_id}",
        incident_id=incident_id,
        epoch_id=1,
        verdict=Verdict.MALICIOUS,
        identifiability="IDENTIFIED",
        hypotheses=(
            {
                "mechanism_id": "privilege_escalation.local",
                "support": 0.91,
                "consequence": "privilege_escalation",
                "uncertainty": 0.09,
                "claim_ids": [],
                "evidence_digests": [],
            },
        ),
        consequence_distribution={"privilege_escalation": 0.91, "benign_admin": 0.09},
        claim_graph={},
        evidence_lineage=(),
        uncertainty=0.09,
        shadow={},
        information_gaps=(),
        truncations=(),
        degradations=(),
    )


def _host_for(*, variant: str, seed: int, clock: ManualClock) -> SimulatedHost:
    """A two-process host: the target, and a bystander that must stay untouched.

    The target belongs to no unit and carries exactly the volatile signals the
    default mission invariants require and nothing the retention policy calls
    uniquely necessary, so neither the evidence-preservation gate nor the mission
    invariants can refuse the action for an unrelated reason. The race must be the
    only thing the suite measures; a refusal for the wrong reason would look like a
    pass.
    """
    del variant
    return SimulatedHost(
        processes=[
            ProcessRow(
                identity=_target_identity(),
                state=ProcessState.RUNNING,
                unit=None,
                session_id="session.lab",
                socket_ids=("sock.lab.1",),
                children=(),
                volatile_signals=REQUIRED_VOLATILE_SIGNALS,
            ),
            ProcessRow(
                identity=_bystander_identity(),
                state=ProcessState.RUNNING,
                unit=None,
                session_id="session.lab",
                socket_ids=(),
                children=(),
                volatile_signals=(),
            ),
        ],
        services=[
            ServiceRow(
                unit="lab-noncritical.service",
                running=True,
                constrained=False,
                restartable=True,
                depends_on=(),
                healthy=True,
            )
        ],
        sessions=["session.lab"],
        security_state=SecurityStateV1(),
        faults=FaultProfile(seed=seed, pid_reuse_rate=1.0),
        clock=clock,
    )


class ExecutorLike(Protocol):
    """What this lab needs from the privileged executor, and nothing more.

    A Protocol rather than an import of ``TransactionalExecutor``, for a reason that
    is a boundary property and not a typing preference: spec §5.1 rule 4 permits
    that name only under ``executor/`` and ``recovery/``, so a module under
    ``labs/`` must be *handed* the capability to execute rather than able to build
    it. That is the stronger arrangement anyway — this lab cannot assemble a
    privileged executor at all, so a fixture here can never quietly wire a
    permissive kernel into one.
    """

    def execute(
        self,
        operator: DefensiveOperator,
        token: CapabilityToken,
        *,
        resolution: CBFResolutionV1,
    ) -> TransactionReceipt: ...


#: Builds the privileged rig for one race setup. Supplied by the caller — the gate
#: or the test file — because only they may name ``TransactionalExecutor``.
ExecutorFactory = Callable[["RaceSetup"], ExecutorLike]


@dataclass(frozen=True, slots=True)
class RaceSetup:
    """Everything one race needs except the executor itself."""

    variant: str
    clock: ManualClock
    inner: SimulatedHost
    host: RacingHost
    invariants: MissionInvariantSet
    tokens: TokenStore
    operator: DefensiveOperator
    token: CapabilityToken
    resolution: CBFResolutionV1
    expected_revalidation: IdentityRevalidation
    substitute: ProcessIdentity | None


def build_race_setup(
    variant: str, *, seed: int = 23, invariants: MissionInvariantSet | None = None
) -> RaceSetup:
    """Assemble the host, the racing adapter, the operator and its token.

    The token is minted from a per-call random key. There is no key constant in this
    repository: a fixture key that looks like a secret is how a fixture key becomes
    a production one.
    """
    substitute, expected = _substitute_for(variant)
    clock = ManualClock(at=1_000)
    inner = _host_for(variant=variant, seed=seed, clock=clock)
    host = RacingHost(inner=inner, pid=_TARGET_PID, substitute=substitute)
    mission = DEFAULT_MISSION_INVARIANTS if invariants is None else invariants
    operator_spec = spec(RACE_OPERATOR_ID)
    operator = DefensiveOperator(
        spec=operator_spec,
        target=ProcessTarget(
            identity=_target_identity(),
            # The identity is a process either way — that is what is revalidated —
            # while the scope is whatever the catalog entry declares it acts on.
            scope=TargetScope(kind=operator_spec.target_kind, subject=_RACE_SUBJECT),
        ),
        incident_id=f"inc.race.{variant.lower()}",
        ttl_seconds=300,
        evidence_refs=(),
    )
    tokens = TokenStore(key=secrets.token_bytes(32), signer="stage5.labs.toctou", clock=clock)
    token = tokens.mint(
        grant=AuthorityGrant(
            authority=required_authority(operator_spec),
            granted_by=GrantSource.POLICY,
            policy_version=FROZEN_CONSTITUTION.policy_version,
            subject_operator_id=operator_spec.operator_id,
            detail="TOCTOU lab: policy grant at the operator's own authority class",
        ),
        operator=operator,
        action_id=f"act.race.{variant.lower()}",
        ttl_seconds=300,
    )
    return RaceSetup(
        variant=variant,
        clock=clock,
        inner=inner,
        host=host,
        invariants=mission,
        tokens=tokens,
        operator=operator,
        token=token,
        resolution=race_resolution(incident_id=operator.incident_id),
        expected_revalidation=expected,
        substitute=substitute,
    )


def run_race(
    variant: str, *, build_executor: ExecutorFactory, seed: int = 23
) -> tuple[TOCTOURace, TransactionReceipt]:
    """Run one race and report what happened, refusal and all."""
    setup = build_race_setup(variant, seed=seed)
    before = setup.inner.snapshot()
    receipt = build_executor(setup).execute(
        setup.operator, setup.token, resolution=setup.resolution
    )
    after = setup.inner.snapshot()
    race = TOCTOURace(
        variant=variant,
        expected_revalidation=setup.expected_revalidation,
        observed_revalidation=receipt.identity_revalidation,
        outcome=receipt.outcome,
        apply_calls=setup.host.apply_calls(),
        refused=receipt.outcome is Outcome.REFUSED_IDENTITY,
        substitute_untouched=_substitute_untouched(setup, before, after),
        target_digest=identity_digest(setup.operator.target.identity),
        host_kind=receipt.host_kind,
        simulated=receipt.simulated,
    )
    return race, receipt


def _substitute_untouched(setup: RaceSetup, before: HostSnapshot, after: HostSnapshot) -> bool:
    """True when nothing that replaced the target was disturbed, on every axis the race
    operator can change.

    For the EXITED variant there is no substitute, so the bystander stands in: the
    assertion is still "no other process was acted upon", which is the harm a pid
    substitution actually causes. Finding F9: this used to check only that the process
    was still RUNNING, but :data:`RACE_OPERATOR_ID` restricts a socket and never changes
    a process's state, so the check could not fail. It now also demands that the
    restricted-socket set, the services and the sessions are exactly as before.
    """
    pid = _BYSTANDER_PID if setup.substitute is None else setup.substitute.pid
    row = after.process(pid)
    return (
        row is not None
        and row.state is ProcessState.RUNNING
        and after.restricted_sockets == before.restricted_sockets
        and after.services == before.services
        and after.sessions == before.sessions
    )


def pid_reuse_suite(
    *, build_executor: ExecutorFactory, seed: int = 23
) -> tuple[TOCTOURace, ...]:
    """§33's "PID reuse / target substitution" family, as a required regression.

    Only the two variants where the pid is genuinely re-occupied: the number is
    reused and the occupant is a different process.
    """
    return tuple(
        run_race(variant, build_executor=build_executor, seed=seed)[0]
        for variant in ("PID_REUSED", "EXITED")
    )


def toctou_suite(
    *, build_executor: ExecutorFactory, seed: int = 23
) -> tuple[TOCTOURace, ...]:
    """§33's "TOCTOU between plan and execution" family — all four variants.

    A suite that returns four rows all reading ``refused=True`` with
    ``apply_calls=0`` is the behavioural half of G5.5. The AST half lives in
    ``tests/test_stage5_executor.py``.
    """
    return tuple(
        run_race(variant, build_executor=build_executor, seed=seed)[0]
        for variant in RACE_VARIANTS
    )
