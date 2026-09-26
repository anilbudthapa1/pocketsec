"""Behaviour tests for Stage 5's outcome package — D5.13, D5.14, D5.15, D5.17.

These tests are about what happens *after* privilege has been used: whether the
action achieved a security outcome, what it did that was not predicted, how the
host gets back, and what may be learned. Every one of them drives a failure path
or a refusal; construction is asserted only where the refusal *is* the
construction.

Four of them are canaries. ``test_unverifiable_is_none_not_false``,
``test_meets_threshold_is_none_below_min_samples``,
``test_crystallization_bounds_are_the_declared_ones`` and
``test_one_epoch_of_evidence_never_crystallizes`` all fail if someone makes an
abstention look like an answer or lowers a bound to make a mechanism produce
output. That is the point of them.

Everything measured here runs against the **simulated** host model, and no figure
in this file is a measurement of a Linux host.
"""

from __future__ import annotations

import pathlib
import secrets
from collections.abc import Mapping
from dataclasses import dataclass, replace

import pytest

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage0.contracts.threat_prediction_v1 import Verdict
from pocketsec.stage1.epoch.model import (
    EpochDecision,
    EpochTransitionReason,
)
from pocketsec.stage1.state.security_state import Privilege, SecurityStateV1
from pocketsec.stage3.cells.schema import CellPhase
from pocketsec.stage4.stage5_interface import CBFResolutionV1
from pocketsec.stage5.authority.capability import (
    AuthorityGrant,
    GrantSource,
    required_authority,
)
from pocketsec.stage5.authority.tokens import TokenStore, TokenVerdict
from pocketsec.stage5.cells.response_cells import (
    MIN_DISTINCT_EPOCHS_TO_CRYSTALLIZE,
    MIN_VERIFIED_EFFECTS_TO_CRYSTALLIZE,
    CrystallizationRefusal,
    MeltScope,
    MeltTrigger,
    ResponseCellField,
    ResponseCellV1,
    incident_invariant_key,
)
from pocketsec.stage5.constitution.invariants import (
    FROZEN_CONSTITUTION,
    AuthorityClass,
)
from pocketsec.stage5.constitution.schema import (
    DEFAULT_MISSION_INVARIANTS,
    InvariantKind,
    MissionInvariant,
    MissionInvariantSet,
)
from pocketsec.stage5.evidence.preservation_gate import (
    DEFAULT_RETENTION,
    EvidencePreservationGate,
)
from pocketsec.stage5.executor import residual as residual_module
from pocketsec.stage5.executor.identity import (
    IdentityRevalidation,
    ManualClock,
    identity_digest,
)
from pocketsec.stage5.executor.journal import RollbackJournal
from pocketsec.stage5.executor.lease import Lease, LeaseRegistry
from pocketsec.stage5.executor.residual import (
    MATERIAL_RESIDUAL,
    NODE_PREFIX_BY_COMPONENT,
    InterventionResidual,
    ResidualCause,
    ResidualComponent,
    evidence_node_id,
    intervention_residual,
    observed_nodes,
    process_node_id,
    recovery_node_id,
    residual_feedback,
    security_node_id,
    service_node_id,
    session_node_id,
    socket_node_id,
)
from pocketsec.stage5.executor.transactional import (
    Outcome,
    Phase,
    PhaseRecord,
    TransactionalExecutor,
    TransactionReceipt,
)
from pocketsec.stage5.executor.verify import (
    PostconditionKind,
    PostconditionProbe,
    PostconditionResult,
    VerificationOutcome,
    verification_outcome,
)
from pocketsec.stage5.governor import ResourceGovernor
from pocketsec.stage5.host.simulated import (
    FaultProfile,
    HostEffect,
    HostFailure,
    HostKind,
    HostSnapshot,
    ProcessRow,
    ProcessState,
    ServiceRow,
    SimulatedHost,
)
from pocketsec.stage5.memory.effectiveness import (
    ALLOWED_LEARNING,
    AUTONOMOUS_ROLLBACK_THRESHOLD,
    MIN_SAMPLES_FOR_RATE,
    EffectivenessMemory,
    LearningSource,
    context_key,
    split_context_key,
)
from pocketsec.stage5.operators.algebra import (
    DefensiveOperator,
    OperatorClass,
    ProcessIdentity,
    ProcessTarget,
    TargetKind,
    TargetScope,
)
from pocketsec.stage5.operators.catalog import CATALOG, spec
from pocketsec.stage5.recovery.safe_state import (
    ManifoldStatus,
    RecoveryAction,
    SafeStateManifold,
    SafeStatePlanner,
    capability_signature,
    execute_recovery,
    in_manifold,
    recovery_action_for,
)
from pocketsec.stage5.sentinel.kernel import (
    CHECK_ORDER,
    Decision,
    DenyReason,
    SentinelKernel,
    SentinelVerdict,
)

TARGET_PID = 4242
CHILD_PID = 4243
SECOND_PID = 4310
#: A process that belongs to ``app.service``. Since findings F3 a SERVICE operator must
#: target a process of the unit it constrains, so the divergence test needs a member.
SERVICE_MEMBER_PID = 4320
REQUIRED_SIGNAL = "process_memory_map"
TARGET_SOCKET = "sock.lab.1"
SESSION = "session.lab"


# --- fixtures ------------------------------------------------------------------
#
# Every number below is a FIXTURE. The support figures, the fault rates and the
# work-unit counts are values this file wrote; none of them measures anything.


def _identity(pid: int, *, ticks: int = 900_100, uid: int = 1000) -> ProcessIdentity:
    return ProcessIdentity(
        pid=pid,
        start_time_ticks=ticks,
        uid=uid,
        executable_digest="sha256:" + f"{pid:04x}" * 16,
        cgroup_id="cgroup.user.slice",
        namespace_id="ns.host",
    )


def _resolution(
    incident_id: str, *, epoch_id: int = 1, truncated: bool = False
) -> CBFResolutionV1:
    return CBFResolutionV1(
        resolution_id=f"res.{incident_id}",
        incident_id=incident_id,
        epoch_id=epoch_id,
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
        truncations=({"what": "worlds", "dropped": 2},) if truncated else (),
        degradations=(),
    )


def _process_rows(
    *, second_process: bool = False, service_member: bool = False
) -> list[ProcessRow]:
    rows = [
        ProcessRow(
            identity=_identity(TARGET_PID),
            state=ProcessState.RUNNING,
            unit=None,
            session_id=SESSION,
            socket_ids=(TARGET_SOCKET,),
            children=(),
            volatile_signals=(REQUIRED_SIGNAL,),
        ),
        ProcessRow(
            identity=_identity(CHILD_PID, ticks=900_200),
            state=ProcessState.RUNNING,
            unit=None,
            session_id=SESSION,
            socket_ids=(),
            children=(),
            volatile_signals=(REQUIRED_SIGNAL,),
        ),
    ]
    if second_process:
        rows.append(
            ProcessRow(
                identity=_identity(SECOND_PID, ticks=900_300),
                state=ProcessState.RUNNING,
                unit=None,
                session_id=SESSION,
                socket_ids=(),
                children=(),
                volatile_signals=(REQUIRED_SIGNAL,),
            )
        )
    if service_member:
        rows.append(
            ProcessRow(
                identity=_identity(SERVICE_MEMBER_PID, ticks=900_300),
                state=ProcessState.RUNNING,
                unit="app.service",
                session_id=SESSION,
                socket_ids=(),
                children=(),
                volatile_signals=(REQUIRED_SIGNAL,),
            )
        )
    return rows


def _service_rows(*, with_dependency: bool = False) -> list[ServiceRow]:
    rows = [
        ServiceRow(
            unit="lab-noncritical.service",
            running=True,
            constrained=False,
            restartable=True,
            depends_on=(),
            healthy=True,
        )
    ]
    if with_dependency:
        rows.extend(
            [
                ServiceRow(
                    unit="app.service",
                    running=True,
                    constrained=False,
                    restartable=True,
                    depends_on=("worker.service",),
                    healthy=True,
                ),
                ServiceRow(
                    unit="worker.service",
                    running=True,
                    constrained=False,
                    restartable=True,
                    depends_on=(),
                    healthy=True,
                ),
            ]
        )
    return rows


def _host(
    *,
    clock: ManualClock,
    faults: FaultProfile,
    with_dependency: bool = False,
    second_process: bool = False,
) -> SimulatedHost:
    """A host that no gate refuses for an unrelated reason.

    The target carries exactly the signal the default mission invariants require
    and nothing ``DEFAULT_RETENTION`` calls uniquely necessary, so a refusal in
    these tests is always the refusal under test.
    """
    return SimulatedHost(
        processes=_process_rows(
            second_process=second_process, service_member=with_dependency
        ),
        services=_service_rows(with_dependency=with_dependency),
        sessions=[SESSION],
        security_state=SecurityStateV1(privilege=Privilege.ROOT),
        faults=faults,
        clock=clock,
    )


def _suspension_invariants() -> MissionInvariantSet:
    """Mission invariants under which a suspension is *allowed* to be measured.

    Deliberately without an ``EVIDENCE_RETENTION`` invariant, so the *verification*
    behaviour under test is what decides these rigs' outcome and nothing about
    evidence can mask it. Integrator note: this docstring used to say the retention
    invariant made every suspension unreachable under ``DEFAULT_MISSION_INVARIANTS``.
    That was a real contradiction (MI-04 denied a target carrying the signal, the
    evidence gate refused one that did not) and it is closed: SENTINEL now reads the
    pre-action bundle it is handed, so a signal the gate preserved is no longer
    "lost before it was preserved".
    ``test_default_invariants_refuse_a_suspension_that_would_lose_evidence`` pins
    all three readings.
    """
    return MissionInvariantSet(
        invariants=(
            MissionInvariant(
                invariant_id="MI-R1",
                kind=InvariantKind.CRITICAL_SERVICE,
                subject="lab-noncritical.service",
                bound_seconds=None,
                detail="the lab unit stands in for a critical service",
            ),
            MissionInvariant(
                invariant_id="MI-R2",
                kind=InvariantKind.MAX_AUTONOMOUS_DOWNTIME,
                subject="",
                bound_seconds=600,
                detail="no autonomous containment longer than ten minutes",
            ),
            MissionInvariant(
                invariant_id="MI-R3",
                kind=InvariantKind.HOST_LOCAL_SCOPE,
                subject="",
                bound_seconds=None,
                detail="host-local defensive scope",
            ),
        )
    )


def _operator(
    operator_id: str,
    *,
    pid: int = TARGET_PID,
    subject: str | None = None,
    incident_id: str = "inc.outcome.1",
) -> DefensiveOperator:
    entry = spec(operator_id)
    default_subject = {
        TargetKind.PROCESS: f"pid.{pid}",
        TargetKind.SOCKET: TARGET_SOCKET,
        TargetKind.SESSION: SESSION,
        TargetKind.SERVICE: "app.service",
        TargetKind.HOST: "host",
    }[entry.target_kind]
    return DefensiveOperator(
        spec=entry,
        target=ProcessTarget(
            identity=_identity(pid, ticks=900_100 if pid == TARGET_PID else 900_300),
            scope=TargetScope(
                kind=entry.target_kind, subject=subject or default_subject
            ),
        ),
        incident_id=incident_id,
        ttl_seconds=min(300, entry.max_duration_seconds),
        evidence_refs=(),
    )


class _RecordingHost:
    """Delegates to a :class:`SimulatedHost` and logs every capability read.

    The incrementality property of §22 is a statement about what the host looked
    like between probes, so the test has to see the probes the executor and the
    recovery loop actually took — not a reconstruction afterwards.
    """

    def __init__(self, inner: SimulatedHost) -> None:
        self._inner = inner
        self.signatures: list[frozenset[str]] = []

    @property
    def host_kind(self) -> HostKind:
        return self._inner.host_kind

    def snapshot(self) -> HostSnapshot:
        snapshot = self._inner.snapshot()
        self.signatures.append(capability_signature(snapshot))
        return snapshot

    def observe_identity(self, pid: int) -> ProcessIdentity | None:
        return self._inner.observe_identity(pid)

    def apply(self, operator: DefensiveOperator, argv: tuple[str, ...]) -> HostEffect:
        return self._inner.apply(operator, argv)


@dataclass
class _Rig:
    clock: ManualClock
    inner: SimulatedHost
    host: object
    executor: TransactionalExecutor
    tokens: TokenStore
    leases: LeaseRegistry
    invariants: MissionInvariantSet

    def run(
        self,
        operator: DefensiveOperator,
        *,
        source: GrantSource = GrantSource.POLICY,
        action_id: str = "act.outcome.1",
    ) -> TransactionReceipt:
        entry = operator.spec
        token = self.tokens.mint(
            grant=AuthorityGrant(
                authority=required_authority(entry),
                granted_by=source,
                policy_version=FROZEN_CONSTITUTION.policy_version,
                subject_operator_id=entry.operator_id,
                detail="outcome test grant at the operator's own authority class",
            ),
            operator=operator,
            action_id=action_id,
            ttl_seconds=operator.ttl_seconds,
        )
        return self.executor.execute(
            operator, token, resolution=_resolution(operator.incident_id)
        )


def _rig(
    *,
    faults: FaultProfile | None = None,
    with_dependency: bool = False,
    second_process: bool = False,
    recording: bool = False,
    invariants: MissionInvariantSet | None = None,
) -> _Rig:
    clock = ManualClock(at=1_000)
    mission = DEFAULT_MISSION_INVARIANTS if invariants is None else invariants
    inner = _host(
        clock=clock,
        faults=faults or FaultProfile(seed=17),
        with_dependency=with_dependency,
        second_process=second_process,
    )
    host = _RecordingHost(inner) if recording else inner
    tokens = TokenStore(
        key=secrets.token_bytes(32), signer="tests.stage5.outcome", clock=clock
    )
    leases = LeaseRegistry(clock=clock)
    executor = TransactionalExecutor(
        kernel=SentinelKernel(
            constitution=FROZEN_CONSTITUTION, invariants=mission, clock=clock
        ),
        host=host,
        journal=RollbackJournal(),
        gate=EvidencePreservationGate(policy=DEFAULT_RETENTION, invariants=mission),
        governor=ResourceGovernor(),
        leases=leases,
        probe=PostconditionProbe(invariants=mission),
        clock=clock,
        tokens=tokens,
    )
    return _Rig(
        clock=clock,
        inner=inner,
        host=host,
        executor=executor,
        tokens=tokens,
        leases=leases,
        invariants=mission,
    )


# --- D5.13 post-action verification -------------------------------------------


def test_unverifiable_is_none_not_false() -> None:
    """A probe that cannot see the answer returns None, and None is not False.

    The canary: if someone makes an unobservable postcondition default to
    ``False``, the first assertion fails; if someone makes the fold treat ``None``
    like ``False``, the second does.
    """
    clock = ManualClock(at=1_000)
    host = _host(clock=clock, faults=FaultProfile(seed=3))
    before = host.snapshot()
    probe = PostconditionProbe(invariants=DEFAULT_MISSION_INVARIANTS)
    # A target the host has never seen: adaptation on its lineage is unobservable.
    operator = _operator("OBSERVE_PROCESS_METADATA", pid=9999)
    results = probe.probe(
        operator, host, before=before, resolution=_resolution(operator.incident_id)
    )
    by_kind = {result.kind: result for result in results}
    absent = by_kind[PostconditionKind.ATTACKER_PATH_UNCHANGED]
    assert absent.satisfied is None
    assert absent.satisfied is not False
    assert "unobservable" in absent.observed or "absent" in absent.observed
    assert verification_outcome(results) is VerificationOutcome.UNVERIFIABLE

    # The same result set with that one answer turned into a False is a different
    # outcome. If the two ever coincide, the distinction has been lost.
    as_false = tuple(
        replace(result, satisfied=False)
        if result.kind is PostconditionKind.ATTACKER_PATH_UNCHANGED
        else result
        for result in results
    )
    assert verification_outcome(as_false) is VerificationOutcome.DIVERGENT


def test_verification_outcome_separates_the_four_answers() -> None:
    state_true = PostconditionResult(
        kind=PostconditionKind.PROCESS_SUSPENDED,
        satisfied=True,
        observed="pid 1 state SUSPENDED",
        detail="",
    )
    assert verification_outcome(()) is VerificationOutcome.UNVERIFIABLE
    assert verification_outcome((state_true,)) is VerificationOutcome.EFFECTIVE
    assert (
        verification_outcome((replace(state_true, satisfied=False),))
        is VerificationOutcome.INEFFECTIVE
    )
    trajectory_false = PostconditionResult(
        kind=PostconditionKind.TRAJECTORY_REDUCED,
        satisfied=False,
        observed="phi unchanged",
        detail="",
    )
    assert (
        verification_outcome((state_true, trajectory_false))
        is VerificationOutcome.INEFFECTIVE
    )
    health_false = PostconditionResult(
        kind=PostconditionKind.SERVICE_HEALTH_ACCEPTABLE,
        satisfied=False,
        observed="1 degraded",
        detail="",
    )
    assert (
        verification_outcome((state_true, health_false))
        is VerificationOutcome.DIVERGENT
    )


def test_a_postcondition_result_needs_a_source() -> None:
    with pytest.raises(ContractError):
        PostconditionResult(
            kind=PostconditionKind.PROCESS_SUSPENDED,
            satisfied=True,
            observed="   ",
            detail="",
        )
    with pytest.raises(ContractError):
        PostconditionResult(
            kind=PostconditionKind.PROCESS_SUSPENDED,
            satisfied="yes",  # type: ignore[arg-type]
            observed="read",
            detail="",
        )


def test_an_ineffective_action_is_rolled_back() -> None:
    """``enforcement_failure_rate=1.0``: the call succeeds and nothing changes.

    Only post-action verification can notice, which is the whole argument of §20.
    """
    rig = _rig(
        faults=FaultProfile(seed=11, enforcement_failure_rate=1.0),
        invariants=_suspension_invariants(),
    )
    receipt = rig.run(_operator("SUSPEND_PROCESS"))
    assert receipt.verification is VerificationOutcome.INEFFECTIVE
    assert receipt.rollback_attempted is True
    assert receipt.outcome in (Outcome.ROLLED_BACK, Outcome.ROLLBACK_FAILED)
    assert receipt.outcome is not Outcome.COMMITTED_VERIFIED
    # The host never actually changed, so the target is still running.
    row = rig.inner.snapshot().process(TARGET_PID)
    assert row is not None and row.state is ProcessState.RUNNING


def test_default_invariants_refuse_a_suspension_that_would_lose_evidence() -> None:
    """The evidence gate comes before the action, and the invariants enforce it.

    Under ``DEFAULT_MISSION_INVARIANTS`` the target holds ``process_memory_map``,
    which ``MI-04`` says must be retained, and ``SUSPEND_PROCESS`` is
    ``DEGRADES_VOLATILE``. Three readings, each asserted:

    1. **Without a pre-action bundle** — the reading every planning-side caller gets —
       the suspension *would lose* the signal and ``violations()`` reports MI-04.
    2. **With a bundle that does not carry the signal**, it is still reported.
    3. **Through the executor**, the evidence gate preserves the signal in the
       pre-action bundle *before* COMMIT, SENTINEL is handed that bundle, and the
       suspension proceeds with the bundle digest on the receipt.

    Integrator note: this test used to assert that (3) is ``REFUSED_SENTINEL`` on
    ``MISSION_INVARIANT``. That was the measured contradiction three packages
    reported — MI-04 denied every suspension of a process carrying the signal while
    the evidence gate refused every one that did not, so no ``DEGRADES_VOLATILE``
    operator was reachable at all. MI-04's own message is "would lose X *before it was
    preserved*"; SENTINEL now reads the bundle it already receives, and (1) and (2)
    keep the fail-closed reading everywhere a bundle does not exist.
    """
    rig = _rig()
    before = rig.inner.snapshot()
    operator = _operator("SUSPEND_PROCESS")
    loss = DEFAULT_MISSION_INVARIANTS.violations(
        operator=operator, lease_ttl_seconds=operator.ttl_seconds, snapshot=before
    )
    assert InvariantKind.EVIDENCE_RETENTION in {violation.kind for violation in loss}
    unrelated = DEFAULT_MISSION_INVARIANTS.violations(
        operator=operator,
        lease_ttl_seconds=operator.ttl_seconds,
        snapshot=before,
        preserved=frozenset({"an_unrelated_signal"}),
    )
    assert InvariantKind.EVIDENCE_RETENTION in {violation.kind for violation in unrelated}
    # 3a. Nothing has CAPTURED the signal yet (findings F4 / S5-SEC-01): a signal merely
    # listed on the row used to count as preserved, so this suspension committed and the
    # memory map was lost with a COMMITTED_VERIFIED receipt. It is refused before the host.
    applied_before = rig.inner.apply_calls
    refused = rig.run(operator)
    assert refused.sentinel_verdict is not None
    assert DenyReason.MISSION_INVARIANT in refused.sentinel_verdict.reasons
    assert refused.outcome is Outcome.REFUSED_SENTINEL
    assert rig.inner.apply_calls == applied_before, "an evidence-losing act reached the host"
    # 3b. Evidence first, then the action: once a preservation operator has captured it,
    # the same suspension proceeds with the bundle digest on the receipt.
    preserved = rig.run(_operator("PRESERVE_VOLATILE_EVIDENCE"), action_id="act.outcome.pre")
    assert preserved.committed(), preserved.outcome
    receipt = rig.run(_operator("SUSPEND_PROCESS"), action_id="act.outcome.after")
    assert receipt.sentinel_verdict is not None
    assert DenyReason.MISSION_INVARIANT not in receipt.sentinel_verdict.reasons
    assert receipt.evidence_bundle_digest is not None
    assert receipt.outcome is Outcome.COMMITTED_VERIFIED


def test_a_divergent_action_is_rolled_back() -> None:
    """``dependency_restart_rate=1.0``: the action works and health is lost.

    The state postcondition holds — the unit *is* constrained — and a dependency
    comes back unhealthy. "It worked" and "it helped" are different questions.
    """
    rig = _rig(
        faults=FaultProfile(seed=5, dependency_restart_rate=1.0), with_dependency=True
    )
    receipt = rig.run(
        _operator("CONSTRAIN_SERVICE", pid=SERVICE_MEMBER_PID, subject="app.service"),
        source=GrantSource.HUMAN,
    )
    by_kind = {result.kind: result for result in receipt.postconditions}
    assert by_kind[PostconditionKind.SERVICE_CONSTRAINED].satisfied is True
    assert by_kind[PostconditionKind.SERVICE_HEALTH_ACCEPTABLE].satisfied is False
    assert receipt.verification is VerificationOutcome.DIVERGENT
    assert receipt.rollback_attempted is True
    assert receipt.outcome in (Outcome.ROLLED_BACK, Outcome.ROLLBACK_FAILED)


# --- D5.13 intervention residual ----------------------------------------------


@dataclass(frozen=True, slots=True)
class _Node:
    node_id: str
    attributes: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class _State:
    nodes: tuple[_Node, ...]
    stamp: str = "sha256:" + "11" * 32

    def digest(self) -> str:
        return self.stamp


@dataclass(frozen=True, slots=True)
class _Prediction:
    candidate_id: str
    before: _State
    predicted: _State
    evidence_lost: tuple[str, ...] = ()
    unknown_dependencies: tuple[str, ...] = ()
    truncated: bool = False


def _effect(
    *,
    failure: HostFailure | None = None,
    collateral: tuple[str, ...] = (),
    evidence_lost: tuple[str, ...] = (),
) -> HostEffect:
    return HostEffect(
        applied=True,
        changed=("changed:1",),
        failure=failure,
        evidence_lost=evidence_lost,
        collateral_units=collateral,
    )


def _observed_snapshot(**kwargs: object) -> HostSnapshot:
    clock = ManualClock(at=2_000)
    return _host(clock=clock, faults=FaultProfile(seed=1), **kwargs).snapshot()  # type: ignore[arg-type]


def _exact_prediction(snapshot: HostSnapshot) -> _Prediction:
    """A prediction that matches the observation on every node it models."""
    seen = observed_nodes(snapshot)
    modelled = tuple(
        _Node(node_id=node_id, attributes=dict(seen[node_id]))
        for node_id in (
            process_node_id(TARGET_PID),
            socket_node_id(TARGET_SOCKET),
            evidence_node_id(REQUIRED_SIGNAL),
        )
    )
    state = _State(nodes=modelled)
    return _Prediction(candidate_id="cand.exact", before=state, predicted=state)


def test_unattributable_residual_is_reachable() -> None:
    """A predicted node the host does not contain cannot be pinned on a mechanism.

    ``UNATTRIBUTABLE`` has to fire for something, or the decomposition is
    explaining noise: every residual would acquire a cause and the causes would
    stop being evidence.
    """
    snapshot = _observed_snapshot()
    ghost = _State(
        nodes=(_Node(node_id=service_node_id("ghost.service"), attributes={"running": "true"}),)
    )
    residual = intervention_residual(
        prediction=_Prediction(candidate_id="cand.ghost", before=ghost, predicted=ghost),
        observed=snapshot,
        effect=_effect(),
        action_id="act.ghost",
    )
    assert residual.attribution is ResidualCause.UNATTRIBUTABLE
    assert residual.distance > 0.0
    assert "absent=" in residual.detail


def test_residual_attribution_table_separates_its_causes() -> None:
    snapshot = _observed_snapshot()
    exact = _exact_prediction(snapshot)

    none_case = intervention_residual(
        prediction=exact, observed=snapshot, effect=_effect(), action_id="act.none"
    )
    assert none_case.attribution is ResidualCause.NONE
    assert none_case.distance == 0.0

    enforcement = intervention_residual(
        prediction=exact,
        observed=snapshot,
        effect=_effect(failure=HostFailure.ENFORCEMENT_SILENTLY_FAILED),
        action_id="act.enforce",
    )
    assert enforcement.attribution is ResidualCause.ENFORCEMENT_FAILURE

    hidden = intervention_residual(
        prediction=exact,
        observed=snapshot,
        effect=_effect(collateral=("worker.service",)),
        action_id="act.hidden",
    )
    assert hidden.attribution is ResidualCause.HIDDEN_DEPENDENCY
    assert hidden.components[ResidualComponent.SERVICE_STATE] > 0.0

    wrong = _Prediction(
        candidate_id="cand.wrong",
        before=exact.before,
        predicted=_State(
            nodes=(
                _Node(
                    node_id=process_node_id(TARGET_PID),
                    attributes={"state": "SUSPENDED"},
                ),
            )
        ),
    )
    model_error = intervention_residual(
        prediction=wrong, observed=snapshot, effect=_effect(), action_id="act.wrong"
    )
    assert model_error.attribution is ResidualCause.MODEL_ERROR
    assert model_error.components[ResidualComponent.PROCESS_STATE] == 1.0


def test_attacker_adaptation_is_attributed_to_a_new_lineage_node() -> None:
    clock = ManualClock(at=2_000)
    host = _host(clock=clock, faults=FaultProfile(seed=1))
    snapshot = host.snapshot()
    # The twin modelled the process but not the socket it now carries, and not
    # the child: a new node on a modelled lineage is adaptation, not arithmetic.
    modelled = _State(
        nodes=(
            _Node(
                node_id=process_node_id(TARGET_PID),
                attributes=dict(observed_nodes(snapshot)[process_node_id(TARGET_PID)]),
            ),
        )
    )
    residual = intervention_residual(
        prediction=_Prediction(
            candidate_id="cand.adapt", before=modelled, predicted=modelled
        ),
        observed=snapshot,
        effect=_effect(),
        action_id="act.adapt",
    )
    assert residual.attribution is ResidualCause.ATTACKER_ADAPTATION


def test_residual_does_not_join_the_two_digests() -> None:
    """A zero residual is still zero when the two digests disagree.

    ``predicted_digest`` and ``observed_digest`` come from different
    canonicalisations. Comparing them would be the S2-FC-01 defect — two key
    spaces joined that could never match — and would report every action as
    materially divergent.
    """
    snapshot = _observed_snapshot()
    residual = intervention_residual(
        prediction=_exact_prediction(snapshot),
        observed=snapshot,
        effect=_effect(),
        action_id="act.digest",
    )
    assert residual.predicted_digest != residual.observed_digest
    assert residual.distance == 0.0
    assert residual.material is False


def test_observed_nodes_uses_the_published_id_builders() -> None:
    """Rule A for the residual's own key space.

    A twin builds node ids with the exported builders and the observation is built
    with the same ones. If the two ever diverge, every predicted node becomes
    unmatched and every cause becomes UNATTRIBUTABLE — visible, but useless.
    """
    snapshot = _observed_snapshot()
    seen = observed_nodes(snapshot)
    for row in snapshot.processes:
        assert process_node_id(row.identity.pid) in seen
        for socket_id in row.socket_ids:
            assert socket_node_id(socket_id) in seen
        for signal in row.volatile_signals:
            assert evidence_node_id(signal) in seen
    for service in snapshot.services:
        assert service_node_id(service.unit) in seen
        assert recovery_node_id(service.unit) in seen
    for session in snapshot.sessions:
        assert session_node_id(session) in seen
    assert security_node_id() in seen
    prefixes = (*NODE_PREFIX_BY_COMPONENT.values(), session_node_id(""))
    for node_id in seen:
        assert node_id.startswith(prefixes), node_id


def test_a_node_outside_the_published_space_is_unmatched_not_agreement() -> None:
    """An id in no published space scores as a miss, never as agreement.

    Scoring it zero would let a twin with a private id vocabulary report a perfect
    residual for a host it never looked at.
    """
    snapshot = _observed_snapshot()
    alien = _State(nodes=(_Node(node_id="widget:7", attributes={"state": "RUNNING"}),))
    residual = intervention_residual(
        prediction=_Prediction(candidate_id="cand.alien", before=alien, predicted=alien),
        observed=snapshot,
        effect=_effect(),
        action_id="act.alien",
    )
    assert "widget:7" in residual.detail
    assert residual.attribution is ResidualCause.UNATTRIBUTABLE
    # And the distance stays 0.0, because an unclassifiable node belongs to none of
    # the six families: the cause carries the caveat, the arithmetic does not lie.
    assert residual.distance == 0.0


def test_residual_feedback_is_a_plain_row_with_no_operator_authority_tokens() -> None:
    snapshot = _observed_snapshot()
    residual = intervention_residual(
        prediction=_exact_prediction(snapshot),
        observed=snapshot,
        effect=_effect(collateral=("worker.service",)),
        action_id="act.feedback",
    )
    row = residual_feedback(residual)
    assert row["feedback_kind"] == "intervention_residual"
    assert row["attribution"] == ResidualCause.HIDDEN_DEPENDENCY.value
    for key in row:
        assert "operator" not in key and "command" not in key
    with pytest.raises(TypeError):
        row["distance"] = 1.0  # type: ignore[index]


def test_the_residual_calls_into_no_learning_stage() -> None:
    """T2/T3: Stage 5 emits rows; it does not teach Stage 3 or Stage 4.

    §21 says the residual is fed back to CBF and CRYSTAL, and the trust rules say
    that path runs through Stage 6's quarantine. So ``residual.py`` must have no
    import of a Stage 3 or Stage 4 module at all — asserted by AST rather than by
    the module's own docstring, because a docstring is not a boundary.
    """
    import ast

    source = pathlib.Path(residual_module.__file__ or "").read_text()
    imported: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.append(node.module)
        elif isinstance(node, ast.ImportFrom):
            imported.append(f"relative:{node.module}")
    assert imported, "the AST walk found no imports at all, so it proves nothing"
    offenders = [
        name
        for name in imported
        if name.startswith(("pocketsec.stage3", "pocketsec.stage4", "relative:"))
    ]
    assert offenders == [], offenders


def test_a_residual_distance_outside_the_unit_interval_is_refused() -> None:
    with pytest.raises(ContractError):
        InterventionResidual(
            action_id="act.bad",
            distance=1.5,
            components={},
            attribution=ResidualCause.NONE,
            predicted_digest="sha256:" + "00" * 32,
            observed_digest="sha256:" + "00" * 32,
            detail="",
        )


# --- D5.14 safe-state recovery ------------------------------------------------


def _manifold(invariants: MissionInvariantSet | None = None) -> SafeStateManifold:
    return SafeStateManifold(
        invariants=invariants or DEFAULT_MISSION_INVARIANTS,
        required_observation=frozenset({REQUIRED_SIGNAL}),
        blocked_trajectory_signals=frozenset(),
    )


def _critical_only() -> MissionInvariantSet:
    """Just the two critical-service invariants, so a snapshot can be INSIDE."""
    return MissionInvariantSet(
        invariants=(
            MissionInvariant(
                invariant_id="MI-T1",
                kind=InvariantKind.CRITICAL_SERVICE,
                subject="lab-noncritical.service",
                bound_seconds=None,
                detail="the lab unit stands in for a critical service",
            ),
            MissionInvariant(
                invariant_id="MI-T2",
                kind=InvariantKind.EVIDENCE_RETENTION,
                subject=REQUIRED_SIGNAL,
                bound_seconds=900,
                detail="the signal the incident is made of",
            ),
        )
    )


def test_outside_unrecoverable_escalates() -> None:
    """A constrained service that lost ``restartable`` has no path back.

    And a lease whose rollback operator is no longer in the catalog has none
    either. Both must land on ESCALATE: a recovery planner that always finds a
    path has not been tested.
    """
    clock = ManualClock(at=1_000)
    host = SimulatedHost(
        processes=_process_rows(),
        services=[
            ServiceRow(
                unit="lab-noncritical.service",
                running=True,
                constrained=True,
                restartable=False,
                depends_on=(),
                healthy=False,
            )
        ],
        sessions=[SESSION],
        security_state=SecurityStateV1(),
        faults=FaultProfile(seed=2),
        clock=clock,
    )
    verdict = in_manifold(host.snapshot(), _manifold(_critical_only()), leases=())
    assert verdict.status is ManifoldStatus.OUTSIDE_UNRECOVERABLE
    assert verdict.recovery_path_exists is False
    assert "not restartable" in verdict.detail
    assert recovery_action_for(verdict) is RecoveryAction.ESCALATE

    healthy = _host(clock=clock, faults=FaultProfile(seed=2))
    orphan = Lease(
        lease_id="lease.orphan",
        action_id="act.orphan",
        incident_id="inc.orphan",
        operator_id="SUSPEND_PROCESS",
        target_digest=identity_digest(_identity(TARGET_PID)),
        granted_at=1_000,
        ttl_seconds=300,
        maximum_lifetime_seconds=3_600,
        renewals=0,
        rollback_operator_id="OPERATOR.THAT.WAS.REMOVED",
    )
    gone = in_manifold(
        healthy.snapshot(), _manifold(_critical_only()), leases=(orphan,)
    )
    assert gone.status is ManifoldStatus.OUTSIDE_UNRECOVERABLE
    assert recovery_action_for(gone) is RecoveryAction.ESCALATE


def test_a_snapshot_with_no_recovery_path_is_never_inside() -> None:
    """§23's third conjunct. Dropping it is how a host calls itself healthy while
    holding a change it can no longer undo."""
    clock = ManualClock(at=1_000)
    host = _host(clock=clock, faults=FaultProfile(seed=2))
    manifold = _manifold(_critical_only())
    assert in_manifold(host.snapshot(), manifold, leases=()).status is (
        ManifoldStatus.INSIDE
    )
    unrollbackable = Lease(
        lease_id="lease.norollback",
        action_id="act.norollback",
        incident_id="inc.norollback",
        operator_id="REVOKE_LOCAL_SESSION",
        target_digest=identity_digest(_identity(TARGET_PID)),
        granted_at=1_000,
        ttl_seconds=300,
        maximum_lifetime_seconds=3_600,
        renewals=0,
        rollback_operator_id=None,
    )
    verdict = in_manifold(host.snapshot(), manifold, leases=(unrollbackable,))
    assert verdict.status is not ManifoldStatus.INSIDE
    assert not verdict.violated  # nothing is violated; the *path* is missing


def test_recovery_is_incremental_not_wholesale() -> None:
    """At most one capability changes between consecutive probes (§22).

    Two processes are suspended, then recovery restores them one at a time. The
    recording host logs the capability signature at every read the executor and
    the recovery loop take, so a wholesale restore would show a two-element
    difference between two consecutive probes.
    """
    rig = _rig(
        second_process=True, recording=True, invariants=_suspension_invariants()
    )
    first = rig.run(_operator("SUSPEND_PROCESS"), action_id="act.contain.1")
    assert first.outcome in (
        Outcome.COMMITTED_VERIFIED,
        Outcome.COMMITTED_UNVERIFIED,
    ), first.sentinel_verdict.detail

    # The SECOND containment is applied to the host directly, and its lease is
    # granted directly. Not a shortcut — a recorded property of this build:
    # ``SUSPEND_PROCESS`` declares ``NO_ACTIVE_LEASE_ON_TARGET`` and the kernel is
    # handed a lease *count*, so it fails that precondition closed while any lease
    # is live. Two concurrent leased containments are therefore not constructible
    # through the executor, and without two there is nothing for "one capability at
    # a time" to be about. The rollback operators declare no such precondition, so
    # the recovery under test still runs through the real executor and the real
    # kernel.
    second_operator = _operator(
        "SUSPEND_PROCESS", pid=SECOND_PID, incident_id="inc.outcome.2"
    )
    rig.inner.apply(second_operator, second_operator.argv())
    granted = rig.leases.grant(
        operator=second_operator,
        action_id="act.contain.2",
        ttl_seconds=second_operator.ttl_seconds,
        resolution=_resolution("inc.outcome.2"),
    )
    assert isinstance(granted, Lease), granted
    contained = rig.leases.active(rig.clock.now())
    assert len(contained) == 2
    suspended = rig.inner.snapshot()
    assert suspended.process(TARGET_PID).state is ProcessState.SUSPENDED  # type: ignore[union-attr]
    assert suspended.process(SECOND_PID).state is ProcessState.SUSPENDED  # type: ignore[union-attr]

    planner = SafeStatePlanner(
        manifold=_manifold(_critical_only()),
        catalog=CATALOG,
        governor=ResourceGovernor(),
    )
    plan = planner.plan(
        contained=contained,
        snapshot=rig.inner.snapshot(),
        incident_id="inc.outcome.1",
    )
    assert len(plan.steps) == 2
    assert [step.step_index for step in plan.steps] == [0, 1]
    assert {step.operator.spec.operator_id for step in plan.steps} == {"RESUME_PROCESS"}

    report = execute_recovery(
        plan,
        executor=rig.executor,
        tokens=rig.tokens,
        grant=AuthorityGrant(
            authority=required_authority(spec("RESUME_PROCESS")),
            granted_by=GrantSource.POLICY,
            policy_version=FROZEN_CONSTITUTION.policy_version,
            subject_operator_id="RESUME_PROCESS",
            detail="recovery grant for the rollback operator",
        ),
        resolution=_resolution("inc.outcome.1"),
    )
    assert report.steps_attempted == 2
    assert report.steps_succeeded == 2, report.detail
    assert report.final_status is ManifoldStatus.INSIDE, report.detail
    assert report.simulated is True
    signatures = rig.host.signatures  # type: ignore[attr-defined]
    assert len(signatures) >= 4
    for earlier, later in zip(signatures, signatures[1:], strict=False):
        assert len(earlier ^ later) <= 1, (
            f"recovery changed {len(earlier ^ later)} capabilities between two "
            f"probes: {sorted(earlier ^ later)}"
        )
    restored = rig.inner.snapshot()
    assert restored.process(TARGET_PID) is not None
    assert restored.process(TARGET_PID).state is ProcessState.RUNNING  # type: ignore[union-attr]


def test_a_plan_over_the_step_bound_is_refused() -> None:
    from pocketsec.stage5.recovery.safe_state import MAX_RECOVERY_STEPS, SafeStatePlan

    rig = _rig(invariants=_suspension_invariants())
    receipt = rig.run(_operator("SUSPEND_PROCESS"))
    assert receipt.outcome in (
        Outcome.COMMITTED_VERIFIED,
        Outcome.COMMITTED_UNVERIFIED,
    )
    planner = SafeStatePlanner(
        manifold=_manifold(_critical_only()),
        catalog=CATALOG,
        governor=ResourceGovernor(),
    )
    plan = planner.plan(
        contained=rig.leases.active(rig.clock.now()),
        snapshot=rig.inner.snapshot(),
        incident_id="inc.outcome.1",
    )
    assert plan.steps
    step = plan.steps[0]
    with pytest.raises(ContractError):
        SafeStatePlan(
            plan_id=plan.plan_id,
            incident_id=plan.incident_id,
            steps=tuple(
                replace(step, step_index=index) for index in range(MAX_RECOVERY_STEPS + 1)
            ),
            manifold=plan.manifold,
        )


def test_execute_recovery_refuses_an_executor_whose_host_it_cannot_read() -> None:
    """``RecoveryReport.simulated`` may not be defaulted (ADR-0046).

    If the host adapter cannot be resolved, the run refuses rather than reporting
    a recovery whose ``simulated`` flag is a guess — a report claiming a real host
    is the one lie this deliverable exists to prevent.
    """
    rig = _rig(invariants=_suspension_invariants())
    assert rig.run(_operator("SUSPEND_PROCESS")).outcome in (
        Outcome.COMMITTED_VERIFIED,
        Outcome.COMMITTED_UNVERIFIED,
    )
    planner = SafeStatePlanner(
        manifold=_manifold(_critical_only()),
        catalog=CATALOG,
        governor=ResourceGovernor(),
    )
    plan = planner.plan(
        contained=rig.leases.active(rig.clock.now()),
        snapshot=rig.inner.snapshot(),
        incident_id="inc.outcome.1",
    )
    assert plan.steps

    class _HostlessExecutor:
        """Something shaped like an executor with no host adapter anywhere on it."""

    with pytest.raises(ContractError) as excinfo:
        execute_recovery(
            plan,
            executor=_HostlessExecutor(),  # type: ignore[arg-type]
            tokens=rig.tokens,
            grant=AuthorityGrant(
                authority=required_authority(spec("RESUME_PROCESS")),
                granted_by=GrantSource.POLICY,
                policy_version=FROZEN_CONSTITUTION.policy_version,
                subject_operator_id="RESUME_PROCESS",
                detail="grant that will never be spent",
            ),
            resolution=_resolution("inc.outcome.1"),
        )
    assert "simulated" in str(excinfo.value)


def test_a_step_with_no_grant_escalates_instead_of_raising() -> None:
    """A recovery step nobody authorised is a human's decision, not a crash."""
    rig = _rig(invariants=_suspension_invariants())
    assert rig.run(_operator("SUSPEND_PROCESS")).outcome in (
        Outcome.COMMITTED_VERIFIED,
        Outcome.COMMITTED_UNVERIFIED,
    )
    planner = SafeStatePlanner(
        manifold=_manifold(_critical_only()),
        catalog=CATALOG,
        governor=ResourceGovernor(),
    )
    plan = planner.plan(
        contained=rig.leases.active(rig.clock.now()),
        snapshot=rig.inner.snapshot(),
        incident_id="inc.outcome.1",
    )
    report = execute_recovery(
        plan,
        executor=rig.executor,
        tokens=rig.tokens,
        grant=AuthorityGrant(
            authority=AuthorityClass.A2,
            granted_by=GrantSource.POLICY,
            policy_version=FROZEN_CONSTITUTION.policy_version,
            subject_operator_id="RELEASE_LOCAL_SOCKET",
            detail="a grant for a different operator than the plan needs",
        ),
        resolution=_resolution("inc.outcome.1"),
    )
    assert report.steps_attempted == 0
    assert report.halted_at == 0
    assert RecoveryAction.ESCALATE.value in report.detail
    assert report.simulated is True


def test_a_step_with_no_expectation_is_refused() -> None:
    from pocketsec.stage5.recovery.safe_state import RecoveryStep

    with pytest.raises(ContractError):
        RecoveryStep(
            step_index=0,
            operator=_operator("RESUME_PROCESS"),
            expects=(),
            on_failure=RecoveryAction.ESCALATE,
            observe_seconds=1,
        )


# --- D5.15 effectiveness memory ----------------------------------------------


def _synthetic_receipt(
    *,
    operator_id: str = "SUSPEND_PROCESS",
    epoch_id: int = 1,
    verification: VerificationOutcome | None = VerificationOutcome.EFFECTIVE,
    outcome: Outcome = Outcome.COMMITTED_UNVERIFIED,
    rollback_attempted: bool = False,
    rollback_succeeded: bool | None = None,
    residual: InterventionResidual | None = None,
    action_id: str = "act.synthetic.1",
    work_units: int = 7,
) -> TransactionReceipt:
    """A receipt built by hand, so memory behaviour can be tested without a host.

    Every field is a fixture. ``work_units`` is a count this file chose, not a
    measurement.
    """
    entry = spec(operator_id)
    return TransactionReceipt(
        receipt_id=f"rcpt.{action_id}",
        action_id=action_id,
        incident_id="inc.synthetic",
        resolution_id="res.synthetic",
        operator_id=operator_id,
        operator_class=entry.operator_class,
        target_digest=identity_digest(_identity(TARGET_PID)),
        outcome=outcome,
        phases=(
            PhaseRecord(phase=Phase.PREPARE, at=1, ok=True, detail="fixture"),
            PhaseRecord(phase=Phase.COMMIT, at=2, ok=True, detail="fixture"),
            PhaseRecord(phase=Phase.VERIFY, at=3, ok=True, detail="fixture"),
        ),
        sentinel_verdict=SentinelVerdict(
            decision=Decision.PASS,
            reasons=(),
            detail="fixture",
            operator_id=operator_id,
            target_digest=identity_digest(_identity(TARGET_PID)),
            evaluated_checks=CHECK_ORDER,
        ),
        token_verdict=TokenVerdict.VALID,
        identity_revalidation=IdentityRevalidation.MATCH,
        evidence_bundle_digest=None,
        lease_id=None,
        postconditions=(),
        verification=verification,
        residual=residual,
        rollback_attempted=rollback_attempted,
        rollback_succeeded=rollback_succeeded,
        host_kind=HostKind.SIMULATED,
        simulated=True,
        work_units=work_units,
        loadavg=(0.0, 0.0, 0.0),
        epoch_id=epoch_id,
    )


def test_effectiveness_write_key_equals_the_planner_read_key() -> None:
    """Rule A. The memory writes with ``context_key`` and the planner reads with it.

    Stage 2 lost a whole result to a join between two key spaces that could never
    match (S2-FC-01). This asserts the producer and the consumer are the same
    call, for the same inputs, and that the parsed key round-trips.
    """
    memory = EffectivenessMemory()
    mechanism = "privilege_escalation.local"
    memory.observe(
        _synthetic_receipt(epoch_id=4),
        source=LearningSource.LAB_SANDBOX,
        mechanism_id=mechanism,
    )
    read_key = context_key(
        epoch_id=4, mechanism_id=mechanism, target_kind=TargetKind.PROCESS
    )
    record = memory.record(context=read_key, operator_id="SUSPEND_PROCESS")
    assert record is not None
    assert record.context == read_key
    assert [row["context"] for row in memory.rows()] == [read_key]
    parsed = split_context_key(read_key)
    assert parsed.epoch_id == 4
    assert parsed.mechanism_id == mechanism
    assert parsed.target_kind is TargetKind.PROCESS
    # A key the planner builds for another epoch must not find this record.
    assert (
        memory.record(
            context=context_key(
                epoch_id=5, mechanism_id=mechanism, target_kind=TargetKind.PROCESS
            ),
            operator_id="SUSPEND_PROCESS",
        )
        is None
    )
    with pytest.raises(ContractError):
        split_context_key("4|privilege_escalation.local")


def test_observe_refuses_a_disallowed_learning_source() -> None:
    """§31 as code: production observation may not learn from an O3 suspension."""
    memory = EffectivenessMemory()
    with pytest.raises(ContractError) as excinfo:
        memory.observe(
            _synthetic_receipt(operator_id="SUSPEND_PROCESS"),
            source=LearningSource.PRODUCTION_OBSERVATION,
            mechanism_id="privilege_escalation.local",
        )
    assert "O3_SUSPEND" in str(excinfo.value)
    assert memory.rows() == ()
    # The same receipt is allowed from the lab, and from a human-approved action.
    memory.observe(
        _synthetic_receipt(operator_id="SUSPEND_PROCESS"),
        source=LearningSource.LAB_SANDBOX,
        mechanism_id="privilege_escalation.local",
    )
    assert len(memory.rows()) == 1
    assert OperatorClass.O5_SERVICE_CONTAINMENT not in ALLOWED_LEARNING[
        LearningSource.AUTONOMOUS_LOW_IMPACT
    ]
    with pytest.raises(ContractError):
        memory.observe(
            _synthetic_receipt(operator_id="CONSTRAIN_SERVICE"),
            source=LearningSource.AUTONOMOUS_LOW_IMPACT,
            mechanism_id="privilege_escalation.local",
        )


def test_meets_threshold_is_none_below_min_samples() -> None:
    """None blocks autonomy. It is not zero and it is not a pass.

    The canary: lowering ``MIN_SAMPLES_FOR_RATE``, or returning ``False`` instead
    of ``None``, changes the first assertion; returning ``True`` on thin evidence
    changes the second.
    """
    memory = EffectivenessMemory()
    mechanism = "privilege_escalation.local"
    for index in range(MIN_SAMPLES_FOR_RATE - 1):
        memory.observe(
            _synthetic_receipt(
                action_id=f"act.rollback.{index}",
                outcome=Outcome.ROLLED_BACK,
                verification=VerificationOutcome.INEFFECTIVE,
                rollback_attempted=True,
                rollback_succeeded=True,
            ),
            source=LearningSource.LAB_SANDBOX,
            mechanism_id=mechanism,
        )
    assert (
        memory.rollback_reliability(operator_id="SUSPEND_PROCESS", epoch_id=1) is None
    )
    assert (
        memory.meets_threshold(
            operator_id="SUSPEND_PROCESS",
            epoch_id=1,
            threshold=AUTONOMOUS_ROLLBACK_THRESHOLD,
        )
        is None
    )
    memory.observe(
        _synthetic_receipt(
            action_id="act.rollback.final",
            outcome=Outcome.ROLLED_BACK,
            verification=VerificationOutcome.INEFFECTIVE,
            rollback_attempted=True,
            rollback_succeeded=True,
        ),
        source=LearningSource.LAB_SANDBOX,
        mechanism_id=mechanism,
    )
    assert (
        memory.meets_threshold(
            operator_id="SUSPEND_PROCESS",
            epoch_id=1,
            threshold=AUTONOMOUS_ROLLBACK_THRESHOLD,
        )
        is True
    )
    record = memory.record(
        context=context_key(
            epoch_id=1, mechanism_id=mechanism, target_kind=TargetKind.PROCESS
        ),
        operator_id="SUSPEND_PROCESS",
    )
    assert record is not None
    assert record.simulated_rollback_success() == 1.0
    assert record.no_effect == MIN_SAMPLES_FOR_RATE


def test_a_failed_rollback_lowers_the_measured_rate_below_the_threshold() -> None:
    memory = EffectivenessMemory()
    for index in range(MIN_SAMPLES_FOR_RATE):
        memory.observe(
            _synthetic_receipt(
                action_id=f"act.mixed.{index}",
                outcome=Outcome.ROLLED_BACK,
                verification=VerificationOutcome.INEFFECTIVE,
                rollback_attempted=True,
                rollback_succeeded=index != 0,
            ),
            source=LearningSource.LAB_SANDBOX,
            mechanism_id="privilege_escalation.local",
        )
    assert (
        memory.meets_threshold(
            operator_id="SUSPEND_PROCESS",
            epoch_id=1,
            threshold=AUTONOMOUS_ROLLBACK_THRESHOLD,
        )
        is False
    )


def test_records_are_never_merged_across_epochs() -> None:
    memory = EffectivenessMemory()
    for epoch in (1, 2):
        memory.observe(
            _synthetic_receipt(epoch_id=epoch, action_id=f"act.epoch.{epoch}"),
            source=LearningSource.LAB_SANDBOX,
            mechanism_id="privilege_escalation.local",
        )
    assert len(memory.rows()) == 2
    assert {row["n"] for row in memory.rows()} == {1}


def test_a_refused_receipt_is_counted_but_not_learned_from() -> None:
    memory = EffectivenessMemory()
    memory.observe(
        _synthetic_receipt(
            outcome=Outcome.REFUSED_SENTINEL, verification=None, action_id="act.refused"
        ),
        source=LearningSource.LAB_SANDBOX,
        mechanism_id="privilege_escalation.local",
    )
    assert memory.rows() == ()
    assert memory.not_executed() == 1


def test_eviction_is_explicit_and_recorded() -> None:
    memory = EffectivenessMemory(max_records=2)
    for index in range(3):
        memory.observe(
            _synthetic_receipt(epoch_id=index + 1, action_id=f"act.evict.{index}"),
            source=LearningSource.LAB_SANDBOX,
            mechanism_id="privilege_escalation.local",
        )
    assert len(memory.rows()) == 2
    assert memory.evictions() == 1
    truncation = memory.truncations()[0]
    assert truncation.what == "effectiveness_record"
    assert truncation.samples_dropped == 1


def test_a_material_residual_is_counted_as_collateral() -> None:
    memory = EffectivenessMemory()
    residual = InterventionResidual(
        action_id="act.material",
        distance=MATERIAL_RESIDUAL,
        components={ResidualComponent.SERVICE_STATE: MATERIAL_RESIDUAL},
        attribution=ResidualCause.HIDDEN_DEPENDENCY,
        predicted_digest="sha256:" + "00" * 32,
        observed_digest="sha256:" + "01" * 32,
        detail="fixture",
    )
    memory.observe(
        _synthetic_receipt(residual=residual, action_id="act.material"),
        source=LearningSource.LAB_SANDBOX,
        mechanism_id="privilege_escalation.local",
    )
    record = memory.record(
        context=context_key(
            epoch_id=1,
            mechanism_id="privilege_escalation.local",
            target_kind=TargetKind.PROCESS,
        ),
        operator_id="SUSPEND_PROCESS",
    )
    assert record is not None
    assert record.collateral == 1
    assert record.collateral_rate() is None  # one sample is not a rate
    assert sum(record.residual_buckets) == 1


# --- D5.17 response cells and melting ----------------------------------------


def _feed(
    memory: EffectivenessMemory,
    *,
    mechanism: str,
    epochs: tuple[int, ...],
    verified_per_epoch: int,
    operator_id: str = "SUSPEND_PROCESS",
) -> None:
    for epoch in epochs:
        for index in range(verified_per_epoch):
            memory.observe(
                _synthetic_receipt(
                    operator_id=operator_id,
                    epoch_id=epoch,
                    action_id=f"act.{mechanism}.{epoch}.{index}",
                ),
                source=LearningSource.LAB_SANDBOX,
                mechanism_id=mechanism,
            )
        memory.observe(
            _synthetic_receipt(
                operator_id=operator_id,
                epoch_id=epoch,
                action_id=f"act.{mechanism}.{epoch}.rollback",
                outcome=Outcome.ROLLED_BACK,
                verification=VerificationOutcome.INEFFECTIVE,
                rollback_attempted=True,
                rollback_succeeded=True,
            ),
            source=LearningSource.LAB_SANDBOX,
            mechanism_id=mechanism,
        )


def test_cell_lookup_key_matches_the_crystallization_key() -> None:
    """Rule A over 20 corpus cases: one key function, both directions.

    ``crystallize`` stores the string and a planner's ``lookup`` builds it. If the
    two ever diverge the field silently holds cells nothing can ever find, which
    is the defect two waves have already shipped.
    """
    field_of_cells = ResponseCellField()
    memory = EffectivenessMemory()
    found = 0
    for case in range(20):
        mechanism = f"mech.case{case:02d}"
        mask = case + 1
        _feed(memory, mechanism=mechanism, epochs=(1, 2), verified_per_epoch=3)
        context = context_key(
            epoch_id=2, mechanism_id=mechanism, target_kind=TargetKind.PROCESS
        )
        cell = field_of_cells.crystallize(
            memory=memory,
            context=context,
            operator_id="SUSPEND_PROCESS",
            invariants=DEFAULT_MISSION_INVARIANTS,
            epoch_id=2,
            state_delta_mask=mask,
        )
        assert cell is not None, field_of_cells.refusals()
        read_key = incident_invariant_key(
            mechanism_id=mechanism,
            state_delta_mask=mask,
            target_kind=TargetKind.PROCESS,
        )
        assert cell.incident_invariant == read_key
        assert field_of_cells.lookup(incident_invariant=read_key, epoch_id=2) is cell
        assert field_of_cells.lookup(incident_invariant=read_key, epoch_id=9) is None
        assert cell.epochs == frozenset({1, 2})
        assert cell.phase is CellPhase.CRYSTALLIZED
        assert cell.authority is AuthorityClass.A2
        assert cell.simulated_rollback_success == 1.0
        found += 1
    assert found == 20
    assert len(field_of_cells.cells()) == 20


def test_crystallize_without_a_state_delta_mask_refuses_rather_than_guessing() -> None:
    field_of_cells = ResponseCellField()
    memory = EffectivenessMemory()
    _feed(memory, mechanism="mech.nomask", epochs=(1, 2), verified_per_epoch=3)
    cell = field_of_cells.crystallize(
        memory=memory,
        context=context_key(
            epoch_id=2, mechanism_id="mech.nomask", target_kind=TargetKind.PROCESS
        ),
        operator_id="SUSPEND_PROCESS",
        invariants=DEFAULT_MISSION_INVARIANTS,
        epoch_id=2,
    )
    assert cell is None
    assert field_of_cells.refusals()[-1].reason is (
        CrystallizationRefusal.MISSING_STATE_DELTA
    )


def test_one_epoch_of_evidence_never_crystallizes() -> None:
    """Stage 2's G2.13 wall, kept rather than lowered (falsifier F8).

    "distinct_epochs 1 < 2, so NOTHING was exported" is the expected Stage 5
    outcome too. The bound is not adjustable to make a cell appear.
    """
    field_of_cells = ResponseCellField()
    memory = EffectivenessMemory()
    _feed(memory, mechanism="mech.oneepoch", epochs=(1,), verified_per_epoch=9)
    cell = field_of_cells.crystallize(
        memory=memory,
        context=context_key(
            epoch_id=1, mechanism_id="mech.oneepoch", target_kind=TargetKind.PROCESS
        ),
        operator_id="SUSPEND_PROCESS",
        invariants=DEFAULT_MISSION_INVARIANTS,
        epoch_id=1,
        state_delta_mask=3,
    )
    assert cell is None
    assert field_of_cells.refusals()[-1].reason is CrystallizationRefusal.TOO_FEW_EPOCHS
    assert field_of_cells.cells() == ()


def test_crystallization_bounds_are_the_declared_ones() -> None:
    """The canary. Four verified effects across two epochs is still not enough."""
    assert MIN_VERIFIED_EFFECTS_TO_CRYSTALLIZE == 5
    assert MIN_DISTINCT_EPOCHS_TO_CRYSTALLIZE == 2
    field_of_cells = ResponseCellField()
    memory = EffectivenessMemory()
    _feed(memory, mechanism="mech.thin", epochs=(1, 2), verified_per_epoch=2)
    cell = field_of_cells.crystallize(
        memory=memory,
        context=context_key(
            epoch_id=2, mechanism_id="mech.thin", target_kind=TargetKind.PROCESS
        ),
        operator_id="SUSPEND_PROCESS",
        invariants=DEFAULT_MISSION_INVARIANTS,
        epoch_id=2,
        state_delta_mask=1,
    )
    assert cell is None
    assert field_of_cells.refusals()[-1].reason is (
        CrystallizationRefusal.TOO_FEW_VERIFIED_EFFECTS
    )


def test_a_failed_rollback_blocks_crystallization() -> None:
    field_of_cells = ResponseCellField()
    memory = EffectivenessMemory()
    _feed(memory, mechanism="mech.badrollback", epochs=(1, 2), verified_per_epoch=3)
    memory.observe(
        _synthetic_receipt(
            epoch_id=2,
            action_id="act.badrollback",
            outcome=Outcome.ROLLBACK_FAILED,
            verification=VerificationOutcome.INEFFECTIVE,
            rollback_attempted=True,
            rollback_succeeded=False,
        ),
        source=LearningSource.LAB_SANDBOX,
        mechanism_id="mech.badrollback",
    )
    cell = field_of_cells.crystallize(
        memory=memory,
        context=context_key(
            epoch_id=2, mechanism_id="mech.badrollback", target_kind=TargetKind.PROCESS
        ),
        operator_id="SUSPEND_PROCESS",
        invariants=DEFAULT_MISSION_INVARIANTS,
        epoch_id=2,
        state_delta_mask=1,
    )
    assert cell is None
    assert field_of_cells.refusals()[-1].reason is (
        CrystallizationRefusal.ROLLBACK_NOT_PERFECT
    )


def _one_cell() -> tuple[ResponseCellField, ResponseCellV1]:
    field_of_cells = ResponseCellField()
    memory = EffectivenessMemory()
    _feed(memory, mechanism="mech.melt", epochs=(1, 2), verified_per_epoch=3)
    cell = field_of_cells.crystallize(
        memory=memory,
        context=context_key(
            epoch_id=2, mechanism_id="mech.melt", target_kind=TargetKind.PROCESS
        ),
        operator_id="SUSPEND_PROCESS",
        invariants=DEFAULT_MISSION_INVARIANTS,
        epoch_id=2,
        state_delta_mask=6,
    )
    assert cell is not None
    return field_of_cells, cell


def test_a_cell_with_no_postconditions_is_refused() -> None:
    """A cell that cannot check its own effect is a wish, not automation (§29)."""
    _, cell = _one_cell()
    with pytest.raises(ContractError) as excinfo:
        replace(cell, postconditions=())
    assert "wish" in str(excinfo.value)
    # And every catalog entry does carry one, so the refusal is not vacuous.
    assert all(entry.postconditions for entry in CATALOG.values())


def test_a_cell_above_the_autonomous_ceiling_cannot_be_active() -> None:
    _, cell = _one_cell()
    with pytest.raises(ContractError):
        replace(cell, authority=AuthorityClass.A4)
    melted = replace(cell, authority=AuthorityClass.A4, phase=CellPhase.MELTED)
    assert melted.phase is CellPhase.MELTED


def test_a_cell_automating_an_o2_operator_needs_a_rollback_operator() -> None:
    _, cell = _one_cell()
    with pytest.raises(ContractError):
        replace(cell, rollback_operator_id=None)


def test_melting_keeps_the_cell_and_takes_it_out_of_lookup() -> None:
    field_of_cells, cell = _one_cell()
    report = field_of_cells.melt(
        cell.cell_id, triggers=(MeltTrigger.ROLLBACK_DEGRADATION,)
    )
    assert report.scope is MeltScope.FULL
    assert report.demoted_to is CellPhase.MELTED
    assert field_of_cells.lookup(
        incident_invariant=cell.incident_invariant, epoch_id=2
    ) is None
    kept = field_of_cells.cells()[0]
    assert kept.phase is CellPhase.MELTED
    assert kept.parent_cell_id == cell.cell_id
    with pytest.raises(ContractError):
        field_of_cells.melt(cell.cell_id, triggers=())


def test_a_residual_increase_is_a_partial_melt() -> None:
    field_of_cells, cell = _one_cell()
    report = field_of_cells.melt(
        cell.cell_id, triggers=(MeltTrigger.RESIDUAL_INCREASE,)
    )
    assert report.scope is MeltScope.PARTIAL
    assert report.demoted_to is CellPhase.STRESSED
    # STRESSED is still consulted, so the cell stays reachable by lookup.
    assert (
        field_of_cells.lookup(
            incident_invariant=cell.incident_invariant, epoch_id=2
        )
        is not None
    )


def test_an_epoch_transition_melts_every_active_cell() -> None:
    field_of_cells, cell = _one_cell()
    reports = field_of_cells.observe_epoch(
        EpochDecision(
            epoch_id=3,
            reason=EpochTransitionReason.SYSTEM_CHANGE_CORROBORATED,
            changed_components=frozenset({"service_digest", "policy_digest"}),
            corroborated=True,
            detail="fixture epoch change",
        )
    )
    assert len(reports) == 1
    assert set(reports[0].triggers) == {
        MeltTrigger.SERVICE_EPOCH_CHANGE,
        MeltTrigger.DEPENDENCY_DRIFT,
        MeltTrigger.AUTHORITY_POLICY_CHANGE,
    }
    assert reports[0].scope is MeltScope.FULL
    assert field_of_cells.cells()[0].phase is CellPhase.MELTED
    # An uncorroborated decision melts nothing: behavioural novelty alone may not
    # open an epoch, and it may not close a cell either.
    assert (
        field_of_cells.observe_epoch(
            EpochDecision(
                epoch_id=3,
                reason=EpochTransitionReason.REJECTED_NO_CORROBORATION,
                changed_components=frozenset(),
                corroborated=False,
                detail="fixture",
            )
        )
        == ()
    )


def test_the_cell_field_is_bounded() -> None:
    field_of_cells = ResponseCellField(max_cells=1)
    memory = EffectivenessMemory()
    for case in range(2):
        mechanism = f"mech.bound{case}"
        _feed(memory, mechanism=mechanism, epochs=(1, 2), verified_per_epoch=3)
        field_of_cells.crystallize(
            memory=memory,
            context=context_key(
                epoch_id=2, mechanism_id=mechanism, target_kind=TargetKind.PROCESS
            ),
            operator_id="SUSPEND_PROCESS",
            invariants=DEFAULT_MISSION_INVARIANTS,
            epoch_id=2,
            state_delta_mask=case + 1,
        )
    assert len(field_of_cells.cells()) == 1
    assert field_of_cells.refusals()[-1].reason is CrystallizationRefusal.FIELD_FULL
    assert field_of_cells.state_bytes() > 0
