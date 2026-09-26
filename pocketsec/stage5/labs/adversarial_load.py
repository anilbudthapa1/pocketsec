"""Adversarial-load suites for the SENTINEL half of §33, and the fixtures they run on.

Architecture §33 says every attack family has a required regression test. The five suites
here are the ones the gate's G5.12 and the §33 table name against SENTINEL, the evidence
preservation gate, the capability-token store and the response-defense monitors:
:func:`self_dos_suite`, :func:`rollback_sabotage_suite`, :func:`candidate_flood`,
:func:`token_replay_suite` and :func:`dependency_poisoning_suite`. Each returns an
:class:`AdversarialReport` carrying the value it observed and the bound it was checked
against, so a caller can print the comparison rather than a verdict somebody has to take on
faith.

**What these suites do not cover, stated so the gate does not over-claim.** They drive the
kernel, the gate, the token store and the monitors. They do not drive the transactional
executor, the rollback journal, the lease registry or the AEGIS planner, which belong to
other work packages: the journal-byte, lease-count and work-unit bounds of G5.12 are those
packages' to assert, and this module deliberately does not construct a second executor to
pretend otherwise. Where a suite needs a plan or a receipt it uses the small typed stand-ins
below, which satisfy the structural ``PlanView`` and ``ReceiptView`` protocols the monitors
read — the same reason the monitors take views at all.

**Every number these suites produce is a property of these fixtures**, which this wave wrote.
They are bound checks, not measurements of a host.
"""

from __future__ import annotations

import secrets
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from os import getloadavg
from time import perf_counter
from types import SimpleNamespace
from typing import Any

from pocketsec.stage0.benchmark.resource_metrics import ResourceSampler
from pocketsec.stage0.contracts.common import ContractError, EvidenceRef, digest_of_bytes
from pocketsec.stage0.contracts.threat_prediction_v1 import Verdict
from pocketsec.stage1.state.security_state import SecurityStateV1
from pocketsec.stage4.stage5_interface import CBFResolutionV1
from pocketsec.stage5.authority.capability import (
    HUMAN_REQUIRED_AUTONOMY,
    AuthorityGrant,
    GrantSource,
    autonomy_of,
    required_authority,
)
from pocketsec.stage5.authority.tokens import CapabilityToken, TokenStore, TokenVerdict
from pocketsec.stage5.constitution.invariants import FROZEN_CONSTITUTION
from pocketsec.stage5.constitution.schema import DEFAULT_MISSION_INVARIANTS, MissionInvariantSet
from pocketsec.stage5.evidence.preservation_gate import (
    DEFAULT_RETENTION,
    EvidencePreservationGate,
    EvidencePreservationVerdict,
    PreActionBundle,
    PreservationDecision,
)
from pocketsec.stage5.executor.identity import ManualClock
from pocketsec.stage5.governor import STAGE5_BUDGET
from pocketsec.stage5.host.simulated import (
    HostKind,
    HostSnapshot,
    ProcessRow,
    ProcessState,
    ServiceRow,
)
from pocketsec.stage5.operators.algebra import (
    DefensiveOperator,
    OperatorClass,
    ProcessIdentity,
    ProcessTarget,
    TargetKind,
    TargetScope,
)
from pocketsec.stage5.operators.catalog import CATALOG
from pocketsec.stage5.sentinel.kernel import Decision, DenyReason, SentinelKernel
from pocketsec.stage5.sentinel.monitors import (
    MAX_MONITOR_HISTORY,
    ROLLBACK_SABOTAGE_HALT,
    MonitorId,
    ResponseDefenseMonitors,
    Severity,
)

__all__ = [
    "BASE_PID",
    "DEFAULT_INCIDENT",
    "FATAL_VOLATILE",
    "FIXTURE_UNIT",
    "AdversarialReport",
    "LoadCandidate",
    "LoadPlan",
    "LoadReceipt",
    "SentinelCostReport",
    "build_kernel",
    "build_monitors",
    "build_operator",
    "build_resolution",
    "build_snapshot",
    "build_token_store",
    "candidate_flood",
    "dependency_poisoning_suite",
    "evidence_gate_for",
    "identity_for",
    "measure_sentinel_cost",
    "mint_token",
    "preserved_verdict",
    "rollback_sabotage_suite",
    "run_all",
    "self_dos_suite",
    "token_replay_suite",
    "token_shaped_impostor",
]

BASE_PID: int = 4242
DEFAULT_INCIDENT: str = "INC-S5-0001"

#: A non-critical unit: the default invariant set protects ``sshd.service`` and
#: ``systemd-journald.service``, so a fixture that used either would be denied for a reason
#: unrelated to whatever the suite is measuring.
FIXTURE_UNIT: str = "app.service"
FIXTURE_SESSION: str = "sess-app"
FIXTURE_SOCKET: str = "sock-1"

#: Volatile signals the fixture host reports. ``process_memory_map`` is deliberately absent:
#: it is the ``EVIDENCE_RETENTION`` subject of ``MI-04``, so a fixture carrying it would make
#: every degrading operator a mission-invariant violation and hide the property under test.
FIXTURE_VOLATILE: tuple[str, ...] = ("open_file_descriptors", "environment")

#: Volatile signals that trip the evidence gate, for the suites and tests that need a
#: would-destroy refusal. ``process_memory`` and ``socket_table`` are in
#: ``DEFAULT_RETENTION.uniquely_necessary``; ``process_memory_map`` is ``MI-04``'s
#: ``EVIDENCE_RETENTION`` subject, so the gate can assemble the signals policy requires
#: instead of answering INSUFFICIENT_EVIDENCE for a reason unrelated to the case.
FATAL_VOLATILE: tuple[str, ...] = ("process_memory", "socket_table", "process_memory_map")

_EXEC_DIGEST: str = digest_of_bytes(b"fixture-executable")
_EVIDENCE = EvidenceRef(store="raw", locator="fixture/evidence-1", digest=digest_of_bytes(b"e1"))

#: Scope subject per target kind. A subject reaches an argument vector, so it must pass
#: ``algebra``'s argv-token pattern; a colon would be refused there.
_SUBJECT_BY_KIND: Mapping[TargetKind, str] = {
    TargetKind.PROCESS: f"proc-{BASE_PID}",
    TargetKind.SERVICE: FIXTURE_UNIT,
    TargetKind.SESSION: FIXTURE_SESSION,
    TargetKind.SOCKET: FIXTURE_SOCKET,
    TargetKind.HOST: "localhost",
}


@dataclass(frozen=True, slots=True)
class AdversarialReport:
    """One suite's result: what it saw, what it was checked against, and whether it held."""

    suite: str
    observed_value: float | int
    bound: float | int
    within_bound: bool
    detail: str
    samples: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "suite": self.suite, "observed_value": self.observed_value, "bound": self.bound,
            "within_bound": self.within_bound, "detail": self.detail, "samples": self.samples,
        }


# --- fixtures ----------------------------------------------------------------------


def identity_for(
    *,
    pid: int = BASE_PID,
    start_time_ticks: int = 99_000,
    uid: int = 1000,
    executable_digest: str | None = _EXEC_DIGEST,
) -> ProcessIdentity:
    """The fixture target's identity. A pid is not an identity, so every field is set."""
    return ProcessIdentity(
        pid=pid,
        start_time_ticks=start_time_ticks,
        uid=uid,
        executable_digest=executable_digest,
        cgroup_id="cgroup.app",
        namespace_id="netns.app",
    )


def build_snapshot(
    *,
    identity: ProcessIdentity | None = None,
    at: int = 1_000,
    volatile: Sequence[str] = FIXTURE_VOLATILE,
    restartable: bool = True,
    unit: str | None = FIXTURE_UNIT,
    include_target: bool = True,
    preserved: Sequence[str] = (),
) -> HostSnapshot:
    """A one-process, one-service fixture host.

    ``preserved`` is what a preservation operator has CAPTURED for the target. Listing a
    signal in ``volatile`` does not preserve it (findings F4 / S5-SEC-01), so a fixture
    that wants a bundle carrying a signal must say it was captured.

    ``include_target=False`` builds the host that cannot locate the target at all — no
    process, no service, no session — which is how the precondition path is exercised for
    every target kind rather than only for processes.
    """
    row = ProcessRow(
        identity=identity or identity_for(),
        state=ProcessState.RUNNING,
        unit=unit,
        session_id=FIXTURE_SESSION,
        socket_ids=(FIXTURE_SOCKET,),
        children=(),
        volatile_signals=tuple(volatile),
        preserved_signals=tuple(preserved),
    )
    service = ServiceRow(
        unit=FIXTURE_UNIT,
        running=True,
        constrained=False,
        restartable=restartable,
        depends_on=(),
        healthy=True,
    )
    return HostSnapshot(
        host_kind=HostKind.SIMULATED,
        at=at,
        processes=(row,) if include_target else (),
        services=(service,) if include_target else (),
        sessions=(FIXTURE_SESSION,) if include_target else (),
        restricted_sockets=frozenset(),
        security_state=SecurityStateV1(),
    )


def build_operator(
    operator_id: str,
    *,
    identity: ProcessIdentity | None = None,
    incident_id: str = DEFAULT_INCIDENT,
    ttl_seconds: int | None = None,
) -> DefensiveOperator:
    """A typed operator for a catalog entry, with the TTL the fixture invariants allow.

    ``MI-06`` bounds autonomous downtime at 300 s, and the kernel applies duration bounds to
    every class, so the fixture TTL is capped there rather than at the operator's own
    maximum — otherwise half the catalog would be denied for the wrong reason.
    """
    spec = CATALOG[operator_id]
    return DefensiveOperator(
        spec=spec,
        target=ProcessTarget(
            identity=identity or identity_for(),
            scope=TargetScope(kind=spec.target_kind, subject=_SUBJECT_BY_KIND[spec.target_kind]),
        ),
        incident_id=incident_id,
        ttl_seconds=ttl_seconds or min(spec.max_duration_seconds, 300),
        evidence_refs=(_EVIDENCE,),
    )


def build_resolution(
    *,
    incident_id: str = DEFAULT_INCIDENT,
    supports: Sequence[float] = (0.90, 0.05),
    uncertainty: float = 0.20,
    truncations: Sequence[Mapping[str, Any]] = (),
    degradations: Sequence[Mapping[str, Any]] = (),
) -> CBFResolutionV1:
    """A resolution the kernel never reads and the monitors do.

    ``claim_ids`` are empty on purpose: a cited claim must resolve in the exported claim
    graph, and a fixture that cited a claim it did not carry would be refused by Stage 4's
    own seam rather than by anything this module is testing.
    """
    return CBFResolutionV1(
        resolution_id="RES-S5-0001",
        incident_id=incident_id,
        epoch_id=1,
        verdict=Verdict.MALICIOUS,
        identifiability="IDENTIFIED",
        hypotheses=tuple(
            {
                "mechanism_id": f"mech_{index}",
                "support": float(support),
                "consequence": 1.0,
                "uncertainty": uncertainty,
                "claim_ids": [],
                "evidence_digests": [_EVIDENCE.digest],
            }
            for index, support in enumerate(supports)
        ),
        consequence_distribution={"service_disruption": 0.3},
        claim_graph={"claims": []},
        evidence_lineage=(
            {
                "store": _EVIDENCE.store,
                "locator": _EVIDENCE.locator,
                "digest": _EVIDENCE.digest,
            },
        ),
        uncertainty=uncertainty,
        shadow={},
        information_gaps=(),
        truncations=tuple(truncations),
        degradations=tuple(degradations),
    )


def build_kernel(
    *, clock: ManualClock | None = None, invariants: MissionInvariantSet | None = None
) -> SentinelKernel:
    """The real kernel on the frozen constitution. There is no permissive variant to build."""
    return SentinelKernel(
        constitution=FROZEN_CONSTITUTION,
        invariants=invariants or DEFAULT_MISSION_INVARIANTS,
        clock=clock or ManualClock(1_000),
    )


def build_monitors(*, invariants: MissionInvariantSet | None = None) -> ResponseDefenseMonitors:
    return ResponseDefenseMonitors(
        invariants=invariants or DEFAULT_MISSION_INVARIANTS, budget=STAGE5_BUDGET
    )


def build_token_store(*, clock: ManualClock) -> TokenStore:
    """A store keyed per call from ``secrets``, never from a constant (S5-SEC-12).

    This used to be ``b"fixture-key-0123456789ab"``: a key-shaped constant in the
    repository contradicts ``labs/toctou.py``'s stated policy, and a fixture key that
    looks like a secret is how a fixture key becomes a production one.
    """
    return TokenStore(key=secrets.token_bytes(32), signer="stage5.labs", clock=clock)


def mint_token(
    store: TokenStore,
    operator: DefensiveOperator,
    *,
    action_id: str = "ACT-0001",
    granted_by: GrantSource | None = None,
) -> CapabilityToken:
    """Mint through the real store, so every token the suites use was really authorised.

    The grant source defaults to whatever the operator's autonomy class permits: the store
    refuses a ``POLICY`` grant for an operator §5 says a person must authorise, and a fixture
    that worked around that refusal would be measuring a different system.
    """
    required = required_authority(operator.spec)
    source = granted_by or (
        GrantSource.HUMAN
        if autonomy_of(operator.spec) in HUMAN_REQUIRED_AUTONOMY
        else GrantSource.POLICY
    )
    grant = AuthorityGrant(
        authority=required,
        granted_by=source,
        policy_version=FROZEN_CONSTITUTION.policy_version,
        subject_operator_id=operator.spec.operator_id,
        detail="labs fixture grant",
    )
    return store.mint(
        grant=grant, operator=operator, action_id=action_id, ttl_seconds=operator.ttl_seconds
    )


def preserved_verdict(
    operator: DefensiveOperator,
    resolution: CBFResolutionV1,
    snapshot: HostSnapshot,
    *,
    rollback_state: Mapping[str, Any] | None = None,
) -> EvidencePreservationVerdict:
    """A PRESERVED verdict carrying a real bundle, for the kernel's compliant baseline.

    The kernel takes the gate's *answer*, not the gate, so the baseline states the answer
    directly. The suites that exercise the gate call :meth:`EvidencePreservationGate.evaluate`
    instead — conflating the two would let a gate change silently rewrite kernel test cases.
    """
    bundle = PreActionBundle.build(
        incident_id=operator.incident_id,
        operator=operator,
        resolution=resolution,
        snapshot=snapshot,
        rollback_state=dict(rollback_state or {"restore": operator.spec.rollback_operator_id or "none"}),
    )
    return EvidencePreservationVerdict(
        PreservationDecision.PRESERVED, bundle, (), (), None, "labs fixture"
    )


# --- typed plan / receipt stand-ins the monitors read through their protocols -------


@dataclass(frozen=True, slots=True)
class LoadCandidate:
    candidate_id: str
    operator: DefensiveOperator


@dataclass(frozen=True, slots=True)
class LoadPlan:
    plan_id: str
    decision: str
    chosen: LoadCandidate | None
    frontier: tuple[LoadCandidate, ...] = ()
    rejected: tuple[str, ...] = ()
    truncations: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class LoadReceipt:
    receipt_id: str
    operator_id: str
    operator_class: int
    target_digest: str
    outcome: str
    rollback_attempted: bool = False
    rollback_succeeded: bool | None = None
    extra: Mapping[str, Any] = field(default_factory=dict)


# --- the five suites ---------------------------------------------------------------


def self_dos_suite(*, attempts: int = 24) -> AdversarialReport:
    """Can an attacker walk the responder into disrupting its own host?

    Two independent bounds have to hold: the monitors must halt autonomy at the window's
    action budget, and the kernel must deny the action whose ``recent_action_times`` already
    fill the window. A monitor that noticed without the kernel refusing would be telemetry.
    """
    monitors = build_monitors()
    limit = STAGE5_BUDGET.max_autonomous_actions_per_window
    accepted = 0
    for index in range(attempts):
        if monitors.halted():
            break
        monitors.observe_receipt(
            LoadReceipt(
                receipt_id=f"R-{index}",
                operator_id="SUSPEND_PROCESS",
                operator_class=int(OperatorClass.O3_SUSPEND),
                target_digest=f"sha256:{index:064x}",
                outcome="COMMITTED_VERIFIED",
            )
        )
        accepted += 1
    kernel_refused = _kernel_refuses_a_full_window(limit)
    held = monitors.halted() and accepted <= limit and kernel_refused
    return AdversarialReport(
        suite="self_dos_suite",
        observed_value=accepted,
        bound=limit,
        within_bound=held,
        detail=(
            f"monitors halted after {accepted} disruptive commits; kernel RESOURCE_LIMIT "
            f"denial={kernel_refused}"
        ),
        samples=attempts,
    )


def _kernel_refuses_a_full_window(limit: int) -> bool:
    """Does SENTINEL itself deny the action whose window is already full?

    The monitors noticing without the kernel refusing would be telemetry, not a control, so
    the suite asserts both halves and this is the kernel half.
    """
    clock = ManualClock(10_000)
    kernel, snapshot = build_kernel(clock=clock), build_snapshot()
    operator = build_operator("SUSPEND_PROCESS")
    resolution = build_resolution()
    verdict = kernel.verify(
        operator,
        mint_token(build_token_store(clock=clock), operator),
        evidence=preserved_verdict(operator, resolution, snapshot),
        observed_identity=operator.target.identity,
        snapshot=snapshot,
        journal_bytes=0,
        active_leases=0,
        recent_action_times=tuple(10_000 - step for step in range(limit)),
        concurrent_operator_ids=frozenset(),
    )
    return verdict.decision is Decision.DENY and DenyReason.RESOURCE_LIMIT in verdict.reasons


def rollback_sabotage_suite(*, attempts: int = 6) -> AdversarialReport:
    """An attacker who breaks rollback must not be able to keep the responder acting."""
    monitors = build_monitors()
    fired_at = 0
    for index in range(1, attempts + 1):
        monitors.observe_receipt(
            LoadReceipt(
                receipt_id=f"R-{index}",
                operator_id="SUSPEND_PROCESS",
                operator_class=int(OperatorClass.O3_SUSPEND),
                target_digest="sha256:" + "0" * 64,
                outcome="ROLLBACK_FAILED",
                rollback_attempted=True,
                rollback_succeeded=False,
            )
        )
        if monitors.halted() and fired_at == 0:
            fired_at = index
    sabotage = [f for f in monitors.findings() if f.monitor is MonitorId.ROLLBACK_SABOTAGE]
    held = bool(sabotage) and 0 < fired_at <= ROLLBACK_SABOTAGE_HALT
    return AdversarialReport(
        suite="rollback_sabotage_suite",
        observed_value=fired_at,
        bound=ROLLBACK_SABOTAGE_HALT,
        within_bound=held,
        detail=f"autonomy halted after {fired_at} failed rollback(s)",
        samples=attempts,
    )


def candidate_flood(*, count: int = 40, per_plan: int = 40) -> AdversarialReport:
    """Can a flood of candidate actions grow the responder's state without bound?

    The monitors' history is the thing under test here: the ring buffers must stay at
    ``MAX_MONITOR_HISTORY`` however many plans arrive, and every over-cap plan must fire
    ``CANDIDATE_EXPLOSION`` rather than being quietly absorbed.
    """
    monitors = build_monitors()
    resolution = build_resolution()
    candidate = LoadCandidate("C-0", build_operator("OBSERVE_PROCESS_METADATA"))
    fired = 0
    for index in range(count):
        plan = LoadPlan(
            plan_id=f"P-{index}",
            decision="OBSERVE",
            chosen=candidate,
            frontier=tuple(candidate for _ in range(per_plan)),
            rejected=tuple(f"r{n}" for n in range(per_plan)),
        )
        for finding in monitors.observe_plan(plan, resolution):
            if finding.monitor is MonitorId.CANDIDATE_EXPLOSION and finding.fired:
                fired += 1
    sizes = monitors.history_sizes()
    bounded = all(sizes[key] <= MAX_MONITOR_HISTORY for key in ("plans", "receipts", "findings"))
    return AdversarialReport(
        suite="candidate_flood",
        observed_value=max(sizes["plans"], sizes["findings"]),
        bound=MAX_MONITOR_HISTORY,
        within_bound=bounded and fired == count,
        detail=f"{fired}/{count} plans fired CANDIDATE_EXPLOSION; buffers {sizes}",
        samples=count,
    )


def token_replay_suite(*, attempts: int = 4) -> AdversarialReport:
    """A capability is single-use, so a replayed token must never verify twice."""
    clock = ManualClock(1_000)
    store = build_token_store(clock=clock)
    operator = build_operator("SUSPEND_PROCESS")
    token = mint_token(store, operator)
    verdicts = [store.redeem(token, operator=operator) for _ in range(attempts)]
    valid = sum(1 for verdict in verdicts if verdict is TokenVerdict.VALID)
    replayed = sum(1 for verdict in verdicts if verdict is TokenVerdict.REPLAYED)
    return AdversarialReport(
        suite="token_replay_suite",
        observed_value=valid,
        bound=1,
        within_bound=valid == 1 and replayed == attempts - 1,
        detail=f"{valid} VALID, {replayed} REPLAYED across {attempts} redemptions",
        samples=attempts,
    )


def dependency_poisoning_suite(*, count: int = 8) -> AdversarialReport:
    """A poisoned dependency view must raise shadow, never authority.

    The monitor has to fire on a plan that acts while the upstream reports a degradation, and
    the finding's severity must stay at ``ESCALATE`` or above without any monitor output being
    able to raise an authority class — which it structurally cannot, since a
    :class:`MonitorFinding` carries no authority field at all.
    """
    monitors = build_monitors()
    poisoned = build_resolution(
        degradations=({"component": "dependency_walk", "reason": "unreachable"},)
    )
    candidate = LoadCandidate("C-0", build_operator("SUSPEND_PROCESS"))
    fired = 0
    for index in range(count):
        plan = LoadPlan(plan_id=f"P-{index}", decision="ACT", chosen=candidate)
        for finding in monitors.observe_plan(plan, poisoned):
            if finding.monitor is MonitorId.DEPENDENCY_POISONING and finding.fired:
                if finding.severity is not Severity.ESCALATE:
                    raise ContractError("dependency poisoning must escalate, never permit")
                fired += 1
    return AdversarialReport(
        suite="dependency_poisoning_suite",
        observed_value=fired,
        bound=count,
        within_bound=fired == count,
        detail=f"{fired}/{count} acting plans raised shadow on a degraded dependency view",
        samples=count,
    )


def run_all() -> tuple[AdversarialReport, ...]:
    """Every suite, once, in one process. The gate reads this."""
    return (
        self_dos_suite(),
        rollback_sabotage_suite(),
        candidate_flood(),
        token_replay_suite(),
        dependency_poisoning_suite(),
    )


@dataclass(frozen=True, slots=True)
class SentinelCostReport:
    """A WITHIN-RUN comparison of the kernel's two paths, plus the state it holds.

    No absolute figure here is a device measurement. This host's load swung by a factor of
    seven between two runs of one Stage 2 gate, so the only number that transfers off it is
    :attr:`deny_to_pass_ratio` — two paths timed in the same process, in the same run, with
    ``/proc/loadavg`` recorded beside them (§2.8).

    ``monitor_delta_rss_bytes`` may be ``None``: on a host where ``/proc`` RSS is unreadable
    the figure is UNMEASURED, and ``None`` is what that means. It is never a plausible guess.
    """

    samples: int
    pass_checks_evaluated: int
    deny_checks_evaluated: int
    pass_wall_seconds: float
    deny_wall_seconds: float
    deny_to_pass_ratio: float | None
    monitor_delta_rss_bytes: int | None
    monitor_history_rows: int
    loadavg: tuple[float, float, float]

    def to_dict(self) -> dict[str, Any]:
        return {
            "samples": self.samples,
            "pass_checks_evaluated": self.pass_checks_evaluated,
            "deny_checks_evaluated": self.deny_checks_evaluated,
            "pass_wall_seconds": self.pass_wall_seconds,
            "deny_wall_seconds": self.deny_wall_seconds,
            "deny_to_pass_ratio": self.deny_to_pass_ratio,
            "monitor_delta_rss_bytes": self.monitor_delta_rss_bytes,
            "monitor_history_rows": self.monitor_history_rows,
            "loadavg": list(self.loadavg),
        }


def measure_sentinel_cost(*, samples: int = 2_000) -> SentinelCostReport:
    """Time both kernel paths in one run and sample the monitors' resident state.

    The comparison is structural first: a PASS must have evaluated all thirteen checks and a
    schema denial exactly one, which is a claim that holds regardless of what the clock says.
    The wall-clock figures are reported only as a ratio, and the load average travels with them.
    """
    clock = ManualClock(1_000)
    kernel, snapshot = build_kernel(clock=clock), build_snapshot()
    operator = build_operator("SUSPEND_PROCESS")
    resolution = build_resolution()
    token = mint_token(build_token_store(clock=clock), operator)
    evidence = preserved_verdict(operator, resolution, snapshot)
    arguments: dict[str, Any] = {
        "evidence": evidence, "observed_identity": operator.target.identity,
        "snapshot": snapshot, "journal_bytes": 0, "active_leases": 0,
        "recent_action_times": (), "concurrent_operator_ids": frozenset(),
    }
    ill_formed = token_shaped_impostor(token)

    passing = kernel.verify(operator, token, **arguments)
    denying = kernel.verify(operator, ill_formed, **arguments)  # type: ignore[arg-type]

    start = perf_counter()
    for _ in range(samples):
        kernel.verify(operator, token, **arguments)
    pass_wall = perf_counter() - start
    start = perf_counter()
    for _ in range(samples):
        kernel.verify(operator, ill_formed, **arguments)  # type: ignore[arg-type]
    deny_wall = perf_counter() - start

    delta_rss, rows = _measure_monitor_state()
    return SentinelCostReport(
        samples=samples,
        pass_checks_evaluated=len(passing.evaluated_checks),
        deny_checks_evaluated=len(denying.evaluated_checks),
        pass_wall_seconds=pass_wall,
        deny_wall_seconds=deny_wall,
        deny_to_pass_ratio=(deny_wall / pass_wall) if pass_wall > 0 else None,
        monitor_delta_rss_bytes=delta_rss,
        monitor_history_rows=rows,
        loadavg=getloadavg(),
    )


def _measure_monitor_state() -> tuple[int | None, int]:
    """Resident-state delta and buffer occupancy after four windows of receipts.

    ``None`` is returned for the RSS delta where ``/proc`` cannot be read: that is UNMEASURED,
    and UNMEASURED is ``None`` rather than a plausible-looking number (ADR-0004).
    """
    monitors = build_monitors()
    events = MAX_MONITOR_HISTORY * 4
    with ResourceSampler() as sampler:
        for index in range(events):
            monitors.observe_receipt(
                LoadReceipt(
                    receipt_id=f"R-{index}", operator_id="SUSPEND_PROCESS",
                    operator_class=int(OperatorClass.O3_SUSPEND),
                    target_digest=f"sha256:{index:064x}", outcome="COMMITTED_VERIFIED",
                )
            )
    metrics = sampler.result(events_processed=events, startup_seconds=None)
    sizes = monitors.history_sizes()
    return metrics.delta_rss_bytes, max(sizes["plans"], sizes["receipts"], sizes["findings"])


def token_shaped_impostor(token: CapabilityToken) -> Any:
    """A token-shaped object carrying every attribute the kernel reads.

    Only an ``isinstance`` check rejects it, which is exactly the property ``_check_schema``
    has to hold: a payload that looks like a capability is not one.
    """
    return SimpleNamespace(
        operator_id=token.operator_id, incident_id=token.incident_id,
        authority=token.authority, target_digest=token.target_digest,
        schema_version=token.schema_version, policy_version=token.policy_version,
        valid_from=token.valid_from, expiry=token.expiry,
        max_duration_seconds=token.max_duration_seconds,
        rollback_required=token.rollback_required, nonce=token.nonce,
        signer=token.signer, mac=token.mac,
    )


def evidence_gate_for(
    *, invariants: MissionInvariantSet | None = None
) -> EvidencePreservationGate:
    """The real gate on the default retention policy, for the suites and tests that need it."""
    return EvidencePreservationGate(
        policy=DEFAULT_RETENTION, invariants=invariants or DEFAULT_MISSION_INVARIANTS
    )
