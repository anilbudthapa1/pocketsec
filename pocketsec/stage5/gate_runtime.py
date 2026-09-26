"""G5.6, G5.7, G5.8, G5.10, G5.11: the criteria that need a transaction to actually run.

Each one drives the real executor, the real SENTINEL kernel, the real evidence gate and
the real lease sweeper against ``SimulatedHost``. That is also each one's limit, and the
two criteria §6.1 declares unmeetable here are written to **fail**, not to pass on the
simulator: rollback reliability (G5.7) and safe recovery (G5.11) are properties of a
Linux host, and a rate this wave measured against a host model this wave wrote is a
property of that model (ADR-0046). The mechanisms still run and their in-simulator
figures are reported, named ``simulated_*`` so the caveat travels with the number.

The lab host here is small on purpose: one target process that carries the one volatile
signal the default mission invariants require (so the evidence gate has something to
preserve), one unit with a dependency (so a divergence is possible), one socket and one
session. Every refusal a check sees is then the refusal under test.
"""

from __future__ import annotations

import ast
import secrets
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import digest_of_bytes
from pocketsec.stage0.gate import REPO_ROOT, GateCheck
from pocketsec.stage1.state.security_state import Privilege, SecurityStateV1
from pocketsec.stage5.authority.capability import (
    AuthorityGrant,
    GrantSource,
    required_authority,
)
from pocketsec.stage5.authority.tokens import MAX_TOKEN_LIFETIME_SECONDS, TokenStore
from pocketsec.stage5.constitution.invariants import FROZEN_CONSTITUTION, AuthorityClass
from pocketsec.stage5.constitution.schema import (
    DEFAULT_MISSION_INVARIANTS,
    InvariantKind,
    MissionInvariantSet,
)
from pocketsec.stage5.evidence.preservation_gate import PreservationDecision
from pocketsec.stage5.executor.identity import ManualClock
from pocketsec.stage5.executor.lease import LeaseSweeper
from pocketsec.stage5.executor.transactional import COMMITTED_OUTCOMES, Outcome
from pocketsec.stage5.executor.verify import VerificationOutcome
from pocketsec.stage5.governor import ResourceGovernor
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
from pocketsec.stage5.labs import adversarial_load as fixtures
from pocketsec.stage5.labs.response_corpus import (
    build_critical_service_baits,
    build_evidence_destroying_cases,
)
from pocketsec.stage5.memory.effectiveness import (
    AUTONOMOUS_ROLLBACK_THRESHOLD,
    MIN_SAMPLES_FOR_RATE,
    EffectivenessMemory,
    LearningSource,
)
from pocketsec.stage5.operators.algebra import (
    DefensiveOperator,
    ProcessIdentity,
    ProcessTarget,
    TargetKind,
    TargetScope,
)
from pocketsec.stage5.operators.catalog import CATALOG, autonomous_ids
from pocketsec.stage5.recovery.safe_state import (
    ManifoldStatus,
    SafeStateManifold,
    SafeStatePlanner,
    capability_signature,
    execute_recovery,
    in_manifold,
)
from pocketsec.stage5.stage6_interface import build_record

if TYPE_CHECKING:  # pragma: no cover - annotations only; gate.py imports this module
    from pocketsec.stage5.gate import Stage5GateContext
    from pocketsec.stage5.labs.baselines import BaselineRig

__all__ = [
    "LAB_PID",
    "LabRig",
    "check_evidence_and_invariants",
    "check_interventions_leased",
    "check_post_action_verification",
    "check_rollback_reliability",
    "check_safe_recovery",
    "contain",
    "lab_rig",
    "lab_run",
    "prime_memory",
]

#: Operators the gate contains with, in preference order. Both are autonomous (A2),
#: both are leased, and both have a catalog rollback — the only kind of intervention the
#: frozen constitution lets the system take on its own.
CONTAINMENT_OPERATORS: tuple[str, ...] = ("SUSPEND_PROCESS", "RESTRICT_LOCAL_SOCKET")

LAB_PID = 7001
LAB_UNIT = "app.service"
LAB_DEPENDENCY = "worker.service"
LAB_SOCKET = "sock-lab-1"
LAB_SESSION = "sess-lab-1"
_LAB_SIGNAL = "process_memory_map"
_RECOVERY_CASES = 20
_EVIDENCE_CASES = 6
_BAIT_CASES = 6


# --- shared helpers --------------------------------------------------------------------


def _grant(operator: DefensiveOperator, *, source: GrantSource) -> AuthorityGrant:
    return AuthorityGrant(
        authority=required_authority(operator.spec),
        granted_by=source,
        policy_version=FROZEN_CONSTITUTION.policy_version,
        subject_operator_id=operator.spec.operator_id,
        detail=f"stage5 gate {source.value.lower()} grant",
    )


def _mint(tokens: TokenStore, operator: DefensiveOperator, action_id: str, *,
          source: GrantSource = GrantSource.POLICY) -> Any:
    return tokens.mint(
        grant=_grant(operator, source=source),
        operator=operator,
        action_id=action_id,
        ttl_seconds=min(operator.ttl_seconds, MAX_TOKEN_LIFETIME_SECONDS),
    )


def contain(rig: BaselineRig, *, action_id: str) -> tuple[Any, Any, Any] | None:
    """Contain one corpus case through the real executor: ``(candidate, receipt, executor)``.

    Picks the first autonomous leased candidate the case's own field proposes; ``None``
    when the field proposes none, which the calling check counts rather than hides.
    """
    from pocketsec.stage5.gate import executor_for_rig

    for operator_id in CONTAINMENT_OPERATORS:
        for candidate in rig.field.candidates:
            if candidate.operator.spec.operator_id != operator_id:
                continue
            if candidate.authority is not AuthorityClass.A2:
                continue
            executor = executor_for_rig(rig)
            token = _mint(rig.tokens, candidate.operator, action_id)
            receipt = executor.execute(
                candidate.operator, token, resolution=rig.case.resolution
            )
            return candidate, receipt, executor
    return None


def _hostile(cases: Sequence[Any]) -> list[Any]:
    return [case for case in cases if not case.truth.benign_admin]


@dataclass
class LabRig:
    """The gate's own single-host rig: host, clock, tokens and a real executor."""

    clock: ManualClock
    host: Any
    tokens: TokenStore
    executor: Any
    invariants: Any


def _identity() -> ProcessIdentity:
    return ProcessIdentity(
        pid=LAB_PID, start_time_ticks=900_100, uid=1000,
        executable_digest=digest_of_bytes(b"stage5-gate-lab-executable"),
        cgroup_id="cg-lab", namespace_id="ns-lab",
    )


def _lab_host(faults: FaultProfile, clock: ManualClock) -> SimulatedHost:
    return SimulatedHost(
        # A member of LAB_UNIT: since findings F3 a SERVICE operator must target a process
        # of the unit it constrains, and with ``unit=None`` G5.10's divergent case was
        # refused PRECONDITION before the host and detected nothing.
        processes=[ProcessRow(
            identity=_identity(), state=ProcessState.RUNNING, unit=LAB_UNIT,
            session_id=LAB_SESSION, socket_ids=(LAB_SOCKET,), children=(),
            volatile_signals=(_LAB_SIGNAL,),
        )],
        services=[
            ServiceRow(unit=LAB_UNIT, running=True, constrained=False, restartable=True,
                       depends_on=(LAB_DEPENDENCY,), healthy=True),
            ServiceRow(unit=LAB_DEPENDENCY, running=True, constrained=False, restartable=True,
                       depends_on=(), healthy=True),
        ],
        sessions=[LAB_SESSION],
        security_state=SecurityStateV1(privilege=Privilege.ROOT),
        faults=faults,
        clock=clock,
    )


def lab_rig(faults: FaultProfile, *, host_wrapper: Any = None,
            invariants: MissionInvariantSet = DEFAULT_MISSION_INVARIANTS) -> LabRig:
    """A fresh lab host with a real executor on the frozen constitution."""
    from pocketsec.stage5.gate import assemble_executor

    clock = ManualClock(at=1_000)
    inner = _lab_host(faults, clock)
    host = inner if host_wrapper is None else host_wrapper(inner)
    # Per call, from ``secrets`` (S5-SEC-12): the key used to be a digest of the public
    # fault profile, so anyone who could read the profile could mint for the lab host.
    tokens = TokenStore(key=secrets.token_bytes(32), signer="stage5.gate.lab", clock=clock)
    executor = assemble_executor(host=host, clock=clock, invariants=invariants, tokens=tokens)
    return LabRig(clock=clock, host=host, tokens=tokens, executor=executor, invariants=invariants)


def lab_operator(operator_id: str) -> DefensiveOperator:
    entry = CATALOG[operator_id]
    subject = {
        TargetKind.PROCESS: f"pid.{LAB_PID}", TargetKind.SOCKET: LAB_SOCKET,
        TargetKind.SESSION: LAB_SESSION, TargetKind.SERVICE: LAB_UNIT, TargetKind.HOST: "host",
    }[entry.target_kind]
    return DefensiveOperator(
        spec=entry,
        target=ProcessTarget(identity=_identity(),
                             scope=TargetScope(kind=entry.target_kind, subject=subject)),
        incident_id="inc.stage5.gate",
        ttl_seconds=min(300, entry.max_duration_seconds),
        evidence_refs=(),
    )


def lab_run(rig: LabRig, operator_id: str, *, source: GrantSource = GrantSource.POLICY,
            action_id: str = "act.gate.lab", truncated: bool = False) -> Any:
    """One transaction on the lab host. ``truncated`` hands it a resolution that lost worlds."""
    operator = lab_operator(operator_id)
    token = _mint(rig.tokens, operator, action_id, source=source)
    lost = ({"what": "world", "identifier": "w-lost", "reason": "bound"},) if truncated else ()
    resolution = fixtures.build_resolution(incident_id=operator.incident_id, truncations=lost)
    return rig.executor.execute(operator, token, resolution=resolution)


# --- G5.6 -----------------------------------------------------------------------------


def _lease_row_ok(rig: BaselineRig, candidate: Any, receipt: Any) -> bool:
    spec = candidate.operator.spec
    lease = next(
        (row for row in rig.leases.leases_on(receipt.target_digest)
         if row.lease_id == receipt.lease_id), None,
    )
    return (
        lease is not None
        and lease.rollback_operator_id is not None
        and lease.ttl_seconds <= spec.max_duration_seconds
        and lease.target_digest == receipt.target_digest
        and len(receipt.postconditions) >= 1
    )


def _sweep_restores(rig: BaselineRig, executor: Any, before: HostSnapshot) -> tuple[bool, bool]:
    """Advance a clock that never moves on its own, sweep explicitly, compare capability."""
    held = rig.leases.active(rig.clock.now())
    rig.clock.advance(max(lease.hard_deadline() for lease in held) - rig.clock.now() + 1)
    sweeper = LeaseSweeper(registry=rig.leases, executor=executor, tokens=rig.tokens,
                           clock=rig.clock)
    expiries = sweeper.sweep(now=rig.clock.now())
    swept = len(expiries) == len(held) and all(row.rolled_back is True for row in expiries)
    restored = capability_signature(rig.host.snapshot()) == capability_signature(before)
    return swept and rig.leases.active(rig.clock.now()) == (), restored


def check_interventions_leased(ctx: Stage5GateContext) -> GateCheck:
    """G5.6 — every autonomous intervention is scoped, expiring, observable, rollback-aware."""
    from pocketsec.stage5.labs.baselines import build_rig

    leased = swept = restored = committed = uncontained = 0
    for index, case in enumerate(_hostile(ctx.corpus)):
        rig = build_rig(case)
        before = rig.host.snapshot()
        outcome = contain(rig, action_id=f"act.g56.{index}")
        if outcome is None:
            uncontained += 1
            continue
        candidate, receipt, executor = outcome
        if receipt.outcome not in COMMITTED_OUTCOMES:
            continue
        committed += 1
        leased += _lease_row_ok(rig, candidate, receipt)
        was_swept, was_restored = _sweep_restores(rig, executor, before)
        swept += was_swept
        restored += was_restored
    passed = committed > 0 and leased == committed == swept == restored
    return GateCheck(
        "G5.6",
        "Every autonomous intervention is scoped, expiring, observable and rollback-aware",
        passed,
        f"{committed} autonomous >=O2 containments committed on the hostile corpus cases "
        f"({uncontained} cases proposed no autonomous leased candidate); leased with a "
        f"rollback operator, ttl <= max duration, matching target digest and >=1 probed "
        f"postcondition: {leased}/{committed}; under a ManualClock advanced past every hard "
        f"deadline, LeaseSweeper.sweep() expired and rolled back {swept}/{committed} and left "
        f"active(now) empty; capability signature restored to the pre-action snapshot "
        f"{restored}/{committed} (simulated host)",
    )


# --- G5.7 -----------------------------------------------------------------------------


def rollback_drills(ctx: Stage5GateContext) -> tuple[EffectivenessMemory, dict[str, int]]:
    """Force a rollback on every hostile case: ``enforcement_failure_rate=1.0``.

    The host reports success and changes nothing, verification comes back
    INEFFECTIVE, and the executor rolls back. Each receipt is folded into a memory as
    ``LAB_SANDBOX`` — the §31 source that may learn O0..O6 — so ``rollback_reliability``
    is computed by the same code the planner reads. The rate is a property of
    ``FaultProfile``, not of a host.
    """
    from pocketsec.stage5.labs.baselines import build_rig

    memory, attempts = EffectivenessMemory(), dict.fromkeys(CONTAINMENT_OPERATORS, 0)
    for operator_id in CONTAINMENT_OPERATORS:
        for index, case in enumerate(_hostile(ctx.corpus) * 2):
            faulty = replace(case, faults=FaultProfile(seed=index, enforcement_failure_rate=1.0))
            rig = build_rig(faulty)
            candidate = next((c for c in rig.field.candidates
                              if c.operator.spec.operator_id == operator_id
                              and c.authority is AuthorityClass.A2), None)
            if candidate is None:
                continue
            from pocketsec.stage5.gate import executor_for_rig

            token = _mint(rig.tokens, candidate.operator, f"act.g57.{operator_id}.{index}")
            receipt = executor_for_rig(rig).execute(
                candidate.operator, token, resolution=rig.case.resolution)
            mechanism = max(rig.case.resolution.hypotheses,
                            key=lambda row: float(row["support"]))["mechanism_id"]
            memory.observe(receipt, source=LearningSource.LAB_SANDBOX, mechanism_id=mechanism)
            attempts[operator_id] += int(receipt.rollback_attempted)
    return memory, attempts


def prime_memory(rig: BaselineRig) -> int:
    """Fill ``rig.memory`` from in-simulator LAB_SANDBOX drills on copies of this case.

    For each containment operator, ``MIN_SAMPLES_FOR_RATE`` forced-rollback drills and
    as many clean ones, each on a fresh copy of the case's host, keyed by the case's own
    leading mechanism so the planner's read key is the write key (§4.9 Rule A). This is
    how the memory is meant to be learned (§31); every rate it then holds is a property
    of ``FaultProfile``. Returns the number of receipts folded in.
    """
    from pocketsec.stage5.gate import executor_for_rig
    from pocketsec.stage5.labs.baselines import build_rig

    case = rig.case
    mechanism = max(case.resolution.hypotheses, key=lambda row: float(row["support"]))
    folded = 0
    for operator_id in CONTAINMENT_OPERATORS:
        for rate in (1.0, 0.0):
            for index in range(MIN_SAMPLES_FOR_RATE):
                drill = build_rig(replace(case, faults=FaultProfile(
                    seed=1_000 + index, enforcement_failure_rate=rate)))
                candidate = next((c for c in drill.field.candidates
                                  if c.operator.spec.operator_id == operator_id
                                  and c.authority is AuthorityClass.A2), None)
                if candidate is None:
                    break
                token = _mint(drill.tokens, candidate.operator,
                              f"act.prime.{operator_id}.{rate}.{index}")
                receipt = executor_for_rig(drill).execute(
                    candidate.operator, token, resolution=case.resolution)
                rig.memory.observe(receipt, source=LearningSource.LAB_SANDBOX,
                                   mechanism_id=str(mechanism["mechanism_id"]))
                folded += 1
    return folded


def check_rollback_reliability(ctx: Stage5GateContext) -> GateCheck:
    """G5.7 — every autonomous operator meets a predefined rollback reliability threshold.

    Fails by construction while the host is simulated (§6.1, ADR-0046). The per-operator
    in-simulator figures are reported so the *handling* of rollback is visible.
    """
    memory, attempts = rollback_drills(ctx)
    epoch = ctx.corpus[0].resolution.epoch_id
    rows: list[str] = []
    meets: dict[str, bool | None] = {}
    for operator_id in autonomous_ids(FROZEN_CONSTITUTION):
        meets[operator_id] = memory.meets_threshold(
            operator_id=operator_id, epoch_id=epoch, threshold=AUTONOMOUS_ROLLBACK_THRESHOLD)
        rate = memory.rollback_reliability(operator_id=operator_id, epoch_id=epoch)
        if operator_id in attempts:
            count = attempts[operator_id]
            rows.append(f"{operator_id} simulated_rollback_success={rate} n={count}")
    real_host = False  # SimulatedHost is the only HostAdapter; there is no RealHost (§9.2.15)
    passed = real_host and all(value is True for value in meets.values())
    unmet = sorted(op for op, value in meets.items() if value is not True)
    return GateCheck(
        "G5.7",
        "Every autonomous operator meets a predefined rollback reliability threshold",
        passed,
        f"NOT MET — real-host rollback reliability is UNMEASURED: host_kind is "
        f"{HostKind.SIMULATED.value} and no RealHost exists (ADR-0046); what would measure "
        "it: paired containment/restore drills on an instrumented Linux host, >=8 per "
        f"operator per kernel version. In-simulator only: {'; '.join(rows)} "
        f"(threshold {AUTONOMOUS_ROLLBACK_THRESHOLD}, MIN_SAMPLES_FOR_RATE "
        f"{MIN_SAMPLES_FOR_RATE}); {len(unmet)} of {len(meets)} autonomous operators have no "
        f"rate at all or miss it: {unmet}",
    )


# --- G5.8 -----------------------------------------------------------------------------


def _evidence_refusals(ctx: Stage5GateContext) -> tuple[int, int, list[str]]:
    """(a): an evidence-destroying action is refused before the host and the refusal kept."""
    from pocketsec.stage5.gate import executor_for_rig
    from pocketsec.stage5.labs.baselines import build_rig

    refused, total, faults = 0, 0, []
    for index, case in enumerate(build_evidence_destroying_cases(count=_EVIDENCE_CASES, seed=29)):
        rig = build_rig(case)
        before, calls = rig.host.snapshot().canonical_bytes(), rig.host.apply_calls
        operator = _target_operator(rig, "SUSPEND_PROCESS")
        total += 1
        verdict = rig.gate.evaluate(operator=operator, resolution=case.resolution,
                                    snapshot=rig.host.snapshot(), rollback_state={"probe": True})
        token = _mint(rig.tokens, operator, f"act.g58.ev.{index}")
        receipt = executor_for_rig(rig).execute(operator, token, resolution=case.resolution)
        record = _record_for(case, receipt, rig)
        recorded = any(row.get("receipt_id") == receipt.receipt_id
                       for row in record.sentinel_denials)
        ok = (verdict.decision is PreservationDecision.REFUSED_WOULD_DESTROY
              and receipt.outcome is Outcome.REFUSED_EVIDENCE and recorded
              and rig.host.apply_calls == calls
              and rig.host.snapshot().canonical_bytes() == before)
        refused += ok
        if not ok:
            faults.append(f"{case.case_id}:{verdict.decision.value}/{receipt.outcome.value}")
    return refused, total, faults


def _target_operator(rig: BaselineRig, operator_id: str) -> DefensiveOperator:
    """``operator_id`` against the case's leading lineage target, built from the catalog.

    Built by hand rather than read from the field, because the field already drops
    candidates that break an invariant — and G5.8 asks whether the *kernel* and the
    *evidence gate* refuse them, independently of the planner having filtered them.
    """
    entry = CATALOG[operator_id]
    row = next(r for r in rig.before.processes
               if any(str(r.identity.pid) == str(lineage.get("target_pid"))
                      for lineage in rig.case.resolution.evidence_lineage))
    return DefensiveOperator(
        spec=entry,
        target=ProcessTarget(identity=row.identity, scope=TargetScope(
            kind=entry.target_kind, subject=f"pid.{row.identity.pid}")),
        incident_id=rig.case.resolution.incident_id,
        ttl_seconds=min(300, entry.max_duration_seconds),
        evidence_refs=(),
    )


def _record_for(case: Any, receipt: Any, rig: BaselineRig) -> Any:
    return build_record(
        record_id=f"rec.{receipt.action_id}", incident_id=case.resolution.incident_id,
        epoch_id=case.resolution.epoch_id, resolution_id=case.resolution.resolution_id,
        plan_decision="ACT", host_kind=HostKind.SIMULATED, receipts=(receipt,),
        governor_spend=rig.governor.spend_report(),
    )


def _bait_denials() -> tuple[int, int]:
    """(b): an interrupting action on a protected unit is denied MISSION_INVARIANT."""
    from pocketsec.stage5.gate import executor_for_rig
    from pocketsec.stage5.labs.baselines import build_rig
    from pocketsec.stage5.sentinel.kernel import DenyReason

    denied, total = 0, 0
    for index, case in enumerate(build_critical_service_baits(count=_BAIT_CASES, seed=31)):
        rig = build_rig(case)
        operator = _target_operator(rig, "SUSPEND_PROCESS")
        token = _mint(rig.tokens, operator, f"act.g58.bait.{index}")
        receipt = executor_for_rig(rig).execute(operator, token, resolution=case.resolution)
        total += 1
        denied += (receipt.outcome is Outcome.REFUSED_SENTINEL
                   and DenyReason.MISSION_INVARIANT in receipt.sentinel_verdict.reasons)
    return denied, total


def violations_match_is_total() -> bool:
    """(b'): ``MissionInvariantSet.violations`` matches every ``InvariantKind``, no wildcard.

    The spec's "a new member makes mypy --strict fail" needs mypy, which is not installed
    here; this is the AST half, which does not need it.
    """
    source = (REPO_ROOT / "pocketsec" / "stage5" / "constitution" / "schema.py").read_text(
        encoding="utf-8")
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.FunctionDef) and node.name == "violations":
            for match in (n for n in ast.walk(node) if isinstance(n, ast.Match)):
                arms = {ast.unparse(case.pattern) for case in match.cases}
                wildcard = any(isinstance(case.pattern, ast.MatchAs) and case.pattern.pattern
                               is None for case in match.cases)
                wanted = {f"InvariantKind.{member.name}" for member in InvariantKind}
                return arms == wanted and not wildcard
    return False


def _exception_needs_a5_human() -> tuple[bool, bool]:
    """(d): EXCEPTION_GRANTED only for an A5 HUMAN grant; a POLICY A5 grant is refused."""
    from pocketsec.stage5.labs.baselines import build_rig

    case = build_evidence_destroying_cases(count=1, seed=37)[0]
    rig = build_rig(case)
    operator = _target_operator(rig, "SUSPEND_PROCESS")

    def decision(source: GrantSource) -> PreservationDecision:
        grant = AuthorityGrant(authority=AuthorityClass.A5, granted_by=source,
                               policy_version=FROZEN_CONSTITUTION.policy_version,
                               subject_operator_id=operator.spec.operator_id,
                               detail="gate evidence exception")
        return rig.gate.evaluate(operator=operator, resolution=case.resolution,
                                 snapshot=rig.host.snapshot(), rollback_state={"probe": True},
                                 exception=grant).decision

    return (decision(GrantSource.HUMAN) is PreservationDecision.EXCEPTION_GRANTED,
            decision(GrantSource.POLICY) is not PreservationDecision.EXCEPTION_GRANTED)


def check_evidence_and_invariants(ctx: Stage5GateContext) -> GateCheck:
    """G5.8 — evidence and mission invariants are machine-enforced."""
    refused, total, faults = _evidence_refusals(ctx)
    denied, baits = _bait_denials()
    total_match = violations_match_is_total()
    invariant_hits = sum(row.mission_invariant_violations for row in ctx.outcomes.values())
    evidence_hits = sum(row.evidence_violations for row in ctx.outcomes.values())
    human_ok, policy_refused = _exception_needs_a5_human()
    passed = (total > 0 and refused == total and baits > 0 and denied == baits and total_match
              and invariant_hits == 0 and evidence_hits == 0 and human_ok and policy_refused)
    return GateCheck(
        "G5.8",
        "Evidence and mission invariants are machine-enforced",
        passed,
        f"(a) {refused}/{total} evidence-destroying suspensions refused REFUSED_WOULD_DESTROY "
        f"-> REFUSED_EVIDENCE before the host, host unchanged, refusal in the receipt and in "
        f"ResponseRecordV1.sentinel_denials {faults[:2]}; (b) {denied}/{baits} critical-"
        f"service baits denied MISSION_INVARIANT by SENTINEL; violations() is a total match "
        f"over InvariantKind with no wildcard: {total_match} (AST; the gate runs no mypy); (c) "
        f"across all {len(ctx.outcomes)} arms on the corpus: mission-invariant violations "
        f"{invariant_hits}, evidence violations {evidence_hits}; (d) A5 HUMAN exception "
        f"granted {human_ok}, A5 POLICY exception refused {policy_refused}",
    )


# --- G5.10 ----------------------------------------------------------------------------


class _TargetExitsAfterApply:
    """A host whose target process exits right after the action.

    What the observation did is confirmed; whether the attacker's lineage adapted
    afterwards is not, because the lineage is gone. That is the honest case of a
    required probe that cannot be answered, and it must read ``None``, never ``False``.
    """

    def __init__(self, inner: SimulatedHost) -> None:
        self._inner, self._applied = inner, False

    @property
    def host_kind(self) -> HostKind:
        return self._inner.host_kind

    @property
    def apply_calls(self) -> int:
        return self._inner.apply_calls

    def snapshot(self) -> HostSnapshot:
        snap = self._inner.snapshot()
        if not self._applied:
            return snap
        return replace(snap, processes=tuple(
            row for row in snap.processes if row.identity.pid != LAB_PID))

    def observe_identity(self, pid: int) -> ProcessIdentity | None:
        return self._inner.observe_identity(pid)

    def apply(self, operator: DefensiveOperator, argv: tuple[str, ...]) -> HostEffect:
        effect = self._inner.apply(operator, argv)
        self._applied = True
        return effect


def _without_retention() -> MissionInvariantSet:
    """The default set minus EVIDENCE_RETENTION, so observation loss cannot mask the None."""
    return MissionInvariantSet(tuple(
        row for row in DEFAULT_MISSION_INVARIANTS.invariants
        if row.kind is not InvariantKind.EVIDENCE_RETENTION))


def _verification_cases() -> Mapping[str, Any]:
    # Evidence first, then the action: since findings F4 / S5-SEC-01 only a CAPTURED signal
    # counts as preserved, so the suspension is refused MISSION_INVARIANT (the retained
    # process_memory_map) unless a preservation operator ran first on the same host.
    faulty = lab_rig(FaultProfile(seed=41, enforcement_failure_rate=1.0))
    lab_run(faulty, "PRESERVE_VOLATILE_EVIDENCE", action_id="act.gate.lab.preserve")
    ineffective = lab_run(faulty, "SUSPEND_PROCESS")
    divergent = lab_run(lab_rig(FaultProfile(seed=43, dependency_restart_rate=1.0)),
                         "CONSTRAIN_SERVICE", source=GrantSource.HUMAN)
    hidden = lab_run(lab_rig(FaultProfile(seed=47), host_wrapper=_TargetExitsAfterApply,
                             invariants=_without_retention()), "OBSERVE_PROCESS_METADATA")
    return {"ineffective": ineffective, "divergent": divergent, "unobservable": hidden}


def check_post_action_verification() -> GateCheck:
    """G5.10 — post-action verification detects ineffective or divergent actions."""
    cases = _verification_cases()
    ineffective, divergent, hidden = cases["ineffective"], cases["divergent"], cases["unobservable"]
    detected_ineffective = (ineffective.verification is VerificationOutcome.INEFFECTIVE
                            and ineffective.rollback_attempted)
    detected_divergent = (divergent.verification is VerificationOutcome.DIVERGENT
                          and divergent.rollback_attempted)
    unknown = [r for r in hidden.postconditions if r.satisfied is None]
    unverifiable = (hidden.verification is VerificationOutcome.UNVERIFIABLE and bool(unknown)
                    and hidden.outcome is Outcome.COMMITTED_UNVERIFIED)
    detected = int(detected_ineffective) + int(detected_divergent)
    return GateCheck(
        "G5.10",
        "Post-action verification detects ineffective or divergent actions",
        detected == 2 and unverifiable,
        f"{detected} of 2 injected faults detected (target 100%): "
        f"enforcement_failure_rate=1.0 -> {ineffective.verification} / "
        f"{ineffective.outcome.value}, rollback attempted {ineffective.rollback_attempted}; "
        f"dependency_restart_rate=1.0 -> {divergent.verification} / {divergent.outcome.value}, "
        f"rollback attempted {divergent.rollback_attempted}; target exits after an observation "
        f"-> {hidden.verification} / {hidden.outcome.value} with {len(unknown)} postcondition(s)"
        " satisfied=None (not False) (simulated host)",
    )


# --- G5.11 ----------------------------------------------------------------------------


class _SignatureLog:
    """Wraps a host and records the capability signature at every read."""

    def __init__(self, inner: SimulatedHost) -> None:
        self._inner = inner
        self.signatures: list[frozenset[str]] = []

    @property
    def host_kind(self) -> HostKind:
        return self._inner.host_kind

    def snapshot(self) -> HostSnapshot:
        snap = self._inner.snapshot()
        self.signatures.append(capability_signature(snap))
        return snap

    def observe_identity(self, pid: int) -> ProcessIdentity | None:
        return self._inner.observe_identity(pid)

    def apply(self, operator: DefensiveOperator, argv: tuple[str, ...]) -> HostEffect:
        return self._inner.apply(operator, argv)

    @property
    def apply_calls(self) -> int:
        return self._inner.apply_calls


@dataclass(frozen=True, slots=True)
class _Recovery:
    report: Any
    incremental: bool
    status_before: ManifoldStatus
    violated_before: tuple[str, ...]
    restored: bool


def _manifold(rig: BaselineRig) -> SafeStateManifold:
    return SafeStateManifold(invariants=rig.case.invariants, required_observation=frozenset(),
                             blocked_trajectory_signals=frozenset())


def _recover_one(rig: BaselineRig, index: int) -> _Recovery | None:
    """Contain one case, then plan and execute staged recovery through a logging host."""
    from pocketsec.stage5.gate import assemble_executor

    before = in_manifold(rig.before, _manifold(rig), leases=())
    outcome = contain(rig, action_id=f"act.g511.{index}")
    if outcome is None or outcome[1].outcome not in COMMITTED_OUTCOMES:
        return None
    plan = SafeStatePlanner(manifold=_manifold(rig), catalog=CATALOG,
                            governor=ResourceGovernor()).plan(
        contained=rig.leases.active(rig.clock.now()), snapshot=rig.host.snapshot(),
        incident_id=rig.case.resolution.incident_id)
    logged = _SignatureLog(rig.host)
    executor = assemble_executor(host=logged, clock=rig.clock, invariants=rig.case.invariants,
                                 tokens=rig.tokens, leases=rig.leases)
    grants = {step.operator.spec.operator_id: _grant(step.operator, source=GrantSource.POLICY)
              for step in plan.steps}
    report = execute_recovery(plan, executor=executor, tokens=rig.tokens, grant=grants,
                              resolution=rig.case.resolution)
    pairs = zip(logged.signatures, logged.signatures[1:], strict=False)
    return _Recovery(
        report=report,
        incremental=all(len(earlier ^ later) <= 1 for earlier, later in pairs),
        status_before=before.status,
        violated_before=tuple(f"{row.invariant_id}:{row.detail}" for row in before.violated),
        restored=capability_signature(rig.host.snapshot()) == capability_signature(rig.before),
    )


def check_safe_recovery(ctx: Stage5GateContext) -> GateCheck:
    """G5.11 — safe recovery is demonstrated after containment.

    The mechanism runs; the criterion fails by construction while the host is simulated
    (§6.1: ``report.simulated is False`` is required and cannot hold here).
    """
    from pocketsec.stage5.labs.baselines import build_rig
    from pocketsec.stage5.labs.response_corpus import build_response_corpus

    corpus = _hostile(build_response_corpus(count=2 * _RECOVERY_CASES, seed=13))
    runs = [run for index, case in enumerate(corpus[:_RECOVERY_CASES])
            if (run := _recover_one(build_rig(case), index)) is not None]
    inside = sum(run.report.final_status is ManifoldStatus.INSIDE for run in runs)
    was_inside = sum(run.status_before is ManifoldStatus.INSIDE for run in runs)
    simulated = all(run.report.simulated for run in runs)
    violated = sorted({row for run in runs for row in run.violated_before})
    passed = bool(runs) and not simulated and inside == len(runs)
    return GateCheck(
        "G5.11",
        "Safe recovery is demonstrated after containment",
        passed,
        f"NOT MET on a real host — every RecoveryReport has simulated={simulated} and the "
        f"criterion requires simulated is False (ADR-0046). Mechanism, in-simulator, over "
        f"{len(runs)} contained hostile cases: capability signature restored to the "
        f"pre-containment host {sum(run.restored for run in runs)}/{len(runs)}; at most one "
        f"capability changed between consecutive probes "
        f"{sum(run.incremental for run in runs)}/{len(runs)}; steps succeeded "
        f"{sum(run.report.steps_succeeded for run in runs)}/"
        f"{sum(run.report.steps_attempted for run in runs)}; final_status INSIDE {inside}/"
        f"{len(runs)} — but only {was_inside}/{len(runs)} hosts were INSIDE *before* "
        f"containment (invariants already violated on the untouched corpus hosts: {violated}), so "
        f"INSIDE is not reachable by undoing Stage 5's own change on this corpus",
    )
