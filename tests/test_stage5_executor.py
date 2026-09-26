"""Stage 5 package 4 — the executor, the journal, target identity, leases, hysteresis.

What this file is for: the properties in D5.11 and D5.12 that are most likely to
be implemented as a comment. Every test here is written so that deleting the
mechanism it names makes it fail.

Three tests are AST assertions over this package's own source rather than
behavioural checks, and that is deliberate:

* ``test_identity_is_revalidated_inside_commit`` — a behavioural test can show
  that *this* call path revalidates. Only the AST can show that no call sits
  between ``revalidate`` and ``host.apply``, which is the property that closes
  the window.
* ``test_commit_requires_a_preservation_bundle_positionally`` — "evidence
  precedes intervention" is arity here, and arity is a syntactic fact.
* ``test_lease_expiry_reads_nothing_but_its_own_frozen_fields`` — purity is what
  makes a lease expired whether or not anybody asked.

A note on imports. ``pocketsec.stage5.executor.transactional`` and
``pocketsec.stage5.labs.toctou`` are imported inside the tests that need them
rather than at module scope, through :func:`_executor`. They depend on
``pocketsec.stage5.sentinel.kernel``, which package 3 owns and which is being
written in this same tree; when it cannot be imported, the tests that need the
whole rig fail with the real reason named instead of the whole file erroring out
at collection and verifying nothing.
"""

from __future__ import annotations

import ast
import re
import typing
from dataclasses import fields, replace
from enum import StrEnum
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage0.contracts.threat_prediction_v1 import Verdict
from pocketsec.stage1.state.security_state import SecurityStateV1
from pocketsec.stage4.stage5_interface import CBFResolutionV1
from pocketsec.stage5.authority.capability import (
    AuthorityGrant,
    GrantSource,
    required_authority,
)
from pocketsec.stage5.authority.tokens import TokenStore
from pocketsec.stage5.constitution.invariants import FROZEN_CONSTITUTION
from pocketsec.stage5.constitution.schema import DEFAULT_MISSION_INVARIANTS
from pocketsec.stage5.evidence.preservation_gate import (
    DEFAULT_RETENTION,
    EvidencePreservationGate,
)
from pocketsec.stage5.executor.identity import (
    ACTIONABLE_REVALIDATIONS,
    IdentityRevalidation,
    ManualClock,
    SystemClock,
    identity_digest,
    revalidate,
)
from pocketsec.stage5.executor.journal import (
    MAX_PHASES_PER_ACTION,
    MIN_FREE_BYTES_FOR_ACTION,
    TERMINAL_PHASE_NAME,
    JournalFull,
    RollbackJournal,
)
from pocketsec.stage5.executor.lease import (
    DEFAULT_HYSTERESIS,
    MAX_CONCURRENT_LEASES,
    MAX_RENEWALS,
    ControlDecision,
    HysteresisController,
    HysteresisPolicy,
    Lease,
    LeaseDenial,
    LeaseDenialReason,
    LeaseRegistry,
    RenewalEvidence,
)
from pocketsec.stage5.executor.verify import PostconditionProbe
from pocketsec.stage5.governor import STAGE5_BUDGET, ResourceGovernor, WorkKind
from pocketsec.stage5.host.simulated import (
    FaultProfile,
    HostKind,
    ProcessRow,
    ProcessState,
    ServiceRow,
    SimulatedHost,
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

# --- source under AST inspection ---------------------------------------------

_PACKAGE_ROOT = Path(__file__).resolve().parent.parent / "pocketsec" / "stage5"
_EXECUTOR_DIR = _PACKAGE_ROOT / "executor"
#: The five modules package 4 owns. AST checks run over exactly these; the
#: package-wide version of the no-shell property is `tests/test_stage5_boundary.py`.
_OWNED_SOURCES = (
    _EXECUTOR_DIR / "identity.py",
    _EXECUTOR_DIR / "journal.py",
    _EXECUTOR_DIR / "transactional.py",
    _EXECUTOR_DIR / "lease.py",
    _PACKAGE_ROOT / "labs" / "toctou.py",
)

_BYPASS_NAME = re.compile(r"force|override|bypass|skip|disable|dry_?run|unsafe|trust_me", re.I)
_SHELL_MODULES = frozenset({"subprocess", "pty", "shlex", "ctypes", "multiprocessing", "asyncio"})
_SHELL_BUILTINS = frozenset({"eval", "exec", "compile", "__import__"})
_SHELL_ATTRS = frozenset({"system", "popen", "execv", "execve", "execl", "spawnv", "fork"})


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _class(tree: ast.Module, name: str) -> ast.ClassDef:
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == name:
            return node
    raise AssertionError(f"class {name!r} not found")


def _method(tree: ast.Module, class_name: str, method: str) -> ast.FunctionDef:
    for node in _class(tree, class_name).body:
        if isinstance(node, ast.FunctionDef) and node.name == method:
            return node
    raise AssertionError(f"{class_name}.{method} not found")


def _call_name(node: ast.Call) -> str:
    """Dotted source spelling of a call target, e.g. ``self._host.apply``."""
    parts: list[str] = []
    current: ast.expr = node.func
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def _calls_in_source_order(node: ast.AST) -> list[str]:
    calls = [child for child in ast.walk(node) if isinstance(child, ast.Call)]
    calls.sort(key=lambda call: (call.lineno, call.col_offset))
    return [_call_name(call) for call in calls]


def _executor() -> ModuleType:
    """Import the transactional executor, naming the blocker if it cannot load."""
    from pocketsec.stage5.executor import transactional

    return transactional


def _toctou() -> ModuleType:
    from pocketsec.stage5.labs import toctou

    return toctou


def _race_executor(setup: Any) -> Any:
    """Build the privileged rig for one TOCTOU race setup.

    Lives here rather than in ``labs/toctou.py`` because spec §5.1 rule 4 permits
    the name ``TransactionalExecutor`` only under ``executor/`` and ``recovery/``.
    The lab is handed the capability to execute; it cannot assemble one, which is
    what stops a fixture from wiring a permissive kernel into a race and calling
    the result a pass.
    """
    from pocketsec.stage5.sentinel.kernel import SentinelKernel

    transactional = _executor()
    return transactional.TransactionalExecutor(
        kernel=SentinelKernel(
            constitution=FROZEN_CONSTITUTION, invariants=setup.invariants, clock=setup.clock
        ),
        host=setup.host,
        journal=RollbackJournal(),
        gate=EvidencePreservationGate(
            policy=DEFAULT_RETENTION, invariants=setup.invariants
        ),
        governor=ResourceGovernor(),
        leases=LeaseRegistry(clock=setup.clock),
        probe=PostconditionProbe(invariants=setup.invariants),
        clock=setup.clock,
        tokens=setup.tokens,
    )


# --- fixtures ----------------------------------------------------------------

_PID = 7001
_TICKS = 55_000
_UID = 1000
_DIGEST = "sha256:" + "5d" * 32
#: `DEFAULT_MISSION_INVARIANTS.required_evidence()`; deliberately not in
#: `DEFAULT_RETENTION.uniquely_necessary`, so the evidence gate returns PRESERVED
#: for a DEGRADES_VOLATILE operator and cannot refuse for an unrelated reason.
_VOLATILE = ("process_memory_map",)

#: The ≥O2 operator these tests lease and roll back. **Not SUSPEND_PROCESS**, and
#: the reason is a measured cross-package contradiction rather than a preference:
#: under ``DEFAULT_MISSION_INVARIANTS`` plus ``DEFAULT_RETENTION`` no
#: ``DEGRADES_VOLATILE`` operator is reachable. MI-04 (EVIDENCE_RETENTION of
#: ``process_memory_map``) denies it when the target carries that signal, and the
#: evidence gate answers INSUFFICIENT_EVIDENCE when it does not, because
#: ``MissionInvariantSet.required_evidence()`` asks for the same signal. A
#: SUSPEND_PROCESS run through this rig returns ``REFUSED_SENTINEL`` /
#: ``MISSION_INVARIANT``, which is a correct refusal and a useless fixture for
#: testing COMMIT. Cutting MI-04 down to make it work would be weakening a safety
#: policy to make a test pass, so the fixture moved and the contradiction is
#: reported to the integrator instead.
_LEASED_OPERATOR_ID = "RESTRICT_LOCAL_SOCKET"


def _identity(
    *,
    pid: int = _PID,
    ticks: int = _TICKS,
    uid: int = _UID,
    digest: str | None = _DIGEST,
) -> ProcessIdentity:
    return ProcessIdentity(
        pid=pid,
        start_time_ticks=ticks,
        uid=uid,
        executable_digest=digest,
        cgroup_id="cgroup.user.slice",
        namespace_id="ns.host",
    )


def _operator(
    operator_id: str,
    *,
    identity: ProcessIdentity | None = None,
    ttl: int = 300,
    incident: str = "inc.x",
) -> DefensiveOperator:
    entry = spec(operator_id)
    kind = entry.target_kind
    subject = {
        TargetKind.PROCESS: f"pid.{_PID}",
        TargetKind.SOCKET: "sock.lab.1",
        TargetKind.SESSION: "session.lab",
        TargetKind.SERVICE: "lab-noncritical.service",
        TargetKind.HOST: "host.lab",
    }[kind]
    return DefensiveOperator(
        spec=entry,
        target=ProcessTarget(
            identity=_identity() if identity is None else identity,
            scope=TargetScope(kind=kind, subject=subject),
        ),
        incident_id=incident,
        ttl_seconds=min(ttl, entry.max_duration_seconds),
        evidence_refs=(),
    )


def _resolution(*, incident: str = "inc.x") -> CBFResolutionV1:
    return CBFResolutionV1(
        resolution_id=f"res.{incident}",
        incident_id=incident,
        epoch_id=1,
        verdict=Verdict.MALICIOUS,
        identifiability="IDENTIFIED",
        hypotheses=(
            {
                "mechanism_id": "privilege_escalation.local",
                "support": 0.9,
                "consequence": "privilege_escalation",
                "uncertainty": 0.1,
                "claim_ids": [],
                "evidence_digests": [],
            },
        ),
        consequence_distribution={"privilege_escalation": 0.9},
        claim_graph={},
        evidence_lineage=(),
        uncertainty=0.1,
        shadow={},
        information_gaps=(),
        truncations=(),
        degradations=(),
    )


def _host(
    *,
    clock: ManualClock,
    faults: FaultProfile | None = None,
    pid: int = _PID,
    volatile: tuple[str, ...] = _VOLATILE,
) -> SimulatedHost:
    return SimulatedHost(
        processes=[
            ProcessRow(
                identity=_identity(pid=pid),
                state=ProcessState.RUNNING,
                unit=None,
                session_id="session.lab",
                socket_ids=("sock.lab.1",),
                children=(),
                volatile_signals=volatile,
            )
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
        faults=FaultProfile(seed=11) if faults is None else faults,
        clock=clock,
    )


def _rig(
    *,
    clock: ManualClock | None = None,
    faults: FaultProfile | None = None,
    volatile: tuple[str, ...] = _VOLATILE,
    journal: RollbackJournal | None = None,
) -> SimpleNamespace:
    """The whole privileged rig, wired with the real kernel, gate and host."""
    from pocketsec.stage5.sentinel.kernel import SentinelKernel

    transactional = _executor()
    the_clock = ManualClock(at=1_000) if clock is None else clock
    host = _host(clock=the_clock, faults=faults, volatile=volatile)
    tokens = TokenStore(key=b"\x11" * 32, signer="tests.stage5.executor", clock=the_clock)
    registry = LeaseRegistry(clock=the_clock)
    governor = ResourceGovernor()
    executor = transactional.TransactionalExecutor(
        kernel=SentinelKernel(
            constitution=FROZEN_CONSTITUTION, invariants=DEFAULT_MISSION_INVARIANTS, clock=the_clock
        ),
        host=host,
        journal=RollbackJournal() if journal is None else journal,
        gate=EvidencePreservationGate(
            policy=DEFAULT_RETENTION, invariants=DEFAULT_MISSION_INVARIANTS
        ),
        governor=governor,
        leases=registry,
        probe=PostconditionProbe(invariants=DEFAULT_MISSION_INVARIANTS),
        clock=the_clock,
        tokens=tokens,
    )
    return SimpleNamespace(
        clock=the_clock,
        host=host,
        tokens=tokens,
        leases=registry,
        executor=executor,
        transactional=transactional,
        journal=executor._journal,
        governor=governor,
    )


def _mint(rig: SimpleNamespace, operator: DefensiveOperator, *, action_id: str) -> Any:
    return rig.tokens.mint(
        grant=AuthorityGrant(
            authority=required_authority(operator.spec),
            granted_by=GrantSource.POLICY,
            policy_version=FROZEN_CONSTITUTION.policy_version,
            subject_operator_id=operator.spec.operator_id,
            detail="test grant at the operator's own authority class",
        ),
        operator=operator,
        action_id=action_id,
        ttl_seconds=min(operator.ttl_seconds, 900),
    )


# --- the clock ---------------------------------------------------------------


def test_a_manual_clock_does_not_advance_on_its_own() -> None:
    clock = ManualClock(at=10)
    readings = [clock.now() for _ in range(5)]
    assert readings == [10] * 5
    clock.advance(301)
    assert clock.now() == 311


def test_a_manual_clock_refuses_to_run_backwards() -> None:
    clock = ManualClock()
    with pytest.raises(ContractError):
        clock.advance(-1)
    with pytest.raises(ContractError):
        ManualClock(at=-5)


def test_the_system_clock_reports_whole_seconds_and_never_decreases() -> None:
    clock = SystemClock()
    first = clock.now()
    assert isinstance(first, int)
    assert clock.now() >= first


# --- the one key space ------------------------------------------------------


def test_identity_digest_is_a_function_of_every_identity_field() -> None:
    """A digest that ignores a field would make two processes one key."""
    base = _identity()
    assert identity_digest(base) == identity_digest(_identity())
    for field in fields(ProcessIdentity):
        changed = {
            "pid": 7002,
            "start_time_ticks": 55_001,
            "uid": 0,
            "executable_digest": "sha256:" + "ee" * 32,
            "cgroup_id": "cgroup.other",
            "namespace_id": "ns.other",
        }[field.name]
        assert identity_digest(replace(base, **{field.name: changed})) != identity_digest(base), (
            f"identity_digest ignores {field.name}"
        )


# --- revalidation: the TOCTOU decision table --------------------------------


def test_a_missing_observation_is_exited_and_never_match() -> None:
    assert revalidate(_identity(), None) is IdentityRevalidation.EXITED


def test_a_recycled_pid_is_pid_reused() -> None:
    assert (
        revalidate(_identity(), _identity(ticks=99_999)) is IdentityRevalidation.PID_REUSED
    )


def test_a_changed_executable_is_executable_changed() -> None:
    other = _identity(digest="sha256:" + "ab" * 32)
    assert revalidate(_identity(), other) is IdentityRevalidation.EXECUTABLE_CHANGED


def test_a_changed_uid_is_uid_changed() -> None:
    assert revalidate(_identity(), _identity(uid=0)) is IdentityRevalidation.UID_CHANGED


def test_an_absence_of_executable_evidence_is_not_a_match() -> None:
    """Asymmetric absence is UNOBSERVABLE in both directions.

    Whichever side lost the digest, the honest answer is "cannot tell", and the
    fail-closed reading of "cannot tell" is a refusal.
    """
    known = _identity()
    unknown = _identity(digest=None)
    assert revalidate(unknown, known) is IdentityRevalidation.UNOBSERVABLE
    assert revalidate(known, unknown) is IdentityRevalidation.UNOBSERVABLE
    # Both unknown is not a refusal: with no filesystem there is no digest to
    # compare, and treating that as a mismatch would make MATCH unreachable.
    assert revalidate(unknown, _identity(digest=None)) is IdentityRevalidation.MATCH


def test_a_moved_containment_boundary_is_unobservable() -> None:
    moved = replace(_identity(), namespace_id="ns.container.7")
    assert revalidate(_identity(), moved) is IdentityRevalidation.UNOBSERVABLE
    regrouped = replace(_identity(), cgroup_id="cgroup.other.slice")
    assert revalidate(_identity(), regrouped) is IdentityRevalidation.UNOBSERVABLE


def test_only_match_permits_an_action() -> None:
    """The set of answers that reach privilege has exactly one member.

    Widening this frozenset is the single edit that would let every other
    revalidation outcome act, so the test pins its contents by value.
    """
    assert frozenset({IdentityRevalidation.MATCH}) == ACTIONABLE_REVALIDATIONS
    assert len(IdentityRevalidation) == 6
    for member in IdentityRevalidation:
        if member is not IdentityRevalidation.MATCH:
            assert member not in ACTIONABLE_REVALIDATIONS


# --- the journal ------------------------------------------------------------


class _JournalPhase(StrEnum):
    """Stand-in for ``transactional.Phase`` in the journal's own unit tests.

    ``journal.py`` deliberately does not import ``Phase`` — that would close an
    import cycle — so its unit tests do not need to either, and they stay
    independent of package 3's kernel. The correspondence between this enum and
    the real declaration is asserted by
    :func:`test_the_journal_constants_do_not_drift_from_phase`, which reads the
    real one out of the AST, so the stand-in cannot drift silently.
    """

    PREPARE = "PREPARE"
    COMMIT = "COMMIT"
    VERIFY = "VERIFY"
    ROLLBACK = "ROLLBACK"
    FINALIZE = "FINALIZE"


def _phase(name: str) -> _JournalPhase:
    return _JournalPhase[name]


def _shape_operator() -> DefensiveOperator:
    return _operator("SNAPSHOT_PROCESS_STATE")


def test_the_journal_chain_is_walked_over_recomputed_digests() -> None:
    """Editing any entry must break every link after it, not just its own.

    Stage 0's registry learned this: verifying against the stored digests leaves
    later entries looking intact after a single-row edit.
    """
    journal = RollbackJournal()
    operator = _shape_operator()
    for index in range(3):
        journal.append(
            action_id=f"act.{index}",
            phase=_phase("PREPARE"),
            at=100 + index,
            operator=operator,
            payload={"rollback_state": {"state": "RUNNING"}},
        )
    assert journal.verify_chain() == ()
    entries = list(journal.entries())
    tampered = replace(entries[0], at=999)
    journal._entries[0] = tampered
    problems = journal.verify_chain()
    assert len(problems) >= 2, problems
    assert any("modified after it was recorded" in problem for problem in problems)
    assert any("chain break" in problem for problem in problems)


def test_a_full_journal_refuses_a_new_action_rather_than_evicting() -> None:
    """Evicting rollback state a live lease needs would make a reversible
    intervention permanent, so the bound refuses instead."""
    journal = RollbackJournal(
        max_bytes=MIN_FREE_BYTES_FOR_ACTION, max_entries=MAX_PHASES_PER_ACTION
    )
    operator = _shape_operator()
    journal.append(
        action_id="act.first",
        phase=_phase("PREPARE"),
        at=1,
        operator=operator,
        payload={"rollback_state": {"state": "RUNNING"}},
    )
    assert journal.full() is True
    with pytest.raises(JournalFull):
        journal.append(
            action_id="act.second",
            phase=_phase("PREPARE"),
            at=2,
            operator=operator,
            payload={"rollback_state": {"state": "RUNNING"}},
        )
    # The first action's undo state survived the refusal. That is the point.
    assert journal.rollback_state("act.first") == {"state": "RUNNING"}
    truncations = journal.truncations()
    assert len(truncations) == 1
    assert truncations[0].identifier == "act.second"
    assert "JOURNAL_FULL" in truncations[0].reason
    # A phase of an action already under way is still accepted: abandoning a
    # transaction half-recorded is worse than overshooting the soft reserve.
    journal.append(
        action_id="act.first",
        phase=_phase("COMMIT"),
        at=3,
        operator=operator,
        payload={},
    )


def test_rollback_state_cannot_be_overwritten_by_a_later_phase() -> None:
    """First write wins: a post-action state stored over the pre-action state
    would turn the recorded undo into a no-op."""
    journal = RollbackJournal()
    operator = _shape_operator()
    journal.append(
        action_id="act.1",
        phase=_phase("PREPARE"),
        at=1,
        operator=operator,
        payload={"rollback_state": {"state": "RUNNING"}},
    )
    journal.append(
        action_id="act.1",
        phase=_phase("COMMIT"),
        at=2,
        operator=operator,
        payload={"rollback_state": {"state": "SUSPENDED"}},
    )
    assert journal.rollback_state("act.1") == {"state": "RUNNING"}


def test_release_refuses_before_the_terminal_phase() -> None:
    journal = RollbackJournal()
    operator = _shape_operator()
    journal.append(
        action_id="act.1",
        phase=_phase("PREPARE"),
        at=1,
        operator=operator,
        payload={"rollback_state": {"state": "RUNNING"}},
    )
    with pytest.raises(ContractError):
        journal.release("act.1")
    with pytest.raises(ContractError):
        journal.release("act.unknown")
    journal.append(
        action_id="act.1", phase=_phase("FINALIZE"), at=2, operator=operator, payload={}
    )
    journal.release("act.1")
    assert journal.rollback_state("act.1") is None


def test_the_journal_key_space_is_identity_digest() -> None:
    journal = RollbackJournal()
    operator = _shape_operator()
    entry = journal.append(
        action_id="act.1", phase=_phase("PREPARE"), at=1, operator=operator, payload={}
    )
    assert entry.target_digest == identity_digest(operator.target.identity)


def test_the_journal_constants_do_not_drift_from_phase() -> None:
    """``MAX_PHASES_PER_ACTION`` and ``TERMINAL_PHASE_NAME`` mirror ``Phase``.

    The journal cannot import ``Phase`` without closing an import cycle, so the
    two facts it needs are named constants. This test is what stops them drifting,
    and it reads the enum out of the AST so it holds even when the module itself
    cannot be imported.
    """
    tree = _tree(_EXECUTOR_DIR / "transactional.py")
    members = [
        node.targets[0].id
        for node in _class(tree, "Phase").body
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
    ]
    assert len(members) == MAX_PHASES_PER_ACTION, members
    assert members[-1] == TERMINAL_PHASE_NAME
    assert members[0] == "PREPARE"
    assert [member.name for member in _JournalPhase] == members, (
        "the journal tests' stand-in for Phase has drifted from the real declaration"
    )


# --- the AST properties -----------------------------------------------------


def test_identity_is_revalidated_inside_commit() -> None:
    """No call may sit between ``revalidate`` and ``host.apply``.

    This is the property the architecture is most likely to get as a comment. A
    behavioural test shows that one path revalidates; only this shows that the
    window between the check and the use is empty. Inserting any call — even a
    constructor for the refusal value — makes it fail.
    """
    commit = _method(_tree(_EXECUTOR_DIR / "transactional.py"), "TransactionalExecutor", "_commit")
    names = _calls_in_source_order(commit)
    assert "revalidate" in names, names
    reval = names.index("revalidate")
    applies = [index for index, name in enumerate(names) if name.endswith(".apply")]
    assert applies, names
    assert applies[0] == reval + 1, (
        f"a call sits between revalidate and host.apply: {names[reval : applies[0] + 1]}"
    )


def test_commit_requires_a_preservation_bundle_positionally() -> None:
    """COMMIT is unreachable without an evidence bundle, by arity."""
    commit = _method(_tree(_EXECUTOR_DIR / "transactional.py"), "TransactionalExecutor", "_commit")
    names = [arg.arg for arg in commit.args.args]
    assert names == ["self", "operator", "bundle"], names
    assert commit.args.defaults == [], "bundle must not be defaulted to None"
    assert commit.args.kwonlyargs == []
    assert commit.args.vararg is None and commit.args.kwarg is None
    assert ast.unparse(commit.args.args[2].annotation) == "PreActionBundle"


def test_the_entry_point_annotation_is_defensive_operator_in_source() -> None:
    """Trust rule T4's syntactic half: not a union, not ``object``, not a string."""
    execute = _method(
        _tree(_EXECUTOR_DIR / "transactional.py"), "TransactionalExecutor", "execute"
    )
    assert [arg.arg for arg in execute.args.args] == ["self", "operator", "token"]
    assert ast.unparse(execute.args.args[1].annotation) == "DefensiveOperator"
    assert [arg.arg for arg in execute.args.kwonlyargs] == ["resolution"]


def test_trust_rule_t4_resolves_the_entry_point_annotation() -> None:
    """And its runtime half: the annotation resolves to the class itself."""
    hints = typing.get_type_hints(_executor().TransactionalExecutor.execute)
    assert hints["operator"] is DefensiveOperator
    assert hints["token"].__name__ == "CapabilityToken"


def test_no_shell_path_exists_anywhere_in_this_package() -> None:
    """Property P2, scoped to the five modules package 4 owns.

    If the executor ever has to call a system tool it will take an enum-selected
    argv list assembled from a frozen catalog entry. It will not format a string,
    and it will not reach a shell.
    """
    offenders: list[str] = []
    for path in _OWNED_SOURCES:
        tree = _tree(path)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                offenders += [
                    f"{path.name}:{node.lineno} import {alias.name}"
                    for alias in node.names
                    if alias.name.split(".")[0] in _SHELL_MODULES
                ]
            elif isinstance(node, ast.ImportFrom) and node.module:
                if node.module.split(".")[0] in _SHELL_MODULES:
                    offenders.append(f"{path.name}:{node.lineno} from {node.module}")
            elif isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name) and func.id in _SHELL_BUILTINS:
                    offenders.append(f"{path.name}:{node.lineno} {func.id}()")
                if isinstance(func, ast.Attribute) and func.attr in _SHELL_ATTRS:
                    offenders.append(f"{path.name}:{node.lineno} .{func.attr}()")
    assert offenders == [], offenders


def test_no_executor_module_defines_a_bypass_name() -> None:
    """A flag is the first of the four ways a safety boundary stops being one."""
    offenders: list[str] = []
    for path in _OWNED_SOURCES:
        for node in ast.walk(_tree(path)):
            names: list[str] = []
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                names = [node.name]
            elif isinstance(node, ast.arg):
                names = [node.arg]
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                names = [node.id]
            elif isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store):
                names = [node.attr]
            offenders += [
                f"{path.name}:{node.lineno} {name}" for name in names if _BYPASS_NAME.search(name)
            ]
    assert offenders == [], offenders


def test_lease_expiry_reads_nothing_but_its_own_frozen_fields() -> None:
    """Property P7 as a syntactic fact.

    Reading a registry attribute inside ``expired`` would make a lease expire only
    when somebody asked the registry, and the ``ManualClock`` test below — which
    never calls the registry — would fail. This check finds that edit even if the
    behavioural test is deleted.
    """
    tree = _tree(_EXECUTOR_DIR / "lease.py")
    expired = _method(tree, "Lease", "expired")
    allowed = {field.name for field in fields(Lease)} | {"expires_at", "hard_deadline"}
    read: set[str] = set()
    for node in ast.walk(expired):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if node.value.id == "self":
                read.add(node.attr)
    assert read <= allowed, read - allowed
    calls = set(_calls_in_source_order(expired))
    assert calls <= {"self.expires_at", "self.hard_deadline"}, calls


def test_only_the_sweeper_drives_the_sweep() -> None:
    """There is no implicit expiry check hidden in another call path."""
    tree = _tree(_EXECUTOR_DIR / "lease.py")
    sweeper = _class(tree, "LeaseSweeper")
    low, high = sweeper.lineno, (sweeper.end_lineno or sweeper.lineno)
    offenders: list[str] = []
    for path in _OWNED_SOURCES:
        for node in ast.walk(_tree(path)):
            if not isinstance(node, ast.Call) or not _call_name(node).endswith(".tick"):
                continue
            if path.name != "lease.py" or not low <= node.lineno <= high:
                offenders.append(f"{path.name}:{node.lineno}")
    assert offenders == [], offenders


# --- the TOCTOU races -------------------------------------------------------


@pytest.mark.parametrize(
    ("variant", "expected"),
    [
        ("EXITED", IdentityRevalidation.EXITED),
        ("PID_REUSED", IdentityRevalidation.PID_REUSED),
        ("EXECUTABLE_CHANGED", IdentityRevalidation.EXECUTABLE_CHANGED),
        ("UID_CHANGED", IdentityRevalidation.UID_CHANGED),
    ],
)
def test_a_substituted_target_is_refused_and_never_acted_on(
    variant: str, expected: IdentityRevalidation
) -> None:
    """The four races of G5.5, run through the real ``execute``.

    Three assertions per race, and all three are needed: the outcome is the
    refusal, ``host.apply`` was never reached, and the process that took the
    pid's place is untouched. The last is the actual harm a pid substitution
    causes.
    """
    toctou = _toctou()
    race, receipt = toctou.run_race(variant, build_executor=_race_executor)
    assert receipt.outcome is _executor().Outcome.REFUSED_IDENTITY, receipt.outcome
    assert race.observed_revalidation is expected
    assert race.apply_calls == 0, "host.apply was reached on a substituted target"
    assert race.substitute_untouched is True
    assert receipt.host_kind is HostKind.SIMULATED and receipt.simulated is True


def test_both_race_suites_refuse_every_case() -> None:
    toctou = _toctou()
    suites = toctou.toctou_suite(build_executor=_race_executor) + toctou.pid_reuse_suite(
        build_executor=_race_executor
    )
    for race in suites:
        assert race.refused is True, race.to_dict()
        assert race.apply_calls == 0, race.to_dict()


def test_prepare_observes_the_identity_exactly_once() -> None:
    """Pins the constant the lab uses to time the race.

    ``labs/toctou.py`` substitutes the target on the observation *after* PREPARE's.
    If PREPARE's count changed, the race would fire in the wrong phase and the
    suite would pass for the wrong reason — SENTINEL denying rather than the
    executor closing the window.
    """
    toctou = _toctou()
    setup = toctou.build_race_setup("PID_REUSED")
    setup.host._fired = 10_000
    receipt = _race_executor(setup).execute(
        setup.operator, setup.token, resolution=setup.resolution
    )
    assert receipt.outcome in _executor().COMMITTED_OUTCOMES | {
        _executor().Outcome.ROLLED_BACK,
        _executor().Outcome.ROLLBACK_FAILED,
    }, receipt.outcome
    # PREPARE's observation plus COMMIT's, and nothing else before apply.
    assert setup.host.observations() == toctou.PREPARE_IDENTITY_OBSERVATIONS + 1


# --- only typed operators reach privilege -----------------------------------


def test_a_string_cannot_reach_the_executor() -> None:
    """P1's named test: every impostor is refused BY THE ENTRY GUARD, before the host.

    Finding F5-honesty: this test used to accept ``AttributeError``, which is what a string
    raises when it reaches ``operator.argv()`` with no guard in front of it, so deleting
    ``_refuse_untyped`` left it green. It now demands a ``TypeError`` or ``ContractError``
    whose innermost frame is ``_refuse_untyped`` itself, and zero ``host.apply`` calls.
    ``SENSITIVITY_EDITS['P1']`` deletes the guard; this test must then fail.

    The forged-spec case is the one that matters: equality would have let it
    through and identity does not.
    """
    import copy

    rig = _rig()
    operator = _operator(_LEASED_OPERATOR_ID)
    token = _mint(rig, operator, action_id="act.forged")
    resolution = _resolution()
    applied = rig.host.apply_calls
    refused = 0

    impostors = (
        _LEASED_OPERATOR_ID,
        {"operator_id": _LEASED_OPERATOR_ID},
        SimpleNamespace(
            spec=operator.spec,
            target=operator.target,
            incident_id="x",
            ttl_seconds=1,
            evidence_refs=(),
        ),
        # An impostor that brings its own vector: without the guard it reaches PREPARE.
        SimpleNamespace(
            spec=operator.spec,
            target=operator.target,
            incident_id=operator.incident_id,
            ttl_seconds=operator.ttl_seconds,
            evidence_refs=(),
            argv=lambda: ("sh", "-c", "id"),
        ),
        copy.deepcopy(operator),
    )
    for forged in impostors:
        with pytest.raises((ContractError, TypeError)) as refusal:
            rig.executor.execute(forged, token, resolution=resolution)  # type: ignore[arg-type]
        assert refusal.traceback[-1].name == "_refuse_untyped", (
            f"{type(forged).__name__} was refused by {refusal.traceback[-1].name}, not the "
            "entry guard"
        )
        refused += 1
    assert rig.host.apply_calls == applied, "an impostor reached the host"

    # A structurally identical OperatorSpec: `replace` of a catalog entry carries
    # the real catalog token, so it is constructible and compares EQUAL to the
    # entry. Equality would have let it through; identity does not.
    forged_spec = replace(operator.spec)
    assert forged_spec == operator.spec and forged_spec is not operator.spec
    with pytest.raises(ContractError):
        DefensiveOperator(
            spec=forged_spec,
            target=operator.target,
            incident_id="inc.x",
            ttl_seconds=60,
            evidence_refs=(),
        )
    refused += 1

    # A DefensiveOperator whose spec is a deep copy of a catalog entry. deepcopy
    # goes through __setstate__ and so never re-runs __post_init__, which is
    # exactly why the check that matters is in DefensiveOperator, not the spec.
    with pytest.raises(ContractError):
        DefensiveOperator(
            spec=copy.deepcopy(operator.spec),
            target=operator.target,
            incident_id="inc.x",
            ttl_seconds=60,
            evidence_refs=(),
        )
    refused += 1
    assert refused == 7


def test_a_forged_spec_is_refused_by_identity_not_equality() -> None:
    """Worth asserting on its own: the forgery is EQUAL to a catalog entry.

    An equality-based membership test would admit it. This needs no executor, so
    it holds whatever else in the stage is mid-build.
    """
    entry = spec(_LEASED_OPERATOR_ID)
    forged = replace(entry)
    assert forged == entry
    assert forged is not entry
    assert not any(forged is member for member in CATALOG.values())
    assert any(forged == member for member in CATALOG.values())
    with pytest.raises(ContractError):
        replace(entry, catalog_token=object())


# --- leases -----------------------------------------------------------------


def _lease(**overrides: Any) -> Lease:
    base = {
        "lease_id": "lease.act.1",
        "action_id": "act.1",
        "incident_id": "inc.x",
        "operator_id": _LEASED_OPERATOR_ID,
        "target_digest": identity_digest(_identity()),
        "granted_at": 0,
        "ttl_seconds": 300,
        "maximum_lifetime_seconds": 3600,
        "renewals": 0,
        "rollback_operator_id": "RELEASE_LOCAL_SOCKET",
    }
    base.update(overrides)
    return Lease(**base)  # type: ignore[arg-type]


def test_a_lease_is_expired_by_data_not_by_a_call() -> None:
    """The headline D5.12 property, under a clock that never moves on its own.

    No registry method is called before the assertion. The lease is expired
    because its arithmetic says so, not because something looked.
    """
    clock = ManualClock(at=0)
    registry = LeaseRegistry(clock=clock)
    operator = _operator(_LEASED_OPERATOR_ID)
    lease = registry.grant(
        operator=operator, action_id="act.1", ttl_seconds=300, resolution=_resolution()
    )
    assert isinstance(lease, Lease)
    assert lease.expired(clock.now()) is False
    clock.advance(301)
    assert lease.expired(clock.now()) is True


def test_a_lease_without_a_rollback_operator_is_never_granted() -> None:
    """An unrollbackable restriction cannot be leased, because a lease promises
    an end."""
    registry = LeaseRegistry(clock=ManualClock())
    for operator_id, entry in CATALOG.items():
        if entry.operator_class < OperatorClass.O2_REVERSIBLE_RESTRICT:
            continue
        if entry.rollback_operator_id is not None:
            continue
        denial = registry.grant(
            operator=_operator(operator_id, incident="inc.norollback"),
            action_id=f"act.{operator_id.lower()}",
            ttl_seconds=60,
            resolution=_resolution(),
        )
        assert isinstance(denial, LeaseDenial), operator_id
        assert denial.reason is LeaseDenialReason.NO_ROLLBACK_OPERATOR


def test_lease_capacity_is_bounded_and_agrees_with_the_governor() -> None:
    registry = LeaseRegistry(clock=ManualClock())
    assert STAGE5_BUDGET.max_concurrent_leases == MAX_CONCURRENT_LEASES
    granted = 0
    for index in range(MAX_CONCURRENT_LEASES + 2):
        outcome = registry.grant(
            operator=_operator(_LEASED_OPERATOR_ID, incident=f"inc.{index}"),
            action_id=f"act.cap.{index}",
            ttl_seconds=300,
            resolution=_resolution(incident=f"inc.{index}"),
        )
        if isinstance(outcome, Lease):
            granted += 1
        else:
            assert outcome.reason is LeaseDenialReason.CAPACITY
    assert granted == MAX_CONCURRENT_LEASES
    assert len(registry.active(0)) == MAX_CONCURRENT_LEASES


def test_the_hard_deadline_beats_renewal() -> None:
    """Two separate refusals: out of renewals, and out of lifetime.

    Perfect evidence cannot buy either of them.
    """
    clock = ManualClock(at=0)
    registry = LeaseRegistry(clock=clock)
    evidence = RenewalEvidence(
        resolution_id="res.inc.x", supporting_claim_ids=("obs.1",), leading_support=0.99
    )
    lease = registry.grant(
        operator=_operator(_LEASED_OPERATOR_ID),
        action_id="act.renew",
        ttl_seconds=300,
        resolution=_resolution(),
    )
    assert isinstance(lease, Lease)
    deadline = lease.hard_deadline()
    for renewal in range(MAX_RENEWALS):
        clock.advance(10)
        renewed = registry.renew(lease.lease_id, evidence=evidence, now=clock.now())
        assert isinstance(renewed, Lease), renewed
        assert renewed.renewals == renewal + 1
        assert renewed.hard_deadline() == deadline, "a renewal moved the hard deadline"
    clock.advance(10)
    out_of_renewals = registry.renew(lease.lease_id, evidence=evidence, now=clock.now())
    assert isinstance(out_of_renewals, LeaseDenial)
    assert out_of_renewals.reason is LeaseDenialReason.MAX_RENEWALS

    # Separately: a renewal that would cross the deadline, with renewals to spare.
    clock2 = ManualClock(at=0)
    registry2 = LeaseRegistry(clock=clock2)
    fresh = registry2.grant(
        operator=_operator(_LEASED_OPERATOR_ID, incident="inc.deadline"),
        action_id="act.deadline",
        ttl_seconds=300,
        resolution=_resolution(incident="inc.deadline"),
    )
    assert isinstance(fresh, Lease)
    late = fresh.hard_deadline() - 10
    crossing = registry2.renew(fresh.lease_id, evidence=evidence, now=late)
    assert isinstance(crossing, LeaseDenial)
    # Expiry is checked first (F6): at ``late`` the 300 s lease ended long ago, and an
    # ended lease is refused as EXPIRED rather than re-based. With ttl <= 900, three
    # renewals and a 3600 s lifetime the registry cannot itself produce a live lease
    # whose ttl crosses its deadline, so the HARD_DEADLINE branch is exercised on a lease
    # whose remaining lifetime is shorter than its ttl, held directly.
    assert crossing.reason is LeaseDenialReason.EXPIRED
    short = replace(fresh, maximum_lifetime_seconds=fresh.ttl_seconds + 50)
    registry2._leases[fresh.lease_id] = short  # noqa: SLF001 - the defensive branch
    near = short.granted_at + 100
    assert not short.expired(near)
    past_deadline = registry2.renew(fresh.lease_id, evidence=evidence, now=near)
    assert isinstance(past_deadline, LeaseDenial)
    assert past_deadline.reason is LeaseDenialReason.HARD_DEADLINE


def test_a_renewal_without_evidence_is_refused() -> None:
    """A renewal needs evidence, not a timer."""
    clock = ManualClock(at=0)
    registry = LeaseRegistry(clock=clock)
    lease = registry.grant(
        operator=_operator(_LEASED_OPERATOR_ID),
        action_id="act.noev",
        ttl_seconds=300,
        resolution=_resolution(),
    )
    assert isinstance(lease, Lease)
    for bad in (
        RenewalEvidence(resolution_id="res.x", supporting_claim_ids=(), leading_support=0.99),
        RenewalEvidence(resolution_id="res.x", supporting_claim_ids=("c",), leading_support=0.1),
        RenewalEvidence(resolution_id="", supporting_claim_ids=("c",), leading_support=0.99),
    ):
        denial = registry.renew(lease.lease_id, evidence=bad, now=10)
        assert isinstance(denial, LeaseDenial), bad
        assert denial.reason is LeaseDenialReason.NO_RENEWAL_EVIDENCE
    assert registry.renew("lease.nope", evidence=bad, now=10).reason is (
        LeaseDenialReason.UNKNOWN_LEASE
    )


def test_the_sweep_rolls_back_every_expired_lease() -> None:
    """The explicit sweep, end to end, and the host really is restored."""
    from pocketsec.stage5.executor.lease import LeaseSweeper

    rig = _rig()
    operator = _operator(_LEASED_OPERATOR_ID, ttl=300)
    subject = operator.target.scope.subject
    assert subject not in rig.host.snapshot().restricted_sockets
    receipt = rig.executor.execute(
        operator, _mint(rig, operator, action_id="act.sweep"), resolution=_resolution()
    )
    assert receipt.lease_id is not None, receipt.outcome
    assert subject in rig.host.snapshot().restricted_sockets
    sweeper = LeaseSweeper(
        registry=rig.leases, executor=rig.executor, tokens=rig.tokens, clock=rig.clock
    )
    rig.clock.advance(301)
    expiries = sweeper.sweep(now=rig.clock.now())
    assert len(expiries) == 1
    assert expiries[0].rolled_back is True, sweeper.unrollbackable()
    assert subject not in rig.host.snapshot().restricted_sockets
    assert rig.leases.active(rig.clock.now()) == ()


def test_no_sweep_means_the_lease_is_still_expired_and_the_host_is_still_changed() -> None:
    """The honest negative, kept because it is what the design makes visible.

    Without a sweeper the lease is expired and the host is **not** restored. This
    is the failure mode; hiding it inside an implicit check would not remove it,
    it would only remove the evidence.
    """
    rig = _rig()
    operator = _operator(_LEASED_OPERATOR_ID, ttl=300)
    subject = operator.target.scope.subject
    receipt = rig.executor.execute(
        operator, _mint(rig, operator, action_id="act.nosweep"), resolution=_resolution()
    )
    assert receipt.lease_id is not None
    rig.clock.advance(301)
    expired = rig.leases.expired(rig.clock.now())
    assert len(expired) == 1 and expired[0].expired(rig.clock.now()) is True
    # Expired, and the host is STILL changed. This is the failure the design makes
    # visible; nothing in the registry undoes anything on its own.
    assert subject in rig.host.snapshot().restricted_sockets
    assert rig.leases.active(rig.clock.now()) == ()


# --- rollback ---------------------------------------------------------------


@pytest.mark.parametrize("rollback_failure_rate", [0.0, 0.1, 0.5])
def test_rollback_restores_the_pre_action_snapshot(rollback_failure_rate: float) -> None:
    """The rollback protocol, under injected rollback failure.

    What this measures is the protocol's *handling*: a rollback that succeeds
    restores the pre-action process state, and one that fails is reported as
    ``ROLLBACK_FAILED`` with ``rollback_succeeded is False`` — never as a success.

    What it does NOT measure is rollback reliability. ``SimulatedHost`` decides
    whether a rollback works by consulting ``FaultProfile.rollback_failure_rate``,
    a number this wave chose, so a success rate taken here is a property of this
    simulator. Real-host rollback reliability is UNMEASURED (ADR-0046).
    """
    outcome_module = _executor()
    rig = _rig(
        faults=FaultProfile(
            seed=5,
            enforcement_failure_rate=1.0,
            rollback_failure_rate=rollback_failure_rate,
        )
    )
    operator = _operator(_LEASED_OPERATOR_ID)
    before = rig.host.snapshot().process(_PID)
    assert before is not None
    receipt = rig.executor.execute(
        operator, _mint(rig, operator, action_id="act.rb"), resolution=_resolution()
    )
    assert receipt.outcome in {
        outcome_module.Outcome.ROLLED_BACK,
        outcome_module.Outcome.ROLLBACK_FAILED,
    }, receipt.outcome
    assert receipt.rollback_attempted is True
    assert receipt.rollback_succeeded is not None
    if receipt.rollback_succeeded:
        assert receipt.outcome is outcome_module.Outcome.ROLLED_BACK
        assert (
            operator.target.scope.subject not in rig.host.snapshot().restricted_sockets
        ), "a successful rollback left the pre-action state unrestored"
    else:
        assert receipt.outcome is outcome_module.Outcome.ROLLBACK_FAILED


def test_a_receipt_cannot_claim_verification_it_does_not_have() -> None:
    """``COMMITTED_VERIFIED`` with an unverifiable postcondition must not exist."""
    transactional = _executor()
    from pocketsec.stage5.executor.verify import PostconditionKind, PostconditionResult

    rig = _rig()
    operator = _operator(_LEASED_OPERATOR_ID)
    receipt = rig.executor.execute(
        operator, _mint(rig, operator, action_id="act.verif"), resolution=_resolution()
    )
    unverifiable = PostconditionResult(
        kind=PostconditionKind.PROCESS_SUSPENDED,
        satisfied=None,
        observed="unobservable",
        detail="the probe could not see the host",
    )
    with pytest.raises(ContractError):
        replace(
            receipt,
            outcome=transactional.Outcome.COMMITTED_VERIFIED,
            postconditions=(unverifiable,),
        )
    with pytest.raises(ContractError):
        replace(receipt, rollback_attempted=False, rollback_succeeded=True)
    with pytest.raises(ContractError):
        replace(receipt, simulated=False)
    with pytest.raises(ContractError):
        replace(receipt, phases=tuple(reversed(receipt.phases)))


def test_a_second_execute_while_one_is_in_flight_raises() -> None:
    """One in-flight transaction per instance: two interleaved transactions could
    revalidate one target and act on another."""
    rig = _rig()
    operator = _operator(_LEASED_OPERATOR_ID)
    token = _mint(rig, operator, action_id="act.reentrant")
    rig.executor._active = "act.other"
    with pytest.raises(ContractError):
        rig.executor.execute(operator, token, resolution=_resolution())


def test_a_replayed_token_is_refused_by_the_executor() -> None:
    rig = _rig()
    operator = _operator("SNAPSHOT_PROCESS_STATE")
    token = _mint(rig, operator, action_id="act.replay")
    first = rig.executor.execute(operator, token, resolution=_resolution())
    assert first.token_verdict.value == "VALID"
    second = rig.executor.execute(operator, token, resolution=_resolution())
    assert second.outcome is _executor().Outcome.REFUSED_TOKEN
    assert second.sentinel_verdict.decision.value == "DENY"


# --- Rule A: one key space --------------------------------------------------


def test_every_target_key_space_is_identity_digest() -> None:
    """§4.9 Rule A, over 20 actions.

    Two waves have shipped a defect where two key spaces were joined that could
    never match. Five strings are produced by five different subsystems here, and
    all five must be the one ``identity_digest`` value.
    """
    from pocketsec.stage5.executor.lease import LeaseSweeper

    del LeaseSweeper  # imported only to prove the module loads before the loop
    checked = 0
    for index in range(20):
        clock = ManualClock(at=1_000)
        rig = _rig(clock=clock)
        operator = _operator(_LEASED_OPERATOR_ID, incident=f"inc.key.{index}")
        expected = identity_digest(operator.target.identity)
        token = _mint(rig, operator, action_id=f"act.key.{index}")
        receipt = rig.executor.execute(
            operator, token, resolution=_resolution(incident=f"inc.key.{index}")
        )
        leases = rig.leases.leases_on(expected)
        entries = rig.executor._journal.entries()
        journal_keys = {entry.target_digest for entry in entries}
        assert token.target_digest == expected
        assert receipt.target_digest == expected
        assert receipt.sentinel_verdict.target_digest == expected
        assert journal_keys == {expected}, journal_keys
        assert [lease.target_digest for lease in leases] in ([], [expected])
        if receipt.lease_id is not None:
            assert len(leases) == 1 and leases[0].target_digest == expected
        checked += 1
    assert checked == 20


# --- hysteresis -------------------------------------------------------------


def test_the_hysteresis_policy_refuses_equal_thresholds() -> None:
    with pytest.raises(ContractError):
        HysteresisPolicy(
            enter_threshold=5.0,
            exit_threshold=5.0,
            min_dwell_seconds=10,
            cooldown_seconds=10,
            max_action_cycles=2,
            escalate_after_rollbacks=2,
        )
    with pytest.raises(ContractError):
        replace(DEFAULT_HYSTERESIS, exit_threshold=DEFAULT_HYSTERESIS.enter_threshold + 1)


def test_the_default_hysteresis_thresholds_are_the_documented_chosen_values() -> None:
    """These are CHOSEN parameters. The test pins them so a silent change to a
    safety-relevant threshold cannot pass as a refactor; it does not make them
    measured."""
    assert (DEFAULT_HYSTERESIS.enter_threshold, DEFAULT_HYSTERESIS.exit_threshold) == (6.0, 3.0)
    assert DEFAULT_HYSTERESIS.min_dwell_seconds == 120
    assert DEFAULT_HYSTERESIS.cooldown_seconds == 300
    assert DEFAULT_HYSTERESIS.max_action_cycles == 3
    assert DEFAULT_HYSTERESIS.escalate_after_rollbacks == 2


def test_hysteresis_stops_thrashing() -> None:
    """Inside the band, a held lease resolves to HOLD rather than oscillating."""
    clock = ManualClock(at=0)
    controller = HysteresisController(policy=DEFAULT_HYSTERESIS, clock=clock)
    digest = identity_digest(_identity())
    lease = _lease(target_digest=digest)
    first = controller.decide(target_digest=digest, phi_total=9.46, now=0, active_lease=None)
    assert first is ControlDecision.ACT
    for phi in (5.9, 4.0, 3.5, 5.0):
        held = controller.decide(
            target_digest=digest, phi_total=phi, now=200, active_lease=lease
        )
        assert held is ControlDecision.HOLD, phi
    assert controller.decide(
        target_digest=digest, phi_total=0.62, now=200, active_lease=lease
    ) is ControlDecision.RELEASE
    # Below the enter threshold and with no lease, the answer is still not ACT.
    assert controller.decide(
        target_digest=digest, phi_total=5.9, now=200, active_lease=None
    ) is ControlDecision.HOLD


def test_hysteresis_escalates_after_the_cycle_and_rollback_ceilings() -> None:
    """A controller that keeps acting is the self-DoS it was meant to prevent."""
    transactional = _executor()
    rig = _rig()
    digest = identity_digest(_identity())
    controller = HysteresisController(policy=DEFAULT_HYSTERESIS, clock=rig.clock)
    operator = _operator(_LEASED_OPERATOR_ID)
    receipt = rig.executor.execute(
        operator, _mint(rig, operator, action_id="act.hyst"), resolution=_resolution()
    )
    assert receipt.reached_host() is True
    for _ in range(DEFAULT_HYSTERESIS.max_action_cycles):
        controller.note_outcome(receipt)
    assert controller.cycles(digest) == DEFAULT_HYSTERESIS.max_action_cycles
    assert controller.decide(
        target_digest=digest, phi_total=9.46, now=10_000, active_lease=None
    ) is ControlDecision.ESCALATE
    # And separately, on rollbacks alone.
    rolled = replace(
        receipt,
        outcome=transactional.Outcome.ROLLED_BACK,
        rollback_attempted=True,
        rollback_succeeded=True,
        postconditions=(),
    )
    fresh = HysteresisController(policy=DEFAULT_HYSTERESIS, clock=rig.clock)
    for _ in range(DEFAULT_HYSTERESIS.escalate_after_rollbacks):
        fresh.note_outcome(rolled)
    assert fresh.decide(
        target_digest=digest, phi_total=9.46, now=10_000, active_lease=None
    ) is ControlDecision.ESCALATE


def test_hysteresis_state_is_bounded() -> None:
    """Unbounded per-target state on a 2 GB host is a resource defect."""
    from pocketsec.stage5.executor.lease import MAX_TRACKED_TARGETS

    rig = _rig()
    operator = _operator(_LEASED_OPERATOR_ID)
    receipt = rig.executor.execute(
        operator, _mint(rig, operator, action_id="act.bound"), resolution=_resolution()
    )
    controller = HysteresisController(policy=DEFAULT_HYSTERESIS, clock=rig.clock)
    for index in range(MAX_TRACKED_TARGETS + 8):
        controller.note_outcome(replace(receipt, target_digest="sha256:" + f"{index:064x}"))
    assert len(controller.tracked()) <= MAX_TRACKED_TARGETS
    assert controller.evictions() == 8


# --- refusals, each of which must be reachable and recorded ------------------


def test_the_evidence_gate_refuses_before_the_action_and_the_refusal_is_recorded() -> None:
    """Containment that would destroy the incident's evidence is refused, and the
    refusal leaves a receipt.

    ``socket_table`` is in ``DEFAULT_RETENTION.uniquely_necessary``, so a
    ``DEGRADES_VOLATILE`` operator on a target that is its only source is
    ``REFUSED_WOULD_DESTROY`` at the gate. The executor must turn that into
    ``REFUSED_EVIDENCE``, never act, and record it — a refusal nobody can audit is
    not a control.
    """
    rig = _rig(volatile=(*_VOLATILE, "socket_table"))
    operator = _operator("SUSPEND_PROCESS")
    before = rig.host.snapshot()
    receipt = rig.executor.execute(
        operator, _mint(rig, operator, action_id="act.evidence"), resolution=_resolution()
    )
    assert receipt.outcome is _executor().Outcome.REFUSED_EVIDENCE, receipt.outcome
    assert "socket_table" in receipt.phases[-1].detail
    assert receipt.lease_id is None
    assert receipt.rollback_attempted is False and receipt.rollback_succeeded is None
    # The host is untouched, and the record says a kernel never passed it.
    after = rig.host.snapshot()
    assert after.process(_PID).state is before.process(_PID).state
    assert after.restricted_sockets == before.restricted_sockets
    assert receipt.sentinel_verdict.decision.value == "DENY"
    assert rig.host.apply_calls == 0


def test_a_full_journal_refuses_the_transaction_before_the_host_is_touched() -> None:
    """``REFUSED_JOURNAL_FULL`` is reachable, and it stops the action.

    The journal refuses rather than evicting, and the executor's answer to that is
    to not act at all: a system that cannot record how to undo something must not
    do it.
    """
    small = RollbackJournal(
        max_bytes=MIN_FREE_BYTES_FOR_ACTION, max_entries=MAX_PHASES_PER_ACTION
    )
    small.append(
        action_id="act.squatter",
        phase=_phase("PREPARE"),
        at=0,
        operator=_shape_operator(),
        payload={"rollback_state": {"state": "RUNNING"}},
    )
    assert small.full() is True
    rig = _rig(journal=small)
    operator = _operator(_LEASED_OPERATOR_ID)
    receipt = rig.executor.execute(
        operator, _mint(rig, operator, action_id="act.full"), resolution=_resolution()
    )
    assert receipt.outcome is _executor().Outcome.REFUSED_JOURNAL_FULL
    assert rig.host.apply_calls == 0
    assert operator.target.scope.subject not in rig.host.snapshot().restricted_sockets
    assert small.rollback_state("act.squatter") == {"state": "RUNNING"}


def test_capacity_denies_at_the_kernel_and_an_exhausted_budget_escalates() -> None:
    """Two refusals for the same situation, and the stricter one wins.

    At lease capacity, SENTINEL's own ``lease_capacity`` check denies before the
    executor ever asks the registry — which is the independence property working:
    the kernel does not need the executor's cooperation to stop an action. The
    executor's ``ESCALATED`` path is reached instead by an exhausted work budget,
    and neither path widens a cap.
    """
    rig = _rig()
    for index in range(MAX_CONCURRENT_LEASES):
        held = rig.leases.grant(
            operator=_operator(_LEASED_OPERATOR_ID, incident=f"inc.hold.{index}"),
            action_id=f"act.hold.{index}",
            ttl_seconds=300,
            resolution=_resolution(incident=f"inc.hold.{index}"),
        )
        assert isinstance(held, Lease)
    operator = _operator(_LEASED_OPERATOR_ID, incident="inc.esc")
    receipt = rig.executor.execute(
        operator,
        _mint(rig, operator, action_id="act.esc"),
        resolution=_resolution(incident="inc.esc"),
    )
    assert receipt.outcome is _executor().Outcome.REFUSED_SENTINEL, receipt.outcome
    assert "lease_capacity" in receipt.sentinel_verdict.detail
    assert rig.host.apply_calls == 0
    assert len(rig.leases.active(rig.clock.now())) == MAX_CONCURRENT_LEASES

    # And the ESCALATED path, on an exhausted work budget.
    spent = _rig()
    drained = spent.governor
    drained.spend(WorkKind.HOST_CALL, units=drained.remaining())
    lone = _operator(_LEASED_OPERATOR_ID, incident="inc.budget")
    escalated = spent.executor.execute(
        lone,
        _mint(spent, lone, action_id="act.budget"),
        resolution=_resolution(incident="inc.budget"),
    )
    assert escalated.outcome is _executor().Outcome.ESCALATED, escalated.outcome
    assert spent.host.apply_calls == 0
    assert drained.escalation() is not None


def test_model_confidence_changes_nothing_the_executor_decides() -> None:
    """ADR-0003 at the executor's own boundary.

    Two resolutions that differ only in how certain the model claims to be — the
    verdict, the leading hypothesis's support and the uncertainty — must produce
    the same outcome, the same authority class and the same kernel decision. Only
    typed evidence and capability tokens may move an authority decision.
    """
    outcomes = []
    for support, uncertainty in ((0.99, 0.01), (0.01, 0.99)):
        rig = _rig()
        operator = _operator(_LEASED_OPERATOR_ID, incident="inc.conf")
        resolution = replace(
            _resolution(incident="inc.conf"),
            hypotheses=(
                {
                    "mechanism_id": "privilege_escalation.local",
                    "support": support,
                    "consequence": "privilege_escalation",
                    "uncertainty": uncertainty,
                    "claim_ids": [],
                    "evidence_digests": [],
                },
            ),
            uncertainty=uncertainty,
        )
        receipt = rig.executor.execute(
            operator, _mint(rig, operator, action_id="act.conf"), resolution=resolution
        )
        outcomes.append(
            (
                receipt.outcome,
                required_authority(operator.spec),
                receipt.sentinel_verdict.decision,
                receipt.token_verdict,
                receipt.lease_id is not None,
            )
        )
    assert outcomes[0] == outcomes[1], outcomes


def test_every_committed_leasable_receipt_is_scoped_expiring_and_rollback_aware() -> None:
    """G5.6's shape, over every catalog operator the executor can lease.

    For each one that commits: a lease exists, its ttl is inside the operator's own
    declared maximum, its target key is the receipt's, its rollback operator is
    named, and at least one postcondition was probed.
    """
    from pocketsec.stage5.executor.lease import requires_lease

    checked = 0
    for operator_id, entry in CATALOG.items():
        if not requires_lease(entry):
            continue
        rig = _rig()
        try:
            operator = _operator(operator_id, incident=f"inc.{operator_id.lower()}")
            token = _mint(rig, operator, action_id=f"act.{operator_id.lower()}")
        except ContractError:
            # The authority plane refuses a POLICY grant for an operator §5 says a
            # person must authorise. That is a pass for this criterion, not a gap.
            continue
        receipt = rig.executor.execute(
            operator, token, resolution=_resolution(incident=f"inc.{operator_id.lower()}")
        )
        if receipt.outcome not in _executor().COMMITTED_OUTCOMES:
            continue
        leases = rig.leases.leases_on(receipt.target_digest)
        assert receipt.lease_id is not None, operator_id
        assert len(leases) == 1, operator_id
        assert leases[0].rollback_operator_id is not None, operator_id
        assert leases[0].ttl_seconds <= entry.max_duration_seconds, operator_id
        assert leases[0].target_digest == receipt.target_digest, operator_id
        assert receipt.postconditions, operator_id
        checked += 1
    assert checked >= 1, "no leasable operator committed; the criterion measured nothing"


def test_the_journal_records_the_privileged_act() -> None:
    """The digest chain must contain the COMMIT, not only the intent and the end."""
    rig = _rig()
    operator = _operator(_LEASED_OPERATOR_ID)
    receipt = rig.executor.execute(
        operator, _mint(rig, operator, action_id="act.chain"), resolution=_resolution()
    )
    phases = [str(phase) for phase in rig.journal.phases_of(receipt.action_id)]
    assert "PREPARE" in phases and "COMMIT" in phases and "FINALIZE" in phases
    assert rig.journal.verify_chain() == ()
    # And FINALIZE released the rollback state, because no live lease needs it once
    # the sweeper has run.
    assert rig.journal.rollback_state(receipt.action_id) is not None, (
        "a live lease still references this action, so its undo state must survive"
    )


# --- bounded endpoint state, including the ledgers about the bounds -----------


def test_the_truncation_ledger_is_itself_bounded() -> None:
    """A record *about* a bound is endpoint state too.

    Found by measuring rather than by reading: a 4000-action flood against a
    default journal produced 3873 refusals and, before this bound existed, 3873
    rows describing them. The head is kept because the first refusal is the
    diagnostic one; the rest is a counter, and the counter is readable so the loss
    stays explicit.
    """
    from pocketsec.stage5.executor.journal import MAX_TRUNCATION_RECORDS

    journal = RollbackJournal(
        max_bytes=MIN_FREE_BYTES_FOR_ACTION, max_entries=MAX_PHASES_PER_ACTION
    )
    operator = _shape_operator()
    journal.append(
        action_id="act.0",
        phase=_phase("PREPARE"),
        at=0,
        operator=operator,
        payload={"rollback_state": {"state": "RUNNING"}},
    )
    attempts = MAX_TRUNCATION_RECORDS * 3
    for index in range(1, attempts + 1):
        with pytest.raises(JournalFull):
            journal.append(
                action_id=f"act.{index}",
                phase=_phase("PREPARE"),
                at=index,
                operator=operator,
                payload={"rollback_state": {"state": "RUNNING"}},
            )
    assert len(journal.truncations()) == MAX_TRUNCATION_RECORDS
    assert journal.truncations_dropped() == attempts - MAX_TRUNCATION_RECORDS
    # The head was kept, not the tail: the first refusal is still readable.
    assert journal.truncations()[0].identifier == "act.1"


def test_the_rate_limit_window_does_not_grow_with_uptime() -> None:
    """SENTINEL's ``recent_action_times`` is a window, not a log."""
    from pocketsec.stage5.executor.transactional import MAX_RECENT_ACTION_TIMES

    rig = _rig()
    for index in range(MAX_RECENT_ACTION_TIMES * 2):
        rig.clock.advance(1)
        rig.executor._note_action_time(rig.clock.now())
    window = rig.executor._recent_action_times
    assert len(window) == MAX_RECENT_ACTION_TIMES
    # Oldest-first eviction: what survives is the recent past, which is what a rate
    # limit is a question about.
    assert window == sorted(window)
    assert window[-1] == rig.clock.now()


def test_the_sweepers_failure_ledger_is_bounded() -> None:
    """A host where every undo is refused must not grow a list forever."""
    from pocketsec.stage5.executor.lease import (
        MAX_UNROLLBACKABLE_RECORDS,
        LeaseSweeper,
    )

    rig = _rig()
    sweeper = LeaseSweeper(
        registry=rig.leases, executor=rig.executor, tokens=rig.tokens, clock=rig.clock
    )
    attempts = MAX_UNROLLBACKABLE_RECORDS * 2
    for index in range(attempts):
        sweeper._note_unrollbackable(f"lease.{index}", "NO_ROLLBACK_CONTEXT")
    assert len(sweeper.unrollbackable()) == MAX_UNROLLBACKABLE_RECORDS
    assert sweeper.unrollbackable_dropped() == attempts - MAX_UNROLLBACKABLE_RECORDS


def test_a_lease_whose_context_was_never_swept_is_counted_not_forgotten_silently() -> None:
    """Undo state is kept until an undo commits, and only an abandonment is counted.

    This test used to pin the defect: a second ``tick`` with nobody having consumed the
    first one threw the rollback context away (counted as one drop), which left a
    containment on the host with no way to undo it. After finding F9 a pending undo
    keeps its context across ticks, so the second tick loses nothing; the counter moves
    only when a pending undo is abandoned because its target is gone.
    """
    rig = _rig()
    operator = _operator(_LEASED_OPERATOR_ID)
    rig.executor.execute(
        operator, _mint(rig, operator, action_id="act.drop"), resolution=_resolution()
    )
    rig.clock.advance(301)
    expiries = rig.leases.tick(rig.clock.now())
    assert expiries != ()
    lease_id = expiries[0].lease.lease_id
    assert rig.leases.dropped_rollback_contexts() == 0
    rig.leases.tick(rig.clock.now())
    assert rig.leases.dropped_rollback_contexts() == 0
    assert rig.leases.rollback_context(lease_id) is not None, "a second tick lost the undo"
    assert lease_id in {lease.lease_id for lease in rig.leases.pending_undos()}
    rig.leases.abandon(lease_id)
    assert rig.leases.dropped_rollback_contexts() == 1
    assert rig.leases.rollback_context(lease_id) is None


def test_a_refusal_raised_after_prepare_still_produces_a_receipt() -> None:
    """No private exception may escape ``execute``.

    The protocol can refuse after PREPARE — a journal that filled between phases,
    for instance — and the contract promises a :class:`TransactionReceipt` for
    every call, not an opaque error. A caller that has to catch a private exception
    class cannot audit what happened, and an un-audited refusal is the failure mode
    the receipt exists to prevent.
    """
    transactional = _executor()
    rig = _rig()

    class _RefusingLate(transactional.TransactionalExecutor):  # type: ignore[misc, name-defined]
        def _act(self, operator: Any, bundle: Any, started: int) -> Any:
            raise transactional._Refusal(
                transactional.Outcome.ESCALATED, "refused after PREPARE"
            )

    late = _RefusingLate(
        kernel=rig.executor._kernel,
        host=rig.host,
        journal=rig.journal,
        gate=rig.executor._gate,
        governor=rig.governor,
        leases=rig.leases,
        probe=rig.executor._probe,
        clock=rig.clock,
        tokens=rig.tokens,
    )
    operator = _operator(_LEASED_OPERATOR_ID, incident="inc.late")
    receipt = late.execute(
        operator,
        _mint(rig, operator, action_id="act.late"),
        resolution=_resolution(incident="inc.late"),
    )
    assert isinstance(receipt, transactional.TransactionReceipt)
    assert receipt.outcome is transactional.Outcome.ESCALATED
    assert receipt.phases[0].phase is transactional.Phase.PREPARE
    assert receipt.phases[-1].phase is transactional.Phase.FINALIZE


def test_the_substitute_check_fails_when_the_race_operator_did_act() -> None:
    """Finding F9: G5.5's "substitute untouched" used to be unfalsifiable.

    The race operator restricts a socket and never changes a process's state, and the old
    check asked only whether the substitute was still RUNNING — so it read True whether or
    not the executor had acted. Hand it an after-snapshot in which the race operator's
    effect is present and it must read False; hand it the unchanged host and True.
    """
    from dataclasses import replace as _replace

    from pocketsec.stage5.labs import toctou as race_lab

    setup = race_lab.build_race_setup("PID_REUSED")
    before = setup.inner.snapshot()
    assert race_lab._substitute_untouched(setup, before, before) is True
    socket = setup.operator.target.scope.subject
    acted = _replace(before, restricted_sockets=frozenset({*before.restricted_sockets, socket}))
    assert race_lab._substitute_untouched(setup, before, acted) is False
