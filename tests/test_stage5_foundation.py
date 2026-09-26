"""Stage 5 work package 1 — the constitution, the authority plane and the governor.

D5.1, D5.6, D5.23 and ``core_ids.py``. The tests here are about **refusals**: a
constitution that cannot be weakened, a grant source that cannot name a model, a
token that cannot be replayed, a budget that cannot be widened and a prune that
cannot drop the safe option. A test that only proved these types *exist* would
repeat the defect both prior stages shipped — a gate check that passed by
asserting a type existed (spec §4.9 rule B).

Several tests are deliberately written so that they fail if someone relaxes the
thing they pin, and say so in their docstring: ``test_a_weakened_constitution_is
_unconstructible``, ``test_permits_has_no_confidence_shaped_parameter``,
``test_violations_is_a_total_match_over_invariant_kind``,
``test_prune_never_drops_the_observe_only_candidate`` and
``test_pinned_upstream_schemas_match_the_live_registry``.
"""

from __future__ import annotations

import ast
import inspect
import json
from dataclasses import fields as dataclass_fields
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from pocketsec.stage0.contracts.common import SCHEMA_REGISTRY, ContractError
from pocketsec.stage0.gate import REPO_ROOT
from pocketsec.stage5.authority.capability import (
    AUTHORITY_BY_OPERATOR_CLASS,
    AUTONOMY_BY_OPERATOR_CLASS,
    HUMAN_REQUIRED_AUTONOMY,
    POLICY_AUTONOMY,
    AuthorityGrant,
    Autonomy,
    GrantSource,
    autonomy_of,
    autonomy_permitted,
    escalates,
    required_authority,
)
from pocketsec.stage5.authority.tokens import (
    MAX_SPENT_NONCES,
    MAX_TOKEN_LIFETIME_SECONDS,
    NONCE_BYTES,
    REFUSAL_VERDICTS,
    CapabilityToken,
    TokenStore,
    TokenVerdict,
)
from pocketsec.stage5.constitution.invariants import (
    AUTHORITY_ORDER,
    FROZEN_CONSTITUTION,
    MAX_AUTONOMOUS_AUTHORITY,
    REVERSIBILITY_ORDER,
    AuthorityClass,
    ConstitutionalLaw,
    ConstitutionDecision,
    ConstitutionVerdict,
    ResponseConstitution,
    authority_rank,
    reversibility_rank,
)
from pocketsec.stage5.constitution.schema import (
    BOUNDED_KINDS,
    DEFAULT_MISSION_INVARIANTS,
    HOST_GLOBAL_KINDS,
    MAX_INVARIANT_SET_BYTES,
    MAX_MISSION_INVARIANTS,
    MAX_SUBJECT_LENGTH,
    InvariantKind,
    MissionInvariant,
    MissionInvariantSet,
)
from pocketsec.stage5.core_ids import (
    ABLATION_FLAGS,
    CORE_IDS,
    OPTIONAL_IDS,
    PINNED_UPSTREAM_SCHEMAS,
    REQUIRED_IDS,
    CoreFunction,
    FunctionClass,
    core_function,
)
from pocketsec.stage5.governor import (
    KIND_CAPS,
    PROTECTED_CANDIDATE_IDS,
    STAGE5_BUDGET,
    BudgetExhausted,
    PruneRecord,
    ResourceBudget,
    ResourceGovernor,
    WorkKind,
)
from pocketsec.stage5.operators.algebra import (
    DefensiveOperator,
    OperatorClass,
    ProcessIdentity,
    ProcessTarget,
    Reversibility,
    TargetKind,
    TargetScope,
)
from pocketsec.stage5.operators.catalog import CATALOG

# --- fixtures: the smallest real operator this package can be tested against ---

#: A key long enough for the store to accept, and obviously not a secret.
TEST_KEY = b"stage5-foundation-test-key-0001"


def identity(pid: int = 4011, *, start: int = 99_000, uid: int = 1000) -> ProcessIdentity:
    return ProcessIdentity(
        pid=pid,
        start_time_ticks=start,
        uid=uid,
        executable_digest=None,
        cgroup_id="cgroup:system.slice:app",
        namespace_id="netns:host",
    )


def operator(
    operator_id: str = "SUSPEND_PROCESS",
    *,
    pid: int = 4011,
    start: int = 99_000,
    kind: TargetKind = TargetKind.PROCESS,
    subject: str = "app-worker",
    ttl_seconds: int | None = None,
) -> DefensiveOperator:
    """A real :class:`DefensiveOperator` built from the real catalog.

    Package 2 landed while this package was being written, so nothing here is
    tested against a stand-in: the specs are ``CATALOG`` members by identity, which
    is the only way a ``DefensiveOperator`` can be constructed at all.
    """
    spec = CATALOG[operator_id]
    return DefensiveOperator(
        spec=spec,
        target=ProcessTarget(
            identity=identity(pid, start=start),
            scope=TargetScope(kind=kind, subject=subject),
        ),
        incident_id="INC-0001",
        ttl_seconds=min(ttl_seconds or 60, spec.max_duration_seconds),
        evidence_refs=(),
    )


class Clock:
    """A clock that does not advance on its own. Every expiry test uses one."""

    def __init__(self, at: int = 1_000) -> None:
        self._at = at

    def now(self) -> int:
        return self._at

    def advance(self, seconds: int) -> None:
        self._at += seconds


# --- D5.1: the ten laws ------------------------------------------------------


def test_the_constitution_is_exactly_the_ten_architecture_laws() -> None:
    """Pinned by value, so a rename is a visible edit rather than a silent drift."""
    assert {law.value for law in ConstitutionalLaw} == {
        "NO_CONFIDENCE_GRANTS_AUTHORITY",
        "NO_NATURAL_LANGUAGE_TO_PRIVILEGE",
        "NO_ACTION_EXCEEDS_DECLARED_SCOPE",
        "UNKNOWN_IS_NOT_PERMISSION",
        "UNVERIFIABLE_IS_NOT_COMPLETE",
        "IRREVERSIBLE_NEEDS_HIGHER_AUTHORITY",
        "EVIDENCE_PRECEDES_INTERVENTION",
        "NO_ACTION_IS_ALWAYS_AVAILABLE",
        "FAILURE_MUST_NOT_STOP_MONITORING",
        "NO_OFFENSIVE_BEHAVIOUR",
    }
    assert FROZEN_CONSTITUTION.laws == tuple(ConstitutionalLaw)
    assert FROZEN_CONSTITUTION.max_autonomous_authority is MAX_AUTONOMOUS_AUTHORITY


WEAKENINGS: tuple[tuple[str, dict[str, Any]], ...] = (
    ("a dropped law", {"laws": tuple(ConstitutionalLaw)[:-1]}),
    (
        "a duplicated law to hide a dropped one",
        {"laws": tuple(ConstitutionalLaw)[:-1] + (ConstitutionalLaw.UNKNOWN_IS_NOT_PERMISSION,)},
    ),
    ("no laws at all", {"laws": ()}),
    ("a lifted autonomy ceiling", {"max_autonomous_authority": AuthorityClass.A3}),
    ("the highest possible ceiling", {"max_autonomous_authority": AuthorityClass.A5}),
    ("an un-prohibited destructive class", {"prohibited_operator_classes": frozenset()}),
    (
        "a prohibition that names the wrong class",
        {"prohibited_operator_classes": frozenset({OperatorClass.O6_DISRUPTIVE})},
    ),
    ("an empty policy version", {"policy_version": ""}),
)


@pytest.mark.parametrize(("label", "override"), WEAKENINGS, ids=[w[0] for w in WEAKENINGS])
def test_a_weakened_constitution_is_unconstructible(label: str, override: dict[str, Any]) -> None:
    """**This is the test that fails if someone relaxes the constitution.**

    SENTINEL's independence rests on there being no way to hand it a permissive
    constitution. Every weakening a caller could plausibly try is a
    ``ContractError`` at construction, so the permissive object never exists to be
    passed anywhere — not from a config file, not from ``from_dict``, not from a
    test fixture.
    """
    payload: dict[str, Any] = {
        "laws": tuple(ConstitutionalLaw),
        "max_autonomous_authority": AuthorityClass.A2,
        "prohibited_operator_classes": frozenset({OperatorClass.O7_DESTRUCTIVE}),
        "policy_version": "1.0.0",
    }
    payload.update(override)
    with pytest.raises(ContractError):
        ResponseConstitution(**payload)


def test_an_equal_constitution_is_constructible_and_digests_identically() -> None:
    """The refusal must be of *weaker*, not of *equal*: deserialisation has to work."""
    twin = ResponseConstitution(
        laws=tuple(ConstitutionalLaw),
        max_autonomous_authority=AuthorityClass.A2,
        prohibited_operator_classes=frozenset({OperatorClass.O7_DESTRUCTIVE}),
        policy_version="1.0.0",
    )
    assert twin.digest() == FROZEN_CONSTITUTION.digest()
    assert twin.to_dict() == FROZEN_CONSTITUTION.to_dict()


def test_the_prohibited_class_key_space_is_operator_class() -> None:
    """Spec §4.9 rule A: the two key spaces must be structurally identical.

    ``constitution/invariants.py`` stores the prohibition as an ordinal to stay a
    leaf module, so this asserts the ordinal set and the ``OperatorClass`` set are
    the same thing from both directions — a membership test and an equality.
    """
    assert OperatorClass.O7_DESTRUCTIVE in FROZEN_CONSTITUTION.prohibited_operator_classes
    assert FROZEN_CONSTITUTION.prohibited_operator_classes == frozenset(
        {OperatorClass.O7_DESTRUCTIVE}
    )
    assert OperatorClass.O6_DISRUPTIVE not in FROZEN_CONSTITUTION.prohibited_operator_classes
    assert FROZEN_CONSTITUTION.to_dict()["prohibited_operator_classes"] == [
        int(OperatorClass.O7_DESTRUCTIVE)
    ]


def test_permits_has_no_confidence_shaped_parameter() -> None:
    """**ADR-0003 by construction:** there is nothing to be confident with.

    If a later change adds ``confidence``, ``score``, ``support``, ``probability``
    or a free-text parameter to ``permits``, this fails. The point is not that the
    parameter would be misused; it is that its absence is what makes "model
    confidence never grants authority" a property of the signature.
    """
    parameters = set(inspect.signature(ResponseConstitution.permits).parameters)
    assert parameters == {
        "self",
        "operator_class",
        "authority",
        "reversibility",
        "has_rollback",
        "autonomous",
    }
    forbidden = ("confidence", "score", "support", "probability", "verdict", "text", "prompt")
    assert not [name for name in parameters if any(token in name for token in forbidden)]


def test_identical_authority_outcomes_regardless_of_upstream_confidence() -> None:
    """A 0.99 prediction and a 0.01 prediction reach the same authority decision.

    The confidence cannot even be passed, so the demonstration is that the same
    operator reaches the same verdict under both readings of the same incident —
    the value that differs upstream has no channel into this decision.
    """
    verdicts = []
    for _confidence in (0.99, 0.01):
        verdicts.append(
            FROZEN_CONSTITUTION.permits(
                operator_class=OperatorClass.O3_SUSPEND,
                authority=AuthorityClass.A2,
                reversibility=Reversibility.FULLY_REVERSIBLE,
                has_rollback=True,
                autonomous=True,
            )
        )
    assert verdicts[0] == verdicts[1]
    assert verdicts[0].decision is ConstitutionDecision.PERMITTED


PERMIT_CASES = (
    ("reversible local action", OperatorClass.O3_SUSPEND, AuthorityClass.A2,
     Reversibility.FULLY_REVERSIBLE, True, True, ConstitutionDecision.PERMITTED),
    ("observation", OperatorClass.O0_OBSERVE, AuthorityClass.A0,
     Reversibility.FULLY_REVERSIBLE, True, True, ConstitutionDecision.PERMITTED),
    ("over the autonomy ceiling", OperatorClass.O4_LOCAL_REVOKE, AuthorityClass.A3,
     Reversibility.DEGRADED, True, True, ConstitutionDecision.HUMAN_REQUIRED),
    ("irreversible autonomously", OperatorClass.O6_DISRUPTIVE, AuthorityClass.A5,
     Reversibility.IRREVERSIBLE, False, True, ConstitutionDecision.HUMAN_REQUIRED),
    ("a release needs no rollback of its own", OperatorClass.O2_REVERSIBLE_RESTRICT,
     AuthorityClass.A2, Reversibility.FULLY_REVERSIBLE, False, True,
     ConstitutionDecision.PERMITTED),
    ("state-carrying with no rollback bound", OperatorClass.O2_REVERSIBLE_RESTRICT,
     AuthorityClass.A2, Reversibility.REVERSIBLE_WITH_STATE, False, True,
     ConstitutionDecision.HUMAN_REQUIRED),
    ("state-carrying with a rollback bound", OperatorClass.O2_REVERSIBLE_RESTRICT,
     AuthorityClass.A2, Reversibility.REVERSIBLE_WITH_STATE, True, True,
     ConstitutionDecision.PERMITTED),
    ("degraded with no rollback bound", OperatorClass.O2_REVERSIBLE_RESTRICT,
     AuthorityClass.A2, Reversibility.DEGRADED, False, True,
     ConstitutionDecision.HUMAN_REQUIRED),
    ("destructive, whatever the authority", OperatorClass.O7_DESTRUCTIVE, AuthorityClass.A5,
     Reversibility.IRREVERSIBLE, False, False, ConstitutionDecision.REFUSED),
    ("AX is off the ladder", OperatorClass.O6_DISRUPTIVE, AuthorityClass.AX,
     Reversibility.IRREVERSIBLE, False, False, ConstitutionDecision.REFUSED),
    ("a person may authorise a disruptive action", OperatorClass.O6_DISRUPTIVE,
     AuthorityClass.A5, Reversibility.IRREVERSIBLE, False, False,
     ConstitutionDecision.PERMITTED),
)


@pytest.mark.parametrize(
    ("label", "operator_class", "authority", "reversibility", "has_rollback", "autonomous",
     "expected"),
    PERMIT_CASES,
    ids=[case[0] for case in PERMIT_CASES],
)
def test_permits_decides_each_constitutional_case(
    label: str,
    operator_class: OperatorClass,
    authority: AuthorityClass,
    reversibility: Reversibility,
    has_rollback: bool,
    autonomous: bool,
    expected: ConstitutionDecision,
) -> None:
    verdict = FROZEN_CONSTITUTION.permits(
        operator_class=operator_class,
        authority=authority,
        reversibility=reversibility,
        has_rollback=has_rollback,
        autonomous=autonomous,
    )
    assert verdict.decision is expected, (label, verdict)
    if expected is not ConstitutionDecision.PERMITTED:
        assert verdict.laws_invoked, "a refusal must name the law it invokes"


def test_a_refusal_that_names_no_law_is_unconstructible() -> None:
    """A refusal nobody can audit or appeal is not a refusal."""
    with pytest.raises(ContractError):
        ConstitutionVerdict(ConstitutionDecision.REFUSED, (), "because")
    with pytest.raises(ContractError):
        ConstitutionVerdict(ConstitutionDecision.PERMITTED, (), "")


def test_destructive_is_refused_rather_than_escalated_to_a_human() -> None:
    """§5's "not autonomous" plus §2's tenth law: no authority unlocks O7.

    Routing destruction to a human would make the constitution a routing table,
    and O7 has zero catalog entries precisely so the case is not expressible.
    """
    for authority in (AuthorityClass.A0, AuthorityClass.A2, AuthorityClass.A5):
        verdict = FROZEN_CONSTITUTION.permits(
            operator_class=OperatorClass.O7_DESTRUCTIVE,
            authority=authority,
            reversibility=Reversibility.IRREVERSIBLE,
            has_rollback=False,
            autonomous=False,
        )
        assert verdict.decision is ConstitutionDecision.REFUSED


def test_authority_is_ordered_by_rank_and_never_by_string() -> None:
    """``"A2" < "AX"`` is true about text and dangerous about privilege."""
    assert set(AUTHORITY_ORDER) == set(AuthorityClass)
    ladder = [AuthorityClass.A0, AuthorityClass.A1, AuthorityClass.A2, AuthorityClass.A3,
              AuthorityClass.A4, AuthorityClass.A5]
    ranks = [authority_rank(step) for step in ladder]
    assert ranks == sorted(ranks) == [0, 1, 2, 3, 4, 5]
    assert authority_rank(AuthorityClass.AX) > authority_rank(AuthorityClass.A5) + 1
    assert authority_rank(MAX_AUTONOMOUS_AUTHORITY) == 2


def test_an_unrecognised_reversibility_is_ranked_irreversible() -> None:
    """Fail-closed: an unranked value must be the *most* constrained case.

    A future ``Reversibility`` member nobody ranked would otherwise be ranked 0 —
    "fully reversible" — which is the failure that quietly permits an
    unrollbackable action.
    """
    assert reversibility_rank("A_MEMBER_NOBODY_RANKED") == REVERSIBILITY_ORDER["IRREVERSIBLE"]
    assert {member.value for member in Reversibility} == set(REVERSIBILITY_ORDER), (
        "spec §4.9 rule A: the reversibility key space is one vocabulary"
    )
    for member in Reversibility:
        assert reversibility_rank(member) == REVERSIBILITY_ORDER[member.value]


# --- D5.1: mission invariants ------------------------------------------------


def test_invariant_kinds_are_exactly_the_eight_architecture_bullets() -> None:
    assert {kind.value for kind in InvariantKind} == {
        "CRITICAL_SERVICE",
        "ADMIN_RECOVERY_ACCESS",
        "EVIDENCE_RETENTION",
        "BOUNDARY_NOT_CROSSED",
        "MAX_AUTONOMOUS_DOWNTIME",
        "MAX_CONTAINMENT_DURATION",
        "FORBIDDEN_KERNEL_MODIFICATION",
        "HOST_LOCAL_SCOPE",
    }
    assert set(InvariantKind) > HOST_GLOBAL_KINDS and len(HOST_GLOBAL_KINDS) == 4
    assert set(InvariantKind) > BOUNDED_KINDS and len(BOUNDED_KINDS) == 3


INVALID_INVARIANTS = (
    ("a subject on a host-global kind", "MI-X", InvariantKind.HOST_LOCAL_SCOPE, "somewhere", None),
    ("no subject on a subject kind", "MI-X", InvariantKind.CRITICAL_SERVICE, "", None),
    ("no bound on a bounded kind", "MI-X", InvariantKind.MAX_CONTAINMENT_DURATION, "", None),
    ("a bound on an unbounded kind", "MI-X", InvariantKind.CRITICAL_SERVICE, "a.service", 30),
    ("an oversized subject", "MI-X", InvariantKind.CRITICAL_SERVICE, "x" * 200, None),
    ("a non-identifier id", "not an id!", InvariantKind.FORBIDDEN_KERNEL_MODIFICATION, "", None),
)


@pytest.mark.parametrize(
    ("label", "invariant_id", "kind", "subject", "bound"),
    INVALID_INVARIANTS,
    ids=[case[0] for case in INVALID_INVARIANTS],
)
def test_an_ill_formed_mission_invariant_is_refused(
    label: str, invariant_id: str, kind: InvariantKind, subject: str, bound: int | None
) -> None:
    with pytest.raises(ContractError):
        MissionInvariant(invariant_id, kind, subject, bound, "why")


def test_a_mission_invariant_with_no_reason_is_refused() -> None:
    """An invariant nobody can explain will be deleted by the first person it blocks."""
    with pytest.raises(ContractError):
        MissionInvariant("MI-X", InvariantKind.HOST_LOCAL_SCOPE, "", None, "")


def test_the_default_mission_invariant_set_covers_every_kind() -> None:
    kinds = {invariant.kind for invariant in DEFAULT_MISSION_INVARIANTS.invariants}
    assert kinds == set(InvariantKind)
    assert len(DEFAULT_MISSION_INVARIANTS.invariants) == 9
    assert DEFAULT_MISSION_INVARIANTS.critical_units() == {
        "sshd.service",
        "systemd-journald.service",
    }
    assert DEFAULT_MISSION_INVARIANTS.required_evidence() == {"process_memory_map"}


def test_the_mission_invariant_set_is_bounded_three_ways() -> None:
    """Bounded endpoint state: policy is state, and unbounded policy is unbounded state."""
    too_many = tuple(
        MissionInvariant(f"MI-{index:03d}", InvariantKind.CRITICAL_SERVICE, f"u{index}", None, "d")
        for index in range(MAX_MISSION_INVARIANTS + 1)
    )
    with pytest.raises(ContractError, match="at most"):
        MissionInvariantSet(too_many)

    duplicate = MissionInvariant("MI-01", InvariantKind.CRITICAL_SERVICE, "a", None, "d")
    with pytest.raises(ContractError, match="unique"):
        MissionInvariantSet((duplicate, duplicate))

    fat = tuple(
        MissionInvariant(
            f"MI-{index:03d}",
            InvariantKind.CRITICAL_SERVICE,
            f"{index:03d}" + "u" * (MAX_SUBJECT_LENGTH - 3),
            None,
            "d" * 120,
        )
        for index in range(MAX_MISSION_INVARIANTS)
    )
    with pytest.raises(ContractError, match="canonical bytes"):
        MissionInvariantSet(fat)


def test_the_default_invariant_set_is_well_inside_its_byte_bound() -> None:
    from pocketsec.stage5.constitution.invariants import canonical_bytes

    size = len(canonical_bytes(DEFAULT_MISSION_INVARIANTS.to_dict()))
    assert 0 < size < MAX_INVARIANT_SET_BYTES
    assert MissionInvariantSet.from_dict(DEFAULT_MISSION_INVARIANTS.to_dict()) == (
        DEFAULT_MISSION_INVARIANTS
    )


def test_an_empty_or_missing_mission_is_unconstructible() -> None:
    """Finding S5-SEC-06: ``MissionInvariantSet(())`` and ``from_dict({})`` were accepted.

    Either one, handed to SENTINEL and the evidence gate, switched off critical-unit
    protection, admin recovery, evidence retention and host-local scope while both still
    answered PASS — the "missing config" disablement vector. Both now refuse.
    """
    from pocketsec.stage5.executor.identity import ManualClock
    from pocketsec.stage5.sentinel.kernel import SentinelKernel

    with pytest.raises(ContractError, match="at least one"):
        MissionInvariantSet(())
    with pytest.raises(ContractError, match="no 'invariants' key"):
        MissionInvariantSet.from_dict({})
    with pytest.raises(ContractError, match="at least one"):
        MissionInvariantSet.from_dict({"invariants": []})
    kernel = SentinelKernel(
        constitution=FROZEN_CONSTITUTION, invariants=DEFAULT_MISSION_INVARIANTS,
        clock=ManualClock(at=0),
    )
    assert kernel is not None


class FakeRow:
    """The ``ProcessRow`` slice ``violations()`` reads, per its Protocol."""

    def __init__(
        self,
        *,
        unit: str | None = None,
        session_id: str | None = None,
        volatile_signals: tuple[str, ...] = (),
    ) -> None:
        self.unit = unit
        self.session_id = session_id
        self.volatile_signals = volatile_signals


class FakeSnapshot:
    """A read-only host view. There is no method here that changes anything."""

    def __init__(self, rows: dict[int, FakeRow] | None = None) -> None:
        self._rows = rows or {}

    def process(self, pid: int) -> FakeRow | None:
        return self._rows.get(pid)


def test_the_process_row_protocol_matches_the_real_host_model() -> None:
    """Spec §4.9 rule A applied to a structural type rather than a key.

    ``violations()`` reads the host through a Protocol, which is invisible to the
    runtime: if ``host/simulated.py`` renamed ``volatile_signals``, every evidence
    check would silently stop firing. This joins the two.
    """
    from pocketsec.stage5.host.simulated import HostSnapshot, ProcessRow

    row_fields = {field.name for field in dataclass_fields(ProcessRow)}
    assert {"unit", "session_id", "volatile_signals"} <= row_fields
    assert hasattr(HostSnapshot, "process")


def test_a_benign_observation_violates_nothing() -> None:
    snapshot = FakeSnapshot({4011: FakeRow(unit="app.service", volatile_signals=("procfs",))})
    assert (
        DEFAULT_MISSION_INVARIANTS.violations(
            operator=operator("OBSERVE_PROCESS_METADATA"),
            lease_ttl_seconds=60,
            snapshot=snapshot,
        )
        == ()
    )


def test_suspending_a_critical_service_violates_the_critical_service_invariant() -> None:
    snapshot = FakeSnapshot({4011: FakeRow(unit="sshd.service")})
    found = DEFAULT_MISSION_INVARIANTS.violations(
        operator=operator("SUSPEND_PROCESS"), lease_ttl_seconds=60, snapshot=snapshot
    )
    assert [violation.kind for violation in found] == [InvariantKind.CRITICAL_SERVICE]
    assert found[0].invariant_id == "MI-01"


def test_revoking_the_recovery_session_violates_admin_recovery_access() -> None:
    snapshot = FakeSnapshot({4011: FakeRow(session_id="admin-recovery")})
    found = DEFAULT_MISSION_INVARIANTS.violations(
        operator=operator(
            "REVOKE_LOCAL_SESSION", kind=TargetKind.SESSION, subject="admin-recovery"
        ),
        lease_ttl_seconds=60,
        snapshot=snapshot,
    )
    assert InvariantKind.ADMIN_RECOVERY_ACCESS in {violation.kind for violation in found}


def test_destroying_required_evidence_violates_evidence_retention() -> None:
    """The evidence gate must come *before* the action, so this must be catchable at plan time."""
    snapshot = FakeSnapshot(
        {4011: FakeRow(unit="app.service", volatile_signals=("process_memory_map", "sockets"))}
    )
    found = DEFAULT_MISSION_INVARIANTS.violations(
        operator=operator("SUSPEND_PROCESS"), lease_ttl_seconds=60, snapshot=snapshot
    )
    kinds = {violation.kind for violation in found}
    assert InvariantKind.EVIDENCE_RETENTION in kinds


def test_acting_inside_a_protected_namespace_violates_the_boundary() -> None:
    quarantined = DefensiveOperator(
        spec=CATALOG["SUSPEND_PROCESS"],
        target=ProcessTarget(
            identity=ProcessIdentity(
                pid=5150,
                start_time_ticks=1,
                uid=0,
                executable_digest=None,
                cgroup_id=None,
                namespace_id="netns:quarantine",
            ),
            scope=TargetScope(kind=TargetKind.PROCESS, subject="isolated"),
        ),
        incident_id="INC-0002",
        ttl_seconds=30,
        evidence_refs=(),
    )
    found = DEFAULT_MISSION_INVARIANTS.violations(
        operator=quarantined, lease_ttl_seconds=30, snapshot=FakeSnapshot()
    )
    assert InvariantKind.BOUNDARY_NOT_CROSSED in {violation.kind for violation in found}


def test_an_overlong_lease_violates_both_duration_bounds() -> None:
    snapshot = FakeSnapshot({4011: FakeRow(unit="app.service")})
    found = DEFAULT_MISSION_INVARIANTS.violations(
        operator=operator("SUSPEND_PROCESS", ttl_seconds=900),
        lease_ttl_seconds=901,
        snapshot=snapshot,
    )
    kinds = {violation.kind for violation in found}
    assert InvariantKind.MAX_AUTONOMOUS_DOWNTIME in kinds
    assert InvariantKind.MAX_CONTAINMENT_DURATION in kinds


def test_a_restriction_under_the_downtime_bound_violates_neither() -> None:
    """The bound must be able to *not* fire, or it is not a bound."""
    snapshot = FakeSnapshot({4011: FakeRow(unit="app.service")})
    found = DEFAULT_MISSION_INVARIANTS.violations(
        operator=operator("RESTRICT_LOCAL_SOCKET", kind=TargetKind.SOCKET, subject="sock-1"),
        lease_ttl_seconds=120,
        snapshot=snapshot,
    )
    assert found == ()


class KernelSpec:
    """A spec naming a kernel change, to prove the §24 kernel arm can fire.

    No catalog entry does this, which is the point: the check protects against the
    *next* catalog entry, so it has to be testable without one.
    """

    operator_id = "LOAD_KERNEL_MODULE"
    operator_class = OperatorClass.O6_DISRUPTIVE
    evidence_effect = "NEUTRAL"
    argv_template = (type("L", (), {"value": "kernel.module.load"})(),)


class KernelOperator:
    def __init__(self) -> None:
        self.spec = KernelSpec()
        self.target = ProcessTarget(
            identity=identity(), scope=TargetScope(kind=TargetKind.HOST, subject="host")
        )


def test_an_operator_naming_a_kernel_change_violates_the_kernel_invariant() -> None:
    found = DEFAULT_MISSION_INVARIANTS.violations(
        operator=KernelOperator(), lease_ttl_seconds=1, snapshot=FakeSnapshot()
    )
    assert InvariantKind.FORBIDDEN_KERNEL_MODIFICATION in {violation.kind for violation in found}


def test_a_non_host_local_action_cannot_even_be_constructed() -> None:
    """Defence in depth, and the algebra gets there first.

    ``DefensiveOperator.__post_init__`` refuses a non-host-local scope, so §24's
    HOST_LOCAL_SCOPE arm is unreachable through a real operator. Both layers are
    asserted: the construction is refused, and the arm still fires on an object
    that bypasses the algebra — because the arm is what protects the invariant if
    a future operator type is added beside ``DefensiveOperator``.
    """
    with pytest.raises(ContractError):
        DefensiveOperator(
            spec=CATALOG["OBSERVE_PROCESS_METADATA"],
            target=ProcessTarget(
                identity=identity(),
                scope=TargetScope(kind=TargetKind.PROCESS, subject="elsewhere", host_local=False),
            ),
            incident_id="INC-0003",
            ttl_seconds=10,
            evidence_refs=(),
        )

    class OffHostOperator:
        def __init__(self) -> None:
            self.spec = KernelSpec()
            self.target = type(
                "T",
                (),
                {
                    "identity": identity(),
                    "scope": type(
                        "S", (), {"kind": "PROCESS", "subject": "elsewhere", "host_local": False}
                    )(),
                },
            )()

    found = DEFAULT_MISSION_INVARIANTS.violations(
        operator=OffHostOperator(), lease_ttl_seconds=10, snapshot=FakeSnapshot()
    )
    assert InvariantKind.HOST_LOCAL_SCOPE in {violation.kind for violation in found}


def test_violations_refuses_a_negative_lease() -> None:
    with pytest.raises(ContractError):
        DEFAULT_MISSION_INVARIANTS.violations(
            operator=operator(), lease_ttl_seconds=-1, snapshot=FakeSnapshot()
        )


def _violations_function() -> ast.FunctionDef:
    source = (REPO_ROOT / "pocketsec" / "stage5" / "constitution" / "schema.py").read_text("utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "MissionInvariantSet":
            for statement in node.body:
                if isinstance(statement, ast.FunctionDef) and statement.name == "violations":
                    return statement
    raise AssertionError("MissionInvariantSet.violations is missing")


def test_violations_is_a_total_match_over_invariant_kind() -> None:
    """**This is the test that fails if the invariant checker gains a fallthrough.**

    G5.8 ("mission invariants are machine-enforced") rests on the ``match`` having
    no ``case _``: a ninth :class:`InvariantKind` then fails ``mypy --strict``
    rather than becoming an invariant that is declared and enforced nowhere. Both
    halves are asserted — no wildcard, and every member handled.
    """
    function = _violations_function()
    matched: set[str] = set()
    for node in ast.walk(function):
        if not isinstance(node, ast.Match):
            continue
        for case in node.cases:
            pattern = case.pattern
            assert not (
                isinstance(pattern, ast.MatchAs) and pattern.pattern is None
            ), "violations() must not have a `case _` fallthrough"
            assert isinstance(pattern, ast.MatchValue), ast.dump(pattern)
            assert isinstance(pattern.value, ast.Attribute), ast.dump(pattern.value)
            matched.add(pattern.value.attr)
    assert matched == {kind.name for kind in InvariantKind}, matched


# --- D5.6: the authority plane ----------------------------------------------


def test_a_grant_comes_from_policy_or_a_person_and_nothing_else() -> None:
    """ADR-0003 pinned by value: there is no MODEL member and no third source."""
    assert {source.value for source in GrantSource} == {"POLICY", "HUMAN"}
    assert len(GrantSource) == 2
    assert not [name for name in GrantSource.__members__ if "MODEL" in name.upper()]


def test_the_authority_and_autonomy_tables_are_total_over_operator_class() -> None:
    """Property P4's construction: an unmapped class is an import-time failure."""
    assert set(AUTHORITY_BY_OPERATOR_CLASS) == set(OperatorClass)
    assert set(AUTONOMY_BY_OPERATOR_CLASS) == set(OperatorClass)
    assert AUTHORITY_BY_OPERATOR_CLASS[OperatorClass.O7_DESTRUCTIVE] is AuthorityClass.AX
    assert AUTHORITY_BY_OPERATOR_CLASS[OperatorClass.O3_SUSPEND] is AuthorityClass.A2
    assert set(Autonomy) == POLICY_AUTONOMY | HUMAN_REQUIRED_AUTONOMY
    assert not POLICY_AUTONOMY & HUMAN_REQUIRED_AUTONOMY


def test_every_catalog_entry_agrees_with_the_authority_table() -> None:
    """The catalog's ``authority`` field and this table are two key spaces (§4.9 rule A)."""
    for operator_id, spec in CATALOG.items():
        assert spec.authority is AUTHORITY_BY_OPERATOR_CLASS[spec.operator_class], operator_id
        assert required_authority(spec) is spec.authority, operator_id


def test_escalation_is_ranked_not_lexicographic() -> None:
    assert escalates(AuthorityClass.A2, AuthorityClass.A3)
    assert not escalates(AuthorityClass.A3, AuthorityClass.A2)
    assert not escalates(AuthorityClass.A2, AuthorityClass.A2)
    assert escalates(AuthorityClass.A5, AuthorityClass.AX), "nothing covers AX"
    assert escalates(AuthorityClass.A0, AuthorityClass.AX)


def test_autonomy_permitted_requires_both_the_column_and_the_constitution() -> None:
    assert autonomy_permitted(CATALOG["OBSERVE_PROCESS_METADATA"], FROZEN_CONSTITUTION)
    assert autonomy_permitted(CATALOG["SUSPEND_PROCESS"], FROZEN_CONSTITUTION)
    assert not autonomy_permitted(CATALOG["REVOKE_LOCAL_SESSION"], FROZEN_CONSTITUTION)
    assert not autonomy_permitted(CATALOG["TERMINATE_PROCESS"], FROZEN_CONSTITUTION)
    assert autonomy_of(CATALOG["TERMINATE_PROCESS"]) is Autonomy.HUMAN_BY_DEFAULT


def test_a_grant_cannot_carry_ax_or_an_invented_source() -> None:
    with pytest.raises(ContractError, match="AX"):
        AuthorityGrant(AuthorityClass.AX, GrantSource.HUMAN, "1.0.0", "TERMINATE_PROCESS", "why")
    with pytest.raises(ContractError, match="GrantSource"):
        AuthorityGrant(
            AuthorityClass.A2,
            "MODEL",  # type: ignore[arg-type]
            "1.0.0",
            "SUSPEND_PROCESS",
            "why",
        )
    with pytest.raises(ContractError):
        AuthorityGrant(AuthorityClass.A2, GrantSource.POLICY, "1.0.0", "SUSPEND_PROCESS", "")


# --- D5.6: capability tokens -------------------------------------------------


def grant(
    operator_id: str = "SUSPEND_PROCESS",
    *,
    authority: AuthorityClass = AuthorityClass.A2,
    source: GrantSource = GrantSource.POLICY,
) -> AuthorityGrant:
    return AuthorityGrant(authority, source, "1.0.0", operator_id, "the foundation test suite")


def store(clock: Clock, *, capacity: int = MAX_SPENT_NONCES) -> TokenStore:
    return TokenStore(key=TEST_KEY, signer="stage5-policy", clock=clock, max_spent_nonces=capacity)


def test_minting_produces_a_token_scoped_to_one_operator_and_one_identity() -> None:
    clock = Clock()
    subject = operator()
    token = store(clock).mint(grant=grant(), operator=subject, action_id="ACT-0001", ttl_seconds=60)
    assert token.operator_id == subject.spec.operator_id
    assert token.target_digest == subject.target.identity.digest()
    assert token.authority is AuthorityClass.A2
    assert token.valid_from == clock.now() and token.expiry == clock.now() + 60
    assert len(token.nonce) == NONCE_BYTES * 2
    assert token.rollback_required is True
    assert CapabilityToken.from_dict(token.to_dict()) == token


def test_the_token_target_digest_is_the_executor_key_space() -> None:
    """Spec §4.9 rule A, the one that has already cost this project two defects.

    ``CapabilityToken.target_digest`` is joined against the live target by the
    executor, so it must be produced by ``identity_digest`` — the same function,
    not merely the same shape.
    """
    from pocketsec.stage5.executor.identity import identity_digest

    subject = operator()
    token = store(Clock()).mint(
        grant=grant(), operator=subject, action_id="ACT-0002", ttl_seconds=60
    )
    assert token.target_digest == identity_digest(subject.target.identity)
    assert token.target_digest == subject.target.identity.digest()


MINT_REFUSALS = (
    ("a grant for a different operator", "SUSPEND_PROCESS", AuthorityClass.A2,
     GrantSource.POLICY, "RESUME_PROCESS", 60),
    ("an escalated grant", "SUSPEND_PROCESS", AuthorityClass.A1, GrantSource.POLICY,
     "SUSPEND_PROCESS", 60),
    ("a policy grant for a human-only operator", "TERMINATE_PROCESS", AuthorityClass.A5,
     GrantSource.POLICY, "TERMINATE_PROCESS", 60),
    ("a lifetime over the token ceiling", "SUSPEND_PROCESS", AuthorityClass.A2,
     GrantSource.POLICY, "SUSPEND_PROCESS", MAX_TOKEN_LIFETIME_SECONDS + 1),
    ("a zero lifetime", "SUSPEND_PROCESS", AuthorityClass.A2, GrantSource.POLICY,
     "SUSPEND_PROCESS", 0),
)


@pytest.mark.parametrize(
    ("label", "operator_id", "authority", "source", "subject_operator_id", "ttl"),
    MINT_REFUSALS,
    ids=[case[0] for case in MINT_REFUSALS],
)
def test_mint_refuses_every_way_a_caller_could_overreach(
    label: str,
    operator_id: str,
    authority: AuthorityClass,
    source: GrantSource,
    subject_operator_id: str,
    ttl: int,
) -> None:
    subject = operator(operator_id, kind=CATALOG[operator_id].target_kind, ttl_seconds=900)
    with pytest.raises(ContractError):
        store(Clock()).mint(
            grant=AuthorityGrant(authority, source, "1.0.0", subject_operator_id, "why"),
            operator=subject,
            action_id="ACT-0003",
            ttl_seconds=ttl,
        )


def test_mint_refuses_a_spec_the_catalog_does_not_own() -> None:
    """Identity, not equality: a structurally-equal forged spec is not a capability."""

    class ForgedSpec:
        operator_id = "SUSPEND_PROCESS"
        operator_class = OperatorClass.O3_SUSPEND
        reversibility = Reversibility.FULLY_REVERSIBLE
        rollback_operator_id = "RESUME_PROCESS"
        max_duration_seconds = 900

    class ForgedOperator:
        def __init__(self) -> None:
            self.spec = ForgedSpec()
            self.target = ProcessTarget(
                identity=identity(), scope=TargetScope(kind=TargetKind.PROCESS, subject="app")
            )
            self.incident_id = "INC-0004"
            self.ttl_seconds = 60

    with pytest.raises(ContractError, match="CATALOG"):
        store(Clock()).mint(
            grant=grant(), operator=ForgedOperator(), action_id="ACT-0004", ttl_seconds=60
        )


def test_a_human_grant_mints_what_policy_cannot() -> None:
    """The refusal must be of the *source*, not of the operator."""
    subject = operator("TERMINATE_PROCESS", ttl_seconds=60)
    token = store(Clock()).mint(
        grant=grant("TERMINATE_PROCESS", authority=AuthorityClass.A5, source=GrantSource.HUMAN),
        operator=subject,
        action_id="ACT-0005",
        ttl_seconds=60,
    )
    assert token.authority is AuthorityClass.A5
    assert token.rollback_required is False, "TERMINATE_PROCESS has no rollback operator"


def test_a_redeemed_token_is_single_use() -> None:
    clock = Clock()
    keeper = store(clock)
    subject = operator()
    token = keeper.mint(grant=grant(), operator=subject, action_id="ACT-0006", ttl_seconds=60)
    assert keeper.redeem(token, operator=subject) is TokenVerdict.VALID
    assert keeper.redeem(token, operator=subject) is TokenVerdict.REPLAYED
    assert keeper.spent_count() == 1


def test_redeem_refuses_a_tampered_token() -> None:
    clock = Clock()
    keeper = store(clock)
    subject = operator()
    token = keeper.mint(grant=grant(), operator=subject, action_id="ACT-0007", ttl_seconds=60)

    lifted = replace(token, authority=AuthorityClass.A5)
    assert keeper.redeem(lifted, operator=subject) is TokenVerdict.BAD_MAC

    foreign = replace(token, signer="somebody-else")
    assert keeper.redeem(foreign, operator=subject) is TokenVerdict.UNKNOWN_SIGNER
    assert keeper.spent_count() == 0, "a refused token must not consume its nonce"


def test_redeem_refuses_outside_the_validity_window() -> None:
    """Expiry is checked against a clock that does not advance on its own."""
    clock = Clock()
    keeper = store(clock)
    subject = operator()
    token = keeper.mint(grant=grant(), operator=subject, action_id="ACT-0008", ttl_seconds=60)

    clock.advance(60)
    assert keeper.redeem(token, operator=subject) is TokenVerdict.EXPIRED

    early = Clock(at=token.valid_from - 1)
    assert store(early).redeem(token, operator=subject) is TokenVerdict.NOT_YET_VALID


def test_redeem_refuses_a_token_minted_for_another_target_or_operator() -> None:
    """A pid is not an identity: the same pid at a different start time is a new process."""
    clock = Clock()
    keeper = store(clock)
    subject = operator()
    token = keeper.mint(grant=grant(), operator=subject, action_id="ACT-0009", ttl_seconds=60)

    reused_pid = operator(start=99_001)
    assert token.target_digest != reused_pid.target.identity.digest()
    assert keeper.redeem(token, operator=reused_pid) is TokenVerdict.SCOPE_MISMATCH

    other_operator = operator("RESUME_PROCESS")
    assert keeper.redeem(token, operator=other_operator) is TokenVerdict.SCOPE_MISMATCH
    assert keeper.spent_count() == 0


def test_an_evicted_nonce_is_a_refusal_and_never_a_pass() -> None:
    """The honest answer to "was this replayed?" is sometimes "I can no longer tell".

    With the spent set bounded, a token old enough to have been forgotten returns
    ``NONCE_EVICTED``. Treating it as ``VALID`` would be an unbounded replay
    window dressed as a bounded one.
    """
    clock = Clock()
    keeper = store(clock, capacity=4)
    subject = operator()
    old = [
        keeper.mint(grant=grant(), operator=subject, action_id=f"ACT-01{index}", ttl_seconds=600)
        for index in range(5)
    ]
    for token in old:
        assert keeper.redeem(token, operator=subject) is TokenVerdict.VALID
    assert keeper.spent_count() == 4, "the spent set is bounded by construction"
    assert keeper.evictions() == 1

    clock.advance(1)
    forgotten = keeper.mint(
        grant=grant(), operator=subject, action_id="ACT-0199", ttl_seconds=600
    )
    assert keeper.redeem(forgotten, operator=subject) is TokenVerdict.VALID
    replayed_after_eviction = old[0]
    assert keeper.redeem(replayed_after_eviction, operator=subject) is TokenVerdict.NONCE_EVICTED
    assert TokenVerdict.NONCE_EVICTED in REFUSAL_VERDICTS


def test_only_valid_is_not_a_refusal() -> None:
    assert frozenset(set(TokenVerdict) - {TokenVerdict.VALID}) == REFUSAL_VERDICTS


ILL_FORMED_TOKEN_FIELDS = (
    ("a short nonce", {"nonce": "abc"}),
    ("an upper-case nonce", {"nonce": "A" * 32}),
    ("a non-digest target", {"target_digest": "pid:4011"}),
    ("AX authority", {"authority": AuthorityClass.AX}),
    ("an expiry before its start", {"expiry": 10, "valid_from": 20}),
    ("a lifetime over the ceiling", {"expiry": 1_000 + MAX_TOKEN_LIFETIME_SECONDS + 1}),
    ("no mac", {"mac": ""}),
)


@pytest.mark.parametrize(
    ("label", "override"), ILL_FORMED_TOKEN_FIELDS, ids=[c[0] for c in ILL_FORMED_TOKEN_FIELDS]
)
def test_an_ill_formed_token_is_unconstructible(label: str, override: dict[str, Any]) -> None:
    payload: dict[str, Any] = {
        "action_id": "ACT-0200",
        "incident_id": "INC-0001",
        "operator_id": "SUSPEND_PROCESS",
        "target_digest": identity().digest(),
        # Schema v2's two required fields (F1 / S5-SEC-04). Without them every row below
        # raised TypeError for the missing argument, not ContractError for the ill-formed
        # field it names, so the parametrisation tested nothing it was labelled with.
        "binding_digest": identity().digest(),
        "granted_by": GrantSource.POLICY,
        "authority": AuthorityClass.A2,
        "valid_from": 1_000,
        "expiry": 1_060,
        "max_duration_seconds": 900,
        "rollback_required": True,
        "policy_version": "1.0.0",
        "nonce": "0" * 32,
        "signer": "stage5-policy",
        "mac": "deadbeef",
    }
    payload.update(override)
    with pytest.raises(ContractError):
        CapabilityToken(**payload)


def test_the_token_store_refuses_a_weak_key_or_an_over_large_nonce_bound() -> None:
    with pytest.raises(ContractError):
        TokenStore(key=b"short", signer="s", clock=Clock())
    with pytest.raises(ContractError):
        TokenStore(key=TEST_KEY, signer="s", clock=Clock(), max_spent_nonces=MAX_SPENT_NONCES + 1)
    with pytest.raises(ContractError):
        TokenStore(key=TEST_KEY, signer="s", clock=Clock(), max_spent_nonces=0)


def test_the_mac_covers_every_authenticated_field() -> None:
    """``canonical_bytes`` excludes only ``mac``; everything else is authenticated."""
    token = store(Clock()).mint(
        grant=grant(), operator=operator(), action_id="ACT-0201", ttl_seconds=60
    )
    signed = set(token.to_dict()) - {"mac"}
    covered = set(json.loads(token.canonical_bytes().decode("utf-8")))
    assert signed == covered


# --- D5.23: the resource governor -------------------------------------------


def test_the_budget_holds_the_spec_constants() -> None:
    assert ResourceBudget() == STAGE5_BUDGET
    assert (STAGE5_BUDGET.max_candidate_actions, STAGE5_BUDGET.max_worlds_per_action) == (16, 8)
    assert (STAGE5_BUDGET.max_cone_depth, STAGE5_BUDGET.max_cone_branches_per_node) == (3, 4)
    assert STAGE5_BUDGET.max_dependency_nodes == 64
    assert STAGE5_BUDGET.max_twin_nodes == 64
    assert STAGE5_BUDGET.max_work_units == 4096
    assert STAGE5_BUDGET.max_concurrent_leases == 4
    assert STAGE5_BUDGET.max_rollback_journal_bytes == 262144
    assert STAGE5_BUDGET.max_autonomous_actions_per_window == 8
    assert STAGE5_BUDGET.window_seconds == 3600


def test_a_zero_cap_is_refused() -> None:
    """A cap of zero would disable planning, which is not what a bound is for."""
    with pytest.raises(ContractError):
        ResourceBudget(max_candidate_actions=0)
    with pytest.raises(ContractError):
        ResourceBudget(max_work_units=-1)


def test_spending_past_the_work_unit_budget_raises_and_records_nothing() -> None:
    governor = ResourceGovernor(ResourceBudget(max_work_units=10))
    governor.spend(WorkKind.SENTINEL_CHECK, 7)
    assert governor.remaining() == 3
    assert governor.would_exceed(WorkKind.SENTINEL_CHECK, 4)
    with pytest.raises(BudgetExhausted):
        governor.spend(WorkKind.SENTINEL_CHECK, 4)
    assert governor.remaining() == 3, "a refused spend must not be recorded"
    assert governor.escalation() is not None


def test_a_per_kind_cap_binds_before_the_total_budget() -> None:
    governor = ResourceGovernor()
    for _ in range(STAGE5_BUDGET.max_candidate_actions):
        governor.spend(WorkKind.CANDIDATE_GENERATION)
    with pytest.raises(BudgetExhausted, match="max_candidate_actions"):
        governor.spend(WorkKind.CANDIDATE_GENERATION)
    governor.spend(WorkKind.SENTINEL_CHECK)
    assert governor.spend_report()["SENTINEL_CHECK"] == 1, "an unrelated kind still has budget"
    assert set(KIND_CAPS) <= set(WorkKind)


def test_an_unknown_work_kind_is_refused() -> None:
    with pytest.raises(ContractError):
        ResourceGovernor().spend("CANDIDATE_GENERATION", 1)  # type: ignore[arg-type]


def test_the_spend_report_is_read_only_and_totals() -> None:
    governor = ResourceGovernor()
    governor.spend(WorkKind.CONE_NODE, 5)
    report = governor.spend_report()
    assert report["CONE_NODE"] == 5 and report["TOTAL"] == 5
    assert report["REMAINING"] == STAGE5_BUDGET.max_work_units - 5
    with pytest.raises(TypeError):
        report["CONE_NODE"] = 0  # type: ignore[index]


class Shadow:
    def __init__(self, score: float) -> None:
        self.score = score


class Candidate:
    """The ``CandidateAction`` slice the governor prunes on, per its Protocol."""

    def __init__(
        self,
        candidate_id: str,
        *,
        authority: AuthorityClass = AuthorityClass.A2,
        reversibility: Reversibility = Reversibility.FULLY_REVERSIBLE,
        shadow: float = 0.1,
    ) -> None:
        self.candidate_id = candidate_id
        self.authority = authority
        self.reversibility = reversibility
        self.shadow = Shadow(shadow)


def a_field(count: int) -> list[Candidate]:
    """One observe-only candidate, one NO_ACTION and ``count`` interventions."""
    field = [
        Candidate("OBSERVE", authority=AuthorityClass.A0, shadow=0.9),
        Candidate("NO_ACTION", authority=AuthorityClass.A2, shadow=1.0),
    ]
    field += [
        Candidate(
            f"ACT-{index:03d}",
            reversibility=(
                Reversibility.IRREVERSIBLE if index % 2 else Reversibility.FULLY_REVERSIBLE
            ),
            shadow=index / 100,
        )
        for index in range(count)
    ]
    return field


def test_prune_never_drops_the_observe_only_candidate() -> None:
    """**This is the test that fails if pruning stops being safety-monotone.**

    §2's eighth law says NO ACTION must always be available. The observe-only
    candidate is given the *worst* shadow in this field on purpose: if pruning
    ranked purely by score it would be the first thing dropped, and an adversary
    who can make planning expensive could thereby make it decisive.
    """
    governor = ResourceGovernor()
    kept, records = governor.prune(a_field(40))
    kept_ids = {candidate.candidate_id for candidate in kept}
    assert "OBSERVE" in kept_ids
    assert "NO_ACTION" in kept_ids
    assert kept_ids >= PROTECTED_CANDIDATE_IDS
    assert len(kept) == STAGE5_BUDGET.max_candidate_actions
    assert len(records) == 42 - STAGE5_BUDGET.max_candidate_actions
    assert all(isinstance(record, PruneRecord) for record in records)
    assert all(record.what == "candidate" and record.reason for record in records)


def test_prune_drops_the_most_irreversible_and_most_shadowed_first() -> None:
    governor = ResourceGovernor(ResourceBudget(max_candidate_actions=4))
    field = [
        Candidate("SAFE-LOW", shadow=0.1),
        Candidate("SAFE-HIGH", shadow=0.8),
        Candidate("HARD-LOW", reversibility=Reversibility.IRREVERSIBLE, shadow=0.1),
        Candidate("HARD-HIGH", reversibility=Reversibility.IRREVERSIBLE, shadow=0.8),
    ]
    kept, records = governor.prune(field[:2] + [Candidate("EXTRA", shadow=0.2)] + field[2:])
    dropped = [record.identifier for record in records]
    assert dropped == ["HARD-HIGH"], dropped
    assert {candidate.candidate_id for candidate in kept} == {
        "SAFE-LOW",
        "SAFE-HIGH",
        "EXTRA",
        "HARD-LOW",
    }


def test_prune_is_deterministic_under_reordering() -> None:
    """Same input, same output: a bound that depends on arrival order is a coin toss."""
    field = a_field(30)
    first, first_records = ResourceGovernor().prune(field)
    shuffled = list(reversed(field))
    second, second_records = ResourceGovernor().prune(shuffled)
    assert sorted(c.candidate_id for c in first) == sorted(c.candidate_id for c in second)
    assert sorted(r.identifier for r in first_records) == sorted(
        r.identifier for r in second_records
    )


def test_prune_keeps_every_protected_candidate_even_over_the_cap() -> None:
    """Dropping the only safe option to satisfy a number is the wrong trade."""
    governor = ResourceGovernor(ResourceBudget(max_candidate_actions=2))
    field = [Candidate(f"OBS-{index}", authority=AuthorityClass.A0) for index in range(5)]
    kept, records = governor.prune(field)
    assert len(kept) == 5
    assert records == ()
    assert governor.escalation() is not None


def test_prune_refuses_duplicate_candidate_ids() -> None:
    with pytest.raises(ContractError):
        ResourceGovernor().prune([Candidate("A"), Candidate("A")])


def test_the_rate_limit_counts_only_the_trailing_window() -> None:
    governor = ResourceGovernor()
    now = 10_000
    inside = [now - index for index in range(STAGE5_BUDGET.max_autonomous_actions_per_window)]
    assert governor.rate_limited(recent_action_times=inside, now=now)
    old = [now - STAGE5_BUDGET.window_seconds - index for index in range(20)]
    assert not ResourceGovernor().rate_limited(recent_action_times=old, now=now)


def test_a_clock_that_runs_backwards_cannot_clear_the_rate_limit() -> None:
    with pytest.raises(ContractError):
        ResourceGovernor().rate_limited(recent_action_times=[10_001], now=10_000)


def test_escalation_is_none_until_something_is_actually_exhausted() -> None:
    """``None`` means nothing was exhausted, not "proceed"."""
    governor = ResourceGovernor()
    assert governor.escalation() is None
    governor.spend(WorkKind.HOST_CALL, 1)
    assert governor.escalation() is None


# --- core_ids ----------------------------------------------------------------


def test_the_core_id_table_is_the_twenty_four_architecture_functions() -> None:
    assert len(CORE_IDS) == 24
    assert [entry.core_id for entry in CORE_IDS.values()] == [
        f"SAFE-F{index:02d}" for index in range(1, 25)
    ]
    assert [entry.architecture_id for entry in CORE_IDS.values()] == [
        f"S5-F{index:02d}" for index in range(1, 25)
    ]
    assert core_function("SAFE-F11").name == "sentinel_verify"
    with pytest.raises(KeyError):
        core_function("SAFE-F99")


def test_every_optional_core_id_names_a_planner_flag() -> None:
    """G5.14 joins ``AblationRow.core_id`` to this table, so the join must be total.

    The spec's §core_ids prose says "Ten OPTIONAL ids" while its own table marks
    **eleven** rows OPTIONAL (F04-F08, F16, F18, F20-F23). The table is
    implemented, and the prose's ten is the count of *distinct flags* — F21 and
    F22 share ``enable_response_cells``. Both numbers are asserted here so the
    discrepancy cannot be read as a defect in either direction.
    """
    entries = list(CORE_IDS.values())
    optional = [e for e in entries if e.function_class is FunctionClass.OPTIONAL]
    required = [e for e in entries if e.function_class is FunctionClass.REQUIRED]
    assert len(optional) == 11
    assert len(required) == 13
    assert len(set(ABLATION_FLAGS.values())) == 10
    assert set(ABLATION_FLAGS) == set(OPTIONAL_IDS)
    assert all(entry.ablation_flag for entry in optional)
    assert not any(entry.ablation_flag for entry in required)
    assert set(REQUIRED_IDS) & set(OPTIONAL_IDS) == set()
    assert ABLATION_FLAGS["SAFE-F21"] == ABLATION_FLAGS["SAFE-F22"] == "enable_response_cells"


def test_a_core_function_with_an_inconsistent_ablation_flag_is_refused() -> None:
    """An optional mechanism with no off switch cannot be ablated; the reverse is a trap."""
    with pytest.raises(ContractError):
        CoreFunction("X", "Y", "n", "p", FunctionClass.REQUIRED, "D5.1", "enable_something")
    with pytest.raises(ContractError):
        CoreFunction("X", "Y", "n", "p", FunctionClass.OPTIONAL, "D5.1", "")


def test_pinned_upstream_schemas_match_the_live_registry() -> None:
    """**G5.1's join, and the test that fails if an upstream contract moves.**

    The five modules are imported first so their ``register_schema`` calls have
    run: a pin that only compared against an empty registry would pass for the
    wrong reason. Both key spaces are asserted identical, then the versions.
    """
    import pocketsec.stage0.contracts.security_event_v1
    import pocketsec.stage0.contracts.threat_prediction_v1
    import pocketsec.stage1.ssir.transition
    import pocketsec.stage3.cells.schema
    import pocketsec.stage4.stage5_interface  # noqa: F401

    assert len(PINNED_UPSTREAM_SCHEMAS) == 5
    assert set(PINNED_UPSTREAM_SCHEMAS) <= set(SCHEMA_REGISTRY), (
        "a pinned schema id that is not in the registry is a typo, not a pin"
    )
    for schema_id, version in PINNED_UPSTREAM_SCHEMAS.items():
        assert SCHEMA_REGISTRY[schema_id] == version, schema_id


def test_stage5_registers_its_own_three_foundation_schema_ids() -> None:
    for schema_id in (
        "pocketsec.response_constitution.v1",
        "pocketsec.capability_token.v1",
        "pocketsec.safe_interface.v1",
    ):
        assert SCHEMA_REGISTRY[schema_id] == "1.0.0"


def test_the_foundation_modules_stay_inside_the_file_size_convention() -> None:
    """Spec §2.3: files under ~800 lines. Cheap to check, easy to let slide."""
    owned = (
        "core_ids.py",
        "governor.py",
        "constitution/invariants.py",
        "constitution/schema.py",
        "authority/capability.py",
        "authority/tokens.py",
    )
    root = REPO_ROOT / "pocketsec" / "stage5"
    oversized = {
        name: len((root / name).read_text(encoding="utf-8").splitlines())
        for name in owned
        if len((root / name).read_text(encoding="utf-8").splitlines()) > 800
    }
    assert not oversized, oversized
    assert all((root / Path(name)).is_file() for name in owned)


def test_a_redemption_burst_inside_one_second_fails_closed_after_eviction() -> None:
    """The coarse-clock consequence of the nonce bound, pinned as intended behaviour.

    The horizon is a ``valid_from`` and the clock is whole seconds, so once one
    nonce has been forgotten every token minted in that same second is refused —
    a freshly minted one included. That is fail-closed, and it is pinned here so
    nobody "fixes" it by widening the replay window: the only way to redeem more
    than ``max_spent_nonces`` tokens per second is a burst the governor's rate
    limit already says is not a legitimate workload.
    """
    clock = Clock()
    keeper = store(clock, capacity=2)
    subject = operator()
    verdicts = []
    for index in range(5):
        token = keeper.mint(
            grant=grant(), operator=subject, action_id=f"ACT-03{index}", ttl_seconds=600
        )
        verdicts.append(keeper.redeem(token, operator=subject))
    assert verdicts[:3] == [TokenVerdict.VALID] * 3
    assert verdicts[3:] == [TokenVerdict.NONCE_EVICTED] * 2
    assert keeper.evictions() == 1
    assert keeper.spent_count() == 2

    clock.advance(1)
    fresh = keeper.mint(grant=grant(), operator=subject, action_id="ACT-0399", ttl_seconds=600)
    assert keeper.redeem(fresh, operator=subject) is TokenVerdict.VALID


def test_the_candidate_protocol_matches_the_real_action_field() -> None:
    """Spec §4.9 rule A for the governor's structural view of a candidate.

    ``prune()`` reads candidates through a Protocol, which is invisible at
    runtime: if ``safe/action_field.py`` renamed ``shadow`` or ``reversibility``,
    pruning would raise ``AttributeError`` at the worst possible moment rather than
    fail a test. This joins the Protocol's member names to the real dataclass's.
    """
    from pocketsec.stage5.aegis.shadow import ActionShadow
    from pocketsec.stage5.safe.action_field import CandidateAction

    candidate_fields = {field.name for field in dataclass_fields(CandidateAction)}
    assert {"candidate_id", "authority", "reversibility", "shadow"} <= candidate_fields
    assert "score" in {field.name for field in dataclass_fields(ActionShadow)}
    assert {member.value for member in Reversibility} == set(REVERSIBILITY_ORDER)
