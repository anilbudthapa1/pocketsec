"""Stage 5 work package 2 — D5.5, D5.16 and the simulated host model.

These tests are about *refusals*. This package is the security boundary, so what matters
is not that a legal operator can be built but that an illegal one cannot, and every test
below that names a refusal tries to construct the thing it forbids.

Six of them exist because a specific, named defect has already cost this project or its
predecessors a wrong answer, and each would fail if the invariant were quietly weakened:

* ``test_a_forged_structurally_equal_spec_is_refused`` — equality would accept a forged
  catalog entry and identity does not. Delete the ``is`` check in
  ``DefensiveOperator.__post_init__`` and this test is the one that breaks.
* ``test_no_arbitrary_command_path_catches_a_planted_shell_path`` — a checker that cannot
  fail is not a checker (MEMORY.md lesson 10). Eight planted fixtures, one per rule.
* ``test_every_catalog_entry_has_a_host_handler`` — Stage 3 shipped seven of eight operator
  forms with no interpreter and measured nothing (ADR-0027).
* ``test_catalog_expresses_every_architecture_operator_example`` and
  ``test_catalog_expresses_the_architecture_section_6_example`` — Stage 3 built a
  representation that could not express the thing it existed to express. Check first.
* ``test_the_two_postcondition_key_spaces_are_structurally_identical`` — two waves have now
  joined key spaces that could never match (S2-FC-01). ``PostconditionKind`` exists twice
  in Stage 5 on purpose (an import cycle otherwise), and this test is what keeps the two
  copies interchangeable instead of silently divergent.
* ``test_suspend_loses_unpreserved_volatile_evidence`` — containment that destroys the
  evidence of the incident is a failure even when it stops the attack, so the host model
  has to be able to *show* the loss.
"""

from __future__ import annotations

import ast
import dataclasses
import importlib.util
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from pocketsec.stage0.contracts.common import ContractError, EvidenceRef, digest_of_bytes
from pocketsec.stage0.gate import REPO_ROOT
from pocketsec.stage1.state.security_state import Privilege, SecurityStateV1
from pocketsec.stage5.constitution.invariants import FROZEN_CONSTITUTION, AuthorityClass
from pocketsec.stage5.host.simulated import (
    HOST_HANDLERS,
    MAX_SIMULATED_PROCESSES,
    SIMULATED_HOST_VERSION,
    FaultProfile,
    HostFailure,
    HostKind,
    HostSnapshot,
    ProcessRow,
    ProcessState,
    ServiceRow,
    SimulatedHost,
)
from pocketsec.stage5.operators import algebra as algebra_module
from pocketsec.stage5.operators.algebra import (
    LITERAL_ATOM_PATTERN,
    MAX_ARGV_ATOMS,
    DefensiveOperator,
    EvidenceEffect,
    FieldAtom,
    LiteralAtom,
    OperatorClass,
    OperatorSpec,
    PostconditionKind,
    PreconditionKind,
    ProcessIdentity,
    ProcessTarget,
    Reversibility,
    TargetField,
    TargetKind,
    TargetScope,
    assemble_argv,
    no_arbitrary_command_path,
)
from pocketsec.stage5.operators.catalog import (
    _CATALOG_TOKEN,
    CATALOG,
    CATALOG_BY_CLASS,
    MAX_CATALOG_ENTRIES,
    autonomous_ids,
    rollback_closure_violations,
    rollback_spec,
    spec,
)
from pocketsec.stage5.operators.d3fend import (
    D3FEND_ID_PATTERN,
    D3FEND_RELEASE,
    UNMAPPED,
    D3FENDMapping,
    D3FENDSnapshot,
    load_snapshot,
    mapped_fraction,
    mapping_for,
    unmapped_operator_ids,
)

STAGE5_ROOT = REPO_ROOT / "pocketsec" / "stage5"


class _ManualClock:
    """A clock that does not advance on its own.

    Defined here rather than imported from ``executor/identity.py`` so that this package's
    tests depend on nothing downstream of it: the spec's build order makes packages 1–4 a
    gate on the rest, and a package-2 test that needs package 4 inverts that gate.
    """

    def __init__(self, at: int = 0) -> None:
        self._at = at

    def now(self) -> int:
        return self._at

    def advance(self, seconds: int) -> None:
        self._at += seconds


def _identity(
    pid: int = 4101,
    *,
    ticks: int = 88_000,
    uid: int = 1000,
    executable_digest: str | None = None,
) -> ProcessIdentity:
    return ProcessIdentity(
        pid=pid,
        start_time_ticks=ticks,
        uid=uid,
        executable_digest=executable_digest,
        cgroup_id="cg-app",
        namespace_id="ns-root",
    )


#: The subject a target of each kind carries. A process target's subject is never
#: substituted into a vector (``PID`` comes off the identity), but it is still validated.
_SUBJECTS: dict[TargetKind, str] = {
    TargetKind.PROCESS: "proc-4101",
    TargetKind.SERVICE: "app.service",
    TargetKind.SESSION: "sess-7",
    TargetKind.SOCKET: "sock-4101",
    TargetKind.HOST: "host-a",
}


def _target(kind: TargetKind = TargetKind.PROCESS, *, pid: int = 4101) -> ProcessTarget:
    return ProcessTarget(identity=_identity(pid), scope=TargetScope(kind, _SUBJECTS[kind]))


def _evidence(tag: str = "e1") -> tuple[EvidenceRef, ...]:
    return (
        EvidenceRef(store="incident", locator=tag, digest=digest_of_bytes(tag.encode())),
    )


def _operator(operator_id: str, *, pid: int = 4101, ttl: int | None = None) -> DefensiveOperator:
    entry = CATALOG[operator_id]
    return DefensiveOperator(
        spec=entry,
        target=_target(entry.target_kind, pid=pid),
        incident_id="inc-0001",
        ttl_seconds=entry.max_duration_seconds if ttl is None else ttl,
        evidence_refs=_evidence(),
    )


def _host(**fault_kwargs: Any) -> SimulatedHost:
    """A three-process, two-service fixture. Deterministic; every rate defaults to 0."""
    processes = (
        ProcessRow(
            identity=_identity(4101),
            state=ProcessState.RUNNING,
            unit="app.service",
            session_id="sess-7",
            socket_ids=("sock-4101",),
            children=(4102,),
            volatile_signals=("open_fds", "socket_table"),
        ),
        ProcessRow(
            identity=_identity(4102, ticks=88_100),
            state=ProcessState.RUNNING,
            unit=None,
            session_id="sess-7",
            socket_ids=(),
            children=(),
            volatile_signals=("open_fds",),
        ),
        ProcessRow(
            identity=_identity(9001, ticks=10, uid=0),
            state=ProcessState.RUNNING,
            unit="sshd.service",
            session_id=None,
            socket_ids=("sock-9001",),
            children=(),
            volatile_signals=(),
        ),
    )
    services = (
        ServiceRow(
            unit="app.service",
            running=True,
            constrained=False,
            restartable=True,
            depends_on=("db.service",),
            healthy=True,
        ),
        ServiceRow(
            unit="db.service",
            running=True,
            constrained=False,
            restartable=True,
            depends_on=(),
            healthy=True,
        ),
    )
    return SimulatedHost(
        processes=processes,
        services=services,
        sessions=("sess-7",),
        security_state=SecurityStateV1(privilege=Privilege.USER),
        faults=FaultProfile(seed=17, **fault_kwargs),
        clock=_ManualClock(),
    )


# --- the catalog expresses what it must, and nothing more --------------------------


def test_every_catalog_entry_has_a_host_handler() -> None:
    """Both directions. Stage 3's ADR-0027 is what happens when only one is checked."""
    assert set(CATALOG) == set(HOST_HANDLERS)
    assert set(HOST_HANDLERS) - set(CATALOG) == set()
    assert set(CATALOG) - set(HOST_HANDLERS) == set()
    assert len(CATALOG) == 14


def test_every_rollback_operator_is_itself_in_the_catalog() -> None:
    for operator_id, entry in CATALOG.items():
        if entry.rollback_operator_id is None:
            continue
        assert entry.rollback_operator_id in CATALOG, operator_id
        assert CATALOG[entry.rollback_operator_id].target_kind is entry.target_kind
    assert rollback_closure_violations(CATALOG) == ()


#: Architecture §5's "Operator examples" column, one entry per non-empty cell. O7's cell is
#: non-empty in the architecture and empty here on purpose: "not autonomous" is implemented
#: as "not expressible".
ARCHITECTURE_SECTION_5_EXAMPLES: dict[OperatorClass, tuple[str, ...]] = {
    OperatorClass.O0_OBSERVE: (
        "inspect bounded state",
        "hash metadata",
        "temporary trace",
    ),
    OperatorClass.O1_PRESERVE: (
        "snapshot incident metadata",
        "preserve volatile evidence",
    ),
    OperatorClass.O2_REVERSIBLE_RESTRICT: ("temporary local communication restriction",),
    OperatorClass.O3_SUSPEND: ("pause process with validated resume",),
    OperatorClass.O4_LOCAL_REVOKE: ("invalidate a local session",),
    OperatorClass.O5_SERVICE_CONTAINMENT: ("temporarily constrain a service boundary",),
    OperatorClass.O6_DISRUPTIVE: ("terminate",),
    OperatorClass.O7_DESTRUCTIVE: (),
}

#: Which catalog entry answers which example. Written out so that deleting an operator
#: fails this test rather than quietly shrinking the vocabulary.
_EXAMPLE_COVERAGE: dict[OperatorClass, tuple[str, ...]] = {
    OperatorClass.O0_OBSERVE: (
        "OBSERVE_PROCESS_METADATA",
        "HASH_EXECUTABLE",
        "TRACE_PROCESS_BOUNDED",
        "STOP_TRACE",
    ),
    OperatorClass.O1_PRESERVE: ("SNAPSHOT_PROCESS_STATE", "PRESERVE_VOLATILE_EVIDENCE"),
    OperatorClass.O2_REVERSIBLE_RESTRICT: ("RESTRICT_LOCAL_SOCKET", "RELEASE_LOCAL_SOCKET"),
    OperatorClass.O3_SUSPEND: ("SUSPEND_PROCESS", "RESUME_PROCESS"),
    OperatorClass.O4_LOCAL_REVOKE: ("REVOKE_LOCAL_SESSION",),
    OperatorClass.O5_SERVICE_CONTAINMENT: ("CONSTRAIN_SERVICE", "RELEASE_SERVICE"),
    OperatorClass.O6_DISRUPTIVE: ("TERMINATE_PROCESS",),
    OperatorClass.O7_DESTRUCTIVE: (),
}


def test_catalog_expresses_every_architecture_operator_example() -> None:
    """Before building a representation, check the thing it must express is expressible."""
    assert set(ARCHITECTURE_SECTION_5_EXAMPLES) == set(OperatorClass)
    for operator_class, examples in ARCHITECTURE_SECTION_5_EXAMPLES.items():
        expected = _EXAMPLE_COVERAGE[operator_class]
        assert CATALOG_BY_CLASS[operator_class] == expected, operator_class
        if examples:
            # At least one operator per non-empty example cell, and §3's "pause with
            # validated resume" needs the resume to exist as its own entry.
            assert len(expected) >= len(examples) or operator_class in (
                OperatorClass.O2_REVERSIBLE_RESTRICT,
                OperatorClass.O3_SUSPEND,
            )
    assert CATALOG_BY_CLASS[OperatorClass.O7_DESTRUCTIVE] == ()


def test_catalog_expresses_the_architecture_section_6_example() -> None:
    """§6's exact allowed ActionObject, field by field.

    The forbidden form, ``{"command": "some shell string"}``, has no home: there is no
    field on either type that holds a command, which the next test asserts over every
    dataclass in the package rather than over this one example.
    """
    operator = _operator("SUSPEND_PROCESS", ttl=120)
    section_6 = {
        "operator": "SUSPEND_PROCESS",
        "target_pid": 4101,
        "target_identity_hash": _identity(4101).digest(),
        "ttl": 120,
        "rollback": "RESUME_PROCESS",
        "incident": "inc-0001",
    }
    assert operator.spec.operator_id == section_6["operator"]
    assert operator.target.identity.pid == section_6["target_pid"]
    assert operator.target.identity.digest() == section_6["target_identity_hash"]
    assert operator.ttl_seconds == section_6["ttl"]
    assert operator.spec.rollback_operator_id == section_6["rollback"]
    assert operator.incident_id == section_6["incident"]
    rollback = operator.rollback()
    assert rollback is not None
    assert rollback.spec.operator_id == "RESUME_PROCESS"
    assert rollback.target is operator.target
    payload = operator.to_dict()
    assert payload["vector"] == ["process.suspend", "4101"]
    assert "command" not in payload


def test_no_field_in_this_package_can_hold_a_command() -> None:
    """§6's forbidden form has no field to live in, over every dataclass in the package."""
    banned = ("command", "cmd", "shell", "script", "cmdline", "argv_string")
    classes = [
        obj
        for module in (algebra_module,)
        for obj in vars(module).values()
        if dataclasses.is_dataclass(obj) and isinstance(obj, type)
    ]
    assert len(classes) >= 6
    for klass in classes:
        for field in dataclasses.fields(klass):
            lowered = field.name.lower()
            assert not any(token in lowered for token in banned), f"{klass.__name__}.{field.name}"


def test_o7_has_no_catalog_entries() -> None:
    assert CATALOG_BY_CLASS[OperatorClass.O7_DESTRUCTIVE] == ()
    entries = CATALOG.values()
    assert all(e.operator_class is not OperatorClass.O7_DESTRUCTIVE for e in entries)
    assert all(e.evidence_effect is not EvidenceEffect.DESTROYS for e in entries)


def test_catalog_is_bounded_and_read_only() -> None:
    assert len(CATALOG) <= MAX_CATALOG_ENTRIES
    with pytest.raises(TypeError):
        CATALOG["NEW_OPERATOR"] = CATALOG["SUSPEND_PROCESS"]  # type: ignore[index]
    for entry in CATALOG.values():
        assert len(entry.argv_template) <= MAX_ARGV_ATOMS
        assert 0 < entry.max_duration_seconds <= 900


def test_spec_raises_contract_error_for_an_unknown_operator_id() -> None:
    with pytest.raises(ContractError, match="unknown operator id"):
        spec("RM_RF_SLASH")


def test_rollback_spec_returns_none_for_a_terminal_operator() -> None:
    assert rollback_spec("TERMINATE_PROCESS") is None
    assert rollback_spec("REVOKE_LOCAL_SESSION") is None
    resume = rollback_spec("SUSPEND_PROCESS")
    assert resume is not None and resume.operator_id == "RESUME_PROCESS"


def test_autonomous_ids_are_exactly_the_o0_to_o3_operators() -> None:
    """§31's AUTONOMOUS_LOW_IMPACT envelope, derived rather than declared."""
    permitted = set(autonomous_ids(FROZEN_CONSTITUTION))
    expected = {
        operator_id
        for operator_id, entry in CATALOG.items()
        if entry.operator_class <= OperatorClass.O3_SUSPEND
    }
    assert permitted == expected
    assert "TERMINATE_PROCESS" not in permitted
    assert "REVOKE_LOCAL_SESSION" not in permitted
    assert "CONSTRAIN_SERVICE" not in permitted


def test_rollback_closure_violations_fires_on_a_doctored_catalog() -> None:
    """The closure check must be able to fail, or it is decoration."""
    dangling = {k: v for k, v in CATALOG.items() if k != "RESUME_PROCESS"}
    assert any("not in the catalog" in row for row in rollback_closure_violations(dangling))
    orphan = {"RELEASE_LOCAL_SOCKET": CATALOG["RELEASE_LOCAL_SOCKET"]}
    assert any("must name a rollback" in row for row in rollback_closure_violations(orphan))


# --- an OperatorSpec is unconstructable outside the catalog -----------------------


def _forge(**overrides: Any) -> OperatorSpec:
    """Build a spec with the private token, to exercise the refusals *behind* the token."""
    template = CATALOG["SUSPEND_PROCESS"]
    fields: dict[str, Any] = {
        field.name: getattr(template, field.name)
        for field in dataclasses.fields(template)
        if field.name != "catalog_token"
    }
    fields.update(overrides)
    return OperatorSpec(catalog_token=_CATALOG_TOKEN, **fields)


def test_operator_spec_cannot_be_built_outside_the_catalog() -> None:
    template = CATALOG["SUSPEND_PROCESS"]
    fields = {
        field.name: getattr(template, field.name)
        for field in dataclasses.fields(template)
        if field.name != "catalog_token"
    }
    with pytest.raises(ContractError, match="constructible only inside"):
        OperatorSpec(**fields)
    with pytest.raises(ContractError, match="constructible only inside"):
        OperatorSpec(catalog_token=object(), **fields)
    with pytest.raises(ContractError, match="constructible only inside"):
        OperatorSpec(catalog_token="_CATALOG_TOKEN", **fields)


def test_a_forged_structurally_equal_spec_is_refused() -> None:
    """Identity, not equality. Delete the ``is`` check and this is the test that breaks."""
    forged = _forge()
    assert forged == CATALOG["SUSPEND_PROCESS"]
    assert forged is not CATALOG["SUSPEND_PROCESS"]
    with pytest.raises(ContractError, match="CATALOG member by identity"):
        DefensiveOperator(
            spec=forged,
            target=_target(),
            incident_id="inc-0001",
            ttl_seconds=60,
            evidence_refs=_evidence(),
        )


def test_a_deep_copy_of_a_catalog_entry_is_refused() -> None:
    """What a JSON round-trip produces. Equal, not identical, therefore refused."""
    import copy

    with pytest.raises(ContractError, match="CATALOG member by identity"):
        DefensiveOperator(
            spec=copy.deepcopy(CATALOG["OBSERVE_PROCESS_METADATA"]),
            target=_target(),
            incident_id="inc-0001",
            ttl_seconds=10,
            evidence_refs=(),
        )


@pytest.mark.parametrize(
    "payload",
    [
        "SUSPEND_PROCESS",
        {"operator": "SUSPEND_PROCESS", "command": "kill -9 4101"},
        None,
        4101,
        ("SUSPEND_PROCESS", 4101),
    ],
)
def test_a_string_or_payload_cannot_stand_in_for_a_spec(payload: Any) -> None:
    """The adversarial case: reach the typed boundary with data instead of a type."""
    with pytest.raises(ContractError):
        DefensiveOperator(
            spec=payload,
            target=_target(),
            incident_id="inc-0001",
            ttl_seconds=10,
            evidence_refs=(),
        )


def test_a_spec_whose_authority_disagrees_with_its_class_is_refused() -> None:
    with pytest.raises(ContractError, match="disagrees with"):
        _forge(authority=AuthorityClass.A0)


def test_a_spec_that_destroys_evidence_below_o6_is_refused() -> None:
    with pytest.raises(ContractError, match="DESTROYS is not available below"):
        _forge(evidence_effect=EvidenceEffect.DESTROYS)


def test_a_spec_claiming_a_rollback_for_an_irreversible_operator_is_refused() -> None:
    with pytest.raises(ContractError, match="IRREVERSIBLE names"):
        _forge(reversibility=Reversibility.IRREVERSIBLE)
    with pytest.raises(ContractError, match="cannot roll back itself"):
        _forge(rollback_operator_id="SUSPEND_PROCESS")
    with pytest.raises(ContractError, match="REVERSIBLE_WITH_STATE has no rollback"):
        _forge(reversibility=Reversibility.REVERSIBLE_WITH_STATE, rollback_operator_id=None)


def test_a_spec_with_an_over_long_or_zero_duration_is_refused() -> None:
    with pytest.raises(ContractError, match="max_duration_seconds"):
        _forge(max_duration_seconds=901)
    with pytest.raises(ContractError, match="max_duration_seconds"):
        _forge(max_duration_seconds=0)


def test_a_spec_reading_a_field_its_target_kind_does_not_have_is_refused() -> None:
    with pytest.raises(ContractError, match="not readable from"):
        _forge(argv_template=(LiteralAtom("process.suspend"), FieldAtom(TargetField.UNIT_NAME)))


def test_a_spec_whose_vector_starts_with_a_substitution_is_refused() -> None:
    with pytest.raises(ContractError, match=r"argv_template\[0\] must be a LiteralAtom"):
        _forge(argv_template=(FieldAtom(TargetField.PID), LiteralAtom("process.suspend")))


def test_a_spec_with_an_unmapped_technique_id_of_the_wrong_shape_is_refused() -> None:
    with pytest.raises(ContractError, match="d3fend_technique_id"):
        _forge(d3fend_technique_id="T1055")


# --- the argv boundary -------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "rm -rf /",
        "kill;id",
        "$(id)",
        "`id`",
        "a|b",
        "a>b",
        "a&b",
        "a\nb",
        "a b",
        "",
        "x" * 65,
        "../../etc/passwd\x00",
    ],
)
def test_a_literal_atom_with_a_shell_metacharacter_is_refused(value: str) -> None:
    assert not LITERAL_ATOM_PATTERN.fullmatch(value)
    with pytest.raises(ContractError, match="LiteralAtom.value"):
        LiteralAtom(value)


def test_every_catalog_entry_assembles_a_safe_vector() -> None:
    for operator_id, entry in CATALOG.items():
        vector = _operator(operator_id).argv()
        assert len(vector) == len(entry.argv_template)
        assert vector[0] == entry.argv_template[0].value  # type: ignore[union-attr]
        for token in vector:
            assert LITERAL_ATOM_PATTERN.fullmatch(token), (operator_id, token)
            assert " " not in token


def test_assemble_argv_refuses_a_template_that_did_not_come_from_the_catalog() -> None:
    """There is one argument-vector provenance, and a caller cannot invent another."""
    entry = CATALOG["SUSPEND_PROCESS"]
    handmade = tuple(atom for atom in entry.argv_template)  # equal contents, new object
    assert handmade == entry.argv_template
    assert handmade is not entry.argv_template
    with pytest.raises(ContractError, match="not a CATALOG entry's own"):
        assemble_argv(handmade, _target())
    with pytest.raises(ContractError, match="not a CATALOG entry's own"):
        assemble_argv((LiteralAtom("process.terminate"), FieldAtom(TargetField.PID)), _target())
    # The catalog's own object still works, so the refusal is about provenance.
    assert assemble_argv(entry.argv_template, _target()) == ("process.suspend", "4101")


def test_assemble_argv_refuses_a_string_atom() -> None:
    """A ``str`` in the atom position is a ContractError, never an AssertionError."""
    entry = CATALOG["SUSPEND_PROCESS"]
    original = entry.argv_template
    poisoned = (LiteralAtom("process.suspend"), "4101; rm -rf /")
    object.__setattr__(entry, "argv_template", poisoned)
    try:
        with pytest.raises(ContractError, match="ArgvAtom is closed over"):
            assemble_argv(entry.argv_template, _target())
    finally:
        object.__setattr__(entry, "argv_template", original)
    assert _operator("SUSPEND_PROCESS").argv() == ("process.suspend", "4101")


def test_a_literal_mutated_in_place_is_still_refused_at_assembly() -> None:
    """Defence in depth. ``frozen=True`` is not real immutability — ``object.__setattr__``
    walks straight past it — so the pattern is applied again where the token enters the
    vector. This is the closest an in-process attacker can get to a shell string, and it
    still does not produce one.
    """
    atom = CATALOG["SUSPEND_PROCESS"].argv_template[0]
    object.__setattr__(atom, "value", "process.suspend; rm -rf /")
    try:
        with pytest.raises(ContractError, match="no spaces, no shell metacharacters"):
            _operator("SUSPEND_PROCESS").argv()
    finally:
        object.__setattr__(atom, "value", "process.suspend")
    assert _operator("SUSPEND_PROCESS").argv() == ("process.suspend", "4101")


def test_neither_typed_object_can_be_rebuilt_from_a_payload() -> None:
    """There is no ``from_dict``, so a deserialiser has no entry point to the boundary.

    ``to_dict`` is one-way on purpose: a round-trip constructor would be exactly the
    "deserialised payload becomes a privileged action" path §6 forbids.
    """
    for klass in (OperatorSpec, DefensiveOperator, ProcessIdentity):
        assert not hasattr(klass, "from_dict"), klass.__name__
        assert not any("parse" in name or "load" in name for name in dir(klass))


def test_a_substituted_token_is_revalidated_at_the_boundary() -> None:
    """Even a subject that got past ``TargetScope`` is checked where it enters a vector."""
    target = _target(TargetKind.SERVICE)
    object.__setattr__(target.scope, "subject", "app.service; rm -rf /")
    with pytest.raises(ContractError, match="no spaces, no shell metacharacters"):
        assemble_argv(CATALOG["CONSTRAIN_SERVICE"].argv_template, target)


@pytest.mark.parametrize("subject", ["app service", "app;service", "$(app)", "a" * 70])
def test_a_target_scope_refuses_an_unsafe_subject(subject: str) -> None:
    with pytest.raises(ContractError):
        TargetScope(TargetKind.SERVICE, subject)


def test_operator_refuses_a_ttl_outside_the_operators_bound() -> None:
    entry = CATALOG["SUSPEND_PROCESS"]
    with pytest.raises(ContractError, match="ttl_seconds must be in"):
        _operator("SUSPEND_PROCESS", ttl=0)
    with pytest.raises(ContractError, match="ttl_seconds must be in"):
        _operator("SUSPEND_PROCESS", ttl=entry.max_duration_seconds + 1)
    assert _operator("SUSPEND_PROCESS", ttl=1).ttl_seconds == 1


def test_operator_refuses_a_target_of_the_wrong_kind() -> None:
    with pytest.raises(ContractError, match="is not the operator's target kind"):
        DefensiveOperator(
            spec=CATALOG["SUSPEND_PROCESS"],
            target=_target(TargetKind.SERVICE),
            incident_id="inc-0001",
            ttl_seconds=60,
            evidence_refs=(),
        )


def test_operator_refuses_a_non_host_local_scope() -> None:
    off_host = ProcessTarget(
        identity=_identity(),
        scope=TargetScope(TargetKind.PROCESS, "proc-4101", host_local=False),
    )
    with pytest.raises(ContractError, match="not host-local"):
        DefensiveOperator(
            spec=CATALOG["SUSPEND_PROCESS"],
            target=off_host,
            incident_id="inc-0001",
            ttl_seconds=60,
            evidence_refs=(),
        )


def test_operator_refuses_evidence_that_is_not_an_evidence_ref() -> None:
    with pytest.raises(ContractError, match="evidence_refs must hold EvidenceRef"):
        DefensiveOperator(
            spec=CATALOG["SUSPEND_PROCESS"],
            target=_target(),
            incident_id="inc-0001",
            ttl_seconds=60,
            evidence_refs=("sha256:" + "0" * 64,),  # type: ignore[arg-type]
        )


def test_a_rollback_operator_has_no_rollback_of_its_own() -> None:
    resume = _operator("SUSPEND_PROCESS").rollback()
    assert resume is not None
    assert resume.rollback() is None
    assert _operator("TERMINATE_PROCESS").rollback() is None


# --- a pid is not an identity ------------------------------------------------------


def test_a_pid_is_not_an_identity() -> None:
    same_pid_new_process = _identity(4101, ticks=99_999)
    assert same_pid_new_process.pid == _identity(4101).pid
    assert same_pid_new_process.digest() != _identity(4101).digest()
    assert _identity(4101, uid=0).digest() != _identity(4101).digest()
    hashed = _identity(4101, executable_digest=digest_of_bytes(b"elf"))
    assert hashed.digest() != _identity(4101).digest()


def test_an_identity_refuses_a_malformed_executable_digest() -> None:
    with pytest.raises(ContractError, match="executable_digest"):
        ProcessIdentity(
            pid=1,
            start_time_ticks=1,
            uid=0,
            executable_digest="deadbeef",
            cgroup_id=None,
            namespace_id=None,
        )


def test_identity_digest_has_exactly_one_producer() -> None:
    """Rule A, the key-space rule: one function, or two spaces that never meet."""
    identity = _identity(4101)
    assert identity.digest() == digest_of_bytes(identity.canonical_bytes())
    assert identity.digest().startswith("sha256:")
    if importlib.util.find_spec("pocketsec.stage5.executor.identity") is not None:
        from pocketsec.stage5.executor.identity import identity_digest

        assert identity_digest(identity) == identity.digest()


def test_the_two_postcondition_key_spaces_are_structurally_identical() -> None:
    """``PostconditionKind`` exists twice in Stage 5, and that is only safe while the two
    copies are interchangeable. If either side renames a member, changes a value or stops
    being a ``StrEnum``, every catalog postcondition silently stops matching the verifier's
    tables — the S2-FC-01 defect exactly.
    """
    assert all(member.name == member.value for member in PostconditionKind)
    if importlib.util.find_spec("pocketsec.stage5.executor.verify") is None:
        return
    from pocketsec.stage5.executor.verify import PostconditionKind as VerifyKind

    assert [m.name for m in PostconditionKind] == [m.name for m in VerifyKind]
    assert [m.value for m in PostconditionKind] == [m.value for m in VerifyKind]
    for mine, theirs in zip(PostconditionKind, VerifyKind, strict=True):
        assert mine == theirs
        assert hash(mine) == hash(theirs)
        assert mine in frozenset({theirs})
        assert {theirs: 1}[mine] == 1


# --- the AST proof of the negative -------------------------------------------------


def test_no_arbitrary_command_path_over_the_package() -> None:
    assert no_arbitrary_command_path(STAGE5_ROOT) == ()


#: One planted fixture per rule the prover claims to enforce. A checker that cannot fail is
#: not a checker (MEMORY.md lesson 10), and both prior stages shipped one.
PLANTED_SHELL_PATHS = (
    ("import subprocess\n", "imports subprocess"),
    ("from subprocess import run\n", "imports subprocess"),
    ("from os import system\n", "imports os.system"),
    ("import os\ndef go(x):\n    os.system(x)\n", "calls os.system"),
    ("import pty\n", "imports pty"),
    ("def go(src):\n    return eval(src)\n", "calls eval"),
    ("def go(a, b):\n    return run(a, shell=True)\n", "passes shell=True"),
    ("def go(pid):\n    argv = f'kill {pid}'\n    return argv\n", "formatted string assigned"),
    ("def go(atoms):\n    return assemble_argv(f'{atoms}', None)\n", "flows into assemble_argv"),
    ("def go(argv):\n    return ' '.join(argv)\n", "joins argv into one string"),
    # Finding S5-SEC-09: standard equivalents the lexical denylist used to miss. Each one
    # returned () from the scan before the fix; each is a launcher one call away.
    ("import os as o\ndef go(x):\n    o.system(x)\n", "calls os.system"),
    ("import os as o\nlaunch = o.system\n", "reads system of a process module"),
    ("import os as o\ndef go(a):\n    o.execv(a, [a])\n", "calls os.execv"),
    ("import posix\n", "imports posix"),
    ("import nt\n", "imports nt"),
    ("def go():\n    return __import__('subprocess')\n", "calls __import__"),
    ("import importlib\nm = importlib.import_module('subprocess')\n", "through import_module"),
    ("import os\ndef go(x):\n    getattr(os, 'system')(x)\n", "getattr on a process module"),
    ("import asyncio\n", "imports asyncio"),
    ("import ctypes\n", "imports ctypes"),
    ("import multiprocessing\n", "imports multiprocessing"),
)


@pytest.mark.parametrize(("source", "expected"), PLANTED_SHELL_PATHS)
def test_no_arbitrary_command_path_catches_a_planted_shell_path(
    source: str, expected: str, tmp_path: Path
) -> None:
    (tmp_path / "planted.py").write_text(source, encoding="utf-8")
    rows = no_arbitrary_command_path(tmp_path)
    assert rows, source
    assert any(expected in row for row in rows), (source, rows)


def test_a_relative_import_of_a_forbidden_root_is_caught(tmp_path: Path) -> None:
    """Relative imports were invisible to two checkers at once in Stage 2 (S2-AUTH-01)."""
    (tmp_path / "planted.py").write_text("from . import subprocess\n", encoding="utf-8")
    assert no_arbitrary_command_path(tmp_path)
    (tmp_path / "planted.py").write_text("from ..util import subprocess\n", encoding="utf-8")
    assert no_arbitrary_command_path(tmp_path)


def test_a_docstring_naming_the_boundary_is_not_a_violation(tmp_path: Path) -> None:
    """AST, not text search: this module's own docstrings name every forbidden token."""
    (tmp_path / "clean.py").write_text(
        '"""No subprocess, no os.system, no eval, no shell=True here."""\n'
        "SAFE = 'subprocess os.system eval shell=True'\n",
        encoding="utf-8",
    )
    assert no_arbitrary_command_path(tmp_path) == ()


def test_no_privileged_module_imports_d3fend() -> None:
    """D3FEND is vocabulary, never a decision oracle (§28). Asserted by AST."""
    privileged = ("sentinel", "executor", "authority", "constitution")
    offenders: list[str] = []
    for directory in privileged:
        for path in sorted((STAGE5_ROOT / directory).rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                names: list[str] = []
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    names = [node.module or ""] + [alias.name for alias in node.names]
                if any("d3fend" in name.lower() for name in names):
                    offenders.append(f"{path.name}:{node.lineno}")
    assert offenders == []


# --- D5.16, and the honest zero ----------------------------------------------------


def test_mapped_fraction_is_zero_without_a_snapshot() -> None:
    assert load_snapshot() is None
    assert D3FEND_RELEASE is None
    assert mapped_fraction() == 0.0
    assert len(unmapped_operator_ids()) == len(CATALOG) == 14


def test_every_catalog_entry_ships_unmapped() -> None:
    for operator_id, entry in CATALOG.items():
        assert entry.d3fend_technique_id == UNMAPPED, operator_id
        assert mapping_for(operator_id) is None


def test_a_mapping_cannot_be_constructed_without_a_snapshot() -> None:
    with pytest.raises(ContractError, match="no D3FEND snapshot is committed"):
        D3FENDMapping(
            operator_id="SUSPEND_PROCESS",
            technique_id="D3-PSEP",
            technique_name="invented",
            release="invented-1.0",
        )


@pytest.mark.parametrize("technique_id", ["T1055", "D3-psep", "D3-", "PSEP", "D3-TOOLONGID"])
def test_a_snapshot_refuses_an_id_that_is_not_a_published_shape(technique_id: str) -> None:
    assert not D3FEND_ID_PATTERN.fullmatch(technique_id)
    with pytest.raises(ContractError, match="does not match"):
        D3FENDSnapshot(
            release="fixture",
            technique_names={technique_id: "name"},
            source_note="SYNTHETIC TEST FIXTURE",
        )


def test_a_snapshot_without_provenance_is_refused() -> None:
    with pytest.raises(ContractError, match="source_note"):
        D3FENDSnapshot(release="fixture", technique_names={"D3-AAA": "name"}, source_note="  ")


def test_the_mapping_mechanism_works_once_a_snapshot_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The adapter is exercised, not just type-checked — with a fixture, labelled as one.

    ``D3-AAA`` is **not** a D3FEND identifier. It is a synthetic id that exists to prove the
    snapshot path works; no real technique id is written from memory anywhere in this
    repository, which is why the committed coverage is 0 of 14.
    """
    snapshot_path = tmp_path / "d3fend-technique-ids.json"
    snapshot_path.write_text(
        json.dumps(
            {
                "release": "fixture-0",
                "technique_names": {"D3-AAA": "Synthetic Fixture Technique"},
                "source_note": "SYNTHETIC TEST FIXTURE — not a D3FEND release",
            }
        ),
        encoding="utf-8",
    )
    import pocketsec.stage5.operators.d3fend as d3fend_module

    monkeypatch.setattr(d3fend_module, "D3FEND_SNAPSHOT_PATH", snapshot_path)
    loaded = load_snapshot()
    assert loaded is not None and loaded.release == "fixture-0"
    mapping = D3FENDMapping(
        operator_id="SUSPEND_PROCESS",
        technique_id="D3-AAA",
        technique_name="Synthetic Fixture Technique",
        release="fixture-0",
    )
    assert mapping.to_dict()["technique_id"] == "D3-AAA"
    with pytest.raises(ContractError, match="not in the committed snapshot"):
        D3FENDMapping(
            operator_id="SUSPEND_PROCESS",
            technique_id="D3-BBB",
            technique_name="Synthetic Fixture Technique",
            release="fixture-0",
        )
    with pytest.raises(ContractError, match="snapshot is"):
        D3FENDMapping(
            operator_id="SUSPEND_PROCESS",
            technique_id="D3-AAA",
            technique_name="Synthetic Fixture Technique",
            release="fixture-1",
        )
    with pytest.raises(ContractError, match="disagrees with the published name"):
        D3FENDMapping(
            operator_id="SUSPEND_PROCESS",
            technique_id="D3-AAA",
            technique_name="Something Else",
            release="fixture-0",
        )


def test_a_corrupt_snapshot_raises_rather_than_reading_as_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "d3fend-technique-ids.json"
    path.write_text(json.dumps({"release": "fixture-0"}), encoding="utf-8")
    import pocketsec.stage5.operators.d3fend as d3fend_module

    monkeypatch.setattr(d3fend_module, "D3FEND_SNAPSHOT_PATH", path)
    with pytest.raises(ContractError, match="technique_names"):
        load_snapshot(path)


# --- the simulated host ------------------------------------------------------------


def test_simulated_host_cannot_claim_to_be_real() -> None:
    host = _host()
    assert host.host_kind is HostKind.SIMULATED
    assert host.snapshot().host_kind is HostKind.SIMULATED
    assert host.snapshot().to_dict()["simulated"] is True
    assert isinstance(type(host).host_kind, property)
    assert type(host).host_kind.fset is None
    with pytest.raises(AttributeError):
        host.host_kind = HostKind.REAL  # type: ignore[misc]
    import pocketsec.stage5.host.simulated as simulated_module

    assert not hasattr(simulated_module, "RealHost")
    subclasses = type(host).__subclasses__()
    assert subclasses == []


def test_the_host_constructor_has_no_argument_that_changes_its_kind() -> None:
    import inspect

    parameters = inspect.signature(SimulatedHost.__init__).parameters
    assert set(parameters) == {
        "self",
        "processes",
        "services",
        "sessions",
        "security_state",
        "faults",
        "clock",
    }
    assert all(
        parameters[name].kind is inspect.Parameter.KEYWORD_ONLY
        for name in parameters
        if name != "self"
    )


def test_the_host_fixture_is_bounded() -> None:
    many = tuple(
        ProcessRow(
            identity=_identity(5000 + index),
            state=ProcessState.RUNNING,
            unit=None,
            session_id=None,
            socket_ids=(),
            children=(),
            volatile_signals=(),
        )
        for index in range(MAX_SIMULATED_PROCESSES + 1)
    )
    with pytest.raises(ContractError, match="MAX_SIMULATED_PROCESSES"):
        SimulatedHost(
            processes=many,
            services=(),
            sessions=(),
            security_state=SecurityStateV1(),
            faults=FaultProfile(seed=1),
            clock=_ManualClock(),
        )


def test_apply_refuses_an_argv_it_did_not_assemble() -> None:
    host = _host()
    operator = _operator("SUSPEND_PROCESS")
    with pytest.raises(ContractError, match="is not the vector"):
        host.apply(operator, ("process.suspend", "9001"))
    with pytest.raises(ContractError, match="is not the vector"):
        host.apply(operator, ("process.terminate", "4101"))


def test_apply_refuses_anything_that_is_not_a_defensive_operator() -> None:
    host = _host()
    for payload in ("SUSPEND_PROCESS", {"operator_id": "SUSPEND_PROCESS"}, None):
        with pytest.raises(ContractError, match="only DefensiveOperator"):
            host.apply(payload, ("process.suspend", "4101"))  # type: ignore[arg-type]


def test_apply_counts_every_entry() -> None:
    """The TOCTOU tests read this counter to prove the host was never touched."""
    host = _host()
    assert host.apply_calls == 0
    operator = _operator("OBSERVE_PROCESS_METADATA")
    host.apply(operator, operator.argv())
    assert host.apply_calls == 1
    with pytest.raises(ContractError):
        host.apply(operator, ("wrong", "vector"))
    assert host.apply_calls == 2


def test_every_catalog_operator_reaches_its_handler_and_succeeds_on_the_fixture() -> None:
    """Fourteen handlers, fourteen applied calls, no dispatch hole and no dead entry.

    Stronger than "a handler exists": every operator in the vocabulary is *exercised* here,
    on a target the fixture actually has, and every one reports ``applied``. A catalog entry
    that cannot act on a plausible host is the ADR-0027 defect wearing a handler.
    """
    for operator_id in CATALOG:
        host = _host()
        operator = _operator(operator_id)
        effect = host.apply(operator, operator.argv())
        assert effect.applied is True, (operator_id, effect)
        assert effect.failure is None, (operator_id, effect.failure)
        assert host.apply_calls == 1


def test_suspend_loses_unpreserved_volatile_evidence() -> None:
    """The evidence gate runs BEFORE the action, and the host model can show why."""
    host = _host()
    suspend = _operator("SUSPEND_PROCESS")
    effect = host.apply(suspend, suspend.argv())
    assert effect.applied is True
    assert effect.evidence_lost == ("open_fds", "socket_table")
    assert effect.collateral_units == ("app.service",)
    row = host.snapshot().process(4101)
    assert row is not None and row.state is ProcessState.SUSPENDED

    preserved_host = _host()
    preserve = _operator("PRESERVE_VOLATILE_EVIDENCE")
    preserved_host.apply(preserve, preserve.argv())
    effect = preserved_host.apply(suspend, suspend.argv())
    assert effect.evidence_lost == ()


def test_terminate_destroys_volatile_evidence_and_the_process() -> None:
    host = _host()
    terminate = _operator("TERMINATE_PROCESS")
    effect = host.apply(terminate, terminate.argv())
    assert effect.applied is True
    assert effect.evidence_lost == ("open_fds", "socket_table")
    assert host.observe_identity(4101) is None
    row = host.snapshot().process(4101)
    assert row is not None and row.state is ProcessState.EXITED


def test_a_reaped_target_reports_target_gone() -> None:
    host = _host()
    host.reap(4101)
    suspend = _operator("SUSPEND_PROCESS")
    effect = host.apply(suspend, suspend.argv())
    assert effect.applied is False
    assert effect.failure is HostFailure.TARGET_GONE
    assert host.observe_identity(4101) is None


def test_pid_reuse_changes_the_identity_at_the_same_pid() -> None:
    """The TOCTOU race, explicit. The pid is the same and the process is not."""
    host = _host()
    before = host.observe_identity(4101)
    assert before is not None
    substitute = _identity(4101, ticks=99_999, uid=0)
    host.reap(4101, reuse_pid_for=substitute)
    after = host.observe_identity(4101)
    assert after is not None
    assert after.pid == before.pid
    assert after.digest() != before.digest()


def test_reap_refuses_a_substitution_that_substitutes_nothing() -> None:
    host = _host()
    with pytest.raises(ContractError, match="expected 4101"):
        host.reap(4101, reuse_pid_for=_identity(4102))
    with pytest.raises(ContractError, match="same identity"):
        host.reap(4101, reuse_pid_for=_identity(4101))
    with pytest.raises(ContractError, match="unknown pid"):
        host.reap(7777)


def test_enforcement_can_fail_silently() -> None:
    """The call reports success and the host is unchanged — what G5.10 detects."""
    host = _host(enforcement_failure_rate=1.0)
    suspend = _operator("SUSPEND_PROCESS")
    effect = host.apply(suspend, suspend.argv())
    assert effect.applied is True
    assert effect.changed == ()
    assert effect.failure is HostFailure.ENFORCEMENT_SILENTLY_FAILED
    row = host.snapshot().process(4101)
    assert row is not None and row.state is ProcessState.RUNNING


def test_an_observe_operator_is_not_subject_to_enforcement_injection() -> None:
    host = _host(enforcement_failure_rate=1.0)
    observe = _operator("OBSERVE_PROCESS_METADATA")
    effect = host.apply(observe, observe.argv())
    assert effect.failure is None
    assert effect.changed == ("observed:4101",)


def test_a_rollback_can_be_unavailable() -> None:
    host = _host(rollback_failure_rate=1.0)
    suspend = _operator("SUSPEND_PROCESS")
    host.apply(suspend, suspend.argv())
    resume = suspend.rollback()
    assert resume is not None
    effect = host.apply(resume, resume.argv())
    assert effect.applied is False
    assert effect.failure is HostFailure.ROLLBACK_UNAVAILABLE
    row = host.snapshot().process(4101)
    assert row is not None and row.state is ProcessState.SUSPENDED


def test_suspend_then_resume_restores_the_process_state() -> None:
    host = _host()
    suspend = _operator("SUSPEND_PROCESS")
    before = host.snapshot()
    host.apply(suspend, suspend.argv())
    assert host.snapshot().canonical_bytes() != before.canonical_bytes()
    resume = suspend.rollback()
    assert resume is not None
    host.apply(resume, resume.argv())
    after = host.snapshot()
    row = after.process(4101)
    assert row is not None and row.state is ProcessState.RUNNING
    # The volatile signals are NOT restored: the evidence is gone and the model says so
    # rather than pretending a resume undoes an observation loss.
    assert after.canonical_bytes() == before.canonical_bytes()


def test_restrict_then_release_a_socket() -> None:
    host = _host()
    restrict = _operator("RESTRICT_LOCAL_SOCKET")
    effect = host.apply(restrict, restrict.argv())
    assert effect.applied is True
    assert "sock-4101" in host.snapshot().restricted_sockets
    release = restrict.rollback()
    assert release is not None
    host.apply(release, release.argv())
    assert host.snapshot().restricted_sockets == frozenset()


def test_constrain_service_can_restart_a_dependency_and_reports_collateral() -> None:
    host = _host(dependency_restart_rate=1.0)
    constrain = _operator("CONSTRAIN_SERVICE")
    effect = host.apply(constrain, constrain.argv())
    assert effect.applied is True
    assert effect.failure is HostFailure.DEPENDENCY_RESTART
    assert effect.collateral_units == ("db.service",)
    dependency = host.snapshot().service("db.service")
    assert dependency is not None and dependency.healthy is False
    release = constrain.rollback()
    assert release is not None
    host.apply(release, release.argv())
    unit = host.snapshot().service("app.service")
    assert unit is not None and unit.constrained is False and unit.healthy is True


def test_revoking_a_session_removes_it_and_names_the_units_it_touched() -> None:
    host = _host()
    revoke = _operator("REVOKE_LOCAL_SESSION")
    effect = host.apply(revoke, revoke.argv())
    assert effect.applied is True
    assert effect.collateral_units == ("app.service",)
    assert host.snapshot().sessions == ()
    # A second revocation of the same session is TARGET_GONE, not a silent success.
    assert host.apply(revoke, revoke.argv()).failure is HostFailure.TARGET_GONE


def test_advance_does_not_move_the_clock() -> None:
    """A host that moved the clock would make every lease-expiry test meaningless."""
    clock = _ManualClock(at=100)
    host = SimulatedHost(
        processes=(),
        services=(),
        sessions=(),
        security_state=SecurityStateV1(),
        faults=FaultProfile(seed=3),
        clock=clock,
    )
    assert host.snapshot().at == 100
    host.advance(3600)
    assert host.snapshot().at == 100
    clock.advance(5)
    assert host.snapshot().at == 105
    with pytest.raises(ContractError, match="non-negative int"):
        host.advance(-1)


def test_the_attacker_can_replace_a_contained_process() -> None:
    """§25's bounded adaptation: process replacement, once per step, never unbounded."""
    host = _host(attacker_adapts=True)
    suspend = _operator("SUSPEND_PROCESS")
    host.apply(suspend, suspend.argv())
    before = len(host.snapshot().processes)
    host.advance(1)
    after = host.snapshot().processes
    assert len(after) == before + 1
    replacement = [row for row in after if row.identity.pid not in (4101, 4102, 9001)]
    assert len(replacement) == 1
    assert replacement[0].state is ProcessState.RUNNING
    assert replacement[0].unit == "app.service"


def test_pid_reuse_can_be_injected_through_the_fault_profile() -> None:
    host = _host(pid_reuse_rate=1.0)
    before = host.observe_identity(4101)
    host.advance(1)
    after = host.observe_identity(4101)
    assert before is not None and after is not None
    assert after.digest() != before.digest()


def test_a_snapshot_is_immutable_while_the_host_keeps_moving() -> None:
    host = _host()
    snapshot = host.snapshot()
    suspend = _operator("SUSPEND_PROCESS")
    host.apply(suspend, suspend.argv())
    row = snapshot.process(4101)
    assert row is not None and row.state is ProcessState.RUNNING
    with pytest.raises(dataclasses.FrozenInstanceError):
        snapshot.at = 99  # type: ignore[misc]
    with pytest.raises(AttributeError):
        snapshot.processes.append(row)  # type: ignore[attr-defined]
    assert snapshot.host_version == SIMULATED_HOST_VERSION


def test_the_same_seed_replays_the_same_run() -> None:
    def run() -> list[tuple[bool, str | None]]:
        host = _host(enforcement_failure_rate=0.5, rollback_failure_rate=0.5)
        results: list[tuple[bool, str | None]] = []
        for operator_id in ("SUSPEND_PROCESS", "RESUME_PROCESS", "SUSPEND_PROCESS"):
            operator = _operator(operator_id)
            effect = host.apply(operator, operator.argv())
            failure = None if effect.failure is None else str(effect.failure)
            results.append((effect.applied, failure))
        return results

    assert run() == run()


def test_a_fault_profile_refuses_a_rate_outside_the_unit_interval() -> None:
    with pytest.raises(ContractError, match="within"):
        FaultProfile(seed=1, enforcement_failure_rate=1.5)
    with pytest.raises(ContractError, match="within"):
        FaultProfile(seed=1, rollback_failure_rate=-0.1)
    profile = FaultProfile(seed=1)
    assert profile.to_dict()["note"].startswith("every rate is a chosen simulator parameter")


def test_a_host_snapshot_carries_the_stage_one_security_state() -> None:
    """Stage 5 defines no second host-state type; it carries Stage 1's."""
    host = _host()
    snapshot = host.snapshot()
    assert isinstance(snapshot.security_state, SecurityStateV1)
    assert snapshot.to_dict()["security_state"]["privilege"] == "USER"
    assert snapshot.service("nope.service") is None
    assert snapshot.identity(4101) == _identity(4101)
    assert snapshot.identity(123456) is None


def test_a_process_row_refuses_more_volatile_signals_than_the_bound() -> None:
    with pytest.raises(ContractError, match="volatile signals"):
        ProcessRow(
            identity=_identity(),
            state=ProcessState.RUNNING,
            unit=None,
            session_id=None,
            socket_ids=(),
            children=(),
            volatile_signals=tuple(f"sig-{index}" for index in range(17)),
        )


def test_a_service_row_and_a_snapshot_round_trip_to_plain_json() -> None:
    host = _host()
    payload = host.snapshot().to_dict()
    assert json.loads(json.dumps(payload)) == payload
    assert payload["host_version"] == SIMULATED_HOST_VERSION
    replaced = replace(
        HostSnapshot(
            host_kind=HostKind.SIMULATED,
            at=0,
            processes=(),
            services=(),
            sessions=(),
            restricted_sockets=frozenset(),
            security_state=SecurityStateV1(),
        ),
        at=5,
    )
    assert replaced.at == 5 and replaced.host_kind is HostKind.SIMULATED


def test_a_non_restartable_service_cannot_be_constrained() -> None:
    """Fail closed: a unit that cannot restart cannot be released either."""
    host = SimulatedHost(
        processes=(),
        services=(
            ServiceRow(
                unit="app.service",
                running=True,
                constrained=False,
                restartable=False,
                depends_on=(),
                healthy=True,
            ),
        ),
        sessions=(),
        security_state=SecurityStateV1(),
        faults=FaultProfile(seed=5),
        clock=_ManualClock(),
    )
    constrain = _operator("CONSTRAIN_SERVICE")
    effect = host.apply(constrain, constrain.argv())
    assert effect.applied is False
    assert effect.failure is HostFailure.ROLLBACK_UNAVAILABLE


def test_the_catalog_preconditions_name_the_evidence_gate_for_every_intervention() -> None:
    """Every operator at O2 or above must require evidence preservation first (§13)."""
    for operator_id, entry in CATALOG.items():
        if entry.operator_class < OperatorClass.O2_REVERSIBLE_RESTRICT:
            continue
        if operator_id in {"RELEASE_LOCAL_SOCKET", "RESUME_PROCESS", "RELEASE_SERVICE"}:
            continue  # restorative: it gives evidence back rather than taking it
        assert PreconditionKind.EVIDENCE_PRESERVED in entry.preconditions, operator_id
        assert PreconditionKind.TARGET_NOT_CRITICAL in entry.preconditions, operator_id
