"""Stage 5 package 3 — SENTINEL, the evidence preservation gate and the response monitors.

The centrepiece is G5.3's matrix: for **every** one of the fourteen catalog operators, with
the planner maximally in favour, thirteen sub-cases each make exactly one SENTINEL input
non-compliant and assert ``DENY`` with the matching ``DenyReason``. That is 182 required
denials, and :data:`MUTATIONS` is the table they come from.

Four things in here are deliberately harder than "does it work":

* :func:`test_every_check_is_load_bearing` monkeypatches the check that *owns* each mutation
  to return no reasons and asserts the reason disappears. Without it, 182 denials could all be
  produced by one over-eager check and nobody would know.
* :func:`test_sentinel_denies_when_a_check_raises` replaces each of the thirteen checks with
  one that raises, thirteen times, and requires ``KERNEL_FAULT`` every time.
* :func:`test_sentinel_module_defines_no_bypass_name` and
  :func:`test_sentinel_shares_no_mutable_state_with_aegis` are AST tests: they hold when the
  code is read, not when it is run.
* :func:`test_a_pass_that_did_not_run_every_check_is_refused` is the invariant somebody would
  weaken first, so it is asserted directly against the verdict constructor.
"""

from __future__ import annotations

import ast
import inspect
import re
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from pocketsec.stage0.contracts.common import ContractError, EvidenceRef, digest_of_bytes
from pocketsec.stage5.authority.capability import AuthorityGrant, GrantSource
from pocketsec.stage5.constitution.invariants import (
    FROZEN_CONSTITUTION,
    AuthorityClass,
    ConstitutionalLaw,
    ResponseConstitution,
)
from pocketsec.stage5.constitution.schema import (
    DEFAULT_MISSION_INVARIANTS,
    InvariantKind,
    MissionInvariant,
    MissionInvariantSet,
)
from pocketsec.stage5.evidence import preservation_gate as gate_module
from pocketsec.stage5.evidence.preservation_gate import (
    MAX_BUNDLE_BYTES,
    MAX_VOLATILE_SIGNALS,
    TRUNCATION_KEY,
    EvidencePreservationVerdict,
    PreActionBundle,
    PreservationDecision,
    RetentionPolicy,
)
from pocketsec.stage5.executor.identity import ManualClock, identity_digest
from pocketsec.stage5.governor import STAGE5_BUDGET
from pocketsec.stage5.labs import adversarial_load as labs
from pocketsec.stage5.operators.catalog import CATALOG
from pocketsec.stage5.sentinel import kernel as kernel_module
from pocketsec.stage5.sentinel import monitors as monitors_module
from pocketsec.stage5.sentinel.kernel import (
    CHECK_ORDER,
    SENTINEL_KERNEL_VERSION,
    Decision,
    DenyReason,
    SentinelKernel,
    SentinelVerdict,
)
from pocketsec.stage5.sentinel.monitors import (
    ACTION_OSCILLATION_FLIPS,
    CERTAINTY_CEILING,
    EXECUTOR_FAULT_BURST_COUNT,
    IDENTIFIABILITY_MARGIN,
    MAX_MONITOR_HISTORY,
    MonitorFinding,
    MonitorId,
    ResponseDefenseMonitors,
    Severity,
)

#: The escape-hatch vocabulary the kernel module may not define a name from. It lives here so
#: ``sentinel/kernel.py`` contains no spelling of it at all — a module that names its own
#: prohibition is a grep away from looking like it has one.
ESCAPE_NAME_PATTERN = re.compile(r"(?i)force|override|bypass|skip|disable|enable|dry_?run|trust|unsafe")

#: Packages SENTINEL may not import, so kernel and planner share no type and no mutable state.
PLANNER_PACKAGES: tuple[str, ...] = (
    "pocketsec.stage5.aegis",
    "pocketsec.stage5.safe",
    "pocketsec.stage5.twin",
    "pocketsec.stage5.memory",
    "pocketsec.stage5.cells",
)

SENTINEL_DIR = Path(kernel_module.__file__).parent
OTHER_DIGEST = digest_of_bytes(b"some other identity entirely")


# --- the compliant baseline the whole matrix is a mutation of ------------------------


class Baseline:
    """One compliant verification, plus the pieces a mutation swaps out.

    The planner is maximally in favour here: the resolution carries ``Verdict.MALICIOUS`` at
    support 1.0 and uncertainty 0.0, which the kernel cannot read at all — that is the point
    of G5.4, and it is why the resolution is only used to build the evidence bundle.
    """

    def __init__(self, operator_id: str) -> None:
        self.clock = ManualClock(1_000)
        self.kernel = labs.build_kernel(clock=self.clock)
        self.store = labs.build_token_store(clock=self.clock)
        self.snapshot = labs.build_snapshot()
        self.operator = labs.build_operator(operator_id)
        self.resolution = labs.build_resolution(supports=(1.0,), uncertainty=0.0)
        self.token = labs.mint_token(self.store, self.operator)
        self.evidence = labs.preserved_verdict(self.operator, self.resolution, self.snapshot)
        self.observed_identity = self.operator.target.identity
        self.journal_bytes = 0
        self.active_leases = 0
        self.recent_action_times: tuple[int, ...] = ()
        self.concurrent_operator_ids: frozenset[str] = frozenset()

    def verify(self) -> SentinelVerdict:
        return self.kernel.verify(
            self.operator,
            self.token,
            evidence=self.evidence,
            observed_identity=self.observed_identity,
            snapshot=self.snapshot,
            journal_bytes=self.journal_bytes,
            active_leases=self.active_leases,
            recent_action_times=self.recent_action_times,
            concurrent_operator_ids=self.concurrent_operator_ids,
        )


def _tamper(instance: Any, field: str, value: Any) -> None:
    """Present a frozen record with a field an adversary or a corruption changed.

    Constructing the bad value instead would test the constructor; the property under test is
    that the kernel refuses a record it is *handed*, however it came to look that way.
    """
    object.__setattr__(instance, field, value)


def _other_authority(case: Baseline) -> AuthorityClass:
    needed = case.token.authority
    return AuthorityClass.A1 if needed is AuthorityClass.A0 else AuthorityClass.A0


def _zero_containment_bound() -> MissionInvariantSet:
    return MissionInvariantSet(
        (
            MissionInvariant(
                "MI-ZERO",
                InvariantKind.MAX_CONTAINMENT_DURATION,
                "",
                0,
                "a zero containment bound: no lease at all may be held autonomously",
            ),
        )
    )


def _mutate_schema(case: Baseline) -> None:
    # A look-alike carrying every attribute the kernel reads; only isinstance catches it.
    case.token = labs.token_shaped_impostor(case.token)


def _mutate_signature_version(case: Baseline) -> None:
    _tamper(case.token, "schema_version", "0.0.1")


def _mutate_constitution(case: Baseline) -> None:
    _tamper(case.token, "authority", AuthorityClass.AX)


def _mutate_authority(case: Baseline) -> None:
    _tamper(case.token, "authority", _other_authority(case))


def _mutate_scope(case: Baseline) -> None:
    _tamper(case.token, "target_digest", OTHER_DIGEST)


def _mutate_target_identity(case: Baseline) -> None:
    case.observed_identity = labs.identity_for(start_time_ticks=123_456)


def _mutate_preconditions(case: Baseline) -> None:
    case.snapshot = labs.build_snapshot(include_target=False)


def _mutate_mission_invariants(case: Baseline) -> None:
    case.kernel = labs.build_kernel(clock=case.clock, invariants=_zero_containment_bound())


def _mutate_evidence_preservation(case: Baseline) -> None:
    case.evidence = EvidencePreservationVerdict(
        PreservationDecision.REFUSED_WOULD_DESTROY,
        case.evidence.bundle,
        ("process_memory",),
        (),
        None,
        "the mutation under test",
    )


def _mutate_rollback_expiry(case: Baseline) -> None:
    # An exception at A5 with no bundle at all: the evidence check clears it and the rollback
    # check does not, because a bundle is where rollback state is captured.
    case.evidence = EvidencePreservationVerdict(
        PreservationDecision.EXCEPTION_GRANTED, None, (), (), AuthorityClass.A5, "no bundle"
    )


def _mutate_expiry(case: Baseline) -> None:
    case.clock.advance(case.token.expiry - case.clock.now() + 1)


def _mutate_resource_limits(case: Baseline) -> None:
    case.journal_bytes = STAGE5_BUDGET.max_rollback_journal_bytes + 1


def _mutate_forbidden_combinations(case: Baseline) -> None:
    case.concurrent_operator_ids = frozenset({case.operator.spec.operator_id})


#: Thirteen mutations, one per :class:`DenyReason` the kernel can reach through a check, each
#: naming the check that owns it. ``lease_capacity`` shares ``RESOURCE_LIMIT`` with
#: ``resource_limits`` and has its own test rather than a fourteenth row.
MUTATIONS: tuple[tuple[DenyReason, str, Callable[[Baseline], None]], ...] = (
    (DenyReason.SCHEMA, "schema", _mutate_schema),
    (DenyReason.SIGNATURE_VERSION, "signature_version", _mutate_signature_version),
    (DenyReason.CONSTITUTION, "constitution", _mutate_constitution),
    (DenyReason.AUTHORITY, "authority", _mutate_authority),
    (DenyReason.SCOPE, "scope", _mutate_scope),
    (DenyReason.TARGET_IDENTITY, "target_identity", _mutate_target_identity),
    (DenyReason.PRECONDITION, "preconditions", _mutate_preconditions),
    (DenyReason.MISSION_INVARIANT, "mission_invariants", _mutate_mission_invariants),
    (DenyReason.EVIDENCE_PRESERVATION, "evidence_preservation", _mutate_evidence_preservation),
    (DenyReason.ROLLBACK_MISSING, "rollback_expiry", _mutate_rollback_expiry),
    (DenyReason.EXPIRY, "rollback_expiry", _mutate_expiry),
    (DenyReason.RESOURCE_LIMIT, "resource_limits", _mutate_resource_limits),
    (DenyReason.FORBIDDEN_COMBINATION, "forbidden_combinations", _mutate_forbidden_combinations),
)

OPERATOR_IDS: tuple[str, ...] = tuple(sorted(CATALOG))


# --- G5.3: the 14 x 13 matrix -------------------------------------------------------


def test_the_catalog_is_fourteen_operators_and_the_matrix_is_182_cases() -> None:
    assert len(OPERATOR_IDS) == 14
    assert len(MUTATIONS) == 13
    assert len(OPERATOR_IDS) * len(MUTATIONS) == 182


@pytest.mark.parametrize("operator_id", OPERATOR_IDS)
def test_the_compliant_baseline_passes(operator_id: str) -> None:
    """The matrix means nothing unless the unmutated case passes every check."""
    verdict = Baseline(operator_id).verify()
    assert verdict.decision is Decision.PASS, verdict.detail
    assert verdict.reasons == ()
    assert verdict.evaluated_checks == CHECK_ORDER
    assert verdict.kernel_version == SENTINEL_KERNEL_VERSION


@pytest.mark.parametrize("operator_id", OPERATOR_IDS)
@pytest.mark.parametrize(
    ("reason", "owning_check", "mutate"), MUTATIONS, ids=[row[0].value for row in MUTATIONS]
)
def test_sentinel_denies_every_operator_on_every_non_compliant_input(
    operator_id: str,
    reason: DenyReason,
    owning_check: str,
    mutate: Callable[[Baseline], None],
) -> None:
    """G5.3: 182 denials, with the planner maximally in favour in every one of them."""
    case = Baseline(operator_id)
    mutate(case)
    verdict = case.verify()
    assert verdict.decision is Decision.DENY, f"{operator_id}/{reason} passed: {verdict.detail}"
    assert reason in verdict.reasons, f"{operator_id}/{reason}: got {verdict.reasons}"
    assert owning_check in verdict.evaluated_checks


@pytest.mark.parametrize(
    ("reason", "owning_check", "mutate"), MUTATIONS, ids=[row[0].value for row in MUTATIONS]
)
def test_every_check_is_load_bearing(
    monkeypatch: pytest.MonkeyPatch,
    reason: DenyReason,
    owning_check: str,
    mutate: Callable[[Baseline], None],
) -> None:
    """Silence the owning check and the reason must vanish.

    This is the test that fails if somebody weakens a check into a no-op, and the test that
    proves the 182 denials are not all produced by one over-eager check.
    """
    case = Baseline("SUSPEND_PROCESS")
    mutate(case)
    monkeypatch.setattr(
        type(case.kernel), f"_check_{owning_check}", lambda self, request: (), raising=True
    )
    verdict = case.verify()
    assert reason not in verdict.reasons, (
        f"{reason} survived silencing _check_{owning_check}, so some other check produces it"
    )


# --- the four independence cases ----------------------------------------------------


def _module_paths() -> tuple[Path, ...]:
    """The three files F5 names as the SENTINEL trusted surface, plus nothing else.

    ``evidence/preservation_gate.py`` is included because F5 counts it as part of that surface,
    so the escape-hatch and planner-import rules apply to it too.
    """
    modules = [path for path in SENTINEL_DIR.glob("*.py") if path.stat().st_size]
    modules.append(Path(gate_module.__file__))
    assert len(modules) == 3, f"the trusted surface is three files, found {modules}"
    return tuple(sorted(modules))


def test_sentinel_module_defines_no_bypass_name() -> None:
    """Independence case 1 — a flag. Asserted over the AST, for every defined name."""
    offenders: list[str] = []
    for path in _module_paths():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names = [node.name] + [arg.arg for arg in _all_args(node)]
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                names = [node.id]
            elif isinstance(node, ast.arg):
                names = [node.arg]
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                names = [node.target.id]
            elif isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store):
                names = [node.attr]
            offenders.extend(
                f"{path.name}:{name}" for name in names if ESCAPE_NAME_PATTERN.search(name)
            )
    assert offenders == [], f"escape-hatch names under sentinel/: {offenders}"


def _all_args(node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> list[ast.arg]:
    if isinstance(node, ast.ClassDef):
        return []
    spec = node.args
    return [*spec.posonlyargs, *spec.args, *spec.kwonlyargs]


KEYWORD_ARGUMENTS: tuple[str, ...] = (
    "evidence",
    "observed_identity",
    "snapshot",
    "journal_bytes",
    "active_leases",
    "recent_action_times",
    "concurrent_operator_ids",
)


@pytest.mark.parametrize("argument", ("operator", "token", *KEYWORD_ARGUMENTS))
def test_sentinel_denies_on_missing_input(argument: str) -> None:
    """Independence case 2 — a None. Every required argument, one at a time."""
    case = Baseline("SUSPEND_PROCESS")
    setattr(case, argument, None)
    verdict = case.verify()
    assert verdict.decision is Decision.DENY
    assert DenyReason.MISSING_INPUT in verdict.reasons
    assert verdict.evaluated_checks == (), "a missing input is refused before any check runs"


def test_sentinel_cannot_be_built_from_a_weaker_constitution() -> None:
    """Independence case 3 — a missing config. The weaker law set never becomes an object."""
    shortened = tuple(law for law in ConstitutionalLaw)[:-1]
    with pytest.raises(ContractError):
        ResponseConstitution(
            laws=shortened,
            max_autonomous_authority=FROZEN_CONSTITUTION.max_autonomous_authority,
            prohibited_operator_classes=FROZEN_CONSTITUTION.prohibited_operator_classes,
            policy_version="1.0.0",
        )
    with pytest.raises(ContractError):
        ResponseConstitution(
            laws=tuple(ConstitutionalLaw),
            max_autonomous_authority=AuthorityClass.A5,
            prohibited_operator_classes=FROZEN_CONSTITUTION.prohibited_operator_classes,
            policy_version="1.0.0",
        )


@pytest.mark.parametrize("check_name", CHECK_ORDER)
def test_sentinel_denies_when_a_check_raises(
    monkeypatch: pytest.MonkeyPatch, check_name: str
) -> None:
    """Independence case 4 — an exception. Thirteen times, one per check."""

    def explode(self: SentinelKernel, request: Any) -> tuple[DenyReason, ...]:
        raise RuntimeError(f"{check_name} is broken")

    case = Baseline("SUSPEND_PROCESS")
    monkeypatch.setattr(type(case.kernel), f"_check_{check_name}", explode, raising=True)
    verdict = case.verify()
    assert verdict.decision is Decision.DENY
    assert DenyReason.KERNEL_FAULT in verdict.reasons
    assert check_name in verdict.evaluated_checks


def test_sentinel_kernel_init_has_exactly_three_parameters() -> None:
    signature = inspect.signature(SentinelKernel.__init__)
    keyword_only = {
        name
        for name, parameter in signature.parameters.items()
        if parameter.kind is inspect.Parameter.KEYWORD_ONLY
    }
    assert keyword_only == {"constitution", "invariants", "clock"}
    positional = [
        name
        for name, parameter in signature.parameters.items()
        if parameter.kind
        in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
    ]
    assert positional == ["self"]
    assert signature.parameters.get("kwargs") is None


def test_sentinel_shares_no_mutable_state_with_aegis() -> None:
    """No import of the planner packages, and no attribute whose type is defined in them."""
    for path in _module_paths():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            modules: list[str] = []
            if isinstance(node, ast.Import):
                modules = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                assert node.level == 0, f"{path.name} uses a relative import; resolve it absolutely"
                modules = [node.module or ""]
            for module in modules:
                assert not module.startswith(PLANNER_PACKAGES), f"{path.name} imports {module}"
    kernel = labs.build_kernel(clock=ManualClock(0))
    for slot in SentinelKernel.__slots__:
        held = getattr(kernel, slot)
        origin = type(held).__module__
        assert not origin.startswith(PLANNER_PACKAGES), f"{slot} holds a {origin} object"


#: Belief-strength vocabulary the kernel may not read. A name, not a docstring word: the
#: module explains at length that it reads none of these, and banning the *explanation* would
#: reward a module that said nothing.
BELIEF_NAME_PATTERN = re.compile(r"(?i)confidence|support|probability|likelihood|expected_")


def test_the_kernel_has_no_confidence_input() -> None:
    """ADR-0003 by construction: there is nothing for the kernel to be confident with."""
    parameters = set(inspect.signature(SentinelKernel.verify).parameters) - {"self"}
    assert parameters == {"operator", "token", *KEYWORD_ARGUMENTS}
    tree = ast.parse(Path(kernel_module.__file__).read_text(encoding="utf-8"))
    identifiers: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            identifiers.add(node.name)
        elif isinstance(node, ast.arg):
            identifiers.add(node.arg)
        elif isinstance(node, ast.Name):
            identifiers.add(node.id)
        elif isinstance(node, ast.Attribute):
            identifiers.add(node.attr)
    offenders = sorted(name for name in identifiers if BELIEF_NAME_PATTERN.search(name))
    assert offenders == [], f"the kernel reads belief strength through {offenders}"
    imported = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    assert "pocketsec.stage0.contracts.threat_prediction_v1" not in imported


@pytest.mark.parametrize("operator_id", OPERATOR_IDS)
def test_confidence_099_and_001_reach_the_same_sentinel_answer(operator_id: str) -> None:
    """G5.4 at the kernel: belief strength changes nothing about authority.

    The two cases differ only in the leading hypothesis's support and the resolution's
    uncertainty — the numbers a planner would push hardest on. The verdict, its reasons and
    the checks it ran must be identical, and so must the answer when one input is then made
    non-compliant: a confident planner does not get a softer denial.
    """
    answers = []
    for support, uncertainty in ((0.99, 0.01), (0.01, 0.99)):
        case = Baseline(operator_id)
        case.resolution = labs.build_resolution(supports=(support,), uncertainty=uncertainty)
        case.evidence = labs.preserved_verdict(case.operator, case.resolution, case.snapshot)
        clean = case.verify()
        _mutate_authority(case)
        denied = case.verify()
        answers.append(
            (clean.decision, clean.reasons, clean.evaluated_checks, denied.decision, denied.reasons)
        )
    assert answers[0] == answers[1]
    assert answers[0][0] is Decision.PASS
    assert answers[0][3] is Decision.DENY


def test_lease_capacity_denies_at_the_concurrent_lease_bound() -> None:
    case = Baseline("SUSPEND_PROCESS")
    case.active_leases = STAGE5_BUDGET.max_concurrent_leases
    verdict = case.verify()
    assert verdict.decision is Decision.DENY
    assert DenyReason.RESOURCE_LIMIT in verdict.reasons
    assert "lease_capacity" in verdict.evaluated_checks


def test_sentinel_refuses_a_baited_critical_unit() -> None:
    """§33's critical-process baiting: a protected unit dressed as the obvious target."""
    baited = MissionInvariantSet(
        (
            MissionInvariant(
                "MI-BAIT",
                InvariantKind.CRITICAL_SERVICE,
                labs.FIXTURE_UNIT,
                None,
                "the fixture unit, declared critical for this case",
            ),
        )
    )
    case = Baseline("CONSTRAIN_SERVICE")
    case.kernel = labs.build_kernel(clock=case.clock, invariants=baited)
    verdict = case.verify()
    assert verdict.decision is Decision.DENY
    assert DenyReason.MISSION_INVARIANT in verdict.reasons


def test_every_target_key_space_the_kernel_reads_is_identity_digest() -> None:
    """§4.9 rule A, consumer side: three producers, one key space, no half-matching join."""
    for operator_id in OPERATOR_IDS:
        case = Baseline(operator_id)
        identity = case.operator.target.identity
        assert identity_digest(identity) == identity.digest()
        assert case.token.target_digest == identity.digest()
        assert case.verify().target_digest == identity.digest()


# --- SentinelVerdict's own invariants ------------------------------------------------


def _verdict(**overrides: Any) -> SentinelVerdict:
    fields: dict[str, Any] = {
        "decision": Decision.PASS,
        "reasons": (),
        "detail": "probe",
        "operator_id": "SUSPEND_PROCESS",
        "target_digest": OTHER_DIGEST,
        "evaluated_checks": CHECK_ORDER,
    }
    fields.update(overrides)
    return SentinelVerdict(**fields)


def test_a_deny_with_no_reasons_is_refused() -> None:
    with pytest.raises(ContractError):
        _verdict(decision=Decision.DENY, reasons=())


def test_a_pass_carrying_reasons_is_refused() -> None:
    with pytest.raises(ContractError):
        _verdict(reasons=(DenyReason.SCOPE,))


def test_a_pass_that_did_not_run_every_check_is_refused() -> None:
    """The invariant somebody weakens first: a PASS over twelve checks is not a PASS."""
    with pytest.raises(ContractError):
        _verdict(evaluated_checks=CHECK_ORDER[:-1])
    with pytest.raises(ContractError):
        _verdict(evaluated_checks=tuple(reversed(CHECK_ORDER)))


@pytest.mark.parametrize(
    "rebound", [(), CHECK_ORDER[1:], (*CHECK_ORDER, CHECK_ORDER[0])], ids=["empty", "short", "dup"]
)
def test_a_rebound_check_order_denies_instead_of_passing_unchecked(
    monkeypatch: pytest.MonkeyPatch, rebound: tuple[str, ...]
) -> None:
    """Finding F4: ``CHECK_ORDER`` is a module global that ``_run`` iterates.

    Before the fix, rebinding it to ``()`` made the kernel evaluate nothing and return a
    PASS whose ``evaluated_checks`` equalled the (equally rebound) global, and every
    consumer accepted it. The kernel now reads its checks off its own class and denies
    ``KERNEL_FAULT`` when the list it is handed does not name each one exactly once.
    """
    case = Baseline("SUSPEND_PROCESS")
    _mutate_scope(case)  # a request that must be denied
    monkeypatch.setattr(kernel_module, "CHECK_ORDER", rebound)
    verdict = case.verify()
    assert verdict.decision is Decision.DENY
    assert DenyReason.KERNEL_FAULT in verdict.reasons
    with pytest.raises(ContractError):
        SentinelVerdict(Decision.PASS, (), "forged", "SUSPEND_PROCESS", OTHER_DIGEST, rebound)


def test_a_switch_spelled_outside_the_escape_regex_is_caught(tmp_path: Path) -> None:
    """Finding F4: the name regex is a spelling check; G5.3's switch rule is a shape check.

    ``ENFORCING`` matches no escape-hatch pattern, and a flag of that name that makes
    ``_run`` return early disabled SENTINEL while every name test stayed green. The shape
    rule catches the binding, the ``global`` and the ``globals()`` read, and the real
    trusted surface has none of the three.
    """
    from pocketsec.stage5.gate_construction import sentinel_switches

    assert not ESCAPE_NAME_PATTERN.search("ENFORCING")
    planted = tmp_path / "kernel.py"
    planted.write_text(
        "ENFORCING = True\n"
        "def disarm():\n    global ENFORCING\n    ENFORCING = False\n"
        "def run():\n    if not globals().get('ENFORCING'):\n        return 'PASS'\n",
        encoding="utf-8",
    )
    rows = sentinel_switches([planted])
    assert any("bool/None binding" in row for row in rows), rows
    assert any("global" in row for row in rows), rows
    assert any("reads globals" in row for row in rows), rows
    assert sentinel_switches() == ()


def test_check_order_names_thirteen_real_methods_and_fifteen_reasons_exist() -> None:
    assert len(CHECK_ORDER) == 13
    assert len(set(CHECK_ORDER)) == 13
    for name in CHECK_ORDER:
        assert callable(getattr(SentinelKernel, f"_check_{name}"))
    assert len(DenyReason) == 15
    reached = {reason for reason, _, _ in MUTATIONS}
    assert reached | {DenyReason.KERNEL_FAULT, DenyReason.MISSING_INPUT} == set(DenyReason)


def test_the_verdict_round_trips_to_plain_json_types() -> None:
    payload = _verdict().to_dict()
    assert payload["decision"] == "PASS"
    assert payload["evaluated_checks"] == list(CHECK_ORDER)
    assert payload["kernel_version"] == SENTINEL_KERNEL_VERSION


# --- D5.10: the evidence preservation gate ------------------------------------------


def _gate_case(
    operator_id: str, *, volatile: tuple[str, ...] = labs.FATAL_VOLATILE
) -> tuple[Any, Any, Any]:
    snapshot = labs.build_snapshot(volatile=volatile)
    return (
        labs.evidence_gate_for(),
        labs.build_operator(operator_id),
        (snapshot, labs.build_resolution()),
    )


def test_a_refused_evidence_destroying_action_is_recorded() -> None:
    """G5.8: the refusal, the signal names and the kernel denial all have to exist."""
    gate, operator, (snapshot, resolution) = _gate_case("TERMINATE_PROCESS")
    verdict = gate.evaluate(
        operator=operator, resolution=resolution, snapshot=snapshot, rollback_state={}
    )
    assert verdict.decision is PreservationDecision.REFUSED_WOULD_DESTROY
    assert set(verdict.destroyed_signals) & {"process_memory", "socket_table"}
    assert verdict.bundle is not None, "a refusal nobody can audit is not a control"
    assert "TERMINATE_PROCESS" in verdict.detail

    case = Baseline("TERMINATE_PROCESS")
    case.evidence = verdict
    kernel_verdict = case.verify()
    assert kernel_verdict.decision is Decision.DENY
    assert DenyReason.EVIDENCE_PRESERVATION in kernel_verdict.reasons
    assert "evidence_preservation" in kernel_verdict.detail


def test_an_a5_policy_grant_cannot_open_an_evidence_exception() -> None:
    """Policy is written once; losing unique evidence is a decision a person takes."""
    gate, operator, (snapshot, resolution) = _gate_case("TERMINATE_PROCESS")
    policy_grant = AuthorityGrant(
        authority=AuthorityClass.A5,
        granted_by=GrantSource.POLICY,
        policy_version=FROZEN_CONSTITUTION.policy_version,
        subject_operator_id=operator.spec.operator_id,
        detail="a policy grant at the highest class",
    )
    refused = gate.evaluate(
        operator=operator,
        resolution=resolution,
        snapshot=snapshot,
        rollback_state={},
        exception=policy_grant,
    )
    assert refused.decision is PreservationDecision.REFUSED_WOULD_DESTROY
    assert refused.exception_authority is None

    human_grant = replace(policy_grant, granted_by=GrantSource.HUMAN)
    granted = gate.evaluate(
        operator=operator,
        resolution=resolution,
        snapshot=snapshot,
        rollback_state={},
        exception=human_grant,
    )
    assert granted.decision is PreservationDecision.EXCEPTION_GRANTED
    assert granted.exception_authority is AuthorityClass.A5


@pytest.mark.parametrize(
    "authority", [AuthorityClass.A0, AuthorityClass.A2, AuthorityClass.A4, AuthorityClass.AX]
)
def test_an_exception_below_a5_cannot_be_constructed(authority: AuthorityClass) -> None:
    with pytest.raises(ContractError):
        EvidencePreservationVerdict(
            PreservationDecision.EXCEPTION_GRANTED, None, (), (), authority, "probe"
        )


def test_a_grant_for_another_operator_does_not_open_an_exception() -> None:
    gate, operator, (snapshot, resolution) = _gate_case("TERMINATE_PROCESS")
    elsewhere = AuthorityGrant(
        authority=AuthorityClass.A5,
        granted_by=GrantSource.HUMAN,
        policy_version=FROZEN_CONSTITUTION.policy_version,
        subject_operator_id="SUSPEND_PROCESS",
        detail="a human grant naming a different operator",
    )
    verdict = gate.evaluate(
        operator=operator,
        resolution=resolution,
        snapshot=snapshot,
        rollback_state={},
        exception=elsewhere,
    )
    assert verdict.decision is PreservationDecision.REFUSED_WOULD_DESTROY


def test_preserved_needs_a_bundle() -> None:
    with pytest.raises(ContractError):
        EvidencePreservationVerdict(PreservationDecision.PRESERVED, None, (), (), None, "probe")


def test_a_missing_required_signal_is_insufficient_evidence_not_a_pass() -> None:
    """``INSUFFICIENT_EVIDENCE`` is an answer; the abstention path has to be reachable."""
    snapshot = labs.build_snapshot(volatile=())
    operator = labs.build_operator("SUSPEND_PROCESS")
    strict = RetentionPolicy(
        required_signals=frozenset({"process_metadata", "kernel_ring_buffer"}),
        volatile_signals=frozenset({"kernel_ring_buffer"}),
        uniquely_necessary=frozenset({"kernel_ring_buffer"}),
        retention_seconds=3600,
    )
    gate = gate_module.EvidencePreservationGate(
        policy=strict, invariants=DEFAULT_MISSION_INVARIANTS
    )
    verdict = gate.evaluate(
        operator=operator,
        resolution=labs.build_resolution(),
        snapshot=snapshot,
        rollback_state={"restore": "RESUME_PROCESS"},
    )
    assert verdict.decision is PreservationDecision.INSUFFICIENT_EVIDENCE
    assert "kernel_ring_buffer" in verdict.unpreservable_signals


def test_a_retention_policy_cannot_require_a_signal_nothing_collects() -> None:
    with pytest.raises(ContractError):
        RetentionPolicy(
            required_signals=frozenset({"a"}),
            volatile_signals=frozenset({"b"}),
            uniquely_necessary=frozenset({"c"}),
            retention_seconds=1,
        )


def test_an_operator_evidence_digest_with_no_lineage_row_is_refused() -> None:
    """A reference the bundle cannot resolve is not evidence (spec §3.2 fact 2)."""
    operator = labs.build_operator("SNAPSHOT_PROCESS_STATE")
    orphan = EvidenceRef(store="raw", locator="nowhere", digest=digest_of_bytes(b"orphan"))
    _tamper(operator, "evidence_refs", (orphan,))
    with pytest.raises(ContractError):
        PreActionBundle.build(
            incident_id=operator.incident_id,
            operator=operator,
            resolution=labs.build_resolution(),
            snapshot=labs.build_snapshot(),
            rollback_state={},
        )


def test_the_bundle_integrity_digest_covers_its_own_fields() -> None:
    bundle = _bundle()
    assert bundle.integrity_digest == digest_of_bytes(bundle.canonical_bytes())
    payload = bundle.to_dict()
    assert payload["integrity_digest"] == bundle.integrity_digest
    edited = dict(payload)
    edited["incident_id"] = "INC-SOMETHING-ELSE"
    assert digest_of_bytes(
        gate_module._canonical({k: v for k, v in edited.items() if k != "integrity_digest"})
    ) != bundle.integrity_digest


def _bundle(**overrides: Any) -> PreActionBundle:
    operator = labs.build_operator("SUSPEND_PROCESS")
    return PreActionBundle.build(
        incident_id=overrides.get("incident_id", operator.incident_id),
        operator=operator,
        resolution=labs.build_resolution(),
        snapshot=labs.build_snapshot(),
        rollback_state=overrides.get("rollback_state", {"restore": "RESUME_PROCESS"}),
    )


def test_a_bundle_over_budget_truncates_state_rows_and_records_it() -> None:
    """Truncation is explicit, and never of the lineage."""
    operator = labs.build_operator("SUSPEND_PROCESS")
    snapshot = labs.build_snapshot()
    big = {"blob": "x" * (MAX_BUNDLE_BYTES // 2)}
    fixed: dict[str, Any] = {
        "incident_id": operator.incident_id,
        "evidence_refs": operator.evidence_refs,
        "volatile_preserved": (),
        "rationale_claim_ids": (),
        "policy_version": FROZEN_CONSTITUTION.policy_version,
        "component_versions": {"probe": "1"},
        "rollback_state": {"restore": "RESUME_PROCESS"},
    }
    state = dict(gate_module._pre_action_state(operator, snapshot))
    state.update({f"blob_{index}": big["blob"] for index in range(4)})
    fitted = gate_module._fit_to_budget(state, fixed)
    assert TRUNCATION_KEY in fitted
    assert fitted[TRUNCATION_KEY], "a dropped row leaves a record"
    assert all(row["reason"] == "MAX_BUNDLE_BYTES" for row in fitted[TRUNCATION_KEY])
    assert "target_digest" in fitted, "the row that identifies the target is never dropped"
    bundle = PreActionBundle(pre_action_state=fitted, **fixed)
    assert len(bundle.canonical_bytes()) <= MAX_BUNDLE_BYTES


def test_a_bundle_whose_rollback_state_exceeds_the_budget_fails_rather_than_truncating() -> None:
    operator = labs.build_operator("SUSPEND_PROCESS")
    fixed: dict[str, Any] = {
        "incident_id": operator.incident_id,
        "evidence_refs": operator.evidence_refs,
        "volatile_preserved": (),
        "rationale_claim_ids": (),
        "policy_version": FROZEN_CONSTITUTION.policy_version,
        "component_versions": {"probe": "1"},
        "rollback_state": {"huge": "x" * (MAX_BUNDLE_BYTES + 1)},
    }
    with pytest.raises(ContractError):
        gate_module._fit_to_budget({"at": 1, "host_kind": "SIMULATED", "target_digest": "d"}, fixed)


def test_a_bundle_refuses_more_volatile_signals_than_the_bound() -> None:
    signals = tuple(f"sig_{index:02d}" for index in range(MAX_VOLATILE_SIGNALS))
    # Captured, not merely listed: only captured signals are preserved (S5-SEC-01).
    snapshot = labs.build_snapshot(volatile=signals, preserved=signals)
    bundle = PreActionBundle.build(
        incident_id=labs.DEFAULT_INCIDENT,
        operator=labs.build_operator("SNAPSHOT_PROCESS_STATE"),
        resolution=labs.build_resolution(),
        snapshot=snapshot,
        rollback_state={},
    )
    assert len(bundle.volatile_preserved) == MAX_VOLATILE_SIGNALS
    with pytest.raises(ContractError):
        PreActionBundle(
            incident_id=labs.DEFAULT_INCIDENT,
            evidence_refs=(),
            volatile_preserved=tuple(f"s{index}" for index in range(MAX_VOLATILE_SIGNALS + 1)),
            pre_action_state={},
            rationale_claim_ids=(),
            policy_version="1.0.0",
            component_versions={},
            rollback_state={},
        )


def test_a_preserving_operator_loses_nothing_and_is_preserved() -> None:
    gate, operator, (snapshot, resolution) = _gate_case("SNAPSHOT_PROCESS_STATE")
    verdict = gate.evaluate(
        operator=operator,
        resolution=resolution,
        snapshot=snapshot,
        rollback_state={"note": "none needed"},
    )
    assert verdict.decision is PreservationDecision.PRESERVED
    assert verdict.destroyed_signals == ()
    assert verdict.bundle is not None


# --- D5.22: the monitors ------------------------------------------------------------


def _plan(decision: str = "ACT", operator_id: str = "SUSPEND_PROCESS") -> labs.LoadPlan:
    candidate = labs.LoadCandidate("C-1", labs.build_operator(operator_id))
    return labs.LoadPlan(plan_id="P-1", decision=decision, chosen=candidate)


def test_false_certainty_fires_on_certainty_a_resolution_cannot_have() -> None:
    monitors = labs.build_monitors()
    resolution = labs.build_resolution(
        supports=(0.99, 0.10), uncertainty=0.0, truncations=({"what": "worlds"},)
    )
    fired = {
        finding.monitor: finding
        for finding in monitors.observe_plan(_plan(), resolution)
        if finding.fired
    }
    assert MonitorId.FALSE_CERTAINTY in fired
    assert fired[MonitorId.FALSE_CERTAINTY].severity is Severity.ESCALATE
    assert fired[MonitorId.FALSE_CERTAINTY].threshold == CERTAINTY_CEILING


def test_false_certainty_fires_on_unseparated_hypotheses() -> None:
    monitors = labs.build_monitors()
    gap = IDENTIFIABILITY_MARGIN / 2
    resolution = labs.build_resolution(supports=(0.50, 0.50 - gap), uncertainty=0.0)
    fired = {f.monitor for f in monitors.observe_plan(_plan(), resolution) if f.fired}
    assert MonitorId.FALSE_CERTAINTY in fired


def test_false_certainty_is_quiet_when_the_resolution_admits_uncertainty() -> None:
    monitors = labs.build_monitors()
    resolution = labs.build_resolution(supports=(0.9, 0.05), uncertainty=0.4)
    fired = {f.monitor for f in monitors.observe_plan(_plan(), resolution) if f.fired}
    assert MonitorId.FALSE_CERTAINTY not in fired


def test_no_monitor_output_can_grant_authority() -> None:
    """A finding has no authority field, and nothing above HALT_AUTONOMY exists."""
    assert set(Severity) == {Severity.INFO, Severity.ESCALATE, Severity.HALT_AUTONOMY}
    fields = set(MonitorFinding.__dataclass_fields__)
    assert not fields & {"authority", "grant", "permitted", "approved"}
    assert len(MonitorId) == 8


def test_a_finding_that_did_not_fire_cannot_carry_a_severity() -> None:
    with pytest.raises(ContractError):
        MonitorFinding(MonitorId.ACTION_OSCILLATION, False, Severity.HALT_AUTONOMY, "x", 1, 0)


def test_action_oscillation_fires_on_flip_flopping_one_target() -> None:
    monitors = labs.build_monitors()
    pairs = ("SUSPEND_PROCESS", "RESUME_PROCESS") * 4
    for index, operator_id in enumerate(pairs):
        monitors.observe_receipt(
            labs.LoadReceipt(
                receipt_id=f"R-{index}",
                operator_id=operator_id,
                operator_class=3,
                target_digest=OTHER_DIGEST,
                outcome="COMMITTED_VERIFIED",
            )
        )
    fired = {f.monitor: f for f in monitors.findings()}
    assert MonitorId.ACTION_OSCILLATION in fired
    assert fired[MonitorId.ACTION_OSCILLATION].observed_value >= ACTION_OSCILLATION_FLIPS


def test_executor_fault_burst_halts_autonomy() -> None:
    monitors = labs.build_monitors()
    for index in range(EXECUTOR_FAULT_BURST_COUNT):
        monitors.observe_receipt(
            labs.LoadReceipt(
                receipt_id=f"R-{index}",
                operator_id="SUSPEND_PROCESS",
                operator_class=3,
                target_digest=OTHER_DIGEST,
                outcome="ROLLBACK_FAILED",
                rollback_attempted=True,
                rollback_succeeded=False,
            )
        )
    assert monitors.halted()


def test_a_refusal_is_not_counted_as_an_executor_fault() -> None:
    """Counting refusals as faults would make a kernel doing its job look like an outage."""
    monitors = labs.build_monitors()
    for index in range(MAX_MONITOR_HISTORY):
        monitors.observe_receipt(
            labs.LoadReceipt(
                receipt_id=f"R-{index}",
                operator_id="SUSPEND_PROCESS",
                operator_class=3,
                target_digest=OTHER_DIGEST,
                outcome="REFUSED_SENTINEL",
            )
        )
    assert not monitors.halted()


def test_monitor_history_is_bounded() -> None:
    monitors = labs.build_monitors()
    resolution = labs.build_resolution(supports=(0.5, 0.5), uncertainty=0.0)
    for index in range(MAX_MONITOR_HISTORY * 3):
        monitors.observe_plan(_plan(), resolution)
        monitors.observe_receipt(
            labs.LoadReceipt(
                receipt_id=f"R-{index}",
                operator_id="SUSPEND_PROCESS",
                operator_class=3,
                target_digest=f"sha256:{index:064x}",
                outcome="COMMITTED_VERIFIED",
            )
        )
    sizes = monitors.history_sizes()
    assert sizes["plans"] == MAX_MONITOR_HISTORY
    assert sizes["receipts"] == MAX_MONITOR_HISTORY
    assert sizes["findings"] <= MAX_MONITOR_HISTORY
    assert len(monitors.findings()) <= MAX_MONITOR_HISTORY


def test_a_halt_latches() -> None:
    """A halt that clears when the next plan looks calmer is what an attacker paces against."""
    monitors = labs.build_monitors()
    for index in range(EXECUTOR_FAULT_BURST_COUNT):
        monitors.observe_receipt(
            labs.LoadReceipt(
                receipt_id=f"R-{index}",
                operator_id="SUSPEND_PROCESS",
                operator_class=3,
                target_digest=OTHER_DIGEST,
                outcome="COMMITTED_UNVERIFIED",
            )
        )
    assert monitors.halted()
    monitors.observe_plan(_plan(decision="NO_ACTION"), labs.build_resolution())
    assert monitors.halted()


def test_a_monitor_set_refuses_a_budget_that_is_not_a_resource_budget() -> None:
    with pytest.raises(ContractError):
        ResponseDefenseMonitors(invariants=DEFAULT_MISSION_INVARIANTS, budget=object())  # type: ignore[arg-type]


def test_the_monitor_outcome_vocabulary_matches_the_real_outcome_enum() -> None:
    """§4.9 rule A, the trap this project has now hit twice: two key spaces that never match.

    The monitors compare ``str(receipt.outcome)`` against closed string sets. If those strings
    drifted from the executor's ``Outcome`` members, every receipt-side monitor would read
    zero for ever and the gate would report a clean run. This test is the join.
    """
    from pocketsec.stage5.executor.transactional import Outcome

    real = {member.value for member in Outcome}
    monitored = monitors_module._FAULT_OUTCOMES | monitors_module._COMMITTED_OUTCOMES
    assert monitored <= real, f"monitors watch outcomes that do not exist: {monitored - real}"
    assert monitors_module._FAULT_OUTCOMES & monitors_module._COMMITTED_OUTCOMES, (
        "a faulted receipt is also a committed one; if these sets were disjoint the fault "
        "monitor would be watching outcomes the oscillation monitor could never see"
    )
    assert not any(name.startswith("REFUSED_") for name in monitored), (
        "a refusal is the system working, not an executor fault"
    )


def test_every_forbidden_combination_names_real_catalog_operators() -> None:
    """A combination naming an operator that does not exist could never match anything."""
    for combination in kernel_module.FORBIDDEN_COMBINATIONS:
        assert combination, "an empty combination matches every action"
        unknown = set(combination) - set(CATALOG)
        assert unknown == set(), f"FORBIDDEN_COMBINATIONS names unknown operators {unknown}"
        assert len(combination) >= 2, (
            "a singleton combination would refuse an operator outright; that belongs to the "
            "constitution or the mission invariants, not to a combination rule"
        )


def test_a_forbidden_pair_denies_when_its_partner_is_in_flight() -> None:
    case = Baseline("SUSPEND_PROCESS")
    case.concurrent_operator_ids = frozenset({"REVOKE_LOCAL_SESSION"})
    verdict = case.verify()
    assert verdict.decision is Decision.DENY
    assert DenyReason.FORBIDDEN_COMBINATION in verdict.reasons
    unrelated = Baseline("SUSPEND_PROCESS")
    unrelated.concurrent_operator_ids = frozenset({"HASH_EXECUTABLE"})
    assert unrelated.verify().decision is Decision.PASS


def test_poisoned_dependency_raises_shadow_not_confidence() -> None:
    """§33's dependency-poisoning row, by the name the spec's regression table gives it.

    The monitor fires, and the thing it produces has no way to raise authority: a
    ``MonitorFinding`` carries no authority, grant or approval field, and the top severity
    *removes* the system's permission to act rather than granting one.
    """
    monitors = labs.build_monitors()
    poisoned = labs.build_resolution(
        degradations=({"component": "dependency_walk", "reason": "unreachable"},)
    )
    findings = monitors.observe_plan(_plan(decision="ACT"), poisoned)
    fired = [f for f in findings if f.monitor is MonitorId.DEPENDENCY_POISONING and f.fired]
    assert fired, "acting on a degraded dependency view must raise shadow"
    assert fired[0].severity is Severity.ESCALATE
    assert fired[0].observed_value == 1
    assert "authority" not in {field.lower() for field in MonitorFinding.__dataclass_fields__}
    quiet = labs.build_monitors().observe_plan(_plan(decision="OBSERVE"), poisoned)
    assert not [
        f for f in quiet if f.monitor is MonitorId.DEPENDENCY_POISONING and f.fired
    ], "a plan that is not about to act is not acting on a poisoned view"


def test_the_monitors_import_no_planner_package() -> None:
    source = Path(monitors_module.__file__).read_text(encoding="utf-8")
    for package in PLANNER_PACKAGES:
        assert f"import {package}" not in source
        assert f"from {package}" not in source


# --- the adversarial-load suites ----------------------------------------------------


@pytest.mark.parametrize(
    "suite",
    [
        labs.self_dos_suite,
        labs.rollback_sabotage_suite,
        labs.candidate_flood,
        labs.token_replay_suite,
        labs.dependency_poisoning_suite,
    ],
    ids=lambda fn: fn.__name__,
)
def test_each_adversarial_suite_holds_its_bound(suite: Callable[[], Any]) -> None:
    report = suite()
    assert report.within_bound, report.detail
    assert report.samples > 0
    assert isinstance(report.to_dict(), dict)


def test_the_measured_cost_report_is_structural_before_it_is_temporal() -> None:
    """A PASS runs all thirteen checks; a schema denial runs one. That holds without a clock.

    The wall-clock figures travel only as a ratio with ``/proc/loadavg`` beside them, so this
    test asserts the structural claim and the presence of the load average — never a
    microsecond threshold, which on this host would be a random number generator.
    """
    report = labs.measure_sentinel_cost(samples=200)
    assert report.pass_checks_evaluated == len(CHECK_ORDER)
    assert report.deny_checks_evaluated == 1
    assert report.monitor_history_rows == MAX_MONITOR_HISTORY
    assert report.deny_to_pass_ratio is not None and report.deny_to_pass_ratio > 0
    assert len(report.loadavg) == 3
    payload = report.to_dict()
    assert payload["monitor_history_rows"] == MAX_MONITOR_HISTORY
    # UNMEASURED is None, never a plausible-looking guess (ADR-0004).
    assert payload["monitor_delta_rss_bytes"] is None or payload["monitor_delta_rss_bytes"] >= 0


def test_run_all_returns_one_report_per_suite() -> None:
    reports = labs.run_all()
    assert len(reports) == 5
    assert {report.suite for report in reports} == {
        "self_dos_suite",
        "rollback_sabotage_suite",
        "candidate_flood",
        "token_replay_suite",
        "dependency_poisoning_suite",
    }
    assert all(report.within_bound for report in reports)


# --- the F5 size clause, measured rather than asserted from memory -------------------


#: F5's combined-line budget for the three files it names.
F5_LINE_BUDGET: int = 900

#: A regression ratchet at the total measured in this session. It is **above**
#: :data:`F5_LINE_BUDGET`, and that overshoot is reported to the integrator as a blocker
#: rather than absorbed here: this constant exists so the surface cannot grow further
#: unnoticed, not to claim F5's size clause is met. Lowering it is the work; raising it
#: requires saying so out loud.
SENTINEL_SURFACE_RATCHET: int = 1330


def measure_sentinel_surface() -> dict[str, int]:
    """Line counts for the three files F5 names, produced by reading them."""
    return {
        path.name: len(path.read_text(encoding="utf-8").splitlines())
        for path in (
            Path(kernel_module.__file__),
            Path(monitors_module.__file__),
            Path(gate_module.__file__),
        )
    }


def test_the_sentinel_trusted_surface_stays_inside_its_ratchet() -> None:
    """F5's size clause, measured rather than recalled.

    Two real assertions: every file stays inside the repository's ~800-line module limit, and
    the combined total stays inside :data:`SENTINEL_SURFACE_RATCHET`. The ratchet is above
    :data:`F5_LINE_BUDGET`; the gap is a reported blocker, and this test exists so it cannot
    widen quietly.
    """
    counted = measure_sentinel_surface()
    total = sum(counted.values())
    assert all(lines <= 800 for lines in counted.values()), counted
    assert total <= SENTINEL_SURFACE_RATCHET, f"{counted} totals {total}"
