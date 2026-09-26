"""Behaviour and failure-path tests for the Stage 5 `aegis` package (D5.3, D5.9).

Three modules are under test — the selector, the planner and the human decision
contract — and every test here is about something one of them must **refuse**,
**bound**, or **keep invariant**. Construction is not tested for its own sake:
both prior stages shipped gate checks that passed by asserting a type existed,
and this file is written so that silently weakening any invariant in the three
modules makes at least one test fail.

The load-bearing test is ``test_confidence_099_and_001_reach_the_same_authority``.
It is G5.4(a) and it is ADR-0003's whole point: a high-confidence prediction and a
low-confidence one must reach the same authority decision. It runs twenty corpus
cases, emits each twice differing **only** in the leading hypothesis's support,
and reports the identical count rather than asserting a bare boolean, because the
number is the finding.

AEGIS is unprivileged. Two AST tests assert that no module under ``aegis/`` can
reach the token store or a ``HostAdapter``; they duplicate two clauses of
``tests/test_stage5_boundary.py`` on purpose, because this package's own test file
should fail on its own if the boundary is broken rather than relying on another
package's file being run.
"""

from __future__ import annotations

import ast
import inspect
import random
from dataclasses import fields, replace
from pathlib import Path
from typing import Any

import pytest

from pocketsec.stage0.contracts.common import ContractError, digest_of_bytes
from pocketsec.stage0.contracts.threat_prediction_v1 import Verdict
from pocketsec.stage1.state.potential import phi
from pocketsec.stage1.state.security_state import (
    CredentialExposure,
    ExecutionControl,
    Privilege,
    SecurityStateV1,
)
from pocketsec.stage4.stage5_interface import CBFResolutionV1
from pocketsec.stage5.aegis import human_contract as contract_module
from pocketsec.stage5.aegis import planner as planner_module
from pocketsec.stage5.aegis.human_contract import (
    APPROVAL_REASONS,
    CONTRACT_HEADINGS,
    CONTRACT_TOKEN_RE,
    MAX_CONTRACT_BYTES,
    MAX_CONTRACT_LIST_ITEMS,
    NO_APPROVAL_REQUIRED,
    OPERATIONAL_EFFECTS,
    SECURITY_EFFECTS,
    HumanDecisionContract,
    WorldEffect,
    build_contract,
)
from pocketsec.stage5.aegis.pareto import (
    DEFAULT_WEIGHTS,
    MAXIMISED,
    MINIMISED,
    POLICY_ORDER,
    REJECTION_REASONS,
    Objective,
    ObjectiveVector,
    RejectionRecord,
    ScoredCandidate,
    Selector,
    admissible_in_world,
    dominates,
    minimal_regret_set,
    minimax_regret,
    pareto_frontier,
    policy_pick,
    regret,
    scalar_utility,
    score,
    select,
    world_ids_of,
)
from pocketsec.stage5.aegis.planner import (
    ABLATION_FLAG_FIELDS,
    UNMAPPED_PLANNER_FLAGS,
    AegisPlanner,
    PlanDecision,
    PlannerConfig,
    ResponsePlan,
)
from pocketsec.stage5.aegis.shadow import (
    SHADOW_HUMAN_CEILING,
    SHADOW_TERMS,
    ActionShadow,
    AutonomyEligibility,
)
from pocketsec.stage5.authority.capability import required_authority
from pocketsec.stage5.cells.response_cells import ResponseCellField
from pocketsec.stage5.constitution.invariants import (
    FROZEN_CONSTITUTION,
    MAX_AUTONOMOUS_AUTHORITY,
    AuthorityClass,
    authority_rank,
)
from pocketsec.stage5.constitution.schema import (
    DEFAULT_MISSION_INVARIANTS,
    InvariantKind,
    MissionInvariant,
    MissionInvariantSet,
)
from pocketsec.stage5.core_ids import ABLATION_FLAGS, OPTIONAL_IDS
from pocketsec.stage5.executor.identity import ManualClock
from pocketsec.stage5.executor.lease import (
    DEFAULT_HYSTERESIS,
    HysteresisController,
    Lease,
)
from pocketsec.stage5.executor.transactional import (
    Outcome,
    Phase,
    PhaseRecord,
    TransactionReceipt,
)
from pocketsec.stage5.executor.verify import PostconditionKind, PostconditionResult
from pocketsec.stage5.governor import ResourceBudget, ResourceGovernor
from pocketsec.stage5.host.simulated import (
    FaultProfile,
    HostKind,
    ProcessRow,
    ProcessState,
    ServiceRow,
    SimulatedHost,
)
from pocketsec.stage5.memory.effectiveness import (
    AUTONOMOUS_ROLLBACK_THRESHOLD,
    MIN_SAMPLES_FOR_RATE,
    EffectivenessMemory,
    LearningSource,
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
from pocketsec.stage5.safe.action_field import (
    ActionField,
    CandidateAction,
    HarmModel,
    generate_action_field,
)
from pocketsec.stage5.sentinel.kernel import CHECK_ORDER, Decision, SentinelVerdict
from pocketsec.stage5.twin.response_twin import ResponseTwin

AEGIS_ROOT = Path(planner_module.__file__).resolve().parent
EVIDENCE_DIGEST = digest_of_bytes(b"stage5-aegis-evidence")

#: The number of corpus cases G5.4(a) runs. Twenty, per the specification.
CORPUS_CASES = 20

#: The two supports the invariance test pairs. The whole point is that these are
#: the extremes of the unit interval: if authority is invariant between 0.99 and
#: 0.01 it is invariant everywhere a resolution can land.
HIGH_SUPPORT = 0.99
LOW_SUPPORT = 0.01


# --- fixtures, built by hand so every field in play is visible ---------------


def identity(pid: int, *, ticks: int = 100, uid: int = 1000) -> ProcessIdentity:
    return ProcessIdentity(
        pid=pid,
        start_time_ticks=ticks,
        uid=uid,
        executable_digest=digest_of_bytes(f"exe-{pid}".encode()),
        cgroup_id="cg-1",
        namespace_id="ns-1",
    )


#: A host state whose Φ is above ``DEFAULT_HYSTERESIS.enter_threshold`` (6.0).
#: Measured, not guessed: ``phi(ESCALATED_STATE).total`` is asserted in
#: ``test_the_fixture_states_bracket_the_hysteresis_thresholds`` so a change to
#: Stage 1's Φ weights fails there rather than silently making every ACT test
#: measure the HOLD path.
ESCALATED_STATE = SecurityStateV1(
    privilege=Privilege.ROOT,
    credential=CredentialExposure.EXTRACTED,
    execution=ExecutionControl.PRIVILEGED,
)

#: Φ = 0.0, below ``DEFAULT_HYSTERESIS.exit_threshold`` (3.0): the controller
#: releases here, which is how ``PlanDecision.ROLLBACK`` is reached.
CALM_STATE = SecurityStateV1()


def clean_host(*, security_state: SecurityStateV1 | None = None) -> SimulatedHost:
    """One process, one unit, no children, no dependencies, one volatile signal.

    Deliberately shadow-free. ``tests/test_stage5_field.py`` already proves that
    an unmodelled dependency raises Action Shadow until the gate refuses autonomy;
    this file needs the *other* case, a host the twin can model completely, or the
    ``ACT`` path would be unreachable and the ACT-side invariants untested.

    The default security state is :data:`ESCALATED_STATE`, because the hysteresis
    controller will not enter an action cycle below its threshold and a fixture at
    Φ = 0 would leave every intervention path untested.
    """
    return SimulatedHost(
        processes=[
            ProcessRow(
                identity=identity(4242),
                state=ProcessState.RUNNING,
                unit="app.service",
                session_id="sess-1",
                socket_ids=("sock-1",),
                children=(),
                volatile_signals=("socket_table",),
            )
        ],
        services=[
            ServiceRow(
                unit="app.service",
                running=True,
                constrained=False,
                restartable=False,
                depends_on=(),
                healthy=True,
            )
        ],
        sessions=["sess-1"],
        security_state=security_state if security_state is not None else ESCALATED_STATE,
        faults=FaultProfile(seed=11),
        clock=ManualClock(0),
    )


def shadowed_host() -> SimulatedHost:
    """A host whose unit depends on four units the snapshot does not hold.

    The conservative case: the twin cannot model the neighbourhood, Action Shadow
    rises, and every intervention should lose its autonomy eligibility.
    """
    return SimulatedHost(
        processes=[
            ProcessRow(
                identity=identity(9100),
                state=ProcessState.RUNNING,
                unit="fragile.service",
                session_id=None,
                socket_ids=(),
                children=(9101, 9102),
                volatile_signals=("socket_table",),
            )
        ],
        services=[
            ServiceRow(
                unit="fragile.service",
                running=True,
                constrained=False,
                restartable=True,
                depends_on=tuple(f"ghost{index}.service" for index in range(4)),
                healthy=True,
            )
        ],
        sessions=["sess-1", "sess-2"],
        security_state=ESCALATED_STATE,
        faults=FaultProfile(seed=13),
        clock=ManualClock(0),
    )


def mission_profile() -> MissionInvariantSet:
    """``DEFAULT_MISSION_INVARIANTS`` with the autonomous-downtime bound raised to 900 s.

    The shipped default bounds autonomous downtime at 300 s, which refuses every
    900 s catalog operator on every host and would leave the intervention path
    untested. All nine invariants are kept; only that one bound moves, and
    ``test_a_mission_invariant_violation_refuses_the_candidate`` uses a strictly
    *stricter* profile so both directions are covered.
    """
    return MissionInvariantSet(
        invariants=tuple(
            MissionInvariant(
                invariant_id=invariant.invariant_id,
                kind=invariant.kind,
                subject=invariant.subject,
                bound_seconds=900
                if invariant.kind is InvariantKind.MAX_AUTONOMOUS_DOWNTIME
                else invariant.bound_seconds,
                detail=invariant.detail,
            )
            for invariant in DEFAULT_MISSION_INVARIANTS.invariants
        )
    )


def resolution(**overrides: Any) -> CBFResolutionV1:
    payload: dict[str, Any] = {
        "resolution_id": "res-0001",
        "incident_id": "inc-0001",
        "epoch_id": 1,
        "verdict": Verdict.MALICIOUS,
        "identifiability": "IDENTIFIED",
        "hypotheses": (
            {
                "mechanism_id": "credential-theft",
                "support": 0.80,
                "consequence": 2.0,
                "uncertainty": 0.20,
                "claim_ids": [],
                "evidence_digests": [EVIDENCE_DIGEST],
            },
        ),
        "consequence_distribution": {"credential-theft": 2.0},
        "claim_graph": {"claims": []},
        "evidence_lineage": (
            {
                "store": "evidence-store",
                "locator": "seq/1",
                "digest": EVIDENCE_DIGEST,
                "target_pid": "4242",
                "target_unit": "app.service",
                "target_session": "sess-1",
                "target_socket": "sock-1",
            },
        ),
        "uncertainty": 0.30,
        "shadow": {},
        "information_gaps": (),
        "truncations": (),
        "degradations": (),
    }
    payload.update(overrides)
    return CBFResolutionV1(**payload)


def corpus_case(index: int, *, leading_support: float, pid: int = 4242) -> CBFResolutionV1:
    """One of twenty resolutions, parameterised so only ``leading_support`` varies.

    Everything else about a case is a deterministic function of ``index``: the
    number of worlds, the identifiability string, the verdict, the upstream
    truncation count and the follower supports. The pair (0.99, 0.01) therefore
    differs in exactly one float, which is what makes the invariance claim
    meaningful rather than a comparison of two unrelated inputs.
    """
    verdicts = (Verdict.MALICIOUS, Verdict.SUSPICIOUS, Verdict.BENIGN, Verdict.UNKNOWN)
    identifiabilities = ("IDENTIFIED", "SEPARABLE", "INSUFFICIENT_EVIDENCE", "UNIDENTIFIABLE")
    # Two or three worlds, never one. A single-world resolution at support 0.01 has
    # every world below ``RULED_OUT_SUPPORT``, and the SAFE Action Field then
    # generates **no** intervention candidate at all — "no surviving world can be
    # cited with reconstructible evidence". That fail-closed rule belongs to the
    # field package and is correct; it just means a single-world case at 0.01 has
    # no action for the planner to grant authority to, so the invariance question
    # is not asked there. ``test_a_ruled_out_leading_hypothesis_withholds_action``
    # covers that case in the direction ADR-0003 actually requires.
    world_count = 2 + index % 2
    mechanisms = [f"mech-{index:02d}-{slot}" for slot in range(world_count)]
    hypotheses: list[dict[str, Any]] = []
    for slot, mechanism_id in enumerate(mechanisms):
        hypotheses.append(
            {
                "mechanism_id": mechanism_id,
                "support": leading_support if slot == 0 else 0.20 + 0.05 * slot,
                "consequence": 1.0 + slot,
                "uncertainty": 0.25,
                "claim_ids": [],
                "evidence_digests": [EVIDENCE_DIGEST],
            }
        )
    truncations = tuple(
        {"what": "world", "identifier": f"w{slot}", "reason": "bound"}
        for slot in range(index % 2)
    )
    return resolution(
        resolution_id=f"res-{index:04d}",
        incident_id=f"inc-{index:04d}",
        epoch_id=1 + index % 2,
        verdict=verdicts[index % len(verdicts)],
        identifiability=identifiabilities[index % len(identifiabilities)],
        hypotheses=tuple(hypotheses),
        consequence_distribution={m: 1.0 + slot for slot, m in enumerate(mechanisms)},
        uncertainty=0.10 + 0.02 * (index % 5),
        truncations=truncations,
        evidence_lineage=(
            {
                "store": "evidence-store",
                "locator": f"seq/{index}",
                "digest": EVIDENCE_DIGEST,
                "target_pid": str(pid),
                "target_unit": "app.service",
                "target_session": "sess-1",
                "target_socket": "sock-1",
            },
        ),
    )


def make_planner(
    *,
    config: PlannerConfig | None = None,
    memory: EffectivenessMemory | None = None,
    invariants: MissionInvariantSet | None = None,
    governor: ResourceGovernor | None = None,
    harm: HarmModel | None = None,
    clock: ManualClock | None = None,
    hysteresis: HysteresisController | None = None,
) -> AegisPlanner:
    """Build a planner with a **fresh** governor unless one is supplied.

    ``ResourceGovernor`` is per-incident state: §34's caps (16 candidate actions,
    4096 work units) bound one incident's planning, so a planner reused across
    incidents with one governor legitimately exhausts it and escalates. Tests that
    plan twice therefore build two planners sharing one
    :class:`HysteresisController` — the controller is the thing with cross-incident
    state, and this keeps the two kinds of state from being confused.
    """
    return AegisPlanner(
        config=config or PlannerConfig(),
        constitution=FROZEN_CONSTITUTION,
        invariants=invariants if invariants is not None else mission_profile(),
        governor=governor or ResourceGovernor(),
        memory=memory if memory is not None else EffectivenessMemory(),
        cells=ResponseCellField(),
        hysteresis=hysteresis
        or HysteresisController(policy=DEFAULT_HYSTERESIS, clock=clock or ManualClock(0)),
        harm=harm if harm is not None else HarmModel(unacceptable=frozenset()),
    )


def lease_on_target(
    *, operator_id: str = "SUSPEND_PROCESS", pid: int = 4242, granted_at: int = 0
) -> Lease:
    """An active lease on the fixture's process, keyed by ``identity_digest``.

    ``target_digest`` is ``ProcessIdentity.digest()`` — the same function the token,
    the receipt and the registry use (§4.9 Rule A). A lease keyed any other way
    would silently never match and the hysteresis path would look untested while
    passing.
    """
    return Lease(
        lease_id=f"lease-{pid}",
        action_id=f"act-{pid}",
        incident_id="inc-0001",
        operator_id=operator_id,
        target_digest=identity(pid).digest(),
        granted_at=granted_at,
        ttl_seconds=300,
        maximum_lifetime_seconds=3600,
        renewals=0,
        rollback_operator_id=CATALOG[operator_id].rollback_operator_id,
    )


def build_field(
    res: CBFResolutionV1, host: SimulatedHost | None = None
) -> tuple[ActionField, ResponseTwin, ResourceGovernor]:
    host = host or clean_host()
    governor = ResourceGovernor()
    snapshot = host.snapshot()
    twin = ResponseTwin(snapshot=snapshot, governor=governor)
    field = generate_action_field(
        res,
        snapshot,
        constitution=FROZEN_CONSTITUTION,
        invariants=mission_profile(),
        governor=governor,
        memory=EffectivenessMemory(),
        cells=ResponseCellField(),
        twin=twin,
    )
    return field, twin, governor


def candidate_named(field: ActionField, operator_id: str) -> CandidateAction:
    for candidate in field.candidates:
        if candidate.operator.spec.operator_id == operator_id:
            return candidate
    raise AssertionError(f"{operator_id} is not in the generated field")


def receipt_for(
    operator_id: str,
    *,
    index: int,
    epoch_id: int = 1,
    rolled_back: bool,
    rollback_ok: bool = True,
) -> TransactionReceipt:
    """One receipt, built by hand so the effectiveness memory can be primed.

    ``EffectivenessMemory`` has no write API other than :meth:`observe`, and
    ``rollback_reliability`` returns ``None`` below ``MIN_SAMPLES_FOR_RATE``
    rollback **attempts** — which is exactly the check that blocks autonomy.
    Priming it is therefore the only way to reach ``PlanDecision.ACT`` at all, and
    that fact is itself asserted by
    ``test_act_is_reachable_only_with_measured_rollback_reliability``.

    Two shapes, because one shape cannot prime both statistics honestly: a
    ``COMMITTED_VERIFIED`` receipt with ``verification=EFFECTIVE`` and no rollback
    feeds ``verified_security_effect``, and a ``ROLLED_BACK`` receipt with
    ``verification=INEFFECTIVE`` feeds ``rollback_attempts``/``successes``. A
    single receipt claiming both would be a rolled-back action that also worked.
    """
    from pocketsec.stage5.executor.verify import VerificationOutcome

    spec = CATALOG[operator_id]
    target_digest = identity(4242).digest()
    phases = (
        PhaseRecord(phase=Phase.PREPARE, at=0, ok=True, detail=""),
        PhaseRecord(phase=Phase.COMMIT, at=1, ok=True, detail=""),
        (
            PhaseRecord(phase=Phase.ROLLBACK, at=3, ok=rollback_ok, detail="")
            if rolled_back
            else PhaseRecord(phase=Phase.VERIFY, at=2, ok=True, detail="")
        ),
    )
    return TransactionReceipt(
        receipt_id=f"rcpt-{operator_id}-{index}",
        action_id=f"act-{operator_id}-{index}",
        incident_id=f"inc-{index:04d}",
        resolution_id=f"res-{index:04d}",
        operator_id=operator_id,
        operator_class=spec.operator_class,
        target_digest=target_digest,
        outcome=Outcome.ROLLED_BACK if rolled_back else Outcome.COMMITTED_VERIFIED,
        phases=phases,
        sentinel_verdict=SentinelVerdict(
            decision=Decision.PASS,
            reasons=(),
            detail="",
            operator_id=operator_id,
            target_digest=target_digest,
            evaluated_checks=CHECK_ORDER,
        ),
        token_verdict=_token_valid(),
        identity_revalidation=_identity_match(),
        evidence_bundle_digest=digest_of_bytes(b"bundle"),
        lease_id=f"lease-{index}",
        postconditions=(
            PostconditionResult(
                kind=PostconditionKind.ROLLBACK_STILL_POSSIBLE,
                satisfied=True,
                observed="restored" if rolled_back else "applied",
                detail="",
            ),
        ),
        verification=(
            VerificationOutcome.INEFFECTIVE if rolled_back else VerificationOutcome.EFFECTIVE
        ),
        residual=None,
        rollback_attempted=rolled_back,
        rollback_succeeded=rollback_ok if rolled_back else None,
        host_kind=HostKind.SIMULATED,
        simulated=True,
        work_units=1,
        loadavg=(0.0, 0.0, 0.0),
        epoch_id=epoch_id,
    )


def _token_valid() -> Any:
    from pocketsec.stage5.authority.tokens import TokenVerdict

    return TokenVerdict.VALID


def _identity_match() -> Any:
    from pocketsec.stage5.executor.identity import IdentityRevalidation

    return IdentityRevalidation.MATCH


def primed_memory(
    *operator_ids: str,
    mechanism_ids: tuple[str, ...] = ("credential-theft",),
    epochs: tuple[int, ...] = (1, 2),
) -> EffectivenessMemory:
    """A memory holding ``MIN_SAMPLES_FOR_RATE`` successful rollbacks per operator.

    ``mechanism_ids`` exists because the memory is keyed by
    ``context_key(epoch_id, mechanism_id, target_kind)``: priming for one mechanism
    primes nothing for another, and a test that forgot to pass its corpus case's
    mechanism would be silently measuring the unprimed path. That is the key-space
    trap §4.9 Rule A names, met here in a test fixture.
    """
    memory = EffectivenessMemory()
    index = 0
    for operator_id in operator_ids:
        for mechanism_id in mechanism_ids:
            for epoch_id in epochs:
                for rolled_back in (True, False):
                    for _ in range(MIN_SAMPLES_FOR_RATE):
                        memory.observe(
                            receipt_for(
                                operator_id,
                                index=index,
                                epoch_id=epoch_id,
                                rolled_back=rolled_back,
                            ),
                            source=LearningSource.LAB_SANDBOX,
                            mechanism_id=mechanism_id,
                        )
                        index += 1
    return memory


# --- the AST rules, duplicated here on purpose -------------------------------


def _imported(path: Path) -> list[tuple[str, int]]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.extend((alias.name, node.lineno) for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                # A relative import resolves against ``aegis``; two checkers in
                # Stage 2 were blind to relative form at once (S2-AUTH-01), so the
                # resolution is done rather than assumed absent.
                prefix = ".".join(
                    ["pocketsec", "stage5", "aegis"][: max(0, 3 - node.level + 1)]
                )
                base = f"{prefix}.{base}" if base else prefix
            found.append((base, node.lineno))
            found.extend((f"{base}.{alias.name}", node.lineno) for alias in node.names)
    return found


def _aegis_modules() -> list[Path]:
    return sorted(p for p in AEGIS_ROOT.rglob("*.py") if "__pycache__" not in p.parts)


def test_the_planner_cannot_mint_a_token() -> None:
    """§35: AEGIS proposes. Only the privileged side mints capability.

    A planner that could reach ``TokenStore`` would be a planner an attacker can
    influence through evidence and then convert into privilege. The property is an
    import-graph property, so it is checked by AST rather than by trusting that
    nobody will add the import.
    """
    offenders = [
        f"{path.name}:{lineno} -> {module}"
        for path in _aegis_modules()
        for module, lineno in _imported(path)
        if module.startswith("pocketsec.stage5.authority.tokens")
    ]
    assert not offenders, f"aegis/ can mint a token: {offenders}"
    names = {
        name
        for path in _aegis_modules()
        for name, _ in _defined_names(path)
    }
    assert "TokenStore" not in names
    assert "CapabilityToken" not in names


def test_the_planner_cannot_reach_a_host_adapter() -> None:
    """The planner sees a read-only ``HostSnapshot`` and never the adapter.

    ``HostSnapshot`` is permitted — a planner that cannot see host state cannot
    plan — but ``SimulatedHost``, ``HostAdapter`` and the executor's write path are
    not, so no planning code can mutate the host even by accident.
    """
    forbidden = (
        "pocketsec.stage5.host.simulated.SimulatedHost",
        "pocketsec.stage5.host.simulated.HostAdapter",
        "pocketsec.stage5.executor.transactional",
        "pocketsec.stage5.executor.journal",
    )
    offenders = [
        f"{path.name}:{lineno} -> {module}"
        for path in _aegis_modules()
        for module, lineno in _imported(path)
        if module in forbidden
    ]
    assert not offenders, f"aegis/ reaches the privileged host surface: {offenders}"
    names = {name for path in _aegis_modules() for name, _ in _defined_names(path)}
    assert "SimulatedHost" not in names
    assert "TransactionalExecutor" not in names


def _defined_names(path: Path) -> list[tuple[str, int]]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            found.append((node.name, node.lineno))
        elif isinstance(node, ast.ImportFrom):
            found.extend((alias.asname or alias.name, node.lineno) for alias in node.names)
    return found


def test_the_ast_rule_catches_its_own_violation(tmp_path: Path) -> None:
    """A rule that cannot catch its own negative fixture is enforcing nothing.

    Both prior stages shipped a check that passed by asserting a type existed. The
    two tests above scan real files; this one proves the scanner itself sees a
    violation, including the relative-import form that was invisible to two Stage 2
    checkers at once.
    """
    offender = tmp_path / "planner.py"
    offender.write_text(
        "from pocketsec.stage5.authority.tokens import TokenStore\n"
        "from ..host.simulated import SimulatedHost\n",
        encoding="utf-8",
    )
    modules = {module for module, _ in _imported(offender)}
    assert "pocketsec.stage5.authority.tokens.TokenStore" in modules
    assert "pocketsec.stage5.host.simulated.SimulatedHost" in modules
    assert "SimulatedHost" in {name for name, _ in _defined_names(offender)}


# --- D5.9: the objective vector and the order it induces ---------------------


def test_the_nine_objectives_are_exactly_section_12s() -> None:
    assert [objective.value for objective in Objective] == [
        "SECURITY_BENEFIT",
        "WORST_WORLD_SECURITY_BENEFIT",
        "COLLATERAL",
        "SCOPE",
        "IRREVERSIBILITY",
        "EVIDENCE_LOSS",
        "ACTION_SHADOW",
        "DOWNTIME",
        "VERIFICATION_LATENCY",
    ]
    assert {
        Objective.SECURITY_BENEFIT,
        Objective.WORST_WORLD_SECURITY_BENEFIT,
    } == MAXIMISED
    assert set(MINIMISED) | MAXIMISED == set(Objective)
    assert set(POLICY_ORDER) == set(MINIMISED)


def test_an_incomplete_objective_vector_is_refused() -> None:
    """A missing axis would be compared against a default, and the default is permissive."""
    partial = {objective: 0.5 for objective in Objective if objective is not Objective.COLLATERAL}
    with pytest.raises(ContractError, match="missing COLLATERAL"):
        ObjectiveVector(values=partial)


@pytest.mark.parametrize("bad", [-0.01, 1.01, float("nan"), float("inf")])
def test_an_out_of_range_objective_is_refused(bad: float) -> None:
    values = {objective: 0.5 for objective in Objective}
    values[Objective.SCOPE] = bad
    with pytest.raises(ContractError):
        ObjectiveVector(values=values)


def test_an_unknown_objective_key_is_refused() -> None:
    values: dict[Any, float] = {objective: 0.5 for objective in Objective}
    values["SMUGGLED"] = 0.0
    with pytest.raises(ContractError, match="unknown objectives"):
        ObjectiveVector(values=values)


def _random_vector(rng: random.Random) -> ObjectiveVector:
    # Three levels rather than a continuum: ties are where a dominance relation
    # actually goes wrong, and a uniform float almost never produces one.
    return ObjectiveVector(
        values={objective: rng.choice((0.0, 0.5, 1.0)) for objective in Objective}
    )


def test_dominates_is_a_strict_partial_order() -> None:
    """Irreflexive, asymmetric and transitive, over 400 generated vectors.

    Checked rather than argued: a dominance relation that admitted a cycle would
    make ``pareto_frontier`` return a set that depends on input order, and the
    whole §12 argument rests on the frontier being well-defined.
    """
    rng = random.Random(4090)
    vectors = [_random_vector(rng) for _ in range(120)]
    for vector in vectors:
        assert not dominates(vector, vector), "dominance must be irreflexive"
    asymmetry_witnesses = 0
    for left in vectors:
        for right in vectors:
            if dominates(left, right):
                asymmetry_witnesses += 1
                assert not dominates(right, left), "dominance must be asymmetric"
    transitive_witnesses = 0
    for a in vectors:
        for b in vectors:
            if not dominates(a, b):
                continue
            for c in vectors:
                if dominates(b, c):
                    transitive_witnesses += 1
                    assert dominates(a, c), "dominance must be transitive"
    # A vacuous pass is the failure mode both prior stages shipped, so the witness
    # counts are asserted non-zero: a generator that produced no comparable pair
    # would satisfy every implication above while testing nothing. Note that
    # *uniform* vectors are never comparable — raising one axis helps on a maximised
    # objective and hurts on a minimised one — which is why ``_random_vector``
    # varies the axes independently.
    assert asymmetry_witnesses > 0, "no pair was comparable; the test proved nothing"
    assert transitive_witnesses > 0, "no transitive chain was found; the test proved nothing"


def test_a_strictly_better_vector_dominates_and_an_equal_one_does_not() -> None:
    base = ObjectiveVector(values={objective: 0.5 for objective in Objective})
    better = ObjectiveVector(
        values={
            **{objective: 0.5 for objective in Objective},
            Objective.COLLATERAL: 0.1,
        }
    )
    assert dominates(better.values and better, base)
    assert not dominates(base, better)
    equal = ObjectiveVector(values={objective: 0.5 for objective in Objective})
    assert not dominates(base, equal)
    # Higher benefit is better; higher harm is worse. A relation that got this
    # backwards would make the planner prefer the more damaging action.
    more_benefit = ObjectiveVector(
        values={
            **{objective: 0.5 for objective in Objective},
            Objective.SECURITY_BENEFIT: 0.9,
        }
    )
    assert dominates(more_benefit, base)
    more_harm = ObjectiveVector(
        values={
            **{objective: 0.5 for objective in Objective},
            Objective.DOWNTIME: 0.9,
        }
    )
    assert dominates(base, more_harm)


def test_the_frontier_holds_only_non_dominated_candidates() -> None:
    res = resolution()
    field, twin, governor = build_field(res)
    scored = [score(candidate, cones={}, resolution=res) for candidate in field.candidates]
    frontier = pareto_frontier(scored)
    assert frontier, "a non-empty field must have a non-empty frontier"
    for item in frontier:
        assert not any(
            dominates(other.objectives, item.objectives) for other in scored if other is not item
        )
    dropped = [item for item in scored if item not in frontier]
    for item in dropped:
        assert any(dominates(other.objectives, item.objectives) for other in scored)


# --- D5.9: regret ------------------------------------------------------------


def test_regret_uses_only_admissible_hindsight_actions() -> None:
    """§26: an inadmissible action is not a hindsight benchmark.

    Built as a direct experiment. The same candidate is measured twice against the
    same pool; the only difference is whether the pool's lowest-loss member is
    marked inadmissible. If regret ignored admissibility the two numbers would be
    equal, so the assertion is that they are not, and that the second equals the
    regret against the admissible remainder.
    """
    res = resolution()
    field, _, _ = build_field(res)
    world = world_ids_of(res)[0]
    scored = [score(candidate, cones={}, resolution=res) for candidate in field.candidates]
    # Data-driven rather than hard-coded operator ids: the benchmark is whichever
    # candidate actually has the lowest loss in this world, and the subject is any
    # candidate with strictly more. Naming two operators by hand would make the
    # test pass or fail on the loss weights rather than on admissibility.
    benchmark = min(scored, key=lambda item: (item.loss(world), item.candidate_id))
    subject = max(scored, key=lambda item: (item.loss(world), item.candidate_id))
    assert subject.loss(world) > benchmark.loss(world)
    admissible_pool = [subject, benchmark]
    inadmissible_pool = [
        subject,
        score(
            benchmark.candidate, cones={}, resolution=res, caller_inadmissible=True
        ),
    ]
    with_cheap = regret(subject, world_id=world, all_candidates=admissible_pool)
    without_cheap = regret(subject, world_id=world, all_candidates=inadmissible_pool)
    assert with_cheap > without_cheap, (
        "marking the best hindsight action inadmissible must lower the regret it "
        "generated; equal numbers would mean admissibility is not consulted"
    )
    # With only itself admissible, the benchmark is its own loss and regret is 0.
    assert without_cheap == pytest.approx(0.0)


def _refusing_shadow_score() -> float:
    """A shadow score the gate must refuse: above ``SHADOW_HUMAN_CEILING``.

    Derived from the ceiling rather than written as a literal, so raising the
    ceiling does not quietly turn this fixture into an *accepted* shadow and make
    the test pass for the wrong reason.
    """
    return min(1.0, SHADOW_HUMAN_CEILING + 0.2)


def test_a_shadow_refused_candidate_is_not_a_hindsight_benchmark() -> None:
    """The shadow-gate half of admissibility, on a candidate the gate sends to a human.

    The Action Shadow score is raised past ``SHADOW_HUMAN_CEILING`` on the
    lowest-loss candidate. ``admissible_in_world`` must then exclude it, and the
    subject's regret must fall to zero because it is the only benchmark left.
    """
    res = resolution()
    field, _, _ = build_field(res)
    world = world_ids_of(res)[0]
    scored = [score(candidate, cones={}, resolution=res) for candidate in field.candidates]
    benchmark = min(scored, key=lambda item: (item.loss(world), item.candidate_id))
    subject = max(scored, key=lambda item: (item.loss(world), item.candidate_id))
    blinded = benchmark.candidate
    high_shadow = ActionShadow(
        candidate_id=blinded.candidate_id,
        unmodelled_dependencies=8,
        uncertain_side_effects=8,
        unobservable_effects=8,
        upstream_truncations=8,
        score=_refusing_shadow_score(),
        # The decomposition must reconstruct the score exactly (Φ's rule), so the
        # four terms are the score split four ways rather than four ones.
        components=dict.fromkeys(SHADOW_TERMS, _refusing_shadow_score() / len(SHADOW_TERMS)),
    )
    refused = ScoredCandidate(
        candidate=CandidateAction(
            **{
                **{
                    field_.name: getattr(blinded, field_.name)
                    for field_ in fields(CandidateAction)
                },
                "shadow": high_shadow,
            }
        ),
        objectives=benchmark.objectives,
        per_world_loss=benchmark.per_world_loss,
    )
    assert not admissible_in_world(refused, world_id=world)
    assert admissible_in_world(benchmark, world_id=world)
    assert regret(subject, world_id=world, all_candidates=[subject, refused]) == pytest.approx(
        0.0
    )
    assert regret(subject, world_id=world, all_candidates=[subject, benchmark]) > 0.0


def test_regret_refuses_when_no_admissible_action_exists() -> None:
    """Returning 0.0 would report 'no regret' for a world where nothing was legal."""
    res = resolution()
    field, _, _ = build_field(res)
    only = score(
        candidate_named(field, "SUSPEND_PROCESS"),
        cones={},
        resolution=res,
        caller_inadmissible=True,
    )
    with pytest.raises(ContractError, match="no admissible hindsight action"):
        regret(only, world_id=world_ids_of(res)[0], all_candidates=[only])


def test_minimax_regret_is_deterministic_and_bounded() -> None:
    res = resolution(
        hypotheses=(
            {
                "mechanism_id": "credential-theft",
                "support": 0.5,
                "consequence": 2.0,
                "uncertainty": 0.2,
                "claim_ids": [],
                "evidence_digests": [EVIDENCE_DIGEST],
            },
            {
                "mechanism_id": "admin-maintenance",
                "support": 0.5,
                "consequence": 0.5,
                "uncertainty": 0.2,
                "claim_ids": [],
                "evidence_digests": [EVIDENCE_DIGEST],
            },
        ),
        consequence_distribution={"credential-theft": 2.0, "admin-maintenance": 0.5},
    )
    field, _, _ = build_field(res)
    scored = [score(candidate, cones={}, resolution=res) for candidate in field.candidates]
    worlds = world_ids_of(res)
    first = minimax_regret(scored, worlds)
    second = minimax_regret(list(reversed(scored)), worlds)
    assert first is not None and second is not None
    assert first.candidate_id == second.candidate_id, "selection must not depend on input order"
    assert minimax_regret([], worlds) is None
    assert minimax_regret(scored, []) is None
    for item in scored:
        for world in worlds:
            assert -1.0 <= regret(item, world_id=world, all_candidates=scored) <= 1.0


def test_the_regret_stage_only_narrows_the_frontier() -> None:
    """SAFE-F07 is a stage, not a second selector: it cannot add a candidate."""
    res = resolution()
    field, _, _ = build_field(res)
    scored = [score(candidate, cones={}, resolution=res) for candidate in field.candidates]
    frontier = pareto_frontier(scored)
    narrowed = minimal_regret_set(frontier, world_ids_of(res))
    assert set(item.candidate_id for item in narrowed) <= set(
        item.candidate_id for item in frontier
    )
    assert narrowed, "the minimal-regret set is never empty for a non-empty frontier"
    assert minimal_regret_set(frontier, []) == tuple(frontier)


# --- D5.9: the scalar control and the selectors ------------------------------


def test_scalar_utility_refuses_incomplete_weights() -> None:
    res = resolution()
    field, _, _ = build_field(res)
    scored = [score(candidate, cones={}, resolution=res) for candidate in field.candidates]
    partial = {objective: 1.0 for objective in Objective if objective is not Objective.SCOPE}
    with pytest.raises(ContractError, match="missing"):
        scalar_utility(scored, partial)
    assert scalar_utility([], DEFAULT_WEIGHTS) is None


def test_default_weights_are_documented_as_arbitrary() -> None:
    """§12's argument is that the weights are arbitrary; the docstring must say so.

    A future reader who quotes ``DEFAULT_WEIGHTS`` as a tuned parameter would be
    quoting a fabrication, so the disclaimer is asserted rather than trusted.
    """
    source = Path(
        inspect.getsourcefile(select) or ""
    ).read_text(encoding="utf-8")
    assert "these weights are arbitrary" in source.lower()
    assert set(DEFAULT_WEIGHTS) == set(Objective)


@pytest.mark.parametrize("selector", list(Selector))
def test_every_selector_returns_a_candidate_and_a_closed_reason_set(
    selector: Selector,
) -> None:
    res = resolution()
    field, _, _ = build_field(res)
    scored = [score(candidate, cones={}, resolution=res) for candidate in field.candidates]
    chosen, rejections = select(scored, selector=selector, world_ids=world_ids_of(res))
    assert chosen is not None
    for record in rejections:
        assert record.reason in REJECTION_REASONS
    if selector is Selector.PARETO_THEN_POLICY:
        assert rejections, "a 14-candidate field must contain a dominated action"
    else:
        assert rejections == (), "a single-stage selector identifies no dominated action"
    assert select([], selector=selector, world_ids=world_ids_of(res)) == (None, ())


def test_pareto_then_policy_and_scalar_utility_can_disagree() -> None:
    """The B6 comparison must be able to differ, or G5.14 would measure nothing.

    Stage 3 built a representation that could not express the thing it existed to
    express. The equivalent check here is that the two selectors are not the same
    function on this corpus: if they always agreed, the B6 ablation delta would be
    structurally zero and reporting it as a result would be meaningless.

    Scored over the **intervention pool** (``operator_class >= FIRST_LEASED_CLASS``),
    because that is the only pool the planner ever runs a selector over for an
    intervention (``AegisPlanner._partition``: observation and intervention are never
    put on one frontier). Integrator note, measured: an earlier version scored the
    whole field, and its disagreements came entirely from *restoration* operators
    (``RESUME_PROCESS``/``RELEASE_*``) that the field wrongly proposed as incident
    responses. With that defect closed, the whole-field selectors agree on all 20
    cases (both pick ``PRESERVE_VOLATILE_EVIDENCE``) and the intervention-pool
    selectors disagree on 10 of the 10 cases that have interventions.
    """
    from pocketsec.stage5.aegis.planner import FIRST_LEASED_CLASS

    disagreements = 0
    for index in range(CORPUS_CASES):
        res = corpus_case(index, leading_support=0.8)
        field, _, _ = build_field(res)
        pool = [
            candidate
            for candidate in field.candidates
            if candidate.operator.spec.operator_class >= FIRST_LEASED_CLASS
        ]
        if not pool:
            continue
        scored = [score(candidate, cones={}, resolution=res) for candidate in pool]
        worlds = world_ids_of(res)
        pareto_choice, _ = select(
            scored, selector=Selector.PARETO_THEN_POLICY, world_ids=worlds
        )
        scalar_choice, _ = select(scored, selector=Selector.SCALAR_UTILITY, world_ids=worlds)
        assert pareto_choice is not None and scalar_choice is not None
        if pareto_choice.candidate_id != scalar_choice.candidate_id:
            disagreements += 1
    assert disagreements > 0, (
        f"the frontier selector and the scalar control agreed on all {CORPUS_CASES} "
        "corpus cases, so B6's ablation delta is structurally zero and no result may "
        "be attributed to it"
    )


def test_policy_pick_prefers_the_reversible_evidence_preserving_action() -> None:
    res = resolution()
    field, _, _ = build_field(res)
    scored = [score(candidate, cones={}, resolution=res) for candidate in field.candidates]
    chosen = policy_pick(pareto_frontier(scored))
    assert chosen is not None
    assert chosen.candidate.reversibility is Reversibility.FULLY_REVERSIBLE
    assert chosen.objectives[Objective.EVIDENCE_LOSS] == pytest.approx(0.0)
    assert policy_pick([]) is None


# --- D5.9: the ablation must never make an action look safer -----------------


def test_ablating_the_cone_does_not_lower_a_harm_score() -> None:
    """Safety monotonicity: ``cones={}`` may only raise, never lower, a harm axis.

    This is the test that would fail if someone "simplified" ``score`` to read the
    cone's degradation instead of taking the maximum. An ablation that made every
    action look cheaper would make G5.14 reward turning the safety machinery off,
    which is the opposite of what an ablation is for.
    """
    from pocketsec.stage5.aegis.cone import build_intervention_cone
    from pocketsec.stage5.aegis.planner import _adaptation_model

    res = resolution()
    host = shadowed_host()
    field, twin, governor = build_field(
        corpus_case(0, leading_support=0.8, pid=9100), host=host
    )
    adaptations = _adaptation_model(host.snapshot())
    world = world_ids_of(corpus_case(0, leading_support=0.8))[0]
    for candidate in field.candidates:
        cone = build_intervention_cone(
            candidate,
            world_id=world,
            twin=twin,
            adaptations=adaptations,
            governor=governor,
        )
        with_cone = score(
            candidate,
            cones={world: cone},
            resolution=corpus_case(0, leading_support=0.8, pid=9100),
        )
        without = score(
            candidate, cones={}, resolution=corpus_case(0, leading_support=0.8, pid=9100)
        )
        for objective in (Objective.COLLATERAL, Objective.ACTION_SHADOW):
            assert with_cone.objectives[objective] >= without.objectives[objective], (
                f"{candidate.candidate_id} scored lower on {objective.value} with a cone "
                "than without one; ablation must never flatter an action"
            )


def test_the_world_key_spaces_are_structurally_identical() -> None:
    """§4.9 Rule A over the three world key spaces AEGIS joins.

    Two waves have shipped a defect where two key spaces were joined that could
    never match. The three keyed by a mechanism id here are ``world_ids_of``, a
    candidate's ``world_applicability`` and a scored candidate's
    ``per_world_loss``; all three must be the same strings.
    """
    for index in range(CORPUS_CASES):
        res = corpus_case(index, leading_support=0.8)
        field, _, _ = build_field(res)
        worlds = set(world_ids_of(res))
        assert worlds, "a resolution with hypotheses must name at least one world"
        for candidate in field.candidates:
            assert candidate.world_applicability <= worlds, (
                f"{candidate.candidate_id} applies to worlds outside the resolution's "
                f"key space: {sorted(candidate.world_applicability - worlds)}"
            )
            scored = score(candidate, cones={}, resolution=res)
            assert set(scored.per_world_loss) == worlds
            for world in worlds:
                assert scored.loss(world) == pytest.approx(scored.per_world_loss[world])
        with pytest.raises(ContractError, match="one world key space"):
            score(field.candidates[0], cones={}, resolution=res).loss("not-a-world")


# --- D5.3: the confidence-invariance property (G5.4a) -----------------------


def test_confidence_099_and_001_reach_the_same_authority() -> None:
    """G5.4(a) and ADR-0003: confidence may change the estimate, never the authority.

    Twenty corpus cases, each emitted twice differing **only** in the leading
    hypothesis's ``support`` (0.99 versus 0.01). What must be identical: the
    chosen candidate's ``authority``, the ``AuthorityClass`` its spec requires,
    and ``human_contract.approval_required``. What is allowed to differ and is
    *not* asserted: ``expected_security_delta``, frontier ordering and the Action
    Shadow score — those are estimates of effect, which is what a belief is for.

    The assertion is the count, because the count is the reportable finding.
    """
    identical = 0
    differing: list[str] = []
    benefit_changed = 0
    for index in range(CORPUS_CASES):
        high = _plan_for(corpus_case(index, leading_support=HIGH_SUPPORT))
        low = _plan_for(corpus_case(index, leading_support=LOW_SUPPORT))
        high_authority = _authority_signature(high)
        low_authority = _authority_signature(low)
        if high_authority == low_authority:
            identical += 1
        else:
            differing.append(f"case {index}: {high_authority} != {low_authority}")
        if _benefit_of(high) != _benefit_of(low):
            benefit_changed += 1
    assert identical == CORPUS_CASES, (
        f"{identical} of {CORPUS_CASES} corpus cases reached the same authority "
        f"decision at support 0.99 and 0.01; differences: {differing}"
    )
    # The test would be vacuous if the two resolutions produced identical plans in
    # every respect, so it also asserts that the benefit estimate *did* move. A
    # pass with zero benefit movement would mean the support value is being ignored
    # entirely rather than being kept out of the authority path.
    assert benefit_changed > 0, (
        "no case changed its expected security benefit between support 0.99 and "
        "0.01, so the invariance result is vacuous"
    )


def _plan_for(res: CBFResolutionV1) -> ResponsePlan:
    """Plan one case with a memory primed for *this* case's mechanisms.

    Priming matters for the invariance claim: a primed operator's
    ``expected_security_delta`` comes from the measured effect rate and is
    therefore support-independent, while an unprimed one's scales with support. The
    two kinds coexist in one field, which is the hardest version of the property —
    and the version the gate will run, since the corpus primes from its own
    replayed receipts.
    """
    host = clean_host()
    return make_planner(
        memory=primed_memory(
            "SUSPEND_PROCESS",
            "RESTRICT_LOCAL_SOCKET",
            mechanism_ids=tuple(world_ids_of(res)),
        )
    ).plan(res, host.snapshot(), now=0, active_leases=())


def test_a_ruled_out_leading_hypothesis_withholds_action_and_never_grants_it() -> None:
    """The single-world case ADR-0003 cares about, in the direction that matters.

    With one world at support 0.01 — below ``RULED_OUT_SUPPORT`` — the SAFE Action
    Field generates no intervention candidate, because no surviving world can be
    cited. The plan must therefore not ACT, and the authority it reaches must be no
    **higher** than at support 0.99.

    That asymmetry is not a violation of ADR-0003; it is the safe half of it. Low
    confidence may withhold action. What ADR-0003 forbids is the other direction —
    high confidence *granting* authority — and
    ``test_confidence_099_and_001_reach_the_same_authority`` is the test for that.
    """
    high = _plan_for(resolution(hypotheses=(_single_hypothesis(HIGH_SUPPORT),)))
    low = _plan_for(resolution(hypotheses=(_single_hypothesis(LOW_SUPPORT),)))
    assert low.decision is not PlanDecision.ACT
    assert low.chosen is not None
    assert authority_rank(low.chosen.authority) <= authority_rank(
        high.chosen.authority if high.chosen is not None else AuthorityClass.AX
    ), "a lower-confidence resolution reached a higher authority than a higher-confidence one"
    assert authority_rank(low.chosen.authority) <= authority_rank(MAX_AUTONOMOUS_AUTHORITY)


def test_the_benefit_floor_never_removes_the_best_intervention() -> None:
    """The construction behind G5.4: ``floor = fraction * max``, so the argmax survives.

    Built as a mutation-sensitive test, because the twenty-case invariance test is
    not: replacing the relative floor with an absolute ``required_risk_reduction``
    leaves that test passing on this corpus (measured), so the construction needs a
    check of its own.

    The resolution here has every support at 0.30, which puts the *best* available
    intervention benefit below ``required_risk_reduction``. Under a relative floor it
    survives; under an absolute floor every intervention is refused as
    INSUFFICIENT_BENEFIT and the plan silently becomes an observation — model
    confidence deciding whether the system may act at all.
    """
    res = resolution(
        hypotheses=(
            {
                "mechanism_id": "credential-theft",
                "support": 0.30,
                "consequence": 2.0,
                "uncertainty": 0.20,
                "claim_ids": [],
                "evidence_digests": [EVIDENCE_DIGEST],
            },
        )
    )
    field, _, _ = build_field(res)
    interventions = [
        candidate
        for candidate in field.candidates
        if candidate.operator.spec.operator_class >= OperatorClass.O2_REVERSIBLE_RESTRICT
    ]
    assert interventions, "the fixture must generate at least one intervention"
    best = max(interventions, key=lambda c: (c.expected_security_delta, c.candidate_id))
    config = PlannerConfig()
    assert best.expected_security_delta < config.required_risk_reduction, (
        f"fixture invalid: best intervention benefit {best.expected_security_delta} is not "
        f"below the floor value {config.required_risk_reduction}"
    )
    plan = make_planner(config=config).plan(
        res, clean_host().snapshot(), now=0, active_leases=()
    )
    starved = {
        record.candidate_id
        for record in plan.rejected
        if record.reason == "INSUFFICIENT_BENEFIT"
    }
    assert best.candidate_id not in starved, (
        f"{best.candidate_id} is the best intervention available and was refused for "
        "insufficient benefit; the floor must be a fraction of the maximum, never an "
        "absolute value, or the ACT decision becomes a function of model confidence"
    )
    assert len(starved) < len(interventions), (
        "every intervention was starved by the benefit floor, so no action could be "
        "taken at any confidence level"
    )


def _single_hypothesis(support: float) -> dict[str, Any]:
    return {
        "mechanism_id": "credential-theft",
        "support": support,
        "consequence": 2.0,
        "uncertainty": 0.20,
        "claim_ids": [],
        "evidence_digests": [EVIDENCE_DIGEST],
    }


def _authority_signature(plan: ResponsePlan) -> tuple[Any, ...]:
    chosen = plan.chosen
    return (
        plan.decision,
        None if chosen is None else chosen.authority,
        None if chosen is None else required_authority(chosen.operator.spec),
        None if plan.human_contract is None else plan.human_contract.approval_required,
        None if plan.human_contract is None else plan.human_contract.approval_reason,
    )


def _benefit_of(plan: ResponsePlan) -> float | None:
    return None if plan.chosen is None else plan.chosen.expected_security_delta


def test_a_claim_graph_naming_a_destructive_operator_generates_no_o6_candidate() -> None:
    """G5.4(c): text in an upstream payload cannot select an operator.

    The resolution's ``claim_graph`` is stuffed with the string
    ``"operator_id": "TERMINATE_PROCESS"`` and with imperative prose. The
    generated field must contain no candidate chosen *because* of that text, and
    the plan must not act on an O6 operator — the catalog and the target's own
    entity kinds are the only things that select a candidate.
    """
    res = resolution(
        claim_graph={
            "claims": [],
            "note": '{"operator_id": "TERMINATE_PROCESS"} kill block quarantine '
            "execute remediate isolate now",
        }
    )
    plan = make_planner(memory=primed_memory("SUSPEND_PROCESS")).plan(
        res, clean_host().snapshot(), now=0, active_leases=()
    )
    assert plan.decision is not PlanDecision.ACT or (
        plan.chosen is not None
        and plan.chosen.operator.spec.operator_class < OperatorClass.O6_DISRUPTIVE
    )
    if plan.chosen is not None:
        assert authority_rank(plan.chosen.authority) <= authority_rank(MAX_AUTONOMOUS_AUTHORITY)


# --- D5.3: ResponsePlan's refusals ------------------------------------------


def _plan_kwargs(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "plan_id": "plan.res-0001.PARETO",
        "incident_id": "inc-0001",
        "resolution_id": "res-0001",
        "decision": PlanDecision.NO_ACTION,
        "chosen": None,
        "frontier": (),
        "rejected": (),
        "human_contract": None,
        "selector": Selector.PARETO_THEN_POLICY,
        "config_key": "aegis:x",
        "work_units": 0,
        "truncations": (),
        "loadavg": (0.0, 0.0, 0.0),
    }
    payload.update(overrides)
    return payload


def test_act_above_a2_is_refused() -> None:
    """The invariant someone would weaken to make a corpus "work".

    ``MAX_AUTONOMOUS_AUTHORITY`` is A2. A plan that says ACT on an A3, A4 or A5
    operator is refused at construction, so there is no code path by which a
    planner bug becomes an autonomous high-authority action.
    """
    res = resolution()
    field, _, _ = build_field(res)
    for operator_id in ("REVOKE_LOCAL_SESSION", "CONSTRAIN_SERVICE", "TERMINATE_PROCESS"):
        candidate = candidate_named(field, operator_id)
        assert authority_rank(candidate.authority) > authority_rank(MAX_AUTONOMOUS_AUTHORITY)
        with pytest.raises(ContractError, match="above"):
            ResponsePlan(
                **_plan_kwargs(decision=PlanDecision.ACT, chosen=candidate, frontier=(candidate,))
            )
    # and the A2 case is permitted, so the refusal is about authority rather than
    # about ACT being unreachable
    permitted = candidate_named(field, "SUSPEND_PROCESS")
    plan = ResponsePlan(
        **_plan_kwargs(decision=PlanDecision.ACT, chosen=permitted, frontier=(permitted,))
    )
    assert plan.decision is PlanDecision.ACT


def test_act_with_no_chosen_candidate_is_refused() -> None:
    with pytest.raises(ContractError, match="chosen=None"):
        ResponsePlan(**_plan_kwargs(decision=PlanDecision.ACT))


@pytest.mark.parametrize("decision", [PlanDecision.ESCALATE, PlanDecision.DEFER])
def test_escalate_without_a_contract_is_refused(decision: PlanDecision) -> None:
    """An escalation with no decision structure is a notification (§32)."""
    res = resolution()
    field, _, _ = build_field(res)
    candidate = candidate_named(field, "TERMINATE_PROCESS")
    with pytest.raises(ContractError, match="notification"):
        ResponsePlan(**_plan_kwargs(decision=decision, chosen=candidate))
    contract = build_contract(
        field.candidates,
        candidate,
        resolution=res,
        constitution=FROZEN_CONSTITUTION,
        shadow_eligibility=AutonomyEligibility.ELIGIBLE,
    )
    plan = ResponsePlan(
        **_plan_kwargs(decision=decision, chosen=candidate, human_contract=contract)
    )
    assert plan.human_contract is contract


def test_a_plan_cannot_carry_an_unknown_rejection_reason() -> None:
    with pytest.raises(ContractError, match="REJECTION_REASONS"):
        RejectionRecord(candidate_id="cand00.X", reason="BECAUSE_I_SAID_SO", detail="")
    assert RejectionRecord(candidate_id="cand00.X", reason="DOMINATED", detail="").to_dict()[
        "reason"
    ] == "DOMINATED"


# --- D5.3: the decisions, each one reachable --------------------------------


def test_act_is_reachable_only_with_measured_rollback_reliability() -> None:
    """G5.7 as a planning constraint: ``None`` blocks autonomy.

    Two runs, identical but for the effectiveness memory. The operators that
    ``requires_lease`` identifies — the ones that leave something a rollback must
    reclaim — are refused with reason RELIABILITY when the memory holds fewer than
    ``MIN_SAMPLES_FOR_RATE`` rollback attempts, and become choosable when it does.

    Asserted on ``requires_lease`` rather than on the operator class, because a
    *restoration* operator such as ``RESUME_PROCESS`` is O3 but needs no rollback
    of its own, and demanding rollback statistics before the system may undo its
    own action would make the safest operator the hardest to reach.
    """
    from pocketsec.stage5.executor.lease import requires_lease

    res = resolution()
    host = clean_host()
    unprimed = make_planner().plan(res, host.snapshot(), now=0, active_leases=())
    assert "RELIABILITY" in unprimed.rejections_by_reason()
    refused = {
        record.candidate_id for record in unprimed.rejected if record.reason == "RELIABILITY"
    }
    assert refused, "no candidate was refused for reliability"
    # With no measured rollback reliability nothing that needs a rollback may be
    # carried autonomously. Integrator note: this used to read "if a candidate is
    # chosen it needs no lease", which held only because the field proposed
    # restoration operators (RELEASE_LOCAL_SOCKET) as incident responses and the
    # planner ACTed on one. With that defect closed the unprimed plan escalates to a
    # person instead, which is the property this test names, asserted directly.
    assert unprimed.decision is not PlanDecision.ACT, unprimed.decision
    if unprimed.chosen is not None:
        assert unprimed.chosen.candidate_id not in refused
        if requires_lease(unprimed.chosen.operator.spec):
            assert unprimed.decision is PlanDecision.ESCALATE
            assert unprimed.human_contract is not None
            assert authority_rank(unprimed.chosen.authority) > authority_rank(
                MAX_AUTONOMOUS_AUTHORITY
            ), "a leased operator reached a person without being above the autonomy ceiling"

    primed = make_planner(
        memory=primed_memory("SUSPEND_PROCESS", "RESTRICT_LOCAL_SOCKET")
    ).plan(res, host.snapshot(), now=0, active_leases=())
    assert primed.decision is PlanDecision.ACT
    assert primed.chosen is not None
    assert requires_lease(primed.chosen.operator.spec), primed.chosen.candidate_id
    assert "RELIABILITY" not in primed.rejections_by_reason()
    assert authority_rank(primed.chosen.authority) <= authority_rank(MAX_AUTONOMOUS_AUTHORITY)
    assert primed.human_contract is None


def test_an_unprimed_memory_reports_none_rather_than_a_default() -> None:
    """``None`` blocks autonomy; 0.0 or 1.0 would each be a fabricated measurement."""
    memory = EffectivenessMemory()
    assert memory.rollback_reliability(operator_id="SUSPEND_PROCESS", epoch_id=1) is None
    assert (
        memory.meets_threshold(
            operator_id="SUSPEND_PROCESS",
            epoch_id=1,
            threshold=AUTONOMOUS_ROLLBACK_THRESHOLD,
        )
        is None
    )
    primed = primed_memory("SUSPEND_PROCESS")
    assert primed.rollback_reliability(operator_id="SUSPEND_PROCESS", epoch_id=1) == 1.0


def test_a_high_shadow_host_refuses_every_intervention() -> None:
    """The conservative path: unmodelled dependencies cost autonomy, not benefit.

    On ``shadowed_host`` the twin cannot model four dependencies, Action Shadow
    rises past ``SHADOW_AUTONOMY_CEILING``, and the plan must not ACT. The
    rejections must name SHADOW, so the refusal is attributable rather than a
    silent absence.
    """
    res = corpus_case(0, leading_support=0.9, pid=9100)
    plan = make_planner(
        memory=primed_memory(
            "SUSPEND_PROCESS", mechanism_ids=tuple(world_ids_of(res))
        )
    ).plan(res, shadowed_host().snapshot(), now=0, active_leases=())
    assert plan.decision is not PlanDecision.ACT
    assert "SHADOW" in plan.rejections_by_reason()


def test_no_action_is_reachable_and_is_not_an_exception() -> None:
    """§2's ``NO_ACTION_IS_ALWAYS_AVAILABLE``, made a reachable outcome.

    Every candidate is made harmful in every world by a total :class:`HarmModel`,
    so response identifiability refuses all of them. The planner must return
    ``NO_ACTION`` with ``chosen=None`` and a rejection per candidate, not raise.
    """
    res = resolution()
    field, _, _ = build_field(res)
    total_harm = HarmModel(
        unacceptable=frozenset(
            (world, spec.operator_class)
            for world in world_ids_of(res)
            for spec in CATALOG.values()
        )
    )
    plan = make_planner(harm=total_harm).plan(
        res, clean_host().snapshot(), now=0, active_leases=()
    )
    assert plan.decision is PlanDecision.NO_ACTION
    assert plan.chosen is None
    assert plan.rejections_by_reason().get("NOT_IDENTIFIABLE", 0) == len(field.candidates)
    # NO_ACTION still carries the decision structure, because "the system declined
    # to act on your incident" is the case a human most needs it for.
    assert plan.human_contract is not None
    assert plan.human_contract.approval_reason == "NO_ADMISSIBLE_ACTION"


def test_a_mission_invariant_violation_refuses_the_candidate() -> None:
    """G5.8: mission invariants are machine-enforced, and the refusal is recorded.

    A stricter profile than ``mission_profile`` — the fixture's only unit is
    declared a critical service — must make every interrupting operator
    inadmissible. Three assertions, because the refusal happens in two layers and
    both must hold:

    1. end to end, the plan does not intervene and nothing above O1 is chosen;
    2. the refusal is **recorded** as a truncation naming the invariant id (§G5.8
       requires the refusal to be auditable, not merely effective);
    3. the planner's own :meth:`_authority_outcome` refuses independently when
       handed a violation, so the planner is not relying on the generator having
       filtered first. Defence in depth, and each layer tested where it lives.
    """
    strict = MissionInvariantSet(
        invariants=(
            *mission_profile().invariants,
            MissionInvariant(
                invariant_id="MI-TEST-CRIT",
                kind=InvariantKind.CRITICAL_SERVICE,
                subject="app.service",
                bound_seconds=None,
                detail="the fixture's only unit is declared critical",
            ),
        )
    )
    res = resolution()
    snapshot = clean_host().snapshot()
    planner = make_planner(
        invariants=strict, memory=primed_memory("SUSPEND_PROCESS", "RESTRICT_LOCAL_SOCKET")
    )
    plan = planner.plan(res, snapshot, now=0, active_leases=())
    assert plan.decision is PlanDecision.OBSERVE, plan.rejections_by_reason()
    assert plan.chosen is not None
    assert plan.chosen.operator.spec.operator_class in {
        OperatorClass.O0_OBSERVE,
        OperatorClass.O1_PRESERVE,
    }
    recorded = [row for row in plan.truncations if "MI-TEST-CRIT" in row.reason]
    assert recorded, [row.reason for row in plan.truncations]

    # Layer three: the planner's own authority computation, handed a violation.
    violation = strict.violations(
        operator=_operator_for("SUSPEND_PROCESS", snapshot),
        lease_ttl_seconds=300,
        snapshot=snapshot,
    )
    assert violation, "the fixture must actually violate the added invariant"
    outcome = planner._authority_outcome(
        spec=CATALOG["SUSPEND_PROCESS"],
        rollback_reliability=1.0,
        eligibility=AutonomyEligibility.ELIGIBLE,
        invariant_violations=violation,
    )
    assert outcome.reason == "MISSION_INVARIANT"
    assert outcome.autonomous_eligible is False


def _operator_for(operator_id: str, snapshot: Any, *, pid: int = 4242) -> DefensiveOperator:
    """A typed operator for the fixture's process, built from the catalog entry.

    Built through ``CATALOG[...]`` rather than by constructing an ``OperatorSpec``,
    because an ``OperatorSpec`` cannot be built outside ``catalog.py`` — which is
    the property G5.2 exists to keep.
    """
    spec = CATALOG[operator_id]
    subject = {
        TargetKind.PROCESS: str(pid),
        TargetKind.SERVICE: "app.service",
        TargetKind.SESSION: "sess-1",
        TargetKind.SOCKET: "sock-1",
        TargetKind.HOST: "host",
    }[spec.target_kind]
    return DefensiveOperator(
        spec=spec,
        target=ProcessTarget(
            identity=identity(pid),
            scope=TargetScope(kind=spec.target_kind, subject=subject),
        ),
        incident_id="inc-0001",
        ttl_seconds=min(300, spec.max_duration_seconds),
        evidence_refs=(),
    )


def test_hysteresis_hold_defers_an_intervention_but_never_observation() -> None:
    """§19's controller stops thrashing; it must not be able to stop monitoring.

    The controller is driven into a cooldown by acting once, then the same
    incident is planned again. The intervention must become ``DEFER`` with a
    contract; and a planner whose only admissible candidates are observations must
    still return ``OBSERVE``, never ``DEFER``.
    """
    res = resolution()
    host = clean_host()
    clock = ManualClock(0)
    controller = HysteresisController(policy=DEFAULT_HYSTERESIS, clock=clock)
    memory = primed_memory("SUSPEND_PROCESS", "RESTRICT_LOCAL_SOCKET")
    first = make_planner(memory=memory, hysteresis=controller).plan(
        res, host.snapshot(), now=0, active_leases=()
    )
    assert first.decision is PlanDecision.ACT
    # An intervention is already in force on this target. A second one must wait for
    # the lease to resolve rather than stacking, which is the oscillation §19 stops.
    second = make_planner(memory=memory, hysteresis=controller).plan(
        res, host.snapshot(), now=1, active_leases=(lease_on_target(),)
    )
    assert second.decision is PlanDecision.DEFER
    assert second.human_contract is not None
    assert "HYSTERESIS" in second.rejections_by_reason()

    # A planner whose only admissible candidates are observations must not have
    # them turned into a DEFER by the same controller state: §2's
    # FAILURE_MUST_NOT_STOP_MONITORING.
    observe_only_harm = HarmModel(
        unacceptable=frozenset(
            (world, operator_class)
            for world in world_ids_of(res)
            for operator_class in OperatorClass
            if operator_class >= OperatorClass.O2_REVERSIBLE_RESTRICT
        )
    )
    watcher = HysteresisController(policy=DEFAULT_HYSTERESIS, clock=ManualClock(0))
    for step in range(2):
        plan = make_planner(harm=observe_only_harm, hysteresis=watcher).plan(
            res, host.snapshot(), now=step, active_leases=()
        )
        assert plan.decision is PlanDecision.OBSERVE, plan.rejections_by_reason()


def test_the_no_hysteresis_ablation_acts_every_time() -> None:
    """§7's B8 control. Turning the controller off must change behaviour."""
    res = resolution()
    host = clean_host()
    config = PlannerConfig(enable_hysteresis=False)
    memory = primed_memory("SUSPEND_PROCESS", "RESTRICT_LOCAL_SOCKET")
    leases = (lease_on_target(),)
    controller = HysteresisController(policy=DEFAULT_HYSTERESIS, clock=ManualClock(0))
    decisions = [
        make_planner(config=config, memory=memory, hysteresis=controller)
        .plan(res, host.snapshot(), now=step, active_leases=leases)
        .decision
        for step in range(3)
    ]
    assert decisions == [PlanDecision.ACT] * 3, decisions
    # The control must differ from the controlled, or B8's ablation delta would be
    # structurally zero and reporting it would be meaningless (Stage 3's lesson).
    on_controller = HysteresisController(policy=DEFAULT_HYSTERESIS, clock=ManualClock(0))
    with_hysteresis = [
        make_planner(memory=memory, hysteresis=on_controller)
        .plan(res, host.snapshot(), now=step, active_leases=leases)
        .decision
        for step in range(3)
    ]
    assert with_hysteresis == [PlanDecision.DEFER] * 3, with_hysteresis
    assert with_hysteresis != decisions


def test_the_controller_escalates_after_max_action_cycles() -> None:
    """§19: repeated cycles on one target stop being an action and become a question.

    The controller counts cycles from receipts, which only the privileged side
    produces, so the fixture feeds it three of them directly. After
    ``max_action_cycles`` the planner must ESCALATE with a contract rather than
    acting a fourth time.
    """
    res = resolution()
    controller = HysteresisController(policy=DEFAULT_HYSTERESIS, clock=ManualClock(0))
    for index in range(DEFAULT_HYSTERESIS.max_action_cycles):
        controller.note_outcome(
            receipt_for("SUSPEND_PROCESS", index=index, rolled_back=False)
        )
    assert controller.cycles(identity(4242).digest()) == DEFAULT_HYSTERESIS.max_action_cycles
    plan = make_planner(
        memory=primed_memory("SUSPEND_PROCESS", "RESTRICT_LOCAL_SOCKET"),
        hysteresis=controller,
    ).plan(res, clean_host().snapshot(), now=10, active_leases=())
    assert plan.decision is PlanDecision.ESCALATE
    assert plan.human_contract is not None


def test_rollback_is_reached_when_the_trajectory_falls_with_a_live_lease() -> None:
    """``PlanDecision.ROLLBACK`` is reachable, and only with a lease to release.

    Φ on the fixture's ``SecurityStateV1()`` is below the controller's exit
    threshold, so the controller returns RELEASE. With an active lease on the
    chosen target the plan is ROLLBACK; without one it must not be, because there
    would be nothing to roll back.
    """
    res = resolution()
    host = clean_host()
    memory = primed_memory("SUSPEND_PROCESS", "RESTRICT_LOCAL_SOCKET")
    target_digest = identity(4242).digest()
    lease = Lease(
        lease_id="lease-1",
        action_id="act-1",
        incident_id="inc-0001",
        operator_id="SUSPEND_PROCESS",
        target_digest=target_digest,
        granted_at=0,
        ttl_seconds=300,
        maximum_lifetime_seconds=3600,
        renewals=0,
        rollback_operator_id="RESUME_PROCESS",
    )
    clock = ManualClock(0)
    controller = HysteresisController(policy=DEFAULT_HYSTERESIS, clock=clock)
    acted = make_planner(memory=memory, hysteresis=controller).plan(
        res, host.snapshot(), now=0, active_leases=()
    )
    assert acted.decision is PlanDecision.ACT
    # The threat recedes: Φ falls below the controller's exit threshold.
    calm = clean_host(security_state=CALM_STATE)
    clock.advance(DEFAULT_HYSTERESIS.min_dwell_seconds + 1)
    with_lease = make_planner(memory=memory, hysteresis=controller).plan(
        res, calm.snapshot(), now=clock.now(), active_leases=(lease,)
    )
    assert with_lease.decision is PlanDecision.ROLLBACK
    assert with_lease.human_contract is None
    # Without a lease there is nothing to release, so ROLLBACK must not be claimed.
    without_lease = make_planner(memory=memory, hysteresis=controller).plan(
        res, calm.snapshot(), now=clock.now(), active_leases=()
    )
    assert without_lease.decision is not PlanDecision.ROLLBACK


def test_the_fixture_states_bracket_the_hysteresis_thresholds() -> None:
    """The fixtures' Φ values are measured here, so a Stage 1 change fails loudly.

    Every intervention test in this file depends on ``ESCALATED_STATE`` sitting
    above ``enter_threshold`` and ``CALM_STATE`` sitting below ``exit_threshold``.
    If Stage 1 reweights Φ, this test fails instead of every ACT test silently
    measuring the HOLD path and passing for the wrong reason.
    """
    escalated = phi(ESCALATED_STATE).total
    calm = phi(CALM_STATE).total
    assert escalated > DEFAULT_HYSTERESIS.enter_threshold, escalated
    assert calm < DEFAULT_HYSTERESIS.exit_threshold, calm


def test_escalate_names_the_binding_reason_for_a_high_authority_proposal() -> None:
    """An A5 operator cannot be autonomous, and the contract must say which reason."""
    res = resolution()
    total_harm = HarmModel(
        unacceptable=frozenset(
            (world, operator_class)
            for world in world_ids_of(res)
            for operator_class in (
                OperatorClass.O0_OBSERVE,
                OperatorClass.O1_PRESERVE,
                OperatorClass.O2_REVERSIBLE_RESTRICT,
                OperatorClass.O3_SUSPEND,
            )
        )
    )
    plan = make_planner(harm=total_harm).plan(
        res, clean_host().snapshot(), now=0, active_leases=()
    )
    assert plan.decision is PlanDecision.ESCALATE
    assert plan.human_contract is not None
    assert plan.human_contract.approval_required is True
    assert plan.human_contract.approval_reason in APPROVAL_REASONS
    assert plan.chosen is not None
    assert authority_rank(plan.chosen.authority) > authority_rank(MAX_AUTONOMOUS_AUTHORITY)


def test_a_budget_exhausted_governor_escalates_rather_than_widening_a_cap() -> None:
    """D5.23: on exhaustion the caller escalates. Nothing relaxes a safety constraint."""
    tiny = ResourceGovernor(budget=ResourceBudget(max_work_units=1))
    plan = make_planner(
        governor=tiny, memory=primed_memory("SUSPEND_PROCESS", "RESTRICT_LOCAL_SOCKET")
    ).plan(resolution(), clean_host().snapshot(), now=0, active_leases=())
    assert plan.decision in {PlanDecision.ESCALATE, PlanDecision.NO_ACTION}
    assert "BUDGET" in plan.rejections_by_reason()
    assert tiny.escalation() is not None
    assert tiny.spend_report()["TOTAL"] <= 1


# --- D5.3: PlannerConfig and the ablation table ------------------------------


def test_every_planner_config_flag_appears_in_core_ids_ablation_flags() -> None:
    """§5: an ablation is a flag the gate sets, never a code edit.

    Both directions, and the one exception is pinned rather than allowed to grow:
    every ``core_ids.ABLATION_FLAGS`` value must be a ``PlannerConfig`` field, and
    every ``PlannerConfig`` ablation flag must be in ``ABLATION_FLAGS`` except the
    members of :data:`UNMAPPED_PLANNER_FLAGS`. A *second* unmapped flag therefore
    fails this test instead of joining the first.
    """
    config_flags = set(ABLATION_FLAG_FIELDS)
    table_flags = set(ABLATION_FLAGS.values())
    assert table_flags <= config_flags, (
        f"core_ids names flags PlannerConfig does not carry: {sorted(table_flags - config_flags)}"
    )
    assert config_flags - table_flags == set(UNMAPPED_PLANNER_FLAGS), (
        "PlannerConfig carries an ablation flag no SAFE-F id names: "
        f"{sorted(config_flags - table_flags - UNMAPPED_PLANNER_FLAGS)}"
    )
    assert set(ABLATION_FLAGS) <= set(OPTIONAL_IDS)
    for core_id, flag in ABLATION_FLAGS.items():
        assert hasattr(PlannerConfig(), flag), f"{core_id} names a missing flag {flag!r}"


def test_the_ablation_key_is_deterministic_and_distinguishes_every_flag() -> None:
    base = PlannerConfig()
    assert base.as_ablation_key() == PlannerConfig().as_ablation_key()
    keys = {base.as_ablation_key()}
    for flag in ABLATION_FLAG_FIELDS:
        if flag == "enable_pareto":
            variant = PlannerConfig(enable_pareto=False, selector=Selector.SCALAR_UTILITY)
        else:
            variant = PlannerConfig(**{flag: False})
        key = variant.as_ablation_key()
        assert key not in keys, f"{flag} does not change the ablation key"
        keys.add(key)
    assert len(keys) == len(ABLATION_FLAG_FIELDS) + 1


def test_a_config_whose_selector_contradicts_its_pareto_flag_is_refused() -> None:
    """A delta attributed to the wrong mechanism is worse than no delta."""
    with pytest.raises(ContractError, match="non-Pareto selector"):
        PlannerConfig(enable_pareto=False)
    with pytest.raises(ContractError, match="ambiguous"):
        PlannerConfig(selector=Selector.MINIMAX_REGRET)
    assert PlannerConfig(enable_pareto=False, selector=Selector.SCALAR_UTILITY).selector is (
        Selector.SCALAR_UTILITY
    )


def test_the_single_world_ablation_keeps_only_the_leading_hypothesis() -> None:
    """§7's B7 control, and it must actually narrow the world set."""
    res = corpus_case(1, leading_support=0.9)
    assert len(world_ids_of(res)) == 3
    multi = make_planner()
    single = make_planner(config=PlannerConfig(enable_multi_world=False))
    assert len(multi._worlds(res)) == 3
    narrowed = single._worlds(res)
    assert len(narrowed) == 1
    assert narrowed[0] == world_ids_of(res)[0]


@pytest.mark.parametrize("bad", [-0.1, 1.1])
def test_a_required_risk_reduction_outside_the_unit_interval_is_refused(bad: float) -> None:
    with pytest.raises(ContractError):
        PlannerConfig(required_risk_reduction=bad)


# --- D5.9b: the human decision contract -------------------------------------


def _contract_for(operator_id: str = "TERMINATE_PROCESS") -> HumanDecisionContract:
    res = resolution()
    field, _, _ = build_field(res)
    return build_contract(
        field.candidates,
        candidate_named(field, operator_id),
        resolution=res,
        constitution=FROZEN_CONSTITUTION,
        shadow_eligibility=AutonomyEligibility.ELIGIBLE,
        collateral_units=("app.service",),
        preserved_signals=("socket_table",),
    )


def test_render_is_deterministic() -> None:
    """Two calls, byte-compared. A contract that varies is a contract nobody can diff."""
    contract = _contract_for()
    first = contract.render().encode("utf-8")
    second = contract.render().encode("utf-8")
    assert first == second
    assert len(first) <= MAX_CONTRACT_BYTES
    rebuilt = _contract_for()
    assert rebuilt.render().encode("utf-8") == first, (
        "two contracts built from the same inputs rendered differently"
    )
    for heading in CONTRACT_HEADINGS:
        assert f"{heading}:" in contract.render()


def test_contract_carries_no_free_text() -> None:
    """Every string field is a catalog id, a digest or a closed-vocabulary member.

    This is the test that would fail if someone added a ``rationale`` or
    ``summary`` field: §32's contract shows the decision structure, and a
    generated sentence in it would be the natural-language-to-privilege path
    ADR-0003 forbids, laundered through an approval click.
    """
    contract = _contract_for()
    assert contract.proposal_operator_id in CATALOG
    assert contract.proposal_target_digest.startswith("sha256:")
    assert contract.approval_reason in APPROVAL_REASONS
    if contract.rollback_operator_id is not None:
        assert contract.rollback_operator_id in CATALOG
    if contract.safer_alternative_id is not None:
        assert contract.safer_alternative_id in CATALOG
    for token in (*contract.collateral_units, *contract.evidence_preserved):
        assert CONTRACT_TOKEN_RE.fullmatch(token), token
    for effect in contract.world_effects:
        assert effect.predicted_security_effect in SECURITY_EFFECTS
        assert effect.predicted_operational_effect in OPERATIONAL_EFFECTS
        assert CONTRACT_TOKEN_RE.fullmatch(effect.mechanism_id)
    # No field in the dataclass may be named like prose.
    names = {field_.name for field_ in fields(HumanDecisionContract)}
    assert not names & {"detail", "summary", "rationale", "recommendation", "narrative"}


def test_a_contract_with_a_free_text_token_is_refused() -> None:
    for bad in ("kill -9 1234", "rm rf /", "a b", "; reboot", "$(whoami)"):
        with pytest.raises(ContractError, match="CONTRACT_TOKEN_RE"):
            WorldEffect(
                mechanism_id=bad,
                support=0.5,
                predicted_security_effect="CONTAINS",
                predicted_operational_effect="NONE",
                harmful=False,
            )


def test_a_world_effect_outside_the_closed_vocabulary_is_refused() -> None:
    with pytest.raises(ContractError, match="SECURITY_EFFECTS"):
        WorldEffect(
            mechanism_id="mech-1",
            support=0.5,
            predicted_security_effect="probably fine",
            predicted_operational_effect="NONE",
            harmful=False,
        )
    with pytest.raises(ContractError, match="OPERATIONAL_EFFECTS"):
        WorldEffect(
            mechanism_id="mech-1",
            support=0.5,
            predicted_security_effect="CONTAINS",
            predicted_operational_effect="a bit slow",
            harmful=False,
        )


def _contract_kwargs(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "proposal_operator_id": "SUSPEND_PROCESS",
        "proposal_target_digest": identity(4242).digest(),
        "world_effects": (),
        "expected_benefit": 0.4,
        "collateral_units": ("app.service",),
        "action_shadow": 0.2,
        "evidence_preserved": ("socket_table",),
        "rollback_operator_id": "RESUME_PROCESS",
        "lease_ttl_seconds": 300,
        "approval_required": False,
        "approval_reason": NO_APPROVAL_REQUIRED,
        "safer_alternative_id": None,
    }
    payload.update(overrides)
    return payload


def test_the_two_approval_fields_must_agree() -> None:
    """A contract cannot ask for approval while stating no reason, or the reverse."""
    with pytest.raises(ContractError, match="contradicts"):
        HumanDecisionContract(**_contract_kwargs(approval_required=True))
    with pytest.raises(ContractError, match="contradicts"):
        HumanDecisionContract(
            **_contract_kwargs(
                approval_required=False, approval_reason="AUTHORITY_ABOVE_AUTONOMOUS_CEILING"
            )
        )
    ok = HumanDecisionContract(
        **_contract_kwargs(
            approval_required=True, approval_reason="AUTHORITY_ABOVE_AUTONOMOUS_CEILING"
        )
    )
    assert ok.approval_required is True


def test_a_contract_naming_an_operator_outside_the_catalog_is_refused() -> None:
    with pytest.raises(ContractError, match="CATALOG operator id"):
        HumanDecisionContract(**_contract_kwargs(proposal_operator_id="RM_MINUS_RF"))
    with pytest.raises(ContractError, match="CATALOG operator id"):
        HumanDecisionContract(**_contract_kwargs(rollback_operator_id="UNDO_EVERYTHING"))


def test_a_contract_without_a_digest_target_is_refused() -> None:
    """A pid is not an identity (§17), and a contract may not name one."""
    with pytest.raises(ContractError, match="sha256 digest"):
        HumanDecisionContract(**_contract_kwargs(proposal_target_digest="4242"))


def test_an_over_long_contract_is_refused_rather_than_truncated() -> None:
    """A silently-truncated escalation is one whose missing line was the important one."""
    with pytest.raises(ContractError, match="MAX_CONTRACT_LIST_ITEMS"):
        HumanDecisionContract(
            **_contract_kwargs(
                collateral_units=tuple(
                    f"unit{index}.service" for index in range(MAX_CONTRACT_LIST_ITEMS + 1)
                )
            )
        )
    many = tuple(
        WorldEffect(
            mechanism_id=f"mech-{index:02d}",
            support=0.5,
            predicted_security_effect="UNKNOWN",
            predicted_operational_effect="UNKNOWN",
            harmful=False,
        )
        for index in range(17)
    )
    with pytest.raises(ContractError, match="MAX_WORLD_EFFECTS"):
        HumanDecisionContract(**_contract_kwargs(world_effects=many))


def test_the_contract_never_reports_evidence_it_would_destroy_as_preserved() -> None:
    """Preservation is derived by subtraction, in the direction that cannot overstate.

    ``SUSPEND_PROCESS`` degrades volatile evidence, so even when the caller offers
    a signal list the contract must report nothing preserved. ``HASH_EXECUTABLE``
    preserves, so the same signal list survives.
    """
    res = resolution()
    field, _, _ = build_field(res)
    degrading = build_contract(
        field.candidates,
        candidate_named(field, "SUSPEND_PROCESS"),
        resolution=res,
        constitution=FROZEN_CONSTITUTION,
        shadow_eligibility=AutonomyEligibility.ELIGIBLE,
        preserved_signals=("socket_table",),
    )
    assert degrading.evidence_preserved == ()
    preserving = build_contract(
        field.candidates,
        candidate_named(field, "HASH_EXECUTABLE"),
        resolution=res,
        constitution=FROZEN_CONSTITUTION,
        shadow_eligibility=AutonomyEligibility.ELIGIBLE,
        preserved_signals=("socket_table",),
    )
    assert preserving.evidence_preserved == ("socket_table",)


def test_build_contract_refuses_an_empty_field() -> None:
    with pytest.raises(ContractError, match="at least one candidate"):
        build_contract(
            (),
            None,
            resolution=resolution(),
            constitution=FROZEN_CONSTITUTION,
            shadow_eligibility=AutonomyEligibility.ELIGIBLE,
        )


def test_the_contract_module_holds_no_model_and_no_generator() -> None:
    """§32: nothing here is generated text, so nothing here may look like a generator."""
    source = Path(contract_module.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imports |= {
        (node.module or "").split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert "random" not in imports
    assert "time" not in imports
    for name, _ in _defined_names(Path(contract_module.__file__)):
        assert "generate" not in name.lower()
        assert "recommend" not in name.lower()


# --- the plan's own bookkeeping ---------------------------------------------


def test_a_plan_serialises_to_json_shaped_rows_and_carries_loadavg() -> None:
    """Every figure a plan reports is comparable only beside the load that produced it."""
    plan = make_planner(memory=primed_memory("SUSPEND_PROCESS")).plan(
        resolution(), clean_host().snapshot(), now=0, active_leases=()
    )
    payload = plan.to_dict()
    assert payload["decision"] == plan.decision.value
    assert payload["config_key"] == plan.config_key
    assert len(payload["loadavg"]) == 3
    assert all(value >= 0.0 for value in payload["loadavg"])
    assert payload["work_units"] >= 0
    assert isinstance(payload["rejected"], list)


def test_the_plan_id_is_stable_for_one_resolution_and_config() -> None:
    res = resolution()
    host = clean_host()
    first = make_planner(memory=primed_memory("SUSPEND_PROCESS")).plan(
        res, host.snapshot(), now=0, active_leases=()
    )
    second = make_planner(memory=primed_memory("SUSPEND_PROCESS")).plan(
        res, host.snapshot(), now=0, active_leases=()
    )
    assert first.plan_id == second.plan_id
    assert first.decision is second.decision
    assert (first.chosen is None) == (second.chosen is None)
    if first.chosen is not None and second.chosen is not None:
        assert first.chosen.candidate_id == second.chosen.candidate_id


def test_the_planner_holds_no_privileged_attribute() -> None:
    """The construction behind §35, checked on the instance rather than the source."""
    planner = make_planner()
    forbidden = ("TokenStore", "SimulatedHost", "TransactionalExecutor", "RollbackJournal")
    for name in dir(planner):
        if name.startswith("__"):
            continue
        value = getattr(planner, name, None)
        assert type(value).__name__ not in forbidden, name
    parameters = set(inspect.signature(AegisPlanner.__init__).parameters) - {"self"}
    assert parameters == {
        "config",
        "constitution",
        "invariants",
        "governor",
        "memory",
        "cells",
        "hysteresis",
        "harm",
    }


def test_the_authority_method_receives_no_confidence_argument() -> None:
    """The construction behind G5.4, asserted on the signature itself.

    ``_authority_outcome``'s parameters are the whole argument that confidence
    cannot reach the authority decision. A future reader who adds ``resolution``
    or ``candidate`` to it breaks this test before they break the property.
    """
    parameters = set(
        inspect.signature(AegisPlanner._authority_outcome).parameters
    ) - {"self"}
    assert parameters == {
        "spec",
        "rollback_reliability",
        "eligibility",
        "invariant_violations",
    }
    forbidden = {"resolution", "candidate", "support", "verdict", "confidence", "benefit"}
    assert not parameters & forbidden


def test_the_twin_snapshot_accessor_still_finds_its_attribute() -> None:
    """``_snapshot_of`` reads a private attribute of a sibling package's class.

    That is a coupling, and this test is where it breaks. If the ``field`` package
    renames ``ResponseTwin._snapshot``, the cone-informed Action Shadow silently
    stops being reachable — so the accessor raises rather than returning ``None``,
    and this test names the rename as the cause instead of leaving a caller to
    discover it as a missing shadow.
    """
    from pocketsec.stage5.aegis.planner import _snapshot_of

    host = clean_host()
    snapshot = host.snapshot()
    twin = ResponseTwin(snapshot=snapshot, governor=ResourceGovernor())
    assert _snapshot_of(twin) is snapshot

    class Renamed:
        pass

    with pytest.raises(ContractError, match="does not expose the snapshot"):
        _snapshot_of(Renamed())  # type: ignore[arg-type]


def test_a_resolution_with_no_hypotheses_plans_without_raising() -> None:
    """The degenerate upstream input: Stage 4 surrendered and named no world.

    ``CBFResolutionV1`` permits an empty ``hypotheses`` tuple, so the planner must
    handle it. There is no world to cite, so no intervention can be justified and
    the outcome must be an observation or NO_ACTION — never ACT, and never a
    traceback, because a planner that crashes on a degenerate resolution is a
    planner that stops responding at the moment Stage 4 is least sure.
    """
    res = resolution(
        hypotheses=(),
        consequence_distribution={},
        identifiability="UNIDENTIFIABLE",
        verdict=Verdict.UNKNOWN,
    )
    assert world_ids_of(res) == ()
    plan = make_planner(memory=primed_memory("SUSPEND_PROCESS")).plan(
        res, clean_host().snapshot(), now=0, active_leases=()
    )
    assert plan.decision in {PlanDecision.OBSERVE, PlanDecision.NO_ACTION, PlanDecision.ESCALATE}
    assert plan.decision is not PlanDecision.ACT
    # And the minimax-regret selector, which needs worlds, must return None rather
    # than inventing one.
    field, _, _ = build_field(res)
    scored = [score(candidate, cones={}, resolution=res) for candidate in field.candidates]
    assert minimax_regret(scored, ()) is None
    chosen, rejections = select(scored, selector=Selector.MINIMAX_REGRET, world_ids=())
    assert chosen is None
    assert rejections == ()


def test_an_unknown_verdict_does_not_change_the_authority_ceiling() -> None:
    """Every ``Verdict`` member must reach the same autonomy ceiling.

    ``Verdict`` is the most obviously "confidence-shaped" field Stage 4 hands over,
    and ADR-0003's rule is that it is evidence, never authorisation. Four plans, one
    per member, differing only in the verdict: none may choose an operator above
    ``MAX_AUTONOMOUS_AUTHORITY`` and none may ACT on one.
    """
    ceilings = set()
    for verdict in Verdict:
        plan = make_planner(
            memory=primed_memory("SUSPEND_PROCESS", "RESTRICT_LOCAL_SOCKET")
        ).plan(resolution(verdict=verdict), clean_host().snapshot(), now=0, active_leases=())
        if plan.chosen is not None:
            assert authority_rank(plan.chosen.authority) <= authority_rank(
                MAX_AUTONOMOUS_AUTHORITY
            ) or plan.decision is not PlanDecision.ACT
        ceilings.add(
            (plan.decision, None if plan.chosen is None else plan.chosen.authority)
        )
    assert len(ceilings) == 1, (
        f"the verdict changed the authority outcome across {len(Verdict)} members: {ceilings}"
    )


def test_the_frontier_stage_cannot_change_the_policy_pick() -> None:
    """Finding R5, measured: under PARETO_THEN_POLICY the frontier stage is inert.

    ``policy_pick`` is a lexicographic minimum over all seven harms and then both
    benefits, i.e. over every objective ``dominates`` compares, with exact comparisons. A
    candidate that dominated the lexicographic winner would be lexicographically smaller,
    so the winner is always on the frontier and filtering to the frontier first cannot
    change it. Checked over 500 random objective assignments to a real field's candidates
    (three levels per objective, so ties are common). The consequence, recorded in the
    findings: SAFE-F08's ablation swaps in SCALAR_UTILITY, so its delta measures
    lexicographic-versus-weighted-sum, not frontier-versus-no-frontier.
    """
    res = resolution()
    field, _twin, _governor = build_field(res)
    real = [score(candidate, cones={}, resolution=res) for candidate in field.candidates]
    assert len(real) >= 2, "a one-candidate field cannot show anything"
    rng = random.Random(5081)
    differ, pruned = 0, 0
    for _ in range(500):
        scored = [replace(item, objectives=_random_vector(rng)) for item in real]
        frontier = pareto_frontier(scored)
        pruned += len(frontier) < len(scored)
        if policy_pick(frontier) is not policy_pick(scored):
            differ += 1
    assert pruned > 0, "vacuous: the frontier never removed anything"
    assert differ == 0
