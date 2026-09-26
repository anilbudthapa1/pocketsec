"""Behaviour and failure-path tests for the Stage 5 `field` package (D5.2, D5.7, D5.8).

Every test here is about something the code must **refuse**, **bound** or **not
raise**. Construction is not tested for its own sake: both prior stages shipped
gate checks that passed by asserting a type existed, and this file is written so
that silently weakening any invariant in the four modules it covers makes at
least one test fail.

The `field` package is unprivileged. Nothing in this file imports a token store,
a journal or the transactional executor, and the twin, the cone and the action
field are only ever handed a read-only ``HostSnapshot``.
"""

from __future__ import annotations

import inspect
from typing import Any

import pytest

from pocketsec.stage0.contracts.common import ContractError, digest_of_bytes
from pocketsec.stage0.contracts.threat_prediction_v1 import Verdict
from pocketsec.stage1.state.security_state import SecurityStateV1
from pocketsec.stage4.stage5_interface import CBFResolutionV1
from pocketsec.stage5.aegis import cone as cone_module
from pocketsec.stage5.aegis.cone import (
    MAX_CONE_BRANCHES_PER_NODE,
    MAX_CONE_DEPTH,
    MAX_CONE_NODES,
    AdaptationKind,
    AdaptationModel,
    Branch,
    ConeNode,
    InterventionCone,
    build_intervention_cone,
)
from pocketsec.stage5.aegis.shadow import (
    MIN_CALIBRATION_SAMPLES,
    SHADOW_AUTONOMY_CEILING,
    SHADOW_HUMAN_CEILING,
    SHADOW_TERMS,
    SHADOW_WEIGHTS,
    UNKNOWN_BRANCH_NAME,
    ActionShadow,
    AutonomyEligibility,
    calibrate_shadow,
    estimate_action_shadow,
    generation_shadow,
    shadow_gate,
)
from pocketsec.stage5.cells.response_cells import ResponseCellField
from pocketsec.stage5.constitution.invariants import FROZEN_CONSTITUTION, AuthorityClass
from pocketsec.stage5.constitution.schema import (
    DEFAULT_MISSION_INVARIANTS,
    InvariantKind,
    MissionInvariant,
    MissionInvariantSet,
)
from pocketsec.stage5.executor.identity import ManualClock
from pocketsec.stage5.executor.residual import InterventionResidual, ResidualCause
from pocketsec.stage5.governor import STAGE5_BUDGET, ResourceBudget, ResourceGovernor
from pocketsec.stage5.host.simulated import (
    FaultProfile,
    ProcessRow,
    ProcessState,
    ServiceRow,
    SimulatedHost,
)
from pocketsec.stage5.memory.effectiveness import EffectivenessMemory
from pocketsec.stage5.operators.algebra import (
    DefensiveOperator,
    EvidenceEffect,
    OperatorClass,
    ProcessIdentity,
    ProcessTarget,
    Reversibility,
    TargetKind,
    TargetScope,
)
from pocketsec.stage5.operators.catalog import CATALOG
from pocketsec.stage5.safe import action_field as field_module
from pocketsec.stage5.safe.action_field import (
    ACTIONABLE_IDENTIFIABILITY,
    GAP_TO_OBSERVE_OPERATOR,
    MAX_CANDIDATES,
    NO_ACTION_OPERATOR_ID,
    ActionField,
    CandidateAction,
    FieldTruncation,
    HarmModel,
    IdentifiabilityOutcome,
    RiskAcceptancePolicy,
    check_response_identifiability,
    generate_action_field,
)
from pocketsec.stage5.twin.response_twin import (
    MAX_TWIN_BYTES,
    MAX_TWIN_DEPTH,
    MAX_TWIN_NODES,
    MAX_TWIN_PROJECTIONS,
    ResponseTwin,
    StateFamily,
    TwinNode,
    TwinState,
    state_degradation,
)

EVIDENCE_DIGEST = digest_of_bytes(b"stage5-field-evidence")
DANGLING_DIGEST = digest_of_bytes(b"stage5-field-evidence-with-no-lineage-row")


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


def target_of(pid: int, kind: TargetKind = TargetKind.PROCESS, subject: str = "") -> ProcessTarget:
    return ProcessTarget(
        identity=identity(pid),
        scope=TargetScope(kind=kind, subject=subject or str(pid)),
    )


def small_host() -> SimulatedHost:
    """One app process with a child, a unit, a session, a socket and volatile evidence.

    ``app.service`` depends on ``absent.service``, which is deliberately not in the
    snapshot: that is the unmodelled dependency §8 says must raise Action Shadow.
    """
    return SimulatedHost(
        processes=[
            ProcessRow(
                identity=identity(4242),
                state=ProcessState.RUNNING,
                unit="app.service",
                session_id="sess-1",
                socket_ids=("sock-1",),
                children=(4243,),
                volatile_signals=("socket_table",),
            ),
            ProcessRow(
                identity=identity(4243, ticks=101),
                state=ProcessState.RUNNING,
                unit=None,
                session_id=None,
                socket_ids=(),
                children=(),
                volatile_signals=(),
            ),
        ],
        services=[
            ServiceRow(
                unit="app.service",
                running=True,
                constrained=False,
                restartable=True,
                depends_on=("db.service", "absent.service"),
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
        ],
        sessions=["sess-1"],
        security_state=SecurityStateV1(),
        faults=FaultProfile(seed=7),
        clock=ManualClock(0),
    )


def wide_host() -> SimulatedHost:
    """A host whose depth-1 neighbourhood alone exceeds ``MAX_TWIN_NODES``."""
    root = ProcessRow(
        identity=identity(5000),
        state=ProcessState.RUNNING,
        unit="wide.service",
        session_id=None,
        socket_ids=tuple(f"s-{index}" for index in range(8)),
        children=tuple(range(5001, 5064)),
        volatile_signals=tuple(f"vol-{index}" for index in range(12)),
    )
    children = [
        ProcessRow(
            identity=identity(pid, ticks=200 + pid),
            state=ProcessState.RUNNING,
            unit=None,
            session_id=None,
            socket_ids=(),
            children=(),
            volatile_signals=(),
        )
        for pid in range(5001, 5064)
    ]
    services = [
        ServiceRow(
            unit=f"u{index}.service",
            running=True,
            constrained=False,
            restartable=True,
            depends_on=tuple(f"u{other}.service" for other in range(index + 1, index + 4)),
            healthy=True,
        )
        for index in range(20)
    ]
    services.append(
        ServiceRow(
            unit="wide.service",
            running=True,
            constrained=False,
            restartable=True,
            depends_on=tuple(f"u{index}.service" for index in range(20)),
            healthy=True,
        )
    )
    return SimulatedHost(
        processes=[root, *children],
        services=services,
        sessions=[],
        security_state=SecurityStateV1(),
        faults=FaultProfile(seed=1),
        clock=ManualClock(0),
    )


def mission_profile() -> MissionInvariantSet:
    """``DEFAULT_MISSION_INVARIANTS`` with the autonomous-downtime bound raised to the
    catalog's own longest ``max_duration_seconds``.

    The shipped default bounds autonomous downtime at 300 s, which refuses every 900 s
    operator in the catalog on every host. Keeping it here would leave the whole
    intervention path untested — a fixture that exercises nothing rather than a safer
    test — so this profile raises that one bound and keeps all nine invariants.
    ``test_an_all_unsafe_incident_yields_no_action_not_an_exception`` uses a strictly
    *stricter* profile, so both directions are covered.
    """
    raised = tuple(
        MissionInvariant(
            invariant_id=invariant.invariant_id,
            kind=invariant.kind,
            subject=invariant.subject,
            bound_seconds=900 if invariant.kind is InvariantKind.MAX_AUTONOMOUS_DOWNTIME
            else invariant.bound_seconds,
            detail=invariant.detail,
        )
        for invariant in DEFAULT_MISSION_INVARIANTS.invariants
    )
    return MissionInvariantSet(invariants=raised)


def unknown_heavy_host() -> SimulatedHost:
    """One process on a unit that depends on six units the snapshot does not hold.

    Six is deliberately more than ``MAX_CONE_BRANCHES_PER_NODE``, so the cone's
    per-node branch cap has something to truncate.
    """
    return SimulatedHost(
        processes=[
            ProcessRow(
                identity=identity(7000),
                state=ProcessState.RUNNING,
                unit="fragile.service",
                session_id=None,
                socket_ids=(),
                children=(),
                volatile_signals=(),
            )
        ],
        services=[
            ServiceRow(
                unit="fragile.service",
                running=True,
                constrained=False,
                restartable=True,
                depends_on=tuple(f"ghost{index}.service" for index in range(6)),
                healthy=True,
            )
        ],
        sessions=[],
        security_state=SecurityStateV1(),
        faults=FaultProfile(seed=3),
        clock=ManualClock(0),
    )


def deep_chain_host() -> SimulatedHost:
    """A four-link service dependency chain, so DEPTH rather than node count binds.

    ``wide_host`` proves the node bound; it cannot prove the depth bound, because 63
    children exhaust ``MAX_TWIN_NODES`` before the walk ever reaches a second hop.
    This host has six nodes in reach and a chain longer than ``MAX_TWIN_DEPTH``.
    """
    return SimulatedHost(
        processes=[
            ProcessRow(
                identity=identity(8000),
                state=ProcessState.RUNNING,
                unit="a.service",
                session_id=None,
                socket_ids=(),
                children=(),
                volatile_signals=(),
            )
        ],
        services=[
            ServiceRow(
                unit=unit,
                running=True,
                constrained=False,
                restartable=True,
                depends_on=depends,
                healthy=True,
            )
            for unit, depends in (
                ("a.service", ("b.service",)),
                ("b.service", ("c.service",)),
                ("c.service", ("d.service",)),
                ("d.service", ()),
            )
        ],
        sessions=[],
        security_state=SecurityStateV1(),
        faults=FaultProfile(seed=5),
        clock=ManualClock(0),
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


def build_field(
    *,
    res: CBFResolutionV1 | None = None,
    host: SimulatedHost | None = None,
    invariants: MissionInvariantSet | None = None,
    governor: ResourceGovernor | None = None,
) -> tuple[ActionField, ResponseTwin, ResourceGovernor]:
    res = res or resolution()
    host = host or small_host()
    governor = governor or ResourceGovernor()
    snapshot = host.snapshot()
    twin = ResponseTwin(snapshot=snapshot, governor=governor)
    generated = generate_action_field(
        res,
        snapshot,
        constitution=FROZEN_CONSTITUTION,
        invariants=invariants if invariants is not None else mission_profile(),
        governor=governor,
        memory=EffectivenessMemory(),
        cells=ResponseCellField(),
        twin=twin,
    )
    return generated, twin, governor


def candidate_named(generated: ActionField, operator_id: str) -> CandidateAction:
    for candidate in generated.candidates:
        if candidate.operator.spec.operator_id == operator_id:
            return candidate
    raise AssertionError(f"{operator_id} is not in the field")


def a_shadow(candidate_id: str = "cand00.probe", **counts: int) -> ActionShadow:
    """A well-formed shadow built through the module's own normalisation."""
    prediction = _FakePrediction(
        unknown=tuple(f"SERVICE:u{index}" for index in range(counts.get("unknown", 0))),
        recovery=tuple(f"PROCESS:{index}" for index in range(counts.get("recovery", 0))),
        evidence=tuple(f"EVIDENCE:e{index}" for index in range(counts.get("evidence", 0))),
    )
    return generation_shadow(
        candidate_id,
        prediction=prediction,
        snapshot=small_host().snapshot(),
        resolution=resolution(),
    )


class _FakePrediction:
    """The narrow surface ``generation_shadow`` reads, so counts can be dialled."""

    def __init__(
        self,
        *,
        unknown: tuple[str, ...] = (),
        recovery: tuple[str, ...] = (),
        evidence: tuple[str, ...] = (),
        truncated: bool = False,
    ) -> None:
        self.unknown_dependencies = unknown
        self.recovery_state_needed = recovery
        self.evidence_lost = evidence
        self.truncated = truncated
        self.predicted = TwinState(nodes=(), edges=())


# --- D5.2 SAFE Action Field --------------------------------------------------


def test_max_candidates_equals_the_governor_budget() -> None:
    """Two constants that must agree. §4.9 lists both; a drift here is silent."""
    assert STAGE5_BUDGET.max_candidate_actions == MAX_CANDIDATES


def test_an_all_unsafe_incident_yields_no_action_not_an_exception() -> None:
    """§2's NO_ACTION_IS_ALWAYS_AVAILABLE, as reachable code.

    The unit is a protected critical service, its volatile evidence is retained,
    autonomous downtime is bounded at zero and identifiability is UNIDENTIFIABLE.
    Every intervention is therefore refused — and the field still answers.
    """
    hostile = MissionInvariantSet(
        invariants=(
            MissionInvariant(
                invariant_id="MX-01",
                kind=InvariantKind.CRITICAL_SERVICE,
                subject="app.service",
                bound_seconds=None,
                detail="the incident target runs the one service that may not be interrupted",
            ),
            MissionInvariant(
                invariant_id="MX-02",
                kind=InvariantKind.EVIDENCE_RETENTION,
                subject="socket_table",
                bound_seconds=900,
                detail="the only volatile signal on the target must survive the response",
            ),
            MissionInvariant(
                invariant_id="MX-03",
                kind=InvariantKind.MAX_AUTONOMOUS_DOWNTIME,
                subject="",
                bound_seconds=0,
                detail="no autonomous downtime is tolerated on this host at all",
            ),
        )
    )
    generated, _, _ = build_field(
        res=resolution(identifiability="UNIDENTIFIABLE"), invariants=hostile
    )
    assert isinstance(generated, ActionField)
    assert generated.candidates, "the field must never run out of options"
    assert any(
        candidate.operator.spec.operator_id == NO_ACTION_OPERATOR_ID
        for candidate in generated.candidates
    )
    assert generated.observe_only(), "observation is what remains when all else is refused"
    assert all(
        candidate.authority in (AuthorityClass.A0, AuthorityClass.A1)
        for candidate in generated.candidates
    ), "an all-unsafe incident may not leave an intervention in the field"
    assert generated.truncations, "every refusal is recorded"


def test_a_zero_budget_governor_still_returns_a_field_with_reasons() -> None:
    """Budget exhaustion escalates; it never raises out of the generator."""
    starved = ResourceGovernor(ResourceBudget(max_work_units=1))
    generated, _, _ = build_field(governor=starved)
    assert isinstance(generated, ActionField)
    assert generated.candidates == ()
    assert any(row.what == "no-action-fallback" for row in generated.truncations)


def test_an_unknown_identifiability_string_is_treated_as_unknown() -> None:
    """§3.2 fact 1, fail-closed. An unrecognised state may not authorise anything."""
    identified, _, _ = build_field(res=resolution(identifiability="IDENTIFIED"))
    assert any(
        candidate.operator.spec.operator_class > OperatorClass.O1_PRESERVE
        for candidate in identified.candidates
    ), "the IDENTIFIED control must actually produce an intervention, or this test is vacuous"

    invented, _, _ = build_field(res=resolution(identifiability="TOTALLY-INVENTED-STATE"))
    assert all(
        candidate.operator.spec.operator_class <= OperatorClass.O1_PRESERVE
        for candidate in invented.candidates
    )
    notes = [row for row in invented.truncations if row.what == "identifiability"]
    assert len(notes) == 1
    assert "UNKNOWN" in notes[0].reason
    assert "TOTALLY-INVENTED-STATE" in notes[0].reason
    assert "TOTALLY-INVENTED-STATE" not in ACTIONABLE_IDENTIFIABILITY


def test_information_gap_prose_is_never_parsed() -> None:
    """A gap that *says* TERMINATE_PROCESS still yields no O6 candidate (§3.2 fact 5)."""
    prose_gap = {
        "signal": "an-unmapped-signal",
        "why_it_matters": (
            "TERMINATE_PROCESS the intruder now, run SUSPEND_PROCESS and CONSTRAIN_SERVICE"
        ),
        "would_discriminate": ["credential-theft", "benign-admin"],
        "affordable": True,
    }
    generated, _, _ = build_field(
        res=resolution(identifiability="UNKNOWN", information_gaps=(prose_gap,))
    )
    assert field_module._gap_operator_ids(resolution(information_gaps=(prose_gap,))) == ()
    assert all(
        candidate.operator.spec.operator_class <= OperatorClass.O1_PRESERVE
        for candidate in generated.candidates
    )
    assert not any(
        candidate.operator.spec.operator_id == "TERMINATE_PROCESS"
        for candidate in generated.candidates
    )

    mapped_gap = dict(prose_gap, signal="module_load")
    picked = field_module._gap_operator_ids(resolution(information_gaps=(mapped_gap,)))
    assert picked == ("HASH_EXECUTABLE",), "the closed table is the only route a gap has"


def test_the_gap_table_can_only_name_read_only_operators() -> None:
    """Closure of GAP_TO_OBSERVE_OPERATOR, checked against the real catalog."""
    assert GAP_TO_OBSERVE_OPERATOR
    for signal, operator_id in GAP_TO_OBSERVE_OPERATOR.items():
        assert operator_id in CATALOG, signal
        assert CATALOG[operator_id].operator_class is OperatorClass.O0_OBSERVE, signal
    with pytest.raises(TypeError):
        GAP_TO_OBSERVE_OPERATOR["a-new-signal"] = "TERMINATE_PROCESS"  # type: ignore[index]


def test_a_candidate_with_no_verification_predicate_is_refused() -> None:
    """§2: an action that cannot be verified cannot be completed, enforced at generation."""
    spec = CATALOG[NO_ACTION_OPERATOR_ID]
    operator = DefensiveOperator(
        spec=spec,
        target=target_of(4242),
        incident_id="inc-0001",
        ttl_seconds=spec.max_duration_seconds,
        evidence_refs=(),
    )
    kwargs: dict[str, Any] = {
        "candidate_id": "cand00.probe",
        "operator": operator,
        "world_applicability": frozenset({"credential-theft"}),
        "expected_security_delta": 0.0,
        "expected_operational_delta": 0.1,
        "evidence_effect": spec.evidence_effect,
        "reversibility": spec.reversibility,
        "rollback_operator_id": None,
        "authority": spec.authority,
        "lease_ttl_seconds": 30,
        "uncertainty": 0.3,
        "shadow": a_shadow(),
        "scope_size": 1,
        "evidence_loss": (),
    }
    with pytest.raises(ContractError, match="verification predicate"):
        CandidateAction(verification_predicates=(), **kwargs)
    # And the generator can never produce one, because no catalog entry is unverifiable.
    assert all(entry.postconditions for entry in CATALOG.values())


def test_a_candidate_refuses_a_shadow_belonging_to_another_candidate() -> None:
    """§4.9 Rule A at the smallest scale: two key spaces that could never match."""
    spec = CATALOG[NO_ACTION_OPERATOR_ID]
    operator = DefensiveOperator(
        spec=spec,
        target=target_of(4242),
        incident_id="inc-0001",
        ttl_seconds=spec.max_duration_seconds,
        evidence_refs=(),
    )
    with pytest.raises(ContractError, match="Rule A"):
        CandidateAction(
            candidate_id="cand00.probe",
            operator=operator,
            world_applicability=frozenset(),
            expected_security_delta=0.0,
            expected_operational_delta=0.1,
            evidence_effect=spec.evidence_effect,
            reversibility=spec.reversibility,
            rollback_operator_id=None,
            authority=spec.authority,
            verification_predicates=spec.postconditions,
            lease_ttl_seconds=30,
            uncertainty=0.3,
            shadow=a_shadow("cand01.other"),
            scope_size=1,
            evidence_loss=(),
        )


def test_candidate_with_no_lineage_row_for_its_digest_is_refused() -> None:
    """§3.2 fact 2: a digest with no lineage row is refused, never defaulted."""
    dangling = resolution(
        hypotheses=(
            {
                "mechanism_id": "credential-theft",
                "support": 0.80,
                "consequence": 2.0,
                "uncertainty": 0.20,
                "claim_ids": [],
                "evidence_digests": [DANGLING_DIGEST],
            },
        )
    )
    generated, _, _ = build_field(res=dangling)
    world_drops = [row for row in generated.truncations if row.what == "world"]
    assert len(world_drops) == 1
    assert DANGLING_DIGEST in world_drops[0].reason
    assert all(
        candidate.operator.spec.operator_class <= OperatorClass.O1_PRESERVE
        for candidate in generated.candidates
    ), "an intervention with no citable world has nothing to justify it"
    assert any(row.what == "candidate" and "no surviving world" in row.reason
               for row in generated.truncations)
    assert generated.observe_only(), "NO ACTION survives the refusal"


def test_upstream_truncations_raise_shadow_not_confidence() -> None:
    """§3.2 fact 4. A resolution that lost worlds is known *less* well, not more."""
    clean, _, _ = build_field()
    damaged, _, _ = build_field(
        res=resolution(
            truncations=({"what": "world", "identifier": "w-3", "reason": "MAX_WORLDS"},),
            degradations=({"subsystem": "counterfactual", "detail": "budget"},),
        )
    )
    clean_candidate = candidate_named(clean, "SUSPEND_PROCESS")
    damaged_candidate = candidate_named(damaged, "SUSPEND_PROCESS")
    assert damaged_candidate.shadow.upstream_truncations == 2
    assert clean_candidate.shadow.upstream_truncations == 0
    assert damaged_candidate.shadow.score > clean_candidate.shadow.score
    assert (
        damaged_candidate.expected_security_delta == clean_candidate.expected_security_delta
    ), "upstream damage must not raise predicted benefit"


def test_a_mission_invariant_removes_a_candidate_and_names_the_invariant() -> None:
    """G5.8's mechanism, exercised rather than asserted to exist.

    ``app.service`` is the incident target's unit. Declaring it a protected critical
    service must remove the service-containment candidate and record which invariant
    did it — the same profile without that invariant must keep the candidate, or this
    test would pass on a generator that ignored invariants entirely.
    """
    permissive = mission_profile()
    protective = MissionInvariantSet(
        invariants=(
            *permissive.invariants,
            MissionInvariant(
                invariant_id="MP-10",
                kind=InvariantKind.CRITICAL_SERVICE,
                subject="app.service",
                bound_seconds=None,
                detail="the unit carrying the incident is the one that may not be interrupted",
            ),
        )
    )
    without, _, _ = build_field(invariants=permissive)
    assert any(
        candidate.operator.spec.operator_id == "CONSTRAIN_SERVICE"
        for candidate in without.candidates
    ), "the control must actually offer the candidate, or the test below proves nothing"

    with_invariant, _, _ = build_field(invariants=protective)
    assert not any(
        candidate.operator.spec.operator_id == "CONSTRAIN_SERVICE"
        for candidate in with_invariant.candidates
    )
    refusals = [
        row
        for row in with_invariant.truncations
        if row.what == "candidate" and "CONSTRAIN_SERVICE" in row.identifier
    ]
    assert len(refusals) == 1
    assert "MP-10" in refusals[0].reason


def test_confidence_does_not_change_the_field_authorities() -> None:
    """ADR-0003 inside this package: a verdict is evidence, never an authorisation."""
    certain, _, _ = build_field(res=resolution(uncertainty=0.01, verdict=Verdict.MALICIOUS))
    unsure, _, _ = build_field(res=resolution(uncertainty=0.99, verdict=Verdict.MALICIOUS))
    assert {
        (c.operator.spec.operator_id, c.authority.value) for c in certain.candidates
    } == {(c.operator.spec.operator_id, c.authority.value) for c in unsure.candidates}


def test_the_field_is_bounded_and_its_state_is_bounded() -> None:
    """MAX_CANDIDATES holds, and the bound keeps the read-only options."""
    generated, _, _ = build_field()
    assert len(generated.candidates) <= MAX_CANDIDATES
    assert generated.state_bytes() > 0
    with pytest.raises(ContractError, match="MAX_CANDIDATES"):
        ActionField(
            incident_id="inc-0001",
            resolution_id="res-0001",
            candidates=tuple(
                # Reuse one real candidate; the bound is on count, not content.
                generated.candidates[index % len(generated.candidates)]
                for index in range(MAX_CANDIDATES + 1)
            ),
            truncations=(),
        )


def test_every_field_candidate_carries_a_real_shadow_not_the_bootstrap() -> None:
    """The provisional zero shadow must never escape the generator."""
    damaged, _, _ = build_field(
        res=resolution(
            truncations=({"what": "world", "identifier": "w-3", "reason": "MAX_WORLDS"},)
        )
    )
    assert damaged.candidates
    for candidate in damaged.candidates:
        assert candidate.shadow.upstream_truncations == 1
        assert candidate.shadow.score > 0.0


def test_evidence_loss_is_reported_for_a_degrading_operator() -> None:
    """A candidate that costs evidence says which signals, before anything runs."""
    generated, _, _ = build_field()
    suspend = candidate_named(generated, "SUSPEND_PROCESS")
    observe = candidate_named(generated, NO_ACTION_OPERATOR_ID)
    assert suspend.evidence_effect is EvidenceEffect.DEGRADES_VOLATILE
    assert suspend.evidence_loss == ("socket_table",)
    assert observe.evidence_loss == ()


# --- §7 response identifiability ---------------------------------------------


def test_check_response_identifiability_refuses_an_unruled_out_harmful_world() -> None:
    """§7 as an execution constraint: a live harmful world blocks the candidate."""
    generated, _, _ = build_field()
    suspend = candidate_named(generated, "SUSPEND_PROCESS")
    harm = HarmModel(unacceptable=frozenset({("credential-theft", OperatorClass.O3_SUSPEND)}))
    policy = RiskAcceptancePolicy(accept_residual_below_support=0.0)
    verdict = check_response_identifiability(
        suspend, resolution(), truth=harm, policy=policy
    )
    assert verdict.outcome is IdentifiabilityOutcome.NOT_IDENTIFIABLE
    assert verdict.unruled_out == ("credential-theft",)


def test_a_ruled_out_harmful_world_leaves_the_candidate_actionable() -> None:
    generated, _, _ = build_field()
    suspend = candidate_named(generated, "SUSPEND_PROCESS")
    ruled_out = resolution(
        hypotheses=(
            {
                "mechanism_id": "credential-theft",
                "support": 0.01,
                "consequence": 2.0,
                "uncertainty": 0.2,
                "claim_ids": [],
                "evidence_digests": [EVIDENCE_DIGEST],
            },
        )
    )
    harm = HarmModel(unacceptable=frozenset({("credential-theft", OperatorClass.O3_SUSPEND)}))
    verdict = check_response_identifiability(
        suspend,
        ruled_out,
        truth=harm,
        policy=RiskAcceptancePolicy(accept_residual_below_support=0.0),
    )
    assert verdict.outcome is IdentifiabilityOutcome.ACTIONABLE
    assert verdict.harmful_worlds == ("credential-theft",)


def test_a_residual_is_accepted_only_for_the_classes_policy_names() -> None:
    """RESIDUAL_ACCEPTED requires an explicit policy, and it is class-scoped."""
    generated, _, _ = build_field()
    observe = candidate_named(generated, NO_ACTION_OPERATOR_ID)
    suspend = candidate_named(generated, "SUSPEND_PROCESS")
    marginal = resolution(
        hypotheses=(
            {
                "mechanism_id": "benign-admin",
                "support": 0.10,
                "consequence": 0.5,
                "uncertainty": 0.4,
                "claim_ids": [],
                "evidence_digests": [EVIDENCE_DIGEST],
            },
        )
    )
    harm = HarmModel(
        unacceptable=frozenset(
            {
                ("benign-admin", OperatorClass.O0_OBSERVE),
                ("benign-admin", OperatorClass.O3_SUSPEND),
            }
        )
    )
    policy = RiskAcceptancePolicy(accept_residual_below_support=0.20)
    assert (
        check_response_identifiability(observe, marginal, truth=harm, policy=policy).outcome
        is IdentifiabilityOutcome.RESIDUAL_ACCEPTED
    )
    assert (
        check_response_identifiability(suspend, marginal, truth=harm, policy=policy).outcome
        is IdentifiabilityOutcome.NOT_IDENTIFIABLE
    ), "O3 is not in the policy's accepted classes, so its residual is not accepted"


def test_the_harm_model_is_a_closed_table_not_a_score() -> None:
    """A HarmModel cannot be built from anything but explicit (mechanism, class) rows."""
    harm = HarmModel(unacceptable=frozenset({("credential-theft", OperatorClass.O6_DISRUPTIVE)}))
    assert harm.harms("credential-theft", CATALOG["TERMINATE_PROCESS"])
    assert not harm.harms("credential-theft", CATALOG["SUSPEND_PROCESS"])
    assert not harm.harms("benign-admin", CATALOG["TERMINATE_PROCESS"])
    with pytest.raises(ContractError):
        HarmModel(unacceptable=frozenset({("not a valid id", OperatorClass.O6_DISRUPTIVE)}))


# --- D5.7 Counterfactual Response Twin ---------------------------------------


def test_the_twin_models_the_seven_architecture_state_families() -> None:
    assert [member.value for member in StateFamily] == [
        "PROCESS",
        "SERVICE",
        "SESSION",
        "COMMUNICATION",
        "SECURITY",
        "EVIDENCE",
        "RECOVERY",
    ]


def test_twin_depth_and_node_bounds_hold_under_a_wide_snapshot() -> None:
    """Narrowness is structural: the walk stops at the bound, and says it did."""
    host = wide_host()
    governor = ResourceGovernor()
    twin = ResponseTwin(snapshot=host.snapshot(), governor=governor)
    state = twin.project(target_of(5000))
    assert len(state.nodes) == MAX_TWIN_NODES
    assert len(state.canonical_bytes()) <= MAX_TWIN_BYTES
    assert governor.spend_report()["TWIN_STEP"] == MAX_TWIN_NODES
    # Depth is enforced by the walk, not by the dataclass: nothing more than
    # MAX_TWIN_DEPTH hops from the root can appear, so no service reached only
    # through another service's dependency chain at distance 3 is present.
    far = {f"SERVICE:u{index}.service" for index in range(20)}
    reached = {node.node_id for node in state.nodes}
    assert MAX_TWIN_DEPTH == 2
    assert not (reached & {f"PROCESS:{pid}" for pid in range(6000, 6100)})
    assert len(reached & far) <= 20

    with pytest.raises(ContractError, match="MAX_TWIN_NODES"):
        TwinState(
            nodes=tuple(
                TwinNode(
                    family=StateFamily.PROCESS,
                    node_id=f"PROCESS:{index}",
                    attributes={"pid": str(index)},
                    observed=True,
                )
                for index in range(MAX_TWIN_NODES + 1)
            ),
            edges=(),
        )


def test_the_twin_walk_stops_at_max_twin_depth() -> None:
    """The depth bound, on a host small enough that the node bound cannot mask it."""
    host = deep_chain_host()
    governor = ResourceGovernor()
    twin = ResponseTwin(snapshot=host.snapshot(), governor=governor)
    reached = {node.node_id for node in twin.project(target_of(8000)).nodes}
    assert len(reached) < MAX_TWIN_NODES, "the node bound must not be what stops this walk"
    assert "SERVICE:a.service" in reached, "one hop from the target"
    assert "SERVICE:b.service" in reached, "two hops, the last MAX_TWIN_DEPTH allows"
    assert "SERVICE:c.service" not in reached, "three hops is past MAX_TWIN_DEPTH"
    assert "SERVICE:d.service" not in reached


def test_the_twin_marks_an_absent_dependency_unobserved_and_that_raises_shadow() -> None:
    """§8: unknown dependencies raise Action Shadow; they never raise benefit."""
    generated, twin, _ = build_field()
    suspend = candidate_named(generated, "SUSPEND_PROCESS")
    unknown = twin.unknown_dependencies(suspend.operator.target)
    assert "SERVICE:absent.service" in unknown
    absent = twin.project(suspend.operator.target).node("SERVICE:absent.service")
    assert absent is not None and absent.observed is False
    with_unknown = a_shadow(unknown=3)
    without = a_shadow(unknown=0)
    assert with_unknown.unmodelled_dependencies > without.unmodelled_dependencies
    assert with_unknown.score > without.score


def test_a_twin_state_refuses_a_dangling_edge() -> None:
    """A dangling edge is an unmodelled dependency pretending to be modelled."""
    node = TwinNode(
        family=StateFamily.PROCESS, node_id="PROCESS:1", attributes={}, observed=True
    )
    with pytest.raises(ContractError, match="does not"):
        TwinState(nodes=(node,), edges=(("PROCESS:1", "PROCESS:2"),))


def test_a_twin_node_must_be_prefixed_with_its_own_family() -> None:
    with pytest.raises(ContractError, match="prefixed"):
        TwinNode(
            family=StateFamily.SERVICE, node_id="PROCESS:1", attributes={}, observed=True
        )


def test_the_twin_predicts_degradation_only_where_the_operator_causes_it() -> None:
    """A read-only observation degrades nothing; a suspend degrades the target."""
    generated, twin, _ = build_field()
    observe = candidate_named(generated, NO_ACTION_OPERATOR_ID)
    suspend = candidate_named(generated, "SUSPEND_PROCESS")
    observed = twin.predict(observe, world_id="credential-theft")
    suspended = twin.predict(suspend, world_id="credential-theft")
    assert observed.predicted_degradation == 0.0
    assert suspended.predicted_degradation > 0.0
    assert state_degradation(suspended.predicted) == suspended.predicted_degradation
    assert suspended.predicted.node("PROCESS:4242") is not None
    assert suspended.predicted.node("PROCESS:4242").attributes["state"] == "SUSPENDED"
    assert observed.evidence_lost == ()
    assert suspended.evidence_lost, "a DEGRADES_VOLATILE operator must name what it costs"


def test_the_twin_projection_cache_is_bounded_and_counts_its_evictions() -> None:
    """Endpoint state stays bounded even when the cache is the thing holding it."""
    host = small_host()
    governor = ResourceGovernor()
    twin = ResponseTwin(snapshot=host.snapshot(), governor=governor)
    first = twin.project(target_of(4242))
    spent = governor.spend_report()["TWIN_STEP"]
    second = twin.project(target_of(4242))
    assert second.digest() == first.digest()
    assert governor.spend_report()["TWIN_STEP"] == spent, "a cached projection costs nothing"
    assert twin.projection_evictions() == 0

    # The cache is endpoint state, so it is bounded and its truncation is countable.
    # Seventeen distinct identities against a sixteen-entry cache must evict.
    fresh = ResponseTwin(snapshot=host.snapshot(), governor=ResourceGovernor())
    for pid in range(9000, 9000 + MAX_TWIN_PROJECTIONS + 1):
        fresh.project(target_of(pid))
    assert fresh.projection_evictions() == 1
    assert twin.projection_evictions() == 0, "the two twins must not share a cache"


def test_the_twin_refuses_anything_but_a_read_only_snapshot() -> None:
    """§35: the planner side never receives a host adapter."""
    with pytest.raises(ContractError, match="HostSnapshot"):
        ResponseTwin(snapshot=small_host(), governor=ResourceGovernor())  # type: ignore[arg-type]


# --- D5.8 Intervention Cone --------------------------------------------------


def test_the_cone_has_the_seven_architecture_branches_and_four_adaptations() -> None:
    assert [member.value for member in Branch] == [
        "INTENDED_SECURITY_EFFECT",
        "ATTACKER_ADAPTATION",
        "SERVICE_DEGRADATION",
        "EVIDENCE_LOSS",
        "PERSISTENCE_TRIGGERED_RESTART",
        "ROLLBACK_PATH",
        "UNKNOWN",
    ]
    assert [member.value for member in AdaptationKind] == [
        "PROCESS_REPLACEMENT",
        "ALTERNATE_DESTINATION",
        "PERSISTENCE_RESTART",
        "SESSION_MIGRATION",
    ]


def test_cone_depth_and_node_bounds_hold() -> None:
    """The builder stays inside the bounds, and the type refuses a cone that does not."""
    generated, twin, governor = build_field()
    suspend = candidate_named(generated, "SUSPEND_PROCESS")
    adaptations = AdaptationModel(
        observed=frozenset(AdaptationKind),
        observation_counts=dict.fromkeys(AdaptationKind, 4),
    )
    built = build_intervention_cone(
        suspend,
        world_id="credential-theft",
        twin=twin,
        adaptations=adaptations,
        governor=governor,
    )
    assert built.nodes
    assert len(built.nodes) <= MAX_CONE_NODES
    # The builder's own structure is the binding bound, and it is tighter than the
    # constant: one root, three deterministic branches, at most
    # MAX_CONE_BRANCHES_PER_NODE adaptations each with one follow-on leaf, and at most
    # MAX_CONE_BRANCHES_PER_NODE unknown branches. MAX_CONE_NODES is the second guard,
    # which is why the type refuses an over-bound cone below as well.
    structural_ceiling = 1 + 3 + 3 * MAX_CONE_BRANCHES_PER_NODE
    assert len(built.nodes) <= structural_ceiling
    assert structural_ceiling <= MAX_CONE_NODES
    assert max(node.depth for node in built.nodes) <= MAX_CONE_DEPTH
    # And it is deliberately *below* the bound: the builder stops one level short of
    # MAX_CONE_DEPTH because a second speculative adversary move would be the
    # unrestricted game-theoretic search §25 forbids. Recorded as an assertion so that
    # a later change which quietly deepened the cone would have to justify itself here.
    assert max(node.depth for node in built.nodes) == 2
    assert len(built.branch_nodes(Branch.ATTACKER_ADAPTATION)) <= MAX_CONE_BRANCHES_PER_NODE
    assert sum(1 for node in built.nodes if node.parent_id is None) == 1

    root = built.nodes[0]
    with pytest.raises(ContractError, match="MAX_CONE_NODES"):
        InterventionCone(
            candidate_id=suspend.candidate_id,
            world_id="credential-theft",
            nodes=tuple(
                ConeNode(
                    node_id=f"{suspend.candidate_id}.n{index}",
                    parent_id=None if index == 0 else root.node_id,
                    branch=Branch.UNKNOWN,
                    depth=0 if index == 0 else 1,
                    probability=None,
                    state=None,
                    detail="filler",
                )
                for index in range(MAX_CONE_NODES + 1)
            ),
            truncations=(),
        )
    with pytest.raises(ContractError, match="MAX_CONE_DEPTH"):
        ConeNode(
            node_id="cand00.deep",
            parent_id="cand00.root",
            branch=Branch.UNKNOWN,
            depth=MAX_CONE_DEPTH + 1,
            probability=None,
            state=None,
            detail="too deep",
        )


def test_cone_unknown_branches_are_capped_and_the_drop_is_recorded() -> None:
    """Per-node branching is bounded, and the truncation names the bound."""
    host = unknown_heavy_host()
    governor = ResourceGovernor()
    twin = ResponseTwin(snapshot=host.snapshot(), governor=governor)
    spec = CATALOG["SUSPEND_PROCESS"]
    operator = DefensiveOperator(
        spec=spec,
        target=target_of(7000),
        incident_id="inc-0001",
        ttl_seconds=spec.max_duration_seconds,
        evidence_refs=(),
    )
    unknown = twin.unknown_dependencies(target_of(7000))
    assert len(unknown) > MAX_CONE_BRANCHES_PER_NODE, unknown
    candidate = CandidateAction(
        candidate_id="cand00.wide",
        operator=operator,
        world_applicability=frozenset({"credential-theft"}),
        expected_security_delta=0.4,
        expected_operational_delta=0.4,
        evidence_effect=spec.evidence_effect,
        reversibility=spec.reversibility,
        rollback_operator_id=spec.rollback_operator_id,
        authority=spec.authority,
        verification_predicates=spec.postconditions,
        lease_ttl_seconds=spec.max_duration_seconds,
        uncertainty=0.3,
        shadow=a_shadow("cand00.wide"),
        scope_size=64,
        evidence_loss=(),
    )
    built = build_intervention_cone(
        candidate,
        world_id="credential-theft",
        twin=twin,
        adaptations=AdaptationModel(observed=frozenset(), observation_counts={}),
        governor=governor,
    )
    assert len(built.branch_nodes(Branch.UNKNOWN)) <= MAX_CONE_BRANCHES_PER_NODE
    assert any(row.what == "cone_unknown_branches" for row in built.truncations)


def test_cone_probability_is_none_when_unmeasured() -> None:
    """ADR-0004: 0.5 is not a stand-in for a number nobody measured."""
    generated, twin, governor = build_field()
    suspend = candidate_named(generated, "SUSPEND_PROCESS")
    unobserved = build_intervention_cone(
        suspend,
        world_id="credential-theft",
        twin=twin,
        adaptations=AdaptationModel(observed=frozenset(), observation_counts={}),
        governor=governor,
    )
    assert unobserved.nodes
    assert all(node.probability is None for node in unobserved.nodes)
    assert not unobserved.branch_nodes(Branch.ATTACKER_ADAPTATION)

    observed = build_intervention_cone(
        suspend,
        world_id="credential-theft",
        twin=twin,
        adaptations=AdaptationModel(
            observed=frozenset({AdaptationKind.PROCESS_REPLACEMENT}),
            observation_counts={AdaptationKind.PROCESS_REPLACEMENT: 3},
        ),
        governor=governor,
    )
    adaptation_nodes = observed.branch_nodes(Branch.ATTACKER_ADAPTATION)
    assert len(adaptation_nodes) == 1
    assert adaptation_nodes[0].probability == 1.0, "3 of 3 recorded adaptations is a real ratio"
    assert "3 of 3" in adaptation_nodes[0].detail
    # Only the adaptation branch carries a number. Every other node in the same cone —
    # including the depth-2 Action Shadow leaf hanging off the adaptation — is None,
    # because nothing counted those.
    carrying = {
        node.node_id for node in observed.nodes if node.probability is not None
    }
    assert carrying == {adaptation_nodes[0].node_id}
    deeper = [node for node in observed.nodes if node.depth == 2]
    assert deeper, "an observed adaptation must produce its follow-on leaf"
    assert all(node.probability is None for node in deeper)


def test_which_constitution_decisions_the_catalog_can_actually_reach() -> None:
    """A measured statement about a branch, rather than a check that cannot fail.

    ``_pre_refusal`` drops a candidate the constitution REFUSES. Against
    ``FROZEN_CONSTITUTION`` and the 14-entry catalog that branch turns out to be
    **unreachable**: every entry is PERMITTED or HUMAN_REQUIRED, because the only
    prohibited operator class is O7 and O7 has no catalog entries at all. The
    refusal path therefore guards a class that is not expressible, and this test
    records that rather than asserting something vacuous. If a later catalog adds an
    entry the constitution refuses, this test fails and has to be re-read — which is
    the point.
    """
    decisions: dict[str, str] = {}
    for operator_id in sorted(CATALOG):
        spec = CATALOG[operator_id]
        verdict = FROZEN_CONSTITUTION.permits(
            operator_class=spec.operator_class,
            authority=spec.authority,
            reversibility=spec.reversibility,
            has_rollback=spec.rollback_operator_id is not None,
            autonomous=True,
        )
        decisions[operator_id] = verdict.decision.value
    assert set(decisions.values()) == {"PERMITTED", "HUMAN_REQUIRED"}
    assert sorted(oid for oid, d in decisions.items() if d == "HUMAN_REQUIRED") == [
        "CONSTRAIN_SERVICE",
        "RELEASE_SERVICE",
        "REVOKE_LOCAL_SESSION",
        "TERMINATE_PROCESS",
    ]
    assert FROZEN_CONSTITUTION.prohibited_operator_classes == frozenset(
        {OperatorClass.O7_DESTRUCTIVE}
    )
    assert not [
        operator_id
        for operator_id, spec in CATALOG.items()
        if spec.operator_class is OperatorClass.O7_DESTRUCTIVE
    ], "the prohibited class must stay inexpressible, not merely refused"
    # And a HUMAN_REQUIRED candidate is kept in the field: the field proposes, the
    # authority plane and SENTINEL decide. Dropping it here would hide the option.
    generated, _, _ = build_field()
    kept = {candidate.operator.spec.operator_id for candidate in generated.candidates}
    assert "TERMINATE_PROCESS" in kept
    assert all(
        candidate.authority is not None for candidate in generated.candidates
    )


def test_an_adaptation_model_refuses_an_observation_it_never_counted() -> None:
    """'Observed' means counted. An unrestricted adversary model is not available."""
    with pytest.raises(ContractError, match="observed"):
        AdaptationModel(
            observed=frozenset({AdaptationKind.SESSION_MIGRATION}), observation_counts={}
        )
    empty = AdaptationModel(observed=frozenset(), observation_counts={})
    assert empty.frequency(AdaptationKind.PROCESS_REPLACEMENT) is None
    assert not empty.likely(AdaptationKind.PROCESS_REPLACEMENT)


def test_rollback_reachable_is_false_when_the_operator_has_no_rollback() -> None:
    """A cone with no modelled rollback path reads as 'not reachable', not 'fine'."""
    generated, twin, governor = build_field()
    empty = AdaptationModel(observed=frozenset(), observation_counts={})
    suspend = candidate_named(generated, "SUSPEND_PROCESS")
    observe = candidate_named(generated, NO_ACTION_OPERATOR_ID)
    assert suspend.rollback_operator_id == "RESUME_PROCESS"
    assert observe.rollback_operator_id is None
    with_rollback = build_intervention_cone(
        suspend, world_id="w-1", twin=twin, adaptations=empty, governor=governor
    )
    without = build_intervention_cone(
        observe, world_id="w-1", twin=twin, adaptations=empty, governor=governor
    )
    assert with_rollback.rollback_reachable() is True
    assert without.rollback_reachable() is False


def test_the_cone_charges_the_governor_for_every_node() -> None:
    """A bound nobody pays for is not a bound."""
    generated, twin, governor = build_field()
    suspend = candidate_named(generated, "SUSPEND_PROCESS")
    before = governor.spend_report()["CONE_NODE"]
    built = build_intervention_cone(
        suspend,
        world_id="w-1",
        twin=twin,
        adaptations=AdaptationModel(observed=frozenset(), observation_counts={}),
        governor=governor,
    )
    after = governor.spend_report()["CONE_NODE"]
    assert after - before == len(built.nodes)


def test_build_intervention_cone_refuses_an_untyped_adaptation_model() -> None:
    generated, twin, governor = build_field()
    suspend = candidate_named(generated, "SUSPEND_PROCESS")
    with pytest.raises(ContractError, match="AdaptationModel"):
        build_intervention_cone(
            suspend,
            world_id="w-1",
            twin=twin,
            adaptations={"observed": ["PROCESS_REPLACEMENT"]},  # type: ignore[arg-type]
            governor=governor,
        )


# --- D5.8 Action Shadow ------------------------------------------------------


def test_the_shadow_unknown_branch_name_equals_the_cone_branch_value() -> None:
    """§4.9 Rule A across the one string shared over the shadow/cone import cut."""
    assert Branch.UNKNOWN.value == UNKNOWN_BRANCH_NAME
    assert not any(
        module.endswith("aegis.cone")
        for module in (getattr(obj, "__module__", "") for obj in (ActionShadow, shadow_gate))
    )


def test_an_action_shadow_branch_node_counts_as_unobservable_even_with_a_state() -> None:
    """The load-bearing use of UNKNOWN_BRANCH_NAME: the label decides, not the state.

    A cone node on §9's Action Shadow branch is the part the twin could not describe.
    Attaching a projected state to it must not make it look observable, so the shadow
    reads the branch label by value — and this test is what stops that read from being
    quietly replaced by an ``is None`` check on ``state``.
    """
    generated, twin, governor = build_field()
    suspend = candidate_named(generated, "SUSPEND_PROCESS")
    prediction = twin.predict(suspend, world_id="credential-theft")
    snapshot = small_host().snapshot()
    root = ConeNode(
        node_id="cand00.root",
        parent_id=None,
        branch=Branch.INTENDED_SECURITY_EFFECT,
        depth=0,
        probability=0.5,
        state=prediction.predicted,
        detail="fully modelled and fully measured, so it adds nothing to the shadow",
    )
    modelled_unknown = ConeNode(
        node_id="cand00.unknown",
        parent_id=root.node_id,
        branch=Branch.UNKNOWN,
        depth=1,
        probability=0.5,
        state=prediction.predicted,
        detail="an Action Shadow node someone gave a state and a probability",
    )
    bare = InterventionCone(
        candidate_id=suspend.candidate_id, world_id="w-1", nodes=(root,), truncations=()
    )
    with_unknown = InterventionCone(
        candidate_id=suspend.candidate_id,
        world_id="w-1",
        nodes=(root, modelled_unknown),
        truncations=(),
    )
    baseline = estimate_action_shadow(
        suspend.candidate_id,
        prediction=prediction,
        cone=bare,
        snapshot=snapshot,
        resolution=resolution(),
    )
    raised = estimate_action_shadow(
        suspend.candidate_id,
        prediction=prediction,
        cone=with_unknown,
        snapshot=snapshot,
        resolution=resolution(),
    )
    assert raised.unobservable_effects == baseline.unobservable_effects + 1
    assert raised.score > baseline.score


def test_shadow_gate_takes_no_benefit_argument() -> None:
    """§10, enforced by the signature. Benefit structurally cannot override shadow."""
    parameters = inspect.signature(shadow_gate).parameters
    assert set(parameters) == {"shadow", "spec"}
    forbidden = ("benefit", "delta", "confidence", "support", "utility", "score", "reward")
    for name in parameters:
        assert not any(token in name.lower() for token in forbidden), name


def test_a_huge_predicted_benefit_cannot_move_the_shadow_gate() -> None:
    """The behavioural half of the previous test: identical shadow, identical answer."""
    high_shadow = a_shadow(unknown=40, recovery=20, evidence=20)
    spec = CATALOG["SUSPEND_PROCESS"]
    assert shadow_gate(high_shadow, spec=spec) is not AutonomyEligibility.ELIGIBLE
    assert high_shadow.score > SHADOW_AUTONOMY_CEILING
    low_shadow = a_shadow(unknown=0)
    assert low_shadow.score <= SHADOW_AUTONOMY_CEILING
    assert shadow_gate(low_shadow, spec=spec) is AutonomyEligibility.ELIGIBLE


def test_an_irreversible_operator_is_never_shadow_eligible_for_autonomy() -> None:
    """§2's IRREVERSIBLE_NEEDS_HIGHER_AUTHORITY, at zero shadow."""
    terminate = CATALOG["TERMINATE_PROCESS"]
    assert terminate.reversibility is Reversibility.IRREVERSIBLE
    assert shadow_gate(a_shadow(), spec=terminate) is AutonomyEligibility.HUMAN_REQUIRED


def test_an_observation_stays_available_at_any_shadow() -> None:
    """Being blind under uncertainty is not the safe option (§2)."""
    hopeless = a_shadow(unknown=64, recovery=64, evidence=64)
    assert hopeless.score > SHADOW_HUMAN_CEILING
    observe = CATALOG[NO_ACTION_OPERATOR_ID]
    assert shadow_gate(hopeless, spec=observe) is AutonomyEligibility.ELIGIBLE


def test_shadow_gate_refuses_a_duck_typed_score() -> None:
    class Looks:
        score = 0.0

    with pytest.raises(ContractError, match="ActionShadow"):
        shadow_gate(Looks(), spec=CATALOG["SUSPEND_PROCESS"])  # type: ignore[arg-type]


def test_a_shadow_score_must_decompose_into_the_counts_that_produced_it() -> None:
    """Φ's rule. This is the test that fails if someone reports a bare number."""
    shadow = a_shadow(unknown=3, recovery=2, evidence=1)
    assert set(shadow.components) == set(SHADOW_TERMS)
    assert abs(sum(shadow.components.values()) - shadow.score) < 1e-9
    with pytest.raises(ContractError, match="decomposition|reconstruct"):
        ActionShadow(
            candidate_id="cand00.probe",
            unmodelled_dependencies=3,
            uncertain_side_effects=0,
            unobservable_effects=0,
            upstream_truncations=0,
            score=0.99,
            components=dict.fromkeys(SHADOW_TERMS, 0.0),
        )
    with pytest.raises(ContractError, match="components keys"):
        ActionShadow(
            candidate_id="cand00.probe",
            unmodelled_dependencies=0,
            uncertain_side_effects=0,
            unobservable_effects=0,
            upstream_truncations=0,
            score=0.0,
            components={"made_up_term": 0.0},
        )


def test_the_shadow_weights_are_a_closed_normalised_table() -> None:
    assert set(SHADOW_WEIGHTS) == set(SHADOW_TERMS)
    assert abs(sum(SHADOW_WEIGHTS.values()) - 1.0) < 1e-9
    integer_fields = {
        name
        for name, spec in ActionShadow.__dataclass_fields__.items()
        if spec.type in ("int",)
    }
    assert integer_fields == set(SHADOW_TERMS)


def test_adding_a_cone_can_only_raise_the_shadow() -> None:
    """The monotonicity the generation-time shadow depends on for safety."""
    generated, twin, governor = build_field()
    suspend = candidate_named(generated, "SUSPEND_PROCESS")
    prediction = twin.predict(suspend, world_id="credential-theft")
    snapshot = small_host().snapshot()
    base = generation_shadow(
        suspend.candidate_id, prediction=prediction, snapshot=snapshot, resolution=resolution()
    )
    built = build_intervention_cone(
        suspend,
        world_id="credential-theft",
        twin=twin,
        adaptations=AdaptationModel(
            observed=frozenset({AdaptationKind.PERSISTENCE_RESTART}),
            observation_counts={AdaptationKind.PERSISTENCE_RESTART: 2},
        ),
        governor=governor,
    )
    full = estimate_action_shadow(
        suspend.candidate_id,
        prediction=prediction,
        cone=built,
        snapshot=snapshot,
        resolution=resolution(),
    )
    assert full.score >= base.score
    assert full.uncertain_side_effects >= base.uncertain_side_effects
    assert full.unobservable_effects >= base.unobservable_effects
    assert full.score > base.score, "a cone with unmeasured branches must move the score"


def test_calibrate_shadow_returns_none_below_thirty_pairs() -> None:
    """ADR-0004: None is not zero, and it is not a pass. Falsifier F3 reads this."""

    def pair(index: int, *, distance: float) -> tuple[ActionShadow, InterventionResidual]:
        return (
            a_shadow(f"cand{index:02d}.probe", unknown=index),
            InterventionResidual(
                action_id=f"act-{index:04d}",
                distance=distance,
                components={},
                attribution=ResidualCause.UNATTRIBUTABLE,
                predicted_digest=digest_of_bytes(b"predicted"),
                observed_digest=digest_of_bytes(b"observed"),
                detail="simulated-host residual (ADR-0046)",
            ),
        )

    assert MIN_CALIBRATION_SAMPLES == 30
    short = [pair(index, distance=min(1.0, index / 40.0)) for index in range(29)]
    result = calibrate_shadow(short)
    assert result.n == 29
    assert result.rank_correlation is None
    assert "MIN_CALIBRATION_SAMPLES" in result.detail

    enough = [pair(index, distance=min(1.0, index / 40.0)) for index in range(30)]
    calibrated = calibrate_shadow(enough)
    assert calibrated.n == 30
    assert calibrated.rank_correlation is not None
    assert calibrated.rank_correlation > 0.9, "the fixture is monotone by construction"
    assert calibrate_shadow([]).rank_correlation is None


def test_calibrate_shadow_returns_none_when_a_ranking_has_no_variation() -> None:
    """A constant shadow ranks nothing, and None says so rather than 0.0."""
    flat = [
        (
            a_shadow(f"cand{index:02d}.probe", unknown=1),
            InterventionResidual(
                action_id=f"act-{index:04d}",
                distance=index / 40.0,
                components={},
                attribution=ResidualCause.UNATTRIBUTABLE,
                predicted_digest=digest_of_bytes(b"p"),
                observed_digest=digest_of_bytes(b"o"),
                detail="simulated",
            ),
        )
        for index in range(MIN_CALIBRATION_SAMPLES)
    ]
    result = calibrate_shadow(flat)
    assert result.n == MIN_CALIBRATION_SAMPLES
    assert result.rank_correlation is None
    assert "no variation" in result.detail
    assert sum(row[2] for row in result.buckets) == MIN_CALIBRATION_SAMPLES


# --- unprivileged-by-construction -------------------------------------------


def test_no_field_module_reaches_the_privileged_plane() -> None:
    """Integration-plan rule 6, checked over this package's own source by AST."""
    import ast
    from pathlib import Path

    forbidden = (
        "pocketsec.stage5.authority.tokens",
        "pocketsec.stage5.executor.transactional",
        "pocketsec.stage5.executor.journal",
    )
    roots = [
        Path(field_module.__file__),
        Path(cone_module.__file__),
        Path(inspect.getsourcefile(ResponseTwin) or ""),
        Path(inspect.getsourcefile(ActionShadow) or ""),
    ]
    for path in roots:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                names.append(node.module)
                names.extend(f"{node.module}.{alias.name}" for alias in node.names)
        for module in names:
            assert not module.startswith(forbidden), f"{path.name} imports {module}"
        assert "SimulatedHost" not in {
            node.id for node in ast.walk(tree) if isinstance(node, ast.Name)
        }, f"{path.name} names SimulatedHost"


def test_a_field_truncation_always_carries_a_reason() -> None:
    """Truncation is explicit or it is not truncation."""
    with pytest.raises(ContractError):
        FieldTruncation(what="candidate", identifier="x", reason="   ")
