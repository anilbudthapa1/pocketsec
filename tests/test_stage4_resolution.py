"""Behaviour tests for Stage 4's resolution package — D4.8, D4.9, D4.10 and D4.18's pairs.

These tests are written to fail if someone weakens an invariant, not to confirm that the
objects can be constructed. The four that matter most, in order:

1. ``test_unidentifiable_requires_empty_discriminating_observations`` — the §19 invariant.
   Weaken ``IdentifiabilityVerdict.__post_init__`` and this is the test that goes red.
2. ``test_horizon_exhaustion_never_resolves_and_never_says_benign`` — §29's "it cannot
   silently simplify into benign".
3. ``test_nonidentifiable_pairs_are_actually_nonidentifiable`` — the construction is
   asserted, not intended. A pair one observation separates is not a pair.
4. ``test_every_granted_observation_has_a_matching_escalation_decision`` — ADR-0035: AOP
   is the only escalation path.

No test here writes to ``experiments/registry.jsonl`` or to any path outside ``tmp_path``.
"""

from __future__ import annotations

import ast
import math
from pathlib import Path

import pytest

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage0.contracts.threat_prediction_v1 import (
    NON_COMMITTAL_VERDICTS,
    ThreatPredictionV1,
    ComputePath,
    Verdict,
)
from pocketsec.stage1.observation.policy import (
    AdaptiveObservationPolicy,
    AOPBudget,
    MANDATORY_SIGNALS,
)
from pocketsec.stage1.telemetry.raw_event_v1 import SensorPath
from pocketsec.stage4.cones.incident_cone import compose_cones
from pocketsec.stage4.evidence.calibration import (
    CALIBRATION_ALERT_ECE,
    CALIBRATION_BINS,
    MAX_CALIBRATION_HISTORY,
    MAX_TRACKED_EPOCHS,
    MIN_CALIBRATION_SAMPLES,
    UNMEASURED_ABSTENTION_PRESSURE,
    CalibrationReport,
    EpochCalibration,
    epoch_key,
)
from pocketsec.stage4.evidence.sequential import (
    BENIGN_NULL_DESCRIPTION,
    E_VALUE_CEILING,
    MAX_EVIDENCE_STEPS,
    STOP_CONTRADICTION_THRESHOLD,
    STOP_SUPPORT_THRESHOLD,
    SequentialEvidence,
    StopReason,
    benign_null_likelihood_ratio,
    model_score_evidence,
    start_benign_null_evidence,
)
from pocketsec.stage4.identifiability.horizon import (
    DEFAULT_HORIZON_ESCALATIONS,
    DEFAULT_HORIZON_TRANSITIONS,
    DEFAULT_HORIZON_WORK_UNITS,
    HorizonOutcome,
    ResolutionHorizon,
)
from pocketsec.stage4.identifiability.resolution import (
    IDENTIFIABILITY_MARGIN,
    IdentifiabilityState,
    IdentifiabilityVerdict,
    mechanism_polarity,
)
from pocketsec.stage4.identifiability.resolution import test_identifiability as identifiability_of
from pocketsec.stage4.labs.incident_corpus import identity_keys
from pocketsec.stage4.labs.nonidentifiable import (
    NONIDENTIFIABLE_EXPECTED,
    NONIDENTIFIABLE_FORBIDDEN,
    RESOLVING_SIGNAL,
    SIGNAL_VOCABULARY,
    apply_granted_observation,
    build_corpus_visibility_model,
    build_nonidentifiable_pairs,
    build_resolvable_after_one_observation,
    field_for_nonidentifiable_pair,
    field_for_resolvable_case,
    reachable_signal_union,
    semantic_key_digest,
)
from pocketsec.stage4.sensing.active_plan import (
    ACTION_SIGNALS,
    MAX_CANDIDATE_ACTIONS,
    MIN_DISCRIMINATION_TO_SPEND,
    NO_OBSERVATION_POLICY,
    SENSOR_COSTS,
    UNMEASURED_COST_REASON,
    ObservationPlan,
    ObservationRequest,
    SensorAction,
    SensorCost,
    plan_discriminating_observation,
)
from pocketsec.stage4.sensing.simulate import (
    js_divergence,
    measure_sensor_costs,
    signal_discrimination,
    simulate_sensor_value,
)

PAIR_COUNT = 20
RESOLVABLE_COUNT = 12
SEED = 17


# --- fixtures ---------------------------------------------------------------


@pytest.fixture(scope="module")
def visibility():
    return build_corpus_visibility_model()


@pytest.fixture(scope="module")
def pairs():
    return build_nonidentifiable_pairs(count=PAIR_COUNT, seed=SEED)


@pytest.fixture(scope="module")
def resolvable():
    return build_resolvable_after_one_observation(count=RESOLVABLE_COUNT, seed=SEED)


@pytest.fixture(scope="module")
def measured_costs(resolvable, visibility):
    field = field_for_resolvable_case(resolvable[0])
    return measure_sensor_costs(field, cones=compose_cones(field), model=visibility)


def _plan(field, *, visibility, observation=None, costs=None, now_ns: int = 1_000_000):
    return plan_discriminating_observation(
        field,
        cones=compose_cones(field),
        shadow=None,
        observation=observation,
        now_ns=now_ns,
        model=visibility,
        costs=SENSOR_COSTS if costs is None else costs,
    )


def _verdict(state, *, discriminating=(), mechanism="approved_administration"):
    return IdentifiabilityVerdict(
        state=state,
        leading_world_id="w-a",
        support_margin=0.0,
        material_alternatives=("w-b",),
        discriminating_observations=discriminating,
        affordable=False,
        shadow_penalty=0.0,
        detail="constructed for test",
        leading_mechanism_id=mechanism,
    )


# --- D4.18: the construction is asserted, not intended ----------------------


def test_action_signal_union_is_the_whole_corpus_vocabulary():
    """If an action reached a signal outside the vocabulary, "no action discriminates"
    would stop being a claim about the whole observable space."""
    assert reachable_signal_union() == SIGNAL_VOCABULARY
    assert set(ACTION_SIGNALS) == set(SensorAction)
    assert all(signals for signals in ACTION_SIGNALS.values())
    assert len(SensorAction) <= MAX_CANDIDATE_ACTIONS
    assert MANDATORY_SIGNALS <= SIGNAL_VOCABULARY
    assert RESOLVING_SIGNAL not in MANDATORY_SIGNALS


def test_nonidentifiable_pairs_are_actually_nonidentifiable(pairs, visibility):
    """Identical semantic keys under EVERY sensor path, and zero discrimination for
    EVERY sensor action. A pair that fails either is not a non-identifiability test."""
    assert len(pairs) == PAIR_COUNT
    for benign, malicious in pairs:
        for sensor in SensorPath:
            assert semantic_key_digest(benign, sensor=sensor) == semantic_key_digest(
                malicious, sensor=sensor
            )
        field = field_for_nonidentifiable_pair((benign, malicious))
        cones = compose_cones(field)
        for action in SensorAction:
            assert (
                simulate_sensor_value(field, action, cones=cones, model=visibility) == 0.0
            ), action
        for signal in SIGNAL_VOCABULARY:
            assert signal_discrimination(field, signal, cones=cones, model=visibility) == 0.0


def test_nonidentifiable_worlds_agree_on_evidence_and_differ_on_consequence(pairs):
    """Equal predictions are what makes the pair non-identifiable; unequal consequence is
    what gives the anti-alarm tie-break something to fail on."""
    for pair in pairs:
        field = field_for_nonidentifiable_pair(pair)
        first, second = field.worlds
        assert first.expected_evidence == second.expected_evidence == NONIDENTIFIABLE_EXPECTED
        assert first.forbidden_evidence == second.forbidden_evidence == NONIDENTIFIABLE_FORBIDDEN
        assert first.latent_state.consequence != second.latent_state.consequence


def test_corpus_cases_use_session_unique_identities(pairs, resolvable):
    """Stage 1 carries lineage state across scenarios; reusing identities silently erases
    the corpus's own signal (MEMORY.md — it retracted a published result)."""
    seen: set[tuple[str, str]] = set()
    cases = [case for pair in pairs for case in pair] + list(resolvable)
    for case in cases:
        keys = identity_keys(case)
        assert keys, case.incident_id
        assert keys.isdisjoint(seen), case.incident_id
        seen |= keys


def test_corpora_are_deterministic_under_seed(pairs, resolvable):
    again_pairs = build_nonidentifiable_pairs(count=PAIR_COUNT, seed=SEED)
    again_cases = build_resolvable_after_one_observation(count=RESOLVABLE_COUNT, seed=SEED)
    assert [c.incident_id for p in again_pairs for c in p] == [
        c.incident_id for p in pairs for c in p
    ]
    assert [b.fields for p in again_pairs for c in p for b in c.scenario.behaviours] == [
        b.fields for p in pairs for c in p for b in c.scenario.behaviours
    ]
    assert [c.incident_id for c in again_cases] == [c.incident_id for c in resolvable]


def test_corpus_builders_refuse_a_nonpositive_count():
    with pytest.raises(ContractError):
        build_nonidentifiable_pairs(count=0, seed=1)
    with pytest.raises(ContractError):
        build_resolvable_after_one_observation(count=-3, seed=1)


# --- D4.8: the invariant ----------------------------------------------------


def test_unidentifiable_requires_empty_discriminating_observations():
    """THE invariant of §19. A case one observation would separate is
    INSUFFICIENT_EVIDENCE, and allowing both would let "we did not look" be reported as
    "it is impossible"."""
    with pytest.raises(ContractError) as excinfo:
        _verdict(IdentifiabilityState.UNIDENTIFIABLE, discriminating=("TRACE_FILE_ACCESS_SUBTREE",))
    assert "discriminating_observations" in str(excinfo.value)
    # The legal shape still constructs.
    assert _verdict(IdentifiabilityState.UNIDENTIFIABLE).discriminating_observations == ()


def test_every_nonidentifiable_pair_returns_unidentifiable_and_abstains(pairs, visibility):
    for pair in pairs:
        field = field_for_nonidentifiable_pair(pair)
        plan = _plan(field, visibility=visibility)
        verdict = identifiability_of(field, shadow=None, plan=plan)
        assert verdict.state is IdentifiabilityState.UNIDENTIFIABLE, pair[0].incident_id
        assert verdict.discriminating_observations == ()
        assert verdict.to_verdict() is Verdict.UNIDENTIFIABLE
        assert verdict.abstains() is True
        assert verdict.affordable is False
        assert len(plan.refused) == len(SensorAction)
        assert plan.requests == ()


def test_nonidentifiable_leader_is_never_the_more_alarming_world(pairs, visibility):
    """A system that always names a culprit is not doing causal reasoning. With supports
    level, the leading world's consequence must not exceed the alternative's."""
    for pair in pairs:
        field = field_for_nonidentifiable_pair(pair)
        verdict = identifiability_of(field, shadow=None, plan=_plan(field, visibility=visibility))
        leader = field.world(verdict.leading_world_id or "")
        assert leader is not None
        others = [w for w in field.worlds if w.world_id != leader.world_id]
        assert others
        for other in others:
            assert leader.latent_state.consequence <= other.latent_state.consequence


def test_resolvable_cases_are_insufficient_evidence_not_unidentifiable(
    resolvable, visibility, measured_costs
):
    """The contrast case. Coming back UNIDENTIFIABLE here would mean the engine cannot
    tell "cannot decide" from "have not looked yet" — falsifier F6."""
    for case in resolvable:
        field = field_for_resolvable_case(case)
        aop = AdaptiveObservationPolicy()
        plan = _plan(field, visibility=visibility, observation=aop, costs=measured_costs)
        verdict = identifiability_of(field, shadow=None, plan=plan)
        assert verdict.state is IdentifiabilityState.INSUFFICIENT_EVIDENCE, case.incident_id
        assert verdict.state is not IdentifiabilityState.UNIDENTIFIABLE
        assert verdict.discriminating_observations == (
            SensorAction.TRACE_FILE_ACCESS_SUBTREE.value,
        )
        assert verdict.to_verdict() is Verdict.INSUFFICIENT_EVIDENCE
        assert verdict.abstains() is True


def test_resolvable_cases_identify_after_exactly_one_granted_observation(
    resolvable, visibility, measured_costs
):
    for case in resolvable:
        field = field_for_resolvable_case(case)
        aop = AdaptiveObservationPolicy()
        plan = _plan(field, visibility=visibility, observation=aop, costs=measured_costs)
        granted = plan.granted_requests()
        assert len(granted) == 1, case.incident_id
        request, decision = granted[0]
        assert RESOLVING_SIGNAL in request.signals
        assert decision.escalated is True

        resolved_field = apply_granted_observation(field, RESOLVING_SIGNAL, observed=True)
        verdict = identifiability_of(
            resolved_field,
            shadow=None,
            plan=_plan(
                resolved_field, visibility=visibility, observation=aop, costs=measured_costs
            ),
        )
        assert verdict.state is IdentifiabilityState.IDENTIFIED, case.incident_id
        assert verdict.support_margin >= IDENTIFIABILITY_MARGIN
        assert verdict.to_verdict() is Verdict.MALICIOUS
        assert verdict.abstains() is False
        leader = resolved_field.world(verdict.leading_world_id or "")
        assert leader is not None and leader.mechanism_id == case.truth.mechanism_id


def test_missing_plan_is_insufficient_evidence_and_never_unidentifiable(pairs, visibility):
    """plan=None means the planner did not run. Non-identifiability is not established by
    failing to look, and a planner crash must not be able to certify an unresolvable
    incident."""
    field = field_for_nonidentifiable_pair(pairs[0])
    verdict = identifiability_of(field, shadow=None, plan=None)
    assert verdict.state is IdentifiabilityState.INSUFFICIENT_EVIDENCE
    assert verdict.discriminating_observations == ()
    assert verdict.affordable is False
    assert "no observation plan" in verdict.detail


def test_unknown_world_only_field_returns_unknown(pairs):
    from pocketsec.stage4.worlds.field import unknown_world

    field = field_for_nonidentifiable_pair(pairs[0]).with_worlds(
        [unknown_world("inc-unknown", at_sequence=0)]
    )
    verdict = identifiability_of(field, shadow=None, plan=None)
    assert verdict.state is IdentifiabilityState.UNKNOWN
    assert verdict.to_verdict() is Verdict.UNKNOWN
    assert verdict.abstains() is True


def test_sensor_shadow_penalty_can_only_make_identification_harder(resolvable, visibility):
    """A blind region must never help. Confidence under a drop is <= confidence at full
    telemetry — falsifier F4 is the most dangerous failure available to this stage."""

    class _Shadow:
        def __init__(self, penalty: float) -> None:
            self._penalty = penalty

        def confidence_penalty(self) -> float:
            return self._penalty

        def blind_signals(self) -> frozenset[str]:
            return frozenset()

    field = apply_granted_observation(
        field_for_resolvable_case(resolvable[0]), RESOLVING_SIGNAL, observed=True
    )
    clear = identifiability_of(field, shadow=None, plan=None)
    assert clear.state is IdentifiabilityState.IDENTIFIED
    blinded = identifiability_of(field, shadow=_Shadow(1.0), plan=None)
    assert blinded.state is not IdentifiabilityState.IDENTIFIED
    assert blinded.abstains() is True
    previous = -1.0
    for penalty in (0.0, 0.25, 0.5, 1.0):
        verdict = identifiability_of(field, shadow=_Shadow(penalty), plan=None)
        assert verdict.shadow_penalty >= previous
        previous = verdict.shadow_penalty


def test_state_to_verdict_table_matches_adr_0032():
    table = {
        (IdentifiabilityState.IDENTIFIED, "compromised_admin_session"): Verdict.MALICIOUS,
        (IdentifiabilityState.IDENTIFIED, "approved_administration"): Verdict.BENIGN,
        (IdentifiabilityState.IDENTIFIED, "coincident_privileged_maintenance"): Verdict.SUSPICIOUS,
        (IdentifiabilityState.UNIDENTIFIABLE, "approved_administration"): Verdict.UNIDENTIFIABLE,
        (
            IdentifiabilityState.INSUFFICIENT_EVIDENCE,
            "approved_administration",
        ): Verdict.INSUFFICIENT_EVIDENCE,
        (IdentifiabilityState.UNKNOWN, "unresolved_novel_mechanism"): Verdict.UNKNOWN,
    }
    for (state, mechanism), expected in table.items():
        verdict = _verdict(state, mechanism=mechanism)
        assert verdict.to_verdict() is expected, (state, mechanism)
        assert verdict.abstains() is (expected in NON_COMMITTAL_VERDICTS)


def test_an_unlisted_mechanism_never_maps_to_benign():
    """The permissive default is the same defect as a bad horizon: a mechanism this table
    has never seen must not be able to clear an incident."""
    assert mechanism_polarity("something_nobody_measured") == "AMBIGUOUS"
    verdict = _verdict(IdentifiabilityState.IDENTIFIED, mechanism="something_nobody_measured")
    assert verdict.to_verdict() is Verdict.SUSPICIOUS
    unnamed = IdentifiabilityVerdict(
        state=IdentifiabilityState.IDENTIFIED,
        leading_world_id="w-a",
        support_margin=0.9,
        material_alternatives=(),
        discriminating_observations=(),
        affordable=True,
        shadow_penalty=0.0,
        detail="no mechanism recorded",
    )
    assert unnamed.to_verdict() is not Verdict.BENIGN


def test_verdict_feeds_threat_prediction_without_violating_the_abstention_contract(
    pairs, visibility
):
    """The abstention half of ADR-0032's table is checked by Stage 0's contract, not by
    review — so run it through the contract."""
    field = field_for_nonidentifiable_pair(pairs[0])
    verdict = identifiability_of(field, shadow=None, plan=_plan(field, visibility=visibility))
    prediction = ThreatPredictionV1(
        prediction_id="pred-s4-0001",
        sequence_id=pairs[0][0].incident_id,
        verdict=verdict.to_verdict(),
        confidence=0.2,
        novelty_score=0.3,
        uncertainty=0.9,
        model_state_version="stage4-test",
        compute_path=ComputePath.STATISTICAL,
        abstained=verdict.abstains(),
        calibration_id=None,
    )
    assert prediction.verdict is Verdict.UNIDENTIFIABLE
    assert prediction.abstained is True
    assert prediction.is_calibrated is False


def test_verdict_refuses_missing_detail_and_leaderless_identification():
    with pytest.raises(ContractError):
        IdentifiabilityVerdict(
            state=IdentifiabilityState.UNKNOWN,
            leading_world_id=None,
            support_margin=0.0,
            material_alternatives=(),
            discriminating_observations=(),
            affordable=False,
            shadow_penalty=0.0,
            detail="",
        )
    with pytest.raises(ContractError):
        IdentifiabilityVerdict(
            state=IdentifiabilityState.IDENTIFIED,
            leading_world_id=None,
            support_margin=0.5,
            material_alternatives=(),
            discriminating_observations=(),
            affordable=True,
            shadow_penalty=0.0,
            detail="identified with no leader",
        )
    with pytest.raises(ContractError):
        IdentifiabilityVerdict(
            state=IdentifiabilityState.UNKNOWN,
            leading_world_id="w-a",
            support_margin=1.5,
            material_alternatives=(),
            discriminating_observations=(),
            affordable=False,
            shadow_penalty=0.0,
            detail="margin out of range",
        )


# --- D4.8: the horizon ------------------------------------------------------


def test_horizon_exhaustion_never_resolves_and_never_says_benign():
    """§29: "It cannot silently simplify into benign." The most important assertion here."""
    exhausted = ResolutionHorizon().charge(
        transitions=DEFAULT_HORIZON_TRANSITIONS,
        work_units=DEFAULT_HORIZON_WORK_UNITS,
        escalations=DEFAULT_HORIZON_ESCALATIONS,
    )
    assert exhausted.exhausted() is True
    non_committal = (
        IdentifiabilityState.UNIDENTIFIABLE,
        IdentifiabilityState.INSUFFICIENT_EVIDENCE,
        IdentifiabilityState.UNKNOWN,
    )
    for state in non_committal:
        for horizon in (ResolutionHorizon(), exhausted):
            verdict = _verdict(state)
            assert horizon.outcome(verdict) is not HorizonOutcome.RESOLVED
            assert verdict.to_verdict() is not Verdict.BENIGN
            assert verdict.to_verdict() in NON_COMMITTAL_VERDICTS
            assert verdict.abstains() is True


def test_horizon_routes_each_state_to_the_intended_ending():
    fresh = ResolutionHorizon()
    assert fresh.outcome(_verdict(IdentifiabilityState.IDENTIFIED)) is HorizonOutcome.RESOLVED
    assert (
        fresh.outcome(_verdict(IdentifiabilityState.UNIDENTIFIABLE))
        is HorizonOutcome.PRESERVE_UNRESOLVED
    )
    assert (
        fresh.outcome(_verdict(IdentifiabilityState.INSUFFICIENT_EVIDENCE, discriminating=("A",)))
        is HorizonOutcome.REQUEST_HIGHER_OBSERVATION_TIER
    )
    spent = fresh.charge(escalations=DEFAULT_HORIZON_ESCALATIONS)
    assert spent.escalations_remaining() == 0
    assert (
        spent.outcome(_verdict(IdentifiabilityState.INSUFFICIENT_EVIDENCE, discriminating=("A",)))
        is HorizonOutcome.ESCALATE_TO_ANALYST
    )
    assert (
        spent.outcome(_verdict(IdentifiabilityState.UNIDENTIFIABLE))
        is HorizonOutcome.PRESERVE_UNRESOLVED
    )


def test_horizon_charge_is_immutable_and_clamped():
    horizon = ResolutionHorizon()
    charged = horizon.charge(transitions=3, work_units=7, escalations=1)
    assert horizon.consumed_transitions == 0
    assert charged.consumed_transitions == 3
    assert charged is not horizon
    overrun = horizon.charge(work_units=DEFAULT_HORIZON_WORK_UNITS * 10)
    assert overrun.consumed_work_units == DEFAULT_HORIZON_WORK_UNITS
    with pytest.raises(ContractError):
        horizon.charge(transitions=-1)


def test_horizon_exhausts_on_any_single_budget():
    for kwargs in (
        {"transitions": DEFAULT_HORIZON_TRANSITIONS},
        {"work_units": DEFAULT_HORIZON_WORK_UNITS},
        {"escalations": DEFAULT_HORIZON_ESCALATIONS},
    ):
        assert ResolutionHorizon().charge(**kwargs).exhausted() is True


def test_horizon_refuses_a_zero_budget_and_a_malformed_verdict():
    with pytest.raises(ContractError):
        ResolutionHorizon(max_work_units=0)
    with pytest.raises(ContractError):
        ResolutionHorizon(max_transitions=-1)
    with pytest.raises(ContractError):
        ResolutionHorizon().outcome(object())  # type: ignore[arg-type]


# --- D4.9: the planner ------------------------------------------------------


def test_planner_refuses_every_action_without_an_observation_policy(resolvable, visibility, measured_costs):
    """observation=None is legal and means every request is refused. The planner does not
    escalate on its own initiative (ADR-0035)."""
    field = field_for_resolvable_case(resolvable[0])
    plan = _plan(field, visibility=visibility, observation=None, costs=measured_costs)
    assert plan.requests == ()
    assert plan.escalations == ()
    assert plan.granted() == ()
    reasons = {reason for _, reason in plan.refused}
    assert NO_OBSERVATION_POLICY in reasons


def test_planner_refuses_to_rank_on_unmeasured_costs(resolvable, visibility):
    """SENSOR_COSTS ships unmeasured. A guessed cost would make the utility ordering a
    fabricated result."""
    assert all(not cost.is_measured for cost in SENSOR_COSTS.values())
    assert all(cost.total() is None for cost in SENSOR_COSTS.values())
    field = field_for_resolvable_case(resolvable[0])
    aop = AdaptiveObservationPolicy()
    plan = _plan(field, visibility=visibility, observation=aop, costs=SENSOR_COSTS)
    assert plan.requests == ()
    assert UNMEASURED_COST_REASON in {reason for _, reason in plan.refused}
    assert aop.report().escalations_opened == 0


def test_measured_costs_carry_provenance_and_unmeasured_ones_refuse_to_claim_it(measured_costs):
    for action, cost in measured_costs.items():
        assert cost.is_measured
        assert cost.provenance == "pocketsec.stage4.sensing.simulate:measure_sensor_costs"
        assert cost.total() is not None and cost.total() > 0.0
        assert cost.authority_risk_units >= 0.0
        assert action in SensorAction
    with pytest.raises(ContractError):
        SensorCost(
            cpu_units=1.0,
            memory_bytes=1,
            telemetry_bytes=1,
            authority_risk_units=1.0,
            provenance="UNMEASURED",
        )
    with pytest.raises(ContractError):
        SensorCost(
            cpu_units=None,
            memory_bytes=1,
            telemetry_bytes=1,
            authority_risk_units=1.0,
            provenance="somewhere:something",
        )


def test_observation_request_refuses_an_unmeasured_cost():
    with pytest.raises(ContractError):
        ObservationRequest(
            sensor_method=SensorAction.CAPTURE_DNS_METADATA,
            target="inc:CAPTURE_DNS_METADATA",
            signals=frozenset({"boundary_crossing"}),
            discrimination=0.5,
            consequence=1.0,
            cost=SENSOR_COSTS[SensorAction.CAPTURE_DNS_METADATA],
            utility=0.5,
        )


def test_below_minimum_discrimination_the_action_is_refused_with_the_reason_recorded(
    pairs, visibility, measured_costs
):
    """§17's rule, and the whole low-overhead argument. The refusal string is kept so a
    run with no collection can be audited for the decision rather than the silence."""
    field = field_for_nonidentifiable_pair(pairs[0])
    aop = AdaptiveObservationPolicy()
    plan = _plan(field, visibility=visibility, observation=aop, costs=measured_costs)
    assert plan.requests == ()
    assert len(plan.refused) == len(SensorAction)
    for action, reason in plan.refused:
        assert "MIN_DISCRIMINATION_TO_SPEND" in reason
        assert str(MIN_DISCRIMINATION_TO_SPEND) in reason
        assert action in SensorAction
    assert aop.report().escalations_opened == 0


def test_every_granted_observation_has_a_matching_escalation_decision(
    resolvable, visibility, measured_costs
):
    """ADR-0035: AOP is the only escalation path, so a grant with no matching request
    would mean Stage 4 collected something it never planned."""
    aop = AdaptiveObservationPolicy()
    total_granted = 0
    for case in resolvable:
        field = field_for_resolvable_case(case)
        plan = _plan(field, visibility=visibility, observation=aop, costs=measured_costs)
        pairs_out = plan.granted_requests()
        assert len(pairs_out) == len(plan.granted())
        for request, decision in pairs_out:
            assert decision.target == request.target
            assert decision.escalated is True
        total_granted += len(pairs_out)
    report = aop.report()
    assert total_granted <= report.escalations_opened + report.currently_active
    assert report.escalations_opened >= 1


def test_plan_refuses_a_grant_it_never_requested(measured_costs):
    from pocketsec.stage1.observation.policy import EscalationDecision, ObservationLevel

    cost = measured_costs[SensorAction.TRACE_FILE_ACCESS_SUBTREE]
    request = ObservationRequest(
        sensor_method=SensorAction.TRACE_FILE_ACCESS_SUBTREE,
        target="inc:TRACE_FILE_ACCESS_SUBTREE",
        signals=frozenset({RESOLVING_SIGNAL}),
        discrimination=0.5,
        consequence=1.0,
        cost=cost,
        utility=0.5,
    )
    rogue = EscalationDecision(
        target="inc:SOMETHING_ELSE", level=ObservationLevel.HIGH_RESOLUTION,
        budget_score=0.9, escalated=True,
    )
    plan = ObservationPlan(requests=(request,), refused=(), escalations=(rogue,))
    with pytest.raises(ContractError):
        plan.granted_requests()


def test_plan_refuses_unordered_requests_and_too_many_candidates(measured_costs):
    cost = measured_costs[SensorAction.TRACE_FILE_ACCESS_SUBTREE]

    def request(action, utility):
        return ObservationRequest(
            sensor_method=action,
            target=f"inc:{action.value}",
            signals=frozenset({"file_staging"}),
            discrimination=0.5,
            consequence=1.0,
            cost=cost,
            utility=utility,
        )

    with pytest.raises(ContractError):
        ObservationPlan(
            requests=(
                request(SensorAction.TRACE_FILE_ACCESS_SUBTREE, 0.1),
                request(SensorAction.CAPTURE_DNS_METADATA, 0.9),
            ),
            refused=(),
        )
    too_many = tuple(
        (action, "refused for the bound test")
        for action in list(SensorAction) * 2
    )[: MAX_CANDIDATE_ACTIONS + 1]
    with pytest.raises(ContractError):
        ObservationPlan(requests=(), refused=too_many)


def test_planner_never_raises_an_aop_cap_and_respects_the_per_incident_escalation_bound(
    resolvable, visibility, measured_costs
):
    """Stage 4 respects AOP's caps; it does not raise them. An incident that could raise
    the cap would be an unbudgeted amplification path."""
    budget = AOPBudget()
    aop = AdaptiveObservationPolicy(budget=budget)
    field = field_for_resolvable_case(resolvable[0])
    _plan(field, visibility=visibility, observation=aop, costs=measured_costs)
    assert aop.budget.to_dict() == AOPBudget().to_dict()
    assert aop.report().escalations_opened <= DEFAULT_HORIZON_ESCALATIONS


def test_planner_refuses_a_negative_timestamp(resolvable, visibility, measured_costs):
    field = field_for_resolvable_case(resolvable[0])
    with pytest.raises(ContractError):
        plan_discriminating_observation(
            field,
            cones=None,
            shadow=None,
            observation=None,
            now_ns=-1,
            model=visibility,
            costs=measured_costs,
        )


def test_simulation_module_cannot_escalate():
    """Structural, by AST. The simulation runs BEFORE any escalation, so the module that
    performs it must not be able to open a sensor at all."""
    source = Path("pocketsec/stage4/sensing/simulate.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                imported.add(f"{node.module}.{alias.name}")
        elif isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.name)
    assert not any("AdaptiveObservationPolicy" in name for name in imported)
    assert ".consider" not in source
    assert "record_observation" not in source


def test_simulation_does_not_escalate_when_an_aop_is_available(resolvable, visibility):
    aop = AdaptiveObservationPolicy()
    field = field_for_resolvable_case(resolvable[0])
    cones = compose_cones(field)
    for action in SensorAction:
        simulate_sensor_value(field, action, cones=cones, model=visibility)
    assert aop.report().escalations_opened == 0
    assert aop.report().currently_active == 0


def test_discrimination_is_bounded_and_zero_for_a_single_world_field(resolvable, visibility):
    field = field_for_resolvable_case(resolvable[0])
    single = field.with_worlds([field.worlds[0]])
    for action in SensorAction:
        assert simulate_sensor_value(single, action, cones=None, model=visibility) == 0.0
        value = simulate_sensor_value(field, action, cones=None, model=visibility)
        assert 0.0 <= value <= 1.0


def test_simulate_refuses_an_unknown_action(resolvable):
    field = field_for_resolvable_case(resolvable[0])
    with pytest.raises(ContractError):
        simulate_sensor_value(field, "NOT_A_SENSOR_ACTION", cones=None, model=None)  # type: ignore[arg-type]


def test_js_divergence_is_a_bounded_symmetric_measure():
    assert js_divergence({"a": 1.0}, {"a": 1.0}) == 0.0
    assert math.isclose(js_divergence({"a": 1.0, "b": 0.0}, {"a": 0.0, "b": 1.0}), 1.0)
    left, right = {"a": 0.7, "b": 0.3}, {"a": 0.2, "b": 0.8}
    assert math.isclose(js_divergence(left, right), js_divergence(right, left))
    assert js_divergence({}, {}) == 0.0
    assert js_divergence({"a": 0.0}, {"a": 0.0}) == 0.0


def test_targeted_sensing_costs_strictly_less_than_always_on(
    resolvable, visibility, measured_costs
):
    """The §17 / G4.5 argument, as a within-run comparison in this process: the planner's
    granted set versus "turn everything on all the time" (B3). Absolute microseconds are
    not claimed — only the ratio, measured in one run."""
    field = field_for_resolvable_case(resolvable[0])
    aop = AdaptiveObservationPolicy()
    plan = _plan(field, visibility=visibility, observation=aop, costs=measured_costs)
    granted = plan.granted_requests()
    assert granted

    targeted_bytes = sum(request.cost.telemetry_bytes or 0 for request, _ in granted)
    targeted_cpu = sum(request.cost.cpu_units or 0.0 for request, _ in granted)
    always_on_bytes = sum(cost.telemetry_bytes or 0 for cost in measured_costs.values())
    always_on_cpu = sum(cost.cpu_units or 0.0 for cost in measured_costs.values())

    assert targeted_bytes < always_on_bytes
    assert targeted_cpu < always_on_cpu


# --- D4.10: sequential evidence --------------------------------------------


def test_anytime_valid_cannot_be_claimed_for_a_null_this_module_cannot_construct():
    """§31: "without pretending all model scores satisfy statistical guarantees" — as a
    boolean a reader can check, and one a caller cannot forge."""
    with pytest.raises(ContractError):
        SequentialEvidence(
            world_id="w-a",
            e_value=1.0,
            steps=0,
            null_description="a model score, honestly described",
            anytime_valid=True,
        )
    assert start_benign_null_evidence("w-a").anytime_valid is True
    assert model_score_evidence("w-a", null_description="tcn score").anytime_valid is False
    with pytest.raises(ContractError):
        model_score_evidence("w-a", null_description=BENIGN_NULL_DESCRIPTION)


def test_null_description_is_required_non_empty():
    for description in ("", "   "):
        with pytest.raises(ContractError):
            SequentialEvidence(
                world_id="w-a", e_value=1.0, steps=0, null_description=description
            )


def test_e_value_is_clipped_at_the_ceiling_and_steps_are_bounded():
    evidence = start_benign_null_evidence("w-a")
    ratio = 10.0
    while evidence.is_running:
        evidence = evidence.update(ratio)
    assert evidence.e_value <= E_VALUE_CEILING
    assert evidence.steps <= MAX_EVIDENCE_STEPS
    assert evidence.stop_reason is StopReason.SUFFICIENT_SUPPORT
    assert evidence.e_value >= STOP_SUPPORT_THRESHOLD
    with pytest.raises(ContractError):
        SequentialEvidence(
            world_id="w-a",
            e_value=E_VALUE_CEILING * 2,
            steps=1,
            null_description=BENIGN_NULL_DESCRIPTION,
            anytime_valid=True,
        )
    with pytest.raises(ContractError):
        SequentialEvidence(
            world_id="w-a",
            e_value=1.0,
            steps=MAX_EVIDENCE_STEPS + 1,
            null_description="x",
        )


def test_horizon_stop_reason_fires_before_support_when_nothing_decides():
    evidence = start_benign_null_evidence("w-slow")
    while evidence.is_running:
        evidence = evidence.update(1.0)
    assert evidence.steps == MAX_EVIDENCE_STEPS
    assert evidence.stop_reason is StopReason.HORIZON_REACHED
    assert evidence.e_value == 1.0


def test_contradiction_stops_the_accumulator():
    evidence = start_benign_null_evidence("w-b")
    evidence = evidence.update(0.001)
    assert evidence.stop_reason is StopReason.SUFFICIENT_CONTRADICTION
    assert evidence.e_value <= STOP_CONTRADICTION_THRESHOLD


def test_a_stopped_accumulator_refuses_further_updates_instead_of_ignoring_them():
    evidence = start_benign_null_evidence("w-b").update(0.001)
    with pytest.raises(ContractError):
        evidence.update(2.0)
    preserved = evidence.stopped(StopReason.NON_IDENTIFIABLE)
    assert preserved.stop_reason is StopReason.NON_IDENTIFIABLE
    with pytest.raises(ContractError):
        evidence.stopped(StopReason.STILL_RUNNING)


def test_update_refuses_a_nonpositive_or_infinite_ratio():
    evidence = start_benign_null_evidence("w-a")
    for ratio in (0.0, -1.0, math.inf, math.nan):
        with pytest.raises(ContractError):
            evidence.update(ratio)


def test_likelihood_ratio_supports_a_world_that_predicted_what_was_seen():
    expected = frozenset({"authentication", "privilege_change"})
    forbidden = frozenset({"module_load"})
    supporting = benign_null_likelihood_ratio(
        ("authentication", "privilege_change"), expected=expected, forbidden=forbidden
    )
    contradicting = benign_null_likelihood_ratio(
        ("module_load",), expected=expected, forbidden=forbidden
    )
    assert supporting > 1.0
    assert contradicting < 1.0
    with pytest.raises(ContractError):
        benign_null_likelihood_ratio(
            ("not_in_the_vocabulary",), expected=expected, forbidden=forbidden
        )


def test_absence_of_an_expected_signal_counts_against_the_world():
    expected = frozenset({"authentication", "privilege_change", "file_staging"})
    forbidden = frozenset({"module_load"})
    with_signal = benign_null_likelihood_ratio(
        ("authentication", "privilege_change", "file_staging"),
        expected=expected,
        forbidden=forbidden,
    )
    without = benign_null_likelihood_ratio(
        ("authentication", "privilege_change"), expected=expected, forbidden=forbidden
    )
    assert without < with_signal


# --- D4.10: calibration -----------------------------------------------------


def test_ece_is_none_when_under_sampled_and_never_zero():
    """Stage 2's G2.5 recorded ECE 0.0 and Brier 0.0 on a perfectly separable split. That
    number looked like excellent calibration and was a saturation artifact; None is the
    correction, and None never means zero (ADR-0004)."""
    calibration = EpochCalibration()
    for index in range(MIN_CALIBRATION_SAMPLES - 1):
        calibration.observe(epoch_id=1, confidence=0.5, correct=index % 2 == 0)
    report = calibration.report(1)
    assert report.samples == MIN_CALIBRATION_SAMPLES - 1
    assert report.ece is None
    assert report.brier is None
    assert report.ece != 0.0
    assert report.calibration_id is None
    assert report.is_measured is False
    calibration.observe(epoch_id=1, confidence=0.5, correct=True)
    measured = calibration.report(1)
    assert measured.samples == MIN_CALIBRATION_SAMPLES
    assert measured.ece is not None
    assert measured.calibration_id is not None


def test_calibration_report_refuses_an_id_without_an_ece_and_an_undersampled_ece():
    with pytest.raises(ContractError):
        CalibrationReport(epoch_id=1, bins=(), ece=None, brier=None, samples=0, calibration_id="x")
    with pytest.raises(ContractError):
        CalibrationReport(
            epoch_id=1,
            bins=((0.5, 0.5, 3),),
            ece=0.0,
            brier=0.0,
            samples=3,
            calibration_id="stage4-cal-e1-n3",
        )


def test_rising_calibration_error_widens_uncertainty_and_raises_abstention():
    """§32's two required responses, as monotonicity inequalities."""
    samples = MIN_CALIBRATION_SAMPLES * 2
    pressures: list[float] = []
    widened: list[float] = []
    eces: list[float] = []
    # Confidence is fixed at 0.9, so calibration error is |0.9 - accuracy| and the wrong
    # counts below walk accuracy from 0.9 (perfectly calibrated) down to 0.4.
    for wrong in (int(samples * 0.1), int(samples * 0.2), int(samples * 0.4), int(samples * 0.6)):
        calibration = EpochCalibration()
        for index in range(samples):
            calibration.observe(epoch_id=7, confidence=0.9, correct=index >= wrong)
        report = calibration.report(7)
        assert report.ece is not None
        eces.append(report.ece)
        pressures.append(calibration.abstention_pressure(7))
        widened.append(calibration.widen_uncertainty(7, 0.4))
    assert eces == sorted(eces)
    assert pressures == sorted(pressures)
    assert widened == sorted(widened)
    assert pressures[-1] > pressures[0]
    assert widened[-1] > widened[0]


def test_widen_uncertainty_never_narrows_and_stays_in_the_unit_interval():
    calibration = EpochCalibration()
    for index in range(MIN_CALIBRATION_SAMPLES * 2):
        calibration.observe(epoch_id=2, confidence=0.9, correct=index % 3 != 0)
    for uncertainty in (0.0, 0.1, 0.5, 0.9, 1.0):
        widened = calibration.widen_uncertainty(2, uncertainty)
        assert widened >= uncertainty
        assert 0.0 <= widened <= 1.0
    with pytest.raises(ContractError):
        calibration.widen_uncertainty(2, 1.5)


def test_unmeasured_calibration_gets_maximal_abstention_pressure():
    """An uncalibrated confidence is not a good confidence. Treating "could not measure"
    as "fine" is the substitution ADR-0004 forbids."""
    calibration = EpochCalibration()
    assert calibration.report(99).ece is None
    assert calibration.abstention_pressure(99) == UNMEASURED_ABSTENTION_PRESSURE
    assert calibration.widen_uncertainty(99, 0.5) > 0.5


def test_alerting_requires_a_measured_ece_at_or_above_the_threshold():
    calibration = EpochCalibration()
    for index in range(MIN_CALIBRATION_SAMPLES * 2):
        calibration.observe(epoch_id=4, confidence=0.95, correct=index % 2 == 0)
    report = calibration.report(4)
    assert report.ece is not None and report.ece >= CALIBRATION_ALERT_ECE
    assert report.alerting is True
    assert EpochCalibration().report(4).alerting is False


def test_calibration_history_and_epoch_table_are_bounded_with_counted_truncation():
    calibration = EpochCalibration()
    for index in range(MAX_CALIBRATION_HISTORY * 2):
        calibration.observe(epoch_id=5, confidence=0.5, correct=index % 2 == 0)
    assert calibration.samples(5) == MAX_CALIBRATION_HISTORY
    bounds = calibration.report_bounds()
    assert bounds["dropped_samples"] == MAX_CALIBRATION_HISTORY
    for epoch_id in range(MAX_TRACKED_EPOCHS * 3):
        calibration.observe(epoch_id=100 + epoch_id, confidence=0.5, correct=True)
    bounds = calibration.report_bounds()
    assert bounds["tracked_epochs"] <= MAX_TRACKED_EPOCHS
    assert bounds["evicted_epochs"] > 0
    assert bounds["memory_bytes"] > 0


def test_calibration_bins_omit_empty_bins_and_sum_to_the_sample_count():
    calibration = EpochCalibration()
    for index in range(MIN_CALIBRATION_SAMPLES * 2):
        calibration.observe(
            epoch_id=6, confidence=(index % CALIBRATION_BINS) / CALIBRATION_BINS, correct=index % 2 == 0
        )
    report = calibration.report(6)
    assert report.bins
    assert all(count > 0 for _, _, count in report.bins)
    assert sum(count for _, _, count in report.bins) == report.samples
    assert len(report.bins) <= CALIBRATION_BINS


def test_calibration_is_keyed_on_stage_1_epochs_and_defines_no_second_epoch_type():
    """Epochs are Stage 1's concept. A parallel Stage 4 epoch type would drift from the
    host's real rotation the first time the host changed."""
    from pocketsec.stage1.epoch.model import EpochModel, SystemIdentity

    identity = SystemIdentity(
        kernel_id="7.1.5",
        package_digest="sha256:" + "a" * 64,
        service_digest="sha256:" + "b" * 64,
    )
    epoch = EpochModel(identity=identity).current
    assert epoch_key(epoch) == epoch.epoch_id
    calibration = EpochCalibration()
    calibration.observe(epoch_id=epoch_key(epoch), confidence=0.5, correct=True)
    assert calibration.samples(epoch.epoch_id) == 1
    with pytest.raises(ContractError):
        epoch_key(object())  # type: ignore[arg-type]


def test_calibration_refuses_malformed_observations():
    calibration = EpochCalibration()
    with pytest.raises(ContractError):
        calibration.observe(epoch_id=-1, confidence=0.5, correct=True)
    with pytest.raises(ContractError):
        calibration.observe(epoch_id=1, confidence=1.5, correct=True)
    with pytest.raises(ContractError):
        calibration.observe(epoch_id=1, confidence=0.5, correct=1)  # type: ignore[arg-type]


# --- adversarial ------------------------------------------------------------


def test_a_flood_of_identical_worlds_does_not_produce_a_confident_answer(pairs, visibility):
    """An attacker who can make the field branch must not be able to buy a verdict. With
    many equally-supported worlds the honest answer stays non-committal."""
    from pocketsec.stage4.labs.nonidentifiable import field_for_nonidentifiable_pair as build

    field = build(pairs[0])
    template = field.worlds[0]
    from dataclasses import replace as dc_replace

    # Distinct world ids AND distinct mechanism ids: the field refuses duplicates, and a
    # branch flood in the wild arrives as many near-identical mechanisms, not one repeated.
    flooded = field.with_worlds(
        [field.worlds[1]]
        + [
            dc_replace(
                template,
                world_id=f"{template.world_id}-{index}",
                mechanism_id=f"{template.mechanism_id}_variant_{index}",
            )
            for index in range(4)
        ]
    )
    verdict = identifiability_of(
        flooded, shadow=None, plan=_plan(flooded, visibility=visibility)
    )
    assert verdict.abstains() is True
    assert verdict.to_verdict() is not Verdict.BENIGN
    assert verdict.to_verdict() in NON_COMMITTAL_VERDICTS


def test_apply_granted_observation_refuses_a_signal_outside_the_vocabulary(resolvable):
    field = field_for_resolvable_case(resolvable[0])
    with pytest.raises(ContractError):
        apply_granted_observation(field, "made_up_signal", observed=True)


def test_an_unobserved_resolving_signal_does_not_resolve_towards_the_alarming_world(
    resolvable, visibility
):
    """Silence is not evidence in the alarming direction: if the staging write is never
    seen, the world that predicted it must lose support, not gain it."""
    case = resolvable[0]
    field = field_for_resolvable_case(case)
    updated = apply_granted_observation(field, RESOLVING_SIGNAL, observed=False)
    support = dict(updated.support_vector())
    compromised = f"{case.incident_id}-w-compromised"
    approved = f"{case.incident_id}-w-approved"
    assert support[compromised] < support[approved]
    verdict = identifiability_of(updated, shadow=None, plan=None)
    assert verdict.to_verdict() is not Verdict.MALICIOUS


def test_the_test_suite_does_not_touch_the_real_experiment_ledger():
    """A gate or a test must never mutate the append-only ledger as a side effect."""
    ledger = Path("experiments/registry.jsonl")
    if not ledger.exists():
        pytest.skip("no experiment ledger in this checkout")
    ledger_token = "registry" + ".jsonl"
    for module in (
        "pocketsec/stage4/identifiability/resolution.py",
        "pocketsec/stage4/identifiability/horizon.py",
        "pocketsec/stage4/evidence/sequential.py",
        "pocketsec/stage4/evidence/calibration.py",
        "pocketsec/stage4/sensing/active_plan.py",
        "pocketsec/stage4/sensing/simulate.py",
        "pocketsec/stage4/labs/nonidentifiable.py",
    ):
        text = Path(module).read_text(encoding="utf-8")
        assert "ExperimentRegistry" not in text
        assert ledger_token not in text
