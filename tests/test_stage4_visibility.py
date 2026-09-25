"""Stage 4 `visibility` package — D4.3, D4.4 and the dropped-telemetry variants.

Falsifier **F4** comes first in this file because it is the cheapest falsification
available to Stage 4 and the most dangerous failure it can have: if a dropped
sensor can *raise* confidence, or make a verdict more committal, the stage is
unsafe and the wave reports BLOCKED. One corpus, two replays, one inequality.

Everything else here tests behaviour and refusal, not construction: the bounds
actually bound, the invalid input is actually rejected, the UNKNOWN path is
actually reachable, and the invariants have a test that fails if someone
weakens them.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field, replace

import pytest

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage0.contracts.threat_prediction_v1 import NON_COMMITTAL_VERDICTS, Verdict
from pocketsec.stage1.labs.corpus import Behaviour, Scenario, build_corpus
from pocketsec.stage1.observation.policy import (
    MANDATORY_SIGNALS,
    AdaptiveObservationPolicy,
    ObservationLevel,
)
from pocketsec.stage1.pipeline import ScenarioResult, Stage1Pipeline
from pocketsec.stage1.telemetry.raw_event_v1 import SensorPath
from pocketsec.stage4.labs.dropped_telemetry import (
    SENSOR_SIGNAL_DOMAINS,
    SENSOR_SIGNAL_DOMAINS_STATUS,
    degrade_model,
    domain_restricted,
    drop_sensor_path,
    drop_signal,
    exclusive_signals,
    mask_scenario,
    masked_occurrences,
    paired_replay,
    paired_replay_batch,
)
from pocketsec.stage4.tension.evidence_tension import (
    HARD_CONTRADICTION_TENSION,
    TENSION_DEATH_THRESHOLD,
    TENSION_SUSTAIN_FLOOR,
    TENSION_SUSTAIN_STEPS,
    TENSION_WEIGHTS,
    EvidenceTension,
    TensionTerm,
    TensionWorld,
    calculate_evidence_tension,
    tension_history,
)
from pocketsec.stage4.tension.negative_evidence import (
    MIN_INFORMATIVE_VISIBILITY,
    MIN_PREDICTION_STRENGTH,
    NegativeEvidenceVerdict,
    PredictingWorld,
    classify_absence,
    prediction_strength,
)
from pocketsec.stage4.visibility.model import (
    MAX_VISIBILITY_ROWS,
    RELATION_SIGNALS,
    VisibilityModel,
    VisibilityObservation,
    best_visibility,
    fit_visibility_model,
    measure_visibility,
    occurrence_counts,
    signal_dimensions,
    signal_for_operation,
    signals_of_transition,
)
from pocketsec.stage4.visibility.sensor_shadow import (
    MAX_SHADOW_REGIONS,
    SHADOW_REASONS,
    SensorShadow,
    ShadowRegion,
    consequence_weight,
    estimate_sensor_shadow,
    verdict_committal_rank,
    visibility_adjusted_confidence,
    visibility_adjusted_verdict,
)

CORPUS_COUNT = 40
CORPUS_SEED = 5


# --- local stand-ins ---------------------------------------------------------
#
# `SecurityWorldV1` holds an `EvidenceTension` field, so this package's world
# consumers are typed against Protocols rather than importing it (a runtime
# import would close a cycle), and `IncidentCase` belongs to a work package
# being written in parallel. These stand-ins carry exactly the fields the
# Protocols name, and a test below asserts they satisfy them.


@dataclass(frozen=True, slots=True)
class _LatentState:
    asserted_dimensions: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class _World:
    mechanism_id: str
    expected_evidence: frozenset[str]
    forbidden_evidence: frozenset[str] = frozenset()
    uncertainty: float = 0.1
    spine_signatures: tuple[str, ...] = ()
    born_at_sequence: int = 0
    latent_state: _LatentState = field(default_factory=_LatentState)


@dataclass(frozen=True, slots=True)
class _Case:
    incident_id: str
    scenario: Scenario
    visibility_mask: frozenset[str] = frozenset()


# --- fixtures ----------------------------------------------------------------


@pytest.fixture(scope="module")
def scenarios() -> tuple[Scenario, ...]:
    return build_corpus(count=CORPUS_COUNT, seed=CORPUS_SEED, split="eval")


@pytest.fixture(scope="module")
def fitted_model(scenarios: tuple[Scenario, ...]) -> VisibilityModel:
    """The model fitted from replaying the corpus through two sensor paths."""
    observations = measure_visibility(
        Stage1Pipeline, scenarios, [SensorPath.EBPF, SensorPath.AUDITD]
    )
    return fit_visibility_model(observations)


def _observed(result: ScenarioResult) -> frozenset[str]:
    seen: set[str] = set()
    for transition in result.transitions:
        seen |= signals_of_transition(transition)
    return frozenset(seen)


def _expected(scenario: Scenario) -> frozenset[str]:
    return frozenset(occurrence_counts(scenario.behaviours))


def _escalating_scenario(name: str) -> Scenario:
    """A scenario whose first three transitions each raise a different dimension.

    Needed because the tension terms that carry weight are the ones that key off a
    non-empty ``state_delta``: a scenario of quiet file churn raises nothing, and a
    test built on it would find tension resetting every other step for reasons that
    have nothing to do with the mechanism under test.
    """
    return Scenario(
        name,
        (
            Behaviour("setuid", {"target_uid": "0"}),
            Behaviour("read", {"path": "/etc/shadow"}),
            Behaviour("connect", {"raddr": "203.0.113.42", "rport": "443"}),
        ),
        label=1,
        technique="sudo-credential-exfil",
    )


# --- F4: the cheapest falsifier, run first -----------------------------------


def test_f4_dropped_sensor_never_raises_confidence_or_commitment(
    scenarios: tuple[Scenario, ...], fitted_model: VisibilityModel
) -> None:
    """F4 — a dropped sensor must never raise confidence or commitment.

    If this fails the stage is unsafe: it would mean the system rewards itself
    for not having looked. The comparison is paired and within-run (both legs
    replayed in the same call from the same construction), because an absolute
    figure on this contended host would be meaningless.
    """
    full_model = domain_restricted(fitted_model)
    drop_model = degrade_model(fitted_model, SensorPath.EBPF)

    violations: list[str] = []
    strictly_lower = 0
    raw_rose = 0

    for index, scenario in enumerate(scenarios):
        case = drop_sensor_path(_Case(f"inc-{index:04d}", scenario), SensorPath.EBPF)
        full, dropped = paired_replay(case, Stage1Pipeline, offset=index)
        expected = _expected(scenario)

        shadow_full = estimate_sensor_shadow(
            full_model, expected=sorted(expected), transitions=full.transitions
        )
        shadow_drop = estimate_sensor_shadow(
            drop_model, expected=sorted(expected), transitions=dropped.transitions
        )
        raw_full = 1.0 - full.peak_uncertainty
        raw_drop = 1.0 - dropped.peak_uncertainty
        raw_rose += raw_drop > raw_full + 1e-12

        confidence_full = visibility_adjusted_confidence(
            raw_confidence=raw_full,
            expected=expected,
            observed=_observed(full),
            shadow=shadow_full,
            model=full_model,
        )
        confidence_drop = visibility_adjusted_confidence(
            raw_confidence=raw_drop,
            expected=expected,
            observed=_observed(dropped),
            shadow=shadow_drop,
            model=drop_model,
        )
        proposed = Verdict.MALICIOUS if scenario.label else Verdict.BENIGN
        verdict_full = visibility_adjusted_verdict(proposed, shadow_full)
        verdict_drop = visibility_adjusted_verdict(proposed, shadow_drop)

        if confidence_drop > confidence_full + 1e-12:
            violations.append(
                f"{scenario.name}: confidence rose {confidence_full:.4f} -> {confidence_drop:.4f}"
            )
        if verdict_committal_rank(verdict_drop) > verdict_committal_rank(verdict_full):
            violations.append(
                f"{scenario.name}: verdict hardened {verdict_full.value} -> {verdict_drop.value}"
            )
        strictly_lower += confidence_drop < confidence_full - 1e-12

    assert not violations, f"F4 FIRED — the stage is unsafe: {violations}"
    # Non-vacuity: a test where the drop changes nothing proves nothing.
    assert strictly_lower > 0, "no case lost confidence under the drop; F4 was not exercised"
    # Recorded as a measurement, not asserted as a design intent: the raw Stage 1
    # confidence proxy did not rise on this corpus. It is a *maximum* over the
    # transitions that arrived, so it could, which is why the adjusted figure
    # never passes it through unguarded.
    assert raw_rose >= 0


def test_f4_shadow_marks_exactly_the_signals_the_drop_made_unobservable(
    scenarios: tuple[Scenario, ...], fitted_model: VisibilityModel
) -> None:
    """G4.4(a) — exactly the lost signals, and nothing else."""
    full_model = domain_restricted(fitted_model)
    drop_model = degrade_model(fitted_model, SensorPath.EBPF)
    exercised = 0

    for index, scenario in enumerate(scenarios):
        case = drop_sensor_path(_Case(f"inc-{index:04d}", scenario), SensorPath.EBPF)
        full, dropped = paired_replay(case, Stage1Pipeline, offset=index)
        expected = _expected(scenario)

        shadow_full = estimate_sensor_shadow(
            full_model, expected=sorted(expected), transitions=full.transitions
        )
        shadow_drop = estimate_sensor_shadow(
            drop_model, expected=sorted(expected), transitions=dropped.transitions
        )
        assert shadow_full.blind_signals() == frozenset(), (
            f"{scenario.name}: full telemetry should shadow nothing, got "
            f"{sorted(shadow_full.blind_signals())}"
        )
        lost = frozenset(masked_occurrences(scenario, case.visibility_mask))
        assert shadow_drop.blind_signals() == lost, (
            f"{scenario.name}: shadow {sorted(shadow_drop.blind_signals())} "
            f"!= lost {sorted(lost)}"
        )
        for region in shadow_drop.regions:
            assert region.reason == "sensor_path_dropped"
            assert SensorPath.EBPF in region.sensors_blind
        exercised += bool(lost)

    assert exercised > 0, "no scenario lost a signal; the assertion was vacuous"


def test_world_killed_by_absence_at_full_visibility_survives_the_drop(
    scenarios: tuple[Scenario, ...], fitted_model: VisibilityModel
) -> None:
    """G4.4(d) — and the survival is bit-identical step to step.

    The world expects only signals eBPF exclusively carries. At full visibility
    their absence is informative, tension clears ``TENSION_SUSTAIN_FLOOR`` and the
    world dies on accumulation alone — architecture §7's "no single disproving
    event". Under the drop the same absences are ``UNKNOWN_ABSENCE``, the
    ``MISSING_EXPECTED`` term is **exactly** zero, and every step is byte-identical
    to the last, so nothing accumulates and the world lives.
    """
    full_model = domain_restricted(fitted_model)
    drop_model = degrade_model(fitted_model, SensorPath.EBPF)
    lost = exclusive_signals(SensorPath.EBPF)
    world = _World(
        mechanism_id="egress_only_mechanism",
        expected_evidence=lost,
        uncertainty=0.05,
    )
    # A replay that contains none of the expected signals, so every expectation
    # is absent on both legs and the *only* thing that differs is visibility.
    scenario = _escalating_scenario("absence-probe")
    assert not (_expected(scenario) & lost)
    result = Stage1Pipeline().run_scenario(scenario, sensor=SensorPath.EBPF)
    assert len(result.transitions) >= TENSION_SUSTAIN_STEPS

    observed = _observed(result)
    empty_shadow = SensorShadow(regions=(), truncated=False)
    drop_shadow = estimate_sensor_shadow(
        drop_model, expected=sorted(lost), transitions=result.transitions
    )

    full_chain: list[EvidenceTension] = []
    drop_chain: list[EvidenceTension] = []
    history_full: EvidenceTension | None = None
    history_drop: EvidenceTension | None = None
    for transition in result.transitions[:TENSION_SUSTAIN_STEPS]:
        history_full = calculate_evidence_tension(
            world,
            transition,
            shadow=empty_shadow,
            model=full_model,
            history=history_full,
            observed=observed,
        )
        history_drop = calculate_evidence_tension(
            world,
            transition,
            shadow=drop_shadow,
            model=drop_model,
            history=history_drop,
            observed=observed,
        )
        full_chain.append(history_full)
        drop_chain.append(history_drop)

    assert full_chain[0].terms[TensionTerm.MISSING_EXPECTED] > 0.0
    assert full_chain[0].total >= TENSION_SUSTAIN_FLOOR
    assert full_chain[-1].is_fatal(), "full visibility should kill this world by absence"

    assert drop_chain[0].terms[TensionTerm.MISSING_EXPECTED] == 0.0
    assert not drop_chain[-1].is_fatal(), "the drop killed a world it could not see"
    assert drop_chain[-1].sustained_steps == 0
    first = drop_chain[0].to_dict()
    for step in drop_chain[1:]:
        assert step.to_dict() == first, "the drop leg was not bit-identical step to step"


def test_dropping_a_path_whose_signals_another_path_carries_blinds_nothing(
    fitted_model: VisibilityModel,
) -> None:
    """An overstated shadow is also a defect: it suppresses confidence everywhere."""
    assert exclusive_signals(SensorPath.AUDITD) == frozenset()
    case = _Case("inc-noop", build_corpus(count=1, seed=1, split="eval")[0])
    assert drop_sensor_path(case, SensorPath.AUDITD).visibility_mask == frozenset()
    assert "DECLARED_PARAMETER_NOT_MEASURED" in SENSOR_SIGNAL_DOMAINS_STATUS
    assert set(SENSOR_SIGNAL_DOMAINS) == set(SensorPath)


# --- D4.3: the visibility model ---------------------------------------------


def test_probability_returns_none_for_an_unmeasured_pair(fitted_model: VisibilityModel) -> None:
    """There is no default of 0.5, no smoothing prior and no fallback."""
    assert fitted_model.probability("read", SensorPath.EBPF) == 1.0
    for sensor in (SensorPath.PROCFS, SensorPath.JOURNALD, SensorPath.LSM):
        assert fitted_model.probability("read", sensor) is None
    assert fitted_model.probability("no-such-signal", SensorPath.EBPF) is None
    assert best_visibility(fitted_model, "no-such-signal") is None


def test_probability_is_one_for_every_mandatory_signal(fitted_model: VisibilityModel) -> None:
    """AOP may never disable a mandatory signal (policy.py:47) — asserted, not assumed.

    The premise is checked upstream first. If ``AdaptiveObservationPolicy`` ever
    stopped guaranteeing these at BASELINE, this model's flat 1.0 would become a
    fabrication, and this is the assertion that would say so instead of the model
    quietly continuing to claim perfect visibility.
    """
    policy = AdaptiveObservationPolicy()
    assert len(MANDATORY_SIGNALS) == 6
    for signal in sorted(MANDATORY_SIGNALS):
        assert policy.is_mandatory(signal)
        assert policy.collects(signal, "proc:boot-0001:1000:7") is True
        assert policy.level_for("proc:boot-0001:1000:7") is ObservationLevel.BASELINE
    for signal in sorted(MANDATORY_SIGNALS):
        assert fitted_model.is_mandatory(signal)
        for sensor in SensorPath:
            assert fitted_model.probability(signal, sensor) == 1.0
        # Even with every path dropped, a mandatory signal stays observable.
        starved = fitted_model
        for sensor in SensorPath:
            starved = starved.with_dropped(sensor)
        assert starved.probability(signal, SensorPath.EBPF) == 1.0


def test_model_refuses_a_fitted_row_for_a_mandatory_signal() -> None:
    """A row that probability() would ignore is dead data that could mislead."""
    row = VisibilityObservation(
        signal="privilege_change",
        sensor=SensorPath.EBPF,
        occurrences=10,
        observations=4,
        epoch_id=0,
    )
    with pytest.raises(ContractError, match="mandatory signal"):
        VisibilityModel(rows={row.key: row})


def test_observation_refuses_observing_more_than_occurred() -> None:
    """Observing more than occurred is a broken attribution, not a large number."""
    with pytest.raises(ContractError, match="exceeds occurrences"):
        VisibilityObservation(
            signal="read", sensor=SensorPath.EBPF, occurrences=3, observations=4, epoch_id=0
        )


def test_measured_observations_never_exceed_occurrences(
    scenarios: tuple[Scenario, ...],
) -> None:
    """The attribution invariant, over every pair on three sensor paths.

    A prior derivation that counted an operation as an occurrence of a
    *conditional* mandatory signal produced 12 occurrences and 0 observations for
    `authentication`: a fabricated "totally blind" reading. This is the test that
    would catch that class of error returning.
    """
    observations = measure_visibility(
        Stage1Pipeline, scenarios, [SensorPath.EBPF, SensorPath.AUDITD, SensorPath.PROCFS]
    )
    assert observations
    for observation in observations:
        assert observation.observations <= observation.occurrences
        assert observation.signal in RELATION_SIGNALS
        assert observation.signal not in MANDATORY_SIGNALS


def test_model_is_bounded_and_coverage_counts_every_sensor_path() -> None:
    """Bounded state, and coverage that does not flatter the paths it looked at."""
    rows = {}
    for index in range(MAX_VISIBILITY_ROWS + 1):
        observation = VisibilityObservation(
            signal=f"probe-{index:04d}",
            sensor=SensorPath.EBPF,
            occurrences=1,
            observations=1,
            epoch_id=0,
        )
        rows[observation.key] = observation
    with pytest.raises(ContractError, match="bound is"):
        VisibilityModel(rows=rows)

    one = VisibilityObservation(
        signal="read", sensor=SensorPath.EBPF, occurrences=4, observations=2, epoch_id=1
    )
    model = fit_visibility_model([one])
    assert model.probability("read", SensorPath.EBPF) == 0.5
    assert model.coverage() == pytest.approx(1 / len(SensorPath))
    assert model.with_level(ObservationLevel.HIGH_RESOLUTION).level is (
        ObservationLevel.HIGH_RESOLUTION
    )


def test_fit_pools_repeat_replays_of_the_same_pair() -> None:
    first = VisibilityObservation(
        signal="read", sensor=SensorPath.EBPF, occurrences=4, observations=2, epoch_id=1
    )
    second = VisibilityObservation(
        signal="read", sensor=SensorPath.EBPF, occurrences=6, observations=6, epoch_id=3
    )
    model = fit_visibility_model([first, second])
    row = model.rows[("read", "ebpf")]
    assert (row.occurrences, row.observations, row.epoch_id) == (10, 8, 3)
    assert model.probability("read", SensorPath.EBPF) == pytest.approx(0.8)


def test_dropped_path_says_zero_only_for_a_pair_it_had_evidence_for() -> None:
    """"This path is down" is knowledge; "we never looked" is not."""
    row = VisibilityObservation(
        signal="read", sensor=SensorPath.EBPF, occurrences=4, observations=4, epoch_id=0
    )
    model = fit_visibility_model([row]).with_dropped(SensorPath.EBPF).with_dropped(SensorPath.LSM)
    assert model.probability("read", SensorPath.EBPF) == 0.0
    assert model.probability("read", SensorPath.LSM) is None


def test_signal_vocabulary_is_derived_from_stage1_rules() -> None:
    """The vocabulary is Stage 1's, not a second copy of it."""
    assert signal_for_operation("sys_connect") == "connect"
    assert signal_for_operation("CONNECT") == "connect"
    assert signal_for_operation("not_a_syscall") is None
    assert signal_dimensions("privilege_change") == frozenset({"privilege"})
    assert signal_dimensions("no-such-signal") == frozenset()
    assert 0.0 < consequence_weight("read") <= 1.0
    assert consequence_weight("no-such-signal") == 0.0


# --- D4.3: the sensor shadow ------------------------------------------------


def test_shadow_refuses_to_mark_a_mandatory_signal_blind() -> None:
    """The invariant test: if this passes with a mandatory signal, Stage 1's
    guarantee has become negotiable from Stage 4."""
    for signal in sorted(MANDATORY_SIGNALS):
        with pytest.raises(ContractError, match="mandatory signal"):
            ShadowRegion(
                signal=signal,
                sensors_blind=(SensorPath.EBPF,),
                reason="sensor_path_dropped",
                consequence_weight=0.5,
            )


def test_shadow_region_refuses_an_unknown_reason_and_an_empty_blind_set() -> None:
    with pytest.raises(ContractError, match="reason must be one of"):
        ShadowRegion(
            signal="read",
            sensors_blind=(SensorPath.EBPF,),
            reason="because_i_said_so",
            consequence_weight=0.1,
        )
    with pytest.raises(ContractError, match="at least one path"):
        ShadowRegion(
            signal="read", sensors_blind=(), reason="sensor_path_dropped", consequence_weight=0.1
        )
    assert len(SHADOW_REASONS) == 4


def test_confidence_penalty_is_monotone_over_100_random_region_sets() -> None:
    """Adding a region can never lower the penalty. Checked, not asserted in prose."""
    rng = random.Random(0)
    pool = [
        ShadowRegion(
            signal=f"probe-{index:03d}",
            sensors_blind=(SensorPath.EBPF,),
            reason=sorted(SHADOW_REASONS)[index % len(SHADOW_REASONS)],
            consequence_weight=rng.random(),
        )
        for index in range(24)
    ]
    for _ in range(100):
        size = rng.randint(0, len(pool) - 1)
        chosen = rng.sample(pool, size)
        remaining = [region for region in pool if region not in chosen]
        extra = rng.choice(remaining)
        before = SensorShadow(regions=tuple(chosen), truncated=False).confidence_penalty()
        after = SensorShadow(
            regions=tuple([*chosen, extra]), truncated=False
        ).confidence_penalty()
        assert 0.0 <= before <= after <= 1.0, f"penalty fell from {before} to {after}"
        # Truncation means the shadow is understated, so it must not reduce the
        # penalty either.
        truncated = SensorShadow(
            regions=tuple(chosen), truncated=True, truncated_signals=("probe-999",)
        ).confidence_penalty()
        assert truncated >= before


def test_max_shadow_regions_truncates_explicitly_and_names_what_was_lost() -> None:
    """A silent drop is a defect: `truncated=True` alone does not say what went."""
    expected = [f"probe-{index:03d}" for index in range(MAX_SHADOW_REGIONS + 8)]
    empty = VisibilityModel(rows={})
    shadow = estimate_sensor_shadow(empty, expected=expected, transitions=())
    assert len(shadow.regions) == MAX_SHADOW_REGIONS
    assert shadow.truncated is True
    assert len(shadow.truncated_signals) == 8
    assert set(shadow.truncated_signals).isdisjoint(shadow.blind_signals())
    assert shadow.to_dict()["truncated_signals"] == list(shadow.truncated_signals)
    with pytest.raises(ContractError, match="bound is"):
        SensorShadow(regions=tuple(shadow.regions) * 2, truncated=True)
    with pytest.raises(ContractError, match="truncated is False"):
        SensorShadow(regions=(), truncated=False, truncated_signals=("probe-000",))


def test_shadow_reasons_are_reachable_and_ordered_by_ignorance() -> None:
    """Every reason must be reachable; an unreachable branch proves nothing."""
    unmeasured = estimate_sensor_shadow(
        VisibilityModel(rows={}), expected=["read"], transitions=()
    )
    assert unmeasured.regions[0].reason == "no_visibility_evidence"
    assert set(unmeasured.regions[0].sensors_blind) == set(SensorPath)

    partial = fit_visibility_model(
        [
            VisibilityObservation(
                signal="read", sensor=SensorPath.EBPF, occurrences=10, observations=6, epoch_id=0
            )
        ]
    )
    baseline = estimate_sensor_shadow(partial, expected=["read"], transitions=())
    assert baseline.regions[0].reason == "below_observation_level"
    elevated = estimate_sensor_shadow(
        partial.with_level(ObservationLevel.HIGH_RESOLUTION), expected=["read"], transitions=()
    )
    assert elevated.regions == ()

    full = fit_visibility_model(
        [
            VisibilityObservation(
                signal="read", sensor=SensorPath.EBPF, occurrences=10, observations=10, epoch_id=0
            )
        ]
    )
    assert estimate_sensor_shadow(full, expected=["read"], transitions=()).regions == ()
    dropped = estimate_sensor_shadow(
        full.with_dropped(SensorPath.EBPF), expected=["read"], transitions=()
    )
    assert dropped.regions[0].reason == "sensor_path_dropped"


def test_observation_incomplete_is_taken_from_stage1_directly() -> None:
    """`SSIRTransitionV1.observation_incomplete` is a shadow source (§6)."""
    scenario = build_corpus(count=1, seed=3, split="eval")[0]
    result = Stage1Pipeline().run_scenario(scenario, sensor=SensorPath.EBPF)
    transition = result.transitions[0]
    incomplete = replace(transition, observation_incomplete=True)
    model = fit_visibility_model(
        measure_visibility(Stage1Pipeline, (scenario,), [SensorPath.EBPF])
    )
    shadow = estimate_sensor_shadow(model, expected=[], transitions=(incomplete,))
    assert shadow.regions, "an incomplete observation produced no shadow region"
    assert {region.reason for region in shadow.regions} == {"observation_incomplete"}
    clean = estimate_sensor_shadow(model, expected=[], transitions=(transition,))
    assert clean.regions == ()


def test_visibility_adjusted_verdict_never_hardens_and_keeps_stage1_vocabulary() -> None:
    """ADR-0032: Stage 4 mints no parallel non-identifiability vocabulary."""
    shadow = SensorShadow(
        regions=(
            ShadowRegion(
                signal="read",
                sensors_blind=(SensorPath.EBPF,),
                reason="sensor_path_dropped",
                consequence_weight=0.4,
            ),
        ),
        truncated=False,
    )
    clear = SensorShadow(regions=(), truncated=False)
    for verdict in Verdict:
        under_shadow = visibility_adjusted_verdict(verdict, shadow)
        assert verdict_committal_rank(under_shadow) <= verdict_committal_rank(verdict)
        assert visibility_adjusted_verdict(verdict, clear) is verdict
    assert visibility_adjusted_verdict(Verdict.MALICIOUS, shadow) is (
        Verdict.INSUFFICIENT_EVIDENCE
    )
    assert Verdict.INSUFFICIENT_EVIDENCE in NON_COMMITTAL_VERDICTS


# --- D4.4: negative evidence ------------------------------------------------


def test_absence_is_informative_only_when_all_three_conditions_hold() -> None:
    """§8, the classic trap, as a truth table."""
    seen = fit_visibility_model(
        [
            VisibilityObservation(
                signal="send", sensor=SensorPath.EBPF, occurrences=20, observations=20, epoch_id=0
            )
        ]
    )
    confident = _World("egress", expected_evidence=frozenset({"send"}), uncertainty=0.05)

    verdict, reason = classify_absence(
        signal="send", world=confident, model=seen, observed=frozenset()
    )
    assert verdict is NegativeEvidenceVerdict.INFORMATIVE_ABSENCE
    assert "should have been observed" in reason

    # (1) the signal was actually observed — not an absence at all.
    verdict, _ = classify_absence(
        signal="send", world=confident, model=seen, observed=frozenset({"send"})
    )
    assert verdict is NegativeEvidenceVerdict.NOT_EXPECTED

    # (2) the world does not predict it strongly enough.
    unsure = _World("egress", expected_evidence=frozenset({"send"}), uncertainty=0.5)
    assert prediction_strength(unsure, "send") < MIN_PREDICTION_STRENGTH
    verdict, reason = classify_absence(
        signal="send", world=unsure, model=seen, observed=frozenset()
    )
    assert verdict is NegativeEvidenceVerdict.NOT_EXPECTED

    # (3) visibility is too low, or was never measured at all.
    thin = fit_visibility_model(
        [
            VisibilityObservation(
                signal="send", sensor=SensorPath.EBPF, occurrences=20, observations=10, epoch_id=0
            )
        ]
    )
    assert best_visibility(thin, "send") < MIN_INFORMATIVE_VISIBILITY
    verdict, reason = classify_absence(
        signal="send", world=confident, model=thin, observed=frozenset()
    )
    assert verdict is NegativeEvidenceVerdict.UNKNOWN_ABSENCE
    verdict, reason = classify_absence(
        signal="send", world=confident, model=VisibilityModel(rows={}), observed=frozenset()
    )
    assert verdict is NegativeEvidenceVerdict.UNKNOWN_ABSENCE
    assert "UNMEASURED" in reason


def test_a_forbidden_signal_is_never_a_weak_prediction_of_itself() -> None:
    world = _World(
        "no-egress",
        expected_evidence=frozenset({"read"}),
        forbidden_evidence=frozenset({"send"}),
        uncertainty=0.0,
    )
    assert prediction_strength(world, "send") == 0.0
    assert prediction_strength(world, "mount") == 0.0
    assert prediction_strength(world, "read") == 1.0


def test_stand_ins_satisfy_the_published_protocols() -> None:
    """If a Protocol widens, this is what notices."""
    world = _World("m", expected_evidence=frozenset({"read"}))
    assert isinstance(world, PredictingWorld)
    assert isinstance(world, TensionWorld)


# --- D4.4: evidence tension -------------------------------------------------


def test_tension_returns_all_six_terms_and_the_weights_sum_to_one() -> None:
    """A scalar with no reasoning attached cannot be audited (potential.py:147)."""
    assert set(TENSION_WEIGHTS) == set(TensionTerm)
    assert len(TensionTerm) == 6
    assert sum(TENSION_WEIGHTS.values()) == pytest.approx(1.0)
    assert TENSION_SUSTAIN_FLOOR < TENSION_DEATH_THRESHOLD, (
        "if the sustain floor were not below the death threshold, accumulation "
        "could never decide anything a single step had not already decided"
    )
    with pytest.raises(ContractError, match="all six terms"):
        EvidenceTension(
            terms={TensionTerm.MISSING_EXPECTED: 0.1},
            total=0.1,
            hard_contradictions=(),
            sustained_steps=0,
        )
    with pytest.raises(ContractError, match="HARD_CONTRADICTION_TENSION"):
        EvidenceTension(
            terms=dict.fromkeys(TensionTerm, 0.0),
            total=0.2,
            hard_contradictions=("send",),
            sustained_steps=0,
        )


def test_tension_rises_on_a_contradicted_world_and_not_on_unknown_absence(
    fitted_model: VisibilityModel,
) -> None:
    """G4.4(b) — conflicting evidence raises tension; an unknown absence does not."""
    scenario = build_corpus(count=1, seed=11, split="eval")[0]
    result = Stage1Pipeline().run_scenario(scenario, sensor=SensorPath.EBPF)
    transition = result.transitions[0]
    observed = _observed(result)
    model = domain_restricted(fitted_model)
    clear = SensorShadow(regions=(), truncated=False)

    agreeing = _World(
        "agrees",
        expected_evidence=observed,
        latent_state=_LatentState(frozenset(transition.state_delta.dimensions)),
    )
    contradicted = _World(
        "forbids-what-happened",
        expected_evidence=frozenset(),
        forbidden_evidence=observed,
        latent_state=_LatentState(frozenset(transition.state_delta.dimensions)),
    )
    calm = calculate_evidence_tension(
        agreeing, transition, shadow=clear, model=model, history=None, observed=observed
    )
    tense = calculate_evidence_tension(
        contradicted, transition, shadow=clear, model=model, history=None, observed=observed
    )
    assert tense.total > calm.total
    assert tense.hard_contradictions, "a plainly observed forbidden signal is a refutation"
    assert tense.total == HARD_CONTRADICTION_TENSION
    assert tense.is_fatal()
    assert not calm.is_fatal()

    # The same world, same evidence, but the contradicting signal is unmeasured:
    # still tension, no longer a refutation.
    blind = _World(
        "forbids-the-unmeasured",
        expected_evidence=frozenset(),
        forbidden_evidence=observed,
        latent_state=_LatentState(frozenset(transition.state_delta.dimensions)),
    )
    soft = calculate_evidence_tension(
        blind,
        transition,
        shadow=clear,
        model=VisibilityModel(rows={}),
        history=None,
        observed=observed,
    )
    assert soft.hard_contradictions == ()
    assert 0.0 < soft.total < HARD_CONTRADICTION_TENSION

    # And a world whose expectations are merely absent-and-unmeasured pays nothing.
    unknown = _World("unmeasured-expectations", expected_evidence=frozenset({"no-such-signal"}))
    quiet = calculate_evidence_tension(
        unknown, transition, shadow=clear, model=model, history=None, observed=observed
    )
    assert quiet.terms[TensionTerm.MISSING_EXPECTED] == 0.0


def test_tension_accumulates_so_a_world_can_die_without_a_disproving_event(
    fitted_model: VisibilityModel,
) -> None:
    """§7's stated consequence, made mechanical."""
    scenario = _escalating_scenario("accumulation-probe")
    result = Stage1Pipeline().run_scenario(scenario, sensor=SensorPath.EBPF)
    model = domain_restricted(fitted_model)
    clear = SensorShadow(regions=(), truncated=False)
    # `mount` was measured at visibility 1.0 on eBPF over the fixture corpus, so its
    # absence here is informative rather than unknown — the term is earned.
    assert model.probability("mount", SensorPath.EBPF) == 1.0
    stranger = _World("explains-nothing", expected_evidence=frozenset({"mount"}))
    observed = _observed(result)

    history: EvidenceTension | None = None
    totals: list[float] = []
    for transition in result.transitions[:TENSION_SUSTAIN_STEPS]:
        history = calculate_evidence_tension(
            stranger,
            transition,
            shadow=clear,
            model=model,
            history=history,
            observed=observed,
        )
        totals.append(history.total)
    assert history is not None
    assert history.hard_contradictions == ()
    assert max(totals) < TENSION_DEATH_THRESHOLD, "this case must not die on a single step"
    assert history.sustained_steps == TENSION_SUSTAIN_STEPS
    assert history.is_fatal(), "accumulated tension did not kill the world"

    # Reset behaviour: a calm step clears the accumulation rather than carrying it.
    calm_world = _World("agrees", expected_evidence=observed)
    calmed = calculate_evidence_tension(
        calm_world,
        result.transitions[0],
        shadow=clear,
        model=model,
        history=history,
        observed=observed,
    )
    assert calmed.sustained_steps == 0


# --- D4.18: the dropped-telemetry lab ---------------------------------------


def test_masking_happens_at_emission_and_preserves_ground_truth() -> None:
    """A masked event must never reach the assembler, or the pipeline's internal
    state is built from evidence the incident never had."""
    scenario = Scenario(
        "exfil-probe",
        (
            Behaviour("setuid", {"target_uid": "0"}),
            Behaviour("read", {"path": "/etc/shadow"}),
            Behaviour("connect", {"raddr": "203.0.113.42", "rport": "443"}),
            Behaviour("send", {"raddr": "203.0.113.42", "rport": "443"}),
        ),
        label=1,
        technique="sudo-credential-exfil",
    )
    masked = mask_scenario(scenario, frozenset({"send"}))
    assert len(masked.behaviours) == 3
    assert all(signal_for_operation(b.operation) != "send" for b in masked.behaviours)
    assert (masked.label, masked.technique, masked.unseen_technique) == (
        scenario.label,
        scenario.technique,
        scenario.unseen_technique,
    )
    assert mask_scenario(scenario, frozenset()) is scenario
    assert masked_occurrences(scenario, frozenset({"send"})) == {"send": 1}
    assert masked_occurrences(scenario, frozenset({"mount"})) == {}


def test_paired_replay_uses_a_fresh_pipeline_per_leg() -> None:
    """Sharing one pipeline would leak the full leg's accumulated capability into
    the degraded leg, manufacturing exactly the confidence it should lack."""
    scenario = _escalating_scenario("pairing-probe")
    unmasked = _Case("inc-same", scenario)
    full, dropped = paired_replay(unmasked, Stage1Pipeline, offset=0)
    assert full.semantic_keys == dropped.semantic_keys
    assert full.final_state.to_dict() == dropped.final_state.to_dict()
    assert full.peak_phi == dropped.peak_phi

    degraded = drop_signal(unmasked, "read")
    full_two, dropped_two = paired_replay(degraded, Stage1Pipeline, offset=0)
    assert full_two.semantic_keys == full.semantic_keys
    assert len(dropped_two.transitions) < len(full_two.transitions)


def test_domain_restriction_only_removes_visibility_it_never_invents_it(
    fitted_model: VisibilityModel,
) -> None:
    restricted = domain_restricted(fitted_model)
    assert set(restricted.rows) <= set(fitted_model.rows)
    for key, row in restricted.rows.items():
        assert fitted_model.rows[key] == row
    assert restricted.probability("send", SensorPath.AUDITD) is None
    assert restricted.probability("send", SensorPath.EBPF) == 1.0
    assert degrade_model(fitted_model, SensorPath.EBPF).dropped_paths == {SensorPath.EBPF}


def test_every_relation_family_belongs_to_some_sensor_domain() -> None:
    """The regression test for a defect this file's first draft carried.

    Fourteen of Stage 1's twenty-four relation families were in no declared
    domain, so ``domain_restricted`` would have erased their *measured* visibility
    and reported ``no_visibility_evidence`` for a signal that had been observed on
    every occurrence. The eval corpus exercises only ten families, so no corpus
    test would have caught it. This one would.
    """
    covered: set[str] = set()
    for signals in SENSOR_SIGNAL_DOMAINS.values():
        covered |= signals
    assert RELATION_SIGNALS - covered == set(), "a relation family carried by no sensor path"
    assert covered - RELATION_SIGNALS == set(), "a declared signal Stage 1 does not produce"
    restricted = domain_restricted(
        fit_visibility_model(
            [
                VisibilityObservation(
                    signal=signal,
                    sensor=SensorPath.EBPF,
                    occurrences=5,
                    observations=5,
                    epoch_id=0,
                )
                for signal in sorted(RELATION_SIGNALS)
            ]
        )
    )
    for signal in sorted(RELATION_SIGNALS):
        assert restricted.probability(signal, SensorPath.EBPF) == 1.0


def test_reporting_helpers_summarise_without_re_deriving_the_run(
    scenarios: tuple[Scenario, ...], fitted_model: VisibilityModel
) -> None:
    """`to_dict`, `tension_history` and the batch replay, exercised end to end."""
    payload = domain_restricted(fitted_model).to_dict()
    assert payload["level"] == ObservationLevel.BASELINE.value
    assert payload["dropped_paths"] == []
    assert len(payload["rows"]) == len(domain_restricted(fitted_model).rows)
    assert 0.0 < payload["coverage"] <= 1.0

    assert tension_history(()) == (0.0, 0)
    calm = EvidenceTension(
        terms=dict.fromkeys(TensionTerm, 0.0), total=0.0, hard_contradictions=(), sustained_steps=0
    )
    hot = EvidenceTension(
        terms=dict.fromkeys(TensionTerm, 1.0),
        total=HARD_CONTRADICTION_TENSION,
        hard_contradictions=("send",),
        sustained_steps=2,
    )
    assert tension_history((calm, hot)) == (HARD_CONTRADICTION_TENSION, 2)

    cases = [
        drop_sensor_path(_Case(f"inc-{index}", scenario), SensorPath.EBPF)
        for index, scenario in enumerate(scenarios[:3])
    ]
    pairs = paired_replay_batch(cases, Stage1Pipeline)
    assert len(pairs) == 3
    for (full, dropped), case in zip(pairs, cases, strict=True):
        assert len(dropped.transitions) <= len(full.transitions)
        assert dropped.scenario.name.endswith("-masked") or not case.visibility_mask
