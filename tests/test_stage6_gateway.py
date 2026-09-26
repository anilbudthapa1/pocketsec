"""Stage 6 gateway package: D6.2 (QuarantineGateway), D6.15 (homeostasis), D6.16 (drift).

Every test is named for the invariant it protects. The central one is the spec §0
probe reproduced through ``QuarantineGateway.admit``: Stage 2's gate alone promotes
one attacker lineage's escalation-free repetition once it spans two corroborated
epochs, and the gateway's source-independence check must refuse it while still
admitting the same pattern shown by three independent groups. The control arm
(``independence_check=False``) runs in the same test so the attack is shown to be
real on this input, not assumed.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Sequence
from functools import cache

import pytest

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage0.contracts.threat_prediction_v1 import Verdict
from pocketsec.stage1.epoch.model import (
    Epoch,
    EpochDecision,
    EpochTransitionReason,
    SystemIdentity,
)
from pocketsec.stage1.pipeline import Stage1Pipeline
from pocketsec.stage1.ssir.entities import SemanticProperty
from pocketsec.stage1.state.security_state import Privilege, SecurityStateV1
from pocketsec.stage2.adaptation.promotion import REFUSE_EVIDENCE, REFUSE_FREQUENCY_ALONE
from pocketsec.stage2.adaptation.quarantine import ESCALATION_MASK, AdaptationSample, pattern_key
from pocketsec.stage2.encoder.ssir_encoder import GROUP_OFFSETS
from pocketsec.stage2.labs.poison_suite import build_poison_suite, poison_lineage
from pocketsec.stage6.capsule import quarantine as gateway_module
from pocketsec.stage6.capsule.experience_capsule import (
    CapsuleKind,
    ContaminationFlag,
    EncodedStep,
    ExperienceCapsuleV1,
    LabelAssertion,
    LabelOrigin,
    PrivacyClass,
    SourceClass,
    SourceProvenance,
    capsule_from_label,
    source_group_of,
    step_draft_fields,
)
from pocketsec.stage6.capsule.quarantine import (
    MAX_PATTERNS_TRACKED,
    REASON_SINGLE_SOURCE,
    QuarantineBucket,
    QuarantineGateway,
    QuarantineVerdict,
    _CandidateRegister,
    _Staging,
)
from pocketsec.stage6.constitution.learning import property_mask
from pocketsec.stage6.fossils.lineage import (
    KnowledgeLineageDAG,
    LineageCapacityError,
    LineageNode,
    NodeKind,
)
from pocketsec.stage6.fossils.store import FossilStore
from pocketsec.stage6.homeostasis import poisoning
from pocketsec.stage6.homeostasis.drift import (
    ContextStatus,
    DriftClass,
    DriftSignals,
    KnowledgeContextRegistry,
    classify_drift_vs_poisoning,
    drift_signals,
)
from pocketsec.stage6.homeostasis.poisoning import (
    RULE_BENIGN_LABEL_ON_PROTECTED_DETECTOR,
    RULE_NORMALITY_ON_PROTECTED_MEANING,
    RULE_REMOVE_PROTECTED_DETECTOR,
    LabelHistory,
    PoisonSuspicion,
    SourceIndependence,
    detect_semantic_normalization_attack,
    label_quorum_met,
    track_key,
)
from pocketsec.stage6.memory.semantic import (
    ALL_CONTEXTS,
    ItemKind,
    ItemLineage,
    ItemValidation,
    KnowledgeItem,
    MotifStep,
    TrustedKnowledgeState,
    context_id_for,
    genesis_state,
    motif_pattern_key,
)
from pocketsec.stage6.provenance.ledger import ProvenanceLedger

IDENTITY_A = SystemIdentity(kernel_id="k-1", package_digest="pkg-a")
IDENTITY_B = SystemIdentity(kernel_id="k-1", package_digest="pkg-b")
CTX_A = context_id_for(IDENTITY_A)
EPOCH_A = Epoch(epoch_id=0, identity=IDENTITY_A, key=IDENTITY_A.key(), opened_at_ns=0)
GROUPS = tuple(source_group_of(f"proc:lab:{n}:0") for n in range(5))
_EVIDENCE = "sha256:" + "ab" * 32


# --- fixtures: real Stage 1 steps, not hand-made vectors ---------------------


@cache
def _suite_steps() -> tuple[EncodedStep, EncodedStep]:
    """(the §0 probe's escalation-free attacker step, a real credential-read step)."""
    suite = build_poison_suite(count=24, seed=11)
    attack = next(s for s in suite if s.technique == "high-frequency-repetition")
    result = Stage1Pipeline().run_scenario(attack, offset=0)
    owner = poison_lineage(attack)
    staging = None
    for transition in result.transitions:
        if transition.actor.identity != owner:
            continue
        step = EncodedStep.from_transition(transition, actor_slot=0)
        quiet = not (step.object_property_mask & ESCALATION_MASK) and not step.state_delta_mask
        if quiet and transition.delta_phi <= 2.0 and transition.uncertainty <= 0.5:
            staging = step
            break
    credential = property_mask([SemanticProperty.CREDENTIAL])
    cred = None
    for scenario in suite:
        for transition in Stage1Pipeline().run_scenario(scenario, offset=0).transitions:
            step = EncodedStep.from_transition(transition, actor_slot=0)
            if step.object_property_mask & credential:
                cred = step
                break
        if cred is not None:
            break
    assert staging is not None and cred is not None, "the Stage 2 poison suite changed shape"
    return staging, cred


def staging_step(*, group: str = GROUPS[0], epoch: int = 0) -> EncodedStep:
    return dataclasses.replace(_suite_steps()[0], source_group=group, epoch_id=epoch)


def credential_step(*, group: str = GROUPS[0], epoch: int = 0) -> EncodedStep:
    return dataclasses.replace(_suite_steps()[1], source_group=group, epoch_id=epoch)


def provenance(
    group: str = "sensor:host-a",
    *,
    source: SourceClass = SourceClass.KERNEL_SENSOR,
    origin: LabelOrigin = LabelOrigin.NONE,
) -> SourceProvenance:
    return SourceProvenance(
        source_class=source,
        source_id=f"src-{group}",
        independence_group=group,
        label_origin=origin,
        transformation_lineage=("stage1.pipeline",),
        host_id="host-a",
    )


def episode(
    steps: Sequence[EncodedStep],
    *,
    seq: int,
    label: LabelAssertion | None = None,
    prov: SourceProvenance | None = None,
    privacy: PrivacyClass = PrivacyClass.PUBLIC_DERIVED,
    kind: CapsuleKind = CapsuleKind.TRANSITION_EPISODE,
) -> ExperienceCapsuleV1:
    return ExperienceCapsuleV1(
        capsule_id="",
        kind=kind,
        epoch_id=steps[0].epoch_id,
        context_id=CTX_A,
        source_provenance=prov or provenance(),
        security_worlds=(),
        resolution_state=Verdict.UNKNOWN,
        response_outcome=None,
        contradiction_history=(),
        privacy_class=privacy,
        label=label,
        procedure_rows=(),
        created_sequence=seq,
        **step_draft_fields(tuple(steps), cut=False),
    )


def label_capsule(
    target: str, verdict: Verdict, *, group: str, origin: LabelOrigin, seq: int,
    source: SourceClass = SourceClass.ANALYST,
) -> ExperienceCapsuleV1:
    label = LabelAssertion(
        verdict=verdict, origin=origin, asserted_by=group, target_capsule_id=target
    )
    prov = provenance(group, source=source, origin=origin)
    return capsule_from_label(label, epoch=EPOCH_A, provenance=prov, sequence=seq)


def lineage_stub(capsule_ids: tuple[str, ...] = ("cap-" + "c" * 24,)) -> ItemLineage:
    return ItemLineage(
        candidate_id="cand-test", capsule_ids=capsule_ids, evidence_digests=(_EVIDENCE,),
        parent_item_ids=(),
    )


def benign_label(group: str = "analyst:1") -> LabelAssertion:
    return LabelAssertion(verdict=Verdict.BENIGN, origin=LabelOrigin.ANALYST,
                          asserted_by=group, target_capsule_id="")


def analyst(group: str = "analyst:1") -> SourceProvenance:
    return provenance(group, source=SourceClass.ANALYST, origin=LabelOrigin.ANALYST)


def validation_stub() -> ItemValidation:
    return ItemValidation(
        validations=1, recurrence=1, contradictions=0, first_sequence=0,
        last_matched_sequence=0, epochs_seen=frozenset({0}),
    )


_FOUNDING = ("cap-" + "c" * 24,)


def protected_detector(
    step: EncodedStep, *, founded_on: tuple[str, ...] = _FOUNDING
) -> KnowledgeItem:
    motif = (MotifStep(relation=step.relation, require_properties=step.object_property_mask,
                       forbid_properties=0, require_raised=0),)
    return KnowledgeItem.build(
        kind=ItemKind.DETECTOR, context_ids={ALL_CONTEXTS}, pattern_key=motif_pattern_key(motif),
        weight=0.9, origin_verdict=Verdict.MALICIOUS, lineage=lineage_stub(founded_on),
        validation=validation_stub(), motif=motif,
    )


class Harness:
    """A gateway bound to a trusted state the test controls (the controller's role)."""

    def __init__(self, *, dag: KnowledgeLineageDAG | None = None, **kwargs: object) -> None:
        self.ledger = ProvenanceLedger()
        self.dag = dag if dag is not None else KnowledgeLineageDAG()
        self.gateway = QuarantineGateway(ledger=self.ledger, lineage=self.dag, **kwargs)
        self.state: TrustedKnowledgeState = genesis_state(identity=IDENTITY_A)
        self.gateway.bind_trusted_view(lambda: self.state)
        self.seq = 0

    def admit(self, capsule: ExperienceCapsuleV1) -> QuarantineVerdict:
        return self.gateway.admit(capsule)

    def offer(self, step: EncodedStep, **kwargs: object) -> QuarantineVerdict:
        self.seq += 1
        return self.admit(episode([step], seq=self.seq, **kwargs))


def corroborated(epoch_id: int) -> EpochDecision:
    return EpochDecision(
        epoch_id=epoch_id, reason=EpochTransitionReason.SYSTEM_CHANGE_CORROBORATED,
        changed_components=frozenset({"package_digest"}), corroborated=True, detail="test",
    )


def uncorroborated(epoch_id: int) -> EpochDecision:
    return EpochDecision(
        epoch_id=epoch_id, reason=EpochTransitionReason.REJECTED_NO_CORROBORATION,
        changed_components=frozenset({"package_digest"}), corroborated=False, detail="test",
    )


def run_probe(harness: Harness, groups: Sequence[str]) -> list[QuarantineVerdict]:
    """Spec §0: 40 offers in epoch 0, a corroborated change, 200 offers in epoch 1."""
    def offer(i: int, epoch: int) -> QuarantineVerdict:
        return harness.offer(staging_step(group=groups[i % len(groups)], epoch=epoch))

    verdicts = [offer(i, 0) for i in range(40)]
    assert harness.gateway.record_epoch_decision(corroborated(1))
    verdicts += [offer(i, 1) for i in range(200)]
    return verdicts


def admissions_of(verdicts: Sequence[QuarantineVerdict]) -> int:
    return sum(len(v.admissions) for v in verdicts)


# --- D6.2: the §0 probe through admit (ADR-0054) ------------------------------


def test_single_source_repetition_across_corroborated_epochs_is_never_admitted() -> None:
    harness = Harness()
    digest_before = harness.state.digest()
    verdicts = run_probe(harness, GROUPS[:1])

    assert admissions_of(verdicts) == 0
    assert harness.gateway.take_admissions() == ()
    refused = [v for v in verdicts if REASON_SINGLE_SOURCE in v.reasons]
    assert len(refused) > 100, "the independence check must be what refused, not something else"
    assert harness.gateway.stats().get("single_source_refusals") == len(refused)
    assert all(v.bucket is not QuarantineBucket.TRUSTED_CANDIDATE for v in verdicts)
    assert harness.state.digest() == digest_before


def test_the_single_source_attack_is_real_without_the_independence_check() -> None:
    """Control arm: Stage 2 alone promotes the same stream (spec §0 measured 3)."""
    control = Harness(independence_check=False)
    verdicts = run_probe(control, GROUPS[:1])
    assert admissions_of(verdicts) > 0
    assert all(REASON_SINGLE_SOURCE not in v.reasons for v in verdicts)


def test_same_pattern_from_three_independent_groups_is_admitted_as_candidate() -> None:
    harness = Harness()
    digest_before = harness.state.digest()
    verdicts = run_probe(harness, GROUPS[:3])

    admitted = [a for v in verdicts for a in v.admissions]
    assert admitted, "a gate that admits nothing is accept-nothing, not a defence (F10)"
    first = admitted[0]
    assert first.independent_groups >= 3
    assert first.pattern_key == pattern_key(staging_step().to_encoded())  # Rule A
    assert first.stage2_reason.endswith("delay served")  # Stage 2's reason, verbatim
    assert first.context_id == CTX_A and first.capsule_ids and first.evidence_digests
    assert any(v.bucket is QuarantineBucket.TRUSTED_CANDIDATE for v in verdicts)
    drained = harness.gateway.take_admissions()
    assert len(drained) == 1 and harness.gateway.take_admissions() == ()
    assert harness.state.digest() == digest_before, "the gateway never writes trusted state"


def test_stage2_refusal_reasons_surface_verbatim() -> None:
    harness = Harness()
    early = harness.offer(staging_step(epoch=0))
    assert REFUSE_FREQUENCY_ALONE in early.reasons
    assert dict(early.stage2_outcomes) == {REFUSE_FREQUENCY_ALONE: 1}
    escalating = harness.offer(credential_step())
    assert REFUSE_EVIDENCE in escalating.reasons


def test_escalating_steps_never_reach_the_candidate_register() -> None:
    harness = Harness()
    for epoch in (0, 1):
        if epoch:
            harness.gateway.record_epoch_decision(corroborated(1))
        for i in range(60):
            verdict = harness.offer(credential_step(group=GROUPS[i % 3], epoch=epoch))
            assert set(dict(verdict.stage2_outcomes)) == {REFUSE_EVIDENCE}
    stats = harness.gateway.stats()
    assert harness.gateway.take_admissions() == ()
    assert stats.get("stage2_promotions") == 0
    assert stats.get("register_refused") == 0 and stats.get("register_unstaged") == 0


def test_candidate_register_never_reads_the_state_argument() -> None:
    encoded = staging_step().to_encoded()
    outputs = []
    for state in (SecurityStateV1(), SecurityStateV1(privilege=Privilege.ROOT)):
        register = _CandidateRegister()
        register.stage(
            _Staging(context_id=CTX_A, capsule_ids=("cap-1",), evidence=(_EVIDENCE,), groups=3)
        )
        atom = register.quantize_behaviour_atom(encoded, state=state, epoch_id=1, sequence=7)
        outputs.append((atom, register.admit_last("reason")))
    assert outputs[0] == outputs[1]
    assert outputs[0][1] is not None and register.get(outputs[0][0]) is None


def test_candidate_register_records_nothing_for_an_unstaged_or_overfull_call() -> None:
    encoded = staging_step().to_encoded()
    register = _CandidateRegister(capacity=1)
    register.quantize_behaviour_atom(encoded, state=SecurityStateV1(), epoch_id=0, sequence=1)
    assert register.admit_last("x") is None and register.unstaged == 1
    register.stage(_Staging(context_id="ctx-one", capsule_ids=(), evidence=(), groups=3))
    register.quantize_behaviour_atom(encoded, state=SecurityStateV1(), epoch_id=0, sequence=2)
    assert register.admit_last("x") is not None
    register.commit()
    register.stage(_Staging(context_id="ctx-two", capsule_ids=(), evidence=(), groups=3))
    register.quantize_behaviour_atom(encoded, state=SecurityStateV1(), epoch_id=0, sequence=3)
    assert register.admit_last("x") is None and register.refused == 1


def test_pattern_tracker_overflow_never_promotes() -> None:
    harness = Harness()
    harness.gateway._independence = SourceIndependence(max_patterns=0, max_groups=16, max_refs=16)
    verdicts = run_probe(harness, GROUPS[:3])
    assert admissions_of(verdicts) == 0
    assert any("pattern_register_full" in v.reasons for v in verdicts)
    assert harness.gateway.stats().get("pattern_overflow") > 0


def test_min_independent_groups_below_two_is_refused() -> None:
    with pytest.raises(ValueError):
        QuarantineGateway(
            ledger=ProvenanceLedger(), lineage=KnowledgeLineageDAG(), min_independent_groups=1
        )


# --- D6.2: the door itself ----------------------------------------------------


def test_admit_refuses_before_a_trusted_view_is_bound() -> None:
    gateway = QuarantineGateway(ledger=ProvenanceLedger(), lineage=KnowledgeLineageDAG())
    with pytest.raises(ContractError):
        gateway.admit(episode([staging_step()], seq=1))


def test_trusted_view_binds_exactly_once() -> None:
    harness = Harness()
    with pytest.raises(ContractError):
        harness.gateway.bind_trusted_view(lambda: harness.state)


def test_a_sample_injected_straight_from_telemetry_is_refused() -> None:
    """RAW_TELEMETRY_IS_NOT_TRAINING_DATA: only an ExperienceCapsuleV1 passes the door."""
    harness = Harness()
    digest = harness.state.digest()
    step = staging_step()
    sample = AdaptationSample(
        encoded=step.to_encoded(), state=SecurityStateV1(), epoch_id=0, delta_phi=0.0,
        uncertainty=0.0, evidence=(), received_at_sequence=1,
    )
    for raw in (step.to_encoded(), step, sample, "raw-event", {"kind": "TRANSITION_EPISODE"}, None):
        with pytest.raises(ContractError):
            harness.admit(raw)  # type: ignore[arg-type]
    assert harness.gateway.stats().get("offered") == 0
    assert harness.gateway._buffer.pending() == () and harness.gateway.take_admissions() == ()
    assert harness.dag.stats().nodes == 0
    assert harness.state.digest() == digest


def test_duplicate_capsule_is_discarded_and_never_relearned() -> None:
    harness = Harness()
    capsule = episode([staging_step()], seq=1)
    first = harness.admit(capsule)
    again = harness.admit(capsule)
    assert first.bucket is not QuarantineBucket.DISCARD
    assert again.bucket is QuarantineBucket.DISCARD and "duplicate" in again.reasons
    assert again.stage2_outcomes == ()
    assert harness.gateway.stats().get("steps_offered") == 1


def test_secret_bearing_capsule_is_discarded_before_any_learning() -> None:
    harness = Harness()
    verdict = harness.admit(episode([staging_step()], seq=1, privacy=PrivacyClass.SECRET_BEARING))
    assert verdict.bucket is QuarantineBucket.DISCARD and verdict.reasons == ("secret_bearing",)
    assert harness.gateway.stats().get("steps_offered") == 0


def test_issued_is_false_for_hand_built_or_altered_verdicts() -> None:
    harness = Harness()
    real = harness.offer(staging_step())
    assert harness.gateway.issued(real)
    forged = dataclasses.replace(real, bucket=QuarantineBucket.TRUSTED_CANDIDATE)
    assert not harness.gateway.issued(forged), "a real verdict_id on an altered body is forged"
    other = Harness()
    assert not other.gateway.issued(real), "a verdict is only issued by the gateway that minted it"


def test_issued_set_is_bounded_and_counts_what_it_forgets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gateway_module, "MAX_ISSUED_VERDICTS", 3)
    harness = Harness()
    verdicts = [harness.offer(staging_step()) for _ in range(5)]
    stats = harness.gateway.stats()
    assert stats.get("issued") == 3 and stats.get("issued_forgotten") >= 2
    assert not harness.gateway.issued(verdicts[0]) and harness.gateway.issued(verdicts[-1])


def test_lineage_records_capsule_then_verdict_before_issuing() -> None:
    harness = Harness()
    capsule = episode([staging_step()], seq=1)
    verdict = harness.admit(capsule)
    assert harness.dag.has(capsule.capsule_id) and harness.dag.has(verdict.verdict_id)
    assert harness.dag.parents(verdict.verdict_id) == (capsule.capsule_id,)
    assert harness.dag.verify() == ()


class _RefusingDAG(KnowledgeLineageDAG):
    """A lineage store that refuses exactly the VERDICT node of an admitting call."""

    def update_lineage_dag(self, *, node: LineageNode, **kwargs: object) -> LineageNode:
        if node.kind is NodeKind.VERDICT and node.detail == QuarantineBucket.TRUSTED_CANDIDATE:
            raise LineageCapacityError("simulated full lineage store")
        return super().update_lineage_dag(node=node, **kwargs)  # type: ignore[arg-type]


def test_a_lineage_failure_fails_closed_and_commits_no_admission() -> None:
    """Step 10: lineage first, issuance second. A verdict that could not be recorded is
    never issued, and the admissions its call staged are aborted, not committed."""
    harness = Harness(dag=_RefusingDAG())
    with pytest.raises(LineageCapacityError):
        run_probe(harness, GROUPS[:3])
    stats = harness.gateway.stats()
    assert stats.get("aborted_calls") == 1 and stats.get("register_aborted") == 1
    assert harness.gateway.take_admissions() == ()
    assert stats.get("issued") == stats.get("offered") - 1


def test_record_epoch_decision_reaches_both_stage2_objects_and_ignores_uncorroborated() -> None:
    harness = Harness()
    assert not harness.gateway.record_epoch_decision(uncorroborated(1))
    assert harness.gateway._buffer.corroborated_epochs == frozenset({0})
    assert harness.gateway._controller.corroborated_epochs == frozenset({0})
    assert harness.gateway.record_epoch_decision(corroborated(1))
    assert harness.gateway._buffer.corroborated_epochs == frozenset({0, 1})
    assert harness.gateway._controller.corroborated_epochs == frozenset({0, 1})


def test_foreign_package_is_at_most_uncertain_even_with_local_corroboration() -> None:
    """A remote majority never overrides local state. Under the §4.21 parameters the
    FOREIGN_ORIGIN risk (0.6) caps provenance at 0.4 < MIN_PROVENANCE_SCORE, so even a
    locally corroborated foreign capsule stays UNCERTAIN: the corroboration branch of
    step 9 is unreachable today, which the gateway's findings report as INERT."""
    harness = Harness()
    run_probe(harness, GROUPS[:3])  # the pattern IS locally corroborated by 3 groups
    steps = (staging_step(epoch=1),)
    draft = step_draft_fields(steps, cut=False)
    draft["contamination_flags"] = draft["contamination_flags"] | {ContaminationFlag.FOREIGN_ORIGIN}
    foreign = dataclasses.replace(
        episode(list(steps), seq=10_000), kind=CapsuleKind.FOREIGN_PACKAGE,
        source_provenance=provenance("foreign:peer-1", source=SourceClass.FOREIGN_HOST),
        capsule_id="", **{k: v for k, v in draft.items() if k != "steps"},
    )
    steps_before = harness.gateway.stats().get("steps_offered")
    verdict = harness.admit(foreign)
    assert verdict.bucket is QuarantineBucket.UNCERTAIN and "low_provenance" in verdict.reasons
    assert verdict.stage2_outcomes == ()
    after = harness.gateway.stats().get("steps_offered")
    assert after == steps_before, "foreign steps never reach Stage 2"


# --- D6.2 step 7: the label quorum -------------------------------------------


def test_label_quorum_needs_two_voting_groups_or_ground_truth() -> None:
    assert not label_quorum_met({"analyst:1": LabelOrigin.ANALYST})
    assert not label_quorum_met({f"teacher:{i}": LabelOrigin.TEACHER for i in range(9)})
    assert not label_quorum_met({"weak:1": LabelOrigin.WEAK, "analyst:1": LabelOrigin.ANALYST})
    assert label_quorum_met({"analyst:1": LabelOrigin.ANALYST, "analyst:2": LabelOrigin.ANALYST})
    assert label_quorum_met({"lab": LabelOrigin.GROUND_TRUTH})


def test_one_analyst_group_is_never_enough_and_teachers_never_count() -> None:
    harness = Harness()
    target = harness.offer(credential_step()).capsule_id
    seq = 100
    for group, origin in (("analyst:1", LabelOrigin.ANALYST), ("analyst:1", LabelOrigin.ANALYST),
                          ("teacher:1", LabelOrigin.TEACHER), ("teacher:2", LabelOrigin.TEACHER)):
        seq += 1
        capsule = label_capsule(target, Verdict.MALICIOUS, group=group, origin=origin, seq=seq)
        verdict = harness.admit(capsule)
        assert verdict.bucket is QuarantineBucket.UNCERTAIN, (group, verdict.reasons)
        assert verdict.target_episode == target
    assert target in harness.gateway.pending_label_episodes()
    settled = harness.admit(
        label_capsule(
            target, Verdict.MALICIOUS, group="analyst:2", origin=LabelOrigin.ANALYST, seq=seq + 1
        )
    )
    assert settled.bucket is QuarantineBucket.TRUSTED_CANDIDATE
    assert target not in harness.gateway.pending_label_episodes()


def test_ground_truth_settles_an_episode_alone() -> None:
    harness = Harness(ground_truth_groups=("lab",))
    target = harness.offer(credential_step()).capsule_id
    verdict = harness.admit(
        label_capsule(target, Verdict.MALICIOUS, group="lab", origin=LabelOrigin.GROUND_TRUTH,
                      seq=50, source=SourceClass.LAB_GROUND_TRUTH)
    )
    assert verdict.bucket is QuarantineBucket.TRUSTED_CANDIDATE


# --- review S6-AUTH-01: GROUND_TRUTH is authenticated, never self-asserted ----------------


def test_only_a_lab_source_may_declare_ground_truth() -> None:
    """S6-AUTH-01: a sensor, analyst or dataset claiming GROUND_TRUTH is refused at build."""
    for source in (SourceClass.KERNEL_SENSOR, SourceClass.ANALYST, SourceClass.EXTERNAL_DATASET):
        with pytest.raises(ContractError, match="GROUND_TRUTH"):
            provenance("lab", source=source, origin=LabelOrigin.GROUND_TRUTH)


def test_unauthenticated_ground_truth_does_not_settle_alone() -> None:
    """S6-AUTH-01: a LAB_GROUND_TRUTH claim from a group the deployment never authenticated
    is one ANALYST vote, so it cannot settle an episode or outvote an analyst quorum."""
    harness = Harness()  # an endpoint: no lab group is authenticated
    target = harness.offer(credential_step()).capsule_id
    for n, group in enumerate(("analyst:1", "analyst:2")):
        harness.admit(label_capsule(target, Verdict.MALICIOUS, group=group,
                                    origin=LabelOrigin.ANALYST, seq=60 + n))
    forged = harness.admit(
        label_capsule(target, Verdict.BENIGN, group="lab", origin=LabelOrigin.GROUND_TRUTH,
                      seq=70, source=SourceClass.LAB_GROUND_TRUTH)
    )
    # Screened like an analyst: the label-shift and protected-meaning rules now apply.
    assert forged.bucket is QuarantineBucket.HOSTILE_SUSPECT, forged.reasons
    assert "suspicion:label_shift" in forged.reasons
    fresh = harness.offer(credential_step()).capsule_id
    alone = harness.admit(
        label_capsule(fresh, Verdict.MALICIOUS, group="lab", origin=LabelOrigin.GROUND_TRUTH,
                      seq=80, source=SourceClass.LAB_GROUND_TRUTH)
    )
    assert alone.bucket is QuarantineBucket.UNCERTAIN, alone.reasons
    assert "ground_truth_unauthenticated" in alone.reasons
    assert harness.gateway.stats().get("ground_truth_demoted") == 1


def test_unauthenticated_ground_truth_benign_on_a_protected_detector_is_hostile() -> None:
    """S6-AUTH-01: the benign-label-on-protected-detector rule applies to a claimed
    GROUND_TRUTH exactly as to an analyst; only an authenticated lab group is exempt."""
    for groups, hostile in (((), True), (("lab",), False)):
        harness = Harness(ground_truth_groups=groups)
        detector = protected_detector(credential_step())
        harness.state = harness.state.with_changes(add=(detector,))
        target = harness.offer(credential_step()).capsule_id
        verdict = harness.admit(
            label_capsule(target, Verdict.BENIGN, group="lab", origin=LabelOrigin.GROUND_TRUTH,
                          seq=90, source=SourceClass.LAB_GROUND_TRUTH)
        )
        assert (verdict.bucket is QuarantineBucket.HOSTILE_SUSPECT) is hostile, verdict.reasons


def test_a_label_on_an_episode_the_gateway_never_admitted_is_refused() -> None:
    harness = Harness()
    verdict = harness.admit(
        label_capsule("cap-" + "0" * 24, Verdict.MALICIOUS, group="lab",
                      origin=LabelOrigin.GROUND_TRUTH, seq=9, source=SourceClass.LAB_GROUND_TRUTH)
    )
    assert verdict.bucket is QuarantineBucket.UNCERTAIN
    assert "label_target_unknown" in verdict.reasons


# --- D6.15: homeostasis --------------------------------------------------------


def test_benign_analyst_label_on_an_episode_matching_a_protected_detector_is_hostile() -> None:
    harness = Harness()
    detector = protected_detector(credential_step())
    assert detector.protected
    harness.state = harness.state.with_changes(add=[detector])
    capsule = episode([credential_step()], seq=1, label=benign_label(), prov=analyst())
    verdict = harness.admit(capsule)
    assert verdict.bucket is QuarantineBucket.HOSTILE_SUSPECT
    assert verdict.normalization is not None
    assert verdict.normalization.rule == RULE_BENIGN_LABEL_ON_PROTECTED_DETECTOR
    assert verdict.normalization.detector_ids == (detector.item_id,)
    assert verdict.stage2_outcomes == (), "hostile: kept as evidence, never learned from"


def test_a_separate_benign_label_on_a_protected_episode_is_hostile_too() -> None:
    harness = Harness()
    harness.state = harness.state.with_changes(add=[protected_detector(credential_step())])
    target = harness.offer(credential_step()).capsule_id
    verdict = harness.admit(label_capsule(target, Verdict.BENIGN, group="analyst:1",
                                          origin=LabelOrigin.ANALYST, seq=20))
    assert verdict.bucket is QuarantineBucket.HOSTILE_SUSPECT
    assert verdict.normalization is not None
    assert verdict.normalization.rule == RULE_BENIGN_LABEL_ON_PROTECTED_DETECTOR


def test_normality_claim_over_protected_meaning_is_hostile_without_any_detector() -> None:
    capsule = episode([credential_step()], seq=1, label=benign_label(), prov=analyst())
    genesis = genesis_state(identity=IDENTITY_A)
    finding = detect_semantic_normalization_attack(capsule, trusted=genesis)
    assert finding is not None and finding.rule == RULE_NORMALITY_ON_PROTECTED_MEANING
    assert "credential_material" in finding.anchors


def test_protected_meaning_does_not_adapt_from_frequency() -> None:
    """The rules read masks and labels only: repetition cannot change their answer."""
    detector = protected_detector(credential_step())
    trusted = genesis_state(identity=IDENTITY_A).with_changes(add=[detector])
    findings = {
        detect_semantic_normalization_attack(
            episode([credential_step()] * n, seq=n, label=benign_label(), prov=analyst()),
            trusted=trusted,
        )
        for n in (1, 8, 64)
    }
    assert len(findings) == 1 and next(iter(findings)) is not None
    harness = Harness()
    harness.state = trusted
    for i in range(30):
        verdict = harness.offer(credential_step(group=GROUPS[i % 3], epoch=i % 2),
                                label=benign_label(), prov=analyst())
        assert verdict.bucket is QuarantineBucket.HOSTILE_SUSPECT, i


def test_beyond_stage2_protected_steps_are_withheld_from_the_normality_learner() -> None:
    base = staging_step()
    bit = property_mask([SemanticProperty.CREDENTIAL_READER])
    reader = dataclasses.replace(base, object_property_mask=base.object_property_mask | bit)
    assert not poisoning.stage2_would_refuse(reader), "Stage 2's own rule would learn this step"
    harness = Harness()
    verdict = harness.offer(reader)
    assert "protected_meaning_withheld" in verdict.reasons and verdict.stage2_outcomes == ()
    assert harness.gateway.stats().get("beyond_stage2") == 1
    control = Harness(homeostasis=False)
    assert control.offer(reader).stage2_outcomes != (), "the ablation control reaches Stage 2"


def test_disowning_a_protected_detectors_evidence_by_label_is_hostile() -> None:
    harness = Harness()
    founding = harness.offer(staging_step()).capsule_id  # steps do NOT match the detector
    detector = protected_detector(credential_step(), founded_on=(founding,))
    harness.state = harness.state.with_changes(add=[detector])
    verdict = harness.admit(label_capsule(founding, Verdict.BENIGN, group="analyst:1",
                                          origin=LabelOrigin.ANALYST, seq=3))
    assert verdict.bucket is QuarantineBucket.HOSTILE_SUSPECT
    assert verdict.normalization is not None
    assert verdict.normalization.rule == RULE_REMOVE_PROTECTED_DETECTOR
    assert verdict.normalization.detector_ids == (detector.item_id,)


def test_label_shift_against_prior_verdicts_is_hostile() -> None:
    harness = Harness()
    for n, group in enumerate(("lab-a", "lab-b")):
        target = harness.offer(credential_step()).capsule_id
        harness.admit(label_capsule(
            target, Verdict.MALICIOUS, group=group, origin=LabelOrigin.ANALYST, seq=200 + n
        ))
    fresh = harness.offer(credential_step()).capsule_id
    flipped = harness.admit(label_capsule(fresh, Verdict.BENIGN, group="analyst:9",
                                          origin=LabelOrigin.ANALYST, seq=300))
    assert flipped.bucket is QuarantineBucket.HOSTILE_SUSPECT
    assert flipped.suspicion.label_shift == 1.0 and "suspicion:label_shift" in flipped.reasons


def test_repeated_votes_from_one_group_become_dependent_and_hostile() -> None:
    harness = Harness()
    target = harness.offer(credential_step()).capsule_id
    buckets = [
        harness.admit(label_capsule(target, Verdict.MALICIOUS, group="analyst:1",
                                    origin=LabelOrigin.ANALYST, seq=400 + n)).bucket
        for n in range(6)
    ]
    assert buckets[0] is QuarantineBucket.UNCERTAIN
    assert buckets[-1] is QuarantineBucket.HOSTILE_SUSPECT


def test_near_miss_mimicry_of_a_trusted_detector_is_hostile() -> None:
    cred = credential_step()
    trusted = genesis_state(identity=IDENTITY_A).with_changes(add=[protected_detector(cred)])
    missing = cred.object_property_mask & -cred.object_property_mask  # lowest required bit
    near = dataclasses.replace(cred, object_property_mask=cred.object_property_mask ^ missing)
    capsule = episode([near], seq=1)
    assert poisoning._trigger_concentration(capsule, trusted) == 1.0
    harness = Harness()
    harness.state = trusted
    assert harness.admit(capsule).bucket is QuarantineBucket.HOSTILE_SUSPECT


def test_suspicion_leaves_conservation_components_unmeasured() -> None:
    harness = Harness()
    verdict = harness.offer(staging_step())
    assert verdict.suspicion.historical_regression is None
    assert verdict.suspicion.counterfactual_instability is None
    quiet = PoisonSuspicion(0.1, 0.2, False, 0.0, 0.0, 0.3)
    assert quiet.summary() == pytest.approx(0.3) and not quiet.is_hostile()
    assert PoisonSuspicion(0.0, 0.0, True, 0.0, 0.0, 0.0).summary() == 1.0
    assert PoisonSuspicion(0.0, 0.8, False, 0.0, 0.0, 0.0).is_hostile()
    assert PoisonSuspicion(0.0, 0.0, False, 0.5, 0.0, 0.0).is_hostile()
    assert PoisonSuspicion(0.0, 0.0, False, 0.0, 0.5, 0.0).is_hostile()


def test_label_history_is_bounded_and_counts_what_it_forgets() -> None:
    history = LabelHistory(capacity=2)
    for n in range(5):
        history.observe(f"motif:{n}", Verdict.MALICIOUS, group="g", epoch_id=0)
    assert len(history) == 2 and history.forgotten() == 3
    history.observe("motif:x", Verdict.UNKNOWN, group="g", epoch_id=0)
    assert history.opposite_share("motif:x", Verdict.BENIGN) == 0.0


def test_epoch_inconsistency_measures_flip_flopping_across_epochs() -> None:
    history = LabelHistory()
    for epoch, verdict in ((0, Verdict.MALICIOUS), (1, Verdict.MALICIOUS), (2, Verdict.BENIGN)):
        history.observe("motif:k", verdict, group=f"g{epoch}", epoch_id=epoch)
    assert history.epoch_inconsistency("motif:k") == pytest.approx(1 / 3)
    assert history.epoch_inconsistency("motif:unseen") == 0.0


def test_track_key_separates_meanings_that_share_a_stage2_pattern() -> None:
    base = staging_step()
    scalar = GROUP_OFFSETS["state_delta_scalars"]
    features = list(base.features)
    features[scalar] = 0.25 if features[scalar] != 0.25 else 0.5
    other = dataclasses.replace(base, features=tuple(features))
    assert pattern_key(base.to_encoded()) == pattern_key(other.to_encoded())
    assert track_key(base.to_encoded()) != track_key(other.to_encoded())


# --- D6.16: drift ---------------------------------------------------------------


def _signals(**overrides: object) -> DriftSignals:
    base = dict(provenance_trusted_change=True, breadth=0.5, timing_aligned=True,
                independent_corroboration=3, semantics_stable=True, rollback_test_passed=None)
    base.update(overrides)
    return DriftSignals(**base)  # type: ignore[arg-type]


def test_drift_classifier_requires_corroboration_and_stable_semantics() -> None:
    assert classify_drift_vs_poisoning(_signals()).drift_class is DriftClass.LEGITIMATE_DRIFT
    for broken in (_signals(semantics_stable=False), _signals(rollback_test_passed=False)):
        assert classify_drift_vs_poisoning(broken).drift_class is DriftClass.POISON_SUSPECT
    lone = _signals(provenance_trusted_change=False, independent_corroboration=1)
    assert classify_drift_vs_poisoning(lone).drift_class is DriftClass.POISON_SUSPECT


def test_no_single_drift_signal_decides() -> None:
    """A corroborated change alone, or broad independent change alone, is not legitimate drift."""
    timed_capture = _signals(independent_corroboration=1)  # arm P2b's shape
    assert classify_drift_vs_poisoning(timed_capture).drift_class is DriftClass.UNDETERMINED
    no_change = _signals(provenance_trusted_change=False, breadth=1.0)
    assert classify_drift_vs_poisoning(no_change).drift_class is DriftClass.UNDETERMINED


def test_drift_signals_are_measured_from_the_verdict_window() -> None:
    harness = Harness()
    before = [harness.offer(staging_step(group=GROUPS[0])) for _ in range(3)]
    pivot = before[-1].sequence
    moved = dataclasses.replace(credential_step(), relation=staging_step().relation + 1)
    after = [harness.offer(dataclasses.replace(moved, source_group=g)) for g in GROUPS[:3]]
    signals = drift_signals(before + after, decision=corroborated(1), decision_sequence=pivot)
    assert signals.provenance_trusted_change and signals.timing_aligned
    assert 0.0 < signals.breadth <= 1.0
    assert signals.independent_corroboration == 3
    assert not signals.semantics_stable, "the changed pattern touches credential meaning"
    assert signals.rollback_test_passed is None
    none = drift_signals(before + after, decision=uncorroborated(1), decision_sequence=pivot)
    assert not none.provenance_trusted_change and not none.timing_aligned


def _baseline_item(context: str) -> KnowledgeItem:
    step = staging_step()
    return KnowledgeItem.build(
        kind=ItemKind.BASELINE, context_ids={context}, pattern_key=pattern_key(step.to_encoded()),
        weight=1.0, origin_verdict=Verdict.BENIGN, lineage=lineage_stub(),
        validation=validation_stub(), anchor=step.meaning(),
    )


def test_uncorroborated_epoch_decision_opens_no_context() -> None:
    registry = KnowledgeContextRegistry(identity=IDENTITY_A)
    trusted = genesis_state(identity=IDENTITY_A)
    fossils = FossilStore()
    for epoch in range(1, 6):
        assert registry.open_new_epoch(uncorroborated(epoch), identity=IDENTITY_B, sequence=epoch,
                                       trusted=trusted, fossils=fossils) is None
    assert [c.status for c in registry.contexts()] == [ContextStatus.ACTIVE]
    assert fossils.fossils() == () and registry.refused_uncorroborated == 5


def test_corroborated_transition_makes_old_context_dormant_and_only_proposes() -> None:
    registry = KnowledgeContextRegistry(identity=IDENTITY_A)
    trusted = genesis_state(identity=IDENTITY_A).with_changes(add=[_baseline_item(CTX_A)])
    digest = trusted.digest()
    fossils = FossilStore()
    transition = registry.open_new_epoch(corroborated(1), identity=IDENTITY_B, sequence=10,
                                         trusted=trusted, fossils=fossils)
    assert transition is not None and transition.previous == CTX_A
    assert transition.current == context_id_for(IDENTITY_B)
    assert transition.proposal.active_context == transition.current
    assert transition.resurrect is None
    old = registry.get(CTX_A)
    assert old is not None and old.status is ContextStatus.DORMANT and old.dormancy_fossil
    assert fossils.load(old.dormancy_fossil).digest() == digest
    assert registry.get(transition.current).status is ContextStatus.PROVISIONAL
    assert trusted.digest() == digest, "a transition is a proposal, never a write"


def test_resurrection_is_inert_while_the_returning_contexts_items_are_resident() -> None:
    item = _baseline_item(CTX_A)
    trusted_a = genesis_state(identity=IDENTITY_A).with_changes(add=[item])
    fossils = FossilStore()
    registry = KnowledgeContextRegistry(identity=IDENTITY_A)
    away = registry.open_new_epoch(corroborated(1), identity=IDENTITY_B, sequence=1,
                                   trusted=trusted_a, fossils=fossils)
    assert away is not None
    registry.activate(away.current, sequence=2)
    assert registry.get(away.current).status is ContextStatus.ACTIVE
    resident = trusted_a.with_changes(active_context=away.current)
    back = registry.open_new_epoch(corroborated(2), identity=IDENTITY_A, sequence=3,
                                   trusted=resident, fossils=fossils)
    assert back is not None and back.resurrect is None
    assert registry.resurrections == 0


def test_resurrection_reloads_only_evicted_items_from_the_verified_fossil() -> None:
    item = _baseline_item(CTX_A)
    trusted_a = genesis_state(identity=IDENTITY_A).with_changes(add=[item])
    fossils = FossilStore()
    registry = KnowledgeContextRegistry(identity=IDENTITY_A)
    away = registry.open_new_epoch(corroborated(1), identity=IDENTITY_B, sequence=1,
                                   trusted=trusted_a, fossils=fossils)
    assert away is not None
    evicted = trusted_a.with_changes(active_context=away.current, remove=[item.item_id])
    back = registry.open_new_epoch(corroborated(2), identity=IDENTITY_A, sequence=5,
                                   trusted=evicted, fossils=fossils)
    assert back is not None and back.resurrect is not None
    assert back.resurrect.items == (item,)
    assert back.resurrect.context_id == CTX_A
    assert registry.get(CTX_A).epoch_ids == (0, 2), "a return is a new Stage 1 epoch, same key"
    assert registry.resurrections == 1
    resident = {i.item_id for i in evicted.items}
    assert item.item_id not in resident, "resurrection proposes, never writes"


def test_resurrection_refuses_a_corrupted_dormancy_fossil(tmp_path: object) -> None:
    item = _baseline_item(CTX_A)
    trusted_a = genesis_state(identity=IDENTITY_A).with_changes(add=[item])
    fossils = FossilStore(directory=tmp_path)  # type: ignore[arg-type]
    registry = KnowledgeContextRegistry(identity=IDENTITY_A)
    t1 = registry.open_new_epoch(corroborated(1), identity=IDENTITY_B, sequence=1,
                                 trusted=trusted_a, fossils=fossils)
    assert t1 is not None
    fossil_hash = registry.get(CTX_A).dormancy_fossil
    for path in tmp_path.iterdir():  # type: ignore[attr-defined]
        path.write_bytes(b"corrupted")
    evicted = trusted_a.with_changes(active_context=t1.current, remove=[item.item_id])
    reloaded = registry.resurrect_dormant_knowledge(IDENTITY_A, trusted=evicted, fossils=fossils)
    assert reloaded is None
    assert registry.unloadable_fossils == 1 and fossil_hash


def test_context_registry_is_bounded_and_drops_only_dormant_contexts() -> None:
    fossils = FossilStore(max_fossils=64)
    registry = KnowledgeContextRegistry(identity=IDENTITY_A, capacity=3)
    trusted = genesis_state(identity=IDENTITY_A)
    for n in range(1, 7):
        identity = SystemIdentity(kernel_id="k-1", package_digest=f"pkg-{n}")
        transition = registry.open_new_epoch(corroborated(n), identity=identity, sequence=n,
                                             trusted=trusted, fossils=fossils)
        assert transition is not None
        trusted = trusted.with_changes(active_context=transition.current)
    assert len(registry.contexts()) == 3 and registry.dropped == 4
    live = [c for c in registry.contexts() if c.status is not ContextStatus.DORMANT]
    assert len(live) == 1


# --- bounds: every store refuses or forgets, counted, and the gateway plateaus -------


def test_label_register_refuses_newcomers_rather_than_evicting_pending_episodes() -> None:
    quorum = poisoning.LabelQuorum(capacity=2)
    for target in ("cap-a", "cap-b"):
        assert quorum.vote(target, Verdict.MALICIOUS, group="g1", origin=LabelOrigin.ANALYST) == (
            False, "awaiting_label_quorum")
    assert quorum.vote("cap-c", Verdict.MALICIOUS, group="g1", origin=LabelOrigin.ANALYST) == (
        False, "label_register_full")
    assert quorum.overflow == 1 and set(quorum.pending()) == {"cap-a", "cap-b"}
    truth = LabelOrigin.GROUND_TRUTH
    settled, _ = quorum.vote("cap-a", Verdict.MALICIOUS, group="lab", origin=truth)
    assert settled
    retry = quorum.vote("cap-c", Verdict.MALICIOUS, group="g1", origin=LabelOrigin.ANALYST)
    assert retry == (False, "awaiting_label_quorum")
    assert set(quorum.pending()) == {"cap-b", "cap-c"}, "only the SETTLED episode made room"


def test_contradicting_quorums_settle_nothing() -> None:
    quorum = poisoning.LabelQuorum(capacity=4)
    for group in ("a1", "a2"):
        quorum.vote("cap-x", Verdict.MALICIOUS, group=group, origin=LabelOrigin.ANALYST)
    for group in ("b1", "b2"):
        settled, reason = quorum.vote(
            "cap-x", Verdict.BENIGN, group=group, origin=LabelOrigin.ANALYST
        )
    assert not settled and reason == "label_contradiction" and "cap-x" in quorum.pending()


def test_independence_groups_per_pattern_are_capped_and_counted() -> None:
    tracker = SourceIndependence(max_patterns=1, max_groups=2, max_refs=4)
    assert tracker.observe("k1", "cap-1")
    counts = [
        tracker.record_group("k1", group=f"g{n}", capsule_id=f"cap-{n}", evidence=())
        for n in range(4)
    ]
    assert counts == [1, 2, 2, 2] and tracker.group_overflow == 2
    assert tracker.record_group("k2", group="g", capsule_id="c", evidence=()) is None


def test_a_full_pattern_tracker_retires_its_least_recent_key_and_counts_it() -> None:
    """S6-AUTH-07: a full tracker retires (counted) instead of refusing every new key forever.

    It retires a key no group ever corroborated before one that has groups, and a retired
    key restarts at zero groups — retirement can only lose corroboration, never add it.
    """
    tracker = SourceIndependence(max_patterns=2, max_groups=4, max_refs=4)
    assert tracker.observe("corroborated", "cap-1")
    assert tracker.record_group("corroborated", group="g1", capsule_id="cap-1", evidence=()) == 1
    assert tracker.observe("junk-1", "cap-2")
    assert tracker.observe("junk-2", "cap-3")  # full: the group-less junk-1 is retired
    assert tracker.pattern_evictions == 1 and tracker.groups("corroborated") == 1
    assert tracker.record_group("junk-1", group="g", capsule_id="c", evidence=()) is None
    assert tracker.observe("junk-3", "cap-4")  # junk-2 retired, corroborated still kept
    assert tracker.groups("corroborated") == 1 and tracker.pattern_evictions == 2


def test_one_source_filling_the_tracker_cannot_end_normality_learning() -> None:
    """S6-AUTH-07: MAX_PATTERNS_TRACKED ineligible single-group offers used to fill every
    track slot for the gateway's lifetime, after which no BASELINE could ever be admitted
    (the §0 probe with three groups then admitted 0, reason pattern_register_full)."""
    harness = Harness()
    attacker = source_group_of("proc:attacker:0")
    base = staging_step(group=attacker)
    for n in range(MAX_PATTERNS_TRACKED):
        features = list(base.features)
        features[71] = round(0.001 * (n + 1), 6)  # a new (pattern, meaning) key each time
        harness.offer(dataclasses.replace(base, features=tuple(features)))
    assert harness.gateway.stats().get("patterns_tracked") == MAX_PATTERNS_TRACKED
    verdicts = run_probe(harness, GROUPS[:3])
    assert admissions_of(verdicts) > 0
    assert not any("pattern_register_full" in v.reasons for v in verdicts)
    assert harness.gateway.stats().get("pattern_evictions") > 0


def test_gateway_memory_plateaus_over_a_long_horizon(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gateway_module, "MAX_ISSUED_VERDICTS", 64)
    monkeypatch.setattr(gateway_module, "MAX_PENDING_LABEL_EPISODES", 32)
    harness = Harness()
    harness.gateway.record_epoch_decision(corroborated(1))
    checkpoints = []
    horizon = 2400
    for n in range(1, horizon + 1):
        group = source_group_of(f"proc:lab:{n}:0")
        if n % 3 == 0:
            step = credential_step(group=group)
        else:
            step = staging_step(group=group, epoch=n % 2)
        harness.offer(step)
        if n % 600 == 0:
            checkpoints.append(harness.gateway.stats())
    sizes = [c.memory_bytes for c in checkpoints]
    # Stage 2's retained-evidence deque (256) is the last cap to fill, at ~n=770; after
    # it the gateway holds a constant amount however long the horizon runs.
    assert max(sizes[1:]) - min(sizes[1:]) <= 0.01 * max(sizes[1:]), sizes
    last = checkpoints[-1]
    assert last.get("issued") == 64 and last.get("issued_forgotten") == horizon - 64
    assert last.get("indexed_episodes") == 32 and last.get("episodes_forgotten") == horizon - 32
    assert last.get("group_overflow") > 0, "one pattern from 1600 lineages must hit the group cap"
    assert last.get("admissions_pending") == 1, "one pattern, one context: one merged admission"


# --- review S6-R2: a full lineage DAG refuses and counts; it never stops the door ------------


def test_a_full_lineage_dag_refuses_and_counts_instead_of_raising_on_every_admit() -> None:
    """S6-R2: past the DAG cap every admit used to raise LineageCapacityError — for legitimate
    capsules too — until someone consolidated, and the ledger kept rows with no verdict."""
    harness = Harness(dag=KnowledgeLineageDAG(max_nodes=12))
    verdicts = [harness.offer(staging_step(group=GROUPS[n % 5])) for n in range(10)]
    refused = [v for v in verdicts if "lineage_full" in v.reasons]
    assert refused and all(v.bucket is QuarantineBucket.DISCARD for v in refused)
    assert not any(harness.gateway.issued(v) for v in refused)  # nothing can learn from them
    assert harness.gateway.stats().get("lineage_full_refused") == len(refused)
    assert harness.dag.stats().nodes <= 12


def test_a_bound_collector_folds_so_admission_continues_past_the_cap() -> None:
    """S6-R2: with the controller's collector bound the gateway folds once and carries on."""
    harness = Harness(dag=KnowledgeLineageDAG(max_nodes=12))
    harness.gateway.bind_lineage_collector(
        lambda: harness.dag.collect(live_items=(), pinned_fossils=()))
    verdicts = [harness.offer(staging_step(group=GROUPS[n % 5])) for n in range(10)]
    assert not any("lineage_full" in v.reasons for v in verdicts)
    assert all(harness.gateway.issued(v) for v in verdicts)
    assert harness.gateway.stats().get("lineage_folds_at_admit") > 0
    with pytest.raises(ContractError, match="bound once"):
        harness.gateway.bind_lineage_collector(lambda: 0)
