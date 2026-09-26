"""Stage 6 package ``capsule``: D6.2 (types), D6.3 provenance ledger + trust, D6.19 fleet import.

Every test here is about a refusal or a bound, because the capsule is the boundary: a
capsule builder that let ground truth in through the side door, or a ledger that counted
one attacker as many voters, would make every later Stage 6 number meaningless.
"""

from __future__ import annotations

import dataclasses
import json
from typing import Any

import pytest

from pocketsec.stage0.contracts.common import ContractError, EvidenceRef, digest_of_bytes
from pocketsec.stage0.contracts.threat_prediction_v1 import Verdict
from pocketsec.stage1.epoch.model import Epoch, EpochModel, SystemIdentity
from pocketsec.stage1.labs.corpus import ATTACK_EXFIL, Behaviour, Scenario
from pocketsec.stage1.pipeline import ScenarioResult, Stage1Pipeline
from pocketsec.stage2.adaptation.quarantine import meaning_vector, pattern_key
from pocketsec.stage2.encoder.ssir_encoder import encode_ssir_transition
from pocketsec.stage4.stage5_interface import CBFResolutionV1
from pocketsec.stage5.stage6_interface import ResponseRecordV1
from pocketsec.stage6.capsule.experience_capsule import (
    MAX_CAPSULE_BYTES,
    MAX_EVIDENCE_PER_STEP,
    MAX_EVIDENCE_REFS_PER_CAPSULE,
    MAX_STEPS_PER_CAPSULE,
    CapsuleKind,
    ContaminationFlag,
    EncodedStep,
    ExperienceCapsuleV1,
    LabelAssertion,
    LabelOrigin,
    PrivacyClass,
    SourceClass,
    SourceProvenance,
    build_experience_capsule,
    capsule_from_label,
    capsule_from_resolution,
    capsule_from_response,
    capsule_from_scenario,
    privacy_audit,
    reseal_capsule,
    source_group_of,
)
from pocketsec.stage6.fleet.package import (
    FLEET_EXCHANGE_ENABLED,
    KNOWLEDGE_PACKAGE_V1_VERSION,
    MAX_PACKAGE_BYTES,
    MAX_PACKAGE_ITEMS,
    FleetDisabledError,
    KnowledgePackageV1,
    PackageVerification,
    fleet_group_of,
    package_to_capsules,
    sign_package,
    verify_package,
)
from pocketsec.stage6.memory.semantic import context_id_for
from pocketsec.stage6.provenance.ledger import MAX_EVICTION_LOG, ProvenanceLedger
from pocketsec.stage6.provenance.trust import (
    FLAG_RISK,
    LABEL_ORIGIN_WEIGHT,
    MIN_PROVENANCE_SCORE,
    SOURCE_CLASS_PRIOR,
    ProvenanceScore,
    detect_evidence_dependence,
    score_provenance,
)

KEY = b"k" * 32
OTHER_KEY = b"z" * 32

# --- fixtures ------------------------------------------------------------------


def _epoch(epoch_id: int = 0) -> Epoch:
    identity = SystemIdentity(kernel_id="6.1.0", package_digest="pkg-a", service_digest="svc-a")
    return dataclasses.replace(EpochModel(identity=identity).current, epoch_id=epoch_id)


def _provenance(**overrides: Any) -> SourceProvenance:
    values: dict[str, Any] = {
        "source_class": SourceClass.KERNEL_SENSOR, "source_id": "sensor.ebpf",
        "independence_group": "host.lab-01", "label_origin": LabelOrigin.NONE,
        "transformation_lineage": ("stage1.pipeline", "stage2.encoder"), "host_id": "lab-host-01",
    }
    values.update(overrides)
    return SourceProvenance(**values)


def _run(behaviours: tuple[Behaviour, ...], *, label: int = 1, offset: int = 0) -> ScenarioResult:
    scenario = Scenario(name="s", behaviours=behaviours, label=label, technique="t")
    return Stage1Pipeline().run_scenario(scenario, offset=offset)


def _episode(result: ScenarioResult | None = None, *, sequence: int = 1,
             label: LabelAssertion | None = None, **prov: Any) -> ExperienceCapsuleV1:
    return capsule_from_scenario(result or _run(ATTACK_EXFIL), epoch=_epoch(),
                                 provenance=_provenance(**prov), sequence=sequence, label=label)


def _record(**overrides: Any) -> ResponseRecordV1:
    payload: dict[str, Any] = {
        "record_id": "REC-0001", "incident_id": "INC-0001", "epoch_id": 1,
        "resolution_id": "RES-0001", "plan_decision": "ACT", "receipts": (), "residuals": (),
        "effectiveness_rows": (), "melt_reports": (), "leases_expired": (),
        "sentinel_denials": (), "monitor_findings": (), "governor_spend": {"TOTAL": 3},
        "host_kind": "SIMULATED", "simulated": True, "truncations": (),
    }
    payload.update(overrides)
    return ResponseRecordV1(**payload)


def _row(**overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "tx_id": "tx-1", "operator_id": "op.suspend_process", "outcome": "COMMITTED_VERIFIED",
        "postconditions": [{"kind": "PROCESS_STOPPED", "satisfied": True, "observed": "T"}],
        "rollback_attempted": False, "rollback_succeeded": False, "host_kind": "SIMULATED",
        "simulated": True, "epoch_id": 1, "target_digest": "sha256:" + "ab" * 32,
    }
    row.update(overrides)
    return row


def _resolution(**overrides: Any) -> CBFResolutionV1:
    payload: dict[str, Any] = {
        "resolution_id": "res.INC-1", "incident_id": "INC-1", "epoch_id": 0,
        "verdict": Verdict.MALICIOUS, "identifiability": "IDENTIFIED",
        "hypotheses": ({"mechanism_id": "credential_exfil.local", "support": 0.9,
                        "consequence": 1.0, "uncertainty": 0.1, "claim_ids": [],
                        "evidence_digests": ["sha256:" + "cd" * 32]},),
        "consequence_distribution": {"credential_exfil.local": 0.9}, "claim_graph": {},
        "evidence_lineage": (), "uncertainty": 0.1, "shadow": {}, "information_gaps": (),
        "truncations": (), "degradations": (),
    }
    payload.update(overrides)
    return CBFResolutionV1(**payload)


def _item(result: ScenarioResult, **overrides: Any) -> dict[str, Any]:
    step = EncodedStep.from_transition(result.transitions[0], actor_slot=0)
    item: dict[str, Any] = {"privacy_class": "PUBLIC_DERIVED", "steps": [step.to_dict()],
                            "evidence_refs": ["sha256:" + "ef" * 32]}
    item.update(overrides)
    return item


def _package(host: str = "host-a", *, key_id: str = "fleet-key-1", items: Any = None,
             key: bytes = KEY) -> KnowledgePackageV1:
    package = KnowledgePackageV1(
        package_id=f"pkg-{host}", source_host=host, key_id=key_id, created_sequence=1,
        items=tuple(items if items is not None else (_item(_run(ATTACK_EXFIL)),)),
        lineage_digests=("sha256:" + "01" * 32,), signature="",
        schema_version=KNOWLEDGE_PACKAGE_V1_VERSION,
    )
    return sign_package(package, key=key)


# --- D6.2: label blindness, round trips, content addressing ---------------------


def test_capsule_from_scenario_never_reads_the_scenario_label() -> None:
    result = _run(ATTACK_EXFIL, label=1)
    relabelled = dataclasses.replace(
        result, scenario=dataclasses.replace(result.scenario, label=0, name="other", technique=None)
    )
    assert result.scenario.label != relabelled.scenario.label
    left, right = _episode(result), _episode(relabelled)
    assert left.canonical_bytes() == right.canonical_bytes()
    assert left.capsule_id == right.capsule_id
    # Ground truth enters only as an explicit label, and then it DOES change the capsule.
    # (From a lab source: a sensor may not declare GROUND_TRUTH — review S6-AUTH-01.)
    lab = _episode(result, label=LabelAssertion(Verdict.MALICIOUS, LabelOrigin.GROUND_TRUTH,
                                                "lab", ""), label_origin=LabelOrigin.GROUND_TRUTH,
                   source_class=SourceClass.LAB_GROUND_TRUTH)
    assert lab.capsule_id != left.capsule_id
    assert lab.label is not None and lab.label.verdict is Verdict.MALICIOUS


def test_encoded_step_round_trips_to_the_stage2_encoding() -> None:
    result = _run(ATTACK_EXFIL + ATTACK_EXFIL)
    for index, transition in enumerate(result.transitions):
        step = EncodedStep.from_transition(transition, actor_slot=index % 2)
        original = encode_ssir_transition(transition, actor_slot=index % 2)
        rebuilt = step.to_encoded()
        assert rebuilt.features == tuple(round(v, 6) for v in original.features)
        restored = dataclasses.replace(
            rebuilt, features=original.features, evidence=original.evidence
        )
        assert restored == original, "only the two documented differences may remain"
        assert rebuilt.evidence == tuple(ref.digest for ref in transition.evidence)
        assert pattern_key(rebuilt) == pattern_key(original)
        assert step.meaning() == meaning_vector(rebuilt)
        wire = json.loads(json.dumps(step.to_dict()))
        assert EncodedStep.from_dict(wire) == step
        assert step.source_group == source_group_of(transition.actor.identity)
        assert transition.actor.identity not in json.dumps(step.to_dict())


def test_capsule_digest_is_stable_and_the_wire_form_round_trips() -> None:
    first, second = _episode(), _episode()
    assert first.digest() == second.digest() and first == second
    rebuilt = ExperienceCapsuleV1.from_dict(json.loads(first.canonical_bytes()))
    assert rebuilt == first and rebuilt.digest() == first.digest()
    assert first.capsule_id.startswith("cap-") and first.canonical_bytes().endswith(b"\n")
    assert _episode(sequence=2).capsule_id != first.capsule_id


def test_a_tampered_payload_is_refused_on_load() -> None:
    payload = json.loads(_episode().canonical_bytes())
    payload["visibility"] = 0.25
    with pytest.raises(ContractError, match="does not match its content"):
        ExperienceCapsuleV1.from_dict(payload)


@pytest.mark.parametrize(
    ("key", "value"),
    [("visibility", "1.0"), ("epoch_id", True), ("kind", "transition_episode"),
     ("truncated", "false"), ("contamination_flags", "TRUNCATED")],
)
def test_from_dict_is_strict_and_uncoerced(key: str, value: Any) -> None:
    payload = json.loads(_episode().canonical_bytes())
    payload[key] = value
    with pytest.raises(ContractError):
        ExperienceCapsuleV1.from_dict(payload)
    payload = json.loads(_episode().canonical_bytes())
    payload["extra"] = 1
    with pytest.raises(ContractError, match="extra"):
        ExperienceCapsuleV1.from_dict(payload)


# --- D6.2: bounds truncate loudly -------------------------------------------------


def test_step_cap_truncates_with_the_flag_raised() -> None:
    result = _run(ATTACK_EXFIL * 20)
    assert len(result.transitions) > MAX_STEPS_PER_CAPSULE
    capsule = _episode(result)
    assert len(capsule.steps) == MAX_STEPS_PER_CAPSULE
    assert capsule.truncated and ContaminationFlag.TRUNCATED in capsule.contamination_flags
    short = _episode(_run(ATTACK_EXFIL))
    assert not short.truncated and ContaminationFlag.TRUNCATED not in short.contamination_flags
    # Exactly at the step cap nothing is lost, although 64 step digests exceed the 32-ref
    # summary: every digest still rides on its step, so this is not truncation.
    full = _episode(_run(ATTACK_EXFIL * 16))
    assert len(full.steps) == MAX_STEPS_PER_CAPSULE and not full.truncated
    assert len(full.evidence_refs) == MAX_EVIDENCE_REFS_PER_CAPSULE
    assert {d for step in full.steps for d in step.evidence} >= set(full.evidence_refs)


def _with_evidence(result: ScenarioResult, per_step: int) -> ScenarioResult:
    transitions = tuple(
        dataclasses.replace(t, evidence=tuple(
            EvidenceRef(store="stage1", locator=f"ev/{i}/{j}",
                        digest=digest_of_bytes(f"{i}:{j}".encode()))
            for j in range(per_step)))
        for i, t in enumerate(result.transitions))
    return dataclasses.replace(result, transitions=transitions)


def test_byte_cap_drops_steps_and_raises_the_flag() -> None:
    result = _with_evidence(_run(ATTACK_EXFIL * 16), MAX_EVIDENCE_PER_STEP)
    capsule = _episode(result)
    assert len(capsule.canonical_bytes()) <= MAX_CAPSULE_BYTES
    assert len(capsule.steps) < MAX_STEPS_PER_CAPSULE, "the byte cap never engaged"
    assert capsule.truncated and ContaminationFlag.TRUNCATED in capsule.contamination_flags


def test_per_step_evidence_cut_is_flagged() -> None:
    capsule = _episode(_with_evidence(_run(ATTACK_EXFIL), MAX_EVIDENCE_PER_STEP + 2))
    assert all(len(step.evidence) == MAX_EVIDENCE_PER_STEP for step in capsule.steps)
    assert capsule.truncated and ContaminationFlag.TRUNCATED in capsule.contamination_flags


def test_truncation_can_never_be_silent_or_cleared() -> None:
    capsule = _episode(_run(ATTACK_EXFIL * 20))
    with pytest.raises(ContractError, match="never cleared"):
        reseal_capsule(capsule, contamination_flags=frozenset())
    with pytest.raises(ContractError, match="never silent"):
        reseal_capsule(capsule, truncated=False)
    flagged = reseal_capsule(capsule, contamination_flags=capsule.contamination_flags
                             | {ContaminationFlag.ATTACKER_CONTROLLED_SOURCE})
    assert ContaminationFlag.ATTACKER_CONTROLLED_SOURCE in flagged.contamination_flags
    assert flagged.capsule_id != capsule.capsule_id


def test_observation_gaps_and_replayed_evidence_are_flagged() -> None:
    result = _run(ATTACK_EXFIL)
    half = tuple(dataclasses.replace(t, observation_incomplete=i % 2 == 0)
                 for i, t in enumerate(result.transitions))
    capsule = _episode(dataclasses.replace(result, transitions=half))
    assert capsule.visibility == 0.5
    assert ContaminationFlag.OBSERVATION_INCOMPLETE in capsule.contamination_flags
    replayed = dataclasses.replace(result, transitions=result.transitions + result.transitions[:1])
    assert ContaminationFlag.DUPLICATE_EVIDENCE in _episode(replayed).contamination_flags
    assert ContaminationFlag.DUPLICATE_EVIDENCE not in _episode(result).contamination_flags


# --- D6.2: privacy ----------------------------------------------------------------


def test_secret_pattern_values_are_classified_and_audited() -> None:
    clean = _episode()
    assert clean.privacy_class is PrivacyClass.HOST_SENSITIVE
    leaked = _episode(source_id="dump.PASSWORD-file")
    assert leaked.privacy_class is PrivacyClass.SECRET_BEARING
    with pytest.raises(ContractError, match="not SECRET_BEARING"):
        reseal_capsule(leaked, privacy_class=PrivacyClass.HOST_SENSITIVE)
    report = privacy_audit([clean, leaked, clean])
    summary = (report.capsules, report.offenders, report.offenders_truncated)
    assert summary == (3, (leaked.capsule_id,), False)
    assert report.secret_pattern_hits >= 1
    assert report.free_text_values == 0, "a builder capsule must hold no path or prose"


def test_label_capsules_are_public_derived_and_carry_no_evidence() -> None:
    target = _episode()
    label = LabelAssertion(
        Verdict.MALICIOUS, LabelOrigin.ANALYST, "analyst.alice", target.capsule_id
    )
    capsule = capsule_from_label(label, epoch=_epoch(), sequence=3, provenance=_provenance(
        source_class=SourceClass.ANALYST, independence_group="analyst.alice",
        label_origin=LabelOrigin.ANALYST))
    assert capsule.kind is CapsuleKind.LABEL_ASSERTION and capsule.evidence_refs == ()
    assert capsule.privacy_class is PrivacyClass.PUBLIC_DERIVED
    with pytest.raises(ContractError, match="independence_group"):
        capsule_from_label(label, epoch=_epoch(), sequence=3, provenance=_provenance(
            source_class=SourceClass.ANALYST, independence_group="analyst.bob",
            label_origin=LabelOrigin.ANALYST))


def test_weak_sources_cannot_launder_a_strong_label() -> None:
    with pytest.raises(ContractError, match="weak evidence"):
        _provenance(source_class=SourceClass.TEACHER, label_origin=LabelOrigin.GROUND_TRUTH)
    with pytest.raises(ContractError, match="weak evidence"):
        _provenance(source_class=SourceClass.FOREIGN_HOST, label_origin=LabelOrigin.ANALYST)
    teacher_label = LabelAssertion(Verdict.BENIGN, LabelOrigin.TEACHER, "teacher.t1", "")
    with pytest.raises(ContractError, match="disagrees with provenance"):
        _episode(label=teacher_label, label_origin=LabelOrigin.GROUND_TRUTH,
                 source_class=SourceClass.LAB_GROUND_TRUTH)


# --- D6.2: Stage 4 / Stage 5 seams ------------------------------------------------


def test_simulated_response_record_is_flagged_forever() -> None:
    record = _record(receipts=(_row(),))
    assert ResponseRecordV1.from_dict(record.to_dict()).digest() == record.digest()
    capsule = capsule_from_response(record, epoch=_epoch(), provenance=_provenance(), sequence=4)
    assert capsule.kind is CapsuleKind.RESPONSE_OUTCOME
    assert ContaminationFlag.SIMULATED_RECORD in capsule.contamination_flags
    assert capsule.response_outcome == "COMMITTED_VERIFIED" and len(capsule.procedure_rows) == 1
    assert record.digest() in capsule.evidence_refs
    assert dict(capsule.confidence_components)["rows_screened_out"] == 0.0
    with pytest.raises(ContractError, match="never cleared"):
        reseal_capsule(capsule, contamination_flags=frozenset())
    payload = json.loads(capsule.canonical_bytes())
    payload["contamination_flags"] = []
    with pytest.raises(ContractError):
        ExperienceCapsuleV1.from_dict(payload)


def test_a_real_host_record_is_not_flagged_simulated() -> None:
    record = _record(host_kind="REAL", simulated=False,
                     receipts=(_row(host_kind="REAL", simulated=False),))
    capsule = capsule_from_response(record, epoch=_epoch(), provenance=_provenance(), sequence=4)
    assert ContaminationFlag.SIMULATED_RECORD not in capsule.contamination_flags


def test_a_record_stage5_would_not_export_cannot_become_a_capsule() -> None:
    record = _record(receipts=(_row(kill_switch="on"),))
    with pytest.raises(ContractError, match="authority"):
        capsule_from_response(record, epoch=_epoch(), provenance=_provenance(), sequence=4)


def test_refused_token_rows_trip_the_secret_screen_and_fail_closed() -> None:
    # A known false positive of the spec's pattern, pinned so nobody mistakes it for a leak.
    record = _record(receipts=(_row(outcome="REFUSED_TOKEN"),))
    capsule = capsule_from_response(record, epoch=_epoch(), provenance=_provenance(), sequence=4)
    assert capsule.privacy_class is PrivacyClass.SECRET_BEARING


def test_resolution_capsule_is_an_inference_label_about_one_episode() -> None:
    target = _episode()
    capsule = capsule_from_resolution(
        _resolution(), target_capsule_id=target.capsule_id, epoch=_epoch(), sequence=5,
        provenance=_provenance(source_class=SourceClass.DERIVED_INFERENCE,
                               label_origin=LabelOrigin.INFERENCE, independence_group="stage4.cbf"))
    assert capsule.label is not None and capsule.label.target_capsule_id == target.capsule_id
    assert capsule.label.origin is LabelOrigin.INFERENCE
    assert capsule.resolution_state is Verdict.MALICIOUS
    assert capsule.security_worlds == ("credential_exfil.local",)
    assert "sha256:" + "cd" * 32 in capsule.evidence_refs
    with pytest.raises(ContractError, match="disagrees with provenance"):
        capsule_from_resolution(_resolution(), target_capsule_id=target.capsule_id,
                                epoch=_epoch(), sequence=5, provenance=_provenance())
    with pytest.raises(ContractError, match="naming its target"):
        capsule_from_resolution(_resolution(), target_capsule_id="", epoch=_epoch(), sequence=5,
                                provenance=_provenance(label_origin=LabelOrigin.INFERENCE))


def test_dispatch_refuses_raw_telemetry_and_misplaced_arguments() -> None:
    result = _run(ATTACK_EXFIL)
    common: dict[str, Any] = {"epoch": _epoch(), "provenance": _provenance(), "sequence": 1}
    assert build_experience_capsule(result, **common) == _episode(result)
    raw = encode_ssir_transition(result.transitions[0])
    for source in (raw, result.transitions[0], {"relation": 1}):
        with pytest.raises(ContractError, match="no capsule builder"):
            build_experience_capsule(source, **common)  # type: ignore[arg-type]
    with pytest.raises(ContractError):
        build_experience_capsule(_record(receipts=(_row(),)), label=LabelAssertion(
            Verdict.BENIGN, LabelOrigin.ANALYST, "a", ""), **common)
    with pytest.raises(ContractError, match="no transitions"):
        capsule_from_scenario(dataclasses.replace(result, transitions=()), **common)


# --- D6.3: provenance scoring and the ledger ------------------------------------------


def test_trust_tables_cover_every_member_and_score_by_the_formula() -> None:
    assert set(SOURCE_CLASS_PRIOR) == set(SourceClass)
    assert set(LABEL_ORIGIN_WEIGHT) == set(LabelOrigin)
    assert set(FLAG_RISK) == set(ContaminationFlag)
    clean = score_provenance(_episode())
    assert clean.score == pytest.approx(0.9) and clean.contamination_risk == 0.0
    mild = reseal_capsule(_episode(), contamination_flags=frozenset(
        {ContaminationFlag.TRUNCATED, ContaminationFlag.SIMULATED_RECORD}), truncated=True)
    risk = score_provenance(mild).contamination_risk
    assert risk == pytest.approx(0.2), "risk is a max, not a sum"
    hostile = reseal_capsule(_episode(), contamination_flags=frozenset(
        {ContaminationFlag.ATTACKER_CONTROLLED_SOURCE}))
    scored = score_provenance(hostile)
    assert scored.score == 0.0 < MIN_PROVENANCE_SCORE and "below_min_provenance" in scored.reasons


def test_ledger_eviction_is_counted_and_forgets_lineage() -> None:
    ledger = ProvenanceLedger(capacity=3)
    capsules = [_episode(sequence=n) for n in range(5)]
    for capsule in capsules:
        ledger.record(capsule, score=score_provenance(capsule))
    assert len(ledger) == 3 and ledger.evicted() == 2 and ledger.stats().evicted == 2
    assert ledger.get(capsules[0].capsule_id) is None, "an evicted record must not answer"
    assert ledger.recent_evictions() == (capsules[0].capsule_id, capsules[1].capsule_id)
    asked = [c.capsule_id for c in capsules]
    assert ledger.missing(asked) == tuple(asked[:2])
    assert [r.capsule_id for r in ledger.records_for(asked)] == asked[2:]


def test_ledger_memory_plateaus_over_a_long_horizon() -> None:
    # Two bounded parts grow and stop: 32 records, then the 128-entry eviction log. After
    # both are full (n >= 32 + 128) the footprint must be flat however long the run.
    ledger = ProvenanceLedger(capacity=32)
    base = _episode()
    readings: dict[int, int] = {}
    for n in range(1200):
        capsule = reseal_capsule(base, created_sequence=n)
        ledger.record(capsule, score=score_provenance(capsule))
        if n in (31, 200, 600, 1199):
            readings[n] = ledger.memory_bytes()
    assert len(ledger) == 32 and ledger.evicted() == 1200 - 32
    assert len(ledger.recent_evictions()) == MAX_EVICTION_LOG
    plateau = [readings[200], readings[600], readings[1199]]
    assert max(plateau) - min(plateau) <= 256, readings
    assert readings[31] < readings[200], "the eviction log is part of the footprint"


def test_ledger_re_record_is_idempotent_and_a_conflicting_score_refused() -> None:
    ledger = ProvenanceLedger(capacity=4)
    capsule = _episode()
    first = ledger.record(capsule, score=score_provenance(capsule))
    assert ledger.record(capsule, score=score_provenance(capsule)) is first
    with pytest.raises(ContractError, match="different score"):
        ledger.record(capsule, score=ProvenanceScore(0.1, 0.0, ("forged",)))
    with pytest.raises(ValueError):
        ProvenanceLedger(capacity=0)


def test_dependence_counts_groups_not_capsules() -> None:
    ledger = ProvenanceLedger(capacity=512)
    base = _episode()
    records = [ledger.record(c, score=score_provenance(c)) for c in
               (reseal_capsule(base, created_sequence=n) for n in range(240))]
    report = detect_evidence_dependence(records, min_groups=3)
    assert report.observations == 240 and report.independent_groups == 1
    assert report.largest_group_share == 1.0 and report.dependent
    lineages = [_episode(_run(ATTACK_EXFIL, offset=n), sequence=900 + n) for n in range(3)]
    assert len({c.steps[0].source_group for c in lineages}) == 3
    spread = [ledger.record(c, score=score_provenance(c)) for c in lineages]
    assert not detect_evidence_dependence(spread, min_groups=3).dependent
    mixed = detect_evidence_dependence(records + spread, min_groups=3)
    assert mixed.independent_groups == 3 and mixed.groups[0][1] == 241
    assert detect_evidence_dependence([], min_groups=1).dependent
    with pytest.raises(ValueError):
        detect_evidence_dependence(records, min_groups=0)


def test_label_votes_count_the_asserting_group() -> None:
    ledger = ProvenanceLedger(capacity=64)
    targets = [_episode(sequence=n) for n in range(10)]
    prov = _provenance(source_class=SourceClass.ANALYST, independence_group="analyst.one",
                       label_origin=LabelOrigin.ANALYST)
    records = []
    for target in targets:
        label = LabelAssertion(
            Verdict.BENIGN, LabelOrigin.ANALYST, "analyst.one", target.capsule_id
        )
        capsule = capsule_from_label(label, epoch=_epoch(), provenance=prov, sequence=1)
        records.append(ledger.record(capsule, score=score_provenance(capsule)))
    report = detect_evidence_dependence(records, min_groups=2)
    assert (report.observations, report.independent_groups, report.dependent) == (10, 1, True)


# --- Rule A --------------------------------------------------------------------------


def test_capsule_id_is_the_same_string_everywhere() -> None:
    ledger = ProvenanceLedger()
    self_label = LabelAssertion(Verdict.MALICIOUS, LabelOrigin.GROUND_TRUTH, "lab", "")
    episode = _episode(label=self_label, source_class=SourceClass.LAB_GROUND_TRUTH,
                       label_origin=LabelOrigin.GROUND_TRUTH)
    record = ledger.record(episode, score=score_provenance(episode))
    assert record.capsule_id == episode.capsule_id == ledger.get(episode.capsule_id).capsule_id  # type: ignore[union-attr]
    assert episode.label is not None and episode.label.target_capsule_id == episode.capsule_id
    assert record.content_digest == episode.digest()
    external = LabelAssertion(
        Verdict.MALICIOUS, LabelOrigin.ANALYST, "analyst.a", episode.capsule_id
    )
    label_capsule = capsule_from_label(external, epoch=_epoch(), sequence=2, provenance=_provenance(
        source_class=SourceClass.ANALYST, independence_group="analyst.a",
        label_origin=LabelOrigin.ANALYST))
    assert label_capsule.label is not None
    assert label_capsule.label.target_capsule_id == episode.capsule_id
    rebuilt = ExperienceCapsuleV1.from_dict(json.loads(episode.canonical_bytes()))
    assert rebuilt.capsule_id == episode.capsule_id
    assert episode.context_id == context_id_for(_epoch().identity)


# --- D6.19: fleet import ---------------------------------------------------------------


def test_fleet_exchange_is_disabled_by_default() -> None:
    package = _package()
    verification = verify_package(package, keyring={"fleet-key-1": KEY})
    assert verification.valid, verification.reasons
    assert FLEET_EXCHANGE_ENABLED is False
    with pytest.raises(FleetDisabledError):
        package_to_capsules(package, verification=verification, epoch=_epoch(), sequence=1)


def test_verify_refuses_every_bad_package() -> None:
    keyring = {"fleet-key-1": KEY}
    good = _package()
    tampered = dataclasses.replace(good, source_host="host-evil")
    assert "bad_signature" in verify_package(tampered, keyring=keyring).reasons
    unsigned = dataclasses.replace(good, signature="")
    assert "unsigned" in verify_package(unsigned, keyring=keyring).reasons
    assert "unknown_key" in verify_package(good, keyring={"other": KEY}).reasons
    unversioned = sign_package(dataclasses.replace(good, schema_version=""), key=KEY)
    assert "unversioned" in verify_package(unversioned, keyring=keyring).reasons
    private = _package(items=[_item(_run(ATTACK_EXFIL), privacy_class="HOST_SENSITIVE")])
    assert "item[0]:not_public_derived" in verify_package(private, keyring=keyring).reasons
    secret = _package(items=[_item(_run(ATTACK_EXFIL), verdict="BENIGN", note="api_key=1")])
    assert not verify_package(secret, keyring=keyring).valid
    crowd = _package(items=[_item(_run(ATTACK_EXFIL))] * (MAX_PACKAGE_ITEMS + 1))
    assert "too_many_items" in verify_package(crowd, keyring=keyring).reasons
    long_steps = _item(_run(ATTACK_EXFIL))["steps"] * MAX_STEPS_PER_CAPSULE
    bulky = _package(items=[_item(_run(ATTACK_EXFIL), steps=long_steps)] * 2)
    assert len(bulky.canonical_bytes()) > MAX_PACKAGE_BYTES
    assert "oversize" in verify_package(bulky, keyring=keyring).reasons
    with pytest.raises(ContractError, match="bytes"):
        KnowledgePackageV1.from_bytes(bulky.canonical_bytes())
    assert KnowledgePackageV1.from_bytes(good.canonical_bytes()) == good


def test_hosts_sharing_a_key_are_one_vote_and_foreign_claims_are_rewritten() -> None:
    keyring = {"fleet-key-1": KEY}
    ledger = ProvenanceLedger()
    local = _epoch(epoch_id=7)
    records = []
    for index, host in enumerate(("host-a", "host-b", "host-c")):
        forged = _item(_run(ATTACK_EXFIL, offset=index), verdict="BENIGN")
        forged["steps"][0]["epoch_id"] = 90 + index  # a claimed foreign epoch
        package = _package(host, items=[forged])
        verification = verify_package(package, keyring=keyring)
        capsules = package_to_capsules(package, verification=verification, epoch=local,
                                       sequence=10, enabled=True)
        for capsule in capsules:
            assert capsule.kind is CapsuleKind.FOREIGN_PACKAGE
            assert ContaminationFlag.FOREIGN_ORIGIN in capsule.contamination_flags
            assert capsule.source_provenance.source_class is SourceClass.FOREIGN_HOST
            assert capsule.label is not None and capsule.label.origin is LabelOrigin.WEAK
            assert all(step.epoch_id == 7 for step in capsule.steps)
            records.append(ledger.record(capsule, score=score_provenance(capsule)))
    assert len({r.source_id for r in records}) == 3
    report = detect_evidence_dependence(records, min_groups=2)
    assert report.independent_groups == 1, "three Sybil hosts, one key, one vote"
    assert report.dependent
    assert {r.independence_group for r in records} == {"fleet:fleet-key-1"}


def test_a_verification_cannot_be_replayed_onto_another_package() -> None:
    keyring = {"fleet-key-1": KEY, "fleet-key-2": OTHER_KEY}
    first = _package("host-a")
    second = _package("host-b", key_id="fleet-key-2", key=OTHER_KEY)
    verification = verify_package(first, keyring=keyring)
    with pytest.raises(ContractError, match="different package"):
        package_to_capsules(second, verification=verification, epoch=_epoch(), sequence=1,
                            enabled=True)
    bad = verify_package(dataclasses.replace(first, signature="00"), keyring=keyring)
    with pytest.raises(ContractError, match="valid"):
        package_to_capsules(first, verification=bad, epoch=_epoch(), sequence=1, enabled=True)
    # S6-AUTH-09: a hand-built "valid" verification of an unsigned package is refused.
    unsigned = dataclasses.replace(first, signature="")
    forged = PackageVerification(valid=True, reasons=(), fleet_group=fleet_group_of(
        unsigned.key_id), package_digest=unsigned.digest())
    with pytest.raises(ContractError, match="not issued by verify_package"):
        package_to_capsules(unsigned, verification=forged, epoch=_epoch(), sequence=1,
                            enabled=True)
    with pytest.raises(ContractError):
        sign_package(first, key=b"short")


def test_repetition_from_one_independence_group_counts_once() -> None:
    """REPETITION_IS_NOT_TRUTH, as ``LEARNING_CONSTITUTION`` binds it.

    One source repeating itself 1, 8 or 240 times is still one vote, and never meets the
    independence quorum; three genuinely separate lineages do. The count of recurrences
    changes nothing but ``observations`` — repetition buys no weight.
    """
    from pocketsec.stage6.constitution.learning import MIN_INDEPENDENT_GROUPS

    ledger = ProvenanceLedger(capacity=512)
    base = _episode()
    for count, offset in ((1, 10_000), (8, 20_000), (240, 30_000)):
        records = [
            ledger.record(c, score=score_provenance(c))
            for c in (reseal_capsule(base, created_sequence=offset + n) for n in range(count))
        ]
        report = detect_evidence_dependence(records, min_groups=MIN_INDEPENDENT_GROUPS)
        assert report.observations == count
        assert report.independent_groups == 1 and report.dependent, count
    independent = [
        ledger.record(c, score=score_provenance(c))
        for c in (_episode(_run(ATTACK_EXFIL, offset=n), sequence=40_000 + n)
                  for n in range(MIN_INDEPENDENT_GROUPS))
    ]
    report = detect_evidence_dependence(independent, min_groups=MIN_INDEPENDENT_GROUPS)
    assert report.independent_groups == MIN_INDEPENDENT_GROUPS and not report.dependent
