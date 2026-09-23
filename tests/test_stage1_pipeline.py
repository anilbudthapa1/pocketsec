"""Stage 1 — end-to-end pipeline, cross-sensor equivalence, gate and slots."""

from __future__ import annotations

import json

import pytest

from pocketsec.stage0.contracts.model_slot import validate_slot
from pocketsec.stage0.contracts.threat_prediction_v1 import Verdict
from pocketsec.stage1.cli import main
from pocketsec.stage1.gate import Stage1GateContext, _stub_sequence
from pocketsec.stage1.gate import run_gate as run_stage1_gate
from pocketsec.stage1.guillotine.ablation import ABLATIONS, run_guillotine
from pocketsec.stage1.labs.adversarial import run_adversarial_suite
from pocketsec.stage1.labs.corpus import (
    ATTACK_EXFIL,
    BENIGN_PRIVILEGED,
    Behaviour,
    Scenario,
    build_corpus,
)
from pocketsec.stage1.pipeline import Stage1Pipeline
from pocketsec.stage1.slot import NoveltyStatisticalSlot, StateCalculusSlot
from pocketsec.stage1.state.potential import phi
from pocketsec.stage1.telemetry.raw_event_v1 import SensorPath

# --- compilation -------------------------------------------------------------


def test_escalation_chain_climbs_the_lattices() -> None:
    result = Stage1Pipeline().run_scenario(Scenario("attack", ATTACK_EXFIL, 1))
    state = result.final_state
    assert state.privilege >= 1
    assert state.credential >= 2
    assert state.reachability >= 3
    assert "exfiltration_triad" in phi(state).active_interactions


def test_benign_privileged_work_stays_low_potential() -> None:
    """An admin with root is not an incident. Φ must not be a privilege detector."""
    result = Stage1Pipeline().run_scenario(Scenario("admin", BENIGN_PRIVILEGED, 0))
    assert result.final_state.privilege >= 1
    assert result.peak_phi < 4.0
    assert phi(result.final_state).active_interactions == ()


def test_unrecognised_operation_is_not_invented() -> None:
    """Returning None beats fabricating a relation into the training data."""
    result = Stage1Pipeline().run_scenario(
        Scenario("weird", (Behaviour("quantum_entangle", {"path": "/x"}),), 0)
    )
    assert result.transitions == ()
    assert result.unresolved == 1


def test_every_transition_carries_evidence_lineage() -> None:
    result = Stage1Pipeline().run_scenario(Scenario("attack", ATTACK_EXFIL, 1))
    for transition in result.transitions:
        assert transition.evidence
        for ref in transition.evidence:
            assert ref.digest.startswith("sha256:")


def test_representation_level_escalates_with_consequence() -> None:
    result = Stage1Pipeline().run_scenario(Scenario("attack", ATTACK_EXFIL, 1))
    consequential = [t for t in result.transitions if t.is_high_consequence]
    assert consequential
    assert all(int(t.level) >= 2 for t in consequential)


# --- cross-sensor equivalence ------------------------------------------------


def test_two_sensor_paths_produce_identical_semantics() -> None:
    """Acceptance criterion 1, and the reason the compiler is the boundary."""
    scenarios = build_corpus(count=25, seed=7, split="eval")
    ebpf, auditd = Stage1Pipeline(), Stage1Pipeline()
    for index, scenario in enumerate(scenarios):
        a = ebpf.run_scenario(scenario, sensor=SensorPath.EBPF, offset=index)
        b = auditd.run_scenario(scenario, sensor=SensorPath.AUDITD, offset=index)
        assert a.semantic_keys == b.semantic_keys, f"divergence on {scenario.name}"


def test_sensor_paths_have_genuinely_different_record_shapes() -> None:
    """Guards the equivalence test: it must not be comparing identical inputs."""
    from pocketsec.stage1.labs.corpus import emit

    behaviour = Behaviour("read", {"path": "/etc/shadow"})
    ebpf = emit(behaviour, sensor=SensorPath.EBPF, index=0, host_id="h")
    auditd = emit(behaviour, sensor=SensorPath.AUDITD, index=0, host_id="h")
    assert len(ebpf) == 1
    assert len(auditd) == 2
    assert {r.record_type for r in ebpf} != {r.record_type for r in auditd}


# --- corpus integrity --------------------------------------------------------


def test_corpus_is_deterministic() -> None:
    assert build_corpus(count=30, seed=5, split="eval") == build_corpus(
        count=30, seed=5, split="eval"
    )


def test_train_split_is_benign_only() -> None:
    assert all(s.label == 0 for s in build_corpus(count=40, seed=1, split="train"))


def test_unseen_techniques_are_absent_from_training() -> None:
    """Leakage-resistant by construction (Stage 0 fair-comparison rule 1)."""
    train = build_corpus(count=60, seed=1, split="train")
    evaluation = build_corpus(count=60, seed=2, split="eval")
    train_ops = {b.operation for s in train for b in s.behaviours}
    unseen_ops = {
        b.operation for s in evaluation if s.unseen_technique for b in s.behaviours
    }
    assert unseen_ops - train_ops, "unseen techniques must introduce novel operations"


# --- guillotine --------------------------------------------------------------


def test_guillotine_produces_a_measured_frontier() -> None:
    ctx = Stage1GateContext.build()
    report = run_guillotine(ctx.guillotine_score, train=ctx.guillotine_fit)
    assert report.is_measured_frontier
    assert len(report.points) == len(ABLATIONS) + 1
    costs = [p.bytes_per_transition for p in report.points]
    assert costs == sorted(costs, reverse=True), "cumulative ablation must shed bytes"


def test_guillotine_knee_is_cheaper_than_the_full_representation() -> None:
    ctx = Stage1GateContext.build()
    report = run_guillotine(ctx.guillotine_score, train=ctx.guillotine_fit)
    assert report.knee is not None
    assert report.knee.bytes_per_transition <= report.baseline.bytes_per_transition


# --- adversarial -------------------------------------------------------------


def test_adversarial_suite_passes() -> None:
    report = run_adversarial_suite()
    failures = [f"{o.name}: {o.detail}" for o in report.failures]
    assert report.passed, "adversarial failures:\n" + "\n".join(failures)
    assert len(report.outcomes) == 8


# --- model slots -------------------------------------------------------------


def _slots():  # type: ignore[no-untyped-def]
    ctx = Stage1GateContext.build()
    keyed = {f"s1-{i:04d}": r for i, r in enumerate(ctx.results)}
    return keyed, StateCalculusSlot(results=keyed), NoveltyStatisticalSlot(results=keyed)


def test_both_slots_satisfy_the_stage0_boundary() -> None:
    _, calculus, statistical = _slots()
    validate_slot(calculus)
    validate_slot(statistical)


def test_slots_report_uncalibrated_confidence() -> None:
    keyed, calculus, _ = _slots()
    prediction = calculus.predict(_stub_sequence(next(iter(keyed))))
    assert not prediction.is_calibrated, "no calibration map exists; must not claim one"


def test_slot_carries_no_authority() -> None:
    from pocketsec.stage0.contracts.threat_prediction_v1 import FORBIDDEN_AUTHORITY_FIELDS

    keyed, calculus, _ = _slots()
    payload = calculus.predict(_stub_sequence(next(iter(keyed)))).to_dict()
    assert not any(
        banned in key.lower() for key in payload for banned in FORBIDDEN_AUTHORITY_FIELDS
    )


def test_unknown_sequence_makes_a_slot_abstain() -> None:
    _, calculus, statistical = _slots()
    for slot in (calculus, statistical):
        prediction = slot.predict(_stub_sequence("never-compiled"))
        assert prediction.abstained
        assert prediction.verdict is Verdict.INSUFFICIENT_EVIDENCE


def test_two_model_families_disagree_on_the_same_representation() -> None:
    """Acceptance criterion 13: SSIR is not tuned to one consumer."""
    keyed, calculus, statistical = _slots()
    verdicts = [
        (
            calculus.predict(_stub_sequence(sid)).verdict,
            statistical.predict(_stub_sequence(sid)).verdict,
        )
        for sid in keyed
    ]
    assert any(a != b for a, b in verdicts)
    assert any(a == b for a, b in verdicts)


def test_novelty_slot_fires_on_novel_benign_work() -> None:
    """Expected, and a result rather than a bug: rare is not malicious.

    This is the control that justifies the state calculus existing at all.
    """
    keyed, _, statistical = _slots()
    benign_ids = [sid for sid, r in keyed.items() if r.scenario.label == 0]
    fired = [
        sid
        for sid in benign_ids
        if statistical.predict(_stub_sequence(sid)).verdict is Verdict.SUSPICIOUS
    ]
    assert fired, "a pure-novelty detector should produce false positives here"


# --- gate and CLI ------------------------------------------------------------


def test_stage1_acceptance_gate_passes() -> None:
    report = run_stage1_gate()
    failures = [f"{c.id}: {c.detail}" for c in report.failures]
    assert report.passed, "Stage 1 gate failures:\n" + "\n".join(failures)
    assert len(report.checks) == 13


def test_gate_cli_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["gate"]) == 0
    assert "GATE: PASSED" in capsys.readouterr().out


def test_adversarial_cli_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["adversarial"]) == 0
    assert "SUITE: PASSED" in capsys.readouterr().out


def test_guillotine_cli_emits_json(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--json", "guillotine"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["is_measured_frontier"] is True
    assert payload["held_out"] is True


def test_replay_cli_reports_bounded_memory(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--json", "replay"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["transitions"] > 0
    assert payload["pipeline"]["novelty_memory_bytes"] < 2_000_000


def test_calibrate_cli_reports_composition_gain(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--json", "calibrate"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert "composition_gain" in payload


def test_guillotine_reports_its_own_degeneracy() -> None:
    """A frontier where every cut is free is a statement about the data.

    The report must say so itself. Presenting a degenerate knee as a
    field-selection result would be exactly the "optimise for byte count at the
    expense of unmeasured security loss" the Stage 1 non-goals forbid.
    """
    ctx = Stage1GateContext.build()

    # Fitted and scored on the same split: the more serious problem, so it
    # takes precedence in the caveat.
    optimistic = run_guillotine(ctx.results)
    assert not optimistic.held_out
    assert "OPTIMISTIC" in optimistic.caveat

    # Held out, so degeneracy is the thing left to report.
    held_out = run_guillotine(ctx.guillotine_score, train=ctx.guillotine_fit)
    assert held_out.held_out
    assert held_out.caveat
    if held_out.degenerate:
        assert "must NOT be used" in held_out.caveat
        assert held_out.informative_cuts <= 1


def test_guillotine_detects_an_informative_frontier() -> None:
    """The degeneracy detector must not simply always fire."""
    ctx = Stage1GateContext.build()
    report = run_guillotine(ctx.guillotine_score, train=ctx.guillotine_fit)
    # Removing the last family always costs retention on this corpus, so at
    # least one informative cut must be detected.
    assert report.informative_cuts >= 1
