"""The Stage 4 gate's own tests: the checks that keep the checks honest.

A gate is the one module entitled to say how a stage did, so the ways it can lie matter
more than the ways it can break. Four of them are pinned here.

1. **A criterion that cannot fail is not a criterion.** Every check must be able to come
   out the other way. Where a check currently passes, something is constructed that makes
   it fail; where it currently fails, the number that decided it is asserted.
2. **A refusal-checker must catch its own fixtures.** The seven laundering attempts and the
   five novelty controls are committed, not described.
3. **A gate must not mutate the experiment ledger.** Stage 3's gate appended a ``PS-S3-*``
   row every time the suite ran, so merely running the tests grew the permanent
   append-only record (spec §2.7). This file asserts the real ledger is byte-identical
   across a gate run, and every registry it constructs itself lives under ``tmp_path``.
4. **A gate must not silently pass on half a criterion.** G4.1's telemetry-source clause is
   unmeasurable here, and the check must FAIL rather than report the measurable half as a
   pass.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pocketsec.stage0.contracts.threat_prediction_v1 import NON_COMMITTAL_VERDICTS, Verdict
from pocketsec.stage0.gate import GateCheck, GateReport, REPO_ROOT
from pocketsec.stage4 import gate_criteria as criteria
from pocketsec.stage4 import gate_probes as probes
from pocketsec.stage4.gate import (
    EXPERIMENT_ID,
    STAGE4_HYPOTHESIS,
    STAGE4_SECONDARY,
    Stage4GateContext,
    run_gate,
)

#: The twelve ids, fixed by integration plan §5.1. Not eleven, not thirteen.
EXPECTED_IDS = tuple(f"G4.{index}" for index in range(1, 13))


@pytest.fixture(scope="module")
def report() -> GateReport:
    """ONE gate run for the whole module. It is by far the expensive thing here.

    Module-scoped deliberately: a full run replays a 60-case corpus twice, drives the
    engine over both arms, fits a visibility model on two splits, runs nine baselines and
    a nine-row ablation, and floods 40 more cases. Re-running it per test would make this
    file the slowest in the suite and would compare figures taken at different moments of
    a contended host against each other (spec §2.8).
    """
    return run_gate()


@pytest.fixture(scope="module")
def ctx() -> Stage4GateContext:
    """One shared context, for the tests that need the walk rather than the report."""
    return Stage4GateContext.build()


@pytest.fixture(scope="module")
def small_split() -> criteria.VisibilitySplit:
    """A visibility model over eight cases, for tests that only need *a* model.

    Eight rather than sixty because these tests assert structure — that ten hooks exist
    and compute, that a fault lands mid-incident — and none of them is a measurement of
    the corpus. A test that pays for sixty cases to check a dictionary's keys is how a
    suite stops being run.
    """
    return criteria.measure_visibility_split(criteria.corpus()[:8])


# --- shape -------------------------------------------------------------------


def test_the_gate_reports_exactly_twelve_criteria(report: GateReport) -> None:
    assert tuple(check.id for check in report.checks) == EXPECTED_IDS
    assert all(isinstance(check, GateCheck) for check in report.checks)


def test_every_check_names_the_number_that_decided_it(report: GateReport) -> None:
    """A detail string with no figure in it is a verdict without evidence."""
    for check in report.checks:
        assert check.detail, check.id
        assert any(character.isdigit() for character in check.detail), check.id
        assert len(check.detail) > 80, f"{check.id} detail is too thin to audit"  # noqa: PLR2004


def test_the_gate_reports_failed_and_says_which(report: GateReport) -> None:
    """The expected outcome. A passing Stage 4 gate today would mean a check was weakened.

    Pinned as an inequality rather than an exact count: a later wave that genuinely fixes
    the belief-update defect should turn checks green without editing this test, but it
    must never be able to turn them all green by accident.
    """
    assert not report.passed
    assert report.failures
    failing = {check.id for check in report.failures}
    # The two the spec declares unmeasurable on synthetic data (§6.1). If either of these
    # ever passes, the criterion was restated rather than met.
    assert "G4.1" in failing
    assert "G4.10" in failing


def test_the_four_construction_criteria_are_the_ones_that_can_be_settled(
    report: GateReport,
) -> None:
    """Spec §6.1 names G4.7, G4.8, G4.9 and G4.11 as free of the authorship confound.

    Two of the four pass, and this test pins *why* the other two do not rather than
    excusing them. G4.9: every bound it exists to enforce holds — now including one
    long incident and the world bound actually hit — and it fails on the separate clause
    about the ground-truth world surviving the flood. G4.7: its behavioural half used to
    pass on the per-world "causal spine" DER, which was world attribution under an
    authoritative type (S4-FC-02); with that removed the engine emits no DER, and the
    requirement was deliberately NOT relaxed to keep the check green.
    """
    by_id = {check.id: check for check in report.checks}
    assert by_id["G4.8"].passed
    assert by_id["G4.11"].passed
    assert not by_id["G4.7"].passed
    assert "DER IS NOT EXERCISED ON REAL OUTPUT" in by_id["G4.7"].detail
    assert "S4-FC-02" in by_id["G4.7"].detail
    assert not by_id["G4.9"].passed
    assert "All within bound: True" in by_id["G4.9"].detail
    assert "Long-incident arm passed: True" in by_id["G4.9"].detail
    assert "world-kind Truncation records" in by_id["G4.9"].detail
    assert "survived the short flood on 0/" in by_id["G4.9"].detail


# --- G4.1 must not pass on half a criterion ---------------------------------


def test_g4_1_fails_even_though_its_simulator_half_is_met(report: GateReport) -> None:
    check = next(c for c in report.checks if c.id == "G4.1")
    assert not check.passed
    assert "simulator half met: True" in check.detail
    assert "UNMEASURED" in check.detail
    assert "paired eBPF/auditd collection on a real host" in check.detail


def test_the_visibility_evidence_carries_its_own_provenance(
    small_split: criteria.VisibilitySplit, tmp_path: Path
) -> None:
    """ADR-0127: a gate may not quote evidence it did not produce."""
    split = small_split
    target = tmp_path / "stage4-visibility.json"
    criteria.write_visibility_evidence(split, path=target)
    assert criteria.visibility_evidence_matches(split, path=target)

    stored = json.loads(target.read_text(encoding="utf-8"))
    assert stored["telemetry_source_clause"] == "UNMEASURED"
    # A stale artefact from a different split must be refused, not read.
    stored["provenance"]["seed"] = stored["provenance"]["seed"] + 1
    target.write_text(json.dumps(stored), encoding="utf-8")
    assert not criteria.visibility_evidence_matches(split, path=target)


# --- the refusal fixtures ----------------------------------------------------


def test_all_seven_laundering_attempts_are_refused() -> None:
    """Spec §D4.13 (a)-(g). All seven must raise; the list is committed, not described."""
    accepted = {
        name: why
        for name, probe in probes.laundering_probes()
        if (why := probes.refused(probe)) is not None
    }
    assert not accepted, f"laundering attempts that were not refused: {accepted}"
    assert len(probes.laundering_probes()) == 7  # noqa: PLR2004


#: One fabricated unbacked claim per novelty word. These are the positive controls the
#: findings document points at: the checker is narrower than a grep, and a narrowing that
#: cannot catch a real claim is a hole rather than a refinement.
NOVELTY_CONTROLS = (
    ("novel", "This is a novel mechanism for holding competing security worlds."),
    ("first", "PocketSec is the first system to hold competing security worlds."),
    ("unprecedented", "The bound is unprecedented for endpoint cognition."),
    ("breakthrough", "The typed claim graph is a breakthrough in evidence conservation."),
    ("patent", "A patent application covers the world lifecycle."),
)


@pytest.mark.parametrize(("word", "line"), NOVELTY_CONTROLS)
def test_a_fabricated_novelty_claim_is_caught(word: str, line: str) -> None:
    assert criteria.claims_novelty(line, word), f"{word!r} claim slipped past the checker"


#: Prose that names a novelty word without claiming anything. A checker that flagged these
#: would be switched off, and then nothing would check the claims that matter (Stage 3's
#: own finding on the same check).
NOVELTY_NON_CLAIMS = (
    ("novel", "No novel mechanism is claimed in this document."),
    ("novel", "All novelty claims remain provisional until prior-art review."),
    ("first", "It is the recommended first work of any follow-on wave."),
    ("first", "Printed by the first gate run of this session."),
    ("patent", "No patent position is asserted anywhere in this document."),
)


@pytest.mark.parametrize(("word", "line"), NOVELTY_NON_CLAIMS)
def test_naming_a_novelty_word_is_not_claiming_novelty(word: str, line: str) -> None:
    assert not criteria.claims_novelty(line, word), f"{line!r} was wrongly flagged"


def test_the_findings_document_makes_no_unbacked_novelty_claim() -> None:
    """Both ledger entries are NOT_REVIEWED, so any claim at all would be unbacked."""
    findings = REPO_ROOT / "docs" / "stage-4-findings.md"
    assert findings.is_file()
    text = findings.read_text(encoding="utf-8")
    flagged = [word for word in criteria.NOVELTY_WORDS if criteria.claims_novelty(text, word)]
    assert not flagged, f"unbacked novelty claims in the findings document: {flagged}"
    missing = [head for head in criteria.LEDGER_HEADINGS if head not in text]
    assert not missing, f"missing honesty-ledger headings: {missing}"


# --- the ledger must not move ------------------------------------------------


def test_running_the_gate_leaves_the_real_experiment_ledger_byte_identical(
    report: GateReport,
) -> None:
    """The defect this test exists for is Stage 3's, reproduced and documented (spec §2.7).

    ``pocketsec/stage3/gate.py`` appended a ``PS-S3-*`` row on every run, so the permanent
    append-only ledger grew as a side effect of running the test suite. Stage 4's gate
    reads the digest and never writes; ``pocketsec-stage4 register`` is the only writer.

    Asserted against the ``report`` fixture's run rather than by calling ``run_gate()``
    again: the gate itself captures the ledger digest before its first check and G4.12
    compares it after the last, so the fixture's own run already carries the before/after
    pair. A second run here would double the slowest test file in the suite to assert the
    same thing.
    """
    ledger = REPO_ROOT / "experiments" / "registry.jsonl"
    check = next(c for c in report.checks if c.id == "G4.12")
    assert "byte-identical before and after this gate run: True" in check.detail
    # And the file on disk still matches the digest the gate recorded, so the assertion
    # above is about this process rather than about a string the check composed.
    assert criteria.registry_digest(ledger) is not None
    assert str(criteria.registry_digest(ledger)) in check.detail


def test_a_test_that_needs_a_registry_builds_its_own_under_tmp_path(tmp_path: Path) -> None:
    """The rule, made executable: a registry a test writes to lives under ``tmp_path``."""
    from pocketsec.stage0.experiments.registry import ExperimentRegistry

    path = tmp_path / "registry.jsonl"
    registry = ExperimentRegistry(path)
    registry.register(
        experiment_id="PS-S4-20260925-H3-cbf-test-0001",
        hypothesis=STAGE4_HYPOTHESIS,
        title="a test's own registry",
        slot_name="stage4-cbf-lucid",
        dataset_name="stage4-incident-corpus",
        dataset_version="test",
        dataset_sha256="sha256:" + "0" * 64,
        git_commit=None,
        seeds={"corpus": criteria.CORPUS_SEED},
        synthetic_data=True,
    )
    assert path.is_file()
    assert criteria.registry_digest(path) is not None
    assert path.parent == tmp_path


def test_the_gate_reads_a_missing_ledger_as_none_rather_than_empty(tmp_path: Path) -> None:
    """``None`` is not a digest of nothing (ADR-0004)."""
    assert criteria.registry_digest(tmp_path / "absent.jsonl") is None


# --- the isolation property, which is the precondition for everything else ---


def test_g4_11_injected_faults_into_the_real_engine_not_stand_ins(
    report: GateReport,
) -> None:
    """S4-FC-01: the check used to fault only the integrator hooks, never ``LucidEngine``."""
    check = next(c for c in report.checks if c.id == "G4.11")
    assert check.passed
    assert "ENGINE ARM — the real LucidEngine" in check.detail
    assert "engine-arm escapes = 0" in check.detail
    assert "fault points that never fired (an arm that injects nothing proves nothing): none" in (
        check.detail
    )


def test_the_ten_real_hooks_cover_every_subsystem_and_actually_compute(
    small_split: criteria.VisibilitySplit,
) -> None:
    """A hook that returned a constant would make the fault injection prove nothing."""
    from pocketsec.stage4.engine.degradation import Subsystem

    hooks = probes.real_subsystem_hooks(small_split.model)
    assert set(hooks) == set(Subsystem)

    from pocketsec.stage1.pipeline import Stage1Pipeline
    from pocketsec.stage4.engine.integrator import integrate_evidence

    pipeline = Stage1Pipeline()
    case = criteria.corpus()[0]
    result = pipeline.run_scenario(case.scenario, sensor=criteria.DROPPED_SENSOR, offset=0)
    evidence = integrate_evidence(
        result, memory=pipeline.causal, incident_id="hooks-0000", sensor=criteria.DROPPED_SENSOR
    )
    transition = evidence.transitions[len(evidence.transitions) // 2]
    for subsystem, hook in hooks.items():
        assert hook(evidence, transition) is not None, subsystem


def test_an_injected_fault_fires_mid_incident_and_nowhere_else(
    small_split: criteria.VisibilitySplit,
) -> None:
    """A subsystem that fails on its first call never held any state.

    The property G4.11 is about is that live Stage 1 state sitting next to a half-built
    Stage 4 reasoning state survives, so the fault has to land in the middle.
    """
    from pocketsec.stage1.pipeline import Stage1Pipeline
    from pocketsec.stage4.engine.degradation import Subsystem
    from pocketsec.stage4.engine.integrator import integrate_evidence

    hooks = probes.real_subsystem_hooks(small_split.model)
    faulted = probes.with_fault(hooks, Subsystem.CLAIM_COMPILER)

    pipeline = Stage1Pipeline()
    case = criteria.corpus()[0]
    result = pipeline.run_scenario(case.scenario, sensor=criteria.DROPPED_SENSOR, offset=0)
    evidence = integrate_evidence(
        result, memory=pipeline.causal, incident_id="fault-0000", sensor=criteria.DROPPED_SENSOR
    )
    raised_at: list[int] = []
    for transition in evidence.transitions:
        try:
            faulted[Subsystem.CLAIM_COMPILER](evidence, transition)
        except RuntimeError:
            raised_at.append(transition.sequence)
    assert raised_at == [evidence.middle_sequence]
    assert evidence.middle_sequence > 0


# --- the two recall readings must both be reported --------------------------


def test_world_set_recall_reports_every_reading_because_they_disagree(
    report: GateReport,
) -> None:
    """The spec's reading and ``labs/baselines.py``'s reading differ by a large factor.

    A gate quoting only the coverage reading would report Stage 4 as nearly meeting G4.2.
    Both are in the detail string, and the criterion is scored on the spec's.
    """
    check = next(c for c in report.checks if c.id == "G4.2")
    assert not check.passed
    assert "by mechanism_id" in check.detail
    assert "by observational equivalence" in check.detail
    assert "signal coverage" in check.detail
    assert "NOT used" in check.detail


def test_the_coverage_reading_is_saturated_by_a_do_nothing_control() -> None:
    """Why G4.2 may not be scored on signal coverage, as a measurement rather than a claim.

    ``B3_AlwaysOnRichTelemetry`` collects everything and reasons about nothing. If it
    reaches 1.0 on a metric, that metric is measuring the metric.
    """
    from pocketsec.stage4.labs.baselines import run_baselines

    corpus = criteria.corpus()[:12]
    split = criteria.measure_visibility_split(corpus)
    outcomes = {
        outcome.baseline_id: outcome
        for outcome in run_baselines(corpus, seed=criteria.CORPUS_SEED, model=split.model)
    }
    assert outcomes["B3_AlwaysOnRichTelemetry"].world_set_recall == 1.0


def test_the_strict_reading_is_the_max_of_the_two_spec_clauses() -> None:
    """Named explicitly so nobody later reads ``strict`` as a third definition."""
    reading = criteria.RecallReading(
        cases=10,
        by_mechanism_id=0.2,
        by_equivalence=0.4,
        by_signal_coverage=0.9,
        premature_collapses=1,
    )
    assert reading.strict == 0.4  # noqa: PLR2004
    assert reading.premature_collapse_rate == 0.1  # noqa: PLR2004


# --- the vacuity guards, which are what stop a pass being worthless ---------


def test_g4_8_would_fail_if_the_engine_emitted_no_authoritative_claims(
    report: GateReport,
) -> None:
    """Zero unsupported claims over zero claims is not a result."""
    check = next(c for c in report.checks if c.id == "G4.8")
    assert check.passed
    assert "vacuous=False" not in check.detail or "vacuous" in check.detail
    # The count of authoritative claims is in the detail and must be non-zero.
    assert "covering 0 authoritative claims" not in check.detail


def test_g4_4_reports_its_own_inequality_as_vacuous(report: GateReport) -> None:
    """F4 holds. The check says why that is not reassuring, instead of banking it."""
    check = next(c for c in report.checks if c.id == "G4.4")
    assert not check.passed
    assert "0 confidence violations" in check.detail
    assert "0.0 <= 0.0" in check.detail
    assert "cannot fail" in check.detail
    # S4-REV-07: the stated cause was the frozen support vector, which is not an input
    # to confidence at all. The corrected detail must say a moving support alone would
    # leave the check vacuous, and must not offer it as the remedy.
    assert "a moving support vector alone would leave it vacuous" in check.detail
    assert "what would make it fail is a support vector that moves" not in check.detail


def test_g4_5_says_whether_the_planner_asked_for_anything(report: GateReport) -> None:
    """A sensing win with zero requests issued would be a win over nothing."""
    check = next(c for c in report.checks if c.id == "G4.5")
    assert not check.passed
    assert "ObservationRequests across" in check.detail
    assert "threshold was NOT lowered" in check.detail
    # S4-FC-07: neither side of the ratio measures telemetry, so it is not reported as
    # a measurement.
    assert check.detail.startswith("UNMEASURED")
    assert "real within-run measurements" not in check.detail


def test_g4_10_runs_the_saturation_guard_before_recording_a_comparison(
    report: GateReport,
) -> None:
    check = next(c for c in report.checks if c.id == "G4.10")
    assert not check.passed
    assert "saturation_check FIRST" in check.detail
    assert "NO COMPARISON IS RECORDED" in check.detail
    assert "REFUSED, not reported" in check.detail


# --- the shared context is shared -------------------------------------------


def test_the_context_drives_one_engine_walk_not_twelve(ctx: Stage4GateContext) -> None:
    """Twelve separate walks would compare twelve moments of a contended host (spec §2.8)."""
    assert len(ctx.runs) == len(ctx.cases) == criteria.CORPUS_COUNT
    assert len(ctx.dropped_runs) == len(ctx.cases)
    assert ctx.work_units > 0
    assert ctx.loadavg[0] >= 0.0
    # Every run carries a real export, so G4.8 walks exported records rather than drafts.
    assert all(run.export.resolution_id for run in ctx.runs)


def test_the_hypothesis_binding_is_an_existing_one() -> None:
    """Spec §2.9: no H10 is minted, because that would edit a Stage 0 file."""
    from pocketsec.stage0.hypotheses import HYPOTHESES

    assert STAGE4_HYPOTHESIS in HYPOTHESES
    assert STAGE4_SECONDARY in HYPOTHESES
    assert STAGE4_HYPOTHESIS in EXPERIMENT_ID


def test_the_verdict_under_a_crash_is_never_benign() -> None:
    """The one verdict a degraded Stage 4 may never produce."""
    from pocketsec.stage4.engine.degradation import DEGRADED_VERDICT

    assert DEGRADED_VERDICT in NON_COMMITTAL_VERDICTS
    assert DEGRADED_VERDICT is not Verdict.BENIGN
