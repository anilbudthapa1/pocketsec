"""G4.11 — Stage 4 remains optional to core Stage 1–3 detection if it crashes.

This file is written **before** the cognition it protects, because an isolation
property that arrives last has never held. Packages 3–8 of the Stage 4 wave do not
start until it passes: if Stage 4 cannot crash safely, nothing else about it
matters.

The shape of the experiment:

1. Run the Stage 1 pipeline over the ambiguous corpus with **no Stage 4 present**
   and digest the `ScenarioResult`s, the pipeline's own end state, and the
   Stage 2 detection scores derived from them.
2. Attach Stage 4 *between scenarios on the same pipeline and the same
   `CausalMemory`*, and for each of the ten `Subsystem` values raise
   `RuntimeError`, `MemoryError` and `RecursionError` at that subsystem's entry
   point, **mid-incident** — at the transition half way through the sequence, not
   at the first one, so the fault lands after state has been built.
3. Assert for all thirty combinations: every digest is unchanged, no exception
   escaped, exactly one `DegradationRecord` *per incident* was written — the
   fallback replaces the subsystem for the rest of that incident rather than
   retrying it every transition — naming the right `Subsystem` and the right
   `FALLBACKS` string, and the Stage 4 verdict is non-committal and **never**
   `BENIGN`.
4. Assert by AST that no module under `pocketsec/stage1/` or `pocketsec/stage2/`
   imports `pocketsec.stage4` (trust rule T7), and that this package imports no
   `pocketsec.stage3` (§2.5).

Each test is named after the invariant it protects, so weakening one means
deleting a test whose name says what was given up.

Two honest limits of this file, stated rather than implied:

* **The fault is injected at the attachment seam**, `run_attached_cognition`'s
  hook mapping, because that is the only entry point the ten subsystems have
  until packages 3–8 land. When a real subsystem exists, its hook is the thing
  that gets monkeypatched and these tests do not change shape.
* **Stage 3's `CrystalSlot` is not in the detection loop.** `pocketsec/stage3/`
  was being edited in this working tree while this file was written, and wiring a
  crash-isolation gate to another wave's work in progress would make the property
  flaky for reasons that have nothing to do with Stage 4. Stage 3 participates
  here through the artefact it actually hands over — the crystal handoff JSON —
  which is the documented seam (§2.5). The Stage 2 half runs the real encoder,
  window store and Φ-oracle scorer, and it is a deterministic function of the
  Stage 1 transitions, so it is a *stronger* form of the digest check rather than
  an independent second opinion. It is not a detection result: the operating
  point below is an arbitrary constant chosen so the verdicts vary.
"""

from __future__ import annotations

import ast
import json
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path

import pytest

from pocketsec.stage0.contracts.common import ContractError, digest_of_bytes
from pocketsec.stage0.contracts.model_slot import validate_slot
from pocketsec.stage0.contracts.security_event_v1 import (
    SecurityEventSequenceV1,
    SecurityEventV1,
)
from pocketsec.stage0.contracts.threat_prediction_v1 import (
    FORBIDDEN_AUTHORITY_FIELDS,
    NON_COMMITTAL_VERDICTS,
    Verdict,
)
from pocketsec.stage0.gate import REPO_ROOT
from pocketsec.stage1.labs.ambiguous_corpus import build_ambiguous_corpus
from pocketsec.stage1.pipeline import ScenarioResult, Stage1Pipeline
from pocketsec.stage1.ssir.transition import SSIRTransitionV1
from pocketsec.stage1.telemetry.raw_event_v1 import SensorPath
from pocketsec.stage2.compile_candidates.phi_oracle_candidate import PHI_ORACLE_SCORER
from pocketsec.stage2.gate_criteria import imported_modules
from pocketsec.stage2.state.window import WindowStore
from pocketsec.stage4.crystal.handoff import (
    CRYSTAL_HANDOFF_V1_ID,
    EMPTY_KNOWLEDGE,
    MAX_HANDOFF_BYTES,
    CrystalKnowledge,
    load_or_empty,
    read_crystal_knowledge,
)
from pocketsec.stage4.engine.degradation import (
    DEGRADED_VERDICT,
    FALLBACKS,
    MAX_DEGRADATION_MESSAGE,
    DegradationLedger,
    DegradationRecord,
    Subsystem,
    downgrade_verdict,
    guarded,
    record_for,
)
from pocketsec.stage4.engine.integrator import (
    MAX_TRANSITIONS_PER_INCIDENT,
    AttachmentOutcome,
    IncidentEvidence,
    SubsystemHook,
    integrate_evidence,
    run_attached_cognition,
)
from pocketsec.stage4.slot import (
    CBFSlot,
    EngineOutcome,
    IncidentEngine,
    NullIncidentEngine,
)
from pocketsec.stage4.worlds.world import authority_named_fields

CORPUS_COUNT = 4
CORPUS_SEED = 11

#: ``MemoryError`` and ``RecursionError`` are not decoration: §45's first rule is
#: about OOM pressure, and neither is caught by ``except Exception``.
INJECTED_EXCEPTIONS: tuple[type[BaseException], ...] = (
    RuntimeError,
    MemoryError,
    RecursionError,
)

INJECTIONS = tuple(
    (subsystem, exception.__name__)
    for subsystem in Subsystem
    for exception in INJECTED_EXCEPTIONS
)

#: An arbitrary operating point, so the Stage 2 verdicts below are not all one
#: value. NOT a detection threshold: Stage 0's harness derives operating points
#: from an FP budget, and nothing here measures detection quality.
DETECTION_OPERATING_POINT = 0.25

#: The four modules this work package owns. The whole-package boundary test is
#: ``tests/test_stage4_boundary.py`` (owned by `foundation`); these are the files
#: this file is allowed to be responsible for.
OWNED_MODULES = (
    Path("pocketsec/stage4/engine/degradation.py"),
    Path("pocketsec/stage4/engine/integrator.py"),
    Path("pocketsec/stage4/crystal/handoff.py"),
    Path("pocketsec/stage4/slot.py"),
)

OWNED_DATACLASSES = (
    DegradationRecord,
    IncidentEvidence,
    AttachmentOutcome,
    CrystalKnowledge,
    EngineOutcome,
    CBFSlot,
)


# --------------------------------------------------------------------------- #
# The harness
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class RunOutput:
    """One replay of the corpus, with or without Stage 4 attached."""

    stage1_digest: str
    stage2_digest: str
    pipeline_digest: str
    stage2_verdicts: tuple[str, ...]
    outcomes: tuple[AttachmentOutcome, ...]
    records: tuple[DegradationRecord, ...]
    #: Non-``None`` when an exception escaped Stage 4 into the caller. Any value
    #: here is a G4.11 failure.
    escaped: str | None


def _stage1_digest(results: tuple[ScenarioResult, ...]) -> str:
    """Digest the Stage 1 output at transition granularity, not just the summary.

    ``to_dict()`` alone would hide a changed signature behind identical counts, so
    the causal signatures, the state-delta bitmasks and ΔΦ go in too.
    """
    payload = [
        {
            "result": result.to_dict(),
            "semantic_keys": [repr(key) for key in result.semantic_keys],
            "signatures": [item.causal_signature for item in result.transitions],
            "parents": [item.parent_signature for item in result.transitions],
            "masks": [item.state_delta.bitmask() for item in result.transitions],
            "delta_phi": [round(item.delta_phi, 9) for item in result.transitions],
            "uncertainty": [round(item.uncertainty, 9) for item in result.transitions],
        }
        for result in results
    ]
    return digest_of_bytes(json.dumps(payload, sort_keys=True, default=repr).encode("utf-8"))


def _stage2_scores(results: tuple[ScenarioResult, ...]) -> tuple[float, ...]:
    """The real Stage 2 path: window store + the zero-parameter Φ-oracle scorer."""
    scores: list[float] = []
    for result in results:
        store = WindowStore()
        best = 0.0
        for transition in result.transitions:
            window = store.update_multiscale_state(transition)
            best = max(best, PHI_ORACLE_SCORER.evaluate(window))
        scores.append(round(best, 9))
    return tuple(scores)


def _stage2_verdicts(scores: tuple[float, ...]) -> tuple[str, ...]:
    return tuple(
        Verdict.MALICIOUS.value if score >= DETECTION_OPERATING_POINT else Verdict.BENIGN.value
        for score in scores
    )


def _pipeline_digest(pipeline: Stage1Pipeline) -> str:
    """Digest the pipeline's own end state — novelty, causal memory, AOP, epoch.

    Stage 4 reads ``CausalMemory.spine()``; if that read mutated the memory, or if
    a crash left the pipeline's counters different, this digest moves even when
    every ``ScenarioResult`` looks the same.
    """
    return digest_of_bytes(
        json.dumps(pipeline.report(), sort_keys=True, default=repr).encode("utf-8")
    )


def _working_hooks() -> dict[Subsystem, SubsystemHook]:
    """Ten hooks that each do real (small) work over the incident evidence.

    ``CLAIM_COMPILER`` returns ``Verdict.BENIGN`` deliberately: it is the most
    dangerous thing a resolver can say, and it is what makes
    ``test_stage4_verdict_is_never_benign_when_a_subsystem_crashed`` a real test
    rather than an accident of a stand-in that never commits.
    """
    running: dict[str, float] = {"evidence": 0.0}

    def lifecycle(evidence: IncidentEvidence, transition: SSIRTransitionV1) -> object:
        return len({node.parent_signature for node in evidence.spine})

    def compiler(evidence: IncidentEvidence, transition: SSIRTransitionV1) -> object:
        return Verdict.BENIGN

    def sensing(evidence: IncidentEvidence, transition: SSIRTransitionV1) -> object:
        return transition.uncertainty

    def counterfactual(evidence: IncidentEvidence, transition: SSIRTransitionV1) -> object:
        return max(0.0, transition.delta_phi)

    def calibration(evidence: IncidentEvidence, transition: SSIRTransitionV1) -> object:
        return 1.0 - transition.uncertainty

    def external(evidence: IncidentEvidence, transition: SSIRTransitionV1) -> object:
        return len(evidence.knowledge.cell_ids())

    def verbalizer(evidence: IncidentEvidence, transition: SSIRTransitionV1) -> object:
        return f"{transition.causal_signature}:{transition.state_delta.bitmask()}"

    def handoff(evidence: IncidentEvidence, transition: SSIRTransitionV1) -> object:
        return evidence.knowledge.is_empty

    def sequential(evidence: IncidentEvidence, transition: SSIRTransitionV1) -> object:
        running["evidence"] += transition.uncertainty
        return running["evidence"]

    def graph(evidence: IncidentEvidence, transition: SSIRTransitionV1) -> object:
        return transition.state_delta.bitmask()

    return {
        Subsystem.WORLD_LIFECYCLE: lifecycle,
        Subsystem.CLAIM_COMPILER: compiler,
        Subsystem.ACTIVE_SENSING: sensing,
        Subsystem.COUNTERFACTUAL: counterfactual,
        Subsystem.CALIBRATION: calibration,
        Subsystem.EXTERNAL_KNOWLEDGE: external,
        Subsystem.VERBALIZER: verbalizer,
        Subsystem.CRYSTAL_HANDOFF: handoff,
        Subsystem.SEQUENTIAL_EVIDENCE: sequential,
        Subsystem.WORLD_GRAPH: graph,
    }


def _hooks_with_fault(
    fault: Subsystem | None, exception: type[BaseException] | None
) -> dict[Subsystem, SubsystemHook]:
    hooks = _working_hooks()
    if fault is None or exception is None:
        return hooks
    healthy = hooks[fault]

    def faulty(evidence: IncidentEvidence, transition: SSIRTransitionV1) -> object:
        # Mid-incident: after the subsystem has already run on half the evidence.
        if transition.sequence == evidence.middle_sequence:
            raise exception(f"injected {fault.value} failure at {transition.sequence}")
        return healthy(evidence, transition)

    hooks[fault] = faulty
    return hooks


def _replay(
    *,
    attach: bool,
    fault: Subsystem | None = None,
    exception: type[BaseException] | None = None,
) -> RunOutput:
    """Replay the corpus, optionally attaching Stage 4 between scenarios.

    Attaching *between* scenarios on one pipeline is the point: Stage 4 sees the
    shared ``CausalMemory`` mid-run, so a crash has live Stage 1 state next to it
    and the scenarios that follow are the proof it was not disturbed.
    """
    pipeline = Stage1Pipeline()
    corpus = build_ambiguous_corpus(count=CORPUS_COUNT, seed=CORPUS_SEED)
    ledger = DegradationLedger()
    results: list[ScenarioResult] = []
    outcomes: list[AttachmentOutcome] = []
    escaped: str | None = None

    for index, scenario in enumerate(corpus):
        result = pipeline.run_scenario(scenario, sensor=SensorPath.EBPF, offset=index)
        results.append(result)
        if not attach:
            continue
        try:
            evidence = integrate_evidence(
                result,
                memory=pipeline.causal,
                knowledge=EMPTY_KNOWLEDGE,
                predictions=(),
                incident_id=f"inc-{index:04d}",
                sensor=SensorPath.EBPF,
            )
            outcomes.append(
                run_attached_cognition(
                    evidence,
                    hooks=_hooks_with_fault(fault, exception),
                    ledger=ledger,
                )
            )
        except (KeyboardInterrupt, SystemExit):  # pragma: no cover - never swallowed
            raise
        except BaseException as exc:  # noqa: BLE001 - the escape IS the measurement
            escaped = f"{type(exc).__name__}: {exc}"

    frozen = tuple(results)
    scores = _stage2_scores(frozen)
    return RunOutput(
        stage1_digest=_stage1_digest(frozen),
        stage2_digest=digest_of_bytes(json.dumps(scores).encode("utf-8")),
        pipeline_digest=_pipeline_digest(pipeline),
        stage2_verdicts=_stage2_verdicts(scores),
        outcomes=tuple(outcomes),
        records=ledger.records(),
        escaped=escaped,
    )


@pytest.fixture(scope="module")
def baseline() -> RunOutput:
    """Stage 1 + Stage 2, with no Stage 4 in the process at all."""
    return _replay(attach=False)


@pytest.fixture(scope="module")
def healthy() -> RunOutput:
    """Stage 4 attached and working. Keeps the crash tests from being vacuous."""
    return _replay(attach=True)


@pytest.fixture(scope="module")
def injected() -> Mapping[tuple[Subsystem, str], RunOutput]:
    """Thirty runs: ten subsystems x three exception types, computed once."""
    by_exception = {item.__name__: item for item in INJECTED_EXCEPTIONS}
    return {
        (subsystem, name): _replay(
            attach=True, fault=subsystem, exception=by_exception[name]
        )
        for subsystem, name in INJECTIONS
    }


# --------------------------------------------------------------------------- #
# G4.11 — the isolation property
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(("subsystem", "exception"), INJECTIONS)
def test_stage1_scenario_output_is_unchanged_when_any_stage4_subsystem_crashes(
    subsystem: Subsystem,
    exception: str,
    baseline: RunOutput,
    injected: Mapping[tuple[Subsystem, str], RunOutput],
) -> None:
    run = injected[(subsystem, exception)]
    assert run.stage1_digest == baseline.stage1_digest, (
        f"{subsystem.value}/{exception} changed Stage 1 output"
    )


@pytest.mark.parametrize(("subsystem", "exception"), INJECTIONS)
def test_stage1_pipeline_state_is_unchanged_when_any_stage4_subsystem_crashes(
    subsystem: Subsystem,
    exception: str,
    baseline: RunOutput,
    injected: Mapping[tuple[Subsystem, str], RunOutput],
) -> None:
    """Stage 4 reads the causal memory. Reading must not be writing."""
    run = injected[(subsystem, exception)]
    assert run.pipeline_digest == baseline.pipeline_digest


@pytest.mark.parametrize(("subsystem", "exception"), INJECTIONS)
def test_stage2_detection_verdicts_are_unchanged_when_any_stage4_subsystem_crashes(
    subsystem: Subsystem,
    exception: str,
    baseline: RunOutput,
    injected: Mapping[tuple[Subsystem, str], RunOutput],
) -> None:
    run = injected[(subsystem, exception)]
    assert run.stage2_digest == baseline.stage2_digest
    assert run.stage2_verdicts == baseline.stage2_verdicts


@pytest.mark.parametrize(("subsystem", "exception"), INJECTIONS)
def test_no_exception_escapes_from_any_stage4_subsystem_crash(
    subsystem: Subsystem,
    exception: str,
    injected: Mapping[tuple[Subsystem, str], RunOutput],
) -> None:
    run = injected[(subsystem, exception)]
    assert run.escaped is None, f"{subsystem.value} let {run.escaped} escape into Stage 1"


@pytest.mark.parametrize(("subsystem", "exception"), INJECTIONS)
def test_exactly_one_degradation_record_is_written_per_crashed_subsystem(
    subsystem: Subsystem,
    exception: str,
    injected: Mapping[tuple[Subsystem, str], RunOutput],
) -> None:
    """One record per (subsystem, incident): the fallback replaces the subsystem.

    There are ``CORPUS_COUNT`` incidents and the attachment is rebuilt for each,
    so a faulty subsystem fails once per incident and never once per transition.
    """
    run = injected[(subsystem, exception)]
    assert len(run.records) == CORPUS_COUNT
    assert {item.subsystem for item in run.records} == {subsystem}
    assert {item.exception_type for item in run.records} == {exception}


@pytest.mark.parametrize(("subsystem", "exception"), INJECTIONS)
def test_the_recorded_fallback_is_the_section_45_rule_for_that_subsystem(
    subsystem: Subsystem,
    exception: str,
    injected: Mapping[tuple[Subsystem, str], RunOutput],
) -> None:
    run = injected[(subsystem, exception)]
    for record in run.records:
        assert record.fallback == FALLBACKS[subsystem]
        assert record.evidence_preserved is True


@pytest.mark.parametrize(("subsystem", "exception"), INJECTIONS)
def test_the_crash_is_recorded_mid_incident_not_at_the_first_transition(
    subsystem: Subsystem,
    exception: str,
    injected: Mapping[tuple[Subsystem, str], RunOutput],
) -> None:
    """A subsystem that only ever fails on transition 0 proves nothing."""
    run = injected[(subsystem, exception)]
    assert all(record.at_sequence > 0 for record in run.records), [
        record.at_sequence for record in run.records
    ]


@pytest.mark.parametrize(("subsystem", "exception"), INJECTIONS)
def test_stage4_verdict_is_never_benign_when_a_subsystem_crashed(
    subsystem: Subsystem,
    exception: str,
    injected: Mapping[tuple[Subsystem, str], RunOutput],
) -> None:
    """The invariant with the most to lose: uncertainty never becomes benign.

    The claim compiler in this harness returns ``Verdict.BENIGN`` on every
    transition, and the healthy run (below) shows that value reaching the output.
    Remove ``downgrade_verdict`` from the attachment and this test fails thirty
    times, which is the point of writing it that way.
    """
    run = injected[(subsystem, exception)]
    assert run.outcomes
    # When the claim compiler itself crashed, nothing was resolved and the answer
    # is UNIDENTIFIABLE; when anything else crashed, the compiler's BENIGN is
    # downgraded. Both are non-committal, and the two cases are kept apart
    # because "no resolution" and "a resolution that cannot be trusted" are
    # different facts about the run.
    expected = (
        Verdict.UNIDENTIFIABLE if subsystem is Subsystem.CLAIM_COMPILER else DEGRADED_VERDICT
    )
    for outcome in run.outcomes:
        assert outcome.verdict is not Verdict.BENIGN
        assert outcome.verdict is expected
        assert outcome.resolved is False


@pytest.mark.parametrize(("subsystem", "exception"), INJECTIONS)
def test_stage4_verdict_is_non_committal_whenever_a_subsystem_crashed(
    subsystem: Subsystem,
    exception: str,
    injected: Mapping[tuple[Subsystem, str], RunOutput],
) -> None:
    run = injected[(subsystem, exception)]
    for outcome in run.outcomes:
        assert outcome.verdict in NON_COMMITTAL_VERDICTS
        assert outcome.degraded is True
        assert outcome.disabled == (subsystem,)


def test_a_healthy_attachment_resolves_so_the_crash_tests_are_not_vacuous(
    baseline: RunOutput, healthy: RunOutput
) -> None:
    """Without a fault the stand-in compiler's BENIGN reaches the output.

    This is the control for every crash test above: it shows the value they
    forbid is reachable, and it shows that attaching a *working* Stage 4 also
    leaves Stage 1 and Stage 2 byte-identical.
    """
    assert healthy.records == ()
    assert healthy.escaped is None
    assert [outcome.verdict for outcome in healthy.outcomes] == [Verdict.BENIGN] * CORPUS_COUNT
    assert all(outcome.resolved for outcome in healthy.outcomes)
    assert healthy.stage1_digest == baseline.stage1_digest
    assert healthy.pipeline_digest == baseline.pipeline_digest
    assert healthy.stage2_verdicts == baseline.stage2_verdicts


@pytest.mark.parametrize(("subsystem", "exception"), INJECTIONS)
def test_a_crashed_subsystem_is_disabled_rather_than_retried_every_transition(
    subsystem: Subsystem,
    exception: str,
    healthy: RunOutput,
    injected: Mapping[tuple[Subsystem, str], RunOutput],
) -> None:
    """§45's fallback replaces the subsystem; it does not race it.

    Fewer hook calls than the healthy run is the observable form of that, and it
    is also the bound: a subsystem that raised on every transition would cost one
    guarded frame per transition forever.
    """
    run = injected[(subsystem, exception)]
    for crashed, intact in zip(run.outcomes, healthy.outcomes, strict=True):
        assert crashed.calls < intact.calls
        assert subsystem not in crashed.results


def test_the_attachments_work_is_bounded_by_transitions_times_subsystems(
    healthy: RunOutput,
) -> None:
    """The reasoning cost is a deterministic work-unit count, not a wall clock.

    §2.8: wall clock on this host is contended enough to make a millisecond bound
    a coin flip, so the bound that is asserted is the number of guarded hook
    frames — which an attacker cannot inflate without first inflating the bounded
    transition count.
    """
    assert healthy.outcomes
    for outcome in healthy.outcomes:
        assert outcome.calls <= MAX_TRANSITIONS_PER_INCIDENT * len(Subsystem)
        assert outcome.calls % len(Subsystem) == 0  # ten live subsystems, every step


# --------------------------------------------------------------------------- #
# ``guarded`` itself
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("exception", INJECTED_EXCEPTIONS)
def test_memory_error_and_recursion_error_are_caught_because_section_45_is_about_oom(
    exception: type[BaseException],
) -> None:
    """``except Exception`` would miss two of these three. §45's first rule is OOM."""
    ledger = DegradationLedger()
    with guarded(Subsystem.WORLD_GRAPH, ledger, at_sequence=9, fallback="fallback") as scope:
        raise exception("injected")
    assert scope.failed is True
    assert scope.result == "fallback"
    assert len(ledger.records()) == 1
    assert ledger.records()[0].exception_type == exception.__name__
    assert ledger.degraded(Subsystem.WORLD_GRAPH) is True
    assert ledger.degraded(Subsystem.CALIBRATION) is False


@pytest.mark.parametrize("exception", [KeyboardInterrupt, SystemExit])
def test_keyboard_interrupt_and_system_exit_are_never_swallowed(
    exception: type[BaseException],
) -> None:
    """Swallowing these would make the endpoint unkillable."""
    ledger = DegradationLedger()
    with pytest.raises(exception):
        with guarded(Subsystem.VERBALIZER, ledger, fallback=None):
            raise exception()
    assert ledger.records() == ()


def test_a_bare_memory_error_with_no_message_is_still_recorded() -> None:
    """The realistic OOM path: ``MemoryError()`` stringifies to ``""``.

    A record that required a non-empty message would raise *inside* the guard on
    the exact failure §45's first rule is about, which would defeat the whole
    mechanism. So an empty message is legal and the exception type carries the
    meaning.
    """
    ledger = DegradationLedger()
    with guarded(Subsystem.WORLD_LIFECYCLE, ledger, at_sequence=3, fallback=()) as scope:
        raise MemoryError
    assert scope.failed is True
    record = ledger.records()[0]
    assert record.exception_type == "MemoryError"
    assert record.message == ""
    assert record.at_sequence == 3


def test_a_guard_wired_to_something_that_is_not_a_ledger_is_refused_eagerly() -> None:
    """Otherwise the one call that must not raise would raise on the crash path."""
    with pytest.raises(ContractError, match="DegradationLedger"):
        guarded(Subsystem.CALIBRATION, [])  # type: ignore[arg-type]
    with pytest.raises(ContractError):
        guarded(Subsystem.CALIBRATION, DegradationLedger(), at_sequence=-1)


def test_the_decorator_form_gives_each_call_its_own_scope() -> None:
    ledger = DegradationLedger()

    @guarded(Subsystem.COUNTERFACTUAL, ledger, at_sequence=3, fallback=-1.0)
    def flux(value: float) -> float:
        if value < 0:
            raise RecursionError("depth")
        return value * 2

    assert flux(2.0) == 4.0
    assert flux(-1.0) == -1.0
    assert flux(3.0) == 6.0  # the failed call did not poison the next one
    assert len(ledger.records()) == 1


def test_a_guarded_failure_downgrades_a_committal_verdict_and_leaves_abstention_alone() -> None:
    for verdict in (Verdict.BENIGN, Verdict.SUSPICIOUS, Verdict.MALICIOUS):
        assert downgrade_verdict(verdict, degraded=True) is DEGRADED_VERDICT
        assert downgrade_verdict(verdict, degraded=False) is verdict
    for verdict in sorted(NON_COMMITTAL_VERDICTS):
        assert downgrade_verdict(verdict, degraded=True) is verdict


def test_degradation_record_refuses_a_fallback_that_is_not_the_section_45_rule() -> None:
    """A record cannot claim a rule that is not this subsystem's.

    Without this, "the right FALLBACKS string was recorded" would be a property of
    whichever caller happened to be right.
    """
    with pytest.raises(ContractError, match="§45 rule"):
        DegradationRecord(
            subsystem=Subsystem.CALIBRATION,
            exception_type="RuntimeError",
            message="x",
            at_sequence=1,
            fallback=FALLBACKS[Subsystem.VERBALIZER],
        )
    with pytest.raises(ContractError, match="§45 rule"):
        DegradationRecord(
            subsystem=Subsystem.CALIBRATION,
            exception_type="RuntimeError",
            message="x",
            at_sequence=1,
            fallback="do whatever seems best",
        )


def test_fallbacks_covers_the_ten_subsystems_and_nothing_else() -> None:
    assert len(Subsystem) == 10
    assert set(FALLBACKS) == set(Subsystem)
    assert all(FALLBACKS[item].strip() for item in Subsystem)


def test_a_degradation_message_is_bounded_and_never_a_traceback() -> None:
    """Unbounded attacker-influenced text is not endpoint state."""
    try:
        raise RuntimeError("line one\nline two\n  File \"x.py\", line 3\n" + "A" * 4096)
    except RuntimeError as exc:
        record = record_for(Subsystem.WORLD_LIFECYCLE, exc, at_sequence=5)
    assert len(record.message) <= MAX_DEGRADATION_MESSAGE
    assert "\n" not in record.message
    assert record.message.endswith("…")


def test_the_degradation_ledger_is_bounded_and_reports_what_it_dropped() -> None:
    ledger = DegradationLedger(capacity=4)
    for index in range(10):
        ledger.record(
            DegradationRecord(
                subsystem=Subsystem.WORLD_GRAPH,
                exception_type="MemoryError",
                message=f"pressure {index}",
                at_sequence=index,
                fallback=FALLBACKS[Subsystem.WORLD_GRAPH],
            )
        )
    assert ledger.count == 4
    assert ledger.dropped == 6
    assert ledger.truncated is True
    assert [item.at_sequence for item in ledger.records()] == [6, 7, 8, 9]
    assert 0 < ledger.memory_bytes() < 4096
    assert ledger.degraded_any() is True


def test_the_ledger_refuses_a_non_record_and_a_zero_capacity() -> None:
    with pytest.raises(ContractError):
        DegradationLedger(capacity=0)
    with pytest.raises(ContractError):
        DegradationLedger().record("COUNTERFACTUAL failed")  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# The Stage 3 handoff reader (D4.14, read half)
# --------------------------------------------------------------------------- #


def _handoff_payload() -> dict[str, object]:
    """The seven-field shape ``write_crystal_handoff`` produces.

    Written out here rather than imported: the seam is the file (§2.5). The key
    set and canonicalisation were read out of
    ``pocketsec/stage3/stage4_interface.py`` (``to_dict``, ``write_crystal_handoff``)
    in the session that wrote this test.
    """
    return {
        "interface_version": "1.0.0",
        "schema_id": CRYSTAL_HANDOFF_V1_ID,
        "handoff_id": "crystal-handoff-0001",
        "encoder_version": "dtl-encoder.1.0.0",
        "cells": [{"cell_id": "cell-alpha"}, {"cell_id": "cell-beta"}],
        "assurance": [{"cell_id": "cell-alpha", "state": "ASSURED"}],
        "boundary_keys": [
            {
                "cell_id": "cell-alpha",
                "relation_family": 3,
                "actor_property_mask": 12,
                "state_delta_mask": 5,
            },
            {
                "cell_id": "cell-beta",
                "relation_family": 1,
                "actor_property_mask": 2,
                "state_delta_mask": 4,
            },
        ],
        "melt_history": [{"cell_id": "cell-beta", "kind": "PARTIAL"}],
    }


def _canonical(payload: object) -> bytes:
    """Byte-for-byte what ``write_crystal_handoff`` writes."""
    return json.dumps(payload, sort_keys=True, allow_nan=False, indent=2).encode("utf-8") + b"\n"


def _write_handoff(tmp_path: Path, payload: object) -> tuple[Path, str]:
    raw = _canonical(payload)
    path = tmp_path / "crystal-handoff.json"
    path.write_bytes(raw)
    return path, digest_of_bytes(raw)


def test_a_missing_handoff_degrades_to_empty_knowledge_and_never_raises(tmp_path: Path) -> None:
    """Stage 3 being absent is a supported configuration, not an error."""
    knowledge, record = load_or_empty(tmp_path / "absent.json", at_sequence=11)
    assert knowledge is EMPTY_KNOWLEDGE
    assert knowledge.is_empty is True
    assert record is not None
    assert record.subsystem is Subsystem.CRYSTAL_HANDOFF
    assert record.fallback == FALLBACKS[Subsystem.CRYSTAL_HANDOFF]
    assert record.at_sequence == 11
    assert record.evidence_preserved is True


def _hostile(**overrides: object) -> bytes:
    """A canonical handoff with one clause broken, so each case tests that clause.

    Built from the valid payload rather than written out per case: a hand-written
    fixture that is *also* missing an unrelated field would be refused for the
    wrong reason, and the test would still pass while measuring nothing.
    """
    payload = _handoff_payload()
    for key, value in overrides.items():
        if value is _ABSENT:
            payload.pop(key, None)
        else:
            payload[key] = value
    return _canonical(payload)


_ABSENT = object()

HOSTILE_PAYLOADS = (
    ("empty", b""),
    ("truncated-json", b'{"cells": ['),
    ("not-an-object", b"[1, 2, 3]\n"),
    ("json-null", b"null\n"),
    ("not-utf8", b"\xff\xfe\x00cells"),
    ("wrong-schema", _hostile(schema_id="pocketsec.something_else.v1")),
    ("no-schema", _hostile(schema_id=_ABSENT)),
    ("missing-interface-version", _hostile(interface_version=_ABSENT)),
    ("incompatible-interface-major", _hostile(interface_version="2.0.0")),
    ("missing-section", _hostile(boundary_keys=_ABSENT)),
    ("cells-not-a-list", _hostile(cells={})),
    ("cell-without-id", _hostile(cells=[{"nope": 1}])),
    ("row-not-an-object", _hostile(cells=["cell-a"])),
    ("handoff-id-not-an-identifier", _hostile(handoff_id="../../etc/passwd")),
    ("encoder-version-not-an-identifier", _hostile(encoder_version="")),
)


@pytest.mark.parametrize(("name", "raw"), HOSTILE_PAYLOADS)
def test_a_corrupt_or_hostile_handoff_never_raises_and_is_never_silently_accepted(
    name: str, raw: bytes, tmp_path: Path
) -> None:
    path = tmp_path / f"{name}.json"
    path.write_bytes(raw)
    knowledge, record = load_or_empty(path)
    assert knowledge is EMPTY_KNOWLEDGE, name
    assert record is not None, name
    assert record.subsystem is Subsystem.CRYSTAL_HANDOFF
    # The strict reader must agree: silence in one path and refusal in the other
    # would mean the degradation record was decoration.
    with pytest.raises(ContractError):
        read_crystal_knowledge(path)


def test_a_valid_handoff_is_read_with_its_cells_keys_and_melt_history(tmp_path: Path) -> None:
    path, digest = _write_handoff(tmp_path, _handoff_payload())
    knowledge = read_crystal_knowledge(path, expected_digest=digest)
    assert knowledge.cell_ids() == ("cell-alpha", "cell-beta")
    assert knowledge.keys_for("cell-alpha") == ((3, 12, 5),)
    assert knowledge.keys_for("cell-beta") == ((1, 2, 4),)
    assert knowledge.keys_for("cell-missing") == ()
    assert knowledge.encoder_version == "dtl-encoder.1.0.0"
    assert knowledge.is_empty is False


def test_a_minor_interface_bump_is_still_readable_but_a_major_one_is_not(
    tmp_path: Path,
) -> None:
    """A breaking change takes a new schema id, so ``1.x`` must keep crossing.

    Refusing a minor bump would be the "too strict and a legitimate cell cannot
    cross" half of the failure the producer's docstring names.
    """
    payload = _handoff_payload()
    payload["interface_version"] = "1.4.2"
    path, digest = _write_handoff(tmp_path, payload)
    assert read_crystal_knowledge(path, expected_digest=digest).cell_ids() == (
        "cell-alpha",
        "cell-beta",
    )
    payload["interface_version"] = "2.0.0"
    path, _ = _write_handoff(tmp_path, payload)
    with pytest.raises(ContractError, match="interface_version"):
        read_crystal_knowledge(path)


def test_melt_history_distinguishes_never_crystallised_from_crystallised_then_melted(
    tmp_path: Path,
) -> None:
    """The producer's docstring says those route differently. So they must be distinct."""
    path, digest = _write_handoff(tmp_path, _handoff_payload())
    knowledge = read_crystal_knowledge(path, expected_digest=digest)
    assert knowledge.melted("cell-beta") is True
    assert knowledge.melted("cell-alpha") is False
    assert knowledge.melted("cell-never-existed") is False


def test_the_handoff_digest_is_recomputed_from_the_bytes_that_were_read(tmp_path: Path) -> None:
    """Stage 4 proves the cells it loaded are the cells Stage 3 wrote."""
    path, digest = _write_handoff(tmp_path, _handoff_payload())
    knowledge = read_crystal_knowledge(path)
    assert knowledge.handoff_digest == digest
    assert knowledge.handoff_digest == digest_of_bytes(path.read_bytes())


def test_a_handoff_whose_digest_does_not_match_the_writers_is_refused(tmp_path: Path) -> None:
    path, digest = _write_handoff(tmp_path, _handoff_payload())
    tampered = json.loads(path.read_text(encoding="utf-8"))
    tampered["cells"].append({"cell_id": "cell-injected"})
    path.write_bytes(_canonical(tampered))
    with pytest.raises(ContractError, match="digest"):
        read_crystal_knowledge(path, expected_digest=digest)
    knowledge, record = load_or_empty(path, expected_digest=digest)
    assert knowledge is EMPTY_KNOWLEDGE
    assert record is not None


def test_an_oversized_handoff_is_refused_before_it_is_parsed(tmp_path: Path) -> None:
    """A 2 GB host cannot learn a file's size by loading it."""
    path = tmp_path / "huge.json"
    path.write_bytes(b"{" + b" " * (MAX_HANDOFF_BYTES + 1))
    with pytest.raises(ContractError, match="cap is"):
        read_crystal_knowledge(path)
    knowledge, record = load_or_empty(path)
    assert knowledge is EMPTY_KNOWLEDGE
    assert record is not None


def test_too_many_cells_is_refused_rather_than_trimmed(tmp_path: Path) -> None:
    payload = _handoff_payload()
    payload["cells"] = [{"cell_id": f"cell-{index:04d}"} for index in range(300)]
    path, _ = _write_handoff(tmp_path, payload)
    with pytest.raises(ContractError, match="cap is"):
        read_crystal_knowledge(path)


def test_empty_knowledge_carries_a_real_digest_of_the_absent_bytes() -> None:
    assert EMPTY_KNOWLEDGE.handoff_digest == digest_of_bytes(b"")
    assert EMPTY_KNOWLEDGE.cell_ids() == ()
    assert EMPTY_KNOWLEDGE.keys_for("anything") == ()
    assert EMPTY_KNOWLEDGE.melted("anything") is False


def test_crystal_knowledge_refuses_a_cell_row_with_no_id() -> None:
    """Built directly, not only read from a file: every lookup is keyed on it."""
    with pytest.raises(ContractError, match="cell_id"):
        CrystalKnowledge(
            handoff_id="h-1",
            handoff_digest=digest_of_bytes(b""),
            cells=({"kind": "invariant"},),
            assurance=(),
            boundary_keys=(),
            melt_history=(),
            encoder_version="e-1",
        )


def test_a_boundary_key_that_is_not_three_ints_is_refused(tmp_path: Path) -> None:
    payload = _handoff_payload()
    payload["boundary_keys"] = [
        {
            "cell_id": "cell-alpha",
            "relation_family": "three",
            "actor_property_mask": 12,
            "state_delta_mask": 5,
        }
    ]
    path, _ = _write_handoff(tmp_path, payload)
    knowledge = read_crystal_knowledge(path)
    with pytest.raises(ContractError, match="must be an int"):
        knowledge.keys_for("cell-alpha")


# --------------------------------------------------------------------------- #
# The evidence integrator
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def one_incident() -> tuple[Stage1Pipeline, ScenarioResult]:
    pipeline = Stage1Pipeline()
    scenario = build_ambiguous_corpus(count=1, seed=CORPUS_SEED)[0]
    return pipeline, pipeline.run_scenario(scenario, sensor=SensorPath.EBPF)


def test_integrate_evidence_takes_the_spine_from_causal_memory(
    one_incident: tuple[Stage1Pipeline, ScenarioResult],
) -> None:
    pipeline, result = one_incident
    evidence = integrate_evidence(
        result,
        memory=pipeline.causal,
        incident_id="inc-0001",
        sensor=SensorPath.EBPF,
    )
    assert evidence.spine == pipeline.causal.spine(min_responsibility=0.01)
    assert evidence.transitions == result.transitions
    assert evidence.host_state == result.final_state
    assert evidence.truncated is False
    assert evidence.knowledge is EMPTY_KNOWLEDGE
    assert evidence.sensor is SensorPath.EBPF
    assert evidence.middle_sequence > 0
    assert evidence.to_dict()["transitions"] == len(result.transitions)


def test_an_over_long_incident_truncates_explicitly_and_keeps_the_recent_evidence(
    one_incident: tuple[Stage1Pipeline, ScenarioResult],
) -> None:
    """The bound holds and the truncation is recorded. A silent drop is a defect."""
    pipeline, result = one_incident
    first, last = result.transitions[0], result.transitions[-1]
    flooded = replace(
        result, transitions=(first,) * (MAX_TRANSITIONS_PER_INCIDENT + 64) + (last,)
    )
    evidence = integrate_evidence(
        flooded, memory=pipeline.causal, incident_id="inc-flood", sensor=SensorPath.AUDITD
    )
    assert len(evidence.transitions) == MAX_TRANSITIONS_PER_INCIDENT
    assert evidence.truncated is True
    assert evidence.transitions[-1] is last


def test_incident_evidence_refuses_an_over_long_construction(
    one_incident: tuple[Stage1Pipeline, ScenarioResult],
) -> None:
    """Trimming belongs to the integrator, which also sets ``truncated``."""
    pipeline, result = one_incident
    with pytest.raises(ContractError, match="cap is"):
        IncidentEvidence(
            incident_id="inc-0002",
            epoch_id=0,
            transitions=(result.transitions[0],) * (MAX_TRANSITIONS_PER_INCIDENT + 1),
            spine=(),
            host_state=result.final_state,
            predictions=(),
            knowledge=EMPTY_KNOWLEDGE,
            sensor=SensorPath.EBPF,
            truncated=True,
        )


def test_the_attachment_refuses_a_hook_mapping_that_names_an_unknown_subsystem(
    one_incident: tuple[Stage1Pipeline, ScenarioResult],
) -> None:
    """A wiring error is raised eagerly; only *hook failures* are swallowed."""
    pipeline, result = one_incident
    evidence = integrate_evidence(
        result, memory=pipeline.causal, incident_id="inc-0004", sensor=SensorPath.EBPF
    )
    hooks = {"WORLD_ORACLE": lambda evidence, transition: None}
    with pytest.raises(ContractError, match="unknown Stage 4 subsystem"):
        run_attached_cognition(
            evidence,
            hooks=hooks,  # type: ignore[arg-type]
            ledger=DegradationLedger(),
        )


def test_integrate_evidence_refuses_something_that_is_not_a_scenario_result() -> None:
    with pytest.raises(ContractError):
        integrate_evidence(
            "not a result",  # type: ignore[arg-type]
            memory=None,  # type: ignore[arg-type]
            incident_id="inc-0003",
            sensor=SensorPath.EBPF,
        )


def test_no_stage4_dataclass_in_this_package_names_response_authority() -> None:
    """Trust rule T5. A verdict is an input to Stage 4, never an authorisation."""
    offenders: list[str] = []
    for cls in OWNED_DATACLASSES:
        for name in getattr(cls, "__dataclass_fields__", {}):
            lowered = name.lower()
            if any(token in lowered for token in FORBIDDEN_AUTHORITY_FIELDS):
                offenders.append(f"{cls.__name__}.{name}")
    assert offenders == []


def test_the_authority_audit_wired_into_post_init_is_not_a_no_op() -> None:
    """A check nobody has seen fire is a hope. This one fires on the tempting name.

    ``IncidentEvidence`` and ``EngineOutcome`` call this helper on construction, so
    showing it catches ``remediation_hint`` shows the guard would fire the day
    someone adds a field like that.
    """

    @dataclass(frozen=True)
    class _Tempting:
        remediation_hint: str

    assert authority_named_fields(_Tempting) == ("remediation_hint",)
    assert authority_named_fields(IncidentEvidence) == ()
    assert authority_named_fields(EngineOutcome) == ()


# --------------------------------------------------------------------------- #
# The model slot
# --------------------------------------------------------------------------- #


def _sequence(sequence_id: str = "seq-0001") -> SecurityEventSequenceV1:
    event = SecurityEventV1(
        event_id="evt-0001",
        host_id="lab-host-01",
        boot_id="boot-0001",
        observed_at_ns=1,
        monotonic_ns=1,
        source="ebpf",
        kind="process.exec",
    )
    return SecurityEventSequenceV1(
        sequence_id=sequence_id, host_id="lab-host-01", events=(event,)
    )


class _CrashingEngine:
    """An engine that fails the way a real one will: part way through."""

    def resolve(
        self, sequence: SecurityEventSequenceV1, *, ledger: DegradationLedger
    ) -> EngineOutcome | None:
        raise MemoryError("world enumeration exhausted the budget")


class _BenignEngine:
    """An engine that wants to say BENIGN, and records a degradation first."""

    def resolve(
        self, sequence: SecurityEventSequenceV1, *, ledger: DegradationLedger
    ) -> EngineOutcome | None:
        ledger.record(
            record_for(Subsystem.CALIBRATION, RuntimeError("isotonic fit failed"), at_sequence=4)
        )
        return EngineOutcome(
            verdict=Verdict.BENIGN,
            confidence=0.99,
            novelty_score=0.1,
            uncertainty=0.01,
            identifiability="IDENTIFIED",
            compute_budget_units=12.0,
        )


class _IdentifyingEngine:
    def resolve(
        self, sequence: SecurityEventSequenceV1, *, ledger: DegradationLedger
    ) -> EngineOutcome | None:
        return EngineOutcome(
            verdict=Verdict.SUSPICIOUS,
            confidence=0.7,
            novelty_score=0.2,
            uncertainty=0.3,
            identifiability="IDENTIFIED",
            compute_budget_units=8.0,
            state_identifier="world-alpha",
        )


def test_the_null_engine_slot_validates_against_the_frozen_model_slot() -> None:
    slot = CBFSlot()
    validate_slot(slot)
    assert isinstance(NullIncidentEngine(), IncidentEngine)
    assert slot.slot_name == "stage4-cbf-lucid"


def test_the_null_engine_slot_abstains_as_unidentifiable_rather_than_guessing() -> None:
    prediction = CBFSlot().predict(_sequence())
    assert prediction.verdict is Verdict.UNIDENTIFIABLE
    assert prediction.abstained is True
    assert prediction.confidence == 0.0
    assert prediction.uncertainty == 1.0
    assert prediction.is_committal is False


def test_the_slot_never_reports_a_calibration_id_because_nothing_measured_one() -> None:
    """An invented calibration id is a fabricated result (ADR-0004's discipline)."""
    for engine in (NullIncidentEngine(), _IdentifyingEngine(), _CrashingEngine()):
        slot = CBFSlot(engine=engine)
        prediction = slot.predict(_sequence())
        assert prediction.calibration_id is None
        assert prediction.is_calibrated is False


def test_a_crashing_engine_yields_a_non_committal_prediction_and_one_record() -> None:
    ledger = DegradationLedger()
    slot = CBFSlot(engine=_CrashingEngine(), ledger=ledger)
    prediction = slot.predict(_sequence())
    assert prediction.verdict is DEGRADED_VERDICT
    assert prediction.abstained is True
    assert len(ledger.records()) == 1
    assert ledger.records()[0].subsystem is Subsystem.WORLD_LIFECYCLE
    assert ledger.records()[0].exception_type == "MemoryError"


def test_an_engine_that_says_benign_after_a_degradation_is_downgraded() -> None:
    """The laundering attempt: a subsystem failed, so BENIGN is not available."""
    ledger = DegradationLedger()
    prediction = CBFSlot(engine=_BenignEngine(), ledger=ledger).predict(_sequence())
    assert prediction.verdict is not Verdict.BENIGN
    assert prediction.verdict is DEGRADED_VERDICT
    assert prediction.confidence == 0.0
    assert prediction.uncertainty == 1.0
    assert ledger.degraded(Subsystem.CALIBRATION) is True


def test_an_undegraded_engine_verdict_passes_through_unchanged() -> None:
    """The control for the test above: the downgrade is not a blanket suppression."""
    prediction = CBFSlot(engine=_IdentifyingEngine()).predict(_sequence())
    assert prediction.verdict is Verdict.SUSPICIOUS
    assert prediction.confidence == 0.7
    assert prediction.abstained is False
    assert prediction.state_identifier == "world-alpha"


def test_the_slot_refuses_an_engine_that_returns_the_wrong_type() -> None:
    class _WrongEngine:
        def resolve(
            self, sequence: SecurityEventSequenceV1, *, ledger: DegradationLedger
        ) -> EngineOutcome | None:
            return "MALICIOUS"  # type: ignore[return-value]

    with pytest.raises(ContractError, match="EngineOutcome"):
        CBFSlot(engine=_WrongEngine()).predict(_sequence())


def test_the_slot_refuses_an_object_that_is_not_an_engine_and_a_bad_sequence() -> None:
    with pytest.raises(ContractError, match="IncidentEngine"):
        CBFSlot(engine=object())  # type: ignore[arg-type]
    with pytest.raises(ContractError):
        CBFSlot().predict("seq-0001")  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Structural: trust rule T7 and the §2.5 seam
# --------------------------------------------------------------------------- #


def _modules_under(*parts: str) -> list[Path]:
    root = REPO_ROOT.joinpath(*parts)
    if not root.is_dir():  # pragma: no cover - the package is the subject
        return []
    return sorted(path for path in root.rglob("*.py") if "__pycache__" not in path.parts)


def _importers_of(paths: list[Path], prefix: str) -> list[str]:
    """Every ``path:lineno`` importing ``prefix``, relative imports resolved.

    Uses the one shared resolver rather than a copy: S2-AUTH-01 was a hole that
    existed in two checkers and was closed in neither.
    """
    offenders: list[str] = []
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            for module in imported_modules(node, path):
                if module == prefix or module.startswith(f"{prefix}."):
                    offenders.append(f"{path}:{node.lineno}")
    return offenders


def test_stage1_and_stage2_never_import_stage4() -> None:
    """Trust rule T7 — what makes "Stage 4 is optional" structural, not hopeful."""
    paths = _modules_under("pocketsec", "stage1") + _modules_under("pocketsec", "stage2")
    assert paths, "no Stage 1/2 modules found; the check would pass vacuously"
    assert _importers_of(paths, "pocketsec.stage4") == []


def test_this_package_never_imports_stage3() -> None:
    """§2.5 — the seam is the JSON file, so Stage 3 can be redesigned."""
    paths = [REPO_ROOT / item for item in OWNED_MODULES]
    for path in paths:
        assert path.is_file(), path
    assert _importers_of(paths, "pocketsec.stage3") == []


RELATIVE_STAGE3_IMPORTS = (
    (("pocketsec", "stage4", "crystal"), "from ...stage3 import stage4_interface"),
    (("pocketsec", "stage4", "crystal"), "from ...stage3.cells.schema import KnowledgeCellV1"),
    (("pocketsec", "stage4"), "from ..stage3 import stage4_interface"),
    (("pocketsec", "stage4", "engine"), "from ... import stage3"),
)


@pytest.mark.parametrize(("where", "source"), RELATIVE_STAGE3_IMPORTS)
def test_a_relative_stage3_import_would_be_caught(
    where: tuple[str, ...], source: str, tmp_path: Path
) -> None:
    """A committed negative fixture, because a checker nobody tested is a hope.

    ``from ..stage3 import x`` gives ``node.module == "stage3"``, which matches
    neither ``pocketsec.stage3`` nor ``.stage3`` — the exact shape of S2-AUTH-01.
    """
    package = tmp_path.joinpath(*where)
    package.mkdir(parents=True, exist_ok=True)
    offender = package / "leak.py"
    offender.write_text(f"{source}\n", encoding="utf-8")
    assert _importers_of([offender], "pocketsec.stage3") == [f"{offender}:1"]
