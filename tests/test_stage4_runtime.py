"""Stage 4 runtime package — behaviour and failure paths, not construction.

Five properties this file exists to hold, each with a defect behind it:

* **Every ``LucidConfig`` flag changes ``work_units``.** ADR-0116 recorded two Stage 2
  mechanisms as "default off" while no constant said so and the Future Cone ran on
  every deep event (``PROGRESS.md`` G2.6). A flag the engine does not honour turns a
  measurement into a story.
* **The Stage 5 seam refuses on the way out.** G4.8 is measured on the exported
  object, because that payload is the only artefact Stage 5 sees.
* **One contradiction may not destabilise a Knowledge Cell** (falsifier F9), and one
  resolution may not propose one.
* **Unmeasured is not within target.** ``Stage4ResourceReport`` refuses to represent
  the lie in its constructor.
* **Running the tests may not mutate ``experiments/registry.jsonl``.** A Stage 3 gate
  appended a ``PS-S3-*`` row on every run, so the permanent ledger grew as a side
  effect of testing.

Two tests here are written specifically to fail if someone weakens an invariant rather
than fixes a bug: :func:`test_resource_report_refuses_unmeasured_pass` and
:func:`test_cell_stress_signal_refuses_a_single_contradiction`.
"""

from __future__ import annotations

import ast
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from pocketsec.stage0.contracts.common import ContractError, EvidenceRef, digest_of_bytes
from pocketsec.stage0.contracts.threat_prediction_v1 import (
    NON_COMMITTAL_VERDICTS,
    Verdict,
)
from pocketsec.stage0.gate import REPO_ROOT
from pocketsec.stage1.pipeline import ScenarioResult, Stage1Pipeline
from pocketsec.stage1.telemetry.raw_event_v1 import SensorPath
from pocketsec.stage4.claims.graph import EMPTY_CLAIM_GRAPH
from pocketsec.stage4.crystal.feedback import (
    MIN_CONTRADICTIONS_FOR_STRESS,
    MIN_RESOLUTIONS_FOR_CRYSTAL_CANDIDATE,
    CellStressSignalV1,
    ResolutionRecord,
    propose_crystal_candidates,
    stress_stage3_cell,
    write_feedback,
)
from pocketsec.stage4.crystal.handoff import CrystalKnowledge
from pocketsec.stage4.engine import lucid_steps
from pocketsec.stage4.engine.degradation import Subsystem
from pocketsec.stage4.engine.lucid import (
    MAX_OPEN_INCIDENTS,
    MAX_UPDATE_STEPS_PER_TRANSITION,
    LucidConfig,
    LucidEngine,
)
from pocketsec.stage4.identifiability.resolution import IdentifiabilityState
from pocketsec.stage4.labs.baseline_metrics import BaselineOutcome
from pocketsec.stage4.labs.baselines import (
    BaselineComparison,
    compare_baselines,
    pareto_frontier,
)
from pocketsec.stage4.labs.experiments import (
    BLOCKED_REASONS,
    EXPERIMENTS,
    AblationRow,
    blocked_experiments,
    run_ablation,
    runnable_experiments,
    saturation_check,
)
from pocketsec.stage4.labs.incident_corpus import IncidentCase, build_incident_corpus
from pocketsec.stage4.resources import (
    STAGE4_NORMAL_INCREMENTAL_RSS_BYTES,
    STAGE4_PEAK_CEILING_BYTES,
    STAGE4_PROFILE,
    Stage4ResourceReport,
    loadavg,
    measure_stage4_profile,
    measure_stage4_resources,
    unmeasured_stage4_resources,
)
from pocketsec.stage4.stage5_interface import (
    CBFResolutionV1,
    IncidentHypothesis,
    InformationGap,
    export_incident_world_record,
    unsupported_authoritative_rows,
    write_resolution,
)
from pocketsec.stage4.visibility.model import fit_visibility_model, measure_visibility

STAGE4_ROOT = REPO_ROOT / "pocketsec" / "stage4"
REGISTRY_PATH = REPO_ROOT / "experiments" / "registry.jsonl"

# Small on purpose. Every figure in this file is a within-run comparison, so a bigger
# corpus buys nothing a test can assert and costs wall clock on a contended host.
CORPUS_COUNT = 6
CORPUS_SEED = 11


# --- fixtures ----------------------------------------------------------------


@pytest.fixture(scope="module")
def corpus() -> tuple[IncidentCase, ...]:
    return build_incident_corpus(count=CORPUS_COUNT, seed=CORPUS_SEED)


@pytest.fixture(scope="module")
def visibility(corpus: Sequence[IncidentCase]) -> Any:
    return fit_visibility_model(
        measure_visibility(
            Stage1Pipeline,
            [case.scenario for case in corpus],
            [SensorPath.EBPF, SensorPath.AUDITD],
        )
    )


@pytest.fixture(scope="module")
def replay(corpus: Sequence[IncidentCase]) -> tuple[IncidentCase, ScenarioResult, Stage1Pipeline]:
    case = corpus[0]
    pipeline = Stage1Pipeline()
    return case, pipeline.run_scenario(case.scenario, offset=0), pipeline


def _drive(
    engine: LucidEngine,
    case: IncidentCase,
    result: ScenarioResult,
    pipeline: Stage1Pipeline,
    *,
    limit: int = 24,
) -> Any:
    """Open, update over the first ``limit`` transitions, resolve. Returns the resolution."""
    epoch = result.transitions[0].epoch_id if result.transitions else 0
    field = engine.open_incident(case.incident_id, epoch)
    spine = pipeline.causal.spine()
    for transition in result.transitions[:limit]:
        field = engine.update(field, transition, spine).field
    return engine.resolve(field), field


# --- the flags ----------------------------------------------------------------


def test_every_lucid_flag_changes_work_units(replay: Any, visibility: Any) -> None:
    """Each of the nine flags must change the deterministic work the engine charges.

    This is the test ADR-0116 earned. A flag whose value the engine ignores is worse
    than no flag: the ablation would report a delta of zero and a reader would conclude
    the mechanism does not help, when in fact it never stopped running.
    """
    case, result, pipeline = replay
    default = LucidConfig()
    baseline = LucidEngine(config=default, visibility=visibility)
    _drive(baseline, case, result, pipeline)
    reference = baseline.work_units
    assert reference > 0

    unchanged: list[str] = []
    for flag in LucidConfig.flag_names():
        values = {name: getattr(default, name) for name in LucidConfig.flag_names()}
        values[flag] = not values[flag]
        engine = LucidEngine(config=LucidConfig(**values), visibility=visibility)
        _drive(engine, case, result, pipeline)
        if engine.work_units == reference:
            unchanged.append(flag)
    assert unchanged == [], f"flags the engine does not honour: {unchanged}"


def test_flag_names_cover_every_config_flag() -> None:
    """``flag_names()`` must not drift from the dataclass, or the test above goes blind."""
    declared = {
        name for name in LucidConfig.__dataclass_fields__ if name.startswith("enable_")
    }
    assert set(LucidConfig.flag_names()) == declared


def test_lucid_config_refuses_a_non_bool_flag() -> None:
    with pytest.raises(ContractError):
        LucidConfig(enable_stress="yes")  # type: ignore[arg-type]


# --- failure paths ------------------------------------------------------------


def test_update_never_raises_when_tension_breaks(
    replay: Any, visibility: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A subsystem that raises mid-incident degrades; it does not escape.

    The tension engine is chosen because it is the step *before* world birth: if a
    failure there stopped the loop, the residual could never spawn the world nobody
    holds, which is the one thing Stage 4 exists to notice.
    """
    case, result, pipeline = replay

    def explode(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("tension engine failed mid-incident")

    monkeypatch.setattr(lucid_steps, "calculate_evidence_tension", explode)
    engine = LucidEngine(config=LucidConfig(), visibility=visibility)
    resolution, _field = _drive(engine, case, result, pipeline)

    records = engine.degradation.records()
    assert records, "a failed subsystem must leave a DegradationRecord"
    assert any(item.subsystem is Subsystem.WORLD_LIFECYCLE for item in records)
    assert all("Traceback" not in item.message for item in records)
    assert resolution.prediction_verdict is not Verdict.BENIGN
    assert resolution.prediction_verdict in NON_COMMITTAL_VERDICTS


def test_update_survives_memory_error_from_the_claim_compiler(
    replay: Any, visibility: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``MemoryError`` is not an ``Exception`` subclass by accident — §45 is about it."""
    case, result, pipeline = replay

    def starve(*_args: Any, **_kwargs: Any) -> Any:
        raise MemoryError("bounded world search ran out")

    monkeypatch.setattr(lucid_steps, "compile_typed_claim_graph", starve)
    engine = LucidEngine(config=LucidConfig(), visibility=visibility)
    resolution, _field = _drive(engine, case, result, pipeline)
    assert engine.degradation.degraded(Subsystem.CLAIM_COMPILER)
    assert resolution.claim_graph.unsupported_authoritative() == ()
    assert resolution.prediction_verdict is not Verdict.BENIGN


def test_update_refuses_an_unopened_incident(corpus: Sequence[IncidentCase], visibility: Any) -> None:
    """Per-incident state is bounded, so it must be opened deliberately."""
    engine = LucidEngine(config=LucidConfig(), visibility=visibility)
    field = engine.open_incident("inc-a", 0)
    engine.close_incident(field)
    pipeline = Stage1Pipeline()
    result = pipeline.run_scenario(corpus[0].scenario)
    with pytest.raises(ContractError):
        engine.update(field, result.transitions[0], pipeline.causal.spine())


def test_open_incident_is_bounded(visibility: Any) -> None:
    """``MAX_OPEN_INCIDENTS`` is a real ceiling, and hitting it refuses rather than grows."""
    engine = LucidEngine(config=LucidConfig(), visibility=visibility)
    for index in range(MAX_OPEN_INCIDENTS):
        engine.open_incident(f"inc-{index}", 0)
    with pytest.raises(ContractError):
        engine.open_incident("inc-overflow", 0)


def test_reopening_the_same_incident_is_refused(visibility: Any) -> None:
    engine = LucidEngine(config=LucidConfig(), visibility=visibility)
    engine.open_incident("inc-a", 0)
    with pytest.raises(ContractError):
        engine.open_incident("inc-a", 0)


def test_engine_refuses_a_missing_visibility_model() -> None:
    """There is no default visibility model: an unmeasured visibility is not 0.5."""
    with pytest.raises(ContractError):
        LucidEngine(config=LucidConfig(), visibility=None)  # type: ignore[arg-type]


# --- bounds hold under load ---------------------------------------------------


def test_bounds_hold_and_losses_are_recorded(replay: Any, visibility: Any) -> None:
    """World count, reasoning units and truncation records, asserted on a real run.

    ``max_worlds=2`` is used so the capacity bound is actually reached on a six-case
    corpus: a bound that is never hit is not demonstrated.
    """
    case, result, pipeline = replay
    config = LucidConfig(max_worlds=2)
    engine = LucidEngine(config=config, visibility=visibility)
    epoch = result.transitions[0].epoch_id if result.transitions else 0
    field = engine.open_incident(case.incident_id, epoch)
    spine = pipeline.causal.spine()
    for transition in result.transitions:
        outcome = engine.update(field, transition, spine)
        field = outcome.field
        assert len(field.worlds) <= config.max_worlds
        assert outcome.steps <= MAX_UPDATE_STEPS_PER_TRANSITION
        assert outcome.work_units >= 0
    assert field.state_bytes() <= config.budget.max_memory_bytes
    # Every world that left the field did so with a recorded reason.
    for item in field.truncations:
        assert item.reason
        assert item.what in {"world", "graph_node", "graph_edge", "branch", "claim"}


def test_counterfactual_cap_records_its_refusal(replay: Any, visibility: Any) -> None:
    """§29's per-incident counterfactual cap must be visible, not just counted.

    An attacker who can make the field branch must not also be able to make it reason
    without limit, and "the bound held" is only checkable if the decline leaves a row.
    """
    case, result, pipeline = replay
    # The counterfactual family is enabled explicitly: since S4-FC-08 it defaults off
    # as inert, and the property under test is the cap, which only a running family
    # can hit.
    config = LucidConfig(
        enable_counterfactual=True, enable_self_questioning=True, enable_stress=True
    )
    engine = LucidEngine(config=config, visibility=visibility)
    epoch = result.transitions[0].epoch_id if result.transitions else 0
    field = engine.open_incident(case.incident_id, epoch)
    spine = pipeline.causal.spine()
    cap = engine.config.budget.max_counterfactuals
    for transition in result.transitions[: cap + 8]:
        field = engine.update(field, transition, spine).field
    declined = [
        item for item in field.truncations if item.reason.startswith("max_counterfactuals:")
    ]
    if len(result.transitions) > cap:
        assert declined, "the counterfactual cap fired without recording a Truncation"


# --- the Stage 5 seam ---------------------------------------------------------


def _authoritative_graph(*, kind: str, digest_ok: bool = True) -> dict[str, Any]:
    digest = digest_of_bytes(b"e0") if digest_ok else "sha256:not-a-digest"
    return {
        "schema": "pocketsec.typed_claim_graph.v1",
        "claims": [
            {
                "claim_id": "obs.0",
                "kind": "OBS",
                "subject": "evidence:e0",
                "text": "ebpf recorded evidence e0",
                "premises": [],
                "evidence": [{"store": "raw.ebpf", "locator": "e0", "digest": digest}],
            },
            {
                "claim_id": "x.0",
                "kind": kind,
                "subject": "world:w1",
                "text": "a claim",
                "premises": ["obs.0"],
            },
        ],
        "authoritative": ["obs.0", "x.0"],
    }


def _resolution(**overrides: Any) -> CBFResolutionV1:
    payload: dict[str, Any] = {
        "resolution_id": "cbf-res-inc-1",
        "incident_id": "inc-1",
        "epoch_id": 0,
        "verdict": Verdict.UNIDENTIFIABLE,
        "identifiability": IdentifiabilityState.UNIDENTIFIABLE.value,
        "hypotheses": (),
        "consequence_distribution": {},
        "claim_graph": _authoritative_graph(kind="DER"),
        "evidence_lineage": (),
        "uncertainty": 0.5,
        "shadow": {},
        "information_gaps": (),
        "truncations": (),
        "degradations": (),
    }
    payload.update(overrides)
    return CBFResolutionV1(**payload)


def test_to_dict_refuses_a_key_that_names_a_stage4_class() -> None:
    """A handoff that carries objects becomes a coupling; a key that names one is the tell."""
    graph = _authoritative_graph(kind="DER")
    graph["security_world_v1"] = {"mechanism": "x"}
    with pytest.raises(ContractError, match="Stage 4 class names"):
        _resolution(claim_graph=graph).to_dict()


def test_to_dict_refuses_an_unsupported_authoritative_claim() -> None:
    """G4.8 measured at export: a DER whose OBS root has a malformed digest is refused."""
    graph = _authoritative_graph(kind="DER", digest_ok=False)
    assert unsupported_authoritative_rows(graph)
    with pytest.raises(ContractError, match="OBS-rooted premise chain"):
        _resolution(claim_graph=graph).to_dict()


def test_to_dict_refuses_an_inference_marked_authoritative() -> None:
    """An INF claim can never leave this stage as an observation."""
    with pytest.raises(ContractError, match="authoritative while they are inferred"):
        _resolution(claim_graph=_authoritative_graph(kind="INF")).to_dict()


def test_to_dict_refuses_a_hypothesis_citing_a_missing_claim() -> None:
    """A citation Stage 5 cannot resolve is an unauditable factual claim."""
    hypothesis = IncidentHypothesis(
        mechanism_id="compromised_session",
        support=0.6,
        consequence=3.0,
        uncertainty=0.4,
        claim_ids=("der.absent",),
        evidence_refs=(),
    )
    with pytest.raises(ContractError, match="not in the exported claim graph"):
        _resolution(hypotheses=(hypothesis.to_dict(),)).to_dict()


def test_unsupported_walk_refuses_a_cycle() -> None:
    """A DER cycle terminates in no observation, so the walk must call it unsupported."""
    graph = {
        "claims": [
            {"claim_id": "a", "kind": "DER", "premises": ["b"], "evidence": []},
            {"claim_id": "b", "kind": "DER", "premises": ["a"], "evidence": []},
        ],
        "authoritative": ["a"],
    }
    assert unsupported_authoritative_rows(graph) == ("a",)


def test_resolution_round_trip_is_lossless_and_digest_reproducible(tmp_path: Path) -> None:
    """``from_dict(to_dict(x))`` must be the same payload, and the digest must repeat."""
    resolution = _resolution()
    first = resolution.to_dict()
    rebuilt = CBFResolutionV1.from_dict(first)
    assert rebuilt.to_dict() == first
    left = write_resolution(resolution, tmp_path / "a.json")
    right = write_resolution(rebuilt, tmp_path / "b.json")
    assert left == right
    assert left.startswith("sha256:")
    assert json.loads((tmp_path / "a.json").read_text()) == first


def test_export_from_a_real_run_carries_no_unsupported_claim(
    replay: Any, visibility: Any, tmp_path: Path
) -> None:
    """The seam's refusals must not fire on an honest run, or they are unusable."""
    case, result, pipeline = replay
    engine = LucidEngine(config=LucidConfig(), visibility=visibility)
    resolution, field = _drive(engine, case, result, pipeline)
    record = export_incident_world_record(
        field,
        verdict=resolution.verdict,
        resolution_id=f"cbf-res-{case.incident_id}",
        claim_graph=resolution.claim_graph.to_dict(),
        gaps=resolution.gaps,
    )
    payload = record.to_dict()
    assert unsupported_authoritative_rows(payload["claim_graph"]) == ()
    assert payload["verdict"] in {member.value for member in Verdict}
    assert write_resolution(record, tmp_path / "r.json").startswith("sha256:")


def test_information_gap_is_a_question_never_an_instruction() -> None:
    """ADR-0003 in the one free-text field that crosses the seam."""
    with pytest.raises(ContractError, match="reads as an instruction"):
        InformationGap(
            signal="dns_metadata",
            why_it_matters="quarantine the process and revoke its token",
            would_discriminate=("w1", "w2"),
            affordable=True,
        )
    # Naming a mandatory signal is not an instruction: privilege_change is a real
    # MANDATORY_SIGNALS member and refusing to name it would make the most
    # consequential gap in the system unreportable.
    assert InformationGap(
        signal="privilege_change",
        why_it_matters="separates the two surviving explanations",
        would_discriminate=("w1", "w2"),
        affordable=False,
    ).signal == "privilege_change"


def test_information_gap_refuses_a_gap_that_discriminates_nothing() -> None:
    with pytest.raises(ContractError, match="discriminates nothing"):
        InformationGap(
            signal="dns_metadata",
            why_it_matters="would be nice to know",
            would_discriminate=("w1",),
            affordable=True,
        )


def test_seam_types_declare_no_authority_named_field() -> None:
    """Trust rule T5, audited on the three types that cross into Stage 5."""
    from pocketsec.stage4.worlds.world import authority_named_fields

    for cls in (InformationGap, IncidentHypothesis, CBFResolutionV1):
        assert authority_named_fields(cls) == ()


def test_runtime_dataclasses_name_no_authority_field() -> None:
    """T5 across the whole runtime package, including the two renames it forced.

    Spec D4.2 names a field ``killed`` and D4.16 names one ``blocked_reason``; ``kill``
    and ``block`` are both ``FORBIDDEN_AUTHORITY_FIELDS`` tokens and §2.4's rule has no
    exemption list, so they are ``UpdateOutcome.retired`` and
    ``ExperimentSpec.refusal_reason``. This test is what keeps a future contributor from
    "fixing" the names back.
    """
    import dataclasses
    import importlib

    from pocketsec.stage0.contracts.threat_prediction_v1 import FORBIDDEN_AUTHORITY_FIELDS

    modules = (
        "pocketsec.stage4.engine.lucid",
        "pocketsec.stage4.engine.lucid_steps",
        "pocketsec.stage4.engine.lucid_support",
        "pocketsec.stage4.crystal.feedback",
        "pocketsec.stage4.stage5_interface",
        "pocketsec.stage4.resources",
        "pocketsec.stage4.labs.baselines",
        "pocketsec.stage4.labs.baseline_metrics",
        "pocketsec.stage4.labs.simple_baselines",
        "pocketsec.stage4.labs.experiments",
    )
    offenders: list[str] = []
    for name in modules:
        module = importlib.import_module(name)
        for attribute in dir(module):
            obj = getattr(module, attribute)
            if not (isinstance(obj, type) and dataclasses.is_dataclass(obj)):
                continue
            for field_name in obj.__dataclass_fields__:
                lowered = field_name.lower()
                for token in FORBIDDEN_AUTHORITY_FIELDS:
                    if token in lowered:
                        offenders.append(f"{obj.__name__}.{field_name} contains {token!r}")
    assert offenders == [], f"T5 violations: {offenders}"


def test_close_incident_drops_the_incident_state(replay: Any, visibility: Any) -> None:
    """Per-incident state is bounded, so closing must actually release it."""
    case, result, pipeline = replay
    engine = LucidEngine(config=LucidConfig(), visibility=visibility)
    _resolution, field = _drive(engine, case, result, pipeline, limit=4)
    before = engine.memory_bytes()
    record = engine.close_incident(field)
    assert record.incident_id == case.incident_id
    assert engine.memory_bytes() <= before
    assert engine.resolved_mechanisms(case.incident_id) == ()
    with pytest.raises(ContractError):
        engine.resolve(field)


def test_update_outcome_reports_what_it_changed(replay: Any, visibility: Any) -> None:
    """A world must actually be born on a real corpus, and the outcome must say so.

    Without this the engine could be silently inert — the ``Residual`` persistence gate
    is a two-step rule, and an engine that recomputed the residual per transition would
    pin ``persistent_steps`` at 1 and never spawn. That was a real defect here.
    """
    case, result, pipeline = replay
    engine = LucidEngine(config=LucidConfig(), visibility=visibility)
    epoch = result.transitions[0].epoch_id if result.transitions else 0
    field = engine.open_incident(case.incident_id, epoch)
    spine = pipeline.causal.spine()
    spawned: list[str] = []
    for transition in result.transitions[:24]:
        outcome = engine.update(field, transition, spine)
        field = outcome.field
        spawned.extend(outcome.spawned)
        assert set(outcome.spawned) <= {world.world_id for world in field.worlds} | set(
            item.identifier for item in outcome.truncations
        )
        for _world_id, cause in outcome.retired:
            assert cause, "a retirement with no recorded cause is a silent drop"
    assert spawned, "no world was ever born; the residual birth gate is inert"


# --- Stage 3 feedback ---------------------------------------------------------


def _knowledge(cell_id: str = "cell-a", key: tuple[int, int, int] = (1, 2, 4)) -> CrystalKnowledge:
    return CrystalKnowledge(
        handoff_id="handoff-1",
        handoff_digest=digest_of_bytes(b"h"),
        cells=({"cell_id": cell_id},),
        assurance=(),
        boundary_keys=(
            {
                "cell_id": cell_id,
                "relation_family": key[0],
                "actor_property_mask": key[1],
                "state_delta_mask": key[2],
            },
        ),
        melt_history=(),
        encoder_version="enc-1",
    )


def _graph_with_contradictions(count: int) -> Any:
    from pocketsec.stage4.claims.typed_claim import ObservedClaim

    graph = EMPTY_CLAIM_GRAPH
    for index in range(count):
        graph = graph.insert(
            ObservedClaim(
                claim_id=f"obs.{index}",
                subject=f"evidence:e{index}",
                text=f"ebpf recorded evidence e{index}",
                evidence=(
                    EvidenceRef(
                        store="raw.ebpf",
                        locator=f"e{index}",
                        digest=digest_of_bytes(f"e{index}".encode()),
                    ),
                ),
                sensor=SensorPath.EBPF,
                at_sequence=index,
            ),
            authoritative=True,
        )
    return graph


def test_cell_stress_needs_three_contradictions(tmp_path: Path) -> None:
    """Falsifier F9: one observation may not destabilise crystallised knowledge."""
    knowledge = _knowledge()
    subjects = [f"evidence:e{i}" for i in range(MIN_CONTRADICTIONS_FOR_STRESS)]
    one = stress_stage3_cell(
        knowledge,
        _graph_with_contradictions(1),
        incident_ids=("inc-1",),
        entered_keys=((1, 2, 4),),
        contradicted_subjects=subjects[:1],
    )
    assert one == (), "a single contradiction produced a stress signal (F9 fired)"
    enough = stress_stage3_cell(
        knowledge,
        _graph_with_contradictions(MIN_CONTRADICTIONS_FOR_STRESS),
        incident_ids=("inc-1",),
        entered_keys=((1, 2, 4),),
        contradicted_subjects=subjects,
    )
    assert len(enough) == 1
    assert enough[0].contradiction_count == MIN_CONTRADICTIONS_FOR_STRESS
    assert enough[0].to_dict()["requests"] == "stage3_audit"
    assert write_feedback(enough, tmp_path / "f.json").startswith("sha256:")


def test_cell_stress_signal_refuses_a_single_contradiction() -> None:
    """The constructor refuses it too, so the threshold cannot be bypassed by a caller.

    Written to fail if someone weakens the invariant rather than fixes a bug: a future
    contributor who lowers ``MIN_CONTRADICTIONS_FOR_STRESS`` to 1 to make a gate green
    breaks this test, and the test names the falsifier it protects.
    """
    with pytest.raises(ContractError, match="falsifier F9"):
        CellStressSignalV1(
            signal_id="s4-stress-cell-a",
            cell_id="cell-a",
            boundary_key=(1, 2, 4),
            contradiction_count=1,
            contradicting_claim_ids=("obs.0",),
            evidence_digests=(digest_of_bytes(b"e0"),),
            incident_ids=("inc-1",),
        )


def test_no_stress_signal_for_a_boundary_the_incident_never_entered() -> None:
    """The other half of F9: a cell whose region was never touched is left alone."""
    knowledge = _knowledge(key=(1, 2, 4))
    subjects = [f"evidence:e{i}" for i in range(MIN_CONTRADICTIONS_FOR_STRESS)]
    graph = _graph_with_contradictions(MIN_CONTRADICTIONS_FOR_STRESS)
    assert (
        stress_stage3_cell(
            knowledge,
            graph,
            incident_ids=("inc-1",),
            entered_keys=((9, 9, 9),),
            contradicted_subjects=subjects,
        )
        == ()
    )
    assert (
        stress_stage3_cell(
            knowledge, graph, incident_ids=("inc-1",), contradicted_subjects=subjects
        )
        == ()
    )


def test_stress_signal_refuses_an_inference_as_a_contradiction() -> None:
    """An ``InferredClaim`` may not question a cell: that would invert the authority."""
    from pocketsec.stage4.claims.typed_claim import InferredClaim

    graph = _graph_with_contradictions(MIN_CONTRADICTIONS_FOR_STRESS)
    inferred = InferredClaim(
        claim_id="inf.0",
        subject="evidence:e0",
        text="possible compromised session",
        premises=(),
        world_id="w1",
        support=0.9,
        shadow_penalty=0.0,
    )
    graph = graph.insert(inferred)
    signals = stress_stage3_cell(
        _knowledge(),
        graph,
        incident_ids=("inc-1",),
        entered_keys=((1, 2, 4),),
        contradicted_subjects=("evidence:e0",),
    )
    # One authoritative OBS on that subject; the INF on the same subject is ignored, so
    # the count stays below the threshold and no signal is produced.
    assert signals == ()


def test_crystal_candidate_needs_three_resolutions_and_a_stable_rule() -> None:
    """A union of rules would propose a cell for whatever happened once."""
    rows = [
        ResolutionRecord(
            mechanism_id="compromised_session",
            incident_id=f"inc-{index}",
            rule_ids=("cbf.spine", f"cbf.only-{index}"),
            boundary_keys=((1, 2, 4),),
            evidence_digests=(digest_of_bytes(b"e0"),),
        )
        for index in range(MIN_RESOLUTIONS_FOR_CRYSTAL_CANDIDATE)
    ]
    candidates = propose_crystal_candidates(rows)
    assert len(candidates) == 1
    assert candidates[0].stable_claim_rule_ids == ("cbf.spine",)
    assert candidates[0].to_dict()["proposes"] == "stage3_candidate_review"
    assert propose_crystal_candidates(rows[:-1]) == ()


def test_no_stage4_module_exports_melt_promote_or_crystallize() -> None:
    """Stage 4 has no path to melt a cell and no path to create one.

    The check is over **callables** whose name contains one of those words as an
    *imperative verb*, and the precision is the point. Two names that must stay legal,
    each for a reason:

    * ``MAX_MELT_ROWS`` (``crystal/handoff.py``) is a bound on how much of Stage 3's
      melt history Stage 4 will *read*. It is a constant, not a callable.
    * ``CrystalKnowledge.melted(cell_id)`` is a **predicate**: it asks whether Stage 3
      already melted a cell, because ``melt_history`` is in the handoff precisely so
      "never crystallised" can be told apart from "crystallised then melted". A check
      that banned the past participle would push the code into calling the question
      something vaguer, which is worse for a reader than the word itself.

    So the forbidden shape is a word equal to ``melt``/``promote``/``crystallize``
    (or their ``-s``/British spellings) in a callable's name — the forms that would
    *do* it. Read by AST rather than by importing, so a module that would fail to
    import cannot hide an export.
    """
    forbidden = {
        "melt",
        "melts",
        "promote",
        "promotes",
        "crystallize",
        "crystallizes",
        "crystallise",
        "crystallises",
    }
    offenders: list[str] = []
    for path in sorted(STAGE4_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            words = set(node.name.lower().strip("_").split("_"))
            if words & forbidden:
                offenders.append(f"{path.name}:def {node.name}")
    assert offenders == [], f"Stage 4 exports a promotion path: {offenders}"


# --- the experiment register --------------------------------------------------


def test_experiments_has_exactly_forty_unique_ids() -> None:
    assert len(EXPERIMENTS) == 40
    ids = [spec.experiment_id for spec in EXPERIMENTS]
    assert len(set(ids)) == 40
    assert ids == [f"S4X-{n:02d}" for n in range(1, 41)]
    assert len(runnable_experiments()) + len(blocked_experiments()) == 40


def test_blocked_experiments_is_a_required_non_empty_output() -> None:
    """Declaring the gap is the deliverable; an empty blocked set would be the lie."""
    blocked = blocked_experiments()
    assert blocked, "no experiment is blocked, which this repository cannot honestly claim"
    for spec in blocked:
        assert spec.refusal_reason in BLOCKED_REASONS
        assert spec.registry_experiment_id is None


def test_experiment_spec_refuses_a_blocked_row_with_no_reason() -> None:
    from pocketsec.stage4.labs.experiments import ExperimentSpec

    # §43 names exactly forty, so an id outside S4X-01..S4X-40 is not one of them, and
    # a malformed id would break the join back to the architecture document.
    for bad in ("S4X-41", "S4X-00", "S4X-1", "X41", "s4x-01"):
        with pytest.raises(ContractError):
            ExperimentSpec(
                experiment_id=bad, title="invented", core_ids=("CBF-F01",), runnable=True
            )
    with pytest.raises(ContractError):
        ExperimentSpec(
            experiment_id="S4X-01",
            title="blocked with no reason",
            core_ids=("CBF-F01",),
            runnable=False,
            refusal_reason="we ran out of time",
        )


def test_ablation_row_refuses_an_invented_verdict() -> None:
    with pytest.raises(ContractError):
        AblationRow(
            core_id="CBF-F04",
            flag="enable_fission_fusion",
            with_value=1.0,
            without_value=0.0,
            delta=1.0,
            metric="world_set_recall",
            verdict="REJECTED",
        )


def test_run_ablation_returns_degenerate_rows_without_a_delta(
    monkeypatch: pytest.MonkeyPatch, corpus: Sequence[IncidentCase]
) -> None:
    """A degenerate split yields ``DEGENERATE`` rows carrying the reason, not a zero delta.

    Monkeypatched rather than hunting for a degenerate corpus, because the property
    under test is that ``run_ablation`` *consults* the guard first — the six-case
    corpus's own verdict is measured separately by
    :func:`test_saturation_check_reports_its_reason`.
    """
    import pocketsec.stage4.labs.experiments as module

    monkeypatch.setattr(module, "saturation_check", lambda _c: (True, "SATURATED: for the test"))
    rows = run_ablation(corpus, seed=CORPUS_SEED)
    assert rows
    assert {row.verdict for row in rows} == {"DEGENERATE"}
    assert all("not-computed" in row.metric for row in rows)
    assert all(row.delta == 0.0 for row in rows)
    assert {row.flag for row in rows} == set(LucidConfig.flag_names())


def test_saturation_check_reports_its_reason(corpus: Sequence[IncidentCase]) -> None:
    degenerate, reason = saturation_check(corpus)
    assert isinstance(degenerate, bool)
    assert reason.strip(), "a saturation verdict with no reason cannot be audited"
    assert saturation_check(())[0] is True


# --- baselines ---------------------------------------------------------------


def _outcome(baseline_id: str, **overrides: Any) -> BaselineOutcome:
    payload: dict[str, Any] = {
        "baseline_id": baseline_id,
        "world_set_recall": None,
        "premature_collapse_rate": None,
        "nonidentifiability_accuracy": None,
        "unsupported_claim_count": 0,
        "telemetry_bytes": 0,
        "cpu_units": 0.0,
        "work_units": 0,
        "resolution_efficiency": None,
    }
    payload.update(overrides)
    return BaselineOutcome(**payload)


def test_pareto_frontier_treats_none_as_incomparable() -> None:
    """A baseline that did not attempt an axis must neither dominate nor be dominated on it."""
    attempted = _outcome("attempted", world_set_recall=0.9, cpu_units=1.0)
    abstained = _outcome("abstained", world_set_recall=None, cpu_units=1.0)
    frontier, dominated = pareto_frontier((attempted, abstained))
    assert dominated == ()
    assert frontier == ("abstained", "attempted")

    cheaper = _outcome("cheap", world_set_recall=0.9, cpu_units=0.5)
    frontier, dominated = pareto_frontier((attempted, cheaper))
    assert dominated == ("attempted",)
    assert frontier == ("cheap",)


def test_baseline_outcome_refuses_a_non_finite_metric() -> None:
    with pytest.raises(ContractError):
        _outcome("bad", world_set_recall=float("nan"))


def test_comparison_refuses_a_baseline_at_or_below_chance() -> None:
    """Rule 1: a model at or below chance is a bug, so its row is refused, not reported."""
    below = _outcome("B_below", detection_accuracy=0.30, world_set_recall=1.0)
    above = _outcome("B_above", detection_accuracy=0.90, world_set_recall=0.5)
    comparison = BaselineComparison(
        outcomes=(below, above),
        base_rate=0.33,
        degenerate=False,
        degenerate_reason="best 0.9000 vs median 0.6000",
        refused=(("B_below", "detection accuracy 0.3000 <= base rate 0.3300"),),
        loadavg=loadavg(),
    )
    assert [item.baseline_id for item in comparison.reportable] == ["B_above"]


def test_comparison_reports_nothing_on_a_degenerate_split() -> None:
    """Rule 2: a frontier computed on a split that cannot separate mechanisms is void."""
    comparison = BaselineComparison(
        outcomes=(_outcome("B1", detection_accuracy=0.9),),
        base_rate=0.33,
        degenerate=True,
        degenerate_reason="SATURATED",
        refused=(),
        loadavg=loadavg(),
    )
    assert comparison.reportable == ()
    assert comparison.frontier() == ((), ())


@pytest.mark.slow
def test_compare_baselines_runs_every_control_in_one_process(
    corpus: Sequence[IncidentCase],
) -> None:
    """All nine rows, one replay set, loadavg recorded. Marked slow: it replays a corpus."""
    comparison = compare_baselines(corpus, seed=CORPUS_SEED)
    ids = {item.baseline_id for item in comparison.outcomes}
    assert "CBF_LUCID" in ids
    assert "B1_SingleWorldMAP" in ids
    assert len(ids) == 9
    assert comparison.loadavg != (0.0, 0.0, 0.0)
    payload = comparison.to_dict()
    assert payload["unbuildable"], "the absent §42 baselines must be declared"
    # Every metric that came back None stays None in the payload: None is not 0.0.
    for row in payload["outcomes"]:
        assert row["nonidentifiability_accuracy"] is None or isinstance(
            row["nonidentifiability_accuracy"], float
        )


# --- resources ---------------------------------------------------------------


def test_resource_report_refuses_unmeasured_pass() -> None:
    """Unmeasured is not within target, and the constructor refuses to say otherwise.

    Written to fail if someone weakens the invariant. A contributor who wants a green
    resource gate has two options: measure it, or report ``None``. Editing this
    constructor to allow ``within_target=True`` beside a missing observation breaks
    this test, which is the point.
    """
    with pytest.raises(ContractError, match="unmeasured is not within target"):
        Stage4ResourceReport(
            peak_sampled_rss_bytes=None,
            incremental_rss_bytes=1024,
            per_component_bytes={},
            within_target=True,
            loadavg=loadavg(),
            measured_by="tests:test_resource_report_refuses_unmeasured_pass",
        )
    assert unmeasured_stage4_resources(measured_by="m:f", reason="nothing sampled").within_target is None


def test_stage0_profile_report_is_never_true_while_unmeasured(
    replay: Any, visibility: Any
) -> None:
    """``ProfileReport.within_target`` may be ``None`` or ``False`` here, never ``True``.

    Stage 4 ships no model, so ``model_bytes`` is genuinely unmeasured and the ``edge``
    profile carries a model-size target. Passing 0 would claim a measurement of a thing
    that does not exist and Stage 0 would record the target as met.

    ``is not True`` rather than ``is None``, and the distinction was found by running the
    full suite: ``getrusage`` peak RSS is a **process-lifetime** high-water mark, so when
    this file runs after the other stages' tests the agent-RSS target is exceeded and
    ``False`` is the correct answer. Asserting ``None`` would have made this test's
    outcome depend on what else ran in the process — a figure that comes out differently
    for reasons unrelated to the property is not a measurement of it.
    """
    case, result, pipeline = replay
    engine = LucidEngine(config=LucidConfig(), visibility=visibility)
    report = measure_stage4_profile(
        lambda: len(_drive(engine, case, result, pipeline, limit=4)[1].worlds) + 1
    )
    assert report.profile == STAGE4_PROFILE
    assert "model_bytes" in report.unmeasured
    assert report.within_target is not True
    if not report.exceeded:
        assert report.within_target is None
    with pytest.raises(ContractError):
        measure_stage4_profile(lambda: 1, profile_name="invented-profile")


def test_resource_report_refuses_an_unbudgeted_component() -> None:
    with pytest.raises(ContractError, match="no §44 budget"):
        Stage4ResourceReport(
            peak_sampled_rss_bytes=1,
            incremental_rss_bytes=1,
            per_component_bytes={"invented_component": 1},
            within_target=None,
            loadavg=loadavg(),
            measured_by="m:f",
        )


def test_resource_report_refuses_a_producerless_figure() -> None:
    """A figure with no ``module:function`` producer is not a measurement."""
    with pytest.raises(ContractError, match="module:function"):
        Stage4ResourceReport(
            peak_sampled_rss_bytes=1,
            incremental_rss_bytes=1,
            per_component_bytes={},
            within_target=None,
            loadavg=loadavg(),
            measured_by="somewhere",
        )


@pytest.mark.slow
def test_measure_stage4_resources_is_none_until_every_component_is_supplied(
    replay: Any, visibility: Any
) -> None:
    """A partial measurement is ``None``, and a complete one is judged against §44."""
    case, result, pipeline = replay
    engine = LucidEngine(config=LucidConfig(), visibility=visibility)

    def work() -> int:
        resolution, field = _drive(engine, case, result, pipeline)
        work.captured = (resolution, field)  # type: ignore[attr-defined]
        return len(result.transitions[:24])

    partial = measure_stage4_resources(work, measured_by="tests:partial")
    assert partial.within_target is None
    assert partial.unmeasured

    resolution, field = work.captured  # type: ignore[attr-defined]
    from pocketsec.stage4.evidence.calibration import EpochCalibration

    full = measure_stage4_resources(
        lambda: 1,
        measured_by="tests:full",
        belief_field_bytes=field.state_bytes(),
        claim_graph_bytes=len(json.dumps(resolution.claim_graph.to_dict()).encode()),
        world_graph=field.graph,
        tombstones=__import__(
            "pocketsec.stage4.worlds.tombstone", fromlist=["TombstoneLedger"]
        ).TombstoneLedger(),
        calibration=EpochCalibration(),
        degradation=engine.degradation,
    )
    assert full.unmeasured == ()
    assert isinstance(full.within_target, bool)
    assert full.over_peak_ceiling is not None
    assert STAGE4_NORMAL_INCREMENTAL_RSS_BYTES < STAGE4_PEAK_CEILING_BYTES


# --- the ledger must not move -------------------------------------------------


def test_no_owned_module_constructs_the_experiment_registry() -> None:
    """A test run may never grow ``experiments/registry.jsonl``.

    Stage 3's gate appended a ``PS-S3-*`` row every time it ran, so merely running the
    suite grew the permanent, append-only, digest-chained ledger. The structural fix is
    that nothing in the runtime package constructs an ``ExperimentRegistry`` at all;
    registration belongs to a deliberate CLI subcommand.

    Checked over the AST with **docstrings excluded**, so a module may (and should)
    explain the rule in prose while being forbidden from executing it.
    """
    owned = [
        STAGE4_ROOT / "engine" / "lucid.py",
        STAGE4_ROOT / "engine" / "lucid_steps.py",
        STAGE4_ROOT / "engine" / "lucid_support.py",
        STAGE4_ROOT / "crystal" / "feedback.py",
        STAGE4_ROOT / "stage5_interface.py",
        STAGE4_ROOT / "resources.py",
        STAGE4_ROOT / "labs" / "baselines.py",
        STAGE4_ROOT / "labs" / "baseline_metrics.py",
        STAGE4_ROOT / "labs" / "simple_baselines.py",
        STAGE4_ROOT / "labs" / "experiments.py",
    ]
    offenders: list[str] = []
    for path in owned:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        docstrings = {
            id(node.body[0].value)
            for node in ast.walk(tree)
            if isinstance(
                node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
            )
            and node.body
            and isinstance(node.body[0], ast.Expr)
            and isinstance(node.body[0].value, ast.Constant)
            and isinstance(node.body[0].value.value, str)
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and node.id == "ExperimentRegistry":
                offenders.append(f"{path.name}:ExperimentRegistry")
            elif isinstance(node, ast.Attribute) and node.attr == "ExperimentRegistry":
                offenders.append(f"{path.name}:ExperimentRegistry")
            elif (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and "registry.jsonl" in node.value
                and id(node) not in docstrings
            ):
                offenders.append(f"{path.name}:{node.value[:40]!r}")
    assert offenders == [], f"a runtime module can write the real ledger: {offenders}"


@pytest.mark.slow
def test_running_the_package_leaves_the_real_ledger_byte_identical(
    corpus: Sequence[IncidentCase], visibility: Any, tmp_path: Path
) -> None:
    """Digest taken either side of the package's heaviest entry points.

    Includes ``pocketsec.stage4.gate`` when the integrator has landed it, so this test
    keeps covering the criterion once the gate exists rather than needing an edit.
    """
    before = digest_of_bytes(REGISTRY_PATH.read_bytes()) if REGISTRY_PATH.exists() else None

    run_ablation(corpus, seed=CORPUS_SEED)
    compare_baselines(corpus, seed=CORPUS_SEED)
    engine = LucidEngine(config=LucidConfig(), visibility=visibility)
    pipeline = Stage1Pipeline()
    result = pipeline.run_scenario(corpus[0].scenario)
    resolution, field = _drive(engine, corpus[0], result, pipeline)
    write_resolution(
        export_incident_world_record(
            field,
            verdict=resolution.verdict,
            resolution_id=f"cbf-res-{corpus[0].incident_id}",
            claim_graph=resolution.claim_graph.to_dict(),
        ),
        tmp_path / "resolution.json",
    )
    write_feedback((), tmp_path / "feedback.json")
    try:
        from pocketsec.stage4 import gate as stage4_gate
    except ImportError:
        stage4_gate = None  # type: ignore[assignment]
    if stage4_gate is not None and hasattr(stage4_gate, "run_gate"):
        stage4_gate.run_gate()  # pragma: no cover - only once the integrator lands it

    after = digest_of_bytes(REGISTRY_PATH.read_bytes()) if REGISTRY_PATH.exists() else None
    assert after == before, "running Stage 4 mutated the real experiment ledger"


# --- abstention is reachable --------------------------------------------------


def test_abstention_is_reachable_and_benign_is_not_manufactured(
    corpus: Sequence[IncidentCase], visibility: Any
) -> None:
    """A non-committal outcome must be reachable on a real corpus, and never BENIGN by default.

    ``UNIDENTIFIABLE``/``UNKNOWN``/``INSUFFICIENT_EVIDENCE`` are valid outputs
    (MEMORY.md invariant). A stage that always names a culprit is not doing causal
    reasoning, and one that resolves an unfinished incident to BENIGN is unsafe.
    """
    engine = LucidEngine(config=LucidConfig(), visibility=visibility)
    states: set[str] = set()
    verdicts: set[Verdict] = set()
    for index, case in enumerate(corpus[:3]):
        pipeline = Stage1Pipeline()
        result = pipeline.run_scenario(case.scenario, offset=index)
        resolution, _field = _drive(engine, case, result, pipeline)
        states.add(resolution.verdict.state.value)
        verdicts.add(resolution.prediction_verdict)
        if resolution.abstained:
            assert resolution.prediction_verdict in NON_COMMITTAL_VERDICTS
    assert states & {
        IdentifiabilityState.UNIDENTIFIABLE.value,
        IdentifiabilityState.UNKNOWN.value,
        IdentifiabilityState.INSUFFICIENT_EVIDENCE.value,
    }, f"no abstention was reachable; states seen: {sorted(states)}"
    assert Verdict.BENIGN not in verdicts or len(verdicts) > 1
