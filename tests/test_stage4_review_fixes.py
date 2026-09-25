"""Regression tests for the confirmed Stage 4 review findings (S4-REV/SEC/FC/RES/MEAS/CPLX).

Each test names the finding it pins in its docstring and was written to FAIL on the
code the finding describes: a bound that was a counter, a ledger shared by every
incident, a verdict path that named a culprit for a single refuted world, a gate
check that could not see the engine. They are behavioural — they drive the real
``LucidEngine`` or the real module — because the defects were all of the kind a
structural test had passed over.
"""

from __future__ import annotations

import dataclasses
import math
import time
from collections.abc import Sequence
from typing import Any

import pytest

from pocketsec.stage0.contracts.common import ContractError, EvidenceRef, digest_of_bytes
from pocketsec.stage0.contracts.threat_prediction_v1 import NON_COMMITTAL_VERDICTS, Verdict
from pocketsec.stage1.observation.policy import AdaptiveObservationPolicy
from pocketsec.stage1.pipeline import Stage1Pipeline
from pocketsec.stage1.telemetry.raw_event_v1 import SensorPath
from pocketsec.stage4.claims.compiler import (
    DERIVATION_RULE_CATALOGUE,
    compile_typed_claim_graph,
)
from pocketsec.stage4.claims.graph import EMPTY_CLAIM_GRAPH
from pocketsec.stage4.claims.typed_claim import (
    ClaimKind,
    DerivedClaim,
    InferredClaim,
    ObservedClaim,
    kind_of,
)
from pocketsec.stage4.engine import lucid_bounds, lucid_steps
from pocketsec.stage4.engine.lucid import INERT_FLAGS, LucidConfig, LucidEngine
from pocketsec.stage4.engine.lucid_support import (
    MAX_SHADOW_EVIDENCE_TRANSITIONS,
    WORK_UNITS,
    IncidentState,
)
from pocketsec.stage4.gate_probes import claim_support_audit
from pocketsec.stage4.graph.entropy_budget import EntropyBudget
from pocketsec.stage4.graph.sparse_world_graph import (
    MAX_FIELD_TRUNCATIONS,
    TRUNCATION_KINDS,
    Truncation,
    append_truncations,
)
from pocketsec.stage4.identifiability.horizon import HorizonOutcome
from pocketsec.stage4.identifiability.resolution import (
    IdentifiabilityState,
    is_unknown_mechanism,
    test_identifiability as identify,
)
from pocketsec.stage4.labs.baseline_metrics import predicted_label, replay_corpus
from pocketsec.stage4.labs.incident_corpus import IncidentCase, build_incident_corpus
from pocketsec.stage4.labs.nonidentifiable import (
    build_corpus_visibility_model,
    build_nonidentifiable_pairs,
    build_resolvable_after_one_observation,
    field_for_nonidentifiable_pair,
    field_for_resolvable_case,
)
from pocketsec.stage4.stage5_interface import CBFResolutionV1, unsupported_authoritative_rows
from pocketsec.stage4.visibility.model import fit_visibility_model, measure_visibility
from pocketsec.stage4.worlds.field import CausalBeliefField, unknown_world
from pocketsec.stage4.worlds.world import BeliefGeometry, WorldSupport

CORPUS_SEED = 11


# --- fixtures ----------------------------------------------------------------


@pytest.fixture(scope="module")
def corpus() -> tuple[IncidentCase, ...]:
    return build_incident_corpus(count=6, seed=CORPUS_SEED)


@pytest.fixture(scope="module")
def replays(corpus: Sequence[IncidentCase]) -> Any:
    return replay_corpus(corpus)


@pytest.fixture(scope="module")
def visibility(corpus: Sequence[IncidentCase]) -> Any:
    return fit_visibility_model(
        measure_visibility(
            Stage1Pipeline,
            [case.scenario for case in corpus],
            [SensorPath.EBPF, SensorPath.AUDITD],
        )
    )


def _engine(visibility: Any, config: LucidConfig | None = None) -> LucidEngine:
    return LucidEngine(
        config=config if config is not None else LucidConfig(),
        visibility=visibility,
        observation=AdaptiveObservationPolicy(),
    )


def _drive(engine: LucidEngine, replay: Any, incident_id: str | None = None) -> Any:
    transitions = replay.result.transitions
    field = engine.open_incident(incident_id or replay.case.incident_id, transitions[0].epoch_id)
    spine = replay.pipeline.causal.spine()
    for transition in transitions:
        field = engine.update(field, transition, spine).field
    return field


def _long_stream(replays: Any) -> list[tuple[Any, Any]]:
    epoch = replays[0].result.transitions[0].epoch_id
    stream = []
    for replay in replays:
        spine = replay.pipeline.causal.spine()
        stream.extend((t, spine) for t in replay.result.transitions if t.epoch_id == epoch)
    return stream


def _world(world_id: str, mechanism: str, log_odds: float) -> Any:
    base = unknown_world("inc-review", at_sequence=0)
    return dataclasses.replace(
        base,
        world_id=world_id,
        mechanism_id=mechanism,
        support=WorldSupport(BeliefGeometry.LOG_ODDS, log_odds),
    )


def _field(*worlds: Any) -> CausalBeliefField:
    return CausalBeliefField(incident_id="inc-review", epoch_id=0, worlds=tuple(worlds))


# --- the work bound: S4-REV-01, S4-SEC-01, S4-FC-04, S4-RES-01, S4-RES-03 -----


def test_one_long_incident_holds_bounded_state_and_bounded_per_update_work(
    replays: Any, visibility: Any
) -> None:
    """S4-REV-01 / S4-SEC-01 / S4-RES-01 / S4-FC-04 / S4-RES-03.

    Before: ``IncidentState.transitions`` kept every transition and was rescanned each
    update, the truncation log re-recorded the same refused edges every step (13895
    records over 1397 transitions), and every step ran after the budget was spent.
    After: the shadow evidence and the log are capped, and once the horizon closes an
    update costs one integrate unit.
    """
    stream = _long_stream(replays)
    assert len(stream) > 200, "the incident must be long enough to exercise the bound"
    engine = _engine(visibility)
    field = engine.open_incident("inc-long", stream[0][0].epoch_id)
    state = engine._incidents["inc-long"]
    units_after_close: list[int] = []
    closed = False
    for transition, spine in stream:
        outcome = engine.update(field, transition, spine)
        field = outcome.field
        if closed:
            units_after_close.append(outcome.work_units)
        closed = closed or lucid_bounds.reasoning_closed(field.horizon)
    assert closed, "the §20 horizon never closed on a long incident"
    assert units_after_close and max(units_after_close) <= WORK_UNITS["integrate"]
    assert len(state.shadow_evidence) <= MAX_SHADOW_EVIDENCE_TRANSITIONS
    assert not hasattr(state, "transitions")
    assert len(field.truncations) <= MAX_FIELD_TRUNCATIONS + len(TRUNCATION_KINDS)
    keys = [(t.what, t.identifier, t.reason) for t in field.truncations]
    assert len(keys) == len(set(keys)), "the same loss was recorded twice"


def test_memory_report_counts_what_the_incident_actually_holds(
    replays: Any, visibility: Any
) -> None:
    """S4-REV-01: ``memory_bytes`` left the per-incident history out and stayed flat."""
    engine = _engine(visibility)
    field = engine.open_incident("inc-mem", replays[0].result.transitions[0].epoch_id)
    empty = engine.memory_bytes()
    spine = replays[0].pipeline.causal.spine()
    for transition in replays[0].result.transitions:
        field = engine.update(field, transition, spine).field
    state = engine._incidents["inc-mem"]
    assert engine.memory_bytes() == engine.degradation.memory_bytes() + state.memory_bytes()
    if state.shadow_evidence:
        assert engine.memory_bytes() > empty


def test_budget_exhaustion_refuses_the_optional_and_fission_passes(
    replays: Any, visibility: Any
) -> None:
    """S4-FC-04 / S4-RES-03: the reasoning-unit cap is checked BEFORE the work.

    With a 64-unit budget the counter is spent within a transition or two; every later
    update must skip fission/fusion and the optional passes (fewer passes, no fission
    spend) and carry one recorded refusal — not merely book ``refused_units``.
    """
    config = LucidConfig(budget=EntropyBudget(max_reasoning_units=64))
    engine = _engine(visibility, config)
    replay = replays[0]
    field = engine.open_incident("inc-budget", replay.result.transitions[0].epoch_id)
    spine = replay.pipeline.causal.spine()
    outcomes = []
    for transition in replay.result.transitions[:6]:
        outcome = engine.update(field, transition, spine)
        field = outcome.field
        outcomes.append(outcome)
    assert outcomes[0].steps > outcomes[-1].steps
    refusals = [t for t in field.truncations if "optional_and_fission_passes_refused" in t.reason]
    assert len(refusals) == 1


def test_the_horizon_is_charged_and_its_exhaustion_is_reachable(
    replays: Any, visibility: Any
) -> None:
    """S4-REV-10: nothing called ``ResolutionHorizon.charge``; ESCALATE_TO_ANALYST was dead."""
    engine = _engine(visibility)
    replay = max(replays, key=lambda item: len(item.result.transitions))
    field = _drive(engine, replay)
    horizon = field.horizon
    assert horizon.consumed_transitions > 0
    assert horizon.exhausted()
    resolution = engine.resolve(field)
    if resolution.verdict.state is not IdentifiabilityState.UNIDENTIFIABLE:
        assert resolution.horizon_outcome is HorizonOutcome.ESCALATE_TO_ANALYST


def test_granted_escalations_are_charged_to_budget_and_horizon() -> None:
    """S4-SEC-09: nothing charged ``sensor_escalation``, so its per-incident cap never fired."""
    state = IncidentState(EntropyBudget())
    state.pending_escalations = 2
    field = dataclasses.replace(_field(), horizon=lucid_bounds.ResolutionHorizon())
    charged = lucid_bounds.charge_horizon(field, state, 10)
    assert charged.horizon.consumed_escalations == 2
    assert charged.horizon.consumed_transitions == 1
    assert state.budget.spend_report()["sensor_escalations"] == 2
    assert state.pending_escalations == 0


def test_truncation_log_is_deduplicated_and_overflows_per_kind() -> None:
    """S4-SEC-01: the log grew with transitions; a world loss must never hide in edge noise."""
    edges = [
        Truncation(what="graph_edge", identifier=f"e{i}", reason="endpoint_absent", consequence_lost=0.0)
        for i in range(MAX_FIELD_TRUNCATIONS + 50)
    ]
    log = append_truncations((), edges)
    log = append_truncations(log, edges)  # the same losses again: nothing new
    world = Truncation(what="world", identifier="w-x", reason="field_at_capacity", consequence_lost=7.5)
    log = append_truncations(log, (world, world))
    assert len(log) <= MAX_FIELD_TRUNCATIONS + len(TRUNCATION_KINDS)
    overflow = {t.what: t for t in log if t.identifier.startswith("truncation_overflow:")}
    # 50 overflowed losses, reported twice: the overflow counts reports, not keys,
    # because remembering the folded keys would be unbounded state.
    assert "reports_folded=100" in overflow["graph_edge"].reason
    assert overflow["world"].consequence_lost == 7.5


# --- per-incident degradation: S4-REV-06, S4-FC-09, S4-RES-04, S4-SEC-06 --------


def test_a_fault_in_one_incident_does_not_reach_the_next(
    replays: Any, visibility: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """S4-REV-06 / S4-FC-09 / S4-RES-04: one engine-lifetime ledger contaminated B with A."""
    original = lucid_steps.calculate_evidence_tension
    armed = {"on": True}

    def flaky(*args: Any, **kwargs: Any) -> Any:
        if armed["on"]:
            raise RuntimeError("injected fault in incident A only")
        return original(*args, **kwargs)

    monkeypatch.setattr(lucid_steps, "calculate_evidence_tension", flaky)
    engine = _engine(visibility)
    field_a = _drive(engine, replays[0], "inc-a")
    export_a = engine.close_incident(field_a)
    armed["on"] = False
    field_b = _drive(engine, replays[1], "inc-b")
    resolution_b = engine.resolve(field_b)
    export_b = engine.close_incident(field_b)
    assert export_a.degradations, "the faulted incident must carry its failure"
    assert resolution_b.degraded == ()
    assert export_b.degradations == ()
    assert any("incident A" in row.message for row in engine.degradation.records())


def test_an_unusable_locator_does_not_abort_the_compile() -> None:
    """S4-SEC-06: a legal 120-char record id made ObservedClaim refuse and erased the graph."""
    refs = (
        EvidenceRef(store="raw.ebpf", locator="x" * 120, digest=digest_of_bytes(b"long")),
        EvidenceRef(store="raw.ebpf", locator="seg-7#offset=4096", digest=digest_of_bytes(b"hash")),
        EvidenceRef(store="raw.ebpf", locator="plain-01", digest=digest_of_bytes(b"plain")),
    )
    world = dataclasses.replace(
        _world("w-a", "compromised_admin_session", 0.0), evidence_refs=refs
    )
    graph, compiled = compile_typed_claim_graph(_field(world))
    observed = [claim for claim in graph.claims.values() if kind_of(claim) is ClaimKind.OBS]
    assert len(observed) == 3
    assert {claim.subject for claim in observed} >= {"evidence:plain-01"}
    assert all(len(claim.subject) <= 128 for claim in observed)
    assert compiled


# --- identifiability: S4-REV-03, S4-REV-05, S4-FC-06 -----------------------------


def test_a_planner_that_was_not_wired_cannot_certify_non_identifiability() -> None:
    """S4-REV-03: "no observation policy" refusals were read as "nothing separates them"."""
    from pocketsec.stage4 import gate_criteria as criteria

    model = build_corpus_visibility_model()
    case = build_resolvable_after_one_observation(count=3, seed=17)[0]
    field = field_for_resolvable_case(case)
    unwired = criteria.plan_for(field, model=model, observation=None)
    assert not unwired.requests and unwired.not_attempted()
    verdict = identify(field, shadow=field.sensor_shadow, plan=unwired)
    assert verdict.state is IdentifiabilityState.INSUFFICIENT_EVIDENCE
    # The genuine case still answers UNIDENTIFIABLE without an AOP: its refusals are
    # about discrimination, which is a statement about the evidence.
    pair = build_nonidentifiable_pairs(count=3, seed=17)[0]
    pair_field = field_for_nonidentifiable_pair(pair)
    plan = criteria.plan_for(pair_field, model=model, observation=None)
    assert identify(pair_field, shadow=None, plan=plan).state is IdentifiabilityState.UNIDENTIFIABLE


def test_a_single_refuted_world_is_not_identified() -> None:
    """S4-REV-05 / S4-FC-06: ``_margin`` returned 1.0 with no runner-up, whatever the support."""
    refuted = _field(_world("w-a", "stolen_credential_reuse", -32.0))
    verdict = identify(refuted, shadow=None, plan=None)
    assert verdict.state is not IdentifiabilityState.IDENTIFIED
    assert verdict.abstains()
    even = identify(_field(_world("w-b", "stolen_credential_reuse", 0.0)), shadow=None, plan=None)
    assert even.state is IdentifiabilityState.INSUFFICIENT_EVIDENCE
    earned = identify(_field(_world("w-c", "stolen_credential_reuse", 3.0)), shadow=None, plan=None)
    assert earned.state is IdentifiabilityState.IDENTIFIED


def test_novel_worlds_are_unknown_never_suspicious() -> None:
    """S4-REV-05: suffixed novel ids were ranked as mechanisms and mapped to SUSPICIOUS."""
    novel = "unresolved_novel_mechanism.0123456789ab"
    assert is_unknown_mechanism(novel)
    alone = identify(_field(_world("w-n", novel, -32.0)), shadow=None, plan=None)
    assert alone.state is IdentifiabilityState.UNKNOWN
    assert alone.to_verdict() is Verdict.UNKNOWN
    leading = identify(
        _field(
            _world("w-u", "unresolved_novel_mechanism", 5.0),
            _world("w-s", "stolen_credential_reuse", -5.0),
        ),
        shadow=None,
        plan=None,
    )
    assert leading.to_verdict() is Verdict.UNKNOWN
    assert leading.to_verdict() is not Verdict.SUSPICIOUS


# --- lab scoring: S4-REV-04 ------------------------------------------------------


def test_abstention_is_not_a_benign_call_and_benign_is_not_malicious() -> None:
    """S4-REV-04: ``int(not abstained) == label`` inverted BENIGN and credited abstention."""
    assert predicted_label(Verdict.BENIGN) == 0
    assert predicted_label(Verdict.MALICIOUS) == 1
    assert predicted_label(Verdict.SUSPICIOUS) == 1
    for verdict in NON_COMMITTAL_VERDICTS:
        assert predicted_label(verdict) is None
    labels = [0, 0, 1]
    hits = sum(1 for label in labels if predicted_label(Verdict.UNKNOWN) == label)
    assert hits == 0, "an engine that abstains everywhere must score zero hits"


def test_engine_rows_report_coverage_and_never_count_abstentions(
    replays: Any, visibility: Any
) -> None:
    """S4-REV-04 / S4-REV-03: the CBF row now runs with an AOP and reports coverage."""
    from pocketsec.stage4.labs.baselines import run_engine_baseline

    outcome = run_engine_baseline(replays, visibility, LucidConfig(), baseline_id="t")
    assert outcome.detection_coverage is not None
    assert outcome.detection_accuracy is not None
    assert outcome.detection_accuracy <= outcome.detection_coverage + 1e-12


# --- claims: S4-FC-02, S4-REV-09, S4-SEC-02, S4-FC-13 ---------------------------


def _obs(claim_id: str, digest: str) -> ObservedClaim:
    return ObservedClaim(
        claim_id=claim_id,
        subject="evidence:e0",
        text="ebpf recorded evidence e0",
        evidence=(EvidenceRef(store="raw.ebpf", locator="e0", digest=digest),),
        sensor=SensorPath.EBPF,
        at_sequence=1,
    )


def test_a_fabricated_digest_and_free_der_text_fail_the_support_audit() -> None:
    """S4-FC-02: G4.8 was structural; a well-formed digest nobody produced passed it."""
    real = digest_of_bytes(b"real-event")
    fabricated = digest_of_bytes(b"never-observed-anything")
    graph = EMPTY_CLAIM_GRAPH.insert(_obs("obs-real", real), authoritative=True)
    graph = graph.insert(_obs("obs-fake", fabricated), authoritative=True)
    graph = graph.insert(
        DerivedClaim(
            claim_id="der-story",
            subject="world:w-a",
            text="the admin session was hijacked by an external actor",
            premises=("obs-real",),
            rule_id="free.text",
        ),
        authoritative=True,
    )
    assert graph.unsupported_authoritative() == ()  # the structural walk still passes
    audit = claim_support_audit(graph, frozenset({real}))
    assert audit["unanchored"] == ("obs-fake",)
    assert audit["uncatalogued"] == ("der-story",)
    assert DERIVATION_RULE_CATALOGUE == frozenset()


def test_the_compiler_emits_no_authoritative_world_attribution() -> None:
    """S4-REV-09: "N observation(s) form the causal spine of <world>" was authoritative DER."""
    refs = (EvidenceRef(store="raw.ebpf", locator="e1", digest=digest_of_bytes(b"e1")),)
    worlds = [
        dataclasses.replace(_world(f"w-{i}", mech, 0.0), evidence_refs=refs)
        for i, mech in enumerate(("compromised_admin_session", "approved_administration"))
    ]
    graph, _ = compile_typed_claim_graph(_field(*worlds))
    for claim_id in graph.authoritative:
        assert kind_of(graph.claims[claim_id]) is ClaimKind.OBS
        assert "world:" not in graph.claims[claim_id].subject


def test_a_subclass_cannot_relabel_its_kind() -> None:
    """S4-SEC-02 / S4-FC-13: ``kind_of`` read an overridable ClassVar."""

    @dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
    class Relabelled(InferredClaim):
        _KIND = ClaimKind.DER  # type: ignore[assignment]

    claim = Relabelled(
        claim_id="inf-x", subject="world:w", text="possible x", premises=("obs-1",),
        world_id="w-a", support=0.5,
    )
    with pytest.raises(ContractError):
        kind_of(claim)
    with pytest.raises(ContractError):
        EMPTY_CLAIM_GRAPH.insert(claim, authoritative=True)


# --- the Stage 5 wire: S4-REV-12, S4-SEC-03, S4-SEC-08 ---------------------------


def _row(claim_id: str, kind: str, premises: Sequence[str] = (), digest: str | None = None) -> dict[str, Any]:
    evidence = [{"store": "raw.ebpf", "locator": "e", "digest": digest}] if digest else []
    return {"claim_id": claim_id, "kind": kind, "premises": list(premises), "evidence": evidence}


def test_duplicate_rows_under_one_id_are_refused() -> None:
    """S4-REV-12: last-row-wins let an INF row ride under an OBS row's id."""
    digest = digest_of_bytes(b"e")
    graph = {"claims": [_row("c1", "INF"), _row("c1", "OBS", digest=digest)], "authoritative": ["c1"]}
    with pytest.raises(ContractError, match="two rows"):
        unsupported_authoritative_rows(graph)


def test_from_dict_runs_the_export_walk() -> None:
    """S4-REV-12: a reader rebuilding from a file accepted an authoritative INF."""
    payload = {
        "resolution_id": "r-1", "incident_id": "i-1", "epoch_id": 0, "verdict": "UNKNOWN",
        "identifiability": "UNKNOWN", "hypotheses": [], "consequence_distribution": {},
        "claim_graph": {"claims": [_row("c1", "INF")], "authoritative": ["c1"]},
        "evidence_lineage": [], "uncertainty": 1.0, "shadow": {}, "information_gaps": [],
        "truncations": [], "degradations": [],
    }
    with pytest.raises(ContractError):
        CBFResolutionV1.from_dict(payload)


def test_authority_keys_are_refused_on_every_construction_path() -> None:
    """S4-SEC-03: only the dataclass path refused ``action``-named keys."""
    with pytest.raises(ContractError, match="authority"):
        CBFResolutionV1(
            resolution_id="r-1", incident_id="i-1", epoch_id=0, verdict=Verdict.UNKNOWN,
            identifiability="UNKNOWN", hypotheses=({"mechanism_id": "m", "action": "x"},),
            consequence_distribution={}, claim_graph={"claims": [], "authoritative": []},
            evidence_lineage=(), uncertainty=1.0, shadow={}, information_gaps=(),
            truncations=(), degradations=(),
        )


def test_the_export_walk_is_not_exponential_on_a_diamond() -> None:
    """S4-SEC-08: an unmemoised walk over 14 two-premise levels visits 2**14 paths."""
    digest = digest_of_bytes(b"leaf")
    rows = [_row("L0a", "OBS", digest=digest), _row("L0b", "OBS", digest=digest)]
    for level in range(1, 15):
        prev = (f"L{level - 1}a", f"L{level - 1}b")
        rows += [_row(f"L{level}a", "DER", prev), _row(f"L{level}b", "DER", prev)]
    graph = {"claims": rows, "authoritative": ["L14a"]}
    started = time.perf_counter()
    assert unsupported_authoritative_rows(graph) == ()
    assert time.perf_counter() - started < 1.0


# --- engine isolation: S4-FC-01, S4-FC-03, S4-MEAS-06 ----------------------------


def test_the_engine_arm_sees_an_engine_that_raises(
    replays: Any, visibility: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """S4-FC-01: G4.11 passed with every LucidEngine entry point replaced by a raiser."""
    from pocketsec.stage4.gate_optionality import engine_arm

    healthy = engine_arm(replays[:3], visibility)
    assert healthy.passed, healthy

    def broken(self: Any, *args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("engine is broken")

    monkeypatch.setattr(LucidEngine, "resolve", broken)
    result = engine_arm(replays[:3], visibility)
    assert result.escaped
    assert not result.passed


@pytest.mark.parametrize(
    ("module", "attribute"),
    [
        ("pocketsec.stage4.engine.lucid", "gaps_from"),
        ("pocketsec.stage4.engine.lucid", "uncertainty_of"),
        ("pocketsec.stage4.engine.lucid", "visibility_adjusted_verdict"),
        ("pocketsec.stage4.engine.lucid_bounds", "export_incident_world_record"),
    ],
)
def test_resolve_and_close_never_raise_on_the_formerly_unguarded_calls(
    replays: Any, visibility: Any, monkeypatch: pytest.MonkeyPatch, module: str, attribute: str
) -> None:
    """S4-FC-03: these four calls ran outside any guard, and the export retry re-raised."""
    import importlib

    def boom(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError(f"{attribute} failed")

    monkeypatch.setattr(importlib.import_module(module), attribute, boom)
    engine = _engine(visibility)
    field = _drive(engine, replays[0])
    resolution = engine.resolve(field)
    export = engine.close_incident(field)
    assert export.verdict in NON_COMMITTAL_VERDICTS
    assert export.degradations
    if attribute != "export_incident_world_record":
        assert resolution.prediction_verdict in NON_COMMITTAL_VERDICTS
        assert resolution.degraded


# --- the world bound: S4-FC-05, S4-RES-02 ----------------------------------------


def test_a_birth_refused_at_capacity_is_a_recorded_world_loss(
    replays: Any, visibility: Any
) -> None:
    """S4-FC-05 / S4-RES-02: FIELD_AT_CAPACITY was bound to ``_refusal`` and dropped."""
    engine = _engine(visibility, LucidConfig(max_worlds=1))
    losses = []
    for replay in replays:
        field = _drive(engine, replay)
        losses += [t for t in field.truncations if t.what == "world"]
        engine.close_incident(field)
    capacity = [t for t in losses if t.reason.startswith("field_at_capacity")]
    assert capacity, "no world-kind Truncation was written for a refused birth"
    assert all(math.isfinite(t.consequence_lost) for t in capacity)


# --- measurement honesty: S4-FC-08, S4-FC-10, S4-REV-02, S4-SEC-05, S4-SEC-07 -----


def test_inert_flags_default_off_and_are_not_scored_as_measured(
    corpus: Sequence[IncidentCase], monkeypatch: pytest.MonkeyPatch
) -> None:
    """S4-FC-08 / S4-CPLX-02: a structural 0.0 was reported as NOT_YET_JUSTIFIED."""
    import pocketsec.stage4.labs.experiments as experiments

    shipped = LucidConfig()
    assert all(getattr(shipped, flag) is False for flag in INERT_FLAGS)
    monkeypatch.setattr(experiments, "saturation_check", lambda _c: (False, "forced"))
    rows = {row.flag: row for row in experiments.run_ablation(corpus[:3], seed=CORPUS_SEED)}
    for flag in INERT_FLAGS:
        assert rows[flag].verdict == "INERT"
        assert "not-computed" in rows[flag].metric
    live = set(LucidConfig.flag_names()) - set(INERT_FLAGS)
    assert all(rows[flag].verdict != "INERT" for flag in live)


def test_the_resolved_field_carries_the_compiled_claim_graph(
    replays: Any, visibility: Any
) -> None:
    """S4-FC-10: ``claim_graph 142`` was the empty sentinel, measured as if it were real."""
    engine = _engine(visibility)
    field = _drive(engine, replays[0])
    resolution = engine.resolve(field)
    assert field.claim_graph is EMPTY_CLAIM_GRAPH
    assert resolution.field.claim_graph is resolution.claim_graph
    assert resolution.claim_graph.claims


def test_each_transition_enters_the_e_process_once(visibility: Any) -> None:
    """S4-REV-02: the cumulative observed set was re-applied on every transition.

    Two transitions seeing A then B must multiply in LR(A) * LR(B). The old code read
    ``state.observed`` (A, then A|B) and produced LR(A) * LR(A|B) — the evidence of A
    counted twice under an ``anytime_valid=True`` stamp.
    """
    from pocketsec.stage4.evidence.sequential import (
        SIGNAL_VOCABULARY,
        benign_null_likelihood_ratio,
    )

    vocabulary = sorted(SIGNAL_VOCABULARY)
    first, second = frozenset(vocabulary[:1]), frozenset(vocabulary[1:2])
    world = dataclasses.replace(
        _world("w-e", "compromised_admin_session", 0.0),
        expected_evidence=first | second,
        visibility_requirements=first | second,
    )
    field = _field(world)
    engine = _engine(visibility, LucidConfig(enable_sequential_evidence=True))
    state = IncidentState(EntropyBudget())
    for signals in (first, second):
        state.last_signals = signals
        state.observed |= signals
        lucid_steps.accumulate_evidence(engine, field, state)
    kwargs = {"expected": first | second, "forbidden": frozenset()}
    expected = benign_null_likelihood_ratio(sorted(first), **kwargs) * benign_null_likelihood_ratio(
        sorted(second), **kwargs
    )
    assert state.sequential["w-e"].e_value == pytest.approx(expected)


def test_a_malformed_engine_outcome_degrades_the_slot_instead_of_raising() -> None:
    """S4-SEC-05 / S4-FC-14: a NaN confidence escaped CBFSlot.predict as ContractError."""
    from test_stage4_optionality import _sequence  # type: ignore[import-not-found]

    from pocketsec.stage4.engine.degradation import DegradationLedger
    from pocketsec.stage4.slot import CBFSlot, EngineOutcome

    class _NaNEngine:
        def resolve(self, sequence: Any, *, ledger: DegradationLedger) -> EngineOutcome:
            return EngineOutcome(
                verdict=Verdict.MALICIOUS, confidence=float("nan"), novelty_score=0.1,
                uncertainty=0.2, identifiability="IDENTIFIED", compute_budget_units=1.0,
            )

    ledger = DegradationLedger()
    prediction = CBFSlot(engine=_NaNEngine(), ledger=ledger).predict(_sequence())
    assert prediction.abstained
    assert prediction.verdict in NON_COMMITTAL_VERDICTS
    assert ledger.count == 1


def test_one_observation_shared_by_three_worlds_is_one_contradiction() -> None:
    """S4-SEC-07: three OBS claims over ONE digest counted as three contradictions."""
    from pocketsec.stage4.crystal.feedback import MIN_CONTRADICTIONS_FOR_STRESS, stress_stage3_cell
    from pocketsec.stage4.crystal.handoff import CrystalKnowledge

    shared = digest_of_bytes(b"one-raw-event")
    graph = EMPTY_CLAIM_GRAPH
    for index in range(MIN_CONTRADICTIONS_FOR_STRESS):
        graph = graph.insert(
            ObservedClaim(
                claim_id=f"obs.w{index}.0", subject="evidence:e0", text="ebpf recorded evidence e0",
                evidence=(EvidenceRef(store="raw.ebpf", locator="e0", digest=shared),),
                sensor=SensorPath.EBPF, at_sequence=index,
            ),
            authoritative=True,
        )
    knowledge = CrystalKnowledge(
        handoff_id="handoff-1",
        handoff_digest=digest_of_bytes(b"h"),
        cells=({"cell_id": "cell-a"},),
        assurance=(),
        boundary_keys=(
            {"cell_id": "cell-a", "relation_family": 1, "actor_property_mask": 2,
             "state_delta_mask": 4},
        ),
        melt_history=(),
        encoder_version="enc-1",
    )
    signals = stress_stage3_cell(
        knowledge, graph, incident_ids=("inc-1",), entered_keys=((1, 2, 4),),
        contradicted_subjects=("evidence:e0",),
    )
    assert signals == ()
