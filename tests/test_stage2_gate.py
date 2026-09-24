"""The Stage 2 gate's own honesty properties.

Running `run_gate()` takes minutes — it compiles two corpus splits, runs the
drift corpus, the poison suite and the counterfactual probes — so it is not what
these tests do. They pin the properties that would let the gate lie: accepting
frontier evidence from a different split, reporting a skip the ledger cannot
prove, passing a criterion in a rejection branch whose mechanism is switched on,
or quietly importing research code into a runtime module.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage2 import gate, gate_evidence
from pocketsec.stage2.gate_criteria import (
    Adaptation,
    ConformalCoverage,
    _replace_candidate,
    adr_naming,
    rejects_unevidenced_candidates,
    research_imports,
)
from pocketsec.stage2.lattice.quantizer import BEHAVIOUR_QUANTIZER_ENABLED, DEFAULT_QUANTIZER
from pocketsec.stage2.predictors.future_cone import FUTURE_CONE_DEFAULT_ENABLED
from pocketsec.stage2.predictors.hazard import HAZARD_DEFAULT_ENABLED
from pocketsec.stage2.router.policy import ROUTER_DEFAULT_ENABLED

EVIDENCE = {
    "corpus": gate.GATE_CORPUS,
    "count": gate.GATE_COUNT,
    "seed": gate.TEST_SEED,
    "base_rate": 0.3333,
    "scores": {"phi-oracle": 1.0, "tcn": 1.0},
    "degenerate": True,
    "reason": "ORDER_FREE_BASELINE_TIES_BEST",
    "best": 1.0,
    "best_model": "phi-oracle",
    "median": 0.6586,
    "spread": 0.3414,
    "order_free_baseline": 1.0,
    "phi_oracle": 1.0,
    "pareto": {"verdict": "phi-oracle is cheapest at tied quality"},
    "measured_by": "test",
}


def _write(path: Path, payload: dict[str, object]) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _authentic(tmp_path: Path, **overrides: object) -> tuple[Path, str]:
    """A signed frontier file whose experiment id really is in a real registry."""
    from pocketsec.stage0.experiments.registry import ExperimentRegistry

    registry_path = tmp_path / "registry.jsonl"
    registry = ExperimentRegistry(registry_path)
    experiment_id = "PS-S2-20260925-H8-baseline-frontier-0019"
    registry.register(
        experiment_id=experiment_id,
        hypothesis="H8",
        title="baseline frontier",
        slot_name="frontier-ambiguous-60-11",
        dataset_name="ambiguous-60",
        dataset_version="v1",
        dataset_sha256="0" * 64,
        git_commit=None,
        seeds={"train": 3, "test": 11},
        synthetic_data=True,
        notes="fixture",
    )
    payload = dict(
        EVIDENCE,
        experiment_id=experiment_id,
        measured_by="pocketsec.stage2.research.cli:measure_frontier",
        **overrides,
    )
    signed = gate.FrontierEvidence.from_dict(payload).signed()
    path = _write(tmp_path / "frontier.json", signed.to_dict())
    return path, str(registry_path)


def test_frontier_evidence_round_trips() -> None:
    evidence = gate.FrontierEvidence.from_dict(EVIDENCE)
    assert gate.FrontierEvidence.from_dict(evidence.to_dict()) == evidence


def test_an_authentic_frontier_file_is_accepted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The guard must not refuse everything; the honest producer's output loads."""
    path, registry = _authentic(tmp_path)
    monkeypatch.setattr(gate_evidence, "REGISTRY_PATH", Path(registry))
    evidence, refusal = gate._load_frontier(path)
    assert refusal == ""
    assert evidence is not None
    assert evidence.experiment_id == "PS-S2-20260925-H8-baseline-frontier-0019"


def test_a_hand_written_frontier_file_cannot_flip_g2_1_and_g2_2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pins S2-AUTH-02.

    ``results/stage2-frontier.json`` is gitignored and decides G2.1, G2.2 and
    G2.12's degeneracy clause. Its only validation was that its
    (corpus, count, seed) triple matched, so a hand-written file — nine baselines
    at 0.99, ``pareto.dominated: []``, ``degenerate: false`` — flipped ADR-0010's
    rejected central result from FAIL to PASS, and the gate then printed the
    file's own ``measured_by`` string as provenance. No diff to review, no
    lineage to check, no privilege required.
    """
    forged = {
        **EVIDENCE,
        "scores": {name: 0.99 for name in ("a", "b", "c", "d", "e", "f", "g", "h", "i")},
        "degenerate": False,
        "pareto": {"verdict": "nothing is dominated", "dominated": []},
        "measured_by": "totally.legit:measure",
    }
    path = _write(tmp_path / "frontier.json", forged)
    evidence, refusal = gate._load_frontier(path)
    assert evidence is None, "an unsigned file must not be usable evidence"
    assert "content_digest" in refusal

    # Signed, but with no ledger lineage.
    signed = gate.FrontierEvidence.from_dict(forged).signed()
    path = _write(tmp_path / "frontier.json", signed.to_dict())
    evidence, refusal = gate._load_frontier(path)
    assert evidence is None and "experiment_id" in refusal

    # Signed and registered, but `measured_by` names no research producer.
    authentic, registry = _authentic(tmp_path, **{k: forged[k] for k in ("scores", "degenerate", "pareto")})
    monkeypatch.setattr(gate_evidence, "REGISTRY_PATH", Path(registry))
    tampered = gate.FrontierEvidence.from_dict(
        {**json.loads(authentic.read_text()), "measured_by": "totally.legit:measure"}
    )
    path = _write(tmp_path / "frontier.json", tampered.signed().to_dict())
    evidence, refusal = gate._load_frontier(path)
    assert evidence is None and "measured_by" in refusal


def test_editing_a_measured_frontier_file_breaks_its_own_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A stale run, a merge or a mistaken `cp` has to be visible."""
    path, registry = _authentic(tmp_path)
    monkeypatch.setattr(gate_evidence, "REGISTRY_PATH", Path(registry))
    assert gate._load_frontier(path)[0] is not None

    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["degenerate"] = False  # the one edit that flips G2.2
    _write(path, payload)
    evidence, refusal = gate._load_frontier(path)
    assert evidence is None
    assert "does not match its own digest" in refusal


def test_g2_1_detail_language_follows_its_verdict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pins S2-AUTH-02's second half.

    The G2.1 detail asserted unconditionally that "the learned core is beaten on
    cost by a zero-parameter scorer ... FAILED, not restated", so a PASSING check
    emitted a sentence contradicting its own verdict — and that sentence was the
    one line a reader would have used to spot a forged file.
    """

    class _Ctx:
        frontier_refusal = ""
        frontier = gate.FrontierEvidence.from_dict(
            dict(
                EVIDENCE,
                scores={
                    name: 0.9 for name in ("a", "b", "c", "d", "e", "f", "g", "h", "i")
                },
                pareto={"verdict": "nothing is dominated", "dominated": []},
            )
        )

    check = gate._baselines_and_pareto(_Ctx())
    assert check.passed is True
    assert "FAILED" not in check.detail, check.detail

    class _Dominated(_Ctx):
        frontier = gate.FrontierEvidence.from_dict(
            dict(
                EVIDENCE,
                scores={
                    name: 0.9 for name in ("a", "b", "c", "d", "e", "f", "g", "h", "i")
                },
                pareto={
                    "verdict": "phi-oracle is cheapest",
                    "dominated": [
                        {"name": "mlp-pooled", "dominated_by": ["phi-oracle"]}
                    ],
                },
            )
        )

    dominated = gate._baselines_and_pareto(_Dominated())
    assert dominated.passed is False
    assert "FAILED, not restated" in dominated.detail


def test_an_unmeasured_figure_stays_none_and_never_becomes_zero() -> None:
    """0.0 means "measured, and it was zero". None means nobody measured it."""
    payload = dict(EVIDENCE, best=None, median=None, spread=None, phi_oracle=None)
    evidence = gate.FrontierEvidence.from_dict(payload)
    assert evidence.best is None
    assert evidence.median is None
    assert evidence.phi_oracle is None
    assert gate_evidence._optional_float(0.0) == 0.0


def test_frontier_evidence_from_another_split_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A figure measured on a different (corpus, count, seed) answers another question.

    Spec section 0.1: the Φ-oracle's PR-AUC on this generator moves 0.4025 with
    sample count alone, so evidence from count=240 is not a weaker answer about
    count=60 — it is not an answer at all.
    """
    for wrong in ({"count": 240}, {"seed": 3}, {"corpus": "hard"}):
        path = _write(tmp_path / "frontier.json", dict(EVIDENCE, **wrong))
        evidence, refusal = gate._load_frontier(path)
        assert evidence is None
        assert "different question" in refusal or "refused" in refusal

    # The matching split loads, but only once it is signed and registered too:
    # the split check is one of four, not the only one (S2-AUTH-02).
    path, registry = _authentic(tmp_path)
    monkeypatch.setattr(gate_evidence, "REGISTRY_PATH", Path(registry))
    evidence, refusal = gate._load_frontier(path)
    assert evidence is not None and refusal == ""


def test_missing_or_unreadable_evidence_is_unmeasured_not_absent(tmp_path: Path) -> None:
    evidence, refusal = gate._load_frontier(tmp_path / "nothing.json")
    assert evidence is None
    assert "run `python -m pocketsec.stage2.research.cli frontier`" in refusal

    broken = tmp_path / "frontier.json"
    broken.write_text("{not json", encoding="utf-8")
    evidence, refusal = gate._load_frontier(broken)
    assert evidence is None and "unreadable" in refusal


def test_the_phantom_savings_check_refuses_a_fabricated_skip() -> None:
    """G2.10 says a bad number may pass but a fakeable one may not.

    So the gate fabricates exactly the ADR-0010 defect — a path reported skipped
    while the work ran — and requires the ledger to refuse it. Without this, the
    gate could not tell an honest ledger from a credulous one.
    """
    assert gate._phantom_check_refuses_a_fake() is True


def test_cheap_fraction_is_none_when_nothing_was_routed() -> None:
    from collections import Counter

    assert gate._cheap_fraction(Counter()) is None
    assert gate._cheap_fraction(Counter({"P0_COMPILED": 1, "P3_PREDICTIVE": 3})) == 0.25


def test_a_derived_cheap_path_is_unreachable_in_the_runtime_harness() -> None:
    """Pins S2-05 / S2-FC-06.

    G2.3's headline — "the ledger derived a cheap path for 0.0000 of events" —
    is a structural floor of the measurement harness, not a fact about the
    router. ``runtime_pass`` performs a WINDOW_UPDATE on every event before the
    cache is consulted, WINDOW_UPDATE derives P2_LOCAL (8.0 units), and
    ``_derive_path`` takes the max over performed work, so no event can derive
    P0/P1 however well the cache performs — a second pass over an already-warm
    cache resolving 100% of events from the cache still reports 0.0000.

    This pins the floor exhaustively: with a mandatory performed WINDOW_UPDATE,
    no combination of the other work kinds yields a cheap path.
    """
    import itertools

    from pocketsec.stage2.router.accounting import WorkKind, WorkLedger

    others = [k for k in WorkKind if k is not WorkKind.WINDOW_UPDATE]
    for size in range(len(others) + 1):
        for subset in itertools.combinations(others, size):
            ledger = WorkLedger()
            ledger.begin("e")
            ledger.record(WorkKind.WINDOW_UPDATE, performed=True, units=1.0)
            for kind in subset:
                # Skipped, i.e. the most favourable case a router could produce.
                ledger.record(kind, performed=False, units=0.0)
            account = ledger.close()
            assert account.path.value not in gate.CHEAP_PATHS, subset

    # And the figure G2.3 reports *instead* can discriminate: an account with
    # the inference genuinely skipped is counted, one that ran it is not.
    ledger = WorkLedger()
    for skipped in (True, False):
        ledger.begin(f"e-{skipped}")
        ledger.record(WorkKind.WINDOW_UPDATE, performed=True, units=1.0)
        if skipped:
            ledger.record(WorkKind.CORE_INFERENCE, performed=False, units=0.0)
        else:
            ledger.record(WorkKind.CORE_INFERENCE, performed=True, units=40.0)
        ledger.close()
    assert gate._skipped_inference_fraction(ledger) == 0.5
    assert gate._expensive_fraction({"P2_LOCAL": 1, "P3_PREDICTIVE": 3}) == 0.75


def test_every_rejected_mechanism_is_off_in_code_not_only_in_an_adr() -> None:
    """The rejection branches of G2.4 and G2.6 must be checkable without a document.

    ADR-0115 and ADR-0116 record the measurements; these constants are what the
    gate actually reads, because a gate that graded itself on prose would be the
    thing ADR-0113 exists to prevent.
    """
    assert BEHAVIOUR_QUANTIZER_ENABLED is False
    assert DEFAULT_QUANTIZER.__name__ == "HashBucketQuantizer"
    assert FUTURE_CONE_DEFAULT_ENABLED is False
    assert HAZARD_DEFAULT_ENABLED is False
    assert ROUTER_DEFAULT_ENABLED is False
    assert adr_naming("behaviour-atoms").startswith("0115-")
    assert adr_naming("future-cone").startswith("0116-")


def _coverage(**overrides: object) -> ConformalCoverage:
    fields: dict[str, object] = {
        "coverage": 0.9167,
        "radius": 0.75,
        "samples": 4297,
        "residuals": 1024,
        "observed": 4323,
        "evictions": 3299,
        "saturated": True,
    }
    fields.update(overrides)
    return ConformalCoverage(**fields)  # type: ignore[arg-type]


def test_g2_5_fails_on_a_perfectly_separable_split() -> None:
    """Pins S2-08.

    ``saturated = held_out.brier_score == 0.0`` was computed, printed as prose
    and never appended to ``failures``. G2.5 could therefore PASS on exactly the
    degenerate split G2.2 refuses the corpus for — the calibration_id, ECE and
    Brier clauses all succeed there — and only the separately defective conformal
    clause kept the aggregate honest. Repairing that clause (S2-04) would have
    flipped G2.5 to PASS while its own detail string still called the split
    degenerate.
    """
    failures = gate._calibration_failures(
        calibration_id="stage2-isotonic-b3e7216da733",
        refusal_reason="",
        ece=0.0,
        brier=0.0,
        conformal=_coverage(),
    )
    assert failures, "a Brier of exactly 0.0 is separability, not calibration"
    assert any("separates the split perfectly" in reason for reason in failures)


def test_g2_5_passes_only_on_a_split_that_is_not_degenerate() -> None:
    """The mirror of the above: the clause must not fail everything."""
    assert (
        gate._calibration_failures(
            calibration_id="stage2-isotonic-b3e7216da733",
            refusal_reason="",
            ece=0.02,
            brier=0.11,
            conformal=_coverage(),
        )
        == []
    )


def test_g2_5_quotes_the_reservoir_a_coverage_figure_came_from() -> None:
    """Pins S2-04's reporting half.

    ``conformal_coverage`` used to return only ``(coverage, radius, samples)``,
    discarding ``saturated()``/``evictions()`` — the very accessors
    ``SplitConformal`` exposes so that "a coverage number measured on a saturated
    reservoir can be recognised as one". The gate then attributed to the
    predictor's calibration a failure its own eviction policy produced.
    """
    out_of_band = _coverage(coverage=0.9793)
    failures = gate._calibration_failures(
        calibration_id="id",
        refusal_reason="",
        ece=0.02,
        brier=0.11,
        conformal=out_of_band,
    )
    assert len(failures) == 1
    assert "1024 of 4323 residuals" in failures[0]
    assert "saturated=True" in failures[0]


def test_a_probe_target_signature_is_never_a_causal_node_identity() -> None:
    """Pins S2-FC-01.

    G2.7, the REJECTED ``causal_credit`` ablation row and registry entry
    PS-S2-20260924-H8-causal-credit-0016 were all produced by a dict join that
    can never match: ``nodes`` is keyed by ``CausalNode.signature`` (a bare
    16-hex string) and the lookup key was ``probe.target_signature``, which
    ``_target_signature`` builds as ``lineage:index:rN:mM`` and whose own
    docstring calls "provenance for the probe itself, never an identity the
    ledger trusts". ``assign_causal_credit`` was therefore never called once,
    and the gate printed "no probe's divergence reached MATERIAL_DIVERGENCE"
    about a comparison that never ran.

    This pins the disjointness of the two key spaces, so the join can never be
    written that way again, and pins that the criterion now reads the real
    signatures index-aligned with the window's steps.
    """
    import inspect

    from pocketsec.stage2 import gate_criteria
    from pocketsec.stage2.counterfactual.twin import _target_signature
    from pocketsec.stage2.gate_measures import lineage_windows_with_signatures
    from pocketsec.stage2.research import stage2_report

    # The two key spaces are structurally disjoint: a locator always contains
    # ':', a causal signature is 16 hex characters and never does.
    from pocketsec.stage1.pipeline import Stage1Pipeline
    from pocketsec.stage2.labs.drift_corpus import build_drift_corpus

    scenario = build_drift_corpus(count=4, seed=gate.TEST_SEED)[0]
    result = Stage1Pipeline().run_scenario(scenario, offset=0)
    pairs = lineage_windows_with_signatures(result.transitions)
    assert pairs, "the fixture must produce at least one lineage window"
    for window, signatures in pairs:
        assert len(signatures) == len(window.steps)
        for index, step in enumerate(window.steps):
            locator = _target_signature(window, step, index)
            assert ":" in locator
            assert ":" not in signatures[index]
            assert locator != signatures[index]

    # And neither measuring site may look a node up by the locator again.
    for source in (
        inspect.getsource(gate_criteria._attribute_one_session),
        inspect.getsource(stage2_report._attribute_one),
    ):
        assert "nodes.get(probe.target_signature)" not in source
        assert "nodes.get(signatures[index])" in source


def _registry_with(tmp_path: Path, rows: list[tuple[str, str, str]]) -> Path:
    """A real, digest-chained registry holding exactly ``rows``."""
    from pocketsec.stage0.experiments.registry import ExperimentRegistry

    path = tmp_path / "registry.jsonl"
    registry = ExperimentRegistry(path)
    for experiment_id, slot_name, notes in rows:
        registry.register(
            experiment_id=experiment_id,
            hypothesis="H8",
            title=slot_name,
            slot_name=slot_name,
            dataset_name="ambiguous-60",
            dataset_version="v1",
            dataset_sha256="0" * 64,
            git_commit=None,
            seeds={"train": 3, "test": 11},
            synthetic_data=True,
            notes=notes,
        )
    return path


def test_g2_12_is_not_satisfiable_by_appending_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pins S2-AUTH-09 and S2-FC-02.

    ``passed`` was ``len(this_wave) >= len(optional)`` — two integers, with
    nothing joining a registered experiment to a component and nothing reading
    what any of them measured. Appending twelve rows about anything at all,
    including twelve reruns of one ablation or twelve about components already
    REJECTED, flipped the criterion to PASS while leaving every OPTIONAL core id
    exactly as unjustified as before. The registry's append-only digest chain
    does not help: appending is a supported operation, and only *editing*
    history breaks the chain.
    """
    padding = [
        (
            f"PS-S2-20260925-H8-padding-{n:04d}",
            "behaviour_atom_quantizer",
            "REJECTED: with 3.5881 vs without 1.846 (delta -1.742).",
        )
        for n in range(7, 27)
    ]
    monkeypatch.setattr(gate_evidence, "REGISTRY_PATH", _registry_with(tmp_path, padding))

    class _Ctx:
        frontier = gate.FrontierEvidence.from_dict(dict(EVIDENCE, degenerate=False))

    check = gate._components_ablation_supported(_Ctx())
    assert check.passed is False, check.detail
    assert "0/12" in check.detail
    # Twenty rows, zero support. The old check passed at twelve.
    assert "20 are from this wave" in check.detail


def test_g2_12_evaluates_the_degeneracy_clause_its_detail_calls_independent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pins S2-FC-02's second half.

    The detail string declared the degeneracy of the measured split "an
    independent failure reason" while ``passed`` never looked at it.
    """
    optional = [
        core_id
        for core_id, function in gate.CORE_IDS.items()
        if function.function_class.value == "OPTIONAL"
    ]
    # DTL-F09 (score_prediction_residual) and DTL-F12
    # (request_observation_escalation) have NO ablation slot at all — the
    # research report never measures them — so with the real table the criterion
    # can never reach its pass branch and this test could not tell the
    # degeneracy term from the support term. Two fixture slots are added here to
    # make the pass branch reachable; the real gap is reported by G2.12 itself
    # and recorded in the findings.
    slots = dict(gate.ABLATION_SLOTS)
    slots["residual_head"] = ("DTL-F09",)
    slots["value_of_information"] = ("DTL-F12",)
    monkeypatch.setattr(gate, "ABLATION_SLOTS", slots)
    covering = [
        (
            f"PS-S2-20260925-H8-slot-{n:04d}",
            slot,
            "JUSTIFIED: with 1.0 vs without 0.5 (delta 0.5).",
        )
        for n, slot in enumerate(sorted(slots), start=7)
    ]
    monkeypatch.setattr(gate_evidence, "REGISTRY_PATH", _registry_with(tmp_path, covering))

    class _Degenerate:
        frontier = gate.FrontierEvidence.from_dict(EVIDENCE)  # degenerate=True

    class _Clean:
        frontier = gate.FrontierEvidence.from_dict(dict(EVIDENCE, degenerate=False))

    assert set(optional) <= set(
        core_id for slot in slots for core_id in slots[slot]
    ), "a JUSTIFIED row for every slot must cover every OPTIONAL id, or this is vacuous"
    assert gate._components_ablation_supported(_Clean()).passed is True
    assert gate._components_ablation_supported(_Degenerate()).passed is False


def test_a_rejected_row_never_counts_as_ablation_support(tmp_path: Path) -> None:
    """REJECTED and NOT_YET_JUSTIFIED are failures, never pending."""
    from pocketsec.stage0.experiments.registry import ExperimentRegistry

    path = _registry_with(
        tmp_path,
        [
            ("PS-S2-20260925-H8-a-0007", "future_cone", "JUSTIFIED: delta 0.31."),
            ("PS-S2-20260925-H8-b-0008", "hazard_heads", "REJECTED: delta -0.08."),
            (
                "PS-S2-20260925-H8-c-0009",
                "transition_cache",
                "NOT_YET_JUSTIFIED: delta 0.0.",
            ),
            # Sequence 0006 is the previous wave and must not count either.
            ("PS-S2-20260925-H8-d-0006", "merge_fission", "JUSTIFIED: delta 1.0."),
        ],
    )
    supported = gate._ablation_support(tuple(ExperimentRegistry(path).all()))
    assert supported == {"DTL-F05"}


def test_the_stage3_seam_holds_by_ast() -> None:
    """Nothing under compile_candidates/ may import research code."""
    assert research_imports(gate._CANDIDATE_PACKAGE) == []


def test_a_candidate_without_evidence_or_a_parseable_id_is_rejectable(tmp_path: Path) -> None:
    from pocketsec.stage0.contracts.common import EvidenceRef
    from pocketsec.stage2.compile_candidates.candidate import CandidateStability, MeasuredCost
    from pocketsec.stage2.compile_candidates.phi_oracle_candidate import phi_oracle_candidate

    candidate = phi_oracle_candidate(
        cost=MeasuredCost(
            microseconds_per_event=0.0,
            parameters=0,
            bytes_on_disk=128,
            peak_rss_bytes=None,
            measured_by="tests:test_stage2_gate",
        ),
        experiment_id="PS-S2-20260925-H8-stage2-gate-0007",
        evidence=(
            EvidenceRef(store="s", locator="l", digest="sha256:" + "0" * 64),
        ),
        stability=CandidateStability(
            observations=16,
            distinct_epochs=2,
            reruns_agreeing=2,
            reruns_total=2,
            drift_invalidations=0,
        ),
        epochs=(0, 1),
    )
    # Nothing to report: both malformed variants raised, as the schema requires.
    assert rejects_unevidenced_candidates(candidate) == []
    with pytest.raises(ContractError):
        _replace_candidate(candidate, evidence_lineage=())


def test_run_gate_reports_exactly_the_thirteen_criteria() -> None:
    """Thirteen criteria, in the order the architecture gate lists them.

    Read from the source rather than by running the gate: the point is that no
    criterion was dropped or duplicated, and that is a property of the wiring.
    """
    source = Path(gate.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    run = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "run_gate"
    )
    calls = [
        node.func.id
        for node in ast.walk(run)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    ]
    checks = [name for name in calls if name.startswith("_")]
    assert len(checks) == 13, checks
    assert len(set(checks)) == 13, "a criterion is wired in twice"

    ids = sorted(
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value.startswith("G2.")
        and len(node.value) <= 5
    )
    assert sorted(set(ids), key=lambda name: int(name[3:])) == [
        f"G2.{n}" for n in range(1, 14)
    ]


def test_adaptation_exposes_refusal_reasons_not_only_counts() -> None:
    """G2.9 needs to know *why* a promotion was refused, not just how many were."""
    assert hasattr(Adaptation, "refusal_reasons")
    assert hasattr(Adaptation, "frequency_alone_refused")


def test_the_cli_exits_non_zero_when_the_frontier_is_unmeasured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from pocketsec.stage2 import cli

    monkeypatch.setattr(gate_evidence, "FRONTIER_PATH", tmp_path / "absent.json")
    assert cli.main(["frontier"]) == 1
    assert "UNMEASURED" in capsys.readouterr().err
