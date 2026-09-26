"""Stage 6 endurance package: D6.20 harness, §4.15 poisoning arms, §7 baselines, §4.20 E1-E5.

Every test is named for the invariant it protects. The ones that matter most:

* the corpus cannot leak ground truth or reuse a lineage (integration plan §5.4);
* every learner is fed byte-identical input, so a difference is the mechanism;
* every poisoning arm fires, and on at least one arm the naive control is really
  poisoned — a defence never attacked is a docstring;
* the preconditions answer BLOCKED / DEGENERATE, never a number, when the corpus
  cannot support the claim (a saturated and a blinded mini-corpus prove both);
* Rule C: an ablation row whose mechanism never fired is INERT, never evidence;
* the harness never writes the experiment registry and never touches TrustedMind.

The fixtures are deliberately small (8 sessions a month, 2 eval sessions a class);
the 60-month run is marked ``slow``. Every figure these tests see is synthetic.
"""

from __future__ import annotations

import ast
import dataclasses
import statistics
from collections import Counter
from functools import cache
from pathlib import Path

import pytest

from pocketsec.stage0.contracts.threat_prediction_v1 import Verdict
from pocketsec.stage1.epoch.model import EpochDecision, SystemIdentity
from pocketsec.stage6.capsule.experience_capsule import (
    CapsuleKind,
    ExperienceCapsuleV1,
    LabelOrigin,
)
from pocketsec.stage6.constitution.learning import MIN_INDEPENDENT_GROUPS
from pocketsec.stage6.labs import continual_baselines as baselines_module
from pocketsec.stage6.labs import endurance as endurance_module
from pocketsec.stage6.labs.continual_baselines import (
    AcceptNothing,
    FullRetrain,
    NaiveFinetune,
    NeverUpdate,
    ReservoirReplay,
    oracle_detectors,
)
from pocketsec.stage6.labs.endurance import (
    STORE_CAPS,
    VERDICTS,
    MonthCheckpoint,
    PreconditionReport,
    StageSixConfig,
    StageSixLearner,
    check_preconditions,
    run_ablation,
    run_endurance,
    store_violations,
)
from pocketsec.stage6.labs.endurance_corpus import (
    ENDURANCE_NAMESPACE,
    FAMILIES,
    TWINS,
    CompiledTimeline,
    Month,
    build_endurance_timeline,
    build_year_timeline,
    compile_timeline,
)
from pocketsec.stage6.labs.poison_suite import (
    POISON_ARMS6,
    PoisonClass,
    arm_verdicts,
    build_poison_arm,
    run_arm,
    simulated_teacher_labels,
)
from pocketsec.stage6.memory.episodic import skeleton_from_capsule
from pocketsec.stage6.memory.semantic import GENESIS_CANDIDATE_ID, context_id_for, match_motif

REPO = Path(__file__).resolve().parents[1]
LABS = REPO / "pocketsec" / "stage6" / "labs"
SMALL = {"sessions_per_month": 8, "eval_per_family": 2}


@cache
def _timeline() -> tuple:
    return build_endurance_timeline(**SMALL)


@cache
def _compiled() -> CompiledTimeline:
    return compile_timeline(_timeline())


@cache
def _preconditions() -> PreconditionReport:
    return check_preconditions(_compiled())


def _episodes(compiled: CompiledTimeline) -> list[ExperienceCapsuleV1]:
    return [e.capsule for m in compiled.months for e in m.events
            if e.capsule is not None and e.capsule.kind is CapsuleKind.TRANSITION_EPISODE]


# --- the corpus -----------------------------------------------------------------------


def test_timeline_has_twelve_months_with_corroborated_m02_and_m06_signals() -> None:
    plans = _timeline()
    assert [p.month for p in plans] == [int(m) for m in Month]
    for month in (Month.M02, Month.M06):
        signal = plans[month - 1].signal
        assert signal is not None and signal.changed and signal.corroborated == signal.changed
    assert context_id_for(plans[Month.M06 - 1].identity) == context_id_for(
        plans[Month.M01 - 1].identity
    )
    assert context_id_for(plans[Month.M02 - 1].identity) != context_id_for(
        plans[Month.M01 - 1].identity
    )
    assert plans[Month.M11 - 1].pressure and not any(
        p.pressure for p in plans if p.month != Month.M11
    )
    compiled = _compiled()
    epochs = {m.month: [e.decision for e in m.events if e.kind == "epoch"] for m in compiled.months}
    assert all(d is not None and d.transitioned for d in epochs[Month.M02] + epochs[Month.M06])
    assert compiled.months[Month.M06 - 1].context_id == compiled.months[Month.M01 - 1].context_id


def test_session_identities_are_unique_across_the_whole_timeline() -> None:
    owner: dict[tuple[str, str], str] = {}
    for plan in _timeline():
        for session in (*plan.sessions, *plan.eval_sessions):
            pairs = {(b.fields["pid"], b.fields["start_time"]) for b in session.scenario.behaviours}
            for pair in pairs:
                assert owner.setdefault(pair, session.session_id) == session.session_id, pair
                assert int(pair[0]) >= ENDURANCE_NAMESPACE  # disjoint from Stage 2's namespaces


def test_median_per_class_delta_phi_is_nonzero_for_both_classes() -> None:
    per_class: dict[int, list[float]] = {0: [], 1: []}
    for month in _compiled().months:
        for family, steps in zip(month.eval_families, month.eval_steps, strict=True):
            per_class[int(family in FAMILIES)].append(sum(max(0.0, s.delta_phi) for s in steps))
    assert statistics.median(per_class[1]) > 0.0 and statistics.median(per_class[0]) > 0.0


def test_ground_truth_never_reaches_a_behaviour_field() -> None:
    words = {*FAMILIES, *TWINS, "attack", "twin", "poison", "routine", "eval", "analyst", "mallory"}
    for plan in _timeline():
        for session in (*plan.sessions, *plan.eval_sessions):
            for behaviour in session.scenario.behaviours:
                for value in behaviour.fields.values():
                    assert not any(
                        word in str(value).split("/") or word == value for word in words
                    ), value
                    assert "attack" not in str(value) and "poison" not in str(value)


def test_skeletons_are_never_byte_truncated_and_agree_with_scoring_on_oracle_motifs() -> None:
    # Lesson 2: a skeleton cut at MAX_SKELETON_BYTES drops the later steps that make
    # a benign session match a 2-step motif, so induce_motifs measures precision on
    # a representation the score never uses (measured on 35-step sessions: every
    # learner at recall 0.0). The corpus is sized so the byte cap never binds. The
    # skeleton's own same-actor/same-key de-duplication still applies (reported).
    oracle = oracle_detectors(_timeline()).detectors()
    for capsule in _episodes(_compiled()):
        skeleton = skeleton_from_capsule(
            capsule, verdict=Verdict.BENIGN, label_origin=LabelOrigin.NONE
        )
        assert not skeleton.truncated
        for item in oracle:
            assert match_motif(item.motif, skeleton.steps) == match_motif(item.motif, capsule.steps)


def test_twins_enter_the_eval_negatives_only_from_their_intro_month() -> None:
    months = _compiled().months
    assert "T3" not in months[Month.M08 - 1].eval_families and "T3" in months[
        Month.M09 - 1
    ].eval_families
    assert "T2" not in months[Month.M04 - 1].eval_families and "T2" in months[
        Month.M05 - 1
    ].eval_families
    assert all(set(FAMILIES) <= set(m.eval_families) for m in months)


def test_corpus_builders_reject_invalid_arguments() -> None:
    with pytest.raises(ValueError):
        build_endurance_timeline(months=0)
    with pytest.raises(ValueError):
        build_endurance_timeline(months=13)
    with pytest.raises(ValueError):
        build_endurance_timeline(sessions_per_month=7)
    with pytest.raises(ValueError):
        build_year_timeline(cycles=0)
    with pytest.raises(ValueError):
        compile_timeline(())


def test_compilation_is_deterministic() -> None:
    first = compile_timeline(build_endurance_timeline(months=2, **SMALL))
    second = compile_timeline(build_endurance_timeline(months=2, **SMALL))
    assert [c.digest() for c in _episodes(first)] == [c.digest() for c in _episodes(second)]


# --- every learner sees the same input ------------------------------------------------


class _Recorder(NeverUpdate):
    def __init__(self, identity: SystemIdentity, name: str) -> None:
        super().__init__(identity, name=name)
        self.seen: list[tuple[str, str, int]] = []

    def observe(self, capsule: ExperienceCapsuleV1, *, sequence: int) -> None:
        self.seen.append(("capsule", capsule.digest(), sequence))
        super().observe(capsule, sequence=sequence)

    def on_epoch(self, decision: EpochDecision, identity: SystemIdentity, *, sequence: int) -> None:
        self.seen.append(("epoch", repr((decision, identity)), sequence))
        super().on_epoch(decision, identity, sequence=sequence)


def test_every_learner_receives_a_byte_identical_stream() -> None:
    compiled = _compiled()
    a, b = _Recorder(compiled.genesis, "rec-a"), _Recorder(compiled.genesis, "rec-b")
    report = run_endurance(compiled, [a, b])
    assert a.seen and a.seen == b.seen
    assert len(report.checkpoints) == 2 * len(compiled.months) and report.synthetic is True


def test_run_endurance_never_writes_the_experiment_registry() -> None:
    registry = REPO / "experiments" / "registry.jsonl"
    before = registry.read_bytes() if registry.exists() else None
    run_endurance(_compiled(), [NeverUpdate(_compiled().genesis)])
    assert (registry.read_bytes() if registry.exists() else None) == before
    for name in (
        "endurance.py", "endurance_corpus.py", "poison_suite.py", "continual_baselines.py"
    ):
        # a docstring may say "never"; a code string naming the file is a path it could open
        assert not _code_strings_naming(LABS / name, "registry.jsonl"), name


def _code_strings_naming(path: Path, word: str) -> list[str]:
    """String constants that mention ``word`` outside docstrings (a path the code could open)."""
    tree = ast.parse(path.read_text())
    docstrings = {
        id(node.body[0].value) for node in ast.walk(tree)
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef) and node.body
        and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant)
    }
    return [n.value for n in ast.walk(tree)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)
            and word in n.value and id(n) not in docstrings]


# --- E1-E5 --------------------------------------------------------------------------


def test_preconditions_on_the_endurance_corpus_report_booleans_not_numbers() -> None:
    report = _preconditions()
    assert report.expressible is True  # E1: the oracle expresses every family
    assert report.saturated is False  # E2: the twins keep every zero-learning control below 0.9
    assert report.vocabulary_leak is False  # E5: a bag of relations sees nothing
    assert report.verdict in {"OK", "DEGENERATE", "BLOCKED", "UNMEASURED"}
    assert all(isinstance(v, bool | None) for v in dataclasses.astuple(report)[:5])


def test_removing_the_twins_saturates_the_corpus_and_the_verdict_is_degenerate() -> None:
    def strip(month):  # noqa: ANN001, ANN202
        keep = [i for i, f in enumerate(month.eval_families) if f not in TWINS]
        return dataclasses.replace(month, eval_families=tuple(month.eval_families[i] for i in keep),
                                   eval_steps=tuple(month.eval_steps[i] for i in keep))

    compiled = _compiled()
    report = check_preconditions(
        dataclasses.replace(compiled, months=tuple(strip(m) for m in compiled.months))
    )
    assert report.saturated is True and report.verdict == "DEGENERATE"


def test_an_inexpressible_family_blocks_every_learner_result() -> None:
    def blind(month):  # noqa: ANN001, ANN202
        routine = next(
            s for f, s in zip(month.eval_families, month.eval_steps, strict=True) if f is None
        )
        pairs = zip(month.eval_families, month.eval_steps, strict=True)
        return dataclasses.replace(
            month, eval_steps=tuple(routine if f == "F1" else s for f, s in pairs)
        )

    compiled = _compiled()
    report = check_preconditions(
        dataclasses.replace(compiled, months=tuple(blind(m) for m in compiled.months))
    )
    assert report.expressible is False and report.verdict == "BLOCKED"


def test_precondition_verdict_orders_blocked_before_degenerate_before_unmeasured() -> None:
    ok = PreconditionReport(True, False, True, True, False, ())
    assert ok.verdict == "OK"
    assert dataclasses.replace(ok, expressible=False, saturated=True).verdict == "BLOCKED"
    assert dataclasses.replace(ok, forgetting_pressure=False).verdict == "DEGENERATE"
    assert dataclasses.replace(ok, vocabulary_leak=True).verdict == "DEGENERATE"
    assert dataclasses.replace(ok, acquisition_need=None).verdict == "UNMEASURED"


def test_oracle_items_cite_their_definition_never_genesis() -> None:
    state = oracle_detectors(_timeline())
    assert len(state.detectors()) == len(FAMILIES)
    for item in state.detectors():
        assert item.lineage.candidate_id != GENESIS_CANDIDATE_ID
        assert item.lineage.capsule_ids and all(
            d.startswith("sha256:") for d in item.lineage.evidence_digests
        )


# --- the baselines ------------------------------------------------------------------


def test_baseline_capacity_is_validated_and_fifo_eviction_is_counted() -> None:
    genesis = _compiled().genesis
    for bad in (0, 65):
        with pytest.raises(ValueError):
            NaiveFinetune(genesis, detector_capacity=bad)
    with pytest.raises(ValueError):
        ReservoirReplay(genesis, budget_bytes=0)
    tight = NaiveFinetune(genesis, detector_capacity=1)
    run_endurance(_compiled(), [tight])
    assert len(tight.trusted_state().detectors()) <= 1 and tight.counters["evicted"] > 0


def test_naive_finetune_takes_an_uncorroborated_change_as_an_epoch_never_update_does_not() -> None:
    scenario = build_poison_arm("P5", multiplier=1, seed=11, background=8)
    naive = run_arm(scenario, NaiveFinetune(scenario.genesis))
    frozen = run_arm(scenario, NeverUpdate(scenario.genesis))
    assert scenario.poisoned_signals > 0
    assert naive.poisoned_promotions and naive.poisoned_promotions > 0
    assert frozen.poisoned_promotions == 0


def test_reservoir_stays_within_its_byte_budget_and_full_retrain_stores_more() -> None:
    compiled = _compiled()
    reservoir = ReservoirReplay(compiled.genesis, budget_bytes=16384)
    full = FullRetrain(compiled.genesis)
    run_endurance(compiled, [reservoir, full])
    assert reservoir._extra_bytes() <= 16384
    assert full.cost().stored_bytes > reservoir.cost().stored_bytes - reservoir._extra_bytes()


def _names_in(path: Path) -> set[str]:
    tree = ast.parse(path.read_text())
    return ({n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
            | {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
            | {a.name for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) for a in n.names})


def test_baselines_never_touch_trusted_mind_and_no_lab_names_the_private_installer() -> None:
    assert not {"TrustedMind", "LearningPromotionController", "_install_trusted"} & _names_in(
        Path(baselines_module.__file__))
    for path in LABS.glob("*.py"):
        assert "_install_trusted" not in _names_in(path), path.name


# --- the Stage 6 learner --------------------------------------------------------------


def test_stage_six_learner_refuses_knobs_the_subsystems_cannot_honour() -> None:
    genesis = _compiled().genesis
    with pytest.raises(ValueError, match="detector_capacity"):
        StageSixLearner(genesis, config=StageSixConfig(detector_capacity=4))
    with pytest.raises(ValueError, match="G4"):
        StageSixLearner(genesis, config=StageSixConfig(counterfactual_variants=False))


def test_raw_telemetry_never_moves_the_stage_six_digest_between_consolidations() -> None:
    compiled = _compiled()
    learner = StageSixLearner(compiled.genesis)
    before = learner.trusted_digest()
    for event in compiled.months[0].events:
        if event.capsule is not None:
            learner.observe(event.capsule, sequence=event.sequence)
            assert learner.trusted_digest() == before  # observe() quarantines; it never installs


def test_the_drift_window_holds_verdicts_from_before_its_pivot(monkeypatch) -> None:
    """Review F1: the HEL-F19 window used to start empty at the pivot, so every key was
    "changed" and every corroborated change was classed POISON_SUSPECT by construction."""
    from pocketsec.stage6.labs import endurance as endurance_module

    seen: list[tuple[int, int]] = []
    real = endurance_module.drift_signals

    def spy(window, *, decision, decision_sequence):  # noqa: ANN001, ANN202
        seen.append((sum(v.sequence <= decision_sequence for v in window),
                     sum(v.sequence > decision_sequence for v in window)))
        return real(window, decision=decision, decision_sequence=decision_sequence)

    monkeypatch.setattr(endurance_module, "drift_signals", spy)
    run_endurance(_compiled(), [StageSixLearner(_compiled().genesis, name="drift-spy")])
    assert seen, "no corroborated change reached the discriminator"
    assert all(before >= 1 for before, _ in seen), seen


def test_labelled_poison_episodes_are_poison_ids_and_removals_are_counted() -> None:
    """Review F2: a label-flip poison session's EPISODE id is a poison id too (items learned
    from it may cite only the episode), and a detector removed right after a poison capsule
    is counted as a poisoning event, not invisible to an additions-only metric."""
    compiled = compile_timeline(build_endurance_timeline(**SMALL))
    episodes = {e.capsule.capsule_id for m in compiled.months for e in m.events
                if e.capsule is not None and e.capsule.kind is CapsuleKind.TRANSITION_EPISODE}
    labels = {e.capsule.label.target_capsule_id for m in compiled.months for e in m.events
              if e.capsule is not None and e.capsule.capsule_id in compiled.poison_ids
              and e.capsule.kind is CapsuleKind.LABEL_ASSERTION}
    assert labels, "the corpus has no label-flip poison"
    assert labels <= compiled.poison_ids & episodes


def test_the_tracker_counts_a_threshold_change_and_a_poison_removal() -> None:
    """Review F3 + F2: a threshold-only promotion keeps its item id, so an id-only tracker
    counted 0 promotions; a removal after a poison capsule was not counted at all."""
    from pocketsec.stage6.labs.endurance import _Tracker
    from pocketsec.stage6.labs.continual_baselines import oracle_detectors

    class _Fixed:
        def __init__(self, state) -> None:  # noqa: ANN001
            self.state = state

        def trusted_state(self):  # noqa: ANN202
            return self.state

    genesis = _compiled().genesis
    learner = _Fixed(oracle_detectors([_Plan(genesis)]))
    tracker = _Tracker(learner, frozenset({"cap-poison"}))  # type: ignore[arg-type]
    learner.state = learner.state.with_changes(threshold=0.99)
    tracker.update()
    victim = learner.state.detectors()[0].item_id
    learner.state = learner.state.with_changes(remove=(victim,))
    tracker.update(after_poison=True)
    promoted, poisoned, removed, poison_removed = tracker.take()
    assert promoted == 1 and poisoned == 0 and removed == 1 and poison_removed == 1


class _Plan:
    """The one field ``oracle_detectors`` reads from a timeline plan."""

    def __init__(self, identity) -> None:  # noqa: ANN001
        self.identity = identity


@cache
def _stage_six_report() -> tuple[StageSixLearner, tuple[MonthCheckpoint, ...]]:
    learner = StageSixLearner(_compiled().genesis)
    return learner, run_endurance(_compiled(), [learner]).checkpoints


def test_stage_six_stores_stay_within_their_caps_every_month() -> None:
    learner, checkpoints = _stage_six_report()
    assert set(checkpoints[0].store_bytes) == set(STORE_CAPS)
    assert all(store_violations(c) == () for c in checkpoints)
    assert learner.counters["ring_seen"] > 0


def test_store_violations_catches_an_overgrown_or_undeclared_store() -> None:
    checkpoint = _stage_six_report()[1][-1]
    grown = dict(checkpoint.store_counts, replay_ring=STORE_CAPS["replay_ring"][1] + 1)
    assert any(
        "replay_ring" in v for v in store_violations(
            dataclasses.replace(checkpoint, store_counts=grown)
        )
    )
    extra = dict(checkpoint.store_bytes, mystery=1)
    assert store_violations(dataclasses.replace(checkpoint, store_bytes=extra)) == (
        "mystery: no cap declared",
    )


def test_dropped_consolidation_candidates_and_the_episode_book_are_reported() -> None:
    """S6-R8 / S6-R5: a consolidation candidate built, lineage-recorded and issued, then not
    submitted (ring too short) was dropped without a counter; the episode book (up to 256
    full capsules) was held but never reported by stores()."""
    learner, checkpoints = _stage_six_report()
    assert learner.counters["consolidation_candidate_dropped_short_ring"] > 0
    assert checkpoints[-1].store_counts["episode_book"] > 0
    assert checkpoints[-1].store_bytes["episode_book"] > 0


def test_stores_sharing_one_budget_are_checked_together() -> None:
    """S6-R9: gateway and ledger were each capped at the whole quarantine-metadata budget,
    so 2 x 10 MiB passed while exceeding the one 15 MiB budget they share."""
    checkpoint = _stage_six_report()[1][-1]
    ten = 10 * 1024 * 1024
    shared = dict(checkpoint.store_bytes, gateway=ten, ledger=ten)
    problems = store_violations(dataclasses.replace(checkpoint, store_bytes=shared))
    assert any(p.startswith("quarantine_metadata") for p in problems), problems


# --- poisoning ------------------------------------------------------------------------


@cache
def _arm(arm_id: str):  # noqa: ANN202
    return build_poison_arm(arm_id, multiplier=1, seed=11, background=8)


@pytest.mark.parametrize("arm_id", [a.arm_id for a in POISON_ARMS6])
def test_every_poison_arm_fires(arm_id: str) -> None:
    scenario = _arm(arm_id)
    assert scenario.poisoned_offered > 0
    offered = {e.capsule.capsule_id for e in scenario.events if e.capsule is not None}
    if scenario.arm.poison_class is PoisonClass.MODEL and arm_id != "P4c":
        # P4a/P4b poison an artefact: the capsules whose learning produces it are offered clean
        assert {c.capsule_id for c in scenario.poisoned} <= offered
    else:
        assert any(e.poisoned for e in scenario.events) or scenario.poisoned_signals > 0


def test_the_suite_covers_every_poison_class_with_eleven_arms() -> None:
    assert [a.arm_id for a in POISON_ARMS6] == [
        "P1", "P1b", "P2", "P2b", "P3", "P3b", "P4a", "P4b", "P4c", "P5", "P6"]
    assert {a.poison_class for a in POISON_ARMS6} == set(PoisonClass)


def test_fork_spray_uses_more_lineages_than_the_independence_quorum() -> None:
    groups = {s.source_group for c in _arm("P1b").poisoned for s in c.steps}
    assert len(groups) >= MIN_INDEPENDENT_GROUPS + 1
    assert len({s.source_group for c in _arm("P1").poisoned for s in c.steps}) < len(groups)


def test_label_poison_really_poisons_the_naive_control_and_accept_nothing_is_vacuous() -> None:
    scenario = _arm("P3")
    naive = run_arm(scenario, NaiveFinetune(scenario.genesis))
    nothing = run_arm(scenario, AcceptNothing(scenario.genesis))
    assert naive.poisoned_promotions and naive.poisoned_promotions > 0  # the attack is real
    assert nothing.poisoned_promotions is None and nothing.detail.startswith("VACUOUS")


def test_build_poison_arm_rejects_invalid_input() -> None:
    with pytest.raises(ValueError):
        build_poison_arm("P9", multiplier=1, seed=11)
    with pytest.raises(ValueError):
        build_poison_arm("P1", multiplier=0, seed=11)
    with pytest.raises(ValueError):
        build_poison_arm("P1", multiplier=1, seed=11, background=3)


def test_simulated_teacher_is_systematically_wrong_only_where_it_is_told_to_be() -> None:
    sessions = [s for p in _timeline()[:1] for s in p.sessions]
    with pytest.raises(ValueError):
        simulated_teacher_labels(sessions, error_share=1.5, seed=1)
    wrong = simulated_teacher_labels(sessions, error_share=1.0, seed=1)
    right = simulated_teacher_labels(sessions, error_share=0.0, seed=1)
    assert all(
        label.origin is LabelOrigin.TEACHER and label.target_capsule_id == "" for label in wrong
    )
    for session, bad, good in zip(sessions, wrong, right, strict=True):
        assert good.verdict is (Verdict.MALICIOUS if session.family in FAMILIES else Verdict.BENIGN)
        assert bad.verdict is (Verdict.BENIGN if session.family in ("F1", "F2") else good.verdict)


def test_arm_verdicts_never_call_a_stage_six_that_learned_nothing_a_defence() -> None:
    from pocketsec.stage6.labs.poison_suite import PoisonRow

    def row(learner: str, poisoned: int | None, clean: int, offered: int = 3) -> PoisonRow:
        return PoisonRow(
            "P1", "DATA", learner, 1, offered, poisoned, None, clean, 0.0 if not clean else 1.0
        )

    def verdict(*rows: PoisonRow) -> str:
        return arm_verdicts(list(rows))["P1"]

    naive_real, six_clean = row("naive-finetune", 2, 1), row("stage6", 0, 1)
    assert verdict(row("naive-finetune", 0, 1), six_clean).startswith("DEGENERATE")
    assert verdict(naive_real, row("stage6", 0, 0)).startswith("ACCEPT_NOTHING_EQUIVALENT")
    assert verdict(naive_real, row("stage6", 1, 1)).startswith("STAGE6_POISONED")
    assert verdict(naive_real, row("stage2-only", 0, 1), six_clean).startswith("HELD_BY_STAGE2_ALONE")
    assert verdict(row("naive-finetune", 2, 1, offered=0), six_clean).startswith("DEGENERATE")
    assert verdict(naive_real, row("stage2-only", 1, 1), six_clean) == "HELD"


# --- ablation (Rule C) ----------------------------------------------------------------


def test_every_ablation_row_obeys_rule_c() -> None:
    rows = run_ablation(_compiled(), preconditions=_preconditions())
    assert {r.core_id for r in rows} >= {
        "HEL-F07",
        "HEL-F08",
        "HEL-F10",
        "HEL-F11",
        "HEL-F15",
        "HEL-F19",
        "HEL-F21",
        "HEL-F25",
        "gateway:independence",
        "gateway:homeostasis",
    }
    for r in rows:
        assert r.verdict in VERDICTS
        if r.firing_count == 0:
            # a mechanism that never fired is not evidence
            assert r.verdict in ("INERT", "UNMEASURED")
        if r.verdict == "JUSTIFIED":
            assert r.delta is not None and r.firing_count > 0
    if _preconditions().verdict != "OK":
        assert not any(
            r.verdict == "JUSTIFIED" and r.metric in ("retention_F1", "mean_recall") for r in rows
        )


def test_verdict_rule_c_and_preconditions_override_any_delta() -> None:
    verdict = endurance_module._verdict
    assert verdict(0.9, 0, "OK", "retention_F1") == "INERT"
    assert verdict(0.9, 5, "BLOCKED", "retention_F1") == "UNMEASURED"
    assert verdict(0.9, 5, "DEGENERATE", "mean_recall") == "DEGENERATE"
    assert verdict(None, 5, "OK", "fp_rate") == "UNMEASURED"
    assert verdict(0.5, 5, "OK", "fp_rate") == "JUSTIFIED"
    assert verdict(-0.5, 5, "OK", "fp_rate") == "HARMFUL"
    assert verdict(0.0, 5, "OK", "fp_rate") == "NOT_YET_JUSTIFIED"


# --- long horizon ---------------------------------------------------------------------


@pytest.mark.slow
def test_sixty_month_stage_six_run_stays_bounded_and_evicts() -> None:
    compiled = compile_timeline(build_year_timeline(sessions_per_month=8, eval_per_family=1))
    assert len(compiled.months) == 60
    learner = StageSixLearner(compiled.genesis)
    checkpoints = run_endurance(compiled, [learner]).checkpoints
    assert all(store_violations(c) == () for c in checkpoints)
    last = checkpoints[-1]
    assert last.evictions["replay_ring"] > 0 and last.evictions["gateway"] > 0
    hit_cap = [k for k, (_, cap) in STORE_CAPS.items() if cap is not None
               and max(c.store_counts[k] for c in checkpoints) >= cap]
    assert all(last.evictions[k] > 0 for k in hit_cap), hit_cap
    assert Counter(c.month for c in checkpoints) == Counter(range(1, 61))
