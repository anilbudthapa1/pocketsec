"""Stage 9 package ``evaluation``: the ARGUS adversary, the splits and worst-case fitness.

An attack never shown to fire is a docstring, so these tests make every mechanism fire and
then check what it reported: every scenario attack must change some scenario while keeping
every label and name; the lineage flood must actually flood without reusing an identity;
the fitness must be a minimum, not a mean; the cache must actually hit and actually evict;
the contamination check, the tampering defences and the budget must actually refuse; and an
attack that changed nothing must be reported INERT and must not count toward coverage.

Sizes are tiny (12 sessions per variant); the count-240 splits belong to the gate.
"""

from __future__ import annotations

import statistics
from dataclasses import replace
from typing import Any

import pytest

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.labs.ambiguous_corpus import build_ambiguous_corpus
from pocketsec.stage6.resources import WorkBudgetExceeded, WorkMeter
from pocketsec.stage9.argus import adversary, tampering
from pocketsec.stage9.argus.adversary import (
    LIFECYCLE_ATTACKS,
    SCENARIO_ATTACKS,
    ArgusFinding,
    ArgusSurface,
    attack_findings,
    constant_corruption,
    coverage,
    state_reset_midsession,
    tampered_genome,
    work_budget_starvation,
)
from pocketsec.stage9.chemistry.phenotype import SessionAggregation
from pocketsec.stage9.chemistry.typed_ir import (
    InputSource,
    IRError,
    IRNode,
    IRProgram,
    IRType,
    NodeKind,
    ProgramPhase,
    RegisterSpec,
)
from pocketsec.stage9.genome.computational import ComputationalGenomeV1, build_genome
from pocketsec.stage9.labs import splits
from pocketsec.stage9.labs.splits import (
    CLEAN,
    CompiledVariant,
    compile_scenarios,
    compile_variant,
    compile_variants,
    split_key,
    stage9_saturation,
)
from pocketsec.stage9.ontogenesis.fitness import (
    EvaluationCache,
    EvaluationSuite,
    contamination_attack,
    contamination_check,
    evaluate,
    session_scores,
)

COUNT = 12
ATTACK_IDS = tuple(attack.attack_id for attack in SCENARIO_ATTACKS)


# --- genomes, built through the documented constructor ------------------------------------


def _reg(index: int = 0, type_: IRType = IRType.FLOAT) -> IRNode:
    return IRNode(kind=NodeKind.REG, type=type_, index=index)


def _input(source: InputSource, index: int = 0, type_: IRType = IRType.FLOAT) -> IRNode:
    return IRNode(kind=NodeKind.INPUT, type=type_, source=source, index=index)


def _apply(primitive: str, *args: int, type_: IRType = IRType.FLOAT) -> IRNode:
    return IRNode(kind=NodeKind.APPLY, type=type_, primitive=primitive, args=args)


def _const(value: float) -> IRNode:
    return IRNode(kind=NodeKind.CONST, type=IRType.FLOAT, value=value)


def phi_oracle() -> ComputationalGenomeV1:
    """max over events of features[73], per lineage, max over lineages: 0 constants."""
    return build_genome(
        registers=(RegisterSpec(type=IRType.FLOAT),),
        update=IRProgram(
            phase=ProgramPhase.UPDATE,
            nodes=(_reg(), _input(InputSource.FEATURE, 73), _apply("MAX", 0, 1)),
            outputs=(2,),
        ),
        readout=IRProgram(phase=ProgramPhase.READOUT, nodes=(_reg(),), outputs=(0,)),
        aggregation=SessionAggregation.MAX,
    )


def phi_oracle_raw() -> ComputationalGenomeV1:
    """max |dPhi| per lineage, read out as r / (r + 8.0): one non-zero constant."""
    return build_genome(
        registers=(RegisterSpec(type=IRType.FLOAT),),
        update=IRProgram(
            phase=ProgramPhase.UPDATE,
            nodes=(
                _reg(),
                _input(InputSource.DELTA_PHI),
                _apply("ABS", 1),
                _apply("MAX", 0, 2),
            ),
            outputs=(3,),
        ),
        readout=IRProgram(
            phase=ProgramPhase.READOUT,
            nodes=(_reg(), _const(8.0), _apply("ADD", 0, 1), _apply("DIV", 0, 2)),
            outputs=(3,),
        ),
        aggregation=SessionAggregation.MAX,
    )


def h1() -> ComputationalGenomeV1:
    """Per-lineage sum of max(dPhi, 0.0): its only constant is 0.0, which +/-10% cannot move."""
    return build_genome(
        registers=(RegisterSpec(type=IRType.FLOAT),),
        update=IRProgram(
            phase=ProgramPhase.UPDATE,
            nodes=(
                _reg(),
                _input(InputSource.DELTA_PHI),
                _const(0.0),
                _apply("MAX", 1, 2),
                _apply("ADD", 0, 3),
            ),
            outputs=(4,),
        ),
        readout=IRProgram(phase=ProgramPhase.READOUT, nodes=(_reg(),), outputs=(0,)),
        aggregation=SessionAggregation.MAX,
    )


def h2() -> ComputationalGenomeV1:
    """Per-lineage popcount of the OR of state-delta masks."""
    return build_genome(
        registers=(RegisterSpec(type=IRType.INT),),
        update=IRProgram(
            phase=ProgramPhase.UPDATE,
            nodes=(
                _reg(type_=IRType.INT),
                _input(InputSource.STATE_DELTA_MASK, type_=IRType.INT),
                _apply("OR", 0, 1, type_=IRType.INT),
            ),
            outputs=(2,),
        ),
        readout=IRProgram(
            phase=ProgramPhase.READOUT,
            nodes=(_reg(type_=IRType.INT), _apply("POPCOUNT", 0)),
            outputs=(1,),
        ),
        aggregation=SessionAggregation.MAX,
    )


# --- fixtures -----------------------------------------------------------------------------


@pytest.fixture(scope="module")
def heldout_variants() -> tuple[CompiledVariant, ...]:
    return compile_variants(count=COUNT, seed=11, attack_ids=(CLEAN, *ATTACK_IDS), workers=4)


@pytest.fixture(scope="module")
def heldout(heldout_variants: tuple[CompiledVariant, ...]) -> EvaluationSuite:
    return EvaluationSuite(name="heldout", clean=heldout_variants[0], attacked=heldout_variants[1:])


@pytest.fixture(scope="module")
def train() -> EvaluationSuite:
    variants = compile_variants(count=COUNT, seed=3, attack_ids=(CLEAN, *ATTACK_IDS[:2]))
    return EvaluationSuite(name="train", clean=variants[0], attacked=variants[1:])


# --- scenario attacks ---------------------------------------------------------------------


def test_every_scenario_attack_preserves_labels_names_and_techniques_and_changes_something() -> (
    None
):
    scenarios = build_ambiguous_corpus(count=COUNT, seed=11, split="eval")
    assert [a.attack_id for a in SCENARIO_ATTACKS] == [
        "rename_binaries",
        "reorder_across_actors",
        "benign_duplicate_flood",
        "timing_stretch",
        "sensor_drop_10",
        "lineage_table_flood",
    ]
    for attack in SCENARIO_ATTACKS:
        attacked = attack.apply(scenarios, seed=11)
        assert [(s.name, s.label, s.technique, s.unseen_technique) for s in attacked] == [
            (s.name, s.label, s.technique, s.unseen_technique) for s in scenarios
        ], attack.attack_id
        pairs = zip(attacked, scenarios, strict=True)
        changed = sum(a.behaviours != s.behaviours for a, s in pairs)
        assert changed > 0, f"{attack.attack_id} changed no scenario: the attack is not real"
        # Deterministic in (seed, salt): the parallel compile relies on it.
        assert attack.apply(scenarios, seed=11) == attacked


def test_rename_binaries_is_consistent_per_original_path() -> None:
    scenarios = build_ambiguous_corpus(count=COUNT, seed=11, split="eval")
    mapping: dict[str, set[str]] = {}
    for before, after in zip(scenarios, SCENARIO_ATTACKS[0].apply(scenarios, seed=1), strict=True):
        for b, a in zip(before.behaviours, after.behaviours, strict=True):
            if b.operation == "execve":
                assert a.fields["path"].startswith("/opt/x/") and len(a.fields["path"]) == 15
                mapping.setdefault(b.fields["path"], set()).add(a.fields["path"])
    assert mapping and all(len(new) == 1 for new in mapping.values())


def test_lineage_table_flood_inserts_64_session_unique_actors_and_reuses_no_identity() -> None:
    scenarios = build_ambiguous_corpus(count=COUNT, seed=11, split="eval")
    flooded = adversary.attack_by_id("lineage_table_flood").apply(scenarios, seed=11)
    pids_by_session = []
    for before, after in zip(scenarios, flooded, strict=True):
        assert len(after.behaviours) == len(before.behaviours) + adversary.FLOOD_ACTORS
        flood = [b for b in after.behaviours if b.fields.get("path") == "/tmp/s9-flood"]
        pids = {(b.fields["pid"], b.fields["start_time"]) for b in flood}
        assert len(pids) == adversary.FLOOD_ACTORS
        pids_by_session.append(pids)
    assert not set.intersection(*pids_by_session)
    variant = compile_variant(count=COUNT, seed=11, attack_id="lineage_table_flood")
    assert variant.identities_reused_across_sessions == 0
    assert variant.audit_failures == ()


def test_identity_reuse_counter_fires_on_a_corpus_that_reuses_identities() -> None:
    """The negative control for the flood test: the counter is not identically 0."""
    scenarios = build_ambiguous_corpus(count=3, seed=11, split="eval")
    doubled = (*scenarios, replace(scenarios[0], name="copy-of-0"))
    variant = compile_scenarios(doubled, key=split_key(count=4, seed=11))
    assert variant.identities_reused_across_sessions > 0
    assert any("reused" in failure for failure in variant.audit_failures)
    with pytest.raises(ContractError, match="corpus audit"):
        EvaluationSuite(name="bad", clean=variant, attacked=())


def test_parallel_and_serial_compiles_give_identical_digests() -> None:
    ids = (CLEAN, "rename_binaries", "lineage_table_flood")
    parallel = compile_variants(count=COUNT, seed=11, attack_ids=ids, workers=3)
    serial = tuple(compile_variant(count=COUNT, seed=11, attack_id=a) for a in ids)
    assert [v.key for v in parallel] == [v.key for v in serial]
    assert [v.content_digest for v in parallel] == [v.content_digest for v in serial]
    assert len({v.content_digest for v in serial}) == len(ids)  # attacks changed content
    for variant in parallel:
        assert variant.loadavg_before and variant.loadavg_after and variant.compile_seconds > 0
        assert variant.results == ()  # the parallel path never ships ScenarioResults back


# --- fitness ------------------------------------------------------------------------------


def test_worst_case_is_the_minimum_over_variants_not_the_mean(heldout: EvaluationSuite) -> None:
    record = evaluate(phi_oracle(), heldout, meter=WorkMeter())
    assert [name for name, _ in record.variant_aps] == [CLEAN, *ATTACK_IDS]
    aps = [ap for _, ap in record.variant_aps if ap is not None]
    assert len(aps) == len(record.variant_aps)  # every variant measured
    assert record.worst_case_ap == min(aps)
    assert dict(record.variant_aps)[record.worst_variant] == record.worst_case_ap
    assert record.clean_ap == aps[0]
    assert record.lineage_evictions > 0  # the flood variant made the lineage table evict
    if max(aps) > min(aps):  # a mean would be strictly larger than the worst case
        assert record.worst_case_ap < statistics.fmean(aps)
    assert record.objective().worst_case_ap == record.worst_case_ap
    assert record.work_units_spent > 0


def test_cache_hit_spends_no_work_and_evictions_are_counted_at_capacity(
    train: EvaluationSuite,
) -> None:
    cache = EvaluationCache(capacity=1)
    meter = WorkMeter()
    first = evaluate(phi_oracle(), train, meter=meter, cache=cache)
    spent = meter.spent
    assert spent > 0 and (cache.hits, cache.misses, cache.evictions) == (0, 1, 0)
    again = evaluate(phi_oracle(), train, meter=meter, cache=cache)
    assert again is first and meter.spent == spent and cache.hits == 1
    evaluate(h2(), train, meter=meter, cache=cache)
    assert cache.evictions == 1 and len(cache) == 1
    evaluate(phi_oracle(), train, meter=meter, cache=cache)  # evicted, so paid again
    assert cache.misses == 3 and meter.spent > spent * 2


def test_shuffled_label_suite_changes_labels_but_not_scores(train: EvaluationSuite) -> None:
    shuffled = train.with_shuffled_labels(seed=9)
    assert shuffled.labels != train.labels
    assert sorted(shuffled.labels) == sorted(train.labels)
    assert shuffled.base_rate == train.base_rate
    real = evaluate(phi_oracle(), train, meter=WorkMeter())
    control = evaluate(phi_oracle(), shuffled, meter=WorkMeter())
    assert control.scores_digest == real.scores_digest
    assert shuffled.labels_digest != train.labels_digest  # never answered from one cache entry
    for variant in shuffled.attacked:
        assert len(shuffled.labels_for(variant)) == len(variant.dataset)


def test_contamination_check_refuses_overlap(
    train: EvaluationSuite, heldout: EvaluationSuite
) -> None:
    clean_pair = contamination_check(train, heldout)
    assert clean_pair.refused is False
    assert (clean_pair.overlapping_sample_ids, clean_pair.overlapping_content) == (0, 0)
    same_split = contamination_check(heldout, heldout)
    assert same_split.refused and same_split.overlapping_sample_ids == len(heldout.clean.dataset)
    finding = contamination_attack(train, heldout)
    assert finding.kind == "DEFENCE" and finding.surface is ArgusSurface.SEARCH
    assert (finding.fired, finding.total) == (1, 1) and not finding.defence_failed
    assert finding.metric_after == float(min(20, len(heldout.clean.dataset)))


# --- lifecycle attacks --------------------------------------------------------------------


def test_tampered_genomes_are_refused_three_of_three() -> None:
    for genome in (phi_oracle(), phi_oracle_raw(), h2()):
        finding = tampered_genome(genome)
        assert finding.kind == "DEFENCE" and finding.surface is ArgusSurface.SUPPLY_CHAIN
        assert (finding.fired, finding.total) == (3, 3), finding.detail
        assert not finding.defence_failed


def _count_genome() -> ComputationalGenomeV1:
    """r' = COUNT(first_event, r): its only APPLY primitive has no same-signature partner."""
    return build_genome(
        registers=(RegisterSpec(type=IRType.FLOAT),),
        update=IRProgram(
            phase=ProgramPhase.UPDATE,
            nodes=(_input(InputSource.LINEAGE_FIRST_EVENT, type_=IRType.BOOL), _reg(),
                   _apply("COUNT", 0, 1)),
            outputs=(2,),
        ),
        readout=IRProgram(phase=ProgramPhase.READOUT, nodes=(_reg(),), outputs=(0,)),
        aggregation=SessionAggregation.MAX,
    )


def test_the_digest_trial_is_refused_by_the_digest_check_even_without_a_swap_partner() -> None:
    """Pins S9-R3: COUNT has no same-signature partner. The old fallback swapped in ADD, the
    attacker's own genome raised IRError, and that was counted as the digest check refusing.
    Now the trial falls back to a register-init change and must meet the digest check."""
    finding = tampered_genome(_count_genome())
    assert (finding.fired, finding.total) == (3, 3), finding.detail
    first = finding.detail.split("; ")[0]
    assert first.startswith("op_swap_digest_kept: refused (ContractError: digest mismatch")
    assert "IRError" not in first


def test_a_tampered_artefact_the_attacker_cannot_build_is_not_a_refusal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pins S9-R3: a ContractError while BUILDING the tampered artefact means the defence
    never ran; it must count as a failed trial, never as a designed refusal."""

    def unbuildable(genome: ComputationalGenomeV1) -> ComputationalGenomeV1:
        raise IRError("TYPE_MISMATCH", "fixture: the attacker built an ill-typed genome")

    monkeypatch.setattr(tampering, "_semantic_swap", unbuildable)
    finding = tampered_genome(phi_oracle())
    assert (finding.fired, finding.total) == (2, 3)
    assert finding.defence_failed
    assert "op_swap_digest_kept: NOT a designed refusal" in finding.detail
    assert "digest check never ran" in finding.detail


def test_budget_starvation_never_yields_a_partial_score(heldout: EvaluationSuite) -> None:
    finding = work_budget_starvation(phi_oracle(), heldout.clean.dataset)
    assert finding.kind == "DEFENCE"
    assert finding.fired == finding.total == len(heldout.clean.dataset)
    assert finding.metric_after == 0.0  # partial scores produced
    meter = WorkMeter(budget=10)
    cache = EvaluationCache()
    with pytest.raises(WorkBudgetExceeded):
        evaluate(phi_oracle(), heldout, meter=meter, cache=cache)
    assert meter.spent <= 10 and len(cache) == 0  # nothing cached for a partial evaluation


def test_padding_a_session_past_the_event_cap_buys_unknown_not_a_benign_score(
    heldout: EvaluationSuite,
) -> None:
    """Pins S9-FC-02 / S9-CX-01: head padding past MAX_SESSION_EVENTS must make every
    session abstain. Before the fix every session scored the padded prefix (fired 0/N, a
    failed DEFENCE) and detection fell to the base rate with nothing flagged."""
    dataset = heldout.clean.dataset
    for genome in (phi_oracle(), h1(), h2()):
        finding = adversary.session_cap_padding(genome, dataset)
        assert finding.kind == "DEFENCE" and finding.surface is ArgusSurface.INPUT
        assert finding.fired == finding.total == len(dataset), finding.detail
        assert not finding.defence_failed
        assert finding.metric_before is not None and finding.metric_after is not None
        assert finding.metric_after <= finding.metric_before  # UNKNOWN is not detection


def test_an_attack_that_changes_nothing_is_reported_inert(heldout: EvaluationSuite) -> None:
    dataset = heldout.clean.dataset
    no_constants = constant_corruption(phi_oracle(), dataset, seed=5)
    zero_constant = constant_corruption(h1(), dataset, seed=5)  # 0.0 * 1.1 == 0.0
    real = constant_corruption(phi_oracle_raw(), dataset, seed=5)
    assert no_constants.inert and no_constants.fired == 0
    assert zero_constant.inert and "1 constants scaled" in zero_constant.detail
    assert not real.inert and real.fired > 0
    assert real.metric_before is not None and real.metric_after is not None


def test_coverage_ignores_inert_findings(heldout: EvaluationSuite) -> None:
    dataset = heldout.clean.dataset
    inert = constant_corruption(phi_oracle(), dataset, seed=5)
    reset = state_reset_midsession(phi_oracle(), dataset)
    assert inert.surface is ArgusSurface.MODEL and inert.inert
    assert reset.surface is ArgusSurface.STATE and reset.fired > 0
    assert coverage([inert, reset]) == frozenset({ArgusSurface.STATE})
    assert coverage([inert]) == frozenset()


def test_scenario_attack_findings_count_changed_sessions(heldout: EvaluationSuite) -> None:
    findings = attack_findings(phi_oracle(), heldout.clean, heldout.attacked)
    assert [f.attack_id for f in findings] == list(ATTACK_IDS)
    base = session_scores(phi_oracle(), heldout.clean.dataset)
    for finding, variant in zip(findings, heldout.attacked, strict=True):
        after = session_scores(phi_oracle(), variant.dataset)
        changed = sum(
            abs(a - b) > 1e-12
            for a, b in zip(base, after, strict=True)
            if a is not None and b is not None
        )
        assert None not in base and None not in after  # min_events_for_score=1: no abstention
        assert finding.fired == changed and finding.inert == (changed == 0)
    # A session absent from a variant counts as fired.
    dropped = replace(
        heldout.clean,
        dataset=replace(heldout.clean.dataset, samples=heldout.clean.dataset.samples[1:]),
    )
    dropped = replace(dropped, key=replace(dropped.key, attack_id="sensor_drop_10"))
    (finding,) = attack_findings(phi_oracle(), heldout.clean, (dropped,))
    assert finding.fired == 1 and "1 sessions missing" in finding.detail


def test_lifecycle_catalogue_names_every_runner_and_all_eight_surfaces_are_reachable() -> None:
    runners = {a.attack_id: a.runner for a in LIFECYCLE_ATTACKS}
    assert runners == {
        "constant_corruption": "argus.adversary:constant_corruption",
        "state_reset_midsession": "argus.adversary:state_reset_midsession",
        "work_budget_starvation": "argus.adversary:work_budget_starvation",
        "tampered_genome": "argus.adversary:tampered_genome",
        "session_cap_padding": "argus.adversary:session_cap_padding",
        "benchmark_contamination": "ontogenesis.fitness:contamination_attack",
        "train_label_noise": "argus.adversary:train_label_noise",
        "shuffled_label_search": "ontogenesis.search:run_shuffled_label_control",
        "hypothesis_explosion": "gaia.qd_ecology:hypothesis_explosion",
        "tampered_successor": "successor.proof_carrying:tampered_successor",
    }
    surfaces = {a.surface for a in SCENARIO_ATTACKS} | {a.surface for a in LIFECYCLE_ATTACKS}
    assert surfaces == set(ArgusSurface) and len(ArgusSurface) == 8
    assert set(adversary.SURFACE_TESTS) == set(ArgusSurface)
    for attack_id, runner in runners.items():
        module, _, name = runner.partition(":")
        if module == "argus.adversary":
            assert callable(getattr(adversary, name)), attack_id


def test_a_finding_cannot_misreport_its_own_firing_count() -> None:
    common: dict[str, Any] = dict(
        attack_id="x",
        surface=ArgusSurface.DATA,
        metric_before=None,
        metric_after=None,
        detail="",
        measured_by="test",
    )
    with pytest.raises(ContractError, match="contradicts"):
        ArgusFinding(kind="MEASUREMENT", fired=0, total=3, inert=False, **common)
    with pytest.raises(ContractError, match=r"0\.\.total"):
        ArgusFinding(kind="MEASUREMENT", fired=4, total=3, inert=False, **common)
    with pytest.raises(ContractError, match="kind"):
        ArgusFinding(kind="PASS", fired=1, total=1, inert=False, **common)
    partial = ArgusFinding(kind="DEFENCE", fired=2, total=3, inert=False, **common)
    vacuous = ArgusFinding(kind="DEFENCE", fired=0, total=0, inert=True, **common)
    assert partial.defence_failed and vacuous.defence_failed


# --- saturation ---------------------------------------------------------------------------


def test_saturation_check_flags_a_phi_oracle_at_ceiling() -> None:
    at_ceiling = stage9_saturation(
        {"phi": 1.0, "h1": 0.70, "h2": 0.55, "control": 0.40}, phi_oracle=1.0, order_free=0.40
    )
    assert at_ceiling.degenerate and at_ceiling.phi_oracle_at_ceiling
    assert at_ceiling.reason.startswith("PHI_ORACLE_AT_CEILING")
    # The same spread with the Φ-oracle below the ceiling is NOT degenerate: the flag is
    # decided by the ceiling, not by Stage 3's guard, in the first case.
    assert at_ceiling.stage3_verdict["degenerate"] is False
    headroom = stage9_saturation(
        {"phi": 0.60, "h1": 0.77, "h2": 0.81, "control": 0.33}, phi_oracle=0.60, order_free=0.33
    )
    assert not headroom.degenerate and not headroom.phi_oracle_at_ceiling
    assert splits.PHI_ORACLE_CEILING == 0.99
