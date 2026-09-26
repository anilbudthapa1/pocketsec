"""Stage 9 package ``evaluation``: failure paths of the splits, the suite and the fitness.

``test_stage9_argus.py`` makes every attack fire. This file attacks the evaluation
substrate itself: invalid inputs must be refused before any compile work starts, the
abstention path must be reachable and must never raise AP, a suite must refuse data that
failed its audit or does not belong to its split, the cache must stay within its bound,
label noise must flip exactly the number it says, and the attrition and label-noise
measurements must count what they claim to count.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage6.resources import WorkMeter
from pocketsec.stage9.argus.adversary import (
    ArgusSurface,
    fittest_die_under_attack,
    train_label_noise,
)
from pocketsec.stage9.chemistry import phenotype as phenotype_module
from pocketsec.stage9.chemistry.phenotype import SessionAggregation
from pocketsec.stage9.chemistry.typed_ir import (
    InputSource,
    IRNode,
    IRProgram,
    IRType,
    NodeKind,
    ProgramPhase,
    RegisterSpec,
)
from pocketsec.stage9.genome.computational import ComputationalGenomeV1, build_genome
from pocketsec.stage9.labs.splits import (
    CLEAN,
    MAX_COMPILE_WORKERS,
    compile_variant,
    compile_variants,
    dataset_digest,
    session_content_digest,
    split_key,
)
from pocketsec.stage9.ontogenesis.fitness import (
    MAX_CACHE_ENTRIES,
    EvaluationCache,
    EvaluationSuite,
    FitnessRecord,
    evaluate,
    score_ap,
)

COUNT = 12


# --- genomes, built through the documented constructor (as in test_stage9_argus.py) ----


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


@pytest.fixture(scope="module")
def suite() -> EvaluationSuite:
    variants = compile_variants(count=COUNT, seed=3, attack_ids=(CLEAN, "sensor_drop_10"))
    return EvaluationSuite(name="train", clean=variants[0], attacked=variants[1:])


def _abstaining_genome() -> ComputationalGenomeV1:
    """The Φ-oracle, but refusing to score any session shorter than 1000 events."""
    base = phi_oracle()
    return build_genome(
        registers=base.registers,
        update=base.update,
        readout=base.readout,
        aggregation=base.aggregation,
        min_events_for_score=1000,
    )


# --- splits: refuse before compiling ------------------------------------------------------


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"attack_ids": ("no_such_attack",)}, "unknown ARGUS"),
        ({"attack_ids": (CLEAN, CLEAN)}, "repeat"),
        ({"attack_ids": ()}, "at least one"),
        ({"attack_ids": (CLEAN,), "workers": 0}, "workers"),
        ({"attack_ids": (CLEAN,), "workers": MAX_COMPILE_WORKERS + 1}, "workers"),
    ],
)
def test_compile_variants_refuses_bad_requests_before_any_work(
    kwargs: dict[str, Any], match: str
) -> None:
    with pytest.raises(ContractError, match=match):
        compile_variants(count=COUNT, seed=11, **kwargs)


def test_split_key_refuses_bad_count_and_seed() -> None:
    for count, seed in ((0, 11), (True, 11), (12, "11")):
        with pytest.raises(ContractError):
            split_key(count=count, seed=seed)  # type: ignore[arg-type]
    assert split_key(count=12, seed=11).attack_version == "none"
    assert split_key(count=12, seed=11, attack_id="timing_stretch").attack_version.startswith(
        "stage9-argus"
    )


def test_content_digest_names_content_not_ids(suite: EvaluationSuite) -> None:
    dataset = suite.clean.dataset
    assert dataset_digest(dataset) == suite.clean.content_digest
    first = dataset.samples[0]
    renamed = replace(first, sample_id="renamed")
    assert session_content_digest(renamed) == session_content_digest(first)
    flipped = replace(first, label=1 - first.label)
    assert session_content_digest(flipped) != session_content_digest(first)
    # The dataset digest DOES bind ids: a renamed split is a different split.
    renamed_ds = replace(dataset, samples=(renamed, *dataset.samples[1:]))
    assert dataset_digest(renamed_ds) != dataset_digest(dataset)


def test_keep_results_is_honoured_only_when_asked() -> None:
    kept = compile_variant(count=3, seed=11, keep_results=True)
    assert len(kept.results) == 3 and kept.results[0].scenario.name.startswith("amb-eval-")
    assert compile_variant(count=3, seed=11).results == ()


# --- the suite ----------------------------------------------------------------------------


def test_suite_refuses_foreign_or_mislabelled_variants(suite: EvaluationSuite) -> None:
    other_seed = compile_variant(count=COUNT, seed=11, attack_id="timing_stretch")
    with pytest.raises(ContractError, match="not a variant"):
        EvaluationSuite(name="x", clean=suite.clean, attacked=(other_seed,))
    with pytest.raises(ContractError, match="not clean"):
        EvaluationSuite(name="x", clean=suite.attacked[0], attacked=())
    with pytest.raises(ContractError, match="unique"):
        EvaluationSuite(name="x", clean=suite.clean, attacked=(suite.clean,))
    with pytest.raises(ContractError, match="labels_override"):
        replace(suite, labels_override=(1, 0))
    with pytest.raises(ContractError, match="only 0 and 1"):
        replace(suite, labels_override=(2,) * len(suite.clean.dataset))


def test_label_noise_flips_exactly_the_stated_number(suite: EvaluationSuite) -> None:
    noisy = suite.with_label_noise(0.25, seed=4)
    flipped = sum(a != b for a, b in zip(noisy.labels, suite.labels, strict=True))
    assert flipped == round(0.25 * len(suite.labels))
    assert suite.with_label_noise(0.0, seed=4).labels == suite.labels
    with pytest.raises(ContractError):
        suite.with_label_noise(1.5, seed=4)


# --- fitness ------------------------------------------------------------------------------


def test_abstention_ranks_as_zero_and_is_counted() -> None:
    ap, abstained = score_ap([1, 0, 0], [None, 0.5, 0.2])
    assert abstained == 1 and ap == pytest.approx(1 / 3)  # the positive is ranked last


def test_a_genome_that_abstains_everywhere_gains_nothing(suite: EvaluationSuite) -> None:
    record = evaluate(_abstaining_genome(), suite, meter=WorkMeter())
    sessions = sum(len(v.dataset) for v in suite.variants)
    assert record.abstained_sessions == sessions
    assert record.constant_output is True
    # All-ties AP is the base rate: abstaining cannot beat chance.
    assert record.clean_ap == pytest.approx(suite.base_rate)
    real = evaluate(phi_oracle(), suite, meter=WorkMeter())
    assert real.constant_output is False and real.abstained_sessions == 0


def test_cache_capacity_is_a_hard_bound_and_invalid_capacity_is_refused(
    suite: EvaluationSuite,
) -> None:
    for bad in (0, -1, True, 2.5):
        with pytest.raises(ContractError):
            EvaluationCache(capacity=bad)  # type: ignore[arg-type]
    assert EvaluationCache().capacity == MAX_CACHE_ENTRIES
    cache = EvaluationCache(capacity=2)
    meter = WorkMeter()
    for genome in (phi_oracle(), h1(), h2(), phi_oracle_raw()):
        evaluate(genome, suite, meter=meter, cache=cache)
    assert len(cache) == 2 and cache.evictions == 2 and cache.misses == 4


def test_worst_case_is_unmeasured_when_no_positive_exists(suite: EvaluationSuite) -> None:
    """A suite with no positive label has no AP; the worst case is None, never a number."""
    all_benign = replace(suite, labels_override=(0,) * len(suite.clean.dataset))
    record = evaluate(phi_oracle(), all_benign, meter=WorkMeter())
    assert record.clean_ap is None and record.worst_case_ap is None
    assert record.worst_variant == CLEAN
    assert record.objective().worst_case_ap is None


def test_suite_refuses_a_variant_whose_audit_failed(suite: EvaluationSuite) -> None:
    """A variant without a malicious session has no class signal to audit: refused."""
    benign_only = replace(
        suite.attacked[0],
        dataset=replace(
            suite.attacked[0].dataset,
            samples=tuple(s for s in suite.attacked[0].dataset.samples if s.label == 0),
        ),
        median_peak_abs_dphi_by_class=(suite.attacked[0].median_peak_abs_dphi_by_class[0], 0.0),
    )
    with pytest.raises(ContractError, match="corpus audit"):
        replace(suite, attacked=(benign_only,))


def test_fitness_carries_sessions_that_hit_the_event_cap(
    suite: EvaluationSuite, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pins S9-FC-02: a session over MAX_SESSION_EVENTS used to be counted only inside one
    SessionRun and discarded; FitnessRecord must carry it (and count it as an abstention)."""
    clean = evaluate(phi_oracle(), suite, meter=WorkMeter())
    assert clean.truncated_sessions == 0
    monkeypatch.setattr(phenotype_module, "MAX_SESSION_EVENTS", 5)
    capped = evaluate(phi_oracle(), suite, meter=WorkMeter())
    over = sum(
        1 for variant in suite.variants for sample in variant.dataset.samples
        if len(sample.steps) > 5
    )
    assert over > 0
    assert capped.truncated_sessions == over
    assert capped.abstained_sessions >= over
    assert capped.to_dict()["truncated_sessions"] == over


# --- attrition and label noise ------------------------------------------------------------


def _record(digest: str, clean: float | None, worst: float | None) -> FitnessRecord:
    return FitnessRecord(
        genome_digest=digest,
        suite="train",
        clean_ap=clean,
        variant_aps=(),
        worst_case_ap=worst,
        worst_variant="",
        wu_per_event=3,
        state_bytes=0,
        description_length_bits=0.0,
        work_units_spent=0,
        constant_output=False,
        lineage_evictions=0,
        scores_digest="",
    )


def test_fittest_die_under_attack_counts_each_death_rule() -> None:
    records = [
        _record("a", 0.90, 0.88),  # survives
        _record("b", 0.95, 0.60),  # below the reference worst case
        _record("c", 0.99, 0.80),  # clean - worst > 0.05
        _record("d", 0.85, None),  # unmeasured worst case is a death
        _record("e", 0.10, 0.10),  # not in the top 4 by clean AP
    ]
    attrition = fittest_die_under_attack(records, reference_worst_case=0.70, top_k=4)
    assert attrition.examined == 4 and attrition.died == 3
    assert set(attrition.died_digests) == {"b", "c", "d"}
    with pytest.raises(ContractError):
        fittest_die_under_attack(records, reference_worst_case=0.7, top_k=0)


def test_attrition_separates_attack_deaths_from_genomes_already_below_the_reference() -> None:
    """Pins S9-R2 / S9-FC-01 / S9-CX-03: "died under attack" must be caused by an attack.

    Record ``f`` fails ONLY the reference rule: its clean AP is already below the reference
    and no attack moved it. The old count called it "died under attack"; with every attack a
    no-op (worst == clean) the gate's evolutionary runs read 10/10 dead.
    """
    records = [
        _record("a", 0.90, 0.88),  # survives
        _record("b", 0.95, 0.60),  # attack pushed it from above the reference to below
        _record("c", 0.99, 0.80),  # attack drop > 0.05
        _record("f", 0.65, 0.64),  # below the reference on CLEAN data; attack did ~nothing
    ]
    attrition = fittest_die_under_attack(records, reference_worst_case=0.70, top_k=4)
    assert attrition.died == 3 and set(attrition.died_digests) == {"b", "c", "f"}
    assert attrition.died_under_attack == 2
    assert set(attrition.died_under_attack_digests) == {"b", "c"}
    assert attrition.died_without_attack == 1 and attrition.unmeasured == 0
    no_op = [_record(f"n{i}", 0.55 - i / 1000, 0.55 - i / 1000) for i in range(10)]
    control = fittest_die_under_attack(no_op, reference_worst_case=0.5872)
    assert control.died == 10  # the disjunctive rule, as the gate used to headline it
    assert control.died_under_attack == 0  # ... and no attack did anything
    assert control.died_without_attack == 10
    assert control.summary().startswith("0/10 killed by an attack")


def test_train_label_noise_reranks_real_records_and_refuses_foreign_ones(
    suite: EvaluationSuite,
) -> None:
    meter = WorkMeter()
    genomes = (phi_oracle(), phi_oracle_raw(), h1(), h2())
    top = [(g, evaluate(g, suite, meter=meter)) for g in genomes]
    finding = train_label_noise(top, suite, rate=0.5, seed=7)
    assert finding.surface is ArgusSurface.DATA and finding.kind == "MEASUREMENT"
    assert finding.total == 4 and 0 <= finding.fired <= 4
    assert "winner changed" in finding.detail
    foreign = [(h1(), top[0][1])]  # phi's record claimed for H1
    with pytest.raises(ContractError, match="does not belong"):
        train_label_noise(foreign, suite, seed=7)


# --- boundary -----------------------------------------------------------------------------


def test_evaluation_modules_import_no_stage5_and_never_touch_the_experiment_ledger() -> None:
    """This package scores candidates; it holds no authority and registers nothing."""
    import ast
    from pathlib import Path

    root = Path(__file__).resolve().parents[1] / "pocketsec" / "stage9"
    for relative in ("labs/splits.py", "argus/adversary.py", "ontogenesis/fitness.py"):
        source = (root / relative).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported = {
            node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
        } | {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        forbidden = ("pocketsec.stage4", "pocketsec.stage5", "pocketsec.stage7", "pocketsec.stage8")
        assert not [m for m in imported if m.startswith(forbidden)], relative
        assert not {"pickle", "subprocess", "socket", "marshal"} & imported, relative
        assert "ExperimentRegistry" not in source and "registry.jsonl" not in source, relative
