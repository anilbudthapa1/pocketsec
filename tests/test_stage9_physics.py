"""Stage 9 package ``physics``: renormalization, symmetry, conservation, geometry, phase, MSDL.

Every mechanism here is a *candidate* that must beat a dumb control or stay switched off, so
these tests pin the arithmetic that decides that: the FPR-0.05 threshold never admits more
false positives than its budget, an inert mechanism can never be JUSTIFIED, an attribution
twin changes only who did what, the envelope is a true 99th percentile of benign steps, and
every ``compare_*`` answers UNMEASURED with a reason instead of raising on a degenerate split.
Splits are tiny (ambiguous corpus, 12 sessions); the count-240 runs belong to the gate.
"""

from __future__ import annotations

import dataclasses
import random
from collections import Counter
from dataclasses import dataclass

import pytest

from pocketsec.stage1.labs.ambiguous_corpus import build_ambiguous_corpus
from pocketsec.stage1.labs.corpus import Scenario
from pocketsec.stage2.dataset import Stage2Dataset
from pocketsec.stage2.encoder.ssir_encoder import FEATURE_LAYOUT, GROUP_OFFSETS
from pocketsec.stage6.resources import WorkMeter
from pocketsec.stage9.compression import msdl as msdl_module
from pocketsec.stage9.compression.msdl import (
    ZDICT_MAX_BYTES,
    build_bigrams,
    build_zdict,
    compare_msdl_selection,
    compare_surprise,
    compressor_surprise,
    fit_logistic,
    msdl,
    nuisance_leakage,
    probabilistic_surprise,
)
from pocketsec.stage9.genome.expressibility import hand_designed_genomes, phi_oracle_genome
from pocketsec.stage9.geometry import causal as causal_module
from pocketsec.stage9.geometry import phase as phase_module
from pocketsec.stage9.geometry.causal import (
    MAX_MECHANISM_LENGTH,
    MAX_PROTOTYPES,
    TransformationCosts,
    build_benign_manifold,
    compare_causal_geometry,
    mechanism_distance,
    mechanism_sequence,
)
from pocketsec.stage9.geometry.phase import (
    OrderParameter,
    compare_phase,
    cusum_score,
    order_parameter_series,
)
from pocketsec.stage9.labs.splits import compile_scenarios, compile_variant, split_key
from pocketsec.stage9.ontogenesis.fitness import EvaluationSuite, evaluate, session_scores
from pocketsec.stage9.renormalization import laboratory as lab
from pocketsec.stage9.renormalization.laboratory import (
    CHAIN_GAP_NS,
    CoarseGraining,
    ScoredDetector,
    attribution_counterfactuals,
    coarse_grain,
    compare_detectors,
    counterfactual_distinction,
    dataset_feature_bytes,
    feature_bytes,
    fpr_threshold,
    group_widths,
    run_renormalization,
    semantic_conservation,
    verdict_against,
)
from pocketsec.stage9.spec.mssc import DetectorComparison, MechanismVerdict
from pocketsec.stage9.symmetry import conservation as conservation_module
from pocketsec.stage9.symmetry import suite as suite_module
from pocketsec.stage9.symmetry.conservation import (
    candidate_quantities,
    compare_conservation,
    conservation_search,
    envelope_of,
    step_deltas,
)
from pocketsec.stage9.symmetry.suite import (
    Transformation,
    compare_symmetry_breaking,
    invariance,
    permute_actor_slots,
)

COUNT = 12


@pytest.fixture(scope="module")
def train_variant():  # type: ignore[no-untyped-def]
    return compile_variant(count=COUNT, seed=3)


@pytest.fixture(scope="module")
def train(train_variant) -> Stage2Dataset:  # type: ignore[no-untyped-def]
    return train_variant.dataset


@pytest.fixture(scope="module")
def heldout_variant():  # type: ignore[no-untyped-def]
    return compile_variant(count=COUNT, seed=11)


@pytest.fixture(scope="module")
def heldout(heldout_variant) -> Stage2Dataset:  # type: ignore[no-untyped-def]
    return heldout_variant.dataset


@pytest.fixture(scope="module")
def renamed() -> Stage2Dataset:
    return compile_variant(count=COUNT, seed=11, attack_id="rename_binaries").dataset


@pytest.fixture(scope="module")
def scenarios() -> tuple[Scenario, ...]:
    return build_ambiguous_corpus(count=COUNT, seed=11, split="eval")


@pytest.fixture(scope="module")
def pairs(scenarios: tuple[Scenario, ...]) -> tuple[tuple[Scenario, Scenario], ...]:
    return attribution_counterfactuals(scenarios, seed=11)


@pytest.fixture(scope="module")
def pair_dataset(pairs: tuple[tuple[Scenario, Scenario], ...]) -> Stage2Dataset:
    flat = [scenario for pair in pairs for scenario in pair]
    return compile_scenarios(flat, key=split_key(count=COUNT, seed=11)).dataset


def _only(dataset: Stage2Dataset, label: int) -> Stage2Dataset:
    kept = tuple(sample for sample in dataset.samples if sample.label == label)
    return dataclasses.replace(dataset, samples=kept)


# --- decision arithmetic -----------------------------------------------------------------


def test_fpr_threshold_never_admits_more_false_positives_than_the_budget() -> None:
    rng = random.Random(7)
    for trial in range(200):
        n = rng.randrange(1, 90)
        scores = [float(rng.randrange(0, 6)) for _ in range(n)]  # heavy ties on purpose
        threshold = fpr_threshold(scores)
        assert threshold is not None
        above = sum(1 for score in scores if score > threshold)
        assert above <= int(0.05 * n), (trial, n, above)
    assert fpr_threshold([]) is None
    assert fpr_threshold([None, None]) == 0.0  # abstentions rank as 0.0


def test_verdict_rule_margin_and_unmeasured_controls() -> None:
    assert verdict_against(0.72, (("a", 0.70),))[0] is MechanismVerdict.JUSTIFIED
    assert verdict_against(0.71, (("a", 0.70),))[0] is MechanismVerdict.NOT_YET_JUSTIFIED
    assert verdict_against(0.68, (("a", 0.70),))[0] is MechanismVerdict.REJECTED
    assert verdict_against(0.99, (("a", 0.5), ("b", None)))[0] is MechanismVerdict.UNMEASURED
    assert verdict_against(None, (("a", 0.5),))[0] is MechanismVerdict.UNMEASURED
    assert verdict_against(0.9, ())[0] is MechanismVerdict.UNMEASURED


def test_compare_detectors_counts_changed_decisions_against_the_strongest_control() -> None:
    labels = (1, 0, 1, 0)
    train_labels = (0,) * 20 + (1,)
    candidate = ScoredDetector("cand", (0.9, 0.1, 0.8, 0.2), (0.5,) * 20 + (1.0,))
    control = ScoredDetector("ctrl", (0.1, 0.9, 0.2, 0.8), (0.5,) * 20 + (1.0,))
    result = compare_detectors(
        "m:FLAG", "ap", candidate, (control,), heldout_labels=labels, train_labels=train_labels
    )
    assert result.value == 1.0
    assert result.fired == 4  # the candidate calls exactly the opposite sessions
    assert result.verdict is MechanismVerdict.JUSTIFIED


def test_an_inert_mechanism_is_never_justified_however_good_its_ap() -> None:
    # Both detectors' train benign scores sit at 5.0, so neither calls anything positive on
    # held-out: the better AP never changes a single decision and must not be credited.
    labels = (1, 0, 1, 0)
    train_labels = (0,) * 20
    candidate = ScoredDetector("cand", (0.9, 0.1, 0.8, 0.2), (5.0,) * 20)
    control = ScoredDetector("ctrl", (0.1, 0.9, 0.2, 0.8), (5.0,) * 20)
    result = compare_detectors(
        "m:FLAG", "ap", candidate, (control,), heldout_labels=labels, train_labels=train_labels
    )
    assert result.fired == 0
    assert result.verdict is not MechanismVerdict.JUSTIFIED
    assert "INERT" in result.detail


def test_compare_detectors_is_unmeasured_not_raising_on_degenerate_labels() -> None:
    one_class = compare_detectors(
        "m:FLAG", "ap", ScoredDetector("c", (0.1, 0.2)), (ScoredDetector("k", (0.3, 0.4)),),
        heldout_labels=(0, 0),
    )
    misaligned = compare_detectors(
        "m:FLAG", "ap", ScoredDetector("c", (0.1,)), (), heldout_labels=(0, 1)
    )
    for result in (one_class, misaligned):
        assert result.verdict is MechanismVerdict.UNMEASURED and result.fired == 0
        assert "UNMEASURED" in result.detail


# --- renormalization ---------------------------------------------------------------------


def test_group_widths_derived_from_offsets_match_the_encoder_layout() -> None:
    assert group_widths() == dict(FEATURE_LAYOUT)


def test_each_coarse_graining_reduces_feature_bytes_as_specified(heldout: Stage2Dataset) -> None:
    raw = feature_bytes(None)
    assert raw == 96 * 8
    assert feature_bytes(CoarseGraining.R1_DROP_NOVELTY_TEMPORAL) == (96 - 8 - 2 - 3) * 8
    assert feature_bytes(CoarseGraining.R2_RELATION_TO_FAMILY) == (96 - 24) * 8
    assert feature_bytes(CoarseGraining.R3_STATE_ONLY) == (9 + 2 + 2) * 8
    assert feature_bytes(CoarseGraining.R4_LINEAGE_EPISODE) == raw  # R4 removes events instead
    raw_total = dataset_feature_bytes(heldout, None)
    for level in CoarseGraining:
        coarse = coarse_grain(heldout, level)
        assert dataset_feature_bytes(coarse, level) < raw_total, level


def test_coarse_graining_keeps_ids_labels_and_zeroes_groups_and_their_fields(
    heldout: Stage2Dataset,
) -> None:
    widths = group_widths()
    coarse = coarse_grain(heldout, CoarseGraining.R3_STATE_ONLY)
    assert [s.sample_id for s in coarse.samples] == [s.sample_id for s in heldout.samples]
    assert coarse.labels == heldout.labels
    changed = 0
    for before, after in zip(heldout.samples, coarse.samples, strict=True):
        assert len(before.steps) == len(after.steps)
        for old, new in zip(before.steps, after.steps, strict=True):
            start = GROUP_OFFSETS["relation_onehot"]
            assert new.features[start : start + widths["relation_onehot"]] == (0.0,) * 24
            assert (new.relation, new.relation_family, new.time_bucket) == (0, 0, 0)
            assert new.state_delta_mask == old.state_delta_mask  # a kept group is untouched
            assert new.delta_phi == old.delta_phi
            changed += new != old
    assert changed > 0  # the level actually fired on this split


def test_lineage_episode_is_one_summary_step_per_lineage(heldout: Stage2Dataset) -> None:
    coarse = coarse_grain(heldout, CoarseGraining.R4_LINEAGE_EPISODE)
    assert coarse.labels == heldout.labels
    for before, after in zip(heldout.samples, coarse.samples, strict=True):
        slots = list(dict.fromkeys(step.actor_slot for step in before.steps))
        assert [step.actor_slot for step in after.steps] == slots
        for summary in after.steps:
            steps = [s for s in before.steps if s.actor_slot == summary.actor_slot]
            mask = 0
            for step in steps:
                mask |= step.state_delta_mask
            assert summary.state_delta_mask == mask
            assert summary.delta_phi == pytest.approx(sum(s.delta_phi for s in steps))
            assert summary.features[73] == max(s.features[73] for s in steps)
            assert set(summary.evidence) == {e for s in steps for e in s.evidence}


_IDENTITY = ("pid", "start_time")


def _identity_free(scenario: Scenario) -> list[tuple[str, tuple[tuple[str, str], ...]]]:
    return [
        (b.operation, tuple(sorted((k, v) for k, v in b.fields.items() if k not in _IDENTITY)))
        for b in scenario.behaviours
    ]


def test_attribution_counterfactual_changes_only_actor_attribution(
    scenarios: tuple[Scenario, ...], pairs: tuple[tuple[Scenario, Scenario], ...]
) -> None:
    assert len(pairs) == sum(1 for s in scenarios if s.label == 1) > 0
    corpus_pids = {b.fields["pid"] for s in scenarios for b in s.behaviours}
    for original, twin in pairs:
        assert (original.label, twin.label) == (1, 0)
        # Same operations, same fields, same order, same gaps: only who did it differs.
        assert _identity_free(original) == _identity_free(twin)
        assert Counter(_identity_free(original)) == Counter(_identity_free(twin))
        twin_pids = [b.fields["pid"] for b in twin.behaviours]
        assert not set(twin_pids) & corpus_pids  # session-unique: no carried lineage state
        stages = [
            i for i, b in enumerate(original.behaviours) if int(b.fields["_gap_ns"]) >= CHAIN_GAP_NS
        ]
        assert len({original.behaviours[i].fields["pid"] for i in stages}) == 1  # one owner
        chain_pids = [twin_pids[i] for i in stages]
        assert len(set(chain_pids)) == len(stages)  # spread over distinct actors
        routine = [i for i in range(len(twin_pids)) if i not in stages]
        assert set(chain_pids) <= {twin_pids[i] for i in routine}  # existing actors, not new
        owner = original.behaviours[stages[0]].fields["pid"]
        renamed_owner = {
            twin_pids[i] for i in routine if original.behaviours[i].fields["pid"] == owner
        }
        assert not renamed_owner & set(chain_pids)  # the owner no longer does any stage
        rename = {original.behaviours[i].fields["pid"]: twin_pids[i] for i in routine}
        assert len(set(rename.values())) == len(rename)  # routine partition kept (a bijection)


def test_attribution_twins_compile_interleaved_and_are_distinguished(
    pair_dataset: Stage2Dataset,
) -> None:
    assert pair_dataset.labels == (1, 0) * (len(pair_dataset) // 2)
    scores = session_scores(hand_designed_genomes()["H2"], pair_dataset)
    record = counterfactual_distinction("raw", pair_scores_before=scores, pair_scores_after=scores)
    assert record.pairs == len(pair_dataset) // 2
    assert record.distinguished_before > 0  # the pair construction yields a real distinction


def test_generic_semantic_conservation_counts_on_hand_vectors() -> None:
    train_benign = [0.1 * i for i in range(20)]  # threshold = 2nd largest = 1.8
    record = semantic_conservation(
        "hand", train_scores_before=train_benign, scores_before=[2.0, 1.0, 1.9, 0.5],
        scores_after=[2.0, 1.9, 1.0, 0.5], labels=[1, 0, 1, 0], bytes_before=100, bytes_after=40,
    )
    assert record.decisions_changed == 2
    assert record.decision_agreement == 0.5
    assert record.ap_before == 1.0
    assert record.ap_after == pytest.approx(0.5 + (2 / 3) * 0.5)
    assert (record.bytes_before, record.bytes_after) == (100, 40)
    unfitted = semantic_conservation(
        "hand", train_scores_before=[], scores_before=[1.0], scores_after=[1.0], labels=[1],
        bytes_before=1, bytes_after=1,
    )
    assert unfitted.decision_agreement is None and unfitted.ap_before is None
    with pytest.raises(ValueError):
        semantic_conservation(
            "bad", train_scores_before=[0.0], scores_before=[1.0], scores_after=[1.0, 2.0],
            labels=[1], bytes_before=1, bytes_after=1,
        )


def test_generic_counterfactual_distinction_counts_on_hand_vectors() -> None:
    record = counterfactual_distinction(
        "hand", pair_scores_before=[0.9, 0.1, 0.5, 0.5, 0.7, 0.2],
        pair_scores_after=[0.9, 0.1, 0.6, 0.5, 0.1, 0.2],
    )
    assert (record.pairs, record.distinguished_before, record.distinguished_after) == (3, 2, 2)
    assert record.lost == 1  # pair 3 was told apart before and is not after
    with pytest.raises(ValueError):
        counterfactual_distinction("odd", pair_scores_before=[1.0], pair_scores_after=[1.0])


def test_run_renormalization_returns_a_verdict_bounded_fixed_point_and_firing(
    train: Stage2Dataset, heldout: Stage2Dataset, pair_dataset: Stage2Dataset
) -> None:
    result = run_renormalization(phi_oracle_genome(), train, heldout, pair_dataset, seed=11)
    assert isinstance(result.verdict, MechanismVerdict)
    assert len(result.conservation) == len(result.counterfactual) == len(CoarseGraining)
    assert all(cf.pairs == len(pair_dataset) // 2 for cf in result.counterfactual)
    assert 1 <= result.fixed_point_iterations <= lab.FIXED_POINT_MAX_ITERATIONS
    assert result.fired > 0
    assert not (result.verdict is MechanismVerdict.JUSTIFIED and result.fired == 0)


def test_run_renormalization_is_unmeasured_on_degenerate_input(
    train: Stage2Dataset, heldout: Stage2Dataset, pair_dataset: Stage2Dataset
) -> None:
    empty_pairs = dataclasses.replace(pair_dataset, samples=())
    for held, pairs in ((_only(heldout, 0), pair_dataset), (heldout, empty_pairs)):
        result = run_renormalization(phi_oracle_genome(), train, held, pairs, seed=1)
        assert result.verdict is MechanismVerdict.UNMEASURED


# --- symmetry and conservation -----------------------------------------------------------


def test_permuting_actor_slots_leaves_the_phi_oracle_invariant(heldout: Stage2Dataset) -> None:
    permuted = permute_actor_slots(heldout, seed=5)
    moved = sum(
        a.actor_slot != b.actor_slot
        for x, y in zip(heldout.samples, permuted.samples, strict=True)
        for a, b in zip(x.steps, y.steps, strict=True)
    )
    assert moved > 0  # the permutation really renamed lineages
    for genome in (phi_oracle_genome(), hand_designed_genomes()["H2"]):
        test = invariance(genome, heldout, permuted, Transformation.ACTOR_SLOT_PERMUTATION)
        assert test.invariant is True and test.score_changed == 0 and test.sessions == len(heldout)


def test_unperformable_transformations_are_unmeasured_never_invariant(
    heldout: Stage2Dataset,
) -> None:
    genome = phi_oracle_genome()
    for transformation in (
        Transformation.HOST_IDENTITY, Transformation.INTERPRETER_SUBSTITUTION,
        Transformation.LEARNED,
    ):
        test = invariance(genome, heldout, heldout, transformation)
        assert test.invariant is None and test.max_abs_delta is None
        assert test.reason.startswith("UNMEASURED")
    missing = invariance(genome, heldout, None, Transformation.PATH_CLASS)
    assert missing.invariant is None


def test_a_session_absent_from_the_transformed_split_counts_as_changed(
    heldout: Stage2Dataset,
) -> None:
    shorter = dataclasses.replace(heldout, samples=heldout.samples[1:])
    test = invariance(phi_oracle_genome(), heldout, shorter, Transformation.BENIGN_REORDER)
    assert test.invariant is False and test.score_changed >= 1


def test_envelope_is_the_nearest_rank_99th_percentile() -> None:
    assert envelope_of([float(v) for v in range(100, 0, -1)]) == 99.0
    assert envelope_of([float(v) for v in range(1, 1001)]) == 990.0
    assert envelope_of([5.0]) == 5.0
    assert envelope_of([]) is None
    with pytest.raises(ValueError):
        envelope_of([1.0], quantile=0.0)


def test_candidate_quantities_are_bounded_genomes() -> None:
    quantities = candidate_quantities()
    assert len(quantities) == 4 + 13
    assert len({q.name for q in quantities}) == 17
    assert sum(q.name.startswith("projection/") for q in quantities) == 13
    for quantity in quantities:
        assert quantity.genome.bounds.update_wu_per_event <= 64


def test_sum_dphi_step_deltas_are_exactly_the_per_step_abs_dphi(heldout: Stage2Dataset) -> None:
    quantity = next(q for q in candidate_quantities() if q.name == "sum(delta-phi)")
    deltas = step_deltas(quantity, heldout)
    for sample, row in zip(heldout.samples, deltas, strict=True):
        assert sorted(row) == pytest.approx(sorted(abs(s.delta_phi) for s in sample.steps))


def test_conservation_envelope_is_fitted_on_train_benign_steps_only(
    train: Stage2Dataset, heldout: Stage2Dataset
) -> None:
    permuted = permute_actor_slots(heldout, seed=5)
    invariants = [
        invariance(phi_oracle_genome(), heldout, permuted, Transformation.ACTOR_SLOT_PERMUTATION),
        invariance(phi_oracle_genome(), heldout, None, Transformation.LEARNED),
    ]
    tests = conservation_search(train, heldout, invariants)
    assert len(tests) == 17
    by_name = {t.quantity: t for t in tests}
    quantity = next(q for q in candidate_quantities() if q.name == "sum(delta-phi)")
    benign_steps = [
        d for row, label in zip(step_deltas(quantity, train), train.labels, strict=True)
        if label == 0 for d in row
    ]
    assert by_name["sum(delta-phi)"].envelope == envelope_of(benign_steps)
    assert all(t.noether_pair is not None and "ACTOR_SLOT" in t.noether_pair for t in tests)
    comparison = compare_conservation(tests, heldout, train=train)
    assert isinstance(comparison.verdict, MechanismVerdict) and comparison.fired >= 0


# --- geometry and phase ------------------------------------------------------------------


def test_mechanism_distance_is_zero_on_identity_symmetric_and_bounded() -> None:
    rng = random.Random(3)

    def draw(n: int) -> tuple[tuple[int, int], ...]:
        return tuple((rng.randrange(8), rng.randrange(512)) for _ in range(n))

    for _ in range(40):
        a, b = draw(rng.randrange(0, 12)), draw(rng.randrange(0, 12))
        assert mechanism_distance(a, a) == 0.0
        assert mechanism_distance(a, b) == mechanism_distance(b, a)
        assert 0.0 <= mechanism_distance(a, b) <= len(a) + len(b)
    long_a, long_b = draw(200), draw(300)
    assert mechanism_distance(long_a, long_b) <= 2 * MAX_MECHANISM_LENGTH  # truncated first
    swap = mechanism_distance(((1, 0), (2, 0)), ((2, 0), (1, 0)))
    assert swap == 0.5  # "change causal ordering" is one cheap edit, not two substitutions
    assert mechanism_distance(((1, 0b1),), ((1, 0b11),)) == 0.5  # one privilege-bit change
    with pytest.raises(ValueError):
        TransformationCosts(insert=-1.0)


def test_mechanism_sequences_and_manifold_are_bounded(train: Stage2Dataset) -> None:
    sample = train.samples[0]
    seq = mechanism_sequence(sample, 0)
    assert 0 < len(seq) <= MAX_MECHANISM_LENGTH
    manifold = build_benign_manifold(train)
    assert 0 < len(manifold) <= MAX_PROTOTYPES
    assert build_benign_manifold(_only(train, 1)) == ()


def test_order_parameter_series_and_cusum(heldout: Stage2Dataset) -> None:
    sample = heldout.samples[0]
    for parameter in OrderParameter:
        series = order_parameter_series(sample, parameter)
        assert len(series) == len(sample.steps)
    rate = order_parameter_series(sample, OrderParameter.TRANSITION_RATE)
    assert all(0.0 <= value <= 1.0 for value in rate)
    peak = max(abs(s.delta_phi) for s in sample.steps)
    assert cusum_score(sample) >= max(0.0, peak - 0.5)
    empty = dataclasses.replace(sample, steps=())
    assert cusum_score(empty) == 0.0


# --- compression -------------------------------------------------------------------------


def test_zlib_dictionary_is_bounded_and_the_dictionary_fires(train: Stage2Dataset) -> None:
    benign = [s for s in train.samples if s.label == 0]
    zdict = build_zdict(benign * 60)
    assert 0 < len(zdict) <= ZDICT_MAX_BYTES
    sample = train.samples[0]
    assert compressor_surprise(sample, zdict) == compressor_surprise(sample, zdict)
    assert compressor_surprise(sample, zdict) != compressor_surprise(sample, b"")
    with pytest.raises(ValueError):
        compressor_surprise(sample, b"x" * (ZDICT_MAX_BYTES + 1))
    bigrams = build_bigrams(benign)
    assert probabilistic_surprise(sample, bigrams) > 0.0


def test_logistic_fit_is_deterministic_and_orders_a_separable_signal() -> None:
    scores, labels = [0.1, 0.2, 0.3, 0.7, 0.8, 0.9], [0, 0, 0, 1, 1, 1]
    first = fit_logistic(scores, labels)
    assert first == fit_logistic(scores, labels)
    assert first[0] > 0.0
    with pytest.raises(ValueError):
        fit_logistic([], [])


@pytest.fixture(scope="module")
def train_suite(train_variant):  # type: ignore[no-untyped-def]
    return EvaluationSuite(name="physics-train", clean=train_variant, attacked=())


@pytest.fixture(scope="module")
def heldout_suite(heldout_variant):  # type: ignore[no-untyped-def]
    return EvaluationSuite(name="physics-heldout", clean=heldout_variant, attacked=())


def test_msdl_is_finite_and_deterministic(train: Stage2Dataset, train_suite) -> None:  # type: ignore[no-untyped-def]
    genome = phi_oracle_genome()
    record = evaluate(genome, train_suite, meter=WorkMeter())
    first, second = msdl(genome, record, train), msdl(genome, record, train)
    assert first == second
    assert first.total is not None
    for value in (first.program_bits, first.residual_bits, first.runtime_term, first.fp_term,
                  first.adversarial_term, first.total):
        assert value is not None and value == value and abs(value) < float("inf")
    assert first.program_bits == genome.description_length_bits()
    assert first.runtime_term == msdl_module.LAMBDA_RUNTIME * record.wu_per_event


def test_nuisance_leakage_is_none_without_a_nuisance_label(heldout: Stage2Dataset) -> None:
    single = dataclasses.replace(heldout, samples=heldout.samples[:1])
    assert nuisance_leakage(phi_oracle_genome(), single) is None
    leak = nuisance_leakage(phi_oracle_genome(), heldout)
    assert leak is None or 0.0 <= leak <= 1.0


@dataclass(frozen=True)
class _Run:
    """A duck-typed stand-in for ``ontogenesis.search.SearchRun`` (records and genomes only)."""

    genomes: tuple
    records: tuple


def test_msdl_selection_returns_a_verdict_and_counts_divergent_choices(
    train: Stage2Dataset, train_suite, heldout_suite  # type: ignore[no-untyped-def]
) -> None:
    genomes = (phi_oracle_genome(), hand_designed_genomes()["H1"], hand_designed_genomes()["H2"])
    records = tuple(evaluate(g, train_suite, meter=WorkMeter()) for g in genomes)
    runs = [_Run(genomes, records), _Run(genomes[::-1], records[::-1])]
    result = compare_msdl_selection(runs, heldout_suite, train=train)  # type: ignore[arg-type]
    assert isinstance(result, DetectorComparison)
    assert result.verdict is not MechanismVerdict.UNMEASURED
    assert 0 <= result.fired <= len(runs)
    assert compare_msdl_selection(runs, heldout_suite).verdict is MechanismVerdict.UNMEASURED  # type: ignore[arg-type]
    no_runs = compare_msdl_selection([], heldout_suite, train=train)
    assert no_runs.verdict is MechanismVerdict.UNMEASURED


# --- every compare_* on real tiny splits and on degenerate ones ---------------------------


def _checked(result: DetectorComparison, flag_module: object, flag: str) -> DetectorComparison:
    assert result.mechanism.endswith(f":{flag}")
    assert getattr(flag_module, flag) is False  # read from code, never from a document
    assert isinstance(result.verdict, MechanismVerdict) and result.fired >= 0
    assert not (result.verdict is MechanismVerdict.JUSTIFIED and result.fired == 0)
    return result


def test_every_compare_returns_a_verdict_and_a_fired_count(
    train: Stage2Dataset, heldout: Stage2Dataset, renamed: Stage2Dataset
) -> None:
    genome = hand_designed_genomes()["H2"]
    _checked(
        compare_symmetry_breaking(genome, heldout, [renamed], train_clean=train,
                                  train_variants=[permute_actor_slots(train, seed=1)]),
        suite_module, "SYMMETRY_BREAKING_DEFAULT_ENABLED",
    )
    _checked(compare_causal_geometry(train, heldout), causal_module,
             "CAUSAL_GEOMETRY_DEFAULT_ENABLED")
    observations, comparison = compare_phase(train, heldout)
    assert len(observations) == len(OrderParameter)
    _checked(comparison, phase_module, "PHASE_OBSERVATORY_DEFAULT_ENABLED")
    _checked(compare_surprise(train, heldout), msdl_module, "SURPRISE_DEFAULT_ENABLED")
    assert lab.RENORMALIZATION_DEFAULT_ENABLED is False
    assert conservation_module.CONSERVATION_DEFAULT_ENABLED is False
    assert msdl_module.MSDL_SELECTION_DEFAULT_ENABLED is False


def test_every_compare_is_unmeasured_not_raising_on_degenerate_splits(
    train: Stage2Dataset, heldout: Stage2Dataset
) -> None:
    benign_only, malicious_only = _only(heldout, 0), _only(train, 1)
    phi = phi_oracle_genome()
    results = [
        compare_symmetry_breaking(phi, heldout, []),
        compare_symmetry_breaking(phi, benign_only, [benign_only]),
        compare_conservation([], heldout),
        compare_causal_geometry(malicious_only, heldout),
        compare_causal_geometry(train, benign_only),
        compare_phase(_only(train, 0), benign_only)[1],
        compare_surprise(malicious_only, heldout),
        compare_surprise(train, benign_only),
    ]
    for result in results:
        assert result.verdict is MechanismVerdict.UNMEASURED, result
        assert result.fired == 0 and "UNMEASURED" in result.detail
