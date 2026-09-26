"""Stage 8 package ``labs``: the Counterfactual / Metamorphic Laboratory and the discovery corpus.

Behaviour and failure paths, on real Stage 1 renders: every transform keeps features
consistent with the masks, the semantics table is exact, bounds bound, the trap is true on
TRAIN and worthless held out, the null arm's labels carry no family signal, and the corpus
preconditions hold on a small seed. Corpora here are small (<= 60 sessions per split, §5).
"""

from __future__ import annotations

import random
from dataclasses import replace
from enum import StrEnum

import pytest

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.ssir.relations import Relation, RelationFamily, family_of
from pocketsec.stage2.encoder.ssir_encoder import FEATURE_LAYOUT, GROUP_OFFSETS
from pocketsec.stage6.memory.semantic import is_escalating
from pocketsec.stage6.resources import WorkBudgetExceeded
from pocketsec.stage8.episode import MAX_EPISODE_STEPS, Episode, Split
from pocketsec.stage8.genome.grammar import StepPredicate, parse_mechanism
from pocketsec.stage8.governor.budget import ResearchBudget, ResearchGovernor
from pocketsec.stage8.laboratory.counterfactual import (
    MAX_COUNTERFACTUAL_SET,
    MAX_TIME_BUCKET,
    TRANSFORM_SEMANTICS,
    Semantics,
    TransformKind,
    TransformSpec,
    apply_transform,
    build_counterfactuals,
    counterfactual_set,
    restep,
)
from pocketsec.stage8.laboratory.metamorphic import (
    DEFAULT_RELATIONS,
    Expectation,
    MetamorphicRelation,
    MetamorphicResult,
    run_metamorphic,
)
from pocketsec.stage8.labs.discovery_corpus import (
    DOPPELGANGER_FAMILY_MAP,
    FAMILY_LABELS,
    MAX_DOPPELGANGERS,
    MONITORING_AGENT,
    NATURAL_SPLITS,
    P1_MAX_PHI_AP,
    P2_MARGIN,
    P5_MAX_LOGISTIC_AP,
    PLANTED_MECHANISMS,
    SPLIT_HOSTS,
    CorpusArm,
    CorpusDoppelgangers,
    DiscoveryCorpus,
    Family,
    LabOracle,
    build_discovery_corpus,
    content_label,
    corpus_preconditions,
    planted_label,
    relabel_null,
)

SMALL = {Split.TRAIN: 60, Split.HOLDOUT: 60, Split.REPLICATION: 60, Split.LAB_POOL: 30,
         Split.INDEPENDENT: 30}
PM1 = PLANTED_MECHANISMS[Family.DROP_EXEC_EGRESS]
PM2 = PLANTED_MECHANISMS[Family.REPEATED_EGRESS]
PM1_TWIN = parse_mechanism("CO_OCCURS(EXECUTE+TEMP_LOCATION,CONNECT+EXTERNAL_ENDPOINT)")
EXEC_TEMP = parse_mechanism("SINGLE(EXECUTE+TEMP_LOCATION)").steps[0]
CONNECT_EXT = parse_mechanism("SINGLE(CONNECT+EXTERNAL_ENDPOINT)").steps[0]
WIDTH = dict(FEATURE_LAYOUT)


@pytest.fixture(scope="module")
def planted() -> DiscoveryCorpus:
    return build_discovery_corpus(arm=CorpusArm.PLANTED, seed=0, counts=SMALL)


@pytest.fixture(scope="module")
def null() -> DiscoveryCorpus:
    return build_discovery_corpus(arm=CorpusArm.NULL, seed=0, counts=SMALL)


@pytest.fixture(scope="module")
def dropout() -> DiscoveryCorpus:
    return build_discovery_corpus(arm=CorpusArm.DROPOUT, seed=0, counts=SMALL)


def _family(corpus: DiscoveryCorpus, split: Split, family: Family) -> list[Episode]:
    return [e for e in corpus.episodes(split) if e.context.family == family.value]


def _dee(corpus: DiscoveryCorpus) -> Episode:
    """A TRAIN drop-exec-egress session: trap fork, write, execve, read, connect, send."""
    return _family(corpus, Split.TRAIN, Family.DROP_EXEC_EGRESS)[0]


def _group(step, name: str) -> tuple[float, ...]:
    start = GROUP_OFFSETS[name]
    return step.features[start:start + WIDTH[name]]


def _bits(values: tuple[float, ...]) -> int:
    return sum(1 << i for i, v in enumerate(values) if v > 0.5)


def _consistent(step) -> None:
    """Every mask-derived feature group agrees with the step's own fields."""
    assert _bits(_group(step, "relation_onehot")) == 1 << step.relation
    assert _bits(_group(step, "relation_family_onehot")) == 1 << step.relation_family
    assert step.relation_family == int(family_of(Relation(step.relation)))
    assert _bits(_group(step, "object_semantics")) == step.object_property_mask
    assert _bits(_group(step, "state_delta_raised")) == step.state_delta_mask
    temporal = _group(step, "temporal")
    assert round(temporal[0] * MAX_TIME_BUCKET) == step.time_bucket
    assert temporal[2] == (1.0 if step.time_bucket <= 1 else 0.0)


def _governor(units: int = 50_000_000) -> ResearchGovernor:
    return ResearchGovernor(ResearchBudget(work_units=units))


# --- restep -----------------------------------------------------------------------------


def test_restep_rederives_each_changed_group_to_the_encoders_own_values(planted):
    episode = _dee(planted)
    write = next(s for s in episode.steps if s.relation == Relation.WRITE)
    connect = next(s for s in episode.steps if s.relation == Relation.CONNECT)
    rewritten = restep(write, relation=connect.relation,
                       object_property_mask=connect.object_property_mask,
                       state_delta_mask=connect.state_delta_mask, time_bucket=connect.time_bucket)
    for name in ("relation_onehot", "relation_family_onehot", "object_semantics",
                 "state_delta_raised"):
        assert _group(rewritten, name) == _group(connect, name), name
    assert rewritten.relation_family == connect.relation_family
    assert _group(rewritten, "temporal")[0] == _group(connect, "temporal")[0]
    assert _group(rewritten, "temporal")[2] == _group(connect, "temporal")[2]
    dimension_count = GROUP_OFFSETS["state_delta_scalars"] + 1
    assert rewritten.features[dimension_count] == connect.features[dimension_count]
    _consistent(rewritten)


def test_restep_clears_magnitude_with_the_mask_and_sets_flags(planted):
    step = next(s for s in _dee(planted).steps if s.state_delta_mask)
    cleared = restep(step, state_delta_mask=0)
    scalars = GROUP_OFFSETS["state_delta_scalars"]
    assert cleared.features[scalars] == 0.0 and cleared.features[scalars + 1] == 0.0
    assert not step.observation_incomplete
    assert restep(step, observation_incomplete=True).observation_incomplete
    assert restep(step, host_bucket=9).features[GROUP_OFFSETS["temporal"] + 1] == round(9 / 15, 6)
    orphan = restep(step, parent_signature="0000")
    assert orphan.features[GROUP_OFFSETS["causal"] + 1] == 0.0
    assert restep(orphan, parent_signature="abc123").features[GROUP_OFFSETS["causal"] + 1] == 1.0


@pytest.mark.parametrize("changes", [
    {"features": (0.0,) * 96}, {"relation_family": 2}, {"relation": 99}, {"relation": True},
    {"relation": "CONNECT"}, {"object_property_mask": 1 << 15}, {"state_delta_mask": -1},
    {"time_bucket": MAX_TIME_BUCKET + 1}, {"host_bucket": -1}, {"observation_incomplete": 1},
    {"nonsense": 1},
])
def test_restep_refuses_derived_unknown_and_out_of_range_changes(planted, changes):
    with pytest.raises(ContractError):
        restep(_dee(planted).steps[1], **changes)


# --- the semantics table and transform specs ----------------------------------------------


def test_semantics_table_is_exactly_the_contract():
    preserving = {k for k, v in TRANSFORM_SEMANTICS.items() if v is Semantics.PRESERVING}
    assert preserving == {TransformKind.ACTOR_RENAME, TransformKind.TIMING_SHIFT,
                          TransformKind.PARENT_SUBSTITUTION, TransformKind.EPOCH_CHANGE,
                          TransformKind.DECOY_INSERTION}
    assert {k for k, v in TRANSFORM_SEMANTICS.items() if v is Semantics.DESTROYING} == {
        TransformKind.NECESSARY_STEP_DELETION}
    assert {k for k, v in TRANSFORM_SEMANTICS.items() if v is Semantics.UNKNOWN} == {
        TransformKind.SENSOR_DROPOUT, TransformKind.DESTINATION_CLASS_SWAP,
        TransformKind.REORDER, TransformKind.ACTOR_SPLIT}
    assert set(TRANSFORM_SEMANTICS) == set(TransformKind) and len(TransformKind) == 10


@pytest.mark.parametrize("kind, parameter, target", [
    (TransformKind.SENSOR_DROPOUT, 1001, None), (TransformKind.SENSOR_DROPOUT, True, None),
    (TransformKind.DECOY_INSERTION, 0, None), (TransformKind.ACTOR_RENAME, 0, None),
    (TransformKind.REORDER, 2, None), (TransformKind.TIMING_SHIFT, 16, None),
    (TransformKind.NECESSARY_STEP_DELETION, 1, None), ("EXPLODE", 0, None),
    (TransformKind.REORDER, 0, "CONNECT"),
])
def test_transform_spec_refuses_invalid_input(kind, parameter, target):
    with pytest.raises(ContractError):
        TransformSpec(kind, parameter, target)


# --- every transform on a real episode ----------------------------------------------------

SPECS = {
    TransformKind.ACTOR_RENAME: TransformSpec(TransformKind.ACTOR_RENAME, 3),
    TransformKind.TIMING_SHIFT: TransformSpec(TransformKind.TIMING_SHIFT, 4),
    TransformKind.SENSOR_DROPOUT: TransformSpec(TransformKind.SENSOR_DROPOUT, 1000,
                                                StepPredicate(int(Relation.EXECUTE), 0, 0, 0)),
    TransformKind.PARENT_SUBSTITUTION: TransformSpec(TransformKind.PARENT_SUBSTITUTION, 7),
    TransformKind.DESTINATION_CLASS_SWAP: TransformSpec(TransformKind.DESTINATION_CLASS_SWAP, 0),
    TransformKind.EPOCH_CHANGE: TransformSpec(TransformKind.EPOCH_CHANGE, 2),
    TransformKind.DECOY_INSERTION: TransformSpec(TransformKind.DECOY_INSERTION, 4),
    TransformKind.NECESSARY_STEP_DELETION: TransformSpec(TransformKind.NECESSARY_STEP_DELETION,
                                                         0, EXEC_TEMP),
    TransformKind.REORDER: TransformSpec(TransformKind.REORDER, 0, CONNECT_EXT),
    TransformKind.ACTOR_SPLIT: TransformSpec(TransformKind.ACTOR_SPLIT, 0, CONNECT_EXT),
}


def _check_effect(kind: TransformKind, source: Episode, out: Episode) -> None:
    before, after = source.steps, out.steps
    if kind is TransformKind.ACTOR_RENAME:
        assert [s.actor_slot for s in after] == [s.actor_slot + 3 for s in before]
    elif kind is TransformKind.TIMING_SHIFT:
        assert [s.time_bucket for s in after] == [min(15, s.time_bucket + 4) for s in before]
    elif kind is TransformKind.SENSOR_DROPOUT:
        assert all(s.relation_family != RelationFamily.EXECUTION for s in after)
        assert all(s.observation_incomplete for s in after) and len(after) < len(before)
    elif kind is TransformKind.PARENT_SUBSTITUTION:
        changed = [(a, b) for a, b in zip(before, after, strict=True)
                   if a.parent_signature != b.parent_signature]
        assert changed and all(b.parent_signature.startswith("psub-") for _, b in changed)
    elif kind is TransformKind.DESTINATION_CLASS_SWAP:
        assert not any(CONNECT_EXT.matches(s) for s in after)
    elif kind is TransformKind.EPOCH_CHANGE:
        assert [s.epoch_id for s in after] == [s.epoch_id + 2 for s in before]
    elif kind is TransformKind.DECOY_INSERTION:
        decoys = [s for s in after if s.actor_slot not in source.actors()]
        assert len(after) == len(before) + 4 and len(decoys) == 4
        assert not any(is_escalating(s) for s in decoys)
        assert len({s.actor_slot for s in decoys}) == 4
    elif kind is TransformKind.NECESSARY_STEP_DELETION:
        assert not any(EXEC_TEMP.matches(s) for s in after)
    elif kind is TransformKind.REORDER:
        assert PM1_TWIN.matches(after) and not PM1.matches(after)
    elif kind is TransformKind.ACTOR_SPLIT:
        assert len({s.actor_slot for s in after}) == 2 and not PM1.matches(after)


@pytest.mark.parametrize("kind", list(TransformKind))
def test_every_transform_kind_on_a_real_episode(planted, kind):
    source = _dee(planted)
    assert PM1.matches(source.steps) and source.label == 1
    out = apply_transform(source, SPECS[kind], rng=random.Random(1),
                          donors=planted.episodes(Split.LAB_POOL))
    assert out is not None and out.split is Split.CHALLENGE
    assert 1 <= len(out.steps) <= MAX_EPISODE_STEPS and out.episode_id != source.episode_id
    preserving = TRANSFORM_SEMANTICS[kind] is Semantics.PRESERVING
    assert out.label == (source.label if preserving else None)
    if preserving:  # the planted truth is still there, and PM1 still sees it
        assert PM1.matches(out.steps)
    for step in out.steps:
        _consistent(step)
    _check_effect(kind, source, out)


def test_transforms_that_do_not_apply_return_none(planted):
    source = _dee(planted)
    rng = random.Random(0)
    first = source.steps[0]
    opener = StepPredicate(first.relation, first.object_property_mask, 0, first.state_delta_mask)
    auth = StepPredicate(int(Relation.AUTHENTICATE), 0, 0, 0)
    for spec in (TransformSpec(TransformKind.NECESSARY_STEP_DELETION, 0),        # no target
                 TransformSpec(TransformKind.NECESSARY_STEP_DELETION, 0, auth),  # absent
                 TransformSpec(TransformKind.REORDER, 0, opener),                 # already first
                 TransformSpec(TransformKind.ACTOR_SPLIT, 0, opener),            # opens its actor
                 TransformSpec(TransformKind.SENSOR_DROPOUT, 1000, auth)):       # family absent
        assert apply_transform(source, spec, rng=rng) is None, spec
    with pytest.raises(ContractError):
        apply_transform(source, SPECS[TransformKind.ACTOR_RENAME], rng=None)  # type: ignore[arg-type]


def test_decoy_insertion_respects_the_step_cap_and_flags_truncation(planted):
    source = _family(planted, Split.TRAIN, Family.REPEATED_EGRESS)[0]
    out = apply_transform(source, TransformSpec(TransformKind.DECOY_INSERTION, MAX_EPISODE_STEPS),
                          rng=random.Random(3), donors=planted.episodes(Split.LAB_POOL))
    assert out is not None and len(out.steps) == MAX_EPISODE_STEPS and out.truncated
    assert PM2.matches(out.steps) and out.label == 1


def test_counterfactual_set_is_capped_and_counts_what_the_cap_refused(planted):
    episodes = planted.episodes(Split.LAB_POOL)[:5]
    specs = [SPECS[TransformKind.TIMING_SHIFT], SPECS[TransformKind.EPOCH_CHANGE]]
    batch = build_counterfactuals(episodes, specs, rng=random.Random(0), cap=3)
    assert len(batch.episodes) == 3 and batch.attempted == 3 and batch.truncated == 7
    whole = build_counterfactuals(episodes, specs, rng=random.Random(0), cap=100)
    assert len(whole.episodes) == 10 and whole.truncated == 0 and whole.not_applicable == 0
    assert counterfactual_set(episodes, specs, rng=random.Random(0), cap=3) == batch.episodes
    assert build_counterfactuals(episodes, specs, rng=random.Random(0), cap=0).truncated == 10
    for cap in (-1, MAX_COUNTERFACTUAL_SET + 1, True):
        with pytest.raises(ContractError):
            build_counterfactuals(episodes, specs, rng=random.Random(0), cap=cap)


# --- metamorphic ------------------------------------------------------------------------


def test_default_relations_are_the_five_preserving_invariants_and_one_support_test():
    invariants = [r for r in DEFAULT_RELATIONS if r.expectation is Expectation.INVARIANT]
    assert len(invariants) == 5 and all(r.tolerance == 0.02 for r in invariants)
    assert {r.transform.kind for r in invariants} == {
        k for k, v in TRANSFORM_SEMANTICS.items() if v is Semantics.PRESERVING}
    (support,) = [r for r in DEFAULT_RELATIONS if r.expectation is Expectation.SUPPORT_FALLS]
    assert support.transform.kind is TransformKind.NECESSARY_STEP_DELETION
    assert support.tolerance == 0.5


def test_planted_mechanism_honours_every_default_relation(planted):
    episodes = planted.episodes(Split.LAB_POOL)
    governor = _governor()
    results = run_metamorphic(lambda e: PM1.matches(e.steps), episodes, DEFAULT_RELATIONS,
                              rng=random.Random(0), governor=governor)
    for result in results:
        assert result.applicable > 0 and result.holds is True, result
    assert all(r.agreement == 1.0 for r in results if r.agreement is not None)
    support = results[-1]
    assert support.support_before > 0 and support.support_after == 0
    assert governor.report().spent > 0


def test_a_detector_keyed_on_slot_numbers_is_caught_by_actor_rename(planted):
    def slot_zero_egress(episode: Episode) -> bool:  # right on this corpus, for a wrong reason
        return any(s.actor_slot == 0 and CONNECT_EXT.matches(s) for s in episode.steps)

    (rename,) = [r for r in DEFAULT_RELATIONS if r.transform.kind is TransformKind.ACTOR_RENAME]
    (result,) = run_metamorphic(slot_zero_egress, planted.episodes(Split.LAB_POOL), [rename],
                                rng=random.Random(0), governor=_governor())
    assert result.holds is False and result.agreement is not None and result.agreement < 0.98


def test_support_falls_for_the_trap_and_not_for_a_constant_detector(planted):
    trap = planted.trap_mechanism
    delete_trap = MetamorphicRelation(
        "mr-delete-trap", TransformSpec(TransformKind.NECESSARY_STEP_DELETION, 0, trap.steps[0]),
        Expectation.SUPPORT_FALLS, 0.5)
    (fell,) = run_metamorphic(lambda e: trap.matches(e.steps), planted.episodes(Split.TRAIN),
                              [delete_trap], rng=random.Random(0), governor=_governor())
    assert fell.holds is True and fell.support_after == 0 and fell.support_before > 0
    untargeted = DEFAULT_RELATIONS[-1]
    (constant,) = run_metamorphic(lambda e: True, planted.episodes(Split.LAB_POOL)[:10],
                                  [untargeted], rng=random.Random(0), governor=_governor())
    assert constant.holds is False and constant.support_after == constant.support_before


def test_a_relation_over_nothing_never_holds(planted):
    results = run_metamorphic(lambda e: True, (), DEFAULT_RELATIONS, rng=random.Random(0),
                              governor=_governor())
    assert all(r.applicable == 0 and r.holds is None for r in results)
    (never,) = run_metamorphic(lambda e: False, planted.episodes(Split.LAB_POOL)[:10],
                               [DEFAULT_RELATIONS[-1]], rng=random.Random(0), governor=_governor())
    assert never.holds is None  # no support existed to fall
    with pytest.raises(ContractError):
        MetamorphicResult("mr-x", episodes=0, applicable=0, agreement=None, support_before=0,
                          support_after=0, holds=True)
    with pytest.raises(ContractError):
        MetamorphicRelation("mr-x", DEFAULT_RELATIONS[0].transform, Expectation.INVARIANT, 1.5)


def test_metamorphic_sweep_is_bounded_by_the_governor(planted):
    governor = _governor(units=200)
    with pytest.raises(WorkBudgetExceeded):
        run_metamorphic(lambda e: PM1.matches(e.steps), planted.episodes(Split.LAB_POOL),
                        DEFAULT_RELATIONS, rng=random.Random(0), governor=governor)
    assert governor.report().spent <= 200


# --- the discovery corpus ---------------------------------------------------------------


def test_corpus_preconditions_hold_on_a_small_seed(planted):
    report = corpus_preconditions(planted)
    print("\nPLANTED seed 0 (60/60/60/30/30):", report)  # the values, reported
    assert report.problems == ()
    assert report.phi_oracle_holdout_ap is not None
    assert report.phi_oracle_holdout_ap <= P1_MAX_PHI_AP
    pm1 = dict(report.planted_f1)["PM1"]
    assert pm1 == 1.0 and dict(report.planted_f1) == {"PM1": 1.0, "PM2": 1.0, "PM3": 1.0}
    assert report.best_single_step_holdout_f1 is not None
    assert report.best_single_step_holdout_f1 <= pm1 - P2_MARGIN
    assert report.best_single_step != planted.trap_mechanism.to_dsl()
    assert report.session_unique and report.planted_label_disagreements == 0
    assert all(value > 0 for _, value in report.median_delta_phi)
    assert report.pooled_logistic_holdout_ap is not None
    assert report.pooled_logistic_holdout_ap < P5_MAX_LOGISTIC_AP


def test_p5_holds_only_with_the_trap_in_place(null):
    """The contract's P5 rationale ("SPLIT_ACTORS is its ceiling") is not what we measure:
    on the same content rendered WITHOUT the trap (the NULL arm, scored on content labels)
    the pooled order-free probe separates the families. P5 must not be quoted as evidence
    that order-free pooling cannot express the planted structure."""
    report = corpus_preconditions(null)
    print("\nNULL-arm content (no trap), content labels:", report.pooled_logistic_holdout_ap)
    assert report.pooled_logistic_holdout_ap is not None
    assert report.pooled_logistic_holdout_ap >= P5_MAX_LOGISTIC_AP
    assert any(p.startswith("P5") for p in report.problems)


def test_trap_is_true_on_train_and_near_base_rate_held_out(planted):
    trap = planted.trap_mechanism
    assert trap.to_dsl() == "SINGLE(SPAWN)"  # derived from the encoded fork step
    train = planted.episodes(Split.TRAIN)
    assert all(trap.matches(e.steps) == (e.label == 1) for e in train)
    for split in (Split.HOLDOUT, Split.REPLICATION):
        episodes = planted.episodes(split)
        matched = [e for e in episodes if trap.matches(e.steps)]
        base = sum(e.label for e in episodes) / len(episodes)
        precision = sum(e.label for e in matched) / len(matched)
        assert 0 < len(matched) < len(episodes)
        assert abs(precision - base) < 0.15, (split, precision, base)
        positives = [e for e in episodes if e.label == 1]
        assert any(not trap.matches(e.steps) for e in positives)  # false held out


def test_null_labels_are_independent_of_family_and_relabel_without_rendering(planted, null):
    natural = [e for s in NATURAL_SPLITS for e in null.episodes(s)]
    rate = {cls: [e.label for e in natural if content_label(e) == cls] for cls in (0, 1)}
    share = {cls: sum(v) / len(v) for cls, v in rate.items()}
    assert abs(share[1] - share[0]) < 0.2, share
    assert not any(null.trap_mechanism.matches(e.steps) for e in natural)  # no trap
    again = relabel_null(null, label_seed=7)
    assert [e.episode_id for e in again.episodes(Split.TRAIN)] == [
        e.episode_id for e in null.episodes(Split.TRAIN)]
    assert [e.label for e in again.episodes(Split.TRAIN)] != [
        e.label for e in null.episodes(Split.TRAIN)]
    assert again.label_seed == 7 and again.results is not None
    with pytest.raises(ContractError):
        relabel_null(planted, label_seed=1)
    for split in NATURAL_SPLITS:  # same content: PLANTED minus the trap prefix
        for a, b in zip(planted.episodes(split), null.episodes(split), strict=True):
            relations = [s.relation for s in a.steps]
            if planted.trap_mechanism.matches(a.steps):
                relations = relations[1:]
            assert relations == [s.relation for s in b.steps]
            assert a.context.family == b.context.family


def test_splits_are_leakage_free_and_hold_every_family(planted):
    seen_ids: set[str] = set()
    seen_groups: set[str] = set()
    for split, episodes in planted.splits.items():
        ids = {e.episode_id for e in episodes}
        groups = {s.source_group for e in episodes for s in e.steps}
        assert not ids & seen_ids and not groups & seen_groups, split
        seen_ids |= ids
        seen_groups |= groups
        assert {e.context.host_id for e in episodes} <= set(SPLIT_HOSTS[split])
        if split in NATURAL_SPLITS:
            assert {e.context.family for e in episodes} == {f.value for f in Family}
    assert set(planted.results) == seen_ids
    for episode in planted.episodes(Split.HOLDOUT)[:10]:  # raw evidence kept apart, linked
        transitions = planted.results[episode.episode_id].transitions
        raw = {r.digest for t in transitions for r in t.evidence}
        assert set(episode.evidence_digests()) <= raw
    duplicate = planted.episodes(Split.TRAIN)[0].with_split(Split.HOLDOUT, label=1)
    leaky = {**planted.splits, Split.HOLDOUT: (*planted.episodes(Split.HOLDOUT), duplicate)}
    with pytest.raises(ContractError):
        replace(planted, splits=leaky)


def test_replication_uses_the_family_split_variants(planted):
    for episode in _family(planted, Split.REPLICATION, Family.DROP_EXEC_EGRESS):
        assert PM1.matches(episode.steps)
        paths = {t.object.identity for t in planted.results[episode.episode_id].transitions}
        assert any("/var/tmp/" in p or "/dev/shm/" in p for p in paths)
    for split, low in ((Split.TRAIN, 4), (Split.REPLICATION, 5)):
        for episode in _family(planted, split, Family.REPEATED_EGRESS):
            connects = sum(CONNECT_EXT.matches(s) for s in episode.steps)
            assert low <= connects <= (5 if split is Split.TRAIN else 7)
    for episode in _family(planted, Split.TRAIN, Family.SPLIT_ACTORS):
        assert len(episode.actors()) == 2 and not PM1.matches(episode.steps)


def test_dropout_arm_blinds_half_the_drop_exec_egress_sessions(dropout):
    report = corpus_preconditions(dropout)
    assert not any(p.startswith("P3") for p in report.problems)  # dropped sessions are exempt
    for split in NATURAL_SPLITS:
        family = _family(dropout, split, Family.DROP_EXEC_EGRESS)
        blind = [e for e in family if e.episode_id in dropout.dropout_episode_ids]
        assert len(blind) == len(family) // 2 and blind
        for episode in blind:
            assert episode.label == 1 and not PM1.matches(episode.steps)
            assert all(s.observation_incomplete for s in episode.steps)
            assert all(s.relation_family != RelationFamily.EXECUTION for s in episode.steps)
            assert episode.episode_id in dropout.results


class _Doppelganger(StrEnum):  # stand-in with the falsification package's member names
    ADMIN_SCRIPT = "admin_script"
    MONITORING_AGENT = "monitoring_agent"


def test_doppelganger_families_are_label_zero_and_monitoring_agent_is_source_only(planted):
    source = CorpusDoppelgangers()
    matched_pm2 = 0
    for name in DOPPELGANGER_FAMILY_MAP:
        episodes = source.benign_alternatives(name, count=6, seed=3)
        assert len(episodes) == 6 and all(e.label == 0 for e in episodes)
        assert all(e.split is Split.CHALLENGE and e.context.family == name for e in episodes)
        if name == MONITORING_AGENT:
            matched_pm2 = sum(PM2.matches(e.steps) for e in episodes)
    assert matched_pm2 == 6  # the grammar cannot separate PM2 from its benign twin
    assert source.benign_alternatives(_Doppelganger.ADMIN_SCRIPT, count=1, seed=0)[0].label == 0
    natural = [e for es in planted.splits.values() for e in es]
    assert not any(e.context.family == MONITORING_AGENT for e in natural)
    assert not any(PM2.matches(e.steps) and content_label(e) == 0 for e in natural)
    for bad in (("NOT_A_FAMILY", 1, 0), (MONITORING_AGENT, MAX_DOPPELGANGERS + 1, 0),
                (MONITORING_AGENT, -1, 0), (MONITORING_AGENT, 1, True)):
        with pytest.raises(ContractError):
            source.benign_alternatives(bad[0], count=bad[1], seed=bad[2])


def test_lab_oracle_agrees_with_families_and_charges_the_governor(planted):
    governor = _governor()
    oracle = LabOracle(governor=governor)
    for split in NATURAL_SPLITS:
        for episode in planted.episodes(split):
            assert oracle.label(episode) == FAMILY_LABELS[Family(episode.context.family)]
    assert oracle.issued == sum(len(planted.episodes(s)) for s in NATURAL_SPLITS)
    assert dict(governor.report().spent_by_component)["labs.lab_oracle"] > 0
    starved = LabOracle(governor=_governor(units=1))
    with pytest.raises(WorkBudgetExceeded):
        starved.label(_dee(planted))
    assert starved.issued == 0
    with pytest.raises(ContractError):
        planted_label([object()])  # type: ignore[list-item]


def test_no_vocabulary_signal_beyond_the_trap(planted):
    """Measured, not claimed: which relations occur in one class only, per split."""
    def exclusive(split: Split) -> set[int]:
        by_class = {0: set(), 1: set()}
        for episode in planted.episodes(split):
            by_class[episode.label].update(s.relation for s in episode.steps)
        return by_class[1] - by_class[0]

    assert exclusive(Split.TRAIN) == {int(Relation.SPAWN)}  # the trap, and only the trap
    for split in (Split.HOLDOUT, Split.REPLICATION):
        assert exclusive(split) == set(), split


def test_build_is_deterministic_and_refuses_bad_input():
    tiny = {Split.TRAIN: 9, Split.HOLDOUT: 9, Split.REPLICATION: 9, Split.LAB_POOL: 9,
            Split.INDEPENDENT: 2}
    a = build_discovery_corpus(arm=CorpusArm.PLANTED, seed=5, counts=tiny)
    b = build_discovery_corpus(arm=CorpusArm.PLANTED, seed=5, counts=tiny)
    assert [e.episode_id for e in a.episodes(Split.TRAIN)] == [
        e.episode_id for e in b.episodes(Split.TRAIN)]
    assert {e.context.family for e in a.episodes(Split.TRAIN)} == {f.value for f in Family}
    for counts in ({**tiny, Split.TRAIN: 8}, {**tiny, Split.HOLDOUT: 10_000},
                   {**tiny, Split.LAB_POOL: True}):
        with pytest.raises(ContractError):
            build_discovery_corpus(arm=CorpusArm.PLANTED, seed=5, counts=counts)
    with pytest.raises(ContractError):
        build_discovery_corpus(arm=CorpusArm.PLANTED, seed=True, counts=tiny)
    with pytest.raises(ContractError):
        build_discovery_corpus(arm="SOMETHING", seed=5, counts=tiny)  # type: ignore[arg-type]
