"""Stage 6 evolution package: plasticity field + masks, competition, HELIOS chamber, MNEMOSYNE.

Every test here exercises behaviour or a refusal path. The chamber tests run on
real gateway-issued verdicts built from the Stage 2 drift corpus through the
Stage 1 pipeline, so "issued" means what the controller will mean by it.
"""

from __future__ import annotations

import dataclasses
import hashlib

import pytest

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage0.contracts.threat_prediction_v1 import Verdict
from pocketsec.stage1.epoch.model import Epoch, SystemIdentity
from pocketsec.stage1.pipeline import Stage1Pipeline
from pocketsec.stage1.ssir.entities import SemanticProperty as P
from pocketsec.stage2.encoder.ssir_encoder import FEATURE_WIDTH, feature_names
from pocketsec.stage2.labs.drift_corpus import build_drift_corpus
from pocketsec.stage6.capsule.experience_capsule import (
    EncodedStep,
    LabelAssertion,
    LabelOrigin,
    SourceClass,
    SourceProvenance,
    capsule_from_scenario,
    source_group_of,
)
from pocketsec.stage6.capsule.quarantine import QuarantineBucket, QuarantineGateway
from pocketsec.stage6.chamber.evolution import (
    FPR_BUDGET,
    HOLDOUT_SHARE,
    MAX_CHAMBER_CAPSULES,
    CandidateKind,
    EvolutionChamber,
    KnowledgeDelta,
    UnquarantinedInputError,
    induce_motifs,
)
from pocketsec.stage6.consolidator.mnemosyne import (
    MAX_DORMANT_SEQUENCES,
    Consolidation,
    MnemosyneConsolidator,
    consolidation_allowed,
)
from pocketsec.stage6.constitution.learning import property_mask, raised_mask, touches_protected
from pocketsec.stage6.fossils.lineage import KnowledgeLineageDAG, NodeKind
from pocketsec.stage6.fossils.store import FossilStore
from pocketsec.stage6.memory.competition import (
    CompetitionOutcome,
    compete_knowledge,
    newest_wins,
    oldest_wins,
    overlaps,
)
from pocketsec.stage6.memory.episodic import (
    EpisodeSkeleton,
    EpisodicMemory,
    episode_value,
    skeleton_from_capsule,
)
from pocketsec.stage6.memory.semantic import (
    ALL_CONTEXTS,
    ItemKind,
    ItemLineage,
    ItemStatus,
    ItemValidation,
    KnowledgeItem,
    MotifStep,
    context_id_for,
    genesis_state,
    motif_pattern_key,
)
from pocketsec.stage6.plasticity.field import (
    PLASTICITY_FLOOR,
    PlasticityTerms,
    compute_plasticity_field,
    plasticity,
)
from pocketsec.stage6.plasticity.masks import (
    MASK_EXPIRY_SEQUENCES,
    MAX_ITEM_MUTATIONS,
    MAX_THRESHOLD_DELTA,
    PlasticityMask,
    field_only_freezes,
    generate_plasticity_mask,
    uniform_mask,
)
from pocketsec.stage6.resources import ResourceSnapshot, WorkBudgetExceeded, WorkMeter

READ, WRITE, CONNECT, SEND = 2, 3, 7, 10
IDENTITY = SystemIdentity(kernel_id="k-evolution-a")
OTHER_IDENTITY = SystemIdentity(kernel_id="k-evolution-b")
CTX_A = context_id_for(IDENTITY)
CTX_B = context_id_for(OTHER_IDENTITY)
_NAMES = feature_names()


# --- hand-built steps, skeletons and items ------------------------------------------


def _digest(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


def _step(relation: int, props=(), raised=(), *, actor: int = 0, tag: str = "t") -> EncodedStep:
    features = [0.0] * FEATURE_WIDTH
    for prop in props:
        features[_NAMES.index(f"object.{prop.value}")] = 1.0
    for dim in raised:
        features[_NAMES.index(f"raised.{dim}")] = 1.0
    return EncodedStep(
        features=tuple(features),
        relation=relation,
        relation_family=0,
        state_delta_mask=raised_mask(raised),
        time_bucket=0,
        delta_phi=0.0,
        object_property_mask=property_mask(props),
        epoch_id=0,
        actor_slot=actor,
        uncertainty=0.0,
        source_group=source_group_of(f"proc:{tag}:{actor}"),
        causal_signature="",
        parent_signature="",
        evidence=(_digest(f"{tag}:{relation}:{actor}"),),
    )


def _skeleton(eid: str, steps, verdict: Verdict, *, context: str = CTX_A) -> EpisodeSkeleton:
    anchors = sorted(
        {a for s in steps for a in touches_protected(s.object_property_mask, s.state_delta_mask)}
    )
    return EpisodeSkeleton(
        episode_id=eid,
        steps=tuple(steps),
        verdict=verdict,
        label_origin=LabelOrigin.GROUND_TRUTH,
        epoch_id=0,
        context_id=context,
        visibility_mask=(1 << len(steps)) - 1,
        anchors_touched=tuple(anchors),
        truncated=False,
    )


def _detector(
    motif,
    *,
    weight: float = 0.8,
    contexts=(ALL_CONTEXTS,),
    last: int = 0,
    status: ItemStatus = ItemStatus.ACTIVE,
) -> KnowledgeItem:
    return KnowledgeItem.build(
        kind=ItemKind.DETECTOR,
        context_ids=set(contexts),
        pattern_key=motif_pattern_key(motif),
        weight=weight,
        origin_verdict=Verdict.MALICIOUS,
        lineage=ItemLineage("cand-fixture", ("cap-fixture",), (_digest("fixture"),), ()),
        validation=ItemValidation(1, 0, 0, 0, last, frozenset({0})),
        motif=tuple(motif),
        status=status,
    )


def _baseline(
    context: str, *, relation: int = WRITE, last: int = 0, status: ItemStatus = ItemStatus.ACTIVE
) -> KnowledgeItem:
    anchor = [0.0] * 26
    anchor[5] = 1.0  # object.SYSTEM_BINARY: no protected anchor
    return KnowledgeItem.build(
        kind=ItemKind.BASELINE,
        context_ids={context},
        pattern_key=f"relation:{relation}",
        weight=1.0,
        origin_verdict=Verdict.BENIGN,
        lineage=ItemLineage("cand-fixture", ("cap-fixture",), (_digest("fixture"),), ()),
        validation=ItemValidation(1, 0, 0, 0, last, frozenset({0})),
        anchor=tuple(anchor),
        status=status,
    )


def _snapshot(**overrides) -> ResourceSnapshot:
    values = dict(
        memory_pressure=0.1,
        cpu_load=0.1,
        incident_urgency=0.0,
        disk_free_bytes=1 << 34,
        thermal_ok=True,
        unmeasured=(),
    )
    values.update(overrides)
    return ResourceSnapshot(**values)


# --- the real gateway fixture ---------------------------------------------------------


@dataclasses.dataclass
class World:
    gateway: QuarantineGateway
    lineage: KnowledgeLineageDAG
    episodic: EpisodicMemory
    verdicts: list
    capsules: list
    trusted: object


@pytest.fixture(scope="module")
def world() -> World:
    """24 drift-corpus sessions: Stage 1 -> capsule -> the real gateway -> episodic memory."""
    from pocketsec.stage6.provenance.ledger import ProvenanceLedger

    pipeline = Stage1Pipeline()
    epoch = Epoch(epoch_id=0, identity=IDENTITY, key=IDENTITY.key(), opened_at_ns=0)
    trusted = genesis_state(identity=IDENTITY)
    lineage = KnowledgeLineageDAG()
    # The lab's four groups are the authenticated ground truth here (review S6-AUTH-01).
    gateway = QuarantineGateway(ledger=ProvenanceLedger(), lineage=lineage,
                                ground_truth_groups=[f"lab:{i}" for i in range(4)])
    gateway.bind_trusted_view(lambda: trusted)
    episodic = EpisodicMemory()
    verdicts, capsules = [], []
    for index, scenario in enumerate(build_drift_corpus(count=24, seed=11)):
        verdict = Verdict.MALICIOUS if scenario.label else Verdict.BENIGN
        provenance = SourceProvenance(
            source_class=SourceClass.LAB_GROUND_TRUTH,
            source_id="lab",
            independence_group=f"lab:{index % 4}",
            label_origin=LabelOrigin.GROUND_TRUTH,
            transformation_lineage=("stage1.pipeline",),
            host_id="host-1",
        )
        label = LabelAssertion(
            verdict=verdict,
            origin=LabelOrigin.GROUND_TRUTH,
            asserted_by="lab",
            target_capsule_id="",
        )
        capsule = capsule_from_scenario(
            pipeline.run_scenario(scenario),
            epoch=epoch,
            provenance=provenance,
            sequence=index,
            label=label,
        )
        issued = gateway.admit(capsule)
        skeleton = skeleton_from_capsule(
            capsule, verdict=verdict, label_origin=LabelOrigin.GROUND_TRUTH
        )
        value = episode_value(
            skeleton,
            trust=issued.trust,
            suspicion_summary=issued.suspicion.summary(),
            resident=episodic.episodes(),
            trusted=trusted,
        )
        episodic.admit_episode(skeleton, value=value, verdict_id=issued.verdict_id)
        verdicts.append(issued)
        capsules.append(capsule)
    assert all(v.bucket is QuarantineBucket.TRUSTED_CANDIDATE for v in verdicts)
    return World(gateway, lineage, episodic, verdicts, capsules, trusted)


def _chamber(world: World, **kwargs) -> tuple[EvolutionChamber, MnemosyneConsolidator]:
    consolidator = MnemosyneConsolidator(fossils=FossilStore(), lineage=world.lineage)
    return EvolutionChamber(
        gateway=world.gateway, episodic=world.episodic, consolidator=consolidator, **kwargs
    ), consolidator


def _calibrated(world: World):
    """Genesis alerts on every session (U = 0.5 = threshold); the first candidate calibrates it.

    Only the threshold move is kept, so the returned state holds no detector and
    the next spawn still has motifs to learn.
    """
    chamber, _ = _chamber(world)
    first = chamber.spawn_evolution_candidate(
        trusted=world.trusted, verdicts=world.verdicts, admissions=(), half_lives=(), sequence=100
    )
    assert first is not None and CandidateKind.CALIBRATION in first.kinds
    return world.trusted.with_changes(threshold=first.delta.threshold)


# --- D6.6 plasticity field -------------------------------------------------------------


def _terms(cid: str, **overrides) -> PlasticityTerms:
    values = dict(
        novelty=1.0,
        validation=1.0,
        stability=1.0,
        utility=1.0,
        forgetting_risk=0.0,
        contradiction=0.0,
        poison=0.0,
        budget_pressure=0.0,
    )
    values.update(overrides)
    return PlasticityTerms(component_id=cid, **values)


def test_plasticity_is_the_architecture_formula_and_terms_are_bounded() -> None:
    terms = _terms("c", novelty=0.5, validation=0.5, utility=0.8, forgetting_risk=0.5, poison=0.5)
    assert plasticity(terms) == pytest.approx(0.5 * 0.5 * 1.0 * 0.8 / (1 + 0.5 + 0.0 + 0.5 + 0.0))
    for bad in (-0.1, 1.5, float("nan")):
        with pytest.raises(ContractError):
            _terms("c", utility=bad)
    with pytest.raises(ContractError):
        compute_plasticity_field([_terms("c"), _terms("c", utility=0.2)])
    field = compute_plasticity_field([_terms("b"), _terms("a", utility=0.0)])
    assert field.component_ids() == ("a", "b")
    assert field.value("never-scored") == 0.0  # an unscored component is frozen, not guessed


def test_mask_bounds_are_enforced_at_construction() -> None:
    with pytest.raises(ContractError):
        PlasticityMask(frozenset({"x"}), frozenset({"x"}), 1, 0.0, 10)
    with pytest.raises(ContractError):
        PlasticityMask(frozenset(), frozenset(), MAX_ITEM_MUTATIONS + 1, 0.0, 10)
    with pytest.raises(ContractError):
        PlasticityMask(frozenset(), frozenset(), 1, MAX_THRESHOLD_DELTA + 0.01, 10)
    with pytest.raises(ContractError):
        uniform_mask(
            ["a"], protected=frozenset(), now_sequence=0, max_item_mutations=MAX_ITEM_MUTATIONS + 1
        )


def test_expired_mask_permits_nothing() -> None:
    mask = uniform_mask(["a", "threshold"], protected=frozenset(), now_sequence=100)
    assert mask.expires_at_sequence == 100 + MASK_EXPIRY_SEQUENCES
    assert mask.permits("a", now_sequence=100 + MASK_EXPIRY_SEQUENCES - 1)
    assert not mask.permits("a", now_sequence=100 + MASK_EXPIRY_SEQUENCES)
    assert mask.threshold_budget(now_sequence=100 + MASK_EXPIRY_SEQUENCES) == 0.0


def test_protected_component_is_frozen_whatever_its_plasticity() -> None:
    field = compute_plasticity_field([_terms("guard"), _terms("free")])
    assert field.value("guard") == 1.0  # maximally plastic by the field
    for mask in (
        generate_plasticity_mask(field, protected=frozenset({"guard", "unscored"}), now_sequence=0),
        uniform_mask(field.component_ids(), protected=frozenset({"guard"}), now_sequence=0),
    ):
        assert "guard" in mask.frozen_core and not mask.permits("guard", now_sequence=0)
        assert mask.permits("free", now_sequence=0)


def test_field_freezes_what_uniform_allows_at_identical_budgets() -> None:
    field = compute_plasticity_field(
        [_terms("weak", utility=PLASTICITY_FLOOR / 2), _terms("strong")]
    )
    field_mask = generate_plasticity_mask(field, protected=frozenset(), now_sequence=0)
    control = uniform_mask(field.component_ids(), protected=frozenset(), now_sequence=0)
    # Lesson 4: the budget is the knob, so the control holds it fixed.
    assert (field_mask.max_item_mutations, field_mask.max_threshold_delta) == (
        control.max_item_mutations,
        control.max_threshold_delta,
    )
    assert not field_mask.permits("weak", now_sequence=0) and control.permits(
        "weak", now_sequence=0
    )
    assert field_only_freezes(field_mask, control, ["weak", "strong"], now_sequence=0) == 1


# --- motif induction (shared with every baseline learner) ------------------------------


def _twin_corpus():
    malicious = [
        _skeleton(
            f"mal-{i}",
            [
                _step(READ, (P.CREDENTIAL,), tag=f"m{i}"),
                _step(WRITE, (P.SYSTEM_BINARY,), actor=1, tag=f"m{i}"),
                _step(SEND, (P.EXTERNAL_ENDPOINT,), tag=f"m{i}"),
            ],
            Verdict.MALICIOUS,
        )
        for i in range(2)
    ]
    benign = [
        # read alone, send alone, split across two actors, and a twin whose send also
        # carries NETWORK_SERVER: every single step is ambiguous, only the same-actor
        # pair separates, and the twin forces a forbid bit.
        _skeleton("ben-read", [_step(READ, (P.CREDENTIAL,), tag="b1")], Verdict.BENIGN),
        _skeleton("ben-send", [_step(SEND, (P.EXTERNAL_ENDPOINT,), tag="b2")], Verdict.BENIGN),
        _skeleton(
            "ben-split",
            [
                _step(READ, (P.CREDENTIAL,), tag="b3"),
                _step(SEND, (P.EXTERNAL_ENDPOINT,), actor=1, tag="b3"),
            ],
            Verdict.BENIGN,
        ),
        _skeleton(
            "ben-twin",
            [
                _step(READ, (P.CREDENTIAL,), tag="b4"),
                _step(SEND, (P.EXTERNAL_ENDPOINT, P.NETWORK_SERVER), tag="b4"),
            ],
            Verdict.BENIGN,
        ),
    ]
    return malicious, benign


def test_induce_motifs_finds_same_actor_pair_and_forbids_the_benign_twin() -> None:
    malicious, benign = _twin_corpus()
    meter = WorkMeter()
    found = induce_motifs(malicious, benign, meter=meter)
    assert meter.spent > 0
    assert all(len(m.motif) == 2 for m in found), "every single step is ambiguous; none may survive"
    server_bit = property_mask((P.NETWORK_SERVER,))
    pair = [m for m in found if m.motif[0].relation == READ and m.motif[1].relation == SEND]
    assert pair, found
    motif = pair[0]
    assert motif.motif[1].forbid_properties & server_bit
    assert motif.precision == 1.0 and motif.support == ("mal-0", "mal-1")
    assert motif.weight == pytest.approx((2 + 1) / (2 + 0 + 2))
    assert induce_motifs(malicious, benign, meter=WorkMeter()) == found  # deterministic


def test_induce_motifs_refuses_mislabelled_input_and_charges_its_budget() -> None:
    malicious, benign = _twin_corpus()
    with pytest.raises(ContractError):
        induce_motifs(malicious + benign[:1], benign, meter=WorkMeter())
    with pytest.raises(WorkBudgetExceeded):
        induce_motifs(malicious, benign, meter=WorkMeter(budget=3))


# --- D6.7 memory competition -------------------------------------------------------------


def _competition_replay():
    positives = [
        _skeleton(
            f"p{i}",
            [_step(READ, (P.SYSTEM_BINARY,), ("discovery",), tag=f"p{i}")],
            Verdict.MALICIOUS,
        )
        for i in range(3)
    ]
    twin = _skeleton(
        "twin",
        [_step(READ, (P.SYSTEM_BINARY, P.ROOT_OWNED), ("discovery",), tag="tw")],
        Verdict.BENIGN,
    )
    return [*positives, twin]


def test_replace_requires_pareto_dominance() -> None:
    replay = _competition_replay()
    general = _detector([MotifStep(READ, 0, 0, raised_mask(("discovery",)))])
    refined = _detector(
        [MotifStep(READ, 0, property_mask((P.ROOT_OWNED,)), raised_mask(("discovery",)))]
    )
    narrow = _detector(
        [MotifStep(READ, property_mask((P.ROOT_OWNED,)), 0, raised_mask(("discovery",)))]
    )
    assert not general.protected and overlaps(refined, general, replay=replay)
    kwargs = dict(replay=replay, variants=(), threshold=0.5, meter=WorkMeter())
    better = compete_knowledge(refined, general, **kwargs)
    assert better.outcome is CompetitionOutcome.REPLACE  # same recall, strictly lower FP burden
    assert better.new.fp_burden < better.old.fp_burden and better.new.recall == better.old.recall
    worse = compete_knowledge(narrow, general, **kwargs)
    assert worse.outcome is CompetitionOutcome.REJECT_NEW  # lower recall: never dominates
    assert newest_wins(narrow, general, **kwargs).outcome is CompetitionOutcome.REPLACE
    assert oldest_wins(refined, general, **kwargs).outcome is CompetitionOutcome.REJECT_NEW


def test_protected_old_item_is_not_replaced_by_one_that_misses_a_variant() -> None:
    from pocketsec.stage6.rehearsal.counterfactual import ReplayVariant, VariantKind

    replay = [
        _skeleton(f"c{i}", [_step(READ, (P.CREDENTIAL,), tag=f"c{i}")], Verdict.MALICIOUS)
        for i in range(2)
    ]
    replay.append(
        _skeleton("cb", [_step(READ, (P.CREDENTIAL, P.ROOT_OWNED), tag="cb")], Verdict.BENIGN)
    )
    old = _detector([MotifStep(READ, property_mask((P.CREDENTIAL,)), 0, 0)])
    new = _detector(
        [MotifStep(READ, property_mask((P.CREDENTIAL,)), property_mask((P.ROOT_OWNED,)), 0)]
    )
    assert old.protected
    variant = ReplayVariant(
        variant_id="v1",
        kind=VariantKind.SUBSTITUTE_PROCESS_CLASS,
        source_episode_id="c0",
        steps=(_step(READ, (P.CREDENTIAL, P.ROOT_OWNED), tag="v1"),),
        expected_verdict=Verdict.MALICIOUS,
        semantics_preserved=True,
        visibility_mask=1,
    )
    result = compete_knowledge(
        new, old, replay=replay, variants=(variant,), threshold=0.5, meter=WorkMeter()
    )
    # new beats old on FP burden, but misses a protected capability's variant: it may not replace.
    assert result.new.fp_burden < result.old.fp_burden
    assert result.outcome is not CompetitionOutcome.REPLACE


def test_coexist_only_on_disjoint_contexts_and_competition_is_detector_only() -> None:
    replay = [
        _skeleton(
            "a1", [_step(READ, (P.SYSTEM_BINARY,), ("discovery",), tag="a1")], Verdict.MALICIOUS
        ),
        _skeleton(
            "b1",
            [_step(READ, (P.TEMP_LOCATION,), ("discovery",), tag="b1")],
            Verdict.MALICIOUS,
            context=CTX_B,
        ),
    ]
    in_a = _detector(
        [MotifStep(READ, property_mask((P.SYSTEM_BINARY,)), 0, raised_mask(("discovery",)))],
        contexts=(CTX_A,),
    )
    in_b = _detector(
        [MotifStep(READ, property_mask((P.TEMP_LOCATION,)), 0, raised_mask(("discovery",)))],
        contexts=(CTX_B,),
    )
    result = compete_knowledge(
        in_b, in_a, replay=replay, variants=(), threshold=0.5, meter=WorkMeter()
    )
    assert result.outcome is CompetitionOutcome.COEXIST
    with pytest.raises(ContractError):
        compete_knowledge(
            _baseline(CTX_A), in_a, replay=replay, variants=(), threshold=0.5, meter=WorkMeter()
        )


# --- D6.11 the chamber: refusals first ----------------------------------------------------


def test_unissued_or_non_candidate_verdicts_are_refused_and_nothing_is_produced(
    world: World,
) -> None:
    chamber, _ = _chamber(world)
    nodes_before = len(world.lineage.nodes())
    forged = dataclasses.replace(world.verdicts[0], verdict_id="ver-" + "0" * 24)
    downgraded = dataclasses.replace(world.verdicts[1], bucket=QuarantineBucket.UNCERTAIN)
    for poison in (forged, downgraded):
        with pytest.raises(UnquarantinedInputError):
            chamber.spawn_evolution_candidate(
                trusted=world.trusted,
                verdicts=[*world.verdicts[2:], poison],
                admissions=(),
                half_lives=(),
                sequence=1,
            )
    assert chamber.stats().spawned == 0 and chamber.stats().issued_live == 0
    assert len(world.lineage.nodes()) == nodes_before  # no partial candidate, no lineage node


def test_hand_built_admission_and_substituted_capsule_are_refused(world: World) -> None:
    from pocketsec.stage6.capsule.quarantine import CandidateAdmission

    chamber, _ = _chamber(world)
    admission = CandidateAdmission(
        pattern_key="relation:3",
        anchor=(0.0,) * 26,
        context_id=CTX_A,
        capsule_ids=(world.verdicts[0].capsule_id,),
        evidence_digests=(_digest("x"),),
        independent_groups=3,
        stage2_reason="PROMOTED",
        sequence=1,
    )
    with pytest.raises(UnquarantinedInputError):
        chamber.spawn_evolution_candidate(
            trusted=world.trusted,
            verdicts=world.verdicts,
            admissions=(admission,),
            half_lives=(),
            sequence=1,
        )
    with pytest.raises(UnquarantinedInputError):  # capsule 1 offered under verdict 0's id
        chamber.spawn_evolution_candidate(
            trusted=world.trusted,
            verdicts=world.verdicts[:1],
            admissions=(),
            half_lives=(),
            sequence=1,
            capsules=(world.capsules[1],),
        )


def test_more_than_max_capsules_is_refused(world: World) -> None:
    chamber, _ = _chamber(world, max_capsules=4)
    with pytest.raises(ContractError):
        chamber.spawn_evolution_candidate(
            trusted=world.trusted,
            verdicts=world.verdicts[:5],
            admissions=(),
            half_lives=(),
            sequence=1,
        )
    with pytest.raises(ContractError):
        _chamber(world, max_capsules=MAX_CHAMBER_CAPSULES + 1)


def test_chamber_exception_leaves_the_input_state_untouched(world: World) -> None:
    chamber, _ = _chamber(world, work_budget=1)
    before = world.trusted.digest()
    snapshot = world.trusted.canonical_bytes()
    nodes_before = len(world.lineage.nodes())
    with pytest.raises(WorkBudgetExceeded):
        chamber.spawn_evolution_candidate(
            trusted=world.trusted, verdicts=world.verdicts, admissions=(), half_lives=(), sequence=5
        )
    assert world.trusted.digest() == before and world.trusted.canonical_bytes() == snapshot
    assert chamber.stats().issued_live == 0 and len(world.lineage.nodes()) == nodes_before


# --- D6.11 the chamber: what it builds ------------------------------------------------------


def test_candidate_is_a_new_value_with_lineage_and_a_tamper_evident_issue(world: World) -> None:
    trusted = _calibrated(world)
    before = trusted.digest()
    chamber, _ = _chamber(world)
    candidate = chamber.spawn_evolution_candidate(
        trusted=trusted, verdicts=world.verdicts, admissions=(), half_lives=(), sequence=200
    )
    assert candidate is not None and CandidateKind.SYMBOLIC in candidate.kinds
    assert trusted.digest() == before != candidate.proposed.digest()
    assert candidate.proposed.parent_digest == before == candidate.base_digest
    assert chamber.issued(candidate)
    verdict_capsules = {v.capsule_id for v in world.verdicts}
    for item in candidate.delta.added:
        assert item.lineage.candidate_id == candidate.candidate_id
        assert item.lineage.capsule_ids and set(item.lineage.capsule_ids) <= verdict_capsules
        assert item.lineage.evidence_digests
    node = world.lineage.node(candidate.candidate_id)
    assert node is not None and node.kind is NodeKind.CANDIDATE
    assert all(
        world.lineage.node(p).kind is NodeKind.VERDICT
        for p in world.lineage.parents(candidate.candidate_id)
    )
    assert set(candidate.holdout_episode_ids) <= verdict_capsules
    assert 0 < len(candidate.holdout_episode_ids) < len(verdict_capsules)
    # P4a: proposed-state bytes altered after issue are no longer "issued".
    tampered = dataclasses.replace(candidate, proposed=trusted.with_changes(threshold=0.9))
    assert not chamber.issued(tampered)
    assert not _chamber(world)[0].issued(candidate)  # another chamber never issued it


def _spawn_pair(world: World, sequence: int):
    field_chamber, _ = _chamber(world)
    uniform_chamber, _ = _chamber(world, plasticity_field=False)
    kwargs = dict(
        trusted=world.trusted,
        verdicts=world.verdicts,
        admissions=(),
        half_lives=(),
        sequence=sequence,
    )
    with_field = field_chamber.spawn_evolution_candidate(**kwargs)
    without = uniform_chamber.spawn_evolution_candidate(**kwargs)
    assert with_field is not None and without is not None
    return field_chamber, uniform_chamber, with_field, without


def _components(candidate) -> set[str]:
    return {f"new:{item.pattern_key}" for item in candidate.delta.added}


def test_field_and_uniform_masks_share_budgets_and_firing_is_outcome_level(world: World) -> None:
    field_chamber, uniform_chamber, with_field, without = _spawn_pair(world, 300)
    assert (
        with_field.mask.max_item_mutations == without.mask.max_item_mutations == MAX_ITEM_MUTATIONS
    )
    assert (
        with_field.mask.max_threshold_delta
        == without.mask.max_threshold_delta
        == MAX_THRESHOLD_DELTA
    )
    stats = field_chamber.stats()
    # The field withholds permissions from single-source, no-gain motifs ...
    assert stats.field_permission_differences > 0
    assert not _components(with_field) & with_field.mask.frozen_core
    # ... but the firing count is what changed the candidate, and on this fixture
    # the identical budget was already spent on the same four motifs: INERT here.
    changed = len(_components(without) - _components(with_field))
    assert stats.field_only_freezes + stats.field_displaced == changed
    assert uniform_chamber.stats().field_only_freezes == 0
    for candidate in (with_field, without):
        assert candidate.delta.item_mutations() <= MAX_ITEM_MUTATIONS
        assert candidate.mask_refusals > 0


def test_field_firing_count_counts_a_freeze_that_changes_the_candidate(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Zero the utility of the first proposed motif: uniform keeps it, the field must not."""
    import pocketsec.stage6.chamber.evolution as evolution

    real = evolution.detector_terms
    first: list[str] = []

    def rigged(component_id, **kwargs):
        if not first:
            first.append(component_id)
        if component_id == first[0]:
            kwargs["utility"] = 0.0
        return real(component_id, **kwargs)

    monkeypatch.setattr(evolution, "detector_terms", rigged)
    field_chamber, _, with_field, without = _spawn_pair(world, 310)
    assert first[0] in _components(without)
    assert first[0] not in _components(with_field)
    assert field_chamber.stats().field_only_freezes >= 1


def test_same_sequence_spawns_from_different_evidence_get_distinct_ids(world: World) -> None:
    """The same motif learned from different verdicts is a different proposed state.

    Before the id covered the draft state, these two spawns shared an id and the
    second was refused as a lineage collision.
    """
    chamber, _ = _chamber(world)
    kwargs = dict(trusted=world.trusted, admissions=(), half_lives=(), sequence=950)
    left = chamber.spawn_evolution_candidate(verdicts=world.verdicts[0:16], **kwargs)
    right = chamber.spawn_evolution_candidate(verdicts=world.verdicts[12:24], **kwargs)
    assert left is not None and right is not None
    assert left.candidate_id != right.candidate_id
    assert left.proposed.digest() != right.proposed.digest()
    assert chamber.issued(left) and chamber.issued(right)


def test_anomaly_only_alerts_do_not_zero_detector_utility(world: World) -> None:
    """Genesis alerts on every session through the unexplained term alone.

    An anomaly alert is not a detection (spec §4.0), so a motif that catches
    held-out attacks still has recall gain and the field lets it through. Scoring
    utility against ``score >= threshold`` instead froze every detector on the
    endurance corpus (35/35 measured) — this test fails if that returns.
    """
    genesis = world.trusted
    assert not genesis.detectors()
    chamber, _ = _chamber(world)
    candidate = chamber.spawn_evolution_candidate(
        trusted=genesis, verdicts=world.verdicts, admissions=(), half_lives=(), sequence=350
    )
    assert candidate is not None and CandidateKind.SYMBOLIC in candidate.kinds
    added = [i for i in candidate.delta.added if i.kind is ItemKind.DETECTOR]
    assert added and all(f"new:{i.pattern_key}" in candidate.mask.adaptable for i in added)


def test_protected_detector_is_never_mutated_even_under_newest_wins(world: World) -> None:
    trusted = _calibrated(world)
    learner, _ = _chamber(world, plasticity_field=False)
    learned = learner.spawn_evolution_candidate(
        trusted=trusted, verdicts=world.verdicts, admissions=(), half_lives=(), sequence=400
    )
    protected = [d for d in learned.proposed.detectors() if d.protected]
    assert protected, "the drift corpus attack touches protected anchors"
    state = learned.proposed
    chamber, _ = _chamber(world, plasticity_field=False, competition=False)
    candidate = chamber.spawn_evolution_candidate(
        trusted=state, verdicts=world.verdicts, admissions=(), half_lives=(), sequence=500
    )
    stats = chamber.stats()
    assert (
        stats.competitions > 0 and stats.competition_non_replace == 0
    )  # newest-wins wanted to replace
    assert stats.mask_refusals > 0
    if candidate is not None:
        assert {d.item_id for d in protected} <= candidate.mask.frozen_core
        touched = set(candidate.delta.removed) | {old for old, _ in candidate.delta.replaced}
        assert not touched & {d.item_id for d in protected}
        after = {i.item_id: i for i in candidate.proposed.items}
        assert all(after[d.item_id] == d for d in protected)


def test_competition_on_reports_its_firing_count(world: World) -> None:
    trusted = _calibrated(world)
    learner, _ = _chamber(world, plasticity_field=False)
    state = learner.spawn_evolution_candidate(
        trusted=trusted, verdicts=world.verdicts, admissions=(), half_lives=(), sequence=600
    ).proposed
    chamber, _ = _chamber(world, plasticity_field=False)
    chamber.spawn_evolution_candidate(
        trusted=state, verdicts=world.verdicts, admissions=(), half_lives=(), sequence=700
    )
    stats = chamber.stats()
    assert stats.competitions > 0 and stats.competition_non_replace > 0


def test_calibration_moves_the_threshold_within_the_mask_budget(world: World) -> None:
    chamber, _ = _chamber(world)
    candidate = chamber.spawn_evolution_candidate(
        trusted=world.trusted, verdicts=world.verdicts, admissions=(), half_lives=(), sequence=800
    )
    assert candidate is not None and candidate.delta.threshold is not None
    move = candidate.delta.threshold - world.trusted.threshold()
    assert 0.0 < move <= MAX_THRESHOLD_DELTA
    assert 0.0 < FPR_BUDGET < HOLDOUT_SHARE


# --- D6.12 MNEMOSYNE ---------------------------------------------------------------------


def _consolidator(**kwargs) -> tuple[MnemosyneConsolidator, EvolutionChamber, KnowledgeLineageDAG]:
    """A consolidator bound to a chamber whose gateway is never consulted (no verdicts)."""
    lineage = KnowledgeLineageDAG()
    fossils = kwargs.pop("fossils", None) or FossilStore()
    consolidator = MnemosyneConsolidator(fossils=fossils, lineage=lineage, **kwargs)
    chamber = EvolutionChamber(gateway=None, episodic=EpisodicMemory(), consolidator=consolidator)  # type: ignore[arg-type]
    return consolidator, chamber, lineage


def test_consolidation_is_deferred_under_pressure_and_never_touches_state() -> None:
    consolidator, _, _ = _consolidator()
    trusted = genesis_state(identity=IDENTITY)
    for pressure in (
        dict(memory_pressure=0.95),
        dict(cpu_load=0.9),
        dict(incident_urgency=0.9),
        dict(disk_free_bytes=0),
        dict(thermal_ok=False),
        dict(unmeasured=("thermal_ok",), thermal_ok=False),
    ):
        allowed, reasons = consolidation_allowed(_snapshot(**pressure))
        assert not allowed and reasons
        result = consolidator.consolidate_memory(
            trusted=trusted,
            episodic=EpisodicMemory(),
            snapshot=_snapshot(**pressure),
            now_sequence=10,
            epochs_since_match={},
        )
        assert isinstance(result, Consolidation) and result.deferred and result.candidate is None
        assert result.work_units == 0 and result.deferred_reasons
    assert consolidator.stats().deferred == 6 and len(consolidator.deferred_records()) == 6
    ran = consolidator.consolidate_memory(
        trusted=trusted,
        episodic=EpisodicMemory(),
        snapshot=_snapshot(),
        now_sequence=10,
        epochs_since_match={},
    )
    assert not ran.deferred and ran.split == ()
    again = consolidator.consolidate_memory(
        trusted=trusted,
        episodic=EpisodicMemory(),
        snapshot=_snapshot(),
        now_sequence=11,
        epochs_since_match={},
    )
    assert not again.deferred and again.deferred_reasons[0].startswith("not_due")


def test_consolidator_cannot_be_bound_to_a_second_chamber() -> None:
    consolidator, _, _ = _consolidator()
    with pytest.raises(ContractError):
        EvolutionChamber(gateway=None, episodic=EpisodicMemory(), consolidator=consolidator)  # type: ignore[arg-type]


def _aged_state():
    old_free = _detector(
        [MotifStep(READ, property_mask((P.SYSTEM_BINARY,)), 0, raised_mask(("discovery",)))],
        status=ItemStatus.DORMANT,
    )
    old_active = _detector(
        [MotifStep(WRITE, property_mask((P.TEMP_LOCATION,)), 0, raised_mask(("discovery",)))]
    )
    old_guard = _detector(
        [MotifStep(READ, property_mask((P.CREDENTIAL,)), 0, 0)], status=ItemStatus.DORMANT
    )
    state = genesis_state(identity=IDENTITY).with_changes(add=[old_free, old_active, old_guard])
    return state, old_free, old_active, old_guard


def test_melt_is_a_status_change_and_retire_never_happens_without_a_fossil() -> None:
    state, old_free, old_active, old_guard = _aged_state()
    assert old_guard.protected and not old_free.protected
    now = 10 * MAX_DORMANT_SEQUENCES
    from pocketsec.stage6.memory.half_life import trust_ranking

    rankings = trust_ranking(state.items, now_sequence=now, epochs_since_match={})
    broken, _, _ = _consolidator(fossils=FossilStore(max_fossils=1, max_bytes=1))
    refused = broken.melt_or_retire_knowledge(state, rankings=rankings, now_sequence=now)
    assert refused.removed == () and broken.stats().retire_refused_no_fossil == 1
    consolidator, _, _ = _consolidator()
    delta = consolidator.melt_or_retire_knowledge(state, rankings=rankings, now_sequence=now)
    assert delta.removed == (old_free.item_id,)
    held = consolidator.fossils.load(state.digest())
    assert old_free.item_id in {i.item_id for i in held.items}
    melted = dict(delta.replaced)
    assert set(melted) == {old_active.item_id}
    assert melted[old_active.item_id].status is ItemStatus.DORMANT
    assert dataclasses.replace(melted[old_active.item_id], status=ItemStatus.ACTIVE) == old_active
    touched = set(delta.removed) | set(melted)
    assert old_guard.item_id not in touched  # protected: never melted, never retired


def test_consolidation_candidate_is_issued_by_the_chamber_and_bounded() -> None:
    state, old_free, _, _ = _aged_state()
    consolidator, chamber, lineage = _consolidator()
    from pocketsec.stage6.fossils.lineage import LineageNode

    lineage.update_lineage_dag(
        node=LineageNode("cand-fixture", NodeKind.GENESIS, state.digest(), 0, "fixture"),
        parents=(),
        reason="fixture",
    )
    result = consolidator.consolidate_memory(
        trusted=state,
        episodic=EpisodicMemory(),
        snapshot=_snapshot(),
        now_sequence=10 * MAX_DORMANT_SEQUENCES,
        epochs_since_match={},
    )
    candidate = result.candidate
    assert candidate is not None and candidate.kinds == frozenset({CandidateKind.CONSOLIDATION})
    assert chamber.issued(candidate) and candidate.delta.item_mutations() <= MAX_ITEM_MUTATIONS
    assert result.retired == (old_free.item_id,)
    assert state.digest() == candidate.base_digest  # a proposal; the input value is unchanged
    assert lineage.node(candidate.candidate_id).kind is NodeKind.CANDIDATE


def test_chamber_refuses_a_consolidation_that_creates_knowledge() -> None:
    state, _, old_active, _ = _aged_state()
    _, chamber, _ = _consolidator()
    novel = _detector(
        [MotifStep(SEND, property_mask((P.TEMP_LOCATION,)), 0, raised_mask(("discovery",)))]
    )
    changed = dataclasses.replace(old_active, weight=0.99)
    for delta in (
        KnowledgeDelta(added=(novel,)),
        KnowledgeDelta(replaced=((old_active.item_id, changed),)),
        KnowledgeDelta(threshold=0.7),
        KnowledgeDelta(
            rehearsal_added=(_skeleton("never-admitted", [_step(READ)], Verdict.BENIGN),)
        ),
    ):
        with pytest.raises(ContractError):
            chamber._issue_consolidation(trusted=state, delta=delta, sequence=1, reason="test")


def test_plan_room_evicts_dormant_context_items_first_behind_a_fossil() -> None:
    other = _baseline(CTX_B, relation=WRITE, last=900)
    stale = _baseline(CTX_A, relation=READ, last=0)
    fresh = _baseline(CTX_A, relation=SEND, last=1000)
    state = genesis_state(identity=IDENTITY).with_changes(add=[other, stale, fresh])
    for half_life in (True, False):
        consolidator, _, _ = _consolidator(half_life=half_life)
        first = consolidator.plan_room(state, {ItemKind.BASELINE: 1}, now_sequence=1000)
        assert first.removed == (other.item_id,)  # dormant context goes first, however recent
        two = consolidator.plan_room(state, {ItemKind.BASELINE: 2}, now_sequence=1000)
        assert two.removed == (other.item_id, stale.item_id)
        assert consolidator.fossils.get(state.digest()) is not None
    broken, _, _ = _consolidator(fossils=FossilStore(max_fossils=1, max_bytes=1))
    assert broken.plan_room(state, {ItemKind.BASELINE: 1}, now_sequence=1000).removed == ()


def test_value_aware_rehearsal_keeps_a_positive_per_detector_where_reservoir_may_not() -> None:
    positives = [
        _skeleton(f"pos-{i}", [_step(READ, (P.CREDENTIAL,), tag=f"q{i}")], Verdict.MALICIOUS)
        for i in range(2)
    ]
    rare = _skeleton(
        "pos-rare", [_step(SEND, (P.EXTERNAL_ENDPOINT,), tag="rare")], Verdict.MALICIOUS
    )
    benign = [
        _skeleton(f"ben-{i}", [_step(WRITE, (P.SYSTEM_BINARY,), tag=f"n{i}")], Verdict.BENIGN)
        for i in range(12)
    ]
    detector = _detector([MotifStep(SEND, property_mask((P.EXTERNAL_ENDPOINT,)), 0, 0)])
    state = genesis_state(identity=IDENTITY).with_changes(
        add=[detector], rehearsal=[*positives, rare, *benign]
    )
    budget = 3 * rare.byte_size()
    aware, _, _ = _consolidator()
    chosen = aware.select_rehearsal_exemplars(EpisodicMemory(), trusted=state, budget_bytes=budget)
    assert "pos-rare" in {e.episode_id for e in chosen}
    assert sum(e.byte_size() for e in chosen) <= budget
    assert not {e.episode_id for e in chosen} - {e.episode_id for e in state.rehearsal}
    misses = 0
    for seed in range(20):
        control, _, _ = _consolidator(value_aware_rehearsal=False, seed=seed)
        picked = control.select_rehearsal_exemplars(
            EpisodicMemory(), trusted=state, budget_bytes=budget
        )
        assert sum(e.byte_size() for e in picked) <= budget
        misses += "pos-rare" not in {e.episode_id for e in picked}
    assert misses > 0, "reservoir sampling at the same bytes loses the only exemplar of a detector"


def test_consolidation_merges_context_twins_into_one_item_through_the_chamber() -> None:
    in_a, in_b = _baseline(CTX_A, relation=WRITE), _baseline(CTX_B, relation=WRITE)
    state = genesis_state(identity=IDENTITY).with_changes(add=[in_a, in_b])
    consolidator, chamber, lineage = _consolidator()
    from pocketsec.stage6.fossils.lineage import LineageNode

    lineage.update_lineage_dag(
        node=LineageNode("cand-fixture", NodeKind.GENESIS, state.digest(), 0, "fixture"),
        parents=(),
        reason="fixture",
    )
    result = consolidator.consolidate_memory(
        trusted=state,
        episodic=EpisodicMemory(),
        snapshot=_snapshot(),
        now_sequence=1,
        epochs_since_match={},
    )
    assert result.merged == ((min(in_a.item_id, in_b.item_id), max(in_a.item_id, in_b.item_id)),)
    candidate = result.candidate
    assert candidate is not None and chamber.issued(candidate)
    (merged,) = candidate.delta.added
    assert merged.context_ids == frozenset({CTX_A, CTX_B})
    assert set(merged.lineage.parent_item_ids) == {in_a.item_id, in_b.item_id}
    assert merged.lineage.candidate_id == candidate.candidate_id
    assert set(candidate.delta.removed) == {in_a.item_id, in_b.item_id}


def test_half_life_eviction_differs_from_lru_and_counts_it() -> None:
    anchor = [0.0] * 26
    anchor[5] = 1.0

    def baseline(
        relation: int, *, last: int, validations: int, contradictions: int
    ) -> KnowledgeItem:
        return KnowledgeItem.build(
            kind=ItemKind.BASELINE,
            context_ids={CTX_A},
            pattern_key=f"relation:{relation}",
            weight=1.0,
            origin_verdict=Verdict.BENIGN,
            lineage=ItemLineage("cand-fixture", ("cap-fixture",), (_digest("fixture"),), ()),
            validation=ItemValidation(
                validations, validations, contradictions, 0, last, frozenset({0})
            ),
            anchor=tuple(anchor),
        )

    older_but_validated = baseline(READ, last=100, validations=50, contradictions=0)
    newer_but_contradicted = baseline(SEND, last=200, validations=0, contradictions=50)
    state = genesis_state(identity=IDENTITY).with_changes(
        add=[older_but_validated, newer_but_contradicted]
    )
    modulated, _, _ = _consolidator()
    lru, _, _ = _consolidator(half_life=False)
    assert modulated.plan_room(state, {ItemKind.BASELINE: 1}, now_sequence=5000).removed == (
        newer_but_contradicted.item_id,
    )
    assert lru.plan_room(state, {ItemKind.BASELINE: 1}, now_sequence=5000).removed == (
        older_but_validated.item_id,
    )
    assert modulated.stats().half_life_decisions_differing_from_lru == 1


def test_resurrection_is_minted_only_from_items_a_verified_fossil_holds() -> None:
    from pocketsec.stage6.fossils.lineage import LineageNode
    from pocketsec.stage6.fossils.store import FossilReason
    from pocketsec.stage6.homeostasis.drift import ResurrectionProposal

    returning = _baseline(CTX_B, relation=WRITE)
    before = genesis_state(identity=IDENTITY).with_changes(add=[returning])
    consolidator, chamber, lineage = _consolidator()
    lineage.update_lineage_dag(
        node=LineageNode("cand-fixture", NodeKind.GENESIS, before.digest(), 0, "fixture"),
        parents=(),
        reason="fixture",
    )
    fossil = consolidator.fossils.create_fossil(
        before,
        reason=FossilReason.CONTEXT_DORMANCY,
        fingerprint=_digest("fp"),
        epoch_range=(0, 0),
        sequence=1,
    )
    evicted = before.with_changes(remove=[returning.item_id])
    forged = ResurrectionProposal(
        CTX_B, fossil.artifact_hash, (dataclasses.replace(returning, weight=3.0),)
    )
    with pytest.raises(UnquarantinedInputError):
        chamber.spawn_resurrection_candidate(trusted=evicted, proposal=forged, sequence=2)
    honest = ResurrectionProposal(CTX_B, fossil.artifact_hash, (returning,))
    candidate = chamber.spawn_resurrection_candidate(trusted=evicted, proposal=honest, sequence=2)
    assert candidate is not None and candidate.kinds == frozenset({CandidateKind.RESURRECTION})
    assert chamber.issued(candidate) and evicted.digest() == candidate.base_digest
    (restored,) = candidate.proposed.baselines()
    assert restored.item_id == returning.item_id
    assert restored.lineage.candidate_id == candidate.candidate_id
    assert chamber.spawn_resurrection_candidate(trusted=before, proposal=honest, sequence=3) is None


# --- review F3 / F5: a learned threshold names its evidence, and it is never the holdout ------


def test_a_learned_threshold_names_its_candidate_and_is_fitted_off_the_holdout(world) -> None:
    """F3: the calibrated THRESHOLD used to keep ItemLineage('genesis', (), (), ()).
    F5: it was fitted on the holdout negatives G3 then scored it on, so G3 passed in-sample."""
    from pocketsec.stage6.conservation.gate import _utility

    chamber, _ = _chamber(world)
    candidate = chamber.spawn_evolution_candidate(
        trusted=world.trusted, verdicts=world.verdicts, admissions=(), half_lives=(), sequence=100
    )
    assert candidate is not None and CandidateKind.CALIBRATION in candidate.kinds
    item = next(i for i in candidate.proposed.items if i.kind is ItemKind.THRESHOLD)
    lineage = item.lineage
    assert lineage.candidate_id == candidate.candidate_id
    assert lineage.capsule_ids and lineage.evidence_digests
    assert set(lineage.capsule_ids) <= {c.capsule_id for c in world.capsules}
    held = set(candidate.holdout_episode_ids)
    assert held, "the fixture must have a holdout for the disjointness to mean anything"
    assert not held & set(lineage.capsule_ids)
    # G3 refuses the claim outright if the fit and the holdout ever share an episode.
    overlap = dataclasses.replace(lineage, capsule_ids=(sorted(held)[0],))
    forged = dataclasses.replace(
        candidate, delta=dataclasses.replace(candidate.delta, threshold_lineage=overlap))
    result = _utility(forged, world.trusted, world.episodic.episodes(), WorkMeter())
    assert not result.passed and "in-sample" in result.detail
