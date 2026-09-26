"""FORGE (D8.14, D8.15) and the Stage 6 door (D8.17): behaviour and failure paths.

What these tests pin, and why each matters:

* **Expressibility is decided before compiling (lesson 2).** MOTIF refuses exactly what Stage
  6's grammar cannot say (co-occurrence, absence, counts, a veto), FSM refuses a state
  explosion, students refuse single-class targets; a refused entrant has no artifact and
  no executor.
* **The mask representations ARE the theory.** FSM and MOTIF decide exactly as
  ``genome.decides`` over random and real episodes, and both classes are seen (the
  mechanism fires, lesson 1).
* **Students learn the theory, never the labels.** Flipping or deleting every TRAIN label
  leaves every student artifact byte-identical.
* **Selection is a pure function of the recorded measurements.** ``reselect`` reproduces
  the choice (also after a JSON round trip), tolerances bite at their exact edges, wall time
  is never read, and TYPED_RULE is never "deployed" (it cannot cost less than itself).
* **Unmeasured is not within.** An unreadable RSS gives ``within_ceiling=None``, and the
  record type refuses any other verdict.
* **The one door** refuses everything that is not a verified, REPRODUCED, evidenced package,
  admits nothing when it refuses, keeps ONE independence group per run and records Stage 6
  verbatim (M0.2-style bucket reporting).
"""

from __future__ import annotations

import dataclasses
import json
import math
import random
from collections import Counter
from typing import Any

import pytest

from pocketsec.stage0.benchmark import resource_metrics
from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.epoch.model import EpochModel, SystemIdentity
from pocketsec.stage1.guillotine.features import LogisticProbe
from pocketsec.stage6.capsule.quarantine import QuarantineBucket, QuarantineGateway
from pocketsec.stage6.fossils.lineage import KnowledgeLineageDAG
from pocketsec.stage6.memory.semantic import genesis_state
from pocketsec.stage6.provenance.ledger import ProvenanceLedger
from pocketsec.stage6.resources import WorkBudgetExceeded, WorkMeter
from pocketsec.stage8.adapters.stage6 import MAX_CAPSULES_PER_PACKAGE, Stage6Adapter
from pocketsec.stage8.challenger.adversarial import ChallengeKind, build_challenge_corpus
from pocketsec.stage8.episode import Episode, Split
from pocketsec.stage8.forge.compiler import (
    CompiledDetector,
    can_express,
    canonical_artifact_bytes,
    compile_all,
    fsm_state_count,
    load_detector,
    required_features,
)
from pocketsec.stage8.forge.package import (
    FAILURE_CONTEXT_PATTERN,
    DiscoveryPackageV1,
    FailureCondition,
    FalsificationRecord,
    IdentifiabilityClass,
    NoveltyClass,
    RepresentationKind,
    RepresentationMeasurement,
    ReproducibilityRecord,
    ReproducibilityStatus,
    ResourceProfile,
    RobustnessProfile,
    TournamentResult,
    artifact_hashes_for,
    verify_package,
)
from pocketsec.stage8.forge.representations import (
    MAX_FSM_STATES,
    FsmDetector,
    pooled_features,
)
from pocketsec.stage8.forge.tournament import (
    ENDPOINT_ARTIFACT_MAX_BYTES,
    FORGE_AGREEMENT_MIN,
    FORGE_WALL_RATIO_MAX,
    STAGE8_ENDPOINT_INCREMENTAL_CEILING_BYTES,
    EndpointFootprint,
    conservation_checks,
    decision_relevant_bytes,
    discovery_compression_ratio,
    measure_endpoint_footprint,
    research_state_bytes_of,
    reselect,
    run_tournament,
)
from pocketsec.stage8.genome.grammar import (
    FEATURE_NAMES,
    Mechanism,
    MechanismRelation,
    Modifier,
    StepPredicate,
    parse_mechanism,
)
from pocketsec.stage8.genome.hypothesis import (
    Direction,
    FalsifierKind,
    GeneratorKind,
    GenomeProvenance,
    HypothesisGenome,
    ObservationScope,
    ResidualType,
    genome_for,
)
from pocketsec.stage8.governor.budget import ResearchBudget, ResearchGovernor
from pocketsec.stage8.labs.discovery_corpus import (
    CorpusArm,
    DiscoveryCorpus,
    build_discovery_corpus,
)
from pocketsec.stage8.ledger.theory import PreRegistration, TheoryLedger, TheoryStatus
from pocketsec.stage8.sandbox.integrity import HoldoutVault

K = RepresentationKind
PM1 = "PRECEDES(EXECUTE+TEMP_LOCATION,CONNECT+EXTERNAL_ENDPOINT)"
PM2 = "REPEATED(CONNECT+EXTERNAL_ENDPOINT,4)"
COUNTS = {Split.TRAIN: 60, Split.HOLDOUT: 20, Split.REPLICATION: 60, Split.LAB_POOL: 30,
          Split.INDEPENDENT: 20}
SCOPE = ObservationScope((), frozenset({ResidualType.OBSERVATION}), ())
HID = "hyp-" + "a" * 24


def genome(dsl: str, *, direction: Direction = Direction.MALICIOUS,
           forbidden: tuple[StepPredicate, ...] = ()) -> HypothesisGenome:
    return genome_for(parse_mechanism(dsl), direction=direction, scope=SCOPE, forbidden=forbidden,
                      provenance=GenomeProvenance(GeneratorKind.SYMBOLIC_ENUMERATOR,
                                                  "sha256:" + "0" * 64, False, 0))


def governor() -> ResearchGovernor:
    return ResearchGovernor(ResearchBudget())


def reproduced_ledger(g: HypothesisGenome, corpus: DiscoveryCorpus) -> TheoryLedger:
    """A ledger in which ``g`` earned REPRODUCED the real way: one preregistered HOLDOUT batch and
    one preregistered REPLICATION batch through the vault. The adapter reads REPRODUCED from a
    ledger, never from the package (S8-AUTH-01), so the door tests need one."""
    ledger = TheoryLedger()
    ledger.record_birth(g)
    for split in (Split.HOLDOUT, Split.REPLICATION):
        vault = HoldoutVault(corpus.episodes(split), split=split, ledger=ledger,
                             governor=governor())
        enrichment = FalsifierKind.HOLDOUT_ENRICHMENT if split is Split.HOLDOUT \
            else FalsifierKind.REPLICATION
        registration = PreRegistration(
            registration_id="", hypothesis_id=g.hypothesis_id, genome_digest=g.digest(),
            split=split, split_digest=vault.split_digest(), batch_size=1,
            alpha=next(f.alpha for f in g.falsification_tests if f.kind is enrichment),
            prediction=next(p for p in g.predicted_observations if p.split is split))
        ledger.preregister(registration)
        (outcome,) = vault.evaluate(vault.seal_batch([registration]))
        assert outcome.survived, (split, outcome.reasons)
    ledger.set_status(g.hypothesis_id, TheoryStatus.REPRODUCED, reason="test:replicated")
    return ledger


@pytest.fixture(scope="module")
def corpus() -> DiscoveryCorpus:
    return build_discovery_corpus(arm=CorpusArm.PLANTED, seed=3, counts=COUNTS)


@dataclasses.dataclass(frozen=True)
class Forged:
    genome: HypothesisGenome
    compiled: tuple[CompiledDetector, ...]
    tournament: TournamentResult
    state_bytes: int


def forge(corpus: DiscoveryCorpus, g: HypothesisGenome,
          replication: tuple[Episode, ...] | None = None) -> Forged:
    gov = governor()
    compiled = compile_all(g, corpus.episodes(Split.TRAIN), governor=gov)
    kinds = tuple(k for k in ChallengeKind if k is not ChallengeKind.POISONED_LABELS)
    challenged = build_challenge_corpus(corpus.episodes(Split.LAB_POOL), kinds=kinds,
                                        rng=random.Random(3), governor=gov,
                                        necessary=g.necessary_conditions)
    state = research_state_bytes_of(g)
    tournament = run_tournament(
        g, compiled, measure_on=replication or corpus.episodes(Split.REPLICATION),
        challenge=challenged, discovery_work_units=gov.meter.spent, research_state_bytes=state,
        governor=gov)
    return Forged(g, compiled, tournament, state)


@pytest.fixture(scope="module")
def pm1(corpus: DiscoveryCorpus) -> Forged:
    """PM1 forged into a DEPLOYABLE tournament (these tests need one to exercise the package,
    the footprint and the door). Deployability now includes a measured within-run wall ratio
    to TYPED_RULE (F2): MOTIF's is ~0.96x and read > 1.0 in about 1 of 10 re-measurements at
    load ~11, so the fixture re-measures up to 5 times. This is a fixture, not a measurement:
    the cost rule itself is pinned deterministically by the ``_m``-based selection tests."""
    for _ in range(5):
        forged = forge(corpus, genome(PM1))
        if forged.tournament.deployable:
            break
    return forged


@pytest.fixture(scope="module")
def pm2(corpus: DiscoveryCorpus) -> Forged:
    return forge(corpus, genome(PM2))


# --- expressibility ---------------------------------------------------------------------

EXEC_TMP = parse_mechanism("SINGLE(EXECUTE+TEMP_LOCATION)").steps[0]
SYS_EXEC = parse_mechanism("SINGLE(EXECUTE+SYSTEM_BINARY)").steps[0]


@pytest.mark.parametrize(("dsl", "forbidden", "code"), [
    ("CO_OCCURS(READ+CREDENTIAL,CONNECT+EXTERNAL_ENDPOINT)", (), "MOTIF_CANNOT_EXPRESS_CO_OCCURS"),
    ("WITHOUT(CONNECT+EXTERNAL_ENDPOINT,EXECUTE)", (), "MOTIF_CANNOT_EXPRESS_WITHOUT"),
    (PM2, (), "MOTIF_CANNOT_EXPRESS_REPEATED"),
    (PM1, (SYS_EXEC,), "MOTIF_CANNOT_EXPRESS_FORBIDDEN_OBSERVATION"),
    (PM1, (), None),
    ("SINGLE(SPAWN)", (), None),
])
def test_motif_refuses_exactly_what_stage6_grammar_cannot_say(
        dsl: str, forbidden: tuple[StepPredicate, ...], code: str | None) -> None:
    assert can_express(genome(dsl, forbidden=forbidden), K.MOTIF) == (code is None, code)


def test_fsm_refuses_a_state_explosion_and_counts_the_veto_sink() -> None:
    seven = genome("REPEATED(CONNECT+EXTERNAL_ENDPOINT,7)")
    assert fsm_state_count(seven) == MAX_FSM_STATES and can_express(seven, K.FSM) == (True, None)
    eight = genome("REPEATED(CONNECT+EXTERNAL_ENDPOINT,8)")
    assert can_express(eight, K.FSM) == (False, "FSM_STATE_EXPLOSION")
    vetoed = genome("REPEATED(CONNECT+EXTERNAL_ENDPOINT,7)", forbidden=(SYS_EXEC,))
    assert fsm_state_count(vetoed) == MAX_FSM_STATES + 1
    assert can_express(vetoed, K.FSM) == (False, "FSM_STATE_EXPLOSION")
    assert all(can_express(seven, k)[0] for k in K if k is not K.MOTIF)


def test_a_refused_entrant_has_no_artifact_and_no_executor(corpus: DiscoveryCorpus) -> None:
    compiled = {c.kind: c for c in compile_all(genome(PM2), corpus.episodes(Split.TRAIN),
                                               governor=governor())}
    motif = compiled[K.MOTIF]
    assert (motif.expressible, motif.refusal, motif.artifact, motif.artifact_bytes) == (
        False, "MOTIF_CANNOT_EXPRESS_REPEATED", None, None)
    with pytest.raises(ContractError, match="refused"):
        load_detector(motif)
    with pytest.raises(ContractError):
        CompiledDetector(K.MOTIF, False, "MOTIF_CANNOT_EXPRESS_REPEATED", {"kind": "MOTIF"}, 3)


def test_students_with_one_class_of_targets_are_refused(corpus: DiscoveryCorpus) -> None:
    """REPEATED(k=8) never fires on this TRAIN split, so a student would learn a constant."""
    g = genome("REPEATED(CONNECT+EXTERNAL_ENDPOINT,8)")
    assert not any(g.decides(e) for e in corpus.episodes(Split.TRAIN))
    compiled = compile_all(g, corpus.episodes(Split.TRAIN), governor=governor())
    refusals = {c.kind: c.refusal for c in compiled}
    assert refusals[K.TYPED_RULE] is None
    assert {refusals[k] for k in (K.THRESHOLD, K.LOGISTIC, K.PROTOTYPE, K.STUMP_TREE)} == {
        "NO_BOTH_CLASSES"}
    assert compile_all(g, (), governor=governor(), kinds=(K.THRESHOLD,))[0].refusal == \
        "NO_BOTH_CLASSES"


def test_compile_refuses_held_out_episodes(corpus: DiscoveryCorpus) -> None:
    for split in (Split.HOLDOUT, Split.REPLICATION, Split.LAB_POOL, Split.INDEPENDENT):
        with pytest.raises(ContractError, match="TRAIN only"):
            compile_all(genome(PM1), corpus.episodes(split)[:3], governor=governor())
    with pytest.raises(ContractError, match="distinct"):
        compile_all(genome(PM1), (), governor=governor(), kinds=(K.MOTIF, K.MOTIF))


# --- the mask representations are the theory ---------------------------------------------


def _random_episodes(corpus: DiscoveryCorpus, count: int, seed: int) -> list[Episode]:
    base = corpus.episodes(Split.TRAIN)[0]
    rng = random.Random(seed)
    out = []
    for _ in range(count):
        steps = tuple(dataclasses.replace(
            base.steps[0], relation=rng.randrange(3), object_property_mask=rng.getrandbits(3),
            state_delta_mask=rng.getrandbits(2), actor_slot=rng.randrange(3))
            for _ in range(rng.randint(1, 8)))
        out.append(Episode("", steps, None, Split.CHALLENGE, base.context, False))
    return out


_A = StepPredicate(0, 1, 0, 0)
_B = StepPredicate(1, 0, 2, 0)
_VETO = StepPredicate(2, 4, 0, 0)
_MECHANISMS = (
    Mechanism(MechanismRelation.SINGLE, (_A,)),
    Mechanism(MechanismRelation.SINGLE, (_A,), Modifier.REPEATED, 2),
    Mechanism(MechanismRelation.SINGLE, (_A,), Modifier.REPEATED, 3),
    Mechanism(MechanismRelation.PRECEDES, (_A, _B)),
    Mechanism(MechanismRelation.PRECEDES, (_B, _A)),
    Mechanism(MechanismRelation.CO_OCCURS, (_A, _B)),
    Mechanism(MechanismRelation.WITHOUT, (_A, _B)),
)


@pytest.mark.parametrize("mechanism", _MECHANISMS, ids=lambda m: m.to_dsl())
@pytest.mark.parametrize("vetoed", [False, True])
def test_fsm_and_motif_decide_exactly_as_the_genome(
        corpus: DiscoveryCorpus, mechanism: Mechanism, vetoed: bool) -> None:
    g = genome_for(mechanism, direction=Direction.MALICIOUS, scope=SCOPE,
                   forbidden=(_VETO,) if vetoed else (),
                   provenance=GenomeProvenance(GeneratorKind.SYMBOLIC_ENUMERATOR,
                                               "sha256:" + "0" * 64, False, 0))
    detectors = {c.kind: load_detector(c) for c in
                 compile_all(g, (), governor=governor(), kinds=(K.FSM, K.MOTIF))
                 if c.expressible}
    assert K.FSM in detectors
    episodes = _random_episodes(corpus, 400, seed=len(mechanism.to_dsl()) + vetoed)
    truth = [g.decides(e) for e in episodes]
    assert 0 < sum(truth) < len(truth), "the test must see both decisions (lesson 1)"
    for kind, detector in detectors.items():
        assert [detector.decide(e) for e in episodes] == truth, kind
        assert [detector.decide(e, WorkMeter()) for e in episodes] == truth, kind


def test_mask_detectors_agree_with_the_genome_on_real_sessions(pm1: Forged,
                                                              corpus: DiscoveryCorpus) -> None:
    episodes = [e for s in (Split.TRAIN, Split.REPLICATION, Split.LAB_POOL, Split.INDEPENDENT)
                for e in corpus.episodes(s)]
    truth = [pm1.genome.decides(e) for e in episodes]
    assert 0 < sum(truth) < len(truth)
    for entrant in pm1.compiled:
        if entrant.kind in (K.TYPED_RULE, K.MOTIF, K.FSM):
            detector = load_detector(entrant)
            assert [detector.decide(e) for e in episodes] == truth, entrant.kind


def test_every_detector_pays_before_it_works(pm1: Forged, corpus: DiscoveryCorpus) -> None:
    episode = next(e for e in corpus.episodes(Split.REPLICATION) if len(e.steps) >= 3)
    for entrant in pm1.compiled:
        detector = load_detector(entrant)
        meter = WorkMeter()
        detector.decide(episode, meter)
        assert meter.spent > 0, entrant.kind
        with pytest.raises(WorkBudgetExceeded):
            detector.decide(episode, WorkMeter(budget=0))
    meter = WorkMeter()
    pooled_features(episode, (3, 7), meter=meter)
    assert meter.spent == 2 * len(episode.steps)


def test_an_fsm_actor_in_the_sink_costs_nothing_more(corpus: DiscoveryCorpus) -> None:
    g = genome_for(Mechanism(MechanismRelation.SINGLE, (_A,)), direction=Direction.MALICIOUS,
                   scope=SCOPE, forbidden=(_VETO,),
                   provenance=GenomeProvenance(GeneratorKind.SYMBOLIC_ENUMERATOR,
                                               "sha256:" + "0" * 64, False, 0))
    fsm = load_detector(compile_all(g, (), governor=governor(), kinds=(K.FSM,))[0])
    assert isinstance(fsm, FsmDetector) and fsm.sink is not None
    base = corpus.episodes(Split.TRAIN)[0].steps[0]
    veto = dataclasses.replace(base, relation=2, object_property_mask=4, actor_slot=0)
    other = dataclasses.replace(base, relation=1, object_property_mask=0, actor_slot=0)
    short = Episode("", (veto,), None, Split.CHALLENGE, corpus.episodes(Split.TRAIN)[0].context,
                    False)
    long = dataclasses.replace(short, episode_id="", steps=(veto, *([other] * 20)))
    costs = []
    for episode in (short, long):
        meter = WorkMeter()
        assert fsm.decide(episode, meter) is False
        costs.append(meter.spent)
    assert costs[0] == costs[1], "steps after the sink must not be paid for"


# --- students learn the theory, never the labels ----------------------------------------


def _relabelled(episodes: tuple[Episode, ...], how: str) -> tuple[Episode, ...]:
    if how == "flip":
        return tuple(e.with_split(Split.TRAIN, label=None if e.label is None else 1 - e.label)
                     for e in episodes)
    return tuple(e.with_split(Split.TRAIN, label=None) for e in episodes)


def test_students_are_fitted_to_the_genomes_decisions_not_the_labels(
        corpus: DiscoveryCorpus) -> None:
    train = corpus.episodes(Split.TRAIN)
    g = genome(PM1)
    kinds = (K.THRESHOLD, K.LOGISTIC, K.PROTOTYPE, K.STUMP_TREE)
    artifacts = [
        [canonical_artifact_bytes(c.artifact) for c in
         compile_all(g, episodes, governor=governor(), kinds=kinds) if c.artifact is not None]
        for episodes in (train, _relabelled(train, "flip"), _relabelled(train, "none"))
    ]
    assert len(artifacts[0]) == len(kinds)
    assert artifacts[0] == artifacts[1] == artifacts[2]


def test_the_logistic_artifact_scores_exactly_as_stage1s_probe(corpus: DiscoveryCorpus) -> None:
    train = corpus.episodes(Split.TRAIN)
    g = genome(PM1)
    entrant = compile_all(g, train, governor=governor(), kinds=(K.LOGISTIC,))[0]
    detector = load_detector(entrant)
    slots = entrant.artifact["slots"]
    rows = [list(pooled_features(e, slots)) for e in train]
    probe = LogisticProbe().fit(rows, [int(g.decides(e)) for e in train])
    expected = probe.predict(rows)
    assert all(math.isclose(detector.score(e), p, rel_tol=1e-12, abs_tol=1e-15)
               for e, p in zip(train, expected, strict=True))


# --- plain-data artifacts ---------------------------------------------------------------


@pytest.mark.parametrize("dsl", [PM1, "CO_OCCURS(READ+CREDENTIAL,CONNECT+EXTERNAL_ENDPOINT)",
                                 "WITHOUT(CONNECT+EXTERNAL_ENDPOINT,EXECUTE+SYSTEM_BINARY)"])
def test_every_kind_round_trips_through_plain_json(corpus: DiscoveryCorpus, dsl: str) -> None:
    g = genome(dsl)
    episodes = corpus.episodes(Split.REPLICATION)
    loaded_kinds = set()
    for entrant in compile_all(g, corpus.episodes(Split.TRAIN), governor=governor()):
        if not entrant.expressible:
            continue
        wire = json.loads(canonical_artifact_bytes(entrant.artifact))
        again = CompiledDetector(entrant.kind, True, None, wire,
                                 len(canonical_artifact_bytes(wire)))
        assert again.artifact_bytes == entrant.artifact_bytes
        first, second = load_detector(entrant), load_detector(again)
        assert [first.decide(e) for e in episodes] == [second.decide(e) for e in episodes]
        assert [first.score(e) for e in episodes] == [second.score(e) for e in episodes]
        loaded_kinds.add(entrant.kind)
    assert {K.TYPED_RULE, K.FSM} <= loaded_kinds


def _tamper(artifact: Any, **changes: Any) -> dict[str, Any]:
    data = json.loads(canonical_artifact_bytes(artifact))
    data.update(changes)
    return data


def test_tampered_artifacts_are_refused(pm1: Forged) -> None:
    by_kind = {c.kind: c for c in pm1.compiled}
    cases = [
        (K.MOTIF, _tamper(by_kind[K.MOTIF].artifact, execute=1)),
        (K.MOTIF, _tamper(by_kind[K.MOTIF].artifact, kind="FSM")),
        (K.MOTIF, _tamper(by_kind[K.MOTIF].artifact, version="0")),
        (K.THRESHOLD, _tamper(by_kind[K.THRESHOLD].artifact, feature=FEATURE_NAMES[0],
                              slot=1)),
        (K.FSM, _tamper(by_kind[K.FSM].artifact, sink=0)),
        (K.FSM, _tamper(by_kind[K.FSM].artifact, table=[[0, 0, 0, 0, 0]] * 9)),
        (K.TYPED_RULE, {**_tamper(by_kind[K.TYPED_RULE].artifact),
                        "genome": {**pm1.genome.to_dict(), "direction": "BENIGN"}}),
    ]
    for kind, artifact in cases:
        with pytest.raises(ContractError):
            load_detector(CompiledDetector(kind, True, None, artifact,
                                           len(canonical_artifact_bytes(artifact))))
    with pytest.raises(ContractError, match="canonical size"):
        CompiledDetector(K.MOTIF, True, None, by_kind[K.MOTIF].artifact, 1)


def test_required_features_are_the_encoder_slots_the_detector_reads(pm1: Forged) -> None:
    by_kind = {c.kind: c for c in pm1.compiled}
    names = required_features(by_kind[K.MOTIF])
    assert set(names) == {"relation=EXECUTE", "relation=CONNECT", "object.TEMP_LOCATION",
                          "object.EXTERNAL_ENDPOINT"}
    assert required_features(by_kind[K.TYPED_RULE]) == names == \
        required_features(by_kind[K.FSM])
    threshold = required_features(by_kind[K.THRESHOLD])
    assert len(threshold) == 1 and threshold[0] in FEATURE_NAMES


# --- the tournament ---------------------------------------------------------------------


def test_every_entrant_is_refused_with_a_code_or_fully_measured(pm1: Forged,
                                                                pm2: Forged) -> None:
    for forged in (pm1, pm2):
        result = forged.tournament
        assert {m.kind for m in result.entrants} == set(K)
        for m in result.entrants:
            if m.expressible:
                assert None not in (m.precision, m.recall, m.false_positive_rate, m.pr_auc,
                                    m.decision_agreement, m.work_units_per_event,
                                    m.artifact_bytes, m.interpretability), m.kind
            else:
                assert m.refusal and m.precision is None and m.work_units_per_event is None
    assert any(m.refusal == "MOTIF_CANNOT_EXPRESS_REPEATED" for m in pm2.tournament.entrants)


def test_reselect_reproduces_the_recorded_selection(pm1: Forged, pm2: Forged) -> None:
    for forged in (pm1, pm2):
        result = forged.tournament
        assert reselect(result) == (result.selected, result.pareto_front)
        stored = TournamentResult.from_dict(json.loads(json.dumps(result.to_dict())))
        assert stored == result and reselect(stored) == (result.selected, result.pareto_front)


def test_pm1_compresses_into_a_cheaper_representation_without_measured_loss(
        pm1: Forged) -> None:
    result = pm1.tournament
    assert result.deployable and result.selected is not None
    by_kind = {m.kind: m for m in result.entrants}
    ref, chosen = by_kind[K.TYPED_RULE], by_kind[result.selected]
    assert chosen.decision_agreement >= FORGE_AGREEMENT_MIN
    assert chosen.recall >= ref.recall - 0.02 and chosen.precision >= ref.precision - 0.02
    assert chosen.false_positive_rate <= ref.false_positive_rate
    assert chosen.work_units_per_event <= ref.work_units_per_event
    assert chosen.artifact_bytes < ref.artifact_bytes
    # F2: measured no slower than the rule in the same run, and the reference's bytes are its
    # decision-relevant content, not the genome with its metadata.
    assert chosen.wall_ratio_to_reference is not None
    assert chosen.wall_ratio_to_reference <= FORGE_WALL_RATIO_MAX
    assert ref.artifact_bytes == decision_relevant_bytes(pm1.genome)
    assert result.compression_ratio == pytest.approx(
        result.discovery_work_units / chosen.work_units_per_event)
    assert result.knowledge_bytes_saved == pm1.state_bytes - chosen.artifact_bytes
    assert f"selected:{result.selected.value}" in result.reasons


def test_pm2_is_not_deployable_and_says_why(pm2: Forged) -> None:
    result = pm2.tournament
    assert (result.selected, result.deployable, result.pareto_front) == (None, False, ())
    assert (result.compression_ratio, result.deployed_work_units_per_event,
            result.knowledge_bytes_saved) == (None, None, None)
    assert "none_eligible" in result.reasons
    assert "MOTIF:refused.MOTIF_CANNOT_EXPRESS_REPEATED" in result.reasons
    assert len([r for r in result.reasons if r.startswith(tuple(k.value for k in K))]) == len(K)


def _m(kind: RepresentationKind, **changes: Any) -> RepresentationMeasurement:
    ref = kind is K.TYPED_RULE
    values: dict[str, Any] = dict(
        kind=kind, expressible=True, refusal=None, precision=0.9, recall=0.8,
        false_positive_rate=0.01, pr_auc=0.7, decision_agreement=1.0,
        work_units_per_event=5.0, artifact_bytes=1500 if ref else 100,
        wall_ratio_to_reference=1.0, loadavg=(0.0, 0.0, 0.0), robustness_recall=0.5,
        interpretability=2)
    values.update(changes)
    return RepresentationMeasurement(**values)


def _refusal(kind: RepresentationKind) -> RepresentationMeasurement:
    return RepresentationMeasurement(kind, False, "NO_BOTH_CLASSES", None, None, None, None, None,
                                     None, None, None, (0.0, 0.0, 0.0), None, None)


def _result(*entrants: RepresentationMeasurement) -> TournamentResult:
    kinds = {m.kind for m in entrants}
    full = (*entrants, *[_refusal(k) for k in K if k not in kinds])
    return TournamentResult("", HID, Split.REPLICATION, full, (), None, False, (), 1, None, None,
                            None, True)


@pytest.mark.parametrize(("changes", "eligible"), [
    ({}, True),
    ({"recall": 0.8 - 0.02}, True),
    ({"recall": 0.8 - 0.0201}, False),
    ({"precision": 0.9 - 0.02}, True),
    ({"precision": 0.9 - 0.0201}, False),
    ({"false_positive_rate": 0.0100001}, False),
    ({"decision_agreement": FORGE_AGREEMENT_MIN}, True),
    ({"decision_agreement": 0.979}, False),
    ({"artifact_bytes": ENDPOINT_ARTIFACT_MAX_BYTES + 1}, False),
    ({"pr_auc": None}, False),
    ({"artifact_bytes": 1500}, False),  # equal cost on both axes: not cheaper
    ({"work_units_per_event": 5.1}, False),  # smaller artifact but more work: not cheaper
    ({"work_units_per_event": 4.0, "artifact_bytes": 1500}, True),
    ({"wall_ratio_to_reference": 1.0}, True),     # F2: no slower than the reference
    ({"wall_ratio_to_reference": 1.0001}, False),  # F2: slower in the same run is not cheaper
    ({"wall_ratio_to_reference": None}, False),    # F2: unmeasured is not cheaper
])
def test_the_selection_rule_bites_at_its_exact_edges(changes: dict[str, Any],
                                                     eligible: bool) -> None:
    """Fails if a tolerance, the agreement floor, the size cap or "costs less" is loosened."""
    selected, front = reselect(_result(_m(K.TYPED_RULE), _m(K.LOGISTIC, **changes)))
    assert (selected is K.LOGISTIC) is eligible and (front == (K.LOGISTIC,)) is eligible


def test_typed_rule_is_never_deployed_and_a_slower_entrant_never_costs_less() -> None:
    """F2 (honesty lens). This test used to pin that a MOTIF 900x slower than TYPED_RULE was
    selected ("wall time is never read"): the defect. Work units are self-charged, so an entrant
    slower than the reference in the same run does not cost less, and an unmeasured ratio is not
    cheaper. Selection still reads only the recorded measurements (the ratio is one)."""
    assert reselect(_result(_m(K.TYPED_RULE))) == (None, ())
    slow = _result(_m(K.TYPED_RULE), _m(K.MOTIF, wall_ratio_to_reference=900.0),
                   _m(K.FSM, artifact_bytes=101, wall_ratio_to_reference=0.001))
    assert reselect(slow)[0] is K.FSM
    for ratio, chosen in ((1.0, K.MOTIF), (1.0001, None), (None, None)):
        result = _result(_m(K.TYPED_RULE), _m(K.MOTIF, wall_ratio_to_reference=ratio))
        assert reselect(result)[0] is chosen, ratio


def test_the_pareto_front_and_the_tie_break() -> None:
    result = _result(
        _m(K.TYPED_RULE),
        _m(K.MOTIF, work_units_per_event=3.0, artifact_bytes=200, robustness_recall=0.5),
        _m(K.FSM, work_units_per_event=4.0, artifact_bytes=100, robustness_recall=0.5),
        _m(K.THRESHOLD, work_units_per_event=4.0, artifact_bytes=150, robustness_recall=0.4),
        _m(K.STUMP_TREE, work_units_per_event=4.0, artifact_bytes=150, robustness_recall=0.9),
    )
    selected, front = reselect(result)
    assert front == (K.MOTIF, K.FSM, K.STUMP_TREE)  # THRESHOLD is dominated by FSM
    assert selected is K.MOTIF  # least work units per event, then bytes
    tie = _result(_m(K.TYPED_RULE), _m(K.PROTOTYPE, interpretability=3),
                  _m(K.THRESHOLD, interpretability=3), _m(K.LOGISTIC, interpretability=1))
    assert reselect(tie)[0] is K.LOGISTIC  # interpretability, then enum order
    assert reselect(_result(_m(K.TYPED_RULE), _m(K.PROTOTYPE), _m(K.THRESHOLD)))[0] is \
        K.THRESHOLD


def test_the_tournament_refuses_what_it_cannot_honestly_measure(
        pm1: Forged, corpus: DiscoveryCorpus) -> None:
    kwargs: dict[str, Any] = dict(challenge={}, discovery_work_units=1, research_state_bytes=1,
                                  governor=governor())
    replication = corpus.episodes(Split.REPLICATION)
    with pytest.raises(ContractError, match="REPLICATION"):
        run_tournament(pm1.genome, pm1.compiled, measure_on=corpus.episodes(Split.HOLDOUT),
                       **kwargs)
    with pytest.raises(ContractError, match="missing"):
        run_tournament(pm1.genome, pm1.compiled[:-1], measure_on=replication, **kwargs)
    with pytest.raises(ContractError, match="own genome"):
        run_tournament(genome(PM2), pm1.compiled, measure_on=replication, **kwargs)
    unlabelled = tuple(e.with_split(Split.REPLICATION, label=None) for e in replication)
    with pytest.raises(ContractError, match="labelled"):
        run_tournament(pm1.genome, pm1.compiled, measure_on=unlabelled, **kwargs)


def test_a_benign_theory_is_measured_against_label_zero(corpus: DiscoveryCorpus) -> None:
    benign = genome("SINGLE(SPAWN)", direction=Direction.BENIGN)
    result = forge(corpus, benign).tournament
    ref = next(m for m in result.entrants if m.kind is K.TYPED_RULE)
    episodes = corpus.episodes(Split.REPLICATION)
    matched = [e for e in episodes if benign.decides(e)]
    assert ref.precision == pytest.approx(sum(e.label == 0 for e in matched) / len(matched))
    assert ref.robustness_recall is None  # the challenger attacks label-1 positives only


def test_discovery_compression_ratio() -> None:
    assert discovery_compression_ratio(1000, 4.0) == 250.0
    assert discovery_compression_ratio(1000, None) is None
    assert discovery_compression_ratio(1000, 0.0) is None
    with pytest.raises(ContractError):
        discovery_compression_ratio(-1, 1.0)


def test_conservation_failures_are_judged_against_the_reference(
        pm1: Forged, corpus: DiscoveryCorpus) -> None:
    from pocketsec.stage8.doppelganger.engine import DoppelgangerFamily
    from pocketsec.stage8.labs.discovery_corpus import CorpusDoppelgangers

    dopp = CorpusDoppelgangers().benign_alternatives(DoppelgangerFamily.DEVELOPER_TOOLING,
                                                     count=8, seed=1)
    report = conservation_checks(pm1.genome, pm1.compiled,
                                 lab_pool=corpus.episodes(Split.LAB_POOL), doppelgangers=dopp,
                                 seed=5, governor=governor())
    expressible = sum(1 for c in pm1.compiled if c.expressible and c.kind is not K.TYPED_RULE)
    assert report.entrants_checked == expressible and report.checks_run > expressible
    assert report.failures, "some pooled student breaks a distinction the theory keeps"
    for failure in report.failures:
        assert isinstance(failure, FailureCondition)
        assert FAILURE_CONTEXT_PATTERN.fullmatch(failure.context)
        kind = failure.context.split(":")[1].rsplit("_", 1)[0].removesuffix("_NECESSARY")
        assert kind not in {K.TYPED_RULE.value, K.MOTIF.value, K.FSM.value}, failure


# --- packages, the footprint and the door ------------------------------------------------


def evidence_fitting(matches: list[Episode]) -> list[Episode]:
    """The production rule (``discovery_run._evidence_episodes``): sessions whose digests fit."""
    chosen: list[Episode] = []
    digests: set[str] = set()
    for episode in matches:
        union = digests | set(episode.evidence_digests())
        if len(chosen) >= 8 or len(union) > 32:
            break
        chosen.append(episode)
        digests = union
    return chosen


def package(forged: Forged, corpus: DiscoveryCorpus, *,
            status: ReproducibilityStatus = ReproducibilityStatus.REPRODUCED,
            evidence_ids: tuple[str, ...] | None = None, bad_hash: bool = False,
            synthetic: bool = True) -> DiscoveryPackageV1:
    g, result = forged.genome, forged.tournament
    chosen = next((c for c in forged.compiled if c.kind is result.selected), None)
    artifact = None if chosen is None else chosen.artifact
    matches = evidence_fitting([e for e in corpus.episodes(Split.REPLICATION)
                                if g.decides(e) and e.label == 1])
    hashes = artifact_hashes_for(mechanism=g.proposed_mechanism, tournament=result,
                                 compiled_artifact=artifact, genome=g)
    if bad_hash:
        hashes = (("mechanism", "sha256:" + "f" * 64), *hashes[1:])
    measured = status is ReproducibilityStatus.REPRODUCED
    return DiscoveryPackageV1(
        package_id="", hypothesis_id=g.hypothesis_id, mechanism=g.proposed_mechanism,
        direction=g.direction, required_features=() if chosen is None
        else required_features(chosen),
        detector_candidates=result, selected_representation=result.selected,
        compiled_artifact=artifact,
        evidence_lineage=("res-0000000000000000", g.hypothesis_id, result.tournament_id),
        evidence_digests=tuple(dict.fromkeys(d for e in matches for d in
                                             e.evidence_digests())),
        evidence_episode_ids=tuple(e.episode_id for e in matches) if evidence_ids is None
        else evidence_ids,
        falsification_results=(FalsificationRecord(FalsifierKind.REPLICATION, Split.REPLICATION,
                                                   measured, 0.001, 0.05, ""),),
        failure_conditions=(FailureCondition("independent:fp", 0.0, "no independent match"),),
        resource_profile=ResourceProfile(None if chosen is None else chosen.artifact_bytes,
                                         result.deployed_work_units_per_event, None,
                                         (0.0, 0.0, 0.0)),
        robustness_profile=RobustnessProfile((), ()), known_technique_mappings=(),
        novelty_classification=NoveltyClass.CONTEXT_EXTENSION, novelty_claim_permitted=False,
        identifiability=IdentifiabilityClass.EQUIVALENCE_CLASS,
        reproducibility=ReproducibilityRecord(status, 1.0 if measured else None,
                                              0.4 if measured else None,
                                              0.0 if measured else None, None, None, False, ()),
        artifact_hashes=hashes, synthetic_data=synthetic)


def test_the_endpoint_footprint_loads_and_runs_what_ships(pm1: Forged, pm2: Forged,
                                                          corpus: DiscoveryCorpus) -> None:
    shipped = package(pm1, corpus)
    unshipped = package(pm2, corpus, evidence_ids=())
    assert verify_package(shipped) == () == verify_package(unshipped)
    events = corpus.episodes(Split.REPLICATION)
    footprint = measure_endpoint_footprint((shipped, unshipped), events)
    assert (footprint.detectors, footprint.events) == (1, len(events))
    assert footprint.work_units_per_event == pytest.approx(
        next(m for m in pm1.tournament.entrants
             if m.kind is pm1.tournament.selected).work_units_per_event)
    if footprint.incremental_rss_bytes is None:
        assert footprint.within_ceiling is None
    else:
        assert footprint.within_ceiling is (
            footprint.incremental_rss_bytes <= STAGE8_ENDPOINT_INCREMENTAL_CEILING_BYTES)
    with pytest.raises(ContractError, match="unverified"):
        measure_endpoint_footprint((package(pm1, corpus, bad_hash=True),), events)


def test_an_unreadable_rss_is_unmeasured_never_within(
        pm1: Forged, corpus: DiscoveryCorpus, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(resource_metrics, "read_rss_bytes", lambda: None)
    footprint = measure_endpoint_footprint((package(pm1, corpus),),
                                           corpus.episodes(Split.REPLICATION))
    assert footprint.incremental_rss_bytes is None and footprint.within_ceiling is None
    assert footprint.peak_sampled_rss_bytes is None and footprint.detectors == 1


@pytest.mark.parametrize(("incremental", "within"), [
    (None, True), (None, False), (STAGE8_ENDPOINT_INCREMENTAL_CEILING_BYTES + 1, True),
    (0, False), (5, None)])
def test_the_footprint_record_refuses_a_verdict_its_figure_does_not_support(
        incremental: int | None, within: bool | None) -> None:
    with pytest.raises(ContractError):
        EndpointFootprint(1, 1, incremental, None, within, 1.0, 0.0, (0.0, 0.0, 0.0))


def _gateway(forced: QuarantineBucket | None = None) -> QuarantineGateway:
    class Gateway(QuarantineGateway):
        def admit(self, capsule):  # type: ignore[no-untyped-def]
            verdict = super().admit(capsule)
            return verdict if forced is None else dataclasses.replace(verdict, bucket=forced)

    gateway = Gateway(ledger=ProvenanceLedger(), lineage=KnowledgeLineageDAG())
    state = genesis_state(identity=SystemIdentity())
    gateway.bind_trusted_view(lambda: state)
    return gateway


_LEDGERS: dict[str, TheoryLedger] = {}


def _adapter(gateway: QuarantineGateway, *, synthetic: bool = True, run: str = "t1",
             capacity: int = 1024, ledger: TheoryLedger | None = None) -> Stage6Adapter:
    return Stage6Adapter(gateway=gateway, ledger=ledger or _LEDGERS["pm1"],
                         epoch=EpochModel(identity=SystemIdentity()).current,
                         run_id=run, host_id="lab-host-01", synthetic=synthetic,
                         capacity=capacity)


@pytest.fixture(scope="module", autouse=True)
def _pm1_reproduced() -> None:
    # The module corpus's 20-episode HOLDOUT is too small to pass enrichment; the ledger only
    # has to hold PM1 as REPRODUCED, so it is earned on a full-size corpus of the same seed.
    _LEDGERS["pm1"] = reproduced_ledger(
        genome(PM1), build_discovery_corpus(arm=CorpusArm.PLANTED, seed=3))


def test_the_adapter_hands_over_evidence_and_reports_stage6_verbatim(
        pm1: Forged, corpus: DiscoveryCorpus) -> None:
    """M0.2-style bucket reporting. The asserted scores and buckets are Stage 6's current
    behaviour (blocker B8-1), pinned so a change in Stage 6's prior is noticed, not hidden."""
    flagged = _adapter(_gateway())
    receipt = flagged.hand_over(package(pm1, corpus), evidence=corpus.results, sequence=1)
    count = len(receipt.capsule_ids)
    assert 0 < count <= MAX_CAPSULES_PER_PACKAGE
    assert flagged.created() == flagged.admitted() == count
    assert sum(flagged.buckets().values()) == count and set(flagged.buckets()) == {
        b.value for b in QuarantineBucket}
    assert receipt.predicted_provenance_scores == pytest.approx((0.4,) * count)
    assert receipt.trusted_candidates == 0 == flagged.stats()["trusted_candidates"]
    # The unflagged arm: the same sessions, declared non-synthetic end to end.
    real = tuple(dataclasses.replace(e, context=dataclasses.replace(e.context, synthetic=False))
                 for e in corpus.episodes(Split.REPLICATION))
    honest = forge(corpus, genome(PM1), replication=real)
    unflagged = _adapter(_gateway(), synthetic=False)
    plain = unflagged.hand_over(package(honest, corpus, synthetic=False),
                                evidence=corpus.results, sequence=1)
    assert plain.predicted_provenance_scores == pytest.approx(
        (0.5,) * len(plain.capsule_ids))
    assert Counter(plain.stage6_buckets)["TRUSTED_CANDIDATE"] == 0


def _refusal_cases(pm1: Forged, corpus: DiscoveryCorpus) -> list[tuple[str, Any, Any, str]]:
    good = package(pm1, corpus)
    first = good.evidence_episode_ids[0]
    other = next(k for k in corpus.results if k not in good.evidence_episode_ids)
    swapped = {**corpus.results, first: corpus.results[other]}
    return [
        ("refused_type", good.to_dict(), corpus.results, "DiscoveryPackageV1"),
        ("refused_unverified", package(pm1, corpus, bad_hash=True), corpus.results,
         "verification"),
        ("refused_not_reproduced", package(pm1, corpus,
                                           status=ReproducibilityStatus.INSUFFICIENT_EVIDENCE),
         corpus.results, "REPRODUCED"),
        ("refused_unevidenced", package(pm1, corpus, evidence_ids=()), corpus.results,
         "no evidence"),
        ("refused_missing_evidence", good, {}, "no raw ScenarioResult"),
        ("refused_lineage_mismatch", good, swapped, "re-derives"),
    ]


def test_every_refusal_admits_nothing(pm1: Forged, corpus: DiscoveryCorpus) -> None:
    for counter, candidate, evidence, message in _refusal_cases(pm1, corpus):
        gateway = _gateway()
        adapter = _adapter(gateway)
        with pytest.raises(ContractError, match=message):
            adapter.hand_over(candidate, evidence=evidence, sequence=1)
        assert adapter.stats()[counter] == 1, counter
        assert adapter.created() == adapter.admitted() == 0 == gateway.stats().get("offered")
    unflagged = _adapter(_gateway(), synthetic=False)
    with pytest.raises(ContractError, match="synthetic"):
        unflagged.hand_over(package(pm1, corpus), evidence=corpus.results, sequence=1)
    assert unflagged.stats()["refused_synthetic_unflagged"] == 1


def test_one_independence_group_per_run(pm1: Forged, corpus: DiscoveryCorpus) -> None:
    seen: list[Any] = []

    class Recording(QuarantineGateway):
        def admit(self, capsule):  # type: ignore[no-untyped-def]
            seen.append(capsule)
            return super().admit(capsule)

    gateway = Recording(ledger=ProvenanceLedger(), lineage=KnowledgeLineageDAG())
    state = genesis_state(identity=SystemIdentity())
    gateway.bind_trusted_view(lambda: state)
    adapter = _adapter(gateway, run="run-a")
    for sequence in (1, 100):
        adapter.hand_over(package(pm1, corpus), evidence=corpus.results, sequence=sequence)
    assert len(seen) == adapter.created() == adapter.admitted()
    assert {c.source_provenance.independence_group for c in seen} == {"stage8:run-a"}
    assert {c.label.asserted_by for c in seen} == {"stage8:run-a"}
    assert _adapter(_gateway(), run="run-b").independence_group == "stage8:run-b"


def test_trusted_candidates_are_counted_never_acted_on(pm1: Forged,
                                                      corpus: DiscoveryCorpus) -> None:
    adapter = _adapter(_gateway(forced=QuarantineBucket.TRUSTED_CANDIDATE))
    receipt = adapter.hand_over(package(pm1, corpus), evidence=corpus.results, sequence=1)
    assert receipt.trusted_candidates == len(receipt.capsule_ids) > 0
    assert set(receipt.stage6_buckets) == {"TRUSTED_CANDIDATE"}
    assert adapter.created() == adapter.admitted() == len(receipt.capsule_ids)


def test_receipts_are_bounded_and_evictions_counted(pm1: Forged,
                                                   corpus: DiscoveryCorpus) -> None:
    adapter = _adapter(_gateway(), capacity=1)
    for sequence in (1, 50, 99):
        adapter.hand_over(package(pm1, corpus), evidence=corpus.results, sequence=sequence)
    assert len(adapter.receipts()) == 1 and adapter.stats()["receipts_evicted"] == 2
    assert adapter.stats()["handed_over"] == 3
    with pytest.raises(ContractError):
        _adapter(_gateway(), capacity=0)


# --- S8-AUTH-01 / S8-LIN-06: the door checks the ledger and the evidence, not the package ------


def test_s8_auth_01_benign_non_matching_evidence_is_refused(
        pm1: Forged, corpus: DiscoveryCorpus) -> None:
    """S8-AUTH-01: the reviewer's case (1). A MALICIOUS package naming label-0 sessions its
    mechanism never matched was admitted as 8 MALICIOUS/INFERENCE votes; it must be refused
    and admit nothing."""
    benign = tuple(e.episode_id for e in corpus.episodes(Split.REPLICATION)
                   if e.label == 0 and not pm1.genome.decides(e))[:8]
    gateway = _gateway()
    adapter = _adapter(gateway)
    with pytest.raises(ContractError, match="does not match"):
        adapter.hand_over(package(pm1, corpus, evidence_ids=benign), evidence=corpus.results,
                          sequence=1)
    assert adapter.stats()["refused_evidence_not_matched"] == 1
    assert adapter.admitted() == 0 and not gateway.stats().get("offered")


def test_s8_auth_01_a_session_whose_label_disagrees_with_the_direction_is_refused(
        pm1: Forged, corpus: DiscoveryCorpus) -> None:
    """S8-AUTH-01: a matched session carrying label 0 cannot become a MALICIOUS vote."""
    good = package(pm1, corpus)
    first = good.evidence_episode_ids[0]
    result = corpus.results[first]
    relabelled = dataclasses.replace(result, scenario=dataclasses.replace(result.scenario, label=0))
    adapter = _adapter(_gateway())
    with pytest.raises(ContractError, match="labelled 0"):
        adapter.hand_over(good, evidence={**corpus.results, first: relabelled}, sequence=1)
    assert adapter.stats()["refused_evidence_label"] == 1 and adapter.admitted() == 0


def test_s8_auth_01_reproduced_beside_a_failed_replication_is_refused(
        pm1: Forged, corpus: DiscoveryCorpus) -> None:
    """S8-AUTH-01: the reviewer's case (2). verify_package accepted status REPRODUCED next to a
    REPLICATION record with passed=False."""
    failed = dataclasses.replace(package(pm1, corpus), package_id="", falsification_results=(
        FalsificationRecord(FalsifierKind.REPLICATION, Split.REPLICATION, False, 0.9, 0.05, ""),))
    assert "status REPRODUCED contradicts a failed REPLICATION record" in verify_package(failed)
    adapter = _adapter(_gateway())
    with pytest.raises(ContractError, match="verification"):
        adapter.hand_over(failed, evidence=corpus.results, sequence=1)
    assert adapter.admitted() == 0


def test_s8_auth_01_reproduced_is_the_ledgers_status_not_the_packages(
        pm1: Forged, corpus: DiscoveryCorpus) -> None:
    """S8-AUTH-01: a self-consistent REPRODUCED package whose theory the run's ledger does not
    hold as REPRODUCED (unborn, or merely PROPOSED) is refused."""
    unborn = _adapter(_gateway(), ledger=TheoryLedger())
    with pytest.raises(ContractError, match="no retained record"):
        unborn.hand_over(package(pm1, corpus), evidence=corpus.results, sequence=1)
    assert unborn.stats()["refused_not_in_ledger"] == 1
    proposed = TheoryLedger()
    proposed.record_birth(pm1.genome)
    open_theory = _adapter(_gateway(), ledger=proposed)
    with pytest.raises(ContractError, match="not REPRODUCED"):
        open_theory.hand_over(package(pm1, corpus), evidence=corpus.results, sequence=1)
    assert open_theory.stats()["refused_ledger_not_reproduced"] == 1
    assert unborn.admitted() == open_theory.admitted() == 0


def test_s8_auth_01_a_second_run_cannot_vote_on_the_same_session(
        pm1: Forged, corpus: DiscoveryCorpus) -> None:
    """S8-AUTH-01: the reviewer's case (3). Six adapters (six independence groups) into one
    gateway admitted 48 capsules: one session voted by two groups would manufacture Stage 6's
    label quorum from Stage 8 alone. The first run is admitted, every other is refused."""
    gateway = _gateway()
    first = _adapter(gateway, run="run0")
    receipt = first.hand_over(package(pm1, corpus), evidence=corpus.results, sequence=1)
    admitted = len(receipt.capsule_ids)
    for run in ("run1", "run2", "run3", "run4", "run5"):
        other = _adapter(gateway, run=run)
        with pytest.raises(ContractError, match="already handed"):
            other.hand_over(package(pm1, corpus), evidence=corpus.results, sequence=1)
        assert other.stats()["refused_evidence_other_run"] == 1 and other.admitted() == 0
    assert gateway.stats().get("offered") == admitted > 0
    again = first.hand_over(package(pm1, corpus), evidence=corpus.results, sequence=50)
    assert len(again.capsule_ids) == admitted  # the same group repeating is not a new vote


def test_s8_lin_06_a_partial_hand_over_keeps_the_lineage_of_what_stage6_admitted(
        pm1: Forged, corpus: DiscoveryCorpus) -> None:
    """S8-LIN-06: Stage 6 raising part-way used to leave the admitted capsules with no receipt."""
    calls = {"n": 0}

    class Flaky(QuarantineGateway):
        def admit(self, capsule):  # type: ignore[no-untyped-def]
            calls["n"] += 1
            if calls["n"] == 2:
                raise RuntimeError("stage 6 fell over")
            return super().admit(capsule)

    gateway = Flaky(ledger=ProvenanceLedger(), lineage=KnowledgeLineageDAG())
    state = genesis_state(identity=SystemIdentity())
    gateway.bind_trusted_view(lambda: state)
    adapter = _adapter(gateway)
    with pytest.raises(RuntimeError):
        adapter.hand_over(package(pm1, corpus), evidence=corpus.results, sequence=1)
    (receipt,) = adapter.receipts()
    assert len(receipt.capsule_ids) == 1 == adapter.admitted()
    assert adapter.stats()["partial_hand_overs"] == 1
    assert adapter.created() == 2   # offered to Stage 6: the second raised, so created != admitted
