"""Stage 8 falsification package: D8.8 doppelgängers, D8.9 challenger, D8.10 identifiability,
D8.12 reproducibility, D8.13 novelty audit.

Every test runs the real subsystem on the lab's real corpus (``labs/discovery_corpus.py``) at
small sizes, and every invariant has a test that fails if it is weakened: PM2 must lose to its
monitoring-agent doppelgänger, PM1 must be an equivalence class without intervention, a trap
that slips through a leaky holdout must still fail replication, and no novelty claim may be
permitted while the prior-art ledger says NOT_REVIEWED.
"""

from __future__ import annotations

import random
from dataclasses import replace

import pytest

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage0.contracts.threat_prediction_v1 import Verdict
from pocketsec.stage0.prior_art import PriorArtLedger, ReviewStatus
from pocketsec.stage6.memory.semantic import MotifStep
from pocketsec.stage6.resources import WorkBudgetExceeded
from pocketsec.stage8.challenger.adversarial import (
    CHALLENGE_PER_KIND,
    LABEL_KEEPING_KINDS,
    AdversarialChallenge,
    ChallengeKind,
    build_challenge_corpus,
    challenge,
    poisoned_labels,
)
from pocketsec.stage8.constitution.discovery import OFFENSIVE_TOKENS
from pocketsec.stage8.doppelganger.engine import (
    BenignDoppelganger,
    DoppelgangerEngine,
    DoppelgangerFamily,
)
from pocketsec.stage8.episode import Episode, FitCounts, Split
from pocketsec.stage8.forge.package import (
    MAX_FAILURE_CONDITIONS,
    FailureCondition,
    IdentifiabilityClass,
    NoveltyClass,
    ReproducibilityStatus,
)
from pocketsec.stage8.genome.grammar import (
    Mechanism,
    MechanismRelation,
    StepPredicate,
    parse_mechanism,
)
from pocketsec.stage8.genome.hypothesis import (
    Direction,
    GeneratorKind,
    GenomeProvenance,
    HypothesisGenome,
    ObservationScope,
    ResidualType,
    genome_for,
)
from pocketsec.stage8.governor.budget import ResearchBudget, ResearchGovernor
from pocketsec.stage8.identifiability.gate import (
    MIN_EVIDENCE_EPISODES,
    IdentifiabilityGate,
    IdentifiabilityVerdict,
)
from pocketsec.stage8.laboratory.counterfactual import TransformKind, TransformSpec, apply_transform
from pocketsec.stage8.labs.discovery_corpus import (
    PLANTED_MECHANISMS,
    CorpusArm,
    CorpusDoppelgangers,
    DiscoveryCorpus,
    Family,
    LabOracle,
    build_discovery_corpus,
)
from pocketsec.stage8.ledger.theory import PreRegistration, TheoryLedger, TheoryStatus
from pocketsec.stage8.novelty.prior_art_audit import (
    MAX_KNOWN_LIBRARY,
    STAGE1_KNOWN_CHAINS,
    audit,
    known_library,
    stage1_known_mechanisms,
)
from pocketsec.stage8.reproducibility.gate import (
    ReproducibilityGate,
    imbalance_precision,
    telemetry_requirements,
)
from pocketsec.stage8.sandbox.integrity import HoldoutVault

# --- shared construction ------------------------------------------------------------------

_SCOPE = ObservationScope((), frozenset({ResidualType.OBSERVATION}), ())
_DIGEST = "sha256:" + "0" * 64
PM1_DSL = "PRECEDES(EXECUTE+TEMP_LOCATION,CONNECT+EXTERNAL_ENDPOINT)"
CO1_DSL = "CO_OCCURS(EXECUTE+TEMP_LOCATION,CONNECT+EXTERNAL_ENDPOINT)"


def genome(
    mechanism: Mechanism | str, direction: Direction = Direction.MALICIOUS
) -> HypothesisGenome:
    mech = parse_mechanism(mechanism) if isinstance(mechanism, str) else mechanism
    generator = (GeneratorKind.NULL_BENIGN if direction is Direction.BENIGN
                 else GeneratorKind.SYMBOLIC_ENUMERATOR)
    return genome_for(mech, direction=direction, scope=_SCOPE,
                      provenance=GenomeProvenance(generator, _DIGEST, False, 0))


def governor(units: int = 50_000_000) -> ResearchGovernor:
    return ResearchGovernor(ResearchBudget(work_units=units))


def of_family(episodes: tuple[Episode, ...], family: Family) -> list[Episode]:
    return [ep for ep in episodes if ep.context.family == family.value]


@pytest.fixture(scope="module")
def planted() -> DiscoveryCorpus:
    # REPLICATION is larger than the other splits: MIN_EVIDENCE_EPISODES (10) true matches of
    # one planted family (mix share 0.12) need about 100 sessions.
    return build_discovery_corpus(arm=CorpusArm.PLANTED, seed=3, counts={
        Split.TRAIN: 60, Split.HOLDOUT: 60, Split.REPLICATION: 100,
        Split.LAB_POOL: 40, Split.INDEPENDENT: 30,
    })


@pytest.fixture(scope="module")
def dropout() -> DiscoveryCorpus:
    return build_discovery_corpus(arm=CorpusArm.DROPOUT, seed=2, counts={
        Split.TRAIN: 120, Split.HOLDOUT: 12, Split.REPLICATION: 12,
        Split.LAB_POOL: 120, Split.INDEPENDENT: 4,
    })


@pytest.fixture(scope="module")
def pm() -> dict[str, HypothesisGenome]:
    return {
        "pm1": genome(PLANTED_MECHANISMS[Family.DROP_EXEC_EGRESS]),
        "pm2": genome(PLANTED_MECHANISMS[Family.REPEATED_EGRESS]),
        "pm3": genome(PLANTED_MECHANISMS[Family.CREDENTIAL_EGRESS]),
        "co1": genome(CO1_DSL),
    }


def observed(corpus: DiscoveryCorpus) -> tuple[Episode, ...]:
    return corpus.episodes(Split.LAB_POOL) + corpus.episodes(Split.TRAIN)


# --- D8.8 the Benign Doppelgänger Engine --------------------------------------------------


class _Source:
    """A scripted DoppelgangerSource: the same episodes for every family."""

    def __init__(self, episodes: tuple[Episode, ...]) -> None:
        self.episodes = episodes

    def benign_alternatives(
        self, family: DoppelgangerFamily, *, count: int, seed: int
    ) -> tuple[Episode, ...]:
        return self.episodes


def test_doppelganger_refutes_pm2_on_monitoring_agent_and_passes_pm1(pm) -> None:
    engine = DoppelgangerEngine(CorpusDoppelgangers(), governor=governor())
    pm2 = engine.challenge(pm["pm2"])
    assert [r.family for r in pm2] == list(DoppelgangerFamily)
    monitoring = next(r for r in pm2 if r.family is DoppelgangerFamily.MONITORING_AGENT)
    # The grammar has no actor properties: PM2 cannot be told from a monitoring agent.
    assert monitoring.matched == monitoring.episodes_tested == 16
    assert monitoring.matched_share == 1.0
    assert engine.separates(pm2, threshold=0.05) is False
    pm1 = engine.challenge(pm["pm1"])
    assert all(r.episodes_tested == 16 and r.matched == 0 for r in pm1)
    assert any(r.partial_matches for r in pm1), "partial matches must fire on some family"
    assert engine.separates(pm1, threshold=0.05) is True
    assert engine.stats()["separation_failed"] == 1 and engine.stats()["separation_passed"] == 1


def test_doppelganger_does_not_challenge_benign_explanations() -> None:
    engine = DoppelgangerEngine(CorpusDoppelgangers(), governor=governor())
    assert engine.challenge(genome("SINGLE(EXECUTE+SYSTEM_BINARY)", Direction.BENIGN)) == ()
    assert engine.stats()["benign_direction_skipped"] == 1


def test_doppelganger_refuses_sources_that_are_not_benign_or_not_bounded(planted, pm) -> None:
    positive = of_family(planted.episodes(Split.TRAIN), Family.DROP_EXEC_EGRESS)[0]
    labelled_one = positive.with_split(Split.CHALLENGE, label=1)
    held_out = planted.episodes(Split.HOLDOUT)[0].with_split(Split.HOLDOUT, label=0)
    many = tuple(ep.with_split(Split.CHALLENGE, label=0)
                 for ep in planted.episodes(Split.TRAIN)[:17])
    for bad in ((labelled_one,), (held_out,), many):
        with pytest.raises(ContractError):
            DoppelgangerEngine(_Source(bad), governor=governor()).challenge(pm["pm1"])
    with pytest.raises(ContractError):
        as_list = _Source(list(many[:2]))  # type: ignore[arg-type]
        DoppelgangerEngine(as_list, governor=governor()).challenge(pm["pm1"])
    with pytest.raises(ContractError):
        DoppelgangerEngine(object(), governor=governor())  # type: ignore[arg-type]
    with pytest.raises(ContractError):
        DoppelgangerEngine(CorpusDoppelgangers(), governor=governor(), per_family=0)


def test_separation_is_never_true_on_nothing(pm) -> None:
    engine = DoppelgangerEngine(_Source(()), governor=governor())
    results = engine.challenge(pm["pm1"])
    assert all(r.episodes_tested == 0 for r in results)
    assert engine.separates(results, threshold=0.05) is False  # untested is not separated
    assert engine.separates((), threshold=0.05) is False
    with pytest.raises(ContractError):
        engine.separates(results, threshold=1.5)
    other = replace(results[0], hypothesis_id=pm["pm2"].hypothesis_id)
    with pytest.raises(ContractError):
        engine.separates((results[1], other), threshold=0.05)
    with pytest.raises(ContractError):  # a share that does not match its counts is refused
        BenignDoppelganger(pm["pm1"].hypothesis_id, DoppelgangerFamily.BACKUP, 4, 1, 0.5, 0, ())


def test_strongest_counterexamples_are_full_matches_first_and_bounded(planted, pm) -> None:
    train = planted.episodes(Split.TRAIN)
    full = [ep.with_split(Split.CHALLENGE, label=0)
            for ep in of_family(train, Family.DROP_EXEC_EGRESS)[:5]]
    partial = [ep.with_split(Split.CHALLENGE, label=0)
               for ep in of_family(train, Family.BUILD_TMP_EXEC)[:2]]
    source = _Source((partial[0], full[0], partial[1], *full[1:]))
    engine = DoppelgangerEngine(source, governor=governor())
    result = engine.challenge(pm["pm1"])[0]
    assert (result.matched, result.partial_matches) == (5, 2)
    assert result.strongest_episode_ids == tuple(ep.episode_id for ep in full[:4])
    one_full = DoppelgangerEngine(_Source((partial[0], full[0], partial[1])), governor=governor())
    assert one_full.challenge(pm["pm1"])[0].strongest_episode_ids == (
        full[0].episode_id, partial[0].episode_id, partial[1].episode_id)


def test_runaway_doppelganger_challenge_hits_the_budget_not_the_host(pm) -> None:
    tight = governor(units=40)
    with pytest.raises(WorkBudgetExceeded):
        DoppelgangerEngine(CorpusDoppelgangers(), governor=tight).challenge(pm["pm1"])
    assert tight.exhausted()


# --- D8.9 the Adversarial Challenger ------------------------------------------------------


@pytest.fixture(scope="module")
def challenge_corpus(planted, pm):
    return build_challenge_corpus(
        planted.episodes(Split.LAB_POOL), kinds=tuple(ChallengeKind), rng=random.Random(0),
        governor=governor(), necessary=pm["pm1"].necessary_conditions,
        trap=planted.trap_mechanism,
    )


def test_every_challenge_kind_builds_a_bounded_labelled_corpus(challenge_corpus) -> None:
    assert list(challenge_corpus) == list(ChallengeKind)
    for kind in ChallengeKind:
        made, sources = challenge_corpus[kind], challenge_corpus.sources(kind)
        assert 0 < len(made) <= CHALLENGE_PER_KIND, kind
        assert len(made) == len(sources)
        assert all(isinstance(ep, Episode) and ep.split is Split.CHALLENGE for ep in made)
        assert all(src.split is Split.LAB_POOL for src in sources)
        if kind in LABEL_KEEPING_KINDS:
            # The defence's question: a challenged positive stays a positive.
            assert [ep.label for ep in made] == [src.label for src in sources], kind
            assert any(ep.label == 1 for ep in made), kind
        elif kind is ChallengeKind.POISONED_LABELS:
            assert [ep.episode_id for ep in made] == [src.episode_id for src in sources]
            flips = sum(ep.label != src.label for ep, src in zip(made, sources))
            assert flips == round(0.2 * len(made))
        else:
            assert all(ep.label == 0 for ep in made), kind
            assert all(len(ep.steps) == len(src.steps) + 1 for ep, src in zip(made, sources))


def test_recall_retained_is_measured_and_exposes_what_pm1_depends_on(challenge_corpus, pm) -> None:
    rows = {row.kind: row for row in challenge("pm1", pm["pm1"].decides, challenge_corpus)}
    assert set(rows) == set(ChallengeKind)
    for kind in LABEL_KEEPING_KINDS | {ChallengeKind.POISONED_LABELS}:
        assert isinstance(rows[kind].recall_retained, float), kind
    # LOTL removes TEMP_LOCATION, which PM1 requires: the defence does not hold, and says so.
    assert rows[ChallengeKind.LOTL_SUBSTITUTION].recall_retained == 0.0
    # Obfuscation clears only bits PM1 does not need: recall must be untouched.
    assert rows[ChallengeKind.FEATURE_OBFUSCATION].recall_retained == 1.0
    assert rows[ChallengeKind.TIMING_SHIFT].recall_retained == 1.0
    # Mimicry inserts ONE necessary step; PRECEDES needs both, so no false positive.
    assert rows[ChallengeKind.RARE_BENIGN_MIMICRY].recall_retained is None
    assert rows[ChallengeKind.RARE_BENIGN_MIMICRY].false_positive_rate == 0.0


def test_shortcut_trigger_exposes_the_trap_and_not_the_planted_mechanism(
    challenge_corpus, planted, pm
) -> None:
    trap = genome(planted.trap_mechanism)
    trap_row = next(r for r in challenge("trap", trap.decides, challenge_corpus)
                    if r.kind is ChallengeKind.SHORTCUT_TRIGGER)
    pm1_row = next(r for r in challenge("pm1", pm["pm1"].decides, challenge_corpus)
                   if r.kind is ChallengeKind.SHORTCUT_TRIGGER)
    assert trap_row.false_positive_rate == 1.0
    assert pm1_row.false_positive_rate == 0.0


def test_plain_mapping_without_sources_is_unmeasured_not_guessed(challenge_corpus, pm) -> None:
    rows = challenge("pm1", pm["pm1"].decides, dict(challenge_corpus))
    assert rows and all(row.recall_retained is None for row in rows)


def test_challenger_refuses_non_lab_pool_bad_caps_and_non_boolean_detectors(
    planted, challenge_corpus
) -> None:
    for split in (Split.TRAIN, Split.HOLDOUT, Split.REPLICATION):
        with pytest.raises(ContractError):
            build_challenge_corpus(planted.episodes(split)[:3], kinds=(ChallengeKind.TIMING_SHIFT,),
                                   rng=random.Random(0), governor=governor())
    pool = planted.episodes(Split.LAB_POOL)
    for cap in (0, CHALLENGE_PER_KIND + 1):
        with pytest.raises(ContractError):
            build_challenge_corpus(pool, kinds=(ChallengeKind.TIMING_SHIFT,), rng=random.Random(0),
                                   governor=governor(), cap=cap)
    with pytest.raises(ContractError):
        build_challenge_corpus(pool, kinds=(ChallengeKind.SHORTCUT_TRIGGER,), rng=random.Random(0),
                               governor=governor(), trap=parse_mechanism(PM1_DSL))
    with pytest.raises(ContractError):
        challenge("bad", lambda episode: 1, challenge_corpus)  # type: ignore[arg-type,return-value]
    with pytest.raises(WorkBudgetExceeded):
        build_challenge_corpus(pool, kinds=tuple(ChallengeKind), rng=random.Random(0),
                               governor=governor(units=100))


def test_recipes_without_their_inputs_apply_to_nothing_and_say_so(planted) -> None:
    corpus = build_challenge_corpus(
        planted.episodes(Split.LAB_POOL), rng=random.Random(1), governor=governor(),
        kinds=(ChallengeKind.RARE_BENIGN_MIMICRY, ChallengeKind.SHORTCUT_TRIGGER))
    assert corpus[ChallengeKind.RARE_BENIGN_MIMICRY] == corpus[ChallengeKind.SHORTCUT_TRIGGER] == ()
    assert all(count > 0 for count in corpus.not_applicable().values())


def test_poisoned_labels_flips_exactly_the_share_and_nothing_else(planted) -> None:
    train = planted.episodes(Split.TRAIN)
    unlabelled = train[0].with_split(Split.TRAIN, label=None)
    episodes = (unlabelled, *train[1:])
    assert poisoned_labels(episodes, share=0.0, rng=random.Random(0)) == episodes
    flipped = poisoned_labels(episodes, share=0.5, rng=random.Random(0))
    changed = [a for a, b in zip(flipped, episodes) if a.label != b.label]
    assert len(changed) == round(0.5 * (len(episodes) - 1))
    assert flipped[0] == unlabelled
    assert [e.episode_id for e in flipped] == [e.episode_id for e in episodes]
    assert all(e.split is Split.TRAIN for e in flipped)
    for share in (-0.1, 1.5):
        with pytest.raises(ContractError):
            poisoned_labels(episodes, share=share, rng=random.Random(0))


def test_challenge_vocabulary_is_defensive_detection_language() -> None:
    assert not [kind for kind in ChallengeKind if OFFENSIVE_TOKENS.search(kind.value)]
    assert not [kind for kind in DoppelgangerFamily if OFFENSIVE_TOKENS.search(kind.value)]
    with pytest.raises(ContractError):
        AdversarialChallenge("d", ChallengeKind.TIMING_SHIFT, 2, 3, None, None)


# --- D8.10 the Causal Identifiability Gate ------------------------------------------------


def _reordered(corpus: DiscoveryCorpus, pm1: HypothesisGenome, gov: ResearchGovernor,
               *, labelled: bool) -> list[Episode]:
    """REORDER interventions: the egress step moved before the execute in the same actor."""
    target = parse_mechanism("SINGLE(CONNECT+EXTERNAL_ENDPOINT)").steps[0]
    rng = random.Random(0)
    oracle = LabOracle(governor=gov)
    made = [apply_transform(ep, TransformSpec(TransformKind.REORDER, 0, target), rng=rng)
            for ep in observed(corpus) if pm1.decides(ep)]
    return [ep.with_split(Split.CHALLENGE, label=oracle.label(ep) if labelled else None)
            for ep in made if ep is not None]


def test_pm1_and_its_co_occurs_twin_are_an_equivalence_class_on_observation(planted, pm) -> None:
    verdict = IdentifiabilityGate(interventions_permitted=False).assess(
        pm["pm1"], [pm["co1"]], observed(planted))
    assert verdict.klass is IdentifiabilityClass.EQUIVALENCE_CLASS
    assert verdict.reason == "NO_DISTINGUISHING_EPISODE"
    assert verdict.verdict is Verdict.UNIDENTIFIABLE
    assert verdict.members == (pm["pm1"].hypothesis_id, pm["co1"].hypothesis_id)
    ledger = TheoryLedger()
    ledger.record_birth(pm["pm1"])
    ledger.record_identifiability(verdict)  # recorded, not forced into a conclusion
    recorded = ledger.record(pm["pm1"].hypothesis_id).identifiability
    assert recorded is IdentifiabilityClass.EQUIVALENCE_CLASS


def test_reorder_interventions_with_the_lab_oracle_identify_pm1(planted, pm) -> None:
    gov = governor()
    interventions = _reordered(planted, pm["pm1"], gov, labelled=True)
    assert len(interventions) >= 3 and {ep.label for ep in interventions} == {0}
    permitted = IdentifiabilityGate(interventions_permitted=True).assess(
        pm["pm1"], [pm["co1"]], observed(planted), interventions)
    assert permitted.klass is IdentifiabilityClass.IDENTIFIED and permitted.verdict is None
    assert permitted.distinguishing_episodes == len(interventions)
    forbidden = IdentifiabilityGate(interventions_permitted=False).assess(
        pm["pm1"], [pm["co1"]], observed(planted), interventions)
    assert (forbidden.klass, forbidden.reason) == (IdentifiabilityClass.UNIDENTIFIABLE,
                                                   "ONLY_UNDER_INTERVENTION")


def test_unlabelled_interventions_distinguish_nothing(planted, pm) -> None:
    interventions = _reordered(planted, pm["pm1"], governor(), labelled=False)
    verdict = IdentifiabilityGate(interventions_permitted=True).assess(
        pm["pm1"], [pm["co1"]], observed(planted), interventions)
    assert verdict.klass is IdentifiabilityClass.EQUIVALENCE_CLASS


def test_dropout_makes_pm1_unidentifiable_and_the_planted_control_does_not(dropout, pm) -> None:
    rival = genome("PRECEDES(WRITE+TEMP_LOCATION,CONNECT+EXTERNAL_ENDPOINT)")
    gate = IdentifiabilityGate(interventions_permitted=False)
    lossy = gate.assess(pm["pm1"], [rival], observed(dropout))
    assert lossy.klass is IdentifiabilityClass.UNIDENTIFIABLE
    assert lossy.reason == "ONLY_UNDER_INCOMPLETE_OBSERVATION"
    assert lossy.verdict is Verdict.UNIDENTIFIABLE
    # Isolating control: the same world without the sensor loss has no distinguishing episode.
    clean = build_discovery_corpus(arm=CorpusArm.PLANTED, seed=2, counts={
        Split.TRAIN: 120, Split.HOLDOUT: 12, Split.REPLICATION: 12,
        Split.LAB_POOL: 120, Split.INDEPENDENT: 4})
    assert gate.assess(pm["pm1"], [rival], observed(clean)).reason == "NO_DISTINGUISHING_EPISODE"


def test_five_matches_are_insufficient_evidence(planted, pm) -> None:
    hits = [ep for ep in observed(planted) if pm["pm1"].decides(ep)][:5]
    others = [ep for ep in observed(planted) if not pm["pm1"].decides(ep)]
    verdict = IdentifiabilityGate(interventions_permitted=True).assess(
        pm["pm1"], [pm["co1"]], hits + others)
    assert verdict.reason == "INSUFFICIENT_EVIDENCE"
    assert verdict.verdict is Verdict.INSUFFICIENT_EVIDENCE
    assert verdict.distinguishing_episodes == 5 < MIN_EVIDENCE_EPISODES


def test_a_rival_that_fits_the_labels_better_is_preferred(planted, pm) -> None:
    broad = genome("SINGLE(CONNECT+EXTERNAL_ENDPOINT)")
    gate = IdentifiabilityGate(interventions_permitted=False)
    verdict = gate.assess(broad, [pm["pm1"]], observed(planted))
    assert verdict.klass is IdentifiabilityClass.UNIDENTIFIABLE
    assert verdict.reason == "RIVAL_PREFERRED"
    assert verdict.members == (broad.hypothesis_id, pm["pm1"].hypothesis_id)


def test_identification_against_no_rival_is_not_identification(planted, pm) -> None:
    gate = IdentifiabilityGate(interventions_permitted=True)
    verdict = gate.assess(pm["pm1"], [], observed(planted))
    assert verdict.klass is not IdentifiabilityClass.IDENTIFIED
    assert verdict.verdict is Verdict.INSUFFICIENT_EVIDENCE


def test_identifiability_refuses_held_out_smuggled_and_unbounded_inputs(planted, pm) -> None:
    gate = IdentifiabilityGate(interventions_permitted=True)
    obs = observed(planted)
    for bad_observed in (planted.episodes(Split.HOLDOUT), planted.episodes(Split.REPLICATION),
                         tuple(ep.with_split(Split.CHALLENGE, label=ep.label) for ep in obs[:3])):
        with pytest.raises(ContractError):
            gate.assess(pm["pm1"], [pm["co1"]], obs + bad_observed)
    with pytest.raises(ContractError):  # an intervention must be a derived CHALLENGE episode
        gate.assess(pm["pm1"], [pm["co1"]], obs, obs[:2])
    rivals = [genome(f"PRECEDES(EXECUTE+TEMP_LOCATION,{r}+EXTERNAL_ENDPOINT)")
              for r in ("CONNECT", "SEND", "RECEIVE", "ACCEPT", "LISTEN", "READ", "WRITE",
                        "CREATE", "DELETE")]
    with pytest.raises(ContractError):
        gate.assess(pm["pm1"], rivals, obs)
    with pytest.raises(ContractError):
        gate.assess(pm["pm1"], [genome(CO1_DSL, Direction.BENIGN)], obs)
    with pytest.raises(ContractError):
        gate.assess(pm["pm1"], [pm["pm1"]], obs)


def test_verdicts_cannot_carry_invented_certainty(pm) -> None:
    hid = pm["pm1"].hypothesis_id
    with pytest.raises(ContractError):  # IDENTIFIED with a non-committal verdict
        IdentifiabilityVerdict(hid, IdentifiabilityClass.IDENTIFIED, (hid,), 5, "IDENTIFIED",
                               Verdict.UNIDENTIFIABLE)
    with pytest.raises(ContractError):  # a downgrade must map to a Stage 0 answer
        IdentifiabilityVerdict(hid, IdentifiabilityClass.EQUIVALENCE_CLASS, (hid,), 0,
                               "NO_DISTINGUISHING_EPISODE", None)
    with pytest.raises(ContractError):  # never MALICIOUS for an unidentified theory
        IdentifiabilityVerdict(hid, IdentifiabilityClass.UNIDENTIFIABLE, (hid,), 0,
                               "RIVAL_PREFERRED", Verdict.MALICIOUS)
    with pytest.raises(ContractError):
        IdentifiabilityVerdict(hid, IdentifiabilityClass.UNIDENTIFIABLE, (hid,), 0,
                               "PROBABLY_FINE", Verdict.UNIDENTIFIABLE)


# --- D8.12 the Reproducibility Gate --------------------------------------------------------


def _holdout(ledger: TheoryLedger, genomes: list[HypothesisGenome], episodes: tuple[Episode, ...],
             gov: ResearchGovernor) -> None:
    for g in genomes:
        ledger.record_birth(g)
    vault = HoldoutVault(episodes, split=Split.HOLDOUT, ledger=ledger, governor=gov)
    regs = [PreRegistration("", g.hypothesis_id, g.digest(), Split.HOLDOUT, vault.split_digest(),
                            len(genomes), 0.05, g.predicted_observations[0]) for g in genomes]
    for reg in regs:
        ledger.preregister(reg)
    vault.evaluate(vault.seal_batch(regs))


def _gate(
    corpus: DiscoveryCorpus, ledger: TheoryLedger, gov: ResearchGovernor
) -> ReproducibilityGate:
    vault = HoldoutVault(corpus.episodes(Split.REPLICATION), split=Split.REPLICATION,
                         ledger=ledger, governor=gov)
    return ReproducibilityGate(vault=vault, ledger=ledger,
                               independent=corpus.episodes(Split.INDEPENDENT),
                               lab_pool=corpus.episodes(Split.LAB_POOL), governor=gov,
                               rng=random.Random(0))


def test_planted_mechanisms_reproduce_and_the_trap_never_reaches_replication(planted, pm) -> None:
    gov, ledger = governor(), TheoryLedger()
    trap = genome(planted.trap_mechanism)
    _holdout(ledger, [pm["pm1"], pm["pm3"], trap], planted.episodes(Split.HOLDOUT), gov)
    assert ledger.status(trap.hypothesis_id) is TheoryStatus.FALSIFIED  # the trap dies on HOLDOUT
    survivors = [pm["pm1"], pm["pm3"]]
    context = FailureCondition("challenge:LOTL_SUBSTITUTION", 0.0,
                               "recall lost when TEMP_LOCATION is gone")
    gate = _gate(planted, ledger, gov)
    verdicts = gate.run(survivors, failing_contexts={pm["pm1"].hypothesis_id: (context,)})
    assert [v.hypothesis_id for v in verdicts] == [g.hypothesis_id for g in survivors]
    for verdict in verdicts:
        record = verdict.record
        assert record.status is ReproducibilityStatus.REPRODUCED, record.reasons
        assert record.reasons == ()
        assert record.imbalance_precision is not None and record.imbalance_precision >= 0.5
        assert record.independent_false_positive_rate == 0.0
        assert record.independent_positives_available is False  # reported, never assumed
        assert all(result.holds is True for result in verdict.invariance)
        assert ledger.status(verdict.hypothesis_id) is TheoryStatus.REPRODUCED
    # Failing contexts are documented even when the theory passes.
    assert verdicts[0].failing_contexts == (context,)
    assert verdicts[0].telemetry_requirements == (
        "relation=EXECUTE", "relation=CONNECT", "object.TEMP_LOCATION", "object.EXTERNAL_ENDPOINT")
    assert gate.stats()["batches"] == 1 and gate.stats()["registered"] == 2


def test_a_trap_that_slips_through_a_leaky_holdout_is_still_not_reproduced(planted, pm) -> None:
    gov, ledger = governor(), TheoryLedger()
    trap = genome(planted.trap_mechanism)
    # TRAIN re-labelled as HOLDOUT: the trap is true there by construction and survives.
    leaky = tuple(ep.with_split(Split.HOLDOUT, label=ep.label)
                  for ep in planted.episodes(Split.TRAIN))
    _holdout(ledger, [pm["pm1"], trap], leaky, gov)
    assert ledger.status(trap.hypothesis_id) is TheoryStatus.SURVIVED
    verdicts = {v.hypothesis_id: v for v in _gate(planted, ledger, gov).run(
        [pm["pm1"], trap], failing_contexts={})}
    record = verdicts[trap.hypothesis_id].record
    assert record.status is ReproducibilityStatus.NOT_REPRODUCED
    assert "replication:HOLDOUT_ENRICHMENT" in record.reasons
    assert "imbalance_precision" in record.reasons
    assert ledger.status(trap.hypothesis_id) is TheoryStatus.NOT_REPRODUCED
    assert verdicts[pm["pm1"].hypothesis_id].record.status is ReproducibilityStatus.REPRODUCED


def test_replication_is_sealed_and_evaluated_once(planted, pm) -> None:
    gov, ledger = governor(), TheoryLedger()
    _holdout(ledger, [pm["pm1"], pm["pm3"]], planted.episodes(Split.HOLDOUT), gov)
    gate = _gate(planted, ledger, gov)
    gate.run([pm["pm1"]], failing_contexts={})
    with pytest.raises(ContractError):  # a second look at REPLICATION is refused
        gate.run([pm["pm3"]], failing_contexts={})


def test_the_gate_refuses_non_survivors_before_writing_anything(planted, pm) -> None:
    gov, ledger = governor(), TheoryLedger()
    trap = genome(planted.trap_mechanism)
    _holdout(ledger, [pm["pm1"], trap], planted.episodes(Split.HOLDOUT), gov)
    before = len(ledger.entries())
    with pytest.raises(ContractError):
        _gate(planted, ledger, gov).run([pm["pm1"], trap], failing_contexts={})
    assert len(ledger.entries()) == before  # no half-registered batch
    assert ledger.status(pm["pm1"].hypothesis_id) is TheoryStatus.SURVIVED


def test_fewer_than_ten_replication_true_matches_is_insufficient_evidence(pm) -> None:
    small = build_discovery_corpus(arm=CorpusArm.PLANTED, seed=5, counts={
        Split.TRAIN: 12, Split.HOLDOUT: 60, Split.REPLICATION: 40,
        Split.LAB_POOL: 30, Split.INDEPENDENT: 10})
    gov, ledger = governor(), TheoryLedger()
    _holdout(ledger, [pm["pm1"]], small.episodes(Split.HOLDOUT), gov)
    (verdict,) = _gate(small, ledger, gov).run([pm["pm1"]], failing_contexts={})
    assert verdict.record.status is ReproducibilityStatus.INSUFFICIENT_EVIDENCE
    assert verdict.record.reasons[0] == "insufficient_evidence"
    assert ledger.status(pm["pm1"].hypothesis_id) is TheoryStatus.INSUFFICIENT_EVIDENCE


def test_a_benign_explanation_cannot_reproduce_on_an_all_benign_control(planted) -> None:
    benign = genome("SINGLE(EXECUTE+SYSTEM_BINARY)", Direction.BENIGN)
    gov, ledger = governor(), TheoryLedger()
    _holdout(ledger, [benign], planted.episodes(Split.HOLDOUT), gov)
    assert ledger.status(benign.hypothesis_id) is TheoryStatus.SURVIVED
    (verdict,) = _gate(planted, ledger, gov).run([benign], failing_contexts={})
    assert verdict.record.independent_false_positive_rate is None
    assert "independent_fp_unmeasured" in verdict.record.reasons  # unmeasured is not a pass
    assert verdict.record.status is not ReproducibilityStatus.REPRODUCED


def test_a_relation_that_could_not_be_measured_blocks_reproduction(planted, pm) -> None:
    gov, ledger = governor(), TheoryLedger()
    _holdout(ledger, [pm["pm1"]], planted.episodes(Split.HOLDOUT), gov)
    # A lab pool on which PM1 never fires: there is no support that could fall.
    blind_pool = tuple(ep for ep in planted.episodes(Split.LAB_POOL) if not pm["pm1"].decides(ep))
    vault = HoldoutVault(planted.episodes(Split.REPLICATION), split=Split.REPLICATION,
                         ledger=ledger, governor=gov)
    gate = ReproducibilityGate(vault=vault, ledger=ledger,
                               independent=planted.episodes(Split.INDEPENDENT),
                               lab_pool=blind_pool, governor=gov, rng=random.Random(0))
    (verdict,) = gate.run([pm["pm1"]], failing_contexts={})
    support = next(r for r in verdict.invariance if r.relation_id == "mr-necessary-step-deletion")
    assert support.holds is None
    assert "support_unmeasured:mr-necessary-step-deletion" in verdict.record.reasons
    assert verdict.record.status is ReproducibilityStatus.NOT_REPRODUCED  # None is never a pass


def test_imbalance_precision_is_the_registered_formula() -> None:
    # TPR 1, FPR' = 0.5 / 10: precision = (1/21) / (1/21 + 0.05 * 20/21) = 0.5 exactly.
    assert imbalance_precision(FitCounts(10, 10, 0, 10, 9)) == pytest.approx(0.5)
    assert imbalance_precision(FitCounts(10, 10, 0, 10, 8)) < 0.5  # a zero FPR is smoothed
    assert imbalance_precision(FitCounts(0, 0, 0, 0, 9)) is None


def test_failing_contexts_are_bounded_with_the_truncation_counted(planted, pm) -> None:
    gov, ledger = governor(), TheoryLedger()
    _holdout(ledger, [pm["pm1"]], planted.episodes(Split.HOLDOUT), gov)
    many = tuple(FailureCondition(f"challenge:KIND_{i}", 0.5, "d") for i in range(20))
    gate = _gate(planted, ledger, gov)
    (verdict,) = gate.run([pm["pm1"]], failing_contexts={pm["pm1"].hypothesis_id: many})
    assert verdict.failing_contexts == many[:MAX_FAILURE_CONDITIONS]
    assert gate.stats()["failing_contexts_truncated"] == 20 - MAX_FAILURE_CONDITIONS


def test_the_gate_needs_the_right_splits(planted) -> None:
    gov, ledger = governor(), TheoryLedger()
    replication = HoldoutVault(planted.episodes(Split.REPLICATION), split=Split.REPLICATION,
                               ledger=ledger, governor=gov)
    holdout = HoldoutVault(planted.episodes(Split.HOLDOUT), split=Split.HOLDOUT,
                           ledger=ledger, governor=gov)
    good = dict(ledger=ledger, independent=planted.episodes(Split.INDEPENDENT),
                lab_pool=planted.episodes(Split.LAB_POOL), governor=gov, rng=random.Random(0))
    for bad in (dict(vault=holdout), dict(vault=replication, independent=()),
                dict(vault=replication, lab_pool=planted.episodes(Split.TRAIN))):
        with pytest.raises(ContractError):
            ReproducibilityGate(**{**good, **bad})
    assert telemetry_requirements(genome("SINGLE(IMPERSONATE^privilege)")) == (
        "relation=IMPERSONATE", "raised.privilege")


# --- D8.13 the Novelty / Prior-Art Audit ----------------------------------------------------


def _ledger(status: ReviewStatus, *, cites: bool) -> PriorArtLedger:
    base = PriorArtLedger.load()
    entry = replace(base.entries["H8"], literature_status=status, patent_status=status,
                    related_work=("ref-1",) if cites else ())
    return PriorArtLedger(entries={**base.entries, "H8": entry})


def test_pm3_is_classified_as_a_rediscovery_of_attack_exfil(pm) -> None:
    result = audit(pm["pm3"], known_library(), prior_art=PriorArtLedger.load())
    assert result.classification is NoveltyClass.KNOWN
    assert "stage1:ATTACK_EXFIL" in result.matched_known
    assert result.novelty_claim_permitted is False
    assert result.external_review is ReviewStatus.NOT_REVIEWED


def test_classification_ladder_is_computed_from_coverage(pm) -> None:
    library = known_library()
    prior = PriorArtLedger.load()
    pm1 = audit(pm["pm1"], library, prior_art=prior).classification
    assert pm1 is NoveltyClass.CONTEXT_EXTENSION
    pm2 = audit(pm["pm2"], library, prior_art=prior).classification
    assert pm2 is NoveltyClass.KNOWN_COMBINATION
    novel = audit(genome("SINGLE(DELETE)"), library, prior_art=prior)
    assert (novel.classification, novel.matched_known) == (NoveltyClass.POTENTIALLY_NOVEL, ())
    # Coverage runs both ways: a more general or a more specific credential read is KNOWN.
    for dsl in ("SINGLE(READ+CREDENTIAL)", "SINGLE(READ+CREDENTIAL+ROOT_OWNED^credential)"):
        assert audit(genome(dsl), library, prior_art=prior).classification is NoveltyClass.KNOWN


def test_co_occurs_coverage_is_order_free() -> None:
    a = StepPredicate(int(parse_mechanism("SINGLE(READ)").steps[0].relation), 0, 0, 0)
    b = parse_mechanism("SINGLE(CONNECT+EXTERNAL_ENDPOINT)").steps[0]
    known = known_library(stage7_seeds=[Mechanism(MechanismRelation.CO_OCCURS, (a, b))])
    theory = genome(Mechanism(MechanismRelation.CO_OCCURS, (b, a)))
    result = audit(theory, known, prior_art=PriorArtLedger.load())
    assert result.classification is NoveltyClass.KNOWN


def test_novelty_claims_need_potentially_novel_and_a_reviewed_entry(pm) -> None:
    library = known_library()
    novel_theory = genome("SINGLE(DELETE)")
    today = PriorArtLedger.load()
    assert all(not e.novelty_claim_permitted for e in today.entries.values())
    assert audit(novel_theory, library, prior_art=today).novelty_claim_permitted is False
    reviewed = _ledger(ReviewStatus.REVIEWED, cites=True)
    assert audit(novel_theory, library, prior_art=reviewed).novelty_claim_permitted is True
    assert audit(pm["pm3"], library, prior_art=reviewed).novelty_claim_permitted is False
    uncited = _ledger(ReviewStatus.REVIEWED, cites=False)
    assert audit(novel_theory, library, prior_art=uncited).novelty_claim_permitted is False
    with pytest.raises(ContractError):
        audit(novel_theory, library, prior_art=today, bound_hypothesis="H99")


def test_audit_output_never_uses_the_word_except_the_enum_value(pm) -> None:
    library = known_library(validated=[pm["pm1"]])
    for theory in (pm["pm1"], pm["pm2"], pm["pm3"], genome("SINGLE(DELETE)")):
        result = audit(theory, library, prior_art=PriorArtLedger.load())
        text = repr((result.hypothesis_id, result.matched_known, result.external_review.value,
                     result.novelty_claim_permitted))
        assert "novel" not in text.lower()
        assert "novel" not in result.classification.value.lower() or (
            result.classification is NoveltyClass.POTENTIALLY_NOVEL)


def test_the_stage1_library_is_computed_by_replay_not_hand_written() -> None:
    library = stage1_known_mechanisms()
    assert {k.known_id for k in library} == {f"stage1:{name}" for name in STAGE1_KNOWN_CHAINS}
    dsl = {k.mechanism.to_dsl() for k in library if k.known_id == "stage1:ATTACK_EXFIL"}
    assert "PRECEDES(READ+CREDENTIAL^credential,CONNECT+EXTERNAL_ENDPOINT^reachability)" in dsl
    # ATTACK_PERSISTENCE's final execve raises nothing, so it is not an escalating step.
    persistence = [k for k in library if k.known_id == "stage1:ATTACK_PERSISTENCE"]
    assert all("EXECUTE" not in k.mechanism.to_dsl() for k in persistence)


def test_the_known_library_extends_and_is_bounded(pm) -> None:
    motif = (MotifStep(1, 0, 0, 0),)
    library = known_library(stage6_motifs=[motif], stage7_seeds=[parse_mechanism("SINGLE(DELETE)")],
                            validated=[pm["pm1"]])
    ids = [k.known_id for k in library]
    assert ids[-3].startswith("stage6:motif:") and ids[-2].startswith("stage7:mech-")
    assert ids[-1] == "validated:" + pm["pm1"].hypothesis_id
    seeds = [Mechanism(MechanismRelation.SINGLE, (StepPredicate(r, p, 0, 0),))
             for r in range(24) for p in range(64)][: MAX_KNOWN_LIBRARY]
    with pytest.raises(ContractError):
        known_library(stage7_seeds=seeds)
    with pytest.raises(ContractError):
        known_library(stage6_motifs=[("not a motif step",)])  # type: ignore[list-item]
