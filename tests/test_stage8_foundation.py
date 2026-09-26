"""Package ``foundation`` of Stage 8: episode, grammar, genome, discovery package, core ids.

These tests pin behaviour and refusals, not construction: the episode must equal Stage 6's
capsule steps, the grammar must equal Stage 6's matcher where they overlap and a brute
force reference everywhere else, the DSL must refuse everything it does not contain, a
genome must refuse to exist without a way to be wrong, and a discovery package must be
reported — every problem named — when anything in it does not recompute.

Package boundary: ``PENDING_MODULES`` names the Stage 8 modules OTHER packages own that the
core-id table points at. A symbol may be unresolved only if its module is listed; the
integrator empties the set. Nothing this package owns may ever be pending.
"""

from __future__ import annotations

import ast
import dataclasses
import json
import random
from pathlib import Path
from typing import Any

import pytest

from pocketsec.stage0.contracts.common import SCHEMA_REGISTRY, ContractError
from pocketsec.stage0.contracts.threat_prediction_v1 import FORBIDDEN_AUTHORITY_FIELDS
from pocketsec.stage0.gate import REPO_ROOT
from pocketsec.stage1.epoch.model import EpochModel, SystemIdentity
from pocketsec.stage1.labs.ambiguous_corpus import build_ambiguous_corpus
from pocketsec.stage1.labs.corpus import build_corpus
from pocketsec.stage1.pipeline import ScenarioResult, Stage1Pipeline
from pocketsec.stage1.ssir.relations import Relation
from pocketsec.stage6.capsule.experience_capsule import (
    EncodedStep,
    LabelOrigin,
    SourceClass,
    SourceProvenance,
    capsule_from_scenario,
)
from pocketsec.stage6.memory.semantic import MAX_MOTIF_LENGTH, match_motif
from pocketsec.stage6.resources import WorkBudgetExceeded, WorkMeter
from pocketsec.stage8 import core_ids
from pocketsec.stage8.episode import (
    MAX_EPISODE_EVIDENCE,
    MAX_EPISODE_STEPS,
    Episode,
    EpisodeContext,
    FitCounts,
    Split,
    episode_from_result,
    episode_id_for,
    fit_counts,
)
from pocketsec.stage8.forge import package as pkg
from pocketsec.stage8.forge.package import (
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
from pocketsec.stage8.genome import grammar, hypothesis
from pocketsec.stage8.genome.grammar import (
    MAX_DSL_BYTES,
    MAX_REPEAT,
    PROPERTY_BITS,
    RAISED_BITS,
    GrammarError,
    Mechanism,
    MechanismRelation,
    Modifier,
    StepPredicate,
    TriggerClass,
    mechanism_from_canonical,
    parse_mechanism,
)
from pocketsec.stage8.genome.hypothesis import (
    DEFAULT_FALSIFIERS,
    DEFAULT_PREDICTIONS,
    MANDATORY_FALSIFIERS,
    MAX_FORBIDDEN,
    CausalAssumption,
    Direction,
    ExperimentClass,
    Falsifier,
    FalsifierKind,
    GeneratorKind,
    GenomeProvenance,
    HypothesisGenome,
    ObservationScope,
    Prediction,
    VisibilityAssumption,
    genome_for,
)

STAGE8 = REPO_ROOT / "pocketsec" / "stage8"
OWN_FILES = (
    STAGE8 / "core_ids.py", STAGE8 / "episode.py", STAGE8 / "genome" / "grammar.py",
    STAGE8 / "genome" / "hypothesis.py", STAGE8 / "forge" / "package.py",
)
_S8 = "pocketsec.stage8."
#: Stage 8 modules owned by OTHER packages that the core-id table names. The integrator
#: empties this set once every package has landed.
# Emptied by the integrator once every package landed: every core-id symbol must resolve.
PENDING_MODULES: frozenset[str] = frozenset()
OWN_MODULES = frozenset({_S8 + "genome.hypothesis", _S8 + "genome.grammar"})
CTX = EpisodeContext("lab-host-01", 0, "", "test-corpus", True)
EXEC_TMP = parse_mechanism("SINGLE(EXECUTE+TEMP_LOCATION)").steps[0]
CONNECT_EXT = parse_mechanism("SINGLE(CONNECT+EXTERNAL_ENDPOINT)").steps[0]
PM1 = Mechanism(MechanismRelation.PRECEDES, (EXEC_TMP, CONNECT_EXT))


# --- fixtures -------------------------------------------------------------------------


@pytest.fixture(scope="module")
def results() -> tuple[ScenarioResult, ...]:
    """10 Stage 1 eval sessions (one actor) and 10 ambiguous ones (7-8 actors, some > 64)."""
    plain = build_corpus(count=10, seed=7, split="eval")
    mixed = build_ambiguous_corpus(count=10, seed=3)
    return tuple(Stage1Pipeline().run_scenario(s, offset=i) for i, s in enumerate(plain + mixed))


@pytest.fixture(scope="module")
def pool(results: tuple[ScenarioResult, ...]) -> tuple[EncodedStep, ...]:
    return tuple(step for r in results
                 for step in episode_from_result(r, split=Split.TRAIN, context=CTX, label=0).steps)


def _epoch() -> Any:
    identity = SystemIdentity(kernel_id="6.1.0", package_digest="pkg-a", service_digest="svc-a")
    return EpochModel(identity=identity).current


def _capsule_steps(result: ScenarioResult) -> tuple[EncodedStep, ...]:
    provenance = SourceProvenance(
        source_class=SourceClass.KERNEL_SENSOR, source_id="sensor.ebpf",
        independence_group="host.lab-01", label_origin=LabelOrigin.NONE,
        transformation_lineage=("stage1.pipeline",), host_id="lab-host-01")
    return capsule_from_scenario(result, epoch=_epoch(), provenance=provenance, sequence=1).steps


def _step(base: EncodedStep, relation: int, props: int, raised: int, slot: int) -> EncodedStep:
    return dataclasses.replace(base, relation=relation, object_property_mask=props,
                               state_delta_mask=raised, actor_slot=slot)


def _random_predicate(rng: random.Random, *, relations: int = len(Relation)) -> StepPredicate:
    req = rng.getrandbits(PROPERTY_BITS) & rng.getrandbits(PROPERTY_BITS)
    forbid = rng.getrandbits(PROPERTY_BITS) & rng.getrandbits(PROPERTY_BITS) & ~req
    raised = rng.getrandbits(RAISED_BITS) & rng.getrandbits(RAISED_BITS) & rng.getrandbits(9)
    return StepPredicate(rng.randrange(relations), req, forbid, raised)


def _small_predicate(rng: random.Random) -> StepPredicate:
    """A predicate over the alphabet of :func:`_random_steps`, so it can match."""
    req = rng.getrandbits(3) & rng.getrandbits(3)
    return StepPredicate(rng.randrange(3), req, rng.getrandbits(3) & ~req & rng.getrandbits(3),
                         rng.getrandbits(2) & rng.getrandbits(2))


def _random_steps(rng: random.Random, base: EncodedStep, n: int) -> list[EncodedStep]:
    # Small alphabets so predicates actually match: a test that never fires tests nothing.
    return [_step(base, rng.randrange(3), rng.getrandbits(3), rng.getrandbits(2), rng.randrange(3))
            for _ in range(n)]


def _scope() -> ObservationScope:
    return ObservationScope(("rc-0001",), frozenset({hypothesis.ResidualType.OBSERVATION}), ())


def _provenance(generator: GeneratorKind = GeneratorKind.SYMBOLIC_ENUMERATOR,
                foreign: bool = False) -> GenomeProvenance:
    return GenomeProvenance(generator, "sha256:" + "a" * 64, foreign, 7)


def _genome(mechanism: Mechanism = PM1, **overrides: Any) -> HypothesisGenome:
    values: dict[str, Any] = {"direction": Direction.MALICIOUS, "scope": _scope(),
                              "provenance": _provenance()}
    values.update(overrides)
    return genome_for(mechanism, **values)


# --- episode ------------------------------------------------------------------------------


def test_episode_steps_equal_stage6_capsule_steps_for_20_sessions(results) -> None:
    episodes = [episode_from_result(r, split=Split.TRAIN, context=CTX, label=None) for r in results]
    assert len(episodes) == 20
    for result, episode in zip(results, episodes, strict=True):
        assert episode.steps == _capsule_steps(result)
    assert len({e.episode_id for e in episodes}) == 20  # distinct sessions never collide
    assert max(len(e.actors()) for e in episodes) >= 7  # the slot rule was exercised
    assert any(e.truncated for e in episodes) and not all(e.truncated for e in episodes)


def test_episode_never_reads_the_scenario(results) -> None:
    class Untouchable:
        def __getattr__(self, name: str) -> Any:
            raise AssertionError(f"episode_from_result read scenario.{name}")

    blind = dataclasses.replace(results[0], scenario=Untouchable())  # type: ignore[arg-type]
    a = episode_from_result(results[0], split=Split.TRAIN, context=CTX, label=1)
    b = episode_from_result(blind, split=Split.TRAIN, context=CTX, label=1)
    assert a == b


def test_episode_truncates_at_stage6_cap_and_says_so(results) -> None:
    long = dataclasses.replace(results[0], transitions=results[0].transitions * 40)
    episode = episode_from_result(long, split=Split.TRAIN, context=CTX, label=None)
    assert len(long.transitions) > MAX_EPISODE_STEPS == 64
    assert len(episode.steps) == MAX_EPISODE_STEPS and episode.truncated
    assert episode.steps == _capsule_steps(long)
    with pytest.raises(ContractError):
        episode_from_result(dataclasses.replace(long, transitions=()), split=Split.TRAIN,
                            context=CTX, label=None)
    with pytest.raises(ContractError):
        episode_from_result(object(), split=Split.TRAIN, context=CTX, label=None)  # type: ignore[arg-type]


def test_episode_id_is_content_of_steps_only_and_tamper_is_refused(results) -> None:
    episode = episode_from_result(results[3], split=Split.TRAIN, context=CTX, label=1)
    moved = episode.with_split(Split.HOLDOUT, label=None)
    other = dataclasses.replace(episode, context=dataclasses.replace(CTX, host_id="lab-host-02"))
    assert moved.episode_id == other.episode_id == episode.episode_id
    assert episode.episode_id == episode_id_for(episode.steps)
    with pytest.raises(ContractError, match="does not match"):
        Episode("ep-" + "0" * 24, episode.steps, 1, Split.TRAIN, CTX, False)
    changed = (dataclasses.replace(episode.steps[0], time_bucket=episode.steps[0].time_bucket + 1),)
    assert Episode("", changed + episode.steps[1:], 1, Split.TRAIN, CTX, False).episode_id != \
        episode.episode_id
    with pytest.raises(dataclasses.FrozenInstanceError):
        episode.label = 0  # type: ignore[misc]


@pytest.mark.parametrize("label", [True, 2, -1, 0.5, 1.0, "1"])
def test_episode_refuses_a_label_that_is_not_0_1_or_none(results, label: Any) -> None:
    steps = episode_from_result(results[0], split=Split.TRAIN, context=CTX, label=None).steps
    with pytest.raises(ContractError):
        Episode("", steps, label, Split.TRAIN, CTX, False)


def test_episode_bounds_and_context_refusals(results) -> None:
    steps = episode_from_result(results[0], split=Split.TRAIN, context=CTX, label=None).steps
    with pytest.raises(ContractError):
        Episode("", (), None, Split.TRAIN, CTX, False)
    with pytest.raises(ContractError):
        Episode("", steps * 30, None, Split.TRAIN, CTX, False)  # > 64 steps
    with pytest.raises(ContractError):
        Episode("", steps, None, "TRAIN", CTX, False)  # type: ignore[arg-type]
    for bad in ({"epoch_id": -1}, {"epoch_id": True}, {"corpus": ""}, {"family": "a b"},
                {"host_id": ""}, {"synthetic": 1}):
        with pytest.raises(ContractError):
            dataclasses.replace(CTX, **bad)


def test_phi_oracle_score_and_evidence_summary(results) -> None:
    episode = episode_from_result(results[10], split=Split.TRAIN, context=CTX, label=None)
    assert episode.phi_oracle_score() == max(s.features[73] for s in episode.steps)
    digests = episode.evidence_digests()
    every = [d for s in episode.steps for d in s.evidence]
    assert len(set(every)) > MAX_EPISODE_EVIDENCE == len(digests)  # the cap was reached
    assert list(digests) == list(dict.fromkeys(every))[:MAX_EPISODE_EVIDENCE]


def test_fit_counts_rates_none_when_undefined_and_unlabelled_counted_nowhere(results) -> None:
    empty = FitCounts(0, 0, 0, 0, 0)
    assert (empty.precision, empty.recall, empty.f1, empty.false_positive_rate) == (None,) * 4
    counts = FitCounts(matched=4, true_matches=3, false_matches=1, positives=6, negatives=10)
    assert counts.precision == 0.75 and counts.recall == 0.5 and counts.false_positive_rate == 0.1
    assert counts.f1 == pytest.approx(0.6)
    assert FitCounts(1, 0, 1, 2, 3).f1 == 0.0
    for bad in ((2, 1, 0, 3, 3), (1, 2, -1, 3, 3), (3, 3, 0, 2, 5), (1, 0, 1, 1, 0),
                (True, 1, 0, 1, 1)):
        with pytest.raises(ContractError):
            FitCounts(*bad)
    base = episode_from_result(results[0], split=Split.TRAIN, context=CTX, label=None)
    episodes = [base.with_split(Split.TRAIN, label=lab) for lab in (1, 1, 0, 0, 0, None, None)]
    meter = WorkMeter()
    counts = fit_counts(lambda e: True, episodes, meter=meter)
    assert counts == FitCounts(5, 2, 3, 2, 3) and meter.spent == 5


# --- grammar: equivalence with Stage 6, and brute-force references ----------------------------


def test_grammar_widths_are_derived_from_the_encoder_and_stage6() -> None:
    assert (PROPERTY_BITS, RAISED_BITS) == (15, 9)
    assert grammar.MAX_MECHANISM_STEPS == MAX_MOTIF_LENGTH == 2
    assert grammar.PROPERTY_NAMES[6] == "TEMP_LOCATION"
    assert grammar.DIMENSION_NAMES[0] == "privilege"


def test_step_predicate_matches_bit_identically_to_motif_step(pool) -> None:
    rng = random.Random(8)
    fired = 0
    for _ in range(500):
        step = _step(pool[rng.randrange(len(pool))], rng.randrange(24),
                     rng.getrandbits(PROPERTY_BITS), rng.getrandbits(RAISED_BITS), 0)
        props, raised = step.object_property_mask, step.state_delta_mask
        full = (1 << PROPERTY_BITS) - 1
        # Half the predicates are drawn to fit the step, half at random: both outcomes occur.
        predicate = StepPredicate(step.relation, props & rng.getrandbits(PROPERTY_BITS),
                                  ~props & full & rng.getrandbits(PROPERTY_BITS),
                                  raised & rng.getrandbits(RAISED_BITS)) \
            if rng.random() < 0.5 else _random_predicate(rng, relations=24)
        ours, theirs = predicate.matches(step), predicate.to_motif_step().matches(step)
        assert ours == theirs
        fired += ours
    assert 20 < fired < 480  # both outcomes were exercised


def _pairs(steps: list[EncodedStep]) -> list[tuple[int, int]]:
    return [(i, j) for i in range(len(steps)) for j in range(len(steps))
            if i != j and steps[i].actor_slot == steps[j].actor_slot]


def _reference(mechanism: Mechanism, steps: list[EncodedStep]) -> bool:
    """The grammar table, written as directly as possible over index pairs."""
    a = mechanism.steps[0]
    if mechanism.relation is MechanismRelation.SINGLE:
        per_actor: dict[int, int] = {}
        for s in steps:
            per_actor[s.actor_slot] = per_actor.get(s.actor_slot, 0) + a.matches(s)
        return any(n >= mechanism.repeat_min for n in per_actor.values())
    b = mechanism.steps[1]
    if mechanism.relation is MechanismRelation.PRECEDES:
        return any(i < j and a.matches(steps[i]) and b.matches(steps[j]) for i, j in _pairs(steps))
    if mechanism.relation is MechanismRelation.CO_OCCURS:
        return any(a.matches(steps[i]) and b.matches(steps[j]) for i, j in _pairs(steps))
    actors = {s.actor_slot for s in steps}
    return any(any(a.matches(s) for s in steps if s.actor_slot == x)
               and not any(b.matches(s) for s in steps if s.actor_slot == x) for x in actors)


def _random_mechanism(rng: random.Random, *, small: bool = True) -> Mechanism:
    def draw() -> StepPredicate:
        return _small_predicate(rng) if small else _random_predicate(rng)

    while True:
        kind = rng.choice(list(MechanismRelation))
        try:
            if kind is MechanismRelation.SINGLE:
                if rng.random() < 0.5:
                    return Mechanism(kind, (draw(),), Modifier.REPEATED,
                                     rng.randrange(2, (4 if small else MAX_REPEAT) + 1))
                return Mechanism(kind, (draw(),))
            return Mechanism(kind, (draw(), draw()))
        except GrammarError:
            continue  # an identical, unsatisfiable or unspellable draw: draw again


def test_precedes_equals_stage6_match_motif_including_the_same_step_case(pool) -> None:
    rng = random.Random(9)
    fired = 0
    for _ in range(400):
        steps = _random_steps(rng, pool[0], rng.randrange(1, 12))
        a, b = _small_predicate(rng), _small_predicate(rng)
        if a == b:
            continue
        mech = Mechanism(MechanismRelation.PRECEDES, (a, b))
        expected = match_motif((a.to_motif_step(), b.to_motif_step()), steps)
        assert mech.matches(steps) == expected == _reference(mech, steps)
        assert Mechanism(MechanismRelation.SINGLE, (a,)).matches(steps) == \
            match_motif((a.to_motif_step(),), steps)
        fired += expected
    assert fired > 20
    # One step satisfying both halves is not i < j (Stage 6 checks b before arming).
    both = StepPredicate(Relation.EXECUTE, 0, 0, 0)
    tmp = StepPredicate(Relation.EXECUTE, 1 << 6, 0, 0)
    one = [_step(pool[0], Relation.EXECUTE, 1 << 6, 0, 0)]
    assert not Mechanism(MechanismRelation.PRECEDES, (both, tmp)).matches(one)
    assert not match_motif((both.to_motif_step(), tmp.to_motif_step()), one)


def test_every_relation_matches_its_brute_force_reference_and_each_fires(pool) -> None:
    rng = random.Random(10)
    outcomes: dict[tuple[MechanismRelation, Modifier], set[bool]] = {}
    for _ in range(1500):
        mech = _random_mechanism(rng)
        steps = _random_steps(rng, pool[0], rng.randrange(1, 14))
        got = mech.matches(steps)
        assert got == _reference(mech, steps), mech.to_dsl()
        assert (len(mech.firing_actors(steps)) > 0) == got
        outcomes.setdefault((mech.relation, mech.modifier), set()).add(got)
    assert len(outcomes) == 5 and all(seen == {True, False} for seen in outcomes.values())


def test_same_actor_is_required_for_two_step_relations(pool) -> None:
    split = [_step(pool[0], Relation.EXECUTE, 1 << 6, 0, 0),
             _step(pool[0], Relation.CONNECT, 1 << 7, 0, 1)]
    joint = [dataclasses.replace(s, actor_slot=0) for s in split]
    assert not PM1.matches(split) and PM1.matches(joint)
    assert PM1.firing_actors(joint) == frozenset({0})


def test_matches_charges_one_unit_per_predicate_test_and_stops_at_budget(pool) -> None:
    steps = [_step(pool[0], Relation.READ, 0, 0, 0)] * 10
    meter = WorkMeter()
    assert not Mechanism(MechanismRelation.SINGLE, (EXEC_TMP,)).matches(steps, meter=meter)
    assert meter.spent == 10
    meter = WorkMeter()
    Mechanism(MechanismRelation.WITHOUT, (EXEC_TMP, CONNECT_EXT)).matches(steps, meter=meter)
    assert meter.spent == 20
    tight = WorkMeter(budget=5)
    with pytest.raises(WorkBudgetExceeded):
        PM1.matches(steps, meter=tight)
    assert tight.spent == 5  # never past the budget


def test_description_length_formula_and_trigger_classes() -> None:
    assert PM1.description_length_bits() == 2 + (5 + 4) + (5 + 4)
    repeated = parse_mechanism("REPEATED(CONNECT+EXTERNAL_ENDPOINT,5)")
    assert repeated.description_length_bits() == 2 + 9 + 3 and repeated.repeat_min == 5
    rich = parse_mechanism("WITHOUT(READ+CREDENTIAL-TEMP_LOCATION^credential,SEND)")
    assert rich.description_length_bits() == 2 + (5 + 12) + 5
    cases = {"GRANT": TriggerClass.PRIVILEGE, "READ^privilege": TriggerClass.PRIVILEGE,
             "AUTHENTICATE": TriggerClass.AUTH, "IMPERSONATE": TriggerClass.IDENTITY,
             "WRITE+PERSISTENCE": TriggerClass.PERSISTENCE, "LOAD": TriggerClass.EXECUTION,
             "READ": TriggerClass.FILE, "SEND": TriggerClass.NETWORK,
             "INSTALL": TriggerClass.CONFIGURATION, "SIGNAL": TriggerClass.CONFIGURATION}
    for text, klass in cases.items():
        assert parse_mechanism(f"SINGLE({text})").steps[0].trigger_class() is klass


def test_grammar_refuses_what_it_does_not_contain() -> None:
    p = EXEC_TMP
    general = StepPredicate(Relation.EXECUTE, 0, 0, 0)
    refusals = [
        lambda: Mechanism(MechanismRelation.PRECEDES, (p, p)),
        lambda: Mechanism(MechanismRelation.CO_OCCURS, (p, p)),
        lambda: Mechanism(MechanismRelation.WITHOUT, (p, general)),  # can never fire
        lambda: Mechanism(MechanismRelation.PRECEDES, (p, CONNECT_EXT), Modifier.REPEATED, 2),
        lambda: Mechanism(MechanismRelation.SINGLE, (p,), Modifier.REPEATED, 1),
        lambda: Mechanism(MechanismRelation.SINGLE, (p,), Modifier.REPEATED, MAX_REPEAT + 1),
        lambda: Mechanism(MechanismRelation.SINGLE, (p,), Modifier.NONE, 2),
        lambda: Mechanism(MechanismRelation.SINGLE, (p, CONNECT_EXT)),
        lambda: Mechanism(MechanismRelation.PRECEDES, (p,)),
        lambda: Mechanism("SINGLE", (p,)),  # type: ignore[arg-type]
        lambda: StepPredicate(24, 0, 0, 0), lambda: StepPredicate(True, 0, 0, 0),
        lambda: StepPredicate(1, 1 << PROPERTY_BITS, 0, 0),
        lambda: StepPredicate(1, 0, 0, 1 << RAISED_BITS), lambda: StepPredicate(1, 3, 1, 0),
        lambda: StepPredicate(1, -1, 0, 0),
    ]
    for make in refusals:
        with pytest.raises(GrammarError):
            make()
    assert issubclass(GrammarError, ContractError)
    assert Mechanism(MechanismRelation.WITHOUT, (general, p)).relation is MechanismRelation.WITHOUT


def test_co_occurs_is_stored_in_one_canonical_order() -> None:
    ab = Mechanism(MechanismRelation.CO_OCCURS, (CONNECT_EXT, EXEC_TMP))
    ba = Mechanism(MechanismRelation.CO_OCCURS, (EXEC_TMP, CONNECT_EXT))
    assert ab == ba and ab.digest() == ba.digest() and ab.to_dsl() == ba.to_dsl()


def test_dsl_and_canonical_round_trip_for_random_mechanisms() -> None:
    rng = random.Random(11)
    digests = set()
    for _ in range(500):
        mech = _random_mechanism(rng, small=False)
        text = mech.to_dsl()
        assert text.isascii() and len(text) <= MAX_DSL_BYTES and " " not in text
        assert parse_mechanism(text) == mech
        assert mechanism_from_canonical(json.loads(json.dumps(mech.canonical()))) == mech
        assert mech.digest().startswith("mech-") and len(mech.digest()) == 21
        digests.add(mech.digest())
    assert len(digests) > 450
    with pytest.raises(GrammarError):  # English is a rendering, never an input
        parse_mechanism(PM1.render())
    swapped = {**Mechanism(MechanismRelation.CO_OCCURS, (EXEC_TMP, CONNECT_EXT)).canonical()}
    swapped["steps"] = swapped["steps"][::-1]
    with pytest.raises(GrammarError, match="canonical"):
        mechanism_from_canonical(swapped)


HOSTILE_DSL = (
    "", " ", "SINGLE()", "SINGLE(EXECUTE", "single(EXECUTE)", "SINGLE(EXECUTE) ",
    "SINGLE( EXECUTE)", "SINGLE(EXECUTE+TEMP_LOCATION+TEMP_LOCATION)",
    "SINGLE(EXECUTE+NOT_A_PROPERTY)", "SINGLE(EXPLODE)", "SINGLE(EXECUTE^root)",
    "SINGLE(EXECUTE^privilege^privilege)", "SINGLE(EXECUTE-CREDENTIAL+CREDENTIAL)",
    "SINGLE(EXECUTE+CREDENTIAL-CREDENTIAL)", "SINGLE(EXECUTE,CONNECT)", "PRECEDES(EXECUTE)",
    "PRECEDES(EXECUTE,EXECUTE)", "REPEATED(EXECUTE,1)", "REPEATED(EXECUTE,09)",
    "REPEATED(EXECUTE,9)", "REPEATED(EXECUTE,-2)", "CAUSES(EXECUTE,CONNECT)",
    "SINGLE(" + chr(0x415) + "XECUTE)", "SINGLE(EXECUTE)\x00", "SINGLE(SINGLE(EXECUTE))",
    "WITHOUT(EXECUTE+TEMP_LOCATION,EXECUTE)", "SINGLE(EXECUTE+TEMP_LOCATION" + "+X" * 200 + ")",
    "SINGLE(EXECUTE);import os", "SINGLE(__import__)",
)


def test_a_mechanism_the_dsl_cannot_spell_is_not_in_the_grammar() -> None:
    every = (1 << PROPERTY_BITS) - 1
    heavy = StepPredicate(Relation.CONTROL, every & 0x7F, every & ~0x7F, (1 << RAISED_BITS) - 1)
    with pytest.raises(GrammarError, match="exceeds"):
        Mechanism(MechanismRelation.PRECEDES, (heavy, EXEC_TMP))
    assert len(Mechanism(MechanismRelation.SINGLE, (EXEC_TMP,)).to_dsl()) < MAX_DSL_BYTES


@pytest.mark.parametrize("text", HOSTILE_DSL)
def test_dsl_refuses_hostile_text(text: str) -> None:
    with pytest.raises(GrammarError):
        parse_mechanism(text)


def test_dsl_mutation_fuzz_never_raises_anything_but_grammar_error() -> None:
    rng = random.Random(12)
    seeds = [_random_mechanism(rng, small=False).to_dsl() for _ in range(40)]
    alphabet = "(),+-^_ AZaz09EXCUTEPRSdgilnpvé\n"
    parsed = refused = 0
    for _ in range(3000):
        text = list(rng.choice(seeds))
        for _ in range(rng.randrange(1, 4)):
            at = rng.randrange(len(text) + 1)
            op = rng.randrange(3)
            if op == 0:
                text.insert(at, rng.choice(alphabet))
            elif text:
                if op == 1:
                    del text[min(at, len(text) - 1)]
                else:
                    text[min(at, len(text) - 1)] = rng.choice(alphabet)
        try:
            mech = parse_mechanism("".join(text))
        except GrammarError:
            refused += 1
            continue
        assert parse_mechanism(mech.to_dsl()) == mech
        parsed += 1
    assert refused > 1000 and parsed > 0
    for bad in (None, b"SINGLE(EXECUTE)", 7):
        with pytest.raises(GrammarError):
            parse_mechanism(bad)  # type: ignore[arg-type]


# --- genome -----------------------------------------------------------------------------------


def test_default_refutation_rules_are_the_spec_table() -> None:
    table = {f.kind: (f.split, f.threshold, f.alpha) for f in DEFAULT_FALSIFIERS}
    assert table == {
        FalsifierKind.HOLDOUT_ENRICHMENT: (Split.HOLDOUT, 0.05, 0.05),
        FalsifierKind.HOLDOUT_FALSE_POSITIVES: (Split.HOLDOUT, 0.01, None),
        FalsifierKind.HOLDOUT_RECALL: (Split.HOLDOUT, 0.10, None),
        FalsifierKind.COUNTERFACTUAL_INVARIANCE: (Split.LAB_POOL, 0.98, None),
        FalsifierKind.NECESSARY_STEP_ABLATION: (Split.LAB_POOL, 0.50, None),
        FalsifierKind.DOPPELGANGER_SEPARATION: (Split.CHALLENGE, 0.05, None),
        FalsifierKind.REPLICATION: (Split.REPLICATION, 0.05, 0.05),
    }
    assert {FalsifierKind.HOLDOUT_ENRICHMENT, FalsifierKind.HOLDOUT_FALSE_POSITIVES,
            FalsifierKind.REPLICATION} == MANDATORY_FALSIFIERS
    assert {p.split for p in DEFAULT_PREDICTIONS} == {Split.HOLDOUT, Split.REPLICATION}
    assert all((p.min_recall, p.max_false_positive_rate) == (0.10, 0.01)
               for p in DEFAULT_PREDICTIONS)


def test_closed_vocabularies_have_no_production_intervention_member() -> None:
    assert {m.value for m in ExperimentClass} == {
        "HISTORICAL_REPLAY", "COUNTERFACTUAL_MUTATION", "TELEMETRY_DROPOUT",
        "METAMORPHIC_TRANSFORM", "BENIGN_ALTERNATIVE", "SYNTHETIC_EVENT_WORLD",
        "ISOLATED_EMULATION"}
    assert len(FalsifierKind) == 7 and len(GeneratorKind) == 11 and len(RepresentationKind) == 7


def _without(kind: FalsifierKind) -> tuple[Falsifier, ...]:
    return tuple(f for f in DEFAULT_FALSIFIERS if f.kind is not kind)


def test_genome_refuses_to_exist_without_a_way_to_be_wrong() -> None:
    with pytest.raises(ContractError, match="cannot be wrong"):
        _genome(falsifiers=())
    for kind in MANDATORY_FALSIFIERS:
        with pytest.raises(ContractError, match="mandatory"):
            _genome(falsifiers=_without(kind))
    extra = (*DEFAULT_FALSIFIERS, Falsifier(FalsifierKind.HOLDOUT_RECALL, Split.HOLDOUT, 0.2, None))
    with pytest.raises(ContractError):
        _genome(falsifiers=extra)  # two rules of one kind
    with pytest.raises(ContractError):
        _genome(predictions=DEFAULT_PREDICTIONS[:1])  # REPLICATION never predicted
    optional_only = _genome(falsifiers=tuple(f for f in DEFAULT_FALSIFIERS
                                              if f.kind in MANDATORY_FALSIFIERS))
    assert len(optional_only.falsification_tests) == 3


@pytest.mark.parametrize("make", [
    lambda: Falsifier(FalsifierKind.HOLDOUT_RECALL, Split.HOLDOUT, 1.5, None),
    lambda: Falsifier(FalsifierKind.HOLDOUT_RECALL, Split.HOLDOUT, float("nan"), None),
    lambda: Falsifier(FalsifierKind.HOLDOUT_RECALL, Split.HOLDOUT, 0.1, 0.05),
    lambda: Falsifier(FalsifierKind.HOLDOUT_RECALL, Split.TRAIN, 0.1, None),
    lambda: Falsifier(FalsifierKind.HOLDOUT_ENRICHMENT, Split.HOLDOUT, 0.05, None),
    lambda: Falsifier(FalsifierKind.HOLDOUT_ENRICHMENT, Split.HOLDOUT, 0.6, 0.6),
    lambda: Falsifier(FalsifierKind.HOLDOUT_ENRICHMENT, Split.HOLDOUT, 0.0, 0.0),
    lambda: Falsifier(FalsifierKind.HOLDOUT_ENRICHMENT, Split.HOLDOUT, 0.01, 0.05),
    lambda: Falsifier(FalsifierKind.REPLICATION, Split.HOLDOUT, 0.05, 0.05),
    lambda: Prediction(Split.TRAIN, 0.0, 0.1, 0.01),
    lambda: Prediction("HOLDOUT", 0.0, 0.1, 0.01),  # type: ignore[arg-type]
    lambda: Prediction(Split.HOLDOUT, 0.0, 1.1, 0.01),
    lambda: GenomeProvenance(GeneratorKind.EXTERNAL_PROPOSAL, "sha256:" + "a" * 64, False, 0),
    lambda: GenomeProvenance(GeneratorKind.SYMBOLIC_ENUMERATOR, "sha256:" + "a" * 64, True, 0),
    lambda: GenomeProvenance(GeneratorKind.MUTATION, "not-a-digest", False, 0),
    lambda: GenomeProvenance(GeneratorKind.MUTATION, "sha256:" + "a" * 64, False, -1),
    lambda: ObservationScope(("rc",) * 2, frozenset(), ()),
    lambda: ObservationScope((), frozenset(), ("episode-1",)),
    lambda: ObservationScope(tuple(f"rc-{i}" for i in range(17)), frozenset(), ()),
])
def test_genome_parts_refuse_malformed_values(make: Any) -> None:
    with pytest.raises(ContractError):
        make()


def test_genome_structural_refusals() -> None:
    parent = _genome().hypothesis_id
    many = tuple(StepPredicate(Relation.SEND, 1 << i, 0, 0) for i in range(MAX_FORBIDDEN + 1))
    cases: list[dict[str, Any]] = [
        {"forbidden": many},
        {"forbidden": (StepPredicate(Relation.EXECUTE, 0, 0, 0),)},  # subsumes a necessary step
        {"visibility": frozenset()},
        {"visibility": frozenset(VisibilityAssumption)},
        {"parents": (parent, parent)},
        {"parents": ("hyp-1",)},
        {"parents": (parent,) * 3},
        {"competing": ("not-an-id",)},
        {"information_requests": tuple(ExperimentClass)[:5]},
    ]
    for overrides in cases:
        with pytest.raises(ContractError):
            _genome(**overrides)
    ok = _genome(parents=(parent,), competing=(parent,),
                 provenance=_provenance(GeneratorKind.STAGE7_SEED, foreign=True))
    assert ok.provenance.foreign and ok.parent_hypotheses == (parent,)


def test_genome_id_is_content_addressed_and_a_tampered_payload_is_refused() -> None:
    genome = _genome()
    assert genome.hypothesis_id == "hyp-" + genome.digest()[7:31]
    assert HypothesisGenome.from_dict(json.loads(json.dumps(genome.to_dict()))) == genome
    payload = genome.to_dict()
    payload["falsification_tests"][1]["threshold"] = 0.5  # loosen the FP rule, keep the id
    with pytest.raises(ContractError, match="does not match"):
        HypothesisGenome.from_dict(payload)
    loosened = dataclasses.replace(genome, hypothesis_id="",
                                   falsification_tests=_without(FalsifierKind.HOLDOUT_RECALL))
    assert loosened.hypothesis_id != genome.hypothesis_id  # an edit is a new theory
    with pytest.raises(dataclasses.FrozenInstanceError):
        genome.falsification_tests = ()  # type: ignore[misc]
    assert not hasattr(genome, "status") and not hasattr(genome, "text")


def test_genome_payload_refuses_authority_keys_at_any_depth_and_unknown_keys() -> None:
    genome = _genome()
    for word in sorted(FORBIDDEN_AUTHORITY_FIELDS):
        for where in ("top", "provenance", "list"):
            payload = genome.to_dict()
            target = {"top": payload, "provenance": payload["provenance"],
                      "list": payload["falsification_tests"][0]}[where]
            target[f"x_{word.upper()}_y"] = 1
            with pytest.raises(ContractError, match="authority"):
                HypothesisGenome.from_dict(payload)
    payload = genome.to_dict()
    payload["note"] = "free text"
    with pytest.raises(ContractError, match="unexpected"):
        HypothesisGenome.from_dict(payload)


def test_decides_blocks_only_on_a_forbidden_observation_in_the_same_actor(pool) -> None:
    backup = StepPredicate(Relation.READ, 1, 0, 0)  # a benign alternative the theory forbids
    genome = _genome(forbidden=(backup,))
    chain = [_step(pool[0], Relation.EXECUTE, 1 << 6, 0, 0),
             _step(pool[0], Relation.CONNECT, 1 << 7, 0, 0)]
    other_actor = [*chain, _step(pool[0], Relation.READ, 1, 0, 1)]
    same_actor = [*chain, _step(pool[0], Relation.READ, 1, 0, 0)]

    def episode(steps: list[EncodedStep]) -> Episode:
        return Episode("", tuple(steps), 1, Split.TRAIN, CTX, False)

    assert genome.decides(episode(chain)) and genome.decides(episode(other_actor))
    meter = WorkMeter()
    assert not genome.decides(episode(same_actor), meter=meter) and meter.spent > 0
    assert _genome().decides(episode(same_actor))  # without the forbidden observation it fires


def test_derived_properties_follow_the_mechanism() -> None:
    genome = _genome()
    assert genome.causal_dependencies == (CausalAssumption.SAME_ACTOR,
                                          CausalAssumption.ORDER_MATTERS)
    assert genome.necessary_conditions == PM1.steps
    assert genome.sufficient_conditions_candidate is genome.proposed_mechanism
    assert genome.complexity_cost == 20 + 4 * 2 + 0 + 2
    without = _genome(Mechanism(MechanismRelation.WITHOUT, (EXEC_TMP, CONNECT_EXT)))
    assert without.necessary_conditions == (EXEC_TMP,)
    assert CausalAssumption.ABSENCE_OBSERVABLE in without.causal_dependencies
    counted = _genome(parse_mechanism("REPEATED(CONNECT+EXTERNAL_ENDPOINT,4)"))
    assert CausalAssumption.COUNT_MATTERS in counted.causal_dependencies
    assert _genome(Mechanism(MechanismRelation.SINGLE, (EXEC_TMP,))).causal_dependencies == ()
    assert "Refuted by" in genome.render() and "HOLDOUT_ENRICHMENT" in genome.render()


# --- discovery package (the Stage 9 interface) ---------------------------------------------


def _measure(kind: RepresentationKind, wu: float, size: int) -> RepresentationMeasurement:
    return RepresentationMeasurement(
        kind=kind, expressible=True, refusal=None, precision=0.9, recall=0.8,
        false_positive_rate=0.0, pr_auc=0.85, decision_agreement=1.0, work_units_per_event=wu,
        artifact_bytes=size, wall_ratio_to_reference=0.5, loadavg=(1.0, 1.0, 1.0),
        robustness_recall=0.7, interpretability=2)


def _refused(kind: RepresentationKind, code: str) -> RepresentationMeasurement:
    return RepresentationMeasurement(kind, False, code, None, None, None, None, None, None, None,
                                     None, (1.0, 1.0, 1.0), None, None)


def _tournament(genome: HypothesisGenome, **overrides: Any) -> TournamentResult:
    entrants = (_measure(RepresentationKind.TYPED_RULE, 6.0, 900),
                _measure(RepresentationKind.MOTIF, 3.0, 60),
                _measure(RepresentationKind.FSM, 4.0, 200),
                *(_refused(kind, "NO_BOTH_CLASSES") for kind in list(RepresentationKind)[3:]))
    values: dict[str, Any] = dict(
        tournament_id="", hypothesis_id=genome.hypothesis_id, split=Split.REPLICATION,
        entrants=entrants, pareto_front=(RepresentationKind.MOTIF,),
        selected=RepresentationKind.MOTIF, deployable=True, reasons=("costs_less",),
        discovery_work_units=30_000, deployed_work_units_per_event=3.0, compression_ratio=10_000.0,
        knowledge_bytes_saved=4000, synthetic_data=True)
    values.update(overrides)
    return TournamentResult(**values)


ARTIFACT = {"kind": "MOTIF", "steps": [[1, 64, 0, 0], [7, 128, 0, 0]]}


def _package(**overrides: Any) -> DiscoveryPackageV1:
    genome = _genome()
    tournament = overrides.pop("detector_candidates", _tournament(genome))
    artifact = overrides.pop("compiled_artifact", ARTIFACT)
    values: dict[str, Any] = dict(
        package_id="", hypothesis_id=genome.hypothesis_id, mechanism=PM1,
        direction=Direction.MALICIOUS, required_features=(), detector_candidates=tournament,
        selected_representation=RepresentationKind.MOTIF, compiled_artifact=artifact,
        evidence_lineage=("res-0001", genome.hypothesis_id, "disc-1", "forge-1"),
        evidence_digests=("sha256:" + "b" * 64,), evidence_episode_ids=("ep-" + "c" * 24,),
        falsification_results=(FalsificationRecord(FalsifierKind.HOLDOUT_ENRICHMENT, Split.HOLDOUT,
                                                   True, 0.001, 0.05, "reg-" + "d" * 24),),
        failure_conditions=(
            FailureCondition("doppelganger:MONITORING_AGENT", 0.0, "none matched"),),
        resource_profile=ResourceProfile(60, 3.0, None, (1.0, 1.0, 1.0)),
        robustness_profile=RobustnessProfile((("TIMING_SHIFT", 1.0), ("EVENT_FLOOD", None)),
                                             (("BACKUP", 0.0),)),
        known_technique_mappings=("stage1:ATTACK_EXFIL",),
        novelty_classification=NoveltyClass.KNOWN, novelty_claim_permitted=False,
        identifiability=IdentifiabilityClass.EQUIVALENCE_CLASS,
        reproducibility=ReproducibilityRecord(ReproducibilityStatus.REPRODUCED, 0.9, 0.8, 0.0,
                                              0.6, 0.0, False, ("ok",)),
        artifact_hashes=artifact_hashes_for(mechanism=PM1, tournament=tournament,
                                            compiled_artifact=artifact, genome=genome),
        synthetic_data=True)
    values.update(overrides)
    return DiscoveryPackageV1(**values)


def test_schema_is_registered_and_a_valid_package_verifies_and_round_trips() -> None:
    assert SCHEMA_REGISTRY["pocketsec.discovery_package.v1"] == "1.0.0"
    package = _package()
    assert verify_package(package) == ()
    wire = json.loads(json.dumps(package.to_dict()))
    assert DiscoveryPackageV1.from_dict(wire) == package
    assert package.package_id.startswith("dp-") and len(package.package_id) == 27
    assert package.detector_candidates.tournament_id.startswith("tn-")


def test_verify_package_names_every_listed_problem() -> None:
    genome = _genome()
    other = _tournament(genome, selected=None, deployable=False, deployed_work_units_per_event=None,
                        compression_ratio=None)
    cases = {
        "failure_conditions is empty": {"failure_conditions": ()},
        "falsification_results is empty": {"falsification_results": ()},
        "evidence_lineage is empty": {"evidence_lineage": ()},
        "evidence digest is not sha256": {"evidence_digests": ("md5:abc",)},
        "novelty_claim_permitted": {"novelty_claim_permitted": True},
        "genome hash does not match": {"artifact_hashes": (
            *_package().artifact_hashes[:-1], ("genome", "sha256:" + "e" * 64))},
        "artifact hash missing: genome": {"artifact_hashes": _package().artifact_hashes[:-1]},
        "authority key": {"compiled_artifact": {"steps": [{"kill_switch": 1}]}},
    }
    for needle, overrides in cases.items():
        problems = verify_package(_package(**overrides))
        assert any(needle in problem for problem in problems), (needle, problems)
    valid = _package()
    swaps = {"mechanism": Mechanism(MechanismRelation.SINGLE, (EXEC_TMP,)),
             "compiled_artifact": {**ARTIFACT, "steps": []}, "detector_candidates": other}
    for name, value in swaps.items():  # same hashes, swapped content: must not recompute
        problems = verify_package(dataclasses.replace(valid, package_id="", **{name: value}))
        label = {"compiled_artifact": "artifact",
                 "detector_candidates": "tournament"}.get(name, name)
        assert f"artifact hash does not recompute: {label}" in problems, (name, problems)
    mismatch = verify_package(_package(detector_candidates=other))
    assert any("disagrees with detector_candidates.selected" in p for p in mismatch)
    assert verify_package(object()) != ()  # type: ignore[arg-type]


def test_package_from_dict_refuses_authority_keys_tamper_and_unknown_keys() -> None:
    package = _package()
    for word in sorted(FORBIDDEN_AUTHORITY_FIELDS):
        for path in ((), ("compiled_artifact",), ("detector_candidates", "entrants", 0),
                     ("reproducibility",)):
            payload = package.to_dict()
            target: Any = payload
            for key in path:
                target = target[key]
            target[word] = 1
            with pytest.raises(ContractError, match="authority"):
                DiscoveryPackageV1.from_dict(payload)
    payload = package.to_dict()
    payload["novelty_claim_permitted"] = True  # flip a claim, keep the id
    with pytest.raises(ContractError, match="does not match"):
        DiscoveryPackageV1.from_dict(payload)
    payload = package.to_dict()
    payload["detector_candidates"]["entrants"][1]["recall"] = 1.0  # inflate a measurement
    with pytest.raises(ContractError, match="does not match"):
        DiscoveryPackageV1.from_dict(payload)
    payload = package.to_dict()
    payload["extra"] = 1
    with pytest.raises(ContractError, match="unexpected"):
        DiscoveryPackageV1.from_dict(payload)


def test_tournament_refuses_inconsistent_selection_and_costs() -> None:
    genome = _genome()
    bad: list[dict[str, Any]] = [
        {"selected": RepresentationKind.FSM},  # not on the front
        {"deployable": False},
        {"compression_ratio": 5.0},  # not discovery / deployed
        {"deployed_work_units_per_event": 4.0},  # not the selected entrant's cost
        {"split": Split.HOLDOUT},
        {"pareto_front": (RepresentationKind.LOGISTIC,)},  # a refused entrant
        {"entrants": _tournament(genome).entrants[1:]},  # no TYPED_RULE reference
        {"selected": None, "deployable": False},  # DCR without a deployment
        {"tournament_id": "tn-" + "0" * 24},
        {"reasons": ("has space",)},
    ]
    for overrides in bad:
        with pytest.raises(ContractError):
            _tournament(genome, **overrides)
    with pytest.raises(ContractError):  # a refused entrant carrying a figure measured nothing
        dataclasses.replace(_refused(RepresentationKind.LOGISTIC, "NO_BOTH_CLASSES"), recall=0.5)
    with pytest.raises(ContractError):
        _measure(RepresentationKind.MOTIF, 1.0, 1).__class__(
            RepresentationKind.MOTIF, True, "X", *([None] * 8), (1.0, 1.0, 1.0), None, None)
    nothing = _tournament(genome, selected=None, deployable=False, pareto_front=(),
                          deployed_work_units_per_event=None, compression_ratio=None)
    assert not nothing.deployable
    missing = verify_package(_package(
        detector_candidates=_tournament(genome, entrants=_tournament(genome).entrants[:3])))
    assert any("entrants missing" in p for p in missing)


def test_package_field_refusals() -> None:
    bad: list[dict[str, Any]] = [
        {"known_technique_mappings": ("T1041",)},  # never ATT&CK ids
        {"required_features": ("not.a.feature",)},
        {"evidence_episode_ids": tuple(f"ep-{i:024x}" for i in range(9))},
        {"evidence_lineage": tuple(f"n{i}" for i in range(65))},
        {"failure_conditions": (FailureCondition("independent:fp", 0.0, "x"),) * 17},
        {"hypothesis_id": "hyp-1"},
        {"compiled_artifact": {"x": float("inf")}},
        {"compiled_artifact": {"x": {1, 2}}},
        {"package_id": "dp-" + "0" * 24},
        {"artifact_hashes": (("weights", "sha256:" + "0" * 64),)},
    ]
    for overrides in bad:
        with pytest.raises(ContractError):
            _package(**overrides)
    for make in (lambda: FailureCondition("free text", None, ""),
                 lambda: FailureCondition("challenge:TIMING_SHIFT", 1.5, ""),
                 lambda: FailureCondition("challenge:TIMING_SHIFT", None, "x" * 161),
                 lambda: ReproducibilityRecord(ReproducibilityStatus.REPRODUCED, None, 0.5, 0.0,
                                               None, None, False, ()),
                 lambda: FalsificationRecord(FalsifierKind.REPLICATION, Split.REPLICATION, True,
                                             None, 0.05, "reg-x")):
        with pytest.raises(ContractError):
            make()
    reads = ("relation=EXECUTE",)
    assert _package(required_features=reads).required_features == reads
    unmeasured = _package(resource_profile=ResourceProfile(None, None, None, (-1.0, -1.0, -1.0)))
    assert unmeasured.resource_profile.endpoint_incremental_rss_bytes is None


def _imports(path: Path) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            found |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module if node.level == 0 else f"<relative>{node.module}")
    return found


def test_own_modules_import_only_stdlib_and_the_allowed_upstream() -> None:
    allowed_prefixes = ("pocketsec.stage0", "pocketsec.stage1", "pocketsec.stage8.episode",
                        "pocketsec.stage8.genome")
    allowed_exact = {"pocketsec.stage2.encoder.ssir_encoder",
                     "pocketsec.stage2.compile_candidates.phi_oracle_candidate",
                     "pocketsec.stage6.capsule.experience_capsule",
                     "pocketsec.stage6.memory.semantic", "pocketsec.stage6.resources"}
    for path in OWN_FILES:
        for module in _imports(path):
            assert not module.startswith("<relative>"), (path, module)
            if module.startswith("pocketsec"):
                assert module.startswith(allowed_prefixes) or module in allowed_exact, \
                    (path, module)
            else:
                assert module.split(".")[0] in {"__future__", "ast", "collections", "dataclasses",
                                                "enum", "hashlib", "importlib", "json", "math",
                                                "re", "types", "typing"}, (path, module)
    package_imports = {m for m in _imports(STAGE8 / "forge" / "package.py")
                       if m.startswith("pocket")}
    assert all(m.startswith(("pocketsec.stage0", "pocketsec.stage8.episode",
                             "pocketsec.stage8.genome")) for m in package_imports)


def test_t5_no_dataclass_field_carries_an_authority_word() -> None:
    modules = (grammar, hypothesis, pkg, core_ids,
               __import__("pocketsec.stage8.episode", fromlist=["x"]))
    checked = 0
    for module in modules:
        for value in vars(module).values():
            if isinstance(value, type) and dataclasses.is_dataclass(value) \
                    and value.__module__ == module.__name__:
                for item in dataclasses.fields(value):
                    checked += 1
                    assert not any(w in item.name.lower() for w in FORBIDDEN_AUTHORITY_FIELDS), \
                        (value.__name__, item.name)
    assert checked > 80


# --- core ids and layout -----------------------------------------------------------------------


def test_core_ids_cover_every_layer_and_resolve_except_declared_pending_modules() -> None:
    rows = core_ids.STAGE8_FUNCTIONS
    assert [r.core_id for r in rows] == [f"PROM-F{i:02d}" for i in range(1, 26)]
    assert [r.layer for r in rows] == [f"8.{i}" for i in range(25)]
    assert {r.core_id for r in core_ids.optional_functions()} == {
        "PROM-F03", "PROM-F06", "PROM-F08", "PROM-F09", "PROM-F12"}
    named = {r.symbol.split(":", 1)[0] for r in rows}
    assert named >= PENDING_MODULES and not PENDING_MODULES & OWN_MODULES
    unexpected = [s for s in core_ids.resolve_symbols()
                  if s.split(":", 1)[0] not in PENDING_MODULES]
    assert unexpected == []
    for own in ("PROM-F04", "PROM-F07"):
        assert core_ids.symbol_problem(core_ids.stage8_function(own).symbol) is None
    assert core_ids.stage8_function("PROM-F23").control_map() == {
        "holdout_discipline": "NAIVE (control only)", "bonferroni": "NAIVE (control only)"}


def test_core_id_rows_and_resolver_refuse_what_the_spec_does_not_name() -> None:
    assert core_ids.symbol_problem("os:system") is not None  # never imported
    assert core_ids.symbol_problem("pocketsec.stage5.executor.transactional:X") is not None
    assert "not found" in (core_ids.symbol_problem("pocketsec.stage8.nowhere:x") or "")
    with pytest.raises(ContractError):
        core_ids.stage8_function("PROM-F26")
    good = core_ids.stage8_function("PROM-F03")
    for bad in ({"ablation_flags": (), "controls": ()},  # OPTIONAL and never removable
                {"layer": "8.9"}, {"ablation_flags": ("made_up",)},
                {"controls": ("",)}, {"symbol": "pocketsec.stage5.x:y"}):
        with pytest.raises(ContractError):
            dataclasses.replace(good, **bad)


def test_layout_empty_directories_are_gone_and_subsystem_inits_are_empty() -> None:
    assert not (STAGE8 / "experiments").exists() and not (STAGE8 / "hypotheses").exists()
    for init in (STAGE8 / "genome" / "__init__.py", STAGE8 / "forge" / "__init__.py"):
        assert init.read_bytes() == b""
    for path in OWN_FILES:
        assert len(path.read_text(encoding="utf-8").splitlines()) <= 800, path
