"""Stage 8 regression tests for the confirmed review findings (fix wave, 2026-09-27).

Each test names the finding it pins and was written to fail on the code the finding was
raised against. They exercise the failure path the reviewer reproduced, not a restatement of
the fix: a MALICIOUS refutation silencing the BENIGN reading (F4), a folded refuted id being
born again (F5), stale screen terms at ranking (F3), the ORACLE fossilizing a whole group and
crashing (F2 / S8-RES-2), a decoy step deciding the invariance screen (F1), and the one door
admitting evidence the mechanism never matched (S8-AUTH-01).
"""

from __future__ import annotations

import pytest

from pocketsec.stage8.episode import Split
from pocketsec.stage8.genome.grammar import parse_mechanism
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
from pocketsec.stage8.ledger.negative_results import NegativeResult, NegativeResultMemory
from pocketsec.stage8.governor.budget import ResearchBudget
from pocketsec.stage8.ledger.theory import LedgerError, TheoryLedger, TheoryStatus

SPAWN = "SINGLE(SPAWN)"
SMALL = ResearchBudget(max_active_residual_clusters=4, max_hypotheses_per_residual=16,
                       max_population=64, max_registrations_per_batch=6)


def _genome(dsl: str = SPAWN, *, direction: Direction = Direction.MALICIOUS,
            seed: int = 0) -> HypothesisGenome:
    return genome_for(
        parse_mechanism(dsl), direction=direction,
        scope=ObservationScope(residual_cluster_ids=(), episode_ids=(),
                               residual_types=frozenset({ResidualType.OBSERVATION})),
        provenance=GenomeProvenance(generator=GeneratorKind.SYMBOLIC_ENUMERATOR,
                                    source_digest="sha256:" + "0" * 64, foreign=False, seed=seed),
    )


def _challenge_out(ledger: TheoryLedger, genome: HypothesisGenome) -> None:
    kind = next(f.kind for f in genome.falsification_tests
                if f.kind is FalsifierKind.COUNTERFACTUAL_INVARIANCE)
    ledger.record_challenge(genome.hypothesis_id, kind=kind, passed=False, statistic=0.5)
    ledger.set_status(genome.hypothesis_id, TheoryStatus.CHALLENGED_OUT,
                      reason=f"challenge:{kind.value}")


# --- F4: negative memory is per reading, not per mechanism ----------------------------------------


def test_f4_a_refuted_malicious_reading_does_not_silence_the_benign_one() -> None:
    """F4: MALICIOUS:M refuted must leave BENIGN:M proposable (it was a dead end both ways)."""
    memory = NegativeResultMemory()
    ledger = TheoryLedger(negative_memory=memory)
    malicious = _genome(direction=Direction.MALICIOUS)
    ledger.record_birth(malicious)
    _challenge_out(ledger, malicious)
    mechanism = malicious.proposed_mechanism
    assert memory.is_dead_end(mechanism, Direction.MALICIOUS) is True
    assert memory.is_dead_end(mechanism, Direction.BENIGN) is False
    # And the BENIGN reading can be born and tested in the same ledger.
    benign = _genome(direction=Direction.BENIGN)
    ledger.record_birth(benign)
    assert ledger.status(benign.hypothesis_id) is TheoryStatus.PROPOSED


def test_f4_negative_result_refuses_a_missing_direction() -> None:
    """F4: a negative result that does not say which reading it refutes is refused."""
    genome = _genome()
    with pytest.raises(Exception):
        NegativeResult(  # type: ignore[call-arg]
            mechanism_digest=genome.proposed_mechanism.digest(),
            hypothesis_id=genome.hypothesis_id, status=TheoryStatus.FALSIFIED, refutation=None,
            reason="HOLDOUT_ENRICHMENT", counterexample_ids=(), recorded_sequence=0)


# --- F5 / S8-RES-1: a folded refuted id is never born again; its status survives the fold ---------


def test_f5_a_folded_refuted_hypothesis_cannot_be_born_again() -> None:
    """F5: the reviewer's probe. g1 CHALLENGED_OUT, folded by g2, g2 FOSSILIZED and folded by g3:
    g1 must still be refused re-birth, its status must still answer, and the mechanism must stay
    a dead end although a sibling with the same mechanism was only retired."""
    memory = NegativeResultMemory()
    ledger = TheoryLedger(max_theories=1, negative_memory=memory)
    g1, g2, g3 = (_genome(seed=s) for s in (1, 2, 3))
    assert len({g1.hypothesis_id, g2.hypothesis_id, g3.hypothesis_id}) == 3
    mechanism = g1.proposed_mechanism
    ledger.record_birth(g1)
    _challenge_out(ledger, g1)
    ledger.record_birth(g2)                       # folds g1
    ledger.set_status(g2.hypothesis_id, TheoryStatus.FOSSILIZED, reason="population_evicted")
    ledger.record_birth(g3)                       # folds g2
    assert memory.is_dead_end(mechanism, Direction.MALICIOUS) is True
    assert memory.stats()["dead_end_kept"] == 1
    assert ledger.status(g1.hypothesis_id) is TheoryStatus.CHALLENGED_OUT
    assert ledger.status(g2.hypothesis_id) is TheoryStatus.FOSSILIZED
    with pytest.raises(LedgerError):
        ledger.record_birth(g1)
    assert ledger.stats()["refused_duplicate_birth"] == 1


def test_f5_a_retirement_never_overwrites_a_refutation_in_memory() -> None:
    """F5: remember(FOSSILIZED) after remember(FALSIFIED) for the same reading keeps FALSIFIED."""
    memory = NegativeResultMemory()
    g1, g2 = _genome(seed=1), _genome(seed=2)

    def result(genome: HypothesisGenome, status: TheoryStatus) -> NegativeResult:
        return NegativeResult(
            mechanism_digest=genome.proposed_mechanism.digest(),
            hypothesis_id=genome.hypothesis_id, status=status, refutation=None,
            reason=status.value, counterexample_ids=(), recorded_sequence=0,
            direction=genome.direction)

    memory.remember(result(g1, TheoryStatus.FALSIFIED))
    memory.remember(result(g2, TheoryStatus.FOSSILIZED))
    assert memory.is_dead_end(g1.proposed_mechanism, Direction.MALICIOUS) is True
    assert memory.result_for_hypothesis(g1.hypothesis_id) is not None


# --- F3: the ledger-backed score terms are read after the screens, not before ---------------------


def test_f3_rank_reads_the_screens_that_ran(monkeypatch: pytest.MonkeyPatch) -> None:
    """F3: every member's score was cached before ``screen()`` wrote a CHALLENGE_RESULT, so at
    ``rank()`` falsification_survival and adversarial_fragility were (0.0, 0.0) for every
    candidate while the ledger said (1.0, ...). The reviewer's run, re-asserted."""
    from pocketsec.stage8.labs import discovery_run as dr
    from pocketsec.stage8.labs.discovery_corpus import CorpusArm, build_discovery_corpus

    counts = {Split.TRAIN: 48, Split.HOLDOUT: 48, Split.REPLICATION: 100, Split.LAB_POOL: 30,
              Split.INDEPENDENT: 30}
    corpus = build_discovery_corpus(arm=CorpusArm.PLANTED, seed=3, counts=counts)
    seen: list[tuple[tuple[float, float], tuple[float, float]]] = []
    original = dr._Run.rank

    def spy(self, kept):  # type: ignore[no-untyped-def]
        population = self.stores.population
        for genome in kept:
            score = population.score(genome.hypothesis_id, self.train)
            seen.append(((score.falsification_survival, score.adversarial_fragility),
                         population._screen_terms(genome.hypothesis_id)))
        return original(self, kept)

    monkeypatch.setattr(dr._Run, "rank", spy)
    dr.run_discovery(corpus, dr.RunConfig(arm=CorpusArm.PLANTED, seed=3, budget=SMALL))
    assert seen, "the run must rank something for this test to mean anything"
    assert all(cached == pytest.approx(ledger) for cached, ledger in seen), seen[:3]
    assert all(cached[0] == 1.0 for cached, _ in seen)  # every ranked genome passed its screens


# --- F2 / S8-RES-2: ORACLE never fossilizes a group by size alone, and never aborts the run ------


def test_f2_s8_res_2_a_large_group_neither_crashes_nor_is_fossilized_wholesale(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """F2 / S8-RES-2: the repository's own crash repro (PLANTED content 0, run seed 1, RANDOM
    count 768) with ORACLE on. Before the fix a 129-hypothesis group had max posterior 0.0078 <
    0.01, every member was written FOSSILIZED, then ``Posterior.restricted([])`` raised and the
    run returned no report. Now the prune is relative to the leader, so group size alone prunes
    nothing, the leader always survives, and the run reports."""
    import functools

    from pocketsec.stage8.labs import discovery_run as dr
    from pocketsec.stage8.labs.discovery_corpus import CorpusArm, build_discovery_corpus
    from pocketsec.stage8.oracle.planner import PRUNE_REASON, SelectionPolicy
    from pocketsec.stage8.prometheus.generators import RandomGenerator

    corpus = build_discovery_corpus(arm=CorpusArm.PLANTED, seed=0)
    monkeypatch.setattr(dr, "RandomGenerator", functools.partial(RandomGenerator, count=768))
    config = dr.RunConfig(arm=CorpusArm.PLANTED, seed=1,
                          generators=(GeneratorKind.RANDOM_BASELINE,),
                          oracle_policy=SelectionPolicy.EIG_PER_COST)
    report = dr.run_discovery(corpus, config)
    sizes = [len(o.final_posterior.hypothesis_ids) + len(o.pruned) for o in report.oracle]
    assert max(sizes) > 100, sizes  # the condition that crashed is actually exercised
    for oracle in report.oracle:
        assert oracle.final_posterior.hypothesis_ids  # never an empty group
    assert report.ledger is not None
    pruned = [e for e in report.ledger.entries()
              if e.payload.get("reason") == PRUNE_REASON]
    assert len(pruned) == sum(len(o.pruned) for o in report.oracle) < max(sizes)


def test_f2_oracle_is_default_off() -> None:
    """F2 / S8-RES-2 / ADR-0078 amendment 2: ORACLE is NOT_YET_JUSTIFIED on replay, so it is
    opt-in. The ablation still measures it, from an all-on base."""
    from pocketsec.stage8.labs.baselines import ablation_base, ablation_control
    from pocketsec.stage8.labs.discovery_corpus import CorpusArm
    from pocketsec.stage8.labs.discovery_run import RunConfig
    from pocketsec.stage8.oracle.planner import SelectionPolicy

    base = RunConfig(arm=CorpusArm.PLANTED, seed=0)
    assert base.oracle_policy is None
    assert ablation_base(base).oracle_policy is SelectionPolicy.EIG_PER_COST
    control, _, _ = ablation_control("oracle", base)
    assert control.oracle_policy is None and control != ablation_base(base)


# --- F1: a decoy the hypothesis names is not a harmless decoy for it -------------------------------


def test_f1_decoys_matching_the_hypothesis_do_not_decide_invariance() -> None:
    """F1: SINGLE(p) over a non-escalating step p fires on a decoy actor performing p, so the
    DECOY_INSERTION relation 'refuted' it whether or not it was true (the trap SINGLE(SPAWN)
    dropped to 0.49), while every escalating SINGLE scored 1.0. With decoys filtered relative
    to the hypothesis, the decoy relation cannot refute a SINGLE over a non-escalating step by
    its own vocabulary: the trap's agreement under the decoy relation is 1.0 again, and a
    decoy never matches any predicate of the genome it is judged against."""
    from pocketsec.stage8.labs import discovery_run as dr
    from pocketsec.stage8.labs.discovery_corpus import CorpusArm, build_discovery_corpus
    from pocketsec.stage8.laboratory.counterfactual import decoy_is_neutral, decoy_steps

    counts = {Split.TRAIN: 48, Split.HOLDOUT: 48, Split.REPLICATION: 100, Split.LAB_POOL: 60,
              Split.INDEPENDENT: 30}
    corpus = build_discovery_corpus(arm=CorpusArm.PLANTED, seed=0, counts=counts)
    run = dr._Run(corpus, dr.RunConfig(arm=CorpusArm.PLANTED, seed=0), dr._Knobs(), None, None)
    bench = run.invariance_bench()
    decoyed = dict(bench)[dr._DECOY_RELATION]
    trap = _genome_for_mechanism(corpus.trap_mechanism)
    # Precondition: the unfiltered decoy relation does flip the trap (the reviewer's 0.49).
    flips = [(a, b) for a, b in decoyed if trap.decides(a) != trap.decides(b)]
    assert flips, "the raw decoy relation must flip the trap for this test to mean anything"
    assert all(not decoy_is_neutral(a, b, trap.proposed_mechanism.steps) for a, b in flips)
    assert all(any(trap.proposed_mechanism.steps[0].matches(s) for s in decoy_steps(a, b))
               for a, b in flips)
    invariance = run.invariance(trap, ((dr._DECOY_RELATION, decoyed),))
    assert invariance == 1.0


def _genome_for_mechanism(mechanism):  # type: ignore[no-untyped-def]
    return genome_for(
        mechanism, direction=Direction.MALICIOUS,
        scope=ObservationScope(residual_cluster_ids=(), episode_ids=(),
                               residual_types=frozenset({ResidualType.OBSERVATION})),
        provenance=GenomeProvenance(generator=GeneratorKind.SYMBOLIC_ENUMERATOR,
                                    source_digest="sha256:" + "0" * 64, foreign=False, seed=0))


# --- F2 (honesty lens): "costs less" is not decided by self-charged work units alone -------------


def test_f2_honesty_a_deliberately_slow_compressed_form_is_not_deployable(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """F2 (honesty): the reviewer patched the FSM with a 200 us busy-wait; it stayed selected and
    deployable (wall ratio 17.9-21.6x, work units unchanged) and G8.7 passed. The same stub on
    the entrant FORGE selects here (MOTIF) must now be refused as slower_than_reference, and
    the gate's independent restatement must agree."""
    import random
    import time

    from pocketsec.stage8.challenger.adversarial import ChallengeKind, build_challenge_corpus
    from pocketsec.stage8.forge.compiler import compile_all
    from pocketsec.stage8.forge.package import RepresentationKind
    from pocketsec.stage8.forge.representations import MotifDetector
    from pocketsec.stage8.forge.tournament import research_state_bytes_of, run_tournament
    from pocketsec.stage8.gate_evidence import _deployable_problem
    from pocketsec.stage8.governor.budget import ResearchGovernor
    from pocketsec.stage8.labs.discovery_corpus import CorpusArm, build_discovery_corpus

    counts = {Split.TRAIN: 60, Split.HOLDOUT: 20, Split.REPLICATION: 60, Split.LAB_POOL: 30,
              Split.INDEPENDENT: 20}
    corpus = build_discovery_corpus(arm=CorpusArm.PLANTED, seed=3, counts=counts)
    genome = _genome("PRECEDES(EXECUTE+TEMP_LOCATION,CONNECT+EXTERNAL_ENDPOINT)")
    governor = ResearchGovernor(ResearchBudget())
    compiled = compile_all(genome, corpus.episodes(Split.TRAIN), governor=governor)
    kinds = tuple(k for k in ChallengeKind if k is not ChallengeKind.POISONED_LABELS)
    challenge = build_challenge_corpus(corpus.episodes(Split.LAB_POOL), kinds=kinds,
                                       rng=random.Random(3), governor=governor,
                                       necessary=genome.necessary_conditions)
    original = MotifDetector.decide

    def slow(self, episode, meter=None):  # type: ignore[no-untyped-def]
        until = time.perf_counter() + 200e-6
        while time.perf_counter() < until:
            pass
        return original(self, episode, meter)

    monkeypatch.setattr(MotifDetector, "decide", slow)
    result = run_tournament(genome, compiled, measure_on=corpus.episodes(Split.REPLICATION),
                            challenge=challenge, discovery_work_units=governor.meter.spent,
                            research_state_bytes=research_state_bytes_of(genome),
                            governor=governor)
    motif = next(m for m in result.entrants if m.kind is RepresentationKind.MOTIF)
    reference = next(m for m in result.entrants if m.kind is RepresentationKind.TYPED_RULE)
    assert motif.work_units_per_event <= reference.work_units_per_event  # "cheaper" by units
    assert motif.wall_ratio_to_reference is not None and motif.wall_ratio_to_reference > 1.0
    assert "MOTIF:slower_than_reference" in result.reasons
    assert result.selected is not RepresentationKind.MOTIF
    assert _deployable_problem(result) is None  # the gate agrees: nothing slow was shipped


# --- S8-DEF-07: adversarial generation perturbs synthetic telemetry only ---------------------------


def test_s8_def_07_real_telemetry_is_never_perturbed() -> None:
    """S8-DEF-07: neither apply_transform nor build_challenge_corpus checked context.synthetic,
    and a derived variant copies its source's context, so a fabricated variant of real
    telemetry would have been stamped synthetic=False, i.e. recorded as real."""
    import dataclasses
    import random

    from pocketsec.stage0.contracts.common import ContractError
    from pocketsec.stage8.challenger.adversarial import ChallengeKind, build_challenge_corpus
    from pocketsec.stage8.governor.budget import ResearchGovernor
    from pocketsec.stage8.laboratory.counterfactual import (
        TransformKind, TransformSpec, apply_transform,
    )
    from pocketsec.stage8.labs.discovery_corpus import CorpusArm, build_discovery_corpus

    counts = {Split.TRAIN: 24, Split.HOLDOUT: 24, Split.REPLICATION: 24, Split.LAB_POOL: 24,
              Split.INDEPENDENT: 10}
    pool = build_discovery_corpus(arm=CorpusArm.PLANTED, seed=0, counts=counts) \
        .episodes(Split.LAB_POOL)
    real = tuple(dataclasses.replace(e, context=dataclasses.replace(e.context, synthetic=False))
                 for e in pool)
    spec = TransformSpec(TransformKind.ACTOR_RENAME, 1)
    assert apply_transform(pool[0], spec, rng=random.Random(0)) is not None  # synthetic: fine
    with pytest.raises(ContractError, match="synthetic"):
        apply_transform(real[0], spec, rng=random.Random(0))
    with pytest.raises(ContractError, match="synthetic"):
        build_challenge_corpus(real, kinds=(ChallengeKind.FEATURE_OBFUSCATION,), rng=random.Random(0),
                               governor=ResearchGovernor(ResearchBudget()), necessary=())


# --- F11: a BENIGN theory has no malicious-label robustness figure ---------------------------------


def test_f11_a_benign_theory_gets_no_inverted_recall() -> None:
    """F11: failure_contexts and package_one called challenge(), which reads label 1 as the
    positive class, for BENIGN theories too; FORGE's tournament already returns None there."""
    from pocketsec.stage8.labs import discovery_run as dr
    from pocketsec.stage8.labs.discovery_corpus import CorpusArm, build_discovery_corpus

    counts = {Split.TRAIN: 24, Split.HOLDOUT: 24, Split.REPLICATION: 24, Split.LAB_POOL: 24,
              Split.INDEPENDENT: 10}
    corpus = build_discovery_corpus(arm=CorpusArm.PLANTED, seed=0, counts=counts)
    run = dr._Run(corpus, dr.RunConfig(arm=CorpusArm.PLANTED, seed=0), dr._Knobs(), None, None)
    assert run.robustness(_genome(direction=Direction.BENIGN)) == ()
    assert run.robustness(_genome(direction=Direction.MALICIOUS))  # MALICIOUS still measured


# --- F3 (honesty lens): the durable ledgers do not repeat a retracted claim ------------------------


#: The RETRACTED rows of docs/stage-8-findings.md name MEMORY and PROGRESS as places the claims
#: were published. Each phrase is the published wording; it may appear only on a line that says
#: it is retracted or corrected.
_RETRACTED_WORDING = (
    "recovers PM1",
    "recover 0 at equal budget",
    "recovers 1 of 3 planted families (PM1)",
    "vs 0 for random and exhaustive single-step",
    "7% cheaper per event",
    "91% smaller",
)


def test_f3_honesty_retracted_claims_are_not_repeated_in_the_durable_ledgers() -> None:
    """F3 (honesty): MEMORY 'Durable Stage 8 facts' and PROGRESS still stated claims the findings'
    RETRACTED table withdraws, so the next session would start from false facts."""
    from pocketsec.stage0.gate import REPO_ROOT

    for name in ("planning/MEMORY.md", "planning/PROGRESS.md"):
        for number, line in enumerate((REPO_ROOT / name).read_text().splitlines(), start=1):
            if "RETRACTED" in line or "CORRECTED" in line or "retracted" in line:
                continue
            for phrase in _RETRACTED_WORDING:
                assert phrase not in line, f"{name}:{number} repeats a retracted claim: {phrase}"


# --- F1 (medium lens): a killed reading cannot be re-born and re-tested on the same split ----------


def test_f1_medium_a_reading_is_tested_once_per_split_whatever_its_id() -> None:
    """F1 (medium): the held-out discipline was per vault and per hypothesis id, so a mechanism
    killed at HOLDOUT could be re-born under a new id (a looser criterion) and re-tested on the
    same split through a second HoldoutVault on the same ledger. The ledger now refuses the
    second preregistration of the same (split digest, mechanism, direction)."""
    from pocketsec.stage8.governor.budget import ResearchGovernor
    from pocketsec.stage8.labs.discovery_corpus import CorpusArm, build_discovery_corpus
    from pocketsec.stage8.ledger.theory import PreRegistration
    from pocketsec.stage8.sandbox.integrity import HoldoutVault

    counts = {Split.TRAIN: 24, Split.HOLDOUT: 48, Split.REPLICATION: 24, Split.LAB_POOL: 24,
              Split.INDEPENDENT: 10}
    holdout = build_discovery_corpus(arm=CorpusArm.PLANTED, seed=0, counts=counts) \
        .episodes(Split.HOLDOUT)
    ledger = TheoryLedger()

    def register(genome: HypothesisGenome) -> tuple[HoldoutVault, PreRegistration]:
        vault = HoldoutVault(holdout, split=Split.HOLDOUT, ledger=ledger,
                             governor=ResearchGovernor(ResearchBudget()))
        registration = PreRegistration(
            registration_id="", hypothesis_id=genome.hypothesis_id,
            genome_digest=genome.digest(), split=Split.HOLDOUT,
            split_digest=vault.split_digest(), batch_size=1,
            alpha=next(f.alpha for f in genome.falsification_tests
                       if f.kind is FalsifierKind.HOLDOUT_ENRICHMENT),
            prediction=next(p for p in genome.predicted_observations
                            if p.split is Split.HOLDOUT))
        ledger.preregister(registration)
        return vault, registration

    first, again = _genome(seed=1), _genome(seed=2)
    ledger.record_birth(first)
    vault, registration = register(first)
    vault.evaluate(vault.seal_batch([registration]))
    ledger.record_birth(again)          # a new id for the same reading is still born
    with pytest.raises(LedgerError, match="already tested on this split"):
        register(again)                 # but it is not tested on the same split again
    assert ledger.stats()["refused_retest_on_split"] == 1
    other = _genome(direction=Direction.BENIGN, seed=3)
    ledger.record_birth(other)
    register(other)                     # the other reading of the mechanism is a new question


# --- F7 (medium lens): the search comparison cannot be JUSTIFIED by construction -----------------


def test_f7_search_is_not_justified_by_an_inexpressible_baseline_or_an_unequal_spend() -> None:
    """F7: PROMETHEUS recovering the 2-step DROP_EXEC_EGRESS was always 'beyond exhaustive'
    (the single-step arm cannot express it), and random 'lost' while spending 0.63x under the
    same cap, so compare_search printed JUSTIFIED. The gate's own shape, re-judged."""
    from pocketsec.stage8.labs.baselines import ComponentVerdict, SearchArm, search_verdict

    def arm(name: str, families: tuple[str, ...], units: int) -> SearchArm:
        return SearchArm(arm=name, seeds=(0,), planted_recovered=(len(families),),
                         families=families, false_reproduced=(0,), work_units=(units,),
                         budget_exhausted=(False,))

    prometheus = arm("PROMETHEUS", ("DROP_EXEC_EGRESS",), 9_000_000)
    exhaustive = arm("EXHAUSTIVE_SINGLE_BASELINE", (), 9_000_000)
    cheap_random = arm("RANDOM_BASELINE", (), 5_670_000)   # 0.63x the spend
    verdict = search_verdict((prometheus, cheap_random, exhaustive))
    assert verdict.beats_random is False and verdict.beyond_exhaustive == ()
    assert verdict.verdict is ComponentVerdict.NOT_YET_JUSTIFIED
    equal_random = arm("RANDOM_BASELINE", (), 9_000_000)
    verdict = search_verdict((prometheus, equal_random, exhaustive))
    assert verdict.beats_random is True             # equal spend: a real win over random
    assert verdict.beyond_exhaustive == ()          # but still not beyond what exhaustive can say
    assert verdict.verdict is ComponentVerdict.NOT_YET_JUSTIFIED
