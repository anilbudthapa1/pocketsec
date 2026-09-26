"""Architecture layer 9.1 — the ONTOGENESIS meta-controller: one budgeted search loop.

This module runs the search for the cheapest computation that does the security job, and
the two searches it must beat, under the **same** work-unit budget:

* ``EVOLUTIONARY``: 32 random genomes, then parent -> GENESIS operator -> worst-case train
  fitness -> GAIA archive, until the shared :class:`WorkMeter` refuses a charge.
* ``RANDOM``: ``genesis.variation.random_genome`` (the generator that also seeds the
  evolutionary population) until the budget is spent.
* ``EXHAUSTIVE``: each of the 126 genomes of :func:`enumerate_exhaustive`, once; its true
  spend is reported, never padded up to the equal budget.

Evolution is JUSTIFIED only if it beats **both** on held-out data
(:func:`compare_strategies`). The lead's honest expectation is that exhaustive enumeration
ties or beats it on this corpus; a rediscovered Φ-oracle is a success.

What this module refuses to do:

* It never seeds the Φ-oracle, H1 or H2 into any population. They are measured, not bred.
* It never exceeds its budget: every proposal is charged ``_PROPOSAL_WU`` before it is
  built and every evaluation charges before it runs, so ``wu_spent <= budget_wu`` always.
  The proposal charge also guarantees that a loop of refusals or cache hits terminates.
* It never selects on held-out data: ``run_search`` sees only the train suite.
* It holds no production authority: its output is a record of candidates, and the only
  exit is ``successor.stage6_exit`` (ADR-0081). Nothing here reaches Stage 5.
* Every buffer is bounded: records and the known-digest set at :data:`MAX_RECORDS`, the
  population at :data:`MAX_POPULATION` (evictions counted), fossils by their own module.
  A re-proposed digest is refused before evaluation and counted in ``cache_hits``.
  Hitting a bound other than the budget stops the run and names it in ``stop_reason``.
Wall-clock figures ride with ``loadavg`` before and after (shared host); WU are primary.
"""

from __future__ import annotations

import functools
import hashlib
import math
import random
import statistics
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from enum import StrEnum

from pocketsec.stage0.benchmark.security_metrics import average_precision
from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage6.resources import WorkBudgetExceeded, WorkMeter, loadavg
from pocketsec.stage9.chemistry.phenotype import SessionAggregation
from pocketsec.stage9.chemistry.typed_ir import (
    INPUT_TYPES,
    InputSource,
    IRNode,
    IRProgram,
    IRType,
    NodeKind,
    ProgramPhase,
    RegisterSpec,
)
from pocketsec.stage9.foundry.primitives import SEED_ALPHABET, PrimitiveAlphabet
from pocketsec.stage9.gaia.qd_ecology import (
    FOSSIL_AVOIDANCE_DEFAULT_ENABLED,
    QD_ARCHIVE_DEFAULT_ENABLED,
    ArchiveOutcome,
    ComputationalFossil,
    Elite,
    FossilReason,
    FossilStore,
    QualityDiversityArchive,
    compare_arm,
    niche_of,
)
from pocketsec.stage9.genesis.variation import (
    OperatorStats,
    VariationOperator,
    crossover,
    mutate,
    random_genome,
)
from pocketsec.stage9.genome.computational import ComputationalGenomeV1, build_genome
from pocketsec.stage9.genome.expressibility import phi_oracle_genome
from pocketsec.stage9.ontogenesis.fitness import (
    EvaluationCache,
    EvaluationSuite,
    FitnessRecord,
    evaluate,
    session_scores,
)
from pocketsec.stage9.spec.mssc import (
    DEFAULT_CONSTRAINTS,
    DetectorComparison,
    MechanismVerdict,
    check_constraints,
)

__all__ = [
    "EVOLUTIONARY_SEARCH_DEFAULT_ENABLED",
    "EXHAUSTIVE_INPUTS",
    "EXHAUSTIVE_SIZE",
    "INITIAL_POPULATION",
    "MAX_POPULATION",
    "MAX_RECORDS",
    "SEARCH_BUDGET_WU",
    "SEARCH_SEEDS",
    "SUBTRACTIVE_BIAS_DEFAULT_ENABLED",
    "SUBTRACTIVE_SHARE",
    "NullVerdict",
    "SearchConfig",
    "SearchRun",
    "SearchStrategy",
    "ShuffledLabelControl",
    "StrategyComparison",
    "WinnerReport",
    "compare_arm",
    "compare_strategies",
    "enumerate_exhaustive",
    "heldout_report",
    "null_verdict",
    "run_search",
    "run_shuffled_label_control",
    "seed_matched",
    "strategy_verdict",
]


class SearchStrategy(StrEnum):
    EVOLUTIONARY = "EVOLUTIONARY"
    RANDOM = "RANDOM"
    EXHAUSTIVE = "EXHAUSTIVE"


#: Per (strategy, seed). Chosen, not measured: arithmetic in spec §4.9.
SEARCH_BUDGET_WU: int = 96_000_000
SEARCH_SEEDS: tuple[int, ...] = (101, 202, 303)
INITIAL_POPULATION: int = 32
MAX_POPULATION: int = 64
#: REMOVE is drawn with this probability when the subtractive bias is on (§33). Chosen.
SUBTRACTIVE_SHARE: float = 0.25
#: Off until ``compare_strategies`` returns JUSTIFIED and the integrator flips it (G9.9).
EVOLUTIONARY_SEARCH_DEFAULT_ENABLED: bool = False
#: Off until ``compare_arm(flag="subtractive")`` returns JUSTIFIED.
SUBTRACTIVE_BIAS_DEFAULT_ENABLED: bool = False
MAX_RECORDS: int = 8192
EXHAUSTIVE_INPUTS: tuple[tuple[InputSource, int], ...] = (
    (InputSource.FEATURE, 73),
    (InputSource.FEATURE, 83),
    (InputSource.FEATURE, 85),
    (InputSource.FEATURE, 90),
    (InputSource.DELTA_PHI, 0),
    (InputSource.STATE_DELTA_MASK, 0),
    (InputSource.RELATION_FAMILY, 0),
)
EXHAUSTIVE_SIZE: int = 126

_CROSSOVER_SHARE: float = 0.1
#: Charged before every proposal: building and validating a genome is work, and a loop that
#: produces only refusals or cache hits must still exhaust its budget. Chosen.
_PROPOSAL_WU: int = 1
#: Consecutive proposals without a new evaluation before a run stops as STALLED. Chosen.
_STALL_LIMIT: int = 4096
#: Clean-minus-worst-case AP drop that makes an evaluated genome an ARGUS fossil (§4.6).
_ARGUS_DROP_TOLERANCE: float = 0.05
_STRATEGY_MARGIN: float = 0.02
_SHUFFLE_PERMUTATIONS: int = 200
_PRIOR_SAMPLE: int = 64
_NULL_ALPHA: float = 0.05
_PRIOR_CUT: float = 0.95
_AP_TIE: float = 1e-12
_FLOAT_OPS: tuple[str, ...] = ("ADD", "MAX", "MIN")
_INT_OPS: tuple[str, ...] = ("OR", "XOR", "AND")
_MODULE = "pocketsec.stage9.ontogenesis.search"


@dataclass(frozen=True, slots=True)
class SearchConfig:
    """One arm. Defaults READ the module flags, so the main arm is "every option off"."""

    strategy: SearchStrategy
    seed: int
    budget_wu: int = SEARCH_BUDGET_WU
    niches: bool = QD_ARCHIVE_DEFAULT_ENABLED
    fossil_avoidance: bool = FOSSIL_AVOIDANCE_DEFAULT_ENABLED
    subtractive: bool = SUBTRACTIVE_BIAS_DEFAULT_ENABLED
    label_shuffle_seed: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.strategy, SearchStrategy):
            raise ContractError(f"SearchConfig.strategy is not a SearchStrategy: {self.strategy!r}")
        for name in ("seed", "budget_wu"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ContractError(f"SearchConfig.{name} must be an int >= 0, got {value!r}")

    @property
    def label(self) -> str:
        flags = [n for n in ("niches", "fossil_avoidance", "subtractive") if getattr(self, n)]
        if self.label_shuffle_seed is not None:
            flags.append(f"shuffled{self.label_shuffle_seed}")
        return "-".join([self.strategy.value.lower(), f"s{self.seed}", *flags])


@dataclass(frozen=True, slots=True)
class SearchRun:
    """Everything one arm did, bounded, with the determinism digest to prove it replays."""

    config: SearchConfig
    evaluations: int
    #: Re-proposals of an already-recorded digest, refused before evaluation at 0 WU.
    cache_hits: int
    wu_spent: int
    budget_exhausted: bool
    records: tuple[FitnessRecord, ...]
    genomes: tuple[ComputationalGenomeV1, ...]
    archive_elites: tuple[Elite, ...]
    winner: int | None
    operator_stats: tuple[OperatorStats, ...]
    population_evictions: int
    fossils_recorded: int
    fossils_avoided: int
    determinism_digest: str
    rediscovered_phi: bool
    wall_seconds: float
    loadavg_before: tuple[float, float, float]
    loadavg_after: tuple[float, float, float]
    #: Meter reading after each record's evaluation (the fossil arm's "WU to reach best").
    wu_at_record: tuple[int, ...] = ()
    #: WORK_BUDGET_EXCEEDED | RECORD_BOUND | STALLED | EXHAUSTED_SPACE
    stop_reason: str = ""
    #: Records from the initial random population; a winner at or past this index came from
    #: variation, which is the evolutionary loop's firing count.
    initial_records: int = 0

    def __post_init__(self) -> None:
        if len(self.records) != len(self.genomes) or len(self.records) > MAX_RECORDS:
            raise ContractError("SearchRun records/genomes misaligned or above MAX_RECORDS")
        if self.config.budget_wu < self.wu_spent:
            raise ContractError("SearchRun spent more than its budget")

    @property
    def label(self) -> str:
        return self.config.label


class _Stop(Exception):
    """A bound other than the work budget ended the run; ``reason`` names it."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# --------------------------------------------------------------------------- exhaustive


def _apply(of: IRType, primitive: str, *args: int) -> IRNode:
    return IRNode(kind=NodeKind.APPLY, type=of, primitive=primitive, args=args)


def _one_register(of: IRType, update: list[IRNode], readout: list[IRNode],
                  aggregation: SessionAggregation) -> ComputationalGenomeV1:
    return build_genome(
        registers=(RegisterSpec(type=of),),
        update=IRProgram(phase=ProgramPhase.UPDATE, nodes=tuple(update),
                         outputs=(len(update) - 1,)),
        readout=IRProgram(phase=ProgramPhase.READOUT, nodes=tuple(readout),
                          outputs=(len(readout) - 1,)),
        aggregation=aggregation,
        mutation="EXHAUSTIVE",
    )


@functools.cache
def enumerate_exhaustive() -> tuple[ComputationalGenomeV1, ...]:
    """EXACTLY 126 one-register genomes, in canonical node order (spec §4.9).

    FLOAT register ``r' = op(r, u(x))``: 12 terms (the 5 float inputs with ``u`` in {id,
    ABS}; the 2 INT inputs through POPCOUNT) x {ADD, MAX, MIN} x 3 aggregations = 108. INT
    register ``r' = op(r, x)``: 2 inputs x {OR, XOR, AND} x 3 aggregations = 18. The node
    order ``(REG r0, INPUT x[, APPLY u], APPLY op(0, last))`` is the one ``phi_oracle_genome()``
    and H2 use, so both are members BY DIGEST.
    """
    float_reg = IRNode(kind=NodeKind.REG, type=IRType.FLOAT)
    int_reg = IRNode(kind=NodeKind.REG, type=IRType.INT)
    leaves = [IRNode(kind=NodeKind.INPUT, type=INPUT_TYPES[source], source=source, index=index)
              for source, index in EXHAUSTIVE_INPUTS]
    terms = [term for leaf in leaves for term in (
        ([leaf], [leaf, _apply(IRType.FLOAT, "ABS", 1)]) if leaf.type is IRType.FLOAT
        else ([leaf, _apply(IRType.FLOAT, "POPCOUNT", 1)],))]
    genomes = [
        _one_register(IRType.FLOAT, [float_reg, *term, _apply(IRType.FLOAT, op, 0, len(term))],
                      [float_reg], aggregation)
        for term in terms for op in _FLOAT_OPS for aggregation in SessionAggregation
    ]
    view = [int_reg, _apply(IRType.FLOAT, "POPCOUNT", 0)]
    genomes += [
        _one_register(IRType.INT, [int_reg, leaf, _apply(IRType.INT, op, 0, 1)], view, aggregation)
        for leaf in leaves if leaf.type is IRType.INT
        for op in _INT_OPS for aggregation in SessionAggregation
    ]
    if len({g.digest for g in genomes}) != EXHAUSTIVE_SIZE:
        raise ContractError(f"exhaustive space has {len(genomes)} genomes, not {EXHAUSTIVE_SIZE}")
    return tuple(genomes)


# --------------------------------------------------------------------------- the loop


class _SearchState:
    """The mutable half of one run. Lives only inside :func:`run_search`."""

    def __init__(self, config: SearchConfig, suite: EvaluationSuite,
                 alphabet: PrimitiveAlphabet) -> None:
        self.config, self.suite, self.alphabet = config, suite, alphabet
        self.meter = WorkMeter(budget=config.budget_wu)  # the ONE meter of this run
        # No EvaluationCache: ``known`` refuses every re-proposal before evaluation, so a
        # per-run cache keyed on the one fixed suite could never be hit (S9-CX-07).
        self.rng = random.Random(config.seed)
        self.fossils = FossilStore()
        self.archive = QualityDiversityArchive(niches=config.niches)
        self.population: list[tuple[ComputationalGenomeV1, FitnessRecord]] = []
        self.records: list[FitnessRecord] = []
        self.genomes: list[ComputationalGenomeV1] = []
        self.wu_at: list[int] = []
        self.known: set[str] = set()
        self.sequence = hashlib.sha256()
        self.evaluations = self.hits = self.evictions = self.fossils_recorded = 0
        self.since_new = 0
        self.initial: int | None = None
        self.stats = {op: [0, 0, 0] for op in VariationOperator}

    def propose_random(self) -> None:
        self.meter.charge(_PROPOSAL_WU)
        self.consider(random_genome(self.rng, alphabet=self.alphabet))

    def propose_variation(self, pool: Sequence[ComputationalGenomeV1]) -> None:
        parent = self.rng.choice(pool)
        operator = _choose_operator(self.rng, self.config.subtractive)
        self.meter.charge(_PROPOSAL_WU)
        if operator is VariationOperator.CROSSOVER:
            other = self.rng.choice(pool)
            mutation = crossover(parent, other, self.rng, alphabet=self.alphabet)
        else:
            mutation = mutate(parent, operator, self.rng, alphabet=self.alphabet)
        counts = self.stats[operator]
        counts[0] += 1
        if mutation.child is None:
            self._stall()
            return
        counts[1] += 1
        if self.consider(mutation.child) in (ArchiveOutcome.NEW_CELL, ArchiveOutcome.IMPROVED):
            counts[2] += 1

    def _stall(self) -> None:
        self.since_new += 1
        if self.since_new >= _STALL_LIMIT:
            raise _Stop("STALLED")

    def consider(self, genome: ComputationalGenomeV1) -> ArchiveOutcome | None:
        """Evaluate a digest not yet seen (and not an avoided fossil); record, archive, fossilise.

        A re-proposed digest is refused BEFORE ``evaluate`` (S9-R7): the bounded evaluation
        cache evicts past :data:`fitness.MAX_CACHE_ENTRIES`, and an evicted duplicate used to
        be re-evaluated at full suite cost only to be thrown away, which taxed the strategy
        that re-proposes most (evolution) at large budgets. ``known`` holds every recorded
        digest and is bounded by :data:`MAX_RECORDS`, so it needs no eviction path.
        """
        if self.config.fossil_avoidance and self.fossils.avoid(genome.digest):
            self._stall()
            return None
        if len(self.records) >= MAX_RECORDS:
            raise _Stop("RECORD_BOUND")
        if genome.digest in self.known:
            # Same bookkeeping as the old cache-hit path, so the determinism digest of every
            # run below the cache capacity is unchanged by this reordering.
            self.sequence.update(genome.digest.encode() + b"\n")
            self.hits += 1
            self._stall()
            return None
        record = evaluate(genome, self.suite, meter=self.meter)
        self.sequence.update(genome.digest.encode() + b"\n")
        self.evaluations += 1
        self.since_new = 0
        self.known.add(genome.digest)
        self.records.append(record)
        self.genomes.append(genome)
        self.wu_at.append(self.meter.spent)
        outcome, _ = self.archive.insert(genome, record, lineage=genome.parent_digests)
        if record.worst_case_ap is not None:
            self.population.append((genome, record))
        if len(self.population) > MAX_POPULATION:  # elitist truncation, eviction counted
            del self.population[min(range(len(self.population)),
                                    key=lambda i: _rank_key(self.population[i][1]))]
            self.evictions += 1
        self._fossilise(genome, record, outcome)
        return outcome

    def _fossilise(self, genome: ComputationalGenomeV1, record: FitnessRecord,
                   outcome: ArchiveOutcome) -> None:
        reason, signature, resource, regression = _fossil_reason(record, outcome)
        if reason is None:
            return
        self.fossils.add(ComputationalFossil(
            genome_hash=genome.digest, niche=niche_of(genome),
            ancestry=tuple(genome.parent_digests)[-16:],
            mutation_history=(genome.mutation,) if genome.mutation else (),
            reason_for_failure=reason, counterexample_signature=signature,
            resource_failure=resource, security_regression=regression, epochs_tested=(),
        ))
        self.fossils_recorded += 1

    def parent_pool(self) -> list[ComputationalGenomeV1]:
        """MAP-Elites draws from the archive; the single-cell GA from its elitist population."""
        if self.config.niches:
            return [elite.genome for elite in self.archive.elites()]
        return [genome for genome, _ in self.population]


def _rank_key(record: FitnessRecord) -> tuple[float, int, int]:
    """Higher is better: worst-case AP, then fewer WU, then fewer bytes."""
    ap = -1.0 if record.worst_case_ap is None else record.worst_case_ap
    return (ap, -record.wu_per_event, -record.state_bytes)


def _fossil_reason(
    record: FitnessRecord, outcome: ArchiveOutcome
) -> tuple[FossilReason | None, str | None, str | None, float | None]:
    limits = DEFAULT_CONSTRAINTS
    if record.wu_per_event > limits.wu_per_event_max or record.state_bytes > limits.ram_bytes_max:
        detail = (f"wu/event {record.wu_per_event} (max {limits.wu_per_event_max}), "
                  f"state bytes {record.state_bytes} (max {limits.ram_bytes_max})")
        return FossilReason.RESOURCE_FAILURE, None, detail, None
    clean, worst = record.clean_ap, record.worst_case_ap
    if clean is not None and worst is not None and clean - worst > _ARGUS_DROP_TOLERANCE:
        return FossilReason.ARGUS_FAILURE, record.worst_variant, None, clean - worst
    if outcome is ArchiveOutcome.REJECTED_WORSE:
        return FossilReason.DOMINATED, None, None, None
    return None, None, None, None


def _choose_operator(rng: random.Random, subtractive: bool) -> VariationOperator:
    """REMOVE with SUBTRACTIVE_SHARE when subtractive; CROSSOVER 0.1; else uniform."""
    if subtractive and rng.random() < SUBTRACTIVE_SHARE:
        return VariationOperator.REMOVE
    if rng.random() < _CROSSOVER_SHARE:
        return VariationOperator.CROSSOVER
    skip = {VariationOperator.CROSSOVER} | ({VariationOperator.REMOVE} if subtractive else set())
    return rng.choice([op for op in VariationOperator if op not in skip])


def _run_evolutionary(state: _SearchState) -> None:
    for _ in range(INITIAL_POPULATION):
        state.propose_random()
    state.initial = len(state.records)
    while True:
        pool = state.parent_pool()
        if pool:
            state.propose_variation(pool)
        else:  # nothing measurable yet: keep drawing from the shared generator
            state.propose_random()


def _run_random(state: _SearchState) -> None:
    while True:
        state.propose_random()


def _run_exhaustive(state: _SearchState) -> None:
    for genome in enumerate_exhaustive():
        state.meter.charge(_PROPOSAL_WU)
        state.consider(genome)
    raise _Stop("EXHAUSTED_SPACE")


_STRATEGIES: dict[SearchStrategy, Callable[[_SearchState], None]] = {
    SearchStrategy.EVOLUTIONARY: _run_evolutionary,
    SearchStrategy.RANDOM: _run_random,
    SearchStrategy.EXHAUSTIVE: _run_exhaustive,
}


def _winner(records: Sequence[FitnessRecord], base_rate: float) -> int | None:
    """Max worst-case train AP among MSSC-satisfying genomes; cost, then order, breaks ties."""
    best: int | None = None
    for index, record in enumerate(records):
        if record.worst_case_ap is None or check_constraints(
            record.objective(), clean_ap=record.clean_ap, base_rate=base_rate
        ).violations:
            continue
        if best is None or _rank_key(record) > _rank_key(records[best]):
            best = index
    return best


def _dense(scores: Sequence[float | None]) -> list[float]:
    return [0.0 if score is None else float(score) for score in scores]


def _ranks(scores: Sequence[float | None]) -> list[int]:
    values = [-math.inf if score is None else float(score) for score in scores]
    order = {value: rank for rank, value in enumerate(sorted(set(values)))}
    return [order[value] for value in values]


def _rediscovered_phi(genomes: Sequence[ComputationalGenomeV1],
                      records: Sequence[FitnessRecord], suite: EvaluationSuite) -> bool:
    """Is some evaluated genome's TRAIN clean score vector rank-identical to the Φ-oracle's?

    Measurement overhead on its own unbounded meter, outside the search budget. Equal AP is
    necessary for rank identity, so only AP-equal genomes are re-scored.
    """
    phi, side, dataset = phi_oracle_genome(), WorkMeter(), suite.clean.dataset
    reference = session_scores(phi, dataset, meter=side)
    reference_ap = average_precision(suite.labels, _dense(reference))
    for genome, record in zip(genomes, records, strict=True):
        if genome.digest == phi.digest:
            return True
        if record.clean_ap is None or reference_ap is None or \
                abs(record.clean_ap - reference_ap) > 1e-9:
            continue
        if _ranks(session_scores(genome, dataset, meter=side)) == _ranks(reference):
            return True
    return False


def run_search(config: SearchConfig, train: EvaluationSuite, *,
               alphabet: PrimitiveAlphabet = SEED_ALPHABET) -> SearchRun:
    """Run one arm on the train suite until a bound stops it. Never sees held-out data."""
    suite = train if config.label_shuffle_seed is None else \
        train.with_shuffled_labels(config.label_shuffle_seed)
    state = _SearchState(config, suite, alphabet)
    before, start = loadavg(), time.perf_counter()
    exhausted, stop_reason = False, ""
    try:
        _STRATEGIES[config.strategy](state)
    except WorkBudgetExceeded:
        exhausted, stop_reason = True, "WORK_BUDGET_EXCEEDED"
    except _Stop as stop:
        stop_reason = stop.reason
    wall, after = time.perf_counter() - start, loadavg()
    initial = len(state.records) if state.initial is None else state.initial
    return SearchRun(
        config=config, evaluations=state.evaluations, cache_hits=state.hits,
        wu_spent=state.meter.spent, budget_exhausted=exhausted,
        records=tuple(state.records), genomes=tuple(state.genomes),
        archive_elites=state.archive.elites(), winner=_winner(state.records, suite.base_rate),
        operator_stats=tuple(OperatorStats(op, *state.stats[op]) for op in VariationOperator),
        population_evictions=state.evictions, fossils_recorded=state.fossils_recorded,
        fossils_avoided=state.fossils.avoided,
        determinism_digest="sha256:" + state.sequence.hexdigest(),
        rediscovered_phi=_rediscovered_phi(state.genomes, state.records, suite),
        wall_seconds=wall, loadavg_before=before, loadavg_after=after,
        wu_at_record=tuple(state.wu_at), stop_reason=stop_reason,
        initial_records=initial if config.strategy is SearchStrategy.EVOLUTIONARY else 0,
    )


# --------------------------------------------------------------------------- held-out


@dataclass(frozen=True, slots=True)
class WinnerReport:
    """A run's winner re-measured on a split the search never saw."""

    run: str
    genome_digest: str  # "" when the run produced no constraint-satisfying winner
    train_worst_case_ap: float | None
    heldout_worst_case_ap: float | None
    heldout_clean_ap: float | None
    gap: float | None  # train_worst_case - heldout_worst_case: the overfitting figure
    wu_per_event: int  # 0 with no winner: there is no computation to cost
    state_bytes: int


def seed_matched(main: Sequence[SearchRun],
                 arm: Sequence[SearchRun]) -> tuple[tuple[SearchRun, SearchRun], ...]:
    """Pairs of runs with the same seed, in seed order. Unmatched runs are left out."""
    by_seed = {run.config.seed: run for run in arm}
    ordered = sorted(main, key=lambda run: run.config.seed)
    return tuple((run, by_seed[run.config.seed]) for run in ordered if run.config.seed in by_seed)


def heldout_report(runs: Sequence[SearchRun], heldout: EvaluationSuite) -> tuple[WinnerReport, ...]:
    """Evaluate each winner on held-out data, on an unbounded meter (measurement, not search)."""
    meter, cache = WorkMeter(), EvaluationCache()
    reports: list[WinnerReport] = []
    for run in runs:
        if run.winner is None:
            reports.append(WinnerReport(run.config.label, "", None, None, None, None, 0, 0))
            continue
        genome, train = run.genomes[run.winner], run.records[run.winner]
        held = evaluate(genome, heldout, meter=meter, cache=cache)
        gap = None if train.worst_case_ap is None or held.worst_case_ap is None \
            else train.worst_case_ap - held.worst_case_ap
        reports.append(WinnerReport(
            run=run.config.label, genome_digest=genome.digest,
            train_worst_case_ap=train.worst_case_ap, heldout_worst_case_ap=held.worst_case_ap,
            heldout_clean_ap=held.clean_ap, gap=gap, wu_per_event=held.wu_per_event,
            state_bytes=held.state_bytes,
        ))
    return tuple(reports)


def _delta(a: WinnerReport, b: WinnerReport) -> float | None:
    if a.heldout_worst_case_ap is None or b.heldout_worst_case_ap is None:
        return None
    return a.heldout_worst_case_ap - b.heldout_worst_case_ap


def _median(values: Sequence[float | None]) -> float | None:
    known = [v for v in values if v is not None]
    return statistics.median(known) if known else None


@dataclass(frozen=True, slots=True)
class StrategyComparison:
    verdict: MechanismVerdict
    per_seed_delta_vs_random: tuple[float | None, ...]
    delta_vs_exhaustive: tuple[float | None, ...]
    median_delta_vs_random: float | None
    median_delta_vs_exhaustive: float | None
    exhaustive_wu: int
    equal_budget_wu: int
    detail: str
    #: Seeds whose evolutionary winner came from variation, not the initial random draw.
    variation_won: int = 0

    def as_detector(self) -> DetectorComparison:
        """The G9.9 record for :data:`EVOLUTIONARY_SEARCH_DEFAULT_ENABLED`."""
        return DetectorComparison(
            mechanism=f"{_MODULE}:EVOLUTIONARY_SEARCH_DEFAULT_ENABLED",
            metric="median held-out worst-case AP delta of the winner (evolutionary - control)",
            value=self.median_delta_vs_random,
            controls=(("random_median_delta", self.median_delta_vs_random),
                      ("exhaustive_median_delta", self.median_delta_vs_exhaustive)),
            verdict=self.verdict,
            fired=self.variation_won,
            detail=self.detail,
        )


def strategy_verdict(
    evolutionary: Sequence[WinnerReport],
    random_reports: Sequence[WinnerReport],
    exhaustive: WinnerReport,
    *,
    exhaustive_wu: int,
    equal_budget_wu: int,
    variation_won: int = 0,
) -> StrategyComparison:
    """The verdict rule alone, on reports already aligned by seed (position i = seed i).

    JUSTIFIED iff the median delta is >= +0.02 vs random AND vs exhaustive, with a positive
    delta on every seed vs both. REJECTED iff either computable median is <= -0.02. Else
    NOT_YET_JUSTIFIED (§4.9): a run with no MSSC-satisfying winner has no delta, so it did not
    beat (named in ``detail``). UNMEASURED only if no run of any strategy has a winner."""
    if len(evolutionary) != len(random_reports):
        raise ContractError("strategy_verdict: evolutionary and random reports must align by seed")
    vs_random = tuple(_delta(e, r) for e, r in zip(evolutionary, random_reports, strict=True))
    vs_exhaustive = tuple(_delta(e, exhaustive) for e in evolutionary)
    med_r, med_e = _median(vs_random), _median(vs_exhaustive)
    all_reports = (*evolutionary, *random_reports, exhaustive)
    if not any(r.genome_digest for r in all_reports):
        verdict = MechanismVerdict.UNMEASURED
    elif any(m is not None and m <= -_STRATEGY_MARGIN for m in (med_r, med_e)):
        verdict = MechanismVerdict.REJECTED
    elif (med_r is not None and med_e is not None and min(med_r, med_e) >= _STRATEGY_MARGIN
          and all(d is not None and d > 0 for d in vs_random + vs_exhaustive)):
        verdict = MechanismVerdict.JUSTIFIED
    else:
        verdict = MechanismVerdict.NOT_YET_JUSTIFIED
    return StrategyComparison(
        verdict=verdict, per_seed_delta_vs_random=vs_random, delta_vs_exhaustive=vs_exhaustive,
        median_delta_vs_random=med_r, median_delta_vs_exhaustive=med_e,
        exhaustive_wu=exhaustive_wu, equal_budget_wu=equal_budget_wu,
        detail=(
            f"evolutionary {[e.heldout_worst_case_ap for e in evolutionary]}; random "
            f"{[r.heldout_worst_case_ap for r in random_reports]}; exhaustive "
            f"{exhaustive.heldout_worst_case_ap} at {exhaustive_wu} WU vs equal budget "
            f"{equal_budget_wu} WU; margin {_STRATEGY_MARGIN}; runs with no MSSC-satisfying "
            f"winner: {[r.run for r in all_reports if not r.genome_digest]}"
        ),
        variation_won=variation_won,
    )


def compare_strategies(
    evolutionary: Sequence[SearchRun],
    random_runs: Sequence[SearchRun],
    exhaustive: SearchRun,
    heldout: EvaluationSuite,
) -> StrategyComparison:
    """Metric: held-out worst-case AP of each run's winner, seed-matched against random."""
    pairs = seed_matched(evolutionary, random_runs)
    evo, rnd = [e for e, _ in pairs], [r for _, r in pairs]
    reports = heldout_report([*evo, *rnd, exhaustive], heldout)
    won = sum(1 for run in evo if run.config.strategy is SearchStrategy.EVOLUTIONARY
              and run.winner is not None and run.winner >= run.initial_records)
    comparison = strategy_verdict(
        reports[: len(evo)], reports[len(evo) : 2 * len(evo)], reports[-1],
        exhaustive_wu=exhaustive.wu_spent,
        equal_budget_wu=max((run.config.budget_wu for run in evo), default=0),
        variation_won=won,
    )
    unmatched = len(evolutionary) + len(random_runs) - 2 * len(pairs)
    if not unmatched:
        return comparison
    return replace(comparison, detail=f"{comparison.detail}; {unmatched} runs unmatched by seed")


# --------------------------------------------------------------------------- null control


class NullVerdict(StrEnum):
    NULL_HELD = "NULL_HELD"
    PRIOR_INFORMATIVE = "PRIOR_INFORMATIVE"
    LEAK_SUSPECTED = "LEAK_SUSPECTED"


@dataclass(frozen=True, slots=True)
class ShuffledLabelControl:
    winner_digest: str | None
    train_ap_on_shuffled: float | None
    heldout_ap: float | None
    permutation_p_value: float | None  # (1 + k) / 201 over held-out label permutations
    prior_percentile: float | None  # winner's held-out AP among unselected random genomes
    verdict: NullVerdict
    detail: str


def null_verdict(p_value: float | None, prior_percentile: float | None) -> NullVerdict:
    """NULL_HELD iff p > 0.05; PRIOR_INFORMATIVE iff significant but below the prior's 95th
    percentile (the search SPACE, not the labels, is informative); else LEAK_SUSPECTED."""
    if p_value is None or p_value > _NULL_ALPHA:
        return NullVerdict.NULL_HELD
    if prior_percentile is not None and prior_percentile < _PRIOR_CUT:
        return NullVerdict.PRIOR_INFORMATIVE
    return NullVerdict.LEAK_SUSPECTED


def _control_pick(run: SearchRun) -> tuple[int | None, str]:
    if run.winner is not None:
        return run.winner, "constraint-satisfying winner"
    measured = [i for i, r in enumerate(run.records) if r.worst_case_ap is not None]
    if not measured:
        return None, "no evaluable genome"
    best = max(measured, key=lambda i: _rank_key(run.records[i]))
    return best, "no genome met the MSSC constraints on shuffled labels; best-effort argmax used"


def _percentile(observed: float, sample: Sequence[float | None]) -> float | None:
    known = [ap for ap in sample if ap is not None]
    if not known:
        return None
    below = sum(ap < observed - _AP_TIE for ap in known)
    ties = sum(abs(ap - observed) <= _AP_TIE for ap in known)
    return (below + 0.5 * ties) / len(known)


def run_shuffled_label_control(
    train: EvaluationSuite,
    heldout: EvaluationSuite,
    *,
    seed: int = 101,
    shuffle_seed: int = 9,
    budget_wu: int = SEARCH_BUDGET_WU,
    strategy: SearchStrategy = SearchStrategy.EVOLUTIONARY,
) -> ShuffledLabelControl:
    """Search on shuffled train labels; the winner must be no better than chance held-out.

    The p-value permutes the TRUE held-out labels 200 times (``p = (1 + k) / 201``, ties
    counted against the search). ``prior_percentile`` places the winner among 64 unselected
    random genomes, separating "the language is informative" from "the selection leaked".
    """
    config = SearchConfig(strategy=strategy, seed=seed, budget_wu=budget_wu,
                          label_shuffle_seed=shuffle_seed)
    run = run_search(config, train)
    index, how = _control_pick(run)
    if index is None:
        return ShuffledLabelControl(None, None, None, None, None, NullVerdict.NULL_HELD, how)
    genome, meter, labels = run.genomes[index], WorkMeter(), heldout.labels

    def heldout_ap(candidate: ComputationalGenomeV1) -> float | None:
        scores = _dense(session_scores(candidate, heldout.clean.dataset, meter=meter))
        return average_precision(labels, scores)

    scores = _dense(session_scores(genome, heldout.clean.dataset, meter=meter))
    observed = average_precision(labels, scores)
    if observed is None:
        raise ContractError("shuffled-label control: the held-out suite has no positives")
    permuter, beaten = random.Random(shuffle_seed * 1_000_003 + seed), 0
    for _ in range(_SHUFFLE_PERMUTATIONS):
        permuted = list(labels)
        permuter.shuffle(permuted)
        ap = average_precision(permuted, scores)
        beaten += ap is not None and ap >= observed - _AP_TIE
    p_value = (1 + beaten) / (_SHUFFLE_PERMUTATIONS + 1)
    prior_rng = random.Random(seed * 7919 + shuffle_seed)
    percentile = _percentile(observed, [heldout_ap(random_genome(prior_rng))
                                        for _ in range(_PRIOR_SAMPLE)])
    return ShuffledLabelControl(
        winner_digest=genome.digest, train_ap_on_shuffled=run.records[index].clean_ap,
        heldout_ap=observed, permutation_p_value=p_value, prior_percentile=percentile,
        verdict=null_verdict(p_value, percentile),
        detail=(
            f"{how}; run {run.config.label}: {run.evaluations} evaluations, {run.wu_spent}/"
            f"{run.config.budget_wu} WU, stop {run.stop_reason}; {beaten}/"
            f"{_SHUFFLE_PERMUTATIONS} held-out label permutations reached the observed AP; "
            f"prior over {_PRIOR_SAMPLE} unselected random genomes"
        ),
    )
