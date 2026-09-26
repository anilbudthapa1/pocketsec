"""D8.4 / PROM-F05 — the PROMETHEUS engine: proposals in, a bounded diverse set of births out.

The generators propose; this module decides which proposals become hypotheses. It runs
every generator under the run's budget, removes duplicates, skips mechanisms the
negative-result memory already refuted, wraps each survivor in a typed genome
(``genome_for``: pre-registered refutation rules, scope = the cluster and the member
episodes read, provenance by digest), selects at most ``max_hypotheses_per_residual`` of
them and records each birth in the theory ledger *before* any held-out data exists for it.

Selection (architecture §10, "Hypothesis Diversity"): :func:`diversity_select` is a greedy
max-min over :func:`mechanism_distance`, seeded by the best TRAIN F1, and keeps at least
``MIN_BENIGN_SHARE`` BENIGN-direction hypotheses when any were proposed. ``diversity=False``
is the control: top-k by TRAIN F1. **Incompatible hypotheses are kept deliberately** — a
MALICIOUS and a BENIGN reading of the same mechanism are two hypotheses, and nothing here
prunes by agreement. The ledger, the vault and replication decide; the engine never does.

Fits are direction-oriented: a BENIGN theory's "true match" is a label-0 episode it
matches (the vault's BENIGN rule reads the same way). They are TRAIN-only and paid for
through the run's meter; a fit already computed for the same mechanism, direction and TRAIN
split is reused (bounded cache, evictions counted), so a baseline that re-proposes the same
3840 singles for every cluster pays for them once.

What it refuses: held-out data (``GenerationContext`` holds TRAIN only), a second birth of an
id the ledger already holds (counted as a duplicate), a birth into a full ledger (counted as
``births_refused``, never a crash), unbounded candidate lists (at most
``MAX_CANDIDATES_PER_GENERATOR`` per generator per call, counted). **The budget is the kill
switch**: when the governor refuses a charge, generation stops cleanly, nothing half-selected
is born, and the report says ``budget_exhausted=True``.
"""

from __future__ import annotations

import hashlib
import math
import sys
from collections import Counter, OrderedDict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage6.resources import WorkBudgetExceeded
from pocketsec.stage8.episode import Episode, FitCounts, fit_counts
from pocketsec.stage8.genome.grammar import Mechanism
from pocketsec.stage8.genome.hypothesis import (
    FOREIGN_GENERATORS,
    MAX_SCOPE_EPISODES,
    Direction,
    GenomeProvenance,
    HypothesisGenome,
    ObservationScope,
    genome_for,
)
from pocketsec.stage8.governor.budget import ResearchGovernor
from pocketsec.stage8.ledger.negative_results import NegativeResultMemory
from pocketsec.stage8.ledger.theory import LedgerError, TheoryLedger
from pocketsec.stage8.prometheus.generators import (
    EXHAUSTIVE_SINGLE_COUNT,
    ExternalProposalGenerator,
    GenerationContext,
    Generator,
    context_digest,
)

__all__ = [
    "ENGINE_FIT_COMPONENT",
    "MAX_CANDIDATES_PER_GENERATOR",
    "MAX_FIT_CACHE",
    "MIN_BENIGN_SHARE",
    "GenerationReport",
    "PrometheusEngine",
    "diversity_select",
    "mechanism_distance",
    "oriented_fit",
]

#: Spec §4.21. Chosen parameter, not a measurement.
MIN_BENIGN_SHARE: float = 0.2
#: Per generator per ``generate`` call; >= the exhaustive baseline so baseline 3 is complete.
MAX_CANDIDATES_PER_GENERATOR: int = EXHAUSTIVE_SINGLE_COUNT
MAX_FIT_CACHE: int = 8192
ENGINE_FIT_COMPONENT: str = "prometheus.engine.fit"

_RELATION_KIND_WEIGHT = 4
_STEP_RELATION_WEIGHT = 5


@dataclass(frozen=True, slots=True)
class GenerationReport:
    """What one ``generate`` call did, per generator. Counts only; decides nothing."""

    births: tuple[str, ...]
    proposed_by: tuple[tuple[str, int], ...]
    kept_by: tuple[tuple[str, int], ...]
    duplicates: int
    dead_ends_skipped: int
    external_refused: int
    budget_exhausted: bool
    candidates_truncated: int = 0  # proposals past MAX_CANDIDATES_PER_GENERATOR, counted
    births_refused: int = 0  # selected genomes the ledger refused (it is full), counted


def mechanism_distance(a: Mechanism, b: Mechanism) -> int:
    """Relation kind (4) + per-step relation (5) + mask Hamming + step-count difference.

    "Step count" counts a REPEATED(k) predicate as k steps, so REPEATED(p,2) and
    REPEATED(p,3) are distinct at distance 1. Symmetric; 0 iff the mechanisms are equal.
    """
    distance = 0
    if (a.relation, a.modifier) != (b.relation, b.modifier):
        distance += _RELATION_KIND_WEIGHT
    for pa, pb in zip(a.steps, b.steps, strict=False):
        if pa.relation != pb.relation:
            distance += _STEP_RELATION_WEIGHT
        distance += ((pa.require_properties ^ pb.require_properties).bit_count()
                     + (pa.forbid_properties ^ pb.forbid_properties).bit_count()
                     + (pa.require_raised ^ pb.require_raised).bit_count())
    return distance + abs(len(a.steps) * a.repeat_min - len(b.steps) * b.repeat_min)


def oriented_fit(counts: FitCounts, direction: Direction) -> FitCounts:
    """The fit read in the theory's own direction: BENIGN counts label-0 matches as true."""
    if direction is Direction.MALICIOUS:
        return counts
    return FitCounts(matched=counts.matched, true_matches=counts.false_matches,
                     false_matches=counts.true_matches, positives=counts.negatives,
                     negatives=counts.positives)


def _f1(fits: Mapping[str, FitCounts], hypothesis_id: str) -> float:
    counts = fits.get(hypothesis_id)
    value = None if counts is None else counts.f1
    return -1.0 if value is None else value


def _rank_key(genome: HypothesisGenome, fits: Mapping[str, FitCounts]) -> tuple[float, int, str]:
    return (-_f1(fits, genome.hypothesis_id), genome.complexity_cost, genome.hypothesis_id)


def diversity_select(genomes: Sequence[HypothesisGenome], fits: Mapping[str, FitCounts], k: int, *,
                     min_benign_share: float = MIN_BENIGN_SHARE) -> tuple[HypothesisGenome, ...]:
    """Greedy max-min mechanism distance, seeded by the best TRAIN F1.

    Ties break by F1, then complexity, then id (deterministic). When BENIGN genomes are
    available, at least ``ceil(min_benign_share x k)`` of them (or all, if fewer) are kept:
    the benign reading of a residual must be in the population that gets tested.
    """
    if isinstance(k, bool) or not isinstance(k, int) or k < 0:
        raise ContractError(f"k must be an int >= 0, got {k!r}")
    if not 0.0 <= min_benign_share <= 1.0:
        raise ContractError(f"min_benign_share must lie in [0, 1], got {min_benign_share!r}")
    pool = sorted(dict.fromkeys(genomes), key=lambda g: _rank_key(g, fits))
    if k == 0 or not pool:
        return ()
    benign_available = sum(1 for g in pool if g.direction is Direction.BENIGN)
    # 1e-9 keeps 0.2 x 5 at exactly 1 despite binary floating point.
    quota = min(benign_available, math.ceil(min_benign_share * k - 1e-9))
    chosen: list[HypothesisGenome] = [pool.pop(0)]
    nearest = {g.hypothesis_id: mechanism_distance(g.proposed_mechanism,
                                                   chosen[0].proposed_mechanism) for g in pool}
    while pool and len(chosen) < k:
        need = quota - sum(1 for g in chosen if g.direction is Direction.BENIGN)
        eligible = pool
        if need > 0 and need >= k - len(chosen):
            eligible = [g for g in pool if g.direction is Direction.BENIGN] or pool
        best = max(eligible, key=lambda g: (nearest[g.hypothesis_id], _f1(fits, g.hypothesis_id),
                                            -g.complexity_cost, _neg_id(g.hypothesis_id)))
        pool.remove(best)
        chosen.append(best)
        for g in pool:
            distance = mechanism_distance(g.proposed_mechanism, best.proposed_mechanism)
            nearest[g.hypothesis_id] = min(nearest[g.hypothesis_id], distance)
    return tuple(chosen)


def _neg_id(hypothesis_id: str) -> tuple[int, ...]:
    """Makes ``max`` prefer the lexically smaller id on a full tie."""
    return tuple(-ord(char) for char in hypothesis_id)


def _top_k(genomes: Sequence[HypothesisGenome], fits: Mapping[str, FitCounts],
           k: int) -> tuple[HypothesisGenome, ...]:
    """The control: the k best TRAIN F1, nothing else considered."""
    return tuple(sorted(dict.fromkeys(genomes), key=lambda g: _rank_key(g, fits))[:k])


@dataclass(slots=True)
class _Tally:
    """Mutable counters of one ``generate`` call."""

    proposed: Counter[str]
    kept: Counter[str]
    duplicates: int = 0
    dead_ends: int = 0
    truncated: int = 0
    refused: int = 0
    exhausted: bool = False


class PrometheusEngine:
    """PROM-F05. The only Stage 8 object that turns proposals into ledger births."""

    def __init__(self, generators: Sequence[Generator], *, ledger: TheoryLedger,
                 negative_memory: NegativeResultMemory | None, governor: ResearchGovernor,
                 diversity: bool = True) -> None:
        held = tuple(generators)
        if not held or any(not isinstance(g, Generator) for g in held):
            raise ContractError("PrometheusEngine needs >= 1 generator with kind and propose()")
        if not isinstance(ledger, TheoryLedger):
            raise ContractError("PrometheusEngine needs the run's TheoryLedger")
        if negative_memory is not None and not isinstance(negative_memory, NegativeResultMemory):
            raise ContractError("negative_memory must be a NegativeResultMemory or None")
        if not isinstance(governor, ResearchGovernor):
            raise ContractError("PrometheusEngine needs the run's ResearchGovernor")
        self._generators = held
        self._ledger = ledger
        self._memory = negative_memory
        self._governor = governor
        self._diversity = bool(diversity)
        self._fits: OrderedDict[tuple[str, str, str], FitCounts] = OrderedDict()
        self._n: Counter[str] = Counter()

    def generate(self, context: GenerationContext) -> GenerationReport:
        """Propose, dedup, skip dead ends, select and record births for one cluster."""
        if not isinstance(context, GenerationContext):
            raise ContractError("generate takes a GenerationContext")
        tally = _Tally(Counter(), Counter())
        candidates: dict[tuple[str, Direction], HypothesisGenome] = {}
        births: tuple[str, ...] = ()
        try:
            for generator in self._generators:
                self._collect(generator, context, candidates, tally)
            genomes = list(candidates.values())
            fits = self._fit_all(genomes, context.train)
            k = self._governor.budget.max_hypotheses_per_residual
            chosen = (diversity_select(genomes, fits, k) if self._diversity
                      else _top_k(genomes, fits, k))
            births = self._record(chosen, tally)
        except WorkBudgetExceeded:
            tally.exhausted = True
            self._n["budget_exhausted"] += 1
        return GenerationReport(
            births=births,
            proposed_by=tuple(sorted(tally.proposed.items())),
            kept_by=tuple(sorted(tally.kept.items())),
            duplicates=tally.duplicates,
            dead_ends_skipped=tally.dead_ends,
            external_refused=sum(g.refusals() for g in self._generators
                                 if isinstance(g, ExternalProposalGenerator)),
            budget_exhausted=tally.exhausted,
            candidates_truncated=tally.truncated,
            births_refused=tally.refused,
        )

    def _collect(self, generator: Generator, context: GenerationContext,
                 candidates: dict[tuple[str, Direction], HypothesisGenome], tally: _Tally) -> None:
        kind = generator.kind
        scope = ObservationScope(
            residual_cluster_ids=(context.cluster.cluster_id,),
            residual_types=context.cluster.types,
            episode_ids=tuple(e.episode_id for e in context.residual_episodes)[:MAX_SCOPE_EPISODES],
        )
        taken = 0
        for mechanism, direction in generator.propose(context, self._governor):
            tally.proposed[kind.value] += 1
            if taken >= MAX_CANDIDATES_PER_GENERATOR:
                tally.truncated += 1
                break  # stop pulling: every further proposal would be paid for and dropped
            key = (mechanism.digest(), direction)
            if key in candidates:
                tally.duplicates += 1
                continue
            # Per reading (F4): a refuted MALICIOUS:M never silences BENIGN:M, or the reverse.
            if self._memory is not None and self._memory.is_dead_end(mechanism, direction):
                tally.dead_ends += 1
                continue
            taken += 1
            candidates[key] = genome_for(
                mechanism, direction=direction, scope=scope,
                provenance=GenomeProvenance(
                    generator=kind,
                    source_digest=_source_digest(generator, context, mechanism),
                    foreign=kind in FOREIGN_GENERATORS,
                    seed=context.seed,
                ),
            )

    def _fit_all(self, genomes: Sequence[HypothesisGenome],
                 train: Sequence[Episode]) -> dict[str, FitCounts]:
        split_key = _split_key(train)
        return {g.hypothesis_id: self._fit(g, train, split_key) for g in genomes}

    def _fit(self, genome: HypothesisGenome, train: Sequence[Episode], split_key: str) -> FitCounts:
        key = (split_key, genome.proposed_mechanism.digest(), genome.direction.value)
        cached = self._fits.get(key)
        if cached is not None and not genome.forbidden_observations:
            self._fits.move_to_end(key)
            self._n["fit_cache_hits"] += 1
            return cached
        meter = self._governor.meter
        before = meter.spent
        try:
            counts = fit_counts(lambda e: genome.decides(e, meter=meter), train, meter=meter)
        finally:
            self._governor.account(ENGINE_FIT_COMPONENT, meter.spent - before)
        oriented = oriented_fit(counts, genome.direction)
        if not genome.forbidden_observations:
            if len(self._fits) >= MAX_FIT_CACHE:
                self._fits.popitem(last=False)
                self._n["fit_cache_evictions"] += 1
            self._fits[key] = oriented
        return oriented

    def _record(self, chosen: Sequence[HypothesisGenome], tally: _Tally) -> tuple[str, ...]:
        births: list[str] = []
        for genome in chosen:
            if self._already_born(genome.hypothesis_id):
                tally.duplicates += 1
                continue
            try:
                self._ledger.record_birth(genome)
            except LedgerError:
                # Not a duplicate (checked above), so the ledger is full of open theories:
                # its own ``births_refused_full`` counter names the bound; the report counts it.
                tally.refused += 1
                continue
            births.append(genome.hypothesis_id)
            tally.kept[genome.provenance.generator.value] += 1
        self._n["births"] += len(births)
        return tuple(births)

    def _already_born(self, hypothesis_id: str) -> bool:
        try:
            self._ledger.status(hypothesis_id)
        except LedgerError:
            return False
        return True

    def stats(self) -> Mapping[str, int]:
        counters = dict(self._n)
        counters["fit_cache_size"] = len(self._fits)
        return MappingProxyType(counters)

    def memory_bytes(self) -> int:
        """The fit cache is the engine's only store (<= MAX_FIT_CACHE entries)."""
        per_entry = sys.getsizeof(("", "", "")) + 3 * 72 + 5 * 28 + 64
        return sys.getsizeof(self._fits) + len(self._fits) * per_entry + sys.getsizeof(self._n)


def _split_key(train: Sequence[Episode]) -> str:
    joined = "|".join(episode.episode_id for episode in train).encode()
    return hashlib.sha256(joined).hexdigest()[:24]


def _source_digest(generator: Generator, context: GenerationContext, mechanism: Mechanism) -> str:
    """The generator's own digest of its input for this mechanism, else the context digest."""
    own = getattr(generator, "source_digest", None)
    if callable(own):
        digest = own(context, mechanism)
        if isinstance(digest, str):
            return digest
    return context_digest(context, generator.kind)
