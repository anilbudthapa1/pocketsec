"""D8.5 / PROM-F06 — the hypothesis ecology: a bounded population, one-change mutation, and MDL.

Architecture §11: ``birth → challenge → mutate → merge/split → experiment → survive/falsify →
fossilize``. PROMETHEUS proposes; this module lets a proposal's close relatives compete with it on
TRAIN before anything is registered, under three pressures that stop the search from drifting into
narrative:

- **Mutation changes exactly one thing** (§11): one property bit, one raised bit, one step's
  relation to a sibling in the same ``RelationFamily``, the mechanism's relation kind, or the
  repeat count by one. Unconstrained genetic programming is not built — a child two edits away
  from its parent would be a new idea wearing an old id.
- **MDL acceptance** (§12): a child that costs more description bits than its parent joins only if
  its TRAIN f1 rises by at least :data:`MDL_GAIN_PER_BIT` per extra bit; a child that costs fewer
  joins if it loses no more than that per bit saved. ``mdl=False`` is the control: any f1 gain.
- **A bounded population with recorded eviction.** At :data:`MAX_POPULATION` the lowest
  :class:`TheoryScore` total leaves and its ledger status becomes ``FOSSILIZED`` (counted).

What it refuses to do:

- **Look past TRAIN.** Every scoring path refuses a non-TRAIN episode (``ContractError``); the
  vault's splits never pass through here.
- **Create a hypothesis off the record.** Every child — accepted, rejected or evicted — is born in
  the :class:`TheoryLedger` first, with its parent link and a MUTATION/MERGE/SPLIT generator, so
  the number of hypotheses the search *considered* is on the record, not only the winners.
- **Decide survival.** The score orders and evicts; only the holdout vault can mark a theory
  SURVIVED or FALSIFIED. The score's nine terms are research objectives (§13, "must be calibrated
  and ablated"): ``ScoreMode.FIT_ONLY`` is their control, and every weight is 1 by choice.
- **Grow a branch forever.** A child deeper than ``max_depth`` edits from a PROMETHEUS birth is
  refused and counted.

Every scoring pass is charged to the run's :class:`ResearchGovernor` *before* the work runs, so a
runaway evolution hits the work budget (``WorkBudgetExceeded`` propagates), not the host.
"""

from __future__ import annotations

import hashlib
import math
import random
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from enum import StrEnum
from types import MappingProxyType

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.ssir.relations import Relation, family_of
from pocketsec.stage8.episode import Episode, FitCounts, Split
from pocketsec.stage8.genome.grammar import (
    MAX_REPEAT, PROPERTY_BITS, RAISED_BITS, Mechanism, MechanismRelation, Modifier, StepPredicate,
)
from pocketsec.stage8.genome.hypothesis import (
    MAX_FORBIDDEN, MAX_SCOPE_EPISODES, MAX_SCOPE_RESIDUALS, Direction, FalsifierKind,
    GeneratorKind, GenomeProvenance, HypothesisGenome, ObservationScope, genome_for,
)
from pocketsec.stage8.governor.budget import ResearchGovernor
from pocketsec.stage8.ledger.theory import LedgerError, LedgerEventKind, TheoryLedger, TheoryStatus

__all__ = [
    "COMPLEXITY_SCALE_BITS", "GENERATIONS", "MAX_BRANCH_DEPTH", "MAX_MERGE_ATTEMPTS",
    "MAX_MUTATIONS_PER_GENERATION", "MAX_POPULATION", "MDL_GAIN_PER_BIT", "EvolutionReport",
    "HypothesisPopulation", "MutationKind", "ScoreMode", "TheoryScore", "mdl_accepts",
    "neighbours",
]

#: §4.21. Chosen parameters, not measurements.
MAX_POPULATION: int = 256
MAX_BRANCH_DEPTH: int = 4
MAX_MUTATIONS_PER_GENERATION: int = 64
GENERATIONS: int = 3
MDL_GAIN_PER_BIT: float = 0.01
#: The complexity term is ``complexity_cost / 64`` (spec D8.5).
COMPLEXITY_SCALE_BITS: int = 64
#: Merge pairs tried per generation before giving up. Chosen, not measured.
MAX_MERGE_ATTEMPTS: int = 8

#: Float slack for the MDL comparisons, so 0.03 − 0.02 ≥ 0.01 is not lost to rounding.
_MDL_EPSILON = 1e-12
_TWO_STEP = (MechanismRelation.PRECEDES, MechanismRelation.CO_OCCURS, MechanismRelation.WITHOUT)
_UNSCORED = -math.inf
#: The five TheoryScore terms that add to ``total``; the other four subtract.
_GAINS = ("predictive_fit", "causal_coherence", "falsification_survival", "cross_epoch",
          "independent_evidence")


class MutationKind(StrEnum):
    """The five one-change edits (§11). Each changes exactly one thing."""

    TOGGLE_PROPERTY = "toggle_property"
    TOGGLE_RAISED = "toggle_raised"
    SIBLING_RELATION = "sibling_relation"
    RELATION_KIND = "relation_kind"
    REPEAT_COUNT = "repeat_count"


class ScoreMode(StrEnum):
    FULL = "full"
    FIT_ONLY = "fit_only"  # the control: total = predictive fit alone


@dataclass(frozen=True, slots=True)
class TheoryScore:
    """§13, one named term each, all on TRAIN. ``total`` = the five gains − the four costs."""

    predictive_fit: float
    causal_coherence: float
    falsification_survival: float
    cross_epoch: float
    independent_evidence: float
    complexity: float
    contradictions: float
    visibility_dependence: float
    adversarial_fragility: float
    total: float

    def __post_init__(self) -> None:
        for name in self.__slots__:
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, float) or not math.isfinite(value):
                raise ContractError(f"TheoryScore.{name} must be a finite float, got {value!r}")


@dataclass(frozen=True, slots=True)
class EvolutionReport:
    """What one :meth:`HypothesisPopulation.evolve` call did — the firing counts of lesson 1."""

    generations: int
    children: int
    accepted: int
    rejected_mdl: int
    merges: int
    splits: int
    evicted: int
    depth_refused: int


def mdl_accepts(
    *,
    parent_bits: int,
    parent_f1: float,
    child_bits: int,
    child_f1: float,
    mdl: bool = True,
    gain_per_bit: float = MDL_GAIN_PER_BIT,
) -> bool:
    """The §12 acceptance rule, exposed so both directions (and the control) are testable.

    More bits: accept iff ``f1 gain ≥ gain_per_bit × extra bits``. Fewer or equal bits: accept iff
    ``f1 loss ≤ gain_per_bit × bits saved``. ``mdl=False`` (control): accept iff f1 strictly rises.
    """
    if not math.isfinite(gain_per_bit) or gain_per_bit < 0.0:
        raise ContractError(f"gain_per_bit must be finite and >= 0, got {gain_per_bit}")
    gain = child_f1 - parent_f1
    if not mdl:
        return gain > _MDL_EPSILON
    delta_bits = child_bits - parent_bits
    if delta_bits > 0:
        return gain + _MDL_EPSILON >= gain_per_bit * delta_bits
    return -gain <= gain_per_bit * (-delta_bits) + _MDL_EPSILON


# --- one-change neighbours -----------------------------------------------------------


def _try_mechanism(**fields: object) -> Mechanism | None:
    try:
        return Mechanism(**fields)  # type: ignore[arg-type]
    except ContractError:  # the grammar refuses this edit (GrammarError): not a neighbour
        return None


def _with_step(mechanism: Mechanism, index: int, step: StepPredicate) -> Mechanism | None:
    steps = tuple(step if i == index else s for i, s in enumerate(mechanism.steps))
    return _try_mechanism(
        relation=mechanism.relation, steps=steps,
        modifier=mechanism.modifier, repeat_min=mechanism.repeat_min,
    )


def _try_step(step: StepPredicate, **changes: int) -> StepPredicate | None:
    try:
        return replace(step, **changes)
    except ContractError:
        return None


def _step_edits(step: StepPredicate, kind: MutationKind) -> list[StepPredicate | None]:
    if kind is MutationKind.TOGGLE_PROPERTY:
        # One require bit; bits the step forbids are skipped (require and forbid stay disjoint).
        return [
            _try_step(step, require_properties=step.require_properties ^ (1 << bit))
            for bit in range(PROPERTY_BITS) if not step.forbid_properties >> bit & 1
        ]
    if kind is MutationKind.TOGGLE_RAISED:
        return [_try_step(step, require_raised=step.require_raised ^ (1 << bit))
                for bit in range(RAISED_BITS)]
    family = family_of(Relation(step.relation))
    return [_try_step(step, relation=int(rel)) for rel in Relation
            if rel != step.relation and family_of(rel) is family]


def neighbours(mechanism: Mechanism, kind: MutationKind) -> tuple[Mechanism, ...]:
    """Every mechanism exactly one ``kind`` edit away from ``mechanism``, in a fixed order."""
    found: list[Mechanism | None] = []
    if kind in (MutationKind.TOGGLE_PROPERTY, MutationKind.TOGGLE_RAISED,
                MutationKind.SIBLING_RELATION):
        for index, step in enumerate(mechanism.steps):
            found.extend(
                None if edited is None else _with_step(mechanism, index, edited)
                for edited in _step_edits(step, kind)
            )
    elif kind is MutationKind.RELATION_KIND and len(mechanism.steps) == 2:
        found.extend(
            _try_mechanism(relation=relation, steps=mechanism.steps,
                           modifier=mechanism.modifier, repeat_min=mechanism.repeat_min)
            for relation in _TWO_STEP if relation is not mechanism.relation
        )
    elif kind is MutationKind.REPEAT_COUNT and mechanism.relation is MechanismRelation.SINGLE:
        # Count 1 is the NONE modifier; 2 … MAX_REPEAT is REPEATED(k). One step either way.
        for count in (mechanism.repeat_min - 1, mechanism.repeat_min + 1):
            if 1 <= count <= MAX_REPEAT:
                modifier = Modifier.NONE if count == 1 else Modifier.REPEATED
                found.append(_try_mechanism(relation=mechanism.relation, steps=mechanism.steps,
                                            modifier=modifier, repeat_min=count))
    return tuple(item for item in found if item is not None and item != mechanism)


# --- TRAIN evaluation ------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _TrainEval:
    counts: FitCounts
    coherent: bool
    cross_epoch: float
    independent: float
    contradictions: float
    visibility: float

    @property
    def f1(self) -> float:
        return float(self.counts.f1) if self.counts.f1 is not None else 0.0


def _share(numerator: int, denominator: int) -> float:
    return min(1.0, numerator / denominator) if denominator > 0 else 0.0


def _evaluate(genome: HypothesisGenome, train: Sequence[Episode]) -> _TrainEval:
    """One pass over TRAIN: the fit counts and the per-episode inputs of the score terms.

    Counts are direction-aware: a BENIGN-direction theory's "positive" is a label-0 episode.
    Unlabelled episodes are skipped, as in ``fit_counts``.
    """
    target = 1 if genome.direction is Direction.MALICIOUS else 0
    necessary = genome.necessary_conditions
    satisfied = [False] * len(necessary)
    matched = true_matches = positives = negatives = blocked = incomplete = 0
    epochs: set[int] = set()
    epochs_hit: set[int] = set()
    lineages: set[frozenset[str]] = set()
    for episode in train:
        if episode.label is None:
            continue
        positive = episode.label == target
        positives += positive
        negatives += not positive
        epochs.add(episode.context.epoch_id)
        fires = genome.decides(episode)
        if not fires:
            # A true episode the mechanism matches but a forbidden observation vetoed.
            if positive and genome.forbidden_observations and \
                    genome.proposed_mechanism.matches(episode.steps):
                blocked += 1
            continue
        matched += 1
        incomplete += any(step.observation_incomplete for step in episode.steps)
        if positive:
            true_matches += 1
            epochs_hit.add(episode.context.epoch_id)
            lineages.add(frozenset(step.source_group for step in episode.steps))
            for index, predicate in enumerate(necessary):
                satisfied[index] = satisfied[index] or any(predicate.matches(s) for s in episode.steps)
    counts = FitCounts(matched=matched, true_matches=true_matches,
                       false_matches=matched - true_matches, positives=positives,
                       negatives=negatives)
    return _TrainEval(
        counts=counts,
        coherent=bool(necessary) and all(satisfied),
        cross_epoch=_share(len(epochs_hit), len(epochs)),
        independent=_share(len(lineages), true_matches),
        contradictions=_share(blocked, matched) if matched else float(blocked > 0),
        visibility=_share(incomplete, matched),
    )


def _digest(*parts: str) -> str:
    return "sha256:" + hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def _union(first: Sequence[str], second: Sequence[str], cap: int) -> tuple[tuple[str, ...], bool]:
    merged = tuple(dict.fromkeys((*first, *second)))
    return merged[:cap], len(merged) > cap


class HypothesisPopulation:
    """PROM-F06. A bounded population of PROPOSED theories competing on TRAIN."""

    def __init__(
        self,
        *,
        ledger: TheoryLedger,
        governor: ResearchGovernor,
        capacity: int = MAX_POPULATION,
        max_depth: int = MAX_BRANCH_DEPTH,
        mdl: bool = True,
        score_mode: ScoreMode = ScoreMode.FULL,
        mdl_gain_per_bit: float = MDL_GAIN_PER_BIT,
        max_mutations_per_generation: int = MAX_MUTATIONS_PER_GENERATION,
    ) -> None:
        if not isinstance(ledger, TheoryLedger) or not isinstance(governor, ResearchGovernor):
            raise ContractError("HypothesisPopulation needs a TheoryLedger and a ResearchGovernor")
        for name, value, low in (("capacity", capacity, 1), ("max_depth", max_depth, 0),
                                 ("max_mutations_per_generation", max_mutations_per_generation, 0)):
            if isinstance(value, bool) or not isinstance(value, int) or value < low:
                raise ContractError(f"HypothesisPopulation.{name} must be an int >= {low}")
        if not isinstance(score_mode, ScoreMode) or not isinstance(mdl, bool):
            raise ContractError("score_mode must be a ScoreMode and mdl a bool")
        mdl_accepts(parent_bits=0, parent_f1=0.0, child_bits=0, child_f1=0.0,
                    gain_per_bit=mdl_gain_per_bit)  # validates the parameter once, here
        self._ledger, self._governor = ledger, governor
        self._capacity, self._max_depth = capacity, max_depth
        self._mdl, self._score_mode = mdl, score_mode
        self._gain_per_bit, self._max_mutations = float(mdl_gain_per_bit), max_mutations_per_generation
        self._members: dict[str, HypothesisGenome] = {}
        self._order: dict[str, int] = {}  # insertion sequence: the eviction tie-break
        self._depth: dict[str, int] = {}
        self._mechanisms: set[tuple[str, str]] = set()  # (mechanism digest, direction) held
        self._bytes: dict[str, int] = {}
        self._scores: dict[str, TheoryScore] = {}
        self._fits: dict[str, float] = {}
        self._pending_depth: dict[str, int] = {}  # children not yet added; ≤ capacity, FIFO
        self._train: tuple[Episode, ...] = ()
        self._train_steps = self._sequence = 0
        self._counters: dict[str, int] = dict.fromkeys(
            ("added", "duplicates", "duplicate_mechanisms", "evicted", "fossilized",
             "evicted_not_proposed", "births", "births_refused", "children_already_born",
             "mutations_attempted", "mutations_inapplicable", "depth_refused", "accepted",
             "rejected_mdl", "merges", "merges_refused", "splits", "scope_truncated",
             "pending_depth_evicted", "scored", "evicted_folded", "screen_terms_refreshed"), 0)

    # --- membership --------------------------------------------------------------

    def add(self, genome: HypothesisGenome) -> bool:
        """Insert ``genome`` (born in the ledger first if it is not yet); ``False`` if refused.

        Full → the lowest :class:`TheoryScore` total among the members *and the newcomer*
        leaves (unscored counts as lowest, oldest first) and is fossilized; if that is the
        newcomer, the answer is ``False``.
        """
        if not isinstance(genome, HypothesisGenome):
            raise ContractError(f"HypothesisPopulation.add takes a HypothesisGenome, got {type(genome)}")
        hid = genome.hypothesis_id
        if hid in self._members:
            self._counters["duplicates"] += 1
            return False
        if self._mechanism_key(genome) in self._mechanisms:
            self._counters["duplicate_mechanisms"] += 1
            return False
        depth = self._pending_depth.pop(hid, None)
        if depth is None:
            depth = 1 + max((self._depth.get(p, 0) for p in genome.parent_hypotheses), default=-1)
        if depth > self._max_depth:
            self._counters["depth_refused"] += 1
            return False
        if not self._born(hid) and not self._birth(genome):
            return False
        if self._train and hid not in self._scores:
            self._score_genome(genome)
        if len(self._members) >= self._capacity:
            victim = self._lowest(extra=hid)
            if victim == hid:
                self._forget_scores(hid)
                self._counters["evicted"] += 1
                self._fossilize(hid, "population_full_newcomer_lowest")
                return False
            self._remove(victim)
            self._fossilize(victim, "population_evicted")
        self._insert(genome, depth)
        return True

    def _lowest(self, *, extra: str) -> str:
        order = {**self._order, extra: self._sequence}
        candidates = (*self._members, extra)
        return min(candidates, key=lambda h: (self._total(h), order[h]))

    def _total(self, hypothesis_id: str) -> float:
        score = self._scores.get(hypothesis_id)
        return _UNSCORED if score is None else score.total

    def _insert(self, genome: HypothesisGenome, depth: int) -> None:
        hid = genome.hypothesis_id
        self._members[hid] = genome
        self._order[hid] = self._sequence
        self._sequence += 1
        self._depth[hid] = depth
        self._mechanisms.add(self._mechanism_key(genome))
        self._bytes[hid] = len(genome.canonical_bytes())
        self._counters["added"] += 1

    def _remove(self, hypothesis_id: str) -> None:
        genome = self._members.pop(hypothesis_id)
        for store in (self._order, self._depth, self._bytes, self._scores, self._fits):
            store.pop(hypothesis_id, None)
        self._mechanisms.discard(self._mechanism_key(genome))
        self._counters["evicted"] += 1

    def _forget_scores(self, hypothesis_id: str) -> None:
        for store in (self._scores, self._fits, self._pending_depth):
            store.pop(hypothesis_id, None)

    @staticmethod
    def _mechanism_key(genome: HypothesisGenome) -> tuple[str, str]:
        return (genome.proposed_mechanism.digest(), str(genome.direction))

    # --- the ledger --------------------------------------------------------------

    def _born(self, hypothesis_id: str) -> bool:
        try:
            self._ledger.status(hypothesis_id)
        except (LedgerError, KeyError):
            return False
        return True

    def _birth(self, genome: HypothesisGenome) -> bool:
        try:
            self._ledger.record_birth(genome)
        except LedgerError:  # the ledger is full of open theories: refused, counted
            self._counters["births_refused"] += 1
            return False
        self._counters["births"] += 1
        return True

    def _fossilize(self, hypothesis_id: str, reason: str) -> None:
        # Only an open PROPOSED theory can be fossilized by the ecology (the ledger's legal
        # transitions); a registered one keeps its status and the eviction is still counted.
        # A member whose terminal record the ledger has already folded into negative memory
        # (MAX_THEORIES reached) has no status left to set: its eviction is counted apart,
        # never allowed to crash a long-lived run (found by run_endurance at cycle 8).
        try:
            proposed = self._ledger.status(hypothesis_id) is TheoryStatus.PROPOSED
        except LedgerError:
            self._counters["evicted_folded"] += 1
            return
        if proposed:
            self._ledger.set_status(hypothesis_id, TheoryStatus.FOSSILIZED, reason=reason)
        self._counters["fossilized" if proposed else "evicted_not_proposed"] += 1

    # --- children ----------------------------------------------------------------

    def _child(self, parents: Sequence[HypothesisGenome], mechanism: Mechanism,
               generator: GeneratorKind, *, scope: ObservationScope | None = None,
               forbidden: tuple[StepPredicate, ...] | None = None) -> HypothesisGenome | None:
        """Build, depth-check and birth one child; ``None`` (counted) when refused."""
        depth = 1 + max(self._depth.get(p.hypothesis_id, 0) for p in parents)
        if depth > self._max_depth:
            self._counters["depth_refused"] += 1
            return None
        first = parents[0]
        parent_ids = tuple(p.hypothesis_id for p in parents)
        provenance = GenomeProvenance(
            generator=generator,
            source_digest=_digest(str(generator), *parent_ids, mechanism.digest()),
            foreign=False,  # MUTATION/MERGE/SPLIT are local generators; the parent link keeps ancestry
            seed=first.provenance.seed,
        )
        child = genome_for(
            mechanism, direction=first.direction,
            scope=first.observation_scope if scope is None else scope,
            provenance=provenance, parents=parent_ids,
            competing=first.competing_explanations,
            forbidden=first.forbidden_observations if forbidden is None else forbidden,
            falsifiers=first.falsification_tests, predictions=first.predicted_observations,
            visibility=first.visibility_assumptions,
            information_requests=first.information_requests,
        )
        if self._born(child.hypothesis_id):
            self._counters["children_already_born"] += 1
            return None
        if not self._birth(child):
            return None
        self._remember_depth(child.hypothesis_id, depth)
        return child

    def _remember_depth(self, hypothesis_id: str, depth: int) -> None:
        if len(self._pending_depth) >= self._capacity:
            self._pending_depth.pop(next(iter(self._pending_depth)))
            self._counters["pending_depth_evicted"] += 1
        self._pending_depth[hypothesis_id] = depth

    def _member(self, hypothesis_id: str) -> HypothesisGenome:
        genome = self._members.get(hypothesis_id)
        if genome is None:
            raise ContractError(f"{hypothesis_id!r} is not in the population")
        return genome

    def mutate(
        self, hypothesis_id: str, kind: MutationKind, *, rng: random.Random
    ) -> HypothesisGenome | None:
        """One ``kind`` edit of a member, born in the ledger; ``None`` if none applies.

        The child is **not** inserted: :meth:`evolve` (or the caller) decides by MDL and calls
        :meth:`add`. A child that is never added stays PROPOSED in the ledger unless fossilized.
        """
        parent = self._member(hypothesis_id)
        if not isinstance(kind, MutationKind):
            raise ContractError(f"mutate needs a MutationKind, got {kind!r}")
        self._counters["mutations_attempted"] += 1
        self._governor.charge("ecology", 1)
        options = neighbours(parent.proposed_mechanism, kind)
        if not options:
            self._counters["mutations_inapplicable"] += 1
            return None
        return self._child((parent,), rng.choice(options), GeneratorKind.MUTATION)

    def merge(
        self, a: str, b: str, *, train: Sequence[Episode] | None = None
    ) -> HypothesisGenome | None:
        """Two SINGLE members → ``PRECEDES`` in the order TRAIN shows most often (§11).

        ``train`` defaults to the episodes of the last :meth:`evolve`/:meth:`score`. Refused
        (``None``, counted) for different directions, non-SINGLE parents, a pair that never
        co-occurs in one actor on TRAIN, or a forbidden set past ``MAX_FORBIDDEN``.
        """
        first, second = self._member(a), self._member(b)
        episodes = self._train if train is None else self._bind(train)
        simple = all(g.proposed_mechanism.relation is MechanismRelation.SINGLE
                     and g.proposed_mechanism.modifier is Modifier.NONE for g in (first, second))
        forbidden = tuple(dict.fromkeys((*first.forbidden_observations,
                                         *second.forbidden_observations)))
        if a == b or not simple or first.direction is not second.direction \
                or len(forbidden) > MAX_FORBIDDEN:
            self._counters["merges_refused"] += 1
            return None
        step_a, step_b = first.proposed_mechanism.steps[0], second.proposed_mechanism.steps[0]
        forward, backward = self._order_votes(step_a, step_b, episodes)
        if forward == backward == 0:
            self._counters["merges_refused"] += 1
            return None
        ordered = (step_a, step_b) if forward >= backward else (step_b, step_a)
        mechanism = _try_mechanism(relation=MechanismRelation.PRECEDES, steps=ordered)
        if mechanism is None:
            self._counters["merges_refused"] += 1
            return None
        child = self._child((first, second), mechanism, GeneratorKind.MERGE,
                            scope=self._merged_scope(first, second), forbidden=forbidden)
        self._counters["merges"] += child is not None
        return child

    def _order_votes(
        self, a: StepPredicate, b: StepPredicate, train: Sequence[Episode]
    ) -> tuple[int, int]:
        """Episodes in which some actor shows ``a`` before ``b``, and ``b`` before ``a``."""
        self._governor.charge("ecology", 2 * sum(len(e.steps) for e in train))
        forward = backward = 0
        for episode in train:
            at_a: dict[int, list[int]] = {}
            at_b: dict[int, list[int]] = {}
            for index, step in enumerate(episode.steps):
                for predicate, where in ((a, at_a), (b, at_b)):
                    if predicate.matches(step):
                        where.setdefault(step.actor_slot, []).append(index)
            shared = at_a.keys() & at_b.keys()
            forward += any(at_a[s][0] < at_b[s][-1] for s in shared)
            backward += any(at_b[s][0] < at_a[s][-1] for s in shared)
        return forward, backward

    def _merged_scope(self, first: HypothesisGenome, second: HypothesisGenome) -> ObservationScope:
        one, two = first.observation_scope, second.observation_scope
        clusters, cut_c = _union(one.residual_cluster_ids, two.residual_cluster_ids,
                                 MAX_SCOPE_RESIDUALS)
        episodes, cut_e = _union(one.episode_ids, two.episode_ids, MAX_SCOPE_EPISODES)
        self._counters["scope_truncated"] += cut_c or cut_e
        return ObservationScope(residual_cluster_ids=clusters,
                                residual_types=one.residual_types | two.residual_types,
                                episode_ids=episodes)

    def split(self, hypothesis_id: str) -> tuple[HypothesisGenome, ...]:
        """A 2-step member → one SINGLE per step (§11), each born; ``()`` for a SINGLE."""
        parent = self._member(hypothesis_id)
        mechanism = parent.proposed_mechanism
        if len(mechanism.steps) != 2:
            return ()
        children: list[HypothesisGenome] = []
        for step in dict.fromkeys(mechanism.steps):
            single = _try_mechanism(relation=MechanismRelation.SINGLE, steps=(step,))
            child = None if single is None else self._child((parent,), single, GeneratorKind.SPLIT)
            if child is not None:
                children.append(child)
        self._counters["splits"] += bool(children)
        return tuple(children)

    # --- scoring -----------------------------------------------------------------

    def _bind(self, train: Sequence[Episode]) -> tuple[Episode, ...]:
        episodes = tuple(train)
        for episode in episodes:
            if not isinstance(episode, Episode) or episode.split is not Split.TRAIN:
                raise ContractError("the population reads TRAIN episodes only")
        if episodes != self._train:
            self._train = episodes
            self._train_steps = sum(len(e.steps) for e in episodes)
            self._scores.clear()  # a score is a statement about one TRAIN set
            self._fits.clear()
        return episodes

    def score(self, hypothesis_id: str, train: Sequence[Episode]) -> TheoryScore:
        """The §13 score of a member on ``train`` (cached until TRAIN changes)."""
        genome = self._member(hypothesis_id)
        self._bind(train)
        cached = self._scores.get(hypothesis_id)
        return cached if cached is not None else self._score_genome(genome)

    def _score_genome(self, genome: HypothesisGenome) -> TheoryScore:
        mechanism = genome.proposed_mechanism
        # Paid before the work: one predicate test per step per mechanism/forbidden predicate.
        per_step = len(mechanism.steps) + len(genome.forbidden_observations) + 1
        self._governor.charge("ecology", self._train_steps * per_step)
        evaluation = _evaluate(genome, self._train)
        survival, fragility = self._screen_terms(genome.hypothesis_id)
        terms = {
            "predictive_fit": evaluation.f1,
            "causal_coherence": 1.0 if evaluation.coherent else 0.0,
            "falsification_survival": survival,
            "cross_epoch": evaluation.cross_epoch,
            "independent_evidence": evaluation.independent,
            "complexity": genome.complexity_cost / COMPLEXITY_SCALE_BITS,
            "contradictions": evaluation.contradictions,
            "visibility_dependence": evaluation.visibility,
            "adversarial_fragility": fragility,
        }
        score = self._assemble(terms)
        self._scores[genome.hypothesis_id] = score
        self._fits[genome.hypothesis_id] = evaluation.f1
        self._counters["scored"] += 1
        return score

    def _assemble(self, terms: Mapping[str, float]) -> TheoryScore:
        if self._score_mode is ScoreMode.FIT_ONLY:
            total = terms["predictive_fit"]
        else:
            total = math.fsum(terms[k] for k in _GAINS) - math.fsum(
                v for k, v in terms.items() if k not in _GAINS)
        return TheoryScore(**{k: float(v) for k, v in terms.items()}, total=float(total))

    def refresh_screen_terms(self, hypothesis_id: str) -> TheoryScore | None:
        """Re-read the two ledger-backed terms of a cached score after its screens ran (F3).

        A score is cached when the genome is added or evolved, which is before ``screen()``
        writes any CHALLENGE_RESULT; without this refresh ``falsification_survival`` and
        ``adversarial_fragility`` read 0.0 for every candidate at ranking, i.e. are INERT. The
        TRAIN terms are kept (TRAIN did not change), so nothing is re-evaluated or re-charged.
        ``None`` when nothing is cached for the id (it will be scored fresh when asked).
        """
        cached = self._scores.get(hypothesis_id)
        if cached is None:
            return None
        survival, fragility = self._screen_terms(hypothesis_id)
        terms = {name: getattr(cached, name) for name in TheoryScore.__slots__ if name != "total"}
        terms["falsification_survival"], terms["adversarial_fragility"] = survival, fragility
        score = self._assemble(terms)
        self._scores[hypothesis_id] = score
        self._counters["screen_terms_refreshed"] += 1
        return score

    def _screen_terms(self, hypothesis_id: str) -> tuple[float, float]:
        """(share of recorded challenge screens passed, 1 − latest invariance agreement).

        Read from the ledger's CHALLENGE_RESULT entries; no screen yet → survival 0 (nothing has
        been survived) and fragility 0 (not measured, so not charged).
        """
        passed = total = 0
        agreement: float | None = None
        for entry in self._ledger.entries():
            if entry.kind is not LedgerEventKind.CHALLENGE_RESULT \
                    or entry.hypothesis_id != hypothesis_id:
                continue
            total += 1
            passed += bool(entry.payload.get("passed", False))
            statistic = entry.payload.get("statistic")
            if entry.payload.get("kind") == FalsifierKind.COUNTERFACTUAL_INVARIANCE \
                    and isinstance(statistic, float) and 0.0 <= statistic <= 1.0:
                agreement = statistic
        survival = passed / total if total else 0.0
        return survival, 0.0 if agreement is None else 1.0 - agreement

    def _fit_of(self, genome: HypothesisGenome) -> float:
        fit = self._fits.get(genome.hypothesis_id)
        if fit is None:
            self._score_genome(genome)
            fit = self._fits[genome.hypothesis_id]
        return fit

    # --- evolution ---------------------------------------------------------------

    def evolve(self, train: Sequence[Episode], *, rng: random.Random) -> EvolutionReport:
        """:data:`GENERATIONS` rounds of mutation, one merge and one split, under MDL."""
        self._bind(train)
        before = dict(self._counters)
        generations = children = accepted = rejected = 0
        for member in tuple(self._members.values()):
            self._fit_of(member)
        tried_pairs: set[tuple[str, str]] = set()
        tried_splits: set[str] = set()
        for _ in range(GENERATIONS):
            if not self._members:
                break
            generations += 1
            proposals: list[tuple[HypothesisGenome, HypothesisGenome]] = []
            for _ in range(self._max_mutations):
                parent_id = rng.choice(sorted(self._members))
                parent = self._members[parent_id]
                child = self.mutate(parent_id, rng.choice(tuple(MutationKind)), rng=rng)
                if child is not None:
                    proposals.append((parent, child))
            proposals.extend(self._merge_round(tried_pairs))
            proposals.extend(self._split_round(tried_splits))
            for parent, child in proposals:
                children += 1
                if self._consider(parent, child):
                    accepted += 1
                else:
                    rejected += 1
        after = self._counters
        return EvolutionReport(
            generations=generations, children=children, accepted=accepted, rejected_mdl=rejected,
            merges=after["merges"] - before["merges"], splits=after["splits"] - before["splits"],
            evicted=after["evicted"] - before["evicted"],
            depth_refused=after["depth_refused"] - before["depth_refused"],
        )

    def _consider(self, parent: HypothesisGenome, child: HypothesisGenome) -> bool:
        """MDL-test a born child against its parent; add it or fossilize it. True iff MDL passed."""
        parent_f1 = self._fits.get(parent.hypothesis_id)
        if parent_f1 is None:  # the parent was evicted meanwhile: judge it afresh on TRAIN
            parent_f1 = _evaluate(parent, self._train).f1
        child_f1 = self._fit_of(child)
        if mdl_accepts(parent_bits=parent.proposed_mechanism.description_length_bits(),
                       parent_f1=parent_f1,
                       child_bits=child.proposed_mechanism.description_length_bits(),
                       child_f1=child_f1, mdl=self._mdl, gain_per_bit=self._gain_per_bit):
            self._counters["accepted"] += 1
            self.add(child)  # may still lose to the capacity bound (counted as an eviction)
            return True
        self._counters["rejected_mdl"] += 1
        self._forget_scores(child.hypothesis_id)
        self._fossilize(child.hypothesis_id, "mdl_rejected")
        return False

    def _merge_round(
        self, tried: set[tuple[str, str]]
    ) -> list[tuple[HypothesisGenome, HypothesisGenome]]:
        """The best-scoring untried same-direction SINGLE pair that merges, judged vs its better parent."""
        singles = sorted(
            (g for g in self._members.values()
             if g.proposed_mechanism.relation is MechanismRelation.SINGLE
             and g.proposed_mechanism.modifier is Modifier.NONE),
            key=lambda g: (-self._total(g.hypothesis_id), g.hypothesis_id),
        )
        attempts = 0
        for i, first in enumerate(singles):
            for second in singles[i + 1:]:
                pair = (first.hypothesis_id, second.hypothesis_id)
                if pair in tried or first.direction is not second.direction:
                    continue
                if attempts >= MAX_MERGE_ATTEMPTS:
                    return []
                attempts += 1
                tried.add(pair)
                child = self.merge(*pair)
                if child is not None:
                    better = max((first, second), key=lambda g: (self._fit_of(g), g.hypothesis_id))
                    return [(better, child)]
        return []

    def _split_round(self, tried: set[str]) -> list[tuple[HypothesisGenome, HypothesisGenome]]:
        """Split the best-scoring untried 2-step member; each part judged against it."""
        two_step = sorted(
            (g for g in self._members.values()
             if len(g.proposed_mechanism.steps) == 2 and g.hypothesis_id not in tried),
            key=lambda g: (-self._total(g.hypothesis_id), g.hypothesis_id),
        )
        if not two_step:
            return []
        parent = two_step[0]
        tried.add(parent.hypothesis_id)
        return [(parent, child) for child in self.split(parent.hypothesis_id)]

    # --- reads -------------------------------------------------------------------

    def ranked(self, k: int) -> tuple[HypothesisGenome, ...]:
        """The top ``k`` members by cached total (unscored last), ties by id."""
        if isinstance(k, bool) or not isinstance(k, int) or k < 0:
            raise ContractError(f"ranked needs an int k >= 0, got {k!r}")
        order = sorted(self._members, key=lambda h: (-self._total(h), h))
        return tuple(self._members[h] for h in order[:k])

    def members(self) -> tuple[HypothesisGenome, ...]:
        return tuple(self._members[h] for h in sorted(self._members))

    def depth(self, hypothesis_id: str) -> int:
        self._member(hypothesis_id)
        return self._depth[hypothesis_id]

    def __len__(self) -> int:
        return len(self._members)

    def stats(self) -> Mapping[str, int]:
        return MappingProxyType({**self._counters, "size": len(self._members),
                                 "capacity": self._capacity, "max_depth": self._max_depth,
                                 "pending_depth": len(self._pending_depth)})

    def memory_bytes(self) -> int:
        """An in-process estimate: the indexes plus each member's canonical genome bytes."""
        stores = (self._members, self._order, self._depth, self._bytes, self._scores,
                  self._fits, self._pending_depth, self._mechanisms)
        total = sum(sys.getsizeof(store) for store in stores)
        total += sum(self._bytes.values()) + len(self._scores) * sys.getsizeof(
            next(iter(self._scores.values()), 0))
        return total
