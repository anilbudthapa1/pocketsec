"""D8.20 — the end-to-end discovery loop, its trap probe and the Stage 1 -> 8 -> 6 endurance run.

This module is the ONE place where every Stage 8 subsystem is wired together, in the spec's
order: corpus preconditions -> residual field on TRAIN -> priority -> per cluster generate and
evolve -> pre-holdout CHALLENGE screens -> ORACLE -> rank -> ONE preregistered HOLDOUT batch
-> identifiability -> ONE REPLICATION batch -> novelty -> FORGE -> ``DiscoveryPackageV1`` ->
``Stage6Adapter.hand_over``. Every step leaves a node in the hypothesis lineage DAG and a
firing count, so a component that never changes an outcome shows up as INERT (lesson 1).

What it refuses to do:

- It writes no trusted state and calls no Stage 6 writer. The only exit is a verified
  ``DiscoveryPackageV1`` handed to ``Stage6Adapter`` (the one module that may call Stage 6's
  ``admit``), and only when the caller passes a lab gateway. Stage 6 adopts nothing today
  (B8-1, ADR-0076): every detection figure here is ``counterfactual_at_boundary``.
- ``holdout_discipline=False`` is the NAIVE control (select on TRAIN at the registered rules,
  no vault, no screens). Its "survivors" are reported so the discipline can be compared with
  its absence; they are **never** packaged, never handed over and never set a ledger status.
- ``WorkBudgetExceeded`` is the kill switch: it ends the run cleanly with
  ``budget_exhausted`` recorded and everything done so far reported. A runaway search hits
  the budget, not the host.
- It never touches the project's experiment registry: registration is an explicit CLI act
  (lesson 7). The theory ledger it drives is in memory.

Measurement honesty: the corpus, the planted mechanisms, the trap and the lab oracle share an
author with this engine (lesson 6); ``synthetic_data`` is always True here. Wall clock is
recorded beside ``/proc/loadavg`` and never asserted; RSS comes only from Stage 0's sampler.
"""

from __future__ import annotations

import random
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from pocketsec.stage0.benchmark.resource_metrics import ResourceSampler, read_rss_bytes
from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage0.prior_art import PriorArtLedger
from pocketsec.stage1.epoch.model import EpochModel, SystemIdentity
from pocketsec.stage6.capsule.quarantine import QuarantineGateway
from pocketsec.stage6.fossils.lineage import KnowledgeLineageDAG
from pocketsec.stage6.memory.semantic import genesis_state
from pocketsec.stage6.provenance.ledger import ProvenanceLedger
from pocketsec.stage6.resources import WorkBudgetExceeded, loadavg
from pocketsec.stage8.adapters.stage6 import MAX_ADAPTER_RECEIPTS, AdapterReceipt, Stage6Adapter
from pocketsec.stage8.adapters.stage7 import Stage7SeedReport, seeds_from_capsules
from pocketsec.stage8.challenger.adversarial import (
    CHALLENGE_PER_KIND, ChallengeKind, build_challenge_corpus, challenge,
)
from pocketsec.stage8.doppelganger.engine import (
    DOPPELGANGER_PER_FAMILY, BenignDoppelganger, DoppelgangerEngine, DoppelgangerFamily,
)
from pocketsec.stage8.ecology.lineage import (
    MAX_LINEAGE_NODES, HypothesisLineageDAG, LineageNode, NodeKind,
)
from pocketsec.stage8.ecology.population import (
    MAX_POPULATION, MDL_GAIN_PER_BIT, EvolutionReport, HypothesisPopulation, ScoreMode,
)
from pocketsec.stage8.episode import Episode, Split, fit_counts
from pocketsec.stage8.forge.compiler import CompiledDetector, compile_all
from pocketsec.stage8.forge.package import (
    MAX_EVIDENCE_EPISODES, MAX_PACKAGE_EVIDENCE,
    DiscoveryPackageV1, FailureCondition, FalsificationRecord, IdentifiabilityClass,
    ReproducibilityStatus, ResourceProfile, RobustnessProfile, TournamentResult,
    artifact_hashes_for, verify_package,
)
from pocketsec.stage8.forge.tournament import (
    conservation_checks, research_state_bytes_of, run_tournament,
)
from pocketsec.stage8.genome.grammar import Mechanism, MechanismRelation
from pocketsec.stage8.genome.hypothesis import (
    Direction, FalsifierKind, GeneratorKind, GenomeProvenance, HypothesisGenome, ObservationScope,
    ResidualType, genome_for,
)
from pocketsec.stage8.governor.budget import GovernorReport, ResearchBudget, ResearchGovernor
from pocketsec.stage8.identifiability.gate import IdentifiabilityGate, IdentifiabilityVerdict
from pocketsec.stage8.laboratory.counterfactual import (
    TransformKind, TransformSpec, apply_transform, decoy_is_neutral,
)
from pocketsec.stage8.laboratory.metamorphic import DEFAULT_RELATIONS, Expectation, run_metamorphic
from pocketsec.stage8.labs.discovery_corpus import (
    PLANTED_MECHANISMS, CorpusArm, CorpusDoppelgangers, DiscoveryCorpus, LabOracle,
    build_discovery_corpus, corpus_preconditions,
)
from pocketsec.stage8.ledger.negative_results import MAX_NEGATIVE_RESULTS, NegativeResultMemory
from pocketsec.stage8.ledger.theory import (
    MAX_LEDGER_ENTRIES, MAX_THEORIES, PreRegistration, TestOutcome, TheoryLedger, TheoryStatus,
)
from pocketsec.stage8.novelty.prior_art_audit import NoveltyAudit, audit, known_library
from pocketsec.stage8.oracle.planner import OraclePlanner, OracleReport, SelectionPolicy
from pocketsec.stage8.prometheus.engine import GenerationReport, PrometheusEngine, oriented_fit
from pocketsec.stage8.prometheus.generators import (
    AnalogyGenerator, ExhaustiveSingleGenerator, ExternalProposalGenerator, GenerationContext,
    Generator, NullBenignGenerator, RandomGenerator, ResidualMotifGenerator, Stage7SeedGenerator,
    SymbolicEnumerator,
)
from pocketsec.stage8.reproducibility.gate import ReproducibilityGate, ReproducibilityVerdict
from pocketsec.stage8.residual.observatory import (
    Explainer, MotifExplainer, PhiOracleExplainer, ResidualCluster, ResidualField,
    ResidualObservatory, cluster_members,
)
from pocketsec.stage8.residual.priority_field import PriorityMode, PriorityScore, prioritise
from pocketsec.stage8.sandbox.boundary import ResearchSandbox
from pocketsec.stage8.sandbox.integrity import (
    ALPHA, HoldoutVault, binomial_upper_tail, content_digest,
)

__all__ = [
    "ENDURANCE_COUNTS",
    "PLANTED_AGREEMENT_MIN",
    "PROMETHEUS_GENERATORS",
    "ComponentFiring",
    "DiscoveryRunReport",
    "EnduranceReport",
    "RunConfig",
    "TrapOutcome",
    "agreement",
    "lab_gateway",
    "probe_trap_at_holdout",
    "run_discovery",
    "run_endurance",
]

PROMETHEUS_GENERATORS: tuple[GeneratorKind, ...] = (
    GeneratorKind.SYMBOLIC_ENUMERATOR, GeneratorKind.RESIDUAL_MOTIF, GeneratorKind.ANALOGY,
    GeneratorKind.NULL_BENIGN, GeneratorKind.STAGE7_SEED, GeneratorKind.EXTERNAL_PROPOSAL,
)
# Chosen, not measured: a theory "recovers" a planted family when its decisions agree with the
# planted mechanism on >= 98 % of REPLICATION episodes (the FORGE agreement floor, D8.15).
PLANTED_AGREEMENT_MIN = 0.98
# Chosen, not measured: endurance corpora are half the gate's size so 12 cycles stay tractable.
ENDURANCE_COUNTS: Mapping[Split, int] = MappingProxyType({
    Split.TRAIN: 120, Split.HOLDOUT: 120, Split.REPLICATION: 120,
    Split.LAB_POOL: 60, Split.INDEPENDENT: 60,
})
_NOT_GENERATORS = frozenset({GeneratorKind.MUTATION, GeneratorKind.MERGE, GeneratorKind.SPLIT})
_REFUTED = frozenset({
    TheoryStatus.CHALLENGED_OUT, TheoryStatus.FALSIFIED, TheoryStatus.NOT_REPRODUCED,
})
_TOURNAMENT_KINDS = tuple(k for k in ChallengeKind if k is not ChallengeKind.POISONED_LABELS)
_SCREEN_NAMES: Mapping[FalsifierKind, str] = MappingProxyType({
    FalsifierKind.COUNTERFACTUAL_INVARIANCE: "counterfactual_screen",
    FalsifierKind.NECESSARY_STEP_ABLATION: "necessary_step_screen",
    FalsifierKind.DOPPELGANGER_SEPARATION: "doppelganger_screen",
})
_ECOLOGY_NAMES: Mapping[GeneratorKind, str] = MappingProxyType({
    GeneratorKind.MUTATION: "mutation", GeneratorKind.MERGE: "merge_split",
    GeneratorKind.SPLIT: "merge_split",
})
_LAB_HOST = "lab-stage8"
_DECOY_RELATION = next(r.relation_id for r in DEFAULT_RELATIONS
                       if r.transform.kind is TransformKind.DECOY_INSERTION)
_MAX_RIVALS = 7
_MAX_KNOWN = 256
_MAX_DOPPELGANGER_MEMO = 64

Bench = tuple[tuple[str, tuple[tuple[Episode, Episode], ...]], ...]


@dataclass(frozen=True, slots=True)
class RunConfig:
    """One discovery run. Every flag defaults to the production discipline; each is an ablation."""

    arm: CorpusArm
    seed: int
    budget: ResearchBudget = ResearchBudget()
    generators: tuple[GeneratorKind, ...] = PROMETHEUS_GENERATORS
    diversity: bool = True
    mdl: bool = True
    score_mode: ScoreMode = ScoreMode.FULL
    priority_mode: PriorityMode = PriorityMode.FULL
    doppelganger_screen: bool = True
    # None = ORACLE off, the default since the 2026-09-27 fix wave (ADR-0078 amendment 2): ORACLE
    # is NOT_YET_JUSTIFIED on replay (EIG does not beat CHEAPEST), so it is opt-in. The gate turns
    # it on explicitly for the runs that test ORACLE's own properties (lab-on, DROPOUT).
    oracle_policy: SelectionPolicy | None = None
    use_lab_oracle: bool = False          # production default: replay only (architecture §3)
    negative_memory: bool = True
    holdout_discipline: bool = True       # False = NAIVE control: TRAIN selection, never packaged
    bonferroni: bool = True
    external_texts: tuple[str, ...] = ()
    stage7_capsules: tuple[object, ...] = ()   # KnowledgeCapsuleV1, typed at seeds_from_capsules


@dataclass(frozen=True, slots=True)
class TrapOutcome:
    """The lead's trap: SINGLE(SPAWN), perfect on TRAIN by construction, worthless held out.

    ``refuted`` (never "killed", T5): at least one trap genome was tested and every tested one
    ended in a refuting status. ``refuted_at`` names where (``challenge:<FalsifierKind>``,
    ``HOLDOUT``, ``REPLICATION``); it is appended to the spec's four fields, defaulted.
    """

    generated: bool
    registered: bool
    refuted: bool
    hypothesis_id: str | None
    refuted_at: str | None = None


@dataclass(frozen=True, slots=True)
class ComponentFiring:
    component: str
    firings: int            # times the mechanism ran on something
    outcome_changes: int    # times it changed which theory was tested, kept or shipped


@dataclass(frozen=True, slots=True)
class DiscoveryRunReport:
    config: RunConfig
    residual_total: int
    residual_explained: int
    clusters: int
    generation: tuple[GenerationReport, ...]
    evolution: tuple[EvolutionReport, ...]
    oracle: tuple[OracleReport, ...]
    births: int
    challenged_out: int
    registered: int
    survived: tuple[str, ...]           # NAIVE control: the TRAIN-selected ids
    falsified: int
    reproduced: tuple[str, ...]         # NAIVE control: the TRAIN-selected ids (nothing replicates)
    identifiability: tuple[IdentifiabilityVerdict, ...]
    novelty: tuple[NoveltyAudit, ...]
    packages: tuple[DiscoveryPackageV1, ...]
    receipts: tuple[AdapterReceipt, ...]
    planted_recovered: tuple[tuple[str, bool], ...]
    false_reproduced: int
    trap: TrapOutcome
    firings: tuple[ComponentFiring, ...]
    governor: GovernorReport
    ledger_problems: tuple[str, ...]
    wall_seconds: float
    loadavg: tuple[float, float, float]
    synthetic_data: bool
    # Appended after the spec's fields (backward compatible, all defaulted):
    budget_exhausted: bool = False
    precondition_problems: tuple[str, ...] = ()
    outcomes: tuple[tuple[str, str], ...] = ()          # ("DIRECTION:DSL", terminal status)
    package_problems: tuple[str, ...] = ()
    oracle_leaders: tuple[tuple[str, str], ...] = ()    # (hypothesis id, "DIRECTION:DSL")
    # Appended by the integrator so the gate can audit the run it is judging, not a summary:
    # the adapter's own counters (G8.9) and the run's ledger and lineage DAG (G8.1, G8.2, G8.8).
    adapter_created: int = 0
    adapter_admitted: int = 0
    ledger: TheoryLedger | None = field(default=None, repr=False, compare=False)
    lineage: HypothesisLineageDAG | None = field(default=None, repr=False, compare=False)

    def firing(self, component: str) -> ComponentFiring | None:
        return next((f for f in self.firings if f.component == component), None)


@dataclass(frozen=True, slots=True)
class EnduranceReport:
    cycles: int
    store_sizes: tuple[tuple[str, tuple[int, ...]], ...]
    evictions: tuple[tuple[str, int], ...]
    plateau_ok: bool
    rss_start: int | None
    rss_peak: int | None
    loadavg: tuple[float, float, float]
    # Appended: what the plateau verdict read.
    store_caps: tuple[tuple[str, int], ...] = ()
    problems: tuple[str, ...] = ()
    packages: int = 0
    capsules_created: int = 0
    capsules_admitted: int = 0
    wall_seconds: float = 0.0
    cycles_completed: int = 0


@dataclass(frozen=True, slots=True)
class _Knobs:
    """Parameters the sensitivity sweep and the ablation vary; RunConfig stays the spec's."""

    evolve: bool = True
    alpha: float = ALPHA
    mdl_gain_per_bit: float = MDL_GAIN_PER_BIT


@dataclass(slots=True)
class _Stores:
    """The long-lived research state. ``run_endurance`` keeps ONE across every cycle."""

    ledger: TheoryLedger
    negative: NegativeResultMemory
    lineage: HypothesisLineageDAG
    population: HypothesisPopulation
    adapter: Stage6Adapter | None = None
    sequence: int = 0          # Stage 6 hand-over sequence, monotone across cycles

    @classmethod
    def fresh(cls, config: RunConfig, knobs: _Knobs, governor: ResearchGovernor) -> _Stores:
        negative = NegativeResultMemory()
        ledger = TheoryLedger(negative_memory=negative)
        population = HypothesisPopulation(
            ledger=ledger, governor=governor, capacity=config.budget.max_population,
            max_depth=config.budget.max_branch_depth, mdl=config.mdl,
            score_mode=config.score_mode, mdl_gain_per_bit=knobs.mdl_gain_per_bit,
        )
        return cls(ledger, negative, HypothesisLineageDAG(), population)


class _CachedDoppelgangers:
    """``DoppelgangerSource`` over the corpus's benign families, rendered once per request key.

    ``CorpusDoppelgangers`` renders every request through fresh Stage 1 pipelines, and the
    engine asks once per genome and family: without this per-run memo the screen re-renders
    the same benign sessions for every candidate. Bounded at ``_MAX_DOPPELGANGER_MEMO`` keys.
    """

    def __init__(self) -> None:
        self._memo: dict[tuple[str, int, int], tuple[Episode, ...]] = {}

    def benign_alternatives(self, family: Any, *, count: int, seed: int) -> tuple[Episode, ...]:
        key = (str(getattr(family, "value", family)), count, seed)
        if key not in self._memo:
            if len(self._memo) >= _MAX_DOPPELGANGER_MEMO:
                self._memo.pop(next(iter(self._memo)))
            source = CorpusDoppelgangers()
            self._memo[key] = source.benign_alternatives(family, count=count, seed=seed)
        return self._memo[key]


def lab_gateway(identity: SystemIdentity | None = None, *,
                provenance: ProvenanceLedger | None = None) -> QuarantineGateway:
    """A real Stage 6 gateway over ``genesis_state`` — LAB ONLY (spec §2.3, Stage 7 precedent).

    Stage 8 builds it and never touches it again: only ``Stage6Adapter`` calls its door, and
    whatever Stage 6 decides is recorded verbatim. ``provenance`` lets the gate keep a handle
    on Stage 6's own trust records of what was admitted (read, never written, by Stage 8).
    """
    ledger = provenance if provenance is not None else ProvenanceLedger()
    gateway = QuarantineGateway(ledger=ledger, lineage=KnowledgeLineageDAG())
    state = genesis_state(identity=identity or SystemIdentity())
    gateway.bind_trusted_view(lambda: state)
    return gateway


def agreement(decide: Callable[[Episode], bool], reference: Callable[[Episode], bool],
              episodes: Sequence[Episode]) -> float | None:
    """Share of ``episodes`` on which two detectors decide alike; None on nothing."""
    if not episodes:
        return None
    return sum(decide(e) == reference(e) for e in episodes) / len(episodes)


def _planted_decider(family: Any) -> Callable[[Episode], bool]:
    mechanism = PLANTED_MECHANISMS[family]
    return lambda e: mechanism.matches(e.steps)


def _dsl(genome: HypothesisGenome) -> str:
    return f"{genome.direction.value}:{genome.proposed_mechanism.to_dsl()}"


def _check_config(corpus: DiscoveryCorpus, config: RunConfig) -> None:
    if not isinstance(config, RunConfig):
        raise ContractError("run_discovery needs a RunConfig")
    if not isinstance(corpus, DiscoveryCorpus):
        raise ContractError("run_discovery needs a DiscoveryCorpus")
    if config.arm is not corpus.arm:
        raise ContractError(f"config arm {config.arm} does not match corpus arm {corpus.arm}")
    if not config.generators:
        raise ContractError("a run needs at least one generator")
    bad = [k for k in config.generators
           if not isinstance(k, GeneratorKind) or k in _NOT_GENERATORS]
    if bad:
        raise ContractError(f"not a generator: {bad!r} (MUTATION/MERGE/SPLIT are the ecology's)")
    if len(set(config.generators)) != len(config.generators):
        raise ContractError("duplicate generator kinds")


class _Run:
    """One run's state. Methods are the spec's steps, in order; each charges the governor."""

    def __init__(self, corpus: DiscoveryCorpus, config: RunConfig, knobs: _Knobs,
                 stores: _Stores | None, gateway: QuarantineGateway | None) -> None:
        self.corpus, self.config, self.knobs, self.gateway = corpus, config, knobs, gateway
        self.governor = ResearchGovernor(config.budget)
        self.stores = stores or _Stores.fresh(config, knobs, self.governor)
        self.ledger = self.stores.ledger
        self.rng = random.Random(config.seed)
        self.train = corpus.episodes(Split.TRAIN)
        self.lab_pool = corpus.episodes(Split.LAB_POOL)
        self.seeds: Stage7SeedReport = seeds_from_capsules(
            config.stage7_capsules)  # type: ignore[arg-type]
        self.doppel_source = _CachedDoppelgangers()
        self.fire: dict[str, list[int]] = {}
        self.generation: list[GenerationReport] = []
        self.evolution: list[EvolutionReport] = []
        self.oracle: list[OracleReport] = []
        self.idents: dict[str, IdentifiabilityVerdict] = {}
        self.novelty: list[NoveltyAudit] = []
        self.packages: list[DiscoveryPackageV1] = []
        self.package_problems: list[str] = []
        self.receipts: list[AdapterReceipt] = []
        self.born: list[str] = []
        # S8-RES-1: this run's genomes, by id. The ledger may fold a theory born in this run
        # (at MAX_THEORIES, in endurance); the report must still name what it tested.
        self.genomes: dict[str, HypothesisGenome] = {}
        self.clusters: dict[str, ResidualCluster] = {}
        self.registered: list[str] = []
        self.holdout: dict[str, TestOutcome] = {}
        self.screens: dict[str, list[FalsificationRecord]] = {}
        self.doppel: dict[str, tuple[BenignDoppelganger, ...]] = {}
        self.refuted_at: dict[str, str] = {}
        self.naive_selected: list[str] = []
        self.reproduced: list[str] = []
        self.budget_exhausted = False
        self.precondition_problems: tuple[str, ...] = ()
        self.field: ResidualField | None = None
        self.challenge_sets: dict[tuple[Any, ...], Mapping[ChallengeKind, tuple[Episode, ...]]] = {}

    # -- bookkeeping ---------------------------------------------------------------------------

    def count(self, component: str, firings: int = 0, changes: int = 0) -> None:
        slot = self.fire.setdefault(component, [0, 0])
        slot[0] += firings
        slot[1] += changes

    def node(self, node_id: str, kind: NodeKind, parents: Sequence[str], detail: Any) -> bool:
        lineage = self.stores.lineage
        if lineage.has(node_id):
            return True
        known = tuple(p for p in parents if lineage.has(p))[:4]
        return lineage.add(LineageNode(node_id=node_id, kind=kind, parents=known,
                                       detail_digest=content_digest(detail)))

    # -- 1. preconditions, residual field, priority ------------------------------------------

    def observe(self) -> tuple[PriorityScore, ...]:
        self.precondition_problems = corpus_preconditions(self.corpus).problems
        explainers: list[Explainer] = [PhiOracleExplainer.fit(self.train)]
        if self.seeds.mechanisms:
            explainers.append(
                MotifExplainer("stage7-seeds", self.seeds.mechanisms, collective=True))
        field_ = ResidualObservatory(explainers, governor=self.governor).observe(self.train)
        self.field = field_
        self.count("observatory", field_.total, len(field_.clusters))
        for name, fired in field_.firings:
            self.count(f"explainer:{name}", fired, 0)
        top_n = self.config.budget.max_active_residual_clusters
        ranked = prioritise(field_, top_n=top_n, mode=self.config.priority_mode)
        if self.config.priority_mode is PriorityMode.FULL:
            # Outcome change = a cluster researched only because priority, not size, ranked it.
            by_size = prioritise(field_, top_n=top_n, mode=PriorityMode.SIZE_ONLY)
            changed = {s.cluster_id for s in ranked} - {s.cluster_id for s in by_size}
            self.count("priority_field", len(field_.clusters), len(changed))
        self.clusters = {c.cluster_id: c for c in field_.clusters}
        for cluster in field_.clusters:
            detail = {"signature": [list(item) for item in cluster.signature]}
            self.node(cluster.cluster_id, NodeKind.RESIDUAL, (), detail)
        return ranked

    # -- 2. generate and evolve ---------------------------------------------------------------

    def generators(self) -> list[Generator]:
        seeds, texts = self.seeds, self.config.external_texts
        made: dict[GeneratorKind, Callable[[], Generator]] = {
            GeneratorKind.SYMBOLIC_ENUMERATOR: SymbolicEnumerator,
            GeneratorKind.RESIDUAL_MOTIF: ResidualMotifGenerator,
            GeneratorKind.ANALOGY: AnalogyGenerator,
            GeneratorKind.NULL_BENIGN: NullBenignGenerator,
            GeneratorKind.STAGE7_SEED: lambda: Stage7SeedGenerator(
                seeds.mechanisms, source_ids=seeds.source_capsule_ids),
            GeneratorKind.EXTERNAL_PROPOSAL: lambda: ExternalProposalGenerator(texts),
            GeneratorKind.RANDOM_BASELINE: RandomGenerator,
            GeneratorKind.EXHAUSTIVE_SINGLE_BASELINE: ExhaustiveSingleGenerator,
        }
        return [made[kind]() for kind in self.config.generators]

    def generate(self, ranked: Sequence[PriorityScore]) -> None:
        negative = self.stores.negative if self.config.negative_memory else None
        engine = PrometheusEngine(self.generators(), ledger=self.ledger, negative_memory=negative,
                                  governor=self.governor, diversity=self.config.diversity)
        known = self.known_mechanisms()
        for score in ranked:
            cluster = self.clusters[score.cluster_id]
            members = cluster_members(cluster, self.field, self.train)  # type: ignore[arg-type]
            context = GenerationContext(train=self.train, cluster=cluster,
                                        residual_episodes=members, known=known,
                                        seed=self.config.seed)
            before = set(self.ledger.hypothesis_ids())
            report = engine.generate(context)
            self.generation.append(report)
            self.count("negative_memory", report.dead_ends_skipped, report.dead_ends_skipped)
            for kind, kept in report.kept_by:
                self.count(f"generator:{kind}", kept, 0)
            for hid in report.births:
                self.stores.population.add(self.ledger.genome(hid))
            self.adopt_births(before, cluster.cluster_id)
            if report.budget_exhausted:
                raise WorkBudgetExceeded("generation hit the research budget")
            self.evolve(cluster.cluster_id)

    def evolve(self, cluster_id: str) -> None:
        if not self.knobs.evolve:
            return
        before = set(self.ledger.hypothesis_ids())
        report = self.stores.population.evolve(self.train, rng=self.rng)
        self.evolution.append(report)
        self.count("mutation", report.accepted, 0)
        rejected = report.rejected_mdl if self.config.mdl else 0
        self.count("mdl", rejected, rejected)
        self.count("merge_split", report.merges + report.splits, 0)
        self.adopt_births(before, cluster_id)

    def adopt_births(self, before: set[str], cluster_id: str) -> None:
        """Every new ledger birth becomes a lineage HYPOTHESIS node under its parents/cluster."""
        lineage = self.stores.lineage
        for hid in self.ledger.hypothesis_ids():
            if hid in before or hid in self.born:
                continue
            genome = self.ledger.genome(hid)
            self.born.append(hid)
            self.genomes[hid] = genome
            parents = [p for p in genome.parent_hypotheses if lineage.has(p)]
            scope = [c for c in genome.observation_scope.residual_cluster_ids if lineage.has(c)]
            self.node(hid, NodeKind.HYPOTHESIS, parents or scope or [cluster_id], genome.digest())

    def known_mechanisms(self) -> tuple[Mechanism, ...]:
        validated = [self.ledger.genome(h).proposed_mechanism
                     for h in self.ledger.hypothesis_ids(TheoryStatus.REPRODUCED)]
        return tuple((list(self.seeds.mechanisms) + validated)[:_MAX_KNOWN])

    def candidates(self) -> list[HypothesisGenome]:
        born = set(self.born)
        return [g for g in self.stores.population.members() if g.hypothesis_id in born
                and self.ledger.status(g.hypothesis_id) is TheoryStatus.PROPOSED]

    # -- 3. pre-holdout screens -----------------------------------------------------------------

    def screen(self, candidates: Sequence[HypothesisGenome]) -> list[HypothesisGenome]:
        doppel = None
        if self.config.doppelganger_screen:
            doppel = DoppelgangerEngine(self.doppel_source, governor=self.governor,
                                        seed=self.config.seed)
        bench = self.invariance_bench() if candidates else ()
        kept: list[HypothesisGenome] = []
        for genome in candidates:
            failed = self.screen_one(genome, bench, doppel)
            if failed is None:
                kept.append(genome)
                continue
            reason = f"challenge:{failed.value}"
            self.refuted_at[genome.hypothesis_id] = reason
            self.ledger.set_status(genome.hypothesis_id, TheoryStatus.CHALLENGED_OUT, reason=reason)
        return kept

    def invariance_bench(self) -> Bench:
        """LAB_POOL under every PRESERVING relation, transformed ONCE per run.

        The transforms do not depend on the theory, so every genome is scored on the same
        worlds (a fair comparison, and 5 x candidates fewer transforms than per-genome runs).
        """
        rng, bench = random.Random(self.config.seed), []
        for relation in DEFAULT_RELATIONS:
            if relation.expectation is not Expectation.INVARIANT:
                continue
            pairs = []
            for episode in self.lab_pool:
                self.governor.charge("labs.invariance_bench", len(episode.steps))
                derived = apply_transform(episode, relation.transform, rng=rng,
                                          donors=self.lab_pool)
                if derived is not None:
                    pairs.append((episode, derived))
            bench.append((relation.relation_id, tuple(pairs)))
        return tuple(bench)

    def screen_one(self, genome: HypothesisGenome, bench: Bench,
                   doppel: DoppelgangerEngine | None) -> FalsifierKind | None:
        """The three pre-holdout screens, each at the threshold the genome registered at birth."""
        limits = {f.kind: f.threshold for f in genome.falsification_tests}
        invariance = self.invariance(genome, bench)
        verdicts: list[tuple[FalsifierKind, bool, float | None]] = [(
            FalsifierKind.COUNTERFACTUAL_INVARIANCE,
            invariance is None or invariance >= limits[FalsifierKind.COUNTERFACTUAL_INVARIANCE],
            invariance)]
        drop = self.deletion_drop(genome)
        verdicts.append((FalsifierKind.NECESSARY_STEP_ABLATION,
                         drop is None or drop >= limits[FalsifierKind.NECESSARY_STEP_ABLATION],
                         drop))
        if doppel is not None and genome.direction is Direction.MALICIOUS:
            found = doppel.challenge(genome)
            self.doppel[genome.hypothesis_id] = found
            share = max((d.matched_share for d in found), default=0.0)
            verdicts.append((FalsifierKind.DOPPELGANGER_SEPARATION,
                             share <= limits[FalsifierKind.DOPPELGANGER_SEPARATION], share))
        return self.record_screens(genome, verdicts)

    def invariance(self, genome: HypothesisGenome, bench: Bench) -> float | None:
        """The weakest PRESERVING relation's agreement (every one must hold); None on nothing.

        F1: a decoyed pair whose decoy performs a step this genome names is not a harmless-decoy
        world for it (``decoy_is_neutral``) and is skipped, never counted as a flip. Before
        this, the decoy relation alone refuted every hypothesis over a non-escalating step
        (the trap SINGLE(SPAWN) among them) and could refute none over an escalating one.
        """
        meter = self.governor.meter
        avoid = genome.proposed_mechanism.steps + genome.forbidden_observations
        rates = []
        for relation_id, pairs in bench:
            if relation_id == _DECOY_RELATION:
                pairs = tuple((a, b) for a, b in pairs if decoy_is_neutral(a, b, avoid))
            if pairs:
                rates.append(sum(genome.decides(a, meter=meter) == genome.decides(b, meter=meter)
                                 for a, b in pairs) / len(pairs))
        return min(rates) if rates else None

    def deletion_drop(self, genome: HypothesisGenome) -> float | None:
        """Share of LAB_POOL matches a single-step deletion removes (None: nothing matched)."""
        matched = [e for e in self.lab_pool if genome.decides(e, meter=self.governor.meter)]
        if not matched:
            return None
        deletion = [r for r in DEFAULT_RELATIONS if r.expectation is Expectation.SUPPORT_FALLS]
        (result,) = run_metamorphic(genome.decides, matched, deletion,
                                    rng=random.Random(self.config.seed), governor=self.governor)
        if result.support_before == 0:
            return None
        return 1.0 - result.support_after / result.support_before

    def record_screens(self, genome: HypothesisGenome,
                       verdicts: Sequence[tuple[FalsifierKind, bool, float | None]],
                       ) -> FalsifierKind | None:
        registered = {f.kind: (f.split, f.threshold) for f in genome.falsification_tests}
        records: list[FalsificationRecord] = []
        first_failure: FalsifierKind | None = None
        for kind, passed, statistic in verdicts:
            self.ledger.record_challenge(genome.hypothesis_id, kind=kind, passed=passed,
                                         statistic=statistic)
            split, threshold = registered[kind]
            records.append(FalsificationRecord(kind=kind, split=split, passed=passed,
                                               statistic=statistic, parameter=threshold,
                                               registration_id=""))
            decisive = not passed and first_failure is None
            self.count(_SCREEN_NAMES[kind], 1, int(decisive))
            if decisive:
                first_failure = kind
        self.screens[genome.hypothesis_id] = records
        # F3: the population cached this genome's score before any screen existed; re-read the
        # survival and fragility terms now, so rank() sees the screens that just ran.
        self.stores.population.refresh_screen_terms(genome.hypothesis_id)
        self.node("scr-" + genome.hypothesis_id[4:], NodeKind.EXPERIMENT, (genome.hypothesis_id,),
                  [r.kind.value for r in records])
        return first_failure

    # -- 4. ORACLE, ranking, one HOLDOUT batch --------------------------------------------------

    def run_oracle(self, kept: list[HypothesisGenome]) -> list[HypothesisGenome]:
        policy = self.config.oracle_policy
        if policy is None:
            return kept
        lab = LabOracle(governor=self.governor) if self.config.use_lab_oracle else None
        planner = OraclePlanner(sandbox=ResearchSandbox(), lab=lab, governor=self.governor,
                                policy=policy, rng=random.Random(self.config.seed),
                                ledger=self.ledger)
        by_cluster: dict[str, list[HypothesisGenome]] = {}
        for genome in kept:
            key = (genome.observation_scope.residual_cluster_ids or ("",))[0]
            by_cluster.setdefault(key, []).append(genome)
        for cluster_id, group in by_cluster.items():
            if len(group) < 2:
                continue
            cluster = self.clusters.get(cluster_id)
            share = None if cluster is None else cluster.visibility_share
            report = planner.run(group, self.lab_pool, visibility_share=share)
            self.oracle.append(report)
            self.count("oracle", len(report.experiments), len(report.pruned))
        return [g for g in kept if self.ledger.status(g.hypothesis_id) is TheoryStatus.PROPOSED]

    def rank(self, kept: Sequence[HypothesisGenome]) -> list[HypothesisGenome]:
        population, m = self.stores.population, self.config.budget.max_registrations_per_batch
        scores = {g.hypothesis_id: population.score(g.hypothesis_id, self.train) for g in kept}

        def top(term: str) -> list[HypothesisGenome]:
            key = lambda g: (-getattr(scores[g.hypothesis_id], term), g.hypothesis_id)  # noqa: E731
            return sorted(kept, key=key)[:m]

        by_total = top("total")
        if self.config.score_mode is ScoreMode.FULL:
            # Outcome change = a theory registered only because the full score, not fit, ranked it.
            swapped = {g.hypothesis_id for g in by_total} - {g.hypothesis_id for g in top(
                "predictive_fit")}
            self.count("score_full", len(kept), len(swapped))
        return by_total

    def run_holdout(self, selected: Sequence[HypothesisGenome]) -> list[HypothesisGenome]:
        if not selected:
            return []
        bonferroni = self.config.bonferroni
        size = len(selected) if bonferroni else 1          # the family actually tested
        vault = HoldoutVault(self.corpus.episodes(Split.HOLDOUT), split=Split.HOLDOUT,
                             ledger=self.ledger, max_batches=1 if bonferroni else len(selected),
                             alpha=self.knobs.alpha, governor=self.governor)
        registrations = [self.preregister(g, vault.split_digest(), size) for g in selected]
        groups = [registrations] if bonferroni else [[r] for r in registrations]
        outcomes: list[TestOutcome] = []
        for group in groups:
            outcomes.extend(vault.evaluate(vault.seal_batch(group)))
        return self.read_holdout(selected, outcomes)

    def preregister(self, genome: HypothesisGenome, digest: str, size: int) -> PreRegistration:
        prediction = next(p for p in genome.predicted_observations if p.split is Split.HOLDOUT)
        alpha = next(f.alpha for f in genome.falsification_tests
                     if f.kind is FalsifierKind.HOLDOUT_ENRICHMENT)
        registration = PreRegistration(
            registration_id="", hypothesis_id=genome.hypothesis_id,
            genome_digest=genome.digest(), split=Split.HOLDOUT, split_digest=digest,
            batch_size=size, alpha=alpha, prediction=prediction)  # type: ignore[arg-type]
        self.ledger.preregister(registration)
        self.registered.append(genome.hypothesis_id)
        parents = ("scr-" + genome.hypothesis_id[4:], genome.hypothesis_id)
        self.node(registration.registration_id, NodeKind.EXPERIMENT, parents,
                  registration.to_payload())
        return registration

    def read_holdout(self, selected: Sequence[HypothesisGenome],
                     outcomes: Sequence[TestOutcome]) -> list[HypothesisGenome]:
        by_id = {g.hypothesis_id: g for g in selected}
        survivors: list[HypothesisGenome] = []
        on = self.config.bonferroni
        for outcome in outcomes:
            self.holdout[outcome.hypothesis_id] = outcome
            # Bonferroni changed the outcome iff enrichment alone refuted and p <= uncorrected α.
            only_enrichment = outcome.reasons == (FalsifierKind.HOLDOUT_ENRICHMENT.value,)
            rescued = (on and only_enrichment and outcome.p_value is not None
                       and outcome.p_value <= self.knobs.alpha)
            self.count("bonferroni", int(on), int(rescued))
            self.count("vault", 1, int(not outcome.survived))
            if outcome.survived:
                survivors.append(by_id[outcome.hypothesis_id])
            else:
                self.refuted_at[outcome.hypothesis_id] = "HOLDOUT"
        return survivors

    # -- 5. identifiability, reproducibility ----------------------------------------------------

    def identify(self, survivors: Sequence[HypothesisGenome]) -> None:
        permitted = self.config.use_lab_oracle
        gate = IdentifiabilityGate(interventions_permitted=permitted)
        observed = tuple(self.train) + tuple(e for e in self.lab_pool if e.label is not None)
        lab = LabOracle(governor=self.governor) if permitted else None
        for genome in survivors:
            interventions = self.interventions(genome, lab) if lab is not None else ()
            verdict = gate.assess(genome, self.rivals(genome, survivors), observed, interventions)
            self.ledger.record_identifiability(verdict)
            self.idents[genome.hypothesis_id] = verdict
            downgraded = verdict.klass is not IdentifiabilityClass.IDENTIFIED
            self.count("identifiability", 1, int(downgraded))

    def rivals(self, genome: HypothesisGenome,
               others: Sequence[HypothesisGenome]) -> list[HypothesisGenome]:
        """Structural twins (order vs co-occurrence) plus observationally near-equal survivors."""
        mech, twins = genome.proposed_mechanism, []
        pair_kinds = (MechanismRelation.PRECEDES, MechanismRelation.CO_OCCURS)
        if len(mech.steps) == 2 and mech.relation in pair_kinds:
            a, b = mech.steps
            shapes = [(MechanismRelation.CO_OCCURS, (a, b)), (MechanismRelation.PRECEDES, (a, b)),
                      (MechanismRelation.PRECEDES, (b, a))]
            twins = [Mechanism(relation=r, steps=s) for r, s in shapes]
        rivals = [self.twin(genome, m) for m in twins if m.digest() != mech.digest()]
        for other in others:
            if other.hypothesis_id == genome.hypothesis_id:
                continue
            same = agreement(other.decides, genome.decides, self.train)
            if other.direction is genome.direction and (same or 0.0) >= PLANTED_AGREEMENT_MIN:
                rivals.append(other)
        return rivals[:_MAX_RIVALS]

    def twin(self, genome: HypothesisGenome, mechanism: Mechanism) -> HypothesisGenome:
        provenance = GenomeProvenance(generator=GeneratorKind.MUTATION,
                                      source_digest=genome.digest(), foreign=False,
                                      seed=self.config.seed)
        return genome_for(mechanism, direction=genome.direction, scope=genome.observation_scope,
                          provenance=provenance, parents=(genome.hypothesis_id,))

    def interventions(self, genome: HypothesisGenome, lab: LabOracle) -> tuple[Episode, ...]:
        """REORDER / ACTOR_SPLIT worlds labelled by the lab oracle (lab_oracle_authored)."""
        cap = self.config.budget.max_counterfactual_worlds
        target = genome.necessary_conditions[0] if genome.necessary_conditions else None
        worlds: list[Episode] = []
        rng = random.Random(self.config.seed)
        # REORDER 1 moves the first necessary step behind its partner: the world where
        # "a precedes b" and "a co-occurs with b" disagree. ACTOR_SPLIT separates same-actor.
        specs = (TransformSpec(kind=TransformKind.REORDER, parameter=1, target=target),
                 TransformSpec(kind=TransformKind.REORDER, parameter=0, target=target),
                 TransformSpec(kind=TransformKind.ACTOR_SPLIT, parameter=0, target=target))
        for spec in specs:
            for episode in self.lab_pool:
                if len(worlds) >= cap:
                    return tuple(worlds)
                world = apply_transform(episode, spec, rng=rng)
                if world is not None:
                    worlds.append(world.with_split(Split.CHALLENGE, label=lab.label(world)))
        return tuple(worlds)

    def reproduce(self, survivors: Sequence[HypothesisGenome]) -> list[ReproducibilityVerdict]:
        if not survivors:
            return []
        vault = HoldoutVault(self.corpus.episodes(Split.REPLICATION), split=Split.REPLICATION,
                             ledger=self.ledger, alpha=self.knobs.alpha, governor=self.governor)
        gate = ReproducibilityGate(vault=vault, ledger=self.ledger,
                                   independent=self.corpus.episodes(Split.INDEPENDENT),
                                   lab_pool=self.lab_pool, governor=self.governor,
                                   rng=random.Random(self.config.seed))
        contexts = {g.hypothesis_id: self.failure_contexts(g) for g in survivors}
        verdicts = gate.run(survivors, failing_contexts=contexts)
        for verdict in verdicts:
            reproduced = verdict.record.status is ReproducibilityStatus.REPRODUCED
            self.count("reproducibility", 1, int(not reproduced))
            if reproduced:
                self.reproduced.append(verdict.hypothesis_id)
            elif self.ledger.status(verdict.hypothesis_id) is TheoryStatus.NOT_REPRODUCED:
                self.refuted_at[verdict.hypothesis_id] = "REPLICATION"
        return list(verdicts)

    def challenge_corpus(self, genome: HypothesisGenome) -> Mapping[ChallengeKind,
                                                                    tuple[Episode, ...]]:
        """The robustness corpus depends only on the necessary predicates: built once per set."""
        key = tuple(p.payload() for p in genome.necessary_conditions)
        if key not in self.challenge_sets:
            self.challenge_sets[key] = build_challenge_corpus(
                self.lab_pool, kinds=_TOURNAMENT_KINDS, rng=random.Random(self.config.seed),
                governor=self.governor, cap=CHALLENGE_PER_KIND,
                necessary=genome.necessary_conditions, trap=self.corpus.trap_mechanism)
        return self.challenge_sets[key]

    def robustness(self, genome: HypothesisGenome) -> tuple[Any, ...]:
        """Recall retained per challenge kind; ``()`` for a BENIGN theory (F11).

        The challenger's positives are label-1 episodes, so for a BENIGN reading "recall
        retained" would be a malicious-label recall, the inverse of the theory's claim. FORGE's
        tournament already reports None there (``tournament._robustness``); this agrees.
        """
        if genome.direction is Direction.BENIGN:
            return ()
        return tuple(challenge(genome.hypothesis_id, genome.decides,
                               self.challenge_corpus(genome)))

    def failure_contexts(self, genome: HypothesisGenome) -> tuple[FailureCondition, ...]:
        """Where the theory is known to fail, whether or not it reproduces (§24)."""
        found: list[FailureCondition] = []
        verdict = self.idents.get(genome.hypothesis_id)
        if verdict is not None and verdict.klass is not IdentifiabilityClass.IDENTIFIED:
            found.append(FailureCondition(context=f"identifiability:{verdict.klass.value}",
                                          observed_rate=None, detail=f"reason {verdict.reason}"))
        for d in self.doppel.get(genome.hypothesis_id, ()):
            if d.matched > 0:
                found.append(FailureCondition(context=f"doppelganger:{d.family.value}",
                                              observed_rate=d.matched_share,
                                              detail="matched benign alternatives"))
        results = self.robustness(genome)
        weakest = sorted((r for r in results if r.recall_retained is not None),
                         key=lambda r: r.recall_retained)  # type: ignore[arg-type, return-value]
        for r in weakest:
            if r.recall_retained < 1.0:  # type: ignore[operator]
                found.append(FailureCondition(context=f"challenge:{r.kind.value}",
                                              observed_rate=r.recall_retained,
                                              detail="recall retained"))
        return tuple(found[:15])   # one slot stays for the gate's own independent:fp

    # -- 6. novelty, FORGE, package, hand-over -------------------------------------------------

    def representatives(self, verdicts: Sequence[ReproducibilityVerdict],
                        ) -> list[ReproducibilityVerdict]:
        """One REPRODUCED theory per observational-equivalence class, best TheoryScore first.

        Two theories with the same direction and the same decision on every TRAIN and LAB_POOL
        episode are the same detector as far as any non-held-out data can tell; compiling and
        handing over both spends FORGE budget and Stage 6 evidence on a duplicate. The others
        stay REPRODUCED in the ledger and are counted (``package_dedup``), never dropped.
        """
        order = {hid: i for i, hid in enumerate(self.registered)}   # rank() order: TheoryScore
        reproduced = sorted((v for v in verdicts
                             if v.record.status is ReproducibilityStatus.REPRODUCED),
                            key=lambda v: order.get(v.hypothesis_id, len(order)))
        world, meter = tuple(self.train) + tuple(self.lab_pool), self.governor.meter
        seen: set[tuple[Any, ...]] = set()
        kept: list[ReproducibilityVerdict] = []
        for verdict in reproduced:
            genome = self.ledger.genome(verdict.hypothesis_id)
            key = (genome.direction, tuple(genome.decides(e, meter=meter) for e in world))
            self.count("package_dedup", 1, int(key in seen))
            if key not in seen:
                seen.add(key)
                kept.append(verdict)
        return kept

    def package_all(self, verdicts: Sequence[ReproducibilityVerdict]) -> None:
        library = known_library(stage7_seeds=self.seeds.mechanisms)
        prior_art = PriorArtLedger.load()
        for verdict in self.representatives(verdicts):
            genome = self.ledger.genome(verdict.hypothesis_id)
            novelty = audit(genome, library, prior_art=prior_art)
            self.novelty.append(novelty)
            self.count("novelty", 1, 0)   # novelty never gates anything: no claim is permitted
            package = self.package_one(genome, verdict, novelty)
            problems = verify_package(package)
            if problems:
                self.package_problems.extend(f"{genome.hypothesis_id}: {p}" for p in problems)
                continue
            self.packages.append(package)

    def forge(self, genome: HypothesisGenome) -> tuple[tuple[CompiledDetector, ...],
                                                       TournamentResult]:
        compiled = compile_all(genome, self.train, governor=self.governor)
        tournament = run_tournament(
            genome, compiled, measure_on=self.corpus.episodes(Split.REPLICATION),
            challenge=self.challenge_corpus(genome),
            discovery_work_units=self.governor.report().spent,
            research_state_bytes=self.research_state_bytes(genome.hypothesis_id),
            governor=self.governor)
        refusals = sum(1 for m in tournament.entrants if not m.expressible)
        self.count("forge_expressibility", refusals, refusals)
        other = tournament.selected is None or tournament.selected.value != "TYPED_RULE"
        self.count("forge", 1, int(other))
        return compiled, tournament

    def package_one(self, genome: HypothesisGenome, verdict: ReproducibilityVerdict,
                    novelty: NoveltyAudit) -> DiscoveryPackageV1:
        hid = genome.hypothesis_id
        compiled, tournament = self.forge(genome)
        selected = next((c for c in compiled if c.kind is tournament.selected), None)
        artifact = None if selected is None else selected.artifact
        disc = "disc-" + hid[4:]
        self.node(disc, NodeKind.DISCOVERY, (self.holdout[hid].registration_id, hid),
                  verdict.record.status.value)
        self.node(tournament.tournament_id, NodeKind.FORGE_CANDIDATE, (disc,),
                  tournament.to_dict())
        label = 1 if genome.direction is Direction.MALICIOUS else 0
        matches = _evidence_episodes([e for e in self.corpus.episodes(Split.REPLICATION)
                                      if e.label == label and genome.decides(e)])
        robust = self.robustness(genome)
        doppel = self.doppel.get(hid, ())
        failures = tuple(verdict.failing_contexts) + self.conservation(genome, compiled)
        return DiscoveryPackageV1(
            package_id="", hypothesis_id=hid, mechanism=genome.proposed_mechanism,
            direction=genome.direction, required_features=verdict.telemetry_requirements,
            detector_candidates=tournament, selected_representation=tournament.selected,
            compiled_artifact=artifact,
            evidence_lineage=self.lineage_path(tournament.tournament_id),
            evidence_digests=tuple(dict.fromkeys(d for e in matches
                                                 for d in e.evidence_digests())),
            evidence_episode_ids=tuple(e.episode_id for e in matches),
            falsification_results=self.falsification_records(genome),
            failure_conditions=failures[:16],
            resource_profile=ResourceProfile(
                artifact_bytes=None if selected is None else selected.artifact_bytes,
                work_units_per_event=tournament.deployed_work_units_per_event,
                endpoint_incremental_rss_bytes=None, loadavg=loadavg()),   # None = UNMEASURED
            robustness_profile=RobustnessProfile(
                recall_retained=tuple((r.kind.value, r.recall_retained) for r in robust),
                doppelganger_matched_share=tuple((d.family.value, d.matched_share)
                                                 for d in doppel)),
            known_technique_mappings=novelty.matched_known,
            novelty_classification=novelty.classification,
            novelty_claim_permitted=novelty.novelty_claim_permitted,
            identifiability=self.idents[hid].klass, reproducibility=verdict.record,
            artifact_hashes=artifact_hashes_for(mechanism=genome.proposed_mechanism,
                                                tournament=tournament,
                                                compiled_artifact=artifact, genome=genome),
            synthetic_data=True)

    def research_state_bytes(self, hypothesis_id: str) -> int:
        entries = [dict(e.payload) for e in self.ledger.entries()
                   if e.hypothesis_id == hypothesis_id]
        return research_state_bytes_of(self.ledger.genome(hypothesis_id), entries)

    def conservation(self, genome: HypothesisGenome,
                     compiled: Sequence[CompiledDetector]) -> tuple[FailureCondition, ...]:
        """§85 checks per entrant; their failures become the package's failure conditions."""
        doppelgangers = [e for family in DoppelgangerFamily
                         for e in self.doppel_source.benign_alternatives(
                             family, count=DOPPELGANGER_PER_FAMILY, seed=self.config.seed)]
        report = conservation_checks(genome, compiled, lab_pool=self.lab_pool,
                                     doppelgangers=doppelgangers, seed=self.config.seed,
                                     governor=self.governor)
        self.count("conservation", report.checks_run, len(report.failures))
        return report.failures

    def falsification_records(self, genome: HypothesisGenome) -> tuple[FalsificationRecord, ...]:
        records = list(self.screens.get(genome.hypothesis_id, ()))
        for registration_id in self.ledger.record(genome.hypothesis_id).experiments:
            outcome = self.ledger.outcome(registration_id)
            if outcome is not None:
                records.extend(_outcome_records(genome, outcome))
        return tuple(records[:16])

    def lineage_path(self, tip: str) -> tuple[str, ...]:
        """Root -> tip by first parents: RESIDUAL, HYPOTHESIS(es), EXPERIMENTs, DISCOVERY, FORGE."""
        lineage, path, current = self.stores.lineage, [], tip
        while current and len(path) < 64:
            path.append(current)
            node = lineage.node(current)
            current = node.parents[0] if node is not None and node.parents else ""
        return tuple(reversed(path))

    def hand_over(self) -> None:
        if self.gateway is None or not self.packages:
            return
        adapter = self.stores.adapter
        if adapter is None:
            adapter = Stage6Adapter(gateway=self.gateway, ledger=self.ledger,
                                    epoch=EpochModel(identity=SystemIdentity()).current,
                                    run_id=f"s{self.config.seed}", host_id=_LAB_HOST,
                                    synthetic=True)
            self.stores.adapter = adapter
        for package in self.packages:
            self.stores.sequence += 1
            partials = adapter.stats().get("partial_hand_overs", 0)
            try:
                receipt = adapter.hand_over(package, evidence=self.corpus.results,
                                            sequence=self.stores.sequence)
            except ContractError as exc:
                # The door refusing is the door working: recorded, never retried, never fatal.
                # A partial hand-over (S8-LIN-06) still left a receipt; its capsules keep lineage.
                self.package_problems.append(f"{package.hypothesis_id}: stage6 refused: {exc}")
                if adapter.stats().get("partial_hand_overs", 0) == partials:
                    continue
                receipt = adapter.receipts()[-1]
            self.receipts.append(receipt)
            self.count("stage6_adapter", len(receipt.capsule_ids), receipt.trusted_candidates)
            for capsule_id in receipt.capsule_ids:
                self.node(capsule_id, NodeKind.STAGE6_CAPSULE, (package.evidence_lineage[-1],),
                          capsule_id)

    # -- the NAIVE control ----------------------------------------------------------------------

    def naive(self, candidates: Sequence[HypothesisGenome]) -> None:
        """Select on TRAIN at the genome's own HOLDOUT rules: no vault, no screens (control)."""
        m = max(1, len(candidates)) if self.config.bonferroni else 1
        for genome in candidates:
            counts = fit_counts(genome.decides, self.train, meter=self.governor.meter)
            if _passes_on_train(genome, oriented_fit(counts, genome.direction),
                                self.knobs.alpha / m):
                self.naive_selected.append(genome.hypothesis_id)


def _evidence_episodes(matches: Sequence[Episode]) -> list[Episode]:
    """The REPLICATION matches a package names as evidence: every one's digests fit the package.

    The adapter refuses an evidence session whose digests the package does not list
    (S8-AUTH-01), and the package lists at most ``MAX_PACKAGE_EVIDENCE`` digests, so sessions
    are taken in order while their digest union still fits (at most ``MAX_EVIDENCE_EPISODES``).
    """
    chosen: list[Episode] = []
    digests: set[str] = set()
    for episode in matches:
        union = digests | set(episode.evidence_digests())
        if len(chosen) >= MAX_EVIDENCE_EPISODES or len(union) > MAX_PACKAGE_EVIDENCE:
            break
        chosen.append(episode)
        digests = union
    return chosen


def _outcome_records(genome: HypothesisGenome,
                     outcome: TestOutcome) -> list[FalsificationRecord]:
    oriented = oriented_fit(outcome.counts, genome.direction)
    statistic = {
        FalsifierKind.HOLDOUT_ENRICHMENT: outcome.p_value,
        FalsifierKind.REPLICATION: outcome.p_value,
        FalsifierKind.HOLDOUT_FALSE_POSITIVES: oriented.false_positive_rate,
        FalsifierKind.HOLDOUT_RECALL: oriented.recall,
    }
    records = []
    for falsifier in genome.falsification_tests:
        if falsifier.split is not outcome.split:
            continue
        passed = (outcome.survived if falsifier.kind is FalsifierKind.REPLICATION
                  else falsifier.kind.value not in outcome.reasons)
        parameter = falsifier.alpha if falsifier.alpha is not None else falsifier.threshold
        records.append(FalsificationRecord(
            kind=falsifier.kind, split=falsifier.split, passed=passed,
            statistic=statistic.get(falsifier.kind), parameter=parameter,
            registration_id=outcome.registration_id))
    return records


def _passes_on_train(genome: HypothesisGenome, counts: Any, alpha: float) -> bool:
    """The HOLDOUT refutation rules applied in-sample: what a scientist without a vault does."""
    limits = {f.kind: f.threshold for f in genome.falsification_tests}
    total = counts.positives + counts.negatives
    if counts.matched == 0 or total == 0:
        return False
    p_value = binomial_upper_tail(counts.true_matches, counts.matched, counts.positives / total)
    fpr, recall = counts.false_positive_rate, counts.recall
    return (p_value <= alpha
            and fpr is not None and fpr <= limits[FalsifierKind.HOLDOUT_FALSE_POSITIVES]
            and recall is not None and recall >= limits[FalsifierKind.HOLDOUT_RECALL])


def run_discovery(corpus: DiscoveryCorpus, config: RunConfig, *,
                  gateway: QuarantineGateway | None = None) -> DiscoveryRunReport:
    """The whole loop on one corpus. ``gateway`` given -> packages handed to Stage 6's door."""
    return _execute(corpus, config, gateway=gateway, knobs=_Knobs(), stores=None)


def _execute(corpus: DiscoveryCorpus, config: RunConfig, *, gateway: QuarantineGateway | None,
             knobs: _Knobs, stores: _Stores | None) -> DiscoveryRunReport:
    _check_config(corpus, config)
    run = _Run(corpus, config, knobs, stores, gateway)
    started = time.perf_counter()
    try:
        _drive(run)
    except WorkBudgetExceeded:
        run.budget_exhausted = True
    return _report(run, time.perf_counter() - started)


def _drive(run: _Run) -> None:
    run.generate(run.observe())
    candidates = run.candidates()
    if not run.config.holdout_discipline:
        run.naive(candidates)
        return
    registered = run.rank(run.run_oracle(run.screen(candidates)))
    survivors = run.run_holdout(registered)
    run.identify(survivors)
    run.package_all(run.reproduce(survivors))
    run.hand_over()


def _trap(run: _Run) -> TrapOutcome:
    digest = run.corpus.trap_mechanism.digest()
    ids = [h for h in run.born if run.genomes[h].direction is Direction.MALICIOUS
           and run.genomes[h].proposed_mechanism.digest() == digest]
    if not ids:
        return TrapOutcome(generated=False, registered=False, refuted=False, hypothesis_id=None)
    if not run.config.holdout_discipline:   # the control never refutes: did it "find" the trap?
        chosen = [h for h in ids if h in run.naive_selected]
        return TrapOutcome(generated=True, registered=False, refuted=False,
                           hypothesis_id=(chosen or ids)[0])
    # Only trap genomes the discipline actually tested count; a duplicate the population refused
    # was never a live theory. Refuted = at least one tested, and every tested one refuted.
    registered = [h for h in ids if h in run.registered]
    tested = [h for h in ids if h in run.screens or h in run.registered]
    refuted = bool(tested) and all(run.ledger.status(h) in _REFUTED for h in tested)
    where = sorted({run.refuted_at[h] for h in ids if h in run.refuted_at})
    return TrapOutcome(generated=True, registered=bool(registered), refuted=refuted,
                       hypothesis_id=(registered or tested or ids)[0],
                       refuted_at=",".join(where) or None)


def _planted(run: _Run) -> tuple[tuple[tuple[str, bool], ...], int]:
    """Planted families a theory recovers; how many 'found' theories match no planted one."""
    replication = run.corpus.episodes(Split.REPLICATION)
    ids = run.reproduced if run.config.holdout_discipline else run.naive_selected
    recovered: dict[str, bool] = {family.value: False for family in PLANTED_MECHANISMS}
    false_count = 0
    for genome in (run.genomes[h] for h in ids):
        hits = [family.value for family in PLANTED_MECHANISMS
                if (agreement(genome.decides, _planted_decider(family), replication) or 0.0)
                >= PLANTED_AGREEMENT_MIN]
        # On NULL every "discovery" is false: the labels carry no mechanism at all.
        if run.corpus.arm is CorpusArm.NULL or not hits or genome.direction is Direction.BENIGN:
            false_count += 1
            continue
        for family in hits:
            recovered[family] = True
    return tuple(sorted(recovered.items())), false_count


def _outcomes(run: _Run) -> tuple[tuple[str, str], ...]:
    if not run.config.holdout_discipline:
        return tuple(sorted((_dsl(run.genomes[h]), "SELECTED_ON_TRAIN")
                            for h in run.naive_selected))
    return tuple(sorted((_dsl(run.genomes[h]), run.ledger.status(h).value)
                        for h in run.registered))


def _leaders(run: _Run) -> tuple[tuple[str, str], ...]:
    return tuple((r.leading, _dsl(run.genomes[r.leading]))
                 for r in run.oracle if r.leading is not None)


def _report(run: _Run, wall: float) -> DiscoveryRunReport:
    ledger, field_ = run.ledger, run.field
    for hid in run.registered:   # a generator changed an outcome when its birth was tested
        kind = run.genomes[hid].provenance.generator
        run.count(_ECOLOGY_NAMES.get(kind, f"generator:{kind.value}"), 0, 1)
    planted, false_reproduced = _planted(run)
    discipline = run.config.holdout_discipline
    if discipline:
        survived = tuple(h for h in run.registered if run.holdout.get(h) is not None
                         and run.holdout[h].survived)
        reproduced = tuple(run.reproduced)
    else:
        survived = reproduced = tuple(run.naive_selected)
    statuses = [ledger.status(h) for h in run.born]
    return DiscoveryRunReport(
        config=run.config, residual_total=0 if field_ is None else field_.total,
        residual_explained=0 if field_ is None else field_.explained,
        clusters=0 if field_ is None else len(field_.clusters),
        generation=tuple(run.generation), evolution=tuple(run.evolution),
        oracle=tuple(run.oracle), births=len(run.born),
        challenged_out=sum(s is TheoryStatus.CHALLENGED_OUT for s in statuses),
        registered=len(run.registered), survived=survived,
        falsified=sum(s is TheoryStatus.FALSIFIED for s in statuses), reproduced=reproduced,
        identifiability=tuple(run.idents.values()), novelty=tuple(run.novelty),
        packages=tuple(run.packages), receipts=tuple(run.receipts), planted_recovered=planted,
        false_reproduced=false_reproduced, trap=_trap(run),
        firings=tuple(ComponentFiring(k, v[0], v[1]) for k, v in sorted(run.fire.items())),
        governor=run.governor.report(), ledger_problems=ledger.verify_chain(),
        wall_seconds=wall, loadavg=loadavg(), synthetic_data=True,
        budget_exhausted=run.budget_exhausted or run.governor.exhausted(),
        precondition_problems=run.precondition_problems, outcomes=_outcomes(run),
        package_problems=tuple(run.package_problems), oracle_leaders=_leaders(run),
        adapter_created=0 if run.stores.adapter is None else run.stores.adapter.created(),
        adapter_admitted=0 if run.stores.adapter is None else run.stores.adapter.admitted(),
        ledger=ledger, lineage=run.stores.lineage)


def probe_trap_at_holdout(corpus: DiscoveryCorpus, *, seed: int = 0) -> TrapOutcome:
    """Preregister the trap genome ALONE on HOLDOUT and let the vault decide (G8.1(d) probe).

    ``run_discovery`` refutes the trap earlier when a pre-holdout screen catches it; this probe
    isolates the vault: a hypothesis true on TRAIN by construction must be falsified held out.
    """
    governor, ledger = ResearchGovernor(ResearchBudget()), TheoryLedger()
    trap = corpus.trap_mechanism
    scope_ids = tuple(e.episode_id for e in corpus.episodes(Split.TRAIN)
                      if trap.matches(e.steps))[:64]
    scope = ObservationScope(residual_cluster_ids=(), episode_ids=scope_ids,
                             residual_types=frozenset({ResidualType.OBSERVATION}))
    provenance = GenomeProvenance(generator=GeneratorKind.SYMBOLIC_ENUMERATOR,
                                  source_digest=content_digest({"trap": scope_ids}),
                                  foreign=False, seed=seed)
    genome = genome_for(trap, direction=Direction.MALICIOUS, scope=scope, provenance=provenance)
    ledger.record_birth(genome)
    vault = HoldoutVault(corpus.episodes(Split.HOLDOUT), split=Split.HOLDOUT, ledger=ledger,
                         governor=governor)
    prediction = next(p for p in genome.predicted_observations if p.split is Split.HOLDOUT)
    registration = PreRegistration(registration_id="", hypothesis_id=genome.hypothesis_id,
                                   genome_digest=genome.digest(), split=Split.HOLDOUT,
                                   split_digest=vault.split_digest(), batch_size=1, alpha=ALPHA,
                                   prediction=prediction)
    ledger.preregister(registration)
    (outcome,) = vault.evaluate(vault.seal_batch([registration]))
    return TrapOutcome(generated=True,
                       registered=ledger.registered_before_tested(genome.hypothesis_id),
                       refuted=not outcome.survived, hypothesis_id=genome.hypothesis_id,
                       refuted_at=None if outcome.survived else "HOLDOUT")


# -- endurance ------------------------------------------------------------------------------------

_STORE_CAPS: Mapping[str, int] = MappingProxyType({
    "ledger_entries": MAX_LEDGER_ENTRIES + 1,    # + the CHECKPOINT that records a head drop
    "ledger_theories": MAX_THEORIES, "negative_results": MAX_NEGATIVE_RESULTS,
    "lineage_nodes": MAX_LINEAGE_NODES, "population": MAX_POPULATION,
    "adapter_receipts": MAX_ADAPTER_RECEIPTS,
})
_EVICTION_WORDS = ("evict", "drop", "fold", "collected", "refused", "replaced", "fossilized",
                   "negative_results_written")


def _store_sizes(stores: _Stores) -> dict[str, int]:
    return {
        "ledger_entries": len(stores.ledger.entries()),
        "ledger_theories": int(stores.ledger.stats().get("theories", 0)),
        "negative_results": int(stores.negative.stats().get("size", 0)),
        "lineage_nodes": int(stores.lineage.stats().get("nodes", 0)),
        "population": len(stores.population.members()),
        "adapter_receipts": 0 if stores.adapter is None else len(stores.adapter.receipts()),
    }


def _evictions(stores: _Stores) -> dict[str, int]:
    counters = {
        "ledger": stores.ledger.stats(), "negative_results": stores.negative.stats(),
        "lineage": stores.lineage.stats(), "population": stores.population.stats(),
        "adapter": {} if stores.adapter is None else stores.adapter.stats(),
    }
    return {f"{store}.{key}": int(value) for store, stats in counters.items()
            for key, value in stats.items() if any(w in key for w in _EVICTION_WORDS)}


def _end_cycle(stores: _Stores, report: DiscoveryRunReport) -> None:
    """Fossilize untested theories that left the population; collect unreachable lineage."""
    members = {g.hypothesis_id for g in stores.population.members()}
    for hid in stores.ledger.hypothesis_ids(TheoryStatus.PROPOSED):
        if hid not in members:
            stores.ledger.set_status(hid, TheoryStatus.FOSSILIZED, reason="endurance_retired")
    keep = [p.evidence_lineage[-1] for p in report.packages] + sorted(members)
    stores.lineage.collect(k for k in keep if stores.lineage.has(k))


def run_endurance(*, cycles: int = 12, seed: int = 0,
                  counts: Mapping[Split, int] = ENDURANCE_COUNTS,
                  budget: ResearchBudget = ResearchBudget()) -> EnduranceReport:
    """Stage 1 -> Stage 8 -> lab Stage 6, ``cycles`` times, with ONE long-lived research state."""
    if isinstance(cycles, bool) or not isinstance(cycles, int) or cycles < 1:
        raise ContractError(f"cycles must be an int >= 1, got {cycles!r}")
    config = RunConfig(arm=CorpusArm.PLANTED, seed=seed, budget=budget)
    # The long-lived population charges its own governor; it gets one run's budget per cycle,
    # so a cycle is never starved by the cycles before it (chosen, not measured).
    fields = {name: getattr(budget, name) for name in budget.__dataclass_fields__}
    lifetime = ResearchBudget(**{**fields, "work_units": budget.work_units * cycles})
    stores = _Stores.fresh(config, _Knobs(), ResearchGovernor(lifetime))
    gateway = lab_gateway()
    sizes: dict[str, list[int]] = {name: [] for name in _STORE_CAPS}
    packages, failures, started, rss_start = 0, [], time.perf_counter(), read_rss_bytes()
    with ResourceSampler() as sampler:
        for cycle in range(cycles):
            corpus = build_discovery_corpus(arm=CorpusArm.PLANTED, seed=seed + cycle,
                                            counts=counts)
            cycle_config = RunConfig(arm=CorpusArm.PLANTED, seed=seed + cycle, budget=budget)
            try:
                report = _execute(corpus, cycle_config, gateway=gateway, knobs=_Knobs(),
                                  stores=stores)
                _end_cycle(stores, report)
            except ContractError as exc:
                # The long-lived state is inconsistent: a finding, reported, never retried.
                failures.append(f"cycle {cycle}: {type(exc).__name__}: {exc}")
                break
            packages += len(report.packages)
            for name, value in _store_sizes(stores).items():
                sizes[name].append(value)
    peak = sampler.result(events_processed=cycles, startup_seconds=None).peak_sampled_rss_bytes
    return _endurance_report(cycles, sizes, stores, (rss_start, peak), packages,
                             time.perf_counter() - started, failures)


def _endurance_report(cycles: int, sizes: Mapping[str, list[int]], stores: _Stores,
                      rss: tuple[int | None, int | None], packages: int, wall: float,
                      failures: Sequence[str] = ()) -> EnduranceReport:
    problems = list(failures)
    problems += [f"{name} exceeded its cap {_STORE_CAPS[name]} (max {max(values)})"
                 for name, values in sizes.items()
                 if values and max(values) > _STORE_CAPS[name]]
    problems.extend(f"ledger: {p}" for p in stores.ledger.verify_chain())
    adapter = stores.adapter
    created = 0 if adapter is None else adapter.created()
    admitted = 0 if adapter is None else adapter.admitted()
    if created != admitted:
        problems.append(f"adapter created {created} != admitted {admitted}")
    return EnduranceReport(
        cycles=cycles, store_sizes=tuple((k, tuple(v)) for k, v in sizes.items()),
        evictions=tuple(sorted(_evictions(stores).items())), plateau_ok=not problems,
        rss_start=rss[0], rss_peak=rss[1], loadavg=loadavg(),
        store_caps=tuple(_STORE_CAPS.items()), problems=tuple(problems), packages=packages,
        capsules_created=created, capsules_admitted=admitted, wall_seconds=wall,
        cycles_completed=len(next(iter(sizes.values()), [])))
