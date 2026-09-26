"""D8.6 / PROM-F08 — the ORACLE planner: the cheapest safe experiment that most separates theories.

Architecture §14: ``X* = argmax EIG(X) / (CPU + RAM + time + privacy + safety + lab cost)``. PROMETHEUS
leaves several live theories per residual cluster, often incompatible on purpose (§10). ORACLE
spends a bounded number of experiments telling them apart *before* anything is registered, so the
holdout vault is asked about fewer, better-separated theories.

The experiments (§16, §40), kept as separate ``ExperimentClass`` values and counted separately so
classification uncertainty is never confused with causal uncertainty:

- **Active learning — HISTORICAL_REPLAY.** Recorded LAB_POOL episodes on which the theories'
  predicted labels disagree (for a one-direction set: matched by some but not all), grouped into
  strata of identical disagreement. Replay can only separate theories that already disagree.
- **Active experimentation — COUNTERFACTUAL_MUTATION / METAMORPHIC_TRANSFORM / TELEMETRY_DROPOUT.**
  One design per laboratory ``TransformKind`` (and per necessary predicate for targeted kinds),
  applied to the LAB_POOL episodes at least one theory matches: interventions *create* the
  disagreements replay cannot find (PRECEDES vs CO_OCCURS needs REORDER).

What it refuses to do, each by construction:

- **Run anything the sandbox has not allowed.** Every design is put to
  ``ResearchSandbox.decide`` *first*, before a single transform is applied; a refusal is recorded
  in the report and the design is never built. ISOLATED_EMULATION is designed only when a theory
  requests it, is always refused (there is no emulator, ADR-0075), and is never run even if a
  sandbox were to allow it. Only emulation left → stop ``SAFETY``.
- **Invent labels.** A PRESERVING transform keeps its source's recorded label. UNKNOWN or
  DESTROYING transforms need the authorised lab oracle; with ``lab=None`` — the **production
  default**, observation and replay only (architecture §3) — those designs do not exist.
- **Admit adversarial evidence.** The pool must be LAB_POOL; a CHALLENGE (or any other) episode is
  refused at the door, so no adversary's episode ever moves a posterior. The worlds this planner
  derives itself are labelled only by a preserved recording or the lab oracle.
- **Decide survival.** The posterior orders and prunes: a theory whose posterior is under
  :data:`PRUNE_POSTERIOR` times the leader's (relative, so group size alone never prunes, and the
  leader always survives; S8-RES-2) is retired ``FOSSILIZED`` (reason ``oracle_posterior``) in the ledger, so it is never registered.
  It is not recorded ``CHALLENGED_OUT``: the ledger admits that only after a failed preregistered
  CHALLENGE_RESULT, and a posterior is not a falsifier (ADR-0078). FOSSILIZED is not a dead end
  for negative memory, so a pruned mechanism can be proposed again. Only the vault can mark a
  theory SURVIVED or FALSIFIED.
- **Pretend a telemetry gap is a mechanism.** A cluster whose ``visibility_share`` is at least
  :data:`TELEMETRY_FAILURE_SHARE` stops ``TELEMETRY_FAILURE`` before any experiment (§43).

Each theory is read as a classifier over a design's episodes (MALICIOUS: match ⇒ 1, else 0;
BENIGN: match ⇒ 0, else 1) — the documented likelihood approximation of §41. Every step is charged
to the governor; a runaway plan hits ``WorkBudgetExceeded`` and stops ``BUDGET``.
"""

from __future__ import annotations

import hashlib
import math
import random
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Protocol

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage6.resources import WorkBudgetExceeded
from pocketsec.stage8.episode import Episode, Split
from pocketsec.stage8.genome.grammar import StepPredicate
from pocketsec.stage8.genome.hypothesis import Direction, ExperimentClass, HypothesisGenome
from pocketsec.stage8.governor.budget import ResearchGovernor
from pocketsec.stage8.laboratory.counterfactual import (
    TRANSFORM_SEMANTICS, Semantics, TransformKind, TransformSpec, apply_transform,
    decoy_is_neutral,
)
from pocketsec.stage8.ledger.theory import LedgerError, TheoryLedger, TheoryStatus
from pocketsec.stage8.oracle.information_gain import (
    Posterior, expected_information_gain, uniform_prior, update,
)
from pocketsec.stage8.sandbox.boundary import (
    LabClearance, ResearchSandbox, SandboxDecision, SandboxOutcome,
)

__all__ = [
    "DEFAULT_TRANSFORM_PARAMETERS", "EMULATION_COST_UNITS", "MAX_ORACLE_EXPERIMENTS",
    "MAX_TARGET_PREDICATES", "PRUNE_POSTERIOR", "PRUNE_REASON", "STOP_EIG_PER_UNIT",
    "STOP_POSTERIOR", "TARGETED_TRANSFORMS", "TELEMETRY_FAILURE_SHARE", "ExperimentDesign",
    "ExperimentRecord", "LabLabeller", "OraclePlanner", "OracleReport", "SelectionPolicy",
    "StopReason", "experiment_class_for", "select_design",
]

#: §4.21. Chosen parameters, not measurements.
STOP_POSTERIOR: float = 0.95
STOP_EIG_PER_UNIT: float = 1e-4
#: A theory is pruned when its posterior falls under this share of the leader's posterior.
PRUNE_POSTERIOR: float = 0.01
MAX_ORACLE_EXPERIMENTS: int = 16
TELEMETRY_FAILURE_SHARE: float = 0.5
PRUNE_REASON: str = "oracle_posterior"
#: Distinct necessary predicates used as transform targets per design round. Chosen.
MAX_TARGET_PREDICATES: int = 8
#: What an emulation design would cost if one could ever run. Chosen; never charged.
EMULATION_COST_UNITS: int = 1_000_000

#: Kinds whose ``TransformSpec.target`` names the step they act on (D8.7), plus SENSOR_DROPOUT,
#: whose dropped ``RelationFamily`` is the target predicate's.
TARGETED_TRANSFORMS: frozenset[TransformKind] = frozenset({
    TransformKind.NECESSARY_STEP_DELETION, TransformKind.REORDER, TransformKind.ACTOR_SPLIT,
    TransformKind.DESTINATION_CLASS_SWAP, TransformKind.SENSOR_DROPOUT,
})
#: One chosen parameter per kind (permille, slot offset, bucket delta or decoy count).
DEFAULT_TRANSFORM_PARAMETERS: Mapping[TransformKind, int] = MappingProxyType({
    TransformKind.ACTOR_RENAME: 1, TransformKind.TIMING_SHIFT: 1,
    TransformKind.SENSOR_DROPOUT: 1000, TransformKind.PARENT_SUBSTITUTION: 1,
    TransformKind.DESTINATION_CLASS_SWAP: 0, TransformKind.EPOCH_CHANGE: 1,
    TransformKind.DECOY_INSERTION: 2, TransformKind.NECESSARY_STEP_DELETION: 0,
    TransformKind.REORDER: 0, TransformKind.ACTOR_SPLIT: 0,
})


class SelectionPolicy(StrEnum):
    EIG_PER_COST = "eig_per_cost"
    EIG_ONLY = "eig_only"  # control: cost-blind
    RANDOM = "random"  # control: uniform over the runnable designs
    CHEAPEST = "cheapest"  # control: lowest cost first


class StopReason(StrEnum):
    """§43's stopping rules, plus the empty case."""

    IDENTIFIED = "identified"
    OBSERVATIONALLY_EQUIVALENT = "observationally_equivalent"
    EIG_BELOW_COST = "eig_below_cost"
    BUDGET = "budget"
    SAFETY = "safety"
    NO_EXPERIMENTS = "no_experiments"
    TELEMETRY_FAILURE = "telemetry_failure"


class LabLabeller(Protocol):
    """The authorised synthetic-world ground truth (``labs.discovery_corpus.LabOracle``).

    A protocol, not an import: runtime Stage 8 modules never import ``labs`` (boundary rule 10).
    """

    def label(self, episode: Episode) -> int: ...


@dataclass(frozen=True, slots=True)
class ExperimentDesign:
    design_id: str
    experiment_class: ExperimentClass
    transform: TransformSpec | None
    episode_ids: tuple[str, ...]  # ≤ max_counterfactual_worlds
    cost_units: int
    privacy_cost: float
    safety_risk: float

    def __post_init__(self) -> None:
        if not isinstance(self.experiment_class, ExperimentClass):
            raise ContractError("ExperimentDesign.experiment_class must be an ExperimentClass")
        if isinstance(self.cost_units, bool) or not isinstance(self.cost_units, int) \
                or self.cost_units < 0:
            raise ContractError("ExperimentDesign.cost_units must be an int >= 0")
        for name in ("privacy_cost", "safety_risk"):
            value = getattr(self, name)
            if not isinstance(value, float) or not 0.0 <= value <= 1.0:
                raise ContractError(f"ExperimentDesign.{name} must be a float in [0, 1]")


@dataclass(frozen=True, slots=True)
class ExperimentRecord:
    design: ExperimentDesign
    eig_bits: float
    observed: tuple[int | None, ...]
    posterior_after: Posterior
    sandbox: SandboxDecision


@dataclass(frozen=True, slots=True)
class OracleReport:
    policy: SelectionPolicy
    experiments: tuple[ExperimentRecord, ...]
    stop: StopReason
    final_posterior: Posterior
    leading: str | None
    pruned: tuple[str, ...]
    work_units: int
    lab_oracle_used: bool
    # Beyond the spec's minimum: what the lead's rules ask to be visible (§40, §43, lesson 1).
    refused: tuple[SandboxDecision, ...] = ()
    active_learning: int = 0  # HISTORICAL_REPLAY experiments run
    active_experimentation: int = 0  # transform experiments run
    designs_offered: int = 0
    designs_needing_lab: int = 0  # UNKNOWN/DESTROYING designs withheld because lab is None
    queue_truncated: int = 0
    visibility_share: float | None = None


def experiment_class_for(kind: TransformKind) -> ExperimentClass:
    """SENSOR_DROPOUT is telemetry dropout; PRESERVING kinds are metamorphic; the rest counterfactual."""
    if kind is TransformKind.SENSOR_DROPOUT:
        return ExperimentClass.TELEMETRY_DROPOUT
    if TRANSFORM_SEMANTICS[kind] is Semantics.PRESERVING:
        return ExperimentClass.METAMORPHIC_TRANSFORM
    return ExperimentClass.COUNTERFACTUAL_MUTATION


def select_design(
    candidates: Sequence[tuple[ExperimentDesign, float]],
    policy: SelectionPolicy,
    rng: random.Random,
) -> int:
    """Index of the design ``policy`` picks from ``(design, EIG bits)`` pairs; ties by cost then id."""
    if not candidates:
        raise ContractError("select_design needs at least one candidate")
    if not isinstance(policy, SelectionPolicy):
        raise ContractError(f"unknown selection policy {policy!r}")
    order = sorted(range(len(candidates)), key=lambda i: candidates[i][0].design_id)
    if policy is SelectionPolicy.RANDOM:
        return rng.choice(order)
    return min(order, key=lambda i: _policy_key(policy, *candidates[i]))


def _policy_key(policy: SelectionPolicy, design: ExperimentDesign, eig: float) -> tuple[float, ...]:
    """Smaller is better; cost then id (via the caller's stable order) break ties."""
    if policy is SelectionPolicy.CHEAPEST:
        return (float(design.cost_units),)
    if policy is SelectionPolicy.EIG_ONLY:
        return (-eig, float(design.cost_units))
    return (-_per_unit(eig, design), float(design.cost_units))


def _per_unit(eig: float, design: ExperimentDesign) -> float:
    return eig / (design.cost_units + 1)


def _digest(*parts: str) -> str:
    return "sha256:" + hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def _predicate_key(predicate: StepPredicate | None) -> str:
    if predicate is None:
        return "-"
    return (f"{predicate.relation}:{predicate.require_properties}:"
            f"{predicate.forbid_properties}:{predicate.require_raised}")


def _predict(genome: HypothesisGenome, episode: Episode) -> int:
    fires = genome.decides(episode)
    return int(fires) if genome.direction is Direction.MALICIOUS else int(not fires)


@dataclass(frozen=True, slots=True)
class _Plan:
    """A runnable design and everything needed to run it; private to one planner."""

    design: ExperimentDesign
    decision: SandboxDecision
    episodes: tuple[Episode, ...]
    predictions: Mapping[str, tuple[int, ...]]
    needs_lab: bool


class OraclePlanner:
    """PROM-F08. Plans and runs at most :data:`MAX_ORACLE_EXPERIMENTS` safe experiments per call."""

    def __init__(
        self,
        *,
        sandbox: ResearchSandbox,
        lab: LabLabeller | None,
        governor: ResearchGovernor,
        policy: SelectionPolicy = SelectionPolicy.EIG_PER_COST,
        rng: random.Random,
        ledger: TheoryLedger | None = None,
        clearances: Sequence[LabClearance] = (),
        max_experiments: int = MAX_ORACLE_EXPERIMENTS,
    ) -> None:
        if not isinstance(sandbox, ResearchSandbox) or not isinstance(governor, ResearchGovernor):
            raise ContractError("OraclePlanner needs a ResearchSandbox and a ResearchGovernor")
        if lab is not None and not callable(getattr(lab, "label", None)):
            raise ContractError("lab must provide label(episode) -> int, or be None")
        if not isinstance(policy, SelectionPolicy) or not isinstance(rng, random.Random):
            raise ContractError("OraclePlanner needs a SelectionPolicy and a random.Random")
        if ledger is not None and not isinstance(ledger, TheoryLedger):
            raise ContractError("ledger must be a TheoryLedger or None")
        if isinstance(max_experiments, bool) or not isinstance(max_experiments, int) \
                or not 1 <= max_experiments <= MAX_ORACLE_EXPERIMENTS:
            raise ContractError(f"max_experiments must be in 1..{MAX_ORACLE_EXPERIMENTS}")
        self._sandbox = sandbox
        self._lab = lab
        self._governor = governor
        self._policy = policy
        self._rng = rng
        self._ledger = ledger
        self._clearances = {c.experiment_class: c for c in clearances}
        self._max_experiments = max_experiments
        self._sequence = 0
        self._plans: list[_Plan] = []
        self._refused: list[SandboxDecision] = []
        self._needing_lab = 0
        self._truncated = 0
        self._lab_calls = 0
        self._counters: dict[str, int] = dict.fromkeys(
            ("runs", "experiments", "designs_built", "sandbox_refused", "transforms_refused",
             "transforms_empty", "emulation_unrunnable", "pruned", "prune_not_recorded",
             "prune_refused_by_ledger", "lab_labels", "decoys_not_neutral"), 0)

    # --- designing ---------------------------------------------------------------

    def candidate_designs(
        self, hypotheses: Sequence[HypothesisGenome], pool: Sequence[Episode]
    ) -> tuple[ExperimentDesign, ...]:
        """Every runnable, sandbox-ALLOWED design for ``hypotheses`` over the LAB_POOL ``pool``."""
        genomes, episodes = self._check_inputs(hypotheses, pool)
        self._plans, self._refused = [], []
        self._needing_lab = self._truncated = 0
        budget = self._governor.report().budget
        worlds, queue = budget.max_counterfactual_worlds, budget.max_experiment_queue
        matrix = self._prediction_matrix(genomes, episodes)
        sources = tuple(ep for ep, column in zip(episodes, matrix) if self._any_fires(genomes, column))
        self._replay_designs(genomes, episodes, matrix, worlds, queue)
        for kind in TransformKind:
            for target in self._targets(genomes, kind):
                try:
                    spec = TransformSpec(kind=kind, parameter=DEFAULT_TRANSFORM_PARAMETERS[kind],
                                         target=target)
                except ContractError:  # the laboratory refuses the parameter: counted, skipped
                    self._counters["transforms_refused"] += 1
                    continue
                self._transform_design(genomes, sources[:worlds], spec, queue)
        if any(ExperimentClass.ISOLATED_EMULATION in g.information_requests for g in genomes):
            self._emulation_design(sources[:worlds])
        return tuple(plan.design for plan in self._plans)

    def _check_inputs(
        self, hypotheses: Sequence[HypothesisGenome], pool: Sequence[Episode]
    ) -> tuple[tuple[HypothesisGenome, ...], tuple[Episode, ...]]:
        genomes = tuple(sorted(hypotheses, key=lambda g: getattr(g, "hypothesis_id", "")))
        if not genomes or any(not isinstance(g, HypothesisGenome) for g in genomes):
            raise ContractError("ORACLE needs >= 1 HypothesisGenome")
        if len({g.hypothesis_id for g in genomes}) != len(genomes):
            raise ContractError("ORACLE hypotheses must have distinct ids")
        episodes = tuple(sorted({e.episode_id: e for e in pool}.values(), key=lambda e: e.episode_id)) \
            if all(isinstance(e, Episode) for e in pool) else None
        if episodes is None or any(e.split is not Split.LAB_POOL for e in episodes):
            # CHALLENGE and every other split are refused here: no adversarially generated or
            # held-out episode ever reaches a posterior.
            raise ContractError("ORACLE's pool must be LAB_POOL episodes only")
        return genomes, episodes

    def _prediction_matrix(
        self, genomes: Sequence[HypothesisGenome], episodes: Sequence[Episode]
    ) -> tuple[tuple[int, ...], ...]:
        """Per episode, each theory's predicted label (the theories in id order)."""
        self._governor.charge("oracle_planning", len(genomes) * sum(len(e.steps) for e in episodes))
        return tuple(tuple(_predict(g, ep) for g in genomes) for ep in episodes)

    @staticmethod
    def _any_fires(genomes: Sequence[HypothesisGenome], column: Sequence[int]) -> bool:
        target = {Direction.MALICIOUS: 1, Direction.BENIGN: 0}
        return any(value == target[g.direction] for g, value in zip(genomes, column))

    def _authorise(self, experiment_class: ExperimentClass, scope_digest: str) -> SandboxDecision:
        self._sequence += 1
        decision = self._sandbox.decide(
            experiment_class, clearance=self._clearances.get(experiment_class),
            scope_digest=scope_digest, sequence=self._sequence,
        )
        if decision.outcome is not SandboxOutcome.ALLOWED:
            self._refused.append(decision)
            self._counters["sandbox_refused"] += 1
        return decision

    def _queue_full(self, queue: int) -> bool:
        if len(self._plans) >= queue:
            self._truncated += 1
            return True
        return False

    def _replay_designs(self, genomes: Sequence[HypothesisGenome], episodes: Sequence[Episode],
                        matrix: Sequence[tuple[int, ...]], worlds: int, queue: int) -> None:
        """Active learning: one design per stratum of labelled episodes the theories disagree on."""
        strata: dict[tuple[int, ...], list[Episode]] = {}
        for episode, column in zip(episodes, matrix):
            if episode.label is not None and len(set(column)) > 1:
                strata.setdefault(column, []).append(episode)
        for column in sorted(strata):
            if self._queue_full(queue):
                return
            members = tuple(strata[column][:worlds])
            ids = tuple(e.episode_id for e in members)
            decision = self._authorise(ExperimentClass.HISTORICAL_REPLAY,
                                       _digest("replay", *ids))
            if decision.outcome is not SandboxOutcome.ALLOWED:
                continue
            self._add_plan(ExperimentClass.HISTORICAL_REPLAY, None, members, genomes, decision,
                           needs_lab=False, cost=sum(len(e.steps) for e in members))

    def _targets(
        self, genomes: Sequence[HypothesisGenome], kind: TransformKind
    ) -> tuple[StepPredicate | None, ...]:
        if kind not in TARGETED_TRANSFORMS:
            return (None,)
        found = dict.fromkeys(p for g in genomes for p in g.necessary_conditions)
        return tuple(found)[:MAX_TARGET_PREDICATES]

    def _transform_design(self, genomes: Sequence[HypothesisGenome], sources: Sequence[Episode],
                          spec: TransformSpec, queue: int) -> None:
        """Active experimentation: authorise, then derive the worlds, then predict on them."""
        needs_lab = TRANSFORM_SEMANTICS[spec.kind] is not Semantics.PRESERVING
        if needs_lab and self._lab is None:
            self._needing_lab += 1  # production default: no ground truth for this design
            return
        if not sources or self._queue_full(queue):
            return
        klass = experiment_class_for(spec.kind)
        decision = self._authorise(klass, _digest(str(klass), str(spec.kind), str(spec.parameter),
                                                  _predicate_key(spec.target),
                                                  *(e.episode_id for e in sources)))
        if decision.outcome is not SandboxOutcome.ALLOWED:
            return
        self._governor.charge("oracle_planning", sum(len(e.steps) for e in sources))
        # A decoyed world keeps its source label only for theories none of whose predicates a
        # decoy step matches (F1); worlds some theory in the group names are left out.
        avoid = tuple(dict.fromkeys(p for g in genomes for p in (
            *g.proposed_mechanism.steps, *g.forbidden_observations)))
        derived: dict[str, Episode] = {}
        for source in sources:
            try:
                world = apply_transform(source, spec, rng=self._rng)
            except ContractError:  # the laboratory refuses this spec: no design, counted
                self._counters["transforms_refused"] += 1
                return
            if world is not None and spec.kind is TransformKind.DECOY_INSERTION \
                    and not decoy_is_neutral(source, world, avoid):
                self._counters["decoys_not_neutral"] += 1  # F1: a theory names this decoy
                continue
            if world is not None and (needs_lab or world.label is not None):
                derived.setdefault(world.episode_id, world)
        if not derived:
            self._counters["transforms_empty"] += 1
            return
        members = tuple(derived.values())
        steps = sum(len(e.steps) for e in members)
        self._add_plan(klass, spec, members, genomes, decision, needs_lab=needs_lab,
                       cost=2 * steps + (steps if needs_lab else 0))

    def _emulation_design(self, sources: Sequence[Episode]) -> None:
        ids = tuple(e.episode_id for e in sources)
        decision = self._authorise(ExperimentClass.ISOLATED_EMULATION, _digest("emulation", *ids))
        if decision.outcome is SandboxOutcome.ALLOWED:
            # No emulator exists in this repository (ADR-0075): an allowed emulation still
            # cannot run, and is treated exactly like a refused one.
            self._counters["emulation_unrunnable"] += 1
            self._refused.append(decision)

    def _add_plan(self, klass: ExperimentClass, spec: TransformSpec | None,
                  members: tuple[Episode, ...], genomes: Sequence[HypothesisGenome],
                  decision: SandboxDecision, *, needs_lab: bool, cost: int) -> None:
        ids = tuple(e.episode_id for e in members)
        design = ExperimentDesign(
            design_id="xd-" + _digest(str(klass), str(getattr(spec, "kind", "-")),
                                      str(getattr(spec, "parameter", "-")),
                                      _predicate_key(getattr(spec, "target", None)), *ids)[7:31],
            experiment_class=klass, transform=spec, episode_ids=ids, cost_units=cost,
            privacy_cost=0.0, safety_risk=0.0,
        )
        self._governor.charge("oracle_planning", len(genomes) * sum(len(e.steps) for e in members))
        predictions = {g.hypothesis_id: tuple(_predict(g, e) for e in members) for g in genomes}
        self._plans.append(_Plan(design=design, decision=decision, episodes=members,
                                 predictions=MappingProxyType(predictions), needs_lab=needs_lab))
        self._counters["designs_built"] += 1

    # --- running -----------------------------------------------------------------

    def run(
        self,
        hypotheses: Sequence[HypothesisGenome],
        pool: Sequence[Episode],
        *,
        visibility_share: float | None = None,
    ) -> OracleReport:
        """Plan, then run experiments until a §43 stopping rule fires.

        ``visibility_share`` is the residual cluster's; when omitted it is measured on the pool
        as the share of theory-matched episodes holding an incomplete step.
        """
        genomes, episodes = self._check_inputs(hypotheses, pool)
        self._counters["runs"] += 1
        start = self._governor.meter.spent
        posterior = uniform_prior([g.hypothesis_id for g in genomes])
        state = _RunState(posterior=posterior, lab_calls_at_start=self._lab_calls)
        if visibility_share is not None and (
                not isinstance(visibility_share, float) or not 0.0 <= visibility_share <= 1.0):
            raise ContractError("visibility_share must be a float in [0, 1]")
        self._plans, self._refused = [], []
        self._needing_lab = self._truncated = 0
        share = visibility_share
        try:
            if share is None:
                share = self._visibility(genomes, episodes)
            if share >= TELEMETRY_FAILURE_SHARE:
                state.stop = StopReason.TELEMETRY_FAILURE  # §43: a telemetry gap, not a mechanism
            elif len(genomes) < 2:
                state.stop = StopReason.NO_EXPERIMENTS  # nothing to separate; never "identified"
            else:
                self.candidate_designs(genomes, episodes)
                self._loop(state)
        except WorkBudgetExceeded:
            state.stop = StopReason.BUDGET  # the kill switch: everything so far is reported
        return self._report(state, start, share)

    def _loop(self, state: _RunState) -> None:
        pending = list(self._plans)
        while state.stop is None:
            state.stop = self._stop_before(state, pending)
            if state.stop is not None:
                return
            alive = state.posterior.hypothesis_ids
            self._governor.charge("oracle_planning", sum(
                len(alive) * len(p.design.episode_ids) for p in pending))
            scored = [(p.design, expected_information_gain(state.posterior, self._restrict(p, alive)))
                      for p in pending]
            if all(len(set(self._restrict(p, alive).values())) == 1 for p in pending):
                state.stop = StopReason.OBSERVATIONALLY_EQUIVALENT
                return
            if max(_per_unit(eig, design) for design, eig in scored) < STOP_EIG_PER_UNIT:
                state.stop = StopReason.EIG_BELOW_COST
                return
            index = select_design(scored, self._policy, self._rng)
            plan = pending.pop(index)
            self._execute(state, plan, scored[index][1])

    def _stop_before(self, state: _RunState, pending: Sequence[_Plan]) -> StopReason | None:
        if max(state.posterior.probabilities) >= STOP_POSTERIOR:
            return StopReason.IDENTIFIED
        if not pending:
            return StopReason.SAFETY if self._refused else StopReason.NO_EXPERIMENTS
        if len(state.records) >= self._max_experiments:
            return StopReason.BUDGET
        return None

    @staticmethod
    def _restrict(plan: _Plan, alive: Sequence[str]) -> dict[str, tuple[int, ...]]:
        return {hid: plan.predictions[hid] for hid in alive}

    def _execute(self, state: _RunState, plan: _Plan, eig: float) -> None:
        """Pay for the experiment, observe its labels, update, prune; the vault decides the rest."""
        self._governor.charge("oracle", plan.design.cost_units)
        observed = tuple(self._observe(episode, plan.needs_lab) for episode in plan.episodes)
        alive = state.posterior.hypothesis_ids
        posterior = update(state.posterior, self._restrict(plan, alive), observed)
        # Relative to the leader, never an absolute floor: over n > 1/PRUNE_POSTERIOR theories a
        # near-uniform posterior puts every one under 0.01 with no evidence against any, and the
        # old absolute rule fossilized the whole group before crashing (S8-RES-2). The leader is
        # always kept, so the restriction below can never be empty.
        floor = PRUNE_POSTERIOR * max(posterior.probabilities)
        survivors = [h for h, p in zip(posterior.hypothesis_ids, posterior.probabilities)
                     if p >= floor]
        # Restrict FIRST: nothing is written to the ledger unless the new posterior exists.
        restricted = posterior.restricted(survivors) if survivors != list(alive) else posterior
        for hypothesis_id in posterior.hypothesis_ids:
            if hypothesis_id not in survivors:
                self._prune(hypothesis_id)
                state.pruned.append(hypothesis_id)
        state.posterior = restricted
        state.records.append(ExperimentRecord(design=plan.design, eig_bits=float(eig),
                                              observed=observed, posterior_after=state.posterior,
                                              sandbox=plan.decision))
        self._counters["experiments"] += 1

    def _observe(self, episode: Episode, needs_lab: bool) -> int | None:
        if not needs_lab:
            return episode.label  # a recording's label, or the preserved source label
        assert self._lab is not None  # designs needing the lab are never built without one
        label = self._lab.label(episode)
        self._lab_calls += 1
        self._counters["lab_labels"] += 1
        if isinstance(label, bool) or label not in (0, 1):
            raise ContractError(f"the lab oracle must answer 0 or 1, got {label!r}")
        return label

    def _prune(self, hypothesis_id: str) -> None:
        self._counters["pruned"] += 1
        if self._ledger is None:
            self._counters["prune_not_recorded"] += 1
            return
        try:
            status = self._ledger.status(hypothesis_id)
        except (LedgerError, KeyError):
            status = None
        if status is not TheoryStatus.PROPOSED:  # unborn or past PROPOSED: not ORACLE's to move
            self._counters["prune_not_recorded"] += 1
            return
        try:
            # FOSSILIZED, not CHALLENGED_OUT: no FalsifierKind names an ORACLE posterior, and
            # filing it under another falsifier's name would be a false record (ADR-0078). A
            # refusal (none is expected from PROPOSED) is still counted, never swallowed.
            self._ledger.set_status(hypothesis_id, TheoryStatus.FOSSILIZED, reason=PRUNE_REASON)
        except LedgerError:
            self._counters["prune_refused_by_ledger"] += 1

    def _visibility(self, genomes: Sequence[HypothesisGenome], episodes: Sequence[Episode]) -> float:
        matched = [e for e in episodes if any(g.decides(e) for g in genomes)]
        self._governor.charge("oracle_planning", len(genomes) * sum(len(e.steps) for e in episodes))
        if not matched:
            return 0.0
        gaps = sum(any(step.observation_incomplete for step in e.steps) for e in matched)
        return gaps / len(matched)

    def _report(self, state: _RunState, start: int, share: float | None) -> OracleReport:
        records = tuple(state.records)
        replay = sum(r.design.experiment_class is ExperimentClass.HISTORICAL_REPLAY for r in records)
        assert state.stop is not None
        return OracleReport(
            policy=self._policy, experiments=records, stop=state.stop,
            final_posterior=state.posterior, leading=state.posterior.leading(),
            pruned=tuple(state.pruned), work_units=self._governor.meter.spent - start,
            lab_oracle_used=self._lab_calls > state.lab_calls_at_start,
            refused=tuple(self._refused), active_learning=replay,
            active_experimentation=len(records) - replay, designs_offered=len(self._plans),
            designs_needing_lab=self._needing_lab, queue_truncated=self._truncated,
            visibility_share=None if share is None else float(share),
        )

    def stats(self) -> Mapping[str, int]:
        return MappingProxyType(dict(self._counters))


@dataclass(slots=True)
class _RunState:
    """Mutable, private to one :meth:`OraclePlanner.run` call."""

    posterior: Posterior
    lab_calls_at_start: int
    stop: StopReason | None = None
    records: list[ExperimentRecord] = field(default_factory=list)
    pruned: list[str] = field(default_factory=list)
