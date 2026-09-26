"""D8.2 / PROM-F02 — the Residual Observatory: what the current theory fails to explain.

Architecture §4 defines the discovery residual as observed structure minus the best
explainable structure. This module binds that to something a test can check: **the current
theory is the OR of a set of explainers**, and a residual is an episode the theory gets
wrong or cannot speak to. Discovery must start from here and nowhere else, or a research
engine spends its budget re-deriving what the endpoint already knows.

The residual kinds (spec §4 D8.2):

* ``MISSED_POSITIVE`` — a label-1 episode no explainer fires on;
* ``FALSE_ALARM`` — a label-0 episode some explainer fires on;
* ``UNEXPLAINED_ESCALATION`` — an **unlabelled** episode holding an escalating step (Stage 6's
  ``is_escalating``) that no explainer fires on. This is architecture §90's open-world
  ``UNKNOWN_MECHANISM``: it is recorded as unexplained and is **never forced into a known
  class** — no label is invented for it, and novelty is not maliciousness.

The decomposition (architecture §5), as sets: every residual is ``OBSERVATION``;
``VISIBILITY`` when any step has ``observation_incomplete`` (missing telemetry may be the
whole explanation, S8X-04); ``CAUSAL`` when at least two actors each hold an escalating
step (the ordering between lineages is what is unexplained); ``COLLECTIVE`` when an
explainer built from Stage 7 seeds (``MotifExplainer(..., collective=True)``) fired on the
episode — the collective pattern is involved in the local failure.

What this module refuses, by construction:

* **Held-out data.** ``observe`` raises ``ContractError`` for any episode that is not
  ``TRAIN`` or an *unlabelled* ``LAB_POOL`` episode. PROMETHEUS sees TRAIN only; LAB_POOL is
  admitted solely for the unlabelled open-world case, so its lab labels can never steer
  discovery.
* **Unbounded growth.** At most ``max_residuals`` residuals and ``MAX_CLUSTER_MEMBERS``
  members per cluster are kept; a signature holds at most ``MAX_SIGNATURE_ITEMS`` items.
  Every cut is counted and flips ``ResidualField.truncated``.
* **Inert explainers passing unnoticed.** Every explainer is evaluated on every episode (no
  short circuit), so ``ResidualField.firings`` reports a true firing count per explainer
  (standing order 1). A Φ-oracle whose fit returned no threshold never fires, and every
  such abstention is counted.

**Not built** (spec §4 D8.2): R-world (no Stage 4 import), R-response (T2), R-learning (no
Stage 6 learner output is consumed), R-temporal (the grammar has no timing). Stage 3 cells
and Stage 4 worlds are not explainers: Stage 8 has no import path to them.

Cost: every episode is paid for through the run's :class:`ResearchGovernor` *before* it is
evaluated — one unit per feature read (Φ), per predicate test (motifs) and per escalation
check — so a runaway observation hits the budget, not the host.
"""

from __future__ import annotations

import hashlib
import sys
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Protocol, runtime_checkable

from pocketsec.stage0.benchmark.security_metrics import recall_at_max_fpr
from pocketsec.stage0.contracts.common import ContractError, require_identifier
from pocketsec.stage6.capsule.experience_capsule import EncodedStep
from pocketsec.stage6.memory.semantic import is_escalating
from pocketsec.stage8.episode import Episode, Split
from pocketsec.stage8.genome.grammar import Mechanism
from pocketsec.stage8.genome.hypothesis import ResidualType
from pocketsec.stage8.governor.budget import ResearchGovernor

__all__ = [
    "FPR_BUDGET",
    "MAX_CLUSTER_MEMBERS",
    "MAX_EXPLAINER_MECHANISMS",
    "MAX_RESIDUALS",
    "MAX_SIGNATURE_ITEMS",
    "OBSERVATORY_COMPONENT",
    "Explainer",
    "MotifExplainer",
    "PhiOracleExplainer",
    "Residual",
    "ResidualCluster",
    "ResidualField",
    "ResidualKind",
    "ResidualObservatory",
    "cluster_members",
]

#: Spec §4.21. Chosen parameters, not measurements.
MAX_RESIDUALS: int = 4096
MAX_CLUSTER_MEMBERS: int = 64
MAX_SIGNATURE_ITEMS: int = 8
FPR_BUDGET: float = 0.01
#: A motif explainer holds Stage 6's trusted DETECTORs (<= 64), Stage 7 seeds (<= 64) and
#: validated discoveries. Past this, an explainer is a store without a bound.
MAX_EXPLAINER_MECHANISMS: int = 256
OBSERVATORY_COMPONENT: str = "residual.observatory"

_ID_HEX = 16
Signature = tuple[tuple[int, int, int], ...]


class ResidualKind(StrEnum):
    MISSED_POSITIVE = "MISSED_POSITIVE"
    FALSE_ALARM = "FALSE_ALARM"
    UNEXPLAINED_ESCALATION = "UNEXPLAINED_ESCALATION"


@runtime_checkable
class Explainer(Protocol):
    """One part of the current theory: a yes/no answer per episode, nothing more."""

    explainer_id: str

    def fires(self, episode: Episode) -> bool: ...


class PhiOracleExplainer:
    """Stage 2's surviving scorer as an explainer: ``max(features[73]) >= threshold``.

    "Stage 2 dynamics" in architecture §4 binds to the Φ-oracle because it is the only
    Stage 2 scorer that survived its own gate (ADR-0010). The threshold is the one
    ``recall_at_max_fpr`` chooses on TRAIN at ``fpr_budget`` — the operating point an
    endpoint pays false positives at. ``None`` (TRAIN held one class) means the explainer
    never fires; every such abstention is counted in ``abstentions``, never hidden.
    """

    explainer_id = "phi-oracle"

    def __init__(self, threshold: float | None) -> None:
        if threshold is not None and (isinstance(threshold, bool) or not isinstance(
            threshold, (int, float)) or threshold != threshold):
            raise ContractError(
                f"PhiOracleExplainer threshold must be a number or None, got {threshold!r}")
        self.threshold: float | None = None if threshold is None else float(threshold)
        self.abstentions = 0

    @classmethod
    def fit(cls, train: Sequence[Episode], *, fpr_budget: float = FPR_BUDGET) -> PhiOracleExplainer:
        """Choose the threshold on labelled TRAIN episodes only."""
        if any(not isinstance(e, Episode) or e.split is not Split.TRAIN for e in train):
            raise ContractError("PhiOracleExplainer.fit reads TRAIN episodes only")
        labelled = [episode for episode in train if episode.label is not None]
        labels = [int(episode.label) for episode in labelled if episode.label is not None]
        scores = [episode.phi_oracle_score() for episode in labelled]
        if not labels:
            return cls(None)
        _, threshold = recall_at_max_fpr(labels, scores, fpr_budget)
        return cls(threshold)

    def fires(self, episode: Episode) -> bool:
        if self.threshold is None:
            self.abstentions += 1
            return False
        return episode.phi_oracle_score() >= self.threshold

    def cost(self, episode: Episode) -> int:
        return len(episode.steps)  # one feature read per step


class MotifExplainer:
    """A set of typed mechanisms as one explainer: fires when any of them matches.

    Holds Stage 6 trusted motifs, Stage 7 seeds or validated discoveries. ``collective``
    marks an explainer built from Stage 7 seeds, so a residual it fires on is typed
    ``COLLECTIVE``. It carries no weight, score or authority.
    """

    def __init__(self, explainer_id: str, mechanisms: Sequence[Mechanism], *,
                 collective: bool = False) -> None:
        require_identifier(explainer_id, "explainer_id")
        held = tuple(mechanisms)
        if any(not isinstance(mechanism, Mechanism) for mechanism in held):
            raise ContractError("MotifExplainer holds Mechanism values only")
        if len(held) > MAX_EXPLAINER_MECHANISMS:
            raise ContractError(
                f"MotifExplainer holds at most {MAX_EXPLAINER_MECHANISMS} mechanisms, "
                f"got {len(held)}"
            )
        self.explainer_id = explainer_id
        self.mechanisms: tuple[Mechanism, ...] = tuple(dict.fromkeys(held))
        self.collective = bool(collective)
        self._predicates = sum(len(mechanism.steps) for mechanism in self.mechanisms)

    def fires(self, episode: Episode) -> bool:
        return any(mechanism.matches(episode.steps) for mechanism in self.mechanisms)

    def cost(self, episode: Episode) -> int:
        # Upper bound of predicate tests (CO_OCCURS/WITHOUT test both predicates per step).
        return len(episode.steps) * 2 * self._predicates


@dataclass(frozen=True, slots=True)
class Residual:
    """One episode the current theory gets wrong, or cannot speak to."""

    residual_id: str  # "res-" + 16 hex of (episode_id, kind)
    episode_id: str
    kind: ResidualKind
    types: frozenset[ResidualType]
    signature: Signature  # sorted distinct (relation, props, raised) of escalating steps, <= 8
    explainers_fired: tuple[str, ...]
    host_id: str
    epoch_id: int
    source_groups: int
    steps: int  # the priority field's cost and impact terms need these two counts
    escalating_steps: int

    def __post_init__(self) -> None:
        if not isinstance(self.kind, ResidualKind):
            raise ContractError(f"Residual.kind must be a ResidualKind, got {self.kind!r}")
        types = frozenset(self.types)
        if ResidualType.OBSERVATION not in types or any(
                not isinstance(item, ResidualType) for item in types):
            raise ContractError("every residual is typed OBSERVATION, with ResidualType values")
        object.__setattr__(self, "types", types)
        if len(self.signature) > MAX_SIGNATURE_ITEMS:
            raise ContractError(f"a residual signature holds <= {MAX_SIGNATURE_ITEMS} items")
        if not 0 <= self.escalating_steps <= self.steps or self.steps < 1:
            raise ContractError(
                "Residual step counts must satisfy 0 <= escalating <= steps, steps >= 1")
        if self.residual_id != residual_id_for(self.episode_id, self.kind):
            raise ContractError("Residual.residual_id does not match (episode_id, kind)")


@dataclass(frozen=True, slots=True)
class ResidualCluster:
    """Residuals that share one escalation signature: one thing the theory keeps missing."""

    cluster_id: str  # "rc-" + 16 hex of the signature
    signature: Signature
    residual_ids: tuple[str, ...]  # <= MAX_CLUSTER_MEMBERS, truncation counted
    kinds: frozenset[ResidualKind]
    types: frozenset[ResidualType]
    hosts: int
    epochs: int
    source_groups: int
    visibility_share: float  # members with any observation_incomplete step

    def __post_init__(self) -> None:
        if not 1 <= len(self.residual_ids) <= MAX_CLUSTER_MEMBERS:
            raise ContractError(f"a cluster holds 1..{MAX_CLUSTER_MEMBERS} residuals")
        if self.cluster_id != cluster_id_for(self.signature):
            raise ContractError("ResidualCluster.cluster_id does not match its signature")
        if not 0.0 <= self.visibility_share <= 1.0:
            raise ContractError("visibility_share must lie in [0, 1]")
        if min(self.hosts, self.epochs) < 1 or self.source_groups < 0:
            raise ContractError("a cluster spans >= 1 host and >= 1 epoch")


@dataclass(frozen=True, slots=True)
class ResidualField:
    """Everything one observation found. ``explained`` = ``total`` - residuals found."""

    residuals: tuple[Residual, ...]
    clusters: tuple[ResidualCluster, ...]
    total: int
    explained: int
    truncated: bool
    firings: tuple[tuple[str, int], ...]  # per explainer: episodes it fired on

    def by_id(self) -> Mapping[str, Residual]:
        return MappingProxyType({residual.residual_id: residual for residual in self.residuals})


def residual_id_for(episode_id: str, kind: ResidualKind) -> str:
    text = f"{episode_id}|{kind.value}".encode()
    return "res-" + hashlib.sha256(text).hexdigest()[:_ID_HEX]


def cluster_id_for(signature: Signature) -> str:
    text = ";".join(f"{r},{p},{q}" for r, p, q in signature).encode()
    return "rc-" + hashlib.sha256(text).hexdigest()[:_ID_HEX]


def cluster_members(cluster: ResidualCluster, field: ResidualField,
                    episodes: Sequence[Episode]) -> tuple[Episode, ...]:
    """The episodes behind a cluster's residuals, in residual order (missing ones skipped)."""
    residuals = field.by_id()
    by_episode = {episode.episode_id: episode for episode in episodes}
    wanted = (residuals[rid].episode_id for rid in cluster.residual_ids if rid in residuals)
    return tuple(dict.fromkeys(by_episode[eid] for eid in wanted if eid in by_episode))


# --- the observatory -----------------------------------------------------------------


@dataclass(slots=True)
class _Pending:
    """Mutable per-cluster accumulator, local to one ``observe`` call."""

    residual_ids: list[str]
    kinds: set[ResidualKind]
    types: set[ResidualType]
    hosts: set[str]
    epochs: set[int]
    groups: set[str]
    incomplete: int


class ResidualObservatory:
    """PROM-F02. Runs the current theory over episodes and keeps what it cannot explain."""

    def __init__(self, explainers: Sequence[Explainer], *, governor: ResearchGovernor,
                 max_residuals: int = MAX_RESIDUALS) -> None:
        held = tuple(explainers)
        ids = [getattr(explainer, "explainer_id", None) for explainer in held]
        if any(not isinstance(explainer, Explainer) for explainer in held):
            raise ContractError("every explainer needs an explainer_id and fires(episode)")
        if len(set(ids)) != len(ids):
            raise ContractError(f"explainer ids must be distinct, got {ids}")
        if not isinstance(governor, ResearchGovernor):
            raise ContractError("ResidualObservatory needs the run's ResearchGovernor")
        if isinstance(max_residuals, bool) or not isinstance(max_residuals, int) or not (
                1 <= max_residuals <= MAX_RESIDUALS):
            raise ContractError(
                f"max_residuals must be in [1, {MAX_RESIDUALS}], got {max_residuals!r}")
        self._explainers = held
        self._governor = governor
        self._max_residuals = max_residuals
        self._n: Counter[str] = Counter()

    def observe(self, episodes: Sequence[Episode]) -> ResidualField:
        """Residuals of the current theory over ``episodes`` (TRAIN, or unlabelled LAB_POOL)."""
        batch = tuple(episodes)
        for episode in batch:
            _require_observable(episode)
        firings: Counter[str] = Counter({e.explainer_id: 0 for e in self._explainers})
        residuals: list[Residual] = []
        groups_of: dict[str, frozenset[str]] = {}
        incomplete_of: dict[str, bool] = {}
        found = dropped = 0
        truncated = False
        for episode in batch:
            residual, groups, incomplete, sig_cut = self._judge(episode, firings)
            truncated = truncated or sig_cut
            if residual is None:
                continue
            found += 1
            if len(residuals) >= self._max_residuals:
                dropped += 1
                continue
            residuals.append(residual)
            groups_of[residual.residual_id] = groups
            incomplete_of[residual.residual_id] = incomplete
        clusters, members_cut = _cluster(residuals, groups_of, incomplete_of)
        self._n.update(episodes=len(batch), residuals=found, residuals_dropped=dropped,
                       members_dropped=members_cut)
        return ResidualField(
            residuals=tuple(residuals),
            clusters=clusters,
            total=len(batch),
            explained=len(batch) - found,
            truncated=truncated or dropped > 0 or members_cut > 0,
            firings=tuple(sorted(firings.items())),
        )

    def _judge(self, episode: Episode, firings: Counter[str]
               ) -> tuple[Residual | None, frozenset[str], bool, bool]:
        self._governor.charge(OBSERVATORY_COMPONENT, self._cost(episode))
        fired = tuple(e.explainer_id for e in self._explainers if e.fires(episode))
        firings.update(fired)
        escalating = [step for step in episode.steps if is_escalating(step)]
        kind = _kind_of(episode.label, bool(fired), bool(escalating))
        incomplete = any(step.observation_incomplete for step in episode.steps)
        groups = frozenset(step.source_group for step in episode.steps)
        if kind is None:
            return None, groups, incomplete, False
        distinct = sorted({(s.relation, s.object_property_mask, s.state_delta_mask)
                           for s in escalating})
        signature = tuple(distinct[:MAX_SIGNATURE_ITEMS])
        cut = len(distinct) > MAX_SIGNATURE_ITEMS
        if cut:
            self._n["signatures_truncated"] += 1
        residual = Residual(
            residual_id=residual_id_for(episode.episode_id, kind),
            episode_id=episode.episode_id,
            kind=kind,
            types=self._types_of(escalating, fired, incomplete),
            signature=signature,
            explainers_fired=fired,
            host_id=episode.context.host_id,
            epoch_id=episode.context.epoch_id,
            source_groups=len(groups),
            steps=len(episode.steps),
            escalating_steps=len(escalating),
        )
        return residual, groups, incomplete, cut

    def _types_of(self, escalating: Sequence[EncodedStep], fired: tuple[str, ...],
                  incomplete: bool) -> frozenset[ResidualType]:
        types = {ResidualType.OBSERVATION}
        if incomplete:
            types.add(ResidualType.VISIBILITY)
        if len({step.actor_slot for step in escalating}) >= 2:
            types.add(ResidualType.CAUSAL)
        collective = {e.explainer_id for e in self._explainers if getattr(e, "collective", False)}
        if collective.intersection(fired):
            types.add(ResidualType.COLLECTIVE)
        return frozenset(types)

    def _cost(self, episode: Episode) -> int:
        units = len(episode.steps)  # the escalation check reads every step once
        for explainer in self._explainers:
            cost = getattr(explainer, "cost", None)
            units += int(cost(episode)) if callable(cost) else len(episode.steps)
        return units

    def stats(self) -> Mapping[str, int]:
        counters = dict(self._n)
        for explainer in self._explainers:
            if isinstance(explainer, PhiOracleExplainer):
                counters["phi_abstentions"] = explainer.abstentions
        return MappingProxyType(counters)

    def memory_bytes(self) -> int:
        """The observatory keeps no episode or residual between calls: counters only."""
        return sys.getsizeof(self._n) + sum(sys.getsizeof(key) + 8 for key in self._n)


def _require_observable(episode: Episode) -> None:
    if not isinstance(episode, Episode):
        raise ContractError(
            f"ResidualObservatory observes Episode values, got {type(episode).__name__}")
    if episode.split is Split.TRAIN:
        return
    if episode.split is Split.LAB_POOL and episode.label is None:
        return
    raise ContractError(
        f"ResidualObservatory reads TRAIN (or unlabelled LAB_POOL) only; episode "
        f"{episode.episode_id} is {episode.split.value} with label {episode.label!r}"
    )


def _kind_of(label: int | None, fired: bool, escalating: bool) -> ResidualKind | None:
    if label == 1 and not fired:
        return ResidualKind.MISSED_POSITIVE
    if label == 0 and fired:
        return ResidualKind.FALSE_ALARM
    if label is None and escalating and not fired:
        return ResidualKind.UNEXPLAINED_ESCALATION
    return None


def _cluster(residuals: Sequence[Residual], groups_of: Mapping[str, frozenset[str]],
             incomplete_of: Mapping[str, bool]) -> tuple[tuple[ResidualCluster, ...], int]:
    """Group by signature, first-come members kept up to the cap; returns (clusters, cut)."""
    pending: dict[Signature, _Pending] = {}
    cut = 0
    for residual in residuals:
        bucket = pending.setdefault(
            residual.signature, _Pending([], set(), set(), set(), set(), set(), 0))
        if len(bucket.residual_ids) >= MAX_CLUSTER_MEMBERS:
            cut += 1
            continue
        bucket.residual_ids.append(residual.residual_id)
        bucket.kinds.add(residual.kind)
        bucket.types.update(residual.types)
        bucket.hosts.add(residual.host_id)
        bucket.epochs.add(residual.epoch_id)
        bucket.groups.update(groups_of[residual.residual_id])
        bucket.incomplete += incomplete_of[residual.residual_id]
    clusters = tuple(
        ResidualCluster(
            cluster_id=cluster_id_for(signature),
            signature=signature,
            residual_ids=tuple(bucket.residual_ids),
            kinds=frozenset(bucket.kinds),
            types=frozenset(bucket.types),
            hosts=len(bucket.hosts),
            epochs=len(bucket.epochs),
            source_groups=len(bucket.groups),
            visibility_share=bucket.incomplete / len(bucket.residual_ids),
        )
        for signature, bucket in pending.items()
    )
    return tuple(sorted(clusters, key=lambda cluster: cluster.cluster_id)), cut
