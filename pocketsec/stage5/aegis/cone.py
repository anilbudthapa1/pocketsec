"""D5.8a — the Intervention Cone: the bounded consequence tree of one candidate action.

Architecture §9 draws the cone as seven branches out of "apply A": intended
security effect, attacker adaptation, service degradation, evidence loss,
persistence-triggered restart, rollback path, and the unknown branch that *is*
the Action Shadow. §9's last line is the whole engineering content: **"Cone depth
and branching are hard bounded."**

Three refusals hold this module honest.

1. **No unrestricted game-theoretic search.** §25 permits only *observed or
   learned* security-relevant adaptations, and :class:`AdaptationKind` is a closed
   four-member enum of exactly the adaptations the architecture names. An
   adaptation the :class:`AdaptationModel` has never observed does not get a
   branch. A cone that could imagine any adversary move would be a cone whose
   worst leaf is always catastrophic, which is the same as having no cone.
2. **``probability`` is ``None`` where nothing measured it, never 0.5.** A
   stand-in of 0.5 is a fabricated measurement wearing the costume of a
   calibrated one (ADR-0004). The only nodes that carry a probability are
   adaptation branches, and theirs is a frequency over the adaptation model's own
   observation counts — a real ratio over real counts, whose denominator travels
   with it in ``detail``.
3. **The bounds truncate explicitly.** Depth, branching and node count each cap,
   and every drop emits a :class:`~pocketsec.stage5.safe.action_field.FieldTruncation`
   row. Silent truncation is how a bounded system starts reporting on a subset it
   never names.

The cone is **unprivileged**: it reads a :class:`~pocketsec.stage5.twin.response_twin.ResponseTwin`
(itself holding only a read-only snapshot) and a resource governor, and it holds
no token store, no journal and no executor (§35).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from pocketsec.stage0.contracts.common import (
    ContractError,
    require_identifier,
    require_non_negative_int,
)
from pocketsec.stage5.governor import ResourceGovernor, WorkKind
from pocketsec.stage5.safe.action_field import CandidateAction, FieldTruncation
from pocketsec.stage5.twin.response_twin import (
    ResponseTwin,
    TwinPrediction,
    TwinState,
    state_degradation,
)

__all__ = [
    "MAX_CONE_BRANCHES_PER_NODE",
    "MAX_CONE_DEPTH",
    "MAX_CONE_NODES",
    "AdaptationKind",
    "AdaptationModel",
    "Branch",
    "ConeNode",
    "InterventionCone",
    "build_intervention_cone",
]

#: §9's hard depth bound, and the same number as ``ResourceBudget.max_cone_depth``.
MAX_CONE_DEPTH: int = 3

#: §9's hard branching bound, and ``ResourceBudget.max_cone_branches_per_node``.
MAX_CONE_BRANCHES_PER_NODE: int = 4

#: Total nodes in one cone. 32 is the whole cone, not a per-level allowance.
MAX_CONE_NODES: int = 32


class Branch(StrEnum):
    """§9's seven branches, exactly.

    ``UNKNOWN`` is not a fallback for "we did not classify this"; it is the Action
    Shadow branch, and a node on it means the cone is telling the planner that
    something happens here it cannot describe.
    """

    INTENDED_SECURITY_EFFECT = "INTENDED_SECURITY_EFFECT"
    ATTACKER_ADAPTATION = "ATTACKER_ADAPTATION"
    SERVICE_DEGRADATION = "SERVICE_DEGRADATION"
    EVIDENCE_LOSS = "EVIDENCE_LOSS"
    PERSISTENCE_TRIGGERED_RESTART = "PERSISTENCE_TRIGGERED_RESTART"
    ROLLBACK_PATH = "ROLLBACK_PATH"
    UNKNOWN = "UNKNOWN"


class AdaptationKind(StrEnum):
    """§25's four observed adaptations. No fifth member without an architecture change."""

    PROCESS_REPLACEMENT = "PROCESS_REPLACEMENT"
    ALTERNATE_DESTINATION = "ALTERNATE_DESTINATION"
    PERSISTENCE_RESTART = "PERSISTENCE_RESTART"
    SESSION_MIGRATION = "SESSION_MIGRATION"


@dataclass(frozen=True, slots=True)
class AdaptationModel:
    """Which adaptations have actually been observed, and how often.

    An empty model is the correct starting state and produces a cone with no
    adaptation branches at all. That is not a claim that the adversary cannot
    adapt; it is a refusal to invent the rate at which it does.
    """

    observed: frozenset[AdaptationKind]
    observation_counts: Mapping[AdaptationKind, int]

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "observed", frozenset(AdaptationKind(kind) for kind in self.observed)
        )
        counts: dict[AdaptationKind, int] = {}
        for kind, count in self.observation_counts.items():
            key = AdaptationKind(kind)
            counts[key] = require_non_negative_int(
                count, f"AdaptationModel.observation_counts[{key.value}]"
            )
        for kind in self.observed:
            if counts.get(kind, 0) < 1:
                raise ContractError(
                    f"AdaptationModel lists {kind.value} as observed with "
                    f"{counts.get(kind, 0)} observations; 'observed' means counted"
                )
        object.__setattr__(self, "observation_counts", MappingProxyType(counts))

    def likely(self, kind: AdaptationKind, *, min_observations: int = 1) -> bool:
        return (
            kind in self.observed
            and self.observation_counts.get(kind, 0) >= min_observations
        )

    def total_observations(self) -> int:
        return sum(self.observation_counts.values())

    def frequency(self, kind: AdaptationKind) -> float | None:
        """Observed frequency, or ``None`` when there is nothing to divide by."""
        total = self.total_observations()
        if total <= 0:
            return None
        return self.observation_counts.get(kind, 0) / total


@dataclass(frozen=True, slots=True)
class ConeNode:
    """One consequence. ``probability is None`` means nothing measured it."""

    node_id: str
    parent_id: str | None
    branch: Branch
    depth: int
    probability: float | None
    state: TwinState | None
    detail: str

    def __post_init__(self) -> None:
        require_identifier(self.node_id, "ConeNode.node_id")
        if self.parent_id is not None:
            require_identifier(self.parent_id, "ConeNode.parent_id")
        object.__setattr__(self, "branch", Branch(self.branch))
        require_non_negative_int(self.depth, "ConeNode.depth")
        if self.depth > MAX_CONE_DEPTH:
            raise ContractError(
                f"ConeNode({self.node_id!r}).depth {self.depth} exceeds "
                f"MAX_CONE_DEPTH={MAX_CONE_DEPTH}"
            )
        if self.probability is not None:
            value = float(self.probability)
            if value != value or not 0.0 <= value <= 1.0:
                raise ContractError(
                    f"ConeNode({self.node_id!r}).probability must be within [0, 1] or None, "
                    f"got {self.probability!r}; None is the answer when nothing measured it"
                )
            object.__setattr__(self, "probability", value)
        if self.state is not None and not isinstance(self.state, TwinState):
            raise ContractError("ConeNode.state must be a TwinState or None")
        if not isinstance(self.detail, str) or not self.detail.strip():
            raise ContractError("ConeNode.detail must say what this consequence is")
        if (self.parent_id is None) != (self.depth == 0):
            raise ContractError(
                f"ConeNode({self.node_id!r}) has parent_id={self.parent_id!r} at depth "
                f"{self.depth}; exactly the depth-0 root is parentless"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "parent_id": self.parent_id,
            "branch": self.branch.value,
            "depth": self.depth,
            "probability": self.probability,
            "state_digest": None if self.state is None else self.state.digest(),
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class InterventionCone:
    """A bounded consequence tree for one (candidate, world) pair."""

    candidate_id: str
    world_id: str
    nodes: tuple[ConeNode, ...]
    truncations: tuple[FieldTruncation, ...]

    def __post_init__(self) -> None:
        require_identifier(self.candidate_id, "InterventionCone.candidate_id")
        require_identifier(self.world_id, "InterventionCone.world_id")
        object.__setattr__(self, "nodes", tuple(self.nodes))
        object.__setattr__(self, "truncations", tuple(self.truncations))
        if len(self.nodes) > MAX_CONE_NODES:
            raise ContractError(
                f"InterventionCone holds {len(self.nodes)} nodes, over "
                f"MAX_CONE_NODES={MAX_CONE_NODES}; the builder truncates rather than "
                "constructing an over-budget cone"
            )
        ids = [node.node_id for node in self.nodes]
        if len(set(ids)) != len(ids):
            raise ContractError("InterventionCone node ids must be unique")
        known = set(ids)
        for node in self.nodes:
            if node.depth > MAX_CONE_DEPTH:
                raise ContractError(
                    f"InterventionCone node {node.node_id!r} at depth {node.depth} exceeds "
                    f"MAX_CONE_DEPTH={MAX_CONE_DEPTH}"
                )
            if node.parent_id is not None and node.parent_id not in known:
                raise ContractError(
                    f"InterventionCone node {node.node_id!r} names parent {node.parent_id!r}, "
                    "which the cone does not hold"
                )

    def branch_nodes(self, branch: Branch) -> tuple[ConeNode, ...]:
        wanted = Branch(branch)
        return tuple(node for node in self.nodes if node.branch is wanted)

    def leaves(self) -> tuple[ConeNode, ...]:
        parents = {node.parent_id for node in self.nodes if node.parent_id is not None}
        return tuple(node for node in self.nodes if node.node_id not in parents)

    def worst_leaf_degradation(self) -> float:
        """The worst operational degradation any leaf projects, in [0, 1].

        Uses ``state_degradation`` from the twin so the cone and the twin report
        degradation on one axis. A leaf with no projected state contributes
        nothing here and contributes to Action Shadow instead: an unprojectable
        consequence is an unknown, not a zero.
        """
        scores = [state_degradation(node.state) for node in self.leaves() if node.state is not None]
        return max(scores) if scores else 0.0

    def rollback_reachable(self) -> bool:
        """Whether the cone contains a rollback path at all.

        The builder adds a ``ROLLBACK_PATH`` node only when the candidate declares
        a rollback operator *and* the twin says the state that rollback needs can
        be captured. A cone with no such node means "no path was modelled", which
        the planner must read as "not reachable" rather than "probably fine".
        """
        return bool(self.branch_nodes(Branch.ROLLBACK_PATH))

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "world_id": self.world_id,
            "nodes": [node.to_dict() for node in self.nodes],
            "truncations": [row.to_dict() for row in self.truncations],
            "worst_leaf_degradation": self.worst_leaf_degradation(),
            "rollback_reachable": self.rollback_reachable(),
        }


@dataclass(slots=True)
class _Builder:
    """Mutable accumulator. Every append is bounds-checked in one place."""

    candidate_id: str
    governor: ResourceGovernor
    nodes: list[ConeNode]
    truncations: list[FieldTruncation]

    def add(
        self,
        *,
        suffix: str,
        parent_id: str | None,
        branch: Branch,
        depth: int,
        probability: float | None,
        state: TwinState | None,
        detail: str,
    ) -> str | None:
        """Append one node, or record a truncation and return ``None``."""
        if depth > MAX_CONE_DEPTH:
            self.truncations.append(
                FieldTruncation(
                    what="cone_depth",
                    identifier=f"{self.candidate_id}.{suffix}",
                    reason=f"depth {depth} exceeds MAX_CONE_DEPTH={MAX_CONE_DEPTH}",
                )
            )
            return None
        if len(self.nodes) >= MAX_CONE_NODES:
            self.truncations.append(
                FieldTruncation(
                    what="cone_nodes",
                    identifier=f"{self.candidate_id}.{suffix}",
                    reason=f"cone already holds MAX_CONE_NODES={MAX_CONE_NODES} nodes",
                )
            )
            return None
        self.governor.spend(WorkKind.CONE_NODE)
        node_id = f"{self.candidate_id}.{suffix}"
        self.nodes.append(
            ConeNode(
                node_id=node_id,
                parent_id=parent_id,
                branch=branch,
                depth=depth,
                probability=probability,
                state=state,
                detail=detail,
            )
        )
        return node_id


def _slug(kind: AdaptationKind) -> str:
    """Hyphenated node-id fragment: ``require_identifier`` rejects underscores."""
    return kind.value.lower().replace("_", "-")


def _first_level(
    builder: _Builder, root: str, candidate: CandidateAction, prediction: TwinPrediction
) -> None:
    """The deterministic branches: degradation, evidence loss, rollback."""
    if prediction.predicted_degradation > 0.0:
        builder.add(
            suffix="degradation",
            parent_id=root,
            branch=Branch.SERVICE_DEGRADATION,
            depth=1,
            probability=None,
            state=prediction.predicted,
            detail=(
                f"twin projects operational degradation {prediction.predicted_degradation:.4f} "
                "on the simulated host; no probability is attached because nothing measured one"
            ),
        )
    if prediction.evidence_lost:
        builder.add(
            suffix="evidence_loss",
            parent_id=root,
            branch=Branch.EVIDENCE_LOSS,
            depth=1,
            probability=None,
            state=prediction.predicted,
            detail=(
                f"{len(prediction.evidence_lost)} volatile signal(s) lost: "
                f"{', '.join(prediction.evidence_lost)}"
            ),
        )
    if candidate.rollback_operator_id is not None and prediction.recovery_state_needed:
        builder.add(
            suffix="rollback",
            parent_id=root,
            branch=Branch.ROLLBACK_PATH,
            depth=1,
            probability=None,
            state=prediction.before,
            detail=(
                f"rollback operator {candidate.rollback_operator_id} restores "
                f"{len(prediction.recovery_state_needed)} captured node(s); simulated rollback "
                "reliability is a property of the simulator (ADR-0046)"
            ),
        )


def _unknown_branch(builder: _Builder, root: str, prediction: TwinPrediction) -> None:
    """One UNKNOWN node per unknown dependency, bounded by the per-node branch cap."""
    unknowns = prediction.unknown_dependencies[:MAX_CONE_BRANCHES_PER_NODE]
    for index, dependency in enumerate(unknowns):
        builder.add(
            suffix=f"unknown{index}",
            parent_id=root,
            branch=Branch.UNKNOWN,
            depth=1,
            probability=None,
            state=None,
            detail=(
                f"{dependency} could not be confirmed in the snapshot, so its response to the "
                "action is unmodelled; this node is the Action Shadow branch of §9"
            ),
        )
    dropped = len(prediction.unknown_dependencies) - len(unknowns)
    if dropped > 0:
        builder.truncations.append(
            FieldTruncation(
                what="cone_unknown_branches",
                identifier=builder.candidate_id,
                reason=(
                    f"{dropped} further unknown dependencies beyond "
                    f"MAX_CONE_BRANCHES_PER_NODE={MAX_CONE_BRANCHES_PER_NODE}"
                ),
            )
        )


def _adaptation_pair(
    builder: _Builder,
    root: str,
    kind: AdaptationKind,
    *,
    adaptations: AdaptationModel,
    total: int,
) -> None:
    """One observed adaptation and its single Action Shadow follow-on.

    Depth stops at 2 even though :data:`MAX_CONE_DEPTH` permits one more level:
    a second speculative adversary move would be the unrestricted game-theoretic
    search §25 forbids, and the third level would be pure invention.
    """
    branch = (
        Branch.PERSISTENCE_TRIGGERED_RESTART
        if kind is AdaptationKind.PERSISTENCE_RESTART
        else Branch.ATTACKER_ADAPTATION
    )
    parent = builder.add(
        suffix=f"adapt.{_slug(kind)}",
        parent_id=root,
        branch=branch,
        depth=1,
        probability=adaptations.frequency(kind),
        state=None,
        detail=(
            f"{kind.value} observed {adaptations.observation_counts.get(kind, 0)} of {total} "
            "recorded adaptations; the frequency is that ratio and nothing else"
        ),
    )
    if parent is None:
        return
    builder.add(
        suffix=f"adapt.{_slug(kind)}.residual",
        parent_id=parent,
        branch=Branch.UNKNOWN,
        depth=2,
        probability=None,
        state=None,
        detail=(
            f"after {kind.value} the intended security effect may not hold; the resulting host "
            "state is not modelled, so this is an Action Shadow leaf"
        ),
    )


def _adaptation_branches(
    builder: _Builder, root: str, adaptations: AdaptationModel
) -> None:
    """One branch per *observed* adaptation, with its observed frequency."""
    kinds = tuple(kind for kind in AdaptationKind if adaptations.likely(kind))
    admitted = kinds[:MAX_CONE_BRANCHES_PER_NODE]
    total = adaptations.total_observations()
    for kind in admitted:
        _adaptation_pair(builder, root, kind, adaptations=adaptations, total=total)
    dropped = len(kinds) - len(admitted)
    if dropped > 0:
        builder.truncations.append(
            FieldTruncation(
                what="cone_adaptation_branches",
                identifier=builder.candidate_id,
                reason=(
                    f"{dropped} observed adaptation(s) beyond "
                    f"MAX_CONE_BRANCHES_PER_NODE={MAX_CONE_BRANCHES_PER_NODE}"
                ),
            )
        )


def build_intervention_cone(
    candidate: CandidateAction,
    *,
    world_id: str,
    twin: ResponseTwin,
    adaptations: AdaptationModel,
    governor: ResourceGovernor,
) -> InterventionCone:
    """Build the bounded cone for one candidate in one world.

    The root is the intended security effect, carrying the twin's projected
    post-action state and **no probability**: nothing in this repository has
    measured how often a defensive operator achieves its intended effect on a
    real host, and a number here would be that fabrication.
    """
    if not isinstance(adaptations, AdaptationModel):
        raise ContractError(
            f"build_intervention_cone needs an AdaptationModel, got "
            f"{type(adaptations).__name__}; only observed adaptations get branches (§25)"
        )
    prediction = twin.predict(candidate, world_id=world_id)
    builder = _Builder(
        candidate_id=candidate.candidate_id, governor=governor, nodes=[], truncations=[]
    )
    root = builder.add(
        suffix="intended",
        parent_id=None,
        branch=Branch.INTENDED_SECURITY_EFFECT,
        depth=0,
        probability=None,
        state=prediction.predicted,
        detail=(
            "intended security effect as the twin projects it on the simulated host; the "
            "probability that it holds on a real host is UNMEASURED (ADR-0046)"
        ),
    )
    if root is None:  # pragma: no cover - only reachable at MAX_CONE_NODES == 0
        raise ContractError("build_intervention_cone could not admit a root node")
    _first_level(builder, root, candidate, prediction)
    _adaptation_branches(builder, root, adaptations)
    _unknown_branch(builder, root, prediction)
    return InterventionCone(
        candidate_id=candidate.candidate_id,
        world_id=world_id,
        nodes=tuple(builder.nodes),
        truncations=tuple(builder.truncations),
    )
