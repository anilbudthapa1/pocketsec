"""D5.7 — the Counterfactual Response Twin: what the host would look like afterwards.

Architecture §8: *"The twin is intentionally narrow. It models only state
relevant to a proposed intervention."* Narrowness here is **structural, not
aspirational**. :meth:`ResponseTwin.project` is a breadth-first walk that stops
after :data:`MAX_TWIN_DEPTH` edges, refuses to hold more than
:data:`MAX_TWIN_NODES` nodes, refuses to serialise past :data:`MAX_TWIN_BYTES`,
and charges the resource governor one ``TWIN_STEP`` per node it admits. A twin
that grew with the host would be a second host model inside the endpoint, and the
2 GB target makes that a non-starter (MEMORY.md).

**What this module predicts, stated so no table can quote it as something else.**

This twin predicts the **simulated** host (``pocketsec/stage5/host/simulated.py``).
Its prediction error against a real Linux host is **UNMEASURED** and there is no
code path in this repository that could measure it, because no real host adapter
exists. What the Stage 5 corpus can measure is this module's prediction against
the simulator's own post-action state — a measurement of internal consistency
between two things the same wave wrote — and that quantity is named
``simulated_twin_prediction_error`` so the caveat travels with the number into
every table that quotes it (ADR-0046, §9.1).

**Unknown dependencies raise Action Shadow. They never raise predicted benefit.**
Every node the twin could not observe is marked ``observed=False``, every service
whose ``depends_on`` names a unit absent from the snapshot is recorded as an
unknown dependency, and both feed :attr:`ActionShadow.unmodelled_dependencies`.
There is no field on :class:`TwinPrediction` through which an unknown could
increase an expected security delta, which is the asymmetry §8 requires: not
knowing something is a reason to act less, never a reason to act more.

The twin is **unprivileged**. It is handed a read-only
:class:`~pocketsec.stage5.host.simulated.HostSnapshot`, never a host adapter, so
no planning code can mutate the host even by accident (§35).
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import (
    ContractError,
    digest_of_bytes,
    freeze_mapping,
    require_finite_unit_interval,
    require_identifier,
)
from pocketsec.stage5.governor import ResourceGovernor, WorkKind
from pocketsec.stage5.host.simulated import HostSnapshot, ProcessRow
from pocketsec.stage5.operators.algebra import (
    EvidenceEffect,
    OperatorClass,
    ProcessTarget,
    Reversibility,
)

if TYPE_CHECKING:  # pragma: no cover - annotation only; the field module imports this one
    from pocketsec.stage5.safe.action_field import CandidateAction

__all__ = [
    "DEGRADED_ATTRIBUTE",
    "MAX_TWIN_BYTES",
    "MAX_TWIN_DEPTH",
    "MAX_TWIN_NODES",
    "MAX_TWIN_PROJECTIONS",
    "ResponseTwin",
    "StateFamily",
    "TwinNode",
    "TwinPrediction",
    "TwinState",
    "state_degradation",
]

#: §34's dependency-node cap, and the same number as
#: ``ResourceBudget.max_twin_nodes``. A twin over this bound truncates and says so.
MAX_TWIN_NODES: int = 64

#: Two edges from the target. Deliberately shorter than the intervention cone's
#: depth: the cone explores *consequences over time*, the twin only describes the
#: *state neighbourhood* an action touches, and a three-hop service dependency is
#: already better modelled as an unknown than as a prediction.
MAX_TWIN_DEPTH: int = 2

#: Canonical-bytes ceiling for one twin state. Endpoint state is bounded.
MAX_TWIN_BYTES: int = 20480

#: How many distinct projections one twin keeps. Equal to
#: ``ResourceBudget.max_candidate_actions``, because a field cannot hold more
#: candidates than that and therefore cannot need more distinct targets. Eviction is
#: FIFO and counted by :meth:`ResponseTwin.projection_evictions`.
MAX_TWIN_PROJECTIONS: int = 16

#: The one attribute key that marks a node as degraded, shared by
#: :func:`state_degradation` and every transform below. A second spelling of this
#: key would be a key-space split of exactly the kind §4.9 Rule A forbids.
DEGRADED_ATTRIBUTE: str = "degraded"

_TRUE = "true"
_FALSE = "false"

class StateFamily(StrEnum):
    """§8's seven state families, exactly. Adding an eighth is an architecture change."""

    PROCESS = "PROCESS"
    SERVICE = "SERVICE"
    SESSION = "SESSION"
    COMMUNICATION = "COMMUNICATION"
    SECURITY = "SECURITY"
    EVIDENCE = "EVIDENCE"
    RECOVERY = "RECOVERY"


#: Families whose degradation is operationally meaningful, held as enum members rather
#: than as their string values so there is one family key space and not two (§4.9
#: Rule A). Evidence, security and recovery nodes are accounted for separately: losing
#: evidence is not service degradation, and adding the two would hide both.
_OPERATIONAL_FAMILIES: frozenset[StateFamily] = frozenset(
    {StateFamily.PROCESS, StateFamily.SERVICE, StateFamily.SESSION}
)


@dataclass(frozen=True, slots=True)
class TwinNode:
    """One modelled entity.

    ``attributes`` is ``str -> str`` and nothing else. No floats, because a float
    in a twin node invites a score; no nesting, because a nested twin node
    invites a second host model. ``observed=False`` means *this is an
    assumption*, and an assumption raises Action Shadow.
    """

    family: StateFamily
    node_id: str
    attributes: Mapping[str, str]
    observed: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "family", StateFamily(self.family))
        if not isinstance(self.node_id, str) or not self.node_id:
            raise ContractError("TwinNode.node_id must be a non-empty string")
        if not self.node_id.startswith(f"{self.family.value}:"):
            raise ContractError(
                f"TwinNode.node_id {self.node_id!r} must be prefixed with its family "
                f"{self.family.value!r}; the prefix is how the walk resolves a node back to the "
                "snapshot, so an unprefixed id is an unresolvable node"
            )
        object.__setattr__(
            self, "attributes", freeze_mapping(dict(self.attributes), "TwinNode.attributes")
        )
        if not isinstance(self.observed, bool):
            raise ContractError("TwinNode.observed must be a bool; None is not 'probably observed'")

    def with_attributes(self, **changes: str) -> TwinNode:
        """Return a new node with attributes replaced. Never mutates (coding style)."""
        merged = dict(self.attributes)
        merged.update(changes)
        return TwinNode(
            family=self.family, node_id=self.node_id, attributes=merged, observed=self.observed
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "family": self.family.value,
            "node_id": self.node_id,
            "attributes": dict(sorted(self.attributes.items())),
            "observed": self.observed,
        }


@dataclass(frozen=True, slots=True)
class TwinState:
    """A bounded, canonically serialisable slice of host state."""

    nodes: tuple[TwinNode, ...]
    edges: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "nodes", tuple(self.nodes))
        object.__setattr__(self, "edges", tuple((str(a), str(b)) for a, b in self.edges))
        if len(self.nodes) > MAX_TWIN_NODES:
            raise ContractError(
                f"TwinState holds {len(self.nodes)} nodes, over MAX_TWIN_NODES={MAX_TWIN_NODES}; "
                "the walk truncates rather than constructing an over-budget state"
            )
        ids = [node.node_id for node in self.nodes]
        if len(set(ids)) != len(ids):
            raise ContractError("TwinState node ids must be unique")
        known = set(ids)
        for source, sink in self.edges:
            if source not in known or sink not in known:
                raise ContractError(
                    f"TwinState edge ({source!r}, {sink!r}) names a node the state does not "
                    "hold; a dangling edge is an unmodelled dependency pretending to be modelled"
                )
        size = len(self.canonical_bytes())
        if size > MAX_TWIN_BYTES:
            raise ContractError(
                f"TwinState canonical bytes {size} over MAX_TWIN_BYTES={MAX_TWIN_BYTES}"
            )

    def node(self, node_id: str) -> TwinNode | None:
        for candidate in self.nodes:
            if candidate.node_id == node_id:
                return candidate
        return None

    def canonical_bytes(self) -> bytes:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")

    def digest(self) -> str:
        return digest_of_bytes(self.canonical_bytes())

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [node.to_dict() for node in sorted(self.nodes, key=lambda n: n.node_id)],
            "edges": [list(edge) for edge in sorted(self.edges)],
        }


def state_degradation(state: TwinState) -> float:
    """Fraction of operational nodes marked degraded, in [0, 1].

    The one definition of "how bad is this state", shared by
    :attr:`TwinPrediction.predicted_degradation` and
    ``InterventionCone.worst_leaf_degradation``. Two definitions of this number
    would be two incomparable axes reported under one name.
    """
    operational = [node for node in state.nodes if node.family in _OPERATIONAL_FAMILIES]
    if not operational:
        return 0.0
    degraded = sum(
        1 for node in operational if node.attributes.get(DEGRADED_ATTRIBUTE) == _TRUE
    )
    return degraded / len(operational)


@dataclass(frozen=True, slots=True)
class TwinPrediction:
    """What the twin expects after the candidate is applied, and what it could not see."""

    candidate_id: str
    world_id: str
    before: TwinState
    predicted: TwinState
    unknown_dependencies: tuple[str, ...]
    predicted_degradation: float
    evidence_lost: tuple[str, ...]
    recovery_state_needed: tuple[str, ...]
    truncated: bool

    def __post_init__(self) -> None:
        require_identifier(self.candidate_id, "TwinPrediction.candidate_id")
        require_identifier(self.world_id, "TwinPrediction.world_id")
        for name in ("unknown_dependencies", "evidence_lost", "recovery_state_needed"):
            object.__setattr__(self, name, tuple(str(item) for item in getattr(self, name)))
        require_finite_unit_interval(
            self.predicted_degradation, "TwinPrediction.predicted_degradation"
        )
        if not isinstance(self.truncated, bool):
            raise ContractError("TwinPrediction.truncated must be a bool")

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "world_id": self.world_id,
            "before_digest": self.before.digest(),
            "predicted_digest": self.predicted.digest(),
            "unknown_dependencies": list(self.unknown_dependencies),
            "predicted_degradation": self.predicted_degradation,
            "evidence_lost": list(self.evidence_lost),
            "recovery_state_needed": list(self.recovery_state_needed),
            "truncated": self.truncated,
            "host_kind": "SIMULATED_OR_AS_SNAPSHOTTED",
        }


@dataclass(frozen=True, slots=True)
class _ClassEffect:
    """The closed consequence table for an operator class.

    A table rather than a chain of ``if`` statements so the match over
    :class:`OperatorClass` can be total: adding a class without a row here is a
    ``mypy --strict`` error, not a silently-unmodelled operator.
    """

    stops_target: bool = False
    suspends_target: bool = False
    constrains_unit: bool = False
    revokes_session: bool = False
    restricts_sockets: bool = False
    preserves_evidence: bool = False


def _class_effect(operator_class: OperatorClass) -> _ClassEffect:
    match operator_class:
        case OperatorClass.O0_OBSERVE:
            return _ClassEffect()
        case OperatorClass.O1_PRESERVE:
            return _ClassEffect(preserves_evidence=True)
        case OperatorClass.O2_REVERSIBLE_RESTRICT:
            return _ClassEffect(restricts_sockets=True)
        case OperatorClass.O3_SUSPEND:
            return _ClassEffect(suspends_target=True)
        case OperatorClass.O4_LOCAL_REVOKE:
            return _ClassEffect(revokes_session=True)
        case OperatorClass.O5_SERVICE_CONTAINMENT:
            return _ClassEffect(constrains_unit=True)
        case OperatorClass.O6_DISRUPTIVE:
            return _ClassEffect(stops_target=True)
        case OperatorClass.O7_DESTRUCTIVE:
            # Unreachable through the catalog (O7 has zero entries, §D5.5) and
            # modelled anyway, because an unmodelled branch here would be an
            # unmodelled branch in the only stage that touches privilege.
            return _ClassEffect(stops_target=True, constrains_unit=True)


class ResponseTwin:
    """Projects and predicts a bounded neighbourhood of one intervention target.

    Holds a read-only snapshot and a governor. It holds no host adapter, no token
    store and no executor, so the whole class is structurally incapable of
    changing the host it describes.
    """

    __slots__ = ("_cache", "_evictions", "_governor", "_snapshot")

    def __init__(self, *, snapshot: HostSnapshot, governor: ResourceGovernor) -> None:
        if not isinstance(snapshot, HostSnapshot):
            raise ContractError(
                f"ResponseTwin needs a HostSnapshot, got {type(snapshot).__name__}; the twin "
                "sees read-only data and never a host adapter (§35)"
            )
        self._snapshot = snapshot
        self._governor = governor
        self._cache: dict[str, tuple[TwinState, bool]] = {}
        self._evictions = 0

    # --- projection ------------------------------------------------------

    def project(self, target: ProcessTarget) -> TwinState:
        """The bounded state neighbourhood of ``target``."""
        state, _ = self._project(target)
        return state

    def projection_evictions(self) -> int:
        """How many cached projections were dropped. Truncation stays countable."""
        return self._evictions

    def _project(self, target: ProcessTarget) -> tuple[TwinState, bool]:
        """Project once per identity, then reuse.

        The snapshot is immutable and the walk reads nothing else, so projecting the
        same identity twice is the same pure function twice. Caching it is what makes
        ``predict`` affordable: without it, one candidate spent two full
        ``MAX_TWIN_NODES`` walks (one for the state, one for the unknown
        dependencies) and four candidates exhausted the governor's whole TWIN_STEP
        allowance — measured, not guessed.

        The cache is keyed by ``identity.digest()``, the same key space
        ``CapabilityToken.target_digest`` and the journal use (§4.9 Rule A), and it
        is bounded at :data:`MAX_TWIN_PROJECTIONS` with explicit FIFO eviction.
        """
        key = target.identity.digest()
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        result = self._walk(target)
        if len(self._cache) >= MAX_TWIN_PROJECTIONS:
            self._cache.pop(next(iter(self._cache)))
            self._evictions += 1
        self._cache[key] = result
        return result

    def _walk(self, target: ProcessTarget) -> tuple[TwinState, bool]:
        root = f"{StateFamily.PROCESS.value}:{target.identity.pid}"
        nodes: dict[str, TwinNode] = {}
        edges: set[tuple[str, str]] = set()
        frontier: list[tuple[str, int]] = [(root, 0)]
        truncated = False
        while frontier:
            node_id, depth = frontier.pop(0)
            if node_id in nodes:
                continue
            if len(nodes) >= MAX_TWIN_NODES:
                truncated = True
                break
            node = self._build_node(node_id, target)
            if node is None:
                continue
            # One TWIN_STEP per admitted node: the governor, not a comment, is
            # what stops a wide host from producing a wide twin.
            self._governor.spend(WorkKind.TWIN_STEP)
            nodes[node_id] = node
            if depth >= MAX_TWIN_DEPTH:
                continue
            for neighbour in self._neighbours(node_id, target):
                edges.add((node_id, neighbour))
                frontier.append((neighbour, depth + 1))
        kept = set(nodes)
        state = TwinState(
            nodes=tuple(nodes[node_id] for node_id in sorted(kept)),
            edges=tuple(sorted(edge for edge in edges if edge[0] in kept and edge[1] in kept)),
        )
        return state, truncated

    def _process_row(self, node_id: str) -> ProcessRow | None:
        try:
            pid = int(node_id.split(":", 1)[1])
        except (IndexError, ValueError):
            return None
        return self._snapshot.process(pid)

    def _build_node(self, node_id: str, target: ProcessTarget) -> TwinNode | None:
        family_name, _, key = node_id.partition(":")
        try:
            family = StateFamily(family_name)
        except ValueError:
            return None
        match family:
            case StateFamily.PROCESS:
                return self._process_node(node_id, key)
            case StateFamily.SERVICE:
                return self._service_node(node_id, key)
            case StateFamily.SESSION:
                observed = key in self._snapshot.sessions
                return TwinNode(
                    family=family,
                    node_id=node_id,
                    attributes={
                        "active": _TRUE if observed else "unknown",
                        DEGRADED_ATTRIBUTE: _FALSE,
                    },
                    observed=observed,
                )
            case StateFamily.COMMUNICATION:
                restricted = key in self._snapshot.restricted_sockets
                return TwinNode(
                    family=family,
                    node_id=node_id,
                    attributes={"restricted": _TRUE if restricted else _FALSE},
                    observed=True,
                )
            case StateFamily.SECURITY:
                return TwinNode(
                    family=family,
                    node_id=node_id,
                    attributes={"privilege": str(self._snapshot.security_state.privilege.name)},
                    observed=True,
                )
            case StateFamily.EVIDENCE:
                return TwinNode(
                    family=family,
                    node_id=node_id,
                    attributes={"available": _TRUE, "volatile": _TRUE},
                    observed=True,
                )
            case StateFamily.RECOVERY:
                return TwinNode(
                    family=family,
                    node_id=node_id,
                    attributes={"captured": _FALSE, "for_pid": str(target.identity.pid)},
                    observed=False,
                )

    def _process_node(self, node_id: str, key: str) -> TwinNode:
        row = self._process_row(node_id)
        if row is None:
            # Referenced but not in the snapshot: an assumption, not an observation.
            return TwinNode(
                family=StateFamily.PROCESS,
                node_id=node_id,
                attributes={"pid": key, "state": "UNKNOWN", DEGRADED_ATTRIBUTE: _FALSE},
                observed=False,
            )
        return TwinNode(
            family=StateFamily.PROCESS,
            node_id=node_id,
            attributes={
                "pid": key,
                "state": str(row.state.value),
                "uid": str(row.identity.uid),
                "unit": row.unit or "",
                DEGRADED_ATTRIBUTE: _FALSE,
            },
            observed=True,
        )

    def _service_node(self, node_id: str, key: str) -> TwinNode:
        row = self._snapshot.service(key)
        if row is None:
            return TwinNode(
                family=StateFamily.SERVICE,
                node_id=node_id,
                attributes={"unit": key, "running": "UNKNOWN", DEGRADED_ATTRIBUTE: _FALSE},
                observed=False,
            )
        return TwinNode(
            family=StateFamily.SERVICE,
            node_id=node_id,
            attributes={
                "unit": key,
                "running": _TRUE if row.running else _FALSE,
                "constrained": _TRUE if row.constrained else _FALSE,
                "restartable": _TRUE if row.restartable else _FALSE,
                "healthy": _TRUE if row.healthy else _FALSE,
                DEGRADED_ATTRIBUTE: _FALSE if row.healthy else _TRUE,
            },
            observed=True,
        )

    def _neighbours(self, node_id: str, target: ProcessTarget) -> tuple[str, ...]:
        family_name, _, key = node_id.partition(":")
        if family_name == StateFamily.PROCESS.value:
            return self._process_neighbours(node_id, target)
        if family_name == StateFamily.SERVICE.value:
            row = self._snapshot.service(key)
            if row is None:
                return ()
            return tuple(f"{StateFamily.SERVICE.value}:{unit}" for unit in row.depends_on)
        return ()

    def _process_neighbours(self, node_id: str, target: ProcessTarget) -> tuple[str, ...]:
        row = self._process_row(node_id)
        out: list[str] = [
            f"{StateFamily.SECURITY.value}:host",
            f"{StateFamily.RECOVERY.value}:{target.identity.pid}",
        ]
        if row is None:
            return tuple(out)
        out.extend(f"{StateFamily.PROCESS.value}:{child}" for child in row.children)
        if row.unit:
            out.append(f"{StateFamily.SERVICE.value}:{row.unit}")
        if row.session_id:
            out.append(f"{StateFamily.SESSION.value}:{row.session_id}")
        out.extend(f"{StateFamily.COMMUNICATION.value}:{sock}" for sock in row.socket_ids)
        out.extend(f"{StateFamily.EVIDENCE.value}:{signal}" for signal in row.volatile_signals)
        return tuple(out)

    # --- unknown dependencies -------------------------------------------

    def unknown_dependencies(self, target: ProcessTarget) -> tuple[str, ...]:
        """Node ids inside the walk that the snapshot could not confirm.

        Two sources, both of which §8 names: a node reached by reference but absent
        from the snapshot, and a service whose ``depends_on`` points at a unit the
        snapshot does not contain. Returned as node ids rather than bare names so
        the caller cannot accidentally join them against a different key space
        (§4.9 Rule A).
        """
        return self._unknown_from(self.project(target))

    def _unknown_from(self, state: TwinState) -> tuple[str, ...]:
        unknown = {node.node_id for node in state.nodes if not node.observed}
        known_units = {service.unit for service in self._snapshot.services}
        for node in state.nodes:
            if node.family is not StateFamily.SERVICE:
                continue
            row = self._snapshot.service(node.attributes.get("unit", ""))
            if row is None:
                continue
            unknown.update(
                f"{StateFamily.SERVICE.value}:{unit}"
                for unit in row.depends_on
                if unit not in known_units
            )
        return tuple(sorted(unknown))

    # --- prediction ------------------------------------------------------

    def predict(self, candidate: CandidateAction, *, world_id: str) -> TwinPrediction:
        """Project, apply the operator class's closed consequence table, and report.

        Nothing here consults an expected security delta, a support value or a
        confidence. The twin answers "what would change", and only that.
        """
        operator = candidate.operator
        target = operator.target
        before, truncated = self._project(target)
        effect = _class_effect(operator.spec.operator_class)
        nodes = tuple(self._apply(node, effect, target) for node in before.nodes)
        predicted = TwinState(nodes=nodes, edges=before.edges)
        evidence_lost = self._evidence_lost(before, operator.spec.evidence_effect)
        recovery = self._recovery_needed(before, operator.spec.reversibility, effect)
        return TwinPrediction(
            candidate_id=candidate.candidate_id,
            world_id=world_id,
            before=before,
            predicted=predicted,
            unknown_dependencies=self._unknown_from(before),
            predicted_degradation=state_degradation(predicted),
            evidence_lost=evidence_lost,
            recovery_state_needed=recovery,
            truncated=truncated,
        )

    def _apply(self, node: TwinNode, effect: _ClassEffect, target: ProcessTarget) -> TwinNode:
        is_target = node.node_id == f"{StateFamily.PROCESS.value}:{target.identity.pid}"
        match node.family:
            case StateFamily.PROCESS:
                if is_target and effect.stops_target:
                    return node.with_attributes(state="EXITED", **{DEGRADED_ATTRIBUTE: _TRUE})
                if is_target and effect.suspends_target:
                    return node.with_attributes(state="SUSPENDED", **{DEGRADED_ATTRIBUTE: _TRUE})
                if not is_target and effect.stops_target:
                    # A child of a terminated process is orphaned, which is a
                    # degradation the caller did not ask for and must still see.
                    return node.with_attributes(**{DEGRADED_ATTRIBUTE: _TRUE})
                return node
            case StateFamily.SERVICE:
                if effect.constrains_unit or effect.stops_target:
                    return node.with_attributes(
                        constrained=_TRUE if effect.constrains_unit else node.attributes.get(
                            "constrained", _FALSE
                        ),
                        healthy=_FALSE,
                        **{DEGRADED_ATTRIBUTE: _TRUE},
                    )
                return node
            case StateFamily.SESSION:
                if effect.revokes_session:
                    return node.with_attributes(active=_FALSE, **{DEGRADED_ATTRIBUTE: _TRUE})
                return node
            case StateFamily.COMMUNICATION:
                if effect.restricts_sockets:
                    return node.with_attributes(restricted=_TRUE)
                return node
            case StateFamily.EVIDENCE:
                if effect.preserves_evidence:
                    return node.with_attributes(preserved=_TRUE)
                if effect.stops_target or effect.suspends_target:
                    return node.with_attributes(available=_FALSE)
                return node
            case StateFamily.SECURITY:
                return node
            case StateFamily.RECOVERY:
                return node

    def _evidence_lost(self, before: TwinState, evidence_effect: EvidenceEffect) -> tuple[str, ...]:
        """Which volatile signals the operator's declared evidence effect costs."""
        volatile = tuple(
            node.node_id for node in before.nodes if node.family is StateFamily.EVIDENCE
        )
        match evidence_effect:
            case EvidenceEffect.PRESERVES | EvidenceEffect.NEUTRAL:
                return ()
            case EvidenceEffect.DEGRADES_VOLATILE | EvidenceEffect.DESTROYS:
                return volatile

    def _recovery_needed(
        self, before: TwinState, reversibility: Reversibility, effect: _ClassEffect
    ) -> tuple[str, ...]:
        """What must be captured beforehand for the undo to be possible at all."""
        if reversibility is Reversibility.IRREVERSIBLE:
            return ()
        needed: list[str] = []
        for node in before.nodes:
            if (node.family is StateFamily.PROCESS and effect.suspends_target) or (node.family is StateFamily.SERVICE and effect.constrains_unit) or (node.family is StateFamily.COMMUNICATION and effect.restricts_sockets):
                needed.append(node.node_id)
        return tuple(sorted(set(needed)))
