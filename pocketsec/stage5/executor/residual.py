"""D5.13 — the Intervention Residual: what the action did that we did not predict.

Architecture §21: ``IR(A) = distance(predicted post-action state, observed
post-action state)``. The number alone is not the point; the *decomposition* is.
A residual that is large because a service we never modelled restarted is a
different engineering problem from one that is large because the enforcement
silently did nothing, and a different one again from an attacker who moved.

Three refusals are built into this module:

- **It never explains noise.** :data:`ResidualCause.UNATTRIBUTABLE` is a
  reachable answer and a test asserts it fires. A decomposition that always
  finds a cause is a decomposition that has stopped being evidence.
- **It never calls into Stage 3 or Stage 4.** §21 says the residual is fed back
  to CBF and CRYSTAL; trust rules T2/T3 say Stage 5 does not decide what becomes
  trusted. :func:`residual_feedback` emits plain JSON rows and Stage 6's
  quarantine path decides. There is no import of a learning subsystem here and
  no write path out of this module.
- **It never joins the two digests.** ``predicted_digest`` comes from the twin's
  own canonicalisation and ``observed_digest`` from this module's; they are
  provenance labels on two different key spaces and comparing them would be the
  S2-FC-01 defect (two key spaces joined that could never match). The distance
  is computed node by node, over the node-id space this module publishes, and a
  test asserts a zero distance is still reported when the digests differ.

**Why the prediction is typed as a Protocol.** ``twin/response_twin.py`` is built
*after* this module (§5's package order: ``field`` depends on ``outcome``), and it
imports the residual's consumers rather than the other way round. A structural
:class:`TwinPredictionLike` keeps the dependency pointing one way — the same
device ``stage4/worlds/field.py`` uses for ``TruncationLike`` — and
``TwinPrediction`` satisfies it field for field.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Protocol

from pocketsec.stage0.contracts.common import (
    ContractError,
    digest_of_bytes,
    require_finite_unit_interval,
    require_identifier,
)

if TYPE_CHECKING:  # pragma: no cover - annotations only
    from pocketsec.stage5.host.simulated import HostEffect, HostSnapshot

__all__ = [
    "MATERIAL_RESIDUAL",
    "NODE_PREFIX_BY_COMPONENT",
    "InterventionResidual",
    "ResidualCause",
    "ResidualComponent",
    "TwinNodeLike",
    "TwinPredictionLike",
    "TwinStateLike",
    "evidence_node_id",
    "intervention_residual",
    "observed_nodes",
    "process_node_id",
    "recovery_node_id",
    "residual_feedback",
    "security_node_id",
    "service_node_id",
    "session_node_id",
    "socket_node_id",
]

#: ``HostFailure`` member names, mirrored rather than imported so this module
#: keeps its runtime import set to Stage 0 only. ``executor/verify.py`` explains
#: the cycle this avoids.
_FAILURE_ENFORCEMENT = "ENFORCEMENT_SILENTLY_FAILED"
_FAILURE_ROLLBACK_UNAVAILABLE = "ROLLBACK_UNAVAILABLE"

#: A residual at or above this is *material*: worth a feedback row, worth
#: blocking crystallisation, worth an operator review. A **chosen** parameter,
#: not a measured one.
MATERIAL_RESIDUAL: float = 0.25


class ResidualComponent(StrEnum):
    """§21's six state families, as the axes the distance is decomposed over."""

    PROCESS_STATE = "PROCESS_STATE"
    SERVICE_STATE = "SERVICE_STATE"
    COMMUNICATION = "COMMUNICATION"
    SECURITY_STATE = "SECURITY_STATE"
    EVIDENCE_VISIBILITY = "EVIDENCE_VISIBILITY"
    RECOVERY_CAPABILITY = "RECOVERY_CAPABILITY"


class ResidualCause(StrEnum):
    """Why the observation and the prediction disagree.

    ``UNATTRIBUTABLE`` is the honest answer when the decomposition cannot pick a
    row of the decision table, and it is load-bearing: without it every residual
    would acquire a cause and the causes would stop meaning anything.
    """

    NONE = "NONE"
    ENFORCEMENT_FAILURE = "ENFORCEMENT_FAILURE"
    HIDDEN_DEPENDENCY = "HIDDEN_DEPENDENCY"
    ATTACKER_ADAPTATION = "ATTACKER_ADAPTATION"
    MODEL_ERROR = "MODEL_ERROR"
    UNATTRIBUTABLE = "UNATTRIBUTABLE"


#: The node-id prefix each component owns. This mapping **is** the join between a
#: twin prediction and an observation, so it is published rather than inlined:
#: the id builders below are the only sanctioned way to produce one.
#:
#: ``session:`` is deliberately folded into ``PROCESS_STATE``: §21 names six
#: components and a session is live actor state, so giving sessions their own
#: axis would mean seven components and an average over a family the
#: architecture does not have.
NODE_PREFIX_BY_COMPONENT: Mapping[ResidualComponent, str] = MappingProxyType(
    {
        ResidualComponent.PROCESS_STATE: "process:",
        ResidualComponent.SERVICE_STATE: "service:",
        ResidualComponent.COMMUNICATION: "socket:",
        ResidualComponent.SECURITY_STATE: "security:",
        ResidualComponent.EVIDENCE_VISIBILITY: "evidence:",
        ResidualComponent.RECOVERY_CAPABILITY: "recovery:",
    }
)

_SESSION_PREFIX = "session:"


def process_node_id(pid: int) -> str:
    return f"process:{pid}"


def service_node_id(unit: str) -> str:
    return f"service:{unit}"


def socket_node_id(socket_id: str) -> str:
    return f"socket:{socket_id}"


def session_node_id(session_id: str) -> str:
    return f"{_SESSION_PREFIX}{session_id}"


def security_node_id() -> str:
    """One node. The security state is a lineage-joined lattice point, not a set."""
    return "security:state"


def evidence_node_id(signal: str) -> str:
    return f"evidence:{signal}"


def recovery_node_id(subject: str) -> str:
    return f"recovery:{subject}"


class TwinNodeLike(Protocol):
    @property
    def node_id(self) -> str: ...

    @property
    def attributes(self) -> Mapping[str, str]: ...


class TwinStateLike(Protocol):
    @property
    def nodes(self) -> tuple[TwinNodeLike, ...]: ...

    def digest(self) -> str: ...


class TwinPredictionLike(Protocol):
    """Exactly the surface of ``TwinPrediction`` this module reads."""

    @property
    def candidate_id(self) -> str: ...

    @property
    def before(self) -> TwinStateLike: ...

    @property
    def predicted(self) -> TwinStateLike: ...

    @property
    def evidence_lost(self) -> tuple[str, ...]: ...

    @property
    def unknown_dependencies(self) -> tuple[str, ...]: ...

    @property
    def truncated(self) -> bool: ...


@dataclass(frozen=True, slots=True)
class InterventionResidual:
    """§21's ``IR(A)``, with its decomposition and one attributed cause."""

    action_id: str
    distance: float
    components: Mapping[ResidualComponent, float]
    attribution: ResidualCause
    predicted_digest: str
    observed_digest: str
    detail: str

    def __post_init__(self) -> None:
        require_identifier(self.action_id, "InterventionResidual.action_id")
        # Stage 0's validator, not a parallel one: §3.1 says Stage 5 writes no
        # second copy of a check the contracts layer already owns.
        object.__setattr__(
            self,
            "distance",
            require_finite_unit_interval(self.distance, "InterventionResidual.distance"),
        )
        if not isinstance(self.attribution, ResidualCause):
            raise ContractError(
                "InterventionResidual.attribution must be a ResidualCause, got "
                f"{self.attribution!r}"
            )
        object.__setattr__(
            self, "components", MappingProxyType(dict(self.components))
        )

    @property
    def material(self) -> bool:
        return self.distance >= MATERIAL_RESIDUAL

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "distance": round(self.distance, 6),
            "components": {
                component.value: round(value, 6)
                for component, value in sorted(
                    self.components.items(), key=lambda item: item[0].value
                )
            },
            "attribution": self.attribution.value,
            "predicted_digest": self.predicted_digest,
            "observed_digest": self.observed_digest,
            "material": self.material,
            "detail": self.detail,
        }


def _flag(value: bool) -> str:
    return "true" if value else "false"


def observed_nodes(snapshot: HostSnapshot) -> dict[str, dict[str, str]]:
    """Project a host snapshot into the published node-id space.

    This is the *consumer* half of the join in :data:`NODE_PREFIX_BY_COMPONENT`.
    A twin that builds ids with the exported builders lands in the same space; a
    twin that invents its own lands in none of it, and the residual reports those
    nodes as unmatched and the cause as ``UNATTRIBUTABLE`` rather than scoring
    them zero. Silence would hide the key-space defect; a visible
    ``UNATTRIBUTABLE`` does not.
    """
    nodes: dict[str, dict[str, str]] = {}
    for row in snapshot.processes:
        nodes[process_node_id(row.identity.pid)] = {"state": row.state.name}
        for socket_id in row.socket_ids:
            nodes[socket_node_id(socket_id)] = {
                "restricted": _flag(socket_id in snapshot.restricted_sockets)
            }
        for signal in row.volatile_signals:
            nodes[evidence_node_id(signal)] = {"present": "true"}
    for service in snapshot.services:
        nodes[service_node_id(service.unit)] = {
            "running": _flag(service.running),
            "constrained": _flag(service.constrained),
            "healthy": _flag(service.healthy),
        }
        nodes[recovery_node_id(service.unit)] = {
            "restartable": _flag(service.restartable)
        }
    for session in snapshot.sessions:
        nodes[session_node_id(session)] = {"present": "true"}
    nodes[security_node_id()] = {
        name: str(level) for name, level in snapshot.security_state.to_levels().items()
    }
    return nodes


def _component_of(node_id: str) -> ResidualComponent | None:
    if node_id.startswith(_SESSION_PREFIX):
        return ResidualComponent.PROCESS_STATE
    for component, prefix in NODE_PREFIX_BY_COMPONENT.items():
        if node_id.startswith(prefix):
            return component
    return None


@dataclass(frozen=True, slots=True)
class _Findings:
    """What the comparison saw, before a cause is chosen."""

    mismatched: tuple[str, ...]
    unmatched: tuple[str, ...]
    unmodelled_services: tuple[str, ...]
    adaptation: tuple[str, ...]


def _modelled_pids(node_ids: frozenset[str]) -> frozenset[int]:
    pids: set[int] = set()
    prefix = NODE_PREFIX_BY_COMPONENT[ResidualComponent.PROCESS_STATE]
    for node_id in node_ids:
        if not node_id.startswith(prefix):
            continue
        tail = node_id[len(prefix) :]
        if tail.isdigit():
            pids.add(int(tail))
    return frozenset(pids)


def _adaptation(
    modelled: frozenset[str], observed: HostSnapshot
) -> tuple[str, ...]:
    """New processes or sockets hanging off a modelled lineage after the action.

    "On the incident lineage" is resolved structurally: a child pid or socket id
    that a modelled process now carries and did not carry in the twin's view. An
    unrelated new process elsewhere on the host is not attributed to this action.
    """
    pids = _modelled_pids(modelled)
    found: set[str] = set()
    for row in observed.processes:
        if row.identity.pid not in pids:
            continue
        for child in row.children:
            if child not in pids:
                found.add(process_node_id(child))
        for socket_id in row.socket_ids:
            if socket_node_id(socket_id) not in modelled:
                found.add(socket_node_id(socket_id))
    return tuple(sorted(found))


def _jaccard_distance(left: frozenset[str], right: frozenset[str]) -> float:
    union = left | right
    if not union:
        return 0.0
    return len(left ^ right) / len(union)


def _node_maps(
    prediction: TwinPredictionLike,
) -> tuple[dict[str, Mapping[str, str]], frozenset[str]]:
    predicted = {node.node_id: node.attributes for node in prediction.predicted.nodes}
    modelled = frozenset(predicted) | {
        node.node_id for node in prediction.before.nodes
    }
    return predicted, modelled


def _compare_nodes(
    predicted: Mapping[str, Mapping[str, str]],
    observed: Mapping[str, Mapping[str, str]],
) -> tuple[dict[ResidualComponent, list[float]], list[str], list[str]]:
    scores: dict[ResidualComponent, list[float]] = {}
    mismatched: list[str] = []
    unmatched: list[str] = []
    for node_id, attributes in sorted(predicted.items()):
        component = _component_of(node_id)
        if component is None:
            # A node id outside the published space: not scored as agreement.
            unmatched.append(node_id)
            continue
        bucket = scores.setdefault(component, [])
        seen = observed.get(node_id)
        if seen is None:
            unmatched.append(node_id)
            bucket.append(1.0)
            continue
        wrong = [key for key, value in attributes.items() if seen.get(key) != value]
        if wrong:
            mismatched.append(f"{node_id}[{','.join(sorted(wrong))}]")
            bucket.append(1.0)
        else:
            bucket.append(0.0)
    return scores, mismatched, unmatched


def _collect(
    prediction: TwinPredictionLike,
    observed: HostSnapshot,
    effect: HostEffect,
    seen: Mapping[str, Mapping[str, str]],
    failure: str,
) -> tuple[dict[ResidualComponent, list[float]], _Findings]:
    """Score every component the prediction or the effect says something about."""
    predicted, modelled = _node_maps(prediction)
    scores, mismatched, unmatched = _compare_nodes(predicted, seen)
    unmodelled_services = tuple(
        sorted(
            unit
            for unit in effect.collateral_units
            if service_node_id(unit) not in modelled
        )
    )
    for _unit in unmodelled_services:
        scores.setdefault(ResidualComponent.SERVICE_STATE, []).append(1.0)
    adaptation = _adaptation(modelled, observed)
    for node_id in adaptation:
        component = _component_of(node_id) or ResidualComponent.PROCESS_STATE
        scores.setdefault(component, []).append(1.0)
    scores.setdefault(ResidualComponent.EVIDENCE_VISIBILITY, []).append(
        _jaccard_distance(
            frozenset(prediction.evidence_lost), frozenset(effect.evidence_lost)
        )
    )
    if failure == _FAILURE_ROLLBACK_UNAVAILABLE:
        scores.setdefault(ResidualComponent.RECOVERY_CAPABILITY, []).append(1.0)
    return scores, _Findings(
        mismatched=tuple(mismatched),
        unmatched=tuple(unmatched),
        unmodelled_services=unmodelled_services,
        adaptation=adaptation,
    )


def intervention_residual(
    *,
    prediction: TwinPredictionLike,
    observed: HostSnapshot,
    effect: HostEffect,
    action_id: str,
) -> InterventionResidual:
    """Compare what the twin predicted with what the host now shows.

    The distance is the mean of the per-component ratios over the components the
    prediction (or the effect) actually says something about. Averaging over all
    six would divide every real disagreement by the number of families the twin
    declined to model, which would make :data:`MATERIAL_RESIDUAL` unreachable for
    a narrow twin — and §8 says the twin is *deliberately* narrow.
    """
    seen = observed_nodes(observed)
    failure = getattr(effect.failure, "name", "")
    scores, findings = _collect(prediction, observed, effect, seen, failure)
    components = {
        component: sum(values) / len(values)
        for component, values in scores.items()
        if values
    }
    distance = sum(components.values()) / len(components) if components else 0.0
    return InterventionResidual(
        action_id=action_id,
        distance=min(1.0, max(0.0, distance)),
        components=components,
        attribution=_attribute(findings, failure=failure, distance=distance),
        predicted_digest=prediction.predicted.digest(),
        observed_digest=digest_of_bytes(
            json.dumps(seen, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ),
        detail=_detail(findings, prediction=prediction, failure=failure),
    )


def _attribute(
    findings: _Findings, *, failure: str, distance: float
) -> ResidualCause:
    """The decision table of §21, evaluated in order, with a total fallthrough.

    Order is the contract. Enforcement failure first because it explains *every*
    downstream disagreement; unmodelled collateral next because it is a fact
    about the twin's coverage rather than about its arithmetic; adaptation before
    model error because a new process is not a mispredicted value; model error
    only for a node that was modelled, observed, and wrong. Anything else
    non-zero is ``UNATTRIBUTABLE``.

    **The unmatched row fires even at distance 0.0, on purpose.** A predicted node
    whose id is outside the published space (:data:`NODE_PREFIX_BY_COMPONENT`)
    belongs to no component, so it cannot enter an average over the six families
    without inventing a seventh — and scoring it as agreement would let a twin
    with a private id vocabulary report a perfect residual for a host it never
    looked at. A zero distance over nothing comparable is not evidence of
    agreement, so the cause says so.
    """
    table: tuple[tuple[bool, ResidualCause], ...] = (
        (failure == _FAILURE_ENFORCEMENT, ResidualCause.ENFORCEMENT_FAILURE),
        (bool(findings.unmodelled_services), ResidualCause.HIDDEN_DEPENDENCY),
        (bool(findings.adaptation), ResidualCause.ATTACKER_ADAPTATION),
        (bool(findings.mismatched), ResidualCause.MODEL_ERROR),
        (bool(findings.unmatched), ResidualCause.UNATTRIBUTABLE),
        (distance > 0.0, ResidualCause.UNATTRIBUTABLE),
    )
    for fired, cause in table:
        if fired:
            return cause
    return ResidualCause.NONE


def _detail(
    findings: _Findings, *, prediction: TwinPredictionLike, failure: str
) -> str:
    parts = [
        f"candidate={prediction.candidate_id}",
        f"mismatched={len(findings.mismatched)}",
        f"unmatched={len(findings.unmatched)}",
        f"unmodelled_services={len(findings.unmodelled_services)}",
        f"adaptation={len(findings.adaptation)}",
        f"unknown_dependencies={len(prediction.unknown_dependencies)}",
        f"twin_truncated={_flag(prediction.truncated)}",
    ]
    if failure:
        parts.append(f"host_failure={failure}")
    if findings.mismatched:
        parts.append("wrong=" + ";".join(findings.mismatched[:4]))
    if findings.unmatched:
        parts.append("absent=" + ";".join(findings.unmatched[:4]))
    return " ".join(parts)


def residual_feedback(residual: InterventionResidual) -> Mapping[str, Any]:
    """A plain JSON row for ``ResponseRecordV1.residuals``.

    Stage 5 emits; it does not teach. §21 wants the residual fed back to Stage 4
    CBF and Stage 3 CRYSTAL, and trust rules T2/T3 say that path runs through
    Stage 6's quarantine — so this function returns data and calls nothing. The
    row carries no Stage 5 class name and no operator id, because the seam that
    screens those tokens (``stage6_interface.py``) should not have to strip them.
    """
    row = residual.to_dict()
    row["feedback_kind"] = "intervention_residual"
    return MappingProxyType(row)
