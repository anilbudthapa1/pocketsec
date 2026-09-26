"""D5.2 — the SAFE Action Field: the bounded set of typed actions Stage 5 will consider.

Architecture §3 gives the field element A_j field for field, then the sentence that
decides the design: *"Candidate generation is constrained by the typed operator
catalog and local policy; it is not open-ended planning."*

So this is a **cross product, not a search**: (catalog entries whose
``target_kind`` matches an entity the resolution names) × (targets the
resolution's ``evidence_lineage`` names), filtered by the response constitution
and the mission invariants, pruned by the resource governor. No sampling, no
beam, no scoring function that could be made to explore, no language model.

Five refusals, each structural rather than reviewed.

1. *No string selects behaviour.* :class:`CandidateAction` holds a
   ``DefensiveOperator`` whose ``spec`` is a ``CATALOG`` member by identity.
2. *Gap prose is never parsed* (§3.2 fact 5). A gap adds an O0 candidate only
   through :data:`GAP_TO_OBSERVE_OPERATOR`, keyed on ``gap["signal"]``;
   ``why_it_matters`` is not read at all — not even to log it.
3. *An unrecognised identifiability string is UNKNOWN* (§3.2 fact 1), because
   Stage 5 must not import Stage 4's enum. UNKNOWN is not permission.
4. *An evidence digest with no lineage row is refused, not defaulted* (§3.2 fact 2).
5. *An action with no verification predicate cannot be constructed* (§2) —
   enforced at generation, not discovered at VERIFY once the host has changed.

Upstream damage raises shadow, never confidence: ``len(truncations) +
len(degradations)`` feeds ``ActionShadow.upstream_truncations`` (§3.2 fact 4), and
no candidate field exists through which it could raise a security delta.

**NO ACTION is always available.** When every intervention is refused the field
still carries :data:`NO_ACTION_OPERATOR_ID` plus one truncation row per refusal.

The module is **unprivileged** (§35): no token store, no journal, no executor.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import (
    ContractError,
    EvidenceRef,
    require_finite_unit_interval,
    require_identifier,
    require_non_negative_int,
)
from pocketsec.stage4.stage5_interface import CBFResolutionV1
from pocketsec.stage5.aegis.shadow import SHADOW_TERMS, ActionShadow, generation_shadow
from pocketsec.stage5.constitution.invariants import (
    AuthorityClass,
    ConstitutionDecision,
    ResponseConstitution,
)
from pocketsec.stage5.constitution.schema import MissionInvariantSet
from pocketsec.stage5.executor.verify import PostconditionKind
from pocketsec.stage5.governor import BudgetExhausted, ResourceGovernor, WorkKind
from pocketsec.stage5.host.simulated import HostSnapshot
from pocketsec.stage5.memory.effectiveness import context_key
from pocketsec.stage5.operators.algebra import (
    DefensiveOperator,
    EvidenceEffect,
    OperatorClass,
    OperatorSpec,
    ProcessIdentity,
    ProcessTarget,
    Reversibility,
    TargetKind,
    TargetScope,
)
from pocketsec.stage5.operators.catalog import CATALOG, RESTORATION_OPERATOR_IDS

if TYPE_CHECKING:  # pragma: no cover - annotations only
    from pocketsec.stage5.cells.response_cells import ResponseCellField
    from pocketsec.stage5.memory.effectiveness import EffectivenessMemory
    from pocketsec.stage5.twin.response_twin import ResponseTwin

__all__ = [
    "ACTIONABLE_IDENTIFIABILITY",
    "GAP_TO_OBSERVE_OPERATOR",
    "LINEAGE_TARGET_KEYS",
    "MAX_CANDIDATES",
    "NO_ACTION_OPERATOR_ID",
    "OBSERVE_CLASSES",
    "REVERSIBILITY_COST",
    "RULED_OUT_SUPPORT",
    "UNDERSTOOD_IDENTIFIABILITY",
    "ActionField",
    "CandidateAction",
    "FieldTruncation",
    "HarmModel",
    "IdentifiabilityOutcome",
    "ResponseIdentifiability",
    "RiskAcceptancePolicy",
    "check_response_identifiability",
    "generate_action_field",
]

#: Equal to ``ResourceBudget.max_candidate_actions``; the test suite asserts it.
MAX_CANDIDATES: int = 16

#: The identifiability strings Stage 5 understands, compared as *values* because
#: ``CBFResolutionV1.identifiability`` is a ``str`` and Stage 5 does not import
#: ``IdentifiabilityState``. Anything else is read as UNKNOWN. Stage 4's enum
#: defines four of these six today (``stage4/identifiability/resolution.py:101``,
#: read this session); ``SEPARABLE`` and ``UNPLANNED`` are reserved slots so a
#: Stage 4 redesign adding them does not fall into the fail-closed branch.
UNDERSTOOD_IDENTIFIABILITY: frozenset[str] = frozenset(
    {"IDENTIFIED", "SEPARABLE", "UNPLANNED", "INSUFFICIENT_EVIDENCE", "UNIDENTIFIABLE", "UNKNOWN"}
)

#: The states under which an intervention above O1 may even be *proposed*. Every
#: other state, including every unrecognised string, limits the field to
#: observation and preservation: UNKNOWN is never permission (§2).
ACTIONABLE_IDENTIFIABILITY: frozenset[str] = frozenset({"IDENTIFIED", "SEPARABLE"})

#: The read-only classes that stay available whatever the belief state is.
OBSERVE_CLASSES: frozenset[OperatorClass] = frozenset(
    {OperatorClass.O0_OBSERVE, OperatorClass.O1_PRESERVE}
)

#: A hypothesis at or below this support is "sufficiently ruled out" for §7.
#: A **chosen** parameter (§4.9), never a measured one.
RULED_OUT_SUPPORT: float = 0.05

#: The operator that is always available: read-only, authority A0, and the reason
#: an all-unsafe incident yields NO ACTION rather than an exception.
NO_ACTION_OPERATOR_ID: str = "OBSERVE_PROCESS_METADATA"

#: §3.2 fact 5's CLOSED signal → O0 operator table, keyed by Stage 1 signal names
#: (``MANDATORY_SIGNALS``, ``stage1/observation/policy.py:47``, plus three
#: observation names). A gap whose ``signal`` is not a key adds no candidate: a
#: default here would let an unnamed signal pick a privileged operator.
GAP_TO_OBSERVE_OPERATOR: Mapping[str, str] = MappingProxyType(
    {
        "privilege_change": "OBSERVE_PROCESS_METADATA",
        "credential_access": "OBSERVE_PROCESS_METADATA",
        "persistence_write": "OBSERVE_PROCESS_METADATA",
        "authentication": "OBSERVE_PROCESS_METADATA",
        "process_metadata": "OBSERVE_PROCESS_METADATA",
        "module_load": "HASH_EXECUTABLE",
        "executable_identity": "HASH_EXECUTABLE",
        "boundary_crossing": "TRACE_PROCESS_BOUNDED",
        "syscall_trace": "TRACE_PROCESS_BOUNDED",
    }
)

#: The CLOSED set of ``evidence_lineage`` row keys that may name a target. The seam
#: does not define how a resolution names a host entity, so this contract defines it
#: as *explicit typed keys on a lineage row*: parsing ``locator`` would be the
#: natural-language-to-privilege path §6 removes. A row carrying none of these keys
#: names no target and yields no intervention candidate.
LINEAGE_TARGET_KEYS: Mapping[str, TargetKind] = MappingProxyType(
    {
        "target_pid": TargetKind.PROCESS,
        "target_unit": TargetKind.SERVICE,
        "target_session": TargetKind.SESSION,
        "target_socket": TargetKind.SOCKET,
    }
)

#: Operational cost of a reversibility class, in [0, 1]. A CHOSEN table (§4.9).
REVERSIBILITY_COST: Mapping[Reversibility, float] = MappingProxyType(
    {
        Reversibility.FULLY_REVERSIBLE: 0.10,
        Reversibility.REVERSIBLE_WITH_STATE: 0.30,
        Reversibility.DEGRADED: 0.60,
        Reversibility.IRREVERSIBLE: 1.00,
    }
)

#: Weight on reversibility versus scope in the operational delta. CHOSEN.
_REVERSIBILITY_WEIGHT: float = 0.75

assert set(REVERSIBILITY_COST) == set(Reversibility)
assert set(GAP_TO_OBSERVE_OPERATOR.values()) <= set(CATALOG)
assert NO_ACTION_OPERATOR_ID in CATALOG

_MAX_OPERATOR_CLASS: int = max(int(member) for member in OperatorClass)


@dataclass(frozen=True, slots=True)
class FieldTruncation:
    """One thing the field does not contain, and why. Truncation is always explicit."""

    what: str
    identifier: str
    reason: str

    def __post_init__(self) -> None:
        for name in ("what", "identifier", "reason"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ContractError(f"FieldTruncation.{name} must be a non-empty string")

    def to_dict(self) -> dict[str, str]:
        return {"what": self.what, "identifier": self.identifier, "reason": self.reason}


@dataclass(frozen=True, slots=True)
class CandidateAction:
    """§3's A_j, field for field. No ``str`` field here selects behaviour:
    ``rollback_operator_id``, ``candidate_id`` and the evidence-loss signal names
    *describe*, and the thing that will run is ``operator``.
    """

    candidate_id: str
    operator: DefensiveOperator
    world_applicability: frozenset[str]
    expected_security_delta: float
    expected_operational_delta: float
    evidence_effect: EvidenceEffect
    reversibility: Reversibility
    rollback_operator_id: str | None
    authority: AuthorityClass
    verification_predicates: tuple[PostconditionKind, ...]
    lease_ttl_seconds: int
    uncertainty: float
    shadow: ActionShadow
    scope_size: int
    evidence_loss: tuple[str, ...]

    def __post_init__(self) -> None:
        require_identifier(self.candidate_id, "CandidateAction.candidate_id")
        if not isinstance(self.operator, DefensiveOperator):
            raise ContractError(
                f"CandidateAction.operator must be a DefensiveOperator, got "
                f"{type(self.operator).__name__}; only typed operators reach privilege (§45)"
            )
        object.__setattr__(self, "world_applicability", frozenset(self.world_applicability))
        require_finite_unit_interval(
            self.expected_security_delta, "CandidateAction.expected_security_delta"
        )
        require_finite_unit_interval(
            self.expected_operational_delta, "CandidateAction.expected_operational_delta"
        )
        object.__setattr__(self, "evidence_effect", EvidenceEffect(self.evidence_effect))
        object.__setattr__(self, "reversibility", Reversibility(self.reversibility))
        object.__setattr__(self, "authority", AuthorityClass(self.authority))
        object.__setattr__(
            self,
            "verification_predicates",
            tuple(PostconditionKind(kind) for kind in self.verification_predicates),
        )
        if not self.verification_predicates:
            raise ContractError(
                f"CandidateAction({self.candidate_id!r}) declares no verification predicate; an "
                "action that cannot be verified cannot be considered successfully completed "
                "(§2), which is enforced here rather than discovered at VERIFY"
            )
        require_non_negative_int(self.lease_ttl_seconds, "CandidateAction.lease_ttl_seconds")
        if self.lease_ttl_seconds <= 0:
            raise ContractError(
                "CandidateAction.lease_ttl_seconds must be positive; an intervention with no "
                "expiry is a permanent change with an optimistic docstring (§18)"
            )
        require_finite_unit_interval(self.uncertainty, "CandidateAction.uncertainty")
        if not isinstance(self.shadow, ActionShadow):
            raise ContractError("CandidateAction.shadow must be an ActionShadow")
        if self.shadow.candidate_id != self.candidate_id:
            raise ContractError(
                f"CandidateAction({self.candidate_id!r}) carries a shadow for "
                f"{self.shadow.candidate_id!r}; two key spaces that can never match is the "
                "defect §4.9 Rule A exists to prevent"
            )
        require_non_negative_int(self.scope_size, "CandidateAction.scope_size")
        object.__setattr__(self, "evidence_loss", tuple(str(item) for item in self.evidence_loss))
        if self.rollback_operator_id is not None:
            require_identifier(self.rollback_operator_id, "CandidateAction.rollback_operator_id")

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "operator_id": self.operator.spec.operator_id,
            "operator_class": int(self.operator.spec.operator_class),
            "target_digest": self.operator.target.identity.digest(),
            "world_applicability": sorted(self.world_applicability),
            "expected_security_delta": self.expected_security_delta,
            "expected_operational_delta": self.expected_operational_delta,
            "evidence_effect": self.evidence_effect.value,
            "reversibility": self.reversibility.value,
            "rollback_operator_id": self.rollback_operator_id,
            "authority": self.authority.value,
            "verification_predicates": [kind.value for kind in self.verification_predicates],
            "lease_ttl_seconds": self.lease_ttl_seconds,
            "uncertainty": self.uncertainty,
            "shadow": self.shadow.to_dict(),
            "scope_size": self.scope_size,
            "evidence_loss": list(self.evidence_loss),
        }


@dataclass(frozen=True, slots=True)
class ActionField:
    """The bounded candidate set for one resolution, plus everything it excluded."""

    incident_id: str
    resolution_id: str
    candidates: tuple[CandidateAction, ...]
    truncations: tuple[FieldTruncation, ...]

    def __post_init__(self) -> None:
        require_identifier(self.incident_id, "ActionField.incident_id")
        require_identifier(self.resolution_id, "ActionField.resolution_id")
        object.__setattr__(self, "candidates", tuple(self.candidates))
        object.__setattr__(self, "truncations", tuple(self.truncations))
        if len(self.candidates) > MAX_CANDIDATES:
            raise ContractError(
                f"ActionField holds {len(self.candidates)} candidates, over "
                f"MAX_CANDIDATES={MAX_CANDIDATES}; the generator prunes rather than building an "
                "over-budget field"
            )
        ids = [candidate.candidate_id for candidate in self.candidates]
        if len(set(ids)) != len(ids):
            raise ContractError("ActionField candidate ids must be unique")

    def observe_only(self) -> tuple[CandidateAction, ...]:
        """The read-only candidates: what remains when everything else is refused."""
        return tuple(
            candidate
            for candidate in self.candidates
            if candidate.operator.spec.operator_class is OperatorClass.O0_OBSERVE
        )

    def state_bytes(self) -> int:
        """Bytes this field occupies as canonical JSON. Endpoint state is bounded."""
        payload = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        return len(payload.encode("utf-8"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "resolution_id": self.resolution_id,
            "candidates": [candidate.to_dict() for candidate in self.candidates],
            "truncations": [row.to_dict() for row in self.truncations],
        }


# --- §7 response identifiability ---------------------------------------------


class IdentifiabilityOutcome(StrEnum):
    ACTIONABLE = "ACTIONABLE"
    NOT_IDENTIFIABLE = "NOT_IDENTIFIABLE"
    RESIDUAL_ACCEPTED = "RESIDUAL_ACCEPTED"


@dataclass(frozen=True, slots=True)
class RiskAcceptancePolicy:
    """The only route by which a residual harmful world becomes acceptable."""

    accept_residual_below_support: float
    accepted_operator_classes: frozenset[OperatorClass] = frozenset(
        {OperatorClass.O0_OBSERVE, OperatorClass.O1_PRESERVE}
    )
    policy_version: str = "1.0.0"

    def __post_init__(self) -> None:
        require_finite_unit_interval(
            self.accept_residual_below_support,
            "RiskAcceptancePolicy.accept_residual_below_support",
        )
        object.__setattr__(
            self,
            "accepted_operator_classes",
            frozenset(OperatorClass(member) for member in self.accepted_operator_classes),
        )
        require_identifier(self.policy_version, "RiskAcceptancePolicy.policy_version")


@dataclass(frozen=True, slots=True)
class HarmModel:
    """Which ``(mechanism_id, operator_class)`` pairs are unacceptable: a closed,
    hand-written table, **never inferred from a model score**, because a harm table
    derived from a confidence would be model confidence granting authority by a
    longer route (ADR-0003). §9.2 records that this table and the planner share an
    author, a confound on every collateral figure built on it.
    """

    unacceptable: frozenset[tuple[str, OperatorClass]]

    def __post_init__(self) -> None:
        rows: set[tuple[str, OperatorClass]] = set()
        for mechanism_id, operator_class in self.unacceptable:
            require_identifier(mechanism_id, "HarmModel.unacceptable mechanism_id")
            rows.add((mechanism_id, OperatorClass(operator_class)))
        object.__setattr__(self, "unacceptable", frozenset(rows))

    def harms(self, mechanism_id: str, spec: OperatorSpec) -> bool:
        return (mechanism_id, spec.operator_class) in self.unacceptable


@dataclass(frozen=True, slots=True)
class ResponseIdentifiability:
    outcome: IdentifiabilityOutcome
    harmful_worlds: tuple[str, ...]
    unruled_out: tuple[str, ...]
    detail: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "outcome", IdentifiabilityOutcome(self.outcome))
        for name in ("harmful_worlds", "unruled_out"):
            object.__setattr__(self, name, tuple(str(item) for item in getattr(self, name)))
        if not isinstance(self.detail, str) or not self.detail.strip():
            raise ContractError("ResponseIdentifiability.detail must say what decided the outcome")

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome.value,
            "harmful_worlds": list(self.harmful_worlds),
            "unruled_out": list(self.unruled_out),
            "detail": self.detail,
        }


def _harm_partition(
    spec: OperatorSpec,
    resolution: CBFResolutionV1,
    *,
    truth: HarmModel,
    policy: RiskAcceptancePolicy,
) -> tuple[list[str], list[str], list[str]]:
    """Split the harmful worlds into (all, still-live, policy-accepted).

    A world at or below :data:`RULED_OUT_SUPPORT` appears in the first list and
    neither of the others: it is harmful in principle and ruled out in fact, and §7
    asks for exactly that distinction to be visible rather than collapsed.
    """
    harmful: list[str] = []
    unruled_out: list[str] = []
    residual_only: list[str] = []
    for row in resolution.hypotheses:
        mechanism_id = str(row.get("mechanism_id", ""))
        if not mechanism_id or not truth.harms(mechanism_id, spec):
            continue
        harmful.append(mechanism_id)
        support = float(row.get("support", 0.0))
        if support <= RULED_OUT_SUPPORT:
            continue
        if (
            support < policy.accept_residual_below_support
            and spec.operator_class in policy.accepted_operator_classes
        ):
            residual_only.append(mechanism_id)
            continue
        unruled_out.append(mechanism_id)
    return harmful, unruled_out, residual_only


def check_response_identifiability(
    candidate: CandidateAction,
    resolution: CBFResolutionV1,
    *,
    truth: HarmModel,
    policy: RiskAcceptancePolicy,
) -> ResponseIdentifiability:
    """§7 as an execution constraint rather than a warning label.

    ``ActionIdentifiable(A)`` holds when every world in which this candidate causes
    unacceptable harm is at or below :data:`RULED_OUT_SUPPORT` **or** explicitly
    accepted by policy. Otherwise the outcome is ``NOT_IDENTIFIABLE`` and the
    planner may not choose it: epistemic uncertainty becomes an execution
    constraint, which is the whole point.
    """
    spec = candidate.operator.spec
    harmful, unruled_out, residual_only = _harm_partition(
        spec, resolution, truth=truth, policy=policy
    )
    if unruled_out:
        return ResponseIdentifiability(
            outcome=IdentifiabilityOutcome.NOT_IDENTIFIABLE,
            harmful_worlds=tuple(harmful),
            unruled_out=tuple(unruled_out),
            detail=(
                f"{spec.operator_id} causes unacceptable harm in {unruled_out}, whose support "
                f"exceeds RULED_OUT_SUPPORT={RULED_OUT_SUPPORT} and which policy "
                f"{policy.policy_version} does not accept"
            ),
        )
    if residual_only:
        return ResponseIdentifiability(
            outcome=IdentifiabilityOutcome.RESIDUAL_ACCEPTED,
            harmful_worlds=tuple(harmful),
            unruled_out=(),
            detail=(
                f"policy {policy.policy_version} explicitly accepts the residual in "
                f"{residual_only} for operator class {spec.operator_class.name}"
            ),
        )
    return ResponseIdentifiability(
        outcome=IdentifiabilityOutcome.ACTIONABLE,
        harmful_worlds=tuple(harmful),
        unruled_out=(),
        detail=(
            f"every world in which {spec.operator_id} causes unacceptable harm is at or below "
            f"RULED_OUT_SUPPORT={RULED_OUT_SUPPORT}"
        ),
    )


# --- generation ---------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _NamedTarget:
    """One (scope, identity, evidence) triple the resolution actually names."""

    scope: TargetScope
    identity: ProcessIdentity
    evidence: EvidenceRef
    scope_size: int


def _lineage_index(
    resolution: CBFResolutionV1,
) -> tuple[dict[str, EvidenceRef], list[FieldTruncation]]:
    """``digest -> EvidenceRef``, rebuilt only from ``evidence_lineage`` (§3.2 fact 2)."""
    index: dict[str, EvidenceRef] = {}
    dropped: list[FieldTruncation] = []
    for position, row in enumerate(resolution.evidence_lineage):
        try:
            ref = EvidenceRef(
                store=str(row["store"]), locator=str(row["locator"]), digest=str(row["digest"])
            )
        except (KeyError, ContractError) as exc:
            dropped.append(
                FieldTruncation(
                    what="evidence-lineage-row",
                    identifier=f"{resolution.resolution_id}.lineage.{position}",
                    reason=f"unusable lineage row: {exc}",
                )
            )
            continue
        index[ref.digest] = ref
    return index, dropped


def _scope_size(snapshot: HostSnapshot, pid: int) -> int:
    """Processes + services + sessions touched, from the snapshot alone — counted
    without the twin so ``scope_size`` costs no twin steps, since a size that spent
    the twin budget would make the affordable candidates the cheap ones by
    construction.
    """
    row = snapshot.process(pid)
    if row is None:
        return 1
    return 1 + len(row.children) + (1 if row.unit else 0) + (1 if row.session_id else 0)


def _scopes_from_row(
    row: Mapping[str, str], snapshot: HostSnapshot, pid: int
) -> tuple[list[TargetScope], list[str]]:
    """The scopes one lineage row names, plus a reason per scope it could not name."""
    scopes = [TargetScope(kind=TargetKind.PROCESS, subject=str(pid))]
    problems: list[str] = []
    process = snapshot.process(pid)
    present: dict[str, bool] = {
        "target_unit": snapshot.service(str(row.get("target_unit"))) is not None,
        "target_session": str(row.get("target_session")) in snapshot.sessions,
        "target_socket": process is not None
        and str(row.get("target_socket")) in process.socket_ids,
    }
    for key, kind in LINEAGE_TARGET_KEYS.items():
        if key == "target_pid":
            continue
        subject = row.get(key)
        if subject is None:
            continue
        if not present[key]:
            problems.append(f"{key} {subject!r} is absent from the snapshot")
            continue
        scopes.append(TargetScope(kind=kind, subject=str(subject)))
    return scopes, problems


def _named_targets(
    resolution: CBFResolutionV1, snapshot: HostSnapshot, lineage: Mapping[str, EvidenceRef]
) -> tuple[tuple[_NamedTarget, ...], list[FieldTruncation]]:
    """Resolve every target the lineage names against the snapshot. No prose is read."""
    targets: list[_NamedTarget] = []
    dropped: list[FieldTruncation] = []
    for position, row in enumerate(resolution.evidence_lineage):
        tag = f"{resolution.resolution_id}.lineage.{position}"
        raw_pid = row.get("target_pid")
        if raw_pid is None:
            continue
        try:
            pid = int(raw_pid)
        except (TypeError, ValueError):
            dropped.append(FieldTruncation("target", tag, f"target_pid {raw_pid!r} is not an int"))
            continue
        identity = snapshot.identity(pid)
        if identity is None:
            dropped.append(
                FieldTruncation(
                    "target",
                    tag,
                    f"pid {pid} has no identity in the snapshot; a pid is not an identity",
                )
            )
            continue
        ref = lineage.get(str(row.get("digest", "")))
        if ref is None:
            dropped.append(
                FieldTruncation(
                    "target", tag, "the row naming this target carries no usable evidence digest"
                )
            )
            continue
        scopes, problems = _scopes_from_row(row, snapshot, pid)
        dropped.extend(FieldTruncation("target-scope", tag, problem) for problem in problems)
        size = _scope_size(snapshot, pid)
        targets.extend(
            _NamedTarget(scope=scope, identity=identity, evidence=ref, scope_size=size)
            for scope in scopes
        )
    return tuple(targets), dropped


def _identifiability(resolution: CBFResolutionV1) -> tuple[str, FieldTruncation | None]:
    """Read the identifiability string fail-closed. An unrecognised value *is* UNKNOWN."""
    raw = resolution.identifiability
    if raw in UNDERSTOOD_IDENTIFIABILITY:
        return raw, None
    return "UNKNOWN", FieldTruncation(
        what="identifiability",
        identifier=resolution.resolution_id,
        reason=(
            f"identifiability {raw!r} is outside UNDERSTOOD_IDENTIFIABILITY and is read as "
            "UNKNOWN; UNKNOWN is never converted into permission (§2)"
        ),
    )


def _applicable_worlds(
    resolution: CBFResolutionV1, lineage: Mapping[str, EvidenceRef]
) -> tuple[frozenset[str], list[FieldTruncation]]:
    """Mechanism ids neither ruled out nor citing evidence that has no lineage row."""
    worlds: set[str] = set()
    dropped: list[FieldTruncation] = []
    for row in resolution.hypotheses:
        mechanism_id = str(row.get("mechanism_id", ""))
        if not mechanism_id or float(row.get("support", 0.0)) <= RULED_OUT_SUPPORT:
            continue
        missing = [
            digest for digest in row.get("evidence_digests", ()) or () if str(digest) not in lineage
        ]
        if missing:
            dropped.append(
                FieldTruncation(
                    what="world",
                    identifier=mechanism_id,
                    reason=(
                        f"evidence digest(s) {missing} have no evidence_lineage row, so no "
                        "EvidenceRef can be reconstructed; refused, not defaulted (§3.2 fact 2)"
                    ),
                )
            )
            continue
        worlds.add(mechanism_id)
    return frozenset(worlds), dropped


def _leading_world(resolution: CBFResolutionV1) -> str:
    """The highest-support mechanism id, or a named placeholder when there is none."""
    best, best_support = "", -1.0
    for row in resolution.hypotheses:
        mechanism_id = str(row.get("mechanism_id", ""))
        support = float(row.get("support", 0.0))
        if mechanism_id and support > best_support:
            best, best_support = mechanism_id, support
    return best or "UNKNOWN-WORLD"


def _security_prior(
    spec: OperatorSpec,
    resolution: CBFResolutionV1,
    memory: EffectivenessMemory,
    world_id: str,
) -> float:
    """Expected security delta, from measured effectiveness where any exists.

    The prior is the operator class's share of the class range scaled by the leading
    world's support, so an O0 observation reduces no security risk. Where memory
    holds enough samples for this context the measured rate replaces it; ``None``
    from memory leaves the prior alone and never raises it, because a missing
    measurement is not an optimistic one (ADR-0004).
    """
    context = context_key(
        epoch_id=resolution.epoch_id, mechanism_id=world_id, target_kind=spec.target_kind
    )
    record = memory.record(context=context, operator_id=spec.operator_id)
    if record is not None:
        measured = record.effect_rate()
        if measured is not None:
            return require_finite_unit_interval(measured, "EffectivenessRecord.effect_rate")
    support = max((float(row.get("support", 0.0)) for row in resolution.hypotheses), default=0.0)
    return min(1.0, (int(spec.operator_class) / _MAX_OPERATOR_CLASS) * support)


def _operational_cost(spec: OperatorSpec, scope_size: int) -> float:
    """Operational delta: reversibility cost weighted against a bounded scope term."""
    scope_term = scope_size / (scope_size + MAX_CANDIDATES)
    return min(
        1.0,
        REVERSIBILITY_COST[spec.reversibility] * _REVERSIBILITY_WEIGHT
        + scope_term * (1.0 - _REVERSIBILITY_WEIGHT),
    )


def _bootstrap_shadow(candidate_id: str) -> ActionShadow:
    """A zero shadow, used only to hand the twin a typed candidate. It never leaves
    :func:`generate_action_field` — the candidate is rebuilt with the real
    generation shadow before it joins the field, and the test suite asserts every
    field candidate carries the resolution's upstream count.
    """
    return ActionShadow(
        candidate_id=candidate_id,
        unmodelled_dependencies=0,
        uncertain_side_effects=0,
        unobservable_effects=0,
        upstream_truncations=0,
        score=0.0,
        components=dict.fromkeys(SHADOW_TERMS, 0.0),
    )


def _evidence_loss(spec: OperatorSpec, snapshot: HostSnapshot, pid: int) -> tuple[str, ...]:
    """Volatile signals the operator's *declared* evidence effect costs."""
    if spec.evidence_effect in (EvidenceEffect.PRESERVES, EvidenceEffect.NEUTRAL):
        return ()
    row = snapshot.process(pid)
    return () if row is None else tuple(row.volatile_signals)


def _candidate(
    *,
    index: int,
    spec: OperatorSpec,
    target: _NamedTarget,
    resolution: CBFResolutionV1,
    snapshot: HostSnapshot,
    worlds: frozenset[str],
    memory: EffectivenessMemory,
    twin: ResponseTwin,
    world_id: str,
) -> CandidateAction:
    """Build one candidate, or raise ``ContractError`` when the operator is unusable."""
    candidate_id = f"cand{index:02d}.{spec.operator_id.replace('_', '-')}"
    operator = DefensiveOperator(
        spec=spec,
        target=ProcessTarget(identity=target.identity, scope=target.scope),
        incident_id=resolution.incident_id,
        ttl_seconds=spec.max_duration_seconds,
        evidence_refs=(target.evidence,),
    )
    common: dict[str, Any] = {
        "candidate_id": candidate_id,
        "operator": operator,
        "world_applicability": worlds,
        "expected_security_delta": _security_prior(spec, resolution, memory, world_id),
        "expected_operational_delta": _operational_cost(spec, target.scope_size),
        "evidence_effect": spec.evidence_effect,
        "reversibility": spec.reversibility,
        "rollback_operator_id": spec.rollback_operator_id,
        "authority": spec.authority,
        "verification_predicates": spec.postconditions,
        "lease_ttl_seconds": spec.max_duration_seconds,
        "uncertainty": resolution.uncertainty,
        "scope_size": target.scope_size,
        "evidence_loss": _evidence_loss(spec, snapshot, target.identity.pid),
    }
    provisional = CandidateAction(shadow=_bootstrap_shadow(candidate_id), **common)
    prediction = twin.predict(provisional, world_id=world_id)
    shadow = generation_shadow(
        candidate_id, prediction=prediction, snapshot=snapshot, resolution=resolution
    )
    return CandidateAction(shadow=shadow, **common)


def _gap_operator_ids(resolution: CBFResolutionV1) -> tuple[str, ...]:
    """O0 operator ids the gaps select, through the CLOSED table only.
    ``gap["signal"]`` is a dict key lookup and ``why_it_matters`` is never read, so
    a gap whose prose names ``TERMINATE_PROCESS`` cannot produce an O6 candidate.
    """
    picked: list[str] = []
    for row in resolution.information_gaps:
        operator_id = GAP_TO_OBSERVE_OPERATOR.get(str(row.get("signal", "")))
        if operator_id is not None and operator_id not in picked:
            picked.append(operator_id)
    return tuple(picked)


def _eligible_specs(identifiability: str) -> tuple[tuple[OperatorSpec, ...], list[FieldTruncation]]:
    """Catalog entries that may be proposed at all, given the identifiability state.

    A restoration operator (``RESTORATION_OPERATOR_IDS``: the entries that are some
    other entry's rollback) is never an incident response. It *raises* capability on
    purpose, so proposing it against an incident is proposing to undo a containment
    that does not exist. It reaches the host only as a rollback (executor, lease
    sweep) or as a staged recovery step (``recovery/safe_state.py``). Measured defect
    this closes: with restorations in the field, the class-proportional security
    prior scored ``RESUME_PROCESS`` equal to ``SUSPEND_PROCESS`` and ``RELEASE_LOCAL_
    SOCKET`` equal to ``RESTRICT_LOCAL_SOCKET``, the restorations carried the lower
    shadow, and AEGIS chose a restoration as "containment" on every hostile case of
    the benchmark corpus while the baselines filtered them out — so the comparison
    measured an enumeration accident rather than the planner.
    """
    allowed: list[OperatorSpec] = []
    refused: list[FieldTruncation] = []
    interventions_permitted = identifiability in ACTIONABLE_IDENTIFIABILITY
    for operator_id in sorted(CATALOG):
        spec = CATALOG[operator_id]
        if operator_id in RESTORATION_OPERATOR_IDS:
            refused.append(
                FieldTruncation(
                    what="operator",
                    identifier=operator_id,
                    reason=(
                        "a restoration operator is reachable only as a rollback or a recovery "
                        "step, never as an incident response"
                    ),
                )
            )
            continue
        if spec.operator_class in OBSERVE_CLASSES or interventions_permitted:
            allowed.append(spec)
            continue
        refused.append(
            FieldTruncation(
                what="operator",
                identifier=operator_id,
                reason=(
                    f"identifiability {identifiability} is not in ACTIONABLE_IDENTIFIABILITY, so "
                    "only O0/O1 may be proposed; UNKNOWN is not permission (§2)"
                ),
            )
        )
    return tuple(allowed), refused


def _bound_field(
    candidates: Sequence[CandidateAction],
) -> tuple[tuple[CandidateAction, ...], list[FieldTruncation]]:
    """Enforce MAX_CANDIDATES deterministically, dropping the least safe first. The
    sort key puts the lowest operator class, shadow and operational cost first, so
    observe-only candidates survive the bound — which is what keeps NO ACTION
    available exactly when the field is most crowded.
    """
    if len(candidates) <= MAX_CANDIDATES:
        return tuple(candidates), []
    order = sorted(
        candidates,
        key=lambda c: (
            int(c.operator.spec.operator_class),
            c.shadow.score,
            c.expected_operational_delta,
            c.candidate_id,
        ),
    )
    return tuple(order[:MAX_CANDIDATES]), [
        FieldTruncation(
            what="candidate",
            identifier=candidate.candidate_id,
            reason=f"field bounded at MAX_CANDIDATES={MAX_CANDIDATES}; least safe dropped first",
        )
        for candidate in order[MAX_CANDIDATES:]
    ]


def _pre_refusal(
    spec: OperatorSpec,
    tag: str,
    *,
    worlds: frozenset[str],
    constitution: ResponseConstitution,
) -> FieldTruncation | None:
    """Why this operator may not even be *proposed*, or ``None`` if it may.

    Checked before the candidate is built, so a refused operator never costs a twin
    projection: the two cheapest refusals in the system should also be the first.
    """
    verdict = constitution.permits(
        operator_class=spec.operator_class,
        authority=spec.authority,
        reversibility=spec.reversibility,
        has_rollback=spec.rollback_operator_id is not None,
        autonomous=True,
    )
    if verdict.decision is ConstitutionDecision.REFUSED:
        return FieldTruncation("candidate", tag, f"constitution refused: {verdict.detail}")
    if spec.operator_class not in OBSERVE_CLASSES and not worlds:
        return FieldTruncation(
            "candidate",
            tag,
            "no surviving world can be cited with reconstructible evidence, so an intervention "
            "has nothing to justify it",
        )
    return None


def _generate(
    *,
    specs: Sequence[OperatorSpec],
    targets: Sequence[_NamedTarget],
    resolution: CBFResolutionV1,
    snapshot: HostSnapshot,
    worlds: frozenset[str],
    world_id: str,
    constitution: ResponseConstitution,
    invariants: MissionInvariantSet,
    governor: ResourceGovernor,
    memory: EffectivenessMemory,
    twin: ResponseTwin,
) -> tuple[list[CandidateAction], list[FieldTruncation]]:
    """The cross product itself. Every skip emits a reason; nothing is silent."""
    candidates: list[CandidateAction] = []
    drops: list[FieldTruncation] = []
    index = 0
    for target in targets:
        for spec in specs:
            if spec.target_kind is not target.scope.kind:
                continue
            tag = f"{spec.operator_id}@{target.scope.subject}"
            refusal = _pre_refusal(spec, tag, worlds=worlds, constitution=constitution)
            if refusal is not None:
                drops.append(refusal)
                continue
            try:
                governor.spend(WorkKind.CANDIDATE_GENERATION)
                candidate = _candidate(
                    index=index,
                    spec=spec,
                    target=target,
                    resolution=resolution,
                    snapshot=snapshot,
                    worlds=worlds,
                    memory=memory,
                    twin=twin,
                    world_id=world_id,
                )
            except BudgetExhausted as exc:
                drops.append(FieldTruncation("candidate-generation", tag, f"budget: {exc}"))
                return candidates, drops
            except ContractError as exc:
                drops.append(FieldTruncation("candidate", tag, f"refused at construction: {exc}"))
                continue
            violations = invariants.violations(
                operator=candidate.operator,
                lease_ttl_seconds=candidate.lease_ttl_seconds,
                snapshot=snapshot,
            )
            if violations:
                drops.append(
                    FieldTruncation(
                        "candidate",
                        tag,
                        "mission invariant(s) "
                        f"{[row.invariant_id for row in violations]} would be violated",
                    )
                )
                continue
            candidates.append(candidate)
            index += 1
    return candidates, drops


def _fallback(
    *,
    targets: Sequence[_NamedTarget],
    resolution: CBFResolutionV1,
    snapshot: HostSnapshot,
    worlds: frozenset[str],
    world_id: str,
    memory: EffectivenessMemory,
    twin: ResponseTwin,
) -> tuple[CandidateAction | None, FieldTruncation]:
    """The NO ACTION option: observe the named process, or say why even that failed."""
    spec = CATALOG[NO_ACTION_OPERATOR_ID]
    for target in targets:
        if target.scope.kind is not spec.target_kind:
            continue
        try:
            candidate = _candidate(
                index=99,
                spec=spec,
                target=target,
                resolution=resolution,
                snapshot=snapshot,
                worlds=worlds,
                memory=memory,
                twin=twin,
                world_id=world_id,
            )
        except (ContractError, BudgetExhausted):
            continue
        return candidate, FieldTruncation(
            what="no-action-fallback",
            identifier=resolution.resolution_id,
            reason=(
                f"no intervention survived, so the field carries {NO_ACTION_OPERATOR_ID} and the "
                "planner returns NO_ACTION rather than raising (§2)"
            ),
        )
    return None, FieldTruncation(
        what="no-action-fallback",
        identifier=resolution.resolution_id,
        reason=(
            "no intervention survived and the resolution names no observable process target, so "
            "the field is empty; fabricating a target to observe would be a wrong action rather "
            "than no action"
        ),
    )


def _prepare(
    resolution: CBFResolutionV1, snapshot: HostSnapshot, *, cells: ResponseCellField
) -> tuple[
    tuple[OperatorSpec, ...],
    tuple[_NamedTarget, ...],
    frozenset[str],
    str,
    list[FieldTruncation],
]:
    """Everything the cross product needs, plus the reasons it will be smaller than it could be."""
    lineage, truncations = _lineage_index(resolution)
    targets, target_drops = _named_targets(resolution, snapshot, lineage)
    truncations.extend(target_drops)
    identifiability, note = _identifiability(resolution)
    if note is not None:
        truncations.append(note)
    worlds, world_drops = _applicable_worlds(resolution, lineage)
    truncations.extend(world_drops)
    specs, refused_specs = _eligible_specs(identifiability)
    truncations.extend(refused_specs)
    truncations.append(
        FieldTruncation(
            what="response-cell-lookup",
            identifier=resolution.resolution_id,
            reason=(
                f"cells ({type(cells).__name__}) are keyed by incident_invariant_key(mechanism_id, "
                "state_delta_mask, target_kind), and a CBFResolutionV1 carries no StateDelta "
                "bitmask, so no lookup key can be derived here without guessing one (§4.9 Rule "
                "A); no cell was consulted and none was assumed. Gap-selected observation "
                f"operators: {list(_gap_operator_ids(resolution))}"
            ),
        )
    )
    return specs, targets, worlds, _leading_world(resolution), truncations


def generate_action_field(
    resolution: CBFResolutionV1,
    snapshot: HostSnapshot,
    *,
    constitution: ResponseConstitution,
    invariants: MissionInvariantSet,
    governor: ResourceGovernor,
    memory: EffectivenessMemory,
    cells: ResponseCellField,
    twin: ResponseTwin,
) -> ActionField:
    """The constrained cross product of §3: never a search, never out of options.

    Returns every candidate that survives the constitution, the mission invariants
    and the governor, plus one :class:`FieldTruncation` per refusal. When no
    intervention survives, the field still carries :data:`NO_ACTION_OPERATOR_ID`.
    """
    specs, targets, worlds, world_id, truncations = _prepare(resolution, snapshot, cells=cells)
    generated, generated_drops = _generate(
        specs=specs,
        targets=targets,
        resolution=resolution,
        snapshot=snapshot,
        worlds=worlds,
        world_id=world_id,
        constitution=constitution,
        invariants=invariants,
        governor=governor,
        memory=memory,
        twin=twin,
    )
    truncations.extend(generated_drops)
    kept, pruned = governor.prune(generated)
    truncations.extend(
        FieldTruncation(what=row.what, identifier=row.identifier, reason=row.reason)
        for row in pruned
    )
    bounded, over_bound = _bound_field(kept)
    truncations.extend(over_bound)
    if not any(
        candidate.operator.spec.operator_id == NO_ACTION_OPERATOR_ID for candidate in bounded
    ):
        fallback, fallback_note = _fallback(
            targets=targets,
            resolution=resolution,
            snapshot=snapshot,
            worlds=worlds,
            world_id=world_id,
            memory=memory,
            twin=twin,
        )
        truncations.append(fallback_note)
        if fallback is not None:
            bounded = (*bounded[: MAX_CANDIDATES - 1], fallback)
    return ActionField(
        incident_id=resolution.incident_id,
        resolution_id=resolution.resolution_id,
        candidates=bounded,
        truncations=tuple(truncations),
    )
