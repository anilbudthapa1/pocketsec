"""D3.5 — ``KnowledgeCellV1``: the versioned unit of crystallised security knowledge.

``K_i = (I, B, Omega, Gamma, E, Q, X, A, V)`` from architecture §12, as a schema
that can only hold a cell that could be melted back. The refusals in
``__post_init__`` are the deliverable:

* **empty evidence lineage** — an unattributable cell has nothing to melt back
  to and cannot be audited to bytes;
* **empty constraints** — a cell with no hard constraint ``Q`` has nothing that
  could fail it, which is indistinguishable from an unconditional rule;
* **empty epochs** and an **empty boundary** — a cell valid nowhere would
  abstain on every frame, so accepting one hides a synthesis bug;
* **an oversized operator** — ``max_steps`` above ``MAX_CELL_STEPS`` is outside
  what the verifier can bound by construction;
* **an authority-named field** — audited over ``__dataclass_fields__`` the way
  ``EvidenceBoundPrediction`` audits its own, because a cell that could carry
  ``remediation`` would be a model output with response authority (ADR-0003).

``AssuranceLevel.A5`` exists but this schema does not grant it. Promotion
(``promotion/assurance.py``) may assign A5 only for a property that is actually
*proven*, and a cell whose safety rests on "no test broke it" is at A4 at best.
That distinction is the whole of acceptance criterion G3.12.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from pocketsec.stage0.contracts.common import (
    ContractError,
    EvidenceRef,
    register_schema,
    require_finite_unit_interval,
    require_identifier,
    require_non_negative_int,
)
from pocketsec.stage0.contracts.threat_prediction_v1 import FORBIDDEN_AUTHORITY_FIELDS
from pocketsec.stage3.boundary.index import CellBoundary
from pocketsec.stage3.cells.invariant import Invariant
from pocketsec.stage3.cells.operator import MAX_CELL_STEPS, OperatorProgram
from pocketsec.stage3.theory import ResolutionState

__all__ = [
    "AssuranceLevel",
    "AuditPolicy",
    "CellPhase",
    "ConstraintKind",
    "HardConstraint",
    "KNOWLEDGE_CELL_V1_ID",
    "KNOWLEDGE_CELL_V1_VERSION",
    "KnowledgeCellV1",
    "MAX_CONSTRAINTS_PER_CELL",
    "authority_named_fields",
]

KNOWLEDGE_CELL_V1_ID = "pocketsec.knowledge_cell.v1"
KNOWLEDGE_CELL_V1_VERSION = register_schema(KNOWLEDGE_CELL_V1_ID, "1.0.0")

#: Bound on ``Q``. Every constraint is checked per execution, so an unbounded
#: list would be an unbounded loop on the cheap path.
MAX_CONSTRAINTS_PER_CELL = 16


class AssuranceLevel(StrEnum):
    """How much is actually known about a cell (architecture §25).

    A5 means "formally verified property set, **if actually proven**". It is
    reachable only with a named prover module; nothing in this schema can award
    it, and G3.12 asserts that every A5 cell names one.
    """

    A0 = "A0"
    A1 = "A1"
    A2 = "A2"
    A3 = "A3"
    A4 = "A4"
    A5 = "A5"


class CellPhase(StrEnum):
    """Where a cell sits in the crystallisation lifecycle (architecture §3).

    ``MELTED`` is a terminal state that is *kept*, not deleted: rollback and
    reconstruction paths are first-class requirements, and a melted cell is the
    record of what was believed and why it stopped being true.
    """

    FLUID = "FLUID"
    STRUCTURED = "STRUCTURED"
    CRYSTALLIZED = "CRYSTALLIZED"
    STRESSED = "STRESSED"
    MELTED = "MELTED"


class ConstraintKind(StrEnum):
    """``Q_i`` — the hard security constraints a cell may never violate (§19).

    These are not thresholds and they do not trade off against cost. A cell that
    violates one is refused, whatever its measured savings.
    """

    NEVER_SUPPRESS_MANDATORY_EVIDENCE = "NEVER_SUPPRESS_MANDATORY_EVIDENCE"
    NEVER_DOWNGRADE_CONSEQUENCE = "NEVER_DOWNGRADE_CONSEQUENCE"
    NEVER_LOWER_PHI = "NEVER_LOWER_PHI"
    NEVER_NORMALISE_HIGH_CONSEQUENCE = "NEVER_NORMALISE_HIGH_CONSEQUENCE"
    STATE_MONOTONE = "STATE_MONOTONE"


@dataclass(frozen=True, slots=True)
class HardConstraint:
    """One named constraint, with the sentence that says what it forbids."""

    constraint_id: str
    kind: ConstraintKind
    detail: str

    def __post_init__(self) -> None:
        require_identifier(self.constraint_id, "HardConstraint.constraint_id")
        if not isinstance(self.kind, ConstraintKind):
            raise ContractError(
                f"HardConstraint.kind must be a ConstraintKind, got {self.kind!r}"
            )
        if not isinstance(self.detail, str) or not self.detail.strip():
            raise ContractError(
                "HardConstraint.detail must state what the constraint forbids; an "
                "unexplained constraint cannot be reviewed"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "constraint_id": self.constraint_id,
            "kind": self.kind.value,
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> HardConstraint:
        try:
            return cls(
                constraint_id=str(payload["constraint_id"]),
                kind=ConstraintKind(str(payload["kind"])),
                detail=str(payload["detail"]),
            )
        except KeyError as exc:
            raise ContractError(f"HardConstraint missing field {exc.args[0]!r}") from exc
        except ValueError as exc:
            raise ContractError(f"HardConstraint could not be rebuilt: {exc}") from exc


@dataclass(frozen=True, slots=True)
class AuditPolicy:
    """``A`` — how often a promoted cell is re-checked against the oracles (§27).

    ``jitter_salt`` exists for the anti-gaming requirement (§40): the audit
    schedule must not be a counter an adversary can observe and step around.

    What it does and does not buy, stated precisely because it was overstated
    here for a while (and, worse, was not read by anything at all):
    unpredictability comes from ``AuditSampler``'s per-boot salt, which is
    secret. ``jitter_salt`` is mixed into the same keyed hash, which decorrelates
    two cells' schedules and makes *rotation* possible — re-salting a cell after a
    suspected compromise changes every one of its draws, which is the documented
    mitigation and was previously a no-op. It carries no secret of its own: the
    values this repository produces are derived from a region key, which an
    adversary can compute from the traffic it generates. A salt derived from
    public data adds no secrecy; it adds separation and rotation.

    ``min_rate`` is a floor, never zero in practice: a promoted cell that is
    never audited is an unverified cell with authority.
    """

    base_rate: float
    min_rate: float
    max_rate: float
    jitter_salt: str

    def __post_init__(self) -> None:
        require_finite_unit_interval(self.base_rate, "AuditPolicy.base_rate")
        require_finite_unit_interval(self.min_rate, "AuditPolicy.min_rate")
        require_finite_unit_interval(self.max_rate, "AuditPolicy.max_rate")
        if not self.min_rate <= self.base_rate <= self.max_rate:
            raise ContractError(
                f"AuditPolicy requires min_rate <= base_rate <= max_rate, got "
                f"{self.min_rate} / {self.base_rate} / {self.max_rate}"
            )
        if not isinstance(self.jitter_salt, str) or not self.jitter_salt.strip():
            raise ContractError(
                "AuditPolicy.jitter_salt must be a non-empty string: it is mixed into "
                "AuditSampler's keyed draw, so an empty one would leave two cells sharing "
                "a schedule and would make re-salting a compromised cell impossible"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "base_rate": self.base_rate,
            "min_rate": self.min_rate,
            "max_rate": self.max_rate,
            "jitter_salt": self.jitter_salt,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> AuditPolicy:
        try:
            return cls(
                base_rate=float(payload["base_rate"]),
                min_rate=float(payload["min_rate"]),
                max_rate=float(payload["max_rate"]),
                jitter_salt=str(payload["jitter_salt"]),
            )
        except KeyError as exc:
            raise ContractError(f"AuditPolicy missing field {exc.args[0]!r}") from exc


def authority_named_fields(cls: type) -> tuple[str, ...]:
    """Return every declared field whose name would smuggle response authority.

    Substring-matched on the lowered field name, so ``recommended_action`` is
    caught as well as ``action``. Mirrors ``forbidden_authority_keys`` but over a
    *type*: the cell's payload is structured, so the risk is a field, not a key.
    """
    return tuple(
        field_name
        for field_name in getattr(cls, "__dataclass_fields__", {})
        if any(token in field_name.lower() for token in FORBIDDEN_AUTHORITY_FIELDS)
    )


@dataclass(frozen=True, slots=True)
class KnowledgeCellV1:
    """One unit of crystallised, bounded, reversible security knowledge."""

    cell_id: str
    invariant: Invariant
    boundary: CellBoundary
    operator: OperatorProgram
    resolution: ResolutionState
    confidence: float
    assurance: AssuranceLevel
    phase: CellPhase
    evidence_lineage: tuple[EvidenceRef, ...]
    constraints: tuple[HardConstraint, ...]
    epochs: frozenset[int]
    audit_policy: AuditPolicy
    version: int
    parent_cell_id: str | None
    source_candidate_id: str | None
    schema_version: str = KNOWLEDGE_CELL_V1_VERSION

    def __post_init__(self) -> None:
        offenders = authority_named_fields(type(self))
        if offenders:
            raise ContractError(
                f"KnowledgeCellV1 declares response-authority field names {list(offenders)}; "
                "no model output carries response authority (ADR-0003)"
            )
        require_identifier(self.cell_id, "KnowledgeCellV1.cell_id")
        self._require_components()
        require_finite_unit_interval(self.confidence, "KnowledgeCellV1.confidence")
        self._require_evidence()
        self._require_constraints()
        self._require_epochs()
        require_non_negative_int(self.version, "KnowledgeCellV1.version")
        for name in ("parent_cell_id", "source_candidate_id"):
            value = getattr(self, name)
            if value is not None:
                require_identifier(value, f"KnowledgeCellV1.{name}")
        if self.schema_version != KNOWLEDGE_CELL_V1_VERSION:
            raise ContractError(
                f"KnowledgeCellV1.schema_version must be {KNOWLEDGE_CELL_V1_VERSION!r}, "
                f"got {self.schema_version!r}; a breaking change takes a new schema id"
            )

    def _require_components(self) -> None:
        if not isinstance(self.invariant, Invariant):
            raise ContractError("KnowledgeCellV1.invariant must be an Invariant")
        if not isinstance(self.boundary, CellBoundary):
            raise ContractError("KnowledgeCellV1.boundary must be a CellBoundary")
        if self.boundary.is_empty:
            raise ContractError(
                "KnowledgeCellV1.boundary is empty; an empty boundary contains nothing, "
                "so the cell would abstain on every frame and hide a synthesis failure"
            )
        if not isinstance(self.operator, OperatorProgram):
            raise ContractError("KnowledgeCellV1.operator must be an OperatorProgram")
        if self.operator.max_steps > MAX_CELL_STEPS:
            raise ContractError(
                f"KnowledgeCellV1.operator.max_steps {self.operator.max_steps} is above "
                f"MAX_CELL_STEPS={MAX_CELL_STEPS}; termination is bounded by instruction "
                "count, and an operator above the cap is outside what the verifier bounds"
            )
        if not isinstance(self.resolution, ResolutionState):
            raise ContractError("KnowledgeCellV1.resolution must be a ResolutionState")
        if not isinstance(self.assurance, AssuranceLevel):
            raise ContractError("KnowledgeCellV1.assurance must be an AssuranceLevel")
        if not isinstance(self.phase, CellPhase):
            raise ContractError("KnowledgeCellV1.phase must be a CellPhase")

    def _require_evidence(self) -> None:
        if not isinstance(self.evidence_lineage, tuple) or not self.evidence_lineage:
            raise ContractError(
                "KnowledgeCellV1.evidence_lineage must be a non-empty tuple: a cell with "
                "no lineage cannot be melted back to the bytes that justified it"
            )
        for ref in self.evidence_lineage:
            if not isinstance(ref, EvidenceRef):
                raise ContractError(
                    f"KnowledgeCellV1.evidence_lineage entries must be EvidenceRef, "
                    f"got {type(ref).__name__}"
                )

    def _require_constraints(self) -> None:
        if not isinstance(self.constraints, tuple) or not self.constraints:
            raise ContractError(
                "KnowledgeCellV1.constraints must be non-empty: a cell with no hard "
                "constraint has nothing that could fail it, which is not the same as safe"
            )
        if len(self.constraints) > MAX_CONSTRAINTS_PER_CELL:
            raise ContractError(
                f"KnowledgeCellV1.constraints holds {len(self.constraints)} entries, above "
                f"MAX_CONSTRAINTS_PER_CELL={MAX_CONSTRAINTS_PER_CELL}"
            )
        for constraint in self.constraints:
            if not isinstance(constraint, HardConstraint):
                raise ContractError(
                    f"KnowledgeCellV1.constraints entries must be HardConstraint, "
                    f"got {type(constraint).__name__}"
                )
        if not isinstance(self.audit_policy, AuditPolicy):
            raise ContractError("KnowledgeCellV1.audit_policy must be an AuditPolicy")

    def _require_epochs(self) -> None:
        if not isinstance(self.epochs, frozenset) or not self.epochs:
            raise ContractError(
                "KnowledgeCellV1.epochs must be a non-empty frozenset: a cell valid in no "
                "epoch is valid nowhere"
            )
        for epoch in self.epochs:
            require_non_negative_int(epoch, "KnowledgeCellV1.epochs entry")
        outside = self.epochs - self.boundary.epochs
        if outside:
            raise ContractError(
                f"KnowledgeCellV1 claims epochs {sorted(outside)} its boundary does not "
                "cover; the cell would answer in an epoch it was never validated for"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "cell_id": self.cell_id,
            "invariant": self.invariant.to_dict(),
            "boundary": self.boundary.to_dict(),
            "operator": self.operator.to_dict(),
            "resolution": self.resolution.to_dict(),
            "confidence": self.confidence,
            "assurance": self.assurance.value,
            "phase": self.phase.value,
            "evidence_lineage": [ref.to_dict() for ref in self.evidence_lineage],
            "constraints": [constraint.to_dict() for constraint in self.constraints],
            "epochs": sorted(self.epochs),
            "audit_policy": self.audit_policy.to_dict(),
            "version": self.version,
            "parent_cell_id": self.parent_cell_id,
            "source_candidate_id": self.source_candidate_id,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> KnowledgeCellV1:
        try:
            parent = payload["parent_cell_id"]
            source = payload["source_candidate_id"]
            return cls(
                cell_id=str(payload["cell_id"]),
                invariant=Invariant.from_dict(payload["invariant"]),
                boundary=CellBoundary.from_dict(payload["boundary"]),
                operator=OperatorProgram.from_dict(payload["operator"]),
                resolution=ResolutionState.from_dict(payload["resolution"]),
                confidence=float(payload["confidence"]),
                assurance=AssuranceLevel(str(payload["assurance"])),
                phase=CellPhase(str(payload["phase"])),
                evidence_lineage=tuple(
                    EvidenceRef.from_dict(ref) for ref in payload["evidence_lineage"]
                ),
                constraints=tuple(
                    HardConstraint.from_dict(item) for item in payload["constraints"]
                ),
                epochs=frozenset(int(e) for e in payload["epochs"]),
                audit_policy=AuditPolicy.from_dict(payload["audit_policy"]),
                version=int(payload["version"]),
                parent_cell_id=None if parent is None else str(parent),
                source_candidate_id=None if source is None else str(source),
                schema_version=str(payload.get("schema_version", KNOWLEDGE_CELL_V1_VERSION)),
            )
        except KeyError as exc:
            raise ContractError(f"KnowledgeCellV1 missing field {exc.args[0]!r}") from exc
        except ValueError as exc:
            raise ContractError(f"KnowledgeCellV1 could not be rebuilt: {exc}") from exc

    def size_bytes(self) -> int:
        """Resident size of the whole cell in canonical serialised form.

        This is the number G3.9 compares against the Φ-oracle's bytes. It counts
        the metadata — boundary, lineage, constraints, audit policy — because
        that metadata is exactly what the cell format charges for over running
        the rule directly, and hiding it would make the comparison flattering
        rather than honest.
        """
        payload = json.dumps(
            self.to_dict(), sort_keys=True, allow_nan=False, separators=(",", ":")
        )
        return len(payload.encode("utf-8"))
