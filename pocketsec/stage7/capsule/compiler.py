"""D7.2 (compiler) / ORPH-F03 — turn local knowledge into an UNSIGNED knowledge capsule.

The compiler is the only producer of outbound ``KnowledgeCapsuleV1`` values, so it is
where "nothing host-identifying leaves the host" is made true rather than hoped for. It
runs four steps in an order that matters:

1. **Distil.** Host facts become coarse context (:func:`distil_context`), the host
   secret becomes a scoped pseudonym, and every evidence digest becomes a keyed
   commitment. Raw ``sha256:`` digests never reach the capsule; the receiver learns
   *that* evidence exists, never which bytes it was.
2. **Charge.** :meth:`PrivacyLedger.charge` runs BEFORE the capsule is sealed. An
   exhausted budget raises :class:`PrivacyBudgetExhausted` and nothing is produced. A
   capsule that later fails sealing or screening has still been charged: the ledger
   over-counts a failed release and never under-counts a real one.
3. **Seal** with ``signature=""``. Signing is ``Keyring.sign`` (identity/), a separate
   step, so this module never holds a signing key.
4. **Screen.** :func:`residual_identifier_hits` runs on the sealed payload and any hit
   raises. The schema already refuses strings outside ``WIRE_STRING_SHAPES``; the
   compiler checks again because a privacy property enforced in exactly one place is
   one refactor away from not being enforced.

:func:`invariants_from_learning_record` is the Stage 6 → 7 handoff. It exports
DETECTOR rows only (a foreign peer may suggest what to fear, never what to trust:
baseline/normality rows are never exported, ADR-0063), only ACTIVE ones, and only rows
explicitly ``simulated: false`` (a simulated detection is not shared as knowledge,
ADR-0046 precedent). A record whose top-level ``simulated`` flag is set exports nothing.

What this module refuses to do: sign, send, choose recipients, claim DP for a capsule,
truncate evidence silently, or read anything from Stage 6 but ``LearningRecordV1``.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from pocketsec.stage0.contracts.common import (
    ContractError,
    require_finite_unit_interval,
    require_identifier,
    require_non_negative_int,
)
from pocketsec.stage1.epoch.model import SystemIdentity
from pocketsec.stage6.capsule.experience_capsule import PrivacyClass
from pocketsec.stage6.export.learning_record import LearningRecordV1
from pocketsec.stage6.memory.semantic import MAX_MOTIF_LENGTH, MotifStep
from pocketsec.stage7.capsule.knowledge_capsule import (
    MAX_EVIDENCE_COMMITMENTS,
    MAX_EXPIRY_HORIZON_ROUNDS,
    FalsificationSummary,
    KnowledgeCapsuleV1,
    KnowledgeType,
    MotifRow,
    ObservabilityClaim,
    ProvenanceCommitment,
    RevocationGround,
    RoleClass,
    Stance,
    ValidationSummary,
    seal_capsule,
)
from pocketsec.stage7.privacy.distiller import (
    MIN_HOST_SECRET_BYTES,
    contributor_pseudonym,
    distil_context,
    evidence_commitment,
    residual_identifier_hits,
)
from pocketsec.stage7.privacy.ledger import PrivacyLedger

__all__ = [
    "ExportContext",
    "compile_capsule",
    "invariants_from_learning_record",
]

_ROOT_PREFIX, _KEY_PREFIX = "root-", "key-"
_HEX = frozenset("0123456789abcdef")


def _require_prefixed_hex(value: object, prefix: str, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith(prefix)
        or len(value) != len(prefix) + 16
        or not set(value[len(prefix):]) <= _HEX
    ):
        raise ContractError(f"{field} must be {prefix!r} + 16 lowercase hex, got {value!r}")
    return value


@dataclass(frozen=True, slots=True)
class ExportContext:
    """What this host knows about itself for export. Nothing here is exported verbatim."""

    host_secret: bytes
    identity: SystemIdentity
    role: RoleClass
    provenance_root: str
    key_id: str
    visibility_share: float
    family_counts: Mapping[int, int]
    fleet_scope: str

    def __post_init__(self) -> None:
        if not isinstance(self.host_secret, bytes) or len(self.host_secret) < MIN_HOST_SECRET_BYTES:
            raise ContractError(f"host_secret must be >= {MIN_HOST_SECRET_BYTES} bytes")
        if not isinstance(self.identity, SystemIdentity):
            raise ContractError("ExportContext.identity must be a SystemIdentity")
        if not isinstance(self.role, RoleClass):
            raise ContractError(f"ExportContext.role must be a RoleClass, got {self.role!r}")
        _require_prefixed_hex(self.provenance_root, _ROOT_PREFIX, "provenance_root")
        _require_prefixed_hex(self.key_id, _KEY_PREFIX, "key_id")
        require_finite_unit_interval(self.visibility_share, "visibility_share")
        require_identifier(self.fleet_scope, "fleet_scope")
        if not isinstance(self.family_counts, Mapping):
            raise ContractError("ExportContext.family_counts must be a mapping")
        # A private copy: an immutable record must not alias the caller's dict.
        object.__setattr__(self, "family_counts", MappingProxyType(dict(self.family_counts)))

    def __repr__(self) -> str:
        # The secret never appears in a repr, a log line or an exception message.
        return (f"ExportContext(role={self.role.value}, provenance_root={self.provenance_root}, "
                f"key_id={self.key_id}, fleet_scope={self.fleet_scope})")


def _commitments(host_secret: bytes, digests: Sequence[str]) -> tuple[str, ...]:
    if isinstance(digests, (str, bytes)) or not isinstance(digests, Sequence):
        raise ContractError("evidence_digests must be a sequence of sha256 digests")
    unique = tuple(dict.fromkeys(digests))
    if not unique:
        raise ContractError("knowledge without evidence has no provenance and is refused")
    if len(unique) > MAX_EVIDENCE_COMMITMENTS:
        # Refused, not cut: which evidence to commit to is the caller's decision, and a
        # silent cut would make the provenance claim smaller than the caller believes.
        raise ContractError(
            f"{len(unique)} distinct evidence digests > MAX_EVIDENCE_COMMITMENTS="
            f"{MAX_EVIDENCE_COMMITMENTS}; select them before compiling"
        )
    return tuple(evidence_commitment(host_secret, digest) for digest in unique)


def _rows(invariant: Sequence[MotifRow], knowledge_type: KnowledgeType) -> tuple[MotifRow, ...]:
    rows = tuple(invariant)
    if any(not isinstance(row, MotifRow) for row in rows):
        raise ContractError("an invariant is a sequence of MotifRow")
    if knowledge_type is KnowledgeType.REVOCATION:
        if rows:
            raise ContractError("a REVOCATION carries no invariant")
        return rows
    if not 1 <= len(rows) <= MAX_MOTIF_LENGTH:
        raise ContractError(f"an invariant has 1..{MAX_MOTIF_LENGTH} rows, got {len(rows)}")
    return rows


def _check_inputs(knowledge_type: object, context: object, ledger: object,
                  created_round: object, sequence: object) -> None:
    if not isinstance(knowledge_type, KnowledgeType):
        raise ContractError(f"unknown knowledge type {knowledge_type!r}")
    if not isinstance(context, ExportContext):
        raise ContractError("compile_capsule needs an ExportContext")
    if not isinstance(ledger, PrivacyLedger):
        raise ContractError("compile_capsule needs a PrivacyLedger: no uncharged export")
    require_non_negative_int(created_round, "created_round")
    require_non_negative_int(sequence, "sequence")


def compile_capsule(
    *,
    knowledge_type: KnowledgeType,
    invariant: Sequence[MotifRow],
    evidence_digests: Sequence[str],
    validation: ValidationSummary,
    falsification: FalsificationSummary,
    context: ExportContext,
    ledger: PrivacyLedger,
    created_round: int,
    sequence: int,
    stance: Stance = Stance.SUPPORT,
    parents: Sequence[str] = (),
    aggregation_decision: str | None = None,
    time_window: tuple[int, int] | None = None,
    observability: ObservabilityClaim | None = None,
    revocation_target: str | None = None,
    revocation_ground: RevocationGround | None = None,
) -> KnowledgeCapsuleV1:
    """Distil → charge → seal (unsigned) → screen. Raises rather than export a residual."""
    _check_inputs(knowledge_type, context, ledger, created_round, sequence)
    rows = _rows(invariant, knowledge_type)
    commitments = _commitments(context.host_secret, evidence_digests)
    epoch_context, sketch = distil_context(
        identity=context.identity, role=context.role,
        visibility_share=context.visibility_share, family_counts=context.family_counts,
    )
    provenance = ProvenanceCommitment(
        contributor=contributor_pseudonym(context.host_secret, context.fleet_scope),
        provenance_root=context.provenance_root,
        evidence_commitments=commitments,
        aggregation_decision=aggregation_decision,
    )
    # Charged before sealing: an exhausted budget raises here and nothing is produced.
    ledger.charge(knowledge_type.value, recipient_scope=context.fleet_scope,
                  round_index=created_round, epsilon=None)
    capsule = seal_capsule(**_draft(
        knowledge_type=knowledge_type, stance=stance, rows=rows, epoch_context=epoch_context,
        sketch=sketch, validation=validation, falsification=falsification,
        provenance=provenance, context=context, created_round=created_round,
        sequence=sequence, parents=parents, time_window=time_window,
        observability=observability, revocation_target=revocation_target,
        revocation_ground=revocation_ground,
    ))
    hits = residual_identifier_hits(capsule.to_dict())
    if hits:
        raise ContractError(f"refusing to export a capsule with residual identifiers: {hits}")
    return capsule


def _draft(
    *, knowledge_type: KnowledgeType, stance: Stance, rows: tuple[MotifRow, ...],
    epoch_context: Any, sketch: Any, validation: ValidationSummary,
    falsification: FalsificationSummary, provenance: ProvenanceCommitment,
    context: ExportContext, created_round: int, sequence: int, parents: Sequence[str],
    time_window: tuple[int, int] | None, observability: ObservabilityClaim | None,
    revocation_target: str | None, revocation_ground: RevocationGround | None,
) -> dict[str, Any]:
    """The fields ``seal_capsule`` does not derive. Every value is already distilled."""
    return {
        "knowledge_type": knowledge_type,
        "stance": stance,
        "semantic_invariant": rows,
        "attack_mappings": (),
        "epoch_context": epoch_context,
        "source_context_sketch": sketch,
        "validation_summary": validation,
        "falsification_summary": falsification,
        "provenance_commitment": provenance,
        "independence_group": context.provenance_root,
        "privacy_class": PrivacyClass.PUBLIC_DERIVED,
        "created_round": created_round,
        "expiry_round": created_round + MAX_EXPIRY_HORIZON_ROUNDS,
        "sequence": sequence,
        "parent_capsules": tuple(parents),
        "time_window": time_window,
        "observability": observability,
        "revocation_target": revocation_target,
        "revocation_ground": revocation_ground,
        "key_id": context.key_id,
    }


def _row_invariant(motif: object, *, index: int) -> tuple[MotifRow, ...]:
    if not isinstance(motif, (list, tuple)) or not 1 <= len(motif) <= MAX_MOTIF_LENGTH:
        raise ContractError(f"items[{index}].motif must hold 1..{MAX_MOTIF_LENGTH} rows")
    rows: list[MotifRow] = []
    for step in motif:
        if not isinstance(step, (list, tuple)) or len(step) != 4:
            raise ContractError(f"items[{index}].motif rows are four ints")
        # MotifStep validates (non-negative ints, require & forbid disjoint).
        rows.append(MotifRow.from_motif_step(MotifStep(*step)))
    return tuple(rows)


def invariants_from_learning_record(record: LearningRecordV1) -> tuple[tuple[MotifRow, ...], ...]:
    """DETECTOR rows, status ACTIVE, ``simulated is False`` — distinct, in record order."""
    if not isinstance(record, LearningRecordV1):
        raise ContractError("invariants_from_learning_record needs a LearningRecordV1")
    if record.simulated:
        # The record-level flag is sticky upstream (ADR-0046): every row came from a
        # simulated procedure, whatever an individual row claims.
        return ()
    found: dict[tuple[MotifRow, ...], None] = {}
    for index, item in enumerate(record.items):
        if item.get("kind") != "DETECTOR" or item.get("status") != "ACTIVE":
            continue
        if item.get("simulated") is not False:
            continue  # only an explicit False is real; a missing flag is not
        found.setdefault(_row_invariant(item.get("motif"), index=index), None)
    return tuple(found)
