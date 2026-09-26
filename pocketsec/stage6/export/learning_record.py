"""HEL-F26 — ``LearningRecordV1``: the plain-JSON projection of trusted state Stage 7 reads.

Integration plan §3.2 and architecture §56 hand Stage 7 a view of what this host has
learned. That view is **plain JSON with a canonical digest**, the shape Stage 5 chose for
its own handoff (``stage5/stage6_interface.py``, ADR-0039) and for the same reason: Stage
6's class names are Stage 6's business, and a record of strings and numbers survives a
redesign on either side.

What the record carries, per item: kind, pattern key, motif bitmasks, weight, context ids,
status, the candidate id that admitted it, the **count** of evidence digests behind it,
and a simulated flag. What it deliberately does not carry — ``privacy_class`` is always
``PUBLIC_DERIVED``:

* no capsule ids (they name individual observations on this host),
* no evidence digests themselves (a count proves support without handing out pointers),
* no causal or parent signatures and no source groups (``grp-…`` hashes are per-lineage
  accounting, and a set of them fingerprints the host's process population),
* no baseline anchors (the host's normality is host-sensitive; Stage 7 distils from
  detectors and counts, not from another host's meaning vectors).

What it refuses, all at export time:

* **Stage 5's two screens, reused rather than re-implemented.** ``to_dict`` raises if
  ``seam_violations`` or ``authority_violations`` from ``stage5.stage6_interface`` finds
  anything. A learning record is never a channel for response authority (ADR-0003).
* **Host-identifying strings.** Any string value that looks like a capsule id or a source
  group raises, so a later edit that leaks one fails loudly instead of shipping.
* **Items without complete lineage.** ``export_learning_record`` refuses a state holding
  an item the lineage DAG cannot account for: a learned fact without lineage is not
  trusted knowledge (architecture §16), so it is not exported as such either.
* **A simulated record becoming a real one by omission.** ``simulated`` is required and
  sticky: it is forced ``True`` if any contributing procedure was simulated, and it can
  never be cleared (ADR-0046).

``rollback_rows`` are plain mappings (the controller passes ``LearningRollback`` rows), so
this module never imports ``promotion/``; each row is projected onto exactly four keys.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from pocketsec.stage0.contracts.common import (
    ContractError,
    digest_of_bytes,
    register_schema,
    require_identifier,
)
from pocketsec.stage5.stage6_interface import authority_violations, seam_violations
from pocketsec.stage6.fossils.lineage import KnowledgeLineageDAG
from pocketsec.stage6.fossils.store import FossilStore
from pocketsec.stage6.memory.semantic import KnowledgeItem, TrustedKnowledgeState

__all__ = [
    "LEARNING_RECORD_V1_ID",
    "LEARNING_RECORD_V1_VERSION",
    "PUBLIC_DERIVED",
    "ROLLBACK_ROW_KEYS",
    "LearningRecordV1",
    "export_learning_record",
    "host_identifier_violations",
]

LEARNING_RECORD_V1_ID = "pocketsec.learning_record.v1"
LEARNING_RECORD_V1_VERSION = register_schema(LEARNING_RECORD_V1_ID, "1.0.0")

#: The only privacy class a learning record may carry.
PUBLIC_DERIVED: str = "PUBLIC_DERIVED"
#: The four keys a rollback row is projected onto; anything else in the source row is dropped.
ROLLBACK_ROW_KEYS: tuple[str, ...] = (
    "trigger",
    "from_digest",
    "to_digest",
    "restored_bytes_identical",
)

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
#: Capsule ids (``cap-…``) and source groups (``grp-…``) identify this host's observations.
_HOST_IDENTIFIER_RE = re.compile(r"^(cap|grp)-[0-9a-f]{6,}")
_RECORD_ID_HEX = 32


def host_identifier_violations(payload: object, *, prefix: str = "record") -> tuple[str, ...]:
    """Every path whose string value looks like a capsule id or a source group."""
    found: list[str] = []
    if isinstance(payload, Mapping):
        for key, value in payload.items():
            found.extend(host_identifier_violations(value, prefix=f"{prefix}.{key}"))
    elif isinstance(payload, (list, tuple)):
        for index, value in enumerate(payload):
            found.extend(host_identifier_violations(value, prefix=f"{prefix}[{index}]"))
    elif isinstance(payload, str) and _HOST_IDENTIFIER_RE.match(payload):
        found.append(prefix)
    return tuple(found)


def _plain(value: object, *, field: str) -> Any:
    """Plain JSON or a refusal: a Stage 6 object on the wire would carry a class across."""
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ContractError(f"{field} must be finite, got {value!r}")
        return value
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise ContractError(f"{field} keys must be strings")
        return {key: _plain(item, field=f"{field}.{key}") for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item, field=f"{field}[{index}]") for index, item in enumerate(value)]
    raise ContractError(f"{field} holds {type(value).__name__}, which is not plain JSON")


@dataclass(frozen=True, slots=True)
class LearningRecordV1:
    """The Stage 7 handoff. Plain JSON throughout; ``to_dict`` does the refusing."""

    record_id: str
    trusted_digest: str
    state_version: int
    active_context: str
    items: tuple[Mapping[str, Any], ...]
    fossil_hashes: tuple[str, ...]
    tombstoned_fossils: int
    rollback_rows: tuple[Mapping[str, Any], ...]
    lineage_intact: bool
    privacy_class: str
    simulated: bool
    interface_version: str = LEARNING_RECORD_V1_VERSION

    def __post_init__(self) -> None:
        require_identifier(self.record_id, "LearningRecordV1.record_id")
        for digest in (self.trusted_digest, *self.fossil_hashes):
            if not isinstance(digest, str) or not _DIGEST_RE.fullmatch(digest):
                raise ContractError(f"LearningRecordV1 digests are sha256:<64 hex>, got {digest!r}")
        for name in ("state_version", "tombstoned_fossils"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ContractError(f"LearningRecordV1.{name} must be a non-negative int")
        for name in ("lineage_intact", "simulated"):
            if not isinstance(getattr(self, name), bool):
                raise ContractError(
                    f"LearningRecordV1.{name} must be an explicit bool; an omitted simulated flag "
                    "is how a simulated record becomes a real one (ADR-0046)"
                )
        if self.privacy_class != PUBLIC_DERIVED:
            raise ContractError(
                f"a learning record is always {PUBLIC_DERIVED}, got {self.privacy_class!r}"
            )
        object.__setattr__(self, "items", tuple(_plain(r, field="items") for r in self.items))
        rows = tuple(_plain(r, field="rollback_rows") for r in self.rollback_rows)
        object.__setattr__(self, "rollback_rows", rows)
        object.__setattr__(self, "fossil_hashes", tuple(self.fossil_hashes))

    def _payload(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "trusted_digest": self.trusted_digest,
            "state_version": self.state_version,
            "active_context": self.active_context,
            "items": [dict(row) for row in self.items],
            "fossil_hashes": list(self.fossil_hashes),
            "tombstoned_fossils": self.tombstoned_fossils,
            "rollback_rows": [dict(row) for row in self.rollback_rows],
            "lineage_intact": self.lineage_intact,
            "privacy_class": self.privacy_class,
            "simulated": self.simulated,
            "interface_version": self.interface_version,
        }

    def to_dict(self) -> dict[str, Any]:
        """The wire form, or a refusal: Stage 5's seam and authority screens, then host ids."""
        payload = self._payload()
        seam = seam_violations(payload)
        if seam:
            raise ContractError(f"learning record names a Stage 5 class: {seam}")
        authority = authority_violations(payload)
        if authority:
            raise ContractError(f"learning record carries an authority-named key: {authority}")
        host = host_identifier_violations(payload)
        if host:
            raise ContractError(f"learning record carries a host-identifying value: {host}")
        return payload

    def canonical_bytes(self) -> bytes:
        text = json.dumps(self.to_dict(), sort_keys=True, allow_nan=False, indent=2)
        return text.encode("utf-8") + b"\n"

    def digest(self) -> str:
        return digest_of_bytes(self.canonical_bytes())


def _item_row(item: KnowledgeItem, *, simulated: bool) -> dict[str, Any]:
    procedure_simulated = item.procedure is not None and item.procedure.simulated
    return {
        "kind": item.kind.value,
        "pattern_key": item.pattern_key,
        "motif": [step.to_payload() for step in item.motif],
        "weight": item.weight,
        "context_ids": sorted(item.context_ids),
        "status": item.status.value,
        "candidate_id": item.lineage.candidate_id,
        "evidence_count": len(item.lineage.evidence_digests),
        "simulated": simulated or procedure_simulated,
    }


def _rollback_row(row: Mapping[str, Any], *, index: int) -> dict[str, Any]:
    missing = [key for key in ROLLBACK_ROW_KEYS if key not in row]
    if missing:
        raise ContractError(f"rollback_rows[{index}] lacks {missing}")
    if not isinstance(row["restored_bytes_identical"], bool):
        raise ContractError(f"rollback_rows[{index}].restored_bytes_identical must be a bool")
    return {
        key: _plain(row[key], field=f"rollback_rows[{index}].{key}") for key in ROLLBACK_ROW_KEYS
    }


def export_learning_record(
    state: TrustedKnowledgeState,
    *,
    lineage: KnowledgeLineageDAG,
    fossils: FossilStore,
    rollback_rows: Sequence[Mapping[str, Any]],
    simulated: bool,
) -> LearningRecordV1:
    """HEL-F26. Project ``state`` for Stage 7, refusing any item without complete lineage."""
    if not isinstance(simulated, bool):
        raise ContractError("simulated must be an explicit bool")
    unlineaged = [item.item_id for item in state.items if not lineage.lineage_complete(item)]
    if unlineaged:
        raise ContractError(f"refusing to export items without complete lineage: {unlineaged}")
    sticky = simulated or any(
        item.procedure is not None and item.procedure.simulated for item in state.procedures()
    )
    items = tuple(_item_row(item, simulated=sticky) for item in state.items)
    rows = tuple(_rollback_row(row, index=i) for i, row in enumerate(rollback_rows))
    trusted_digest = state.digest()
    fossil_hashes = tuple(f.artifact_hash for f in fossils.fossils())
    material = json.dumps(
        {
            "state": trusted_digest,
            "fossils": list(fossil_hashes),
            "rollbacks": list(rows),
            "items": list(items),
        },
        sort_keys=True,
    )
    hex_digest = digest_of_bytes(material.encode("utf-8"))[len("sha256:") :]
    record_id = "lrec-" + hex_digest[:_RECORD_ID_HEX]
    return LearningRecordV1(
        record_id=record_id,
        trusted_digest=trusted_digest,
        state_version=state.version,
        active_context=state.active_context,
        items=items,
        fossil_hashes=fossil_hashes,
        tombstoned_fossils=fossils.evictions(),
        rollback_rows=rows,
        lineage_intact=lineage.verify() == (),
        privacy_class=PUBLIC_DERIVED,
        simulated=sticky,
    )
