"""D1.2 — ``RawEventV1`` and ``EvidenceEvent``: the lossless assembly layer.

This is the source-neutral landing zone. auditd emits several records for one
logical ``execve``; an eBPF probe emits one. Both must arrive here, be fused
into one logical operation, and compile to *semantically equivalent* SSIR —
that is acceptance criterion 1 (spec section 29).

Raw evidence stays lossless and separate from the model representation
(principle carried from Stage 0). Compression happens downstream, in SSIR, and
never destroys the investigator's trail.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from pocketsec.stage0.contracts.common import (
    ContractError,
    EvidenceRef,
    digest_of_bytes,
    register_schema,
    require_identifier,
    require_non_negative_int,
)

__all__ = [
    "EvidenceEvent",
    "RAW_EVENT_V1_ID",
    "RAW_EVENT_V1_VERSION",
    "RawEventV1",
    "SensorPath",
]

RAW_EVENT_V1_ID = "pocketsec.raw_event.v1"
RAW_EVENT_V1_VERSION = register_schema(RAW_EVENT_V1_ID, "1.0.0")


class SensorPath(StrEnum):
    """Telemetry sources Stage 1 must reconcile.

    Cross-sensor equivalence is tested by replaying identical controlled actions
    through at least two of these and comparing the resulting SSIR semantics.
    """

    AUDITD = "auditd"
    EBPF = "ebpf"
    PROCFS = "procfs"
    JOURNALD = "journald"
    LSM = "lsm"


@dataclass(frozen=True, slots=True)
class RawEventV1:
    """One raw telemetry record, before fusion and before semantics.

    ``fields`` is intentionally an untyped string map: this layer is lossless
    and source-shaped. Imposing structure here would discard exactly the sensor
    idiosyncrasies that fusion needs in order to reconcile them.
    """

    record_id: str
    host_id: str
    boot_id: str
    sensor: SensorPath
    observed_at_ns: int
    monotonic_ns: int
    record_type: str
    #: Short-lived key grouping records that describe one logical operation.
    #: ``None`` means the sensor emits one record per operation.
    assembly_key: str | None = None
    fields: dict[str, str] = field(default_factory=dict)
    #: True when the sensor reported this record as partial or lossy. Drives
    #: uncertainty upward rather than being silently dropped.
    incomplete: bool = False

    def __post_init__(self) -> None:
        require_identifier(self.record_id, "RawEventV1.record_id")
        require_identifier(self.host_id, "RawEventV1.host_id")
        require_identifier(self.boot_id, "RawEventV1.boot_id")
        require_non_negative_int(self.observed_at_ns, "RawEventV1.observed_at_ns")
        require_non_negative_int(self.monotonic_ns, "RawEventV1.monotonic_ns")
        require_identifier(self.record_type, "RawEventV1.record_type")
        object.__setattr__(self, "sensor", SensorPath(self.sensor))
        if self.assembly_key is not None and not self.assembly_key:
            raise ContractError("RawEventV1.assembly_key must be non-empty or None")
        if not isinstance(self.fields, dict):
            raise ContractError("RawEventV1.fields must be a dict")
        for key, value in self.fields.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise ContractError("RawEventV1.fields must be a str->str mapping")
        object.__setattr__(self, "fields", MappingProxyType(dict(self.fields)))

    @property
    def group_key(self) -> str:
        """The key fusion groups on. Falls back to the record's own id."""
        return self.assembly_key or self.record_id

    def evidence_ref(self) -> EvidenceRef:
        """A lineage-preserving pointer to this exact record.

        The digest covers the canonical field content, so a later stage can
        prove the bytes it reads are the bytes the transition was compiled from.
        """
        canonical = "|".join(
            [
                self.record_id,
                self.host_id,
                self.boot_id,
                self.sensor.value,
                self.record_type,
                str(self.observed_at_ns),
                *(f"{k}={self.fields[k]}" for k in sorted(self.fields)),
            ]
        )
        return EvidenceRef(
            store=f"raw.{self.sensor.value}",
            locator=self.record_id,
            digest=digest_of_bytes(canonical.encode("utf-8")),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": RAW_EVENT_V1_ID,
            "schema_version": RAW_EVENT_V1_VERSION,
            "record_id": self.record_id,
            "host_id": self.host_id,
            "boot_id": self.boot_id,
            "sensor": self.sensor.value,
            "observed_at_ns": self.observed_at_ns,
            "monotonic_ns": self.monotonic_ns,
            "record_type": self.record_type,
            "assembly_key": self.assembly_key,
            "fields": dict(self.fields),
            "incomplete": self.incomplete,
        }


@dataclass(frozen=True, slots=True)
class EvidenceEvent:
    """A fused logical operation: every raw record describing one action.

    This is what the semantic compiler consumes. It keeps all contributing raw
    records so the evidence trail survives compression, and it knows whether the
    fusion was complete — a partially-assembled operation must raise uncertainty
    rather than be interpreted confidently or dropped.
    """

    evidence_id: str
    host_id: str
    boot_id: str
    observed_at_ns: int
    monotonic_ns: int
    records: tuple[RawEventV1, ...]
    #: True when the assembly window expired before every expected record
    #: arrived, or any contributing record was flagged incomplete.
    partial: bool = False

    def __post_init__(self) -> None:
        require_identifier(self.evidence_id, "EvidenceEvent.evidence_id")
        require_identifier(self.host_id, "EvidenceEvent.host_id")
        object.__setattr__(self, "records", tuple(self.records))
        if not self.records:
            raise ContractError("EvidenceEvent must contain at least one raw record")
        for record in self.records:
            if record.host_id != self.host_id:
                raise ContractError("EvidenceEvent records must share a host_id")
        if any(record.incomplete for record in self.records):
            object.__setattr__(self, "partial", True)

    @property
    def sensors(self) -> frozenset[SensorPath]:
        return frozenset(record.sensor for record in self.records)

    @property
    def evidence_refs(self) -> tuple[EvidenceRef, ...]:
        return tuple(record.evidence_ref() for record in self.records)

    def merged_fields(self) -> dict[str, str]:
        """Fields from every contributing record, in arrival order.

        Later records win on conflict, which matches how auditd compound events
        refine an operation across records. Conflicts are surfaced by
        :meth:`conflicting_fields` rather than being silently resolved.
        """
        merged: dict[str, str] = {}
        for record in self.records:
            merged.update(record.fields)
        return merged

    def conflicting_fields(self) -> frozenset[str]:
        """Field names where contributing records disagree.

        Sensor disagreement must increase uncertainty, not produce false
        certainty (hard requirement, spec section 28).
        """
        seen: dict[str, str] = {}
        conflicts: set[str] = set()
        for record in self.records:
            for key, value in record.fields.items():
                if key in seen and seen[key] != value:
                    conflicts.add(key)
                seen[key] = value
        return frozenset(conflicts)

    def field(self, name: str, default: str = "") -> str:
        return self.merged_fields().get(name, default)

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "host_id": self.host_id,
            "boot_id": self.boot_id,
            "observed_at_ns": self.observed_at_ns,
            "monotonic_ns": self.monotonic_ns,
            "partial": self.partial,
            "sensors": sorted(sensor.value for sensor in self.sensors),
            "conflicting_fields": sorted(self.conflicting_fields()),
            "records": [record.to_dict() for record in self.records],
        }
