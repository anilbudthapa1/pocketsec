"""D0.2 — ``SecurityEventSequenceV1``, the hub -> model-slot input contract.

Stage 0 deliberately does **not** define the security ontology; Stage 1 does
(spec section 10, and the Stage 0 non-goal "do not hard-code a final threat
taxonomy"). So this contract freezes only the envelope every Linux telemetry
source must supply, and carries the ontology-bearing fields in an opaque
``attributes`` mapping that Stage 1 is free to formalise without renegotiating
the measurement rules.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from pocketsec.stage0.contracts.common import (
    ContractError,
    EvidenceRef,
    freeze_mapping,
    register_schema,
    require_identifier,
    require_non_negative_int,
)

__all__ = [
    "MAX_SEQUENCE_CAPACITY",
    "SECURITY_EVENT_SEQUENCE_V1_ID",
    "SECURITY_EVENT_SEQUENCE_V1_VERSION",
    "SecurityEventSequenceV1",
    "SecurityEventV1",
]

SECURITY_EVENT_SEQUENCE_V1_ID = "pocketsec.security_event_sequence.v1"
SECURITY_EVENT_SEQUENCE_V1_VERSION = register_schema(SECURITY_EVENT_SEQUENCE_V1_ID, "1.0.0")

# Hard upper bound on a single window handed to a model slot. Endpoint memory,
# queues and caches must be bounded (MEMORY.md invariant); an unbounded sequence
# is an unbounded allocation on a 2 GB host.
MAX_SEQUENCE_CAPACITY = 4096


@dataclass(frozen=True, slots=True)
class SecurityEventV1:
    """One normalised Linux security-relevant observation.

    ``kind`` is a coarse *source-level* label ("process.exec", "auth.sudo"), not
    a threat class. Nothing in this contract may encode a verdict: classification
    is the model slot's job and lives in ``ThreatPredictionV1``.
    """

    event_id: str
    host_id: str
    boot_id: str
    observed_at_ns: int
    monotonic_ns: int
    source: str
    kind: str
    attributes: Mapping[str, str] = field(default_factory=dict)
    evidence: tuple[EvidenceRef, ...] = ()

    def __post_init__(self) -> None:
        require_identifier(self.event_id, "SecurityEventV1.event_id")
        require_identifier(self.host_id, "SecurityEventV1.host_id")
        require_identifier(self.boot_id, "SecurityEventV1.boot_id")
        require_non_negative_int(self.observed_at_ns, "SecurityEventV1.observed_at_ns")
        require_non_negative_int(self.monotonic_ns, "SecurityEventV1.monotonic_ns")
        require_identifier(self.source, "SecurityEventV1.source")
        require_identifier(self.kind, "SecurityEventV1.kind")
        object.__setattr__(
            self, "attributes", freeze_mapping(self.attributes, "SecurityEventV1.attributes")
        )
        object.__setattr__(self, "evidence", _freeze_evidence(self.evidence))

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "host_id": self.host_id,
            "boot_id": self.boot_id,
            "observed_at_ns": self.observed_at_ns,
            "monotonic_ns": self.monotonic_ns,
            "source": self.source,
            "kind": self.kind,
            "attributes": dict(self.attributes),
            "evidence": [ref.to_dict() for ref in self.evidence],
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> SecurityEventV1:
        _require_keys(payload, _EVENT_REQUIRED_KEYS, "SecurityEventV1")
        return cls(
            event_id=str(payload["event_id"]),
            host_id=str(payload["host_id"]),
            boot_id=str(payload["boot_id"]),
            observed_at_ns=int(payload["observed_at_ns"]),
            monotonic_ns=int(payload["monotonic_ns"]),
            source=str(payload["source"]),
            kind=str(payload["kind"]),
            attributes=payload.get("attributes") or {},
            evidence=tuple(
                EvidenceRef.from_dict(item) for item in (payload.get("evidence") or ())
            ),
        )


@dataclass(frozen=True, slots=True)
class SecurityEventSequenceV1:
    """A bounded, host-local window of events offered to the model slot.

    ``window_capacity`` and ``truncated`` are part of the contract on purpose.
    A model slot must be able to tell "nothing happened before this" apart from
    "the window dropped what happened before this" — otherwise a bounded buffer
    silently becomes a false negative.
    """

    sequence_id: str
    host_id: str
    events: tuple[SecurityEventV1, ...]
    window_capacity: int = MAX_SEQUENCE_CAPACITY
    truncated: bool = False
    schema_version: str = SECURITY_EVENT_SEQUENCE_V1_VERSION

    def __post_init__(self) -> None:
        require_identifier(self.sequence_id, "SecurityEventSequenceV1.sequence_id")
        require_identifier(self.host_id, "SecurityEventSequenceV1.host_id")
        object.__setattr__(self, "events", tuple(self.events))
        if not self.events:
            raise ContractError("SecurityEventSequenceV1.events must not be empty")
        if not isinstance(self.truncated, bool):
            raise ContractError("SecurityEventSequenceV1.truncated must be a bool")
        self._validate_capacity()
        self._validate_events()

    def _validate_capacity(self) -> None:
        require_non_negative_int(self.window_capacity, "SecurityEventSequenceV1.window_capacity")
        if not 1 <= self.window_capacity <= MAX_SEQUENCE_CAPACITY:
            raise ContractError(
                f"window_capacity must be within [1, {MAX_SEQUENCE_CAPACITY}], "
                f"got {self.window_capacity}"
            )
        if len(self.events) > self.window_capacity:
            raise ContractError(
                f"sequence holds {len(self.events)} events, exceeding declared "
                f"window_capacity {self.window_capacity}"
            )

    def _validate_events(self) -> None:
        previous: SecurityEventV1 | None = None
        for index, event in enumerate(self.events):
            if not isinstance(event, SecurityEventV1):
                raise ContractError(f"events[{index}] must be a SecurityEventV1")
            if event.host_id != self.host_id:
                raise ContractError(
                    f"events[{index}].host_id {event.host_id!r} does not match "
                    f"sequence host_id {self.host_id!r}"
                )
            if (
                previous is not None
                and event.boot_id == previous.boot_id
                and event.monotonic_ns < previous.monotonic_ns
            ):
                raise ContractError(
                    f"events[{index}] goes backwards in monotonic time within boot "
                    f"{event.boot_id!r}; ordering is part of the contract"
                )
            previous = event

    @property
    def evidence(self) -> tuple[EvidenceRef, ...]:
        """Every evidence reference in the window, in observation order."""
        return tuple(ref for event in self.events for ref in event.evidence)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SECURITY_EVENT_SEQUENCE_V1_ID,
            "schema_version": self.schema_version,
            "sequence_id": self.sequence_id,
            "host_id": self.host_id,
            "window_capacity": self.window_capacity,
            "truncated": self.truncated,
            "events": [event.to_dict() for event in self.events],
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> SecurityEventSequenceV1:
        _require_keys(payload, _SEQUENCE_REQUIRED_KEYS, "SecurityEventSequenceV1")
        declared = str(payload.get("schema", SECURITY_EVENT_SEQUENCE_V1_ID))
        if declared != SECURITY_EVENT_SEQUENCE_V1_ID:
            raise ContractError(
                f"expected schema {SECURITY_EVENT_SEQUENCE_V1_ID!r}, got {declared!r}"
            )
        return cls(
            sequence_id=str(payload["sequence_id"]),
            host_id=str(payload["host_id"]),
            events=tuple(SecurityEventV1.from_dict(item) for item in payload["events"]),
            window_capacity=int(payload.get("window_capacity", MAX_SEQUENCE_CAPACITY)),
            truncated=bool(payload.get("truncated", False)),
            schema_version=str(payload.get("schema_version", SECURITY_EVENT_SEQUENCE_V1_VERSION)),
        )


_EVENT_REQUIRED_KEYS = (
    "event_id",
    "host_id",
    "boot_id",
    "observed_at_ns",
    "monotonic_ns",
    "source",
    "kind",
)
_SEQUENCE_REQUIRED_KEYS = ("sequence_id", "host_id", "events")


def _require_keys(payload: Mapping[str, Any], keys: Sequence[str], label: str) -> None:
    missing = [key for key in keys if key not in payload]
    if missing:
        raise ContractError(f"{label} missing required field(s): {', '.join(missing)}")


def _freeze_evidence(value: Iterable[EvidenceRef]) -> tuple[EvidenceRef, ...]:
    refs = tuple(value)
    for index, ref in enumerate(refs):
        if not isinstance(ref, EvidenceRef):
            raise ContractError(f"evidence[{index}] must be an EvidenceRef")
    return refs
