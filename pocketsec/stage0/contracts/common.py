"""Shared primitives for PocketSec Stage 0 versioned contracts.

Stage 0 freezes the *boundary*, not the ontology. Everything here is deliberately
small: validation helpers, evidence lineage references, and the schema-version
registry that keeps the hub independent of any particular model family.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

__all__ = [
    "ContractError",
    "EvidenceRef",
    "SCHEMA_REGISTRY",
    "digest_of_bytes",
    "freeze_mapping",
    "register_schema",
    "require_finite_unit_interval",
    "require_identifier",
    "require_non_negative_int",
]

_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:\-]{0,127}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class ContractError(ValueError):
    """Raised when a value violates a versioned PocketSec contract.

    Contracts fail loudly. Stage 0 hard rule: do not silently weaken a contract
    to make a caller (or a test) pass.
    """


# --- schema version registry -------------------------------------------------

# Maps schema id -> semantic version. The hub refuses to wire a model slot whose
# declared schemas are not registered here, which is what makes the model slot
# replaceable without touching the hub.
_SCHEMA_REGISTRY: dict[str, str] = {}
SCHEMA_REGISTRY: Mapping[str, str] = MappingProxyType(_SCHEMA_REGISTRY)


def register_schema(schema_id: str, version: str) -> str:
    """Register a schema id/version pair, returning the version.

    Re-registering the same pair is a no-op so modules can be imported twice.
    Re-registering a *different* version for an existing id is a contract error:
    a breaking change must take a new schema id (``...v2``).
    """
    require_identifier(schema_id, "schema_id")
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ContractError(f"schema version must be semver, got {version!r}")
    existing = _SCHEMA_REGISTRY.get(schema_id)
    if existing is not None and existing != version:
        raise ContractError(
            f"schema {schema_id!r} already registered at {existing}; "
            f"a breaking change requires a new schema id, not version {version}"
        )
    _SCHEMA_REGISTRY[schema_id] = version
    return version


# --- validation helpers ------------------------------------------------------


def require_identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER_RE.fullmatch(value):
        raise ContractError(f"{field} must be a 1-128 char identifier, got {value!r}")
    return value


def require_non_negative_int(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ContractError(f"{field} must be a non-negative int, got {value!r}")
    return value


def require_finite_unit_interval(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ContractError(f"{field} must be a number in [0, 1], got {value!r}")
    numeric = float(value)
    if numeric != numeric or numeric in (float("inf"), float("-inf")):
        raise ContractError(f"{field} must be finite, got {value!r}")
    if not 0.0 <= numeric <= 1.0:
        raise ContractError(f"{field} must be within [0, 1], got {numeric!r}")
    return numeric


def freeze_mapping(value: Mapping[str, str] | None, field: str) -> Mapping[str, str]:
    """Copy and freeze a str->str mapping.

    Copying is deliberate: a contract object must never alias mutable caller
    state, otherwise "immutable record" is a lie the moment the caller edits its
    own dict.
    """
    if value is None:
        return MappingProxyType({})
    if not isinstance(value, Mapping):
        raise ContractError(f"{field} must be a mapping, got {type(value).__name__}")
    snapshot: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not key:
            raise ContractError(f"{field} keys must be non-empty strings, got {key!r}")
        if not isinstance(item, str):
            raise ContractError(f"{field}[{key!r}] must be a string, got {type(item).__name__}")
        snapshot[key] = item
    return MappingProxyType(snapshot)


def digest_of_bytes(payload: bytes) -> str:
    """Return the canonical ``sha256:<hex>`` digest used for evidence lineage."""
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


# --- evidence lineage --------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EvidenceRef:
    """A pointer to raw evidence held outside the learned model.

    Invariant (MEMORY.md): raw evidence is distinct from any compressed or model
    representation and must retain lineage. A reference therefore carries a
    content digest, so a later stage can prove the bytes it reads are the bytes
    the prediction was made from. Evidence is *referenced*, never inlined.
    """

    store: str
    locator: str
    digest: str

    def __post_init__(self) -> None:
        require_identifier(self.store, "EvidenceRef.store")
        if not isinstance(self.locator, str) or not self.locator:
            raise ContractError("EvidenceRef.locator must be a non-empty string")
        if not isinstance(self.digest, str) or not _DIGEST_RE.fullmatch(self.digest):
            raise ContractError(
                f"EvidenceRef.digest must look like 'sha256:<64 hex>', got {self.digest!r}"
            )

    def to_dict(self) -> dict[str, str]:
        return {"store": self.store, "locator": self.locator, "digest": self.digest}

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> EvidenceRef:
        try:
            return cls(
                store=str(payload["store"]),
                locator=str(payload["locator"]),
                digest=str(payload["digest"]),
            )
        except KeyError as exc:  # pragma: no cover - defensive
            raise ContractError(f"EvidenceRef missing field {exc.args[0]!r}") from exc
