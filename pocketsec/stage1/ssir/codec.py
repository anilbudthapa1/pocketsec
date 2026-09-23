"""D1.1/D1.9 — the SSIR v1 binary layout and versioning rules (spec section 23).

The spec's prototype struct, made concrete::

    uint64 causal_sig    uint32 actor_id      uint32 object_id
    uint32 evidence_id   uint16 actor_sem     uint16 object_sem
    uint16 state_delta   uint16 invariant_delta
    uint8  relation      uint8  novelty_host  uint8 novelty_actor
    uint8  novelty_relation uint8 novelty_object uint8 uncertainty
    uint8  time_bucket   uint8  epoch_id_low  uint8 flags

**The packing, widths and field set are explicitly provisional.** Stage 1's
Information Guillotine challenges 64/48/40/32/24/16-byte targets and measures
the security loss at each; this module provides the encoders those measurements
run against. Nothing here is frozen until the D1.13 freeze.

Versioning rule, inherited from Stage 0: a breaking layout change takes a new
schema id (``ssir_transition.v2``), never a version bump in place. The magic
number and version byte in the header make a mismatched decoder fail loudly
rather than silently misread fields.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.ssir.transition import RepresentationLevel, SSIRTransitionV1

__all__ = [
    "SSIR_MAGIC",
    "SSIR_WIRE_VERSION",
    "SSIRCodec",
    "SSIRHeader",
    "LAYOUTS",
]

SSIR_MAGIC = 0x5353  # "SS"
SSIR_WIRE_VERSION = 1

#: Field families, in the order the Information Guillotine removes them
#: (spec section 21). Each maps to the bytes it contributes.
LAYOUTS: dict[str, int] = {
    "causal_sig": 8,
    "actor_id": 4,
    "object_id": 4,
    "evidence_id": 4,
    "actor_sem": 2,
    "object_sem": 2,
    "state_delta": 2,
    "invariant_delta": 2,
    "relation": 1,
    "novelty_host": 1,
    "novelty_actor": 1,
    "novelty_relation": 1,
    "novelty_object": 1,
    "uncertainty": 1,
    "time_bucket": 1,
    "epoch_id_low": 1,
    "flags": 1,
}

#: The full L2 record: 37 payload bytes.
FULL_RECORD_BYTES = sum(LAYOUTS.values())

#: Fields carried at each representation level. L0 is the cheap path the
#: novelty-energy principle depends on being genuinely cheap.
LEVEL_FIELDS: dict[RepresentationLevel, tuple[str, ...]] = {
    RepresentationLevel.L0: ("actor_id", "object_id", "relation", "flags"),
    RepresentationLevel.L1: (
        "actor_id",
        "object_id",
        "actor_sem",
        "object_sem",
        "state_delta",
        "relation",
        "novelty_host",
        "novelty_actor",
        "time_bucket",
        "epoch_id_low",
        "flags",
    ),
    RepresentationLevel.L2: tuple(LAYOUTS),
    RepresentationLevel.L3: tuple(LAYOUTS),
}

# Header: magic (uint16), wire version (uint8), level (uint8).
_HEADER = struct.Struct("<HBB")

_FLAG_HIGH_CONSEQUENCE = 1 << 0
_FLAG_OBSERVATION_INCOMPLETE = 1 << 1
_FLAG_AGGREGATED = 1 << 2
_FLAG_EVIDENCE_LINKED = 1 << 3


@dataclass(frozen=True, slots=True)
class SSIRHeader:
    magic: int
    wire_version: int
    level: RepresentationLevel


class SSIRCodec:
    """Encoder/decoder for SSIR v1, parameterised by retained field set.

    ``retained`` lets the ablation harness encode a record with an information
    family removed and measure the *real* byte cost, rather than estimating it.
    """

    def __init__(self, *, retained: frozenset[str] | None = None) -> None:
        unknown = (retained or frozenset()) - set(LAYOUTS)
        if unknown:
            raise ContractError(f"unknown SSIR fields: {sorted(unknown)}")
        self.retained = retained

    def fields_for(self, level: RepresentationLevel) -> tuple[str, ...]:
        fields = LEVEL_FIELDS[RepresentationLevel(level)]
        if self.retained is None:
            return fields
        return tuple(name for name in fields if name in self.retained)

    def record_bytes(self, level: RepresentationLevel) -> int:
        """Payload size for this level and field set, excluding the header."""
        return sum(LAYOUTS[name] for name in self.fields_for(level))

    def encode(self, transition: SSIRTransitionV1) -> bytes:
        """Serialise to the wire layout."""
        level = transition.level
        values = self._field_values(transition)
        payload = bytearray()
        for name in self.fields_for(level):
            payload += values[name].to_bytes(LAYOUTS[name], "little", signed=False)
        return _HEADER.pack(SSIR_MAGIC, SSIR_WIRE_VERSION, int(level)) + bytes(payload)

    def decode_header(self, blob: bytes) -> SSIRHeader:
        """Read and validate the header.

        A wrong magic or wire version raises rather than proceeding. Silently
        misreading a security representation is worse than refusing to read it.
        """
        if len(blob) < _HEADER.size:
            raise ContractError("SSIR blob too short to contain a header")
        magic, version, level = _HEADER.unpack_from(blob, 0)
        if magic != SSIR_MAGIC:
            raise ContractError(f"bad SSIR magic {magic:#06x}; not an SSIR record")
        if version != SSIR_WIRE_VERSION:
            raise ContractError(
                f"SSIR wire version {version} != {SSIR_WIRE_VERSION}; "
                "a breaking layout change requires a new schema id, not a silent decode"
            )
        return SSIRHeader(magic=magic, wire_version=version, level=RepresentationLevel(level))

    def decode_fields(self, blob: bytes) -> dict[str, int]:
        """Decode the payload back into its integer fields."""
        header = self.decode_header(blob)
        offset = _HEADER.size
        decoded: dict[str, int] = {}
        for name in self.fields_for(header.level):
            width = LAYOUTS[name]
            if offset + width > len(blob):
                raise ContractError(f"SSIR blob truncated while reading {name!r}")
            decoded[name] = int.from_bytes(blob[offset : offset + width], "little")
            offset += width
        return decoded

    # --- field extraction -----------------------------------------------

    @staticmethod
    def _field_values(transition: SSIRTransitionV1) -> dict[str, int]:
        novelty = transition.novelty
        flags = 0
        if transition.is_high_consequence:
            flags |= _FLAG_HIGH_CONSEQUENCE
        if transition.observation_incomplete:
            flags |= _FLAG_OBSERVATION_INCOMPLETE
        if transition.evidence:
            flags |= _FLAG_EVIDENCE_LINKED

        return {
            "causal_sig": int(transition.causal_signature[:16] or "0", 16) & 0xFFFFFFFFFFFFFFFF,
            "actor_id": _identity_id(transition.actor.identity),
            "object_id": _identity_id(transition.object.identity),
            "evidence_id": (
                _identity_id(transition.evidence[0].locator) if transition.evidence else 0
            ),
            "actor_sem": _semantic_mask(transition.actor),
            "object_sem": _semantic_mask(transition.object),
            "state_delta": transition.state_delta.bitmask() & 0xFFFF,
            "invariant_delta": min(0xFFFF, int(max(0.0, transition.delta_phi) * 100)),
            "relation": int(transition.relation) & 0xFF,
            "novelty_host": novelty.quantised("host"),
            "novelty_actor": novelty.quantised("actor"),
            "novelty_relation": novelty.quantised("relation"),
            "novelty_object": novelty.quantised("object"),
            "uncertainty": min(255, int(transition.uncertainty * 255)),
            "time_bucket": transition.temporal.since_actor_bucket & 0xFF,
            "epoch_id_low": transition.epoch_id & 0xFF,
            "flags": flags & 0xFF,
        }

    def describe(self) -> dict[str, Any]:
        return {
            "wire_version": SSIR_WIRE_VERSION,
            "full_record_bytes": FULL_RECORD_BYTES,
            "header_bytes": _HEADER.size,
            "retained": sorted(self.retained) if self.retained else "all",
            "bytes_by_level": {
                level.name: self.record_bytes(level) + _HEADER.size
                for level in RepresentationLevel
            },
        }


def _identity_id(identity: str) -> int:
    """Stable 32-bit handle for an identity string.

    The full identity lives in the evidence store; the model sees only this
    opaque handle. That is deliberate — Stage 1 non-goal: executable names and
    raw command strings must not become mandatory model vocabulary.
    """
    if not identity:
        return 0
    return int.from_bytes(identity.encode("utf-8")[:4].ljust(4, b"\0"), "little") ^ (
        len(identity) & 0xFF
    )


def _semantic_mask(entity: Any) -> int:
    """Pack asserted semantic properties into a uint16."""
    from pocketsec.stage1.ssir.entities import SemanticProperty

    ordered = list(SemanticProperty)
    mask = 0
    for index, prop in enumerate(ordered[:16]):
        if prop in entity.semantics.asserted:
            mask |= 1 << index
    return mask & 0xFFFF
