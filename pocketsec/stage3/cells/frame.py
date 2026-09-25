"""``CellFrame`` — the only thing a Knowledge Cell is ever allowed to read.

Everything a compiled cell can see passes through this one type. That is the
containment argument for the whole stage: a cell cannot reach a file, a socket,
a process table or an ``Entity``, because it is never handed one.

What is deliberately **absent** is as load-bearing as what is present. There is
no ``Entity``, no ``identity`` and no ``display_name`` anywhere in this frame.
ADR-0006/0007: semantics are earned by behaviour and names are evidence, never
model vocabulary. A cell that could branch on a process name would be a rename
away from being wrong, and would quietly reintroduce the signature matching this
architecture exists to avoid. ``tests/test_stage3_foundation.py`` asserts the
absence over ``__dataclass_fields__`` so the property survives a future edit.

``frame_digest`` is the canonical join key between a frame and the frozen
teacher snapshot (Oracle A, D3.8). It lives here rather than in
``oracles/teacher.py`` so that the digest and the fields it digests cannot drift
apart across packages.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from pocketsec.stage0.contracts.common import (
    ContractError,
    EvidenceRef,
    digest_of_bytes,
    require_finite_unit_interval,
    require_identifier,
    require_non_negative_int,
)
from pocketsec.stage1.ssir.relations import RelationFamily
from pocketsec.stage1.state.security_state import SecurityStateV1, StateDelta
from pocketsec.stage3.cells.masks import BoundaryKey, require_property_mask

__all__ = ["CellFrame", "FRAME_DIGEST_PRECISION", "boundary_key_of", "frame_digest"]

#: Decimal places floats are rounded to before digesting. A join key that
#: depended on the last bit of a float would miss on a rebuild for no security
#: reason; six places is far finer than any Phi difference that matters and is
#: reproducible across runs.
FRAME_DIGEST_PRECISION = 6

#: A frame carries a bounded slice of recent history, not a log. The window is
#: keyed by relation family, so its size is fixed by Stage 1's vocabulary.
MAX_WINDOW_KEYS = len(RelationFamily)

#: Hoisted out of the validator: a frame is built per event, and rebuilding this
#: set per key would put Stage 1's whole family vocabulary on the hot path.
_FAMILY_VALUES = frozenset(int(family) for family in RelationFamily)


@dataclass(frozen=True, slots=True)
class CellFrame:
    """One normalised Stage 1 observation, as a cell sees it (architecture §30)."""

    state: SecurityStateV1
    delta: StateDelta
    actor_properties: int
    object_properties: int
    relation_family: RelationFamily
    phi: float
    delta_phi: float
    uncertainty: float
    epoch_id: int
    window_counts: Mapping[int, int]
    evidence: tuple[EvidenceRef, ...]
    encoder_version: str

    def __post_init__(self) -> None:
        if not isinstance(self.state, SecurityStateV1):
            raise ContractError("CellFrame.state must be a SecurityStateV1")
        if not isinstance(self.delta, StateDelta):
            raise ContractError("CellFrame.delta must be a StateDelta")
        require_property_mask(self.actor_properties, "CellFrame.actor_properties")
        require_property_mask(self.object_properties, "CellFrame.object_properties")
        if not isinstance(self.relation_family, RelationFamily):
            raise ContractError(
                f"CellFrame.relation_family must be a RelationFamily, "
                f"got {type(self.relation_family).__name__}"
            )
        _require_finite(self.phi, "CellFrame.phi")
        _require_finite(self.delta_phi, "CellFrame.delta_phi")
        require_finite_unit_interval(self.uncertainty, "CellFrame.uncertainty")
        require_non_negative_int(self.epoch_id, "CellFrame.epoch_id")
        object.__setattr__(self, "window_counts", _frozen_window(self.window_counts))
        object.__setattr__(self, "evidence", _require_evidence(self.evidence))
        require_identifier(self.encoder_version, "CellFrame.encoder_version")

    def to_dict(self) -> dict[str, Any]:
        """Canonical projection. This is exactly what ``frame_digest`` hashes."""
        return {
            "state": self.state.to_levels(),
            "delta_bitmask": self.delta.bitmask(),
            "delta_raised": {
                name: [before, after] for name, (before, after) in sorted(self.delta.raised.items())
            },
            "actor_properties": self.actor_properties,
            "object_properties": self.object_properties,
            "relation_family": int(self.relation_family),
            "phi": round(self.phi, FRAME_DIGEST_PRECISION),
            "delta_phi": round(self.delta_phi, FRAME_DIGEST_PRECISION),
            "uncertainty": round(self.uncertainty, FRAME_DIGEST_PRECISION),
            "epoch_id": self.epoch_id,
            "window_counts": {
                str(key): self.window_counts[key] for key in sorted(self.window_counts)
            },
            # Evidence joins by digest, sorted: the *set* of bytes behind the
            # frame is what identifies it, not the order they arrived in.
            "evidence": sorted(ref.digest for ref in self.evidence),
            "encoder_version": self.encoder_version,
        }


def _require_finite(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ContractError(f"{field} must be a number, got {value!r}")
    numeric = float(value)
    if numeric != numeric or numeric in (float("inf"), float("-inf")):
        raise ContractError(f"{field} must be finite, got {value!r}")
    return numeric


def _frozen_window(value: object) -> Mapping[int, int]:
    """Bound and freeze the window counts.

    Bounded because endpoint state is bounded (MEMORY.md): a frame that could
    carry an unbounded histogram would be an unbounded per-event allocation.
    """
    if not isinstance(value, Mapping):
        raise ContractError(
            f"CellFrame.window_counts must be a mapping, got {type(value).__name__}"
        )
    if len(value) > MAX_WINDOW_KEYS:
        raise ContractError(
            f"CellFrame.window_counts holds {len(value)} keys, above the "
            f"{MAX_WINDOW_KEYS} relation families; the window is bounded by construction"
        )
    snapshot: dict[int, int] = {}
    for key, count in value.items():
        if not isinstance(key, int) or isinstance(key, bool):
            raise ContractError(f"CellFrame.window_counts keys must be ints, got {key!r}")
        if key not in _FAMILY_VALUES:
            raise ContractError(
                f"CellFrame.window_counts key {key!r} is not a RelationFamily value"
            )
        require_non_negative_int(count, f"CellFrame.window_counts[{key}]")
        snapshot[key] = count
    return MappingProxyType(snapshot)


def _require_evidence(value: object) -> tuple[EvidenceRef, ...]:
    """A frame with no evidence is not an observation; it is an assertion."""
    if not isinstance(value, tuple) or not value:
        raise ContractError(
            "CellFrame.evidence must be a non-empty tuple: a cell answering about a "
            "frame with no evidence lineage could not be audited back to bytes"
        )
    for ref in value:
        if not isinstance(ref, EvidenceRef):
            raise ContractError(
                f"CellFrame.evidence entries must be EvidenceRef, got {type(ref).__name__}"
            )
    return value


def frame_digest(frame: CellFrame) -> str:
    """Canonical ``sha256:`` digest of a frame — the teacher-snapshot join key.

    ``sort_keys`` plus ``allow_nan=False`` is the point: a teacher snapshot
    produced offline and a frame produced at runtime must hash identically, and
    ``json.dumps`` emits bare ``NaN`` by default, which no other reader accepts.
    """
    if not isinstance(frame, CellFrame):
        raise ContractError(f"frame_digest expects a CellFrame, got {type(frame).__name__}")
    payload = json.dumps(
        frame.to_dict(), sort_keys=True, allow_nan=False, separators=(",", ":")
    )
    return digest_of_bytes(payload.encode("utf-8"))


def boundary_key_of(frame: CellFrame) -> BoundaryKey:
    """The three-int index key this frame falls under.

    Object properties are absent on purpose: the boundary index is keyed on what
    *acted* and what *changed*. Object semantics are checked by the boundary's
    predicates after the index narrows the search, so the key stays small.
    """
    return (int(frame.relation_family), frame.actor_properties, frame.delta.bitmask())
