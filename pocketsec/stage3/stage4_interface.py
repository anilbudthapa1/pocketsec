"""D3.16 — the Stage 4 seam: crystallised knowledge as plain data, and nothing else.

This mirrors ``pocketsec/stage2/compile_candidates/stage3_interface.py`` on
purpose, clause for clause. Stage 2 learned that a handoff which carries objects
becomes a coupling: Stage 2 has been redesigned twice (ADR-0009, ADR-0010) and
its seam survived both only because Stage 3 reads JSON. Stage 3 will be
redesigned too — ADR-0021 may yet reject the cell format outright — so Stage 4
gets the same protection.

Every nested member of a :class:`CrystalHandoffV1` is a plain
``Mapping[str, Any]`` of JSON values, and :meth:`CrystalHandoffV1.to_dict`
refuses to emit a payload whose keys name a Stage 3 class. The refusal runs
*before* the bytes exist, so a leak cannot be written and then noticed.

``FORBIDDEN_SEAM_TOKENS`` names classes, never data. ``cell_id``, ``cells`` and
``epochs`` are plain data and are deliberately not caught; ``KnowledgeCellV1``,
``BoundaryIndex`` and ``CellVM`` are couplings and are. Getting that line wrong
in either direction breaks something: too strict and a legitimate cell cannot
cross, too loose and Stage 4 grows an import of this package.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import (
    ContractError,
    digest_of_bytes,
    register_schema,
    require_identifier,
)
from pocketsec.stage2.encoder.ssir_encoder import ENCODER_VERSION
from pocketsec.stage3.cells.field import KnowledgeField

if TYPE_CHECKING:  # pragma: no cover - typing only
    from pocketsec.stage3.boundary.index import BoundaryIndex

__all__ = [
    "CRYSTAL_HANDOFF_V1_ID",
    "CRYSTAL_HANDOFF_V1_VERSION",
    "CrystalHandoffV1",
    "FORBIDDEN_SEAM_TOKENS",
    "build_crystal_handoff",
    "seam_violations",
    "write_crystal_handoff",
]

CRYSTAL_HANDOFF_V1_ID = "pocketsec.crystal_handoff.v1"
CRYSTAL_HANDOFF_V1_VERSION = register_schema(CRYSTAL_HANDOFF_V1_ID, "1.0.0")

#: Stage 3 class names Stage 4 must never see as a key. Compared against keys
#: with separators stripped, so ``knowledge_cell``, ``knowledgeCell`` and
#: ``KnowledgeCell`` are all caught.
#:
#: Deliberately absent: ``cell``, ``boundary``, ``invariant``, ``operator``,
#: ``audit_policy`` and ``resolution``. Those are field names a
#: ``KnowledgeCellV1.to_dict()`` row legitimately carries, and banning them
#: would mean no cell could cross the seam at all — a refusal so total it would
#: be deleted within a week rather than respected.
FORBIDDEN_SEAM_TOKENS = frozenset(
    {
        "knowledgecell",
        "knowledgecellv1",
        "knowledgefield",
        "knowledgepressure",
        "boundaryindex",
        "boundarypressurereport",
        "boundaryprobe",
        "cellboundary",
        "cellframe",
        "cellvm",
        "cellresult",
        "cellactivation",
        "cellutility",
        "cellstress",
        "cellisa",
        "cellverifier",
        "cellbytecode",
        "crystalslot",
        "crystalrun",
        "operatorprogram",
        "operatorcandidate",
        "compositionverdict",
        "dualoracle",
        "dualoracleverdict",
        "counterexamplestore",
        "teachersnapshot",
        "teacheroracle",
        "assurancestate",
        "meltreport",
        "fissionresult",
        "promotionverdict",
        "semanticpredicate",
        "resolutionstate",
        "intelligencedensity",
        "shadowrun",
        "auditsampler",
    }
)


def seam_violations(payload: object, *, prefix: str = "handoff") -> tuple[str, ...]:
    """Return every key path whose name would leak a Stage 3 class across the seam."""
    found: list[str] = []
    if isinstance(payload, Mapping):
        for key, value in payload.items():
            path = f"{prefix}.{key}"
            flattened = str(key).lower().replace("_", "").replace("-", "")
            if any(token in flattened for token in FORBIDDEN_SEAM_TOKENS):
                found.append(path)
            found.extend(seam_violations(value, prefix=path))
    elif isinstance(payload, (list, tuple)):
        for index, item in enumerate(payload):
            found.extend(seam_violations(item, prefix=f"{prefix}[{index}]"))
    return tuple(found)


def _require_json(value: object, *, field: str) -> Any:
    """Refuse anything that is not a JSON scalar, list or mapping.

    A class instance that happens to be JSON-serialisable by a custom encoder is
    still a class: it would make Stage 4's reader depend on Stage 3's encoder.
    """
    if value is None or isinstance(value, (str, int, float, bool)):
        # NaN *and* both infinities. Only NaN was refused, so a handoff carrying
        # ``inf`` constructed cleanly and then raised ValueError — not
        # ContractError — inside ``write_crystal_handoff``'s ``json.dumps(...,
        # allow_nan=False)``. The refusal has to run before the bytes exist, which
        # is this module's opening claim.
        if isinstance(value, float) and not isinstance(value, bool):
            if value != value:
                raise ContractError(f"{field} is NaN; canonical JSON cannot carry it")
            if value in (float("inf"), float("-inf")):
                raise ContractError(
                    f"{field} is {value}; canonical JSON cannot carry an infinity"
                )
        return value
    if isinstance(value, Mapping):
        return {
            str(key): _require_json(item, field=f"{field}.{key}")
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_require_json(item, field=f"{field}[{index}]") for index, item in enumerate(value)]
    raise ContractError(
        f"{field} holds {type(value).__name__}, which is not plain JSON; Stage 4 "
        "imports no Stage 3 class and therefore cannot be handed one"
    )


def _plain_rows(rows: Sequence[Mapping[str, Any]], *, field: str) -> tuple[Mapping[str, Any], ...]:
    normalised: list[Mapping[str, Any]] = []
    for index, row in enumerate(rows):
        where = f"{field}[{index}]"
        if not isinstance(row, Mapping):
            raise ContractError(f"{where} must be a mapping, got {type(row).__name__}")
        clean = _require_json(row, field=where)
        offenders = seam_violations(clean, prefix=where)
        if offenders:
            raise ContractError(
                f"{where} names Stage 3 classes {list(offenders)}; Stage 4 reads plain data"
            )
        normalised.append(clean)
    return tuple(normalised)


@dataclass(frozen=True, slots=True)
class CrystalHandoffV1:
    """Everything Stage 4 needs about crystallised knowledge, and no Stage 3 object.

    ``melt_history`` is part of the seam rather than an afterthought: Stage 4 has
    to be able to tell "this region was never crystallised" from "this region was
    crystallised and then melted", and those route differently. A handoff that
    dropped the melt history would make a reopened region look like a region that
    never had knowledge.
    """

    handoff_id: str
    cells: tuple[Mapping[str, Any], ...]
    assurance: tuple[Mapping[str, Any], ...]
    boundary_keys: tuple[Mapping[str, Any], ...]
    melt_history: tuple[Mapping[str, Any], ...]
    encoder_version: str
    interface_version: str = CRYSTAL_HANDOFF_V1_VERSION

    def __post_init__(self) -> None:
        require_identifier(self.handoff_id, "CrystalHandoffV1.handoff_id")
        require_identifier(self.encoder_version, "CrystalHandoffV1.encoder_version")
        require_identifier(self.interface_version, "CrystalHandoffV1.interface_version")
        for name in ("cells", "assurance", "boundary_keys", "melt_history"):
            object.__setattr__(
                self, name, _plain_rows(getattr(self, name), field=f"CrystalHandoffV1.{name}")
            )

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "interface_version": self.interface_version,
            "schema_id": CRYSTAL_HANDOFF_V1_ID,
            "handoff_id": self.handoff_id,
            "encoder_version": self.encoder_version,
            "cells": [dict(row) for row in self.cells],
            "assurance": [dict(row) for row in self.assurance],
            "boundary_keys": [dict(row) for row in self.boundary_keys],
            "melt_history": [dict(row) for row in self.melt_history],
        }
        offenders = seam_violations(payload)
        if offenders:
            raise ContractError(
                f"CrystalHandoffV1.to_dict would leak Stage 3 class names {list(offenders)}"
            )
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> CrystalHandoffV1:
        try:
            return cls(
                handoff_id=str(payload["handoff_id"]),
                cells=tuple(payload["cells"]),
                assurance=tuple(payload["assurance"]),
                boundary_keys=tuple(payload["boundary_keys"]),
                melt_history=tuple(payload["melt_history"]),
                encoder_version=str(payload["encoder_version"]),
                interface_version=str(
                    payload.get("interface_version", CRYSTAL_HANDOFF_V1_VERSION)
                ),
            )
        except KeyError as exc:
            raise ContractError(f"CrystalHandoffV1 missing field {exc.args[0]!r}") from exc


def _boundary_key_rows(
    field: KnowledgeField, index: BoundaryIndex | None
) -> tuple[Mapping[str, Any], ...]:
    """One row per (cell, key). Keys are three ints, which is the whole point of them."""
    if index is None:
        return ()
    rows: list[Mapping[str, Any]] = []
    for cell in field.cells():
        for key in index.keys_for(cell.cell_id):
            rows.append(
                {
                    "cell_id": cell.cell_id,
                    "relation_family": int(key[0]),
                    "actor_property_mask": int(key[1]),
                    "state_delta_mask": int(key[2]),
                }
            )
    return tuple(rows)


def build_crystal_handoff(
    field: KnowledgeField,
    index: BoundaryIndex | None = None,
    *,
    handoff_id: str,
    assurance: Sequence[Mapping[str, Any]] = (),
    melt_history: Sequence[Mapping[str, Any]] = (),
    encoder_version: str = ENCODER_VERSION,
) -> CrystalHandoffV1:
    """Project a live field into the plain-data shape Stage 4 consumes.

    ``assurance`` and ``melt_history`` arrive already projected, as
    ``AssuranceState.to_dict()`` and ``MeltReport``-shaped rows. They are
    parameters rather than something read off the field because assurance and
    melt lineage live in the ``lifecycle`` package: reaching into it from here
    would put the seam on the wrong side of a package boundary and make this
    module import the very thing it exists to keep out of Stage 4.
    """
    return CrystalHandoffV1(
        handoff_id=handoff_id,
        cells=tuple(cell.to_dict() for cell in field.cells()),
        assurance=tuple(assurance),
        boundary_keys=_boundary_key_rows(field, index),
        melt_history=tuple(melt_history),
        encoder_version=encoder_version,
    )


def write_crystal_handoff(handoff: CrystalHandoffV1, path: Path) -> str:
    """Write canonical JSON and return its ``sha256:`` digest.

    Canonical (sorted keys, no NaN, fixed indent, trailing newline) so the digest
    is reproducible: Stage 4 can prove the cells it loaded are the cells Stage 3
    wrote, which is the same lineage guarantee ``EvidenceRef`` gives raw evidence.
    """
    payload = (
        json.dumps(handoff.to_dict(), sort_keys=True, allow_nan=False, indent=2).encode("utf-8")
        + b"\n"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return digest_of_bytes(payload)
