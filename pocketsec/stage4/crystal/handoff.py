"""D4.14 (read half) — Stage 3's crystallised knowledge, read as plain JSON.

This module is Stage 4's **only** contact with Stage 3, and it makes that contact
through a file rather than an import. The reason is written in the producer's own
docstring (``pocketsec/stage3/stage4_interface.py:1-20``): a handoff that carries
objects becomes a coupling, Stage 2 was redesigned twice and its seam survived
only because the consumer read JSON, and Stage 3 will be redesigned too — ADR-0021
may reject the cell format outright. So there is **zero** ``import
pocketsec.stage3`` here or anywhere else under ``pocketsec/stage4/``
(spec §2.5, asserted by AST).

The file format is fixed by ``write_crystal_handoff`` (``stage4_interface.py:271``):
canonical JSON — ``sort_keys=True``, ``allow_nan=False``, ``indent=2``, one
trailing newline — whose ``sha256:`` digest is returned to the writer. This reader
recomputes that digest from the bytes it actually read, so Stage 4 can prove the
cells it loaded are the cells Stage 3 wrote. That is the same lineage guarantee
``EvidenceRef`` gives raw evidence, and it is why :attr:`CrystalKnowledge.handoff_digest`
is not taken from inside the payload.

What this module refuses to do:

* **It never raises at the point of use.** Stage 3 being absent is a supported
  configuration, so :func:`load_or_empty` answers ``(EMPTY_KNOWLEDGE, record)`` for
  a missing, unreadable, oversized or schema-mismatched file. Only
  :func:`read_crystal_knowledge` raises, and it is for callers that have already
  decided a handoff must exist.
* **It never interprets Stage 3's vocabulary.** ``melted(cell_id)`` reports that a
  melt row names the cell; it does not read ``kind``, because that enum belongs to
  Stage 3 and re-encoding it here would rebuild the coupling the JSON seam exists
  to prevent.
* **It never reads an unbounded file.** A handoff larger than
  :data:`MAX_HANDOFF_BYTES`, or with more rows than the per-section caps, is
  refused *before* it is parsed. An endpoint with 2 GB of RAM cannot afford to
  find out how big a file is by loading it.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pocketsec.stage0.contracts.common import (
    ContractError,
    digest_of_bytes,
    require_identifier,
)
from pocketsec.stage4.engine.degradation import (
    DegradationRecord,
    Subsystem,
    record_for,
)

__all__ = [
    "CRYSTAL_HANDOFF_V1_ID",
    "CrystalKnowledge",
    "EMPTY_KNOWLEDGE",
    "MAX_ASSURANCE_ROWS",
    "MAX_BOUNDARY_KEY_ROWS",
    "MAX_CELLS",
    "MAX_HANDOFF_BYTES",
    "MAX_MELT_ROWS",
    "load_or_empty",
    "read_crystal_knowledge",
]

#: The producer's schema id, as a literal. Importing it would import Stage 3.
#: Read from ``pocketsec/stage3/stage4_interface.py:52`` this session; a mismatch
#: is a refusal, never a coercion.
CRYSTAL_HANDOFF_V1_ID = "pocketsec.crystal_handoff.v1"

#: 4 MiB. Stage 3's whole promoted field is KB-scale; anything larger is either a
#: defect upstream or a file an attacker put where a handoff goes.
MAX_HANDOFF_BYTES: int = 4 * 1024 * 1024
MAX_CELLS: int = 256
MAX_ASSURANCE_ROWS: int = 512
MAX_BOUNDARY_KEY_ROWS: int = 2048
MAX_MELT_ROWS: int = 512

_SECTION_CAPS: Mapping[str, int] = {
    "cells": MAX_CELLS,
    "assurance": MAX_ASSURANCE_ROWS,
    "boundary_keys": MAX_BOUNDARY_KEY_ROWS,
    "melt_history": MAX_MELT_ROWS,
}


def _rows(payload: Mapping[str, Any], name: str) -> tuple[Mapping[str, Any], ...]:
    """One section of the handoff, validated as a bounded list of JSON objects."""
    raw = payload.get(name)
    if raw is None:
        raise ContractError(f"crystal handoff missing section {name!r}")
    if not isinstance(raw, list):
        raise ContractError(f"crystal handoff section {name!r} must be a list")
    cap = _SECTION_CAPS[name]
    if len(raw) > cap:
        raise ContractError(f"crystal handoff section {name!r} holds {len(raw)} rows, cap is {cap}")
    rows: list[Mapping[str, Any]] = []
    for index, row in enumerate(raw):
        if not isinstance(row, dict):
            raise ContractError(f"crystal handoff {name}[{index}] must be a JSON object")
        rows.append(dict(row))
    return tuple(rows)


def _int_field(row: Mapping[str, Any], key: str, *, where: str) -> int:
    value = row.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ContractError(f"{where}.{key} must be an int, got {value!r}")
    return value


#: The interface major version this reader was written against.
_SUPPORTED_INTERFACE_MAJOR = "1"


def _require_compatible_interface(version: object, *, path: Path) -> None:
    """Accept any ``1.x.y`` handoff, refuse a different major.

    Stage 0's registry rule is that a breaking change takes a new schema id
    (``register_schema``, ``common.py:49``), so within one id a minor bump must
    stay readable — refusing it would make the seam brittle in exactly the way the
    producer's docstring warns about. A *major* bump under the same id is an
    upstream contract violation, and reading it as if it were compatible is how a
    silent misinterpretation happens.
    """
    if not isinstance(version, str) or not version:
        raise ContractError(f"crystal handoff {path.name} has no interface_version")
    if version.split(".", 1)[0] != _SUPPORTED_INTERFACE_MAJOR:
        raise ContractError(
            f"crystal handoff {path.name} declares interface_version {version!r}; "
            f"this reader was written against {_SUPPORTED_INTERFACE_MAJOR}.x"
        )


def _require_cell_ids(cells: Sequence[Mapping[str, Any]]) -> None:
    """Every cell row must carry an identifier-shaped ``cell_id``.

    As strict as the producer (``KnowledgeCellV1.cell_id`` passes Stage 0's
    ``require_identifier``) and no stricter: too strict and a legitimate cell
    cannot cross, which is the failure mode the producer's docstring names.
    """
    for index, row in enumerate(cells):
        require_identifier(row.get("cell_id"), f"crystal handoff cells[{index}].cell_id")


@dataclass(frozen=True, slots=True)
class CrystalKnowledge:
    """Stage 3's handoff as Stage 4 holds it: seven fields of plain JSON.

    Mirrors ``CrystalHandoffV1``'s seven data fields field-for-field. The
    producer's eighth field, ``interface_version``, is checked by
    :func:`read_crystal_knowledge` and deliberately not retained: it says what
    shape was *intended*, and ``handoff_digest`` says what actually arrived.
    """

    handoff_id: str
    #: ``sha256:`` of the bytes actually read, not a value copied out of them.
    handoff_digest: str
    cells: tuple[Mapping[str, Any], ...]
    assurance: tuple[Mapping[str, Any], ...]
    boundary_keys: tuple[Mapping[str, Any], ...]
    melt_history: tuple[Mapping[str, Any], ...]
    encoder_version: str

    def __post_init__(self) -> None:
        require_identifier(self.handoff_id, "CrystalKnowledge.handoff_id")
        require_identifier(self.encoder_version, "CrystalKnowledge.encoder_version")
        if not isinstance(self.handoff_digest, str) or not self.handoff_digest.startswith(
            "sha256:"
        ):
            raise ContractError(
                f"CrystalKnowledge.handoff_digest must be a sha256: digest, "
                f"got {self.handoff_digest!r}"
            )
        for name in ("cells", "assurance", "boundary_keys", "melt_history"):
            object.__setattr__(self, name, tuple(getattr(self, name)))
        # Validated here rather than only in the reader, so a caller that builds
        # knowledge some other way cannot hand the rest of Stage 4 a cell with no
        # id — every lookup below is keyed on it.
        _require_cell_ids(self.cells)

    def cell_ids(self) -> tuple[str, ...]:
        """Every cell id, in file order. Duplicates are preserved, not merged.

        A duplicate would be an upstream defect and hiding it here would hide the
        defect rather than the duplicate.
        """
        return tuple(str(row["cell_id"]) for row in self.cells)

    def melted(self, cell_id: str) -> bool:
        """True when the melt history names this cell.

        "Never crystallised" and "crystallised then melted" route differently
        (the producer's docstring says so), and this is the only question Stage 4
        asks of the melt history — the melt *kind* is Stage 3's vocabulary.
        """
        return any(str(row.get("cell_id", "")) == cell_id for row in self.melt_history)

    def keys_for(self, cell_id: str) -> tuple[tuple[int, int, int], ...]:
        """The ``(relation_family, actor_property_mask, state_delta_mask)`` triples.

        Three ints, which is the whole point of a boundary key: Stage 4 can index
        a world's expected evidence on them without knowing what a cell is.
        """
        keys: list[tuple[int, int, int]] = []
        for index, row in enumerate(self.boundary_keys):
            if str(row.get("cell_id", "")) != cell_id:
                continue
            where = f"CrystalKnowledge.boundary_keys[{index}]"
            keys.append(
                (
                    _int_field(row, "relation_family", where=where),
                    _int_field(row, "actor_property_mask", where=where),
                    _int_field(row, "state_delta_mask", where=where),
                )
            )
        return tuple(keys)

    @property
    def is_empty(self) -> bool:
        """True for :data:`EMPTY_KNOWLEDGE` and for a handoff with no cells."""
        return not self.cells

    def to_dict(self) -> dict[str, Any]:
        return {
            "handoff_id": self.handoff_id,
            "handoff_digest": self.handoff_digest,
            "cells": len(self.cells),
            "assurance": len(self.assurance),
            "boundary_keys": len(self.boundary_keys),
            "melt_history": len(self.melt_history),
            "encoder_version": self.encoder_version,
        }


#: The zero-cell value. ``handoff_digest`` is the digest of the empty byte string,
#: which is a real digest of the real (absent) bytes rather than a placeholder
#: string that could be mistaken for a loaded handoff.
EMPTY_KNOWLEDGE = CrystalKnowledge(
    handoff_id="crystal-handoff-absent",
    handoff_digest=digest_of_bytes(b""),
    cells=(),
    assurance=(),
    boundary_keys=(),
    melt_history=(),
    encoder_version="absent",
)


def read_crystal_knowledge(path: Path, *, expected_digest: str | None = None) -> CrystalKnowledge:
    """Parse and validate a crystal handoff file. Raises ``ContractError``.

    ``expected_digest`` is the value ``write_crystal_handoff`` returned to whoever
    wrote the file. Passing it turns "these are probably the cells Stage 3 wrote"
    into a checked claim; omitting it still records the digest, so a later reader
    can compare.
    """
    try:
        size = path.stat().st_size
        if size > MAX_HANDOFF_BYTES:
            raise ContractError(
                f"crystal handoff {path.name} is {size} bytes, cap is {MAX_HANDOFF_BYTES}"
            )
        raw = path.read_bytes()
    except OSError as exc:
        # A missing or unreadable handoff is a supported configuration, so it
        # arrives as the same ContractError as a malformed one and callers need
        # one branch rather than two.
        raise ContractError(f"crystal handoff {path} could not be read: {exc}") from exc
    digest = digest_of_bytes(raw)
    if expected_digest is not None and digest != expected_digest:
        raise ContractError(
            f"crystal handoff {path.name} digest {digest} does not match the "
            f"expected {expected_digest}"
        )
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractError(f"crystal handoff {path.name} is not JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ContractError(
            f"crystal handoff {path.name} must be a JSON object, got {type(payload).__name__}"
        )
    schema_id = payload.get("schema_id")
    if schema_id != CRYSTAL_HANDOFF_V1_ID:
        raise ContractError(
            f"crystal handoff {path.name} declares schema {schema_id!r}, "
            f"Stage 4 reads {CRYSTAL_HANDOFF_V1_ID!r}"
        )
    _require_compatible_interface(payload.get("interface_version"), path=path)
    return CrystalKnowledge(
        handoff_id=str(payload.get("handoff_id", "")),
        handoff_digest=digest,
        cells=_rows(payload, "cells"),
        assurance=_rows(payload, "assurance"),
        boundary_keys=_rows(payload, "boundary_keys"),
        melt_history=_rows(payload, "melt_history"),
        encoder_version=str(payload.get("encoder_version", "")),
    )


def load_or_empty(
    path: Path,
    *,
    expected_digest: str | None = None,
    at_sequence: int = 0,
) -> tuple[CrystalKnowledge, DegradationRecord | None]:
    """Read ``path``, or degrade to :data:`EMPTY_KNOWLEDGE`. **Never raises.**

    Stage 3 being absent is a supported configuration: a host that never
    crystallised anything, or a Stage 3 that was rolled back, must not stop Stage
    4 reasoning from Stage 1 evidence. A corrupt or hostile file is the same
    situation with a record attached, which is why the failure path is one branch
    rather than two.
    """
    try:
        return read_crystal_knowledge(path, expected_digest=expected_digest), None
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException as exc:  # noqa: BLE001 - the whole contract is "never raises"
        record = record_for(
            Subsystem.CRYSTAL_HANDOFF,
            exc,
            at_sequence=at_sequence,
            # The handoff is Stage 3's artefact; Stage 1's evidence references are
            # untouched by failing to read it.
            evidence_preserved=True,
        )
        return EMPTY_KNOWLEDGE, record
