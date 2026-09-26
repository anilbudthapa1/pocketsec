"""D5.16 — the D3FEND adapter. Vocabulary, never a decision oracle.

MITRE says it itself, and architecture §28 quotes it: D3FEND "does not prescribe
countermeasures, prioritize them or characterize their effectiveness". So this module can
say *what a defensive technique is called* and nothing about whether to run it. No
privileged module imports it — ``tests/test_stage5_boundary.py`` and this package's own
``test_no_privileged_module_imports_d3fend`` assert that by AST — so even a poisoned
snapshot cannot reach an authority decision.

**The policy, and it is not negotiable: a wrong external identifier is worse than an
absent one.** No D3FEND id is written into this repository from memory. A
:class:`D3FENDMapping` is unconstructable unless a dated snapshot of a real D3FEND release
sits at :data:`D3FEND_SNAPSHOT_PATH` and contains the id, and there is no second code path
that produces one. This environment assumes no network access, so the expected and correct
outcome is:

    load_snapshot() is None;  mapped_fraction() == 0.0;  0 of 14 operators mapped.

That number is a *result*, not a gap to be filled with plausible-looking ids. The findings
document records it as "0 of 14 mapped, 14 UNMAPPED" (ADR-0047).

:data:`D3FEND_RELEASE` stays ``None`` for the same reason: pinning a release string with no
snapshot behind it would be the same fabrication in a different field.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage0.gate import REPO_ROOT
from pocketsec.stage5.operators.d3fend_ids import D3FEND_ID_PATTERN, UNMAPPED

__all__ = [
    "D3FEND_ID_PATTERN",
    "D3FEND_RELEASE",
    "D3FEND_SNAPSHOT_PATH",
    "MAX_SNAPSHOT_TECHNIQUES",
    "UNMAPPED",
    "D3FENDMapping",
    "D3FENDSnapshot",
    "load_snapshot",
    "mapped_fraction",
    "mapping_for",
    "unmapped_operator_ids",
]

# UNMAPPED and D3FEND_ID_PATTERN live in ``d3fend_ids.py`` (finding S5-SEC-11): the
# operator algebra validates every catalog entry against them, and importing THIS module
# from there pulled ``stage0.gate`` — the experiment registry, the prior-art ledger and the
# benchmark profiles — into the privileged executor's and SENTINEL's import graph.

#: Where a committed snapshot must live. Absent in this repository, on purpose.
D3FEND_SNAPSHOT_PATH: Path = REPO_ROOT / "baselines" / "d3fend-technique-ids.json"

#: ``None`` until a real snapshot is committed. A release string without a snapshot is a
#: fabricated provenance claim.
D3FEND_RELEASE: str | None = None

#: Bounded, like all endpoint state. D3FEND's published catalogue is a few hundred
#: techniques; a file larger than this is refused rather than truncated silently.
MAX_SNAPSHOT_TECHNIQUES: int = 1024


@dataclass(frozen=True, slots=True)
class D3FENDSnapshot:
    """A dated, provenance-carrying copy of a D3FEND release's technique names."""

    release: str
    technique_names: Mapping[str, str]
    source_note: str

    def __post_init__(self) -> None:
        if not isinstance(self.release, str) or not self.release.strip():
            raise ContractError("D3FENDSnapshot.release must be a non-empty release string")
        if not isinstance(self.source_note, str) or not self.source_note.strip():
            raise ContractError(
                "D3FENDSnapshot.source_note must record where the snapshot came from; "
                "a snapshot without provenance is an assertion, not evidence"
            )
        if not isinstance(self.technique_names, Mapping) or not self.technique_names:
            raise ContractError("D3FENDSnapshot.technique_names must be a non-empty mapping")
        if len(self.technique_names) > MAX_SNAPSHOT_TECHNIQUES:
            raise ContractError(
                f"D3FENDSnapshot holds {len(self.technique_names)} techniques, "
                f"bound is {MAX_SNAPSHOT_TECHNIQUES}"
            )
        frozen: dict[str, str] = {}
        for technique_id, name in self.technique_names.items():
            if not isinstance(technique_id, str) or not D3FEND_ID_PATTERN.fullmatch(technique_id):
                raise ContractError(
                    f"D3FEND technique id {technique_id!r} does not match "
                    f"{D3FEND_ID_PATTERN.pattern}"
                )
            if not isinstance(name, str) or not name.strip():
                raise ContractError(f"D3FEND technique {technique_id} has no published name")
            frozen[technique_id] = name
        object.__setattr__(self, "technique_names", MappingProxyType(frozen))

    def to_dict(self) -> dict[str, Any]:
        return {
            "release": self.release,
            "source_note": self.source_note,
            "technique_count": len(self.technique_names),
        }


@dataclass(frozen=True, slots=True)
class D3FENDMapping:
    """One operator's link into the external vocabulary.

    Unconstructable without a snapshot that contains the id at the stated release. There
    is deliberately no ``force``, no ``unchecked`` classmethod and no default release: the
    only way to get a mapping is to have the published data on disk.
    """

    operator_id: str
    technique_id: str
    technique_name: str
    release: str

    def __post_init__(self) -> None:
        if not D3FEND_ID_PATTERN.fullmatch(self.technique_id):
            raise ContractError(
                f"technique_id {self.technique_id!r} does not match "
                f"{D3FEND_ID_PATTERN.pattern}"
            )
        snapshot = load_snapshot()
        if snapshot is None:
            raise ContractError(
                "no D3FEND snapshot is committed, so no mapping can be constructed; "
                f"every operator stays {UNMAPPED} (ADR-0047)"
            )
        if self.technique_id not in snapshot.technique_names:
            raise ContractError(
                f"technique_id {self.technique_id!r} is not in the committed snapshot "
                f"for release {snapshot.release!r}"
            )
        if self.release != snapshot.release:
            raise ContractError(
                f"mapping claims release {self.release!r}, snapshot is {snapshot.release!r}"
            )
        published = snapshot.technique_names[self.technique_id]
        if self.technique_name != published:
            raise ContractError(
                f"technique_name {self.technique_name!r} disagrees with the published "
                f"name {published!r}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "operator_id": self.operator_id,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "release": self.release,
        }


def load_snapshot(path: Path | None = None) -> D3FENDSnapshot | None:
    """The committed snapshot, or ``None`` when there is not one.

    ``path`` defaults to :data:`D3FEND_SNAPSHOT_PATH` read at *call* time, not at
    definition time. The spec writes the default into the signature; binding it there would
    freeze the path into the function object, and then the only way to exercise the mapping
    path at all would be to commit a snapshot — which would mean inventing technique ids to
    test the machinery that exists to stop technique ids being invented.

    ``None`` means "no external vocabulary is available", which is a fine state to run in:
    Stage 5 decides from typed evidence and capability tokens, and the technique id is a
    label on the outcome. A malformed file raises rather than returning ``None`` — a
    corrupt snapshot is a different situation from an absent one and must not be silently
    read as the benign case.
    """
    path = D3FEND_SNAPSHOT_PATH if path is None else path
    if not path.is_file():
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping):
        raise ContractError(f"{path} must hold a JSON object")
    release = payload.get("release")
    names = payload.get("technique_names")
    source_note = payload.get("source_note")
    if not isinstance(release, str) or not isinstance(names, Mapping):
        raise ContractError(f"{path} must hold 'release' and 'technique_names'")
    if not isinstance(source_note, str):
        raise ContractError(f"{path} must record 'source_note' provenance")
    return D3FENDSnapshot(
        release=release,
        technique_names={str(key): str(value) for key, value in names.items()},
        source_note=source_note,
    )


def mapping_for(operator_id: str) -> D3FENDMapping | None:
    """The mapping for one operator, or ``None`` when it is ``UNMAPPED``.

    ``None`` is the honest answer for every entry in this repository today.
    """
    # Deferred so this module has no import-time dependency on the catalog, which keeps
    # the arrow pointing from the adapter at the algebra and never the other way.
    from pocketsec.stage5.operators.catalog import CATALOG

    entry = CATALOG.get(operator_id)
    if entry is None:
        raise ContractError(f"unknown operator id {operator_id!r}")
    if entry.d3fend_technique_id == UNMAPPED:
        return None
    snapshot = load_snapshot()
    if snapshot is None:
        return None
    return D3FENDMapping(
        operator_id=operator_id,
        technique_id=entry.d3fend_technique_id,
        technique_name=snapshot.technique_names[entry.d3fend_technique_id],
        release=snapshot.release,
    )


def mapped_fraction() -> float:
    """Fraction of catalog operators carrying a verified D3FEND technique id.

    Expected to be ``0.0``. That is a measured coverage result, and it is reported as one.
    """
    from pocketsec.stage5.operators.catalog import CATALOG

    if not CATALOG:  # pragma: no cover - an empty catalog is an ImportError upstream
        return 0.0
    mapped = sum(1 for operator_id in CATALOG if mapping_for(operator_id) is not None)
    return mapped / len(CATALOG)


def unmapped_operator_ids() -> tuple[str, ...]:
    """Every operator with no verified technique id, sorted."""
    from pocketsec.stage5.operators.catalog import CATALOG

    return tuple(
        sorted(
            operator_id
            for operator_id in CATALOG
            if mapping_for(operator_id) is None
        )
    )
