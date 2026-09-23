"""Benchmark dataset loading with mandatory version + checksum binding.

Fair-comparison rule (spec section 13): the same dataset version and a
leakage-resistant split. A result that cannot name the exact bytes it was
computed over is not a comparable result, so loading verifies the declared
SHA-256 and refuses to proceed on a mismatch.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pocketsec.stage0.contracts.security_event_v1 import SecurityEventSequenceV1

__all__ = ["DatasetError", "LabelledSequence", "SequenceDataset", "sha256_file"]


class DatasetError(RuntimeError):
    """Raised when a dataset is missing, malformed, or fails its checksum."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65_536), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class LabelledSequence:
    """One evaluation item: a bounded window plus its ground-truth label."""

    sequence: SecurityEventSequenceV1
    label: int
    #: Free-text technique tag used for unseen-technique reporting. Stage 0 does
    #: not fix a taxonomy (non-goal 6), so this is metadata, never a model input.
    technique: str | None = None
    #: True when this item's technique is absent from the training split.
    unseen_technique: bool = False

    def __post_init__(self) -> None:
        if self.label not in (0, 1):
            raise DatasetError(f"label must be 0 or 1, got {self.label!r}")


@dataclass(frozen=True, slots=True)
class SequenceDataset:
    """An immutable, checksum-verified split."""

    name: str
    version: str
    sha256: str
    path: Path
    items: tuple[LabelledSequence, ...]

    def __len__(self) -> int:
        return len(self.items)

    def __iter__(self) -> Iterator[LabelledSequence]:
        return iter(self.items)

    @property
    def event_count(self) -> int:
        return sum(len(item.sequence.events) for item in self.items)

    @property
    def positive_count(self) -> int:
        return sum(1 for item in self.items if item.label == 1)

    def to_provenance(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "sha256": self.sha256,
            "path": str(self.path),
            "item_count": len(self.items),
            "event_count": self.event_count,
            "positive_count": self.positive_count,
        }

    @classmethod
    def load_jsonl(
        cls, path: Path, *, name: str, version: str, expected_sha256: str | None = None
    ) -> SequenceDataset:
        """Load a JSONL split, verifying its checksum before parsing."""
        path = Path(path)
        if not path.is_file():
            raise DatasetError(f"dataset file not found: {path}")

        actual = sha256_file(path)
        if expected_sha256 is not None and actual != expected_sha256:
            raise DatasetError(
                f"dataset checksum mismatch for {path}: "
                f"expected {expected_sha256}, measured {actual}. "
                "Results computed over different bytes are not comparable."
            )

        items = tuple(cls._parse_lines(path))
        if not items:
            raise DatasetError(f"dataset {path} contains no items")
        return cls(name=name, version=version, sha256=actual, path=path, items=items)

    @staticmethod
    def _parse_lines(path: Path) -> Iterator[LabelledSequence]:
        with open(path, encoding="utf-8") as handle:
            for number, raw in enumerate(handle, start=1):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    payload = json.loads(line)
                    yield LabelledSequence(
                        sequence=SecurityEventSequenceV1.from_dict(payload["sequence"]),
                        label=int(payload["label"]),
                        technique=payload.get("technique"),
                        unseen_technique=bool(payload.get("unseen_technique", False)),
                    )
                except (KeyError, ValueError, TypeError) as exc:
                    raise DatasetError(f"{path}:{number}: {exc}") from exc
