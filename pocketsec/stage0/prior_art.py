"""D0.7 — the literature / prior-art ledger.

Stage 0 principle: "no novelty claim without literature and, before publication
or patenting, patent/prior-art review." The ledger is the machine-readable side
of that rule — every hypothesis must have an entry, and an entry may only be
marked ``REVIEWED`` when it actually cites something.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from pocketsec.stage0.hypotheses import HYPOTHESES

__all__ = ["LEDGER_PATH", "PriorArtEntry", "PriorArtLedger", "ReviewStatus"]

LEDGER_PATH = Path(__file__).resolve().parents[2] / "docs" / "prior-art" / "ledger.json"


class ReviewStatus(StrEnum):
    NOT_REVIEWED = "NOT_REVIEWED"
    IN_PROGRESS = "IN_PROGRESS"
    REVIEWED = "REVIEWED"


@dataclass(frozen=True, slots=True)
class PriorArtEntry:
    hypothesis_id: str
    claim: str
    literature_status: ReviewStatus
    patent_status: ReviewStatus
    related_work: tuple[str, ...]
    notes: str = ""

    @property
    def novelty_claim_permitted(self) -> bool:
        """A novelty claim needs both reviews done and at least one citation."""
        return (
            self.literature_status is ReviewStatus.REVIEWED
            and self.patent_status is ReviewStatus.REVIEWED
            and bool(self.related_work)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "claim": self.claim,
            "literature_status": self.literature_status.value,
            "patent_status": self.patent_status.value,
            "related_work": list(self.related_work),
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> PriorArtEntry:
        return cls(
            hypothesis_id=str(payload["hypothesis_id"]),
            claim=str(payload["claim"]),
            literature_status=ReviewStatus(payload["literature_status"]),
            patent_status=ReviewStatus(payload["patent_status"]),
            related_work=tuple(str(item) for item in payload.get("related_work", ())),
            notes=str(payload.get("notes", "")),
        )


@dataclass(frozen=True, slots=True)
class PriorArtLedger:
    entries: Mapping[str, PriorArtEntry]

    @classmethod
    def load(cls, path: Path | None = None) -> PriorArtLedger:
        target = Path(path or LEDGER_PATH)
        if not target.is_file():
            raise FileNotFoundError(f"prior-art ledger not found: {target}")
        payload = json.loads(target.read_text(encoding="utf-8"))
        entries = {
            item["hypothesis_id"]: PriorArtEntry.from_dict(item)
            for item in payload.get("entries", ())
        }
        return cls(entries=entries)

    def missing_hypotheses(self) -> list[str]:
        """Hypotheses with no ledger entry at all."""
        return sorted(set(HYPOTHESES) - set(self.entries))

    def inconsistencies(self) -> list[str]:
        """Entries whose review status is not backed by citations."""
        problems = [f"{hid}: no prior-art entry" for hid in self.missing_hypotheses()]
        for entry in self.entries.values():
            if entry.hypothesis_id not in HYPOTHESES:
                problems.append(f"{entry.hypothesis_id}: entry for unknown hypothesis")
            if entry.literature_status is ReviewStatus.REVIEWED and not entry.related_work:
                problems.append(
                    f"{entry.hypothesis_id}: marked REVIEWED but cites no related work"
                )
        return problems
