"""D0.4 — the append-only experiment registry.

The registry is a JSONL ledger. It exposes ``register``, ``get``, ``all`` and
``verify_integrity`` — and deliberately exposes no update or delete. Stage 0
hard rule: do not delete prior research artifacts, counterexamples, provenance
or rollback information. A refuted experiment stays in the ledger; that is the
point of it.

Tamper-evidence: each entry stores a digest over its own canonical content plus
the previous entry's digest, so any edit to history breaks the chain from that
point forward.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from pocketsec.stage0.contracts.common import digest_of_bytes
from pocketsec.stage0.experiments.ids import parse_experiment_id

__all__ = ["ExperimentEntry", "ExperimentRegistry", "RegistryError"]

GENESIS_DIGEST = "sha256:" + "0" * 64


class RegistryError(RuntimeError):
    """Raised on duplicate ids, malformed entries, or a broken digest chain."""


@dataclass(frozen=True, slots=True)
class ExperimentEntry:
    """One immutable ledger row."""

    experiment_id: str
    hypothesis: str
    title: str
    slot_name: str
    dataset_name: str
    dataset_version: str
    dataset_sha256: str
    git_commit: str | None
    seeds: Mapping[str, int]
    synthetic_data: bool
    recorded_at_ns: int
    notes: str = ""
    result_path: str | None = None
    previous_digest: str = GENESIS_DIGEST
    entry_digest: str = ""

    def content_payload(self) -> dict[str, Any]:
        """The canonical, digest-covered content of this entry."""
        return {
            "experiment_id": self.experiment_id,
            "hypothesis": self.hypothesis,
            "title": self.title,
            "slot_name": self.slot_name,
            "dataset_name": self.dataset_name,
            "dataset_version": self.dataset_version,
            "dataset_sha256": self.dataset_sha256,
            "git_commit": self.git_commit,
            "seeds": dict(self.seeds),
            "synthetic_data": self.synthetic_data,
            "recorded_at_ns": self.recorded_at_ns,
            "notes": self.notes,
            "result_path": self.result_path,
            "previous_digest": self.previous_digest,
        }

    def compute_digest(self) -> str:
        canonical = json.dumps(self.content_payload(), sort_keys=True, separators=(",", ":"))
        return digest_of_bytes(canonical.encode("utf-8"))

    def to_dict(self) -> dict[str, Any]:
        return {**self.content_payload(), "entry_digest": self.entry_digest}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ExperimentEntry:
        try:
            return cls(
                experiment_id=str(payload["experiment_id"]),
                hypothesis=str(payload["hypothesis"]),
                title=str(payload["title"]),
                slot_name=str(payload["slot_name"]),
                dataset_name=str(payload["dataset_name"]),
                dataset_version=str(payload["dataset_version"]),
                dataset_sha256=str(payload["dataset_sha256"]),
                git_commit=payload.get("git_commit"),
                seeds=dict(payload.get("seeds") or {}),
                synthetic_data=bool(payload["synthetic_data"]),
                recorded_at_ns=int(payload["recorded_at_ns"]),
                notes=str(payload.get("notes", "")),
                result_path=payload.get("result_path"),
                previous_digest=str(payload.get("previous_digest", GENESIS_DIGEST)),
                entry_digest=str(payload.get("entry_digest", "")),
            )
        except KeyError as exc:
            raise RegistryError(f"registry entry missing field {exc.args[0]!r}") from exc


class ExperimentRegistry:
    """Append-only JSONL ledger of every experiment ever run."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    # --- reads ---------------------------------------------------------

    def all(self) -> tuple[ExperimentEntry, ...]:
        return tuple(self._iter_entries())

    def get(self, experiment_id: str) -> ExperimentEntry | None:
        for entry in self._iter_entries():
            if entry.experiment_id == experiment_id:
                return entry
        return None

    def _iter_entries(self) -> Iterator[ExperimentEntry]:
        if not self.path.is_file():
            return
        with open(self.path, encoding="utf-8") as handle:
            for number, raw in enumerate(handle, start=1):
                line = raw.strip()
                if not line:
                    continue
                try:
                    yield ExperimentEntry.from_dict(json.loads(line))
                except (json.JSONDecodeError, RegistryError) as exc:
                    raise RegistryError(f"{self.path}:{number}: {exc}") from exc

    # --- append --------------------------------------------------------

    def register(
        self,
        *,
        experiment_id: str,
        hypothesis: str,
        title: str,
        slot_name: str,
        dataset_name: str,
        dataset_version: str,
        dataset_sha256: str,
        git_commit: str | None,
        seeds: Mapping[str, int],
        synthetic_data: bool,
        notes: str = "",
        result_path: str | None = None,
    ) -> ExperimentEntry:
        """Append one entry. Raises if the id was already used."""
        parse_experiment_id(experiment_id)
        existing = self.all()
        if any(entry.experiment_id == experiment_id for entry in existing):
            raise RegistryError(
                f"experiment id {experiment_id!r} is already registered; "
                "ids are immutable and never reused"
            )

        entry = ExperimentEntry(
            experiment_id=experiment_id,
            hypothesis=hypothesis,
            title=title,
            slot_name=slot_name,
            dataset_name=dataset_name,
            dataset_version=dataset_version,
            dataset_sha256=dataset_sha256,
            git_commit=git_commit,
            seeds=dict(seeds),
            synthetic_data=synthetic_data,
            recorded_at_ns=time.time_ns(),
            notes=notes,
            result_path=result_path,
            previous_digest=existing[-1].entry_digest if existing else GENESIS_DIGEST,
        )
        sealed = replace(entry, entry_digest=entry.compute_digest())
        self._append(sealed)
        return sealed

    def _append(self, entry: ExperimentEntry) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(entry.to_dict(), sort_keys=True, separators=(",", ":"))
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
            handle.flush()
            os.fsync(handle.fileno())

    # --- integrity -----------------------------------------------------

    def verify_integrity(self) -> list[str]:
        """Return a list of problems; empty means the ledger is intact.

        The chain is walked over **recomputed** digests, not the stored ones, so
        editing any entry's content invalidates every link after it. Verifying
        against stored digests would let a single-row edit slip through with
        only a local digest mismatch.

        This is tamper-*evident*, not tamper-proof: someone who rewrites every
        subsequent entry consistently can still forge history. Detecting that
        needs an external anchor (a signature, or the digest published
        elsewhere), which Stage 0 does not have. The threat model here is
        accidental or casual rewriting, and that is what it catches.
        """
        problems: list[str] = []
        seen: set[str] = set()
        previous = GENESIS_DIGEST
        for index, entry in enumerate(self._iter_entries()):
            label = f"entry {index} ({entry.experiment_id})"
            if entry.experiment_id in seen:
                problems.append(f"{label}: duplicate experiment id")
            seen.add(entry.experiment_id)
            if entry.previous_digest != previous:
                problems.append(
                    f"{label}: chain break - expected previous digest {previous}, "
                    f"found {entry.previous_digest}"
                )
            recomputed = entry.compute_digest()
            if entry.entry_digest != recomputed:
                problems.append(f"{label}: content was modified after it was recorded")
            previous = recomputed
        return problems
