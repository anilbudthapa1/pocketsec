"""D6.3 — the provenance / trust ledger: one bounded record per admitted capsule.

Architecture §7 binds a row per capsule: source class, epoch, independence group,
visibility, label origin, transformation lineage, hash, contamination risk. The ledger
is that table, and it exists so every later decision can ask *where did this come from
and how many independent sources said it* — the question Stage 2 cannot answer.

What it refuses to be:

* **Trusted state.** A record describes a capsule; it changes nothing the endpoint
  believes. Nothing here imports ``memory/`` or ``promotion/``.
* **Unbounded.** At ``capacity`` the OLDEST record is evicted, counted and logged
  (bounded log). This is the opposite of Stage 2's refuse-the-newcomer rule, and the
  asymmetry is deliberate: the ledger is a lookup table, not a waiting queue, so an
  attacker flooding it gains nothing by evicting old records — **a promotion whose
  lineage the ledger has forgotten fails** (architecture §41, "unknown lineage blocks
  promotion"). :meth:`ProvenanceLedger.get` returns ``None`` after eviction, and
  callers must treat ``None`` as refusal, never as "no objection".
* **A second content address.** ``TrustRecord.capsule_id`` is the capsule's own id and
  ``content_digest`` is ``capsule.digest()``; Rule A tests they are the same strings.

``step_groups`` holds at most ``MAX_STEP_GROUPS`` distinct lineages. Cutting it can
only *under*-count independence, which makes dependence more likely to be reported —
the fail-closed direction — and every cut is counted in :class:`LedgerStats`.
"""

from __future__ import annotations

import sys
from collections import OrderedDict, deque
from collections.abc import Iterable
from dataclasses import dataclass, fields
from typing import Any

from pocketsec.stage0.contracts.common import (
    ContractError,
    require_finite_unit_interval,
    require_identifier,
)
from pocketsec.stage6.capsule.experience_capsule import (
    ExperienceCapsuleV1,
    LabelOrigin,
    SourceClass,
)
from pocketsec.stage6.provenance.trust import ProvenanceScore

__all__ = [
    "MAX_EVICTION_LOG",
    "MAX_STEP_GROUPS",
    "MAX_TRUST_RECORDS",
    "LedgerStats",
    "ProvenanceLedger",
    "TrustRecord",
]

#: §4.21. Chosen parameter.
MAX_TRUST_RECORDS: int = 4096
#: §D6.3: ``step_groups`` holds at most this many distinct lineages. Chosen.
MAX_STEP_GROUPS: int = 16
#: Most recent evicted capsule ids kept for audit; the eviction COUNT never resets.
MAX_EVICTION_LOG: int = 128


@dataclass(frozen=True, slots=True)
class TrustRecord:
    """Architecture §7, every row bound. Immutable; the ledger never edits a record."""

    capsule_id: str
    source_class: SourceClass
    source_id: str
    independence_group: str
    epoch_id: int
    visibility: float
    label_origin: LabelOrigin
    transformation_lineage: tuple[str, ...]
    content_digest: str
    contamination_risk: float
    provenance_score: float
    step_groups: tuple[str, ...]
    recorded_sequence: int

    def __post_init__(self) -> None:
        for name in ("capsule_id", "source_id", "independence_group"):
            require_identifier(getattr(self, name), f"TrustRecord.{name}")
        if not isinstance(self.source_class, SourceClass):
            raise ContractError("TrustRecord.source_class must be a SourceClass")
        if not isinstance(self.label_origin, LabelOrigin):
            raise ContractError("TrustRecord.label_origin must be a LabelOrigin")
        for name in ("epoch_id", "recorded_sequence"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ContractError(f"TrustRecord.{name} must be a non-negative int")
        for name in ("visibility", "contamination_risk", "provenance_score"):
            require_finite_unit_interval(getattr(self, name), f"TrustRecord.{name}")
        digest = self.content_digest
        if not isinstance(digest, str) or not digest.startswith("sha256:"):
            raise ContractError("TrustRecord.content_digest must be a sha256: digest")
        groups = tuple(self.step_groups)
        if len(groups) > MAX_STEP_GROUPS or list(groups) != sorted(set(groups)):
            raise ContractError(f"step_groups must be sorted, distinct, <= {MAX_STEP_GROUPS}")
        object.__setattr__(self, "step_groups", groups)
        object.__setattr__(self, "transformation_lineage", tuple(self.transformation_lineage))

    def to_dict(self) -> dict[str, Any]:
        row: dict[str, Any] = {}
        for item in fields(self):
            value = getattr(self, item.name)
            row[item.name] = list(value) if isinstance(value, tuple) else value
        row["source_class"] = self.source_class.value
        row["label_origin"] = self.label_origin.value
        return row


@dataclass(frozen=True, slots=True)
class LedgerStats:
    records: int
    evicted: int
    memory_bytes: int
    capacity: int
    step_groups_truncated: int


def _record_bytes(record: TrustRecord) -> int:
    """An upper-bound estimate from ``sys.getsizeof`` (the Stage 2 precedent).

    Counts the record object, every field value, every string inside a tuple field, and
    a fixed 128 B for the OrderedDict entry (key pointer, links, hash). An estimate, not
    an RSS measurement; ``resources.measure_stage6_resources`` owns the latter.
    """
    total = sys.getsizeof(record) + 128
    for item in fields(record):
        value = getattr(record, item.name)
        total += sys.getsizeof(value)
        if isinstance(value, tuple):
            total += sum(sys.getsizeof(entry) for entry in value)
    return total


class ProvenanceLedger:
    """Bounded map ``capsule_id -> TrustRecord``, oldest evicted first, every eviction counted."""

    def __init__(self, *, capacity: int = MAX_TRUST_RECORDS) -> None:
        if isinstance(capacity, bool) or not isinstance(capacity, int) or capacity < 1:
            raise ValueError(f"capacity must be an int >= 1, got {capacity!r}")
        self._capacity = capacity
        self._records: OrderedDict[str, TrustRecord] = OrderedDict()
        self._bytes: dict[str, int] = {}
        self._evicted = 0
        self._eviction_log: deque[str] = deque(maxlen=MAX_EVICTION_LOG)
        self._sequence = 0
        self._groups_truncated = 0

    def record(self, capsule: ExperienceCapsuleV1, *, score: ProvenanceScore) -> TrustRecord:
        """Record one capsule's provenance, evicting the oldest record if full.

        Re-recording a capsule already held returns the held record unchanged: a capsule
        id is a content address, so the same id is the same content. A different score
        for the same capsule is refused, because one of the two scorers is wrong and
        silently keeping either would hide which.
        """
        if not isinstance(capsule, ExperienceCapsuleV1):
            raise ContractError(f"the ledger records capsules, got {type(capsule).__name__}")
        if not isinstance(score, ProvenanceScore):
            raise ContractError(f"score must be a ProvenanceScore, got {type(score).__name__}")
        held = self._records.get(capsule.capsule_id)
        if held is not None:
            if held.provenance_score != score.score:
                raise ContractError(f"{capsule.capsule_id} re-recorded with a different score")
            return held
        record = self._build(capsule, score)
        while len(self._records) >= self._capacity:
            oldest, _ = self._records.popitem(last=False)
            del self._bytes[oldest]
            self._evicted += 1
            self._eviction_log.append(oldest)
        self._records[record.capsule_id] = record
        self._bytes[record.capsule_id] = _record_bytes(record)
        return record

    def _build(self, capsule: ExperienceCapsuleV1, score: ProvenanceScore) -> TrustRecord:
        groups = sorted({step.source_group for step in capsule.steps})
        if len(groups) > MAX_STEP_GROUPS:
            self._groups_truncated += 1
        provenance = capsule.source_provenance
        self._sequence += 1
        return TrustRecord(
            capsule_id=capsule.capsule_id,
            source_class=provenance.source_class,
            source_id=provenance.source_id,
            independence_group=provenance.independence_group,
            epoch_id=capsule.epoch_id,
            visibility=capsule.visibility,
            label_origin=provenance.label_origin,
            transformation_lineage=provenance.transformation_lineage,
            content_digest=capsule.digest(),
            contamination_risk=score.contamination_risk,
            provenance_score=score.score,
            step_groups=tuple(groups[:MAX_STEP_GROUPS]),
            recorded_sequence=self._sequence,
        )

    def get(self, capsule_id: str) -> TrustRecord | None:
        """The record, or ``None`` if never recorded or evicted. ``None`` blocks promotion."""
        return self._records.get(capsule_id)

    def records_for(self, capsule_ids: Iterable[str]) -> tuple[TrustRecord, ...]:
        """Held records for ``capsule_ids``, in the order asked; unknown ids are skipped.

        Skipping is not approval: callers that need every id resolved use
        :meth:`missing`, which names exactly the ids this returned nothing for.
        """
        return tuple(r for r in (self._records.get(cid) for cid in capsule_ids) if r is not None)

    def missing(self, capsule_ids: Iterable[str]) -> tuple[str, ...]:
        """The ids this ledger holds no record for (evicted or never seen)."""
        return tuple(cid for cid in capsule_ids if cid not in self._records)

    def evicted(self) -> int:
        return self._evicted

    def recent_evictions(self) -> tuple[str, ...]:
        """The last ``MAX_EVICTION_LOG`` evicted capsule ids, oldest first."""
        return tuple(self._eviction_log)

    def memory_bytes(self) -> int:
        log = sum(sys.getsizeof(cid) for cid in self._eviction_log)
        return sum(self._bytes.values()) + log + sys.getsizeof(self._records)

    def __len__(self) -> int:
        return len(self._records)

    def stats(self) -> LedgerStats:
        return LedgerStats(
            records=len(self._records),
            evicted=self._evicted,
            memory_bytes=self.memory_bytes(),
            capacity=self._capacity,
            step_groups_truncated=self._groups_truncated,
        )
