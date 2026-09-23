"""D1.2 (part) — event fusion (spec section 17).

Compound telemetry describing one logical operation must be fused before
intelligence processing. auditd emits SYSCALL + PATH + CWD + EXECVE records for
a single ``execve``; an eBPF probe emits one. Both must produce one
``EvidenceEvent``.

Hard requirement (spec section 28): all queues and caches are bounded, and
overload degrades observability *predictably* rather than OOMing the host. The
assembler therefore has a fixed slot budget and evicts oldest-first, counting
what it dropped instead of growing.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any

from pocketsec.stage1.telemetry.raw_event_v1 import EvidenceEvent, RawEventV1

__all__ = ["AssemblerStats", "EventAssembler"]

#: Default assembly window. Records for one operation arrive within microseconds
#: in practice; a wide window only buys mis-fusion and memory.
DEFAULT_WINDOW_NS = 50_000_000  # 50 ms

#: Hard cap on in-flight partial assemblies.
DEFAULT_MAX_PENDING = 4096


@dataclass
class _Pending:
    key: str
    records: list[RawEventV1] = field(default_factory=list)
    opened_at_ns: int = 0
    expected: int | None = None


@dataclass(frozen=True, slots=True)
class AssemblerStats:
    """Measured, not estimated. Every loss path is counted."""

    fused: int = 0
    expired_partial: int = 0
    evicted_under_pressure: int = 0
    singleton: int = 0
    max_pending_seen: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "fused": self.fused,
            "expired_partial": self.expired_partial,
            "evicted_under_pressure": self.evicted_under_pressure,
            "singleton": self.singleton,
            "max_pending_seen": self.max_pending_seen,
            "lost": self.evicted_under_pressure,
        }


class EventAssembler:
    """Bounded fuser from ``RawEventV1`` records to ``EvidenceEvent``.

    Usage is pull-based: feed records in, collect whatever completed. Call
    :meth:`flush` at end of stream to drain partials — they emit as
    ``partial=True`` rather than being discarded, because a partially observed
    privilege escalation is still worth knowing about.
    """

    def __init__(
        self,
        *,
        window_ns: int = DEFAULT_WINDOW_NS,
        max_pending: int = DEFAULT_MAX_PENDING,
    ) -> None:
        if max_pending < 1:
            raise ValueError("max_pending must be >= 1")
        self._window_ns = window_ns
        self._max_pending = max_pending
        self._pending: OrderedDict[str, _Pending] = OrderedDict()
        self._fused = 0
        self._expired_partial = 0
        self._evicted = 0
        self._singleton = 0
        self._max_pending_seen = 0

    @property
    def pending_count(self) -> int:
        return len(self._pending)

    def stats(self) -> AssemblerStats:
        return AssemblerStats(
            fused=self._fused,
            expired_partial=self._expired_partial,
            evicted_under_pressure=self._evicted,
            singleton=self._singleton,
            max_pending_seen=self._max_pending_seen,
        )

    def feed(self, record: RawEventV1) -> list[EvidenceEvent]:
        """Accept one record; return any operations that completed."""
        completed = self._expire(now_ns=record.monotonic_ns)

        if record.assembly_key is None:
            self._singleton += 1
            completed.append(self._build(_Pending(record.record_id, [record], record.monotonic_ns)))
            return completed

        slot = self._pending.get(record.group_key)
        if slot is None:
            slot = _Pending(key=record.group_key, opened_at_ns=record.monotonic_ns)
            self._pending[record.group_key] = slot
            self._evict_if_over_capacity()
        slot.records.append(record)

        expected = record.fields.get("_expected_records")
        if expected is not None and expected.isdigit():
            slot.expected = int(expected)

        if slot.expected is not None and len(slot.records) >= slot.expected:
            self._pending.pop(record.group_key, None)
            self._fused += 1
            completed.append(self._build(slot))

        self._max_pending_seen = max(self._max_pending_seen, len(self._pending))
        return completed

    def flush(self) -> list[EvidenceEvent]:
        """Drain every pending assembly as partial."""
        drained = [self._build(slot, partial=True) for slot in self._pending.values()]
        self._expired_partial += len(drained)
        self._pending.clear()
        return drained

    # --- internals ------------------------------------------------------

    def _expire(self, *, now_ns: int) -> list[EvidenceEvent]:
        """Close assemblies whose window has passed, as partial."""
        expired: list[EvidenceEvent] = []
        for key in list(self._pending):
            slot = self._pending[key]
            if now_ns - slot.opened_at_ns < self._window_ns:
                # OrderedDict is insertion-ordered and windows are uniform, so
                # the first slot still inside its window ends the scan.
                break
            self._pending.pop(key)
            self._expired_partial += 1
            expired.append(self._build(slot, partial=True))
        return expired

    def _evict_if_over_capacity(self) -> None:
        """Drop oldest pending assemblies to stay inside the hard bound.

        Predictable degradation: under a flood we lose the *oldest* incomplete
        assemblies and count them, rather than growing until the host OOMs.
        """
        while len(self._pending) > self._max_pending:
            self._pending.popitem(last=False)
            self._evicted += 1

    @staticmethod
    def _build(slot: _Pending, *, partial: bool = False) -> EvidenceEvent:
        records = tuple(slot.records)
        first = records[0]
        return EvidenceEvent(
            evidence_id=f"ev-{first.host_id}-{slot.key}",
            host_id=first.host_id,
            boot_id=first.boot_id,
            observed_at_ns=first.observed_at_ns,
            monotonic_ns=first.monotonic_ns,
            records=records,
            partial=partial,
        )
