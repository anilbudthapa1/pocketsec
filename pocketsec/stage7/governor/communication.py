"""D7.18 — the communication governor and Stage 7's resource measurement.

Architecture §28: *the endpoint remains useful offline indefinitely; Stage 7 is an
intelligence accelerator, not a dependency.* The governor is what makes that sentence a
number. It owns every byte and every message that crosses the (simulated) wire in
either direction, per round, and it refuses before anything is parsed.

**Exchange modes** (:class:`ExchangeMode`), with the outbound bytes each may send per
round (:data:`MODE_ROUND_BYTES`):

* ``OFFLINE`` — no exchange in either direction. Inbound is refused as ``partitioned``.
* ``IDLE`` — **zero required peer traffic**: nothing is sent. Inbound is still accepted at
  the ROUTINE cap, because hearing about a threat costs this host nothing it did not choose.
* ``ROUTINE`` — small signed capsule batches, KB-scale.
* ``INCIDENT`` — a bounded burst; it **reverts to ROUTINE by itself** after
  :data:`INCIDENT_MAX_ROUNDS`, so an incident flag nobody clears cannot leave the host in
  burst mode for good.
* ``RESEARCH`` — MB-scale, **refused unless research was explicitly enabled** at
  construction. Off by default (:data:`RESEARCH_ENABLED`).

**Inbound refusals, in the order they are checked**: ``partitioned`` (a partition or
OFFLINE: nothing enters), ``oversize`` (a single message above
``MAX_KNOWLEDGE_CAPSULE_BYTES`` — refused on its length, before a byte of it is parsed),
``peer_count`` and ``peer_bytes`` (one sender's share of a round), ``round_bytes`` (the
round's inbound cap, ``max(ROUTINE, mode)``), and ``inbox_full`` (the inbox's capsule or
byte capacity — or the round having already admitted as many messages as the inbox
holds, which is what bounds the per-round sender table).

What the governor does **not** do: it does not authenticate senders. ``sender`` is the
transport's label for the simulated link, used only to share out bandwidth; a Sybil with
many transport labels gets many per-sender shares and still hits the round and inbox
caps. Senders are never trusted for anything else. Long sender labels are hashed before
they are stored, so a label cannot be used to grow memory.

**Resource measurement** (:func:`measure_stage7_resources`) wraps Stage 0's
:class:`ResourceSampler`, the only RSS source. Incremental RSS is the sampled peak's
growth over the start figure, **floored at 0** (end-minus-start goes negative and crashed
Stage 5's gate). ``within_ceiling`` is ``None`` whenever RSS was unreadable, and
:class:`Stage7ResourceReport` refuses to be constructed with a verdict its own figures do
not support: UNMEASURED is never True. ``loadavg`` rides on every report because this
host is shared; wall and CPU seconds are observations and never asserted.
"""

from __future__ import annotations

import hashlib
import math
import sys
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType

from pocketsec.stage0.benchmark.profiles import ProfileReport, check_profile
from pocketsec.stage0.benchmark.resource_metrics import ResourceSampler
from pocketsec.stage0.contracts.common import ContractError, require_non_negative_int
from pocketsec.stage6.resources import loadavg
from pocketsec.stage7.capsule.knowledge_capsule import MAX_KNOWLEDGE_CAPSULE_BYTES

__all__ = [
    "INBOUND_REFUSALS",
    "INCIDENT_MAX_ROUNDS",
    "MAX_BYTES_PER_PEER_PER_ROUND",
    "MAX_CAPSULES_PER_PEER_PER_ROUND",
    "MAX_INBOX_BYTES",
    "MAX_INBOX_CAPSULES",
    "MODE_ROUND_BYTES",
    "OUTBOUND_REFUSALS",
    "RESEARCH_ENABLED",
    "STAGE7_INCREMENTAL_CEILING_BYTES",
    "STAGE7_INCREMENTAL_NORMAL_BYTES",
    "STAGE7_PROFILE",
    "CommunicationBudget",
    "CommunicationGovernor",
    "ExchangeMode",
    "Stage7ResourceReport",
    "measure_stage7_resources",
]

_MIB = 1024 * 1024


class ExchangeMode(StrEnum):
    OFFLINE = "OFFLINE"
    IDLE = "IDLE"
    ROUTINE = "ROUTINE"
    INCIDENT = "INCIDENT"
    RESEARCH = "RESEARCH"


#: §4.23: outbound bytes each mode may send per round. Chosen, not measured.
MODE_ROUND_BYTES: Mapping[ExchangeMode, int] = MappingProxyType(
    {
        ExchangeMode.OFFLINE: 0,
        ExchangeMode.IDLE: 0,
        ExchangeMode.ROUTINE: 16384,
        ExchangeMode.INCIDENT: 262144,
        ExchangeMode.RESEARCH: 1048576,
    }
)
MAX_BYTES_PER_PEER_PER_ROUND: int = 8192
MAX_CAPSULES_PER_PEER_PER_ROUND: int = 8
MAX_INBOX_CAPSULES: int = 1024
MAX_INBOX_BYTES: int = 4194304
INCIDENT_MAX_ROUNDS: int = 8
RESEARCH_ENABLED: bool = False
#: Architecture §28/§44: "prefer 25-55 MB", "<120 MB initial ceiling". Targets, not facts.
STAGE7_INCREMENTAL_NORMAL_BYTES: int = 55 * _MIB
STAGE7_INCREMENTAL_CEILING_BYTES: int = 120 * _MIB
#: Stage 0's primary 2 GB profile.
STAGE7_PROFILE: str = "edge"

INBOUND_REFUSALS: tuple[str, ...] = (
    "partitioned",
    "oversize",
    "peer_count",
    "peer_bytes",
    "round_bytes",
    "inbox_full",
)
OUTBOUND_REFUSALS: tuple[str, ...] = ("partitioned", "oversize", "round_bytes")

#: Sender labels longer than this are stored as a hash, so a label cannot grow memory.
_MAX_SENDER_LABEL: int = 64


@dataclass(frozen=True, slots=True)
class CommunicationBudget:
    """A snapshot of the governor: the round's caps, what was used, and every refusal so far."""

    mode: ExchangeMode
    round_index: int
    outbound_cap: int
    outbound_used: int
    inbound_cap: int
    inbound_used: int
    inbox_capsules: int
    inbox_bytes: int
    refused: tuple[tuple[str, int], ...]

    def __post_init__(self) -> None:
        for label in (
            "round_index",
            "outbound_cap",
            "outbound_used",
            "inbound_cap",
            "inbound_used",
            "inbox_capsules",
            "inbox_bytes",
        ):
            require_non_negative_int(getattr(self, label), f"CommunicationBudget.{label}")
        # ``used`` may exceed ``cap`` only when the cap was lowered mid-round (a partition
        # or a mode change after sending); it is reported as it happened, never clamped.


def _sender_key(sender: str) -> str:
    if not isinstance(sender, str) or not sender:
        raise ContractError(f"sender must be a non-empty string, got {sender!r}")
    if len(sender) <= _MAX_SENDER_LABEL:
        return sender
    return "h:" + hashlib.sha256(sender.encode("utf-8", "surrogatepass")).hexdigest()[:32]


class CommunicationGovernor:
    """Per-round byte and message budgets for the simulated wire, in both directions."""

    __slots__ = (
        "_inbound_used",
        "_inbox_bytes",
        "_inbox_capsules",
        "_incident_since",
        "_mode",
        "_outbound_used",
        "_partitioned",
        "_per_sender",
        "_refused",
        "_research_enabled",
        "_round",
        "_round_admitted",
    )

    def __init__(
        self, *, mode: ExchangeMode = ExchangeMode.IDLE, research_enabled: bool = RESEARCH_ENABLED
    ) -> None:
        if not isinstance(research_enabled, bool):
            raise ContractError("research_enabled must be a bool")
        self._research_enabled = research_enabled
        self._round = 0
        self._mode = ExchangeMode.IDLE
        self._incident_since: int | None = None
        self._partitioned = False
        self._inbox_capsules = 0
        self._inbox_bytes = 0
        self._refused: Counter[str] = Counter()
        self._reset_round_counters()
        self.set_mode(mode, round_index=0)

    def _reset_round_counters(self) -> None:
        self._inbound_used = 0
        self._outbound_used = 0
        self._round_admitted = 0
        self._per_sender: dict[str, tuple[int, int]] = {}

    @property
    def mode(self) -> ExchangeMode:
        return self._mode

    @property
    def partitioned(self) -> bool:
        return self._partitioned

    def set_mode(self, mode: ExchangeMode, *, round_index: int) -> None:
        """Change the exchange mode. RESEARCH is refused unless research was enabled."""
        if not isinstance(mode, ExchangeMode):
            raise ContractError(f"mode must be an ExchangeMode, got {mode!r}")
        require_non_negative_int(round_index, "round_index")
        if mode is ExchangeMode.RESEARCH and not self._research_enabled:
            raise ContractError("RESEARCH exchange is refused: research_enabled is False")
        self._mode = mode
        self._incident_since = round_index if mode is ExchangeMode.INCIDENT else None

    def begin_round(self, round_index: int) -> None:
        """Start ``round_index``: reset per-round counters and expire a stale INCIDENT mode."""
        require_non_negative_int(round_index, "round_index")
        if round_index < self._round:
            raise ContractError(f"rounds may not run backwards: {round_index} < {self._round}")
        self._round = round_index
        self._reset_round_counters()
        if (
            self._mode is ExchangeMode.INCIDENT
            and self._incident_since is not None
            and round_index - self._incident_since >= INCIDENT_MAX_ROUNDS
        ):
            self._mode = ExchangeMode.ROUTINE
            self._incident_since = None

    def _at_round(self, round_index: int) -> None:
        require_non_negative_int(round_index, "round_index")
        if round_index != self._round:
            self.begin_round(round_index)

    def inbound_cap(self) -> int:
        if self._partitioned or self._mode is ExchangeMode.OFFLINE:
            return 0
        return max(MODE_ROUND_BYTES[ExchangeMode.ROUTINE], MODE_ROUND_BYTES[self._mode])

    def outbound_cap(self) -> int:
        return 0 if self._partitioned else MODE_ROUND_BYTES[self._mode]

    def admit_inbound(self, sender: str, size: int, *, round_index: int) -> str | None:
        """Admit one received message of ``size`` bytes, or name the first refusal.

        Called before the message is parsed; ``size`` is its length on the wire.
        """
        require_non_negative_int(size, "size")
        key = _sender_key(sender)
        self._at_round(round_index)
        reason = self._inbound_refusal(key, size)
        if reason is not None:
            self._refused["inbound:" + reason] += 1
            return reason
        count, used = self._per_sender.get(key, (0, 0))
        self._per_sender[key] = (count + 1, used + size)
        self._inbound_used += size
        self._round_admitted += 1
        self._inbox_capsules += 1
        self._inbox_bytes += size
        return None

    def _inbound_refusal(self, key: str, size: int) -> str | None:
        if self._partitioned or self._mode is ExchangeMode.OFFLINE:
            return "partitioned"
        if size > MAX_KNOWLEDGE_CAPSULE_BYTES:
            return "oversize"
        count, used = self._per_sender.get(key, (0, 0))
        if count + 1 > MAX_CAPSULES_PER_PEER_PER_ROUND:
            return "peer_count"
        if used + size > MAX_BYTES_PER_PEER_PER_ROUND:
            return "peer_bytes"
        if self._inbound_used + size > self.inbound_cap():
            return "round_bytes"
        if (
            self._inbox_capsules + 1 > MAX_INBOX_CAPSULES
            or self._inbox_bytes + size > MAX_INBOX_BYTES
            or self._round_admitted + 1 > MAX_INBOX_CAPSULES
        ):
            return "inbox_full"
        return None

    def admit_outbound(self, size: int, *, round_index: int) -> str | None:
        """Admit ``size`` bytes for sending this round, or name the refusal.

        A mode whose cap is 0 (OFFLINE, IDLE) or a partition refuses every send, even an
        empty one: IDLE means no peer traffic at all.
        """
        require_non_negative_int(size, "size")
        self._at_round(round_index)
        cap = self.outbound_cap()
        if self._partitioned or self._mode is ExchangeMode.OFFLINE:
            reason: str | None = "partitioned"
        elif size > MAX_KNOWLEDGE_CAPSULE_BYTES:
            reason = "oversize"
        elif cap == 0 or self._outbound_used + size > cap:
            reason = "round_bytes"
        else:
            reason = None
        if reason is not None:
            self._refused["outbound:" + reason] += 1
            return reason
        self._outbound_used += size
        return None

    def release(self, count: int, size: int) -> None:
        """The fabric drained ``count`` messages totalling ``size`` bytes from the inbox."""
        require_non_negative_int(count, "count")
        require_non_negative_int(size, "size")
        if count > self._inbox_capsules or size > self._inbox_bytes:
            raise ContractError(
                f"release({count}, {size}) exceeds the inbox "
                f"({self._inbox_capsules} messages, {self._inbox_bytes} bytes)"
            )
        self._inbox_capsules -= count
        self._inbox_bytes -= size

    def partition(self) -> None:
        """Cut the (simulated) link: every inbound and outbound message is refused."""
        self._partitioned = True

    def heal(self, *, round_index: int) -> None:
        """Restore the link, starting a fresh round's counters at ``round_index``."""
        self._partitioned = False
        self.begin_round(max(round_index, self._round))

    def budget(self) -> CommunicationBudget:
        return CommunicationBudget(
            mode=self._mode,
            round_index=self._round,
            outbound_cap=self.outbound_cap(),
            outbound_used=self._outbound_used,
            inbound_cap=self.inbound_cap(),
            inbound_used=self._inbound_used,
            inbox_capsules=self._inbox_capsules,
            inbox_bytes=self._inbox_bytes,
            refused=tuple(sorted(self._refused.items())),
        )

    def senders_this_round(self) -> int:
        """Distinct sender labels admitted this round; never above :data:`MAX_INBOX_CAPSULES`."""
        return len(self._per_sender)

    def memory_bytes(self) -> int:
        """An upper-bound estimate of the governor's state, in bytes."""
        senders = sum(sys.getsizeof(k) + 120 for k in self._per_sender)
        refused = sum(sys.getsizeof(k) + 32 for k in self._refused)
        return senders + refused + sys.getsizeof(self._per_sender) + sys.getsizeof(self._refused)


@dataclass(frozen=True, slots=True)
class Stage7ResourceReport:
    """What one measured Stage 7 block resided in, against the §44 incremental ceiling.

    ``incremental_rss_bytes`` is ``max(0, sampled peak - start)``; ``None`` is UNMEASURED,
    and then ``within_ceiling`` must be ``None`` too. Wall and CPU seconds are
    observations beside ``loadavg`` on a shared host, never device figures.
    """

    peak_sampled_rss_bytes: int | None
    incremental_rss_bytes: int | None
    within_ceiling: bool | None
    profile: ProfileReport | None
    store_bytes: tuple[tuple[str, int], ...]
    loadavg: tuple[float, float, float]
    wall_seconds: float
    cpu_seconds: float

    def __post_init__(self) -> None:
        object.__setattr__(self, "store_bytes", _checked_store_bytes(self.store_bytes))
        if len(self.loadavg) != 3:
            raise ContractError("loadavg must hold the 1, 5 and 15 minute figures")
        object.__setattr__(self, "loadavg", tuple(float(value) for value in self.loadavg))
        for label in ("wall_seconds", "cpu_seconds"):
            value = getattr(self, label)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ContractError(f"{label} must be a number")
            if not math.isfinite(value) or value < 0:
                raise ContractError(f"{label}={value} must be finite and >= 0")
        self._require_honest_verdict()

    def _require_honest_verdict(self) -> None:
        """The point of the type: the verdict is exactly what the figures support."""
        if self.incremental_rss_bytes is None:
            if self.within_ceiling is not None:
                raise ContractError("within_ceiling must be None when RSS is UNMEASURED")
            return
        require_non_negative_int(self.incremental_rss_bytes, "incremental_rss_bytes")
        if self.peak_sampled_rss_bytes is None:
            raise ContractError("an incremental RSS figure needs the peak it was measured from")
        expected = self.incremental_rss_bytes <= STAGE7_INCREMENTAL_CEILING_BYTES
        if self.within_ceiling is not expected:
            raise ContractError(
                f"within_ceiling={self.within_ceiling} contradicts incremental RSS "
                f"{self.incremental_rss_bytes} B against the "
                f"{STAGE7_INCREMENTAL_CEILING_BYTES} B ceiling"
            )

    @property
    def within_normal(self) -> bool | None:
        """Against the 55 MiB preference; ``None`` when unmeasured."""
        if self.incremental_rss_bytes is None:
            return None
        return self.incremental_rss_bytes <= STAGE7_INCREMENTAL_NORMAL_BYTES


def _checked_store_bytes(
    store_bytes: tuple[tuple[str, int], ...] | Mapping[str, int],
) -> tuple[tuple[str, int], ...]:
    items = store_bytes.items() if isinstance(store_bytes, Mapping) else store_bytes
    checked: dict[str, int] = {}
    for name, value in items:
        if not isinstance(name, str) or not name:
            raise ContractError(f"store names must be non-empty strings, got {name!r}")
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ContractError(f"store {name!r} reported {value!r}; memory_bytes is an int >= 0")
        checked[name] = value
    return tuple(sorted(checked.items()))


def measure_stage7_resources(run: Callable[[], Mapping[str, int]]) -> Stage7ResourceReport:
    """Run ``run()`` under Stage 0's sampler; ``run`` returns each store's ``memory_bytes()``.

    The block's peak is the larger of the sampled peak and the end RSS (the end is also a
    point inside the block); incremental is that peak's rise over the start, floored at 0.
    Any unreadable start or peak makes the figure — and the verdict — ``None``.
    """
    sampler = ResourceSampler()
    with sampler:
        store_bytes = run()
    metrics = sampler.result(events_processed=0, startup_seconds=None)
    start = metrics.idle_rss_bytes
    end = (
        None
        if start is None or metrics.delta_rss_bytes is None
        else start + metrics.delta_rss_bytes
    )
    observed = [v for v in (metrics.peak_sampled_rss_bytes, end) if v is not None]
    peak = max(observed) if observed else None
    incremental = None if start is None or peak is None else max(0, peak - start)
    return Stage7ResourceReport(
        peak_sampled_rss_bytes=peak,
        incremental_rss_bytes=incremental,
        within_ceiling=(
            None if incremental is None else incremental <= STAGE7_INCREMENTAL_CEILING_BYTES
        ),
        profile=check_profile(metrics, STAGE7_PROFILE),
        store_bytes=_checked_store_bytes(store_bytes),
        loadavg=loadavg(),
        wall_seconds=metrics.wall_seconds,
        cpu_seconds=metrics.cpu_seconds,
    )
