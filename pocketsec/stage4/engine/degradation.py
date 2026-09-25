"""D4.17 — what Stage 4 does when Stage 4 breaks.

Stage 4 is an *attachment*, not a layer. Stages 1–3 must keep producing their
verdicts when the cognition above them raises, so every call into a Stage 4
subsystem is made through :class:`guarded`, which converts a failure into a
recorded :class:`DegradationRecord` plus a declared fallback value. Gate
criterion G4.11 ("Stage 4 remains optional to core Stage 1–3 detection if it
crashes") is measured against this module, and it is built before the cognition
because an isolation property that arrives last has never held.

Three things this module refuses to do, each for its own reason:

* **It never converts uncertainty into a benign resolution.** Architecture §45's
  first rule says so about OOM pressure, and the same logic covers every other
  failure: a subsystem that crashed did not observe anything reassuring.
  :func:`downgrade_verdict` is the mechanism, and it is the invariant with the
  most hostile test behind it.
* **It never stores a traceback.** ``DegradationRecord.message`` is one line of
  at most :data:`MAX_DEGRADATION_MESSAGE` characters. A traceback is unbounded
  attacker-influenced text on a 2 GB host, and it names file paths a resolution
  handed to Stage 5 has no business carrying.
* **It never lets a record claim a fallback rule that is not §45's.** The
  ``fallback`` string is checked against :data:`FALLBACKS` at construction, so
  "the right fallback was applied" is a type property rather than a promise in a
  test.

:data:`FALLBACKS` exists because §45 is prose with seven rules and this enum has
ten members. Three entries (``CLAIM_COMPILER``, ``SEQUENTIAL_EVIDENCE``,
``CRYSTAL_HANDOFF``) are *derived* rather than quoted, and each is labelled as
such in the table. Code consults the table; nobody consults their memory of a
document.
"""

from __future__ import annotations

import functools
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType, TracebackType
from typing import Any, TypeVar

from pocketsec.stage0.contracts.common import (
    ContractError,
    require_non_negative_int,
)
from pocketsec.stage0.contracts.threat_prediction_v1 import (
    NON_COMMITTAL_VERDICTS,
    Verdict,
)

__all__ = [
    "DEGRADED_VERDICT",
    "DegradationLedger",
    "DegradationRecord",
    "FALLBACKS",
    "FALLBACK_SOURCES",
    "MAX_DEGRADATION_MESSAGE",
    "MAX_DEGRADATION_RECORDS",
    "Subsystem",
    "downgrade_verdict",
    "guarded",
    "record_for",
]

#: One line, bounded. Never a traceback (see the module docstring).
MAX_DEGRADATION_MESSAGE: int = 240

#: Endpoint state is bounded (MEMORY.md invariant). A subsystem is disabled after
#: its first failure, so ten subsystems cannot fill this by themselves; the cap
#: exists for the caller that re-attaches per incident and never drains.
MAX_DEGRADATION_RECORDS: int = 64

#: Where a degraded run lands when it would otherwise have committed. UNKNOWN
#: rather than INSUFFICIENT_EVIDENCE: the evidence may well have been sufficient,
#: it is the *reasoning* that did not complete, and conflating the two would
#: misreport a crash as a gap in telemetry.
DEGRADED_VERDICT: Verdict = Verdict.UNKNOWN


class Subsystem(StrEnum):
    """The ten Stage 4 subsystems a failure can be attributed to.

    Closed on purpose. A new subsystem needs a new :data:`FALLBACKS` row, which
    forces whoever adds it to say what happens when it breaks.
    """

    WORLD_LIFECYCLE = "WORLD_LIFECYCLE"
    CLAIM_COMPILER = "CLAIM_COMPILER"
    ACTIVE_SENSING = "ACTIVE_SENSING"
    COUNTERFACTUAL = "COUNTERFACTUAL"
    CALIBRATION = "CALIBRATION"
    EXTERNAL_KNOWLEDGE = "EXTERNAL_KNOWLEDGE"
    VERBALIZER = "VERBALIZER"
    CRYSTAL_HANDOFF = "CRYSTAL_HANDOFF"
    SEQUENTIAL_EVIDENCE = "SEQUENTIAL_EVIDENCE"
    WORLD_GRAPH = "WORLD_GRAPH"


#: Architecture §45, as a table the code consults rather than prose an engineer
#: remembers. ``[§45.n]`` cites the bullet; ``[derived]`` marks the three rows
#: §45 does not cover, because seven rules cannot address ten subsystems and a
#: silently invented rule is worse than a labelled one.
FALLBACKS: Mapping[Subsystem, str] = MappingProxyType(
    {
        Subsystem.WORLD_LIFECYCLE: (
            "prune low-consequence dominated worlds first; never convert "
            "uncertainty to benign"
        ),
        Subsystem.CLAIM_COMPILER: (
            "emit no authoritative claim; preserve the evidence references and "
            "the detection path"
        ),
        Subsystem.ACTIVE_SENSING: "fall back to the Stage 1 default observation policy",
        Subsystem.COUNTERFACTUAL: (
            "disable counterfactual claims; preserve evidence and detection"
        ),
        Subsystem.CALIBRATION: "widen uncertainty and increase abstention",
        Subsystem.EXTERNAL_KNOWLEDGE: "drop EXT claims; internal reasoning continues",
        Subsystem.VERBALIZER: "deterministic typed claim rendering",
        Subsystem.CRYSTAL_HANDOFF: (
            "continue with zero crystallised cells; internal reasoning continues"
        ),
        Subsystem.SEQUENTIAL_EVIDENCE: (
            "stop accumulating the e-process; widen uncertainty and increase abstention"
        ),
        Subsystem.WORLD_GRAPH: (
            "isolate the corrupt incident state; reconstruct from retained "
            "evidence references where possible"
        ),
    }
)

#: Which §45 bullet each row above came from, kept beside the table so the three
#: derived rows cannot be mistaken for quotations. ``0`` means derived.
FALLBACK_SOURCES: Mapping[Subsystem, int] = MappingProxyType(
    {
        Subsystem.WORLD_LIFECYCLE: 1,
        Subsystem.CLAIM_COMPILER: 0,
        Subsystem.ACTIVE_SENSING: 3,
        Subsystem.COUNTERFACTUAL: 2,
        Subsystem.CALIBRATION: 4,
        Subsystem.EXTERNAL_KNOWLEDGE: 5,
        Subsystem.VERBALIZER: 6,
        Subsystem.CRYSTAL_HANDOFF: 0,
        Subsystem.SEQUENTIAL_EVIDENCE: 0,
        Subsystem.WORLD_GRAPH: 7,
    }
)


def _one_line(message: object) -> str:
    """Collapse to one bounded line, so a traceback cannot be stored as a message.

    Splitting on whitespace and rejoining removes the newlines that make a
    traceback a traceback, and the slice bounds what an attacker-influenced
    exception string can cost. Truncation is marked, never silent.
    """
    text = " ".join(str(message).split())
    if len(text) <= MAX_DEGRADATION_MESSAGE:
        return text
    return text[: MAX_DEGRADATION_MESSAGE - 1] + "…"


@dataclass(frozen=True, slots=True)
class DegradationRecord:
    """One Stage 4 subsystem failure, and the §45 rule applied in its place."""

    subsystem: Subsystem
    exception_type: str
    #: One line, ``<= MAX_DEGRADATION_MESSAGE`` chars, never a traceback.
    message: str
    at_sequence: int
    #: The §45 rule applied, verbatim from :data:`FALLBACKS`.
    fallback: str
    #: True when the evidence references survived the failure, which is what
    #: makes the incident reconstructable (§45's last rule).
    evidence_preserved: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "subsystem", Subsystem(self.subsystem))
        if not isinstance(self.exception_type, str) or not self.exception_type.strip():
            raise ContractError("DegradationRecord.exception_type must be a non-empty string")
        object.__setattr__(self, "exception_type", _one_line(self.exception_type))
        object.__setattr__(self, "message", _one_line(self.message))
        require_non_negative_int(self.at_sequence, "DegradationRecord.at_sequence")
        expected = FALLBACKS[self.subsystem]
        if self.fallback != expected:
            raise ContractError(
                f"DegradationRecord.fallback for {self.subsystem.value} must be the "
                f"§45 rule {expected!r}, got {self.fallback!r}"
            )
        if not isinstance(self.evidence_preserved, bool):
            raise ContractError("DegradationRecord.evidence_preserved must be a bool")

    def to_dict(self) -> dict[str, Any]:
        return {
            "subsystem": self.subsystem.value,
            "exception_type": self.exception_type,
            "message": self.message,
            "at_sequence": self.at_sequence,
            "fallback": self.fallback,
            "evidence_preserved": self.evidence_preserved,
        }


def record_for(
    subsystem: Subsystem,
    exc: BaseException,
    *,
    at_sequence: int = 0,
    evidence_preserved: bool = True,
) -> DegradationRecord:
    """Build the record for ``exc`` with the fallback this subsystem declares."""
    subsystem = Subsystem(subsystem)
    return DegradationRecord(
        subsystem=subsystem,
        exception_type=type(exc).__name__,
        message=_one_line(exc),
        at_sequence=at_sequence,
        fallback=FALLBACKS[subsystem],
        evidence_preserved=evidence_preserved,
    )


class DegradationLedger:
    """Bounded record of this run's Stage 4 failures.

    Bounded because it is endpoint state. When the cap is reached the *oldest*
    record is dropped and :attr:`dropped` counts it: the newest failure is the
    one that explains the current output, and a dropped record is reported
    rather than forgotten.
    """

    __slots__ = ("_capacity", "_dropped", "_records")

    def __init__(self, *, capacity: int = MAX_DEGRADATION_RECORDS) -> None:
        if capacity < 1:
            raise ContractError(f"DegradationLedger capacity must be >= 1, got {capacity}")
        self._capacity = capacity
        self._records: list[DegradationRecord] = []
        self._dropped = 0

    def record(self, record: DegradationRecord) -> None:
        if not isinstance(record, DegradationRecord):
            raise ContractError("DegradationLedger.record takes a DegradationRecord")
        self._records.append(record)
        while len(self._records) > self._capacity:
            self._records.pop(0)
            self._dropped += 1

    def records(self) -> tuple[DegradationRecord, ...]:
        return tuple(self._records)

    def degraded(self, subsystem: Subsystem) -> bool:
        target = Subsystem(subsystem)
        return any(item.subsystem is target for item in self._records)

    def degraded_any(self) -> bool:
        """True when anything failed. What :func:`downgrade_verdict` consults."""
        return bool(self._records) or self._dropped > 0

    @property
    def count(self) -> int:
        return len(self._records)

    @property
    def dropped(self) -> int:
        return self._dropped

    @property
    def truncated(self) -> bool:
        """True when the bound was hit and records were lost. Never silent."""
        return self._dropped > 0

    def memory_bytes(self) -> int:
        """Bytes the retained records hold, for the Stage 4 resource budget."""
        total = 0
        for item in self._records:
            total += (
                len(item.subsystem.value)
                + len(item.exception_type)
                + len(item.message)
                + len(item.fallback)
                + 16  # at_sequence + evidence_preserved + object overhead estimate
            )
        return total

    def to_dict(self) -> dict[str, Any]:
        return {
            "records": [item.to_dict() for item in self._records],
            "dropped": self._dropped,
            "truncated": self.truncated,
            "memory_bytes": self.memory_bytes(),
        }


_T = TypeVar("_T")


class guarded:
    """Run one Stage 4 subsystem so that its failure cannot reach Stage 1–3.

    Usable both ways, because both shapes occur in this codebase:

        with guarded(Subsystem.COUNTERFACTUAL, ledger, fallback=()) as scope:
            scope.result = intervene(world)
        worlds = scope.result          # () when intervene() raised

        @guarded(Subsystem.VERBALIZER, ledger, fallback="")
        def verbalize(claim): ...

    Catches ``BaseException`` apart from ``KeyboardInterrupt`` and ``SystemExit``:
    ``MemoryError`` and ``RecursionError`` are the failures §45's first rule is
    actually about, and they are not ``Exception`` subclasses by accident — they
    are the ones a bounded-world search hits first. The operator's interrupt and
    the process's own exit are re-raised, because swallowing them would make the
    endpoint unkillable.

    It records exactly one :class:`DegradationRecord` per failed scope and then
    returns the declared fallback. It never invents a resolution: see
    :func:`downgrade_verdict` for what the caller must do with the verdict
    afterwards.
    """

    __slots__ = (
        "_failed",
        "at_sequence",
        "evidence_preserved",
        "fallback",
        "ledger",
        "result",
        "subsystem",
    )

    def __init__(
        self,
        subsystem: Subsystem,
        ledger: DegradationLedger,
        *,
        at_sequence: int = 0,
        fallback: Any = None,
        evidence_preserved: bool = True,
    ) -> None:
        self.subsystem = Subsystem(subsystem)
        # Checked here, not at failure time: a mis-wired ledger would otherwise
        # turn the one call that must not raise into an escaping AttributeError,
        # and it would only show up on the day something actually crashed.
        if not isinstance(ledger, DegradationLedger):
            raise ContractError(
                f"guarded needs a DegradationLedger, got {type(ledger).__name__}"
            )
        self.ledger = ledger
        self.at_sequence = require_non_negative_int(at_sequence, "guarded at_sequence")
        self.fallback = fallback
        self.evidence_preserved = evidence_preserved
        self.result: Any = fallback
        self._failed = False

    # --- context-manager form ------------------------------------------------

    def __enter__(self) -> guarded:
        self.result = self.fallback
        self._failed = False
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        if exc is None:
            return False
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            return False
        self.ledger.record(
            record_for(
                self.subsystem,
                exc,
                at_sequence=self.at_sequence,
                evidence_preserved=self.evidence_preserved,
            )
        )
        self.result = self.fallback
        self._failed = True
        return True

    @property
    def failed(self) -> bool:
        return self._failed

    # --- decorator form ------------------------------------------------------

    def __call__(self, func: Callable[..., _T]) -> Callable[..., _T | Any]:
        """Wrap ``func`` so each call gets its own scope, not this one's state."""

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            scope = guarded(
                self.subsystem,
                self.ledger,
                at_sequence=self.at_sequence,
                fallback=self.fallback,
                evidence_preserved=self.evidence_preserved,
            )
            with scope:
                scope.result = func(*args, **kwargs)
            return scope.result

        return wrapper


def downgrade_verdict(verdict: Verdict, *, degraded: bool) -> Verdict:
    """Never let a guarded failure resolve an incident.

    §45's first rule — "never converts uncertainty to benign" — is the floor, not
    the ceiling. A subsystem that raised observed nothing, so a *committal*
    verdict computed around the hole is not supported by the reasoning that was
    supposed to support it. Any committal verdict therefore becomes
    :data:`DEGRADED_VERDICT`; an already non-committal verdict is left alone,
    because ``UNIDENTIFIABLE`` is an answer and rewriting it would lose the
    distinction between "cannot be identified" and "did not finish".

    Stage 1–3 keep their own verdicts either way. This function only ever makes
    Stage 4's contribution *less* committal, which is why it is safe for it to be
    the one thing every caller must not skip.
    """
    if not degraded:
        return Verdict(verdict)
    committal = Verdict(verdict)
    if committal in NON_COMMITTAL_VERDICTS:
        return committal
    return DEGRADED_VERDICT
