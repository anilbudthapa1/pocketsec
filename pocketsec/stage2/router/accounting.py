"""Honest path accounting — a saving that was not made cannot be reported.

ADR-0114, superseding the notional accounting recorded in ADR-0010.

The measured defect this module exists to make impossible: the Need-to-Compute
router reported **100 % of events resolved on cheap paths (P0–P2) while every
branch was computed regardless of its gate**, and the model was still 3.4× slower
than a plain TCN. The gate labelled work instead of avoiding it, and the number
that was supposed to demonstrate "computation proportional to novelty" was a
label, not a measurement. That is the single most damning result in Stage 2.

The fix is structural, not procedural:

* ``ExecutionPath`` is **derived** from the highest-cost ``WorkKind`` that was
  actually performed. ``WorkLedger.close()`` takes no path argument and
  ``PathAccount`` refuses to be constructed with a path its own work does not
  imply. **No caller can declare a path.** A path can therefore only be reported
  cheap because the expensive work genuinely did not run.
* A record marked ``performed=False`` must cost ``0.0`` units. "Units I avoided"
  is the exact shape of a phantom saving, so it is a contract error.
* ``measured()`` writes its record in a ``finally`` block and never writes a
  skip. If the body raises, the work is still charged — an exception halfway
  through inference spent compute, and reporting that event as cheap would be
  banking a saving the host never received.
* ``assert_no_phantom_savings()`` refuses a ledger in which any kind was recorded
  both skipped and performed.

This module does **not** ship a router. The Need router is measured harmful
(−0.115 PR-AUC) and no design in this repository delivers savings; see
`router/policy.py` for the retained deterministic policy and its default-off
flag. What ships here is the accounting that makes a future savings claim
checkable instead of rhetorical.

Stdlib only: this runs on the endpoint.
"""

from __future__ import annotations

import math
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Iterator

from pocketsec.stage0.contracts.common import ContractError

# PATH_COST_UNITS is intentionally not in `core_ids.__all__`; it is imported by
# name because the cost *ordering* is what derives a path, and re-declaring that
# ordering here would let the two drift apart.
from pocketsec.stage2.core_ids import PATH_COST_UNITS, ExecutionPath

__all__ = [
    "MAX_LEDGER_EVENTS",
    "PathAccount",
    "WorkKind",
    "WorkLedger",
    "WorkRecord",
    "measured",
]

#: Ledger capacity in closed event accounts. Bounded endpoint state; truncation
#: is explicit through `WorkLedger.truncated()`.
MAX_LEDGER_EVENTS: int = 4096


class WorkKind(StrEnum):
    """Units of work whose presence or absence decides the execution path."""

    CACHE_LOOKUP = "CACHE_LOOKUP"
    LATTICE_LOOKUP = "LATTICE_LOOKUP"
    WINDOW_UPDATE = "WINDOW_UPDATE"
    CORE_INFERENCE = "CORE_INFERENCE"
    CONE_EXPANSION = "CONE_EXPANSION"
    COUNTERFACTUAL = "COUNTERFACTUAL"


#: Which path each kind of work implies *when it actually runs*. The mapping is
#: the honest half of `ExecutionPath`'s docstring: P0 is a compiled/cached answer,
#: P1 a lattice lookup, P2 a local state update, P3 predictive inference, P4
#: counterfactual/deep analysis.
_KIND_PATHS: dict[WorkKind, ExecutionPath] = {
    WorkKind.CACHE_LOOKUP: ExecutionPath.P0_COMPILED,
    WorkKind.LATTICE_LOOKUP: ExecutionPath.P1_LATTICE,
    WorkKind.WINDOW_UPDATE: ExecutionPath.P2_LOCAL,
    WorkKind.CORE_INFERENCE: ExecutionPath.P3_PREDICTIVE,
    WorkKind.CONE_EXPANSION: ExecutionPath.P3_PREDICTIVE,
    WorkKind.COUNTERFACTUAL: ExecutionPath.P4_DEEP,
}


def _derive_path(work: tuple[WorkRecord, ...]) -> ExecutionPath:
    """The path implied by what ran. The only way a path is ever produced.

    An event with nothing performed lands on the cheapest path, which is safe:
    no expensive work can hide there, because a single performed expensive record
    lifts the whole event.
    """
    performed = [_KIND_PATHS[record.kind] for record in work if record.performed]
    if not performed:
        return ExecutionPath.P0_COMPILED
    return max(performed, key=lambda path: PATH_COST_UNITS[path])


@dataclass(frozen=True, slots=True)
class WorkRecord:
    """One unit of work, and whether it genuinely happened."""

    kind: WorkKind
    #: True only when the work actually ran.
    performed: bool
    #: PATH_COST_UNITS-comparable cost. Must be 0.0 on a skipped record.
    units: float
    detail: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", WorkKind(self.kind))
        if not isinstance(self.performed, bool):
            raise ContractError(
                f"performed must be a bool, got {type(self.performed).__name__}"
            )
        units = float(self.units)
        if not math.isfinite(units) or units < 0.0:
            raise ContractError(f"units must be finite and >= 0, got {self.units!r}")
        object.__setattr__(self, "units", units)
        if not self.performed and units != 0.0:
            raise ContractError(
                "a skipped record must cost 0.0 units; "
                f"{self.kind.value} claims {units} units it did not spend, "
                "which is how a phantom saving gets written"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "performed": self.performed,
            "units": round(self.units, 6),
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class PathAccount:
    """One event's work, and the path that work derives.

    The constructor re-derives the path and refuses a mismatch, so this type
    cannot be used to assert a cheap path over expensive work even by building it
    directly. That refusal is ADR-0114 expressed as a type.
    """

    path: ExecutionPath
    work: tuple[WorkRecord, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "work", tuple(self.work))
        derived = _derive_path(self.work)
        if ExecutionPath(self.path) is not derived:
            raise ContractError(
                f"path {ExecutionPath(self.path).value} was declared but the recorded "
                f"work derives {derived.value}; a path is derived, never declared"
            )
        object.__setattr__(self, "path", derived)

    @property
    def performed_units(self) -> float:
        """Cost that was actually spent. Skipped records contribute nothing."""
        return sum(record.units for record in self.work if record.performed)

    @property
    def skipped_kinds(self) -> frozenset[WorkKind]:
        """Kinds with at least one ``performed=False`` record."""
        return frozenset(record.kind for record in self.work if not record.performed)

    @property
    def performed_kinds(self) -> frozenset[WorkKind]:
        return frozenset(record.kind for record in self.work if record.performed)

    @property
    def contradictions(self) -> frozenset[WorkKind]:
        """Kinds recorded both skipped and performed — the ADR-0010 defect."""
        return self.performed_kinds & self.skipped_kinds

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path.value,
            "performed_units": round(self.performed_units, 6),
            "skipped_kinds": sorted(kind.value for kind in self.skipped_kinds),
            "work": [record.to_dict() for record in self.work],
        }


class WorkLedger:
    """A path may be reported as skipped only if nothing recorded it as performed.

    Bounded at ``max_events`` closed accounts; beyond that, accounts are still
    returned to the caller but no longer retained, and `truncated()` says so.
    `histogram()` and `compute_units_per_event()` therefore describe the retained
    accounts, which is why the truncation flag is part of the reported result and
    not an implementation detail.
    """

    def __init__(self, *, max_events: int = MAX_LEDGER_EVENTS) -> None:
        if max_events < 1:
            raise ContractError(f"max_events must be >= 1, got {max_events}")
        self.max_events = max_events
        self._accounts: list[PathAccount] = []
        self._open_key: str | None = None
        self._open: list[WorkRecord] = []
        self._truncated = False
        self._events_seen = 0

    def begin(self, event_key: str) -> None:
        """Open an account for one event."""
        if not event_key:
            raise ContractError("event_key must be non-empty")
        if self._open_key is not None:
            raise ContractError(
                f"event {self._open_key!r} is still open; an abandoned account "
                "loses its records and would report the next event as cheaper "
                "than it was"
            )
        self._open_key = event_key
        self._open = []

    def record(
        self, kind: WorkKind, *, performed: bool, units: float, detail: str = ""
    ) -> None:
        """Append one work record to the open account."""
        if self._open_key is None:
            raise ContractError(
                "record() outside begin()/close(): unattributed work is "
                "indistinguishable from work that never ran"
            )
        self._open.append(
            WorkRecord(kind=kind, performed=performed, units=units, detail=detail)
        )

    def close(self) -> PathAccount:
        """Close the open account, deriving its path from what ran.

        Takes no path argument, and never will: the whole point of ADR-0114 is
        that the caller does not get a vote.
        """
        if self._open_key is None:
            raise ContractError("close() without begin()")
        work = tuple(self._open)
        account = PathAccount(path=_derive_path(work), work=work)
        self._open_key = None
        self._open = []
        self._events_seen += 1
        if len(self._accounts) < self.max_events:
            self._accounts.append(account)
        else:
            self._truncated = True
        return account

    def histogram(self) -> dict[str, int]:
        """Retained accounts per path. Every path key is present, including zeros."""
        counts = {path.value: 0 for path in ExecutionPath}
        for account in self._accounts:
            counts[account.path.value] += 1
        return counts

    def path_fractions(self) -> dict[str, float]:
        """`histogram()` normalised. Sums to 1.0 when anything is retained."""
        total = len(self._accounts)
        if total == 0:
            return {path.value: 0.0 for path in ExecutionPath}
        return {key: value / total for key, value in self.histogram().items()}

    def compute_units_per_event(self) -> float:
        """Mean units **actually spent** per retained event.

        Deliberately not a `PATH_COST_UNITS`-weighted figure. That constant's
        docstring claims calibration from measured CPU time and no calibration
        code exists anywhere in this repository, so a weighted total would be a
        policy simulation wearing a measurement's clothes. The honest cost number
        beside this one is wall-clock µs/event from
        `research/sleeping_brain.py`.
        """
        if not self._accounts:
            return 0.0
        return sum(account.performed_units for account in self._accounts) / len(
            self._accounts
        )

    def truncated(self) -> bool:
        """True when events were seen but not retained."""
        return self._truncated

    def events_seen(self) -> int:
        """Closed events, including any the ledger stopped retaining."""
        return self._events_seen

    def accounts(self) -> tuple[PathAccount, ...]:
        return tuple(self._accounts)

    def open_event(self) -> str | None:
        return self._open_key

    def assert_no_phantom_savings(self) -> None:
        """Raise when any kind was recorded both skipped and performed.

        The open account is checked too: a contradiction found only after
        `close()` would already have been reported to the caller.
        """
        offenders: list[str] = []
        for index, account in enumerate(self._accounts):
            if account.contradictions:
                offenders.append(
                    f"account[{index}]:"
                    + ",".join(sorted(k.value for k in account.contradictions))
                )
        if self._open:
            performed = {r.kind for r in self._open if r.performed}
            skipped = {r.kind for r in self._open if not r.performed}
            contradictions = performed & skipped
            if contradictions:
                offenders.append(
                    f"open[{self._open_key}]:"
                    + ",".join(sorted(k.value for k in contradictions))
                )
        if offenders:
            raise ContractError(
                "phantom savings: work recorded as skipped was also performed "
                f"({'; '.join(offenders)}). This is the ADR-0010 defect: a gate "
                "that labels work instead of avoiding it."
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "events_seen": self._events_seen,
            "events_retained": len(self._accounts),
            "truncated": self._truncated,
            "histogram": self.histogram(),
            "path_fractions": {
                key: round(value, 6) for key, value in self.path_fractions().items()
            },
            "performed_units_per_event": round(self.compute_units_per_event(), 6),
            "path_cost_units_calibrated": False,
        }


@contextmanager
def measured(ledger: WorkLedger, kind: WorkKind, units: float) -> Iterator[None]:
    """Charge ``kind`` for the body, whatever the body does.

    The record is written in a ``finally``, so a raise or an early return inside
    the body still charges the work. It is never written as a skip: entering the
    block *is* performing the work, and an exception halfway through inference
    spent real compute. A genuine skip is recorded by the branch that did not
    enter the block, with ``ledger.record(kind, performed=False, units=0.0)`` —
    and `assert_no_phantom_savings` then catches any caller that does both.

    A context manager that is created but never entered records nothing, because
    nothing ran.
    """
    entered = False
    completed = False
    try:
        entered = True
        yield
        completed = True
    finally:
        if entered:
            ledger.record(
                kind,
                performed=True,
                units=units,
                detail=(
                    "measured block exited normally"
                    if completed
                    else "measured block raised; work was still spent"
                ),
            )
