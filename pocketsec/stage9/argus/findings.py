"""ARGUS's vocabulary: the eight attack surfaces and the one record every attack returns.

It lives apart from ``argus.adversary`` so the attack modules (``adversary``, ``tampering``)
can share one ``ArgusFinding`` without importing each other. ``argus.adversary`` re-exports
every name here, so consumers keep importing from there.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from pocketsec.stage0.contracts.common import ContractError

__all__ = [
    "DEFENCE",
    "MEASUREMENT",
    "SURFACE_TESTS",
    "ArgusFinding",
    "ArgusSurface",
    "coverage",
]

#: A MEASUREMENT fires when an outcome changed; a DEFENCE fires when it refused a trial.
MEASUREMENT = "MEASUREMENT"
DEFENCE = "DEFENCE"


class ArgusSurface(StrEnum):
    """The eight attack surfaces of architecture §50."""

    DATA = "DATA"
    INPUT = "INPUT"
    STATE = "STATE"
    MODEL = "MODEL"
    SEARCH = "SEARCH"
    RESOURCE = "RESOURCE"
    SENSORS = "SENSORS"
    SUPPLY_CHAIN = "SUPPLY_CHAIN"


#: Architecture §50's "Test" column, row by row.
SURFACE_TESTS: Mapping[ArgusSurface, str] = {
    ArgusSurface.DATA: "poisoning, mislabeled episodes, corrupt baselines",
    ArgusSurface.INPUT: "evasion, mimicry, malformed/high-volume events",
    ArgusSurface.STATE: "memory corruption/restart/stale state",
    ArgusSurface.MODEL: "backdoor/shortcut/parameter corruption",
    ArgusSurface.SEARCH: "fitness hacking, benchmark overfit, hypothesis explosion",
    ArgusSurface.RESOURCE: "RAM/CPU/disk/network starvation",
    ArgusSurface.SENSORS: "partial loss/delay/reordering",
    ArgusSurface.SUPPLY_CHAIN: "tampered artifact/rule/model",
}


@dataclass(frozen=True, slots=True)
class ArgusFinding:
    """What one attack did. ``fired`` is the firing count; 0 means INERT."""

    attack_id: str
    surface: ArgusSurface
    kind: str  # "MEASUREMENT" (fired = outcomes changed) | "DEFENCE" (fired = refusals)
    fired: int
    total: int
    inert: bool
    metric_before: float | None
    metric_after: float | None
    detail: str
    measured_by: str

    def __post_init__(self) -> None:
        if self.kind not in (MEASUREMENT, DEFENCE):
            raise ContractError(f"finding kind must be MEASUREMENT or DEFENCE, got {self.kind!r}")
        if not isinstance(self.surface, ArgusSurface):
            raise ContractError(f"surface must be an ArgusSurface, got {self.surface!r}")
        if not 0 <= self.fired <= self.total:
            raise ContractError(f"fired must be in 0..total, got {self.fired} of {self.total}")
        # A finding may not call itself non-inert while having changed nothing, nor the
        # reverse: ``inert`` is checked against the firing count, never trusted.
        if self.inert != (self.fired == 0):
            raise ContractError(f"inert={self.inert} contradicts fired={self.fired}")

    @property
    def defence_failed(self) -> bool:
        """A DEFENCE must refuse on every trial (and have trials); anything less FAILED."""
        return self.kind == DEFENCE and (self.total == 0 or self.fired != self.total)

    def to_dict(self) -> dict[str, Any]:
        return {
            "attack_id": self.attack_id,
            "surface": self.surface.value,
            "kind": self.kind,
            "fired": self.fired,
            "total": self.total,
            "inert": self.inert,
            "defence_failed": self.defence_failed,
            "metric_before": self.metric_before,
            "metric_after": self.metric_after,
            "detail": self.detail,
            "measured_by": self.measured_by,
        }


def coverage(findings: Sequence[ArgusFinding]) -> frozenset[ArgusSurface]:
    """The surfaces some NON-INERT finding exercised. An attack that changed nothing
    covers nothing."""
    return frozenset(finding.surface for finding in findings if not finding.inert)
