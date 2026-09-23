"""D1.4 — Host Security State v1 and the state calculus (spec sections 4-5).

Capabilities are modelled as **ordered lattices**, so an event becomes an
operator over state rather than another categorical event id. This is the claim
Stage 1 has to test: that ``privilege: user < elevated < root`` generalises
better than a process-name feature, especially under renamed tools and unseen
binaries.

State is tracked per **causal lineage**, not only per host. A host-wide
aggregate saturates immediately and meaninglessly — root exists on every
machine. The security signal comes from one actor lineage accumulating
privilege *and* credential access *and* external reachability. See ADR-0005.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import IntEnum
from typing import Any

from pocketsec.stage0.contracts.common import ContractError

__all__ = [
    "CredentialExposure",
    "DIMENSIONS",
    "Discovery",
    "ExecutionControl",
    "Isolation",
    "ModificationCapability",
    "Persistence",
    "Privilege",
    "Reachability",
    "SecurityStateV1",
    "StateDelta",
    "Trust",
]


# --- ordered capability lattices ---------------------------------------------
# Each is a total order where a higher value means more capability (or, for
# Trust, less confidence). Ordering is what lets the calculus express "this
# event raised privilege" without naming the binary that did it.


class Privilege(IntEnum):
    USER = 0
    ELEVATED = 1
    ROOT = 2


class Trust(IntEnum):
    TRUSTED = 0
    UNCERTAIN = 1
    UNTRUSTED = 2


class CredentialExposure(IntEnum):
    NONE = 0
    METADATA = 1
    READABLE = 2
    EXTRACTED = 3


class Reachability(IntEnum):
    NONE = 0
    LOCAL = 1
    LAN = 2
    EXTERNAL = 3


class Persistence(IntEnum):
    NONE = 0
    USER = 1
    SERVICE = 2
    BOOT_KERNEL = 3


class ExecutionControl(IntEnum):
    LIMITED = 0
    INTERPRETER = 1
    PRIVILEGED = 2


class ModificationCapability(IntEnum):
    NONE = 0
    USER_FILES = 1
    CONFIG = 2
    SYSTEM = 3


class Discovery(IntEnum):
    NONE = 0
    LOCAL_INVENTORY = 1
    CREDENTIAL_SYSTEM = 2


class Isolation(IntEnum):
    """Boundary state. Higher means a boundary has been crossed."""

    CONFINED = 0
    NAMESPACE_AWARE = 1
    BOUNDARY_CROSSED = 2


#: Dimension name -> its lattice type. The single source of truth for the
#: calculus, the binary encoder and the ablation harness, so a new dimension
#: cannot be half-added.
DIMENSIONS: dict[str, type[IntEnum]] = {
    "privilege": Privilege,
    "trust": Trust,
    "credential": CredentialExposure,
    "reachability": Reachability,
    "persistence": Persistence,
    "execution": ExecutionControl,
    "modification": ModificationCapability,
    "discovery": Discovery,
    "isolation": Isolation,
}


@dataclass(frozen=True, slots=True)
class SecurityStateV1:
    """What is now true about one causal lineage (or the host aggregate)."""

    privilege: Privilege = Privilege.USER
    trust: Trust = Trust.TRUSTED
    credential: CredentialExposure = CredentialExposure.NONE
    reachability: Reachability = Reachability.NONE
    persistence: Persistence = Persistence.NONE
    execution: ExecutionControl = ExecutionControl.LIMITED
    modification: ModificationCapability = ModificationCapability.NONE
    discovery: Discovery = Discovery.NONE
    isolation: Isolation = Isolation.CONFINED

    def level(self, dimension: str) -> int:
        try:
            return int(getattr(self, dimension))
        except AttributeError as exc:
            raise ContractError(f"unknown state dimension {dimension!r}") from exc

    def raised_to(self, dimension: str, level: IntEnum) -> SecurityStateV1:
        """Return a new state with ``dimension`` raised to at least ``level``.

        Monotone within a lineage: capability does not spontaneously decay. You
        do not un-read a credential, and an attacker does not lose root by
        running ``ls``. Decay belongs to epoch rotation and lineage expiry,
        which are explicit and evidence-backed, not to per-event drift.
        """
        if dimension not in DIMENSIONS:
            raise ContractError(f"unknown state dimension {dimension!r}")
        if int(level) <= self.level(dimension):
            return self
        return replace(self, **{dimension: level})

    def delta_from(self, previous: SecurityStateV1) -> StateDelta:
        return StateDelta.between(previous, self)

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name).name for name in DIMENSIONS}

    def to_levels(self) -> dict[str, int]:
        return {name: self.level(name) for name in DIMENSIONS}

    @classmethod
    def join(cls, left: SecurityStateV1, right: SecurityStateV1) -> SecurityStateV1:
        """Lattice join — the per-dimension maximum.

        Used to fold lineage states into the host aggregate. Join is monotone
        and order-independent, so the host view never depends on the order
        lineages happened to be visited.
        """
        return cls(
            **{
                name: enum_type(max(left.level(name), right.level(name)))
                for name, enum_type in DIMENSIONS.items()
            }  # type: ignore[arg-type]
        )


@dataclass(frozen=True, slots=True)
class StateDelta:
    """ΔS — what security-relevant truth changed.

    Only *raised* dimensions appear. A transition that changes nothing yields an
    empty delta, which is exactly the signal the aggregation policy needs to
    decide a transition is safely coalescible.
    """

    raised: dict[str, tuple[int, int]]

    def __post_init__(self) -> None:
        object.__setattr__(self, "raised", dict(self.raised))

    def __bool__(self) -> bool:
        return bool(self.raised)

    @property
    def dimensions(self) -> frozenset[str]:
        return frozenset(self.raised)

    @property
    def magnitude(self) -> int:
        """Total number of lattice steps climbed."""
        return sum(after - before for before, after in self.raised.values())

    def bitmask(self) -> int:
        """Pack raised dimensions into the SSIR ``state_delta`` field.

        Bit order follows ``DIMENSIONS`` insertion order, which is frozen by the
        SSIR v1 spec; appending a dimension is backward-compatible, reordering
        is not.
        """
        mask = 0
        for index, name in enumerate(DIMENSIONS):
            if name in self.raised:
                mask |= 1 << index
        return mask

    def to_dict(self) -> dict[str, Any]:
        return {
            "raised": {
                name: {"from": before, "to": after}
                for name, (before, after) in self.raised.items()
            },
            "magnitude": self.magnitude,
            "bitmask": self.bitmask(),
        }

    @classmethod
    def between(cls, previous: SecurityStateV1, current: SecurityStateV1) -> StateDelta:
        raised = {
            name: (previous.level(name), current.level(name))
            for name in DIMENSIONS
            if current.level(name) > previous.level(name)
        }
        return cls(raised=raised)

    @classmethod
    def empty(cls) -> StateDelta:
        return cls(raised={})


assert len(DIMENSIONS) <= 16, "state_delta bitmask is a uint16 in the SSIR layout"
